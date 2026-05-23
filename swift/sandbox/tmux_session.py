"""Persistent interactive tool sessions via tmux (libtmux).

Why this exists
---------------
Some red-team tools (msfconsole, sliver, evil-winrm, certipy interactive)
maintain state between commands; one-shot ``subprocess.run`` loses it. SWIFT's
existing :mod:`kali.runner` already handles fire-and-forget tools well; this
module is its complement for the long-lived interactive case.

Design follows the Decepticon ``sandbox_kernel/tmux.py`` semantics but slims
the implementation by using :mod:`libtmux` directly rather than parsing tmux
CLI output:

* one tmux session per logical job (keyed by ``session_name``)
* :meth:`send` types text + Enter, then polls the pane for new output
* :attr:`STALL_SECONDS` of pane silence is treated as "tool is waiting for
  more input" (typical interactive prompt) and the call returns
* if total wall time exceeds :attr:`AUTO_BACKGROUND_SECONDS` the session is
  detached and the partial output returned -- caller can poll later

Every external interaction is ROE-gated by ``tmux_interactive``.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import libtmux  # type: ignore
except ImportError:  # pragma: no cover -- optional
    libtmux = None  # type: ignore

log = logging.getLogger("swift.sandbox.tmux")

POLL_INTERVAL = 0.4
STALL_SECONDS = 3.0
AUTO_BACKGROUND_SECONDS = 60.0
MAX_OUTPUT_CHARS = 30_000


@dataclass
class SessionResult:
    output: str
    completed: bool
    stalled: bool
    background: bool
    elapsed: float
    truncated: bool = False
    meta: dict[str, Any] = field(default_factory=dict)


class TmuxNotInstalledError(RuntimeError):
    """Raised when libtmux or the tmux binary is missing."""


def _require_libtmux() -> None:
    if libtmux is None:
        raise TmuxNotInstalledError(
            "libtmux missing; pip install swiftsec[tmux] (and `brew install tmux` / `apt install tmux`)"
        )


class TmuxSession:
    """One persistent tmux pane wrapped in a small Python class.

    Sessions auto-create on first :meth:`send`. :meth:`close` kills the tmux
    session (use :meth:`detach` to leave it running for later reattachment).
    """

    def __init__(self, session_name: str, *, server: Any | None = None) -> None:
        _require_libtmux()
        self.name = session_name
        self._server = server or libtmux.Server()
        self._session = None
        self._pane = None
        self._created = False

    def _ensure(self) -> None:
        if self._created:
            return
        # libtmux will reuse a session of the same name if it exists.
        try:
            self._session = self._server.new_session(
                session_name=self.name, kill_session=False, attach=False
            )
        except libtmux.exc.TmuxSessionExists:  # type: ignore[attr-defined]
            self._session = self._server.find_where({"session_name": self.name})
        self._pane = self._session.attached_pane
        self._created = True

    # ------------------------------------------------------------------- I/O

    def send(
        self,
        command: str,
        *,
        timeout: float | None = None,
        expect: str | None = None,
    ) -> SessionResult:
        """Type ``command`` + Enter, wait for output to settle, return it.

        Stops when one of:
        * pane is silent for ``STALL_SECONDS``     -> ``stalled=True``
        * ``expect`` substring appears in output   -> ``completed=True``
        * total time exceeds ``timeout`` (or ``AUTO_BACKGROUND_SECONDS``)
          -> ``background=True``
        """
        self._ensure()
        deadline = timeout or AUTO_BACKGROUND_SECONDS
        log.info("tmux.send session=%s len=%d", self.name, len(command))
        self._pane.send_keys(command, enter=True, suppress_history=False)

        start = time.monotonic()
        last_output_at = start
        last_lines: list[str] = []
        background = False
        completed = False
        stalled = False

        while True:
            time.sleep(POLL_INTERVAL)
            lines = self._pane.cmd("capture-pane", "-p").stdout
            elapsed = time.monotonic() - start

            if lines != last_lines:
                last_lines = lines
                last_output_at = time.monotonic()
                if expect and any(expect in ln for ln in lines):
                    completed = True
                    break
            else:
                if (time.monotonic() - last_output_at) >= STALL_SECONDS:
                    stalled = True
                    break

            if elapsed >= deadline:
                background = True
                break

        text = "\n".join(last_lines)
        truncated = False
        if len(text) > MAX_OUTPUT_CHARS:
            text = text[-MAX_OUTPUT_CHARS:]
            truncated = True

        return SessionResult(
            output=text,
            completed=completed,
            stalled=stalled,
            background=background,
            elapsed=time.monotonic() - start,
            truncated=truncated,
            meta={"session": self.name},
        )

    # ----------------------------------------------------------------- mgmt

    def kill(self) -> None:
        if self._session is not None:
            try:
                self._session.kill_session()
            finally:
                self._session = None
                self._pane = None
                self._created = False

    def detach(self) -> None:
        """Leave session running; just drop our references."""
        self._session = None
        self._pane = None
        self._created = False

    def __enter__(self) -> "TmuxSession":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.kill()


def list_sessions(server: Any | None = None) -> list[str]:
    _require_libtmux()
    srv = server or libtmux.Server()
    return [s.name for s in (srv.sessions or [])]
