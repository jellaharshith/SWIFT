"""Engagement-planning workflow (Decepticon-ported).

Three artifacts per engagement, all human-readable:

* ``roe.yaml``    -- loaded by :func:`security.roe.load_roe`
* ``OPPLAN.md``   -- MITRE ATT&CK-mapped operation plan
* ``ConOps.md``   -- Concept of Operations narrative

:func:`engage` drives the Soundwave specialist when an LLM is reachable; the
quick path (:func:`engage_quick`) skips the interview and stamps a template
the operator edits by hand.
"""
from engagement.soundwave import engage, engage_quick
from engagement.opplan import OPPLAN, render_opplan
from engagement.conops import render_conops

__all__ = ["engage", "engage_quick", "OPPLAN", "render_opplan", "render_conops"]
