"""CLI handlers for plugin install/list/remove/validate."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run_install(args) -> None:
    package = args.package
    print(f"[plugin] Installing {package!r} ...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", package, "-q"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"[plugin] ERROR: pip install failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    # Re-discover after install
    from sdk.registry import PluginRegistry
    reg = PluginRegistry()
    reg.discover()
    if not reg.names():
        print(f"[plugin] Installed {package!r} but no swift.modules entry-points found. "
              "Ensure the package declares [project.entry-points.\"swift.modules\"] in pyproject.toml.")
    else:
        print(f"[plugin] ✓ Installed. Discovered modules: {', '.join(reg.names())}")


def run_list(args) -> None:
    from sdk.migration import ALL_ADAPTERS
    from sdk.registry import PluginRegistry
    try:
        from rich.console import Console
        from rich.table import Table
        reg = PluginRegistry()
        reg.discover()
        for cls in ALL_ADAPTERS:
            try:
                reg.register(cls)
            except Exception:
                pass
        table = Table(title="SWIFT Modules")
        table.add_column("Name")
        table.add_column("Version")
        table.add_column("Author")
        table.add_column("Phase")
        table.add_column("Vuln Types")
        table.add_column("Source")
        for name in sorted(reg._modules):
            cls = reg._modules[name]
            is_builtin = any(cls is a for a in ALL_ADAPTERS)
            source = "builtin-adapter" if is_builtin else "installed"
            table.add_row(
                cls.name, cls.version, cls.author, cls.phase.value,
                ", ".join(vt.value for vt in cls.vuln_types), source,
            )
        Console().print(table)
    except ImportError:
        # Fallback without rich
        reg = PluginRegistry()
        reg.discover()
        for name in sorted(reg._modules):
            cls = reg._modules[name]
            print(f"{cls.name:<20} {cls.version:<8} {cls.author:<15} {cls.phase.value}")


def run_remove(args) -> None:
    name = args.name
    print(f"[plugin] Removing {name!r} ...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "uninstall", name, "-y"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"[plugin] ERROR: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"[plugin] ✓ Removed {name!r}")


def run_validate(args) -> None:
    path = Path(args.path)
    if not path.exists():
        print(f"[plugin] ERROR: path not found: {path}", file=sys.stderr)
        sys.exit(1)
    import importlib.util
    spec = importlib.util.spec_from_file_location("_plugin_validate", path)
    if spec is None:
        print(f"[plugin] ERROR: cannot load {path}", file=sys.stderr)
        sys.exit(1)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    from sdk.base import BaseModule
    from sdk.registry import PluginRegistry
    reg = PluginRegistry()
    found = 0
    for attr in vars(mod).values():
        if isinstance(attr, type) and issubclass(attr, BaseModule) and attr is not BaseModule:
            result = reg.validate(attr)
            if result.valid:
                print(f"[plugin] ✓ {attr.__name__} — valid")
                found += 1
            else:
                print(f"[plugin] ✗ {attr.__name__} — {'; '.join(result.errors)}", file=sys.stderr)
    if found == 0:
        print("[plugin] No BaseModule subclasses found in file.")
        sys.exit(1)
