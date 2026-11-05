from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from .utils import decode_console, run_process, which_powershell


class PowerShellError(RuntimeError):
    pass


def powershell_available() -> bool:
    return bool(which_powershell())


def run_ps_script(
    script_path: str,
    arguments: Optional[List[str]] = None,
    timeout: int = 240,
) -> Dict[str, Any]:
    """Run a bundled PowerShell helper and return its combined output.

    Helpers write machine-readable JSON to a file supplied by the caller.
    Stdout/stderr are captured only for diagnostics.
    """
    ps = which_powershell()
    if not ps:
        raise PowerShellError("PowerShell was not found")
    cmd = [
        ps,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_path,
    ] + list(arguments or [])
    try:
        proc = run_process(cmd, timeout=timeout)
    except Exception as exc:
        raise PowerShellError(str(exc)) from exc
    return {
        "returncode": proc.returncode,
        "stdout": decode_console(proc.stdout or b""),
        "stderr": decode_console(proc.stderr or b""),
        "command": cmd,
    }


def ps_json(
    script_path: str,
    arguments: Optional[List[str]] = None,
    timeout: int = 240,
) -> Any:
    """Run a helper that accepts -OutputFile and parse the resulting JSON."""
    args = list(arguments or [])
    with tempfile.TemporaryDirectory(prefix="vcheck-ps-") as temp_dir:
        output_path = os.path.join(temp_dir, "output.json")
        args += ["-OutputFile", output_path]
        result = run_ps_script(script_path, args, timeout=timeout)
        if not os.path.exists(output_path):
            raise PowerShellError(
                "PowerShell helper produced no output. "
                f"exit={result['returncode']} stderr={result['stderr'][-1200:]}"
            )
        try:
            with open(output_path, "r", encoding="utf-8-sig") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise PowerShellError(f"invalid JSON from PowerShell helper: {exc}") from exc
        if isinstance(data, dict) and data.get("__error__"):
            raise PowerShellError(str(data.get("__error__")))
        return data
