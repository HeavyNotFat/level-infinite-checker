from __future__ import annotations

import os
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .utils import canonical_key, now_iso, read_text_safe
from .winps import PowerShellError, ps_json, powershell_available


PROJECT_ROOT = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIGNATURE_SCRIPT = os.path.join(PROJECT_ROOT, "tools", "Get-SignatureInfo.ps1")


def collect_signatures(paths: Iterable[str], timeout: int = 240) -> Dict[str, Dict[str, Any]]:
    paths = [path for path in dict.fromkeys(paths) if path and os.path.isfile(path)]
    if not paths or not powershell_available() or not os.path.isfile(SIGNATURE_SCRIPT):
        return {}
    with tempfile.TemporaryDirectory(prefix="vcheck-sig-") as temp_dir:
        paths_file = os.path.join(temp_dir, "paths.txt")
        with open(paths_file, "w", encoding="utf-8-sig") as handle:
            for path in paths:
                handle.write(path + "\n")
        try:
            data = ps_json(SIGNATURE_SCRIPT, ["-PathsFile", paths_file], timeout=timeout)
        except PowerShellError:
            return {}
    result: Dict[str, Dict[str, Any]] = {}
    if isinstance(data, dict):
        data = [data]
    for item in data or []:
        if not isinstance(item, dict):
            continue
        path = item.get("path", "")
        if path:
            result[canonical_key(path)] = item
    return result


def signature_for(path: str, signatures: Optional[Dict[str, Dict[str, Any]]]) -> Dict[str, Any]:
    if not signatures:
        return {}
    return signatures.get(canonical_key(path), {})


def is_valve(subject: str) -> bool:
    return "valve" in (subject or "").casefold()


def is_trusted_third_party(subject: str) -> bool:
    subject_lower = (subject or "").casefold()
    return any(name in subject_lower for name in (
        "microsoft", "nvidia", "advanced micro devices", "amd", "intel",
        "google", "mozilla", "apple", "digicert",
    ))


def status_severity(status: str, is_core: bool = False) -> str:
    status = (status or "").casefold()
    if status == "valid":
        return "info"
    if status in ("hashmismatch", "nottrusted", "notsupported", "incompatible"):
        return "high" if is_core else "medium"
    if status == "notsigned":
        return "high" if is_core else "medium"
    if status == "missing":
        return "high" if is_core else "low"
    return "medium" if is_core else "low"
