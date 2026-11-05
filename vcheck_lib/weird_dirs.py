from __future__ import annotations

import json
import os
import re
import time
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .utils import (
    canonical_key,
    is_hidden_or_system,
    is_reparse_point,
    is_user_writable,
    shannon_entropy,
    string_score,
    utc_iso_from_timestamp,
)


# Names that are normal Windows/app data containers.  This is an allow-list of
# *containers*, not an allow-list of everything inside them: unknown names
# below these folders are still scored.
ROOT_CONTAINERS = {
    "$recycle.bin",
    "$winreagent",
    "$winre_backup_partition.marker",
    "config.msi",
    "documents and settings",
    "efi",
    "intel",
    "amd",
    "nvidia",
    "perflogs",
    "program files",
    "program files (x86)",
    "programdata",
    "recovery",
    "system volume information",
    "users",
    "windows",
    "msocache",
    "boot",
    "oem",
    "drivers",
    "temp",
    "tmp",
    "dell",
    "hp",
    "lenovo",
    "swsetup",
}

# Folders that are almost always generated caches.  They are skipped in the
# quick profile because they contain thousands of hash-like names and would
# drown the report.  Full mode can include them with --include-caches.
CACHE_CONTAINERS = {
    "cache",
    "cache2",
    "cachestorage",
    "code cache",
    "dawncache",
    "gpucache",
    "graphitedawncache",
    "grshadercache",
    "shadercache",
    "service worker",
    "indexeddb",
    "local storage",
    "session storage",
    "blob_storage",
    "databases",
    "file system",
    "jump list data",
    "inetcache",
    "webcache",
    "temporary internet files",
    "wernr",
    "crashpad",
    "reports",
    "gpupersistentcache",
    "dawngraphitecache",
    "shader_cache",
    "dynamicresource",
}

# Large or system-managed trees that are not useful for a name-only sweep.
SKIP_SUBTREES = (
    r"\windows\winsxs",
    r"\windows\servicing",
    r"\windows\installer",
    r"\windows\softwaredistribution",
    r"\windows\assembly",
    r"\windows\microsoft.net",
    r"\windows\drivers\driverstore",
    r"\windows\system32\driverstore",
    r"\windows\syswow64\driverstore",
    r"\programdata\package cache",
    r"\programdata\microsoft\windows\wer",
    r"\$recycle.bin",
    r"\system volume information",
    r"\node_modules",
    r"\.git",
    r"\__pycache__",
    r"\steamapps\common",
    r"\steamapps\workshop",
    r"\steamapps\downloading",
    r"\appdata\local\microsoft\applicationinsights",
    r"\appdata\local\officeplus\telemetrycache",
    r"\appdata\local\d3dscache",
    r"\appdata\local\ollama\updates_v2",
    r"\appdata\local\placeholdertilelogofolder",
    r"\appdata\local\package cache",
    r"\appdata\local\packages",
    r"\appdata\local\node-compile-cache",
)

# Mojibake fragments commonly produced by decoding UTF-8 as GBK/Latin-1, plus
# the classic replacement-character bug.  A hit is a reason to inspect, not a
# malware verdict: badly packaged ZIPs produce these names legitimately.
MOJIBAKE_PATTERNS = (
    ("锟斤拷", "classic GBK/UTF-8 mojibake sequence"),
    ("烫烫烫", "classic uninitialised-memory mojibake sequence"),
    ("屯屯屯", "classic uninitialised-memory mojibake sequence"),
    ("ï¿½", "UTF-8 replacement-character mojibake"),
    ("\ufffd", "Unicode replacement character"),
    ("Ã", "Latin-1/UTF-8 mojibake marker"),
    ("Â", "Latin-1/UTF-8 mojibake marker"),
    ("â€", "Windows-1252/UTF-8 mojibake marker"),
    ("ã€", "Shift-JIS/UTF-8 mojibake marker"),
    ("å¤", "UTF-8/GBK mojibake marker"),
    ("æ–", "UTF-8/GBK mojibake marker"),
    ("çš", "UTF-8/GBK mojibake marker"),
    ("é›", "UTF-8/GBK mojibake marker"),
    ("ðŸ", "UTF-8/Windows-1252 mojibake marker"),
    ("Ð", "Cyrillic/Latin-1 mojibake marker"),
)

MOJIBAKE_RE = re.compile(
    r"(?:Ã[\x80-\xBF]|Â[\x80-\xBF]|â€[\x80-\xBF]|ðŸ|ï¿½|ã€|å¤|æ–|çš|é›)"
)

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
BIDI_CONTROLS = {chr(code) for code in range(0x202A, 0x202F)} | {chr(code) for code in range(0x2066, 0x206A)}

FILE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".lnk", ".url", ".msi",
}

RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

# Compatibility junctions that Windows creates in user profiles and
# ProgramData.  They are reparse points by design and must not be reported as
# suspicious just because of that.
KNOWN_COMPAT_JUNCTIONS = {
    "application data", "cookies", "desktop", "documents", "favorites",
    "local settings", "my documents", "my music", "my pictures", "my videos",
    "nethood", "printhood", "recent", "sendto", "start menu", "templates",
    "「开始」菜单", "桌面", "我的文档", "收藏夹",
}

PACKAGE_NAME_RE = re.compile(r"_[a-z0-9]{12,13}$|[-_][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
GUID_RE = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.I)

DEVELOPER_TEMP_PREFIXES = (
    "playwright-", "ugc-php-test-", "pip-", "npm-", "pytest-", "go-build",
    "vscode-", "cursor-", "scoped_dir", "chrome_", "msedge_", "puppeteer_dev_",
    "cq_syntax_", "dsh-", "tmp", "tmp-", "tmp_", "build-", "test-",
    "coverage", "yarn-", "pnpm-", "electron-", "windsurf-", "claude-",
    "tfjs_", "tensorflow", "onnx", "torch", "huggingface", "transformers",
    "webpack", "vite", "esbuild", "rollup", "jest", "cypress",
    "frida-", "is-", "dsh-edge-", "dsh-probe-", "playwright_chromiumdev_profile-",
)


def _category_flags(name: str) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    controls = []
    private = []
    unassigned = []
    for char in name:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            controls.append(char)
            continue
        category = unicodedata.category(char)
        if category in ("Cc", "Cs"):
            controls.append(char)
        elif category == "Co":
            private.append(char)
        elif category == "Cn":
            unassigned.append(char)
    if controls:
        score += 5.0
        reasons.append(f"contains control/unpaired-surrogate characters ({len(controls)})")
    if private:
        score += 3.0
        reasons.append(f"contains private-use characters ({len(private)})")
    if unassigned:
        score += 2.0
        reasons.append(f"contains unassigned Unicode characters ({len(unassigned)})")
    if any(ch in ZERO_WIDTH for ch in name):
        score += 3.0
        reasons.append("contains zero-width characters")
    if any(ch in BIDI_CONTROLS for ch in name):
        score += 4.0
        reasons.append("contains bidirectional control characters")
    return score, reasons


def _mojibake_flags(name: str) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    for marker, label in MOJIBAKE_PATTERNS:
        if marker == "\ufffd":
            hit = "\ufffd" in name
        else:
            hit = marker in name
        if hit:
            score += 4.0
            reasons.append(label)
            break
    if MOJIBAKE_RE.search(name) and not reasons:
        score += 3.0
        reasons.append("mixed Latin-1/UTF-8 mojibake pattern")
    # Latin-1 supplement letters mixed with CJK/Cyrillic is unusual in a real
    # filename and common when a UTF-8 name was decoded as Latin-1.
    latin1 = sum(1 for ch in name if 0x00C0 <= ord(ch) <= 0x00FF and ch.isalpha())
    cjk = sum(1 for ch in name if "\u4e00" <= ch <= "\u9fff")
    cyrillic = sum(1 for ch in name if "\u0400" <= ch <= "\u04ff")
    if latin1 >= 2 and (cjk >= 2 or cyrillic >= 2):
        score += 3.0
        reasons.append("mixes Latin-1 letters with CJK/Cyrillic characters")
    return score, reasons


def _symbol_flags(name: str) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    visible = [ch for ch in name if not ch.isspace()]
    if not visible:
        return 5.0, ["name consists only of whitespace"]
    symbols = [ch for ch in visible if unicodedata.category(ch).startswith(("S", "P")) and ch not in "._-()[]{}"]
    symbol_ratio = len(symbols) / len(visible)
    if symbol_ratio >= 0.4 and len(visible) >= 6:
        score += 2.0
        reasons.append(f"symbol-heavy name ({symbol_ratio:.0%})")
    if name.count(" ") >= 4 and len(name) >= 16:
        score += 1.0
        reasons.append("many spaces in name")
    return score, reasons


def _extension_and_reserved_flags(name: str) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    lower = name.lower().rstrip(" .")
    if any(lower.endswith(ext) for ext in FILE_EXTENSIONS):
        score += 2.5
        reasons.append("directory name looks like an executable/script file")
    if lower in RESERVED_NAMES:
        score += 2.0
        reasons.append("reserved DOS device name")
    if lower.startswith(".") and len(name) <= 2:
        score += 1.0
        reasons.append("single-character dot directory")
    return score, reasons


def score_name(name: str) -> Dict[str, Any]:
    """Score a directory name for visible weirdness.

    The score is heuristic and intentionally returns its reasons.  Callers add
    context (root-level, temp, PlatformExperienceHelper, age) separately.
    """
    reasons: List[str] = []
    score = 0.0

    base_score, base_reasons = string_score(name)
    score += base_score
    reasons.extend(base_reasons)
    if PACKAGE_NAME_RE.search(name):
        # Microsoft Store package families and Mozilla-style GUID folders are
        # normal, despite looking random.
        score = max(0.0, score - 2.2)
        reasons.append("package-family style name (common on Windows)")
    if GUID_RE.match(name):
        score = max(0.0, score - 2.0)
        reasons.append("GUID-style name (common for installers/caches)")
    if name.casefold().startswith(DEVELOPER_TEMP_PREFIXES):
        score = max(0.0, score - 1.8)
        reasons.append("developer/test-tool temporary directory (common)")

    for part_score, part_reasons in (
        _category_flags(name),
        _mojibake_flags(name),
        _symbol_flags(name),
        _extension_and_reserved_flags(name),
    ):
        score += part_score
        reasons.extend(part_reasons)

    normalized = unicodedata.normalize("NFC", name)
    if normalized != name:
        score += 0.5
        reasons.append("name is not NFC-normalised")

    if len(name) >= 10:
        entropy = shannon_entropy(name)
        if entropy >= 3.8:
            score += 0.5
            reasons.append(f"high name entropy ({entropy:.2f})")

    return {
        "score": round(score, 2),
        "reasons": list(dict.fromkeys(reasons)),
    }


def _severity_for_score(score: float) -> str:
    if score >= 7.0:
        return "critical"
    if score >= 5.0:
        return "high"
    if score >= 3.5:
        return "medium"
    if score >= 2.0:
        return "low"
    return "info"


def _is_skipped(path: str, name: str, include_caches: bool, full: bool) -> bool:
    lower = name.casefold()
    if lower in CACHE_CONTAINERS and not include_caches:
        return True
    if lower in {"node_modules", ".git", "__pycache__", ".svn", ".hg"}:
        return True
    path_key = canonical_key(path)
    for fragment in SKIP_SUBTREES:
        if fragment in path_key:
            return True
    if r"\windows\winsxs" in path_key or r"\windows\driverstore" in path_key:
        return True
    return False


def _is_empty_dir(path: str) -> bool:
    try:
        with os.scandir(path) as iterator:
            return next(iterator, None) is None
    except OSError:
        return False


def scan_weird_dirs(
    roots: Iterable[str],
    max_depth: Optional[int] = 4,
    max_seconds: int = 180,
    include_files: bool = False,
    include_caches: bool = False,
    full: bool = False,
    max_candidates: int = 400,
    dir_log_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Walk roots and return unusual names plus scan statistics.

    The walk never follows reparse points.  If dir_log_path is supplied, every
    directory record examined by the walk (scanned, candidate, skipped, queued
    or error) is appended to that JSONL file.  A time budget keeps a full C:
    sweep bounded; if it expires the result is marked truncated instead of
    silently pretending to be complete.
    """
    started = time.monotonic()
    deadline = started + max(5, max_seconds)
    candidates: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    roots = [os.path.abspath(root) for root in roots if root and os.path.isdir(root)]
    scanned_dirs = 0
    scanned_files = 0
    skipped_reparse = 0
    skipped_names = 0
    truncated = False
    root_set = {canonical_key(root) for root in roots}
    candidate_by_key: Dict[str, Dict[str, Any]] = {}
    dir_log_records = 0
    dir_log_error = ""
    dir_log_handle = None
    if dir_log_path:
        dir_log_path = os.path.abspath(dir_log_path)
        try:
            parent = os.path.dirname(dir_log_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            dir_log_handle = open(dir_log_path, "a", encoding="utf-8", buffering=1)
        except OSError as exc:
            dir_log_error = str(exc)
            dir_log_handle = None

    def emit_dir(record: Dict[str, Any]) -> None:
        nonlocal dir_log_records, dir_log_error
        if dir_log_handle is None:
            return
        try:
            dir_log_handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            dir_log_records += 1
        except (OSError, UnicodeError) as exc:
            dir_log_error = str(exc)

    stack: List[Tuple[str, int]] = []
    for root in roots:
        stack = [(root, 0)]
        while stack:
            if time.monotonic() > deadline:
                truncated = True
                break
            current, depth = stack.pop()
            if max_depth is not None and depth >= max_depth:
                continue
            try:
                with os.scandir(current) as iterator:
                    entries = list(iterator)
            except OSError as exc:
                errors.append({"path": current, "error": str(exc)})
                emit_dir({
                    "type": "dir", "path": current, "name": os.path.basename(current),
                    "parent": os.path.dirname(current), "depth": depth,
                    "status": "error", "score": 0, "severity": "info",
                    "reasons": ["directory could not be listed"], "error": str(exc),
                })
                continue

            candidate_record = candidate_by_key.get(canonical_key(current))
            try:
                current_mtime = utc_iso_from_timestamp(os.stat(current, follow_symlinks=False).st_mtime)
            except OSError:
                current_mtime = ""
            emit_dir({
                "type": "dir", "path": current, "name": os.path.basename(current) or current,
                "parent": os.path.dirname(current), "depth": depth,
                "status": "candidate" if candidate_record else "scanned",
                "score": candidate_record.get("score", 0) if candidate_record else 0,
                "severity": _severity_for_score(float(candidate_record.get("score", 0))) if candidate_record else "info",
                "reasons": candidate_record.get("reasons", []) if candidate_record else [],
                "mtime": (candidate_record.get("mtime", "") if candidate_record else current_mtime),
                "is_empty": candidate_record.get("is_empty", False) if candidate_record else False,
            })

            for entry in entries:
                if time.monotonic() > deadline:
                    truncated = True
                    break
                name = entry.name
                path = entry.path
                st = None
                try:
                    st = entry.stat(follow_symlinks=False)
                    attrs = st.st_file_attributes
                    entry_mtime = utc_iso_from_timestamp(st.st_mtime)
                except OSError:
                    attrs = 0
                    entry_mtime = ""
                reparse = bool(attrs & 0x400)
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    is_dir = False
                if not is_dir and reparse:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=True)
                    except OSError:
                        is_dir = False

                if not is_dir:
                    if include_files:
                        scanned_files += 1
                        info = score_name(name)
                        context = 0.0
                        reasons = list(info["reasons"])
                        if reparse:
                            context += 1.0
                            reasons.append("reparse-point file")
                        if info["score"] + context >= 3.0:
                            candidates.append(_candidate(path, name, current, depth, info["score"] + context, reasons, attrs, reparse, False))
                    continue

                scanned_dirs += 1
                if reparse and name.casefold() in KNOWN_COMPAT_JUNCTIONS:
                    skipped_names += 1
                    emit_dir({
                        "type": "dir", "path": path, "name": name, "parent": current,
                        "depth": depth + 1, "status": "skipped_compat",
                        "score": 0, "severity": "info",
                        "reasons": ["known Windows compatibility junction"],
                        "mtime": entry_mtime, "is_reparse": True,
                    })
                    continue
                if _is_skipped(path, name, include_caches, full):
                    skipped_names += 1
                    emit_dir({
                        "type": "dir", "path": path, "name": name, "parent": current,
                        "depth": depth + 1, "status": "skipped_cache",
                        "score": 0, "severity": "info",
                        "reasons": ["cache/system path excluded by the selected profile"],
                        "mtime": entry_mtime, "is_reparse": reparse,
                    })
                    continue

                info = score_name(name)
                score = float(info["score"])
                reasons = list(info["reasons"])
                parent_name = os.path.basename(current)
                parent_lower = parent_name.casefold()

                # Context: unknown top-level folders are worth listing even
                # when the name itself is normal.
                is_root_child = bool(re.fullmatch(r"[A-Za-z]:\\?", current)) and depth == 0
                if is_root_child and name.casefold() not in ROOT_CONTAINERS:
                    score = max(score, 2.0)
                    reasons.append("unrecognised top-level directory")

                if name.casefold() in {"platformexperiencehelper", "tbs_cache"}:
                    score = max(score, 3.0)
                    reasons.append("name is associated with the K2F persistence location")

                if re.fullmatch(r"[0-9a-fA-F]{64}", name) and parent_lower == "platformexperiencehelper":
                    score = max(score, 8.0)
                    reasons.append("64-hex folder directly under PlatformExperienceHelper")

                if re.search(r"(?i)(k2f|insightjs|insight\.bundle|platform_experience_helper)", name):
                    score = max(score, 7.0)
                    reasons.append("name contains a known K2F/insight indicator")

                if reparse:
                    score += 1.0
                    reasons.append("directory is a reparse point/junction (not traversed)")

                if is_hidden_or_system(path):
                    score += 0.5
                    reasons.append("hidden/system attribute")

                high_risk_path = "\\" + canonical_key(path).strip("\\") + "\\"
                if any(fragment in high_risk_path for fragment in ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\")):
                    score += 0.3
                    reasons.append("inside a user-writable location")

                empty = _is_empty_dir(path)
                if empty and score >= 2.5:
                    score += 0.7
                    reasons.append("empty directory")

                if st is not None:
                    age_days = max(0.0, (time.time() - st.st_mtime) / 86400.0)
                else:
                    age_days = 9999.0
                if empty and score >= 2.5 and age_days <= 30:
                    score += 0.5
                    reasons.append("recently created/modified empty directory")

                if score >= 2.0:
                    record = _candidate(path, name, current, depth, score, reasons, attrs, reparse, empty)
                    candidates.append(record)
                    candidate_by_key[canonical_key(path)] = record

                if reparse:
                    skipped_reparse += 1
                    emit_dir({
                        "type": "dir", "path": path, "name": name, "parent": current,
                        "depth": depth + 1, "status": "skipped_reparse",
                        "score": round(score, 2), "severity": _severity_for_score(score),
                        "reasons": list(dict.fromkeys(reasons)), "mtime": entry_mtime,
                        "is_reparse": True, "is_empty": empty,
                    })
                else:
                    if max_depth is None or depth + 1 < max_depth:
                        stack.append((path, depth + 1))
                    else:
                        emit_dir({
                            "type": "dir", "path": path, "name": name, "parent": current,
                            "depth": depth + 1, "status": "skipped_depth",
                            "score": round(score, 2), "severity": _severity_for_score(score),
                            "reasons": list(dict.fromkeys(reasons)), "mtime": entry_mtime,
                            "is_reparse": False, "is_empty": empty,
                        })

            if truncated:
                break
        if truncated:
            break

    # Any directories still queued when the time budget expired were
    # discovered but not listed.  Record them as such rather than silently
    # dropping them from the complete inventory.
    if stack:
        for queued_path, queued_depth in stack:
            emit_dir({
                "type": "dir", "path": queued_path, "name": os.path.basename(queued_path),
                "parent": os.path.dirname(queued_path), "depth": queued_depth,
                "status": "queued_time", "score": 0, "severity": "info",
                "reasons": ["time budget expired before this directory was listed"],
            })

    deduped: Dict[str, Dict[str, Any]] = {}
    for item in candidates:
        key = canonical_key(item["path"])
        if key not in deduped or item["score"] > deduped[key]["score"]:
            deduped[key] = item
    ordered = sorted(
        deduped.values(),
        key=lambda item: (item["score"], item.get("mtime", "")),
        reverse=True,
    )
    total = len(ordered)
    if len(ordered) > max_candidates:
        ordered = ordered[:max_candidates]

    for item in ordered:
        item["severity"] = _severity_for_score(float(item["score"]))

    if dir_log_handle is not None:
        try:
            dir_log_handle.flush()
            dir_log_handle.close()
        except OSError:
            pass

    return {
        "roots": roots,
        "candidates": ordered,
        "total_candidates": total,
        "returned_candidates": len(ordered),
        "dir_log": dir_log_path or "",
        "dir_log_records": dir_log_records,
        "dir_log_error": dir_log_error,
        "stats": {
            "scanned_dirs": scanned_dirs,
            "scanned_files": scanned_files,
            "skipped_names": skipped_names,
            "skipped_reparse": skipped_reparse,
            "errors": len(errors),
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "truncated": truncated,
            "max_depth": max_depth,
            "profile": "full" if full else "quick",
            "dir_log_records": dir_log_records,
            "dir_log_error": dir_log_error,
        },
        "errors": errors[:100],
    }


def _candidate(path: str, name: str, parent: str, depth: int, score: float, reasons: List[str], attrs: int, reparse: bool, empty: bool) -> Dict[str, Any]:
    try:
        st = os.stat(path, follow_symlinks=False)
        mtime = utc_iso_from_timestamp(st.st_mtime)
        size = st.st_size
    except OSError:
        mtime = ""
        size = 0
    return {
        "path": path,
        "name": name,
        "parent": parent,
        "depth": depth,
        "score": round(score, 2),
        "severity": "info",
        "reasons": list(dict.fromkeys(reasons)),
        "mtime": mtime,
        "size": size,
        "attributes": attrs,
        "is_reparse": reparse,
        "is_empty": empty,
    }
