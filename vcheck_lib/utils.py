from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
FILE_ATTRIBUTE_HIDDEN = getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 0x2)
FILE_ATTRIBUTE_SYSTEM = getattr(stat, "FILE_ATTRIBUTE_SYSTEM", 0x4)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def utc_iso_from_timestamp(value: Optional[float]) -> str:
    if not value:
        return ""
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="seconds")
    except (OSError, ValueError, OverflowError):
        return ""


def human_size(value: Optional[int]) -> str:
    if value is None:
        return ""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{value} B"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def expand_path(value: str) -> str:
    value = (value or "").strip().strip('"').strip("'")
    if not value:
        return ""
    value = os.path.expandvars(value)
    value = os.path.expanduser(value)
    if value.startswith("\\\\?\\"):
        value = value[4:]
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return value


def normalize_path(value: str) -> str:
    value = expand_path(value)
    if not value:
        return ""
    value = value.replace("/", "\\")
    # Do not resolve symlinks: the link itself can be evidence.
    try:
        value = os.path.abspath(value)
    except (OSError, ValueError):
        return value
    return os.path.normpath(value)


def canonical_key(value: str) -> str:
    value = normalize_path(value)
    return os.path.normcase(value) if value else ""


def is_subpath(child: str, parent: str) -> bool:
    child_key = canonical_key(child)
    parent_key = canonical_key(parent)
    if not child_key or not parent_key:
        return False
    try:
        return os.path.commonpath([child_key, parent_key]) == parent_key
    except ValueError:
        return False


def path_attributes(path: str) -> int:
    try:
        return int(os.lstat(path).st_file_attributes)
    except (OSError, AttributeError):
        return 0


def is_reparse_point(path: str) -> bool:
    return bool(path_attributes(path) & FILE_ATTRIBUTE_REPARSE_POINT)


def is_hidden_or_system(path: str) -> bool:
    attrs = path_attributes(path)
    return bool(attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))


def sha256_file(path: str, max_bytes: Optional[int] = None, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    remaining = max_bytes
    with open(path, "rb") as handle:
        while True:
            if remaining is not None:
                if remaining <= 0:
                    break
                block = handle.read(min(chunk_size, remaining))
            else:
                block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
    return digest.hexdigest()


def file_meta(path: str, include_hash: bool = False, hash_limit: Optional[int] = 300 * 1024 * 1024) -> Dict[str, Any]:
    try:
        st = os.stat(path)
    except OSError as exc:
        return {"path": path, "exists": False, "error": str(exc)}
    meta: Dict[str, Any] = {
        "path": path,
        "exists": True,
        "size": st.st_size,
        "size_human": human_size(st.st_size),
        "mtime": utc_iso_from_timestamp(st.st_mtime),
        "ctime": utc_iso_from_timestamp(st.st_ctime),
        "attributes": int(getattr(st, "st_file_attributes", 0)),
        "is_reparse": is_reparse_point(path),
    }
    if include_hash and st.st_size <= (hash_limit or 0):
        try:
            meta["sha256"] = sha256_file(path)
        except OSError as exc:
            meta["hash_error"] = str(exc)
    return meta


def atomic_write_text(path: str, text: str, encoding: str = "utf-8") -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".vcheck-", suffix=".tmp", dir=parent or None)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass


def atomic_write_json(path: str, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n")


def load_json(path: str, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return default


def read_text_safe(path: str, max_bytes: int = 8 * 1024 * 1024) -> str:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raw = raw[:max_bytes]
        for encoding in ("utf-8-sig", "utf-16", "gb18030", "latin-1"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return ""


def find_bytes_in_file(path: str, needles: Iterable[bytes], max_bytes: int = 64 * 1024 * 1024) -> List[str]:
    """Return the ASCII needles found in a bounded binary file."""
    wanted = [(needle, needle.decode("ascii", "replace")) for needle in needles if needle]
    if not wanted:
        return []
    found: List[str] = []
    overlap = max(len(n) for n, _ in wanted) - 1
    try:
        with open(path, "rb") as handle:
            remaining = max_bytes
            tail = b""
            while remaining > 0:
                block = handle.read(min(1024 * 1024, remaining))
                if not block:
                    break
                data = tail + block
                for needle, label in wanted:
                    if needle in data and label not in found:
                        found.append(label)
                tail = data[-overlap:] if overlap > 0 else b""
                remaining -= len(block)
    except OSError:
        return found
    return found


def string_score(value: str) -> Tuple[float, List[str]]:
    """Generic randomness score for a single path segment or file name."""
    name = value or ""
    if not name:
        return 0.0, []
    reasons: List[str] = []
    score = 0.0
    if name in (".", ".."):
        return 0.0, []
    stripped = name.strip()
    if stripped != name:
        score += 2.0
        reasons.append("name has leading/trailing whitespace")
    if name.endswith("."):
        score += 2.0
        reasons.append("name ends with a dot")
    if len(name) > 120:
        score += 1.0
        reasons.append("very long name")
    if re.fullmatch(r"[0-9a-fA-F]{64}", name):
        score += 1.8
        reasons.append("64-character hexadecimal name")
    elif re.fullmatch(r"[0-9a-fA-F]{40}", name):
        score += 1.6
        reasons.append("40-character hexadecimal name")
    elif re.fullmatch(r"[0-9a-fA-F]{32}", name):
        score += 1.4
        reasons.append("32-character hexadecimal name")
    elif re.fullmatch(r"[0-9a-fA-F]{16}", name):
        score += 1.0
        reasons.append("16-character hexadecimal name")
    hex_name = bool(re.fullmatch(r"[0-9a-fA-F]{16,64}", name)) and len(name) in (16, 32, 40, 64)
    if len(name) >= 8:
        entropy = shannon_entropy(name)
        letters = [c for c in name if c.isalpha()]
        vowels = sum(1 for c in letters if c.lower() in "aeiou")
        vowel_ratio = (vowels / len(letters)) if letters else 1.0
        if not hex_name and entropy >= 3.4 and len(letters) >= 6 and vowel_ratio <= 0.22:
            score += 2.0
            reasons.append(f"random-looking name (entropy {entropy:.2f}, vowel ratio {vowel_ratio:.2f})")
        if not hex_name and re.fullmatch(r"[A-Za-z0-9_-]{12,}", name) and re.search(r"[A-Za-z]", name) and re.search(r"\d", name):
            score += 0.8
            reasons.append("long mixed letter/digit token")
    if re.search(r"(.)\1{5,}", name):
        score += 1.0
        reasons.append("long repeated-character run")
    if re.fullmatch(r"\d{6,}", name):
        score += 0.5
        reasons.append("long numeric name")
    return score, reasons


# Windows path fragments that suggest a user-writable location.  Keep this
# separate from "is this malicious": a portable app in Downloads is normal.
USER_WRITABLE_HINTS = (
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\documents\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
)


def is_user_writable(path: str) -> bool:
    value = "\\" + canonical_key(path).strip("\\") + "\\"
    if any(hint in value for hint in USER_WRITABLE_HINTS):
        return True
    for env_name in ("TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "PUBLIC"):
        base = os.environ.get(env_name)
        if base and is_subpath(path, base):
            return True
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        for sub in ("Downloads", "Desktop", "Documents", "AppData", "Public"):
            if is_subpath(path, os.path.join(user_profile, sub)):
                return True
    return False


def is_windows_path(path: str) -> bool:
    return is_subpath(path, os.environ.get("SystemRoot", r"C:\Windows"))


def is_program_files_path(path: str) -> bool:
    for env_name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(env_name)
        if base and is_subpath(path, base):
            return True
    return False


SYSTEM_BINARY_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "explorer.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe",
    "dllhost.exe", "conhost.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
}


def looks_like_system_binary_masquerade(path: str) -> bool:
    normalized = normalize_path(path)
    name = os.path.basename(normalized).lower()
    if name not in SYSTEM_BINARY_NAMES:
        return False
    windows_root = os.environ.get("SystemRoot", r"C:\Windows")
    system32 = os.path.join(windows_root, "System32")
    syswow64 = os.path.join(windows_root, "SysWOW64")
    # explorer.exe legitimately lives in the Windows root; the other system
    # binaries belong in System32/SysWOW64.
    if name == "explorer.exe" and canonical_key(os.path.dirname(normalized)) == canonical_key(windows_root):
        return False
    return not (is_subpath(normalized, system32) or is_subpath(normalized, syswow64))


def _strip_outer_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


_EXE_EXTENSIONS = r"(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|msi|scr|sys|dll)"


def extract_executable(command_line: str) -> Tuple[str, str]:
    """Best-effort extraction of the program path from a Windows command line.

    This is intentionally conservative.  It is used for inventory and
    signature checks, never to launch anything.
    """
    raw = (command_line or "").strip()
    if not raw:
        return "", ""
    raw = _strip_outer_quotes(raw)
    if raw.startswith('"'):
        end = raw.find('"', 1)
        if end > 1:
            return expand_path(raw[1:end]), raw[end + 1:].strip()
    # A quoted path after common launchers, e.g. cmd.exe /c "C:\x y\a.exe" ...
    for match in re.finditer(r'"([^"]+)"', raw):
        candidate = match.group(1)
        if re.search(r"\." + _EXE_EXTENSIONS + r"$", candidate, re.I):
            return expand_path(candidate), raw[:match.start()] + " " + raw[match.end():]
    # Unquoted path with an executable extension.
    match = re.match(r"^(.+?\." + _EXE_EXTENSIONS + r")(?=\s|$)", raw, re.I)
    if match:
        candidate = match.group(1)
        # Avoid treating a sentence-like string as a path.
        if "\\" in candidate or "/" in candidate or ":" in candidate:
            return expand_path(candidate), raw[match.end():].strip()
    # First token fallback.
    parts = re.split(r"\s+", raw, maxsplit=1)
    candidate = _strip_outer_quotes(parts[0])
    candidate = expand_path(candidate)
    args = parts[1].strip() if len(parts) > 1 else ""
    return candidate, args


COMMANDLINE_PATTERNS = (
    (r"(?i)-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "PowerShell encoded command"),
    (r"(?i)frombase64string", "Base64 decoding in command line"),
    (r"(?i)(?:powershell|pwsh)(?:\.exe)?[^\r\n]{0,120}(?:-w(?:indowstyle)?\s+hidden|-nop|-noni|-ep\s+bypass|-exec(?:utionpolicy)?\s+bypass)", "hidden/bypassed PowerShell execution"),
    (r"(?i)(?:mshta|wscript|cscript|regsvr32|rundll32)(?:\.exe)?[^\r\n]{0,160}(?:https?://|\\\\)", "script host reaching a URL/UNC path"),
    (r"(?i)(?:certutil|bitsadmin)(?:\.exe)?[^\r\n]{0,160}(?:-urlcache|-decode|/transfer|/addfile)", "certutil/bitsadmin download or decode"),
    (r"(?i)(?:curl|wget)(?:\.exe)?[^\r\n]{0,160}\|\s*(?:powershell|pwsh|cmd|sh)", "download piped into a shell"),
    (r"(?i)(?:invoke-webrequest|iwr|invoke-expression|iex)\b", "PowerShell download/execute expression"),
    (r"(?i)(?:wmic|schtasks)(?:\.exe)?[^\r\n]{0,120}(?:create|/create)", "remote/scheduled task creation"),
    (r"(?i)(?:-windowstyle\s+hidden|/hidden)\b", "hidden window flag"),
    (r"(?i)(?:vssadmin|bcdedit|wbadmin)(?:\.exe)?[^\r\n]{0,100}(?:delete|disable)", "destructive recovery command"),
    (r"(?i)\b(?:net\s+user|net\s+localgroup)\b[^\r\n]{0,80}(?:/add|administrators)", "account/group modification"),
)


def commandline_flags(command_line: str) -> List[str]:
    text = command_line or ""
    flags: List[str] = []
    for pattern, label in COMMANDLINE_PATTERNS:
        if re.search(pattern, text) and label not in flags:
            flags.append(label)
    return flags


_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer|access[_-]?key|client[_-]?secret)\b(\s*[:=]\s*|\s+)([^\s\"']+)"
)


def redact_command_line(command_line: str) -> str:
    text = command_line or ""
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)


def safe_filename(value: str, max_length: int = 80) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "")
    return value[:max_length].strip("._") or "report"


def which_powershell() -> str:
    for name in ("powershell.exe", "pwsh.exe"):
        found = shutil.which(name)
        if found:
            return found
    fallback = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return fallback if os.path.exists(fallback) else ""


def run_process(args: List[str], timeout: int = 120, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def decode_console(data: bytes) -> str:
    if not data:
        return ""
    for encoding in ("utf-8", "gb18030", "mbcs", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def parse_windows_time(value: str) -> str:
    """Normalise CIM datetime strings to ISO-8601 when possible."""
    if not value:
        return ""
    match = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", str(value))
    if match:
        return f"{match.group(1)}-{match.group(2)}-{match.group(3)}T{match.group(4)}:{match.group(5)}:{match.group(6)}"
    return str(value)


def now_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        key = canonical_key(item)
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def get_file_version(path: str) -> Dict[str, Any]:
    """Read PE version info without external packages.

    The implementation is intentionally small; it falls back to an empty
    result on any parse error.
    """
    info: Dict[str, Any] = {}
    try:
        import ctypes
        from ctypes import wintypes

        size = ctypes.windll.version.GetFileVersionInfoSizeW(path, None)
        if not size:
            return info
        buffer = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(path, 0, size, buffer):
            return info
        pointer = ctypes.c_void_p()
        length = wintypes.UINT()
        if ctypes.windll.version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)):
            fixed = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 13)).contents
            # VS_FIXEDFILEINFO starts with signature and structure version.
            if fixed[0] == 0xFEEF04BD:
                info["file_version"] = f"{fixed[2] >> 16}.{fixed[2] & 0xFFFF}.{fixed[3] >> 16}.{fixed[3] & 0xFFFF}"
                info["product_version"] = f"{fixed[4] >> 16}.{fixed[4] & 0xFFFF}.{fixed[5] >> 16}.{fixed[5] & 0xFFFF}"
    except Exception:
        return info
    return info


def ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def dump_debug(label: str, value: Any) -> None:
    if os.environ.get("VCHECK_DEBUG"):
        print(f"[debug] {label}: {value!r}")
