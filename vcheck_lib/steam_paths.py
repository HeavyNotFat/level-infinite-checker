from __future__ import annotations

import ctypes
import glob
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import Finding, max_severity
from .utils import (
    canonical_key,
    expand_path,
    extract_executable,
    file_meta,
    is_reparse_point,
    is_subpath,
    is_user_writable,
    normalize_path,
    now_iso,
    read_text_safe,
    sha256_file,
    unique_preserve_order,
)
from .weird_dirs import score_name
from .winps import ps_json, powershell_available

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows
    winreg = None


STEAM_EXE_NAMES = ("steam.exe", "steam")
SHORTCUT_SCRIPT = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tools", "Resolve-Shortcuts.ps1")
STEAM_CORE_FILES = (
    "steam.exe",
    "steamclient.dll",
    "steamclient64.dll",
    "steamui.dll",
    "gameoverlayrenderer.dll",
    "gameoverlayrenderer64.dll",
    "tier0_s.dll",
    "tier0_s64.dll",
    "vstdlib_s.dll",
    "vstdlib_s64.dll",
    "crashhandler.dll",
    "crashhandler64.dll",
    "steamservice.exe",
    "bin\\steamservice.exe",
)

PATH_VALUE_NAMES = {
    "steampath", "steamexe", "installpath", "installlocation",
    "sourcemodinstallpath", "displayicon", "uninstallstring",
    "defaulticon", "icon", "command", "",
}

VOLATILE_VALUE_NAMES = {
    "steampid", "runningappid", "rate", "autologinuser",
    "autologinuser_steamchina", "lastgamenameused",
}

DRIVE_TYPES = {
    0: "unknown",
    1: "no-root",
    2: "removable",
    3: "fixed",
    4: "network",
    5: "cdrom",
    6: "ramdisk",
}


def _drive_type(path: str) -> str:
    try:
        root = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
        return DRIVE_TYPES.get(int(ctypes.windll.kernel32.GetDriveTypeW(root)), "unknown")
    except Exception:
        return "unknown"


def get_drives() -> List[str]:
    drives: List[str] = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for index in range(26):
            if mask & (1 << index):
                drives.append(f"{chr(65 + index)}:\\")
    except Exception:
        if os.name == "nt":
            drives = [f"{chr(65 + i)}:\\" for i in range(26) if os.path.exists(f"{chr(65 + i)}:\\")]
        else:
            drives = ["/"]
    return drives


def _reg_view_name(view: int) -> str:
    if view == getattr(winreg, "KEY_WOW64_32KEY", 0):
        return "32"
    if view == getattr(winreg, "KEY_WOW64_64KEY", 0):
        return "64"
    return "default"


def _open_key(hive, path: str, view: int):
    if winreg is None:
        return None
    access = winreg.KEY_READ | view
    try:
        return winreg.OpenKey(hive, path, 0, access)
    except OSError:
        return None


def _read_values(key) -> List[Dict[str, Any]]:
    values: List[Dict[str, Any]] = []
    if key is None:
        return values
    index = 0
    while True:
        try:
            name, value, value_type = winreg.EnumValue(key, index)
        except OSError:
            break
        values.append({"name": name, "value": value, "type": value_type})
        index += 1
    return values


def _read_default(key) -> str:
    if key is None:
        return ""
    try:
        value, _ = winreg.QueryValueEx(key, "")
        return str(value)
    except OSError:
        return ""


def _string_value(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-16-le", errors="replace").rstrip("\x00")
    return str(value)


def _command_to_path(value: str) -> str:
    value = _string_value(value).strip()
    if not value:
        return ""
    # DisplayIcon often looks like C:\Steam\steam.exe,0
    if re.match(r"^[A-Za-z]:[\\/].*,\s*-?\d+$", value):
        value = re.sub(r",\s*-?\d+$", "", value)
    exe, _ = extract_executable(value)
    if exe and os.path.splitext(exe)[1].lower() in (".exe", ".com", ".dll", ".sys"):
        return exe
    return value


def _maybe_dir(path: str) -> str:
    path = _command_to_path(path)
    path = normalize_path(path)
    if not path:
        return ""
    if os.path.isfile(path):
        return os.path.dirname(path)
    return path


def _reg_value_record(hive_label: str, key_path: str, view_label: str, name: str, value: Any, value_type: Any) -> Dict[str, Any]:
    return {
        "hive": hive_label,
        "key": key_path,
        "name": name or "(default)",
        "value": _string_value(value),
        "type": int(value_type) if isinstance(value_type, int) else str(value_type),
        "view": view_label,
    }


def collect_registry() -> Dict[str, Any]:
    values: List[Dict[str, Any]] = []
    uninstall: List[Dict[str, Any]] = []
    errors: List[str] = []
    if winreg is None:
        return {"values": values, "uninstall": uninstall, "errors": ["winreg unavailable (not Windows)"]}

    locations = [
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", 0),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", getattr(winreg, "KEY_WOW64_32KEY", 0)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Classes\steam\Shell\Open\Command", 0),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\steam\Shell\Open\Command", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\steam\Shell\Open\Command", getattr(winreg, "KEY_WOW64_32KEY", 0)),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\App Paths\steam.exe", 0),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\steam.exe", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\steam.exe", getattr(winreg, "KEY_WOW64_32KEY", 0)),
    ]
    seen_locations = set()
    for hive_label, hive, key_path, view in locations:
        loc_key = (hive_label, key_path.casefold(), view)
        if loc_key in seen_locations:
            continue
        seen_locations.add(loc_key)
        key = _open_key(hive, key_path, view)
        if key is None:
            continue
        try:
            view_label = _reg_view_name(view) if winreg else "?"
            default_value = _read_default(key)
            if default_value:
                values.append(_reg_value_record(hive_label, key_path, view_label, "(default)", default_value, winreg.REG_SZ))
            for item in _read_values(key):
                if item["name"] in ("",):
                    continue
                values.append(_reg_value_record(hive_label, key_path, view_label, item["name"], item["value"], item["type"]))
        finally:
            try:
                winreg.CloseKey(key)
            except OSError:
                pass

    uninstall_roots = [
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", getattr(winreg, "KEY_WOW64_32KEY", 0)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0),
    ]
    for hive_label, hive, key_path, view in uninstall_roots:
        parent = _open_key(hive, key_path, view)
        if parent is None:
            continue
        try:
            index = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(parent, index)
                except OSError:
                    break
                index += 1
                sub_path = key_path + "\\" + sub_name
                sub_key = _open_key(hive, sub_path, view)
                if sub_key is None:
                    continue
                try:
                    record = {"hive": hive_label, "key": sub_path, "view": _reg_view_name(view), "values": {}}
                    for item in _read_values(sub_key):
                        record["values"][item["name"]] = _string_value(item["value"])
                    display = record["values"].get("DisplayName", "")
                    if "steam" in display.casefold() or "steam" in sub_name.casefold():
                        uninstall.append(record)
                finally:
                    try:
                        winreg.CloseKey(sub_key)
                    except OSError:
                        pass
        finally:
            try:
                winreg.CloseKey(parent)
            except OSError:
                pass

    return {"values": values, "uninstall": uninstall, "errors": errors}


# ----------------------------- VDF parsing -----------------------------

class VDFError(ValueError):
    pass


class _VDFParser:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.length = len(text)

    def _skip(self) -> None:
        while self.pos < self.length:
            char = self.text[self.pos]
            if char.isspace():
                self.pos += 1
                continue
            if char == "/" and self.pos + 1 < self.length and self.text[self.pos + 1] == "/":
                end = self.text.find("\n", self.pos)
                self.pos = self.length if end < 0 else end + 1
                continue
            break

    def _token(self) -> str:
        self._skip()
        if self.pos >= self.length:
            raise VDFError("unexpected end of file")
        char = self.text[self.pos]
        if char in "{}":
            self.pos += 1
            return char
        if char == '"':
            self.pos += 1
            out = []
            while self.pos < self.length:
                char = self.text[self.pos]
                self.pos += 1
                if char == '"':
                    return "".join(out)
                if char == "\\" and self.pos < self.length:
                    esc = self.text[self.pos]
                    self.pos += 1
                    out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}.get(esc, esc))
                else:
                    out.append(char)
            raise VDFError("unterminated quoted string")
        start = self.pos
        while self.pos < self.length and not self.text[self.pos].isspace() and self.text[self.pos] not in '{}"':
            self.pos += 1
        return self.text[start:self.pos]

    def parse(self) -> Dict[str, Any]:
        self._skip()
        if self.pos < self.length and self.text[self.pos] == "{":
            self.pos += 1
            return self._object_body()
        key = self._token()
        if not key or key in "{}":
            raise VDFError("expected root key")
        value = self._value()
        return {key: value}

    def _object_body(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        while True:
            self._skip()
            if self.pos >= self.length:
                raise VDFError("unterminated object")
            if self.text[self.pos] == "}":
                self.pos += 1
                return result
            key = self._token()
            if not key or key in "{}":
                raise VDFError("invalid object key")
            result[key] = self._value()

    def _value(self) -> Any:
        token = self._token()
        if token == "{":
            return self._object_body()
        if token == "}":
            raise VDFError("unexpected closing brace")
        return token


def parse_vdf(text: str) -> Dict[str, Any]:
    return _VDFParser(text).parse()


def _path_like(value: str) -> bool:
    if not isinstance(value, str):
        return False
    return bool(re.match(r"^(?:[A-Za-z]:[\\/]|\\\\|/)", value.strip()))


def extract_library_records(parsed: Dict[str, Any], source: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []

    def visit(node: Any, key_path: str = "") -> None:
        if isinstance(node, dict):
            path_value = node.get("path")
            if isinstance(path_value, str) and _path_like(path_value):
                apps = node.get("apps") if isinstance(node.get("apps"), dict) else {}
                records.append({
                    "path": normalize_path(path_value),
                    "label": str(node.get("label", "")),
                    "contentid": str(node.get("contentid", "")),
                    "apps_count": len(apps),
                    "source": source,
                })
            for key, value in node.items():
                if isinstance(value, str) and _path_like(value) and key.casefold() not in ("path", "label", "contentid"):
                    records.append({"path": normalize_path(value), "label": "", "contentid": "", "apps_count": 0, "source": source})
                else:
                    visit(value, key_path + "/" + str(key))
        elif isinstance(node, list):
            for value in node:
                visit(value, key_path)

    visit(parsed)
    # Older libraryfolders.vdf format: "1" "D:\\SteamLibrary"
    root = parsed.get("libraryfolders") if isinstance(parsed.get("libraryfolders"), dict) else parsed
    for key, value in root.items():
        if isinstance(value, str) and _path_like(value):
            records.append({"path": normalize_path(value), "label": "", "contentid": "", "apps_count": 0, "source": source})
    return records


def parse_libraryfolders(path: str) -> Dict[str, Any]:
    text = read_text_safe(path, max_bytes=16 * 1024 * 1024)
    if not text:
        return {"path": path, "libraries": [], "error": "empty or unreadable"}
    try:
        parsed = parse_vdf(text)
    except VDFError as exc:
        return {"path": path, "libraries": [], "error": str(exc)}
    records = extract_library_records(parsed, path)
    return {"path": path, "libraries": records, "error": ""}


# ----------------------------- discovery -----------------------------

def _known_candidates() -> List[Tuple[str, str]]:
    candidates: List[Tuple[str, str]] = []
    for env_name in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432", "LOCALAPPDATA"):
        base = os.environ.get(env_name)
        if base:
            candidates.append((os.path.join(base, "Steam"), f"env:{env_name}"))
    for drive in get_drives():
        candidates.extend([
            (os.path.join(drive, "Steam"), "drive-root"),
            (os.path.join(drive, "SteamLibrary"), "drive-root"),
            (os.path.join(drive, "Games", "Steam"), "drive-root"),
            (os.path.join(drive, "Games", "SteamLibrary"), "drive-root"),
            (os.path.join(drive, "Program Files", "Steam"), "drive-root"),
            (os.path.join(drive, "Program Files (x86)", "Steam"), "drive-root"),
        ])
    return candidates


def _validate_root(path: str) -> bool:
    """An install root must contain steam.exe; a library alone is not an install."""
    if not path or not os.path.isdir(path):
        return False
    return os.path.isfile(os.path.join(path, "steam.exe"))


def _find_library_vdfs(candidate_roots: Iterable[str], drives: Iterable[str]) -> List[str]:
    found: List[str] = []
    seen = set()
    roots = list(candidate_roots)
    for drive in drives:
        try:
            with os.scandir(drive) as iterator:
                top_dirs = [entry.path for entry in iterator if entry.is_dir(follow_symlinks=False)][:80]
        except OSError:
            top_dirs = []
        roots.extend(top_dirs)
    for root in roots:
        for vdf in (
            os.path.join(root, "steamapps", "libraryfolders.vdf"),
            os.path.join(root, "libraryfolders.vdf"),
        ):
            key = canonical_key(vdf)
            if key and key not in seen and os.path.isfile(vdf):
                seen.add(key)
                found.append(vdf)
    return found


def collect_steam_shortcuts() -> List[Dict[str, Any]]:
    if not powershell_available() or not os.path.isfile(SHORTCUT_SCRIPT):
        return []
    candidates: List[str] = []
    roots = [
        os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
        os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "Desktop"),
        os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows", "Start Menu", "Programs"),
    ]
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for pattern in ("*.lnk", "*.url"):
            for path in glob.glob(os.path.join(root, "**", pattern), recursive=True):
                if "steam" in (os.path.basename(path) + " " + path).casefold():
                    candidates.append(path)
                if len(candidates) >= 80:
                    break
            if len(candidates) >= 80:
                break
    candidates = unique_preserve_order(candidates)[:80]
    if not candidates:
        return []
    with tempfile.TemporaryDirectory(prefix="vcheck-shortcuts-") as temp_dir:
        paths_file = os.path.join(temp_dir, "paths.txt")
        with open(paths_file, "w", encoding="utf-8-sig") as handle:
            for path in candidates:
                handle.write(path + "\n")
        try:
            data = ps_json(SHORTCUT_SCRIPT, ["-PathsFile", paths_file], timeout=60)
        except Exception:
            return []
    if isinstance(data, dict):
        data = [data]
    return [item for item in (data or []) if isinstance(item, dict)]


def discover_steam(processes: Optional[List[Dict[str, Any]]] = None, shortcuts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    processes = processes or []
    shortcuts = shortcuts or []
    started = time.monotonic()
    reg = collect_registry()
    registry_values = reg["values"]
    errors: List[str] = list(reg["errors"])

    root_sources: List[Tuple[str, str]] = []
    for item in registry_values:
        name = item["name"].casefold()
        key = item["key"].casefold()
        raw = item["value"]
        if name in PATH_VALUE_NAMES or "steam" in key:
            path = _maybe_dir(raw)
            if path:
                root_sources.append((path, f"registry:{item['hive']}\\{item['key']}:{item['name']}"))
    for item in reg["uninstall"]:
        for field in ("InstallLocation", "UninstallString", "DisplayIcon"):
            raw = item["values"].get(field, "")
            if raw:
                path = _maybe_dir(raw)
                if path:
                    root_sources.append((path, "uninstall:" + field))

    steam_processes: List[Dict[str, Any]] = []
    for proc in processes:
        name = str(proc.get("name", "")).casefold()
        path = str(proc.get("path", "") or "")
        if name in ("steam.exe", "steam") or os.path.basename(path).casefold() == "steam.exe":
            record = {
                "pid": proc.get("pid"),
                "name": proc.get("name"),
                "path": normalize_path(path),
                "cmdline": proc.get("cmdline", ""),
                "parent_pid": proc.get("ppid"),
            }
            steam_processes.append(record)
            if path:
                root_sources.append((os.path.dirname(path), "process:" + str(proc.get("pid"))))

    for item in shortcuts:
        target = item.get("target") or item.get("url") or ""
        if target and "steam" in (str(item.get("name", "")) + " " + target).casefold():
            path = _maybe_dir(target)
            if path:
                root_sources.append((path, "shortcut:" + str(item.get("path", ""))))

    for path, source in _known_candidates():
        root_sources.append((path, source))

    # Deduplicate by path while preserving the first useful source.
    roots: List[Dict[str, Any]] = []
    seen_roots = set()
    for raw_path, source in root_sources:
        path = normalize_path(raw_path)
        if not path:
            continue
        key = canonical_key(path)
        if not key or key in seen_roots:
            continue
        seen_roots.add(key)
        if not _validate_root(path):
            continue
        roots.append({
            "path": path,
            "steam_exe": os.path.join(path, "steam.exe"),
            "exists": os.path.isdir(path),
            "source": source,
            "drive_type": _drive_type(path),
            "is_reparse": is_reparse_point(path),
        })

    # Add roots from every libraryfolders.vdf we can reach cheaply.
    vdfs = _find_library_vdfs([root["path"] for root in roots], get_drives())
    libraries: List[Dict[str, Any]] = []
    seen_libraries = set()
    for vdf in vdfs:
        parsed = parse_libraryfolders(vdf)
        if parsed.get("error"):
            errors.append(f"{vdf}: {parsed['error']}")
        for record in parsed.get("libraries", []):
            path = normalize_path(record["path"])
            key = canonical_key(path)
            if not key or key in seen_libraries:
                continue
            seen_libraries.add(key)
            record = dict(record)
            record["path"] = path
            record["exists"] = os.path.isdir(path)
            record["is_reparse"] = is_reparse_point(path) if record["exists"] else False
            record["drive_type"] = _drive_type(path)
            libraries.append(record)
            if _validate_root(path):
                root_key = canonical_key(path)
                if root_key not in seen_roots:
                    seen_roots.add(root_key)
                    roots.append({
                        "path": path,
                        "steam_exe": os.path.join(path, "steam.exe"),
                        "exists": True,
                        "source": "library:" + vdf,
                        "drive_type": record["drive_type"],
                        "is_reparse": record["is_reparse"],
                    })

    primary = _choose_primary(roots, registry_values, steam_processes)
    for root in roots:
        root["is_primary"] = canonical_key(root["path"]) == canonical_key(primary) if primary else False

    anomalies = _path_anomalies(roots, libraries, registry_values, steam_processes, primary)
    findings = [item.to_dict() for item in anomalies]
    verdict = max_severity([item.severity for item in anomalies])

    return {
        "generated_at": now_iso(),
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "primary_root": primary,
        "install_roots": roots,
        "libraries": libraries,
        "registry_values": registry_values,
        "uninstall_entries": reg["uninstall"],
        "processes": steam_processes,
        "shortcuts": shortcuts,
        "library_vdf_files": vdfs,
        "findings": findings,
        "verdict": verdict,
        "errors": errors,
    }


def _choose_primary(roots: List[Dict[str, Any]], registry_values: List[Dict[str, Any]], processes: List[Dict[str, Any]]) -> str:
    # Prefer a registry SteamPath/InstallPath that points at a real install.
    for preferred in ("steampath", "installpath", "steamexe"):
        for item in registry_values:
            if item["name"].casefold() == preferred:
                path = _maybe_dir(item["value"])
                if any(canonical_key(root["path"]) == canonical_key(path) and root["exists"] for root in roots):
                    return path
    for proc in processes:
        path = proc.get("path")
        if path and os.path.isfile(path):
            for root in roots:
                if canonical_key(root["path"]) == canonical_key(os.path.dirname(path)):
                    return root["path"]
    for root in roots:
        if root["exists"] and os.path.isfile(root["steam_exe"]):
            return root["path"]
    return roots[0]["path"] if roots else ""


def _path_anomalies(
    roots: List[Dict[str, Any]],
    libraries: List[Dict[str, Any]],
    registry_values: List[Dict[str, Any]],
    processes: List[Dict[str, Any]],
    primary: str,
) -> List[Finding]:
    findings: List[Finding] = []

    def add(title: str, severity: str, detail: str, path: str = "", evidence: Optional[Dict[str, Any]] = None, recommendation: str = "") -> None:
        findings.append(Finding(
            title=title,
            severity=severity,
            category="Steam path",
            detail=detail,
            path=path,
            source="steam_paths",
            evidence=evidence or {},
            recommendation=recommendation,
        ))

    # Registry path values that disagree with each other.
    reg_paths: Dict[str, List[str]] = {}
    for item in registry_values:
        name = item["name"].casefold()
        if name not in ("steampath", "installpath", "steamexe"):
            continue
        path = _maybe_dir(item["value"])
        if path:
            reg_paths.setdefault(name, []).append(path)
    unique_install = {canonical_key(path): path for values in reg_paths.values() for path in values if os.path.isdir(path)}
    if len(unique_install) > 1:
        add(
            "Steam 注册表中的安装路径不一致",
            "medium",
            "SteamPath / InstallPath / SteamExe 指向多个不同的现存目录。可能是多套安装，也可能是路径被改写。",
            evidence={"paths": list(unique_install.values()), "values": reg_paths},
            recommendation="核对每个路径下的 steam.exe 和时间戳；保留实际使用的那套，确认其余来源。",
        )

    for item in registry_values:
        name = item["name"].casefold()
        if name not in ("steampath", "installpath", "steamexe"):
            continue
        raw = item["value"]
        path = _maybe_dir(raw)
        if not path:
            continue
        if not os.path.exists(path):
            add(
                "Steam 注册表路径不存在",
                "low",
                "注册表值指向的路径当前不存在；移动硬盘/网络盘未连接时也会这样。",
                path=path,
                evidence={"registry": item},
                recommendation="确认该盘是否应连接；若不应存在，记录原值后再修正。",
            )
            continue
        for segment in re.split(r"[\\/]+", path):
            if not segment:
                continue
            scored = score_name(segment)
            if scored["score"] >= 4.0:
                add(
                    "Steam 路径包含异常名称片段",
                    "medium",
                    "路径片段看起来像乱码/随机字符串：" + "；".join(scored["reasons"]),
                    path=path,
                    evidence={"segment": segment, "score": scored["score"], "reasons": scored["reasons"], "registry": item},
                )
                break

        if is_user_writable(path) and not is_subpath(path, os.environ.get("LOCALAPPDATA", "")):
            add(
                "Steam 安装路径位于用户可写目录",
                "medium",
                "Steam 客户端通常安装在 Program Files 或独立游戏盘；位于 Temp/Downloads/AppData 等目录值得核对。",
                path=path,
                evidence={"registry": item, "drive_type": _drive_type(path)},
            )
        if _drive_type(path) in ("network", "removable"):
            add(
                "Steam 安装路径位于网络盘/可移动盘",
                "low",
                "这可能是正常的外置库，也可能让路径随盘符变化而波动。",
                path=path,
                evidence={"drive_type": _drive_type(path)},
            )
        if is_reparse_point(path):
            add(
                "Steam 安装路径是重解析点/链接",
                "medium",
                "目录本身是 junction/symlink，实际内容可能在别处；需要确认链接目标。",
                path=path,
                evidence={"registry": item},
            )

    # Multiple install roots and multiple steam.exe hashes.
    exe_paths = []
    for root in roots:
        exe = root["steam_exe"]
        if os.path.isfile(exe):
            exe_paths.append(exe)
    if len(exe_paths) > 1:
        hashes: Dict[str, List[str]] = {}
        for exe in exe_paths:
            try:
                digest = sha256_file(exe)
            except OSError:
                continue
            hashes.setdefault(digest, []).append(exe)
        if len(hashes) > 1:
            add(
                "发现多个内容不同的 steam.exe",
                "high",
                "多个 Steam 安装根下的 steam.exe 哈希不同。多套安装可能版本不同，但也可能是被替换的客户端。",
                path="; ".join(exe_paths),
                evidence={"sha256": {digest: paths for digest, paths in hashes.items()}},
                recommendation="分别检查每个文件的 Authenticode 签名和版本；以实际启动的那套为准。",
            )

    # Running Steam outside all discovered roots.
    if processes and roots:
        root_keys = [canonical_key(root["path"]) for root in roots]
        for proc in processes:
            path = proc.get("path") or ""
            if path and os.path.isfile(path):
                if not any(is_subpath(path, root) for root in root_keys):
                    add(
                        "运行中的 Steam 不在已发现的安装目录内",
                        "high",
                        "进程路径与注册表/库配置不一致，可能是便携版、被移动的客户端，或伪装进程。",
                        path=path,
                        evidence={"process": proc, "known_roots": [root["path"] for root in roots]},
                    )

    # Library anomalies.
    seen_lib_paths = set()
    for lib in libraries:
        path = lib["path"]
        key = canonical_key(path)
        if key in seen_lib_paths:
            add(
                "Steam 库路径重复",
                "low",
                "libraryfolders.vdf 中同一路径出现多次，通常无害，但会造成范围统计波动。",
                path=path,
                evidence={"library": lib},
            )
        seen_lib_paths.add(key)
        if not lib["exists"]:
            add(
                "Steam 库路径不存在",
                "low",
                "库目录当前不可访问；外置盘未连接时常见。",
                path=path,
                evidence={"library": lib},
                recommendation="确认对应磁盘；若路径被篡改，先备份 libraryfolders.vdf 再修正。",
            )
            continue
        if _drive_type(path) in ("network", "removable"):
            add(
                "Steam 库位于网络盘/可移动盘",
                "low",
                "盘符变化会导致 Steam 路径范围波动。",
                path=path,
                evidence={"library": lib, "drive_type": _drive_type(path)},
            )
        if is_user_writable(path):
            add(
                "Steam 库位于用户可写目录",
                "low",
                "库本身可以放在用户目录；此处仅记录，结合其他异常判断。",
                path=path,
                evidence={"library": lib},
            )
        for segment in re.split(r"[\\/]+", path):
            if not segment:
                continue
            scored = score_name(segment)
            if scored["score"] >= 4.0:
                add(
                    "Steam 库路径包含异常名称片段",
                    "medium",
                    "库路径片段看起来像乱码/随机字符串：" + "；".join(scored["reasons"]),
                    path=path,
                    evidence={"segment": segment, "score": scored["score"], "reasons": scored["reasons"], "library": lib},
                )
                break

    # Protocol handler mismatch.
    for item in registry_values:
        if "shell\\open\\command" in item["key"].casefold() and item["name"] == "(default)":
            command = _command_to_path(item["value"])
            if command and not os.path.exists(command):
                add(
                    "steam:// 协议处理程序指向不存在的文件",
                    "medium",
                    "协议处理程序被改写或 Steam 已被移动。",
                    path=command,
                    evidence={"registry": item},
                    recommendation="将默认值恢复为实际 steam.exe 的路径，或让 Steam 重新注册协议。",
                )

    # SourceMod path should normally be under a Steam library.
    for item in registry_values:
        if item["name"].casefold() == "sourcemodinstallpath":
            path = _maybe_dir(item["value"])
            if path and not any(is_subpath(path, lib["path"]) for lib in libraries):
                add(
                    "SourceMod 路径不在任何 Steam 库内",
                    "low",
                    "可能只是自定义安装位置；与路径波动一起出现时值得核对。",
                    path=path,
                    evidence={"registry": item},
                )

    return findings


# ----------------------------- snapshots / drift -----------------------------

SNAPSHOT_VERSION = 1


def build_snapshot(steam: Dict[str, Any], key_hashes: Optional[Dict[str, str]] = None, client_version: str = "") -> Dict[str, Any]:
    roots = []
    for root in steam.get("install_roots", []):
        roots.append({
            "path": canonical_key(root["path"]),
            "display_path": root["path"],
            "steam_exe": canonical_key(root.get("steam_exe", "")),
            "exists": bool(root.get("exists")),
            "source": root.get("source", ""),
        })
    libraries = []
    for lib in steam.get("libraries", []):
        libraries.append({
            "path": canonical_key(lib["path"]),
            "display_path": lib["path"],
            "label": lib.get("label", ""),
            "source": lib.get("source", ""),
        })
    registry = []
    for item in steam.get("registry_values", []):
        name = item["name"].casefold()
        if name in VOLATILE_VALUE_NAMES:
            continue
        if name not in PATH_VALUE_NAMES and "steam" not in item["key"].casefold():
            continue
        registry.append({
            "hive": item["hive"],
            "key": item["key"],
            "name": item["name"],
            "value": item["value"],
            "view": item["view"],
        })
    processes = []
    for proc in steam.get("processes", []):
        if proc.get("path"):
            processes.append({"path": canonical_key(proc["path"]), "display_path": proc["path"]})
    return {
        "version": SNAPSHOT_VERSION,
        "captured_at": now_iso(),
        "client_version": client_version,
        "install_roots": sorted(roots, key=lambda item: item["path"]),
        "libraries": sorted(libraries, key=lambda item: item["path"]),
        "registry": sorted(registry, key=lambda item: (item["hive"], item["key"].casefold(), item["name"].casefold(), item["view"])),
        "processes": sorted(processes, key=lambda item: item["path"]),
        "key_hashes": dict(sorted((key_hashes or {}).items())),
    }


def compare_snapshots(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    changes: List[Dict[str, Any]] = []

    def set_diff(kind: str, old_items: List[Dict[str, Any]], new_items: List[Dict[str, Any]], key: str) -> None:
        old_map = {str(item.get(key, "")): item for item in old_items}
        new_map = {str(item.get(key, "")): item for item in new_items}
        for item_key in sorted(old_map.keys() - new_map.keys()):
            changes.append({"kind": kind, "change": "removed", "key": item_key, "old": old_map[item_key], "new": None})
        for item_key in sorted(new_map.keys() - old_map.keys()):
            changes.append({"kind": kind, "change": "added", "key": item_key, "old": None, "new": new_map[item_key]})
        for item_key in sorted(old_map.keys() & new_map.keys()):
            if old_map[item_key] != new_map[item_key]:
                changes.append({"kind": kind, "change": "changed", "key": item_key, "old": old_map[item_key], "new": new_map[item_key]})

    set_diff("install_root", old.get("install_roots", []), new.get("install_roots", []), "path")
    set_diff("library", old.get("libraries", []), new.get("libraries", []), "path")
    set_diff("process", old.get("processes", []), new.get("processes", []), "path")

    old_reg = {(item["hive"], item["key"], item["name"], item["view"]): item for item in old.get("registry", [])}
    new_reg = {(item["hive"], item["key"], item["name"], item["view"]): item for item in new.get("registry", [])}
    for key in sorted(old_reg.keys() | new_reg.keys()):
        if key not in old_reg:
            changes.append({"kind": "registry", "change": "added", "key": "\\".join(key), "old": None, "new": new_reg[key]})
        elif key not in new_reg:
            changes.append({"kind": "registry", "change": "removed", "key": "\\".join(key), "old": old_reg[key], "new": None})
        elif old_reg[key].get("value") != new_reg[key].get("value"):
            changes.append({"kind": "registry", "change": "changed", "key": "\\".join(key), "old": old_reg[key], "new": new_reg[key]})

    old_hashes = old.get("key_hashes", {}) or {}
    new_hashes = new.get("key_hashes", {}) or {}
    for key in sorted(old_hashes.keys() | new_hashes.keys()):
        if old_hashes.get(key) != new_hashes.get(key):
            changes.append({
                "kind": "key_binary",
                "change": "changed",
                "key": key,
                "old": old_hashes.get(key),
                "new": new_hashes.get(key),
            })

    return {
        "baseline_captured_at": old.get("captured_at", ""),
        "current_captured_at": new.get("captured_at", ""),
        "changes": changes,
        "counts": {
            "total": len(changes),
            "added": sum(1 for item in changes if item["change"] == "added"),
            "removed": sum(1 for item in changes if item["change"] == "removed"),
            "changed": sum(1 for item in changes if item["change"] == "changed"),
        },
    }


def compare_with_baseline(state_dir: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Compare the current Steam state against the existing baseline.

    The baseline and the snapshot history are **never written**.  This is a
    hard product requirement: the tool must not "update the Steam baseline",
    because that would silently accept a tampered Steam install as normal.
    """
    baseline_path = os.path.join(state_dir, "steam_baseline.json")
    baseline = None
    if os.path.isfile(baseline_path):
        try:
            with open(baseline_path, "r", encoding="utf-8-sig") as handle:
                baseline = json.load(handle)
        except (OSError, json.JSONDecodeError):
            baseline = None
    info: Dict[str, Any] = {
        "mode": "read-only",
        "baseline_path": baseline_path,
        "baseline_written": False,
        "snapshot_written": False,
        "drift": {"changes": [], "counts": {"total": 0, "added": 0, "removed": 0, "changed": 0}},
    }
    if not isinstance(baseline, dict):
        info["status"] = "no_baseline"
        info["message"] = (
            "没有找到 Steam 基线。本工具不会创建或更新基线，因此本次只能做签名/结构检查；"
            "如需基线漂移对比，请手工放入 state\\steam_baseline.json。"
        )
        return info
    info["status"] = "compared"
    info["drift"] = compare_snapshots(baseline, snapshot)
    info["message"] = "只读比对完成；基线文件与快照均未被写入或修改。"
    return info


def shorten_path(path: str, limit: int = 120) -> str:
    if len(path) <= limit:
        return path
    return path[: max(0, limit - 3)] + "..."
