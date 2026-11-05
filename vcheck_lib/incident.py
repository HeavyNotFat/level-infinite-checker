"""Complete read-only detector for the 2026 Level Infinite / insightjs incident.

Covers the whole publicly documented chain:

* tampered official launcher JavaScript (loader) and its cache artefacts;
* the LuaJIT payload downloaded through the launcher's ``Srv_DownloadFile``;
* the Lua agent (``k2f``) logs, LevelDB state, temp files and named pipe;
* the ``chrome_install`` persistence (64-hex PlatformExperienceHelper folder and
  the HKCU CLSID) plus loaded modules;
* network-side leftovers (hosts, DNS cache, live sockets) without ever
  contacting the attacker infrastructure;
* deleted-file evidence through the NTFS USN journal (optional, needs admin);
* the credential inventory the payload targets, so the user knows what to
  rotate if the host was exposed.

Everything here is read-only.  Files are opened with ``rb``, registry keys are
opened with ``KEY_READ`` and no file, key or process is modified.
"""
from __future__ import annotations

import ctypes
import glob
import gzip
import os
import re
import shutil
import subprocess
import time
import zlib
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from . import iocs
from .leveldb import search_leveldb
from .models import Finding, max_severity
from .utils import (
    canonical_key,
    file_meta,
    human_size,
    now_iso,
    read_text_safe,
    sha256_file,
)

try:
    import winreg
except ImportError:  # pragma: no cover
    winreg = None


CATEGORY = "Level Infinite 供应链事件"
MAX_HASH_BYTES = 300 * 1024 * 1024


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
class Budget:
    """Wall-clock budget shared by the expensive cache walks."""

    def __init__(self, seconds: float) -> None:
        self.deadline = time.monotonic() + max(5.0, float(seconds))

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def left(self) -> float:
        return max(0.0, self.deadline - time.monotonic())


def _add(
    findings: List[Finding],
    title: str,
    severity: str,
    detail: str,
    path: str = "",
    evidence: Optional[Dict[str, Any]] = None,
    recommendation: str = "",
    category: str = CATEGORY,
) -> None:
    findings.append(Finding(
        title=title,
        severity=severity,
        category=category,
        detail=detail,
        path=path,
        source="incident",
        evidence=evidence or {},
        recommendation=recommendation or DEFAULT_ADVICE,
    ))


DEFAULT_ADVICE = (
    "按供应链失陷处置：立即断网并保全证据（先复制 debug.log、Launcher\\log、tbs_cache）；"
    "不要在取证前再次打开启动器或游戏；从另一台干净设备轮换所有凭据；主机最安全的处置是重装系统。"
)


def _decode(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "gb18030", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _read_bytes(path: str, max_bytes: int = 32 * 1024 * 1024) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(max_bytes)
    except OSError:
        return b""


def _read_tail_text(path: str, max_bytes: int = 24 * 1024 * 1024) -> str:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
            return _decode(handle.read(max_bytes))
    except OSError:
        return ""


def _hash(path: str) -> str:
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return ""
        return sha256_file(path)
    except OSError:
        return ""


def _hash_verdict(digest: str) -> Tuple[str, str]:
    if not digest:
        return "", ""
    if digest in iocs.TAMPERED_ASSETS:
        meta = iocs.TAMPERED_ASSETS[digest]
        return f"被篡改的官方文件：{meta['name']}", "critical"
    if digest in iocs.PAYLOAD_ASSETS:
        meta = iocs.PAYLOAD_ASSETS[digest]
        return f"K2F 载荷/加载器：{meta['name']}（{meta['note']}）", "critical"
    if digest in iocs.CLEAN_ASSETS:
        return f"已修复版本：{iocs.CLEAN_ASSETS[digest]}", "info"
    return "", ""


def _iter_files(root: str, limit: int = 4000) -> Iterator[str]:
    count = 0
    try:
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                if count >= limit:
                    return
                count += 1
                yield os.path.join(dirpath, name)
    except OSError:
        return


def _match_markers(blob: bytes, markers: Sequence[bytes]) -> List[str]:
    found = []
    for marker in markers:
        if marker in blob:
            found.append(marker.decode("ascii", "replace"))
    return found


def _gzip_payloads(blob: bytes, max_output: int = 48 * 1024 * 1024, max_streams: int = 24) -> List[bytes]:
    """Inflate every gzip stream that starts inside ``blob``.

    Chromium's simple HTTP cache stores gzip-encoded bodies, so a plain text
    search misses the tampered launcher JavaScript.  The public report
    recommends inflating each stream that starts with ``1F 8B 08``.
    """
    results: List[bytes] = []
    start = 0
    consumed = 0
    scanned = 0
    while scanned < max_streams:
        index = blob.find(b"\x1f\x8b\x08", start)
        if index < 0:
            break
        scanned += 1
        start = index + 3
        decompressor = zlib.decompressobj(31)
        try:
            chunk = decompressor.decompress(blob[index:], max_output - consumed)
        except zlib.error:
            continue
        if chunk:
            results.append(chunk)
            consumed += len(chunk)
        if consumed >= max_output:
            break
    return results


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _user_profiles() -> List[str]:
    profiles: Dict[str, str] = {}
    base = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users")
    try:
        with os.scandir(base) as iterator:
            for entry in iterator:
                if not entry.is_dir(follow_symlinks=False) or "~" in entry.name:
                    continue
                profiles[os.path.normcase(os.path.realpath(entry.path))] = entry.path
    except OSError:
        pass
    current = os.environ.get("USERPROFILE")
    if current:
        profiles.setdefault(os.path.normcase(os.path.realpath(current)), current)
    return list(profiles.values())


def _drives() -> List[str]:
    result = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for index in range(26):
            if mask & (1 << index):
                drive = f"{chr(65 + index)}:\\"
                try:
                    if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive)) in (2, 3):
                        result.append(drive)
                except Exception:
                    result.append(drive)
    except Exception:
        result = ["C:\\"]
    return result or ["C:\\"]


def _registry_read(key_path: str, hive=None, view: int = 0) -> Optional[str]:
    if winreg is None:
        return None
    hive = winreg.HKEY_CURRENT_USER if hive is None else hive
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view)
    except OSError:
        return None
    try:
        value, _ = winreg.QueryValueEx(key, "")
        return str(value)
    except OSError:
        return ""
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass


def _count_subkeys(key_path: str, hive=None, view: int = 0) -> int:
    if winreg is None:
        return 0
    hive = winreg.HKEY_CURRENT_USER if hive is None else hive
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view)
    except OSError:
        return 0
    count = 0
    try:
        while True:
            try:
                winreg.EnumKey(key, count)
            except OSError:
                break
            count += 1
            if count > 5000:
                break
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass
    return count


# ---------------------------------------------------------------------------
# Launcher discovery
# ---------------------------------------------------------------------------
def _root_from_exe(path: str) -> str:
    current = os.path.dirname(path)
    for _ in range(4):
        if not current:
            break
        if os.path.isdir(os.path.join(current, "Launcher")) or os.path.isdir(os.path.join(current, "launcher")):
            return current
        current = os.path.dirname(current)
    return os.path.dirname(path)


def _launcher_dirs_for_root(root: str) -> List[str]:
    dirs = []
    for rel in ("Launcher", "launcher"):
        path = os.path.join(root, rel)
        if os.path.isdir(path):
            dirs.append(path)
    return dirs


def _install_dir_name_hit(name: str) -> bool:
    lower = name.casefold()
    for _label, hints in iocs.GAME_HINTS:
        if any(hint in lower for hint in hints):
            return True
    return False


def _uninstall_roots() -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    if winreg is None:
        return results
    uninstall_paths = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    )
    views = [0, getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0)]
    for hive, hive_label in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        for base_path in uninstall_paths:
            for view in views:
                try:
                    base = winreg.OpenKey(hive, base_path, 0, winreg.KEY_READ | view)
                except OSError:
                    continue
                index = 0
                while index < 400:
                    try:
                        sub_name = winreg.EnumKey(base, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        sub = winreg.OpenKey(base, sub_name, 0, winreg.KEY_READ | view)
                    except OSError:
                        continue
                    values = {}
                    for value_name in ("DisplayName", "InstallLocation", "DisplayIcon", "Publisher"):
                        try:
                            values[value_name] = str(winreg.QueryValueEx(sub, value_name)[0])
                        except OSError:
                            values[value_name] = ""
                    try:
                        winreg.CloseKey(sub)
                    except OSError:
                        pass
                    display = values.get("DisplayName", "")
                    publisher = values.get("Publisher", "").casefold()
                    haystack = (display + " " + values.get("InstallLocation", "")).casefold()
                    hit = _install_dir_name_hit(display) or any(
                        token in publisher for token in ("level infinite", "proxima beta", "tencent")
                    ) or any(token in haystack for token in ("level infinite", "nikke"))
                    if not hit:
                        continue
                    location = values.get("InstallLocation", "").strip().strip('"')
                    if not location:
                        icon = values.get("DisplayIcon", "")
                        match = re.match(r'"?([^",]+\.exe)', icon, re.I)
                        if match:
                            location = _root_from_exe(match.group(1))
                    if location:
                        results.append({"root": location, "source": f"卸载项 {hive_label}\\{sub_name}", "name": display})
                try:
                    winreg.CloseKey(base)
                except OSError:
                    pass
    return results


def _registry_nikke_roots() -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    if winreg is None:
        return results
    for class_name in ("nikkelauncher", "nikkelauncherhmt", "nikkelauncher_google"):
        for view in (0, getattr(winreg, "KEY_WOW64_32KEY", 0)):
            value = _registry_read(rf"Software\Classes\{class_name}\DefaultIcon", view=view)
            if not value:
                continue
            match = re.match(r'"?([^",]+?\.exe)', value if isinstance(value, str) else str(value), re.I)
            if match:
                results.append({"root": _root_from_exe(match.group(1)), "source": f"HKCU Classes {class_name}"})
    return results


def discover_launchers(processes: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Find every installed/ running Level Infinite style launcher."""
    candidates: List[Dict[str, str]] = []
    for proc in processes or []:
        path = str(proc.get("path", "") or "")
        if not path:
            continue
        name = os.path.basename(path).casefold()
        if name in iocs.LAUNCHER_EXE_NAMES or ("launcher" in name and _install_dir_name_hit(path)):
            candidates.append({"root": _root_from_exe(path), "source": "运行中的进程"})
    for profile in _user_profiles():
        for data_dir in glob.glob(os.path.join(profile, "AppData", "Roaming", "nikke_launcher*")):
            for reg_file in ("url_protocol.reg", "url_protocol_hmt.reg"):
                text = read_text_safe(os.path.join(data_dir, reg_file), max_bytes=1024 * 1024)
                for match in re.finditer(r'([A-Za-z]:\\[^"\r\n]+?\.exe)', text):
                    candidates.append({"root": _root_from_exe(match.group(1)), "source": f"启动器数据 {os.path.basename(data_dir)}"})
    candidates.extend(_registry_nikke_roots())
    candidates.extend(_uninstall_roots())

    for drive in _drives():
        for name in iocs.KNOWN_INSTALL_DIR_NAMES:
            path = os.path.join(drive, name)
            if os.path.isdir(path):
                candidates.append({"root": path, "source": "常见安装路径"})
        try:
            with os.scandir(drive) as iterator:
                top = list(iterator)[:400]
        except OSError:
            continue
        for entry in top:
            if not entry.is_dir(follow_symlinks=False):
                continue
            if _install_dir_name_hit(entry.name):
                candidates.append({"root": entry.path, "source": "盘符顶层目录名"})
                continue
            # Common parent folders (Games, SteamLibrary, Program Files...)
            if any(token in entry.name.casefold() for token in ("games", "steamlibrary", "program files", "epic games", "xboxgames")):
                try:
                    with os.scandir(entry.path) as iterator:
                        children = list(iterator)[:120]
                except OSError:
                    continue
                for child in children:
                    if not child.is_dir(follow_symlinks=False):
                        continue
                    if _install_dir_name_hit(child.name) or any(
                        os.path.isdir(os.path.join(child.path, sub)) for sub in ("Launcher", "launcher")
                    ):
                        candidates.append({"root": child.path, "source": f"上层目录 {entry.name}"})

    found: Dict[str, Dict[str, Any]] = {}
    for item in candidates:
        root = os.path.normpath(str(item.get("root", "")).strip().strip('"'))
        if not root or not os.path.isdir(root):
            continue
        key = canonical_key(root)
        launcher_dirs = _launcher_dirs_for_root(root)
        has_intl = any(os.path.isdir(os.path.join(path, "intl_service")) for path in launcher_dirs)
        has_exe = bool(glob.glob(os.path.join(root, "nikke_launcher*.exe"))) or any(
            os.path.isfile(os.path.join(path, name))
            for path in launcher_dirs
            for name in iocs.LAUNCHER_EXE_NAMES
        )
        if not launcher_dirs and not has_exe:
            continue
        if key in found:
            sources = found[key]["sources"]
            if item.get("source") not in sources:
                sources.append(item.get("source"))
            continue
        debug_log = ""
        for launcher_dir in launcher_dirs:
            candidate = os.path.join(launcher_dir, "intl_service", "debug.log")
            if os.path.isfile(candidate):
                debug_log = candidate
                break
        tinyget = ""
        for launcher_dir in launcher_dirs:
            candidate = os.path.join(launcher_dir, "log", "tinyget")
            if os.path.isdir(candidate):
                tinyget = candidate
                break
        found[key] = {
            "root": root,
            "launcher_dirs": launcher_dirs,
            "has_intl_service": has_intl,
            "has_launcher_exe": has_exe,
            "debug_log": debug_log,
            "tinyget": tinyget,
            "sources": [str(item.get("source", ""))],
            "game": next((label for label, hints in iocs.GAME_HINTS if any(hint in root.casefold() for hint in hints)), ""),
            "confirmed": "nikke" in root.casefold(),
        }
    return list(found.values())


def _launcher_data_dirs(profiles: Iterable[str]) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    seen = set()
    for profile in profiles:
        roaming = os.path.join(profile, "AppData", "Roaming")
        for name in iocs.LAUNCHER_DATA_DIRS:
            path = os.path.join(roaming, name)
            if not os.path.isdir(path):
                continue
            key = canonical_key(path)
            if key in seen:
                continue
            seen.add(key)
            results.append({"profile": profile, "path": path})
    return results


# ---------------------------------------------------------------------------
# 1. Launcher debug.log
# ---------------------------------------------------------------------------
def scan_debug_logs(launchers: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    findings: List[Finding] = []
    files: List[Dict[str, Any]] = []
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    for launcher in launchers:
        paths: List[str] = []
        if launcher.get("debug_log"):
            paths.append(str(launcher["debug_log"]))
        for launcher_dir in launcher.get("launcher_dirs", []):
            for rel in (("intl_service", "debug.log"), ("debug.log",)):
                candidate = os.path.join(launcher_dir, *rel)
                if os.path.isfile(candidate) and candidate not in paths:
                    paths.append(candidate)
        for path in paths:
            text = _read_tail_text(path)
            lines = text.splitlines()
            markers: List[Dict[str, Any]] = []
            for needle, label, severity, stage in iocs.DEBUG_MARKERS:
                hits = [(number, line) for number, line in enumerate(lines, 1) if needle in line]
                if not hits:
                    continue
                markers.append({
                    "marker": needle,
                    "label": label,
                    "severity": severity,
                    "stage": stage,
                    "count": len(hits),
                    "first_line": hits[0][0],
                    "samples": [line.strip()[:400] for _number, line in hits[:3]],
                })
            meta = file_meta(path, include_hash=False)
            files.append({"path": path, "launcher": launcher.get("root", ""), "markers": markers, "meta": meta})
            if not markers:
                continue
            severity = max_severity(item["severity"] for item in markers)
            for item in markers:
                if item["stage"] >= 3:
                    flags["agent"] = True
                elif item["stage"] == 2:
                    flags["download"] = True
            if severity == "critical":
                title = "启动器 debug.log 证明 K2F 代理已运行"
                detail = (
                    "日志中出现 k2f_chan registered / agent started as / startup failed: EIO。"
                    "这是官方与公开分析共同认可的判准：代理已被下载并执行，即使后面的 adopted 行不存在。"
                )
            elif severity == "high":
                title = "启动器 debug.log 显示 K2F 载荷已下载"
                detail = "日志中出现 Lua 载荷下载/接管标记；需要结合 tinyget 日志与 tbs_cache 进一步确认。"
            else:
                title = "启动器 debug.log 出现 K2F 相关标记"
                detail = "仅有间接标记（例如 startup already in progress / resuming），不能单独定性，但需要核对。"
            _add(
                findings,
                title,
                severity,
                detail,
                path,
                {"launcher": launcher.get("root", ""), "markers": markers, "file": meta},
            )

    for launcher in launchers:
        if launcher.get("launcher_dirs") and not launcher.get("debug_log"):
            _add(
                findings,
                "启动器目录缺少 debug.log",
                "info",
                "找不到 Launcher\\intl_service\\debug.log。可能是从未运行过、已重装、被清理，"
                "或 2026-11-05 之后的官方版本在启动时删除了它；不能据此排除感染。",
                str(launcher.get("root", "")),
                {"launcher": launcher.get("root", "")},
            )
    return {"findings": [item.to_dict() for item in findings], "files": files, "flags": flags}


# ---------------------------------------------------------------------------
# 2. Launcher tinyget logs / payload files
# ---------------------------------------------------------------------------
def scan_tinyget(launchers: Sequence[Dict[str, Any]], budget: Budget) -> Dict[str, Any]:
    findings: List[Finding] = []
    files: List[Dict[str, Any]] = []
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    etag_pattern = re.compile(r"\b[0-9a-f]{8}-3214f\b", re.I)
    for launcher in launchers:
        directories = []
        if launcher.get("tinyget"):
            directories.append(str(launcher["tinyget"]))
        for launcher_dir in launcher.get("launcher_dirs", []):
            candidate = os.path.join(launcher_dir, "log", "tinyget")
            if os.path.isdir(candidate) and candidate not in directories:
                directories.append(candidate)
        for directory in directories:
            try:
                names = os.listdir(directory)[:800]
            except OSError:
                continue
            for name in names:
                if budget.expired():
                    break
                path = os.path.join(directory, name)
                if not os.path.isfile(path):
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size > MAX_HASH_BYTES:
                    continue
                header = _read_bytes(path, 8)
                digest = _hash(path)
                label, severity = _hash_verdict(digest)
                record: Dict[str, Any] = {
                    "path": path,
                    "name": name,
                    "size": size,
                    "size_human": human_size(size),
                    "sha256": digest,
                    "lua_header": header[:4] == iocs.LUAJIT_HEADER,
                    "known": label,
                    "markers": [],
                    "etags": [],
                }
                if header[:4] == iocs.LUAJIT_HEADER:
                    flags["download"] = True
                    record["markers"] = ["LuaJIT bytecode header 1B 4C 4A 01"]
                    _add(
                        findings,
                        "启动器下载目录存在 LuaJIT 载荷",
                        "critical",
                        "文件头为 1B 4C 4A 01，与 insight.bundle / K2F bundle 格式一致。"
                        "官方手动检查只按 205,135 字节匹配，会漏掉 165,108 字节的早期构建。",
                        path,
                        {"size": size, "sha256": digest, "header": "1B 4C 4A 01"},
                    )
                elif label:
                    flags["download"] = True
                    _add(findings, "命中 K2F 已知样本哈希", severity, label, path, record)
                else:
                    text = ""
                    if name.casefold().endswith((".log", ".mem.log", ".cdt", ".txt")) or size < 8 * 1024 * 1024:
                        text = _read_tail_text(path, 24 * 1024 * 1024)
                    if text:
                        hits = [marker for marker, _label, _sev in iocs.TINYGET_MARKERS if marker in text]
                        etags = sorted(set(etag_pattern.findall(text)))[:10]
                        record["markers"] = hits
                        record["etags"] = etags
                        if hits or etags:
                            flags["download"] = True
                            _add(
                                findings,
                                "启动器下载日志显示 insightjs 载荷下载",
                                "high",
                                "日志中出现 K2F 下载地址/文件名/成功记录或 insight.bundle 的 ETag。"
                                "官方修复会删除这些日志，所以这是重要证据。",
                                path,
                                {"markers": hits, "etags": etags, "size": size},
                            )
                files.append(record)
    return {"findings": [item.to_dict() for item in findings], "files": files, "dirs": [str(item.get("tinyget")) for item in launchers if item.get("tinyget")], "flags": flags}


# ---------------------------------------------------------------------------
# 3. tbs_cache: code cache, HTTP cache, Local Storage
# ---------------------------------------------------------------------------
def _cache_dirs(data_dirs: Sequence[Dict[str, str]]) -> List[Dict[str, str]]:
    results = []
    for item in data_dirs:
        tbs = os.path.join(item["path"], "tbs_cache")
        if os.path.isdir(tbs):
            results.append({"profile": item["profile"], "data_dir": item["path"], "tbs": tbs})
    return results


def scan_code_cache(data_dirs: Sequence[Dict[str, str]], budget: Budget) -> Dict[str, Any]:
    findings: List[Finding] = []
    entries: List[Dict[str, Any]] = []
    scanned = 0
    markers_hits: List[Dict[str, Any]] = []
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    for cache in _cache_dirs(data_dirs):
        code_cache = os.path.join(cache["tbs"], "Code Cache", "js")
        if not os.path.isdir(code_cache):
            continue
        for known, label in iocs.CODE_CACHE_ENTRIES.items():
            path = os.path.join(code_cache, known)
            if not os.path.isfile(path):
                continue
            meta = file_meta(path)
            entries.append({"name": known, "label": label, "path": path, "meta": meta})
            flags["loader"] = True
        if entries:
            _add(
                findings,
                "启动器 V8 Code Cache 中存在 insightjs 加载器条目",
                "high",
                "已知的四个加载器缓存条目（aegis/images/feedlist/vue）存在，说明被篡改的官方 JS 至少运行过一次；"
                "条目的修改时间就是加载器最后一次运行的时间。",
                code_cache,
                {"entries": entries, "cache": code_cache},
            )
        for path in _iter_files(code_cache, limit=3000):
            if budget.expired():
                break
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size > 8 * 1024 * 1024:
                continue
            scanned += 1
            blob = _read_bytes(path, 8 * 1024 * 1024)
            found = _match_markers(blob, iocs.LOADER_JS_MARKERS)
            if not found:
                continue
            flags["loader"] = True
            markers_hits.append({"path": path, "markers": found, "size": size})
        if len(markers_hits) >= 20:
            break
    if markers_hits:
        _add(
            findings,
            "启动器 Code Cache 中出现 insightjs 加载器内容",
            "high",
            "缓存条目包含 l.js 地址或注入代码特征，说明加载器在启动器内置浏览器中执行过。",
            markers_hits[0]["path"],
            {"hits": markers_hits[:10], "scanned": scanned},
        )
    return {"findings": [item.to_dict() for item in findings], "entries": entries, "hits": markers_hits, "scanned": scanned, "flags": flags}


def scan_http_cache(data_dirs: Sequence[Dict[str, str]], budget: Budget) -> Dict[str, Any]:
    findings: List[Finding] = []
    hits: List[Dict[str, Any]] = []
    scanned = 0
    decompressed = 0
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    for cache in _cache_dirs(data_dirs):
        cache_dir = os.path.join(cache["tbs"], "Cache")
        if not os.path.isdir(cache_dir):
            continue
        for path in _iter_files(cache_dir, limit=4000):
            if budget.expired():
                break
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size > 32 * 1024 * 1024:
                continue
            scanned += 1
            blob = _read_bytes(path, 32 * 1024 * 1024)
            if not blob:
                continue
            candidates: List[Tuple[bytes, str]] = [(blob, "raw")]
            for payload in _gzip_payloads(blob)[:4]:
                candidates.append((payload, "gzip"))
                decompressed += len(payload)
            for content, kind in candidates:
                if not content:
                    continue
                digest = ""
                if len(content) <= 300 * 1024:
                    try:
                        import hashlib
                        digest = hashlib.sha256(content).hexdigest()
                    except Exception:
                        digest = ""
                label, severity = _hash_verdict(digest)
                if label and severity == "critical" and "被篡改" in label:
                    flags["loader"] = True
                    hits.append({"path": path, "kind": kind, "sha256": digest, "label": label, "size": len(content)})
                    _add(
                        findings,
                        "启动器 HTTP 缓存中仍藏有被篡改的官方 JS",
                        "critical",
                        "缓存内容哈希与被篡改版本一致（" + label + "）。即使启动器已更新，缓存仍会让启动器再次加载它。",
                        path,
                        {"sha256": digest, "kind": kind, "size": len(content)},
                    )
                    continue
                found = _match_markers(content, iocs.CACHE_MARKERS)
                if found:
                    flags["loader"] = True
                    hits.append({"path": path, "kind": kind, "markers": found, "size": len(content), "sha256": digest})
                    _add(
                        findings,
                        "启动器 HTTP 缓存中出现 insightjs 痕迹",
                        "high",
                        "缓存内容（解压后）含加载器地址、载荷地址或 K2F 标记；这是启动器实际请求过恶意资源的直接证据。",
                        path,
                        {"markers": found, "kind": kind, "size": len(content)},
                    )
            if len(hits) >= 25:
                break
        if len(hits) >= 25:
            break
    return {"findings": [item.to_dict() for item in findings], "hits": hits, "scanned": scanned, "decompressed": decompressed, "flags": flags}


def scan_local_storage(data_dirs: Sequence[Dict[str, str]], budget: Budget) -> Dict[str, Any]:
    findings: List[Finding] = []
    hits: List[Dict[str, Any]] = []
    scanned = 0
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    for cache in _cache_dirs(data_dirs):
        tbs = cache["tbs"]
        leveldb_dir = os.path.join(tbs, "Local Storage", "leveldb")
        if os.path.isdir(leveldb_dir):
            for name in sorted(os.listdir(leveldb_dir))[:600]:
                if budget.expired():
                    break
                path = os.path.join(leveldb_dir, name)
                if not os.path.isfile(path):
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size > 128 * 1024 * 1024:
                    continue
                scanned += 1
                result = search_leveldb(path, iocs.LEVELDB_NEEDLES)
                found = list(result.get("found") or [])
                if not found:
                    continue
                flags["agent"] = True
                hits.append({
                    "path": path,
                    "found": found,
                    "method": result.get("method"),
                    "blocks": result.get("blocks"),
                    "size": size,
                })
                critical = "k2f.agent.state" in found or "k2f.agent" in found
                _add(
                    findings,
                    "启动器 Local Storage 中存在 K2F agent 状态",
                    "critical" if critical else "high",
                    "leveldb 中出现 k2f.agent.state / agent_pass / poll_interval / collect_cookies。"
                    "代理的状态在删除游戏或启动器后仍然保留；压缩的 .ldb 表也能被本工具读取。",
                    path,
                    {"found": found, "method": result.get("method"), "blocks": result.get("blocks")},
                )
        for rel, needles, severity, title in (
            (("TransportSecurity",), (b"insightjs",), "medium", "启动器 HSTS 记录中出现 insightjs"),
            (("Network Persistent State",), (b"insightjs", b"analytics.insightjs.com"), "medium", "启动器网络状态中出现 insightjs"),
            (("Code Cache", "js"), iocs.LOADER_JS_MARKERS[:2], "medium", "启动器 Code Cache 含加载器解码特征"),
        ):
            path = os.path.join(tbs, *rel)
            if not os.path.isfile(path):
                continue
            found = _match_markers(_read_bytes(path, 32 * 1024 * 1024), needles)
            if not found:
                continue
            hits.append({"path": path, "found": found})
            _add(
                findings,
                title,
                severity,
                "缓存/网络状态中发现 K2F 关联字符串；可能是历史接触痕迹，也可能仍在活动。",
                path,
                {"found": found},
            )
    return {"findings": [item.to_dict() for item in findings], "hits": hits, "scanned": scanned, "flags": flags}


# ---------------------------------------------------------------------------
# 4. Browser persistence + wallet extensions
# ---------------------------------------------------------------------------
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def scan_browser(profiles: Iterable[str], budget: Optional[Budget] = None) -> Dict[str, Any]:
    findings: List[Finding] = []
    artifacts: List[Dict[str, Any]] = []
    wallets: List[Dict[str, str]] = []
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    for profile in profiles:
        local = os.path.join(profile, "AppData", "Local")
        roaming = os.path.join(profile, "AppData", "Roaming")
        for rel in iocs.BROWSER_DATA_DIRS:
            user_data = os.path.join(local, rel) if not rel.startswith("Opera Software") else os.path.join(roaming, rel)
            if not os.path.isdir(user_data):
                continue
            helper_root = os.path.join(user_data, iocs.HELPER_DIR_NAME)
            if os.path.isdir(helper_root):
                for entry in os.scandir(helper_root):
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if not _HEX64.match(entry.name):
                        continue
                    dlls = []
                    for name in os.listdir(entry.path):
                        path = os.path.join(entry.path, name)
                        if not os.path.isfile(path):
                            continue
                        dlls.append({"name": name, "path": path, "sha256": _hash(path)})
                    if not dlls:
                        continue
                    flags["active"] = True
                    artifacts.append({"path": entry.path, "files": dlls})
                    _add(
                        findings,
                        "浏览器数据目录存在 64-hex PlatformExperienceHelper 组件",
                        "critical",
                        "这是 chrome_install 的落地点：文件夹名是 DLL 的 SHA-256，DLL 也是每个受害者单独构建，"
                        "所以哈希不是通用 IOC，必须看路径和 HKCU CLSID。PlatformExperienceHelper 文件夹本身是 Chrome 的正常文件夹。",
                        entry.path,
                        {"profile": profile, "browser": rel, "files": dlls},
                    )
            # Installer residue written by older builds.
            app_dir = os.path.join(os.path.dirname(user_data), "Application")
            for name in iocs.HELPER_DLL_NAMES:
                path = os.path.join(app_dir, name)
                if not os.path.isfile(path):
                    continue
                artifacts.append({"path": path, "residue": name})
                _add(
                    findings,
                    f"浏览器安装目录存在 K2F 安装残留：{name}",
                    "medium",
                    "报告提到的安装器残留文件；含义取决于 HKCU CLSID 与 debug.log 是否也存在。",
                    path,
                    {"profile": profile, "browser": rel},
                )
            # Wallet extensions are only relevant as "what could have been taken".
            if budget is not None and budget.expired():
                continue
            for profile_dir in sorted(glob.glob(os.path.join(user_data, "*"))) [:12]:
                extensions_dir = os.path.join(profile_dir, "Extensions")
                if not os.path.isdir(extensions_dir):
                    continue
                for manifest in glob.glob(os.path.join(extensions_dir, "*", "*", "manifest.json"))[:400]:
                    name = _extension_name(manifest)
                    if not name:
                        continue
                    lower = name.casefold()
                    if not any(keyword in lower for keyword in iocs.WALLET_KEYWORDS):
                        continue
                    wallets.append({"name": name, "manifest": manifest, "profile": profile, "browser": rel})
    dedup: Dict[str, Dict[str, str]] = {}
    for item in wallets:
        dedup.setdefault(item["name"].casefold(), item)
    return {"findings": [item.to_dict() for item in findings], "artifacts": artifacts, "wallets": list(dedup.values()), "flags": flags}


def _extension_name(manifest_path: str) -> str:
    text = read_text_safe(manifest_path, max_bytes=8192)
    match = re.search(r'"name"\s*:\s*"((?:[^"\\]|\\.){1,120})"', text)
    if not match:
        return ""
    name = match.group(1)
    if name.startswith("__MSG_") and name.endswith("__"):
        # Localised extensions (MetaMask, Phantom, ...) store the real name in
        # _locales/<locale>/messages.json.
        key = name[6:-2]
        base = os.path.dirname(manifest_path)
        for locale in ("en", "en_US", "zh_CN", "zh_TW"):
            messages_path = os.path.join(base, "_locales", locale, "messages.json")
            messages = read_text_safe(messages_path, max_bytes=256 * 1024)
            if not messages:
                continue
            found = re.search(
                r'"' + re.escape(key) + r'"\s*:\s*\{[^{}]*?"message"\s*:\s*"((?:[^"\\]|\\.){1,120})"',
                messages,
            )
            if found:
                return found.group(1)
        return ""
    return name


def _enum_registry_values(key_path: str, hive, view: int = 0) -> List[Tuple[str, str]]:
    if winreg is None:
        return []
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view)
    except OSError:
        return []
    values: List[Tuple[str, str]] = []
    index = 0
    try:
        while index < 400:
            try:
                name, data, _kind = winreg.EnumValue(key, index)
            except OSError:
                break
            index += 1
            if isinstance(data, (list, tuple)):
                data = ";".join(str(item) for item in data)
            values.append((str(name), str(data)))
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass
    return values


def _enum_registry_subkeys(key_path: str, hive, view: int = 0) -> List[str]:
    if winreg is None:
        return []
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view)
    except OSError:
        return []
    names: List[str] = []
    index = 0
    try:
        while index < 400:
            try:
                names.append(winreg.EnumKey(key, index))
            except OSError:
                break
            index += 1
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass
    return names


def scan_browser_config(profiles: Iterable[str]) -> Dict[str, Any]:
    """Registry + browser-profile checks around the browser side of the chain.

    * the benign HKLM copy of the abused CLSID (so the report can prove it was
      compared, and tell the user not to delete it);
    * force-installed extensions and NativeMessagingHosts, two other ways to run
      code in Chromium browsers;
    * which browser profiles actually hold saved passwords / cookies, i.e. what
      ``browserscan`` would have taken.
    """
    findings: List[Finding] = []
    records: Dict[str, Any] = {"policies": [], "native_messaging": [], "profiles": [], "clsid": []}
    flags = _empty_flags()
    if winreg is not None:
        # HKLM has the same CLSID for WindowsParentalControls; keep it.
        for view, view_label in ((getattr(winreg, "KEY_WOW64_64KEY", 0), "64"), (getattr(winreg, "KEY_WOW64_32KEY", 0), "32")):
            for hive, hive_label in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
                value = _registry_read(r"Software\Classes\CLSID" + "\\" + iocs.KNOWN_CLSID + r"\InprocServer32", hive=hive, view=view)
                if value is None:
                    continue
                record = {"hive": hive_label, "view": view_label, "value": value, "malicious": hive_label == "HKCU"}
                records["clsid"].append(record)
                if hive_label == "HKLM":
                    _add(
                        findings,
                        "HKLM 中存在同名 CLSID（正常组件，请保留）",
                        "info",
                        "HKLM 下的 {E77CC89B-…} 指向 WindowsParentalControls（wpc.dll），是系统自带组件；"
                        "只有 HKCU 下的同名项是恶意的。清理时不要删除 HKLM 这一项。",
                        str(value),
                        record,
                    )
        policy_keys = (
            r"Software\Policies\Google\Chrome\ExtensionInstallForcelist",
            r"Software\Policies\Google\Chrome\ExtensionSettings",
            r"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist",
            r"Software\Policies\Microsoft\Edge\ExtensionSettings",
        )
        for key_path in policy_keys:
            for hive, hive_label in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
                values = _enum_registry_values(key_path, hive)
                if not values:
                    continue
                records["policies"].append({"key": f"{hive_label}\\{key_path}", "values": values[:40]})
                _add(
                    findings,
                    "浏览器存在策略强制安装的扩展",
                    "medium",
                    "企业/软件通过策略下发的扩展也会出现在这里；如果这些扩展是钱包或密码相关，需要确认其来源。",
                    f"{hive_label}\\{key_path}",
                    {"values": values[:20]},
                )
        native_keys = (
            ("Chrome", r"Software\Google\Chrome\NativeMessagingHosts"),
            ("Edge", r"Software\Microsoft\Edge\NativeMessagingHosts"),
            ("Firefox", r"Software\Mozilla\NativeMessagingHosts"),
        )
        for browser, key_path in native_keys:
            for hive, hive_label in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
                for name in _enum_registry_subkeys(key_path, hive):
                    value = _registry_read(key_path + "\\" + name, hive=hive)
                    if not value:
                        continue
                    record = {"browser": browser, "hive": hive_label, "name": name, "manifest": value}
                    records["native_messaging"].append(record)
                    if "appdata" in value.casefold() or "\\temp\\" in value.casefold() or "\\users\\public\\" in value.casefold():
                        severity = "medium" if ("\\temp\\" in value.casefold() or "\\users\\public\\" in value.casefold()) else "low"
                        _add(
                            findings,
                            "NativeMessagingHost 指向用户可写目录",
                            severity,
                            "浏览器 NativeMessaging 可以启动本机程序。很多正常软件（密码管理器、下载器）也会把清单放在 AppData；"
                            "只有同时存在 insightjs/K2F 其他证据时才需要进一步处理。",
                            value,
                            record,
                        )
    for profile in profiles:
        local = os.path.join(profile, "AppData", "Local")
        roaming = os.path.join(profile, "AppData", "Roaming")
        for browser, rel in (
            ("Chrome", r"Google\Chrome\User Data"),
            ("Edge", r"Microsoft\Edge\User Data"),
            ("Brave", r"BraveSoftware\Brave-Browser\User Data"),
            ("Vivaldi", r"Vivaldi\User Data"),
        ):
            base = os.path.join(local, rel)
            if not os.path.isdir(base):
                continue
            for profile_dir in sorted(glob.glob(os.path.join(base, "*")))[:12]:
                if not os.path.isdir(profile_dir):
                    continue
                names = ("Login Data", os.path.join("Network", "Cookies"), "Cookies", "Web Data")
                present = [name for name in names if os.path.isfile(os.path.join(profile_dir, name))]
                if not present:
                    continue
                records["profiles"].append({
                    "profile": profile,
                    "browser": browser,
                    "path": profile_dir,
                    "stores": present,
                })
        for places in glob.glob(os.path.join(roaming, "Mozilla", "Firefox", "Profiles", "*")):
            present = [name for name in ("logins.json", "key4.db", "cookies.sqlite") if os.path.isfile(os.path.join(places, name))]
            if present:
                records["profiles"].append({"profile": profile, "browser": "Firefox", "path": places, "stores": present})
    if records["profiles"]:
        _add(
            findings,
            "浏览器配置中存在保存的密码/Cookie 存储",
            "info",
            "browserscan 会读取 Chrome/Edge/Brave/Vivaldi 的 Login Data 与 Cookies（Firefox 只读 logins.json/key4.db）。"
            "文件存在只说明有可窃取的数据；是否被读走取决于主机是否执行过代理。",
            records["profiles"][0]["path"],
            {"profiles": records["profiles"][:40]},
        )
    return {"findings": [item.to_dict() for item in findings], "records": records, "flags": flags}



# ---------------------------------------------------------------------------
# 5. HKCU CLSID persistence
# ---------------------------------------------------------------------------
def scan_clsid() -> Dict[str, Any]:
    findings: List[Finding] = []
    records: List[Dict[str, Any]] = []
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    if winreg is None:
        return {"findings": [], "records": records, "flags": flags, "available": False}
    base_path = r"Software\Classes\CLSID"
    for view, view_label in ((getattr(winreg, "KEY_WOW64_64KEY", 0), "64"), (getattr(winreg, "KEY_WOW64_32KEY", 0), "32")):
        # 1. The known CLSID: check existence even when InprocServer32 is empty.
        key_path = base_path + "\\" + iocs.KNOWN_CLSID
        value = _registry_read(key_path + r"\InprocServer32", view=view)
        exists = False
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | view)
            winreg.CloseKey(key)
            exists = True
        except OSError:
            exists = False
        if exists or value is not None:
            flags["active"] = True
            records.append({"clsid": iocs.KNOWN_CLSID, "view": view_label, "path": value or "", "exists": exists})
            if value:
                _add(
                    findings,
                    "HKCU 已知 K2F CLSID 指向 DLL",
                    "critical",
                    "Chrome 会按 HKCU\\Software\\Classes\\CLSID 加载 InprocServer32 指定的 DLL。"
                    "HKLM 下的同名项是 WindowsParentalControls（wpc.dll），只有 HKCU 这一项是恶意的。",
                    value,
                    {"clsid": iocs.KNOWN_CLSID, "view": view_label, "value": value},
                )
            else:
                _add(
                    findings,
                    "HKCU 已知 K2F CLSID 仍存在（默认值为空）",
                    "high",
                    "这是 chrome_uninstall 执行后留下的状态：DLL 可能已删除，但注册表项还在。"
                    "仍说明 chrome_install 执行过。",
                    key_path,
                    {"clsid": iocs.KNOWN_CLSID, "view": view_label, "empty": True},
                )
        # 2. Any other HKCU CLSID pointing at PlatformExperienceHelper or a 64-hex folder.
        try:
            base = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        index = 0
        visited = 0
        while visited < 4000:
            try:
                clsid = winreg.EnumKey(base, index)
            except OSError:
                break
            index += 1
            visited += 1
            if clsid.upper() == iocs.KNOWN_CLSID:
                continue
            other = _registry_read(f"{base_path}\\{clsid}\\InprocServer32", view=view)
            if not other:
                continue
            lower = str(other).casefold()
            if "platformexperiencehelper" not in lower and not re.search(r"\\[0-9a-f]{64}\\", lower):
                continue
            flags["active"] = True
            records.append({"clsid": clsid, "view": view_label, "path": other})
            _add(
                findings,
                "HKCU 有其他 CLSID 指向 PlatformExperienceHelper/64-hex 目录",
                "high",
                "同一加载器可能换用了新的 CLSID；需要与公开 IOC 对照。",
                str(other),
                {"clsid": clsid, "view": view_label, "value": other},
            )
        try:
            winreg.CloseKey(base)
        except OSError:
            pass

    # 3. Other loaded user hives (only the known CLSID, to stay fast).
    try:
        users = winreg.OpenKey(winreg.HKEY_USERS, "")
    except OSError:
        users = None
    seen = set()
    if users is not None:
        index = 0
        while index < 500:
            try:
                sid = winreg.EnumKey(users, index)
            except OSError:
                break
            index += 1
            for base_path in (sid + r"\Software\Classes\CLSID", sid + r"_Classes\CLSID"):
                sub_path = base_path + "\\" + iocs.KNOWN_CLSID + r"\InprocServer32"
                try:
                    key = winreg.OpenKey(winreg.HKEY_USERS, sub_path, 0, winreg.KEY_READ)
                except OSError:
                    continue
                try:
                    value, _ = winreg.QueryValueEx(key, "")
                except OSError:
                    value = ""
                finally:
                    try:
                        winreg.CloseKey(key)
                    except OSError:
                        pass
                key_id = (sid, str(value).casefold())
                if key_id in seen:
                    continue
                seen.add(key_id)
                flags["active"] = True
                records.append({"clsid": iocs.KNOWN_CLSID, "view": "HKU", "hive": "HKU\\" + sid, "path": str(value)})
                _add(
                    findings,
                    "其他用户 HKCU/Classes 中也存在 K2F CLSID",
                    "critical",
                    "该 CLSID 位于另一个已加载的用户 hive，说明对应账号也被设置了浏览器持久化。",
                    str(value),
                    {"clsid": iocs.KNOWN_CLSID, "hive": "HKU\\" + sid, "value": str(value)},
                )
        try:
            winreg.CloseKey(users)
        except OSError:
            pass
    return {"findings": [item.to_dict() for item in findings], "records": records, "flags": flags, "available": True}


# ---------------------------------------------------------------------------
# 6. TEMP files and named pipe
# ---------------------------------------------------------------------------
def scan_temp_and_pipes(profiles: Iterable[str], budget: Optional[Budget] = None) -> Dict[str, Any]:
    findings: List[Finding] = []
    files: List[Dict[str, Any]] = []
    pipes: List[str] = []
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    temp_dirs = set()
    for profile in profiles:
        temp_dirs.add(os.path.join(profile, "AppData", "Local", "Temp"))
    for env_name in ("TEMP", "TMP"):
        value = os.environ.get(env_name)
        if value:
            temp_dirs.add(os.path.realpath(value))
    for temp_dir in temp_dirs:
        if not os.path.isdir(temp_dir):
            continue
        for pattern, label in iocs.TEMP_PATTERNS:
            for path in glob.glob(os.path.join(temp_dir, pattern))[:50]:
                if budget is not None and budget.expired():
                    break
                if not os.path.isfile(path):
                    continue
                digest = _hash(path)
                known, severity = _hash_verdict(digest)
                record = {"path": path, "label": label, "sha256": digest, "known": known, "size": os.path.getsize(path)}
                files.append(record)
                if pattern in ("k2f*.lua", "insight.bundle"):
                    flags["download"] = True
                    severity = "critical"
                elif pattern.startswith("k2f"):
                    flags["agent"] = True
                    severity = "critical"
                else:
                    severity = severity or "high"
                _add(
                    findings,
                    "TEMP 中存在 K2F 运行痕迹",
                    severity or "high",
                    f"{label}：{os.path.basename(path)}。代理用后立即删除，残留文件表示操作发生在该文件生成的时间。",
                    path,
                    record,
                )
    try:
        for name in os.listdir(r"\\.\pipe"):
            lower = name.casefold()
            if "k2f" in lower or "insight" in lower:
                pipes.append(name)
                flags["active"] = True
                _add(
                    findings,
                    "存在 K2F 命名管道",
                    "critical",
                    "k2f_chan 表示启动器/代理当前正在运行；重启会清除管道，但不会清除持久化。",
                    os.path.join(r"\\.\pipe", name),
                    {"pipe": name},
                )
    except OSError:
        pass
    return {"findings": [item.to_dict() for item in findings], "files": files, "pipes": pipes, "flags": flags}


# ---------------------------------------------------------------------------
# 7. hosts, DNS cache, live connections
# ---------------------------------------------------------------------------
def _run_quiet(args: List[str], timeout: int = 25) -> str:
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return _decode(proc.stdout or b"")
    except Exception:
        return ""


def scan_hosts_dns() -> Dict[str, Any]:
    findings: List[Finding] = []
    records: Dict[str, Any] = {"hosts": [], "dns": []}
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    hosts_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    text = read_text_safe(hosts_path, max_bytes=4 * 1024 * 1024)
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lower = stripped.casefold()
        for domain in iocs.C2_DOMAINS:
            if domain not in lower:
                continue
            loopback = "127.0.0.1" in lower or "::1" in lower or "0.0.0.0" in lower
            record = {"line": number, "content": stripped[:300], "domain": domain, "loopback": loopback}
            records["hosts"].append(record)
            flags["loader"] = True
            _add(
                findings,
                "hosts 中存在 insightjs 域名映射",
                "medium" if loopback else "high",
                "指向回环通常是事后阻断（仍说明曾被处理过）；指向其他地址则是主动劫持/代理。",
                hosts_path,
                record,
            )
    dns_text = _run_quiet(["ipconfig", "/displaydns"], timeout=30)
    if dns_text:
        lower = dns_text.casefold()
        for domain in iocs.C2_DOMAINS:
            if domain not in lower:
                continue
            count = lower.count(domain)
            records["dns"].append({"domain": domain, "count": count})
            flags["loader"] = True
            if domain.startswith("analytics."):
                flags["agent"] = True
            _add(
                findings,
                "DNS 缓存中仍有 insightjs 查询记录",
                "medium",
                "说明本机近期解析过该域名。DNS 缓存会过期，没有记录不能排除感染。",
                "",
                {"domain": domain, "occurrences": count},
            )
    return {"findings": [item.to_dict() for item in findings], "records": records, "dns_available": bool(dns_text), "flags": flags}


def scan_connections() -> Dict[str, Any]:
    findings: List[Finding] = []
    hits: List[Dict[str, Any]] = []
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    text = _run_quiet(["netstat", "-ano"], timeout=30)
    for line in text.splitlines():
        if not any(ip in line for ip in iocs.C2_IPS):
            continue
        record = {"line": line.strip()[:300]}
        hits.append(record)
        flags["active"] = True
        _add(
            findings,
            "存在与 insightjs C2 IP 的 TCP 连接",
            "critical",
            "本机与已知攻击者 IP 存在套接字；请立即断网并保全内存/磁盘证据。",
            line.strip()[:200],
            record,
        )
    return {"findings": [item.to_dict() for item in findings], "hits": hits, "flags": flags, "checked": bool(text)}


# ---------------------------------------------------------------------------
# 8. Loaded modules
# ---------------------------------------------------------------------------
def scan_modules(modules_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    findings: List[Finding] = []
    records: List[Dict[str, Any]] = []
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    if not isinstance(modules_data, dict):
        return {"findings": [], "records": records, "flags": flags}
    for module in modules_data.get("modules", []) or []:
        path = str(module.get("path", "") or "")
        lower = path.casefold()
        name = os.path.basename(lower)
        hit = (
            name == "platform_experience_helper.dll"
            or "platformexperiencehelper" in lower
            or re.search(r"\\[0-9a-f]{64}\\", lower)
            or "k2f" in name
        )
        if not hit:
            continue
        flags["active"] = True
        records.append(module)
        _add(
            findings,
            "运行中的进程加载了 K2F 相关模块",
            "critical",
            "该模块位于浏览器/用户可写目录，是第 2 阶段持久化或代理组件；正常 Chrome 组件是 Program Files 下的 EXE。",
            path,
            {"process": module.get("process"), "pid": module.get("pid"), "module": module.get("module")},
        )
    return {"findings": [item.to_dict() for item in findings], "records": records, "flags": flags}


# ---------------------------------------------------------------------------
# 9. NTFS USN journal (deleted payload evidence)
# ---------------------------------------------------------------------------
_USN_TIME = re.compile(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})[ T](\d{1,2}):(\d{2}):(\d{2})")


def scan_usn(launchers: Sequence[Dict[str, Any]], seconds: float = 60.0) -> Dict[str, Any]:
    findings: List[Finding] = []
    records: List[Dict[str, Any]] = []
    flags = {"loader": False, "download": False, "agent": False, "active": False}
    if not _is_admin():
        return {
            "findings": [],
            "records": records,
            "flags": flags,
            "available": False,
            "reason": "需要管理员权限才能读取 USN 更改日志",
            "drives": [],
        }
    fsutil = shutil.which("fsutil") or os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "fsutil.exe")
    if not os.path.isfile(fsutil):
        return {"findings": [], "records": records, "flags": flags, "available": False, "reason": "找不到 fsutil.exe", "drives": []}
    drives = ["C:\\"]
    for launcher in launchers:
        drive = os.path.splitdrive(str(launcher.get("root", "")))[0]
        if drive and (drive + "\\") not in drives:
            drives.append(drive + "\\")
    deadline = time.monotonic() + max(10.0, seconds)
    for drive in drives:
        if time.monotonic() > deadline:
            break
        entry: Dict[str, Any] = {
            "drive": drive,
            "scanned_lines": 0,
            "truncated": False,
            "coverage_from": "",
            "coverage_to": "",
            "matches": [],
            "error": "",
        }
        counts: Dict[str, int] = {}
        samples: Dict[str, List[str]] = {}
        first_seen = ""
        last_seen = ""
        handled = False
        try:
            proc = subprocess.Popen(
                # fsutil takes the volume as "C:" (a trailing backslash is an error).
                [fsutil, "usn", "readjournal", drive.rstrip("\\/") or drive, "csv"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            entry["error"] = str(exc)
            records.append(entry)
            continue
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                handled = True
                entry["scanned_lines"] += 1
                if entry["scanned_lines"] >= 400000:
                    entry["truncated"] = True
                    break
                if entry["scanned_lines"] % 512 == 0 and time.monotonic() > deadline:
                    entry["truncated"] = True
                    break
                lower = line.casefold()
                matched = False
                for pattern, label, severity in iocs.USN_PATTERNS:
                    if pattern in lower:
                        counts[pattern] = counts.get(pattern, 0) + 1
                        if len(samples.setdefault(pattern, [])) < 2:
                            samples[pattern].append(line.strip()[:280])
                        matched = True
                        if pattern in ("k2f-bcreds", "k2f_screen", "k2f-keyscan", "k2f.lua"):
                            flags["agent"] = True
                        elif pattern in ("insight.bundle", "tinyget."):
                            flags["download"] = True
                        elif pattern == "platform_experience_helper.dll":
                            # The file is gone from disk, so this is execution
                            # evidence, not an "active" module indicator.
                            flags["agent"] = True
                if matched or entry["scanned_lines"] % 256 == 0 or entry["scanned_lines"] <= 20:
                    if line and line[0].isdigit():
                        found = _USN_TIME.search(line[:160])
                        if found:
                            stamp = "{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(
                                int(found.group(1)), int(found.group(2)), int(found.group(3)),
                                int(found.group(4)), int(found.group(5)), int(found.group(6)),
                            )
                            if not first_seen:
                                first_seen = stamp
                            last_seen = stamp
        finally:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        proc.kill()
            except Exception:
                pass
        entry["coverage_from"] = first_seen
        entry["coverage_to"] = last_seen
        if first_seen and first_seen[:10] > iocs.INCIDENT_WINDOW_START:
            entry["coverage_warning"] = (
                f"该盘 USN 日志只能追溯到 {first_seen}，无法覆盖 {iocs.INCIDENT_WINDOW_START} 以来的事件窗口；"
                "没有命中不代表没发生。"
            )
        entry["matches"] = [
            {"pattern": pattern, "label": label, "count": counts[pattern], "samples": samples.get(pattern, [])}
            for pattern, label, _severity in iocs.USN_PATTERNS
            if counts.get(pattern)
        ]
        if not handled:
            entry["error"] = "fsutil 未返回数据（可能未启用 USN 或被策略禁止）"
        records.append(entry)
        if entry["matches"]:
            _add(
                findings,
                "USN 更改日志中发现 K2F 删除痕迹",
                "high",
                "代理和 browserscan 的文件用后立即删除；USN 日志证明这些文件名在该盘出现过。"
                "这只是文件名证据：同名的测试文件、其他程序也可能造成，需结合时间与其他证据判断。"
                "没有命中只代表日志已循环覆盖，不代表干净。",
                drive,
                entry,
            )
    return {"findings": [item.to_dict() for item in findings], "records": records, "flags": flags, "available": True, "reason": "", "drives": drives}


# ---------------------------------------------------------------------------
# 10. Credential inventory (what the payload goes after)
# ---------------------------------------------------------------------------
def _expand(pattern: str) -> str:
    value = pattern
    if value.startswith("~"):
        profile = os.environ.get("USERPROFILE", "")
        value = profile + value[1:]
    value = os.path.expandvars(value)
    return os.path.normpath(value) if value else ""


def _category(path: str) -> str:
    lower = path.casefold()
    if any(key in lower for key in (
        ".claude", "\\claude", "codex", ".gemini", "\\.kimi", "\\cursor", "windsurf", "\\.continue",
        "\\qwen", "aider", "dsh", "copilot", "mcp", "anthropic", "code\\user", "code - insiders",
    )):
        return "AI 工具 / AI Agent 配置"
    if any(key in lower for key in (".ssh", "gnupg", "private-keys", "\\age\\", "\\.keys", "\\.certs")):
        return "SSH / GPG / 私钥"
    if any(key in lower for key in ("wallet", "metamask", "exodus")):
        return "钱包"
    if any(key in lower for key in ("user data", "opera stable", "firefox\\profiles")):
        return "浏览器数据"
    if any(key in lower for key in (
        "aws", "azure", "gcloud", "cloudsdk", "oci", "oraclebmc", "terraform", "pulumi", "kube", "helm",
        "docker", "github cli", "glab", "snowflake", "databricks", "vercel", "netlify", "stripe",
        "cloudflare", "wrangler", "supabase", "neonctl", "railway", "\\.fly", "linode", "doctl",
        "hcloud", "tccli", "bce", "aliyun", "volcengine", "ncloud", "jfrog", "argocd", "circleci",
        "buildkite", "jenkins", "gitlab-runner", "atlascli", "octopus", "sentry", "twilio", "rclone",
        "s3cmd", "b2_account", "firebase", "snyk", "modal", "runpod", "dbt", "expo", "planetscale",
    )):
        return "云 / DevOps 凭据"
    if any(key in lower for key in (
        "npmrc", "yarnrc", "pypirc", "pip.ini", "gem\\credentials", "cargo", "m2\\settings", "gradle",
        "sbt", "nuget", "composer", "pub-credentials", "netrc", "kaggle", "huggingface", "hf_home",
        "gitconfig", "git-credentials", "semgrep", "user secrets",
    )):
        return "包管理器 / 代码托管"
    if any(key in lower for key in ("history", "profile.ps1", "fish_history")):
        return "Shell 历史 / 配置"
    if any(key in lower for key in (
        "filezilla", "winscp", "putty", "pgpass", "pg_service", "psql_history", "postgresql",
        "mysql_history", "sqlite_history", "rediscli_history",
    )):
        return "数据库 / 远程访问"
    if "nikke_launcher" in lower:
        return "启动器数据"
    if any(key in lower for key in ("\\desktop", "\\documents", "\\code", "\\dev", "\\source", "\\programming")):
        return "项目目录（.env / MCP 配置）"
    return "其他"


def _project_secrets(directory: str, budget: Budget) -> List[str]:
    hits: List[str] = []
    if not os.path.isdir(directory):
        return hits
    count = 0
    deadline = time.monotonic() + 4.0
    base_depth = directory.rstrip("\\/").count(os.sep)
    for dirpath, dirnames, filenames in os.walk(directory):
        if time.monotonic() > deadline or budget.expired():
            break
        if dirpath.rstrip("\\/").count(os.sep) - base_depth >= 3:
            dirnames[:] = []
        dirnames[:] = [name for name in dirnames if name.casefold() not in (
            "node_modules", ".git", "dist", "build", "target", ".venv", "venv", "__pycache__", "site-packages",
        )][:40]
        for name in filenames:
            count += 1
            if count > 20000:
                break
            lower = name.casefold()
            if lower in iocs.PROJECT_SECRET_NAMES or lower.startswith(".env.") or lower.endswith(".env"):
                hits.append(os.path.join(dirpath, name))
                if len(hits) >= 40:
                    break
        if len(hits) >= 40:
            break
    return hits


def scan_credential_exposure(
    profiles: Iterable[str],
    wallets: Sequence[Dict[str, Any]],
    budget: Optional[Budget] = None,
) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    seen = set()
    for pattern in iocs.SENSITIVE_PATHS:
        expanded = _expand(pattern)
        if not expanded:
            continue
        matches: List[str] = []
        if "*" in expanded:
            matches = glob.glob(expanded)[:40]
        elif os.path.isfile(expanded) or os.path.isdir(expanded):
            matches = [expanded]
        for path in matches:
            key = canonical_key(path)
            if not key or key in seen:
                continue
            seen.add(key)
            try:
                stat = os.stat(path)
                is_dir = os.path.isdir(path)
                size = 0 if is_dir else stat.st_size
                mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))
            except OSError:
                continue
            items.append({
                "path": path,
                "category": _category(path),
                "is_dir": is_dir,
                "size": size,
                "size_human": "" if is_dir else human_size(size),
                "mtime": mtime,
                "pattern": pattern,
            })
    project_secrets: List[str] = []
    if budget is None or not budget.expired():
        for profile in profiles:
            for name in ("code", "dev", "source", "Programming"):
                directory = os.path.join(profile, name)
                project_secrets.extend(_project_secrets(directory, budget or Budget(10)))
                if len(project_secrets) >= 60:
                    break
            if len(project_secrets) >= 60:
                break
    for path in project_secrets:
        key = canonical_key(path)
        if key in seen:
            continue
        seen.add(key)
        try:
            stat = os.stat(path)
            items.append({
                "path": path,
                "category": "项目目录（.env / MCP 配置）",
                "is_dir": False,
                "size": stat.st_size,
                "size_human": human_size(stat.st_size),
                "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "pattern": "keyscan 项目搜索",
            })
        except OSError:
            continue
    env_set = [name for name in iocs.SENSITIVE_ENV_VARS if os.environ.get(name)]
    registry: List[Dict[str, Any]] = []
    if winreg is not None:
        for key_path in iocs.SENSITIVE_REGISTRY:
            registry.append({"key": key_path, "exists": _registry_exists(key_path)})
        for label, key_path in (
            ("PuTTY 会话", r"Software\SimonTatham\PuTTY\Sessions"),
            ("WinSCP 会话", r"Software\Martin Prikryl\WinSCP 2\Sessions"),
        ):
            count = _count_subkeys(key_path)
            if count:
                registry.append({"key": key_path, "exists": True, "subkeys": count, "label": label})
    categories: Dict[str, int] = {}
    for item in items:
        categories[item["category"]] = categories.get(item["category"], 0) + 1
    return {
        "findings": [],
        "items": items,
        "total": len(items),
        "categories": categories,
        "env_set": env_set,
        "registry": registry,
        "wallets": list(wallets),
        "project_secrets": project_secrets[:60],
    }


def _registry_exists(key_path: str) -> bool:
    if winreg is None:
        return False
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
    except OSError:
        return False
    try:
        return True
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def _empty_flags() -> Dict[str, bool]:
    return {"loader": False, "download": False, "agent": False, "active": False}


def _safe(label: str, func, errors: List[str], default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        return func()
    except Exception as exc:  # keep the rest of the scan usable
        errors.append(f"{label}: {exc}")
        fallback = {"findings": [], "flags": _empty_flags()}
        if default:
            fallback.update(default)
        return fallback


def _dedupe(findings: Sequence[Finding]) -> List[Finding]:
    seen = set()
    result = []
    for item in findings:
        key = (item.title, canonical_key(item.path), item.severity)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def scan_incident(
    processes: Optional[List[Dict[str, Any]]] = None,
    modules_data: Optional[Dict[str, Any]] = None,
    usn: bool = True,
    budget_seconds: float = 240.0,
) -> Dict[str, Any]:
    started = now_iso()
    started_monotonic = time.monotonic()
    profiles = _user_profiles()
    launchers = discover_launchers(processes)
    data_dirs = _launcher_data_dirs(profiles)
    budget = Budget(budget_seconds)
    errors: List[str] = []

    debug = _safe("debug_logs", lambda: scan_debug_logs(launchers), errors, {"files": []})
    tinyget = _safe("tinyget", lambda: scan_tinyget(launchers, budget), errors, {"files": [], "dirs": []})
    code_cache = _safe("code_cache", lambda: scan_code_cache(data_dirs, budget), errors, {"entries": [], "hits": [], "scanned": 0})
    http_cache = _safe("http_cache", lambda: scan_http_cache(data_dirs, budget), errors, {"hits": [], "scanned": 0, "decompressed": 0})
    local_storage = _safe("local_storage", lambda: scan_local_storage(data_dirs, budget), errors, {"hits": [], "scanned": 0})
    browser = _safe("browser", lambda: scan_browser(profiles, budget), errors, {"artifacts": [], "wallets": []})
    browser_config = _safe(
        "browser_config",
        lambda: scan_browser_config(profiles),
        errors,
        {"records": {"policies": [], "native_messaging": [], "profiles": [], "clsid": []}},
    )
    clsid = _safe("clsid", lambda: scan_clsid(), errors, {"records": [], "available": False})
    temp = _safe("temp_pipes", lambda: scan_temp_and_pipes(profiles, budget), errors, {"files": [], "pipes": []})
    hosts_dns = _safe("hosts_dns", lambda: scan_hosts_dns(), errors, {"records": {"hosts": [], "dns": []}})
    connections = _safe("connections", lambda: scan_connections(), errors, {"hits": []})
    modules = _safe("modules", lambda: scan_modules(modules_data), errors, {"records": []})
    if usn:
        usn_block = _safe("usn", lambda: scan_usn(launchers, min(90.0, max(20.0, budget.left()))), errors, {"records": [], "available": False, "reason": "", "drives": []})
    else:
        usn_block = {"findings": [], "records": [], "flags": _empty_flags(), "available": False, "reason": "已按参数跳过", "drives": []}
    credentials = _safe(
        "credential_exposure",
        lambda: scan_credential_exposure(profiles, browser.get("wallets", []) or [], budget),
        errors,
        {"items": [], "total": 0, "categories": {}, "env_set": [], "registry": [], "wallets": []},
    )

    flags = _empty_flags()
    strong_flags = _empty_flags()
    for block in (debug, tinyget, code_cache, http_cache, local_storage, browser, browser_config, clsid, temp, hosts_dns, connections, modules, usn_block):
        for key, value in (block.get("flags") or {}).items():
            if value:
                flags[key] = True
    for block in (debug, tinyget, code_cache, http_cache, local_storage, browser, browser_config, clsid, temp, hosts_dns, connections, modules):
        for key, value in (block.get("flags") or {}).items():
            if value:
                strong_flags[key] = True
    strong = any(strong_flags.values())

    findings: List[Finding] = []
    allowed = {"title", "severity", "category", "detail", "path", "source", "evidence", "recommendation"}
    for block in (debug, tinyget, code_cache, http_cache, local_storage, browser, browser_config, clsid, temp, hosts_dns, connections, modules, usn_block):
        for item in block.get("findings", []) or []:
            data = {key: value for key, value in dict(item).items() if key in allowed}
            try:
                findings.append(Finding(**data))
            except TypeError:
                continue

    # A running launcher means the official "fix" can delete the evidence.
    running = []
    for proc in processes or []:
        name = os.path.basename(str(proc.get("path", "") or "")).casefold()
        if name in iocs.LAUNCHER_EXE_NAMES or name == "tbs_browser.exe":
            running.append({"pid": proc.get("pid"), "name": proc.get("name"), "path": proc.get("path")})
    if running:
        _add(
            findings,
            "启动器/内置浏览器正在运行",
            "high",
            "代理只在启动器运行时活动；同时 2026-11-05 之后的官方客户端会在启动时删除 debug.log、DLL 与注册表项。"
            "先复制证据（Launcher\\intl_service\\debug.log、Launcher\\log、%APPDATA%\\nikke_launcher*\\tbs_cache 与 TEMP 中的 k2f* 文件），再关闭，并且不要再次打开启动器。",
            str(running[0].get("path", "")),
            {"processes": running},
        )

    if flags["active"]:
        stage = 4
    elif flags["agent"]:
        stage = 3
    elif flags["download"]:
        stage = 2
    elif flags["loader"]:
        stage = 1
    else:
        stage = 0

    stage_labels = {
        0: "第 0 阶段：未发现本次事件的公开痕迹",
        1: "第 1 阶段：发现加载器运行痕迹",
        2: "第 2 阶段：发现载荷下载痕迹",
        3: "第 3 阶段：确认代理执行（按失陷处理）",
        4: "第 4 阶段：发现当前驻留/活跃指标（按完全失陷处理）",
    }
    status_labels = {
        0: "未发现公开 IOC",
        1: "加载器接触/运行痕迹，需人工核对",
        2: "观察到恶意载荷下载，执行未确认",
        3: "代理执行确认，主机应按失陷处置",
        4: "存在当前驻留/活跃指标，主机应按完全失陷处置",
    }
    stage_label = stage_labels[stage]
    status_label = status_labels[stage]
    if stage >= 3 and not strong:
        stage_label = f"第 {stage} 阶段：仅发现已删除文件的名称证据（USN）"
        status_label = "仅在 USN 日志中发现已删除的 K2F 文件名，需人工核对"

    # Credential exposure severity depends on the stage.
    total_credentials = int(credentials.get("total", 0) or 0)
    if total_credentials:
        categories = credentials.get("categories", {}) or {}
        top = ", ".join(f"{name} {count}" for name, count in sorted(categories.items(), key=lambda item: -item[1])[:6])
        strong_critical = any(item.severity == "critical" for item in findings)
        if strong_critical:
            severity = "critical"
        elif stage >= 2:
            severity = "high"
        else:
            severity = "low"
        detail = (
            f"本机存在 {total_credentials} 个 insight.bundle 会主动读取的凭据/配置文件（{top}）。"
            "本工具只检查是否存在，不读取内容。"
        )
        if stage >= 2:
            detail += " 本机已发现代理下载/执行痕迹，这些凭据必须视为已泄露并全部轮换。"
        else:
            detail += " 若本机曾打开过受影响的启动器，也要按已泄露处理。"
        _add(
            findings,
            "凭据暴露面：insight.bundle 的目标文件在本机存在",
            severity,
            detail,
            "",
            {
                "total": total_credentials,
                "categories": categories,
                "env_set": credentials.get("env_set", []),
                "wallets": [item.get("name") for item in credentials.get("wallets", []) or []],
                "registry": credentials.get("registry", []),
            },
            "按公开处置建议轮换：SSH/GPG、云厂商密钥、CI/包管理器令牌、AI Agent 配置、浏览器 Cookie（登出所有设备）、"
            "以及钱包（必须新建钱包并转移资产，改密码不能保护助记词）。",
        )

    findings = _dedupe(findings)
    findings.sort(key=lambda item: (-_severity_rank(item.severity), item.title))
    severity = max_severity([item.severity for item in findings])
    elapsed = round(time.monotonic() - started_monotonic, 1)

    notes = [
        "官方修复不完整：截至 2026-11-04 02:01-02:07 UTC 复核，na-webassets.playerinfinite.com 上的 "
        "FeedList.feb647c9.js 仍返回 5,808 字节受污染版本；aegis-fix.min.js 与 images.7fec4c32.js 已修复。"
        "本工具只检查本机，不联网验证 CDN。",
        "仅依赖文件哈希不可靠：chrome_install 会按服务器下发的 base64 重新安装加载器，DLL 也是每个受害者单独构建；"
        "本工具因此同时检查路径、注册表、日志、缓存与 LevelDB。",
        "代理没有计划任务、Run 键、服务或 WMI 持久化；这些位置出现的东西只能来自 exec 命令，不能反过来排除感染。",
        "找不到痕迹不等于没中：官方客户端自 2026-11-05 起会在启动时删除 debug.log 等证据，payload_cleanup 也会删除下载日志；"
        "USN 日志循环覆盖后旧记录会消失。",
        "onominan.tmp（%TEMP% 下 22 字节十六进制文件）不是本事件指标，它来自腾讯其他软件；本工具不会把它当作感染证据。",
        "Proton / Steam Deck：Windows 路径扫描命中很少，但 Wine 会映射整个主目录，exec/cat/download 仍能读取 ~/.ssh、浏览器资料与 API key。",
        "公开的“所有腾讯游戏都被黑”名单来自 4chan 匿名帖，目前只有 NIKKE 启动器被证实加载过该加载器；本工具对其他 Level Infinite 启动器只做同框架检查。",
    ]

    return {
        "generated_at": started,
        "elapsed_seconds": elapsed,
        "verdict": severity,
        "status_label": status_label,
        "stage": stage,
        "stage_label": stage_label,
        "evidence_strength": "strong" if strong else ("forensic-only" if stage else "none"),
        "stage1": stage >= 1,
        "stage2": stage >= 2,
        "stage3": stage >= 3,
        "stage4": stage >= 4,
        "flags": flags,
        "launchers": launchers,
        "data_dirs": data_dirs,
        "profiles": profiles,
        "sections": {
            "debug_logs": debug,
            "tinyget": tinyget,
            "code_cache": code_cache,
            "http_cache": http_cache,
            "local_storage": local_storage,
            "browser": browser,
            "browser_config": browser_config,
            "clsid": clsid,
            "temp_and_pipes": temp,
            "hosts_dns": hosts_dns,
            "connections": connections,
            "modules": modules,
            "usn": usn_block,
            "credentials": credentials,
        },
        "findings": [item.to_dict() for item in findings],
        "counts": {
            "findings": len(findings),
            "launchers": len(launchers),
            "profiles": len(profiles),
            "debug_logs": len(debug.get("files", []) or []),
            "tinyget_files": len(tinyget.get("files", []) or []),
            "code_cache_scanned": code_cache.get("scanned", 0),
            "http_cache_scanned": http_cache.get("scanned", 0),
            "local_storage_scanned": local_storage.get("scanned", 0),
            "browser_artifacts": len(browser.get("artifacts", []) or []),
            "wallets": len(browser.get("wallets", []) or []),
            "browser_profiles": len((browser_config.get("records", {}) or {}).get("profiles", []) or []),
            "native_messaging": len((browser_config.get("records", {}) or {}).get("native_messaging", []) or []),
            "clsid_records": len(clsid.get("records", []) or []),
            "usn_matches": sum(len(item.get("matches", []) or []) for item in usn_block.get("records", []) or []),
            "credentials": total_credentials,
        },
        "errors": errors,
        "notes": notes,
        "reference": {
            "ioc_domains": list(iocs.C2_DOMAINS),
            "ioc_ips": list(iocs.C2_IPS),
            "tampered_assets": [
                {"name": meta["name"], "size": meta["size"], "sha256": digest, "host": meta["host"]}
                for digest, meta in iocs.TAMPERED_ASSETS.items()
            ],
            "payload_assets": [
                {"name": meta["name"], "size": meta["size"], "sha256": digest, "note": meta["note"]}
                for digest, meta in iocs.PAYLOAD_ASSETS.items()
            ],
            "commands": list(iocs.AGENT_COMMANDS),
            "review_snapshot": iocs.REVIEW_SNAPSHOT,
        },
    }


def _severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get((value or "info").lower(), 0)
