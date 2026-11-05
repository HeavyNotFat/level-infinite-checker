from __future__ import annotations

import os
import re
import shutil
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import Finding, max_severity
from .signatures import collect_signatures, is_trusted_third_party, is_valve, signature_for, status_severity
from .utils import (
    canonical_key,
    commandline_flags,
    expand_path,
    extract_executable,
    is_reparse_point,
    is_subpath,
    is_user_writable,
    looks_like_system_binary_masquerade,
    normalize_path,
    now_iso,
    parse_windows_time,
    redact_command_line,
    safe_filename,
    unique_preserve_order,
)
from .weird_dirs import score_name
from .winps import PowerShellError, ps_json, powershell_available

try:
    import winreg
except ImportError:  # pragma: no cover
    winreg = None


PROJECT_ROOT = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXECUTION_SCRIPT = os.path.join(PROJECT_ROOT, "tools", "Get-ExecutionInventory.ps1")
MODULE_SCRIPT = os.path.join(PROJECT_ROOT, "tools", "Get-ProcessModules.ps1")

COMMON_SYSTEM_BINARIES = (
    "cmd.exe", "powershell.exe", "pwsh.exe", "where.exe", "whoami.exe",
    "net.exe", "net1.exe", "reg.exe", "schtasks.exe", "sc.exe", "tasklist.exe",
    "ipconfig.exe", "ping.exe", "curl.exe", "tar.exe", "ssh.exe", "certutil.exe",
    "bitsadmin.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "wmic.exe", "robocopy.exe", "icacls.exe",
)

AUTORUN_KEYS = (
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "PoliciesRun"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunServices", "RunServices"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", "RunServicesOnce"),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "WindowsLoad"),
)

WINLOGON_VALUES = ("Shell", "Userinit", "Taskman", "AppSetup", "VmApplet", "GinaDLL")

PATH_VALUE_NAMES = ("Path", "PSModulePath")
SELF_EXE_KEY = canonical_key(sys.executable) if getattr(sys, "frozen", False) else ""


def _reg_view(view: int) -> int:
    return view


def _open(hive, path: str, view: int = 0):
    if winreg is None:
        return None
    try:
        return winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view)
    except OSError:
        return None


def _values(key) -> List[Tuple[str, Any, int]]:
    result = []
    if key is None:
        return result
    index = 0
    while True:
        try:
            name, value, value_type = winreg.EnumValue(key, index)
        except OSError:
            break
        result.append((name, value, value_type))
        index += 1
    return result


def _subkeys(key) -> List[str]:
    result = []
    if key is None:
        return result
    index = 0
    while True:
        try:
            result.append(winreg.EnumKey(key, index))
        except OSError:
            break
        index += 1
    return result


def _default(key) -> str:
    if key is None:
        return ""
    try:
        value, _ = winreg.QueryValueEx(key, "")
        return str(value)
    except OSError:
        return ""


def _resolve_executable(value: str) -> Tuple[str, str]:
    raw = (value or "").strip()
    if not raw:
        return "", ""
    # NT object-manager prefixes used by services/drivers.
    if raw.startswith("\\??\\"):
        raw = raw[4:]
    if raw.startswith("\\\\?\\"):
        raw = raw[4:]
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    if raw.lower().startswith("\\systemroot\\"):
        raw = system_root + raw[len("\\systemroot"):]
    elif raw.lower().startswith("systemroot\\"):
        raw = system_root + "\\" + raw[len("systemroot\\"):]
    raw = raw.replace("%SystemRoot%", system_root)
    exe, args = extract_executable(raw)
    exe = expand_path(exe)
    if not exe:
        return "", args
    if not os.path.isabs(exe):
        candidate = shutil.which(exe)
        if not candidate:
            for base in (
                os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"),
                os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64"),
                os.environ.get("SystemRoot", r"C:\Windows"),
            ):
                candidate = os.path.join(base, exe)
                if os.path.isfile(candidate):
                    break
                candidate = ""
        if candidate:
            exe = candidate
    return normalize_path(exe), args


def _collect_autoruns() -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    if winreg is None:
        return {"records": records, "errors": ["winreg unavailable"]}

    locations = []
    for view, view_label in (
        (getattr(winreg, "KEY_WOW64_64KEY", 0), "64"),
        (getattr(winreg, "KEY_WOW64_32KEY", 0), "32"),
    ):
        for key_path, label in AUTORUN_KEYS:
            locations.append(("HKLM", winreg.HKEY_LOCAL_MACHINE, key_path, view, view_label, label))
    for key_path, label in AUTORUN_KEYS:
        locations.append(("HKCU", winreg.HKEY_CURRENT_USER, key_path, 0, "default", label))

    for hive_label, hive, key_path, view, view_label, label in locations:
        key = _open(hive, key_path, view)
        if key is None:
            continue
        try:
            for name, value, value_type in _values(key):
                if label == "WindowsLoad" and name not in ("load", "run"):
                    continue
                if label != "WindowsLoad" and (not name or name.startswith("-")):
                    continue
                command = str(value)
                if not command.strip():
                    continue
                exe, args = _resolve_executable(command)
                records.append({
                    "source": label,
                    "hive": hive_label,
                    "key": key_path,
                    "view": view_label,
                    "name": name or "(default)",
                    "command": redact_command_line(command),
                    "raw_command": command,
                    "executable": exe,
                    "arguments": args,
                    "exists": os.path.isfile(exe) if exe else False,
                })
        except OSError as exc:
            errors.append(f"{hive_label}\\{key_path}: {exc}")
        finally:
            try:
                winreg.CloseKey(key)
            except OSError:
                pass

    # Winlogon values.
    for view, view_label in (
        (getattr(winreg, "KEY_WOW64_64KEY", 0), "64"),
        (getattr(winreg, "KEY_WOW64_32KEY", 0), "32"),
    ):
        key = _open(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", view)
        if key is None:
            continue
        for name, value, _ in _values(key):
            if name not in WINLOGON_VALUES:
                continue
            command = str(value)
            exe, args = _resolve_executable(command)
            records.append({
                "source": "Winlogon",
                "hive": "HKLM",
                "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "view": view_label,
                "name": name,
                "command": redact_command_line(command),
                "raw_command": command,
                "executable": exe,
                "arguments": args,
                "exists": os.path.isfile(exe) if exe else False,
            })
        try:
            winreg.CloseKey(key)
        except OSError:
            pass

    # IFEO entries with a Debugger or VerifierDlls value.
    for view, view_label in (
        (getattr(winreg, "KEY_WOW64_64KEY", 0), "64"),
        (getattr(winreg, "KEY_WOW64_32KEY", 0), "32"),
    ):
        base_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        base = _open(winreg.HKEY_LOCAL_MACHINE, base_path, view)
        if base is None:
            continue
        for sub_name in _subkeys(base):
            sub_path = base_path + "\\" + sub_name
            sub = _open(winreg.HKEY_LOCAL_MACHINE, sub_path, view)
            if sub is None:
                continue
            values = {name: value for name, value, _ in _values(sub)}
            try:
                winreg.CloseKey(sub)
            except OSError:
                pass
            command = values.get("Debugger") or values.get("VerifierDlls")
            if not command:
                continue
            exe, args = _resolve_executable(str(command))
            records.append({
                "source": "IFEO",
                "hive": "HKLM",
                "key": sub_path,
                "view": view_label,
                "name": sub_name,
                "command": redact_command_line(str(command)),
                "raw_command": str(command),
                "executable": exe,
                "arguments": args,
                "exists": os.path.isfile(exe) if exe else False,
            })
        try:
            winreg.CloseKey(base)
        except OSError:
            pass

    # App Paths entries: these influence CreateProcess lookup.
    for view, view_label in (
        (getattr(winreg, "KEY_WOW64_64KEY", 0), "64"),
        (getattr(winreg, "KEY_WOW64_32KEY", 0), "32"),
    ):
        for hive_label, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
            base_path = r"Software\Microsoft\Windows\CurrentVersion\App Paths"
            base = _open(hive, base_path, view)
            if base is None:
                continue
            for sub_name in _subkeys(base)[:500]:
                sub_path = base_path + "\\" + sub_name
                sub = _open(hive, sub_path, view)
                if sub is None:
                    continue
                command = _default(sub)
                try:
                    winreg.CloseKey(sub)
                except OSError:
                    pass
                if not command:
                    continue
                exe, args = _resolve_executable(command)
                records.append({
                    "source": "AppPaths",
                    "hive": hive_label,
                    "key": sub_path,
                    "view": view_label,
                    "name": sub_name,
                    "command": redact_command_line(command),
                    "raw_command": command,
                    "executable": exe,
                    "arguments": args,
                    "exists": os.path.isfile(exe) if exe else False,
                })
            try:
                winreg.CloseKey(base)
            except OSError:
                pass

    return {"records": records, "errors": errors}


def _read_env_path() -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    if winreg is None:
        return {"entries": entries, "errors": ["winreg unavailable"]}
    locations = [
        ("machine", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("user", winreg.HKEY_CURRENT_USER, r"Environment", 0),
    ]
    for scope, hive, key_path, view in locations:
        key = _open(hive, key_path, view)
        if key is None:
            continue
        value = ""
        for name, data, _ in _values(key):
            if name.casefold() == "path":
                value = str(data)
                break
        try:
            winreg.CloseKey(key)
        except OSError:
            pass
        raw_parts = value.split(";") if value else []
        for index, raw in enumerate(raw_parts):
            raw = raw.strip()
            expanded = expand_path(raw)
            kind = "directory"
            exists = bool(expanded) and os.path.isdir(expanded)
            if not raw:
                kind = "empty"
            elif raw == ".":
                kind = "current-directory"
            elif raw.startswith("\\\\"):
                kind = "unc"
            elif not os.path.isabs(expanded):
                kind = "relative"
            elif not exists:
                kind = "missing"
            entries.append({
                "scope": scope,
                "index": index,
                "raw": raw,
                "expanded": expanded,
                "kind": kind,
                "exists": exists,
                "user_writable": is_user_writable(expanded) if expanded else False,
            })
    return {"entries": entries, "errors": []}


def _analyze_path(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings: List[Finding] = []
    hijacks: List[Dict[str, Any]] = []
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    system32 = os.path.join(system_root, "System32")
    system32_key = canonical_key(system32)
    system32_index = next((entry["index"] for entry in entries if canonical_key(entry.get("expanded", "")) == system32_key), None)

    for entry in entries:
        raw = entry.get("raw", "")
        expanded = entry.get("expanded", "")
        index = entry.get("index", 0)
        if entry.get("kind") in ("empty", "current-directory", "relative"):
            findings.append(Finding(
                title="PATH 包含空项、相对路径或当前目录",
                severity="high" if entry.get("kind") == "current-directory" else ("medium" if entry.get("kind") == "relative" else "low"),
                category="Execution",
                detail="Windows 会按 PATH 顺序查找程序；空项/当前目录可导致当前目录中的同名程序被执行。",
                path=raw,
                source="execution",
                evidence={"scope": entry.get("scope"), "index": index, "entry": entry},
                recommendation="从用户/系统 PATH 中移除空项和相对路径（尤其是 .）。",
            ))
            continue
        if not entry.get("exists") and entry.get("kind") == "missing":
            continue
        before_system32 = system32_index is None or index < system32_index
        if not before_system32:
            continue
        if not entry.get("user_writable"):
            continue
        shadowed = []
        for name in COMMON_SYSTEM_BINARIES:
            candidate = os.path.join(expanded, name)
            if os.path.isfile(candidate):
                shadowed.append(candidate)
        if shadowed:
            hijacks.append({"entry": entry, "shadowed": shadowed})
            findings.append(Finding(
                title="PATH 中用户可写目录可能劫持系统命令",
                severity="high",
                category="Execution",
                detail="该目录位于 System32 之前，且包含与 Windows 系统命令同名的程序。",
                path=expanded,
                source="execution",
                evidence={"entry": entry, "shadowed": shadowed},
                recommendation="确认这些程序来源；非预期时调整 PATH 顺序或移除该目录。",
            ))
        else:
            findings.append(Finding(
                title="PATH 中 System32 之前存在用户可写目录",
                severity="low",
                category="Execution",
                detail="不一定是恶意，但会扩大命令劫持面。",
                path=expanded,
                source="execution",
                evidence={"entry": entry},
                recommendation="确认该目录确有必要；尽量放在 System32 之后。",
            ))
    return {"findings": [item.to_dict() for item in findings], "hijacks": hijacks}


def _collect_protocol_handlers() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if winreg is None:
        return records
    for protocol in ("steam", "http", "https"):
        for hive_label, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
            for view, view_label in (
                (getattr(winreg, "KEY_WOW64_64KEY", 0), "64"),
                (getattr(winreg, "KEY_WOW64_32KEY", 0), "32"),
            ):
                key_path = rf"Software\Classes\{protocol}\shell\open\command"
                key = _open(hive, key_path, view)
                if key is None:
                    continue
                command = _default(key)
                try:
                    winreg.CloseKey(key)
                except OSError:
                    pass
                if not command:
                    continue
                exe, args = _resolve_executable(command)
                records.append({
                    "protocol": protocol,
                    "hive": hive_label,
                    "view": view_label,
                    "key": key_path,
                    "command": redact_command_line(command),
                    "raw_command": command,
                    "executable": exe,
                    "arguments": args,
                    "exists": os.path.isfile(exe) if exe else False,
                })
    return records


def _collect_com_hijacks() -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    if winreg is None:
        return {"records": records, "errors": ["winreg unavailable"]}
    scanned = 0
    for view, view_label in (
        (getattr(winreg, "KEY_WOW64_64KEY", 0), "64"),
        (getattr(winreg, "KEY_WOW64_32KEY", 0), "32"),
    ):
        base_path = r"Software\Classes\CLSID"
        base = _open(winreg.HKEY_CURRENT_USER, base_path, view)
        if base is None:
            continue
        for clsid in _subkeys(base)[:5000]:
            scanned += 1
            for server_name in ("InprocServer32", "LocalServer32"):
                server_path = base_path + "\\" + clsid + "\\" + server_name
                server = _open(winreg.HKEY_CURRENT_USER, server_path, view)
                if server is None:
                    continue
                command = _default(server)
                try:
                    winreg.CloseKey(server)
                except OSError:
                    pass
                if not command:
                    continue
                exe, args = _resolve_executable(command)
                lower = (command + " " + exe).casefold()
                suspicious = (
                    not os.path.isfile(exe)
                    or is_user_writable(exe)
                    or "platformexperiencehelper" in lower
                    or bool(re.search(r"\\[0-9a-f]{64}\\", lower))
                    or clsid.upper() == "{E77CC89B-7401-4C04-8CED-149DB35ADD04}"
                )
                if suspicious:
                    records.append({
                        "clsid": clsid,
                        "server_type": server_name,
                        "hive": "HKCU",
                        "view": view_label,
                        "key": server_path,
                        "command": redact_command_line(command),
                        "raw_command": command,
                        "executable": exe,
                        "arguments": args,
                        "exists": os.path.isfile(exe) if exe else False,
                        "known_k2f": clsid.upper() == "{E77CC89B-7401-4C04-8CED-149DB35ADD04}",
                    })
        try:
            winreg.CloseKey(base)
        except OSError:
            pass
    return {"records": records, "errors": errors, "scanned": scanned}


def _collect_installed() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if winreg is None:
        return records
    roots = [
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", getattr(winreg, "KEY_WOW64_32KEY", 0)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0),
    ]
    seen = set()
    for hive_label, hive, root_path, view in roots:
        parent = _open(hive, root_path, view)
        if parent is None:
            continue
        for sub_name in _subkeys(parent)[:4000]:
            sub_path = root_path + "\\" + sub_name
            sub = _open(hive, sub_path, view)
            if sub is None:
                continue
            values = {name: str(value) for name, value, _ in _values(sub)}
            try:
                winreg.CloseKey(sub)
            except OSError:
                pass
            display = values.get("DisplayName", "").strip()
            if not display:
                continue
            key = (display.casefold(), values.get("DisplayVersion", ""), hive_label)
            if key in seen:
                continue
            seen.add(key)
            records.append({
                "display_name": display,
                "version": values.get("DisplayVersion", ""),
                "publisher": values.get("Publisher", ""),
                "install_location": values.get("InstallLocation", ""),
                "uninstall_string": values.get("UninstallString", ""),
                "display_icon": values.get("DisplayIcon", ""),
                "install_date": values.get("InstallDate", ""),
                "estimated_size": values.get("EstimatedSize", ""),
                "hive": hive_label,
                "key": sub_path,
                "view": "64" if view == getattr(winreg, "KEY_WOW64_64KEY", 0) else ("32" if view == getattr(winreg, "KEY_WOW64_32KEY", 0) else "default"),
            })
        try:
            winreg.CloseKey(parent)
        except OSError:
            pass
    return records


def collect_process_modules() -> Dict[str, Any]:
    if not powershell_available() or not os.path.isfile(MODULE_SCRIPT):
        return {"modules": [], "errors": ["PowerShell 或模块收集脚本不可用"]}
    try:
        data = ps_json(MODULE_SCRIPT, [], timeout=180)
    except PowerShellError as exc:
        return {"modules": [], "errors": [str(exc)]}
    if not isinstance(data, dict):
        return {"modules": [], "errors": ["模块收集脚本返回格式无效"]}
    data.setdefault("modules", [])
    data.setdefault("errors", [])
    return data


def collect_inventory() -> Dict[str, Any]:
    if not powershell_available():
        return {
            "available": False,
            "error": "PowerShell 不可用，无法枚举进程/服务/计划任务/WMI。",
            "processes": [], "services": [], "drivers": [], "tasks": [], "startup": [], "wmi": [], "errors": [],
        }
    try:
        data = ps_json(EXECUTION_SCRIPT, [], timeout=300)
    except PowerShellError as exc:
        return {
            "available": False,
            "error": str(exc),
            "processes": [], "services": [], "drivers": [], "tasks": [], "startup": [], "wmi": [], "errors": [],
        }
    data["available"] = True
    if not isinstance(data.get("errors"), list):
        data["errors"] = []
    return data


def assess_program(
    path: str,
    command: str = "",
    context: str = "",
    signature: Optional[Dict[str, Any]] = None,
    extra_flags: Optional[List[str]] = None,
    hidden: bool = False,
    unquoted: bool = False,
) -> Dict[str, Any]:
    reasons: List[str] = []
    score = 0.0
    path = normalize_path(path)
    exists = os.path.isfile(path) if path else False
    lower = path.casefold()

    if not path:
        return {"score": 0, "severity": "info", "reasons": ["no executable path"], "exists": False}
    if not exists:
        score += 1.0
        reasons.append("可执行文件不存在")
    if is_user_writable(path):
        score += 2.0
        reasons.append("位于用户可写目录")
    if any(fragment in lower for fragment in ("\\temp\\", "\\tmp\\", "\\downloads\\", "\\users\\public\\")):
        score += 2.0
        reasons.append("位于 Temp/Downloads/Public 等高风险管理目录")
    if looks_like_system_binary_masquerade(path):
        score += 8.0
        reasons.append("伪装成 Windows 系统程序")
    if is_reparse_point(path):
        score += 1.0
        reasons.append("路径是重解析点/链接")
    for segment in re.split(r"[\\/]+", path):
        if segment and score_name(segment)["score"] >= 4.0:
            score += 2.0
            reasons.append("路径包含乱码/随机名称片段")
            break

    if signature:
        status = str(signature.get("status", "UnknownError"))
        subject = str(signature.get("subject", ""))
        if status.casefold() == "valid":
            if is_valve(subject) or is_trusted_third_party(subject):
                pass
            else:
                score += 1.0
                reasons.append("签名有效但签发者不是常见可信厂商")
        elif status.casefold() == "notsigned":
            score += 4.0
            reasons.append("文件没有数字签名")
        elif status.casefold() == "missing":
            score += 1.0
            reasons.append("签名信息缺失")
        elif status.casefold() in ("unknownerror", "unknown"):
            score += 2.0
            reasons.append("签名状态未知")
        else:
            score += 8.0
            reasons.append(f"签名校验失败：{status}")
    elif exists:
        score += 1.0
        reasons.append("未能获取签名信息")

    # Only apply command-line heuristics when the target itself is an
    # interpreter/script host.  Otherwise a benign shell (for example a Bash
    # process that happens to contain the words "powershell -File") would be
    # flagged just because its script text mentions PowerShell.
    interpreters = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "curl.exe", "wget.exe", "msiexec.exe", "wmic.exe",
        "schtasks.exe",
    }
    basename = os.path.basename(path).casefold()
    flags = []
    if basename in interpreters or (extra_flags and any("download" in flag.casefold() or "base64" in flag.casefold() for flag in extra_flags)):
        flags = list(dict.fromkeys(list(commandline_flags(command)) + list(extra_flags or [])))
    elif extra_flags:
        flags = list(dict.fromkeys(extra_flags))
    if flags:
        score += min(9.0, 3.0 * len(flags))
        if any(("encoded" in flag.casefold() or "base64" in flag.casefold()) for flag in flags):
            score += 3.0
        reasons.extend(flags)

    if context == "service":
        if unquoted and " " in path:
            score += 2.0
            reasons.append("服务路径含空格但未加引号")
    elif context == "task":
        if hidden:
            score += 2.0
            reasons.append("计划任务被标记为隐藏")
    elif context == "com":
        score += 2.0
        reasons.append("HKCU COM 服务器可由当前用户改写")
    elif context == "wmi":
        score += 4.0
        reasons.append("WMI 事件订阅是罕见的持久化方式")
    elif context == "autostart":
        if path.casefold().endswith((".js", ".jse", ".vbs", ".vbe", ".wsf", ".ps1", ".bat", ".cmd")):
            score += 3.0
            reasons.append("启动项直接执行脚本文件")

    if score >= 12:
        severity = "high"
    elif score >= 7:
        severity = "medium"
    elif score >= 3:
        severity = "low"
    else:
        severity = "info"
    return {
        "score": round(score, 2),
        "severity": severity,
        "reasons": list(dict.fromkeys(reasons)),
        "exists": exists,
        "user_writable": is_user_writable(path),
        "signature_status": (signature or {}).get("status", ""),
        "signer": (signature or {}).get("subject", ""),
    }


def _add_program(
    programs: Dict[str, Dict[str, Any]],
    path: str,
    command: str,
    source: str,
    context: str,
    assessment: Dict[str, Any],
) -> None:
    path = normalize_path(path)
    if not path:
        return
    key = canonical_key(path)
    if key not in programs:
        programs[key] = {
            "path": path,
            "exists": os.path.isfile(path),
            "sources": [],
            "commands": [],
            "max_score": 0,
            "severity": "info",
            "reasons": [],
            "signature": {},
        }
    record = programs[key]
    if source not in record["sources"]:
        record["sources"].append(source)
    if command and command not in record["commands"]:
        record["commands"].append(redact_command_line(command))
    record["max_score"] = max(record["max_score"], assessment.get("score", 0))
    if _severity_rank(assessment.get("severity", "info")) > _severity_rank(record["severity"]):
        record["severity"] = assessment.get("severity", "info")
    for reason in assessment.get("reasons", []):
        if reason not in record["reasons"]:
            record["reasons"].append(reason)


def _severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get((value or "info").lower(), 0)


def build_execution_report(inventory: Dict[str, Any]) -> Dict[str, Any]:
    programs: Dict[str, Dict[str, Any]] = {}
    records: Dict[str, List[Dict[str, Any]]] = {
        "processes": [], "services": [], "drivers": [], "tasks": [], "startup": [],
        "autoruns": [], "com": [], "protocols": [], "wmi": [],
    }
    suspicious: List[Dict[str, Any]] = []
    findings: List[Finding] = []
    errors: List[str] = []
    if inventory.get("error"):
        errors.append(str(inventory["error"]))
    for error in inventory.get("errors", []) or []:
        if isinstance(error, dict):
            errors.append(f"{error.get('context', '')}: {error.get('message', '')}")
        else:
            errors.append(str(error))

    autoruns = _collect_autoruns()
    errors.extend(autoruns.get("errors", []))
    com_data = _collect_com_hijacks()
    errors.extend(com_data.get("errors", []))
    protocols = _collect_protocol_handlers()
    installed = _collect_installed()

    # Unique executable paths for one batched signature call.
    candidates: List[str] = []
    for proc in inventory.get("processes", []) or []:
        path, _ = _resolve_executable(proc.get("path", "") or proc.get("cmdline", ""))
        if path:
            candidates.append(path)
    for service in (inventory.get("services", []) or []) + (inventory.get("drivers", []) or []):
        path, _ = _resolve_executable(service.get("image_path", ""))
        if path:
            candidates.append(path)
    for task in inventory.get("tasks", []) or []:
        for action in task.get("actions", []) or []:
            command = (action.get("execute", "") + " " + action.get("arguments", "")).strip()
            path, _ = _resolve_executable(command)
            if path:
                candidates.append(path)
    for item in inventory.get("startup", []) or []:
        command = item.get("target", "") or item.get("path", "")
        path, _ = _resolve_executable(command)
        if path:
            candidates.append(path)
    for item in autoruns.get("records", []):
        if item.get("executable"):
            candidates.append(item["executable"])
    for item in com_data.get("records", []):
        if item.get("executable"):
            candidates.append(item["executable"])
    for item in protocols:
        if item.get("executable"):
            candidates.append(item["executable"])
    for item in inventory.get("wmi", []) or []:
        path, _ = _resolve_executable(item.get("consumer", ""))
        if path:
            candidates.append(path)
    signatures = collect_signatures(unique_preserve_order(candidates)[:900])

    def assess_record(path: str, command: str, context: str, **kwargs) -> Dict[str, Any]:
        return assess_program(path, command, context, signature_for(path, signatures), **kwargs)

    # Processes.
    for proc in inventory.get("processes", []) or []:
        path, _ = _resolve_executable(proc.get("path", "") or proc.get("cmdline", ""))
        command = proc.get("cmdline", "") or path
        is_self = bool(SELF_EXE_KEY and canonical_key(path) == SELF_EXE_KEY)
        assessment = (
            {"score": 0, "severity": "info", "reasons": ["本工具自身进程，不参与可疑评分"], "exists": True}
            if is_self else assess_record(path, command, "process")
        )
        record = {
            "pid": proc.get("pid"),
            "ppid": proc.get("ppid"),
            "name": proc.get("name"),
            "path": path,
            "command": redact_command_line(command),
            "user": proc.get("user", ""),
            "creation": parse_windows_time(proc.get("creation", "")),
            "assessment": assessment,
        }
        records["processes"].append(record)
        if not is_self:
            _add_program(programs, path, command, "process", "process", assessment)

    # Services / drivers.
    for kind, key in (("service", "services"), ("driver", "drivers")):
        for item in inventory.get(key, []) or []:
            image_path = item.get("image_path", "")
            path, args = _resolve_executable(image_path)
            command = image_path
            unquoted = bool(path and " " in path and not image_path.strip().startswith('"'))
            assessment = assess_record(path, command, "service", unquoted=unquoted)
            record = {
                "kind": kind,
                "name": item.get("name"),
                "display_name": item.get("display_name"),
                "image_path": image_path,
                "path": path,
                "arguments": args,
                "start_mode": item.get("start_mode"),
                "state": item.get("state"),
                "account": item.get("account"),
                "assessment": assessment,
            }
            records["services" if kind == "service" else "drivers"].append(record)
            _add_program(programs, path, command, kind, "service", assessment)

    # Scheduled tasks.
    for task in inventory.get("tasks", []) or []:
        task_path = (task.get("path", "") or "") + (task.get("name", "") or "")
        for action in task.get("actions", []) or []:
            command = (action.get("execute", "") + " " + action.get("arguments", "")).strip()
            path, args = _resolve_executable(command)
            assessment = assess_record(path, command, "task", hidden=bool(task.get("hidden")))
            record = {
                "name": task.get("name"),
                "path": task.get("path"),
                "command": redact_command_line(command),
                "executable": path,
                "arguments": args,
                "run_as": task.get("run_as"),
                "run_level": task.get("run_level"),
                "hidden": bool(task.get("hidden")),
                "state": task.get("state"),
                "author": task.get("author"),
                "assessment": assessment,
            }
            records["tasks"].append(record)
            _add_program(programs, path, command, "task:" + task_path, "task", assessment)

    # Startup folders.
    for item in inventory.get("startup", []) or []:
        target = item.get("target", "") or item.get("path", "")
        command = (target + " " + item.get("arguments", "")).strip()
        path, args = _resolve_executable(command)
        assessment = assess_record(path, command, "autostart")
        record = {
            "scope": item.get("scope"),
            "name": item.get("name"),
            "path": item.get("path"),
            "target": target,
            "arguments": args,
            "url": item.get("url", ""),
            "assessment": assessment,
        }
        records["startup"].append(record)
        _add_program(programs, path, command, "startup:" + str(item.get("name", "")), "autostart", assessment)

    # Registry autoruns.
    for item in autoruns.get("records", []):
        path = item.get("executable", "")
        command = item.get("command", "")
        assessment = assess_record(path, command, "autostart")
        record = dict(item)
        record["assessment"] = assessment
        records["autoruns"].append(record)
        _add_program(programs, path, command, "autorun:" + item.get("source", ""), "autostart", assessment)

    # COM hijacks.
    for item in com_data.get("records", []):
        path = item.get("executable", "")
        command = item.get("command", "")
        assessment = assess_record(path, command, "com")
        record = dict(item)
        record["assessment"] = assessment
        records["com"].append(record)
        _add_program(programs, path, command, "com:" + item.get("clsid", ""), "com", assessment)

    # Protocol handlers.
    for item in protocols:
        path = item.get("executable", "")
        command = item.get("command", "")
        assessment = assess_record(path, command, "protocol")
        record = dict(item)
        record["assessment"] = assessment
        records["protocols"].append(record)
        _add_program(programs, path, command, "protocol:" + item.get("protocol", ""), "protocol", assessment)

    # WMI subscriptions.  EventFilter/Binding entries are metadata, not
    # executable consumers; only CommandLineEventConsumer and
    # ActiveScriptEventConsumer should contribute a program path.
    for item in inventory.get("wmi", []) or []:
        consumer_type = str(item.get("type", ""))
        if consumer_type not in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
            record = dict(item)
            record["executable"] = ""
            record["assessment"] = {"score": 0, "severity": "info", "reasons": ["WMI metadata"], "exists": False}
            records["wmi"].append(record)
            continue
        consumer = item.get("consumer", "") or item.get("query", "")
        path, _ = _resolve_executable(consumer)
        assessment = assess_record(path, consumer, "wmi")
        record = dict(item)
        record["executable"] = path
        record["assessment"] = assessment
        records["wmi"].append(record)
        _add_program(programs, path, consumer, "wmi:" + consumer_type, "wmi", assessment)

    # Build suspicious records and findings.
    for key, items in records.items():
        for item in items:
            assessment = item.get("assessment", {})
            severity = assessment.get("severity", "info")
            if severity in ("medium", "high", "critical"):
                suspicious.append({
                    "kind": key,
                    "name": item.get("name") or item.get("display_name") or item.get("path") or "",
                    "path": item.get("path") or item.get("executable") or "",
                    "command": item.get("command", ""),
                    "severity": severity,
                    "score": assessment.get("score", 0),
                    "reasons": assessment.get("reasons", []),
                    "source": key,
                })

    # PATH findings.
    path_data = _read_env_path()
    path_analysis = _analyze_path(path_data.get("entries", []))
    for item in path_analysis["findings"]:
        data = dict(item)
        data.pop("severity_label", None)
        findings.append(Finding(**data))

    # Installed software anomalies (only strong signals).
    for item in installed:
        command = " ".join(filter(None, [item.get("uninstall_string", ""), item.get("display_icon", "")]))
        flags = commandline_flags(command)
        if flags:
            findings.append(Finding(
                title="安装/卸载命令包含高风险参数",
                severity="high" if len(flags) >= 2 else "medium",
                category="Execution",
                detail="注册表中的卸载/显示图标命令包含脚本下载、隐藏执行或编码命令特征。",
                path=item.get("key", ""),
                source="execution",
                evidence={"software": item, "flags": flags},
                recommendation="核对软件来源；不要直接运行该卸载命令。",
            ))

    for finding in findings:
        pass
    # Findings from suspicious records, deduplicated by (kind, path, command).
    seen_findings = set()
    for item in suspicious:
        key = (item["kind"], canonical_key(item["path"]), item["command"][:200])
        if key in seen_findings:
            continue
        seen_findings.add(key)
        findings.append(Finding(
            title=f"可疑程序调用路径：{item['name'] or item['path']}",
            severity=item["severity"],
            category="Execution",
            detail="；".join(item["reasons"]) if item["reasons"] else "该程序调用路径需要人工核对。",
            path=item["path"],
            source="execution:" + item["kind"],
            evidence={"command": item["command"], "score": item["score"], "reasons": item["reasons"]},
            recommendation="核对文件签名、来源、父进程与启动时间；先取证，不要直接删除。",
        ))

    all_findings = [item.to_dict() for item in findings]
    verdict = max_severity([item["severity"] for item in all_findings])
    program_list = sorted(programs.values(), key=lambda item: (-item["max_score"], item["path"].casefold()))

    return {
        "generated_at": now_iso(),
        "verdict": verdict,
        "status_label": {
            "critical": "发现严重异常",
            "high": "发现高优先级异常",
            "medium": "发现需要核对的程序",
            "low": "仅有低优先级信息",
            "info": "未发现明显异常",
        }.get(verdict, verdict),
        "records": records,
        "program_paths": program_list,
        "suspicious": sorted(suspicious, key=lambda item: (-_severity_rank(item["severity"]), -item["score"])),
        "findings": all_findings,
        "path": path_data,
        "path_analysis": path_analysis,
        "installed_software": installed,
        "stats": {
            "processes": len(records["processes"]),
            "services": len(records["services"]),
            "drivers": len(records["drivers"]),
            "tasks": len(records["tasks"]),
            "startup": len(records["startup"]),
            "autoruns": len(records["autoruns"]),
            "com_hijacks": len(records["com"]),
            "protocol_handlers": len(records["protocols"]),
            "wmi": len(records["wmi"]),
            "program_paths": len(program_list),
            "installed_software": len(installed),
            "suspicious": len(suspicious),
            "path_entries": len(path_data.get("entries", [])),
            "com_scanned": com_data.get("scanned", 0),
        },
        "errors": errors[:100],
    }
