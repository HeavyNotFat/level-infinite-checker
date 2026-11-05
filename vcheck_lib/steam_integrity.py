from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional

from .models import Finding, max_severity
from .signatures import collect_signatures, is_trusted_third_party, is_valve, signature_for, status_severity
from .steam_paths import STEAM_CORE_FILES
from .utils import (
    canonical_key,
    file_meta,
    is_subpath,
    is_user_writable,
    now_iso,
    read_text_safe,
)

try:
    import winreg
except ImportError:  # pragma: no cover
    winreg = None


PROXY_DLL_NAMES = {
    "version.dll", "winmm.dll", "wininet.dll", "ws2_32.dll", "wldap32.dll",
    "dwmapi.dll", "dbghelp.dll", "uxtheme.dll", "cryptbase.dll", "profapi.dll",
    "msimg32.dll", "secur32.dll", "netapi32.dll", "userenv.dll", "psapi.dll",
    "shfolder.dll", "mpr.dll", "netutils.dll", "tapi32.dll", "rasadhlp.dll",
    "dnsapi.dll", "iphlpapi.dll", "schannel.dll", "ncrypt.dll", "bcrypt.dll",
}

def _pe_extension(name: str) -> bool:
    lower = name.casefold()
    if lower.endswith((".exe", ".dll", ".sys", ".ocx", ".cpl")):
        return True
    if lower.endswith((".exe.old", ".dll.old", ".exe.bak", ".dll.bak")):
        return True
    return False


def _iter_root_pe(root: str) -> Iterable[str]:
    try:
        with os.scandir(root) as iterator:
            for entry in iterator:
                if entry.is_file(follow_symlinks=False) and _pe_extension(entry.name):
                    yield entry.path
    except OSError:
        return


def _iter_dir_pe(directory: str) -> Iterable[str]:
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if entry.is_file(follow_symlinks=False) and _pe_extension(entry.name):
                    yield entry.path
    except OSError:
        return


def enumerate_steam_binaries(steam: Dict[str, Any]) -> List[Dict[str, Any]]:
    files: List[str] = []
    roots = [root["path"] for root in steam.get("install_roots", []) if root.get("exists")]
    for root in roots:
        for rel in STEAM_CORE_FILES:
            path = os.path.join(root, rel)
            if os.path.isfile(path):
                files.append(path)
        files.extend(_iter_root_pe(root))
        bin_dir = os.path.join(root, "bin")
        if os.path.isdir(bin_dir):
            files.extend(_iter_dir_pe(bin_dir))
            cef_dir = os.path.join(bin_dir, "cef")
            if os.path.isdir(cef_dir):
                files.extend(_iter_dir_pe(cef_dir))
                for cef_ver in ("cef.win7", "cef.win7x64", "cef.win64"):
                    files.extend(_iter_dir_pe(os.path.join(cef_dir, cef_ver)))
    # Include .old/.bak siblings of core files; updates leave these behind.
    for root in roots:
        for rel in STEAM_CORE_FILES:
            for suffix in (".old", ".bak"):
                path = os.path.join(root, rel + suffix)
                if os.path.isfile(path):
                    files.append(path)
    unique: Dict[str, Dict[str, Any]] = {}
    for path in files:
        key = canonical_key(path)
        if not key or key in unique:
            continue
        root = ""
        for candidate in roots:
            if is_subpath(path, candidate):
                root = candidate
                break
        rel = os.path.relpath(path, root) if root else os.path.basename(path)
        unique[key] = {
            "path": path,
            "root": root,
            "relative": rel,
            "is_core": rel.casefold() in {item.casefold() for item in STEAM_CORE_FILES},
            "is_old": rel.casefold().endswith((".old", ".bak")),
        }
    return list(unique.values())


def _hosts_findings() -> List[Finding]:
    hosts_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    text = read_text_safe(hosts_path, max_bytes=2 * 1024 * 1024)
    if not text:
        return []
    steam_words = ("steam", "valve", "steampowered", "steamcommunity", "steamserver", "steamcontent", "steamstatic")
    entries: List[Dict[str, Any]] = []
    any_non_loopback = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        hosts = parts[1:]
        if not any(word in host.casefold() for host in hosts for word in steam_words):
            continue
        address = parts[0]
        loopback = address in ("127.0.0.1", "::1", "0.0.0.0")
        any_non_loopback = any_non_loopback or not loopback
        entries.append({
            "line": line_number,
            "address": address,
            "hosts": hosts,
            "loopback": loopback,
            "content": redact_line(stripped),
        })
    if not entries:
        return []
    return [Finding(
        title="hosts 文件包含 Steam 域名映射",
        severity="high" if any_non_loopback else "info",
        category="Steam integrity",
        detail=("hosts 中存在指向非回环地址的 Steam 域名映射，可能劫持登录/更新流量。"
                if any_non_loopback else
                "hosts 中存在指向回环/黑洞地址的 Steam 域名映射，通常是 Steam++/Watt Toolkit 等工具或广告屏蔽；"
                "这是信息项，不是恶意判定。"),
        path=hosts_path,
        source="steam_integrity",
        evidence={"entries": entries},
        recommendation="确认这些行是否由你或 Steam 加速/屏蔽工具添加；非预期时备份 hosts 后移除。",
    )]


def redact_line(line: str) -> str:
    # Do not leak tokens that a user may have put in a hosts comment.
    return re.sub(r"(?i)(token|password|secret)=\S+", r"\1=<redacted>", line)


def _persistence_findings() -> List[Finding]:
    findings: List[Finding] = []
    if winreg is None:
        return findings

    def open_key(hive, path, view=0):
        try:
            return winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view)
        except OSError:
            return None

    def read_values(key) -> Dict[str, Any]:
        result = {}
        if key is None:
            return result
        index = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, index)
            except OSError:
                break
            result[name] = value
            index += 1
        return result

    # AppInit_DLLs: legitimate value is empty on modern Windows.
    appinit_locations = [
        ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", 0),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", getattr(winreg, "KEY_WOW64_32KEY", 0)),
    ]
    for hive_label, hive, path, view in appinit_locations:
        key = open_key(hive, path, view)
        values = read_values(key)
        if key is not None:
            try:
                winreg.CloseKey(key)
            except OSError:
                pass
        dlls = str(values.get("AppInit_DLLs", "") or "").strip()
        if dlls:
            findings.append(Finding(
                title="AppInit_DLLs 非空",
                severity="medium",
                category="Steam integrity",
                detail="AppInit_DLLs 会让多个进程在启动时加载指定 DLL；现代 Windows 默认应为空。",
                path=path,
                source="steam_integrity",
                evidence={"hive": hive_label, "value": dlls, "view": view},
                recommendation="确认该 DLL 是否由可信软件安装；不要直接删除，先备份注册表值。",
            ))

    # IFEO for Steam: a Debugger value hijacks steam.exe.
    for view, view_label in (
        (getattr(winreg, "KEY_WOW64_64KEY", 0), "64"),
        (getattr(winreg, "KEY_WOW64_32KEY", 0), "32"),
    ):
        path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\steam.exe"
        key = open_key(winreg.HKEY_LOCAL_MACHINE, path, view)
        values = read_values(key)
        if key is not None:
            try:
                winreg.CloseKey(key)
            except OSError:
                pass
        if values.get("Debugger") or values.get("VerifierDlls"):
            findings.append(Finding(
                title="steam.exe 存在 IFEO 调试器/验证器劫持",
                severity="high",
                category="Steam integrity",
                detail="Image File Execution Options 可以让 steam.exe 启动时改跑另一个程序。",
                path=path,
                source="steam_integrity",
                evidence={"view": view_label, "values": values},
                recommendation="备份后删除该 IFEO 子键，并检查指向的程序。",
            ))
    return findings


def evaluate_integrity(
    steam: Dict[str, Any],
    signatures: Dict[str, Dict[str, Any]],
    modules_data: Optional[Dict[str, Any]] = None,
    previous_hashes: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    previous_hashes = previous_hashes or {}
    binaries = enumerate_steam_binaries(steam)
    findings: List[Finding] = []
    records: List[Dict[str, Any]] = []
    core_records: List[Dict[str, Any]] = []
    missing_core: List[str] = []

    for item in binaries:
        path = item["path"]
        meta = file_meta(path, include_hash=True, hash_limit=300 * 1024 * 1024)
        sig = signature_for(path, signatures)
        status = str(sig.get("status", "UnknownError"))
        subject = str(sig.get("subject", ""))
        valve_signed = is_valve(subject)
        is_trusted = valve_signed or is_trusted_third_party(subject)
        name = os.path.basename(path).casefold()
        issues: List[str] = []
        severity = "info"

        if status.casefold() != "valid":
            issues.append(f"signature status: {status}")
            severity = status_severity(status, item["is_core"])
            if item["is_core"]:
                severity = "high"
        elif not valve_signed:
            issues.append("valid signature is not Valve")
            severity = "high" if item["is_core"] else "low"
        elif name in PROXY_DLL_NAMES:
            issues.append("Valve-signed file uses a system proxy DLL name")
            severity = "medium"

        if name in PROXY_DLL_NAMES and not valve_signed and item["relative"].casefold() == name:
            severity = "high" if severity in ("info", "low", "medium") else severity
            issues.append("proxy-DLL name outside Valve signature")

        if item["is_old"]:
            issues.append("leftover .old/.bak copy (normal after an update, but also used by malware)")
            if severity == "info":
                severity = "low"

        previous = previous_hashes.get(item["relative"].casefold()) or previous_hashes.get(item["relative"])
        if previous and meta.get("sha256") and previous != meta.get("sha256"):
            issues.append("hash differs from the saved baseline")
            if severity == "info":
                severity = "low"

        record = {
            **item,
            **meta,
            "signature_status": status,
            "signer_subject": subject,
            "file_version": sig.get("file_version", ""),
            "product_version": sig.get("product_version", ""),
            "company": sig.get("company", ""),
            "is_valve_signed": valve_signed,
            "is_trusted_signer": is_trusted,
            "issues": issues,
            "severity": severity,
        }
        records.append(record)
        if item["is_core"]:
            core_records.append(record)
            if not meta.get("exists"):
                missing_core.append(item["relative"])

    for rel in STEAM_CORE_FILES:
        if not any(record["relative"].casefold() == rel.casefold() for record in core_records):
            # Some paths (steamservice.exe) legitimately live under bin; do not
            # treat every name in the list as mandatory at the root.
            if rel in ("steam.exe", "steamclient.dll", "steamclient64.dll", "steamui.dll"):
                missing_core.append(rel)

    for rel in sorted(set(missing_core)):
        findings.append(Finding(
            title="Steam 核心文件缺失",
            severity="high",
            category="Steam integrity",
            detail=f"未找到核心文件 {rel}；安装可能不完整，或文件被移动/删除。",
            path=os.path.join(steam.get("primary_root", ""), rel),
            source="steam_integrity",
            evidence={"missing": rel},
            recommendation="让 Steam 重新校验文件；若文件被安全软件隔离，先确认隔离原因。",
        ))

    core_bad = [record for record in core_records if record["severity"] in ("high", "critical")]
    for record in core_bad:
        findings.append(Finding(
            title="Steam 核心文件签名/完整性异常",
            severity=record["severity"],
            category="Steam integrity",
            detail="核心文件未通过 Authenticode 校验，或签名者不是 Valve。",
            path=record["path"],
            source="steam_integrity",
            evidence={
                "signature_status": record["signature_status"],
                "signer": record["signer_subject"],
                "issues": record["issues"],
                "sha256": record.get("sha256", ""),
            },
            recommendation="不要直接删除；先备份该文件，再让 Steam 校验/重装，并排查是否被替换。",
        ))

    extra_bad = [record for record in records if not record["is_core"] and record["severity"] in ("high", "critical")]
    for record in extra_bad:
        findings.append(Finding(
            title="Steam 目录存在可疑二进制",
            severity=record["severity"],
            category="Steam integrity",
            detail="Steam 目录中的可执行文件签名异常，或使用了系统代理 DLL 名称。",
            path=record["path"],
            source="steam_integrity",
            evidence={
                "signature_status": record["signature_status"],
                "signer": record["signer_subject"],
                "issues": record["issues"],
                "sha256": record.get("sha256", ""),
            },
            recommendation="核对文件来源和修改时间；先备份再隔离，不要删除整个 Steam 目录。",
        ))

    # Loaded module checks: the strongest signal of injection into Steam.
    module_findings: List[Finding] = []
    modules = (modules_data or {}).get("modules", []) if isinstance(modules_data, dict) else []
    steam_root_keys = [canonical_key(root["path"]) for root in steam.get("install_roots", [])]
    for module in modules:
        path = str(module.get("path", "") or "")
        if not path or not os.path.exists(path):
            continue
        lower = path.casefold()
        process = str(module.get("process", ""))
        if not process.casefold().startswith("steam") and not any(is_subpath(path, root) for root in steam_root_keys):
            continue
        if "platformexperiencehelper" in lower or os.path.basename(lower) == "platform_experience_helper.dll":
            module_findings.append(Finding(
                title="Steam 进程加载了 PlatformExperienceHelper 目录中的 DLL",
                severity="critical",
                category="Steam integrity",
                detail="这是公开 K2F 报告中记录的浏览器驻留位置；正常 Chrome 组件是 EXE，不是该目录下的 DLL。",
                path=path,
                source="steam_integrity",
                evidence={"process": process, "pid": module.get("pid"), "module": module.get("module")},
                recommendation="按 K2F 处置流程先取证、断网、轮换凭据；不要只删除 DLL。",
            ))
            continue
        if is_user_writable(path) and not any(is_subpath(path, root) for root in steam_root_keys):
            module_findings.append(Finding(
                title="Steam 进程从用户可写目录加载 DLL",
                severity="high",
                category="Steam integrity",
                detail="正常 Steam 模块应来自 Steam 安装目录或系统目录；用户目录模块可能是注入。",
                path=path,
                source="steam_integrity",
                evidence={"process": process, "pid": module.get("pid"), "module": module.get("module")},
                recommendation="记录模块路径和 PID，使用 Autoruns/Process Explorer 核对签名；先取证再处理。",
            ))
    findings.extend(module_findings)

    # Hosts and persistence checks.
    findings.extend(_hosts_findings())
    findings.extend(_persistence_findings())

    # Baseline hash changes are already reflected per record; add a summary.
    changed_core = [record for record in core_records if any("hash differs" in issue for issue in record["issues"])]
    if changed_core:
        findings.append(Finding(
            title="Steam 核心文件哈希与基线不同",
            severity="low",
            category="Steam integrity",
            detail="Steam 更新会正常改变哈希；只有签名同时异常时才应视为篡改。",
            path=steam.get("primary_root", ""),
            source="steam_integrity",
            evidence={"files": [{"path": record["path"], "sha256": record.get("sha256", "")} for record in changed_core]},
            recommendation="确认最近是否更新过 Steam；若没有，核对签名和修改时间。",
        ))

    verdict = max_severity([finding.severity for finding in findings])
    if not binaries:
        verdict = "unknown"
    if verdict == "info":
        verdict = "clean"
    status_label = {
        "critical": "发现严重异常",
        "high": "发现高优先级异常",
        "medium": "需要人工核对",
        "low": "有低优先级差异",
        "info": "未发现已知异常",
        "clean": "签名/结构未发现异常",
        "unknown": "未找到可检查的 Steam 安装",
    }.get(verdict, verdict)

    return {
        "generated_at": now_iso(),
        "verdict": verdict,
        "status_label": status_label,
        "primary_root": steam.get("primary_root", ""),
        "client_version": _client_version(core_records),
        "binaries": records,
        "core_binaries": core_records,
        "module_findings": [item.to_dict() for item in module_findings],
        "findings": [item.to_dict() for item in findings],
        "counts": {
            "binaries": len(records),
            "core": len(core_records),
            "core_high": len(core_bad),
            "extra_high": len(extra_bad),
            "module_findings": len(module_findings),
        },
        "notes": [
            "Authenticode 通过只证明文件由该签名者签署且未被改动，不能证明它是当前最新版本。",
            "首次运行没有基线；哈希变化要结合 Steam 更新时间和签名一起判断。",
        ],
    }


def _client_version(core_records: List[Dict[str, Any]]) -> str:
    for record in core_records:
        if record.get("relative", "").casefold() == "steam.exe":
            return str(record.get("file_version", "") or "")
    return ""


def summarize_integrity(integrity: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "verdict": integrity.get("verdict", "unknown"),
        "status_label": integrity.get("status_label", ""),
        "client_version": integrity.get("client_version", ""),
        "counts": integrity.get("counts", {}),
    }
