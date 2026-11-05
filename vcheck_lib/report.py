from __future__ import annotations

import html
import json
import os
from typing import Any, Dict, Iterable, List

from .models import SEVERITY_LABEL_ZH, max_severity, severity_rank
from .utils import atomic_write_json, atomic_write_text, now_iso


SEVERITY_CLASS = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}

AI_HINT = (
    "如果自己看不懂本报告：请把本目录下的 report.md（或 HTML 报告、gui-run.log）发送给 AI，"
    "让它逐条解释“这条发现是什么意思、需不需要处理、下一步做什么”。发送前请先删除计算机名、用户名、"
    "路径与域名记录中的隐私内容。"
)


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _md(value: Any) -> str:
    return ("" if value is None else str(value)).replace("|", "\\|").replace("\n", " ")


def _short_hash(value: str, length: int = 16) -> str:
    value = value or ""
    return value[:length] + "..." if len(value) > length else value


def summarize(result: Dict[str, Any]) -> Dict[str, Any]:
    findings = result.get("findings", []) or []
    severity = max_severity([item.get("severity", "info") for item in findings])
    incident = result.get("incident", {}) or {}
    stage = int(incident.get("stage", 0) or 0)
    if severity == "info":
        headline = "未发现需要立即处理的异常"
        advice = "保持只读复核；本工具不能证明系统干净。如果曾打开过受影响的启动器，仍建议按“已接触”处理。"
    elif severity == "low":
        headline = "仅有低优先级差异，需要结合上下文核对"
        advice = "先看低优先级条目，确认是否由正常更新、便携软件或缓存造成。"
    elif severity == "medium":
        headline = "发现需要人工核对的异常"
        advice = "优先核对高/中优先级条目的文件路径、时间与来源；不要直接删除系统目录。"
    elif severity == "high":
        headline = "发现高优先级异常，建议按失陷流程处理"
        advice = "断网、保全证据、从另一台干净设备轮换密码/令牌/SSH/钱包；不要只运行杀毒后继续使用。"
    else:
        headline = "发现严重指标，按已失陷处理"
        advice = "立即断网并保全证据；从另一台干净设备轮换所有高价值凭据；钱包助记词需要新建钱包转移资产。"
    if stage >= 3 and severity in ("high", "critical"):
        if incident.get("evidence_strength") == "forensic-only":
            headline = "仅发现已删除文件的名称证据，需要人工核对"
            advice = (
                "USN 日志中出现 K2F 文件名，但没有仍存在的恶意文件、日志或注册表项。"
                "这可能来自同名测试文件或其他程序，请结合文件时间、启动器使用历史与其他证据判断；"
                "如果确实打开过受影响的启动器，仍应按凭据已泄露处理。"
            )
        else:
            headline = "确认 K2F 代理执行痕迹，主机应按完全失陷处置"
            advice = (
                "立即断网并保全证据（先复制启动器日志、Launcher\\log 与 tbs_cache），不要再次打开启动器或游戏；"
                "代理暴露了任意命令执行与文件下载能力，最安全的处置是重装系统；在重装前用另一台干净设备轮换全部凭据。"
            )
    counts = {
        "total_findings": len(findings),
        "critical": sum(1 for item in findings if item.get("severity") == "critical"),
        "high": sum(1 for item in findings if item.get("severity") == "high"),
        "medium": sum(1 for item in findings if item.get("severity") == "medium"),
        "low": sum(1 for item in findings if item.get("severity") == "low"),
        "info": sum(1 for item in findings if item.get("severity") == "info"),
    }
    top = sorted(findings, key=lambda item: (-severity_rank(item.get("severity", "info")), item.get("category", ""), item.get("title", "")))[:12]
    return {
        "severity": severity,
        "severity_label": SEVERITY_LABEL_ZH.get(severity, severity),
        "headline": headline,
        "advice": advice,
        "counts": counts,
        "top_findings": top,
        "incident_stage": stage,
        "incident_stage_label": incident.get("stage_label", ""),
        "ai_hint": AI_HINT,
    }


def _table(headers: List[str], rows: Iterable[List[Any]], limit: int = 200) -> str:
    rows = list(rows)
    if not rows:
        return "_无_\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows[:limit]:
        out.append("| " + " | ".join(_md(cell) for cell in row) + " |")
    if len(rows) > limit:
        out.append(f"\n_仅显示前 {limit} 行，完整数据见 report.json。_")
    return "\n".join(out) + "\n"


def _findings_md(findings: List[Dict[str, Any]], limit: int = 160) -> str:
    rows = []
    for item in sorted(findings, key=lambda value: (-severity_rank(value.get("severity", "info")), value.get("title", ""))):
        rows.append([
            SEVERITY_LABEL_ZH.get(item.get("severity", "info"), item.get("severity", "")),
            item.get("category", ""),
            item.get("title", ""),
            item.get("path", ""),
            item.get("detail", ""),
        ])
    return _table(["级别", "类别", "发现", "路径", "说明"], rows, limit=limit)


def _incident_md(incident: Dict[str, Any]) -> str:
    if not incident or incident.get("status_label") == "已跳过":
        return "已跳过本次供应链事件检测。\n"
    sections = incident.get("sections", {}) or {}
    counts = incident.get("counts", {}) or {}
    lines: List[str] = []
    lines.append(
        f"**结论：{incident.get('status_label', '')}**（{incident.get('stage_label', '')}；阶段 1/2/3/4："
        f"{'是' if incident.get('stage1') else '否'}/{'是' if incident.get('stage2') else '否'}/"
        f"{'是' if incident.get('stage3') else '否'}/{'是' if incident.get('stage4') else '否'}）\n"
    )
    lines.append(
        f"检查启动器 {counts.get('launchers', 0)} 个，debug.log {counts.get('debug_logs', 0)} 个，"
        f"tinyget 文件 {counts.get('tinyget_files', 0)} 个，Code Cache {counts.get('code_cache_scanned', 0)} 个文件，"
        f"HTTP 缓存 {counts.get('http_cache_scanned', 0)} 个文件，LevelDB {counts.get('local_storage_scanned', 0)} 个文件，"
        f"浏览器资料 {counts.get('browser_profiles', 0)} 个，凭据目标 {counts.get('credentials', 0)} 个。\n"
    )

    launchers = incident.get("launchers", []) or []
    lines.append("### 发现的启动器\n")
    lines.append(_table(
        ["游戏/名称", "安装根", "Launcher 目录", "debug.log", "tinyget", "已确认"],
        [[item.get("game", ""), item.get("root", ""), "、".join(item.get("launcher_dirs", []) or []),
          item.get("debug_log", "") or "缺失", item.get("tinyget", "") or "缺失",
          "是" if item.get("confirmed") else "待确认"] for item in launchers],
        limit=60,
    ))

    debug = sections.get("debug_logs", {}) or {}
    lines.append("### 1) 启动器 debug.log\n")
    rows = []
    for item in debug.get("files", []) or []:
        for marker in item.get("markers", []) or []:
            rows.append([item.get("path", ""), marker.get("marker", "").strip(), marker.get("count", ""),
                         marker.get("first_line", ""), "；".join(marker.get("samples", [])[:1])])
    lines.append(_table(["debug.log", "标记", "次数", "首次行号", "样例"], rows, limit=80))
    if not rows:
        lines.append("未在 debug.log 中找到 K2F 标记。注意：2026-11-05 之后的官方客户端可能在启动时删除该文件，缺失不能排除感染。\n")

    tinyget = sections.get("tinyget", {}) or {}
    lines.append("### 2) Launcher\\log\\tinyget（载荷下载）\n")
    rows = []
    for item in tinyget.get("files", []) or []:
        if not (item.get("lua_header") or item.get("known") or item.get("markers") or item.get("etags")):
            continue
        rows.append([item.get("name", ""), item.get("size_human", ""), _short_hash(item.get("sha256", "")),
                     "是" if item.get("lua_header") else "否", item.get("known", "") or "；".join(item.get("markers", [])[:3]),
                     "；".join(item.get("etags", [])[:3])])
    lines.append(_table(["文件", "大小", "SHA-256", "LuaJIT 头", "命中", "ETag"], rows, limit=80))
    if not rows:
        lines.append("tinyget 目录中没有发现 LuaJIT 载荷、insight.bundle 或相关下载记录。\n")

    code_cache = sections.get("code_cache", {}) or {}
    lines.append("### 3) 启动器 Code Cache / HTTP 缓存 / Local Storage\n")
    entry_rows = []
    for item in code_cache.get("entries", []) or []:
        meta = item.get("meta", {}) or {}
        entry_rows.append([item.get("label", ""), item.get("name", ""), meta.get("mtime", ""), item.get("path", "")])
    lines.append("Code Cache 中的加载器条目：\n")
    lines.append(_table(["加载器", "缓存文件", "修改时间", "路径"], entry_rows, limit=40))
    http_cache = sections.get("http_cache", {}) or {}
    http_rows = []
    for item in http_cache.get("hits", []) or []:
        http_rows.append([item.get("kind", ""), item.get("size", ""), _short_hash(item.get("sha256", "")),
                          item.get("label", "") or "；".join(item.get("markers", [])[:3]), item.get("path", "")])
    lines.append("HTTP 缓存（已按 1F 8B 08 解压 gzip）：\n")
    lines.append(_table(["编码", "解压后大小", "SHA-256", "命中", "缓存文件"], http_rows, limit=60))
    storage = sections.get("local_storage", {}) or {}
    storage_rows = []
    for item in storage.get("hits", []) or []:
        storage_rows.append([item.get("path", ""), "、".join(item.get("found", []) or []),
                             "、".join(item.get("method", []) or []), item.get("blocks", "")])
    lines.append("LevelDB（含 Snappy 压缩块）：\n")
    lines.append(_table(["文件", "命中字符串", "读取方式", "解压块数"], storage_rows, limit=40))
    if not (entry_rows or http_rows or storage_rows):
        lines.append("缓存与本机 LevelDB 中没有发现 insightjs/K2F 痕迹。\n")

    browser = sections.get("browser", {}) or {}
    browser_config = sections.get("browser_config", {}) or {}
    lines.append("### 4) 浏览器持久化与浏览器配置\n")
    helper_rows = []
    for item in browser.get("artifacts", []) or []:
        for file_item in item.get("files", []) or []:
            helper_rows.append([os.path.basename(item.get("path", "")), file_item.get("name", ""),
                                _short_hash(file_item.get("sha256", "")), item.get("path", "")])
    lines.append("PlatformExperienceHelper / 安装残留：\n")
    lines.append(_table(["64-hex 目录", "文件", "SHA-256", "路径"], helper_rows, limit=40))
    policies = (browser_config.get("records", {}) or {}).get("policies", []) or []
    native = (browser_config.get("records", {}) or {}).get("native_messaging", []) or []
    profiles = (browser_config.get("records", {}) or {}).get("profiles", []) or []
    lines.append("扩展强制安装策略（注册表）：\n")
    lines.append(_table(
        ["注册表项", "值"],
        [[item.get("key", ""), "；".join(f"{name}={value}" for name, value in (item.get("values", []) or [])[:4])] for item in policies],
        limit=20,
    ))
    lines.append("NativeMessagingHosts（注册表）：\n")
    lines.append(_table(["浏览器", "Hive", "名称", "清单路径"], [[item.get("browser", ""), item.get("hive", ""), item.get("name", ""), item.get("manifest", "")] for item in native], limit=30))
    lines.append("含保存密码/Cookie 的浏览器资料：\n")
    lines.append(_table(["浏览器", "资料目录", "存储文件"], [[item.get("browser", ""), item.get("path", ""), "、".join(item.get("stores", []) or [])] for item in profiles], limit=40))
    wallets = browser.get("wallets", []) or []
    lines.append(f"检测到的钱包扩展：{'、'.join(item.get('name', '') for item in wallets) if wallets else '无'}\n")

    clsid = sections.get("clsid", {}) or {}
    lines.append("### 5) 注册表 CLSID 持久化\n")
    lines.append(_table(["CLSID", "视图", "InprocServer32", "用户 Hive"],
                         [[item.get("clsid", ""), item.get("view", ""), item.get("path", ""), item.get("hive", "")] for item in clsid.get("records", []) or []],
                         limit=40))
    if not clsid.get("records"):
        lines.append("HKCU（含其他已加载用户 Hive）中没有发现 K2F CLSID 或指向 PlatformExperienceHelper 的 CLSID。\n")

    temp = sections.get("temp_and_pipes", {}) or {}
    lines.append("### 6) TEMP 与命名管道\n")
    lines.append(_table(["文件", "说明", "SHA-256"], [[item.get("path", ""), item.get("label", ""), _short_hash(item.get("sha256", ""))] for item in temp.get("files", []) or []], limit=40))
    lines.append(f"命名管道：{'、'.join(temp.get('pipes', []) or []) if temp.get('pipes') else '无 k2f/insight 管道'}\n")

    hosts = sections.get("hosts_dns", {}) or {}
    lines.append("### 7) hosts / DNS 缓存 / 连接\n")
    host_rows = [[item.get("content", ""), item.get("domain", ""), "是" if item.get("loopback") else "否"] for item in (hosts.get("records", {}) or {}).get("hosts", [])]
    lines.append(_table(["hosts 行", "域名", "回环"], host_rows, limit=30))
    dns_rows = [[item.get("domain", ""), item.get("count", "")] for item in (hosts.get("records", {}) or {}).get("dns", [])]
    lines.append("DNS 缓存：\n")
    lines.append(_table(["域名", "次数"], dns_rows, limit=20))
    connections = sections.get("connections", {}) or {}
    lines.append("与 C2 IP 的套接字：\n")
    lines.append(_table(["netstat 行"], [[item.get("line", "")] for item in connections.get("hits", []) or []], limit=20))
    if not (host_rows or dns_rows or connections.get("hits")):
        lines.append("hosts、DNS 缓存与套接字表中没有 insightjs 相关记录。\n")

    modules = sections.get("modules", {}) or {}
    lines.append("### 8) 运行中的进程模块\n")
    lines.append(_table(["进程", "PID", "模块", "路径"],
                         [[item.get("process", ""), item.get("pid", ""), item.get("module", ""), item.get("path", "")] for item in modules.get("records", []) or []],
                         limit=40))
    if not modules.get("records"):
        lines.append("没有进程加载 PlatformExperienceHelper / 64-hex 目录 / k2f 命名的模块。\n")

    usn = sections.get("usn", {}) or {}
    lines.append("### 9) NTFS USN 更改日志（已删除文件证据）\n")
    if not usn.get("available"):
        lines.append(f"未执行：{usn.get('reason', '未知原因')}\n")
    else:
        for record in usn.get("records", []) or []:
            lines.append(
                f"- 盘 {record.get('drive', '')}：扫描 {record.get('scanned_lines', 0)} 行"
                + ("（截断，结果不完整）" if record.get("truncated") else "")
                + f"，覆盖 {record.get('coverage_from', '') or '?'} ～ {record.get('coverage_to', '') or '?'}"
                + (f"；错误：{record.get('error')}" if record.get("error") else "")
            )
            if record.get("coverage_warning"):
                lines.append(f"  - **注意**：{record['coverage_warning']}")
            for match in record.get("matches", []) or []:
                lines.append(f"  - {match.get('label', '')}：{match.get('count', '')} 次；样例：{' / '.join(match.get('samples', [])[:1])}")
        if not any(record.get("matches") for record in usn.get("records", []) or []):
            lines.append("  USN 日志中没有 K2F 相关文件名。日志循环覆盖后旧记录会消失，这不是安全证明。")
        lines.append("")

    credentials = sections.get("credentials", {}) or {}
    lines.append("### 10) 凭据暴露面（insight.bundle 的目标）\n")
    categories = credentials.get("categories", {}) or {}
    lines.append(_table(["类别", "文件数"], [[name, count] for name, count in sorted(categories.items(), key=lambda item: -item[1])], limit=30))
    items = credentials.get("items", []) or []
    lines.append("存在的目标文件（前 60 个；本工具只检查存在性，不读取内容）：\n")
    lines.append(_table(["类别", "路径", "大小", "修改时间"],
                         [[item.get("category", ""), item.get("path", ""), item.get("size_human", ""), item.get("mtime", "")] for item in items[:60]],
                         limit=60))
    if credentials.get("env_set"):
        lines.append("已设置且会被 payload 读取的环境变量：" + "、".join(credentials["env_set"]) + "\n")
    if credentials.get("wallets"):
        lines.append("检测到的钱包扩展：" + "、".join(item.get("name", "") for item in credentials["wallets"]) + "\n")

    reference = incident.get("reference", {}) or {}
    lines.append("### 11) 本次事件公开 IOC（供对照，不要主动连接）\n")
    lines.append(_table(["被篡改的官方文件", "大小", "SHA-256", "主机"],
                         [[item.get("name", ""), item.get("size", ""), item.get("sha256", ""), item.get("host", "")] for item in reference.get("tampered_assets", [])],
                         limit=10))
    lines.append(_table(["载荷", "大小", "SHA-256", "说明"],
                         [[item.get("name", ""), item.get("size", ""), item.get("sha256", ""), item.get("note", "")] for item in reference.get("payload_assets", [])],
                         limit=10))
    lines.append("域名：" + "、".join(reference.get("ioc_domains", []) or []) + "；IP：" + "、".join(reference.get("ioc_ips", []) or []) + "\n")
    lines.append("Lua 代理暴露的命令：" + "、".join(reference.get("commands", []) or []) + "\n")
    lines.append("### 12) 事件检测的限制\n")
    for note in incident.get("notes", []) or []:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def _domains_md(domains: Dict[str, Any]) -> str:
    if not domains or not domains.get("domains"):
        return "已跳过或未采集到域名访问记录。\n"
    lines: List[str] = []
    available = domains.get("available", {}) or {}
    counts = domains.get("counts", {}) or {}
    sources = domains.get("sources", {}) or {}
    lines.append(f"共采集 **{counts.get('domains', 0)}** 个域名，其中命中攻击者基础设施 **{counts.get('ioc_domains', 0)}** 个，"
                 f"AI API/工具域名 **{counts.get('ai_domains', 0)}** 个；程序级 DNS 事件 {counts.get('program_events', 0)} 条，"
                 f"可识别的 API 端点 {counts.get('api_endpoints', 0)} 条。\n")
    lines.append("### 数据来源是否可用\n")
    lines.append(_table(["来源", "是否可用", "记录数"], [
        ["DNS 客户端缓存", "是" if available.get("dns_cache") else "否", (sources.get("dns_cache", {}) or {}).get("entries", 0)],
        ["DNS 客户端操作日志", "是" if available.get("dns_events") else "否", (sources.get("dns_events", {}) or {}).get("entries", 0)],
        ["Sysmon DNS（可归因到进程）", "是" if available.get("sysmon") else "否", (sources.get("sysmon", {}) or {}).get("entries", 0)],
        ["浏览器历史", "是" if available.get("browser_history") else "否", (sources.get("browser_history", {}) or {}).get("rows", 0)],
        ["程序日志中的 URL", "是" if available.get("program_logs") else "否", (sources.get("program_logs", {}) or {}).get("urls", 0)],
        ["程序配置中的 URL（MCP/API）", "是" if available.get("program_configs") else "否", (sources.get("program_configs", {}) or {}).get("urls", 0)],
        ["hosts 自定义映射", "是" if available.get("hosts") else "否", (sources.get("hosts", {}) or {}).get("entries", 0)],
        ["实时套接字表", "是" if available.get("sockets") else "否", (sources.get("connections", {}) or {}).get("total", 0)],
    ], limit=20))
    lines.append("### 重点域名（AI / 开发 / 云 / 攻击者基础设施）\n")
    focus = [item for item in domains.get("domains", []) or [] if item.get("ioc") or item.get("class") != "其他"]
    lines.append(_table(
        ["域名", "分类", "记录数", "来源", "最后时间"],
        [[item.get("domain", ""), item.get("class", ""), item.get("count", ""),
          "、".join(item.get("sources", [])[:4]), item.get("last_seen", "")] for item in focus[:60]],
        limit=60,
    ))
    lines.append("### 域名汇总（IOC 优先，其次按记录数）\n")
    lines.append(_table(
        ["域名", "分类", "记录数", "来源", "相关进程", "最后时间"],
        [[item.get("domain", ""), item.get("class", ""), item.get("count", ""),
          "、".join(item.get("sources", [])[:4]), "、".join(item.get("processes", [])[:4]), item.get("last_seen", "")]
         for item in domains.get("domains", [])[:200]],
        limit=200,
    ))
    events = domains.get("program_events", []) or []
    lines.append("### 程序级 DNS 记录（谁请求了哪个域名）\n")
    lines.append(_table(
        ["程序", "域名", "时间", "来源"],
        [[item.get("process", "") or "未归因", item.get("domain", ""), item.get("time", ""), item.get("source", "")] for item in events[:200]],
        limit=200,
    ))
    endpoints = domains.get("api_endpoints", []) or []
    lines.append("### 程序请求的 API 地址（去参数，仅保留域名与路径前缀）\n")
    lines.append(_table(
        ["端点", "程序", "来源"],
        [[item.get("endpoint", ""), "、".join(item.get("processes", [])[:3]), "、".join(item.get("sources", [])[:3])] for item in endpoints[:150]],
        limit=150,
    ))
    lines.append("### 说明\n")
    for note in domains.get("notes", []) or []:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def build_markdown(result: Dict[str, Any]) -> str:
    summary = summarize(result)
    meta = result.get("meta", {})
    weird = result.get("weird_dirs", {}) or {}
    steam = result.get("steam_paths", {}) or {}
    integrity = result.get("steam_integrity", {}) or {}
    execution = result.get("execution", {}) or {}
    incident = result.get("incident", {}) or {}
    domains = result.get("domains", {}) or {}
    findings = result.get("findings", []) or []
    lines: List[str] = []
    lines.append("# Windows 只读排查报告（异常文件夹 / Steam / 程序调用路径 / Level Infinite 供应链事件 / 域名访问）\n")
    lines.append(f"- 生成时间：{meta.get('generated_at', '')}")
    lines.append(f"- 主机：{meta.get('computer', '')} / 用户：{meta.get('user', '')}")
    lines.append(f"- 管理员权限：{'是' if meta.get('is_admin') else '否（部分系统项可能读不到）'}")
    lines.append(f"- 扫描配置：{meta.get('profile', '')}；耗时 {meta.get('elapsed_seconds', '')} 秒")
    lines.append(f"- 工具版本：{meta.get('tool_version', '')}")
    lines.append(f"- Steam 基线：**只读比对，不会创建或更新**（state\\steam_baseline.json 不会被写入）\n")
    lines.append(f"> **{AI_HINT}**\n")
    lines.append("## 结论摘要\n")
    lines.append(f"**总体级别：{summary['severity_label']}** — {summary['headline']}\n")
    lines.append(f"{summary['advice']}\n")
    lines.append(f"发现计数：严重 {summary['counts']['critical']}，高 {summary['counts']['high']}，中 {summary['counts']['medium']}，低 {summary['counts']['low']}，信息 {summary['counts']['info']}。\n")
    if incident:
        lines.append(f"供应链事件阶段：**{incident.get('stage_label', '未检查')}**（0-4 阶段，阶段越高越应按失陷处理）。\n")
    if summary["top_findings"]:
        lines.append("优先核对：\n")
        for item in summary["top_findings"]:
            path = f" — {item.get('path', '')}" if item.get("path") else ""
            lines.append(f"- **[{SEVERITY_LABEL_ZH.get(item.get('severity'), item.get('severity'))}]** {item.get('title', '')}{path}")
        lines.append("")
    lines.append("## 先看这几条限制\n")
    lines.append("- 本工具是**只读分诊**：不删除、不隔离、不改注册表、不连接 C2、不上传任何数据；它不能证明系统“干净”。")
    lines.append("- **不会更新 Steam 基线**：基线只做只读比对，缺失时也不会自动创建，避免把异常状态固化成“正常”。")
    lines.append("- 供应链事件中，仅靠文件哈希检测不可靠：`chrome_install` 会按服务器下发的 base64 重新安装 DLL，且 DLL 每个受害者都不同；本工具因此同时检查路径、注册表、日志、缓存、LevelDB 与 USN。")
    lines.append("- 官方修复不完整：截至 2026-11-04 02:01-02:07 UTC，部分 CDN 仍可能返回被污染的 `FeedList.feb647c9.js`。")
    lines.append("- 域名/网络记录会过期或被清理（DNS 缓存、浏览器历史、USN 日志都是如此）；没有命中不等于没发生。\n")
    lines.append("## 全部发现（按级别）\n")
    lines.append(_findings_md(findings, limit=200))

    lines.append("## 1. C: 盘乱码/异常文件夹\n")
    stats = weird.get("stats", {}) or {}
    lines.append(f"扫描目录 {stats.get('scanned_dirs', 0)} 个，候选 {weird.get('total_candidates', 0)} 个，耗时 {stats.get('elapsed_seconds', '')} 秒" + ("；**因时间预算提前结束**" if stats.get("truncated") else "。"))
    weird_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in weird.get("candidates", []) or []:
        level = item.get("severity", "info")
        weird_counts[level] = weird_counts.get(level, 0) + 1
    lines.append(f"候选级别：高 {weird_counts.get('high', 0)} / 中 {weird_counts.get('medium', 0)} / 低 {weird_counts.get('low', 0)} / 信息 {weird_counts.get('info', 0)}。")
    if weird.get("dir_log"):
        lines.append(f"完整目录清单：{_md(weird.get('dir_log'))}（{weird.get('dir_log_records', 0)} 条 JSONL；GUI 的“目录（全部）”可完整分页查看）。")
    lines.append("")
    rows = []
    for item in (weird.get("candidates", []) or [])[:80]:
        rows.append([
            SEVERITY_LABEL_ZH.get(item.get("severity", "info"), item.get("severity", "")),
            item.get("score", ""),
            item.get("path", ""),
            "；".join(item.get("reasons", [])[:4]),
            item.get("mtime", ""),
        ])
    lines.append(_table(["级别", "分数", "路径", "原因", "修改时间"], rows, limit=80))

    lines.append("## 2. Steam 路径与只读基线比对\n")
    roots = steam.get("install_roots", []) or []
    libraries = steam.get("libraries", []) or []
    lines.append(f"主安装目录：{steam.get('primary_root', '')}\n")
    lines.append("### 安装根\n")
    lines.append(_table(["主", "路径", "steam.exe", "来源", "盘类型", "链接"], [[("是" if item.get("is_primary") else ""), item.get("path", ""), item.get("steam_exe", ""), item.get("source", ""), item.get("drive_type", ""), ("是" if item.get("is_reparse") else "")] for item in roots], limit=100))
    lines.append("### 库目录\n")
    lines.append(_table(["路径", "存在", "盘类型", "App 数", "来源"], [[item.get("path", ""), ("是" if item.get("exists") else "否"), item.get("drive_type", ""), item.get("apps_count", ""), item.get("source", "")] for item in libraries], limit=150))
    drift = steam.get("drift") or {}
    lines.append("### 与基线的范围波动（只读）\n")
    lines.append(f"{drift.get('message', '')}\n")
    if drift.get("status") in ("no_baseline", "skipped"):
        lines.append("本次没有可用基线（本工具不会创建或更新基线），因此不输出漂移对比。\n")
    else:
        changes = (drift.get("drift", {}) or {}).get("changes", []) or []
        if not changes:
            lines.append("与基线一致，未发现 Steam 路径/核心哈希变化。\n")
        else:
            rows = []
            for item in changes:
                rows.append([item.get("kind", ""), item.get("change", ""), item.get("key", ""),
                             json.dumps(item.get("old"), ensure_ascii=False, default=str)[:300] if item.get("old") else "",
                             json.dumps(item.get("new"), ensure_ascii=False, default=str)[:300] if item.get("new") else ""])
            lines.append(_table(["类型", "变化", "键", "旧值", "新值"], rows, limit=100))
            lines.append(f"基线文件：{drift.get('baseline_path', '')}（未被修改）\n")

    lines.append("## 3. Steam 客户端完整性\n")
    lines.append(f"结论：**{integrity.get('status_label', '')}**；客户端版本：{integrity.get('client_version', '')}\n")
    core_rows = []
    for item in integrity.get("core_binaries", []) or []:
        core_rows.append([item.get("relative", ""), item.get("signature_status", ""), "是" if item.get("is_valve_signed") else "否", item.get("signer_subject", ""), _short_hash(item.get("sha256", "")), "；".join(item.get("issues", [])[:3])])
    lines.append(_table(["文件", "签名状态", "Valve", "签名者", "SHA-256", "问题"], core_rows, limit=80))
    if integrity.get("module_findings"):
        lines.append("### 进程模块异常\n")
        lines.append(_findings_md(integrity.get("module_findings", []), limit=50))
    if integrity.get("findings"):
        lines.append("### 完整性发现\n")
        lines.append(_findings_md(integrity.get("findings", []), limit=80))

    lines.append("## 4. 程序调用路径与可疑软件\n")
    ex_stats = execution.get("stats", {}) or {}
    lines.append(f"进程 {ex_stats.get('processes', 0)}，服务 {ex_stats.get('services', 0)}，驱动 {ex_stats.get('drivers', 0)}，计划任务 {ex_stats.get('tasks', 0)}，注册表启动项 {ex_stats.get('autoruns', 0)}，唯一程序路径 {ex_stats.get('program_paths', 0)}，可疑 {ex_stats.get('suspicious', 0)}。\n")
    suspicious_rows = []
    for item in execution.get("suspicious", []) or []:
        suspicious_rows.append([SEVERITY_LABEL_ZH.get(item.get("severity", "info"), item.get("severity", "")), item.get("score", ""), item.get("kind", ""), item.get("name", ""), item.get("path", ""), "；".join(item.get("reasons", [])[:4])])
    lines.append("### 可疑调用路径\n")
    lines.append(_table(["级别", "分数", "类型", "名称", "路径", "原因"], suspicious_rows, limit=120))
    lines.append("### 程序路径清点（按风险排序，前 60）\n")
    program_rows = []
    for item in (execution.get("program_paths", []) or [])[:60]:
        program_rows.append([SEVERITY_LABEL_ZH.get(item.get("severity", "info"), item.get("severity", "")), item.get("max_score", ""), item.get("path", ""), "；".join(item.get("sources", [])[:4])])
    lines.append(_table(["级别", "分数", "路径", "来源"], program_rows, limit=60))
    lines.append("### PATH 分析\n")
    path_rows = []
    for item in (execution.get("path", {}).get("entries", []) or []):
        path_rows.append([item.get("scope", ""), item.get("index", ""), item.get("raw", ""), item.get("kind", ""), "是" if item.get("exists") else "否", "是" if item.get("user_writable") else "否"])
    lines.append(_table(["范围", "序号", "原始项", "类型", "存在", "用户可写"], path_rows, limit=120))

    lines.append("## 5. Level Infinite / insightjs 供应链事件（文件 + 注册表 + 浏览器）\n")
    lines.append(_incident_md(incident))

    lines.append("## 6. 域名与网络访问证据\n")
    lines.append(_domains_md(domains))

    lines.append("## 7. 扫描统计与错误\n")
    lines.append(_table(["项目", "数值"], [
        ["异常文件夹候选", weird.get("total_candidates", 0)],
        ["目录清单记录", weird.get("dir_log_records", 0)],
        ["Steam 安装根", len(roots)],
        ["Steam 库", len(libraries)],
        ["Steam 核心文件", len(integrity.get("core_binaries", []) or [])],
        ["唯一程序路径", ex_stats.get("program_paths", 0)],
        ["可疑程序/启动项", ex_stats.get("suspicious", 0)],
        ["供应链事件发现", len(incident.get("findings", []) or [])],
        ["域名记录", len(domains.get("domains", []) or [])],
        ["程序级 DNS 事件", len(domains.get("program_events", []) or [])],
        ["错误/不可读", len(result.get("errors", []) or [])],
    ], limit=30))
    if result.get("errors"):
        lines.append("错误/不可读（前 80 项）：\n")
        lines.append("\n".join(f"- {item}" for item in result["errors"][:80]) + "\n")

    lines.append("## 8. 建议的下一步\n")
    lines.append("1. 先处理 high/critical：不要直接删除，先复制文件、记录哈希/签名/时间。")
    lines.append("2. 如果供应链事件阶段 ≥ 3：立即断网，保全证据；从另一台干净设备改密码、撤销 API key、SSH/GPG，并转移钱包资产；最安全的处置是重装系统。")
    lines.append("3. 如果阶段为 1-2：**不要再次打开启动器**，先备份 `Launcher\\intl_service\\debug.log`、`Launcher\\log\\` 与 `%APPDATA%\\nikke_launcher*\\tbs_cache`，再按官方说明清理缓存。")
    lines.append("4. 如果抓到了 insightjs 域名或 C2 IP：在 hosts、路由器或防火墙中继续屏蔽 `insightjs.com`、`analytics.insightjs.com`、`insightjs.org`、`89.127.233.127`、`89.126.250.172`（暂停可以解除）。")
    lines.append("5. 如果 Steam 核心文件签名异常：备份后让 Steam 校验文件；本工具不会更新基线，避免覆盖证据。")
    lines.append("6. 如果只是乱码文件夹：先确认是否来自解压工具/旧软件；不要因为名字奇怪就删除数据。")
    lines.append(f"7. **{AI_HINT}**\n")
    lines.append("---\n")
    lines.append("参考：MotherSphere《NIKKE PC launcher compromise》（2026-11-05）、Level Infinite 2026-11-04 公告、WormW/nikke_malware_analysis、Sheisback/nikke_malware_scanner、巧克力的博客与本仓库规则。公开 IOC 仅用于防御；不要主动连接 C2 或探测攻击者基础设施。")
    return "\n".join(lines)


def build_summary_text(result: Dict[str, Any]) -> str:
    summary = summarize(result)
    meta = result.get("meta", {})
    incident = result.get("incident", {}) or {}
    domains = result.get("domains", {}) or {}
    lines = [
        "Windows 只读排查完成",
        f"总体级别：{summary['severity_label']} — {summary['headline']}",
        f"发现：严重 {summary['counts']['critical']} / 高 {summary['counts']['high']} / 中 {summary['counts']['medium']} / 低 {summary['counts']['low']}",
        f"供应链事件：{incident.get('stage_label', '未检查')}",
        f"域名记录：{len(domains.get('domains', []) or [])} 个（其中 IOC {sum(1 for item in domains.get('domains', []) or [] if item.get('ioc'))} 个）",
        f"报告目录：{meta.get('output_dir', '')}",
        "Steam 基线：只读比对，本次未写入/未更新基线",
        "",
    ]
    for item in summary["top_findings"][:8]:
        lines.append(f"[{SEVERITY_LABEL_ZH.get(item.get('severity'), item.get('severity'))}] {item.get('title', '')}")
        if item.get("path"):
            lines.append(f"    {item['path']}")
    if not summary["top_findings"]:
        lines.append("没有 high/critical 条目；请查看 report.md 的低优先级差异。")
    lines.append("")
    lines.append(AI_HINT)
    lines.append("注意：这是只读分诊，不能证明系统干净；报告含计算机名、用户名、本地路径与域名记录，公开前请脱敏。")
    return "\n".join(lines) + "\n"


def _html_findings(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return '<p class="muted">无。</p>'
    rows = []
    for item in sorted(findings, key=lambda value: (-severity_rank(value.get("severity", "info")), value.get("title", ""))):
        severity = item.get("severity", "info")
        rows.append(
            f'<tr data-severity="{_esc(severity)}">'
            f'<td><span class="badge {_esc(SEVERITY_CLASS.get(severity, "info"))}">{_esc(SEVERITY_LABEL_ZH.get(severity, severity))}</span></td>'
            f'<td>{_esc(item.get("category", ""))}</td>'
            f'<td><strong>{_esc(item.get("title", ""))}</strong><div class="detail">{_esc(item.get("detail", ""))}</div></td>'
            f'<td class="path">{_esc(item.get("path", ""))}</td>'
            f'</tr>'
        )
    return '<table class="findings"><thead><tr><th>级别</th><th>类别</th><th>发现</th><th>路径</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table>"


def _rows_html(items, headers):
    items = list(items)
    if not items:
        return '<p class="muted">无。</p>'
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = []
    for row in items:
        body.append("<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>")
    return f'<table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>'


def build_html(result: Dict[str, Any]) -> str:
    summary = summarize(result)
    meta = result.get("meta", {})
    weird = result.get("weird_dirs", {}) or {}
    steam = result.get("steam_paths", {}) or {}
    integrity = result.get("steam_integrity", {}) or {}
    execution = result.get("execution", {}) or {}
    incident = result.get("incident", {}) or {}
    domains = result.get("domains", {}) or {}
    findings = result.get("findings", []) or []
    incident_sections = incident.get("sections", {}) or {}

    weird_rows = [[SEVERITY_LABEL_ZH.get(item.get("severity", "info"), item.get("severity", "")), item.get("score", ""), item.get("path", ""), "；".join(item.get("reasons", [])[:4]), item.get("mtime", "")] for item in (weird.get("candidates", []) or [])[:80]]
    root_rows = [[("是" if item.get("is_primary") else ""), item.get("path", ""), item.get("steam_exe", ""), item.get("source", ""), item.get("drive_type", "")] for item in (steam.get("install_roots", []) or [])]
    lib_rows = [[item.get("path", ""), ("是" if item.get("exists") else "否"), item.get("drive_type", ""), item.get("apps_count", ""), item.get("source", "")] for item in (steam.get("libraries", []) or [])]
    core_rows = [[item.get("relative", ""), item.get("signature_status", ""), ("是" if item.get("is_valve_signed") else "否"), item.get("signer_subject", ""), _short_hash(item.get("sha256", "")), "；".join(item.get("issues", [])[:3])] for item in (integrity.get("core_binaries", []) or [])]
    suspicious_rows = [[SEVERITY_LABEL_ZH.get(item.get("severity", "info"), item.get("severity", "")), item.get("score", ""), item.get("kind", ""), item.get("name", ""), item.get("path", ""), "；".join(item.get("reasons", [])[:4])] for item in (execution.get("suspicious", []) or [])]
    drift_rows = []
    for item in (((steam.get("drift") or {}).get("drift", {}) or {}) or {}).get("changes", []):
        drift_rows.append([item.get("kind", ""), item.get("change", ""), item.get("key", ""), json.dumps(item.get("old"), ensure_ascii=False)[:300] if item.get("old") else "", json.dumps(item.get("new"), ensure_ascii=False)[:300] if item.get("new") else ""])

    launcher_rows = [[item.get("game", ""), item.get("root", ""), item.get("debug_log", "") or "缺失", item.get("tinyget", "") or "缺失"] for item in (incident.get("launchers", []) or [])]
    debug_rows = []
    for item in ((incident_sections.get("debug_logs", {}) or {}).get("files", []) or []):
        for marker in item.get("markers", []) or []:
            debug_rows.append([item.get("path", ""), marker.get("marker", ""), marker.get("count", "")])
    cache_rows = []
    for item in ((incident_sections.get("local_storage", {}) or {}).get("hits", []) or []):
        cache_rows.append([item.get("path", ""), "、".join(item.get("found", []) or []), "、".join(item.get("method", []) or [])])
    http_rows = []
    for item in ((incident_sections.get("http_cache", {}) or {}).get("hits", []) or []):
        http_rows.append([item.get("kind", ""), item.get("label", "") or "；".join(item.get("markers", [])[:3]), _short_hash(item.get("sha256", "")), item.get("path", "")])
    helper_rows = []
    for item in ((incident_sections.get("browser", {}) or {}).get("artifacts", []) or []):
        helper_rows.append([item.get("path", ""), "、".join(file.get("name", "") for file in item.get("files", []) or [])])
    clsid_rows = [[item.get("clsid", ""), item.get("view", ""), item.get("path", ""), item.get("hive", "")] for item in ((incident_sections.get("clsid", {}) or {}).get("records", []) or [])]
    temp_rows = [[item.get("path", ""), item.get("label", "")] for item in ((incident_sections.get("temp_and_pipes", {}) or {}).get("files", []) or [])]
    usn_rows = []
    for record in ((incident_sections.get("usn", {}) or {}).get("records", []) or []):
        usn_rows.append([
            record.get("drive", ""),
            record.get("scanned_lines", ""),
            "是" if record.get("truncated") else "否",
            f"{record.get('coverage_from', '')} ~ {record.get('coverage_to', '')}",
            "；".join(f"{item.get('label', '')}×{item.get('count', '')}" for item in record.get("matches", []) or []),
        ])
    credential_rows = [[name, count] for name, count in sorted(((incident_sections.get("credentials", {}) or {}).get("categories", {}) or {}).items(), key=lambda item: -item[1])]
    domain_rows = [[item.get("domain", ""), item.get("class", ""), item.get("count", ""), "、".join(item.get("sources", [])[:4]), "、".join(item.get("processes", [])[:4]), item.get("last_seen", "")] for item in (domains.get("domains", []) or [])[:200]]
    event_rows = [[item.get("process", "") or "未归因", item.get("domain", ""), item.get("time", ""), item.get("source", "")] for item in (domains.get("program_events", []) or [])[:200]]
    endpoint_rows = [[item.get("endpoint", ""), "、".join(item.get("processes", [])[:3]), "、".join(item.get("sources", [])[:3])] for item in (domains.get("api_endpoints", []) or [])[:150]]

    cards = [
        ("总体级别", summary["severity_label"], summary["severity"]),
        ("严重/高", f"{summary['counts']['critical']} / {summary['counts']['high']}", "high"),
        ("供应链事件阶段", incident.get("stage", "—"), "critical" if int(incident.get("stage", 0) or 0) >= 3 else ("high" if int(incident.get("stage", 0) or 0) >= 2 else "info")),
        ("域名记录", len(domains.get("domains", []) or []), "high" if any(item.get("ioc") for item in domains.get("domains", []) or []) else "info"),
        ("凭据目标", (incident_sections.get("credentials", {}) or {}).get("total", 0), "medium"),
        ("唯一程序路径", (execution.get("stats", {}) or {}).get("program_paths", 0), "low"),
    ]
    cards_html = "".join(f'<div class="card"><div class="card-label">{_esc(label)}</div><div class="card-value {_esc(str(cls))}">{_esc(value)}</div></div>' for label, value, cls in cards)
    parts = []
    parts.append("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Windows 只读排查报告</title>")
    parts.append("<style>body{margin:0;background:#f6f7f9;color:#1c2024;font:14px/1.55 system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif}header{background:#101828;color:#fff;padding:28px 24px}header h1{margin:0 0 6px;font-size:23px}header p{margin:0;color:#cbd5e1}main{max-width:1320px;margin:0 auto;padding:20px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:18px}.card{background:#fff;border:1px solid #d9dee5;border-radius:10px;padding:14px}.card-label{color:#667085;font-size:12px}.card-value{font-size:20px;font-weight:700;margin-top:6px}.critical{color:#b42318}.high{color:#d92d20}.medium{color:#b54708}.low{color:#475467}.info{color:#175cd3}section{background:#fff;border:1px solid #d9dee5;border-radius:10px;padding:18px;margin:16px 0}h2{margin:0 0 12px;font-size:18px}h3{margin:18px 0 8px;font-size:15px}table{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}th,td{border-bottom:1px solid #d9dee5;text-align:left;vertical-align:top;padding:8px}th{background:#f2f4f7}td.path{font-family:ui-monospace,Consolas,monospace;word-break:break-all}.detail{color:#667085;font-size:12px;margin-top:3px}.badge{display:inline-block;padding:2px 7px;border-radius:999px;font-size:12px;border:1px solid currentColor}.filter{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}input,select{padding:8px 10px;border:1px solid #d9dee5;border-radius:7px;background:#fff}.banner{border-left:4px solid #b54708;background:#fffaeb;padding:12px 14px;border-radius:6px}.ai{border-left:4px solid #1f5eff;background:#eff4ff;padding:12px 14px;border-radius:6px}code{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-family:ui-monospace,Consolas,monospace}footer{color:#667085;padding:18px 0 40px;font-size:12px}</style></head><body>")
    parts.append(f"<header><h1>Windows 只读排查</h1><p>{_esc(meta.get('generated_at',''))} · {_esc(meta.get('computer',''))} / {_esc(meta.get('user',''))} · {_esc(meta.get('profile',''))} · v{_esc(meta.get('tool_version',''))}</p></header><main>")
    parts.append(f'<div class="cards">{cards_html}</div>')
    parts.append(f'<section><h2>结论摘要</h2><p><strong>{_esc(summary["headline"])}</strong></p><p>{_esc(summary["advice"])}</p><div class="banner">只读分诊：不删除文件、不联网、不上传，也不能证明系统干净。Steam 基线只读比对，本次未写入或更新。</div><div class="ai"><strong>如果自己看不懂：</strong>{_esc(AI_HINT)}</div></section>')
    parts.append('<section><h2>发现</h2><div class="filter"><label>筛选：<input id="q" type="search" placeholder="输入路径、标题、类别…"></label><label>级别：<select id="sev"><option value="">全部</option><option value="critical">严重</option><option value="high">高</option><option value="medium">中</option><option value="low">低</option><option value="info">信息</option></select></label></div>')
    parts.append(_html_findings(findings))
    parts.append('</section>')
    parts.append(f'<section><h2>1. C: 盘乱码/异常文件夹</h2><p>扫描 {_esc((weird.get("stats",{}) or {}).get("scanned_dirs",0))} 个目录；候选 {_esc(weird.get("total_candidates",0))} 个。完整目录清单：<code>{_esc(weird.get("dir_log",""))}</code></p>{_rows_html(weird_rows, ["级别","分数","路径","原因","修改时间"])}</section>')
    parts.append(f'<section><h2>2. Steam 路径与只读基线</h2><p>主安装目录：<code>{_esc(steam.get("primary_root",""))}</code></p><h3>安装根</h3>{_rows_html(root_rows, ["主","路径","steam.exe","来源","盘类型"])}<h3>库目录</h3>{_rows_html(lib_rows, ["路径","存在","盘类型","App 数","来源"])}<h3>与基线的变化（只读）</h3>{_rows_html(drift_rows, ["类型","变化","键","旧值","新值"])}</section>')
    parts.append(f'<section><h2>3. Steam 客户端完整性</h2><p>结论：<strong>{_esc(integrity.get("status_label",""))}</strong>；版本 <code>{_esc(integrity.get("client_version",""))}</code></p>{_rows_html(core_rows, ["文件","签名状态","Valve","签名者","SHA-256","问题"])}<h3>完整性发现</h3>{_html_findings(integrity.get("findings",[]) or [])}</section>')
    parts.append(f'<section><h2>4. 程序调用路径与可疑软件</h2><p>进程 {_esc((execution.get("stats",{}) or {}).get("processes",0))}，服务 {_esc((execution.get("stats",{}) or {}).get("services",0))}，计划任务 {_esc((execution.get("stats",{}) or {}).get("tasks",0))}，唯一程序路径 {_esc((execution.get("stats",{}) or {}).get("program_paths",0))}。</p>{_rows_html(suspicious_rows, ["级别","分数","类型","名称","路径","原因"])}</section>')
    parts.append(f'<section><h2>5. Level Infinite / insightjs 供应链事件（文件 + 注册表 + 浏览器）</h2><p>结论：<strong>{_esc(incident.get("status_label",""))}</strong>；{_esc(incident.get("stage_label",""))}；阶段 1/2/3/4：{_esc(incident.get("stage1"))}/{_esc(incident.get("stage2"))}/{_esc(incident.get("stage3"))}/{_esc(incident.get("stage4"))}</p><h3>启动器</h3>{_rows_html(launcher_rows, ["游戏","安装根","debug.log","tinyget"])}<h3>debug.log 标记</h3>{_rows_html(debug_rows, ["文件","标记","次数"])}<h3>Code Cache / Local Storage</h3>{_rows_html(cache_rows, ["文件","命中","读取方式"])}<h3>HTTP 缓存（gzip 已解压）</h3>{_rows_html(http_rows, ["编码","命中","SHA-256","缓存文件"])}<h3>浏览器持久化</h3>{_rows_html(helper_rows, ["路径","文件"])}<h3>CLSID</h3>{_rows_html(clsid_rows, ["CLSID","视图","InprocServer32","用户 Hive"])}<h3>TEMP 痕迹</h3>{_rows_html(temp_rows, ["文件","说明"])}<h3>USN 更改日志</h3>{_rows_html(usn_rows, ["盘","扫描行数","截断","覆盖时间","命中"])}<h3>凭据暴露面</h3>{_rows_html(credential_rows, ["类别","文件数"])}<h3>本次事件发现</h3>{_html_findings(incident.get("findings",[]) or [])}</section>')
    parts.append(f'<section><h2>6. 域名与网络访问证据</h2><p>域名 {_esc((domains.get("counts",{}) or {}).get("domains",0))} 个，IOC {_esc((domains.get("counts",{}) or {}).get("ioc_domains",0))} 个；程序级 DNS {_esc((domains.get("counts",{}) or {}).get("program_events",0))} 条；API 端点 {_esc((domains.get("counts",{}) or {}).get("api_endpoints",0))} 条。</p><h3>域名汇总</h3>{_rows_html(domain_rows, ["域名","分类","记录数","来源","相关进程","最后时间"])}<h3>程序级 DNS</h3>{_rows_html(event_rows, ["程序","域名","时间","来源"])}<h3>程序请求的 API 地址</h3>{_rows_html(endpoint_rows, ["端点","程序","来源"])}<h3>域名发现</h3>{_html_findings(domains.get("findings",[]) or [])}</section>')
    parts.append(f'<section><h2>7. 扫描统计与错误</h2><p>错误/不可读：{_esc(len(result.get("errors",[]) or []))}</p><pre>{_esc(chr(10).join(str(item) for item in (result.get("errors",[]) or [])[:80]))}</pre></section>')
    parts.append(f'<footer>只读报告 · 生成于 {_esc(now_iso())} · 详细数据见 report.json · 报告含本机路径与域名，公开前请脱敏</footer></main>')
    parts.append('<script>const q=document.getElementById("q");const sev=document.getElementById("sev");function applyFilter(){const text=(q.value||"").toLowerCase();const level=sev.value;document.querySelectorAll("table.findings tbody tr").forEach(function(row){const hay=row.innerText.toLowerCase();const show=(!text||hay.indexOf(text)>=0)&&(!level||row.dataset.severity===level);row.style.display=show?"":"none";});}q.addEventListener("input",applyFilter);sev.addEventListener("change",applyFilter);</script></body></html>')
    return "".join(parts)


def write_reports(result: Dict[str, Any], output_dir: str) -> Dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "report.json")
    md_path = os.path.join(output_dir, "report.md")
    html_path = os.path.join(output_dir, "report.html")
    summary_path = os.path.join(output_dir, "summary.txt")
    atomic_write_json(json_path, result)
    atomic_write_text(md_path, build_markdown(result))
    atomic_write_text(html_path, build_html(result))
    atomic_write_text(summary_path, build_summary_text(result))
    return {"json": json_path, "markdown": md_path, "html": html_path, "summary": summary_path}
