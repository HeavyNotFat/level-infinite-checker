#!/usr/bin/env python3
"""Read-only Windows triage for weird folder names, Steam path drift,
Steam client integrity, program invocation paths, and the 2026 NIKKE/K2F IOCs.

This tool never deletes, quarantines, or modifies system state.  It writes a
report under the chosen output directory and, on first Steam run, a baseline
under the state directory.
"""
from __future__ import annotations

import argparse
import ctypes
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from vcheck_lib import __version__
from vcheck_lib.execution import build_execution_report, collect_inventory, collect_process_modules
from vcheck_lib.incident import scan_incident
from vcheck_lib.models import Finding, max_severity, severity_rank
from vcheck_lib.netintel import collect_domain_intel
from vcheck_lib.report import summarize, write_reports
from vcheck_lib.steam_integrity import evaluate_integrity, enumerate_steam_binaries, summarize_integrity
from vcheck_lib.steam_paths import build_snapshot, collect_steam_shortcuts, compare_with_baseline, discover_steam
from vcheck_lib.signatures import collect_signatures
from vcheck_lib.utils import canonical_key, ensure_dir, get_file_version, load_json, now_iso, now_timestamp
from vcheck_lib.weird_dirs import scan_weird_dirs


def _configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _log(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(message, flush=True)


def _user_profiles() -> List[str]:
    base = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users")
    profiles: Dict[str, str] = {}
    try:
        with os.scandir(base) as iterator:
            for entry in iterator:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                # Do not scan the 8.3 alias (ADMINI~1) as a second profile.
                if "~" in entry.name:
                    continue
                key = os.path.normcase(os.path.realpath(entry.path))
                profiles[key] = entry.path
    except OSError:
        pass
    current = os.environ.get("USERPROFILE")
    if current:
        key = os.path.normcase(os.path.realpath(current))
        profiles.setdefault(key, current)
    return list(profiles.values())


def _quick_weird_groups() -> List[tuple]:
    groups = [
        ("C:\\", 1),
        (r"C:\ProgramData", 3),
        (os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"), 3),
    ]
    temp = os.environ.get("TEMP")
    if temp:
        groups.append((os.path.realpath(temp), 4))
    for profile in _user_profiles():
        for rel, depth in (
            (r"AppData\Local", 3),
            (r"AppData\Roaming", 3),
            (r"Downloads", 3),
            (r"Desktop", 2),
            (r"Documents", 2),
        ):
            path = os.path.join(profile, rel)
            if os.path.isdir(path):
                groups.append((path, depth))
    groups.append((os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users", "Public"), 3))
    return groups


def _merge_weird(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not results:
        return {"roots": [], "candidates": [], "total_candidates": 0, "returned_candidates": 0, "stats": {"scanned_dirs": 0, "scanned_files": 0, "skipped_names": 0, "skipped_reparse": 0, "errors": 0, "elapsed_seconds": 0, "truncated": False, "max_depth": None, "profile": "quick"}, "errors": [], "dir_log": "", "dir_log_records": 0, "dir_log_error": ""}
    merged: Dict[str, Dict[str, Any]] = {}
    roots: List[str] = []
    errors: List[Dict[str, str]] = []
    stats = {"scanned_dirs": 0, "scanned_files": 0, "skipped_names": 0, "skipped_reparse": 0, "errors": 0, "elapsed_seconds": 0.0, "truncated": False, "max_depth": None, "profile": "quick"}
    for result in results:
        roots.extend(result.get("roots", []))
        for item in result.get("candidates", []):
            key = canonical_key(item.get("path", ""))
            if key and (key not in merged or item.get("score", 0) > merged[key].get("score", 0)):
                merged[key] = item
        errors.extend(result.get("errors", []))
        for key in ("scanned_dirs", "scanned_files", "skipped_names", "skipped_reparse"):
            stats[key] += int(result.get("stats", {}).get(key, 0) or 0)
        stats["elapsed_seconds"] += float(result.get("stats", {}).get("elapsed_seconds", 0) or 0)
        stats["truncated"] = stats["truncated"] or bool(result.get("stats", {}).get("truncated"))
    ordered = sorted(merged.values(), key=lambda item: (-float(item.get("score", 0)), item.get("mtime", "")))
    stats["errors"] = len(errors)
    stats["elapsed_seconds"] = round(stats["elapsed_seconds"], 2)
    dir_log = next((item.get("dir_log", "") for item in results if item.get("dir_log")), "")
    dir_log_records = sum(int(item.get("dir_log_records", 0) or 0) for item in results)
    dir_log_error = next((item.get("dir_log_error", "") for item in results if item.get("dir_log_error")), "")
    stats["dir_log_records"] = dir_log_records
    stats["dir_log_error"] = dir_log_error
    return {
        "roots": list(dict.fromkeys(roots)),
        "candidates": ordered[:400],
        "total_candidates": len(ordered),
        "returned_candidates": min(len(ordered), 400),
        "dir_log": dir_log,
        "dir_log_records": dir_log_records,
        "dir_log_error": dir_log_error,
        "stats": stats,
        "errors": errors[:100],
    }


def _run_weird_scan(args, deadline: float, dir_log_path: str = "") -> Dict[str, Any]:
    if args.roots:
        groups = [(root, 6 if not args.full else None) for root in args.roots]
    elif args.full:
        groups = [("C:\\", None)]
    else:
        groups = _quick_weird_groups()
    results = []
    for root, depth in groups:
        remaining = int(max(5, deadline - time.monotonic()))
        result = scan_weird_dirs(
            [root],
            max_depth=depth,
            max_seconds=remaining,
            include_files=args.include_files,
            include_caches=args.include_caches,
            full=args.full,
            max_candidates=400,
            dir_log_path=dir_log_path or None,
        )
        results.append(result)
        if result.get("stats", {}).get("truncated"):
            break
        if time.monotonic() > deadline:
            break
    return _merge_weird(results)


def _findings_from_weird(weird: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    for item in weird.get("candidates", []) or []:
        if item.get("severity") not in ("high", "critical"):
            continue
        findings.append(Finding(
            title="异常文件夹名称：" + str(item.get("name", "")),
            severity=item.get("severity", "medium"),
            category="Weird folder",
            detail="；".join(item.get("reasons", [])[:6]),
            path=item.get("path", ""),
            source="weird_dirs",
            evidence={"score": item.get("score"), "reasons": item.get("reasons", []), "mtime": item.get("mtime", ""), "is_empty": item.get("is_empty")},
            recommendation="先确认是否由解压工具、旧软件或语言包造成；不要仅凭名称删除文件夹。",
        ).to_dict())
    return findings


def _dedupe_findings(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        key = (item.get("title", ""), canonical_key(item.get("path", "")), item.get("source", ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return sorted(result, key=lambda item: (-severity_rank(item.get("severity", "info")), item.get("category", ""), item.get("title", "")))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Windows 只读排查：异常文件夹 / Steam 路径与完整性 / 程序调用路径 / Level Infinite 供应链事件 / 域名访问")
    parser.add_argument("--full", action="store_true", help="完整扫描 C:（默认 quick：根目录+常见高风险目录）")
    parser.add_argument("--root", dest="roots", action="append", default=[], help="自定义扫描根，可重复")
    parser.add_argument("--max-seconds", type=int, default=0, help="异常文件夹扫描时间预算；默认 quick=180，full=900")
    parser.add_argument("--incident-budget", type=int, default=240, help="供应链事件检测时间预算（秒，默认 240）")
    parser.add_argument("--include-files", action="store_true", help="也检查异常文件名，不只文件夹")
    parser.add_argument("--include-caches", action="store_true", help="不跳过 Cache/Code Cache 等缓存目录")
    parser.add_argument("--output", default="", help="报告输出目录；默认 reports/scan-时间戳")
    parser.add_argument("--dir-log", default="", help="扫描目录清单 JSONL 路径；默认写到报告目录的 scanned_dirs.jsonl")
    parser.add_argument("--no-dir-log", action="store_true", help="不生成完整扫描目录清单")
    parser.add_argument("--state", default="state", help="Steam 基线目录（只读比对；本工具不会写入或更新基线）")
    parser.add_argument("--skip-weird", action="store_true", help="跳过异常文件夹扫描")
    parser.add_argument("--skip-steam", action="store_true", help="跳过 Steam 路径/完整性")
    parser.add_argument("--skip-execution", action="store_true", help="跳过程序调用路径清点")
    parser.add_argument("--skip-k2f", action="store_true", help="跳过 Level Infinite/K2F 供应链事件检测")
    parser.add_argument("--skip-domains", action="store_true", help="跳过域名与网络访问证据采集")
    parser.add_argument("--no-usn", action="store_true", help="不读取 NTFS USN 更改日志（更慢、需要管理员）")
    parser.add_argument("--quiet", action="store_true", help="少打印进度")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    _configure_console()
    args = parse_args(argv)
    if os.name != "nt":
        print("此工具针对 Windows；当前系统不是 Windows。", file=sys.stderr)
        return 2
    started = time.time()
    timestamp = now_timestamp()
    output_dir = args.output or os.path.join("reports", "scan-" + timestamp)
    ensure_dir(output_dir)
    max_seconds = args.max_seconds or (900 if args.full else 180)
    dir_log_path = ""
    if not args.skip_weird and not args.no_dir_log:
        dir_log_path = os.path.abspath(args.dir_log) if args.dir_log else os.path.join(os.path.abspath(output_dir), "scanned_dirs.jsonl")
        try:
            if os.path.exists(dir_log_path):
                os.remove(dir_log_path)
        except OSError as exc:
            print(f"警告：无法清理旧目录清单 {dir_log_path}: {exc}", flush=True)
    admin = _is_admin()
    _log("=" * 72)
    _log("Windows 只读排查")
    _log(f"主机: {socket.gethostname()}  用户: {os.environ.get('USERNAME', '')}  管理员: {'是' if admin else '否'}")
    _log(f"配置: {'full' if args.full else 'quick'}  输出: {os.path.abspath(output_dir)}")
    _log("提示: 如果自己看不懂结果，请把本软件生成的日志/报告（report.md 或 gui-run.log）发送给 AI 帮你解读。")
    _log("=" * 72)

    errors: List[str] = []

    # 1. Execution inventory first: Steam discovery uses the live process list.
    _log("[1/6] 收集进程、服务、计划任务、启动项、WMI、PATH ...")
    if args.skip_execution:
        inventory = {"available": False, "processes": [], "services": [], "drivers": [], "tasks": [], "startup": [], "wmi": [], "errors": []}
        execution = {"verdict": "info", "status_label": "已跳过", "records": {}, "program_paths": [], "suspicious": [], "findings": [], "path": {"entries": []}, "path_analysis": {"findings": []}, "installed_software": [], "stats": {}, "errors": []}
    else:
        inventory = collect_inventory()
        if inventory.get("error"):
            errors.append("execution: " + str(inventory["error"]))
        execution = build_execution_report(inventory)
        errors.extend("execution: " + str(item) for item in execution.get("errors", [])[:50])
    _log(f"      进程 {execution.get('stats', {}).get('processes', 0)}，服务 {execution.get('stats', {}).get('services', 0)}，"
         f"计划任务 {execution.get('stats', {}).get('tasks', 0)}，唯一程序路径 {execution.get('stats', {}).get('program_paths', 0)}")

    # 2. Modules + Steam discovery + integrity.
    modules = collect_process_modules()
    if modules.get("errors"):
        errors.extend("modules: " + str(item) for item in modules["errors"][:10])
    _log("[2/6] Steam 路径、库目录、签名与进程模块 ...")
    if args.skip_steam:
        steam = {"verdict": "info", "primary_root": "", "install_roots": [], "libraries": [], "registry_values": [], "processes": [], "findings": [], "errors": []}
        integrity = {"verdict": "info", "status_label": "已跳过", "client_version": "", "binaries": [], "core_binaries": [], "findings": [], "module_findings": [], "counts": {}}
        baseline_info = {"status": "skipped", "message": "已跳过 Steam 模块", "drift": {"changes": [], "counts": {"total": 0, "added": 0, "removed": 0, "changed": 0}}}
        steam["drift"] = baseline_info
    else:
        shortcuts = collect_steam_shortcuts()
        steam = discover_steam(inventory.get("processes", []), shortcuts)
        steam["shortcuts"] = shortcuts
        errors.extend("steam: " + str(item) for item in steam.get("errors", [])[:30])
        baseline = load_json(os.path.join(args.state, "steam_baseline.json"), default={}) or {}
        previous_hashes = baseline.get("key_hashes", {}) if isinstance(baseline, dict) else {}
        binaries = enumerate_steam_binaries(steam)
        signatures = collect_signatures([item["path"] for item in binaries]) if binaries else {}
        integrity = evaluate_integrity(steam, signatures, modules, previous_hashes)
        key_hashes = {item["relative"].casefold(): item.get("sha256", "") for item in integrity.get("core_binaries", []) if item.get("sha256")}
        snapshot = build_snapshot(steam, key_hashes, integrity.get("client_version", ""))
        # Read-only: the Steam baseline is compared but never created or updated.
        baseline_info = compare_with_baseline(os.path.join(args.state), snapshot)
        steam["drift"] = baseline_info
        _log(f"      主目录 {steam.get('primary_root', '')}；安装根 {len(steam.get('install_roots', []))}，"
             f"库 {len(steam.get('libraries', []))}；完整性 {integrity.get('status_label', '')}")
        _log(f"      基线 {baseline_info.get('status', '')}（只读，不写入）；变化 {baseline_info.get('drift', {}).get('counts', {}).get('total', 0)} 项")

    # 3. Weird folder scan.
    _log("[3/6] 扫描 C: 盘异常/乱码文件夹 ...")
    if args.skip_weird:
        weird = {"roots": [], "candidates": [], "total_candidates": 0, "returned_candidates": 0, "stats": {}, "errors": [], "dir_log": "", "dir_log_records": 0}
    else:
        weird = _run_weird_scan(args, time.monotonic() + max_seconds, dir_log_path)
        weird["dir_log"] = dir_log_path
        if weird.get("dir_log_error"):
            errors.append("dir-log: " + str(weird["dir_log_error"]))
        _log(f"      目录 {weird.get('stats', {}).get('scanned_dirs', 0)}，候选 {weird.get('total_candidates', 0)}，"
             f"目录清单 {weird.get('dir_log_records', 0)} 条"
             + ("（时间预算用尽，结果不完整）" if weird.get("stats", {}).get("truncated") else ""))

    # 4. Level Infinite / insightjs supply-chain incident (files, registry, browser).
    _log("[4/6] Level Infinite/insightjs 供应链事件全量检测（文件 + 注册表 + 浏览器 + 缓存 + USN）...")
    if args.skip_k2f:
        incident = {"verdict": "info", "status_label": "已跳过", "stage": 0, "stage_label": "已跳过", "stage1": False, "stage2": False, "stage3": False, "stage4": False, "launchers": [], "findings": [], "counts": {}, "sections": {}, "notes": []}
    else:
        incident = scan_incident(
            inventory.get("processes", []),
            modules,
            usn=not args.no_usn,
            budget_seconds=max(30, int(args.incident_budget)),
        )
        errors.extend("incident: " + str(item) for item in incident.get("errors", [])[:30])
        _log(f"      {incident.get('status_label', '')}；启动器 {incident.get('counts', {}).get('launchers', 0)} 个；发现 {len(incident.get('findings', []))}")

    # 5. Domain / network access evidence.
    _log("[5/6] 采集域名访问记录（DNS 缓存 / DNS 日志 / Sysmon / 浏览器历史 / 程序日志）...")
    if args.skip_domains:
        domains = {"verdict": "info", "findings": [], "domains": [], "program_events": [], "api_endpoints": [], "available": {}, "counts": {}, "sources": {}, "notes": [], "errors": []}
    else:
        extra_logs = []
        for launcher in incident.get("launchers", []) or []:
            if launcher.get("tinyget"):
                extra_logs.append((str(launcher["tinyget"]), "NIKKE 启动器"))
        domains = collect_domain_intel(
            incident.get("profiles") or _user_profiles(),
            inventory.get("processes", []),
            extra_log_dirs=extra_logs,
            budget_seconds=120,
        )
        errors.extend("domains: " + str(item) for item in domains.get("errors", [])[:20])
        _log(f"      域名 {domains.get('counts', {}).get('domains', 0)} 个；程序级 DNS {domains.get('counts', {}).get('program_events', 0)} 条；"
             f"API 端点 {domains.get('counts', {}).get('api_endpoints', 0)} 条")

    # 6. Aggregate and write.
    all_findings: List[Dict[str, Any]] = []
    for block in (steam, integrity, execution, incident, domains):
        all_findings.extend(block.get("findings", []) or [])
    all_findings.extend(_findings_from_weird(weird))
    all_findings = _dedupe_findings(all_findings)
    overall = max_severity([item.get("severity", "info") for item in all_findings])
    elapsed = round(time.time() - started, 1)
    meta = {
        "generated_at": now_iso(),
        "computer": socket.gethostname(),
        "user": os.environ.get("USERNAME", ""),
        "is_admin": admin,
        "profile": "full" if args.full else "quick",
        "elapsed_seconds": elapsed,
        "tool_version": __version__,
        "output_dir": os.path.abspath(output_dir),
        "state_dir": os.path.abspath(args.state),
        "steam_baseline_writable": False,
        "python": sys.version.split()[0],
        "max_seconds": max_seconds,
        "incident_budget": int(args.incident_budget),
        "usn_enabled": not args.no_usn,
        "roots": args.roots or (["C:\\"] if args.full else ["quick-profile"]),
    }
    result = {
        "meta": meta,
        "verdict": overall,
        "summary": summarize({"findings": all_findings}),
        "findings": all_findings,
        "weird_dirs": weird,
        "steam_paths": steam,
        "steam_integrity": integrity,
        "steam_integrity_summary": summarize_integrity(integrity),
        "execution": execution,
        "incident": incident,
        "domains": domains,
        "errors": errors[:200],
    }
    _log("[6/6] 生成报告 ...")
    paths = write_reports(result, output_dir)
    summary = result["summary"]
    print("")
    print("=" * 72)
    print(f"总体级别：{summary['severity_label']} — {summary['headline']}")
    print(f"报告：{os.path.abspath(paths['markdown'])}")
    print(f"      {os.path.abspath(paths['html'])}")
    print(f"      {os.path.abspath(paths['json'])}")
    print("=" * 72)
    if summary["top_findings"]:
        print("优先核对：")
        for item in summary["top_findings"][:10]:
            print(f"- [{item.get('severity')}] {item.get('title')}  {item.get('path', '')}")
    else:
        print("没有 high/critical 条目；仍请阅读报告中的低优先级差异与限制说明。")
    print("")
    print("如果自己看不懂结果：请把本次生成的 report.md 或 gui-run.log 发送给 AI，让它帮你逐条解读。")
    print("注意：报告含计算机名、用户名、本地路径和域名记录，公开前请脱敏。")
    if overall == "critical":
        return 3
    if overall == "high":
        return 2
    if overall == "medium":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
