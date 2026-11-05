"""Read-only domain / network access evidence collector.

Answers two questions the report needs:

1. Which domains did this host resolve or visit?  Sources: DNS client cache,
   the DNS Client operational event log, Sysmon event 22, browser history,
   hosts file and the launcher/agent logs.
2. Which program requested which address?  Sources: Sysmon DNS events (per
   process), program logs that contain URLs, and the live socket table.

No network request is made.  Browser databases are copied to a temporary
folder before SQLite reads them, so a running browser cannot be corrupted.
Only hostnames (and for API hosts a short path) are stored - never cookies,
passwords or query strings.
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from . import iocs
from .models import Finding, max_severity
from .utils import canonical_key, now_iso
from .winps import PowerShellError, ps_json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:  # frozen bundle
    import sys as _sys
    PROJECT_ROOT = getattr(_sys, "_MEIPASS", PROJECT_ROOT)
except Exception:  # pragma: no cover
    pass
DOMAIN_SCRIPT = os.path.join(PROJECT_ROOT, "tools", "Get-DomainAccess.ps1")

URL_RE = re.compile(r"https?://[^\s\"'<>\\\x00-\x1f]{4,600}", re.I)
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")

IOC_SEVERITY = {
    "analytics.insightjs.com": "critical",
    "insightjs.com": "high",
    "insightjs.org": "medium",
}

AI_HOSTS = (
    "api.anthropic.com", "claude.ai", "console.anthropic.com", "anthropic.com",
    "api.openai.com", "chatgpt.com", "platform.openai.com", "openai.com",
    "generativelanguage.googleapis.com", "gemini.google.com", "aistudio.google.com",
    "api.githubcopilot.com", "copilot.microsoft.com", "githubcopilot.com",
    "api.cursor.sh", "api2.cursor.sh", "cursor.com", "cursor.sh",
    "server.codeium.com", "codeium.com", "windsurf.com", "api.windsurf.com",
    "api.mistral.ai", "openrouter.ai", "api.deepseek.com", "api.groq.com",
    "api.together.xyz", "api.cohere.ai", "api.perplexity.ai", "api.x.ai",
    "huggingface.co", "api-inference.huggingface.co", "api.qwen.ai",
    "dashscope.aliyuncs.com", "api.replicate.com", "api.fireworks.ai",
    "api.llama.com", "api.minimax.chat", "api.moonshot.cn", "open.bigmodel.cn",
)

DEV_HOSTS = (
    "github.com", "api.github.com", "objects.githubusercontent.com",
    "raw.githubusercontent.com", "codeload.github.com", "gitlab.com",
    "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org",
    "files.pythonhosted.org", "crates.io", "static.crates.io",
    "proxy.golang.org", "repo.maven.apache.org", "plugins.gradle.org",
    "nuget.org", "api.nuget.org", "hub.docker.com", "registry-1.docker.io",
    "ghcr.io", "gcr.io", "packages.microsoft.com", "marketplace.visualstudio.com",
    "update.code.visualstudio.com", "vscode.dev", "api.vercel.com", "vercel.com",
)

CLOUD_HOSTS = (
    "amazonaws.com", "aws.amazon.com", "azure.com", "microsoftonline.com",
    "login.microsoftonline.com", "cloud.google.com", "cloudfunctions.net",
    "run.app", "digitalocean.com", "linode.com", "hetzner.cloud",
    "cloudflare.com", "api.cloudflare.com", "supabase.co", "neon.tech",
    "planetscale.com", "snowflakecomputing.com", "databricks.com",
    "mongodb.com", "terraform.io", "registry.terraform.io", "pulumi.com",
    "stripe.com", "api.stripe.com", "twilio.com", "sentry.io", "kaggle.com",
    "firebaseio.com", "googleapis.com",
)

ALERT_HOSTS = (
    "hooks.slack.com",
    "slack.com",
    "pastebin.com",
    "transfer.sh",
    "0x0.st",
    "file.io",
    "gofile.io",
    "catbox.moe",
    "temp.sh",
    "oshi.at",
    "termbin.com",
)

BROWSER_HISTORY = (
    ("Chrome", r"Google\Chrome\User Data"),
    ("Edge", r"Microsoft\Edge\User Data"),
    ("Brave", r"BraveSoftware\Brave-Browser\User Data"),
    ("Vivaldi", r"Vivaldi\User Data"),
)

PROGRAM_LOG_ROOTS = (
    ("%APPDATA%\\Code\\logs", "VS Code"),
    ("%APPDATA%\\Code - Insiders\\logs", "VS Code Insiders"),
    ("%APPDATA%\\Cursor\\logs", "Cursor"),
    ("%APPDATA%\\Windsurf\\logs", "Windsurf"),
    ("%APPDATA%\\Claude\\logs", "Claude Desktop"),
    ("%APPDATA%\\Claude", "Claude Desktop"),
    ("~/.claude", "Claude Code"),
    ("~/.codex", "Codex CLI"),
    ("~/.gemini", "Gemini CLI"),
    ("%APPDATA%\\npm-cache\\_logs", "npm"),
    ("%LOCALAPPDATA%\\pip\\Cache", "pip"),
)

# Config files that usually hold the API base URL / MCP server endpoints of an
# AI tool.  Only the URLs are kept, never the surrounding values (they often
# contain API keys).
PROGRAM_CONFIG_FILES = (
    ("~/.claude/settings.json", "Claude Code"),
    ("~/.claude.json", "Claude Code"),
    ("%APPDATA%\\Claude\\claude_desktop_config.json", "Claude Desktop"),
    ("~/.codex/config.toml", "Codex CLI"),
    ("~/.gemini/settings.json", "Gemini CLI"),
    ("%APPDATA%\\Code\\User\\mcp.json", "VS Code"),
    ("%APPDATA%\\Code\\User\\settings.json", "VS Code"),
    ("%APPDATA%\\Cursor\\User\\settings.json", "Cursor"),
    ("~/.cursor/mcp.json", "Cursor"),
    ("%APPDATA%\\Windsurf\\User\\settings.json", "Windsurf"),
    ("~/.codeium/windsurf/mcp_config.json", "Windsurf"),
    ("~/.continue/config.json", "Continue"),
    ("~/.continue/config.yaml", "Continue"),
    ("~/.kimi/mcp.json", "Kimi"),
    ("~/.qwen/settings.json", "Qwen Code"),
    ("~/.mcp.json", "MCP"),
)

LOG_SUFFIXES = (".log", ".txt", ".jsonl")
MAX_HISTORY_ROWS = 15000


# ---------------------------------------------------------------------------
def _expand(pattern: str) -> str:
    value = pattern
    if value.startswith("~"):
        value = os.environ.get("USERPROFILE", "") + value[1:]
    return os.path.normpath(os.path.expandvars(value))


def _normalise_host(value: str) -> str:
    host = (value or "").strip().strip(".").casefold()
    if not host:
        return ""
    if host.startswith("www."):
        host = host[4:]
    if ":" in host and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    if not HOST_RE.match(host):
        return ""
    if "." not in host:
        return ""
    # Reverse-DNS lookups and bare addresses are not "visited domains"; the
    # socket table covers addresses separately.
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or host.endswith(".in-addr.arpa") or host.endswith(".ip6.arpa"):
        return ""
    return host


def _is_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value or ""))


def classify(host: str) -> str:
    lower = host.casefold()
    if any(lower == item or lower.endswith("." + item) for item in iocs.C2_DOMAINS):
        return "攻击者基础设施"
    if any(lower == item or lower.endswith("." + item) for item in AI_HOSTS):
        return "AI API / AI 工具"
    if any(lower == item or lower.endswith("." + item) for item in DEV_HOSTS):
        return "开发 / 包管理 / 代码托管"
    if any(lower == item or lower.endswith("." + item) for item in CLOUD_HOSTS):
        return "云服务"
    if lower.endswith(".playerinfinite.com") or "playerinfinite" in lower:
        return "Level Infinite CDN"
    if lower.startswith("mcp.") or ".mcp." in lower or "modelcontextprotocol" in lower:
        return "MCP 服务"
    if any(lower == item or lower.endswith("." + item) for item in ALERT_HOSTS):
        return "Slack / 文件外传服务（需核对）"
    return "其他"


def _endpoint(url: str) -> str:
    """Keep scheme://host plus the first path segment; drop query/fragment.

    Chat web apps put conversation IDs in the path, so only one segment is
    kept and token-like segments are dropped.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = _normalise_host(parts.hostname or "")
    if not host:
        return ""
    segments = [item for item in (parts.path or "").split("/") if item][:1]
    if segments:
        segment = segments[0]
        if len(segment) > 24 or re.fullmatch(r"[0-9a-fA-F-]{8,}", segment) or segment.isdigit():
            segments = []
    path = "/" + "/".join(segments) if segments else ""
    return f"https://{host}{path}"


def _parse_time(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text[:19]


def _chromium_time(value: int) -> str:
    try:
        stamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value))
        return stamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError, TypeError):
        return ""


def _unix_micro(value: int) -> str:
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError, TypeError):
        return ""


# ---------------------------------------------------------------------------
class DomainTable:
    def __init__(self) -> None:
        self.records: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
        self.endpoints: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add(
        self,
        raw_host: str,
        source: str,
        count: int = 1,
        last_seen: str = "",
        process: str = "",
        url: str = "",
    ) -> None:
        host = _normalise_host(raw_host)
        if not host:
            return
        record = self.records.get(host)
        if record is None:
            record = {
                "domain": host,
                "class": classify(host),
                "count": 0,
                "sources": [],
                "processes": [],
                "last_seen": "",
                "ioc": any(host == item or host.endswith("." + item) for item in iocs.C2_DOMAINS),
            }
            self.records[host] = record
        record["count"] = int(record["count"]) + max(1, int(count))
        if source and source not in record["sources"]:
            record["sources"].append(source)
        if process:
            name = os.path.basename(process) or process
            if name not in record["processes"] and len(record["processes"]) < 8:
                record["processes"].append(name)
        if last_seen and last_seen > str(record["last_seen"]):
            record["last_seen"] = last_seen
        if url and record["class"] in ("AI API / AI 工具", "开发 / 包管理 / 代码托管", "云服务", "攻击者基础设施", "MCP 服务") and len(self.endpoints) < 1500:
            endpoint = _endpoint(url)
            if endpoint:
                key = (host, endpoint)
                item = self.endpoints.get(key)
                if item is None:
                    self.endpoints[key] = {"host": host, "endpoint": endpoint, "sources": [source], "processes": [process] if process else []}
                else:
                    if source not in item["sources"]:
                        item["sources"].append(source)
                    if process and os.path.basename(process) not in item["processes"]:
                        item["processes"].append(os.path.basename(process))

    def add_event(self, query: str, source: str, when: str, process: str = "") -> None:
        host = _normalise_host(query)
        if not host:
            return
        if len(self.events) < 20000:
            self.events.append({
                "domain": host,
                "source": source,
                "time": when,
                "process": os.path.basename(process) if process else "",
                "ioc": any(host == item or host.endswith("." + item) for item in iocs.C2_DOMAINS),
            })

    def sorted_domains(self) -> List[Dict[str, Any]]:
        items = list(self.records.values())
        items.sort(key=lambda item: (not item["ioc"], -int(item["count"]), item["domain"]))
        return items


# ---------------------------------------------------------------------------
def _run_domain_script(max_events: int = 3000) -> Dict[str, Any]:
    if not os.path.isfile(DOMAIN_SCRIPT):
        return {"available": {"dns_cache": False, "dns_events": False, "sysmon": False}, "errors": ["找不到 Get-DomainAccess.ps1"]}
    try:
        data = ps_json(DOMAIN_SCRIPT, ["-MaxEvents", str(max_events)], timeout=150)
    except PowerShellError as exc:
        return {"available": {"dns_cache": False, "dns_events": False, "sysmon": False}, "errors": [str(exc)]}
    if not isinstance(data, dict):
        return {"available": {"dns_cache": False, "dns_events": False, "sysmon": False}, "errors": ["域名脚本返回格式无效"]}
    data.setdefault("dns_cache", [])
    data.setdefault("dns_events", [])
    data.setdefault("sysmon_dns", [])
    data.setdefault("errors", [])
    data.setdefault("available", {})
    return data


def _dns_cache_from_ipconfig() -> List[str]:
    try:
        proc = subprocess.run(
            ["ipconfig", "/displaydns"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return []
    text = (proc.stdout or b"").decode("gb18030", "replace")
    names: List[str] = []
    for line in text.splitlines():
        lower = line.casefold()
        if "记录名称" not in lower and "record name" not in lower:
            continue
        if ":" not in line:
            continue
        candidate = line.split(":", 1)[1].strip()
        host = _normalise_host(candidate)
        if host:
            names.append(host)
    return names


def _browser_history(profiles: Iterable[str], table: DomainTable, budget: "Deadline") -> Dict[str, Any]:
    databases: List[Dict[str, str]] = []
    for profile in profiles:
        local = os.path.join(profile, "AppData", "Local")
        roaming = os.path.join(profile, "AppData", "Roaming")
        for browser, rel in BROWSER_HISTORY:
            base = os.path.join(local, rel)
            for path in [os.path.join(base, "History")] + glob.glob(os.path.join(base, "*", "History")):
                if os.path.isfile(path):
                    databases.append({"browser": browser, "path": path})
        opera = os.path.join(roaming, "Opera Software", "Opera Stable", "History")
        if os.path.isfile(opera):
            databases.append({"browser": "Opera", "path": opera})
        for path in glob.glob(os.path.join(roaming, "Mozilla", "Firefox", "Profiles", "*", "places.sqlite")):
            databases.append({"browser": "Firefox", "path": path})
    seen = set()
    result: Dict[str, Any] = {"databases": 0, "rows": 0, "browsers": [], "errors": []}
    for item in databases:
        key = canonical_key(item["path"])
        if key in seen or budget.expired():
            continue
        seen.add(key)
        rows = _read_history(item["path"], item["browser"] == "Firefox", budget)
        if rows is None:
            result["errors"].append(f"{item['browser']}: {item['path']}")
            continue
        result["databases"] += 1
        if item["browser"] not in result["browsers"]:
            result["browsers"].append(item["browser"])
        for url, visits, last in rows:
            host = ""
            try:
                host = urlsplit(url).hostname or ""
            except ValueError:
                continue
            table.add(host, f"{item['browser']} 历史", count=max(1, int(visits or 1)), last_seen=last, url=url)
            result["rows"] += 1
    return result


def _read_history(path: str, firefox: bool, budget: "Deadline") -> Optional[List[Tuple[str, int, str]]]:
    temp_dir = tempfile.mkdtemp(prefix="vcheck-hist-")
    try:
        target = os.path.join(temp_dir, "history.db")
        try:
            shutil.copy2(path, target)
        except OSError:
            return None
        # Sidecar files are best effort: a locked -shm must not lose the main DB.
        for suffix in ("-wal", "-journal", "-shm"):
            extra = path + suffix
            if not os.path.isfile(extra):
                continue
            try:
                shutil.copy2(extra, target + suffix)
            except OSError:
                continue
        try:
            connection = sqlite3.connect(target, timeout=8)
            connection.text_factory = lambda raw: raw.decode("utf-8", "replace")
            try:
                if firefox:
                    cursor = connection.execute(
                        "SELECT url, visit_count, last_visit_date FROM moz_places "
                        "WHERE url LIKE 'http%' ORDER BY last_visit_date DESC LIMIT ?",
                        (MAX_HISTORY_ROWS,),
                    )
                else:
                    cursor = connection.execute(
                        "SELECT url, visit_count, last_visit_time FROM urls "
                        "WHERE url LIKE 'http%' ORDER BY last_visit_time DESC LIMIT ?",
                        (MAX_HISTORY_ROWS,),
                    )
                rows: List[Tuple[str, int, str]] = []
                for url, visits, last in cursor:
                    if budget.expired():
                        break
                    rows.append((str(url or ""), int(visits or 0), _unix_micro(last) if firefox else _chromium_time(last)))
                return rows
            finally:
                connection.close()
        except sqlite3.Error:
            return None
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _program_logs(table: DomainTable, extra_dirs: Sequence[Tuple[str, str]], budget: "Deadline") -> Dict[str, Any]:
    roots: List[Tuple[str, str]] = []
    for pattern, label in PROGRAM_LOG_ROOTS:
        path = _expand(pattern)
        if os.path.isdir(path):
            roots.append((path, label))
    for path, label in extra_dirs:
        if path and os.path.isdir(path) and (path, label) not in roots:
            roots.append((path, label))
    result: Dict[str, Any] = {"files": 0, "urls": 0, "roots": [path for path, _label in roots], "errors": []}
    deadline = min(budget.deadline, time.monotonic() + 15.0)
    for root, label in roots:
        if time.monotonic() > deadline:
            break
        for path in _iter_log_files(root, limit=160):
            if time.monotonic() > deadline:
                break
            text = _read_text_tail(path, 2 * 1024 * 1024)
            if not text:
                continue
            result["files"] += 1
            for match in URL_RE.finditer(text):
                url = match.group(0).rstrip(").,;\"'")
                host = ""
                try:
                    host = urlsplit(url).hostname or ""
                except ValueError:
                    continue
                if not host:
                    continue
                table.add(host, f"{label} 日志", last_seen="", process=label, url=url)
                table.add_event(host, f"{label} 日志", "", process=label)
                result["urls"] += 1
    return result


def _iter_log_files(root: str, limit: int = 160, max_depth: int = 4):
    base_depth = root.rstrip("\\/").count(os.sep)
    count = 0
    cutoff = time.time() - 45 * 86400
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.rstrip("\\/").count(os.sep) - base_depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [name for name in dirnames if name.casefold() not in ("cache", "cacheddata", "node_modules", ".git")][:24]
        for name in filenames:
            if count >= limit:
                return
            if not name.casefold().endswith(LOG_SUFFIXES):
                continue
            path = os.path.join(dirpath, name)
            try:
                stat = os.stat(path)
            except OSError:
                continue
            if stat.st_size <= 0 or stat.st_size > 16 * 1024 * 1024 or stat.st_mtime < cutoff:
                continue
            count += 1
            yield path


def _read_text_tail(path: str, max_bytes: int) -> str:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
            raw = handle.read(max_bytes)
    except OSError:
        return ""
    for encoding in ("utf-8-sig", "gb18030", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _config_urls(table: DomainTable) -> Dict[str, Any]:
    result: Dict[str, Any] = {"files": 0, "urls": 0, "paths": []}
    for pattern, label in PROGRAM_CONFIG_FILES:
        path = _expand(pattern)
        if not os.path.isfile(path):
            continue
        try:
            if os.path.getsize(path) > 4 * 1024 * 1024:
                continue
        except OSError:
            continue
        text = _read_text_tail(path, 512 * 1024)
        if not text:
            continue
        result["files"] += 1
        result["paths"].append(path)
        for match in URL_RE.finditer(text):
            url = match.group(0).rstrip(").,;\"'")
            try:
                host = urlsplit(url).hostname or ""
            except ValueError:
                continue
            if not host:
                continue
            table.add(host, f"{label} 配置", process=label, url=url)
            result["urls"] += 1
    return result


def _hosts_entries() -> Dict[str, Any]:
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    try:
        with open(path, "rb") as handle:
            text = handle.read(4 * 1024 * 1024).decode("utf-8", "replace")
    except OSError:
        return {"path": path, "entries": 0, "mappings": []}
    mappings: List[Dict[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        address = parts[0]
        for host in parts[1:]:
            if host.startswith("#"):
                break
            normalised = _normalise_host(host)
            if not normalised:
                continue
            mappings.append({"host": normalised, "address": address})
            if len(mappings) >= 1000:
                break
        if len(mappings) >= 1000:
            break
    return {"path": path, "entries": len(mappings), "mappings": mappings[:400]}


def _connections(table: DomainTable, processes: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    names = {}
    for proc in processes or []:
        try:
            names[int(proc.get("pid") or 0)] = str(proc.get("name") or os.path.basename(str(proc.get("path") or "")))
        except (TypeError, ValueError):
            continue
    try:
        proc = subprocess.run(
            ["netstat", "-ano"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        return {"checked": False, "error": str(exc), "ioc": [], "total": 0}
    text = (proc.stdout or b"").decode("latin-1", "replace")
    total = 0
    ioc_hits: List[Dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        remote = parts[2]
        ip = remote.rsplit(":", 1)[0].strip("[]")
        if not _is_ip(ip) or ip.startswith(("127.", "0.0.0.0", "::")):
            continue
        total += 1
        pid = parts[-1] if parts[-1].isdigit() else ""
        name = names.get(int(pid), "") if pid else ""
        if ip in iocs.C2_IPS:
            ioc_hits.append({"ip": ip, "port": remote.rsplit(":", 1)[-1], "pid": pid, "process": name, "line": line.strip()[:240]})
    return {"checked": True, "error": "", "ioc": ioc_hits, "total": total}


class Deadline:
    def __init__(self, seconds: float) -> None:
        self.deadline = time.monotonic() + max(5.0, float(seconds))

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline


# ---------------------------------------------------------------------------
def collect_domain_intel(
    profiles: Sequence[str],
    processes: Optional[List[Dict[str, Any]]] = None,
    extra_log_dirs: Optional[Sequence[Tuple[str, str]]] = None,
    budget_seconds: float = 120.0,
) -> Dict[str, Any]:
    started = time.monotonic()
    budget = Deadline(budget_seconds)
    table = DomainTable()
    errors: List[str] = []
    script = _run_domain_script()
    for item in script.get("errors", []) or []:
        text = str(item)
        # "channel disabled / no events" means the source is unavailable, not
        # that the scan failed; the availability flags already report it.
        if any(token in text for token in (
            "No events were found", "not an event log", "未找到符合", "没有与",
            "no events", "not found",
        )):
            continue
        errors.append(f"domain-script: {text}")
    available = dict(script.get("available") or {})

    cache_rows = script.get("dns_cache") or []
    if cache_rows:
        for row in cache_rows:
            if not isinstance(row, dict):
                continue
            table.add(str(row.get("name", "")), "DNS 缓存")
    else:
        names = _dns_cache_from_ipconfig()
        for host in names:
            table.add(host, "DNS 缓存 (ipconfig)")
        if names:
            available["dns_cache"] = True

    event_rows = script.get("dns_events") or []
    for row in event_rows:
        if not isinstance(row, dict):
            continue
        query = str(row.get("query", ""))
        table.add_event(query, "DNS 客户端日志", _parse_time(str(row.get("time", ""))))
        table.add(query, "DNS 客户端日志", last_seen=_parse_time(str(row.get("time", ""))))

    sysmon_rows = script.get("sysmon_dns") or []
    for row in sysmon_rows:
        if not isinstance(row, dict):
            continue
        query = str(row.get("query", ""))
        image = str(row.get("image", ""))
        when = _parse_time(str(row.get("time", "")))
        table.add_event(query, "Sysmon DNS", when, process=image)
        table.add(query, "Sysmon DNS", last_seen=when, process=image)

    history = _browser_history(profiles, table, budget)
    errors.extend(history.get("errors", [])[:20])
    hosts = _hosts_entries()
    program_logs = _program_logs(table, list(extra_log_dirs or []), budget)
    configs = _config_urls(table)
    connections = _connections(table, processes)

    domains = table.sorted_domains()
    findings: List[Finding] = []
    for domain, severity in IOC_SEVERITY.items():
        record = table.records.get(domain)
        if not record:
            continue
        related = [
            item for host, item in table.records.items()
            if host == domain or host.endswith("." + domain)
        ]
        total = sum(int(item["count"]) for item in related)
        sources = sorted({source for item in related for source in item["sources"]})
        processes = sorted({name for item in related for name in item["processes"]})
        findings.append(Finding(
            title=f"本机访问记录中出现攻击者域名：{domain}",
            severity=severity,
            category="域名/网络证据",
            detail=(
                f"共 {total} 条记录，来源：{'、'.join(sources) or '未知'}。"
                + (f" 相关进程：{'、'.join(processes[:8])}。" if processes else "")
                + (" analytics 子域通常只在代理回连/上传时出现。" if domain.startswith("analytics.") else "")
            ),
            path="",
            source="domains",
            evidence={
                "domain": domain,
                "count": total,
                "sources": sources,
                "processes": processes,
                "related": {item["domain"]: item["count"] for item in related},
            },
            recommendation="按供应链失陷处置：断网、保全证据、轮换凭据；不要把 DNS 记录被清空当作安全证明。",
        ))
    for hit in connections.get("ioc", []) or []:
        findings.append(Finding(
            title="与已知 C2 IP 的实时连接",
            severity="critical",
            category="域名/网络证据",
            detail=f"{hit.get('ip')}:{hit.get('port')} 由 {hit.get('process') or '未知进程'} (PID {hit.get('pid')}) 持有。",
            path="",
            source="domains",
            evidence=hit,
            recommendation="立即断网并保全证据；该连接说明攻击者可能仍在操作主机。",
        ))
    if domains:
        findings.append(Finding(
            title="已采集本机域名访问记录",
            severity="info",
            category="域名/网络证据",
            detail=(
                f"共 {len(domains)} 个域名；DNS 缓存 {len(cache_rows)} 条，DNS 日志 {len(event_rows)} 条，"
                f"Sysmon {len(sysmon_rows)} 条，浏览器历史 {history.get('rows', 0)} 条，程序日志 URL {program_logs.get('urls', 0)} 条。"
            ),
            path="",
            source="domains",
            evidence={"counts": {"domains": len(domains)}},
        ))

    available_flags = {
        "dns_cache": bool(available.get("dns_cache")),
        "dns_events": bool(available.get("dns_events")),
        "sysmon": bool(available.get("sysmon")),
        "browser_history": bool(history.get("databases")),
        "program_logs": bool(program_logs.get("files")),
        "program_configs": bool(configs.get("files")),
        "hosts": bool(hosts.get("entries")),
        "sockets": bool(connections.get("checked")),
    }
    notes = [
        "DNS 缓存只保留最近解析；清空缓存、重启或用另一个 DNS 服务器都会让记录消失。",
        "DNS 客户端日志默认可能未启用；Sysmon 未安装时无法把域名精确归因到进程。",
        "浏览器历史只保存浏览器访问，AI CLI / IDE / Agent 的 API 请求不会出现在浏览器历史里；"
        "这部分由 Sysmon、程序日志和程序配置（MCP/API base URL）覆盖，都没有时无法证明。",
        "本工具不发起任何 DNS/TLS/HTTP 请求，也不会主动连接 C2；所有数据都来自本机已有记录。",
        "hosts 文件中的自定义映射不是访问记录，本工具单独列出，不混入域名访问统计。",
    ]
    verdict = max_severity([item.severity for item in findings])
    return {
        "generated_at": now_iso(),
        "verdict": verdict,
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "findings": [item.to_dict() for item in findings],
        "domains": domains[:4000],
        "program_events": table.events[:20000],
        "api_endpoints": sorted(table.endpoints.values(), key=lambda item: (item["host"], item["endpoint"]))[:1500],
        "sources": {
            "dns_cache": {"available": available_flags["dns_cache"], "entries": len(cache_rows)},
            "dns_events": {"available": available_flags["dns_events"], "entries": len(event_rows)},
            "sysmon": {"available": available_flags["sysmon"], "entries": len(sysmon_rows)},
            "browser_history": history,
            "hosts": {"path": hosts.get("path", ""), "entries": hosts.get("entries", 0), "mappings": hosts.get("mappings", [])[:200]},
            "program_logs": program_logs,
            "program_configs": configs,
            "connections": {"checked": connections.get("checked"), "total": connections.get("total", 0), "ioc": len(connections.get("ioc", []) or []), "error": connections.get("error", "")},
        },
        "available": available_flags,
        "counts": {
            "domains": len(domains),
            "ioc_domains": sum(1 for item in domains if item.get("ioc")),
            "ai_domains": sum(1 for item in domains if item.get("class") == "AI API / AI 工具"),
            "program_events": len(table.events),
            "api_endpoints": len(table.endpoints),
            "browser_rows": history.get("rows", 0),
            "program_log_urls": program_logs.get("urls", 0),
            "config_urls": configs.get("urls", 0),
        },
        "errors": errors[:50],
        "notes": notes,
    }
