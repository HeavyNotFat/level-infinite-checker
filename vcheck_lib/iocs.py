"""Indicators for the 2026 Level Infinite launcher supply-chain incident.

All data below is defensive and read-only.  It comes from the public incident
report (MotherSphere, "NIKKE PC launcher compromise", 2026-11-05), the Level
Infinite advisory and the community analyses linked from it.

Nothing in this module is used to contact the attacker infrastructure.  The C2
domains/IPs are only used to match local artefacts (hosts, DNS cache, sockets).
"""
from __future__ import annotations

INCIDENT_NAME = "Level Infinite 启动器供应链投毒 / insightjs K2F RAT"
INCIDENT_WINDOW_START = "2026-09-27"
AGENT_EARLIEST = "2026-10-23"
REVIEW_SNAPSHOT = "2026-11-04 02:01-02:07 UTC"

# --------------------------------------------------------------------------
# Infrastructure (never contacted; match only)
# --------------------------------------------------------------------------
C2_DOMAINS = (
    "insightjs.com",
    "analytics.insightjs.com",
    "insightjs.org",
)
C2_IPS = (
    "89.127.233.127",
    "89.126.250.172",
)
LOADER_URL_FRAGMENTS = (
    "insightjs.com/l.js",
    "insightjs.org/l.js",
    "l.js?f=aegis",
    "l.js?f=images",
    "l.js?f=feedlist",
    "l.js?f=vue",
)
PAYLOAD_URL = "analytics.insightjs.com/comm/assets/insight.bundle"
PAYLOAD_PATH = "/comm/assets/insight.bundle"
TELEMETRY_URL = "na.fleetlogd.com"
TELEMETRY_REFERER = "Referer: https://analytics.insightjs.com/"
C2_ENDPOINTS = (
    "/px/",
    "/collect/",
)

# --------------------------------------------------------------------------
# Official CDN files that were tampered with (2026-09-27 06:41-06:42 UTC)
# --------------------------------------------------------------------------
TAMPERED_ASSETS = {
    "2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203": {
        "name": "FeedList.feb647c9.js",
        "size": 5808,
        "last_modified": "2026-09-27 06:42:03 UTC",
        "host": "na-webassets.playerinfinite.com",
    },
    "3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193": {
        "name": "vue-bucket.min.js",
        "size": 135273,
        "last_modified": "2026-09-27 06:41:44 UTC",
        "host": "na-webassets.playerinfinite.com",
    },
    "21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce": {
        "name": "images.7fec4c32.js",
        "size": 4358,
        "last_modified": "2026-09-27 06:41:57 UTC",
        "host": "na-webassets.playerinfinite.com",
    },
    "04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d": {
        "name": "aegis-fix.min.js",
        "size": 69731,
        "last_modified": "2026-09-27 06:41:40 UTC",
        "host": "sg-gpts.playerinfinite.com",
    },
}

CLEAN_ASSETS = {
    "83bb8f30c65fd31208089f4107f316e7073c9b1213a8a3b2b512ab99e261de18": "aegis-fix.min.js",
    "4ad53349f98b86fd3a97bc386b2a1f555baf27c27a270f272404d47c9d7cc065": "images.7fec4c32.js",
    "49b625b30b34dc1fa16edba30bdf63c18b6171a0fc4cf030e21ea4e1263ae18a": "FeedList.feb647c9.js",
    "459343517635a96caa109b050361b4d32393e8727b2f54b44749db783feb4199": "vue-bucket.min.js",
}

# LuaJIT payload builds.  Sizes are build-specific, so the LuaJIT header below
# is the authoritative check.
PAYLOAD_ASSETS = {
    "cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec": {
        "name": "insight.bundle",
        "size": 205135,
        "note": "2026-11-03 16:22 UTC 构建，公开样本",
    },
    "60fd53ab7356384ba2161b9bc84420cd170905011a2f3ca09f3e38fe3122f3a1": {
        "name": "k2f.lua",
        "size": 165108,
        "note": "2026-10-23 早期构建，只有 14 条命令",
    },
    "f3e93d049851d5c19552c7d9b73c8be4580dc9d549e8f65f9f0c357c1df9d252": {
        "name": "k2f loader DLL",
        "size": 0,
        "note": "公开样本 Sample-A",
    },
    "931747d56b9639829aecd5540991d53df336ff4e93b30c7db0c8df7a6038942e": {
        "name": "platform_experience_helper.dll",
        "size": 0,
        "note": "公开扫描器给出的第 2 阶段 DLL 哈希（每个受害者可能不同）",
    },
}

HASH_LABELS = {}
for _digest, _meta in TAMPERED_ASSETS.items():
    HASH_LABELS[_digest] = ("被篡改的官方文件：" + _meta["name"], "critical")
for _digest, _meta in PAYLOAD_ASSETS.items():
    HASH_LABELS[_digest] = ("K2F 载荷/加载器：" + _meta["name"], "critical")

LUAJIT_HEADER = b"\x1bLJ\x01"

# nginx ETag of insight.bundle: hex mtime + "-3214f" (size 205,135)
INSIGHT_ETAGS = (
    "6ae60b83-3214f",
    "6ae69086-3214f",
    "6ae78037-3214f",
    "6ae8ccff-3214f",
    "6ae90538-3214f",
    "6ae9d408-3214f",
    "6ae9f628-3214f",
)

# --------------------------------------------------------------------------
# Launcher cache artefacts
# --------------------------------------------------------------------------
CODE_CACHE_ENTRIES = {
    "dd65fa4d61079e7e_0": "aegis",
    "ce2fd3f1007a9fe9_0": "images",
    "1416c638b3830103_0": "feedlist",
    "fd520c7c0f65c2d7_0": "vue",
}

LOADER_JS_MARKERS = (
    b"String.fromCharCode(111,114,103)",
    b"new Uint32Array(",
    b"TextDecoder().decode",
    b"insightjs.com/l.js",
    b"insightjs.org/l.js",
    b"Srv_DownloadFile",
)

CACHE_MARKERS = (
    b"insightjs.com/l.js",
    b"insightjs.org/l.js",
    b"l.js?f=",
    b"analytics.insightjs.com",
    b"insight.bundle",
    b"K2F_LUA_BUILD",
    b"k2f_chan",
    b"k2f.agent",
    b"BEARER000",
    b"/collect/",
    b"chrome_install",
)

LEVELDB_NEEDLES = (
    b"k2f.agent.state",
    b"k2f.agent",
    b"agent_pass",
    b"poll_interval_seconds",
    b"collect_cookies",
    b"k2f_chan",
)

# debug.log markers: (needle, label, severity, stage)
DEBUG_MARKERS = (
    ("k2f_chan registered", "K2F 命名管道已注册（代理已下载并运行）", "critical", 3),
    ("agent started as", "K2F agent 已启动并取得主机标识", "critical", 3),
    ("adopted ", "K2F 已接管管道/会话", "high", 3),
    ("startup failed: EIO", "K2F 启动失败（仍代表已执行）", "high", 3),
    ("lua downloaded to log", "K2F Lua 载荷已下载", "high", 2),
    ("startup already in progress", "K2F 下载前重复启动标记", "medium", 2),
    ("resuming", "K2F 会话恢复标记", "medium", 3),
)

TINYGET_MARKERS = (
    ("analytics.insightjs.com", "载荷下载地址", "high"),
    ("insight.bundle", "载荷文件名", "high"),
    ("K2F_LUA_BUILD", "K2F 内部构建名", "high"),
    ("k2f_chan", "K2F 管道标记", "high"),
    ("curl perform success", "下载请求成功", "medium"),
    ("OnDownloadResult", "下载结果记录", "medium"),
    ("insightjs", "insightjs 域名引用", "high"),
)

# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------
KNOWN_CLSID = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}"
HELPER_DIR_NAME = "PlatformExperienceHelper"
HELPER_DLL_NAMES = (
    "platform_experience_helper.dll",
    "platform_experience_helper.dll.old",
    "old-clsid.txt",
    "service_util.dll",
)

BROWSER_DATA_DIRS = (
    r"Google\Chrome\User Data",
    r"Microsoft\Edge\User Data",
    r"BraveSoftware\Brave-Browser\User Data",
    r"Vivaldi\User Data",
    r"Chromium\User Data",
    r"Opera Software\Opera Stable",
    r"Opera Software\Opera GX Stable",
)

TEMP_PATTERNS = (
    ("k2f-bcreds-*", "浏览器凭据临时副本（browserscan）"),
    ("k2f_screen_*.jpg", "屏幕截图"),
    ("k2f_screen_*.png", "屏幕截图（早期构建）"),
    ("k2f-keyscan-*", "keyscan 凭据临时副本（早期构建）"),
    ("k2f*.lua", "K2F Lua 载荷"),
    ("insight.bundle", "K2F LuaJIT 载荷"),
)

# --------------------------------------------------------------------------
# Launchers / affected titles
# --------------------------------------------------------------------------
LAUNCHER_EXE_NAMES = (
    "nikke_launcher.exe",
    "nikke_launcher_hmt.exe",
    "nikke_launcher_google.exe",
)

# Only NIKKE is confirmed by the public analysis.  The other titles are the
# ones named in the widely shared list; they are probed for the same launcher
# framework but a hit is reported as "needs confirmation", not as an IOC.
GAME_HINTS = (
    ("NIKKE", ("nikke",)),
    ("PUBG: 绝地求生", ("pubg",)),
    ("Conan Chop Chop", ("conan chop chop", "conanchopchop")),
    ("Davy x Jones", ("davy x jones", "davyxjones")),
    ("Den of Wolves", ("den of wolves", "denofwolves")),
    ("Dune: Awakening", ("dune awakening", "duneawakening")),
    ("Dune: Spice Wars", ("dune spice wars", "dunespicewars")),
    ("Exoborne", ("exoborne",)),
    ("Exterminauts", ("exterminauts",)),
    ("GTFO", ("gtfo",)),
    ("Metal: Hellsinger", ("hellsinger",)),
    ("Nightingale", ("nightingale",)),
    ("Song of Nunu", ("song of nunu", "songofnunu")),
    ("Undawn", ("undawn",)),
    ("V Rising", ("v rising", "vrising")),
    ("Warhammer 40,000: Darktide", ("darktide",)),
    ("Warhammer: Vermintide 2", ("vermintide",)),
)

KNOWN_INSTALL_DIR_NAMES = (
    "NIKKE",
    "NIKKE_GOOGLE",
    "NIKKE_HMT",
    "Level Infinite",
    "LevelInfinite",
    "Tencent",
)

LAUNCHER_DATA_DIRS = (
    "nikke_launcher",
    "nikke_launcher_hmt",
    "nikke_launcher_google",
)

# --------------------------------------------------------------------------
# Credential inventory (decoded from insight.bundle; `~` = %USERPROFILE%)
# --------------------------------------------------------------------------
SENSITIVE_PATHS = (
    # AI / coding agents
    r"~\.claude\.credentials.json",
    r"~\.claude.json",
    r"~\.claude\settings.json",
    r"%APPDATA%\Claude\claude_desktop_config.json",
    r"%APPDATA%\Anthropic\credentials\*.json",
    r"~\.codex\auth.json",
    r"~\.codex\config.toml",
    r"$CODEX_HOME\auth.json",
    r"$CODEX_HOME\config.toml",
    r"~\.gemini\oauth_creds.json",
    r"~\.gemini\settings.json",
    r"~\.gemini\google_accounts.json",
    r"$GEMINI_CLI_HOME\.gemini\oauth_creds.json",
    r"~\.copilot\mcp-config.json",
    r"$COPILOT_HOME\mcp-config.json",
    r"%APPDATA%\Code\User\mcp.json",
    r"%APPDATA%\Code\User\settings.json",
    r"%APPDATA%\Code\User\globalStorage\state.vscdb",
    r"%APPDATA%\Code\User\workspaceStorage\*\state.vscdb",
    r"%APPDATA%\Code - Insiders\User\globalStorage\state.vscdb",
    r"%APPDATA%\Cursor\User\settings.json",
    r"%APPDATA%\Cursor\User\globalStorage\state.vscdb",
    r"%APPDATA%\Windsurf\User\settings.json",
    r"%APPDATA%\Windsurf\User\globalStorage\state.vscdb",
    r"%APPDATA%\Windsurf\User\globalStorage\storage.json",
    r"~\.codeium\windsurf\mcp_config.json",
    r"~\.cursor\mcp.json",
    r"~\.kimi\config.toml",
    r"~\.kimi\credentials\*.json",
    r"~\.kimi\mcp.json",
    r"~\.continue\config.json",
    r"~\.continue\config.yaml",
    r"~\.continue\assistants\*.yaml",
    r"~\.qwen\settings.json",
    r"~\.qwen\.env",
    r"~\.aider.conf.yml",
    r"~\.dsh\.credentials.yaml",
    r"$DSH_HOME\.credentials.yaml",
    r"$CLAUDE_CONFIG_DIR\.credentials.json",
    r"%PROGRAMDATA%\gemini-cli\settings.json",
    # Cloud / DevOps
    r"~\.aws\credentials",
    r"~\.aws\config",
    r"~\.aws\sso\cache\*.json",
    r"~\.aws\sso\cache\kiro-auth-token.json",
    r"%APPDATA%\gcloud\credentials.db",
    r"%APPDATA%\gcloud\access_tokens.db",
    r"%APPDATA%\gcloud\application_default_credentials.json",
    r"$CLOUDSDK_CONFIG\credentials.db",
    r"$CLOUDSDK_CONFIG\access_tokens.db",
    r"$CLOUDSDK_CONFIG\application_default_credentials.json",
    r"~\.Azure\accessTokens.json",
    r"~\.Azure\msal_token_cache.bin",
    r"~\.Azure\service_principal_entries.bin",
    r"$AZURE_CONFIG_DIR\accessTokens.json",
    r"$AZURE_CONFIG_DIR\msal_token_cache.bin",
    r"~\.oci\config",
    r"~\.oci\*",
    r"~\.oraclebmc\config",
    r"~\.tccli\*.credential",
    r"~\.bce\config.json",
    r"~\.volcengine\config.json",
    r"~\.aliyun\config.json",
    r"~\.hcloud\config.json",
    r"%APPDATA%\hcloud\cli.toml",
    r"~\.config\linode-cli",
    r"%APPDATA%\doctl\config.yaml",
    r"~\.fly\config.yml",
    r"~\.railway\config.json",
    r"%APPDATA%\netlify\Config\config.json",
    r"%APPDATA%\.wrangler\config\default.toml",
    r"~\.config\configstore\firebase-tools.json",
    r"%USERPROFILE%\.config\configstore\snyk.json",
    r"~\.config\stripe\credentials.json",
    r"~\.config\stripe\config.toml",
    r"~\.config\planetscale\access-token",
    r"~\.supabase\access-token",
    r"%USERPROFILE%\.config\neonctl\credentials.json",
    r"~\.terraformrc",
    r"~\.terraform.d\credentials.tfrc.json",
    r"%APPDATA%\terraform.rc",
    r"%APPDATA%\terraform.d\credentials.tfrc.json",
    r"~\.pulumi\credentials.json",
    r"$PULUMI_HOME\credentials.json",
    r"~\.kube\config",
    r"%APPDATA%\helm\repositories.yaml",
    r"~\.config\gh\hosts.yml",
    r"%APPDATA%\GitHub CLI\hosts.yml",
    r"$GH_CONFIG_DIR\hosts.yml",
    r"~\.config\glab-cli\config.yml",
    r"%LOCALAPPDATA%\glab-cli\config.yml",
    r"~\.docker\config.json",
    r"%USERPROFILE%\.config\containers\auth.json",
    r"$DOCKER_CONFIG\config.json",
    r"~\.argocd\config",
    r"$ARGOCD_CONFIG_DIR\config",
    r"~\.databrickscfg",
    r"~\.snowflake\config.toml",
    r"~\.snowflake\connections.toml",
    r"%LOCALAPPDATA%\snowflake\config.toml",
    r"%LOCALAPPDATA%\snowflake\connections.toml",
    r"$SNOWFLAKE_HOME\config.toml",
    r"~\.dbt\profiles.yml",
    r"~\.modal.toml",
    r"~\.runpod\config.toml",
    r"~\.expo\state.json",
    r"~\.jenkins\secrets\initialAdminPassword",
    r"C:\Program Files\Jenkins\secrets\initialAdminPassword",
    r"C:\GitLab-Runner\config.toml",
    r"C:\buildkite-agent\buildkite-agent.cfg",
    r"%APPDATA%\Buildkite CLI\bk.yaml",
    r"~\.circleci\cli.yml",
    r"~\.config\circleci\config.yml",
    r"~\.config\tea\config.yml",
    r"~\.config\tc\config.yml",
    r"~\.jfrog\jfrog-cli.conf.v6",
    r"$JFROG_CLI_HOME_DIR\jfrog-cli.conf.v6",
    r"%APPDATA%\cloudsmith\credentials.ini",
    r"%APPDATA%\atlascli\config.toml",
    r"%APPDATA%\octopus\cli_config.json",
    r"~\.config\neonctl\credentials.json",
    # Package managers / dev tools
    r"~\.npmrc",
    r"%APPDATA%\npm\etc\npmrc",
    r"~\.yarnrc",
    r"~\.yarnrc.yml",
    r"~\.pypirc",
    r"%APPDATA%\pip\pip.ini",
    r"~\.gem\credentials",
    r"~\.cargo\credentials",
    r"~\.cargo\credentials.toml",
    r"$CARGO_HOME\credentials.toml",
    r"~\.m2\settings.xml",
    r"~\.gradle\gradle.properties",
    r"$GRADLE_USER_HOME\gradle.properties",
    r"~\.sbt\.credentials",
    r"~\.sbt\sonatype_central_credentials",
    r"%APPDATA%\NuGet\NuGet.Config",
    r"%APPDATA%\Composer\auth.json",
    r"$COMPOSER_HOME\auth.json",
    r"%APPDATA%\dart\pub-credentials.json",
    r"~\.netrc",
    r"~\_netrc",
    r"~\.gitconfig",
    r"~\.git-credentials",
    r"~\.config\git\credentials",
    r"~\.hf_token",
    r"$HF_HOME\stored_tokens",
    r"$HF_HOME\token",
    r"~\.cache\huggingface\stored_tokens",
    r"~\.cache\huggingface\token",
    r"~\.kaggle\kaggle.json",
    r"~\.kaggle\access_token",
    r"~\.s3cfg",
    r"%APPDATA%\s3cmd.ini",
    r"~\.rclone.conf",
    r"%APPDATA%\rclone\rclone.conf",
    r"~\.b2_account_info",
    r"~\.sentryclirc",
    r"~\.twilio-cli\config.json",
    r"$TWILIO_CONFIG_DIR\config.json",
    r"~\.semgrep\settings.yml",
    r"%APPDATA%\Microsoft\UserSecrets\*\secrets.json",
    r"~\.docker\config.json",
    # SSH / GPG / remote access / history
    r"~\.ssh\config",
    r"~\.ssh\*",
    r"~\.keys\*",
    r"~\.certs\*",
    r"%APPDATA%\gnupg",
    r"%APPDATA%\gnupg\private-keys-v1.d",
    r"~\.config\age\*",
    r"%APPDATA%\age\*",
    r"%APPDATA%\FileZilla\sitemanager.xml",
    r"%APPDATA%\FileZilla\recentservers.xml",
    r"%APPDATA%\postgresql\pgpass.conf",
    r"%APPDATA%\postgresql\.pg_service.conf",
    r"~\.pg_service.conf",
    r"~\.psql_history",
    r"~\.mysql_history",
    r"~\.sqlite_history",
    r"~\.rediscli_history",
    r"~\.node_repl_history",
    r"~\.python_history",
    r"%APPDATA%\fish\fish_history",
    r"~\.local\share\fish\fish_history",
    r"~\.bash_history",
    r"~\.zsh_history",
    r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    r"~\Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
    r"~\Documents\PowerShell\profile.ps1",
    r"~\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
    r"~\Documents\WindowsPowerShell\profile.ps1",
    r"~\.vault-token",
    r"~\.dogrc",
    r"~\.ncloud\configure",
    r"~\.mc\config.json",
    r"%APPDATA%\go\env",
    # Browsers / launcher data
    r"%LOCALAPPDATA%\Google\Chrome\User Data",
    r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
    r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
    r"%LOCALAPPDATA%\Vivaldi\User Data",
    r"%APPDATA%\Opera Software\Opera Stable",
    r"%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper",
    r"%APPDATA%\Mozilla\Firefox\Profiles",
    r"%APPDATA%\nikke_launcher",
    r"%APPDATA%\nikke_launcher_hmt",
    r"%APPDATA%\nikke_launcher_google",
    # Project folders scanned by keyscan
    r"%USERPROFILE%\code",
    r"%USERPROFILE%\dev",
    r"%USERPROFILE%\source",
    r"%USERPROFILE%\Programming",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\Desktop",
)

SENSITIVE_ENV_VARS = (
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "B2_ACCOUNT_INFO",
    "BUILDKITE_AGENT_CONFIG",
    "DATABRICKS_CONFIG_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "HELM_REPOSITORY_CONFIG",
    "HF_TOKEN_PATH",
    "MODAL_CONFIG_PATH",
    "NPM_CONFIG_USERCONFIG",
    "OCI_CONFIG_FILE",
    "PGPASSFILE",
    "PGSERVICEFILE",
    "PIP_CONFIG_FILE",
    "RCLONE_CONFIG",
    "TF_CLI_CONFIG_FILE",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "GH_CONFIG_DIR",
    "KUBECONFIG",
    "DOCKER_CONFIG",
    "AZURE_CONFIG_DIR",
    "CLOUDSDK_CONFIG",
    "DSH_HOME",
)

# Sub-keys the payload reads from HKCU.  Counts are reported for the session
# stores (the values themselves are never printed).
SENSITIVE_REGISTRY = (
    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
    r"Software\Classes\CLSID" + "\\" + KNOWN_CLSID + r"\InprocServer32",
    r"Software\GNU\GnuPG",
    r"Software\Martin Prikryl\WinSCP 2\Sessions",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    r"Software\SimonTatham\PuTTY\Sessions",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
)

# Wallet extensions the payload targets (matched by manifest name).
WALLET_KEYWORDS = (
    "metamask",
    "phantom",
    "coinbase wallet",
    "binance",
    "okx wallet",
    "bybit wallet",
    "bitget wallet",
    "trust wallet",
    "rabby",
    "rainbow",
    "keplr",
    "solflare",
    "backpack",
    "tonkeeper",
    "tronlink",
    "xverse",
    "unisat",
    "petra",
    "ronin",
    "magic eden",
    "exodus",
    "keystone",
    "sui wallet",
    "leather",
    "onekey",
    "imtoken",
    "tokenpocket",
    "safepal",
)

# Project files the payload searches for inside those folders.
PROJECT_SECRET_NAMES = (
    ".env",
    ".mcp.json",
    "mcp.json",
    "docker-compose.yml",
    "docker-compose.yaml",
    "appsettings.json",
)

# --------------------------------------------------------------------------
# USN / journal indicators (deleted evidence)
# --------------------------------------------------------------------------
USN_PATTERNS = (
    ("k2f-bcreds", "浏览器凭据临时副本", "critical"),
    ("k2f_screen", "屏幕截图", "critical"),
    ("k2f-keyscan", "keyscan 临时副本", "high"),
    ("k2f.lua", "LuaJIT 载荷文件", "critical"),
    ("insight.bundle", "LuaJIT 载荷下载", "high"),
    ("platform_experience_helper.dll", "Chrome 持久化 DLL", "high"),
    ("service_util.dll", "安装器残留 DLL", "medium"),
    ("tinyget.", "启动器下载日志", "medium"),
)

# Fixed payload/agent commands, used only for report context.
AGENT_COMMANDS = (
    "exec", "ls", "cd", "cat", "download", "file_chunk", "screens", "creds",
    "browserscan", "chrome_scan", "keyscan", "wallet_files", "whoami",
    "sysinfo", "host_facts", "chrome_install", "chrome_cleanup",
    "chrome_uninstall", "payload_cleanup",
)
