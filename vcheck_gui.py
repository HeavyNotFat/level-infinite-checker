#!/usr/bin/env python3
"""Tkinter UI for the read-only VirusChecker toolkit.

The GUI only launches vcheck.py as a subprocess and displays its existing
reports.  It does not add any write/delete/remediation behavior.
"""
from __future__ import annotations

import ctypes
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional


FROZEN = bool(getattr(sys, "frozen", False))
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
APP_DIR = Path(sys.executable).resolve().parent if FROZEN else BUNDLE_DIR
BASE_DIR = APP_DIR
VCHECK_SCRIPT = BUNDLE_DIR / "vcheck.py"
APP_TITLE = "VirusChecker · Windows 只读排查"
APP_VERSION = "2.0.0"
AI_HINT = (
    "如果自己看不懂结果：请把本目录下的 gui-run.log 或 report.md 发送给 AI，"
    "让它逐条解释发现、判断是否需要处理。发送前请删除计算机名、用户名与本地路径。"
)
NAVY = "#101828"
INK = "#1c2024"
MUTED = "#667085"
BG = "#f4f6fa"
CARD = "#ffffff"
LINE = "#d9dee5"
ACCENT = "#1f5eff"
ACCENT_ACTIVE = "#1747c7"
DANGER = "#b42318"

SEVERITY_COLORS = {
    "critical": "#b42318",
    "high": "#d92d20",
    "medium": "#b54708",
    "low": "#475467",
    "info": "#175cd3",
}
SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "信息",
}
STATUS_COLORS = {
    "clean": "#067647",
    "info": "#175cd3",
    "low": "#475467",
    "medium": "#b54708",
    "high": "#d92d20",
    "critical": "#b42318",
}


def _enable_dpi_awareness() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _settings_path() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home())
    return Path(base) / "VirusChecker" / "gui_settings.json"


def _pick_font(root: tk.Misc) -> str:
    try:
        families = set(tkfont.families(root))
    except Exception:
        families = set()
    for name in ("Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", "Arial"):
        if name in families:
            return name
    return "TkDefaultFont"


def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def build_scan_command(
    profile: str,
    max_seconds: int,
    output: str,
    state: str,
    modules: Dict[str, bool],
    include_files: bool = False,
    include_caches: bool = False,
    usn: bool = True,
    roots: Optional[List[str]] = None,
) -> List[str]:
    """Build the vcheck.py command line.  Kept separate so it is testable."""
    prefix = [sys.executable, "--cli"] if FROZEN else [sys.executable, str(VCHECK_SCRIPT)]
    cmd = prefix + [
        "--output", output,
        "--state", state,
        "--max-seconds", str(max(5, int(max_seconds))),
    ]
    if (profile or "quick").lower() == "full":
        cmd.append("--full")
    if not modules.get("weird", True):
        cmd.append("--skip-weird")
    if not modules.get("steam", True):
        cmd.append("--skip-steam")
    if not modules.get("execution", True):
        cmd.append("--skip-execution")
    if not modules.get("incident", True):
        cmd.append("--skip-k2f")
    if not modules.get("domains", True):
        cmd.append("--skip-domains")
    if not usn:
        cmd.append("--no-usn")
    if include_files:
        cmd.append("--include-files")
    if include_caches:
        cmd.append("--include-caches")
    for root in roots or []:
        root = (root or "").strip()
        if root:
            cmd.extend(["--root", root])
    return cmd


class VCheckGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.font_family = _pick_font(root)
        self.root.title(APP_TITLE)
        self.root.geometry("1180x860")
        self.root.minsize(1040, 760)
        self.root.configure(bg=BG)

        self.events: "queue.Queue[tuple[str, Any]]" = queue.Queue()
        self.proc: Optional[subprocess.Popen] = None
        self.cancel_requested = False
        self.closing = False
        self.report_data: Optional[Dict[str, Any]] = None
        self.report_dir: Optional[Path] = None
        self.current_output = ""
        self.findings: List[Dict[str, Any]] = []
        self.findings_by_iid: Dict[str, Dict[str, Any]] = {}
        self.open_buttons: List[ttk.Button] = []
        self.dir_records: List[Dict[str, Any]] = []
        self.dir_filtered: List[Dict[str, Any]] = []
        self.dir_page = 0
        self.dir_page_size = 1000
        self.dir_load_token = 0
        self._dir_filter_job = None
        self.dir_log_path: Optional[Path] = None
        self.gui_log_path: Optional[Path] = None
        self.log_handle = None
        self.domain_records: List[Dict[str, Any]] = []
        self.domain_filtered: List[Dict[str, Any]] = []
        self.domain_by_iid: Dict[str, Dict[str, Any]] = {}

        self.profile_var = tk.StringVar(value="quick")
        self.module_vars = {
            "weird": tk.BooleanVar(value=True),
            "steam": tk.BooleanVar(value=True),
            "execution": tk.BooleanVar(value=True),
            "incident": tk.BooleanVar(value=True),
            "domains": tk.BooleanVar(value=True),
        }
        self.include_files_var = tk.BooleanVar(value=False)
        self.include_caches_var = tk.BooleanVar(value=False)
        self.usn_var = tk.BooleanVar(value=True)
        self.max_seconds_var = tk.StringVar(value="180")
        self.output_var = tk.StringVar(value="")
        self.state_var = tk.StringVar(value="state")
        self.extra_roots_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="就绪")
        self.progress_var = tk.DoubleVar(value=0)

        self._build_style()
        self._build_ui()
        self._load_settings()
        self._update_admin_label()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._poll_queue)
        self._set_report_buttons(False)

    # ------------------------------------------------------------------ style
    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        for theme in ("vista", "clam", "default"):
            try:
                style.theme_use(theme)
                break
            except tk.TclError:
                continue
        try:
            style.configure("TFrame", background=BG)
            style.configure("Card.TFrame", background=CARD)
            style.configure("TLabel", background=BG, foreground=INK, font=(self.font_family, 10))
            style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=(self.font_family, 9))
            style.configure("CardTitle.TLabel", background=CARD, foreground=MUTED, font=(self.font_family, 9))
            style.configure("CardValue.TLabel", background=CARD, foreground=INK, font=(self.font_family, 16, "bold"))
            style.configure("TLabelframe", background=BG, bordercolor=LINE, relief="solid")
            style.configure("TLabelframe.Label", background=BG, foreground=INK, font=(self.font_family, 10, "bold"))
            style.configure("TCheckbutton", background=BG, foreground=INK, font=(self.font_family, 10))
            style.configure("TRadiobutton", background=BG, foreground=INK, font=(self.font_family, 10))
            style.configure("TButton", font=(self.font_family, 10), padding=(10, 6))
            style.configure("Accent.TButton", font=(self.font_family, 10, "bold"), padding=(14, 8), foreground="white", background=ACCENT)
            style.map("Accent.TButton", background=[("active", ACCENT_ACTIVE), ("disabled", "#98a2b3")])
            style.configure("TNotebook", background=BG, borderwidth=0)
            style.configure("TNotebook.Tab", padding=(14, 8), font=(self.font_family, 10))
            style.configure("Treeview", font=(self.font_family, 9), rowheight=26, background=CARD, fieldbackground=CARD)
            style.configure("Treeview.Heading", font=(self.font_family, 9, "bold"))
            style.configure("TEntry", padding=4)
        except tk.TclError:
            pass

    # --------------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self._build_header()
        self.main = ttk.Frame(self.root, padding=(14, 10, 14, 8))
        self.main.grid(row=1, column=0, sticky="nsew")
        self.main.grid_rowconfigure(0, weight=1)
        self.main.grid_columnconfigure(0, weight=1)

        self.notebook = ttk.Notebook(self.main)
        self.notebook.grid(row=0, column=0, sticky="nsew")

        self.scan_tab = ttk.Frame(self.notebook, padding=12)
        self.results_tab = ttk.Frame(self.notebook, padding=12)
        self.domains_tab = ttk.Frame(self.notebook, padding=12)
        self.directories_tab = ttk.Frame(self.notebook, padding=12)
        self.log_tab = ttk.Frame(self.notebook, padding=12)
        self.about_tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.scan_tab, text="扫描")
        self.notebook.add(self.results_tab, text="结果")
        self.notebook.add(self.domains_tab, text="域名/网络")
        self.notebook.add(self.directories_tab, text="目录（全部）")
        self.notebook.add(self.log_tab, text="日志（完整）")
        self.notebook.add(self.about_tab, text="说明")

        self._build_scan_tab()
        self._build_results_tab()
        self._build_domains_tab()
        self._build_directories_tab()
        self._build_log_tab()
        self._build_about_tab()
        self._build_status_bar()

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=NAVY, height=94)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.grid_columnconfigure(0, weight=1)

        title = tk.Label(header, text="VirusChecker", bg=NAVY, fg="white", font=(self.font_family, 21, "bold"))
        title.grid(row=0, column=0, sticky="w", padx=24, pady=(16, 0))
        subtitle = tk.Label(
            header,
            text="异常文件夹 · Steam（只读基线） · 程序调用路径 · Level Infinite 供应链事件 · 域名/API 访问",
            bg=NAVY,
            fg="#cbd5e1",
            font=(self.font_family, 9),
        )
        subtitle.grid(row=1, column=0, sticky="w", padx=24, pady=(2, 16))

        right = tk.Frame(header, bg=NAVY)
        right.grid(row=0, column=1, rowspan=2, sticky="e", padx=24)
        self.admin_label = tk.Label(right, text="", bg=NAVY, font=(self.font_family, 9, "bold"))
        self.admin_label.pack(anchor="e")
        tk.Label(right, text="只读 · 不上传 · 不自动清理", bg=NAVY, fg="#98a2b3", font=(self.font_family, 8)).pack(anchor="e", pady=(4, 0))

    def _build_scan_tab(self) -> None:
        self.scan_tab.grid_rowconfigure(0, weight=1)
        self.scan_tab.grid_columnconfigure(0, weight=0)
        self.scan_tab.grid_columnconfigure(1, weight=1)

        options_outer = ttk.Frame(self.scan_tab)
        options_outer.grid(row=0, column=0, sticky="nsw", padx=(0, 12))
        options_outer.grid_rowconfigure(0, weight=1)
        options_outer.grid_columnconfigure(0, weight=1)

        self.options_canvas = tk.Canvas(options_outer, bg=BG, highlightthickness=0, width=390)
        self.options_canvas.grid(row=0, column=0, sticky="nsew")
        options_scroll = ttk.Scrollbar(options_outer, orient="vertical", command=self.options_canvas.yview)
        options_scroll.grid(row=0, column=1, sticky="ns")
        self.options_canvas.configure(yscrollcommand=options_scroll.set)

        options = ttk.Frame(self.options_canvas)
        options.grid_columnconfigure(0, weight=1)
        options_window = self.options_canvas.create_window((0, 0), window=options, anchor="nw")

        def _resize_options(event):
            self.options_canvas.itemconfigure(options_window, width=event.width)

        def _scroll_options(event):
            self.options_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        options.bind("<Configure>", lambda _event: self.options_canvas.configure(scrollregion=self.options_canvas.bbox("all")))
        self.options_canvas.bind("<Configure>", _resize_options)
        self.options_canvas.bind("<Enter>", lambda _event: self.options_canvas.bind_all("<MouseWheel>", _scroll_options))
        self.options_canvas.bind("<Leave>", lambda _event: self.options_canvas.unbind_all("<MouseWheel>"))

        self._build_profile_card(options, 0)
        self._build_module_card(options, 1)
        self._build_paths_card(options, 2)

        log_card = ttk.LabelFrame(self.scan_tab, text="运行日志", padding=8)
        log_card.grid(row=0, column=1, sticky="nsew")
        log_card.grid_rowconfigure(0, weight=1)
        log_card.grid_columnconfigure(0, weight=1)
        self.log_text = tk.Text(
            log_card,
            wrap="none",
            bg="#0f172a",
            fg="#d7e3ff",
            insertbackground="white",
            relief="flat",
            font=("Consolas" if "Consolas" in tkfont.families(self.root) else "Courier New", 9),
            state="disabled",
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll_y = ttk.Scrollbar(log_card, orient="vertical", command=self.log_text.yview)
        log_scroll_y.grid(row=0, column=1, sticky="ns")
        log_scroll_x = ttk.Scrollbar(log_card, orient="horizontal", command=self.log_text.xview)
        log_scroll_x.grid(row=1, column=0, sticky="ew")
        self.log_text.configure(yscrollcommand=log_scroll_y.set, xscrollcommand=log_scroll_x.set)
        self.log_text.tag_configure("stage", foreground="#7dd3fc", font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("warn", foreground="#fbbf24")
        self.log_text.tag_configure("error", foreground="#fca5a5")
        self.log_text.tag_configure("ok", foreground="#86efac")

        progress_card = ttk.Frame(self.scan_tab)
        progress_card.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        progress_card.grid_columnconfigure(1, weight=1)
        ttk.Label(progress_card, text="进度").grid(row=0, column=0, padx=(0, 8))
        self.progress = ttk.Progressbar(progress_card, variable=self.progress_var, maximum=100, mode="determinate")
        self.progress.grid(row=0, column=1, sticky="ew")
        self.progress_label = ttk.Label(progress_card, text="0%", style="Muted.TLabel", width=6)
        self.progress_label.grid(row=0, column=2, padx=(8, 0))
        self._build_actions(progress_card, 1)

    def _build_profile_card(self, parent: ttk.Frame, row: int) -> None:
        card = ttk.LabelFrame(parent, text="扫描范围", padding=10)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)
        ttk.Radiobutton(card, text="Quick：根目录 + 高风险位置（推荐）", value="quick", variable=self.profile_var, command=self._on_profile_change).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(card, text="Full：递归扫描 C:（较慢）", value="full", variable=self.profile_var, command=self._on_profile_change).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))
        ttk.Label(card, text="时间预算（秒）", style="Muted.TLabel").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.max_spin = ttk.Spinbox(card, from_=5, to=86400, increment=30, width=10, textvariable=self.max_seconds_var)
        self.max_spin.grid(row=2, column=1, sticky="e", pady=(8, 0))

    def _build_module_card(self, parent: ttk.Frame, row: int) -> None:
        card = ttk.LabelFrame(parent, text="检查模块", padding=10)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        ttk.Checkbutton(card, text="C: 异常/乱码文件夹", variable=self.module_vars["weird"]).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(card, text="Steam 路径与完整性（基线只读）", variable=self.module_vars["steam"]).grid(row=1, column=0, sticky="w", pady=(2, 0))
        ttk.Checkbutton(card, text="程序调用路径与可疑软件", variable=self.module_vars["execution"]).grid(row=2, column=0, sticky="w", pady=(2, 0))
        ttk.Checkbutton(card, text="供应链事件：文件 + 注册表 + 浏览器", variable=self.module_vars["incident"]).grid(row=3, column=0, sticky="w", pady=(2, 0))
        ttk.Checkbutton(card, text="域名与 API 访问记录", variable=self.module_vars["domains"]).grid(row=4, column=0, sticky="w", pady=(2, 0))
        ttk.Separator(card).grid(row=5, column=0, sticky="ew", pady=(7, 5))
        ttk.Checkbutton(card, text="同时检查异常文件名", variable=self.include_files_var).grid(row=6, column=0, sticky="w")
        ttk.Checkbutton(card, text="包含缓存目录（噪声更多）", variable=self.include_caches_var).grid(row=7, column=0, sticky="w", pady=(2, 0))
        ttk.Checkbutton(card, text="读取 NTFS USN 日志（找已删除载荷，需管理员）", variable=self.usn_var).grid(row=8, column=0, sticky="w", pady=(2, 0))

    def _build_paths_card(self, parent: ttk.Frame, row: int) -> None:
        card = ttk.LabelFrame(parent, text="输出与路径", padding=10)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        ttk.Label(card, text="报告目录（留空自动）").grid(row=0, column=0, sticky="w")
        ttk.Entry(card, textvariable=self.output_var).grid(row=0, column=1, sticky="ew", padx=(6, 4))
        ttk.Button(card, text="…", width=3, command=self._browse_output).grid(row=0, column=2)

        ttk.Label(card, text="Steam 基线目录（只读）").grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Entry(card, textvariable=self.state_var).grid(row=1, column=1, sticky="ew", padx=(6, 4), pady=(4, 0))
        ttk.Button(card, text="…", width=3, command=self._browse_state).grid(row=1, column=2, pady=(4, 0))

        ttk.Label(card, text="额外根（; 分隔）").grid(row=2, column=0, sticky="w", pady=(4, 0))
        ttk.Entry(card, textvariable=self.extra_roots_var).grid(row=2, column=1, columnspan=2, sticky="ew", padx=(6, 0), pady=(4, 0))

        ttk.Label(
            card,
            text="Steam 基线只做比对：本工具不会创建、更新或写入基线文件。",
            style="Muted.TLabel",
            wraplength=350,
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))

    def _build_actions(self, parent: ttk.Frame, row: int) -> None:
        bar = ttk.Frame(parent)
        bar.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        bar.grid_columnconfigure(0, weight=1)
        self.start_button = ttk.Button(bar, text="开始扫描", style="Accent.TButton", command=self._start_scan)
        self.start_button.grid(row=0, column=0, sticky="ew")
        self.stop_button = ttk.Button(bar, text="停止", command=self._stop_scan)
        self.stop_button.grid(row=0, column=1, padx=(8, 0))
        self.stop_button.configure(state="disabled")

    def _build_results_tab(self) -> None:
        self.results_tab.grid_rowconfigure(2, weight=1)
        self.results_tab.grid_rowconfigure(3, weight=0)
        self.results_tab.grid_columnconfigure(0, weight=1)

        summary = tk.Frame(self.results_tab, bg=BG)
        summary.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        for idx in range(7):
            summary.grid_columnconfigure(idx, weight=1)
        self.card_values: Dict[str, tk.Label] = {}
        cards = [
            ("overall", "总体级别"),
            ("weird", "异常文件夹"),
            ("steam", "Steam"),
            ("execution", "程序路径"),
            ("incident", "事件阶段"),
            ("domains", "域名记录"),
            ("dirs", "目录记录"),
        ]
        for idx, (key, title) in enumerate(cards):
            card = tk.Frame(summary, bg=CARD, highlightbackground=LINE, highlightthickness=1)
            card.grid(row=0, column=idx, sticky="ew", padx=(0, 8) if idx < 6 else 0)
            tk.Label(card, text=title, bg=CARD, fg=MUTED, font=(self.font_family, 9)).pack(anchor="w", padx=12, pady=(10, 2))
            value = tk.Label(card, text="—", bg=CARD, fg=INK, font=(self.font_family, 13, "bold"))
            value.pack(anchor="w", padx=12, pady=(0, 10))
            self.card_values[key] = value

        self.banner_var = tk.StringVar(value="尚未扫描。点击“开始扫描”后，这里会显示结果摘要。")
        self.banner_label = tk.Label(
            self.results_tab,
            textvariable=self.banner_var,
            bg="#fff7ed",
            fg="#7c2d12",
            anchor="w",
            justify="left",
            wraplength=1000,
            padx=10,
            pady=8,
        )
        self.banner_label.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        findings_frame = ttk.LabelFrame(self.results_tab, text="发现（双击查看完整报告）", padding=8)
        findings_frame.grid(row=2, column=0, sticky="nsew")
        findings_frame.grid_rowconfigure(0, weight=1)
        findings_frame.grid_columnconfigure(0, weight=1)
        columns = ("severity", "category", "title", "path")
        self.tree = ttk.Treeview(findings_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("severity", text="级别")
        self.tree.heading("category", text="类别")
        self.tree.heading("title", text="发现")
        self.tree.heading("path", text="路径")
        self.tree.column("severity", width=70, anchor="center", stretch=False)
        self.tree.column("category", width=120, stretch=False)
        self.tree.column("title", width=380)
        self.tree.column("path", width=460)
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(findings_frame, orient="vertical", command=self.tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=tree_scroll.set)
        for level, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(level, foreground=color)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", lambda _event: self._open_report("html"))

        detail_frame = ttk.LabelFrame(self.results_tab, text="详情", padding=8)
        detail_frame.grid(row=3, column=0, sticky="ew", pady=(8, 8))
        detail_frame.grid_columnconfigure(0, weight=1)
        self.detail_text = tk.Text(detail_frame, height=7, wrap="word", relief="flat", bg=CARD, fg=INK, font=(self.font_family, 9))
        self.detail_text.grid(row=0, column=0, sticky="ew")
        self.detail_text.configure(state="disabled")

        actions = ttk.Frame(self.results_tab)
        actions.grid(row=4, column=0, sticky="ew")
        for text, kind in (("打开 HTML 报告", "html"), ("打开 Markdown", "markdown"), ("打开 JSON", "json"), ("打开报告目录", "dir")):
            button = ttk.Button(actions, text=text, command=lambda k=kind: self._open_report(k))
            button.pack(side="left", padx=(0, 8))
            self.open_buttons.append(button)
        ttk.Button(actions, text="打开完整日志", command=self._open_gui_log).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="复制摘要", command=self._copy_summary).pack(side="right")

        hint = tk.Frame(self.results_tab, bg="#eff4ff", highlightbackground="#c7d7fe", highlightthickness=1)
        hint.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        hint.grid_columnconfigure(0, weight=1)
        tk.Label(
            hint,
            text="看不懂结果？" + AI_HINT,
            bg="#eff4ff",
            fg="#1e3a8a",
            anchor="w",
            justify="left",
            wraplength=900,
            font=(self.font_family, 9),
            padx=10,
            pady=7,
        ).grid(row=0, column=0, sticky="ew")
        ttk.Button(hint, text="复制”给 AI”信息", command=self._copy_ai_hint).grid(row=0, column=1, padx=8, pady=6)

    def _build_domains_tab(self) -> None:
        self.domains_tab.grid_rowconfigure(3, weight=1)
        self.domains_tab.grid_columnconfigure(0, weight=1)

        self.domain_info_var = tk.StringVar(value="尚未扫描。扫描后会列出本机解析/访问过的域名，以及能归因到程序的 DNS 记录与 API 地址。")
        tk.Label(
            self.domains_tab,
            textvariable=self.domain_info_var,
            bg=CARD,
            fg=INK,
            anchor="w",
            justify="left",
            wraplength=1080,
            padx=10,
            pady=8,
            font=(self.font_family, 9),
            highlightbackground=LINE,
            highlightthickness=1,
        ).grid(row=0, column=0, sticky="ew", pady=(0, 8))

        toolbar = ttk.Frame(self.domains_tab)
        toolbar.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(toolbar, text="搜索域名").pack(side="left")
        self.domain_search_var = tk.StringVar(value="")
        entry = ttk.Entry(toolbar, textvariable=self.domain_search_var, width=34)
        entry.pack(side="left", padx=(6, 12))
        entry.bind("<KeyRelease>", lambda _event: self._apply_domain_filter())
        self.domain_focus_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar,
            text="只看 IOC 与 AI/开发/云域名",
            variable=self.domain_focus_var,
            command=self._apply_domain_filter,
        ).pack(side="left")
        self.domain_count_var = tk.StringVar(value="")
        ttk.Label(toolbar, textvariable=self.domain_count_var, style="Muted.TLabel").pack(side="right")

        tree_frame = ttk.LabelFrame(self.domains_tab, text="域名访问记录（DNS 缓存 / DNS 日志 / Sysmon / 浏览器历史 / 程序日志）", padding=8)
        tree_frame.grid(row=3, column=0, sticky="nsew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        columns = ("domain", "class", "count", "sources", "processes", "last")
        self.domain_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        for key, title, width in (
            ("domain", "域名", 250),
            ("class", "分类", 150),
            ("count", "记录数", 70),
            ("sources", "来源", 240),
            ("processes", "相关进程", 130),
            ("last", "最后时间", 140),
        ):
            self.domain_tree.heading(key, text=title)
            self.domain_tree.column(key, width=width, anchor="w" if key in ("domain", "class", "sources", "processes") else "center")
        self.domain_tree.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.domain_tree.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.domain_tree.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        self.domain_tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.domain_tree.tag_configure("ioc", foreground=DANGER)
        self.domain_tree.tag_configure("focus", foreground="#175cd3")
        self.domain_tree.bind("<<TreeviewSelect>>", self._on_domain_select)

        detail_frame = ttk.LabelFrame(self.domains_tab, text="选中域名详情", padding=8)
        detail_frame.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        detail_frame.grid_columnconfigure(0, weight=1)
        self.domain_detail_text = tk.Text(detail_frame, height=6, wrap="word", relief="flat", bg=CARD, fg=INK, font=(self.font_family, 9))
        self.domain_detail_text.grid(row=0, column=0, sticky="ew")
        self.domain_detail_text.configure(state="disabled")

    def _build_directories_tab(self) -> None:
        self.directories_tab.grid_rowconfigure(2, weight=1)
        self.directories_tab.grid_columnconfigure(0, weight=1)

        toolbar = ttk.Frame(self.directories_tab)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(toolbar, text="状态").pack(side="left")
        self.dir_status_var = tk.StringVar(value="全部")
        self.dir_status_combo = ttk.Combobox(
            toolbar,
            textvariable=self.dir_status_var,
            values=("全部", "候选", "已扫描", "跳过", "未扫描", "错误"),
            state="readonly",
            width=10,
        )
        self.dir_status_combo.pack(side="left", padx=(6, 14))
        self.dir_status_combo.bind("<<ComboboxSelected>>", lambda _event: self._schedule_dir_filter())

        ttk.Label(toolbar, text="搜索路径").pack(side="left")
        self.dir_search_var = tk.StringVar(value="")
        search_entry = ttk.Entry(toolbar, textvariable=self.dir_search_var, width=34)
        search_entry.pack(side="left", padx=(6, 14))
        search_entry.bind("<KeyRelease>", lambda _event: self._schedule_dir_filter())

        self.dir_count_var = tk.StringVar(value="尚未加载目录清单")
        ttk.Label(toolbar, textvariable=self.dir_count_var, style="Muted.TLabel").pack(side="left")

        ttk.Button(toolbar, text="打开目录清单", command=self._open_dir_log).pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text="复制选中路径", command=self._copy_selected_dir).pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text="打开选中目录", command=self._open_selected_dir).pack(side="right")

        info = ttk.Label(
            self.directories_tab,
            text="这里显示扫描器实际写入 scanned_dirs.jsonl 的每一条目录记录（含候选、已扫描、跳过缓存/链接/深度上限、时间上限未扫描、错误）；分页显示，但数据完整保留，可用状态/搜索定位。",
            style="Muted.TLabel",
            wraplength=1050,
        )
        info.grid(row=1, column=0, sticky="ew", pady=(0, 6))

        tree_frame = ttk.LabelFrame(self.directories_tab, text="目录记录", padding=8)
        tree_frame.grid(row=2, column=0, sticky="nsew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        columns = ("path", "status", "depth", "score", "severity", "reasons")
        self.dir_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        self.dir_tree.heading("path", text="目录路径")
        self.dir_tree.heading("status", text="状态")
        self.dir_tree.heading("depth", text="深度")
        self.dir_tree.heading("score", text="分数")
        self.dir_tree.heading("severity", text="级别")
        self.dir_tree.heading("reasons", text="原因")
        self.dir_tree.column("path", width=500)
        self.dir_tree.column("status", width=95, anchor="center", stretch=False)
        self.dir_tree.column("depth", width=55, anchor="center", stretch=False)
        self.dir_tree.column("score", width=60, anchor="center", stretch=False)
        self.dir_tree.column("severity", width=65, anchor="center", stretch=False)
        self.dir_tree.column("reasons", width=260)
        self.dir_tree.grid(row=0, column=0, sticky="nsew")
        dir_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.dir_tree.yview)
        dir_scroll.grid(row=0, column=1, sticky="ns")
        dir_xscroll = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.dir_tree.xview)
        dir_xscroll.grid(row=1, column=0, sticky="ew")
        self.dir_tree.configure(yscrollcommand=dir_scroll.set, xscrollcommand=dir_xscroll.set)
        for level, color in SEVERITY_COLORS.items():
            self.dir_tree.tag_configure(level, foreground=color)
        self.dir_tree.bind("<<TreeviewSelect>>", self._on_dir_select)

        detail_frame = ttk.LabelFrame(self.directories_tab, text="选中目录详情（完整字段）", padding=6)
        detail_frame.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        detail_frame.grid_columnconfigure(0, weight=1)
        self.dir_detail_text = tk.Text(detail_frame, height=4, wrap="word", relief="flat", bg=CARD, fg=INK, font=(self.font_family, 9))
        self.dir_detail_text.grid(row=0, column=0, sticky="ew")
        self.dir_detail_text.configure(state="disabled")

        pager = ttk.Frame(self.directories_tab)
        pager.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        self.dir_first_btn = ttk.Button(pager, text="首页", command=lambda: self._goto_dir_page(0))
        self.dir_first_btn.pack(side="left")
        self.dir_prev_btn = ttk.Button(pager, text="上一页", command=lambda: self._goto_dir_page(self.dir_page - 1))
        self.dir_prev_btn.pack(side="left", padx=(6, 0))
        self.dir_page_label = ttk.Label(pager, text="第 0 / 0 页", style="Muted.TLabel")
        self.dir_page_label.pack(side="left", padx=12)
        self.dir_next_btn = ttk.Button(pager, text="下一页", command=lambda: self._goto_dir_page(self.dir_page + 1))
        self.dir_next_btn.pack(side="left")
        self.dir_last_btn = ttk.Button(pager, text="末页", command=self._goto_last_dir_page)
        self.dir_last_btn.pack(side="left", padx=(6, 0))
        ttk.Label(pager, text="每页 1000 条；所有记录均保留。", style="Muted.TLabel").pack(side="right")

    def _build_log_tab(self) -> None:
        self.log_tab.grid_rowconfigure(1, weight=1)
        self.log_tab.grid_columnconfigure(0, weight=1)
        bar = ttk.Frame(self.log_tab)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(
            bar,
            text="完整运行日志（stdout + stderr），不截断；同时写入报告目录的 gui-run.log。",
            style="Muted.TLabel",
        ).pack(side="left")
        ttk.Button(bar, text="打开 gui-run.log", command=self._open_gui_log).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="复制全部日志", command=self._copy_full_log).pack(side="right")
        self.log_path_var = tk.StringVar(value="尚未运行")
        ttk.Label(bar, textvariable=self.log_path_var, style="Muted.TLabel").pack(side="left", padx=(10, 0))
        frame = ttk.LabelFrame(self.log_tab, text="日志", padding=8)
        frame.grid(row=1, column=0, sticky="nsew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        self.full_log_text = tk.Text(
            frame,
            wrap="none",
            bg="#0f172a",
            fg="#d7e3ff",
            insertbackground="white",
            relief="flat",
            font=("Consolas" if "Consolas" in tkfont.families(self.root) else "Courier New", 9),
            state="disabled",
        )
        self.full_log_text.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(frame, orient="vertical", command=self.full_log_text.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=self.full_log_text.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        self.full_log_text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        for tag, color in (("stage", "#7dd3fc"), ("warn", "#fbbf24"), ("error", "#fca5a5"), ("ok", "#86efac")):
            self.full_log_text.tag_configure(tag, foreground=color)

    def _build_about_tab(self) -> None:
        about = (
            "如果自己看不懂结果：请把本软件生成的日志（gui-run.log）或报告（report.md）发送给 AI，"
            "让它帮你逐条解释“这条发现是什么意思、需不需要处理、下一步做什么”。"
            "发送前请删除计算机名、用户名与本地路径。\n\n"
            "本软件做什么：\n"
            "  • 只读排查 Windows 10/11，不会删除、隔离、修改文件或注册表；\n"
            "  • 进程、服务、驱动、计划任务、启动项、WMI、COM、PATH、协议处理器；\n"
            "  • Steam 安装/库/注册表路径、核心文件签名、进程模块；基线只做只读比对，"
            "不会创建或更新基线；\n"
            "  • 2026 Level Infinite 启动器供应链事件（insightjs / K2F RAT）全量检测：\n"
            "      启动器 debug.log、Launcher\\log\\tinyget（LuaJIT 头）、\n"
            "      tbs_cache 的 Code Cache 条目、HTTP 缓存 gzip 解压、LevelDB（含 Snappy 压缩块）、\n"
            "      浏览器 PlatformExperienceHelper 64-hex DLL、HKCU CLSID、\n"
            "      NativeMessagingHosts、扩展强制安装策略、TEMP 的 k2f-* 文件、命名管道；\n"
            "  • 注册表与浏览器：CLSID、浏览器策略、NativeMessaging、保存的密码/Cookie 存储、钱包扩展；\n"
            "  • 域名与 API 访问记录：DNS 缓存、DNS 客户端日志、Sysmon DNS（可归因到进程）、\n"
            "      浏览器历史、程序日志里的 URL、hosts 映射与实时套接字；\n"
            "  • NTFS USN 更改日志（管理员）：查找已被删除的 k2f 载荷/截图/凭据副本。\n\n"
            "它不会：\n"
            "  • 连接 insightjs 等 C2、不发起 DNS 查询、不上传报告；\n"
            "  • 更新 Steam 基线（这是硬限制）；\n"
            "  • 证明系统一定干净。\n\n"
            "重要限制：\n"
            "  • 官方修复不完整：截至 2026-11-04 02:01-02:07 UTC，部分 CDN 仍可能返回被污染的 "
            "FeedList.feb647c9.js；本机扫描不联网验证 CDN。\n"
            "  • 仅靠哈希不可靠：chrome_install 会重新下发 base64 DLL，DLL 每个受害者都不同。\n"
            "  • 找不到痕迹不等于没中：官方客户端会删除 debug.log，payload_cleanup 会删除下载日志，"
            "USN 日志会循环覆盖。\n"
            "  • Quick 只扫 C: 根目录与高风险位置；Full 才会递归全盘；--full 可能很慢。\n"
            "  • 浏览器历史与 DNS 记录只保留一段时间；AI CLI / IDE 的 API 请求通常只出现在程序日志或 Sysmon 里。\n"
            "  • 非管理员会漏掉部分计划任务、服务、其他用户目录与 USN。\n\n"
            "如果事件阶段 ≥ 3：立即断网并保全证据（先复制 debug.log、Launcher\\log 与 tbs_cache），"
            "不要再次打开启动器；从另一台干净设备轮换全部凭据；最安全的处置是重装系统。\n\n"
            "报告含计算机名、用户名、本地路径与域名记录；公开前请脱敏。"
        )
        text = tk.Text(self.about_tab, wrap="word", relief="flat", bg=CARD, fg=INK, font=(self.font_family, 10), padx=14, pady=14)
        text.pack(fill="both", expand=True)
        text.insert("1.0", about)
        text.configure(state="disabled")
        bar = ttk.Frame(self.about_tab)
        bar.pack(fill="x", pady=(8, 0))
        ttk.Button(bar, text="复制“给 AI”信息", command=self._copy_ai_hint).pack(side="right")
        ttk.Button(bar, text="打开日志目录", command=self._open_log_folder).pack(side="right", padx=(0, 8))

    def _build_status_bar(self) -> None:
        bar = tk.Frame(self.root, bg="#e9edf5")
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        tk.Label(bar, textvariable=self.status_var, bg="#e9edf5", fg=INK, font=(self.font_family, 9), anchor="w").grid(row=0, column=0, sticky="ew", padx=14, pady=5)
        self.version_label = tk.Label(bar, text=f"v{APP_VERSION}", bg="#e9edf5", fg=MUTED, font=(self.font_family, 8))
        self.version_label.grid(row=0, column=1, sticky="e", padx=14)

    # ------------------------------------------------------------------ state
    def _update_admin_label(self) -> None:
        if _is_admin():
            self.admin_label.configure(text="管理员权限", fg="#86efac")
        else:
            self.admin_label.configure(text="普通用户 · 部分项目可能读不到", fg="#fbbf24")

    def _on_profile_change(self) -> None:
        full = self.profile_var.get() == "full"
        current = self.max_seconds_var.get().strip()
        if current in ("180", "900", ""):
            self.max_seconds_var.set("900" if full else "180")

    def _browse_output(self) -> None:
        path = filedialog.askdirectory(initialdir=self._existing_dir(self.output_var.get()) or str(BASE_DIR), title="选择报告目录")
        if path:
            self.output_var.set(path)

    def _browse_state(self) -> None:
        path = filedialog.askdirectory(initialdir=self._existing_dir(self.state_var.get()) or str(BASE_DIR), title="选择基线目录")
        if path:
            self.state_var.set(path)

    def _existing_dir(self, value: str) -> str:
        try:
            path = Path(os.path.expandvars(os.path.expanduser(value.strip())))
            if not path.is_absolute():
                path = BASE_DIR / path
            return str(path) if path.is_dir() else ""
        except Exception:
            return ""

    # ------------------------------------------------------------------ start
    def _start_scan(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            return
        if not any(var.get() for var in self.module_vars.values()):
            messagebox.showwarning("没有检查模块", "至少选择一个检查模块。")
            return
        try:
            max_seconds = int(float(self.max_seconds_var.get().strip()))
        except ValueError:
            messagebox.showerror("参数错误", "时间预算必须是整数秒。")
            return
        max_seconds = max(5, min(86400, max_seconds))

        output = self.output_var.get().strip()
        if not output:
            output = str(BASE_DIR / "reports" / ("gui-scan-" + _now_stamp()))
        output = str(Path(os.path.expandvars(os.path.expanduser(output))))
        if not Path(output).is_absolute():
            output = str(BASE_DIR / output)

        state = self.state_var.get().strip() or "state"
        state = str(Path(os.path.expandvars(os.path.expanduser(state))))
        if not Path(state).is_absolute():
            state = str(BASE_DIR / state)

        try:
            Path(output).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("目录不可用", f"无法创建报告目录：\n{exc}")
            return

        if (Path(output) / "report.json").exists():
            if not messagebox.askyesno("覆盖报告", "该目录已有 report.json。继续会覆盖旧报告，是否继续？"):
                return

        roots = [part.strip().strip('"') for part in re.split(r"[;\n]+", self.extra_roots_var.get()) if part.strip()]
        modules = {key: bool(var.get()) for key, var in self.module_vars.items()}
        cmd = build_scan_command(
            profile=self.profile_var.get(),
            max_seconds=max_seconds,
            output=output,
            state=state,
            modules=modules,
            include_files=self.include_files_var.get(),
            include_caches=self.include_caches_var.get(),
            usn=self.usn_var.get(),
            roots=roots,
        )

        self._save_settings()
        self.current_output = output
        self.report_dir = Path(output)
        self.report_data = None
        self.findings = []
        self.findings_by_iid = {}
        self._clear_results()
        self._clear_dir_view()
        self._clear_log()
        self._close_log_file()
        self.gui_log_path = Path(output) / "gui-run.log"
        try:
            self.log_path_var.set(str(self.gui_log_path))
            self.log_handle = open(self.gui_log_path, "w", encoding="utf-8", buffering=1)
        except OSError:
            self.log_handle = None
        self._append_log("命令：" + subprocess.list2cmdline(cmd))
        self._append_log("=" * 78)
        self._set_running(True)
        self.status_var.set("正在启动扫描…")
        self.progress_var.set(0)
        self.progress_label.configure(text="0%")
        self.cancel_requested = False
        self.proc = None
        self.notebook.select(self.scan_tab)
        threading.Thread(target=self._worker, args=(cmd,), daemon=True).start()

    def _set_running(self, running: bool) -> None:
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.max_spin.configure(state="disabled" if running else "normal")

    def _worker(self, cmd: List[str]) -> None:
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            proc = subprocess.Popen(
                cmd,
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags,
            )
            self.proc = proc
            if self.cancel_requested:
                self._kill_process_tree(proc)
            if proc.stdout is not None:
                for line in proc.stdout:
                    self.events.put(("log", line.rstrip("\r\n")))
            code = proc.wait()
            self.events.put(("done", code))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def _poll_queue(self) -> None:
        if self.closing:
            return
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                    self._update_progress_from_line(str(payload))
                elif kind == "done":
                    self._on_done(int(payload))
                elif kind == "error":
                    self._on_error(str(payload))
                elif kind == "dirs":
                    self._on_dirs_loaded(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _update_progress_from_line(self, line: str) -> None:
        match = re.match(r"^\[(\d)/6\]", line.strip())
        if match:
            step = int(match.group(1))
            value = min(95, step * 15)
            self.progress_var.set(value)
            self.progress_label.configure(text=f"{value}%")
            self.status_var.set(line.strip())
        elif "总体级别" in line:
            self.status_var.set(line.strip())

    def _on_done(self, code: int) -> None:
        self.proc = None
        self._set_running(False)
        self.progress_var.set(100)
        self.progress_label.configure(text="100%")
        if self.cancel_requested:
            self.status_var.set("扫描已停止")
            self._append_log("扫描已停止。")
            return
        if self.report_dir is None:
            self._on_error("没有报告目录")
            return
        self._append_log(f"扫描进程退出码：{code}")
        report_path = self.report_dir / "report.json"
        if report_path.exists():
            try:
                self._load_report(report_path)
                self._load_directory_log_async()
                self.status_var.set("扫描完成")
                self._append_log("")
                self._append_log("扫描完成，报告已生成。", "ok")
                self.notebook.select(self.results_tab)
                return
            except Exception as exc:
                self._on_error(f"读取报告失败：{exc}")
                return
        self._load_directory_log_async()
        self._on_error(f"扫描进程结束（退出码 {code}），但没有找到 report.json。")

    def _on_error(self, message: str) -> None:
        self.proc = None
        self._set_running(False)
        self.progress_var.set(0)
        self.progress_label.configure(text="—")
        self.status_var.set("运行失败")
        self._append_log("错误：" + message, "error")
        messagebox.showerror("运行失败", message)

    def _stop_scan(self) -> None:
        if self.proc is None:
            self.cancel_requested = True
            self.status_var.set("已请求停止（进程尚未启动）")
            return
        self.cancel_requested = True
        self.stop_button.configure(state="disabled")
        self.status_var.set("正在停止扫描…")
        self._append_log("正在停止扫描…", "warn")
        self._kill_process_tree(self.proc)

    def _kill_process_tree(self, proc: subprocess.Popen) -> None:
        try:
            if proc.poll() is not None:
                return
            if os.name == "nt":
                subprocess.Popen(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            else:
                proc.terminate()
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass

    # ----------------------------------------------------------------- report
    # --------------------------------------------------------------- dir list
    DIR_STATUS_LABELS = {
        "scanned": "已扫描",
        "candidate": "候选",
        "skipped_cache": "跳过：缓存",
        "skipped_compat": "跳过：兼容链接",
        "skipped_reparse": "跳过：链接",
        "skipped_depth": "跳过：深度上限",
        "queued_time": "未扫描：时间上限",
        "error": "错误",
    }

    def _dir_status_label(self, status: str) -> str:
        return self.DIR_STATUS_LABELS.get(status, status or "未知")

    def _clear_dir_view(self) -> None:
        for item in self.dir_tree.get_children():
            self.dir_tree.delete(item)
        self.dir_records = []
        self.dir_filtered = []
        self.dir_page = 0
        self.dir_page_label.configure(text="第 0 / 0 页")
        self.dir_count_var.set("尚未加载目录清单")
        self._show_dir_detail(None)
        self._set_dir_page_buttons()

    def _load_directory_log_async(self) -> None:
        self._clear_dir_view()
        path = None
        if self.report_data:
            raw = (self.report_data.get("weird_dirs", {}) or {}).get("dir_log", "")
            if raw:
                path = Path(raw)
        if path is None and self.report_dir is not None:
            path = self.report_dir / "scanned_dirs.jsonl"
        self.dir_log_path = path
        if path is None or not path.is_file():
            self.dir_count_var.set("未找到 scanned_dirs.jsonl（可能跳过了异常文件夹扫描）")
            self.card_values["dirs"].configure(text="无清单", fg=MUTED)
            return
        self.dir_count_var.set(f"正在读取 {path.name} …")
        self.dir_load_token += 1
        token = self.dir_load_token
        threading.Thread(target=self._read_dir_log, args=(path, token), daemon=True).start()

    def _read_dir_log(self, path: Path, token: int) -> None:
        records: List[Dict[str, Any]] = []
        errors: List[str] = []
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
                for line_number, line in enumerate(handle, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        if len(errors) < 20:
                            errors.append(f"第 {line_number} 行不是有效 JSON")
                        continue
                    if isinstance(item, dict) and item.get("path"):
                        records.append(item)
        except OSError as exc:
            errors.append(str(exc))
        self.events.put(("dirs", (token, records, errors, str(path))))

    def _on_dirs_loaded(self, payload) -> None:
        token, records, errors, path = payload
        if token != self.dir_load_token:
            return
        self.dir_records = records
        self.dir_filtered = list(records)
        self.dir_page = 0
        self.dir_log_path = Path(path)
        self.dir_count_var.set(f"全部 {len(records)} 条目录记录")
        self.card_values["dirs"].configure(text=f"{len(records)} 条", fg=INK)
        self._render_dir_page()
        if errors:
            self._append_log("目录清单读取警告：" + "；".join(errors), "warn")
        if not records:
            self.dir_count_var.set("目录清单为空（可能扫描被跳过或时间预算耗尽）")

    def _schedule_dir_filter(self) -> None:
        if getattr(self, "_dir_filter_job", None):
            try:
                self.root.after_cancel(self._dir_filter_job)
            except tk.TclError:
                pass
        self._dir_filter_job = self.root.after(350, self._apply_dir_filter)

    def _apply_dir_filter(self) -> None:
        self._dir_filter_job = None
        status = self.dir_status_var.get()
        term = self.dir_search_var.get().strip().casefold()
        result = []
        for item in self.dir_records:
            raw_status = str(item.get("status", ""))
            if status == "候选" and raw_status != "candidate":
                continue
            if status == "已扫描" and raw_status != "scanned":
                continue
            if status == "跳过" and not raw_status.startswith("skipped"):
                continue
            if status == "未扫描" and raw_status != "queued_time":
                continue
            if status == "错误" and raw_status != "error":
                continue
            if term and term not in str(item.get("path", "")).casefold():
                continue
            result.append(item)
        self.dir_filtered = result
        self.dir_page = 0
        self._render_dir_page()

    def _render_dir_page(self) -> None:
        for item in self.dir_tree.get_children():
            self.dir_tree.delete(item)
        self._show_dir_detail(None)
        total = len(self.dir_filtered)
        pages = max(1, (total + self.dir_page_size - 1) // self.dir_page_size)
        self.dir_page = max(0, min(self.dir_page, pages - 1))
        start = self.dir_page * self.dir_page_size
        end = min(total, start + self.dir_page_size)
        for index, item in enumerate(self.dir_filtered[start:end], start=start):
            severity = str(item.get("severity", "info"))
            reasons = item.get("reasons", []) or []
            if isinstance(reasons, list):
                reason_text = "；".join(str(reason) for reason in reasons[:4])
            else:
                reason_text = str(reasons)
            self.dir_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    item.get("path", ""),
                    self._dir_status_label(str(item.get("status", ""))),
                    item.get("depth", ""),
                    item.get("score", ""),
                    SEVERITY_LABELS.get(severity, severity),
                    reason_text,
                ),
                tags=(severity,),
            )
        if total:
            self.dir_page_label.configure(text=f"第 {self.dir_page + 1} / {pages} 页（{start + 1}-{end} / {total}）")
            self.dir_count_var.set(f"显示 {total} / 全部 {len(self.dir_records)} 条")
        else:
            self.dir_page_label.configure(text="第 0 / 0 页")
            self.dir_count_var.set(f"筛选结果 0 / 全部 {len(self.dir_records)} 条")
        self._set_dir_page_buttons()

    def _set_dir_page_buttons(self) -> None:
        total = len(self.dir_filtered)
        pages = max(1, (total + self.dir_page_size - 1) // self.dir_page_size)
        first = self.dir_page <= 0
        last = self.dir_page >= pages - 1
        self.dir_first_btn.configure(state="disabled" if first else "normal")
        self.dir_prev_btn.configure(state="disabled" if first else "normal")
        self.dir_next_btn.configure(state="disabled" if last else "normal")
        self.dir_last_btn.configure(state="disabled" if last else "normal")

    def _goto_dir_page(self, page: int) -> None:
        pages = max(1, (len(self.dir_filtered) + self.dir_page_size - 1) // self.dir_page_size)
        self.dir_page = max(0, min(int(page), pages - 1))
        self._render_dir_page()

    def _goto_last_dir_page(self) -> None:
        pages = max(1, (len(self.dir_filtered) + self.dir_page_size - 1) // self.dir_page_size)
        self._goto_dir_page(pages - 1)

    def _on_dir_select(self, _event=None) -> None:
        selection = self.dir_tree.selection()
        if not selection:
            self._show_dir_detail(None)
            return
        try:
            index = int(selection[0])
            item = self.dir_filtered[index]
        except (ValueError, IndexError):
            self._show_dir_detail(None)
            return
        self._show_dir_detail(item)

    def _show_dir_detail(self, item: Optional[Dict[str, Any]]) -> None:
        self.dir_detail_text.configure(state="normal")
        self.dir_detail_text.delete("1.0", "end")
        if item is None:
            self.dir_detail_text.insert("1.0", "未选择目录。")
        else:
            reasons = item.get("reasons", []) or []
            if isinstance(reasons, list):
                reason_text = "；".join(str(reason) for reason in reasons)
            else:
                reason_text = str(reasons)
            lines = [
                str(item.get("path", "")),
                f"状态：{self._dir_status_label(str(item.get('status', '')))}    深度：{item.get('depth', '')}    分数：{item.get('score', '')}    级别：{SEVERITY_LABELS.get(str(item.get('severity', 'info')), item.get('severity', ''))}",
                f"修改时间：{item.get('mtime', '') or '—'}    链接：{item.get('is_reparse', False)}    空目录：{item.get('is_empty', False)}",
                "原因：" + (reason_text or "—"),
            ]
            if item.get("error"):
                lines.append("错误：" + str(item["error"]))
            self.dir_detail_text.insert("1.0", "\n".join(lines))
        self.dir_detail_text.configure(state="disabled")

    def _open_dir_log(self) -> None:
        if self.dir_log_path is None or not self.dir_log_path.is_file():
            messagebox.showwarning("没有目录清单", "未找到 scanned_dirs.jsonl。")
            return
        try:
            os.startfile(str(self.dir_log_path))
        except OSError as exc:
            messagebox.showerror("打开失败", str(exc))

    def _selected_dir_path(self) -> str:
        selection = self.dir_tree.selection()
        if not selection:
            return ""
        values = self.dir_tree.item(selection[0], "values")
        return str(values[0]) if values else ""

    def _open_selected_dir(self) -> None:
        path = self._selected_dir_path()
        if not path:
            messagebox.showinfo("未选择", "请先在目录表中选中一行。")
            return
        target = Path(path)
        if not target.is_dir():
            target = target.parent
        if not target.is_dir():
            messagebox.showwarning("目录不存在", path)
            return
        try:
            os.startfile(str(target))
        except OSError as exc:
            messagebox.showerror("打开失败", str(exc))

    def _copy_selected_dir(self) -> None:
        path = self._selected_dir_path()
        if not path:
            messagebox.showinfo("未选择", "请先在目录表中选中一行。")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(path)
        self.status_var.set("目录路径已复制")

    # ------------------------------------------------------------------- log
    def _open_gui_log(self) -> None:
        if self.gui_log_path is None or not self.gui_log_path.is_file():
            messagebox.showwarning("没有日志", "尚未生成 gui-run.log。")
            return
        try:
            os.startfile(str(self.gui_log_path))
        except OSError as exc:
            messagebox.showerror("打开失败", str(exc))

    def _copy_full_log(self) -> None:
        text = self.full_log_text.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("完整日志已复制到剪贴板")

    def _load_report(self, path: Path) -> None:
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
        self.report_data = data
        self.report_dir = path.parent
        self.findings = data.get("findings", []) or []
        self._populate_cards(data)
        self._populate_findings()
        self._populate_domains(data)
        self._set_report_buttons(True)

    def _populate_cards(self, data: Dict[str, Any]) -> None:
        summary = data.get("summary", {}) or {}
        verdict = data.get("verdict", "info")
        label = summary.get("severity_label", SEVERITY_LABELS.get(verdict, verdict))
        self.card_values["overall"].configure(text=label, fg=SEVERITY_COLORS.get(verdict, INK))

        weird = data.get("weird_dirs", {}) or {}
        candidates = weird.get("candidates", []) or []
        medium_plus = sum(1 for item in candidates if item.get("severity") in ("medium", "high", "critical"))
        weird_stats = weird.get("stats", {}) or {}
        weird_truncated = bool(weird_stats.get("truncated"))
        self.card_values["weird"].configure(
            text=f"{weird.get('total_candidates', len(candidates))} 个 / 中高 {medium_plus}" + (" · 不完整" if weird_truncated else ""),
            fg=STATUS_COLORS.get("high" if weird_truncated else ("medium" if medium_plus else "low"), INK),
        )

        integrity = data.get("steam_integrity", {}) or {}
        steam = data.get("steam_paths", {}) or {}
        drift = (steam.get("drift", {}) or {}).get("drift", {}) or {}
        drift_count = (drift.get("counts", {}) or {}).get("total", 0)
        steam_text = integrity.get("status_label", "未检查")
        if integrity.get("client_version"):
            steam_text += " · " + str(integrity["client_version"])
        self.card_values["steam"].configure(
            text=steam_text,
            fg=STATUS_COLORS.get(integrity.get("verdict", "info"), INK),
        )

        execution = data.get("execution", {}) or {}
        stats = execution.get("stats", {}) or {}
        self.card_values["execution"].configure(
            text=f"可疑 {stats.get('suspicious', 0)} / 路径 {stats.get('program_paths', 0)}",
            fg=STATUS_COLORS.get(execution.get("verdict", "info"), INK),
        )

        k2f = data.get("incident", {}) or {}
        self.card_values["incident"].configure(
            text=f"第 {k2f.get('stage', 0)} 阶段" if k2f else "未检查",
            fg=STATUS_COLORS.get(k2f.get("verdict", "info"), INK),
        )
        domains = data.get("domains", {}) or {}
        domain_counts = domains.get("counts", {}) or {}
        domain_total = int(domain_counts.get("domains", 0) or 0)
        ioc_total = int(domain_counts.get("ioc_domains", 0) or 0)
        self.card_values["domains"].configure(
            text=f"{domain_total} 个" + (f" / IOC {ioc_total}" if ioc_total else ""),
            fg=DANGER if ioc_total else (INK if domain_total else MUTED),
        )
        dir_count = len(self.dir_records) or int(weird.get("dir_log_records", 0) or 0)
        self.card_values["dirs"].configure(
            text=f"{dir_count} 条" if dir_count else "无清单",
            fg=INK if dir_count else MUTED,
        )

        headline = summary.get("headline", "")
        counts = summary.get("counts", {}) or {}
        if verdict in ("critical", "high"):
            bg, fg = "#fef3f2", "#912018"
        elif verdict == "medium":
            bg, fg = "#fffaeb", "#7a2e0e"
        else:
            bg, fg = "#ecfdf3", "#05603a"
        self.banner_var.set(
            f"{headline}\n"
            f"严重 {counts.get('critical', 0)} / 高 {counts.get('high', 0)} / 中 {counts.get('medium', 0)} / 低 {counts.get('low', 0)}"
            f" · 供应链事件 {k2f.get('stage_label', '未检查')} · Steam 基线变化 {drift_count} 项（只读）"
            + (" · 异常文件夹扫描因时间预算提前结束，结果不完整" if weird_truncated else "")
        )
        self.banner_label.configure(bg=bg, fg=fg)

    def _populate_findings(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.findings_by_iid = {}
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings = sorted(self.findings, key=lambda item: (order.get(item.get("severity", "info"), 9), item.get("title", "")))
        for index, item in enumerate(findings):
            iid = str(index)
            self.findings_by_iid[iid] = item
            severity = item.get("severity", "info")
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    SEVERITY_LABELS.get(severity, severity),
                    item.get("category", ""),
                    item.get("title", ""),
                    item.get("path", ""),
                ),
                tags=(severity,),
            )
        if findings:
            first = "0"
            self.tree.selection_set(first)
            self.tree.focus(first)
            self._show_detail(findings[0])
        else:
            self._show_detail(None)

    def _populate_domains(self, data: Dict[str, Any]) -> None:
        block = data.get("domains", {}) or {}
        self.domain_records = block.get("domains", []) or []
        counts = block.get("counts", {}) or {}
        available = block.get("available", {}) or {}
        flags = []
        for label, key in (
            ("DNS 缓存", "dns_cache"),
            ("DNS 日志", "dns_events"),
            ("Sysmon", "sysmon"),
            ("浏览器历史", "browser_history"),
            ("程序日志", "program_logs"),
            ("程序配置", "program_configs"),
            ("套接字", "sockets"),
        ):
            flags.append(f"{label} {'可用' if available.get(key) else '缺失'}")
        self.domain_info_var.set(
            f"域名 {counts.get('domains', 0)} 个（IOC {counts.get('ioc_domains', 0)}，AI/工具 {counts.get('ai_domains', 0)}）；"
            f"程序级 DNS {counts.get('program_events', 0)} 条；API 端点 {counts.get('api_endpoints', 0)} 条；"
            f"浏览器历史 {counts.get('browser_rows', 0)} 条。数据来源：" + "、".join(flags)
            + "。DNS 缓存与日志会过期，找不到记录不等于没发生。"
        )
        self._apply_domain_filter()

    def _apply_domain_filter(self) -> None:
        text = self.domain_search_var.get().strip().casefold()
        focus_only = bool(self.domain_focus_var.get())
        filtered = []
        for item in self.domain_records:
            domain = str(item.get("domain", ""))
            category = str(item.get("class", ""))
            haystack = " ".join((
                domain,
                category,
                "、".join(item.get("sources", []) or []),
                "、".join(item.get("processes", []) or []),
            )).casefold()
            if text and text not in haystack:
                continue
            if focus_only and not (item.get("ioc") or category != "其他"):
                continue
            filtered.append(item)
        self.domain_filtered = filtered
        for iid in self.domain_tree.get_children():
            self.domain_tree.delete(iid)
        self.domain_by_iid = {}
        for index, item in enumerate(filtered[:3000]):
            iid = str(index)
            self.domain_by_iid[iid] = item
            tag = "ioc" if item.get("ioc") else ("focus" if item.get("class") != "其他" else "")
            self.domain_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    item.get("domain", ""),
                    item.get("class", ""),
                    item.get("count", ""),
                    "、".join(item.get("sources", [])[:3]),
                    "、".join(item.get("processes", [])[:3]),
                    item.get("last_seen", ""),
                ),
                tags=(tag,) if tag else (),
            )
        self.domain_count_var.set(f"显示 {len(filtered)} / {len(self.domain_records)} 条")
        if filtered:
            self.domain_tree.selection_set("0")
            self.domain_tree.focus("0")
            self._show_domain_detail(filtered[0])
        else:
            self._show_domain_detail(None)

    def _on_domain_select(self, _event=None) -> None:
        selection = self.domain_tree.selection()
        if not selection:
            self._show_domain_detail(None)
            return
        self._show_domain_detail(self.domain_by_iid.get(selection[0]))

    def _show_domain_detail(self, item: Optional[Dict[str, Any]]) -> None:
        self.domain_detail_text.configure(state="normal")
        self.domain_detail_text.delete("1.0", "end")
        if item is None:
            self.domain_detail_text.insert("1.0", "未选择域名（或本次没有采集到域名记录）。")
        else:
            lines = [
                f"域名：{item.get('domain', '')}",
                f"分类：{item.get('class', '')}    记录数：{item.get('count', '')}    最后时间：{item.get('last_seen', '') or '未知'}",
                f"来源：{'、'.join(item.get('sources', []) or []) or '未知'}",
                f"相关进程：{'、'.join(item.get('processes', []) or []) or '未归因（需要 Sysmon 或程序日志）'}",
            ]
            if item.get("ioc"):
                lines.append("")
                lines.append("!!! 这是本次供应链事件的攻击者域名。它代表加载器/代理在本机运行过，按失陷处理。")
            endpoints = []
            if self.report_data:
                for endpoint in (self.report_data.get("domains", {}) or {}).get("api_endpoints", []) or []:
                    if endpoint.get("host") == item.get("domain"):
                        endpoints.append(endpoint)
            if endpoints:
                lines.extend(["", "该域名下记录到的 API 地址："])
                for endpoint in endpoints[:8]:
                    lines.append(f"- {endpoint.get('endpoint', '')}（{'、'.join(endpoint.get('sources', [])[:2])}）")
            self.domain_detail_text.insert("1.0", "\n".join(lines))
        self.domain_detail_text.configure(state="disabled")

    def _clear_domains(self) -> None:
        for iid in self.domain_tree.get_children():
            self.domain_tree.delete(iid)
        self.domain_records = []
        self.domain_filtered = []
        self.domain_by_iid = {}
        self.domain_info_var.set("扫描后可在这里查看本机域名访问记录。")
        self.domain_count_var.set("")
        self._show_domain_detail(None)

    def _copy_ai_hint(self) -> None:
        lines = ["VirusChecker 结果摘要（请帮我解读）", AI_HINT, ""]
        if self.report_data:
            summary = self.report_data.get("summary", {}) or {}
            lines.append(f"总体级别：{summary.get('severity_label', '')} — {summary.get('headline', '')}")
            incident = self.report_data.get("incident", {}) or {}
            if incident:
                lines.append(f"供应链事件阶段：{incident.get('stage_label', '')}")
            for item in self.findings[:15]:
                lines.append(f"[{SEVERITY_LABELS.get(item.get('severity', 'info'), item.get('severity', ''))}] {item.get('title', '')}")
                if item.get("path"):
                    lines.append("    " + str(item["path"]))
        if self.report_dir is not None:
            lines.extend(["", f"报告目录：{self.report_dir}", f"完整日志：{self.report_dir / 'gui-run.log'}"])
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.status_var.set("已复制给 AI 的摘要与日志路径")

    def _on_tree_select(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            self._show_detail(None)
            return
        self._show_detail(self.findings_by_iid.get(selection[0]))

    def _show_detail(self, item: Optional[Dict[str, Any]]) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        if item is None:
            self.detail_text.insert("1.0", "未选择发现。")
        else:
            lines = [
                f"{item.get('title', '')}",
                f"级别：{SEVERITY_LABELS.get(item.get('severity', 'info'), item.get('severity', ''))}    类别：{item.get('category', '')}",
                f"路径：{item.get('path', '') or '—'}",
                "",
                item.get("detail", "") or "无说明",
            ]
            if item.get("recommendation"):
                lines.extend(["", "建议：" + item["recommendation"]])
            evidence = item.get("evidence")
            if evidence:
                try:
                    text = json.dumps(evidence, ensure_ascii=False, default=str)
                except Exception:
                    text = str(evidence)
                if len(text) > 1200:
                    text = text[:1200] + "..."
                lines.extend(["", "证据：" + text])
            self.detail_text.insert("1.0", "\n".join(lines))
        self.detail_text.configure(state="disabled")

    def _copy_summary(self) -> None:
        if not self.report_data:
            return
        summary = self.report_data.get("summary", {}) or {}
        lines = [
            "VirusChecker 结果摘要",
            f"总体：{summary.get('severity_label', self.report_data.get('verdict', ''))}",
            summary.get("headline", ""),
            "",
        ]
        for item in self.findings[:12]:
            lines.append(f"[{SEVERITY_LABELS.get(item.get('severity', 'info'), item.get('severity', ''))}] {item.get('title', '')}")
            if item.get("path"):
                lines.append("    " + str(item["path"]))
        lines.extend(["", AI_HINT])
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.status_var.set("摘要已复制到剪贴板")

    def _open_report(self, kind: str) -> None:
        if self.report_dir is None:
            return
        mapping = {
            "html": self.report_dir / "report.html",
            "markdown": self.report_dir / "report.md",
            "json": self.report_dir / "report.json",
            "dir": self.report_dir,
        }
        target = mapping.get(kind)
        if target is None:
            return
        if not target.exists():
            messagebox.showwarning("文件不存在", f"未找到：\n{target}")
            return
        try:
            os.startfile(str(target))
        except OSError as exc:
            messagebox.showerror("打开失败", str(exc))

    def _open_log_folder(self) -> None:
        target = self.report_dir or (BASE_DIR / "reports")
        try:
            Path(target).mkdir(parents=True, exist_ok=True)
            os.startfile(str(target))
        except OSError as exc:
            messagebox.showerror("打开失败", str(exc))

    def _set_report_buttons(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for button in self.open_buttons:
            button.configure(state=state)

    def _clear_results(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.findings_by_iid = {}
        self._show_detail(None)
        for label in self.card_values.values():
            label.configure(text="—", fg=INK)
        self.banner_var.set("扫描中…")
        self._clear_domains()
        self._set_report_buttons(False)

    # -------------------------------------------------------------------- log
    def _append_log(self, text: str, tag: str = "") -> None:
        for widget in (self.log_text, self.full_log_text):
            try:
                widget.configure(state="normal")
                if tag:
                    widget.insert("end", text + "\n", tag)
                else:
                    widget.insert("end", text + "\n")
                widget.see("end")
                widget.configure(state="disabled")
            except tk.TclError:
                pass
        if self.log_handle is not None:
            try:
                self.log_handle.write(text + "\n")
                self.log_handle.flush()
            except (OSError, UnicodeError):
                pass

    def _clear_log(self) -> None:
        for widget in (self.log_text, self.full_log_text):
            try:
                widget.configure(state="normal")
                widget.delete("1.0", "end")
                widget.configure(state="disabled")
            except tk.TclError:
                pass

    def _close_log_file(self) -> None:
        if self.log_handle is not None:
            try:
                self.log_handle.flush()
                self.log_handle.close()
            except OSError:
                pass
            self.log_handle = None

    # ---------------------------------------------------------------- settings
    def _load_settings(self) -> None:
        path = _settings_path()
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        profile = str(data.get("profile", "quick"))
        self.profile_var.set("full" if profile == "full" else "quick")
        modules = data.get("modules", {})
        if isinstance(modules, dict):
            for key in self.module_vars:
                if key in modules:
                    self.module_vars[key].set(bool(modules[key]))
            # Migration from 1.x: "k2f" was the incident module.
            if "incident" not in modules and "k2f" in modules:
                self.module_vars["incident"].set(bool(modules["k2f"]))
        self.include_files_var.set(bool(data.get("include_files", False)))
        self.include_caches_var.set(bool(data.get("include_caches", False)))
        self.usn_var.set(bool(data.get("usn", True)))
        try:
            self.max_seconds_var.set(str(int(data.get("max_seconds", 180))))
        except (TypeError, ValueError):
            pass
        self.output_var.set(str(data.get("output", "")))
        self.state_var.set(str(data.get("state", "state")))
        self.extra_roots_var.set(str(data.get("extra_roots", "")))

    def _save_settings(self) -> None:
        data = {
            "profile": self.profile_var.get(),
            "modules": {key: bool(var.get()) for key, var in self.module_vars.items()},
            "include_files": bool(self.include_files_var.get()),
            "include_caches": bool(self.include_caches_var.get()),
            "usn": bool(self.usn_var.get()),
            "max_seconds": self.max_seconds_var.get(),
            "output": self.output_var.get(),
            "state": self.state_var.get(),
            "extra_roots": self.extra_roots_var.get(),
        }
        path = _settings_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ------------------------------------------------------------------ close
    def _on_close(self) -> None:
        running = self.proc is not None and self.proc.poll() is None
        if running:
            if not messagebox.askyesno("扫描进行中", "扫描仍在进行，确定停止并退出吗？"):
                return
            self.cancel_requested = True
            self._kill_process_tree(self.proc)
        self.closing = True
        self._save_settings()
        self._close_log_file()
        self.root.destroy()


def main() -> int:
    _enable_dpi_awareness()
    if os.name != "nt":
        print("此 UI 面向 Windows；当前系统不是 Windows。", file=sys.stderr)
        return 2
    if not FROZEN and not VCHECK_SCRIPT.exists():
        print("找不到 vcheck.py，请把 vcheck_gui.py 放在项目目录。", file=sys.stderr)
        return 2
    root = tk.Tk()
    VCheckGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
