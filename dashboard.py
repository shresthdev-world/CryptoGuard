"""Local Tk desktop dashboard for live monitoring and the offline college demo."""
import os
import queue
import subprocess
import threading
import tkinter as tk
from collections import deque
from pathlib import Path
from tkinter import messagebox, ttk

from detector import DemoSample, Live, demo, log_action, trust
from evidence import INTERPRETATION, LIKELY, POSSIBLE, UNUSUAL, file_hash, idle_seconds, powershell
import portable


def show_evidence(item):
    def group(label, values, empty):
        return f"{label}\n" + ("\n".join("  " + str(v) for v in values) if values else "  " + empty)
    cpu = "unavailable" if item["cpu"] is None else f"{item['cpu']}% of one logical CPU"
    gpu = "unavailable" if item["gpu"] is None else f"{item['gpu']}%"
    idle = "unavailable" if item["idle"] is None else f"{item['idle']:.0f}s"
    return "\n\n".join([
        f"{item['verdict']}   /   {item['mode']}\n{INTERPRETATION[item['verdict']]}\n{item['time']}",
        f"{item['name']}   ·   PID {item['pid']}\n{item['path'] or 'Path unavailable'}"
        + ("\n\nAction result\n  " + item["action"] if item.get("action") else ""),
        f"Usage at selection\n  CPU {cpu}   ·   GPU {gpu}\n"
        f"  User idle {idle}\n  {item['load'] or 'Selected for manual review'}",
        group("Mining-specific evidence", item["markers"] + item["pool_matches"], "No match in the checks performed"),
        group("Network  ·  " + item["network"], item["endpoints"], "No peer data"),
        f"File inspection\n  Publisher signature: {item['signature']}\n  Sample entropy: {item['entropy']}\n"
        f"  Approved file hash: {'yes' if item.get('trusted') else 'no'}",
        group("Matching startup entries", item["startup"], "No matches reported; check coverage below"),
        group("Coverage and notes", item["notes"], "No additional notes"),
    ])


class Dashboard:
    """A native Tkinter security console. Backend behaviour is unchanged."""

    BG = "#080F1D"
    SIDEBAR = "#0C1727"
    SURFACE = "#111E30"
    SURFACE_HIGH = "#17273B"
    BORDER = "#29394F"
    TEXT = "#F1F5FA"
    MUTED = "#94A5B9"
    ACCENT = "#5BE0C4"
    ACCENT_DARK = "#143B39"
    AMBER = "#F6C37A"
    RED = "#F28B98"
    BLUE = "#88B9F4"

    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.stop = threading.Event()
        self.session = 0
        self.live = None
        self.worker = None
        self.mode = "Ready"
        self.sample = None
        self.busy_scans = set()
        self.findings = {}
        self.rows = {}
        self.selected_item = None
        self.series = deque(maxlen=100)
        self.peak_cpu = 0.0
        self.nav_buttons = {}

        root.title("CryptoGuard | Cryptojacking Detection Desktop")
        root.geometry("1420x850")
        root.minsize(1050, 690)
        root.configure(bg=self.BG)
        try:
            self.icon_image = tk.PhotoImage(file=str(Path(__file__).with_name("app-icon.png")))
            root.iconphoto(True, self.icon_image)
        except tk.TclError:
            pass  # Keep the desktop app usable on Tk builds without PNG support.

        style = ttk.Style(root)
        style.theme_use("clam")
        # Native modal windows reuse the same desktop palette.
        style.configure("TFrame", background=self.SURFACE)
        style.configure("TLabel", background=self.SURFACE, foreground=self.TEXT,
                        font=("Segoe UI", 10))
        style.configure("TButton", background=self.SURFACE_HIGH,
                        foreground=self.TEXT, padding=(11, 8),
                        font=("Segoe UI", 10), borderwidth=0)
        style.map("TButton", background=[("active", "#294661")],
                  foreground=[("disabled", self.MUTED)])
        style.configure("TCombobox", fieldbackground=self.SURFACE_HIGH,
                        background=self.SURFACE_HIGH, foreground=self.TEXT)
        style.configure("Dark.Treeview", font=("Segoe UI", 10), rowheight=34,
                        background=self.SURFACE, fieldbackground=self.SURFACE,
                        foreground=self.TEXT, borderwidth=0, relief="flat")
        style.configure("Dark.Treeview.Heading", background=self.SURFACE_HIGH,
                        foreground="#ADC0D6", font=("Segoe UI", 9, "bold"),
                        padding=(12, 12), relief="flat", borderwidth=0)
        style.map("Dark.Treeview", background=[("selected", "#284D5C")],
                  foreground=[("selected", "#FFFFFF")])
        style.map("Dark.Treeview.Heading", background=[("active", "#20344C")])
        style.configure("Dark.TNotebook", background=self.SURFACE,
                        borderwidth=0, tabmargins=(8, 4, 0, 0))
        style.configure("Dark.TNotebook.Tab", background=self.SURFACE,
                        foreground=self.MUTED, padding=(18, 11),
                        font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("Dark.TNotebook.Tab", background=[("selected", self.SURFACE_HIGH),
                                                     ("active", "#1B3148")],
                  foreground=[("selected", self.ACCENT)])
        style.configure("Dark.TFrame", background=self.SURFACE)
        style.configure("Dark.Vertical.TScrollbar", background=self.SURFACE_HIGH,
                        troughcolor=self.SURFACE, arrowcolor=self.MUTED, borderwidth=0)

        # Persistent desktop navigation - this is not a website/webview.
        side = tk.Frame(root, bg=self.SIDEBAR, width=214)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(root, width=1, bg=self.BORDER).pack(side="left", fill="y")

        brand = tk.Frame(side, bg=self.SIDEBAR, padx=19, pady=23)
        brand.pack(fill="x")
        icon = tk.Label(brand, text="⬡", bg="#17463F", fg=self.ACCENT,
                        font=("Segoe UI Symbol", 23, "bold"), width=2, height=1)
        icon.pack(side="left", padx=(0, 10))
        brand_text = tk.Frame(brand, bg=self.SIDEBAR)
        brand_text.pack(side="left", anchor="center")
        tk.Label(brand_text, text="CRYPTOGUARD", bg=self.SIDEBAR, fg=self.TEXT,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(brand_text, text="SECURITY DESKTOP", bg=self.SIDEBAR, fg=self.MUTED,
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        tk.Frame(side, bg=self.BORDER, height=1).pack(fill="x", padx=18, pady=(0, 23))

        tk.Label(side, text="WORKSPACE", bg=self.SIDEBAR, fg="#6E849B",
                 font=("Segoe UI", 9, "bold"), padx=23).pack(anchor="w", pady=(0, 13))
        self.navigation(side, "▦  Overview", lambda: self.go_to("Overview"))
        self.navigation(side, "▤  Processes", lambda: self.go_to("Processes"))
        self.navigation(side, "◷  Findings", lambda: self.go_to("Findings"))
        self.navigation(side, "≡  Evidence", lambda: self.go_to("Evidence"))
        self.navigation(side, "▣  Isolated files", self.vault)
        self.select_nav("▦  Overview")

        tk.Label(side, text="ABOUT THIS APP", bg=self.SIDEBAR, fg="#6E849B",
                 font=("Segoe UI", 9, "bold"), padx=23).pack(anchor="w", pady=(40, 12))
        tk.Label(side, text="CPU usage alone is not proof\nof cryptojacking. Inspect the\nevidence before acting.",
                 bg=self.SIDEBAR, fg=self.MUTED, justify="left",
                 font=("Segoe UI", 9), padx=23).pack(anchor="w")
        tk.Frame(side, bg=self.SIDEBAR).pack(fill="both", expand=True)
        tk.Frame(side, bg=self.BORDER, height=1).pack(fill="x", padx=18, pady=(0, 18))
        tk.Label(side, text="KCC ITM  /  B.TECH MINI PROJECT", bg=self.SIDEBAR,
                 fg=self.MUTED, font=("Segoe UI", 8), padx=18).pack(anchor="w", pady=(0, 6))
        tk.Label(side, text="Developed by Shresth & Pratyush", bg=self.SIDEBAR,
                 fg=self.ACCENT, font=("Segoe UI", 8, "bold"), padx=18).pack(anchor="w", pady=(0, 6))
        tk.Label(side, text="WINDOWS DESKTOP EDITION", bg=self.SIDEBAR,
                 fg="#547F82", font=("Segoe UI", 8, "bold"), padx=18).pack(anchor="w", pady=(0, 18))

        main = tk.Frame(root, bg=self.BG)
        main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(main, bg=self.BG, padx=26, pady=18)
        header.pack(fill="x")
        heading = tk.Frame(header, bg=self.BG)
        heading.pack(side="left")
        tk.Label(heading, text="SYSTEM  /  SECURITY OVERVIEW", bg=self.BG,
                 fg=self.ACCENT, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(heading, text="Threat intelligence dashboard", bg=self.BG,
                 fg=self.TEXT, font=("Segoe UI", 23, "bold")).pack(anchor="w", pady=(5, 2))
        tk.Label(heading, text="Monitor running processes and investigate potential mining activity.",
                 bg=self.BG, fg=self.MUTED, font=("Segoe UI", 10)).pack(anchor="w")

        mode_area = tk.Frame(header, bg=self.BG)
        mode_area.pack(side="right", anchor="n")
        self.mode_label = tk.Label(mode_area, text="●  STANDBY", bg=self.SURFACE,
                                   fg=self.MUTED, font=("Segoe UI", 10, "bold"),
                                   padx=16, pady=8, highlightbackground=self.BORDER,
                                   highlightthickness=1)
        self.mode_label.pack(anchor="e")
        tk.Label(mode_area, text="LOCAL DEVICE  •  NO CLOUD UPLOAD", bg=self.BG,
                 fg="#71879E", font=("Segoe UI", 8)).pack(anchor="e", pady=(9, 0))

        controls = tk.Frame(main, bg=self.BG, padx=26)
        controls.pack(fill="x", pady=(0, 17))
        self.go_live = self.button(controls, "▶  Start live monitor",
                                   lambda: self.start("Live"), primary=True)
        self.go_demo = self.button(controls, "◇  Run safe demo",
                                   lambda: self.start("Demo"), secondary=True)
        self.halt = self.button(controls, "■  Stop", self.cancel)
        self.halt.configure(state="disabled")
        self.go_live.pack(side="left", padx=(0, 10))
        self.go_demo.pack(side="left", padx=(0, 10))
        self.halt.pack(side="left")
        tk.Label(controls, text="Safe demo uses generated readings only", bg=self.BG,
                 fg=self.MUTED, font=("Segoe UI", 9)).pack(side="right")

        metrics = tk.Frame(main, bg=self.BG, padx=26)
        metrics.pack(fill="x", pady=(0, 17))
        self.metric_processes = self.metric(metrics, "PROCESSES TRACKED", "00", "Observed this snapshot", self.BLUE)
        self.metric_findings = self.metric(metrics, "FINDINGS", "00", "This monitoring session", self.AMBER)
        self.metric_peak = self.metric(metrics, "BUSIEST PROCESS", "0.0%", "One logical processor", self.ACCENT)
        self.metric_indicators = self.metric(metrics, "MINING INDICATORS", "00", "Possible / likely", self.RED, last=True)

        # Reserve the footer before allocating expandable workspace height.
        bottom = tk.Frame(main, bg=self.SIDEBAR, padx=26, pady=9)
        bottom.pack(fill="x", side="bottom")
        tk.Label(bottom, text="●", bg=self.SIDEBAR, fg=self.ACCENT,
                 font=("Segoe UI", 10)).pack(side="left", padx=(0, 8))
        self.status = tk.StringVar(value="Ready. Start live monitoring or run the safe demo.")
        tk.Label(bottom, textvariable=self.status, bg=self.SIDEBAR, fg="#B4C7D9",
                 font=("Segoe UI", 9), anchor="w").pack(side="left", fill="x", expand=True)
        tk.Label(bottom, text="LOCAL ANALYSIS", bg=self.SIDEBAR,
                 fg="#728BA1", font=("Segoe UI", 8, "bold")).pack(side="right")

        workspace = tk.PanedWindow(main, orient="horizontal", bg=self.BG,
                                  borderwidth=0, sashwidth=11, sashrelief="flat",
                                  showhandle=False)
        workspace.pack(fill="both", expand=True, padx=26, pady=(0, 14))
        left = tk.Frame(workspace, bg=self.SURFACE, highlightbackground=self.BORDER, highlightthickness=1)
        right = tk.Frame(workspace, bg=self.SURFACE, highlightbackground=self.BORDER, highlightthickness=1)
        workspace.add(left, minsize=475, stretch="always")
        workspace.add(right, minsize=300, stretch="always")
        root.after(100, lambda: self._initial_sash(workspace))

        activity = tk.Frame(left, bg=self.SURFACE, padx=18, pady=13)
        activity.pack(fill="x")
        tk.Label(activity, text="PROCESS ACTIVITY", bg=self.SURFACE, fg=self.TEXT,
                 font=("Segoe UI", 12, "bold")).pack(side="left")
        self.meter = tk.Label(activity, text="Waiting for monitoring data", bg=self.SURFACE,
                              fg=self.MUTED, font=("Segoe UI", 9))
        self.meter.pack(side="right")
        self.graph = tk.Canvas(left, background=self.SURFACE, height=101,
                               highlightthickness=0, bd=0)
        self.graph.pack(fill="x", padx=18, pady=(0, 7))
        self.graph.bind("<Configure>", lambda _: self.draw_graph())
        tk.Frame(left, bg=self.BORDER, height=1).pack(fill="x")

        tabs = ttk.Notebook(left, style="Dark.TNotebook")
        tabs.pack(fill="both", expand=True, padx=7, pady=(7, 9))
        running = ttk.Frame(tabs, style="Dark.TFrame")
        history = ttk.Frame(tabs, style="Dark.TFrame")
        tabs.add(running, text="RUNNING PROCESSES")
        tabs.add(history, text="DETECTION FINDINGS")
        self.tabs = tabs
        inspect_bar = tk.Frame(running, bg=self.SURFACE, padx=8, pady=9)
        inspect_bar.pack(fill="x", side="bottom")
        self.button(inspect_bar, "↗  Inspect selected process", self.inspect, secondary=True).pack(side="left")
        tk.Label(inspect_bar, text="Double-click a process to inspect", bg=self.SURFACE,
                 fg=self.MUTED, font=("Segoe UI", 8)).pack(side="right")
        self.processes = self.table(running, ("Process", "PID", "CPU %", "GPU %"), (235, 70, 82, 78))
        self.processes.bind("<Double-1>", lambda _: self.inspect())
        self.history = self.table(history, ("Time", "Process", "Result"), (90, 180, 175))
        for verdict, bg, fg in [(LIKELY, "#412834", "#FF9DA9"),
                                (POSSIBLE, "#3E3428", "#F8D19A"),
                                (UNUSUAL, "#22354A", "#A9CEFC")]:
            self.history.tag_configure(verdict, background=bg, foreground=fg)
        self.history.bind("<<TreeviewSelect>>", self.choose)

        inspector_header = tk.Frame(right, bg=self.SURFACE, padx=17, pady=15)
        inspector_header.pack(fill="x")
        tk.Label(inspector_header, text="EVIDENCE INSPECTOR", bg=self.SURFACE,
                 fg=self.TEXT, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(inspector_header, text="Understand why a process was flagged", bg=self.SURFACE,
                 fg=self.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))
        self.verdict_tag = tk.Label(inspector_header, text="NO FINDING SELECTED",
                                    bg="#1F3445", fg=self.MUTED,
                                    font=("Segoe UI", 9, "bold"), padx=11, pady=7)
        self.verdict_tag.pack(anchor="w", pady=(15, 0))
        tk.Frame(right, bg=self.BORDER, height=1).pack(fill="x")

        tk.Frame(right, bg=self.BORDER, height=1).pack(fill="x")
        actions = tk.Frame(right, bg=self.SURFACE, padx=16, pady=15)
        actions.pack(fill="x", side="bottom")
        self.removal = self.button(actions, "Remove miner…", self.remove, primary=True)
        self.removal.configure(state="disabled")
        self.removal.pack(side="left", padx=(0, 8))
        self.button(actions, "Review actions…", self.actions, secondary=True).pack(side="left")

        detail_box = tk.Frame(right, bg=self.SURFACE, padx=15, pady=12)
        detail_box.pack(fill="both", expand=True)
        self.detail = tk.Text(detail_box, wrap="word", relief="flat", bd=0,
                              bg=self.SURFACE, fg="#DCE8F7", insertbackground=self.TEXT,
                              highlightthickness=0, padx=8, pady=8,
                              font=("Segoe UI", 10), width=28, spacing1=2, spacing3=3)
        self.detail.tag_configure("section", foreground=self.ACCENT, font=("Segoe UI", 10, "bold"), spacing1=13)
        self.detail.tag_configure("title", foreground=self.TEXT, font=("Segoe UI", 12, "bold"))
        self.detail.tag_configure("subtle", foreground=self.MUTED)
        scroll = ttk.Scrollbar(detail_box, command=self.detail.yview, style="Dark.Vertical.TScrollbar")
        self.detail.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.detail.pack(fill="both", expand=True)
        self.write_detail("Select a finding to review its evidence, network clues, and inspection coverage.\n\nTip: Run safe demo to compare ordinary high CPU usage with mining indicators.")
        self.update_metrics()
        self.draw_graph()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(70, self.drain)

    def _initial_sash(self, pane):
        try:
            if pane.winfo_exists() and pane.winfo_width() >= 800:
                pane.sash_place(0, int(pane.winfo_width() * .64), 0)
        except tk.TclError:
            pass

    def button(self, parent, label, command, primary=False, secondary=False):
        bg = self.ACCENT if primary else (self.SURFACE_HIGH if secondary else "#1A293D")
        fg = "#09201E" if primary else self.TEXT
        return tk.Button(parent, text=label, command=command,
                         bg=bg, fg=fg, activebackground=("#8AF6D9" if primary else "#24415B"),
                         activeforeground=fg, disabledforeground="#6B8795",
                         relief="flat", bd=0, highlightthickness=0,
                         cursor="hand2", font=("Segoe UI", 10, "bold"), padx=14, pady=10)

    def navigation(self, parent, label, command):
        holder = tk.Frame(parent, bg=self.SIDEBAR, padx=12, pady=2)
        holder.pack(fill="x")
        btn = tk.Button(holder, text=label, command=command, anchor="w", bg=self.SIDEBAR,
                        activebackground=self.SURFACE_HIGH, activeforeground=self.TEXT,
                        fg=self.MUTED, font=("Segoe UI", 10), padx=13, pady=11,
                        relief="flat", bd=0, highlightthickness=0, cursor="hand2")
        btn.pack(fill="x")
        self.nav_buttons[label] = btn

    def select_nav(self, label):
        for name, btn in self.nav_buttons.items():
            selected = name == label
            btn.configure(bg=self.ACCENT_DARK if selected else self.SIDEBAR,
                          fg=self.ACCENT if selected else self.MUTED,
                          font=("Segoe UI", 10, "bold" if selected else "normal"))

    def go_to(self, target):
        if target == "Overview":
            self.tabs.select(0)
            self.select_nav("▦  Overview")
        elif target == "Processes":
            self.tabs.select(0)
            self.select_nav("▤  Processes")
            self.processes.focus_set()
        elif target == "Findings":
            self.tabs.select(1)
            self.select_nav("◷  Findings")
            self.history.focus_set()
        elif target == "Evidence":
            self.select_nav("≡  Evidence")
            self.detail.focus_set()

    def metric(self, parent, label, value, hint, color, last=False):
        frame = tk.Frame(parent, bg=self.SURFACE, highlightbackground=self.BORDER,
                         highlightthickness=1, height=116)
        frame.pack(side="left", fill="x", expand=True, padx=(0, 0 if last else 11))
        frame.pack_propagate(False)
        tk.Frame(frame, bg=color, height=3).pack(fill="x")
        tk.Label(frame, text=label, bg=self.SURFACE, fg=self.MUTED,
                 font=("Segoe UI", 8, "bold"), padx=14).pack(anchor="w", pady=(13, 2))
        big = tk.Label(frame, text=value, bg=self.SURFACE, fg=self.TEXT,
                       font=("Segoe UI", 24, "bold"), padx=14)
        big.pack(anchor="w")
        tk.Label(frame, text=hint, bg=self.SURFACE, fg="#71879D",
                 font=("Segoe UI", 8), padx=14).pack(anchor="w", pady=(0, 5))
        return big

    def update_metrics(self):
        self.metric_processes.configure(text=f"{len(self.rows):02d}")
        self.metric_findings.configure(text=f"{len(self.findings):02d}")
        self.metric_peak.configure(text=f"{self.peak_cpu:.1f}%")
        indicators = sum(x["verdict"] in (POSSIBLE, LIKELY) for x in self.findings.values())
        self.metric_indicators.configure(text=f"{indicators:02d}")

    def draw_graph(self):
        canvas = self.graph
        canvas.delete("all")
        width = max(360, canvas.winfo_width())
        height = max(120, canvas.winfo_height())
        left, right, top, bottom = 12, width-14, 24, height-18
        ceiling = max(100, ((max(self.series, default=0) // 100) + 1) * 100)
        for factor in (0.0, .33, .66, 1.0):
            y = bottom - (bottom-top) * factor
            canvas.create_line(left, y, right, y, fill="#24364A", dash=(3, 6))
        canvas.create_text(left, 5, anchor="nw", fill=self.ACCENT,
                           font=("Segoe UI", 9, "bold"),
                           text=f"PEAK CPU  /  {self.peak_cpu:.1f}%")
        canvas.create_text(right, 5, anchor="ne", fill=self.MUTED,
                           font=("Segoe UI", 8), text=f"Scale {ceiling:.0f}%  •  last 100 samples")
        samples = list(self.series)
        if len(samples) > 1:
            points = [(left + i * (right-left) / max(99, len(samples)-1),
                       bottom - max(0, min(val, ceiling)) / ceiling * (bottom-top))
                      for i, val in enumerate(samples)]
            polygon = [left, bottom] + [v for point in points for v in point] + [points[-1][0], bottom]
            canvas.create_polygon(polygon, fill="#143F42", outline="")
            canvas.create_line(*[v for pt in points for v in pt],
                               fill=self.ACCENT, width=3, smooth=True)
            x, y = points[-1]
            canvas.create_oval(x-4, y-4, x+4, y+4, fill=self.ACCENT, outline=self.SURFACE, width=2)
        elif samples:
            y = bottom - samples[-1] / ceiling * (bottom-top)
            canvas.create_oval(left-3, y-3, left+3, y+3, fill=self.ACCENT, outline="")
        else:
            canvas.create_text(width/2, (height+top)/2, text="No process readings yet",
                               fill="#6D8297", font=("Segoe UI", 10))

    def table(self, parent, columns, widths):
        frame = ttk.Frame(parent, style="Dark.TFrame")
        frame.pack(fill="both", expand=True, padx=7, pady=(7, 0))
        tree = ttk.Treeview(frame, columns=columns, show="headings",
                            selectmode="browse", style="Dark.Treeview")
        for col, width in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=width, minwidth=55, stretch=True,
                        anchor="w" if col in ("Process", "Result") else "center")
        tree.tag_configure("alternating", background="#142238")
        scroll = ttk.Scrollbar(frame, command=tree.yview, style="Dark.Vertical.TScrollbar")
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return tree

    def write_detail(self, message):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        blocks = message.split("\n")
        titles = ("Usage at selection", "Mining-specific evidence", "Network", "File inspection",
                  "Matching startup entries", "Coverage and notes", "Action result")
        for i, line in enumerate(blocks):
            tag = "title" if i == 0 else "section" if line.startswith(titles) else "subtle" if not line else None
            self.detail.insert("end", line + "\n", tag)
        self.detail.configure(state="disabled")

    def start(self, mode):
        if self.worker and self.worker.is_alive():
            return
        self.session += 1
        ticket = self.session
        self.mode = mode
        self.stop = threading.Event()
        stop = self.stop
        self.removal.configure(state="disabled", text="Remove miner…")
        self.sample = None
        self.findings.clear()
        self.rows.clear()
        self.selected_item = None
        self.series.clear()
        self.peak_cpu = 0.0
        self.draw_graph()
        self.update_metrics()
        for tree in (self.history, self.processes):
            tree.delete(*tree.get_children())
        self.tabs.select(0)
        self.write_detail("Select a finding to see its evidence.")
        self.live = None
        self.mode_label.configure(text="●  " + ("LIVE MONITORING" if mode == "Live" else "SIMULATED DEMO"),
                                  fg=self.ACCENT if mode == "Live" else self.AMBER)
        self.verdict_tag.configure(text="NO FINDING SELECTED", bg="#1F3445", fg=self.MUTED)
        self.status.set("Sampling…" if mode == "Live" else "Running generated test readings…")
        self.go_live.configure(state="disabled")
        self.go_demo.configure(state="disabled")
        self.halt.configure(state="normal")

        def emit(kind, data):
            self.events.put((ticket, kind, data))

        def work():
            try:
                if mode == "Demo":
                    demo(emit, stop, .15)
                else:
                    self.live = Live(emit, stop)
                    self.live.run()
            except ModuleNotFoundError as exc:
                emit("status", "Live mode needs psutil. Run Setup-Live.cmd, then reopen Start.cmd." if exc.name == "psutil" else str(exc))
            except Exception as exc:
                emit("status", f"Could not run {mode.lower()}: {exc}")
            finally:
                stop.set()
                emit("finished", None)
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def cancel(self):
        self.stop.set()
        self.status.set("Monitoring stopped.")
        self.mode_label.configure(text="●  STOPPING", fg=self.MUTED)
        self.halt.configure(state="disabled")

    def close(self):
        self.stop.set()
        self.root.destroy()

    def draw_snapshot(self, rows, idle, gpu_status):
        old = self.processes.selection()
        self.rows = {f"{r['pid']}_{r['born']}": r for r in rows}
        for key in self.processes.get_children():
            if key not in self.rows:
                self.processes.delete(key)
        for pos, (key, r) in enumerate(self.rows.items()):
            vals = (r["name"], r["pid"], r["cpu"], "—" if r["gpu"] is None else r["gpu"])
            if self.processes.exists(key):
                self.processes.item(key, values=vals, tags=("alternating",) if pos % 2 else ())
                self.processes.move(key, "", pos)
            else:
                self.processes.insert("", "end", iid=key, values=vals,
                                      tags=("alternating",) if pos % 2 else ())
        if old and old[0] in self.rows:
            self.processes.selection_set(old[0])
        idle_text = "" if idle is None else f"  ·  Idle {idle:.0f}s"
        self.meter.configure(text=f"{len(rows)} processes  ·  {gpu_status}{idle_text}")
        peak = max((r["cpu"] for r in rows), default=0)
        self.peak_cpu = peak
        self.series.append(peak)
        self.draw_graph()
        self.update_metrics()

    def inspect(self):
        ids = self.processes.selection()
        if self.mode != "Live" or self.stop.is_set() or not self.live:
            self.status.set("Start live monitoring to inspect an actual process.")
        elif ids and ids[0] in self.rows:
            row = self.rows[ids[0]]
            self.live.request(row, idle=idle_seconds())
            self.status.set(f"Review queued for {row['name']}. Results appear under Findings.")
        else:
            self.status.set("Select a process from the list.")

    def choose(self, _=None):
        ids = self.history.selection()
        if ids and ids[0] in self.findings:
            self.selected_item = self.findings[ids[0]]
            item = self.selected_item
            self.write_detail(show_evidence(item))
            verdict = item["verdict"]
            colour = (self.RED if verdict == LIKELY else self.AMBER if verdict == POSSIBLE
                      else self.BLUE if verdict == UNUSUAL else self.ACCENT)
            self.verdict_tag.configure(text=verdict.upper(),
                                        bg=self.SURFACE_HIGH, fg=colour)
            allow = item["verdict"] in (LIKELY, POSSIBLE) and (item["mode"] == "Live" or item["name"] == "Simulated miner")
            self.removal.configure(state="normal" if allow else "disabled",
                                   text="Demo removal…" if item["mode"] == "Demo" else "Remove miner…")

    def drain(self):
        try:
            while True:
                ticket, kind, data = self.events.get_nowait()
                if ticket != self.session:
                    continue
                if kind == "snapshot":
                    self.draw_snapshot(*data)
                elif kind == "finding":
                    key = self.history.insert("", 0, values=(data["time"][11:19], data["name"], data["verdict"]), tags=(data["verdict"],))
                    self.findings[key] = data
                    self.update_metrics()
                    if not self.history.selection() or self.mode == "Demo" or data.get("manual"):
                        self.history.selection_set(key)
                        self.choose()
                    if data.get("manual"):
                        self.tabs.select(1)
                    self.status.set(f"{data['verdict']} · {data['name']} · See Findings")
                elif kind == "action":
                    item, outcome = data
                    item["action"] = outcome
                    self.choose()
                    self.status.set(outcome)
                    messagebox.showinfo("Selected file · action result", item["name"] + "\n\n" + outcome, parent=self.root)
                elif kind == "status":
                    self.status.set(data)
                elif kind == "finished":
                    self.halt.configure(state="disabled")
                    self.go_live.configure(state="normal")
                    self.go_demo.configure(state="normal")
                    self.mode_label.configure(text="●  DEMO COMPLETE" if self.mode == "Demo" else "●  STOPPED",
                                              fg=self.MUTED)
                    if self.mode == "Demo" and self.findings:
                        self.tabs.select(1)
        except queue.Empty:
            pass
        self.root.after(70, self.drain)

    def training(self):
        try:
            if not self.sample:
                self.sample = DemoSample()
            restore = self.sample.isolated.exists()
            verb = "Restore" if restore else "Quarantine"
            if messagebox.askokcancel(f"{verb} demo sample", f"{verb} the app-created text sample?\n\n{self.sample.folder}"):
                path = self.sample.move(restore)
                state = "Restored" if restore else "Quarantined"
                self.selected_item["action"] = f"{state} the harmless demo sample. File location: {path}"
                log_action(self.selected_item, self.selected_item["action"])
                self.choose()
                messagebox.showinfo("Demo sample", self.selected_item["action"])
        except (ValueError, OSError) as exc:
            messagebox.showerror("Demo sample", str(exc))

    def remove(self):
        item = self.selected_item
        if not item or item["verdict"] not in (LIKELY, POSSIBLE):
            return
        if item["mode"] == "Demo":
            if item["name"] == "Simulated miner":
                self.training()
            return
        if os.name != "nt":
            messagebox.showinfo("Remove miner", "Live remediation uses Windows.")
            return
        window = tk.Toplevel(self.root)
        window.configure(bg=self.SURFACE)
        window.title("Remove miner")
        window.transient(self.root)
        window.grab_set()
        panel = ttk.Frame(window, padding=18)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text=item["name"], font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(panel, text=item["path"] or "Executable path unavailable", wraplength=500).pack(anchor="w", pady=5)
        ttk.Label(panel, text="For a suspected threat, scan the selected file. In Protection history, match the affected path and choose Quarantine or Remove when offered.", wraplength=500).pack(anchor="w", pady=6)

        def action(label, callback):
            def run():
                try:
                    callback()
                except Exception as exc:
                    messagebox.showerror(label, str(exc), parent=window)
            ttk.Button(panel, text=label, command=run).pack(fill="x", pady=2)

        if item.get("digest"):
            action("Scan selected file with Defender…", lambda: self.scan(item))
        action("Open Protection history", lambda: os.startfile("windowsdefender://history/"))
        action("Uninstall an installed app in Windows Settings", lambda: os.startfile("ms-settings:appsfeatures"))
        if portable.eligible(item):
            ttk.Label(panel, text="For this standalone miner, end the selected process and then isolate its executable. Isolated files can be restored from the toolbar.", wraplength=500).pack(anchor="w", pady=6)
            action("End selected process…", lambda: self.end_process(item))
            def isolate():
                if messagebox.askyesno("Isolate portable file", "Move this executable out of its launch path?\n\n" + item["path"], parent=window):
                    case = portable.isolate(item)
                    item["action"] = "Portable file isolated. Recovery record: " + case.name
                    self.choose()
                    log_action(item, item["action"])
                    messagebox.showinfo("Isolated", item["action"], parent=window)
            action("Isolate portable file…", isolate)

    def vault(self):
        win = tk.Toplevel(self.root)
        win.configure(bg=self.SURFACE)
        win.title("Isolated portable files")
        panel = ttk.Frame(win, padding=14)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text="Portable files held by this detector", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(panel, text="Defender-managed files appear in Windows Security > Protection history.").pack(anchor="w", pady=5)
        tree = self.table(panel, ("Original executable", "Record"), (430, 140))
        cases = {}
        try:
            for case in portable.held_files():
                data = portable.record(case)
                key = tree.insert("", "end", values=(data["source"], case.name[:10]))
                cases[key] = case
        except (OSError, ValueError, KeyError) as exc:
            messagebox.showerror("Isolation records", str(exc), parent=win)
        if not cases:
            ttk.Label(panel, text="No portable files in isolation.").pack(anchor="w")
        def restore():
            selection = tree.selection()
            if not selection:
                return
            case = cases[selection[0]]
            try:
                path = portable.record(case)["source"]
                if messagebox.askyesno("Restore executable", "Restore this exact file only if you trust it?\n\n" + path, parent=win):
                    portable.restore(case)
                    tree.delete(selection[0])
                    messagebox.showinfo("Restored", path, parent=win)
            except Exception as exc:
                messagebox.showerror("Restore failed", str(exc), parent=win)
        ttk.Button(panel, text="Restore selected file…", command=restore).pack(anchor="w", pady=6)

    def actions(self):
        item = self.selected_item
        if not item or item["mode"] != "Live":
            messagebox.showinfo("Review actions", "Select a live finding or inspect a live process first. Use Demo removal on the simulated miner for training.")
            return
        window = tk.Toplevel(self.root)
        window.configure(bg=self.SURFACE)
        window.title("Review actions")
        panel = ttk.Frame(window, padding=14)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text=f"{item['name']} · PID {item['pid']}", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(panel, text=item["path"] or "Path unavailable", wraplength=480).pack(anchor="w", pady=6)
        def button(label, action):
            def run():
                try:
                    action()
                except Exception as exc:
                    messagebox.showerror(label, str(exc), parent=window)
            ttk.Button(panel, text=label, command=run).pack(fill="x", pady=2)
        def change_trust():
            enable = not item["trusted"]
            trust(item, enable)
            item["trusted"] = enable
            self.choose()
            window.destroy()
        if item.get("digest"):
            button("Remove app approval" if item["trusted"] else "Approve this file hash", change_trust)
        if os.name == "nt":
            button("Scan selected file with Defender…", lambda: self.scan(item))
            button("End selected process…", lambda: self.end_process(item))
            button("Open Windows Security", lambda: os.startfile("windowsdefender://threat/"))
            if item["startup"]:
                button("Review matching startup entries…", lambda: self.startup_review(item))

    def startup_review(self, item):
        win = tk.Toplevel(self.root)
        win.configure(bg=self.SURFACE)
        win.title("Matching startup entries")
        panel = ttk.Frame(win, padding=12)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text="\n".join(item["startup"]), wraplength=600).pack(anchor="w")
        ttk.Label(panel, text="Review the target path in the corresponding Windows tool before changing a startup entry.", wraplength=500).pack(pady=8)
        system = Path(os.environ["SystemRoot"])
        selection = ttk.Combobox(panel, state="readonly", values=item["startup"], width=65)
        selection.pack(fill="x", pady=4)
        selection.current(0)
        def disable():
            entry = selection.get()
            try:
                path = Path(item["path"]).resolve()
                if (not item.get("digest") or file_hash(path) != item["digest"]
                        or path.is_relative_to(system.resolve())):
                    raise ValueError("Target is protected or changed. Inspect it again.")
                if not messagebox.askyesno("Disable startup entry",
                        "Disable this exact entry? A task or service will be disabled. A Run value will be backed up and removed.\n\n" + entry,
                        parent=win):
                    return
                message = powershell("disable-startup", path, 45, entry)
                messagebox.showinfo("Startup review", message, parent=win)
            except Exception as exc:
                messagebox.showerror("Startup review", str(exc), parent=win)
        ttk.Button(panel, text="Disable selected startup entry…", command=disable).pack(fill="x")
        for label, filename, arg in [
            ("Task Scheduler", "System32/mmc.exe", "taskschd.msc"),
            ("Services", "System32/mmc.exe", "services.msc"),
            ("Registry Editor", "regedit.exe", ""),
        ]:
            cmd = [str(system / filename)]
            if arg:
                cmd.append(str(system / "System32" / arg))
            ttk.Button(panel, text=label, command=lambda command=cmd: subprocess.Popen(command)).pack(fill="x", pady=2)

    def scan(self, item):
        if not item.get("digest") or file_hash(item["path"]) != item["digest"]:
            raise ValueError("File identity unavailable or changed. Inspect again.")
        if not messagebox.askyesno("Microsoft Defender", "Scan this file? Defender can quarantine threats according to your Windows settings.\n\n" + item["path"]):
            return
        path = item["path"]
        if path in self.busy_scans:
            messagebox.showinfo("Defender scan", "A scan of this file is already in progress.")
            return
        self.busy_scans.add(path)
        ticket = self.session
        def run():
            try:
                if file_hash(path) != item["digest"]:
                    raise ValueError("The file changed after selection.")
                result = powershell("scan", path, timeout=300)
            except Exception as exc:
                result = f"Defender action unverified. Check Protection history. {exc}"
            finally:
                self.busy_scans.discard(path)
            try:
                log_action(item, result)
            except OSError as exc:
                result += f" Action log unavailable: {exc}"
            self.events.put((ticket, "action", (item, result)))
        threading.Thread(target=run, daemon=True).start()
        self.status.set(f"Defender is scanning {item['name']}.")

    def end_process(self, item):
        import psutil
        p = psutil.Process(item["pid"])
        path = Path(p.exe()).resolve()
        if (p.create_time() != item["born"] or path != Path(item["path"]).resolve()
                or not item.get("digest") or file_hash(path) != item["digest"]):
            raise ValueError("Process identity or file changed. Inspect again.")
        if (p.pid in {0, 4, os.getpid()} or path.is_relative_to(Path(os.environ["SystemRoot"]).resolve())
                or p.username().casefold() != psutil.Process().username().casefold()):
            raise ValueError("This action is available for non-system applications owned by the current user.")
        if messagebox.askyesno("End selected process", f"Stop {p.name()} (PID {p.pid})? Unsaved work in it may be lost.\n\n{path}"):
            if not p.is_running():
                raise ValueError("The original process has exited.")
            p.terminate()
            self.status.set("Termination requested for the selected process.")


def launch(run_demo=False):
    root = tk.Tk()
    app = Dashboard(root)
    if run_demo:
        root.after(20, lambda: app.start("Demo"))
    root.mainloop()


if __name__ == "__main__":
    launch()
