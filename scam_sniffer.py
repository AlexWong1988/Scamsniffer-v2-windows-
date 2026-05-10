"""
╔══════════════════════════════════════════════════════════════╗
║  SCAM SNIFFER v2.0                                          ║
║  Singapore Threat Intelligence Scanner                       ║
║  Portable Windows 11 Desktop Edition                         ║
╚══════════════════════════════════════════════════════════════╝

Two scan modes:
  1. FREE MODE  — Google News RSS + DuckDuckGo (no API key needed)
  2. AI MODE    — Anthropic Claude API with web search + AI threat rating

Requirements: Python 3.10+
Optional:     anthropic SDK (only for AI mode)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import csv
import json
import os
import sys
import re
import urllib.request
import urllib.parse
import urllib.error
import ssl
import xml.etree.ElementTree as ET
from datetime import datetime
from html import unescape
from html.parser import HTMLParser

# ─── Attempt to import anthropic (optional) ──────────────────
ANTHROPIC_AVAILABLE = False
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    pass


# ─── KEYWORD PRESETS ──────────────────────────────────────────

KEYWORD_PRESETS = {
    "Scam Alerts": [
        "Singapore scam alert",
        "Singapore phishing scam",
        "Singapore investment scam",
        "Singapore job scam",
        "Singapore love scam romance",
        "Singapore scam victim",
        "Singapore crypto scam",
        "Singapore CPF scam",
        "Singapore bank scam SMS",
        "Singapore impersonation scam",
    ],
    "Propaganda & Misinfo": [
        "Singapore fake news POFMA",
        "Singapore disinformation",
        "Singapore misinformation online",
        "Singapore foreign interference",
        "Singapore deepfake",
        "Singapore social media manipulation",
        "Singapore propaganda",
    ],
    "Fraud Trends": [
        "Singapore online fraud",
        "Singapore scam statistics police",
        "Singapore ScamShield",
        "Singapore anti-scam centre",
        "Singapore money mule",
        "Singapore Carousell scam",
        "Singapore Shopee Lazada scam",
        "Singapore telegram scam",
    ],
}

ALL_CATEGORIES = list(KEYWORD_PRESETS.keys())

# ─── DARK THEME ───────────────────────────────────────────────

C = {
    "bg":         "#0a0d12",
    "bg2":        "#10141c",
    "bg3":        "#181d28",
    "border":     "#1e2530",
    "border_hi":  "#2a3545",
    "fg":         "#c0c8d8",
    "fg_dim":     "#556677",
    "accent":     "#00ffc8",
    "accent2":    "#00aa88",
    "red":        "#ff4455",
    "orange":     "#ffaa00",
    "green":      "#00cc88",
    "blue":       "#4488dd",
    "blue_dim":   "#335588",
    "yellow":     "#cccc44",
}

# ─── CONFIG ───────────────────────────────────────────────────

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sniffer_config.json")

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_config(data):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except:
        pass


# ─── HTML TEXT STRIPPER ───────────────────────────────────────

class HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result = []
    def handle_data(self, d):
        self.result.append(d)
    def get_text(self):
        return "".join(self.result)

def strip_html(html_str):
    s = HTMLStripper()
    try:
        s.feed(unescape(html_str or ""))
    except:
        return html_str or ""
    return s.get_text().strip()


# ─── FREE SCANNER: Google News RSS ───────────────────────────

def scan_google_news_rss(keyword, log_fn=None):
    """Fetch Google News RSS for a keyword. Returns list of result dicts."""
    results = []
    encoded = urllib.parse.quote(keyword)
    url = f"https://news.google.com/rss/search?q={encoded}&hl=en-SG&gl=SG&ceid=SG:en"

    if log_fn:
        log_fn(f"  → GET {url[:90]}...")

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = resp.read().decode("utf-8", errors="replace")

        root = ET.fromstring(data)
        items = root.findall(".//item")

        if log_fn:
            log_fn(f"  ✓ Found {len(items)} articles from Google News")

        for item in items[:8]:  # Cap at 8 per keyword
            title = strip_html(item.findtext("title", ""))
            link = item.findtext("link", "")
            pub_date = item.findtext("pubDate", "Unknown")
            description = strip_html(item.findtext("description", ""))
            source = item.findtext("source", "")

            # Clean up date
            if pub_date and pub_date != "Unknown":
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(pub_date)
                    pub_date = dt.strftime("%Y-%m-%d")
                except:
                    pub_date = pub_date[:16]

            # Simple threat classification by keyword matching
            threat = classify_threat_simple(title + " " + description, keyword)

            results.append({
                "title": title[:200],
                "source": source or extract_domain(link),
                "url": link,
                "snippet": description[:300],
                "date": pub_date,
                "threat_level": threat,
                "keyword": keyword,
                "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

    except Exception as e:
        if log_fn:
            log_fn(f"  ✗ Google News error: {e}")

    return results


# ─── FREE SCANNER: DuckDuckGo HTML ───────────────────────────

def scan_duckduckgo(keyword, log_fn=None):
    """Scrape DuckDuckGo Lite for results. Returns list of result dicts."""
    results = []
    encoded = urllib.parse.quote(keyword)
    url = f"https://lite.duckduckgo.com/lite/?q={encoded}"

    if log_fn:
        log_fn(f"  → GET DuckDuckGo Lite...")

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            html = resp.read().decode("utf-8", errors="replace")

        # Parse DDG Lite results (simple regex for the lite page)
        # Links are in <a> tags with class="result-link"
        link_pattern = re.findall(
            r'<a[^>]*rel="nofollow"[^>]*href="([^"]+)"[^>]*>\s*(.*?)\s*</a>',
            html, re.DOTALL
        )
        snippet_pattern = re.findall(
            r'<td[^>]*class="result-snippet"[^>]*>(.*?)</td>',
            html, re.DOTALL
        )

        count = min(len(link_pattern), 8)
        if log_fn:
            log_fn(f"  ✓ Found {count} results from DuckDuckGo")

        for i in range(count):
            link_url = link_pattern[i][0]
            title = strip_html(link_pattern[i][1])
            snippet = strip_html(snippet_pattern[i]) if i < len(snippet_pattern) else ""

            threat = classify_threat_simple(title + " " + snippet, keyword)

            results.append({
                "title": title[:200],
                "source": extract_domain(link_url),
                "url": link_url,
                "snippet": snippet[:300],
                "date": "Unknown",
                "threat_level": threat,
                "keyword": keyword,
                "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

    except Exception as e:
        if log_fn:
            log_fn(f"  ✗ DuckDuckGo error: {e}")

    return results


def extract_domain(url):
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        return domain
    except:
        return ""


def classify_threat_simple(text, keyword):
    """Rule-based threat classification without AI."""
    text_lower = text.lower()
    high_signals = [
        "victim", "lost", "million", "arrested", "police", "warning",
        "urgent", "alert", "danger", "report", "charged", "syndicate",
        "convicted", "fraud ring", "crackdown", "scam call", "malware",
        "data breach", "identity theft", "money laundered", "POFMA",
        "correction direction", "fake news order"
    ]
    medium_signals = [
        "scam", "phishing", "fake", "fraud", "suspicious", "beware",
        "caution", "advisory", "propaganda", "misleading", "manipulat",
        "disinformation", "misinformation", "deepfake"
    ]

    high_count = sum(1 for s in high_signals if s.lower() in text_lower)
    med_count = sum(1 for s in medium_signals if s.lower() in text_lower)

    if high_count >= 2:
        return "High"
    elif high_count >= 1 or med_count >= 2:
        return "Medium"
    else:
        return "Low"


# ─── AI SCANNER: Anthropic API ────────────────────────────────

def scan_anthropic_ai(keyword, client, log_fn=None):
    """Use Anthropic API with web search + AI classification."""
    if log_fn:
        log_fn(f"  → Calling Claude API with web search...")

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            tools=[{"type": "web_search_20250305", "name": "web_search"}],
            messages=[{
                "role": "user",
                "content": f"""Search the web for: "{keyword}"

Return ONLY a JSON array of results. Each object must have:
- "title": article/page title
- "source": website or publication name
- "url": the URL
- "snippet": 1-2 sentence summary
- "date": publication date if visible, otherwise "Unknown"
- "threat_level": "High", "Medium", or "Low" — based on how directly it relates to active scams, fraud, or propaganda targeting Singapore

Return ONLY the raw JSON array. No markdown fences, no preamble. If nothing found, return [].
"""
            }]
        )

        texts = [b.text for b in response.content if b.type == "text"]
        combined = "\n".join(texts)

        cleaned = re.sub(r"```json|```", "", combined).strip()
        match = re.search(r"\[[\s\S]*\]", cleaned)
        if match:
            parsed = json.loads(match.group(0))
            if log_fn:
                log_fn(f"  ✓ Claude returned {len(parsed)} AI-classified results")
            return [{
                "title": item.get("title", ""),
                "source": item.get("source", ""),
                "url": item.get("url", ""),
                "snippet": item.get("snippet", ""),
                "date": item.get("date", "Unknown"),
                "threat_level": item.get("threat_level", "Low"),
                "keyword": keyword,
                "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            } for item in parsed]
        else:
            if log_fn:
                log_fn(f"  ⚠ No JSON array in API response. Raw: {combined[:200]}")

    except anthropic.AuthenticationError:
        if log_fn:
            log_fn(f"  ✗ AUTHENTICATION ERROR — Invalid API key!")
        raise
    except anthropic.RateLimitError:
        if log_fn:
            log_fn(f"  ✗ RATE LIMITED — Too many requests, wait a moment")
    except anthropic.APIError as e:
        if log_fn:
            log_fn(f"  ✗ API Error: {e}")
    except Exception as e:
        if log_fn:
            log_fn(f"  ✗ Error: {type(e).__name__}: {e}")

    return []


# ═══════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════

class ScamSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SCAM SNIFFER v2.0 — Singapore Threat Intelligence Scanner")
        self.root.geometry("1340x820")
        self.root.minsize(1000, 650)
        self.root.configure(bg=C["bg"])

        # State
        self.results = []
        self.scanning = False
        self.abort_flag = False
        self.api_key = tk.StringVar()
        self.scan_mode = tk.StringVar(value="free")  # "free" or "ai"
        self.custom_keywords = []
        self.cat_vars = {}

        # Load config
        cfg = load_config()
        self.api_key.set(cfg.get("api_key", ""))
        self.custom_keywords = cfg.get("custom_keywords", [])
        self.scan_mode.set(cfg.get("scan_mode", "free"))

        self._apply_theme()
        self._build_ui()

        # Restore
        saved_cats = cfg.get("categories", ALL_CATEGORIES)
        for cat in KEYWORD_PRESETS:
            if cat in saved_cats:
                self.cat_vars[cat].set(True)
        for kw in self.custom_keywords:
            self.custom_listbox.insert(tk.END, kw)
        self._update_kw_count()
        self._on_mode_change()

    # ── Theme ──

    def _apply_theme(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=C["bg"], foreground=C["fg"],
                         fieldbackground=C["bg2"], bordercolor=C["border"],
                         troughcolor=C["bg2"], font=("Consolas", 10))
        style.configure("TFrame", background=C["bg"])
        style.configure("TLabel", background=C["bg"], foreground=C["fg"], font=("Consolas", 10))
        style.configure("Dim.TLabel", background=C["bg"], foreground=C["fg_dim"], font=("Consolas", 9))
        style.configure("Title.TLabel", background=C["bg"], foreground=C["accent"],
                         font=("Consolas", 16, "bold"))
        style.configure("Section.TLabel", background=C["bg"], foreground=C["fg_dim"],
                         font=("Consolas", 9, "bold"))
        style.configure("Status.TLabel", background=C["bg"], foreground=C["fg_dim"],
                         font=("Consolas", 10))
        style.configure("Green.TLabel", background=C["bg"], foreground=C["green"],
                         font=("Consolas", 10, "bold"))

        style.configure("TButton", background=C["bg3"], foreground=C["fg"],
                         bordercolor=C["border_hi"], padding=(12, 6),
                         font=("Consolas", 10, "bold"))
        style.map("TButton",
                   background=[("active", C["border_hi"]), ("disabled", C["bg2"])],
                   foreground=[("disabled", C["fg_dim"])])

        style.configure("Scan.TButton", background=C["bg3"], foreground=C["accent"],
                         bordercolor=C["accent2"], padding=(16, 8),
                         font=("Consolas", 11, "bold"))
        style.configure("Stop.TButton", background=C["bg3"], foreground=C["red"],
                         bordercolor="#882233", padding=(16, 8),
                         font=("Consolas", 11, "bold"))
        style.configure("Export.TButton", background=C["bg3"], foreground=C["blue"],
                         bordercolor=C["blue_dim"], padding=(12, 6),
                         font=("Consolas", 10, "bold"))

        style.configure("TCheckbutton", background=C["bg"], foreground=C["fg"], font=("Consolas", 10))
        style.map("TCheckbutton", background=[("active", C["bg"])], foreground=[("active", C["accent"])])

        style.configure("TRadiobutton", background=C["bg"], foreground=C["fg"], font=("Consolas", 10))
        style.map("TRadiobutton", background=[("active", C["bg"])], foreground=[("active", C["accent"])])

        style.configure("TEntry", fieldbackground=C["bg2"], foreground=C["fg"],
                         bordercolor=C["border"], insertcolor=C["accent"], font=("Consolas", 10))

        style.configure("Horizontal.TProgressbar",
                         background=C["accent"], troughcolor=C["bg2"],
                         bordercolor=C["border"])

        style.configure("Treeview", background=C["bg2"], foreground=C["fg"],
                         fieldbackground=C["bg2"], bordercolor=C["border"],
                         rowheight=28, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=C["bg3"], foreground=C["fg_dim"],
                         bordercolor=C["border"], font=("Consolas", 9, "bold"))
        style.map("Treeview",
                   background=[("selected", "#1a2a35")],
                   foreground=[("selected", C["accent"])])

        style.configure("TLabelframe", background=C["bg"], foreground=C["fg_dim"],
                         bordercolor=C["border"], font=("Consolas", 9, "bold"))
        style.configure("TLabelframe.Label", background=C["bg"], foreground=C["fg_dim"],
                         font=("Consolas", 9, "bold"))

    # ── Build UI ──

    def _build_ui(self):
        # HEADER
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=16, pady=(12, 0))
        ttk.Label(header, text="⦿ SCAM SNIFFER v2", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Singapore Threat Intelligence Scanner",
                  style="Dim.TLabel").pack(side="left", padx=(12, 0), pady=(4, 0))
        self.status_label = ttk.Label(header, text="● STANDBY", style="Status.TLabel")
        self.status_label.pack(side="right")

        tk.Frame(self.root, height=1, bg=C["border"]).pack(fill="x", padx=16, pady=(10, 0))

        # BODY
        body = tk.PanedWindow(self.root, orient="horizontal", bg=C["bg"],
                               sashwidth=4, sashrelief="flat", bd=0)
        body.pack(fill="both", expand=True, padx=16, pady=10)

        # ── LEFT PANEL ──
        left = ttk.Frame(body)
        body.add(left, width=280, minsize=240)

        # Scan mode
        mode_frame = ttk.LabelFrame(left, text=" SCAN MODE ", padding=8)
        mode_frame.pack(fill="x", pady=(0, 10))

        ttk.Radiobutton(mode_frame, text="🌐 Free (Google News + DDG)",
                         variable=self.scan_mode, value="free",
                         command=self._on_mode_change).pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="🤖 AI Enhanced (Claude API)",
                         variable=self.scan_mode, value="ai",
                         command=self._on_mode_change).pack(anchor="w", pady=(2, 0))

        # API key (for AI mode)
        self.api_frame = ttk.LabelFrame(left, text=" ANTHROPIC API KEY ", padding=8)
        self.api_frame.pack(fill="x", pady=(0, 10))
        key_row = ttk.Frame(self.api_frame)
        key_row.pack(fill="x")
        self.key_entry = ttk.Entry(key_row, textvariable=self.api_key, show="•", width=24)
        self.key_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(key_row, text="👁", width=3,
                   command=self._toggle_key).pack(side="right", padx=(4, 0))

        if not ANTHROPIC_AVAILABLE:
            ttk.Label(self.api_frame, text="⚠ 'anthropic' package not installed",
                      style="Dim.TLabel", foreground=C["orange"]).pack(anchor="w", pady=(4, 0))

        # Categories
        ttk.Label(left, text="SCAN CATEGORIES", style="Section.TLabel").pack(anchor="w", pady=(0, 4))
        for cat, keywords in KEYWORD_PRESETS.items():
            var = tk.BooleanVar(value=True)
            self.cat_vars[cat] = var
            ttk.Checkbutton(left, text=f"{cat}  ({len(keywords)})",
                             variable=var, command=self._update_kw_count).pack(anchor="w", pady=1)

        # Custom keywords
        ttk.Label(left, text="\nCUSTOM KEYWORDS", style="Section.TLabel").pack(anchor="w", pady=(0, 4))
        kw_row = ttk.Frame(left)
        kw_row.pack(fill="x", pady=(0, 4))
        self.custom_entry = ttk.Entry(kw_row, width=22)
        self.custom_entry.pack(side="left", fill="x", expand=True)
        self.custom_entry.bind("<Return>", lambda e: self._add_custom())
        ttk.Button(kw_row, text="+", width=3, command=self._add_custom).pack(side="right", padx=(4, 0))

        self.custom_listbox = tk.Listbox(left, height=4, bg=C["bg2"], fg=C["fg"],
                                          selectbackground=C["border_hi"], selectforeground=C["accent"],
                                          borderwidth=1, relief="solid", highlightthickness=0,
                                          font=("Consolas", 9))
        self.custom_listbox.pack(fill="x", pady=(0, 4))
        ttk.Button(left, text="Remove Selected", command=self._remove_custom).pack(anchor="w", pady=(0, 6))

        self.kw_count_label = ttk.Label(left, text="", style="Dim.TLabel")
        self.kw_count_label.pack(pady=(4, 6))

        tk.Frame(left, height=1, bg=C["border"]).pack(fill="x", pady=4)

        # Buttons
        self.scan_btn = ttk.Button(left, text="▶  INITIATE SCAN", style="Scan.TButton",
                                    command=self._start_scan)
        self.scan_btn.pack(fill="x", pady=(8, 4))
        self.stop_btn = ttk.Button(left, text="■  ABORT", style="Stop.TButton",
                                    command=self._stop_scan, state="disabled")
        self.stop_btn.pack(fill="x", pady=(0, 4))
        self.export_btn = ttk.Button(left, text="⬇  EXPORT CSV", style="Export.TButton",
                                      command=self._export_csv, state="disabled")
        self.export_btn.pack(fill="x", pady=(0, 4))
        self.clear_btn = ttk.Button(left, text="✕  CLEAR ALL",
                                     command=self._clear, state="disabled")
        self.clear_btn.pack(fill="x")

        # ── RIGHT PANEL ──
        right = ttk.Frame(body)
        body.add(right, minsize=500)

        # Progress
        self.prog_frame = ttk.Frame(right)
        self.prog_label = ttk.Label(self.prog_frame, text="", style="Dim.TLabel")
        self.prog_label.pack(anchor="w")
        self.prog_bar = ttk.Progressbar(self.prog_frame, mode="determinate")
        self.prog_bar.pack(fill="x", pady=(4, 0))

        # Summary
        self.summary_label = ttk.Label(right, text="", style="Dim.TLabel")
        self.summary_label.pack(anchor="w", pady=(0, 4))

        # Results table
        tree_frame = ttk.Frame(right)
        tree_frame.pack(fill="both", expand=True)

        cols = ("threat", "title", "source", "date", "keyword", "snippet", "url")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        for col, w in zip(cols, [70, 220, 110, 90, 130, 300, 180]):
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=w, minwidth=60)

        sy = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        sx = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.tag_configure("high", foreground=C["red"])
        self.tree.tag_configure("medium", foreground=C["orange"])
        self.tree.tag_configure("low", foreground=C["green"])
        self.tree.bind("<Double-1>", self._open_url)

        # LOG CONSOLE
        ttk.Label(right, text="SCAN LOG", style="Section.TLabel").pack(anchor="w", pady=(8, 2))
        log_frame = ttk.Frame(right)
        log_frame.pack(fill="x")

        self.log_text = tk.Text(log_frame, height=8, bg="#080a0f", fg=C["fg_dim"],
                                 insertbackground=C["accent"], borderwidth=1, relief="solid",
                                 highlightthickness=0, font=("Consolas", 9), wrap="word",
                                 state="disabled")
        log_sb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_sb.pack(side="right", fill="y")

        # Tag colors for log
        self.log_text.tag_configure("info", foreground=C["fg_dim"])
        self.log_text.tag_configure("success", foreground=C["green"])
        self.log_text.tag_configure("warn", foreground=C["orange"])
        self.log_text.tag_configure("error", foreground=C["red"])
        self.log_text.tag_configure("accent", foreground=C["accent"])

    # ── Log ──

    def log(self, msg, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{ts}] {msg}\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def log_safe(self, msg, tag="info"):
        """Thread-safe log."""
        self.root.after(0, self.log, msg, tag)

    # ── Helpers ──

    def _toggle_key(self):
        show = "" if self.key_entry.cget("show") == "•" else "•"
        self.key_entry.configure(show=show)

    def _on_mode_change(self):
        if self.scan_mode.get() == "ai":
            self.api_frame.pack(fill="x", pady=(0, 10), after=self.api_frame.master.winfo_children()[0])
        # Always show API frame but visually indicate if not needed
        pass

    def _update_kw_count(self):
        count = len(self._get_keywords())
        self.kw_count_label.configure(text=f"{count} keywords queued")

    def _get_keywords(self):
        kws = []
        for cat, var in self.cat_vars.items():
            if var.get():
                kws.extend(KEYWORD_PRESETS[cat])
        kws.extend(self.custom_keywords)
        return kws

    def _add_custom(self):
        kw = self.custom_entry.get().strip()
        if kw and kw not in self.custom_keywords:
            self.custom_keywords.append(kw)
            self.custom_listbox.insert(tk.END, kw)
            self.custom_entry.delete(0, tk.END)
            self._update_kw_count()
            self._save()

    def _remove_custom(self):
        sel = self.custom_listbox.curselection()
        if sel:
            self.custom_keywords.pop(sel[0])
            self.custom_listbox.delete(sel[0])
            self._update_kw_count()
            self._save()

    def _save(self):
        save_config({
            "api_key": self.api_key.get(),
            "custom_keywords": self.custom_keywords,
            "categories": [c for c, v in self.cat_vars.items() if v.get()],
            "scan_mode": self.scan_mode.get(),
        })

    def _open_url(self, event):
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0], "values")
            url = vals[6] if len(vals) > 6 else ""
            if url.startswith("http"):
                import webbrowser
                webbrowser.open(url)

    # ── Scan ──

    def _scan_thread(self):
        keywords = self._get_keywords()
        total = len(keywords)
        mode = self.scan_mode.get()
        client = None

        if mode == "ai":
            if not ANTHROPIC_AVAILABLE:
                self.log_safe("ERROR: 'anthropic' package not installed!", "error")
                self.log_safe("Run: pip install anthropic", "warn")
                self.root.after(0, self._scan_done)
                return

            key = self.api_key.get().strip()
            if not key:
                self.log_safe("ERROR: No API key entered!", "error")
                self.root.after(0, self._scan_done)
                return

            client = anthropic.Anthropic(api_key=key)
            self.log_safe("Initialized Anthropic client", "accent")

        for i, kw in enumerate(keywords):
            if self.abort_flag:
                self.log_safe("Scan aborted by user.", "warn")
                break

            self.root.after(0, self._update_progress, kw, i + 1, total)
            self.log_safe(f"Scanning [{i+1}/{total}]: \"{kw}\"", "accent")

            kw_results = []

            if mode == "free":
                # Try Google News first
                kw_results = scan_google_news_rss(kw, log_fn=self.log_safe)
                # Supplement with DuckDuckGo if few results
                if len(kw_results) < 3:
                    self.log_safe("  → Supplementing with DuckDuckGo...", "info")
                    ddg = scan_duckduckgo(kw, log_fn=self.log_safe)
                    # Deduplicate by URL
                    existing_urls = {r["url"] for r in kw_results}
                    for r in ddg:
                        if r["url"] not in existing_urls:
                            kw_results.append(r)
            else:
                try:
                    kw_results = scan_anthropic_ai(kw, client, log_fn=self.log_safe)
                except anthropic.AuthenticationError:
                    self.log_safe("FATAL: Invalid API key. Stopping scan.", "error")
                    break

            if kw_results:
                self.results.extend(kw_results)
                self.root.after(0, self._add_to_tree, kw_results)
                self.log_safe(f"  → Added {len(kw_results)} results (total: {len(self.results)})", "success")
            else:
                self.log_safe(f"  → No results for this keyword", "warn")

        self.root.after(0, self._scan_done)

    def _start_scan(self):
        keywords = self._get_keywords()
        if not keywords:
            messagebox.showwarning("No Keywords", "Select at least one category or add a custom keyword.")
            return

        self._save()
        self.results = []
        self.abort_flag = False
        self.scanning = True
        self.tree.delete(*self.tree.get_children())

        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.export_btn.configure(state="disabled")
        self.clear_btn.configure(state="disabled")
        self.status_label.configure(text="● SCANNING", foreground=C["orange"])
        self.prog_frame.pack(fill="x", pady=(0, 6), before=self.summary_label)
        self.prog_bar["value"] = 0

        mode_name = "FREE (Google News + DuckDuckGo)" if self.scan_mode.get() == "free" else "AI (Claude API + Web Search)"
        self.log(f"═══ SCAN STARTED — Mode: {mode_name} ═══", "accent")
        self.log(f"Keywords to scan: {len(keywords)}", "info")

        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _stop_scan(self):
        self.abort_flag = True
        self.status_label.configure(text="● ABORTING...", foreground=C["red"])

    def _update_progress(self, kw, current, total):
        self.prog_label.configure(text=f"[{current}/{total}] {kw}")
        self.prog_bar["maximum"] = total
        self.prog_bar["value"] = current

    def _add_to_tree(self, new_results):
        for r in new_results:
            threat = r.get("threat_level", "Low")
            self.tree.insert("", "end", values=(
                f"  {threat}",
                r.get("title", "")[:80],
                r.get("source", ""),
                r.get("date", ""),
                r.get("keyword", ""),
                r.get("snippet", "")[:120],
                r.get("url", ""),
            ), tags=(threat.lower(),))
        self._update_summary()

    def _update_summary(self):
        h = sum(1 for r in self.results if r.get("threat_level") == "High")
        m = sum(1 for r in self.results if r.get("threat_level") == "Medium")
        lo = sum(1 for r in self.results if r.get("threat_level") == "Low")
        self.summary_label.configure(
            text=f"RESULTS: {len(self.results)} total  |  ● {h} High  ● {m} Medium  ● {lo} Low"
        )

    def _scan_done(self):
        self.scanning = False
        self.prog_frame.pack_forget()
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

        if self.results:
            self.export_btn.configure(state="normal")
            self.clear_btn.configure(state="normal")
            self.status_label.configure(text=f"● DONE — {len(self.results)} results", foreground=C["accent"])
            self.log(f"═══ SCAN COMPLETE — {len(self.results)} results collected ═══", "success")
        else:
            self.status_label.configure(text="● DONE — No results", foreground=C["orange"])
            self.log("═══ SCAN COMPLETE — No results found ═══", "warn")
            self.log("TIP: Check the log above for errors. Try Free mode if AI mode fails.", "info")

        self._update_summary()

    def _clear(self):
        self.results = []
        self.tree.delete(*self.tree.get_children())
        self.summary_label.configure(text="")
        self.export_btn.configure(state="disabled")
        self.clear_btn.configure(state="disabled")
        self.status_label.configure(text="● STANDBY", foreground=C["fg_dim"])

    # ── Export ──

    def _export_csv(self):
        if not self.results:
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All", "*.*")],
            initialfile=f"scam_sniffer_sg_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            title="Export Results"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fieldnames=[
                    "title", "source", "url", "snippet", "date",
                    "threat_level", "keyword", "scanned_at"
                ])
                w.writeheader()
                w.writerows(self.results)

            self.log(f"Exported {len(self.results)} results → {path}", "success")
            messagebox.showinfo("Export OK", f"Saved {len(self.results)} results to:\n{path}")
        except Exception as e:
            self.log(f"Export failed: {e}", "error")
            messagebox.showerror("Export Error", str(e))


# ═══════════════════════════════════════════════════════════════

def main():
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

    ScamSnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
