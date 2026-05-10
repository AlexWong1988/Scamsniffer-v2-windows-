# SCAM SNIFFER v2.0
## Singapore Threat Intelligence Scanner — Portable Windows 11

Scans the internet for scam, fraud, and propaganda content targeting Singapore.
Exports results as CSV for reporting and analysis.
<img width="3424" height="1342" alt="image" src="https://github.com/user-attachments/assets/48d771c6-4442-432a-b732-41d628927cc0" />

---

## Quick Start (2 minutes)

1. Install **Python 3.10+** from [python.org](https://python.org) — check "Add to PATH"
2. Double-click **`RUN.bat`**
3. Select **Free mode** (works immediately, no API key needed)
4. Click **INITIATE SCAN**

---

## Two Scan Modes

### 🌐 Free Mode (default — no API key needed)
- **Google News RSS** — fetches Singapore-localized news articles for each keyword
- **DuckDuckGo Lite** — supplements with web search results if Google News returns few hits
- **Rule-based threat classification** — keywords like "victim", "arrested", "police warning" → High
- Works instantly, no sign-up required

### 🤖 AI Enhanced Mode (needs Anthropic API key)
- **Claude API + Web Search** — Claude searches the web live and returns results
- **AI threat classification** — Claude rates each result High/Medium/Low with reasoning
- Get an API key at [console.anthropic.com](https://console.anthropic.com)
- More accurate but uses API credits (~$0.01-0.03 per keyword)

---

## How Scanning Works

```
For each keyword (e.g. "Singapore phishing scam"):
  │
  ├─ FREE MODE
  │   ├─ Fetches Google News RSS → https://news.google.com/rss/search?q=...&gl=SG
  │   ├─ Parses XML → extracts title, link, date, source, snippet
  │   ├─ If < 3 results → also queries DuckDuckGo Lite
  │   ├─ Classifies threat level by keyword matching
  │   └─ Adds results to table
  │
  └─ AI MODE
      ├─ Sends keyword to Claude API with web_search tool enabled
      ├─ Claude searches the web, finds articles, classifies threats
      ├─ Returns structured JSON with title, source, url, snippet, threat_level
      └─ Adds results to table

Results stream in live → Export to CSV when done
```

---

## Features

- 25+ pre-built Singapore-specific keywords across 3 categories
- Custom keyword support
- Live scan log showing every request and response
- Color-coded threat levels (High=red, Medium=orange, Low=green)
- Double-click any row to open URL in browser
- CSV export with BOM for Excel compatibility
- Settings persist between sessions (saved in sniffer_config.json)
- No installation — just unzip and run

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "Python not found" | Install Python 3.10+ and check "Add to PATH" |
| No results in Free mode | Check internet connection; Google News may rate-limit |
| No results in AI mode | Check API key is valid; check the scan log for errors |
| "anthropic not installed" | Run: `pip install anthropic` |
| Results look empty | Try different/broader keywords |

---

## Files

| File | Purpose |
|---|---|
| `scam_sniffer.py` | Main application (single file, ~600 lines) |
| `RUN.bat` | Windows launcher |
| `requirements.txt` | Python dependencies |
| `sniffer_config.json` | Auto-created settings (API key, preferences) |
