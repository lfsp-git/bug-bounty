# 🛡️ HUNT3R v1.0-EXCALIBUR: Autonomous Bug Bounty Hunter

## 🎯 Mission
Hunt3r is an autonomous reconnaissance and vulnerability scanner for bug bounty hunters. It automates the full pipeline — from target discovery to **submission-ready reports** — via Telegram/Discord notifications.

## 🔄 Pipeline (Predator Cycle)
1. **WATCHDOG**: Collects wildcards from HackerOne, BugCrowd, Intigriti every 4-6h (12h cache)
2. **DIFF ENGINE**: Compares with baselines, processes only new/modified targets
3. **RECON PHASE**:
   - Subfinder (subdomain enumeration)
   - DNSX (live subdomain resolution)
   - Uncover (takeover candidate detection)
   - HTTPX (endpoint discovery — output used as input for Katana/Nuclei)
4. **JS HUNTER**: Real extraction of secrets from JavaScript assets
5. **TACTICAL PHASE**:
   - Katana crawler (`-timeout 15 -depth 2`)
   - Nuclei (`-severity critical,high,medium -tags cve,misconfig,takeover -c 25 -timeout 5 -duc`)
6. **VALIDATION**: FalsePositiveKiller (6 filters) + AI confirmation (score ≥ 80)
7. **NOTIFICATION**: Telegram (Critical/High/Medium) · Discord (Low/Info)
8. **REPORT**: Markdown bug bounty report ready for H1/BC/IT submission

## 🚀 Quick Start
```bash
pip install -r requirements.txt
cp .env.example .env  # Fill in API keys and Telegram/Discord tokens

python3 main.py              # Interactive menu
python3 main.py --watchdog   # 24/7 autonomous mode
python3 main.py --dry-run    # Preview targets, no tools executed
python3 main.py --export csv # Export findings (csv|xlsx|xml)
python3 main.py --resume <id> # Resume interrupted scan
```

## ⚙️ Environment (.env)
```
H1_TOKEN=your_hackerone_token
H1_USER=your_hackerone_username
BC_TOKEN=your_bugcrowd_token
IT_TOKEN=your_intigriti_token
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
DISCORD_WEBHOOK=your_discord_webhook_url
OPENROUTER_API_KEY=your_openrouter_key  # optional, for AI validation
SHODAN_API_KEY=your_shodan_key          # optional, for Uncover
```

## 📊 Live View (Terminal UI)
Real-time htop-style view frozen at the bottom of the terminal:
- Tool status: 🟢 running / 🟡 idle
- Progress bars colored by elapsed/ETA ratio (green → yellow → red)
- Rolling counters: subdomains, live hosts, endpoints, vulns
- Mission elapsed time

## 🗂️ Architecture
```
main.py                     ← CLI entry point (~283 lines)
core/
  scanner.py                ← MissionRunner + ProOrchestrator
  ui.py                     ← Terminal UI, scroll region, _stdout_lock, snapshots
  config.py                 ← Constants, timeouts, rate limiter, validators
  filter.py                 ← FalsePositiveKiller (6 filters)
  watchdog.py               ← 24/7 autonomous scan loop
  updater.py                ← PDTM + nuclei-templates auto-update
  ai.py                     ← AIClient (OpenRouter)
  storage.py                ← ReconDiff + CheckpointManager
  notifier.py               ← NotificationDispatcher (Telegram/Discord)
  reporter.py               ← BugBountyReporter (Markdown reports)
  export.py                 ← CSV/XLSX/XML export + dry-run
recon/
  engines.py                ← Tool wrappers; stderr captured for debug visibility
  js_hunter.py              ← JSHunter (real JS secret extraction)
  platforms.py              ← H1/BC/IT API clients
  tool_discovery.py         ← find_tool() with cache (~/.pdtm/go/bin + ~/go/bin + PATH)
reports/                    ← Generated bug bounty reports (Markdown)
recon/baselines/            ← Scan baselines and findings (JSONL)
logs/
  hunt3r.log                ← Persistent scan log
  snapshots/                ← Auto-captured terminal snapshots on errors/SIGINT
```

## 📤 Output
After each scan:
- `recon/baselines/<handle>_findings.jsonl` — raw Nuclei findings (filtered)
- `reports/<handle>_<date>_report.md` — submission-ready Markdown report
- Telegram: Critical/High/Medium alerts (per finding)
- Discord: Low/Info batch logs

## 🔧 Key Configuration (`core/config.py`)
```python
TOOL_TIMEOUTS = {
    "subfinder": 60, "dnsx": 60, "httpx": 120,
    "katana": 120, "nuclei": 300,   # increase for large targets
}
RATE_LIMIT = 50          # requests/s for tools
MAX_SUBS_PER_TARGET = 2000
```

## 🧪 Tests
```bash
python3 -m pytest tests/ -q   # 52 tests, 52 PASS (36 unit + 16 integration)
```

## 📝 Changelog
See `docs/CHANGELOG.md`

## 🙏 Credits
- [ProjectDiscovery](https://projectdiscovery.io) — subfinder, dnsx, httpx, katana, nuclei, uncover
- Telegram Bot API / Discord Webhooks
- OpenRouter AI API

## 📄 License
MIT

## 🎯 Mission
Hunt3r is an autonomous reconnaissance and vulnerability scanner for bug bounty hunters. It automates the full pipeline — from target discovery to **submission-ready reports** — via Telegram/Discord notifications.

## 🔄 Pipeline (Predator Cycle)
1. **WATCHDOG**: Collects wildcards from HackerOne, BugCrowd, Intigriti every 4-6h (12h cache)
2. **DIFF ENGINE**: Compares with baselines, processes only new/modified targets
3. **RECON PHASE**:
   - Subfinder (subdomain enumeration)
   - DNSX (live subdomain resolution)
   - Uncover (takeover candidate detection)
   - HTTPX (endpoint discovery)
4. **JS HUNTER**: Passive extraction of secrets from JavaScript assets
5. **TACTICAL PHASE**:
   - Katana crawler (intelligent crawling)
   - Nuclei (CVE, misconfig, takeover tags)
6. **VALIDATION**: FalsePositiveKiller + AI confirmation (score ≥ 80)
7. **NOTIFICATION**: Telegram (Critical/High/Medium) · Discord (Low/Info)
8. **REPORT**: Markdown bug bounty report ready for H1/BC/IT submission

## 🚀 Quick Start
```bash
# Install
pip install -r requirements.txt
cp .env.example .env  # Fill in API keys and Telegram/Discord tokens

# Watchdog mode (24/7 autonomous)
python3 main.py --watchdog

# Interactive menu
python3 main.py

# Dry-run (preview targets, no tools executed)
python3 main.py --dry-run

# Export findings
python3 main.py --export csv    # or xlsx, xml

# Resume interrupted scan
python3 main.py --resume <mission_id>
```

## ⚙️ Environment (.env)
```
H1_TOKEN=your_hackerone_token
H1_USER=your_hackerone_username
BC_TOKEN=your_bugcrowd_token
IT_TOKEN=your_intigriti_token
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
DISCORD_WEBHOOK=your_discord_webhook_url
OPENROUTER_API_KEY=your_openrouter_key  # optional, for AI validation
```

## 📊 Live View
Real-time terminal UI showing:
- Active tool status (Subfinder, DNSX, Uncover, HTTPX, JS Hunter, Katana, Nuclei)
- Statistics (subdomains, endpoints, vulnerabilities)
- Progress by phase

## 🗂️ Architecture
```
main.py                     ← CLI entry point
core/
  orchestrator.py           ← MissionRunner + ProOrchestrator
  watchdog.py               ← 24/7 continuous scan loop
  notifier.py               ← Telegram + Discord notifications
  reporter.py               ← Bug bounty Markdown report generator  ← NEW
  ai_client.py              ← AI validation (OpenRouter)
  diff_engine.py            ← Baseline comparison
  fp_filter.py              ← FalsePositiveKiller
  rate_limiter.py           ← Per-target throttling
  checkpoint.py             ← Scan resumption
  exporter.py               ← CSV/XLSX/XML export
  dry_run.py                ← Dry-run preview mode
recon/
  engines.py                ← Tool wrappers (subfinder/dnsx/httpx/katana/nuclei)
  js_hunter.py              ← JS secret extractor
  platforms.py              ← H1/BC/IT API clients
  tool_discovery.py         ← Dynamic binary path resolution
config/
  tools_config.yaml         ← Tool parameters
  platforms_config.yaml     ← Platform API config
reports/                    ← Generated bug bounty reports (Markdown)
recon/baselines/            ← Scan baselines and findings
```

## 📤 Output
After each scan:
- `recon/baselines/<handle>_findings.jsonl` — raw Nuclei findings
- `reports/<handle>_<date>_report.md` — submission-ready Markdown report
- Telegram: Critical/High/Medium alerts
- Discord: Low/Info batch logs

## 🔧 Configuration
- `config/tools_config.yaml` — tool paths and timeouts
- `config/platforms_config.yaml` — H1/BC/IT API endpoints
- `.env` — credentials and webhook URLs

## 📝 Changelog
See `docs/CHANGELOG.md`

## 🙏 Credits
- [ProjectDiscovery](https://projectdiscovery.io) — subfinder, dnsx, httpx, katana, nuclei, uncover
- Telegram Bot API / Discord Webhooks
- OpenRouter AI API

## 📄 License
MIT
.