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