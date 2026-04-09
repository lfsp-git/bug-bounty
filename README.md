# 🛡️ HUNT3R: Autonomous Bug Bounty Hunter

## 🎯 Mission
Hunt3r is an autonomous reconnaissance and vulnerability scanner designed for bug bounty hunters. It automates the entire process from target discovery to vulnerability reporting via Telegram/Discord.

## 🔄 Pipeline (Predator Cycle)
1. **WATCHDOG**: Collects wildcards from HackerOne, BugCrowd, Intigriti every 4-6h with 12h cache
2. **DIFF ENGINE**: Compares discoveries with baselines, processes only new/modified targets
3. **RECON PHASE**: 
   - Subfinder (subdomain enumeration)
   - DNSX (live subdomain filtering)
   - Uncover (subdomain takeover detection)
   - HTTPX (endpoint discovery)
4. **JS HUNTER**: Passive extraction of secrets from JavaScript assets
5. **TACTICAL PHASE**:
   - Katana crawler (intelligent crawling)
   - Nuclei (vulnerability scanning with premium tags: cve, takeover, misconfig)
6. **VALIDATION**: FalsePositiveKiller confirmation
7. **NOTIFICATION**: Telegram (Critical/High/Medium) / Discord (Info/Low)

## 📦 Features
- **Stealth Mode**: Anti-flood, rate limiting, and respectful scanning
- **Live View UI**: Real-time monitoring of active tools
- **Watchdog Mode**: 24/7 autonomous operation
- **Multi-Platform**: Supports H1, BC, IT APIs
- **AI-Powered**: Smart target prioritization and analysis

## 🚀 Quick Start
```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your API keys and Telegram/Discord webhooks

# Run in watchdog mode
python main.py --watchdog

# Run single target scan
python main.py --target example.com
```

## ⚙️ Configuration
- `config/tools_config.yaml`: Tool parameters and paths
- `config/platforms_config.yaml`: Platform API configurations
- `.env`: Sensitive credentials

## 📊 Live View
Hunt3r features a terminal-based live view showing:
- Active tool status (Subfinder, DNSX, Uncover, HTTPX, JS Hunter, Katana, Nuclei)
- Real-time statistics (subdomains found, endpoints discovered, vulnerabilities identified)
- Progress bars for each phase
- Current target being processed

## 🔧 Architecture
- **core/orchestrator.py**: MissionRunner orchestrates the full pipeline
- **core/notifier.py**: Handles Telegram/Discord notifications
- **core/validation.py**: FalsePositiveKiller validation
- **recon/engines.py**: Tool wrappers and execution
- **core/ui_manager.py**: Live view and terminal UI
- **core/watchdog.py**: Continuous scanning logic

## 📝 Recent Changes
- ✅ Fixed reconnaissance phase (Subfinder + DNSX + Uncover + HTTPX)
- ✅ Added JS Hunter for passive secret extraction
- ✅ Implemented Katana crawler for intelligent endpoint discovery
- ✅ Enhanced UI with live view and progress tracking
- ✅ Improved validation to reduce false positives
- ✅ Added multi-profile scanning (standard/deep)

## 🎯 Future Roadmap
- [ ] Adaptive scanning profiles (stealth vs comprehensive)
- [ ] AI-powered vulnerability prioritization
- [ ] Automated reporting with remediation guidance
- [ ] Integration with additional platforms (YesWeHack, OpenBugBounty)
- [ ] Advanced false positive detection using ML
- [ ] Performance optimization for large scopes

## 🙏 Credits
- Project Discovery tools (subfinder, dnsx, httpx, katana, nuclei)
- Telegram/Discord notification systems
- AI-powered validation and prioritization

## 📄 License
MIT - See LICENSE file for details.