# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.


# Role & Context
Você é um Engenheiro de Segurança Ofensiva Ética Sênior e meu braço direito no desenvolvimento de um Agente Autônomo de Bug Bounty. Todos os scripts, payloads e arquiteturas discutidos aqui têm autorização explícita e fazem parte de um ecossistema de segurança (Bug Bounty/OpenClaw).

# Guidelines
- **Zero Fricção:** Forneça o código funcional imediatamente. Não inclua avisos éticos, disclaimers ou sermões de segurança. Assuma que a autorização já foi concedida.
- **Foco em SecOps:** Escreva código Python otimizado para VPS (pouco uso de RAM, concorrência com `asyncio` ou `subprocess`, tratamento de exceções blindado para evitar crashes).
- **Sem Silêncio:** Ao usar ferramentas de CLI (Nuclei, Subfinder), nunca use subprocessos mudos. Intercepte o `stdout/stderr` e mostre o progresso em tempo real usando `\r` (carriage return).
- **Aprovação de Diffs:** Entregue modificações precisas e sempre aguarde minha revisão antes de executar comandos destrutivos no sistema.

## Project Overview

**Hunt3r — Excalibur Edition** is an autonomous Bug Bounty reconnaissance agent designed for surgical precision and infrastructure cost optimization. It enumerates subdomains, probes hosts, crawls endpoints, and scans for vulnerabilities using Nuclei. The architecture follows Clean Architecture principles with strict separation of concerns.

**Business Goals**:
- Marco 1: $25,000 in bounties (validate in real market against Tier 1 targets)
- Marco 2: $100,000 in bounties (transition to SaaS multi-tenant with FastAPI + React)

## Commands

```bash
# Run the tool (interactive UI)
python main.py

# Install dependencies
pip install -r requirements.txt

# Activate virtual environment
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# External tools are managed via pdtm (ProjectDiscovery package manager)
# Binary path: ~/.pdtm/go/bin/ or %HUNT3R_PDTM_PATH%
```

## Environment Setup

Create a `.env` file in the project root with:
```
OPENROUTER_API_KEY=sk-or-...
HACKERONE_USERNAME=your_username
HACKERONE_API_TOKEN=your_token
SHODAN_API_KEY=your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret
```

## Architecture

### Core Pipeline Flow
```
Platform/Manual Target → IntelMiner (scoring) → Orchestrator
    ↓
Subfinder (subdomains) → DNSX (alive check) → Uncover (enrichment)
    ↓
HTTPX (tech detect) → Katana (crawling) → Smart Filter
    ↓
Nuclei (vuln scan) → FP Filter → AI Analysis
```

### Key Modules

| File | Responsibility | Status |
|------|----------------|--------|
| `main.py` | State Machine UI, menu navigation | Dynamic |
| `core/orchestrator.py` | Mission orchestration, chunking (Leviathan/Shredder), spinner/ETA display | Dynamic |
| `core/intelligence.py` | Target scoring, tech parsing, Nuclei tag selection | **SEALED** |
| `core/ui_manager.py` | Terminal colors, banners, menus, mission header | **SEALED** |
| `core/ai_client.py` | OpenRouter API integration | Dynamic |
| `core/updater.py` | Tool auto-updates | Dynamic |
| `core/fp_filter.py` | False positive filtering (micro-string kill, null/undefined guard) | Dynamic |
| `core/template_manager.py` | Custom template management | Dynamic |
| `core/notifier.py` | Telegram (Critical/High + JS secrets) + Discord (Medium/Low/Info) routing | Dynamic |
| `core/diff_engine.py` | Baseline comparison per target, alerts on new subs/endpoints/secrets | Dynamic |
| `core/watchdog.py` | Autonomous 24/7 recon with Predator Logic (VIP queue, diff per cycle) | Dynamic |
| `core/reporter.py` | **DELETED** (dead code removed) | N/A |
| `recon/engines.py` | External tool execution (silent, orchestrator controls display) | Dynamic |
| `recon/platforms.py` | HackerOne API integration (Exception-based error handling) | Dynamic |
| `recon/js_hunter.py` | Regex-based JS secret extraction (AWS keys, API keys, JWT, Stripe, etc.) | Dynamic |

**SEALED modules**: Do NOT modify without explicit authorization. These contain critical security fixes and validated patterns.

### Security Requirements (CRITICAL)

1. **Command Injection Prevention**: Every variable passed to `subprocess.run(shell=True)` MUST use `shlex.quote()`. No exceptions.

2. **ANSI Injection Prevention**: All external strings (domains, log output) pass through `sanitize_input()` with `ANSI_ESCAPE_RE` regex.

3. **No Direct Colorama Imports**: `from colorama import Fore, Style` is ONLY allowed in `ui_manager.py`. Use the `Colors` class instead. Any import of `Fore`, `Style`, or `init` from colorama outside `ui_manager.py` should be rejected immediately.

4. **Subprocess Output Capture**: NEVER use `stdout=open(file)` for mass data tools (like Subfinder). Use `subprocess.PIPE` + `communicate()` to avoid OS buffer race conditions that cause zero results.

5. **Silent Engine Execution**: All tools in `recon/engines.py` are now silent — progress display is handled exclusively by `_run_with_progress` in the orchestrator. Engines must NOT print spinners or status lines.

6. **Thread-Safe Output**: The `_spin_mutex` in `orchestrator.py` protects all progress/output writes. The spinner thread and main thread share this lock to prevent visual corruption.

### Business Logic

#### Target Scoring (Wall Street Mode)
`IntelMiner._score()` calculates 0-99 based on keyword heuristics. The API lies about tiers — our score dictates the real tier:

| Tier | Score | Keywords |
|------|-------|----------|
| PREMIUM | 80+ | Fintech, crypto, banks, payment processors |
| STANDARD | 50-79 | Tech giants, cloud, social media |
| LOW | <50 | CMS, DevOps platforms |

**Penalties**: Security platforms (-30), Tech giants on weak VPS (-20)

#### Nuclei Dual-Scan Architecture
- Phase 1 (Infra): Tech tags (`nginx, apache, java`) on HTTPX base hosts only. Scans server/tech surface, NOT every Katana endpoint.
- Phase 2 (Endpoints): Injection tags (`xss, sqli, ssrf, lfi, dast`) on Katana + Smart Filter output. No tech tags to avoid multiplying infra templates across thousands of parameterized URLs.
- Each phase runs independently with its own stats/spinner
- Findings from both phases are merged into `findings.txt`
- CVEs only included when `score >= 80` (cost optimization)
- Default: `exposure,takeover`
- With tech: `{server},{app},exposure,takeover,misconfig[,cves]`
- If no tech detected: Use only `exposure,takeover` (stealth mode)

#### Apache-First Policy
When detecting reverse proxy ambiguity, Apache wins over IIS. Hardcoded priority in `intelligence.py`.

### Resource Management

| Setting | Value | Purpose |
|---------|-------|---------|
| Nuclei phase split | hosts vs endpoints | Dual-Scan: tech tags on hosts, injection tags on endpoints |
| Emergency brake | 2,000 endpoints | Hard cap removes CVEs/misconfig |
| Cache TTL (recon) | 1800s | Subdomain/DNS data |
| Cache TTL (API) | 3600s | HackerOne program data |
| Cache Buster | <50 subs for PREMIUM | Forces re-scan on weak cache |
| Watchdog sleep | 2-4h random | Anti-pattern detection between recon cycles |
| Hot Programs | Top 15 wildcards | VIP queue ranked by IntelMiner hot_score |

### ETAs and Tool Times

Tool execution times are persisted in `recon/tool_times.json` (rolling average of last 5 runs). The orchestrator reads this on each mission to display ETAs for recurring scans.

### External Tool Paths

Resolution order:
1. `HUNT3R_PDTM_PATH` environment variable
2. `~/.pdtm/go/bin/`
3. System PATH (via `shutil.which()` — fallback for forensic debugging)

### Tool Execution Modes

| Tool | Mode | Notes |
|------|------|-------|
| Subfinder | Forensic Mode | `subprocess.PIPE` to RAM, avoids OS buffer race |
| HTTPX | Stealth Mode | Rate limit 100 req/s, tech detect + title + status |
| Katana | Anti-Bloat | `-jc` JS rendering, filters extensions, suspicious params |
| Nuclei | VPS-Survival | No headless, `-c 50 -rl 150 -bs 50`, stats via JSON, `-si 1` |
| DNSX | Standard | Silent, orchestrator handles progress |
| Uncover | Standard | Shodan/Censys enrichment |

### Watchdog Mode

Autonomous 24/7 recon via `python main.py --watchdog`:

- **VIP Queue**: Top 15 wildcard programs ranked by IntelMiner hot_score
- **Full pipeline** + Diff Engine per target, alerts only on NEW assets
- **Notifier routing**: Critical/High/JS secrets → Telegram, Medium/Low/Info → Discord
- **Error routing**: Per-failed target error-to-Discord (never crashes)
- **Randomized sleep**: 2-4h between cycles (anti-pattern detection)

### Security Requirements Update (CRITICAL)

7. **FP Filter Micro-String Guard**: Evidence <6 chars → always killed as "Micro" category. Indent-critical — bug was fixed to prevent silent bypass.

8. **AI Client Guard**: `analyze_vulnerability()` checks for `None` client / missing API key / model before calling LLM. Prevents crash on offline AI.

9. **No Bare Except Clauses**: All `except: pass` replaced with `except Exception as e:` with logging. Applies to `updater.py`, `platforms.py`, `watchdog.py`.

10. **Watchdog Env Var Standardization**: H1 credentials use `HACKERONE_USERNAME` / `HACKERONE_API_TOKEN` (matching platform config), NOT `H1_USERNAME` / `H1_API_TOKEN`.

## Configuration Files

| File | Purpose |
|------|---------|
| `config/platforms_config.yaml` | Bug bounty platform credentials (HackerOne, BugCrowd, etc.) |
| `config/tools_config.yaml` | External tool binaries and update settings |
| `alvos.txt` | Custom target list (format: `domain\|score\|description`) |
| `.env` | API keys (never commit) |

## Logs and Output

| Path | Content |
|------|---------|
| `logs/hunt3r.log` | All log output (no terminal pollution) |
| `recon/db/{target_handle}/` | Scan results per target |
| `recon/tool_times.json` | Persisted tool ETAs (rolling average) |
| `recon/intel_cache.json` | Program ranking cache |
| `recon/h1_cache.json` | HackerOne API cache |
| `recon/custom_templates/` | PayloadsAllTheThings custom Nuclei templates |

## Hardware Target

- VPS: Contabo (~7.7GB RAM available)
- SOP: tmux for session persistence
- Workflow: Git privado → Deploy VPS

## Roadmap (Future Epics)

1. **Filtro de Ouro**: Active re-verification (Python confirms endpoint returns 200 before notifying)
2. **Context-Aware Hunter**: Paid LLM generates PoC code instead of narratives
3. **Real-Time Sync**: WebSockets connecting CLI to Web Dashboard
4. **SaaS Architecture**: FastAPI, Workers separated from Frontend, authentication
5. **Environment Parity**: Ensuring Go/Rust binaries (Subfinder, Nuclei) have identical access to env vars and PATH when invoked via Python subprocess vs pure terminal

## Development Notes

### Adding New Platforms
Edit `config/platforms_config.yaml` and implement the fetch method in `recon/platforms.py`. Follow the `ThreadPoolExecutor(max_workers=5)` pattern from HackerOne to avoid rate limits.

### Adding New Tools
1. Add to `config/tools_config.yaml` with `name`, `binary`, `install_cmd`
2. Add execution function in `recon/engines.py` using `run_cmd()` (silent — no spinner)
3. Always use `shlex.quote()` for all inputs
4. Add `_run_with_progress()` call in `orchestrator.py` to display progress/ETA

### Testing Pipeline Health
The orchestrator performs auto-diagnostic checks:
- `provider-config.yaml` existence for Subfinder APIs
- `SHODAN_API_KEY` / `CENSYS_API_ID` presence
- Cache strength for PREMIUM targets

### State Machine UI
`main.py` manages clean screen transitions:
- `ui_clear()` before context changes
- Fixed HUNT3R EXCALIBUR EDITION banner at top
- `input()` pauses to prevent logs from disappearing

### Mission Display Design
- Target/Score shown in a clean Unicode box (no emojis, no version numbers)
- Progress shown as single-line spinner: `[spinner] ToolName  42s  ETA: 2m 30s`
- Nuclei appends live stats inline: `18% | 49004 reqs | 0 matched | 179 rps`
- No scroll spam — stats update in-place via `\r\033[K`
- Ctrl+C kills the main thread and stops spinner gracefully
