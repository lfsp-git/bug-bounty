# Hunt3r v1.0-EXCALIBUR

Pipeline autônomo de bug bounty com execução terminal-first, watchdog 24/7, port scanning, URLs históricas, filtragem determinística (7 camadas + ML), validação por IA e relatórios operacionais.

## Arquitetura (Slim Core)

| Módulo | Responsabilidade |
|--------|------------------|
| `main.py` | Ponto de entrada CLI e roteamento de modos |
| `core/runner.py` | Orquestração unificada (`MissionRunner`, `ProOrchestrator`) |
| `core/scanner.py` | Pipeline de fases (recon → tática → validação) |
| `core/intel.py` | IA + scoring unificado (`AIClient`, `IntelMiner`, `BountyScorer`) |
| `core/bounty_scorer.py` | Score 0-100 por programa (wildcard/breadth/quality/platform) |
| `core/state.py` | Baseline e checkpoints |
| `core/output.py` | Notificação, relatório e exportação |
| `core/watchdog.py` | Loop adaptativo 1-2h com métricas de ciclo |
| `core/filter.py` | FalsePositiveKiller (7 filtros + ML) |
| `core/cleaner.py` | Workflow `--clean`: purge, update, health check, testes |
| `core/ui.py` | UI tática fullscreen (Rich Live, 9 tools) |
| `core/config.py` | Configuração centralizada, timeouts, rate limits |
| `recon/tools.py` | Descoberta de binários e wrappers de ferramentas |
| `recon/engines.py` | run_subfinder, dnsx, naabu, httpx, katana, urlfinder, nuclei |
| `recon/js_hunter.py` | Extração de segredos em JavaScript (c/ severidade por tipo) |
| `recon/platforms.py` | APIs H1/BC/IT via bbscope + alvos.txt customizados |

## Pipeline

```
WATCHDOG → DIFF
  ├─ [Domínio] Subfinder → DNSX → Uncover ─┐
  └─ [IP/CIDR] Naabu (30 portas) ──────────┤
                                            ↓
                                          HTTPX
                                            ↓
                               Katana (-js-crawl, depth 3)
                                            ↓
                                       URLFinder
                                            ↓
                                     Merge dedup URLs
                                            ↓
                                        JS Hunter
                                            ↓
                                    Nuclei (M/H/C)
                                            ↓
                                  FP Filter (7+ML)
                                            ↓
                               IA (score≥60) → Notificar → Relatório
```

## Início rápido

```bash
cp .env.example .env   # configurar tokens
python3 main.py --clean   # instalar deps + verificar ferramentas + rodar testes
python3 main.py           # Menu interativo
```

### Modos disponíveis

```bash
python3 main.py              # Menu interativo
python3 main.py --watchdog   # Modo autônomo 24/7
python3 main.py --clean      # Purge + update + health check + testes
python3 main.py --dry-run    # Preview sem executar ferramentas
python3 main.py --resume ID  # Retomar missão
python3 main.py --export csv # Exportar findings (csv/xlsx/xml/pdf)
```

### Tipos de alvo suportados

```bash
# Domínio
example.com
*.example.com

# IP único
192.168.1.1

# CIDR (colapsado em handle único)
10.0.0.0/24
```

### Variáveis de ambiente (`.env`)

```bash
# IA
OPENROUTER_API_KEY=...

# Notificações
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...

# Plataformas bug bounty
H1_USER=...
H1_TOKEN=...
IT_TOKEN=...

# APIs de reconhecimento
SHODAN_API_KEY=...
CENSYS_API_ID=...      # token curto tipo "Pu1KHr6r"
CENSYS_API_SECRET=...
CHAOS_KEY=...
```

## Flags das ferramentas

```bash
naabu      -list <file> -o <out> -silent -rate 1000 -p <30 web ports> -exclude-cdn
katana     -list <file> -o <out> -silent -js-crawl -crawl-duration Ns -depth 3
urlfinder  -list <file> -o <out> -silent
nuclei     -l <file> -o <out> -duc -silent -rl N -c 25 -timeout 5 -severity critical,high,medium
```

## Validação

```bash
python3 -m pytest tests/ -q
```

Baseline atual: **364 testes aprovados, 11 subtestes, 0 falhas**.


Pipeline autônomo de bug bounty com execução terminal-first, watchdog 24/7, filtragem determinística (7 camadas + ML), validação por IA e relatórios operacionais.

## Arquitetura (Slim Core)

| Módulo | Responsabilidade |
|--------|------------------|
| `main.py` | Ponto de entrada CLI e roteamento de modos |
| `core/runner.py` | Orquestração unificada (`MissionRunner`, `ProOrchestrator`) |
| `core/scanner.py` | Pipeline de fases (recon → tática → validação) |
| `core/intel.py` | IA + scoring unificado (`AIClient`, `IntelMiner`, `BountyScorer`) |
| `core/bounty_scorer.py` | Score 0-100 por programa (wildcard/breadth/quality/platform) |
| `core/state.py` | Baseline e checkpoints |
| `core/output.py` | Notificação, relatório e exportação |
| `core/watchdog.py` | Loop adaptativo 1-2h com métricas de ciclo |
| `core/filter.py` | FalsePositiveKiller (7 filtros + ML) |
| `core/cleaner.py` | Workflow `--clean`: purge, update, health check, testes |
| `core/ui.py` | UI tática fullscreen (Rich Live) |
| `core/config.py` | Configuração centralizada, timeouts, rate limits |
| `recon/tools.py` | Descoberta de binários e wrappers de ferramentas |
| `recon/engines.py` | Execução de subfinder, dnsx, httpx, katana, nuclei, uncover |
| `recon/js_hunter.py` | Extração de segredos em JavaScript (c/ severidade por tipo) |
| `recon/platforms.py` | APIs H1/BC/IT via bbscope + alvos.txt customizados |

## Pipeline

```
WATCHDOG → DIFF → Subfinder → DNSX → Uncover → HTTPX → Katana → JS Hunter → Nuclei → FP Filter (7+ML) → IA (score≥60) → Notificar → Relatório
```

## Início rápido

```bash
cp .env.example .env   # configurar tokens
python3 main.py --clean   # instalar deps + verificar ferramentas + rodar testes
python3 main.py           # Menu interativo
```

### Modos disponíveis

```bash
python3 main.py              # Menu interativo
python3 main.py --watchdog   # Modo autônomo 24/7
python3 main.py --clean      # Purge + update + health check + testes
python3 main.py --dry-run    # Preview sem executar ferramentas
python3 main.py --resume ID  # Retomar missão
python3 main.py --export csv # Exportar findings (csv/xlsx/xml/pdf)
```

### Variáveis de ambiente (`.env`)

```bash
# IA
OPENROUTER_API_KEY=...

# Notificações
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...

# Plataformas bug bounty
H1_USER=...
H1_TOKEN=...
IT_TOKEN=...

# APIs de reconhecimento
SHODAN_API_KEY=...
CENSYS_API_ID=...      # token curto tipo "Pu1KHr6r"
CENSYS_API_SECRET=...
CHAOS_KEY=...
```

## Validação

```bash
python3 -m pytest tests/ -q
```

Baseline atual: **364 testes aprovados, 11 subtestes, 0 falhas**.
