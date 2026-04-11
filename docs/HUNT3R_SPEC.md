# HUNT3R v1.0-EXCALIBUR — Especificação Técnica

## 1. Modelo de execução ponta a ponta

1. **Loop Watchdog** (`core/watchdog.py`)
   - Sincroniza alvos wildcard via bbscope (H1/IT) — cada target tagueado com plataforma de origem
   - Prioriza alvos com scoring unificado (`core/intel.py`) — escreve score no target dict
   - Executa scans paralelos com sleep adaptativo 1-2h baseado em métricas de ciclo
2. **Orquestração de missão** (`core/runner.py` → `core/scanner.py`)
   - `ProOrchestrator.start_mission()` → `MissionRunner.run()`
3. **Fase de reconhecimento**
   - Subfinder → DNSX → Uncover → HTTPX
4. **Fase tática**
   - Katana → JS Hunter → Nuclei (apenas Medium/High/Critical)
5. **Validação e filtragem**
   - `FalsePositiveKiller` (7 filtros determinísticos + ML LightGBM) + validação IA (score ≥ 60)
6. **Saída e estado**
   - Notificação (Telegram vulns M/H/C; Discord stats) + relatório Markdown + exportação + baseline

## 2. Superfícies unificadas

| Módulo | Responsabilidade |
|--------|------------------|
| `core/runner.py` | Ponto de entrada de orquestração |
| `core/intel.py` | IA + scoring de alvos (`score_watchdog_target()`) |
| `core/state.py` | Baseline e checkpoints |
| `core/output.py` | Notificação, relatório, exportação |
| `recon/tools.py` | Descoberta de binários + execução de ferramentas |

## 3. Scoring de alvos (BountyScorer)

`core/bounty_scorer.py` → `core/intel.py:score_watchdog_target()`:

| Sinal | Peso | Critério |
|-------|------|---------|
| Wildcard scope | 35% | `*.domain.com` = 100pts; múltiplos wildcards; sem wildcard = 30-55pts |
| Breadth | 25% | scope_size / bounty_scopes / crit_scopes — mais domínios = mais superfície |
| Quality | 25% | TLD (`.io/.ai/.app` = alto), padrões fintech/security no domínio, bounty_range |
| Platform | 15% | h1=75, it=65, bc=60, ywh=55; default=55 |

**Score ≥ 60** → AI validation dispara. Score é escrito no `target['score']` antes do scan.

## 4. UI Terminal

`core/ui.py` usa zonas fixas (topo/base) com stdout sincronizado e telemetria por worker:

- `_stdout_lock` serializa escritas no terminal
- `_live_view_lock` protege estado compartilhado do live view
- Roteamento de workers via `set_worker_context()`
- Guard para terminais pequenos (< 80x24)

## 5. Contratos do pipeline

`MissionRunner` emite payloads explícitos por fase:

- `ok` — sucesso da fase
- `errors` — lista de erros
- `counts` — contagens de resultados
- `paths` — caminhos de arquivos gerados

Resultado final da missão inclui:
- `phase_results` — resultados por fase
- `errors` — erros agregados
- `ok` — sucesso geral
- `metrics.phase_duration_seconds` — duração por fase

## 6. Comportamento operacional do Watchdog

- Workers paralelos configuráveis (`WATCHDOG_WORKERS`, default: 3)
- Platform tagging: `platform_map` mantém `raw_target → 'h1'/'it'/'custom'`
- Ciclo de sleep adaptativo (1-2h base):
  - `change_ratio ≥ 30%` → dorme `SLEEP_MIN` (1h)
  - `change_ratio = 0 && erros = 0` → dorme `SLEEP_MAX + 1800` (~3h)
  - `erros > 1/3 dos alvos` → dorme `SLEEP_MAX + 3600` (~4h)
  - Sem alvos → dorme 15min (retry rápido)

## 7. Notificações

| Canal | Conteúdo | Trigger |
|-------|----------|---------|
| Telegram | Vuln Medium/High/Critical (nuclei) | Finding por alvo |
| Telegram | Segredo JS CRITICAL/HIGH/MEDIUM | JS Hunter com severity no finding |
| Discord | Stats de scan (embed) | Fim de cada missão |
| Discord | Heartbeat/rain-check | Fim de cada ciclo watchdog |

## 8. Flags das ferramentas (implementadas)

```bash
subfinder  -dL <file> -o <out> -silent -rate-limit=N
dnsx       -l <file> -o <out> -wd -silent -a -rate-limit=N
httpx      -l <file> -o <out> -silent -rate-limit N
katana     -list <file> -o <out> -silent -crawl-duration Ns -depth 2
nuclei     -l <file> -o <out> -duc -silent -rl N -c 25 -timeout 5 -severity critical,high,medium [-tags tags]
uncover    -q <query> -o <out> -silent -provider shodan,censys
```

## 9. JS Hunter — severidade por tipo

| Tipo | Severidade |
|------|-----------|
| aws_access_key, aws_secret_key, private_key, stripe_key | CRITICAL |
| google_api, slack_webhook, discord_webhook, auth_token, jwt_token, firebase_db | HIGH |
| generic_api_key, password_or_secret | MEDIUM |
| generic_url_param, interactsh | LOW |

## 10. Filtro de falso positivo (8 camadas)

1. Serviços OOB (interact.sh, oast.fun)
2. Templates tech/WAF (header-detect, tech-detect)
3. Fingerprints WAF (patterns cloudflare)
4. Código-fonte HTML/Script
5. Strings placeholder/exemplo
6. Valores nulos/vazios
7. Micro findings (< 3 chars)
8. Filtro ML (LightGBM) — opcional, threshold configurável

## 11. Relatórios e exportação

- `reports/{handle}_TIMESTAMP_report.md` — relatório Markdown por missão
- Platform label correto: HackerOne / Intigriti / Bugcrowd / Custom (alvos.txt) / Unknown
- `ExportFormatter(target="...")` → `{target}_TIMESTAMP.{csv,xlsx,xml,report.html}`
- `--export pdf` → `.report.html` (browser print-to-PDF) ou `.pdf` (fpdf2 se instalado)

## 12. Workflow --clean

```
1. Purge: cache, baselines, logs antigos
2. Update tools: go install subfinder/dnsx/httpx/katana/nuclei
3. Update deps: pip install -r requirements.txt
4. Health check: versão de cada ferramenta
5. API keys: status de cada chave (.env)
6. Uncover sync: escreve ~/.config/uncover/provider-config.yaml
7. ML model: verifica models/fp_filter_v1.pkl
8. Tests: pytest com output limpo (sem ANSI, sem noise)
9. Summary: tabela de status geral
```

## 13. Limitações conhecidas

- APIs de plataforma dependem de `bbscope` e credenciais válidas (H1_USER/H1_TOKEN, IT_TOKEN)
- Censys API usa token curto (ex: `Pu1KHr6r`) — não UUID nem e-mail
- Terminais muito pequenos podem degradar a renderização do watchdog
- Alvos com 400+ hosts vivos podem precisar de timeout nuclei ajustado
- Modelo ML treinado com dados sintéticos — retraining com dados reais aumenta precisão
- Uncover retorna 0 se Shodan/Censys sem créditos de consulta disponíveis

## 14. Baseline de validação

```bash
python3 -m pytest tests/ -q
```

Baseline atual: **364 testes aprovados, 11 subtestes, 0 falhas**
