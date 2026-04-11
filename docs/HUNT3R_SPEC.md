# HUNT3R v1.0-EXCALIBUR — Especificação Técnica

## 1. Modelo de execução ponta a ponta

1. **Loop Watchdog** (`core/watchdog.py`)
   - Sincroniza alvos wildcard via bbscope (H1/BC/IT)
   - Prioriza alvos com scoring unificado (`core/intel.py`)
   - Executa scans paralelos com sleep adaptativo baseado em métricas de ciclo
2. **Orquestração de missão** (`core/runner.py` → `core/scanner.py`)
   - `ProOrchestrator.start_mission()` → `MissionRunner.run()`
3. **Fase de reconhecimento**
   - Subfinder → DNSX → Uncover → HTTPX
4. **Fase tática**
   - Katana → JS Hunter → Nuclei
5. **Validação e filtragem**
   - `FalsePositiveKiller` (7 filtros determinísticos + ML LightGBM) + validação IA opcional
6. **Saída e estado**
   - Notificação (Telegram/Discord) + relatório Markdown + exportação + baseline/checkpoints

## 2. Superfícies unificadas

| Módulo | Responsabilidade |
|--------|------------------|
| `core/runner.py` | Ponto de entrada de orquestração |
| `core/intel.py` | IA + scoring de alvos |
| `core/state.py` | Baseline e checkpoints |
| `core/output.py` | Notificação, relatório, exportação |
| `recon/tools.py` | Descoberta de binários + execução de ferramentas |

Arquivos de implementação internos ainda funcionam, mas importações do projeto passam pelas superfícies unificadas.

## 3. UI Terminal

`core/ui.py` usa zonas fixas (topo/base) com stdout sincronizado e telemetria por worker:

- `_stdout_lock` serializa escritas no terminal
- `_live_view_lock` protege estado compartilhado do live view
- Roteamento de workers via `set_worker_context()`
- Guard para terminais pequenos (< 80x24)

Ordem de chamada no scanner:
1. `ui_mission_footer()`
2. `ui_scan_summary()`

## 4. Contratos do pipeline

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

## 5. Comportamento operacional do Watchdog

- Workers paralelos configuráveis (`WATCHDOG_WORKERS`)
- Agregação de métricas por ciclo: alvos alterados, erros, durações médias
- Sleep adaptativo: ciclos mais rápidos quando há mudanças, mais lentos quando estável
- Deduplicação temporal de notificações (TTL configurável)

## 6. Flags das ferramentas (implementadas)

```bash
subfinder  -dL <file> -o <out> -silent -rate-limit=N
dnsx       -l <file> -o <out> -wd -silent -a -rate-limit=N
httpx      -l <file> -o <out> -silent -rate-limit N
katana     -list <file> -o <out> -silent -rate-limit=N -timeout 15 -depth 2
nuclei     -l <file> -o <out> -duc -silent -rl N -c 25 -timeout 5 -severity critical,high,medium [-tags tags]
```

## 7. Filtro de falso positivo (8 camadas)

1. Serviços OOB (interact.sh, oast.fun)
2. Templates tech/WAF (header-detect, tech-detect)
3. Fingerprints WAF (patterns cloudflare)
4. Código-fonte HTML/Script
5. Strings placeholder/exemplo
6. Valores nulos/vazios
7. Micro findings (< 3 chars)
8. Filtro ML (LightGBM) — opcional, threshold configurável

## 8. Limitações conhecidas

- APIs de plataforma dependem de `bbscope` e credenciais válidas
- Terminais muito pequenos podem degradar a renderização do watchdog
- Alvos com 400+ hosts vivos podem precisar de timeout nuclei ajustado
- Modelo ML treinado com dados sintéticos — precisa de retraining com dados reais

## 9. Baseline de validação

```bash
python3 -m pytest tests/ -q
```

Baseline atual: **73 testes aprovados, 11 subtestes**
