# Hunt3r v1.0-EXCALIBUR

Pipeline autônomo de bug bounty com execução terminal-first, watchdog 24/7, filtragem determinística (7 camadas + ML), validação por IA e relatórios operacionais.

## Arquitetura (Slim Core)

| Módulo | Responsabilidade |
|--------|------------------|
| `main.py` | Ponto de entrada CLI e roteamento de modos |
| `core/runner.py` | Orquestração unificada (`MissionRunner`, `ProOrchestrator`) |
| `core/scanner.py` | Pipeline de fases (recon → tática → validação) |
| `core/intel.py` | IA + scoring unificado (`AIClient`, `IntelMiner`, `BountyScorer`) |
| `core/state.py` | Baseline e checkpoints |
| `core/output.py` | Notificação, relatório e exportação |
| `core/watchdog.py` | Loop adaptativo 24/7 com métricas de ciclo |
| `core/filter.py` | FalsePositiveKiller (7 filtros + ML) |
| `core/ui.py` | UI tática fullscreen (Rich Live) |
| `core/config.py` | Configuração centralizada, timeouts, rate limits |
| `recon/tools.py` | Descoberta de binários e wrappers de ferramentas |
| `recon/engines.py` | Execução de subfinder, dnsx, httpx, katana, nuclei |
| `recon/js_hunter.py` | Extração de segredos em JavaScript |
| `recon/platforms.py` | APIs H1/BC/IT via bbscope |

## Pipeline

```
WATCHDOG → DIFF → Subfinder → DNSX → Uncover → HTTPX → Katana → JS Hunter → Nuclei → FP Filter (7+ML) → IA → Notificar → Relatório
```

## Início rápido

```bash
pip install -r requirements.txt
cp .env.example .env   # configurar tokens
python3 main.py
```

### Modos disponíveis

```bash
python3 main.py              # Menu interativo
python3 main.py --watchdog   # Modo autônomo 24/7
python3 main.py --dry-run    # Preview sem executar ferramentas
python3 main.py --resume ID  # Retomar missão
python3 main.py --export csv # Exportar findings (csv/xlsx/xml)
```

## Validação

```bash
python3 -m pytest tests/ -q
```

Baseline atual: **73 testes aprovados, 11 subtestes**.
