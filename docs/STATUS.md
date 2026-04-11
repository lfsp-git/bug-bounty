# Hunt3r — Status Operacional

## Checkpoint atual

- **Data**: 2026-04-11
- **Branch**: `main`
- **Estado**: Slim Core consolidado + hardening operacional completo
- **Testes**: 73 aprovados, 11 subtestes, 0 falhas

## Commits recentes (mais relevantes)

| Commit | Descrição |
|--------|-----------|
| `f3155ff` | Fix: TypeError no BountyScorer com campos None/inválidos |
| `1844105` | Guard para terminal pequeno + timeout adaptativo nuclei |
| `a8da7ff` | Remoção de módulos legados + alinhamento de estrutura |
| `f66ba69` | Testes de hardening + cobertura de contratos unificados |
| `e71fe99` | Watchdog adaptativo + dedup de notificações |
| `14987f0` | Intel scoring unificado + correção filtro Micro |
| `cdfd64e` | Normalização I/O do pipeline + erros explícitos por fase |
| `ab859d1` | Módulos unificados (runner/state/output/tools) |

## Arquitetura ativa

- **Superfícies unificadas**: `runner.py`, `intel.py`, `state.py`, `output.py`, `tools.py`
- **Watchdog**: sleep adaptativo + métricas de ciclo + slots de worker
- **Scanner**: contratos explícitos por fase + métricas de duração
- **Filtro FP**: 7 camadas determinísticas + ML LightGBM
- **UI**: dashboard tático fullscreen (Rich Live)

## Limitações conhecidas

- APIs de plataforma dependem de `bbscope` + credenciais válidas
- Terminais < 80x24 reduzem legibilidade do dashboard
- Alvos com 400+ hosts vivos podem precisar de ajuste no timeout do nuclei
- Modelo ML treinado com dados sintéticos (precisa de retraining)
