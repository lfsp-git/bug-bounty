# Hunt3r — Changelog

## 2026-04-11 — Correção de TypeError no BountyScorer

### `f3155ff`
- Guard de tipo para `bounty_range` com elementos `None` (ex: `(None, None)`)
- Guard de tipo para `last_found` com valores truthy não-numéricos
- Guard de tipo para `created_at` com valor `None` explícito
- Previne crash `float - NoneType` na priorização de alvos do watchdog

## 2026-04-10 — Slim Core + Hardening operacional

### `1844105` Edge cases
- Guard para terminal pequeno (< 80x24): fallback para `Live(screen=False)`
- Timeout adaptativo do Nuclei: escala para 5400s quando inputs >= 400

### `a8da7ff` Limpeza e alinhamento
- Removidos stubs legados: `core/ai_client.py`, `core/orchestrator.py`
- Todos os testes migrados para superfícies unificadas
- Documentação reescrita (README, SPEC, STATUS)

### `f66ba69` Hardening de release (Fase E)
- Testes de contrato para módulos unificados (`runner/state/output/tools`)
- Teste de roundtrip do cache de dedup do notificador
- Migração para UTC timezone-aware

### `e71fe99` Watchdog adaptativo (Fase D)
- Sleep adaptativo baseado em delta/erro do ciclo
- Métricas de duração por fase no resultado da missão
- Cache de deduplicação temporal para Telegram/Discord

### `14987f0` Intel unificado (Fase C)
- `core/intel.py` como facade de inteligência/scoring
- Correção do filtro Micro FP (não elimina findings sem `extracted-results`)

### `cdfd64e` Pipeline I/O (Fase B)
- Contratos padronizados por fase (`ok/errors/counts/paths`)
- Propagação explícita de erros por fase
- Caminhos de leitura URL/JSONL normalizados

### `ab859d1` Módulos unificados (Fase A)
- Facades: `core/runner.py`, `core/state.py`, `core/output.py`, `recon/tools.py`
- Importações de runtime rewired para superfícies unificadas

## 2026-04-10 — UI tática do watchdog

### `c7e1084`
- Mapeamento de workers com fila (evita drift de labels)
- Contadores operacionais no banner (`RUN`, `DONE`, `ERR`)
- Coloração semântica no log de atividade

### `14d2c57`
- Dashboard tático fullscreen (Rich Live `screen=True`)
- 3 painéis de worker (`W1/W2/W3`) com progresso por ferramenta
- Painel de log de atividade com rolagem
- Contexto thread-local e snapshot automático em falhas

## 2026-04-10 — FASE 8: Filtro ML de falso positivo

### `c5b1a98` + `b5e6c09`
- Camada ML integrada ao pipeline FP (LightGBM)
- Pipeline de treinamento: extração → labeling → augmentação → treino
- Modelo: `models/fp_filter_v1.pkl` (8 features, 201 amostras)
- Config: `ML_FILTER_ENABLED`, `ML_CONFIDENCE_THRESHOLD`

---

Histórico completo de FASE 1-7 visível no git log.
