# ✅ Suite de testes aprimorada — 256 testes passando

## 5 novos arquivos de teste criados (213 testes novos):

| Arquivo | Testes | Cobertura |
|---|---|---|
| `test_bounty_scorer.py` | 53 | Wildcard (9 casos), Breadth (9), Quality (13), Platform (5), score_program (8), rank_programs (6), format_score_report (3), backwards-compat aliases (3) |
| `test_notifier_v2.py` | 62 | `_tg_escape`, dedup cache, `NotifierConfig`, `alert_scan_complete` (embed structure, 4 cores por status, labels de plataforma), `alert_watchdog_heartbeat`, `alert_watchdog_error`, `alert_nuclei` (Low/Info dropados, Medium/High/Critical→Telegram), `alert_nuclei_discord_batch` no-op, `alert_js_secrets` (Low dropado) |
| `test_reporter_v2.py` | 41 | `load_findings`, `generate()` filtra info/low, plataforma nos relatórios (h1→HackerOne etc.), `load_js_secrets` dedup, tabela summary sem Low/Info rows |
| `test_ml_filter.py` | 30 | `_ML_DEPS_AVAILABLE`, fallback sem modelo, `_detect_content_type` (8 tipos), `_detect_host_type` (12 tipos), `_extract_status_code` (8 casos), `_extract_features` (8 features numéricas), `_encode_categorical` |
| `test_engines.py` | 27 | Censys UUID/email validation (9 casos), Katana adaptive timeout formula (10 casos), `apply_sniper_filter` (8 casos de remoção/preservação) |

### Resultado final:
```
256 passed in 2.73s
```
Commit: `26d23a4`