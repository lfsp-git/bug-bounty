# Hunt3r — Changelog

## 2026-04-11 — Deep Pipeline + UI Full Refresh

### `ccd749c` UI/UX completa para novos tools
- `core/ui.py`: `PIPELINE_TOOLS` 7 → 9 tools (Naabu + URLFinder na ordem correta)
- `_reset_live_view_data`: registra `Naabu {ports}` e `URLFinder {hist_urls}`
- `_METRIC` map: `Naabu → live`, `URLFinder → endpoints`
- `ui_worker_done`: exibe `pts:N` e `hist:N` no activity log quando > 0
- `ui_scan_summary`: exibe "Portas Abertas" e "URLs Históricas" (condicionais)
- `ICONS`: adicionados `NAABU 🔌`, `URLFINDER 📜`, `MERGE 🔀`
- Panel height: 13 → 15 linhas (acomoda 9 tools sem cortar)
- `__all__`: exporta `ui_interrupt_requested`, `TOOL_ICONS`, `PIPELINE_TOOLS`
- `core/scanner.py`: `_build_results_snapshot` inclui `open_ports` e `hist_urls`
- `tests/test_integration.py`: expected set atualizado de 7 → 9 tools

### `f1af61d` Deep pipeline: port scan + hist URLs + JS-crawl
- `recon/engines.py`: `run_naabu()` — port-scan em 30 portas web comuns (80, 443, 3000, 8080, 8443, etc.) antes do HTTPX para IPs/CIDRs
- `recon/engines.py`: `run_urlfinder()` — URLs históricas via Wayback/AlienVault; deduped com HTTPX+Katana antes do Nuclei
- `recon/engines.py`: `run_katana_surgical()` — `-js-crawl` (extrai endpoints de Angular/React JS bundles) + depth 2→3
- `recon/tools.py`: exporta `run_naabu`, `run_urlfinder`
- `core/scanner.py`: Naabu no fluxo IP mode (com fallback IPs brutos); URLFinder após Katana; merge dedup → `live.txt.combined_urls`; counts `open_ports`, `hist_urls`

### `21521f2` UI single-mode spinner + scope_type
- Spinner duplicado no banner corrigido
- `scope_type` IP não descartado no pipeline

### `703b70f` Menu interativo
- Opção [4] Caçar TODOS os alvos.txt
- Seleção de alvos com display de scope_type IP

### `c7de89d` Suporte a IPs e CIDRs
- `core/config.py`: `is_ip_target()`, `expand_cidr()` (colapsa /24→256 IPs em handle único)
- `core/scanner.py`: `is_ip_mode` — skip Subfinder/DNSX/Uncover para IPs/CIDRs
- `core/ui.py`: `ui_manual_target_input()` detecta e normaliza IPs/CIDRs

## 2026-04-11 — Sessão de debug/fix pós-watchdog noturno

### `5f246ef` Platform tagging + report naming
- `recon/platforms.py`: `load_custom_targets()` adiciona `platform='custom'`; H1 API adiciona `platform='h1'` e `original_handle`
- `core/watchdog.py`: `_fetch_global_wildcards()` mantém `platform_map` (raw→platform) em vez de flat set; `_process_raw_to_targets()` recebe e grava campo `platform` em cada target
- `core/reporter.py`: label `'custom'` → "Custom (alvos.txt)"; `'unknown'` → "Unknown"
- `core/export.py`: `ExportFormatter.__init__` aceita `target` opcional; `_filename()` usa `{target}_TIMESTAMP.ext`; PDF fallback gera `.report.html` em vez de `.pdf.html`
- Removidos arquivos `findings_*.pdf.html` antigos de `reports/`

### `97d6081` Score writeback + severidade de segredos + ciclo 1h
- `core/intel.py`: `score_watchdog_target()` agora passa `original_handle`, `domains`, `offers_bounty`, `bounty_scopes`, `crit_scopes` — scoring de wildcard/quality funcionando corretamente
- `core/watchdog.py`: `_prioritize_targets_by_bounty_potential()` escreve `target['score']` — AI validation agora dispara corretamente
- `core/config.py`: `WATCHDOG_SLEEP` reduzido de 4-6h para 1-2h
- `recon/js_hunter.py`: adicionado mapa `SEVERITY` por tipo de padrão; campo `severity` incluído em cada finding — notifier agora roteia corretamente
- `tests/conftest.py`: remove `FileHandler` do root logger antes de cada teste — testes não mais poluem hunt3r.log/debug.log

### `00f2d1a` Fix: --clean output (ANSI, noise, versão httpx)
- Códigos ANSI raw `\033[32m` renderizavam como texto literal `[32m` — removidos de todas as mensagens de log do cleaner
- `Hunt3r terminated` aparecia na seção TEST do --clean — filtrado em `_run_tests()`
- httpx versão aparecia vazia — adicionado padrão regex `[Cc]urrent\s+[Vv]ersion`
- 9 novos testes: `TestStripAnsi`, `test_hunt3r_terminated_filtered`, `test_parses_inf_current_version_format`

### `ed74494` Improve: workflow --clean completo
- `core/cleaner.py`: rewrite completo com `_check_tools()`, `_check_api_keys()`, `_sync_providers()`, `_check_ml_model()`, `_get_venv_python()`, `_print_summary()`
- 32 novos testes em `tests/test_cleaner.py`

### `298aeb9` Fix: _ensure_venv() no guard __main__
- `_ensure_venv()` no nível de módulo em `main.py` causava `os.execv()` quando pytest importava — substituía o processo pytest inteiro
- Fix: movido para dentro do guard `if __name__ == "__main__":`
- `tests/test_hunt3r.py`: corrigido teste que usava `"pdf"` → `"docx"` como formato inválido

### `ed0af87` Fix: token Censys curto + export PDF
- Token Censys real é `Pu1KHr6r` (8 chars alfanuméricos) — não UUID nem e-mail
- `recon/engines.py`: adicionado `_is_valid_censys_id()` + blocklist `_CENSYS_PLACEHOLDERS`; aceita ≥6 chars não-whitespace fora da blocklist
- `core/export.py`: adicionado `to_pdf()` (HTML fallback) + `_to_pdf_fpdf()` (fpdf2 verdadeiro)

### `26d23a4` Tests: suite abrangente
- Criados 5 novos arquivos de teste: `test_bounty_scorer.py` (53), `test_notifier_v2.py` (62), `test_reporter_v2.py` (41), `test_ml_filter.py` (30), `test_engines.py` (27)
- Total: 73 → 324 testes

### `008bdd5` + `84c8471` Discord stats + remover Low/Info
- `core/notifier.py`: `alert_nuclei()` → apenas Medium+ para Telegram; `alert_scan_complete()` → embed Discord com estatísticas; `alert_watchdog_heartbeat()` → rain-check Discord
- `core/reporter.py`: plataforma no cabeçalho; Low/Info removidos da tabela de vulnerabilidades
- `core/watchdog.py`: contador `_cycle_num` + chamada de heartbeat

### `ecaddab` Fix P1: Nuclei templates + JS dedup + Katana
- `main.py`: `_ensure_nuclei_templates()` chamado antes do watchdog
- `core/reporter.py`: dedup de segredos JS por fingerprint `(type, value, source)`
- `recon/engines.py`: Katana usa `-crawl-duration` (total) em vez de `-timeout` (por request); timeout adaptativo `300+6×(N-30)` cap 900s

### `61d1e17` Fix: venv + bounty scorer + Censys
- `main.py`: `_ensure_venv()` usando `os.execv()` para garantir execução no venv correto
- `core/bounty_scorer.py`: rewrite completo — 4 sinais (wildcard/breadth/quality/platform)
- `recon/engines.py`: `_sync_uncover_providers()` escreve `~/.config/uncover/provider-config.yaml`; Katana timeout adaptativo

### `57d8ddd` Fix P0: ML deps + AI validation
- `core/ml_filter.py`: imports numpy/pandas no nível de módulo com flag `_ML_DEPS_AVAILABLE`
- `core/scanner.py`: threshold AI validation reduzido de 80 → 60

---

## 2026-04-11 — Correção de TypeError no BountyScorer

### `f3155ff`
- Guard de tipo para `bounty_range` com elementos `None`
- Guard de tipo para `last_found` com valores truthy não-numéricos
- Guard de tipo para `created_at` com valor `None` explícito

## 2026-04-10 — Slim Core + Hardening operacional

### `1844105` Edge cases
- Guard para terminal pequeno (< 80x24): fallback para `Live(screen=False)`
- Timeout adaptativo do Nuclei: escala para 5400s quando inputs >= 400

### `a8da7ff` Limpeza e alinhamento
- Removidos stubs legados: `core/ai_client.py`, `core/orchestrator.py`
- Todos os testes migrados para superfícies unificadas

### `f66ba69` Hardening de release (Fase E)
- Testes de contrato para módulos unificados
- Cache de dedup do notificador com roundtrip test

### `e71fe99` Watchdog adaptativo (Fase D)
- Sleep adaptativo baseado em delta/erro do ciclo
- Métricas de duração por fase no resultado da missão

### `14987f0` Intel unificado (Fase C)
- `core/intel.py` como facade de inteligência/scoring

### `cdfd64e` Pipeline I/O (Fase B)
- Contratos padronizados por fase (`ok/errors/counts/paths`)

### `ab859d1` Módulos unificados (Fase A)
- Facades: `core/runner.py`, `core/state.py`, `core/output.py`, `recon/tools.py`

## 2026-04-10 — UI tática do watchdog

### `c7e1084` + `14d2c57`
- Dashboard tático fullscreen (Rich Live `screen=True`)
- 3 painéis de worker com progresso por ferramenta
- Contadores operacionais no banner

## 2026-04-10 — FASE 8: Filtro ML de falso positivo

### `c5b1a98` + `b5e6c09`
- Camada ML integrada ao pipeline FP (LightGBM)
- Modelo: `models/fp_filter_v1.pkl` (8 features, 201 amostras)

---

Histórico completo de FASE 1-7 visível no git log.

