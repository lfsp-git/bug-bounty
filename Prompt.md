## CONTEXTO

Estou trabalhando no **Hunt3r v1.0-EXCALIBUR** — um scanner autônomo de bug bounty em Python, localizado em `/home/leonardofsp/bug-bounty`.

### Estado atual (commit `133141c`)

**52 testes passando.** Pipeline end-to-end funcional. CTRL+C graceful. Live View estável.

### Arquitetura (resumida)

```
main.py                    ← CLI (~294 linhas)
core/scanner.py            ← MissionRunner (linha 152) + ProOrchestrator (linha 416)
core/ui.py                 ← Terminal UI, scroll region, _stdout_lock, live view snapshots (~658 linhas)
core/config.py             ← Timeouts, rate limiter, validators
core/filter.py             ← FalsePositiveKiller (6 filtros)
core/watchdog.py           ← Loop 24/7
core/updater.py            ← PDTM + nuclei-templates
core/ai.py                 ← AIClient + IntelMiner (OpenRouter)
core/storage.py            ← ReconDiff + CheckpointManager
core/notifier.py           ← NotificationDispatcher (Telegram/Discord, severity-based routing)
core/reporter.py           ← BugBountyReporter (Markdown)
core/export.py             ← CSV/XLSX/XML + dry-run
recon/engines.py           ← Wrappers de ferramentas; run_nuclei usa Popen + stderr streaming (~248 linhas)
recon/js_hunter.py         ← JSHunter (extração real de secrets via regex, JSONL output)
recon/platforms.py         ← H1/BC/IT API clients
recon/tool_discovery.py    ← find_tool() com cache
```

### Flags das ferramentas (verificadas, funcionando)

```
subfinder  -dL <file> -o <out> -silent -rate-limit=50
dnsx       -l <file> -o <out> -wd -silent -a -rate-limit=50
httpx      -l <file> -o <out> -silent -rate-limit 50
katana     -list <file> -o <out> -silent -rate-limit=50 -timeout 15 -depth 2
nuclei     -l <file> -o <out> -duc -stats -sj -rl 50 -c 25 -timeout 5
           -severity critical,high,medium [-tags cve,misconfig,takeover]
```

### UI / Terminal

- `_FIXED_TOP=12` (7 linhas banner + 5 header box) → frozen no topo via scroll region
- `_LIVE_VIEW_LINES=12` → frozen na base via scroll region
- `_stdout_lock` (threading.Lock) → serializa TODOS os writes no stdout
- `_live_view_lock` (threading.RLock) → protege `_live_view_data`
- `_render_live_view` → snapshot data under lock, acquire não-bloqueante no `_stdout_lock`
- `_live_view_loop` → wrapped em try/except (previne thread crash)
- Status icons: ● cinza (idle) → amarelo (running) → verde (done) / azul (0) / vermelho (error)
- TOTAL line: `x SUB | x LV | x TECH | x EP | x VN`
- Nuclei progress: real-time via `-stats -sj` (requests_done/total, rps)
- **Ordem obrigatória** em `scanner.py`: `ui_mission_footer()` ANTES de `ui_scan_summary()`

### Notification Routing

- Critical/High/Medium → Telegram (HTML individual)
- Low/Info → Discord (embed batch)
- JS Secrets: severity-based (Critical/High/Medium → TG, Low → DC)

### Timeouts (`core/config.py`)

```python
TOOL_TIMEOUTS = {
    "subfinder": 60, "dnsx": 60, "uncover": 90,
    "httpx": 120, "katana": 180, "nuclei": 3600,
}
RATE_LIMIT = 50
MAX_SUBS_PER_TARGET = 2000
```

### Bugs já resolvidos (NÃO REPORTAR como novos)

- Nuclei flags inválidas (`-uau`, `-t`, `-rate-limit=N`) ✓
- Nuclei timeout por excesso de templates ✓
- `-stats -sj` conflito com `-silent` ✓
- Race condition stdout (spinner vs main thread) ✓
- `ui_scan_summary` corrompida por spinner ✓
- Banner/live view não fixos ✓
- Progress bars todas cinza ✓
- Summary mostrando "UNKNOWN" como alvo ✓
- Katana/Nuclei recebendo hostnames brutos ✓
- `class MissionRunner:` deletada por edit ✓
- Traceback CTRL+C no prompt `[Enter para voltar]` ✓
- Stderr de ferramentas silenciosamente descartado ✓
- Live view thread crash (race condition `_live_view_data`) ✓
- JS Hunter output plaintext (notifier silently failed to parse) ✓
- JS secrets all routed to Telegram regardless of severity ✓
- Nuclei Medium not routed to Telegram ✓
- FD leaks in `_count_lines`/`_count_findings` ✓
- Subfinder duplicates across scans ✓
- DNSX stderr banner spam ✓
- KeyboardInterrupt during scan crashes with traceback ✓
- Pylance type errors (7 across 5 files) ✓

### Comportamentos NORMAIS (não são bugs)

- **FP Titanium no startup do Watchdog** → filtro roda sobre cache da sessão anterior
- **Nuclei 0 findings em alvos limpos** → esperado
- **Template update failed no startup** → sem git/internet; scan continua normalmente
- **HTTPX 0s em saída vazia do DNSX** → comportamento correto

### Como rodar

```bash
cd /home/leonardofsp/bug-bounty
python3 main.py                    # menu interativo
python3 -m pytest tests/ -q       # 52 testes, todos devem passar
```

### Para debug com snapshot

Snapshots automáticos ficam em `logs/snapshots/` — cada erro ou SIGINT gera um `.log` com:
- Status de cada ferramenta (idle/running + count)
- Variáveis de ambiente (mascaradas)
- Buffer dos últimos logs

### Documentação atualizada

- `README.md` — overview, quick start, architecture
- `docs/CHANGELOG.md` — todas as sessões de fix
- `docs/HUNT3R_SPEC.md` — spec técnica completa
- `docs/System_Prompt.md` — agent persona + invariants

---

## PROBLEMA ATUAL

[DESCREVA AQUI O BUG OU COMPORTAMENTO INESPERADO]

Anexe os arquivos de snapshot relevantes de `logs/snapshots/` se disponíveis.

---

## INSTRUÇÕES PARA O AGENTE

- Use **Caveman Mode**: identificar → corrigir → validar → commitar
- Sempre rodar `python3 -m pytest tests/ -q` antes de commitar
- Formato de resposta:
  ```
  [PROBLEM]: causa raiz em 1 frase
  [FIX]: arquivos modificados e o que mudou
  [TESTS]: N passed / N failed
  [COMMIT]: SHA
  [NEXT]: work pendente
  ```
