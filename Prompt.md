## CONTEXTO

Estou trabalhando no **Hunt3r v1.0-EXCALIBUR** — um scanner autônomo de bug bounty em Python, localizado em `/home/leonardofsp/bug-bounty`.

### Estado atual (commit `e1b0285`)

**52 testes passando.** Pipeline end-to-end funcional. CTRL+C graceful. Live View estável. Cache inteligente de 1h ativo. Nuclei rodando sem erros até conclusão.

### Arquitetura (resumida)

```
main.py                    ← CLI (~294 linhas)
core/scanner.py            ← MissionRunner (linha 165) + ProOrchestrator + cache 1h + auto-cleanup
core/ui.py                 ← Terminal UI, scroll region, _stdout_lock, live view, snapshots (~670 linhas)
core/config.py             ← Timeouts, rate limiter, validators
core/filter.py             ← FalsePositiveKiller (6 filtros)
core/watchdog.py           ← Loop 24/7
core/updater.py            ← PDTM + nuclei-templates
core/ai.py                 ← AIClient + IntelMiner (OpenRouter)
core/storage.py            ← ReconDiff + CheckpointManager
core/notifier.py           ← NotificationDispatcher (Telegram/Discord, severity-based routing)
core/reporter.py           ← BugBountyReporter (Markdown)
core/export.py             ← CSV/XLSX/XML + dry-run
recon/engines.py           ← Wrappers de ferramentas; run_nuclei usa Popen + real-time stats streaming
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
- Status: ● cinza (idle) → amarelo (running) → **ciano (cached)** → verde (done) / azul (0) / vermelho (error)
- Live view dict order: Subfinder → DNSX → Uncover → HTTPX → Katana → JS Hunter → Nuclei
- TOTAL line: `x SUB | x LV | x TECH | x EP | x VN`
- Nuclei progress: real-time via `-stats -sj` (requests_done/total, rps)
- SIGWINCH: recalcula scroll region + limpa 3 linhas para erradicar wrap do spinner
- **Ordem obrigatória** em `scanner.py`: `ui_mission_footer()` ANTES de `ui_scan_summary()`

### Cache Inteligente (scanner.py)

- `_CACHE_TTL = 3600` (1 hora)
- `_is_cache_valid(filepath)` — existe + não-vazio + mtime < 1h
- `_tool_cached(name, key, file)` → status "cached" (cyan no live view)
- **Com cache**: Subfinder, DNSX, Uncover, HTTPX, Katana
- **Sem cache (sempre roda)**: JS Hunter, Nuclei
- `_auto_cleanup(target_dir)` — chamado no início de cada scan; remove arquivos >1h do alvo e snapshots antigos

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

- Nuclei TypeError (`'>' not supported between 'str' and 'int'`) ✓
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
- FP TITANIUM gerando snapshots desnecessários ✓
- Live view order wrong (JS Hunter before Katana) ✓
- Cache inteligente ausente no production ✓
- Linha do spinner quebra ao redimensionar terminal ✓

### Comportamentos NORMAIS (não são bugs)

- **FP Titanium no startup do Watchdog** → filtro roda sobre cache da sessão anterior
- **Nuclei 0 findings em alvos limpos** → esperado
- **Template update failed no startup** → sem git/internet; scan continua normalmente
- **HTTPX 0s em saída vazia do DNSX** → comportamento correto
- **Uncover "Done in 0s"** → ferramenta rápida, normal

### Como rodar

```bash
cd /home/leonardofsp/bug-bounty
python3 main.py                    # menu interativo
python3 -m pytest tests/ -q       # 52 testes, todos devem passar
```

### Para debug com snapshot

Snapshots automáticos ficam em `logs/snapshots/` — cada erro ou SIGINT gera um `.log` com:
- Status de cada ferramenta (idle/running/cached/finished + count)
- Variáveis de ambiente (mascaradas)
- Buffer dos últimos logs
- Auto-limpeza de snapshots >1h a cada novo scan

### Documentação atualizada

- `README.md` — overview, quick start, architecture (Session 4)
- `docs/CHANGELOG.md` — todas as sessões de fix (Session 4)
- `Prompt.md` — este arquivo, prompt para novo chat

---

## PROBLEMA ATUAL

[DESCREVA AQUI O BUG OU COMPORTAMENTO INESPERADO]

Anexe os arquivos de snapshot relevantes de `logs/snapshots/` se disponíveis.

---

## INSTRUÇÕES PARA O AGENTE

- Use **Caveman Mode**: identificar → corrigir → validar → commitar
- Sempre rodar `python3 -m pytest tests/ -q` antes de commitar
- Editar sempre `/home/leonardofsp/bug-bounty/` (produção), não worktrees
- Formato de resposta:
  ```
  [PROBLEM]: causa raiz em 1 frase
  [FIX]: arquivos modificados e o que mudou
  [TESTS]: N passed / N failed
  [COMMIT]: SHA
  [NEXT]: work pendente
  ```
