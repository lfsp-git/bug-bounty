# HUNT3R v1.1-OVERLORD — Especificação Técnica

## 1. Modelo de execução ponta a ponta

1. **Loop Watchdog** (`core/watchdog.py`)
   - Sincroniza alvos wildcard via bbscope (H1/IT) — cada target tagueado com plataforma de origem
   - Prioriza alvos com scoring unificado (`core/intel.py`) — escreve score no target dict
   - Executa scans paralelos com sleep adaptativo 1-2h baseado em métricas de ciclo
2. **Orquestração de missão** (`core/runner.py` → `core/scanner.py`)
   - `ProOrchestrator.start_mission()` → `MissionRunner.run()`
3. **Fase de reconhecimento**
   - *Domínios*: Subfinder → DNSX → Uncover → HTTPX
   - *IPs/CIDRs*: Naabu (30 portas web) → HTTPX
4. **Fase tática**
   - Katana (`-js-crawl`, depth 3) → URLFinder (hist URLs) → Merge dedup → JS Hunter → **ReAct Heuristic Agent** → Nuclei (apenas Medium/High/Critical)
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

`core/ui.py` usa Rich Live (watchdog) e prints sequenciais (single mode):

- `PIPELINE_TOOLS` = 9 tools: Subfinder, DNSX, Uncover, Naabu, HTTPX, Katana, URLFinder, JS Hunter, Nuclei
- `_stdout_lock` serializa escritas no terminal
- `_live_view_lock` protege estado compartilhado do live view
- Roteamento de workers via `set_worker_context()`
- Worker panels: height=15 (acomoda 9 tools)
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
- `open_ports` — portas abertas encontradas pelo Naabu (IP mode)
- `hist_urls` — URLs históricas encontradas pelo URLFinder

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
| Discord | Stats de scan (sub/host/ports/ep/hist/sec/vuln embed) | Fim de cada missão |
| Discord | Heartbeat/rain-check | Fim de cada ciclo watchdog |

## 8. Flags das ferramentas (implementadas)

```bash
subfinder  -dL <file> -o <out> -silent -rate-limit=N
dnsx       -l <file> -o <out> -wd -silent -a -rate-limit=N
naabu      -list <file> -o <out> -silent -rate 1000 -p <30 web ports> -exclude-cdn
httpx      -l <file> -o <out> -silent -rate-limit N -H "User-Agent: <rotated-UA>" [-proxy <proxy>]
katana     -list <file> -o <out> -silent -js-crawl -crawl-duration Ns -depth 3 -H "User-Agent: <rotated-UA>" [-proxy <proxy>]
urlfinder  -list <file> -o <out> -silent
nuclei     -l <file> -o <out> -duc -j -stats -sj -rl N -c 25 -timeout 5 -severity critical,high,medium
           [-t <tech-dir1> -t <tech-dir2> ...] [-tags <detected-tags>]
uncover    -q <query> -o <out> -silent -e shodan,censys
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

## 11. Modo IP/CIDR

- Targets como `192.168.1.1`, `10.0.0.0/24` são detectados por `is_ip_target()`
- CIDRs são expandidos por `expand_cidr()` — colapsados em handle único (`10_0_0_0_24`)
- Subfinder/DNSX/Uncover são skippados
- Naabu escaneia as 30 portas web antes do HTTPX — falha segura (fallback para IP:80)
- URLFinder não retornará resultados para IPs (sem domínio histórico) — comportamento esperado

## 12. Relatórios e exportação

- `reports/{handle}_TIMESTAMP_report.md` — relatório Markdown por missão
- Platform label correto: HackerOne / Intigriti / Bugcrowd / Custom (alvos.txt) / Unknown
- Summary inclui: subdomínios, hosts vivos, portas abertas, endpoints, URLs históricas, segredos JS, vulns

## 13. Stealth / WAF Evasion (v1.1-OVERLORD)

### Jitter gaussiano entre ferramentas

`core/config.py:jitter_sleep(tool, base, sigma_ratio)` introduz um atraso
aleatório com distribuição Normal(µ=base, σ=base×JITTER_SIGMA_RATIO) antes de
cada chamada a `run_httpx` e `run_katana_surgical`.

| Parâmetro | Padrão | Env var |
|-----------|--------|---------|
| `JITTER_BASE["httpx"]` | 1.5 s | — |
| `JITTER_BASE["katana"]` | 2.0 s | — |
| `JITTER_SIGMA_RATIO` | 0.35 | `HUNT3R_JITTER_SIGMA` |
| `STEALTH_ENABLED` | true | `HUNT3R_STEALTH` |

O jitter quebra padrões temporais regulares que WAFs usam para fingerprint de
ferramentas automatizadas.

### Rotação de User-Agent

Pool de 20 User-Agents reais (Chrome/Firefox/Safari/Edge/mobile) definido em
`STEALTH_USER_AGENTS`.  `get_random_ua()` sorteia um UA por chamada.

- **httpx**: injeta `-H "User-Agent: <UA>"` — sobrescreve o header padrão
- **katana**: injeta `-H "User-Agent: <UA>"` — cada sessão de crawl usa UA diferente

### Pool dinâmico de Proxies

`get_random_proxy()` lê `HUNT3R_PROXIES` (env, lista CSV) e retorna um proxy
aleatório.  Suporta `http://`, `https://` e `socks5://`.

```bash
HUNT3R_PROXIES=http://proxy1:8080,socks5://proxy2:1080,http://proxy3:3128
```

Quando a variável não está definida, nenhum proxy é adicionado ao comando
(comportamento direto — backward compatible).

### Nuclei: Templates Tech-Específicos

`MissionRunner._get_smart_nuclei_template_dirs(httpx_file, katana_file)`:

1. Reutiliza as URLs do HTTPX + Katana para detectar o stack tecnológico via
   `TechDetector.detect_from_urls()`
2. Mapeia cada tecnologia detectada → subdiretórios específicos de
   `~/nuclei-templates/` via `TechDetector.get_nuclei_template_dirs()`
3. Passa os diretórios existentes como `-t <dir>` para o Nuclei

**Efeito**: ao invés de varrer ~9000 templates, o Nuclei roda apenas os
templates relevantes ao alvo (ex: WordPress → ~180 templates) + as tags
detectadas como filtro adicional.  Reduz requisições em ~85% em alvos CMS.

**Fallback**: se `~/nuclei-templates/` não existir ou nenhum subdiretório
corresponder, o scan retorna ao modo padrão (todas as templates + `-tags` filter).

| Tecnologia detectada | Dirs adicionados |
|----------------------|-----------------|
| wordpress | `http/cves/wordpress`, `http/technologies/wordpress` |
| php | `http/cves/php` |
| spring | `http/cves/spring`, `http/cves/java` |
| iis / aspnet | `http/cves/iis`, `http/misconfiguration/iis` |
| apache | `http/cves/apache`, `http/misconfiguration/apache` |
| graphql | `http/graphql`, `http/cves/graphql` |
| (todos) | `http/misconfiguration`, `http/exposures`, `http/takeovers`, `http/default-logins`, `http/cves` |

## 14. Limitações conhecidas

- APIs de plataforma dependem de `bbscope` e credenciais válidas (H1_USER/H1_TOKEN, IT_TOKEN)
- Censys API usa token curto (ex: `Pu1KHr6r`) — não UUID nem e-mail
- Terminais muito pequenos podem degradar a renderização do watchdog
- Alvos com 400+ hosts vivos podem precisar de timeout nuclei ajustado
- Modelo ML treinado com dados sintéticos — retraining com dados reais aumenta precisão
- Uncover retorna 0 se Shodan/Censys sem créditos de consulta disponíveis
- ReAct Agent desativado automaticamente quando OPENROUTER_API_KEY não definida

## 15. Cognição — ReAct Heuristic Agent (v1.1-OVERLORD)

### Módulo: `core/heuristic_agent.py` → `ReActHeuristicAgent`

Implementa um agente ReAct (Reason → Act → Observe) puro Python sobre o
`AIClient` (OpenRouter) existente — sem LangChain ou dependências externas.

### Pipeline position

```
JS Hunter → [ReAct Agent] → Nuclei
```

O agente pré-popula `findings_file` com anomalias de lógica de negócio
**antes** do Nuclei rodar — Nuclei então appenda seus próprios findings no
mesmo arquivo, e o FP filter processa tudo junto.

### Loop ReAct

```
THOUGHT  → LLM analisa endpoints e decide INJECT | DISCARD
ACTION   → Agente constrói URLs mutadas + headers BAC e executa probes
OBSERVE  → Compara baseline vs probe: status diff, size diff
FINDING  → Anomalia confirmada → JSONL appended ao findings_file
```

### Seleção de endpoints (Thought)

`_is_interesting(url)` filtra endpoints por 6 padrões regex:
- Query params com IDs (`?id=N`, `?user_id=N`, `?uuid=...`)
- Paths com segmentos numéricos (`/users/123`, `/orders/456`)
- APIs versionadas (`/api/v1/.../N`)
- Params de controle de acesso (`?role=`, `?permission=`)
- Paths privilegiados (`/admin`, `/internal`, `/dashboard`)
- Paths object-reference genéricos (`/resource/N`)

Seleciona até `REACT_MAX_ENDPOINTS` (padrão: 15) mais complexos por prioridade.

### Prompt LLM (ReAct style)

Estruturado como Thought/Action/Observation com regras explícitas:
- INJECT apenas quando há referência a objeto identificável
- DISCARD assets estáticos, forms de busca, endpoints sem objeto
- Resposta esperada: JSON array puro (sem markdown fences)

### Rate limiting e retries

`_call_llm_with_retry()` implementa exponential backoff:

| Tentativa | Delay |
|-----------|-------|
| 1 | imediata |
| 2 | 3s |
| 3 | 6s |
| (esgotado) | retorna "[AI Offline]" |

Detecta rate limit por `"429"` ou `"rate limit"` na resposta string.

### Probe de endpoints (Action + Observe)

Para cada decisão INJECT:
1. `_build_probe_urls()` — muta IDs numéricos em path e query (±1, 0, 1, 9999); cap 6 URLs/endpoint
2. `_build_bac_headers()` — header sets BAC (X-Forwarded-For, X-Original-URL, X-Rewrite-URL)
3. `_probe_endpoint()` — busca baseline + probe com `httpx.Client(timeout=8s, verify=False)`
4. Compara: status code diff OU `size_diff ≥ REACT_SIZE_DIFF` bytes

### Critérios de anomalia

| Sinal | Severidade |
|-------|-----------|
| 401/403/404 → 200 + body > 50 bytes | HIGH |
| 200 → 200, size_diff ≥ 80 bytes | MEDIUM |

### Schema de findings (compatível com FalsePositiveKiller + Reporter)

```json
{
  "template-id": "llm-heuristic-idor-bac",
  "info": {"severity": "high", "tags": ["idor", "auth-bypass", "llm-heuristic"]},
  "host": "<baseline_url>",
  "matched-at": "<probe_url>",
  "severity": "high",
  "extracted-results": ["status_diff=403→200", "size_diff=1234", "reason=..."],
  "_hunt3r_source": "llm_heuristic_agent",
  "_llm_reason": "<LLM justification>"
}
```

### Env vars de controle

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `REACT_MAX_ENDPOINTS` | 15 | Endpoints máximos por chamada LLM |
| `REACT_MAX_PROBES` | 30 | Probes HTTP máximos por missão |
| `REACT_SIZE_DIFF` | 80 | Threshold size diff (bytes) para anomalia MEDIUM |
| `REACT_PROBE_TIMEOUT` | 8 | Timeout por probe request (seconds) |

### Tolerância a falhas

- LLM offline/erro → log + skip, scan continua ao Nuclei
- JSON inválido na resposta LLM → log + skip
- Probe HTTP timeout/error → log + skip endpoint  
- KeyboardInterrupt propagado normalmente
- Toda exceção inesperada → `logging.warning` + retorna result dict com `ok=False`

## 16. Baseline de validação

```bash
python3 -m pytest tests/ -q
```

Baseline atual: **364 testes aprovados, 11 subtestes, 0 falhas**
