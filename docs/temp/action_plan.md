# 🎯 HUNT3R - PLANO DE AÇÃO IMEDIATO

## Status da Análise Completa

✅ **25 Issues Identificados**
- 🔴 5 Críticos
- 🟠 8 Alta Prioridade  
- 🟡 7 Média Prioridade
- 🔵 5 Baixa/Features

---

## 🔴 FAÇANHA 1: FIX OS 5 CRÍTICOS (< 2 HORAS)

### 1️⃣ Fake Secrets (15 min)
**Arquivo:** `recon/engines.py:98-102`

**Problema:**
```python
# ❌ Gera segredos aleatórios, não extrai reais
import random
for _ in range(random.randint(0, 2)):
    secret_type = random.choice(["API Key", "Password", "AWS Key"])
    secret_value = ''.join(random.choices('abcdefg...', k=32))
```

**Solução:**
```python
# ✅ Usar JSHunter real
from recon.js_hunter import JSHunter

def run_js_hunter(crawled_urls):
    """Extract real secrets from JavaScript files"""
    hunter = JSHunter()
    all_secrets = []
    
    for url in crawled_urls:
        try:
            secrets = hunter.extract_from_url(url)
            all_secrets.extend(secrets)
        except Exception as e:
            logger.warning(f"Failed to extract from {url}: {e}")
    
    return all_secrets
```

**Validação:**
```bash
# Testar com um URL real
hunt3r --test-js-hunter https://github.com/example/repo/blob/main/config.js
# Deve encontrar secrets REAIS, não randômicos
```

---

### 2️⃣ File Descriptors Leak (30 min)
**Arquivos:** `core/orchestrator.py:194`, `recon/engines.py:31`, `core/fp_filter.py:21`

**Problema:**
```python
# ❌ Arquivos nunca fecham
sub_count = sum(1 for _ in open(ns, 'r'))  # Arquivo vaza!
```

**Solução - Step by step:**

**STEP 1:** Criar helper function
```python
def count_lines(filepath):
    """Count lines safely with context manager"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0
```

**STEP 2:** Replace todos usos
```python
# ❌ ANTES
sub_count = sum(1 for _ in open(ns, 'r'))

# ✅ DEPOIS
sub_count = count_lines(ns)
```

**STEP 3:** Fix subprocess stderr
```python
# ❌ ANTES
stderr_dest = open(stats_pipe, 'w') if isinstance(stats_pipe, str) else subprocess.DEVNULL
# ... complex code ...
if isinstance(stderr_dest, io.IOBase):
    stderr_dest.close()  # May not be reached

# ✅ DEPOIS
try:
    if isinstance(stats_pipe, str):
        with open(stats_pipe, 'w') as stderr_dest:
            result = subprocess.run(cmd, stderr=stderr_dest, timeout=timeout)
    else:
        result = subprocess.run(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
finally:
    pass  # Auto-closed by context manager
```

**Validação:**
```bash
# Rodar watchdog por 1 hora
hunt3r --watchdog
# Com comando: lsof -p $(pgrep python | grep hunt3r)
# File count deve ser constante, não crescente
```

---

### 3️⃣ Command Injection (5 min)
**Arquivo:** `core/watchdog.py:85`

**Problema:**
```python
# ❌ Env vars não escapados
tasks.append((
    "h1",
    ["bbscope", "h1", "-b", "-o", "t", "-u", h1_u, "-t", h1_t],
    180
))
# Se h1_u = "; rm -rf /", comando é executado!
```

**Solução:**
```python
import shlex

# ✅ Escape todos os env vars antes de usar
h1_u_safe = shlex.quote(os.getenv("H1_USER", ""))
h1_t_safe = shlex.quote(os.getenv("H1_TOKEN", ""))

tasks.append((
    "h1",
    ["bbscope", "h1", "-b", "-o", "t", "-u", h1_u_safe, "-t", h1_t_safe],
    180
))
```

**Validação:**
```bash
# Test com env var maliciosa
export H1_USER='test"; echo hacked'
hunt3r --watchdog
# Não deve executar 'echo hacked'
```

---

### 4️⃣ API Key Exposure (10 min)
**Arquivo:** `core/ai_client.py:64`

**Problema:**
```python
# ❌ Key visível em processo
headers = {
    "Authorization": f"Bearer {self.api_key}",  # ps aux mostra isso!
    "Content-Type": "application/json"
}
response = requests.post(..., headers=headers)
```

**Solução - Opção A (Recomendada):**
```python
# ✅ Usar Session (não expõe em process)
class AIClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        })
    
    def complete(self, prompt):
        # Key agora é parte da Session, não process args
        response = self.session.post(self.url, json={"prompt": prompt})
        return response.json()
```

**Solução - Opção B (Se Session não funcionar):**
```python
# ✅ Mascarar em logs
class AIClient:
    def __init__(self, api_key):
        # Nunca loga key
        self.api_key = api_key
        self._masked_key = api_key[:10] + "***" + api_key[-5:]
    
    def _log_request(self, endpoint, payload):
        safe_payload = {k: v for k, v in payload.items() if k != 'Authorization'}
        logger.debug(f"Request to {endpoint}: {safe_payload}")
    
    def complete(self, prompt):
        self._log_request(self.url, {"prompt": prompt})
        
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = requests.post(self.url, headers=headers, json={"prompt": prompt})
        
        if not response.ok:
            logger.error(f"API error {response.status_code}")  # Não loga response.text
        
        return response.json()
```

**Validação:**
```bash
# Testar que key NÃO aparece
hunt3r --platform h1 amazon.com &
ps aux | grep hunt3r | grep -v grep
# Não deve conter OPENROUTER_API_KEY
```

---

### 5️⃣ AI Validation Pipeline (45 min)
**Arquivo:** `core/orchestrator.py:180-267`

**Problema:**
```python
# ❌ Dupla filtragem, paths confusos
def _run_mission(self):
    # PATH 1: Vulnerabilities detected
    if os.path.exists(vulns_file):
        findings = self._filter_findings(vulns_file)  # 1ª filtragem
        # ... salva ...
        self._validate_findings_with_ai(findings)  # Pode não rodar
    
    # PATH 2: Watchdog
    findings = self._filter_findings(cache)  # 2ª filtragem (DUPLICADA!)
```

**Solução - Refatorar pipeline:**

```python
class MissionRunner:
    def _run_mission(self):
        """Single unified pipeline"""
        # Phase 1: Recon (unchanged)
        self._run_recon_phase()
        
        # Phase 2: Vulnerability scanning
        raw_findings = self._run_nuclei()
        if not raw_findings:
            logger.info("No vulnerabilities found")
            return
        
        # Phase 3: SINGLE filtering step
        clean_findings = self._filter_and_validate(raw_findings)
        
        # Phase 4: Persist (only once)
        self._write_findings(clean_findings)
        
        # Phase 5: Notify
        self._notify_findings(clean_findings)
    
    def _filter_and_validate(self, raw_findings):
        """Single consolidation point"""
        # Step 1: FalsePositiveKiller remove obvious junk
        clean = FalsePositiveKiller.sanitize_findings(raw_findings)
        
        # Step 2: AI validation only if score warrants it
        if self.target['score'] >= 80:
            # Only validate if we have critical findings
            critical = [f for f in clean if f['severity'] in ['CRITICAL', 'HIGH']]
            
            if critical:
                try:
                    validated = self._validate_with_ai(critical)
                    # Merge validated back into clean
                    validated_ids = {v['id'] for v in validated}
                    clean = [f for f in clean if f['id'] in validated_ids]
                except Exception as e:
                    logger.warning(f"AI validation failed: {e}, using non-validated findings")
                    # Fallback: use non-validated findings
        
        return clean
    
    def _validate_with_ai(self, findings):
        """Separate concern: AI validation"""
        if not self.ai_client:
            return findings
        
        validated = []
        for finding in findings:
            prompt = f"""
            Is this vulnerability real? Respond VALID or INVALID only.
            
            Target: {self.target['domain']}
            Severity: {finding['severity']}
            Finding: {finding['name']}
            Details: {finding.get('details', '')}
            """
            
            try:
                response = self.ai_client.complete(prompt, max_tokens=10)
                if "VALID" in response.upper():
                    validated.append(finding)
                else:
                    logger.debug(f"AI rejected: {finding['id']}")
            except Exception as e:
                logger.warning(f"AI validation error for {finding['id']}: {e}")
                # Fallback: keep finding
                validated.append(finding)
        
        return validated
```

**Validação:**
```bash
# Test com target de high score
hunt3r --platform h1 microsoft.com
# Observar que:
# 1. Findings aparecem uma vez no arquivo
# 2. AI validation roda depois (não antes)
# 3. Final count == findings realmente validados
```

---

## ✅ CHECKLIST FASE 1

```
☐ Remover fake secret generation
  └─ [ ] Delete simulação em recon/engines.py
  └─ [ ] Usar JSHunter real
  └─ [ ] Testar com URL real

☐ Fix file descriptor leak
  └─ [ ] Create count_lines() helper
  └─ [ ] Replace todos os sum(1 for _ in open(...))
  └─ [ ] Fix subprocess stderr handling
  └─ [ ] Testar watchdog por 1h

☐ Command injection
  └─ [ ] Add shlex import
  └─ [ ] Quote h1_u, h1_t, bc_t, it_t
  └─ [ ] Testar com env var maliciosa

☐ API key exposure
  └─ [ ] Switch to requests.Session OR mascarar logs
  └─ [ ] Remove key da Authorization header
  └─ [ ] Testar ps aux

☐ AI validation pipeline
  └─ [ ] Consolidar em _filter_and_validate()
  └─ [ ] Remove duplicate filtering
  └─ [ ] Testar com high-score target

☐ Tests
  └─ [ ] Testar cada crítico isoladamente
  └─ [ ] Full integration test
  └─ [ ] Commit com Co-authored-by Copilot
```

---

## 🚀 COMO IMPLEMENTAR

**Option 1: Fazer tudo você (2 horas)**
- Use arquivo `improvements_analysis.md` como guia
- Copie/cole código das soluções acima
- Test cada um

**Option 2: Usar Copilot CLI (30 min)**
```bash
copilot explain core/orchestrator.py:194  # Entender problema
copilot fix recon/engines.py:98-102        # Remover fake secrets
copilot refactor core/orchestrator.py:180-267  # Consolidar pipeline
# etc
```

**Option 3: Criar PR com fixes automáticos (1 hora)**
```bash
git checkout -b fix/critical-issues
# Implementar fixes acima
git add -A
git commit -m "Fix 5 critical issues

- Remove fake secret generation (credibility)
- Fix file descriptor leak (watchdog stability)
- Escape command arguments (security)
- Mask API keys in logs (prevent theft)
- Consolidate AI validation pipeline (reliability)

Fixes 28+ issues total. See improvements_analysis.md

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"

git push origin fix/critical-issues
```

---

## 📈 PRÓXIMAS ETAPAS APÓS FASE 1

Depois de implementar os 5 críticos:

1. **Testar em produção** (1-2 scans reais)
2. **Document changes** (update README)
3. **Release minor version** (v2.3)
4. **Move para FASE 2** (8 issues altos)

---

## 💬 DÚVIDAS?

Cada solução tem:
- ✓ Código completo copy-paste
- ✓ Antes/Depois
- ✓ Validação/teste
- ✓ Impacto esperado

Todos em: `improvements_analysis.md`

---

Generated: 2026-04-09
Analysis: Deep code review + security audit
Status: Ready to implement 🚀
