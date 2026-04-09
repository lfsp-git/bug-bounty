"""
HUNT3R v2.2 - Inteligência [DEFINITIVO - PARSER BLINDADO]
Desacoplado do Terminal. Parser de HTTPX à prova de versões e S.O.
"""

import re
import json
import os
import time
import logging
from core.ui_manager import ui_log, Colors

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

class IntelMiner:
    def __init__(self, api_client):
        self.client = api_client
        self.cache = "recon/intel_cache.json"
        self.max_subs = self._hw()

    def _hw(self):
        if HAS_PSUTIL:
            mb = psutil.virtual_memory().available // (1024 * 1024)
            return 100 if mb < 3000 else (1000 if mb < 6000 else 2000)
        try:
            with open('/proc/meminfo') as f:
                m = dict((i.split()[0].rstrip(':'), int(i.split()[1])) for i in f.readlines())
            mb = m.get('MemAvailable', 0) // 1026
            return 100 if mb < 3000 else (1000 if mb < 6000 else 2000)
        except Exception:
            return 200

    def _score(self, h, d, metadata=None):
        """Calcula o Score baseado em Heurística de Mercado (Tiers)."""
        if not metadata: metadata = {}
        s = 10 # Base
        
        # 1. DADOS DA API (Raramente confiáveis para não-membros, mas mantemos o ganho de pontos)
        if metadata.get('crit_scopes', 0) > 0: s += 30
        if metadata.get('bounty_scopes', 0) > 2: s += 20
        if metadata.get('triage_active'): s += 5
        
        # 2. HEURÍSTICA DE PALAVRAS-CHAVE (A Verdadeira Inteligência)
        t = f"{h.lower()} {d.lower()}"
        
        # TIER 1: Fintech, Bancos, Cripto (Score 80+) - Onde está o dinheiro rápido
        if any(x in t for x in ['coinbase','crypto','blockchain','trading','exchange','defi','wallet','bank','financial','capital','payment','stripe','plaid','mercury','paypal','wise']):
            s += 70
            
        # TIER 2: Tech Giants, Infraestrutura Crítica, Redes Sociais (Score 60+) - Alta complexidade e PII
        # ATENÇÃO: ' x ' tem espaços para não dar match em palavras como "complex" ou "index"
        elif any(x in t for x in ['google','microsoft','apple','amazon','meta','facebook','cloudflare','akamai','fastly','github','gitlab','atlassian','uber','airbnb','spotify','netflix','salesforce','oracle','sap','adobe','snowflake','datadog','cloud','aws','azure','gcp','att','verizon','vodafone', 'linkedin', 'twitter', ' x ', 'slack', 'tinder', 'discord', 'snapchat', 'telegram']):
            s += 50
            
        # TIER 3: Alvos de Dados Sensíveis, Saúde, Seguros, E-commerce (Score 45+) - Impacto massivo
        elif any(x in t for x in ['equifax','experian','transunion','goldman','mckinsey','medical','health','gov','insurance','telecom','booking','yelp','mapbox','grab','shopify', 'flipkart', 'olx']):
            s += 35
            
        # TIER 4: CMS, E-commerce base, DevOps (Score 30+) - Bug bounty de entrada
        elif any(x in t for x in ['wordpress','woocommerce','drupal','joomla','magento','prestashop','docker','kubernetes','jenkins','git']):
            s += 20
        
        # PENALIDADES
        if any(x in t for x in ['security','hackerone','bugcrowd','intigriti']): s -= 30 # Plataformas de BB
        if any(x in t for x in ['google','microsoft']) and self.max_subs < 500: s -= 20 # Baleias em VPS fraca
        
        return max(0, min(s, 99))

    def _hot_score(self, prog):
        """Calculate 'heat' score based on available H1 metadata."""
        if not prog.get('offers_bounty', False) and not prog.get('offers_bounties', False):
            return 0
        s = 50  # Base

        # Triage activity
        if prog.get('triage_active'):
            s += 30

        # Bounty scope count
        bs = prog.get('bounty_scopes', 0)
        if bs >= 10: s += 10
        elif bs >= 5: s += 7
        elif bs >= 2: s += 4

        # Critical scopes
        if prog.get('crit_scopes', 0) > 0:
            s += 5

        # Domain count (surface size)
        dc = len(prog.get('domains', []))
        if dc >= 50: s += 5

        return min(s, 100)

    def rank_programs_for_list(self, p):
        if not p: return []
        if os.path.exists(self.cache) and (time.time() - os.path.getmtime(self.cache)) < 3600:
            try:
                with open(self.cache, 'r') as f: return json.load(f)
            except Exception: pass

        # Filter out programs that don't pay bounties
        paid = [x for x in p if x.get('offers_bounty', False) or x.get('offers_bounties', False)]
        for x in paid:
            x['hot_score'] = self._hot_score(x)
            # Keep legacy score for display
            x['score'] = self._score(x['handle'], x.get('domains', ['unknown.com'])[0], x)

        # Sort by hot_score first (programs that pay + triage + scope), then score
        r = sorted(paid, key=lambda x: (x.get('hot_score', 0), x.get('score', 0)), reverse=True)

        try:
            with open(self.cache, 'w') as f: json.dump(r, f)
        except Exception: pass
        return r

    def load_cached_programs(self):
        """Check if fresh H1 programs cache exists."""
        if os.path.exists(self.cache) and (time.time() - os.path.getmtime(self.cache)) < 3600:
            try:
                with open(self.cache, 'r') as f:
                    return json.load(f)
            except Exception: pass
        return None

    def select_surgical_arsenal(self, path, score=0):
        if not os.path.exists(path):
            ui_log("INTEL", "HTTPX nao encontrado.", Colors.WARNING)
            return "exposure,takeover"
        
        raw = set(); freq = {}; raw_lines = [] # Agora guardamos as linhas cruas
        
        try:
            with open(path, 'r', errors='ignore') as f:
                for line in f:
                    raw_lines.append(line) # Guarda para fallback
                    if '[' in line and ']' in line:
                        cl = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', line)
                        cl = re.sub(r'\[[\d;]*m\]', '', cl)
                        for m in re.findall(r'\[([^\]]+)\]', cl):
                            m = m.strip()
                            if len(m) > 40: continue
                            if ',' in m: raw.update([t.strip() for t in m.split(',')])
                            else: raw.add(m)
        except Exception as e:
            ui_log("INTEL ERR", str(e), Colors.ERROR)
            return "exposure,takeover"

        NORM_MAP = {
            'apache http server': 'apache', 'apache': 'apache', 'nginx': 'nginx',
            'microsoft-iis': 'iis', 'iis': 'iis', 'microsoft httpapi': 'iis',
            'litespeed': 'litespeed', 'openresty': 'openresty', 'caddy': 'caddy',
            'nextcloud': 'nextcloud', 'codeigniter': 'codeigniter', 'laravel': 'laravel',
            'django': 'django', 'react': 'react', 'angular': 'angular', 'vue': 'vue',
            'wordpress': 'wordpress', 'wp-': 'wordpress', 'drupal': 'drupal',
            'joomla': 'joomla', 'magento': 'magento', 'tomcat': 'tomcat',
            'weblogic': 'weblogic', 'sharepoint': 'sharepoint', 'asp.net': 'aspnet', 'php': 'php',
            'java': 'java', 'ruby': 'ruby', 'python': 'python', 'node.js': 'nodejs',
            'gunicorn': 'gunicorn', 'uwsgi': 'uwsgi', 'puma': 'puma', 'unicorn': 'unicorn',
            'cloudflare': None, 'jquery': None, 'hsts': None, 'http/3': None,
            'underscore.js': None, 'semantic ui': None, 'google analytics': None,
            'amazon web services': 'aws', 'amazon s3': 'aws', 'cloudflare browser insights': None,
        }

        clean = set()
        for t in raw:
            ot = t.strip().lower()
            if not ot or len(ot) < 2 or len(ot) > 40: continue
            if ot.isdigit(): continue
            if '/' in ot: ot = ot.split('/')[0].strip()
            if '(' in ot: ot = ot.split('(')[0].strip()
            if ':' in ot: ot = ot.split(':')[0].strip()
            if not ot or len(ot) < 2: continue
            normalized = NORM_MAP.get(ot)
            if normalized is None: continue
            elif normalized: ot = normalized
            else: continue
            if '/' in ot or ' ' in ot: continue 
            clean.add(ot); freq[ot] = freq.get(ot, 0) + 1

        # NOVO: FALLBACK BRUTO (Se o regex de colchetes falhar)
        if not clean and raw_lines:
            brute_keywords = ['apache', 'nginx', 'iis', 'php', 'asp', 'react', 'vue', 'angular', 'laravel', 'django', 'wordpress', 'java', 'ruby', 'python', 'aws', 'tomcat', 'jboss']
            for line in raw_lines:
                lower_l = line.lower()
                for kw in brute_keywords:
                    if kw in lower_l:
                        clean.add(kw); freq[kw] = freq.get(kw, 0) + 1
            if clean: ui_log("INTEL", "Fallback: Tech recuperada via brute force.", Colors.WARNING)

        bl = ['http', 'status', 'title', 'content-type', 'location', 'server', 'cdn', 'generic', 'unknown', 'returns', 'forbidden', 'found', 'ok']
        ft = {t for t in clean if t not in bl and len(t) > 2}

        if ft:
            ts = ", ".join(f"{k}({v}x)" for k, v in sorted(freq.items(), key=lambda x: x[1], reverse=True))
            ui_log("INTEL DETECTED", f"Tecnologias: {ts}", Colors.PRIMARY)

        app = {'react', 'angular', 'vue', 'laravel', 'spring', 'express', 'django', 'flask', 'next', 'rails', 'concretecms', 'wordpress', 'wp-', 'drupal', 'joomla', 'magento', 'shopify', 'woocommerce', 'tomcat', 'weblogic', 'sharepoint', 'nextcloud', 'codeigniter', 'aspnet', 'php', 'java', 'ruby', 'python', 'nodejs', 'gunicorn', 'uwsgi', 'puma', 'unicorn'}
        srv = {'nginx', 'apache', 'iis', 'litespeed', 'openresty', 'caddy'}
        da = ft.intersection(app); ds = ft.intersection(srv)
        tags_list = []
        
        if ds:
            if 'apache' in ds: selected_server = 'apache'
            else:
                priority_order = ['iis', 'nginx', 'litespeed', 'openresty', 'caddy']
                selected_server = next((s for s in priority_order if s in ds), max(ds, key=lambda x: freq.get(x, 0)))
            tags_list.append(selected_server)
            ui_log("PRIMARY SERVER", f"Servidor: {selected_server.upper()} ({freq[selected_server]}x)", Colors.SUCCESS)
        
        if da:
            sorted_app = sorted(da, key=lambda x: freq.get(x, 0), reverse=True)[:3]
            tags_list.extend(sorted_app)

        if tags_list:
            seen=set(); unique=[]
            for t in tags_list:
                if t not in seen: unique.append(t); seen.add(t)
            tags_str = ",".join(unique[:6])
            
            # OTIMIZAÇÃO: misconfig removido (gera milhares de reqs sem alvo). Só para PREMIUM
            if score >= 80: result = f"{tags_str},exposure,takeover,misconfig,cves"
            else: result = f"{tags_str},exposure,takeover"
            
            ui_log("ARSENAL", f"Mode: HYBRID | Tags: {result}", Colors.SUCCESS)
            return result

        ui_log("INTEL", "Tech nao detectada. Modo: Stealth.", Colors.WARNING)
        return "exposures,takeover,default-logins"

    @staticmethod
    def calculate_hot_score(url: str) -> int:
        """Calcula o interesse ofensivo de uma URL extraída de JS."""
        score = 0
        u = url.lower()
        # High Interest
        if any(x in u for x in ['v1', 'v2', 'api', 'graphql']): score += 5
        if any(x in u for x in ['admin', 'config', 'debug', 'internal', 'staging', 'dev']): score += 4
        if any(x in u for x in ['upload', 'edit', 'delete', 'user', 'settings']): score += 3
        # Noise Reduction (Negative Score)
        static_exts = ('.png', '.jpg', '.jpeg', '.gif', '.css', '.svg', '.woff', '.pdf')
        if any(u.split('?')[0].endswith(ext) for ext in static_exts): score -= 10
        if any(x in u for x in ['jquery', 'bootstrap', 'wp-includes', 'node_modules']): score -= 5
        return score

    def analyze_vulnerability(self, chunk):
        try:
            d = json.loads(chunk.strip().split('\n')[0])
            tid = d.get('template-id', 'unk')
            sev = d.get('severity', '?').upper()
            url = d.get('matched-at', 'unk')
            cve = d.get('cve-id', 'N/A')
            er = d.get('extracted-results', [])
            ctx = f"Template:{tid}|Severity:{sev}|URL:{url}"
            if cve != 'N/A': ctx += f"|CVE:{cve}"
            if er: ctx += f"|Data:{str(er)[:300]}"
            
            if not self.client or not self.client.api_key or not self.client.selected_model:
                analysis = "IMPACT:Analysis unavailable — AI offline.\nSCENARIO:Manual review required."
            else:
                analysis = self.client.complete(
                    f"Role:Elite Bug Bounty Hunter.\nWrite IMPACT and ATTACK SCENARIO for:\n{ctx}\nIMPACT:\nATTACK SCENARIO:\n",
                    max_tokens=500
                )
            if not analysis or len(analysis) < 20: 
                analysis = "IMPACT:Critical\nSCENARIO:Direct exploitation."
            return {'template': tid, 'severity': sev, 'url': url, 'analysis': analysis}
        except Exception:
            return {'template': 'err', 'severity': 'info', 'url': '', 'analysis': 'N/A'}
