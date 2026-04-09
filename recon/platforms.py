"""
HUNT3R v2.2 - Platform Manager [SLOW FETCH TACTICAL]
Extrai alvos reais respeitando Rate Limits da plataforma.
"""

import os
import yaml
import logging
import time
import requests
from typing import List, Dict
from urllib.parse import urlparse

# Camada de Apresentação desacoplada
from core.ui_manager import ui_log, Colors, sanitize_input

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


def _clean_wildcard(domain: str) -> str:
    """Remove leading *./HTTP cleanly, preserving compound TLDs like dyson.com.ee."""
    domain = domain.lower().strip()
    if domain.startswith('*.'):
        domain = domain[2:]
    if domain.startswith('http://'):
        domain = domain[7:]
    if domain.startswith('https://'):
        domain = domain[8:]
    return domain


class PlatformManager:
    """Camada de Infraestrutura para comunicação com APIs de BB."""
    
    def __init__(self):
        self.config_path = "config/platforms_config.yaml"
        self.h1_username = os.getenv("HACKERONE_USERNAME")
        self.h1_token = os.getenv("HACKERONE_API_TOKEN")
        # Create session with explicit SSL verification
        self.session = requests.Session()
        self.session.verify = True  # Explicit: Always verify SSL certificates

    def get_available_platforms(self) -> List[Dict]:
        if not os.path.exists(self.config_path):
            ui_log("CONFIG", f"Arquivo {self.config_path} nao encontrado.", Colors.ERROR)
            return []
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            platforms = [
                {'name': k.lower(), **v} 
                for k, v in data.get('platforms', {}).items() 
                if v.get('enabled', False)
            ]
            return platforms
        except Exception as e:
            ui_log("CONFIG ERR", str(e), Colors.ERROR)
            return []

    def get_all_programs_from_platform(self, platform_name: str) -> List[Dict]:
        """Get programs from a specific platform with input validation."""
        if not platform_name or not isinstance(platform_name, str):
            logger.error("Platform name must be a non-empty string")
            return []
        
        platform_name = platform_name.lower().strip()
        
        if platform_name == 'hackerone':
            return self._fetch_hackerone_programs()
        
        ui_log("PLATFORM", f"Plataforma '{platform_name}' nao implementada.", Colors.WARNING)
        return []

    def _fetch_hackerone_programs(self) -> List[Dict]:
        """Mass Extraction Multithread: Rápido e profundo.
        
        Fetches all public HackerOne programs with detailed scope information.
        Uses multithreading to parallelize API calls while respecting rate limits.
        
        Returns:
            List of program dictionaries with handles and scopes
        """
        if not self.h1_username or not self.h1_token:
            ui_log("H1 API", "Credenciais incompletas.", Colors.ERROR)
            logger.error("Missing HackerOne credentials")
            return []
        
        ui_log("H1 API", "Baixando lista de programas...", Colors.PRIMARY)
        list_url = "https://api.hackerone.com/v1/hackers/programs"
        
        handles_to_fetch = []
        page = 1
        
        try:
            # 1. EXTRAÇÃO RÁPIDA: Puxa apenas os handles (sem detalhes pesados)
            while True:
                params = {"page[number]": page, "page[size]": 100}
                auth = (self.h1_username, self.h1_token) if (self.h1_username and self.h1_token) else None
                resp = self.session.get(list_url, auth=auth, params=params, timeout=20, verify=True)
                
                if resp.status_code == 429:
                    ui_log("H1 API", "Rate Limit. Aguarde 5s...", Colors.WARNING)
                    time.sleep(5); continue
                elif resp.status_code != 200: break
                
                data = resp.json()
                for item in data.get('data', []):
                    attrs = item.get('attributes', {})
                    handle = attrs.get('handle', '')
                    
                    # Otimização: A lista geral já traz se paga bounty!
                    if handle:
                        handles_to_fetch.append({
                            'handle': handle,
                            'offers_bounties': attrs.get('offers_bounties', False),
                            'triage_active': attrs.get('triage_active', False)
                        })
                
                meta = data.get('meta', {}).get('page', {})
                if meta.get('current_page', 1) >= meta.get('total_pages', 1): break
                
                page += 1
                time.sleep(0.3)
                
        except Exception as e:
            ui_log("H1 API ERR", f"Lista: {e}", Colors.ERROR)
            return []

        if not handles_to_fetch:
            ui_log("H1 API", "Nenhum programa público encontrado.", Colors.WARNING)
            return []

        ui_log("H1 API", f"{len(handles_to_fetch)} encontrados. Extraindo escopos (5 threads)...", Colors.WARNING)

        # 2. MULTITHREADING: Busca detalhes de forma paralela e segura
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import sys as sys_module
        
        def fetch_single_program(prog_data):
            handle = prog_data['handle']
            detail_url = f"https://api.hackerone.com/v1/hackers/programs/{handle}"
            try:
                # Delay mínimo por thread para não estourar o Rate Limit global
                time.sleep(0.8) 
                auth = (self.h1_username, self.h1_token) if (self.h1_username and self.h1_token) else None
                r = self.session.get(detail_url, params={"include": "structured_scopes"}, auth=auth, timeout=15, verify=True)
                if r.status_code != 200: return None
                
                d_json = r.json()
                attrs = d_json.get('attributes', {})
                scopes = d_json.get('relationships', {}).get('structured_scopes', {}).get('data', [])
                
                domains = set()
                bounty_scopes = 0
                crit_scopes = 0
                
                for asset in scopes:
                    s_attrs = asset.get('attributes', {})
                    identifier = s_attrs.get('asset_identifier', '')
                    
                    if s_attrs.get('bounty_eligible', False): bounty_scopes += 1
                    if s_attrs.get('max_severity') == 'critical': crit_scopes += 1
                    
                    if s_attrs.get('asset_type') in ['URL', 'DOMAIN']:
                        if identifier.startswith(('http://', 'https://')):
                            parsed = urlparse(identifier)
                            if parsed.hostname: domains.add(parsed.hostname)
                        elif '.' in identifier: 
                            cleaned = _clean_wildcard(identifier)
                            if cleaned:
                                domains.add(cleaned)
                
                if domains:
                    safe_handle = sanitize_input(handle).replace('.', '_').replace('-', '_')
                    return {
                        'handle': safe_handle,
                        'domains': list(domains),
                        'score': 0,
                        'offers_bounty': prog_data['offers_bounties'],
                        'triage_active': prog_data['triage_active'],
                        'bounty_scopes': bounty_scopes,
                        'crit_scopes': crit_scopes
                    }
            except Exception as e:
                logging.warning(f"H1 fetch error for {handle}: {e}")
                pass
            return None

        programs = []
        # max_workers=5 é o seguro para a API do H1 não dar 429
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch_single_program, p): p for p in handles_to_fetch}
            
            for i, future in enumerate(as_completed(futures), 1):
                result = future.result()
                if result: programs.append(result)
                
                # UX: Barra de progresso silenciosa
                sys_module.stdout.write(f"\r  [H1] Processados: {i}/{len(handles_to_fetch)} | Mapeados: {len(programs)}   ")
                sys_module.stdout.flush()

        # Limpa a linha do terminal
        sys_module.stdout.write(f"\r{' ':70}\r")
        sys_module.stdout.flush()
        
        ui_log("H1 API", f"{len(programs)} programas mapeados com sucesso.", Colors.SUCCESS)
        return programs


def load_custom_targets() -> List[Dict]:
    """Carrega alvos do alvos.txt usando parsing seguro de URL."""
    from config.validators import validate_and_extract_domain
    from core.ui_manager import ui_log, Colors
    
    t = []
    filepath = "alvos.txt"
    if not os.path.exists(filepath): return []
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for l in f:
                raw = l.strip()
                if not raw or raw.startswith('#'): continue
                
                # Validate input
                domain = validate_and_extract_domain(raw)
                if not domain:
                    ui_log("TARGETS", f"Pulando entrada invalida: {raw}", Colors.WARNING)
                    continue
                
                safe_handle = sanitize_input(domain).replace('.', '_').replace('-', '_')
                t.append({
                    'domain': domain, 
                    'domains': [domain], 
                    'handle': safe_handle, 
                    'score': 30
                })
        return t
    except Exception as e:
        ui_log("TARGETS ERR", f"Erro ao ler {filepath}: {e}", Colors.ERROR)
        return []