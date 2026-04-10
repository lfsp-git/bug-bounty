"""
HUNT3R Watchdog — Motor de Recon Contínuo 24/7 (Lógica do Predador)
Versão Corrigida: Foco em Estabilidade, VPS Contabo e Novos Alvos
"""

import sys
import os
import time
import json
import random
import logging
import shutil
import subprocess
import shlex
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from core.config import to_set  # Unified deduplication

# Adiciona os caminhos de binários ao PATH
home = os.path.expanduser("~")
os.environ["PATH"] += os.pathsep + os.path.join(home, "go", "bin") + os.pathsep + "/usr/local/bin"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Importe apenas o necessário
from core.ui import ui_log, Colors, ui_clear_and_banner, ui_set_mission_meta, ui_enable_watchdog_mode
from core.config import TOOL_TIMEOUTS  # Centralized timeouts
from core.bounty_scorer import BountyScorer  # Bounty program prioritization

# Configurações
GLOBAL_TARGETS_HISTORY = "recon/baselines/global_targets.txt"
SLEEP_MIN = 14400  # 4h
SLEEP_MAX = 21600  # 6h
MAX_TARGETS_PER_CYCLE = 50
MAX_PARALLEL_WORKERS = 3  # Process 3 targets in parallel

# Blacklist reduzida para focar em alvos lucrativos
TARGET_BLACKLIST = ['ui', 'spotify', 'gitlab', 'coinbase']

def _cleanup_disk(handle):
    """Remove pastas pesadas do Katana/Nuclei para poupar o NVMe de 75GB."""
    base_path = f"recon/db/{handle}"
    for folder in ["crawling", "tmp", "logs_raw"]:
        path = os.path.join(base_path, folder)
        if os.path.exists(path):
            try:
                shutil.rmtree(path)
                ui_log("DISK", f"Limpeza: {handle}/{folder} removido.", Colors.DIM)
            except Exception as e:
                logging.error(f"Erro na limpeza de {path}: {e}")

import threading

def _scan_target(orch, target):
    """Run a single target scan using the orchestrator and return results dict.
    This mirrors the behavior of ProOrchestrator.start_mission.
    """
    try:
        # Expect target dict compatible with start_mission signature
        return orch.start_mission(target)
    except Exception as e:
        ui_log("ERR", f"Scan failed for {target.get('original_handle','')}: {e}", Colors.ERROR)
        return {}

def _fetch_global_wildcards():
    """Coleta alvos das APIs com cache de 12h e execução em paralelo."""
    CACHE_FILE = "recon/baselines/api_wildcards.txt"
    
    # 1. Lógica de Cache (Só gasta API e tempo uma vez a cada 12 horas)
    if os.path.exists(CACHE_FILE):
        mtime = os.path.getmtime(CACHE_FILE)
        if (time.time() - mtime) < 43600: # 12 horas
            ui_log("WATCHDOG", "Usando cache local de wildcards (Cache < 12h).", Colors.DIM)
            with open(CACHE_FILE, 'r') as f:
                raw_list = [l.strip() for l in f if l.strip()]
            return _process_raw_to_targets(raw_list)

    ui_log("WATCHDOG", "Cache expirado. Sincronizando com APIs em paralelo...", Colors.PRIMARY)
    
    h1_u, h1_t = os.getenv("H1_USER"), os.getenv("H1_TOKEN")
    bc_t, it_t = os.getenv("BC_TOKEN"), os.getenv("IT_TOKEN")
    
    # Escape environment variables to prevent command injection
    h1_u_safe = shlex.quote(h1_u) if h1_u else ""
    h1_t_safe = shlex.quote(h1_t) if h1_t else ""
    bc_t_safe = shlex.quote(bc_t) if bc_t else ""
    it_t_safe = shlex.quote(it_t) if it_t else ""

    all_raw = to_set([])  # Start with empty deduplicated set
    threads = []
    lock = threading.Lock()

    def fetch_task(name, cmd, timeout):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0:
                targets = [l.strip() for l in res.stdout.split('\n') if "*" in l]
                with lock:
                    all_raw.update(to_set(targets))  # Deduplicate on add
                ui_log("WATCHDOG", f"{name.upper()} pronto ({len(targets)} alvos).", Colors.SUCCESS)
            else:
                ui_log("WATCHDOG", f"Falha no {name.upper()}.", Colors.WARNING)
        except subprocess.TimeoutExpired:
            ui_log("WATCHDOG", f"PULADO: {name.upper()} (Timeout excedido).", Colors.WARNING)

    # Configuração de comandos com env vars escapados - usando timeouts centralizados
    from recon.tool_discovery import find_tool
    bbscope_path = find_tool("bbscope")
    if bbscope_path == "bbscope" and not shutil.which("bbscope"):
        ui_log("WATCHDOG", "bbscope não encontrado. Pulando coleta de wildcards via API.", Colors.WARNING)
        return []

    tasks = []
    if h1_u_safe and h1_t_safe:
        tasks.append(("h1", [bbscope_path, "h1", "-b", "-o", "t", "-u", h1_u_safe, "-t", h1_t_safe, "--active-only"], TOOL_TIMEOUTS.get("uncover", 90)))
    if bc_t_safe:
        tasks.append(("bc", [bbscope_path, "bc", "-b", "-o", "t", "-t", bc_t_safe], TOOL_TIMEOUTS.get("uncover", 90)))
    if it_t_safe:
        tasks.append(("it", [bbscope_path, "it", "-b", "-o", "t", "-t", it_t_safe], TOOL_TIMEOUTS.get("uncover", 90)))

    # Dispara as threads
    for t_name, t_cmd, t_time in tasks:
        th = threading.Thread(target=fetch_task, args=(t_name, t_cmd, t_time))
        th.start()
        threads.append(th)

    for th in threads: th.join()

    # Salva no cache para o próximo ciclo
    if all_raw:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            f.write('\n'.join(list(all_raw)))

    return _process_raw_to_targets(list(all_raw))

def _process_raw_to_targets(raw_list):
    """Lógica auxiliar para limpar e rankear os wildcards brutos."""
    from core.config import to_set
    
    # Load history once at start (optimization: avoid repeated file I/O)
    history = to_set([])
    if os.path.exists(GLOBAL_TARGETS_HISTORY):
        with open(GLOBAL_TARGETS_HISTORY, 'r') as f: 
            history = to_set(f.read().splitlines())
    
    valid_targets = []
    new_found = []

    for raw in raw_list:
        clean = raw.lower().replace('*.', '').strip()
        if not clean or any(b in clean for b in TARGET_BLACKLIST): continue
        
        if clean not in history:
            new_found.append(clean)
            history.add(clean)  # Add to memory copy

        valid_targets.append({
            'handle': clean.replace('.', '_'),
            'original_handle': clean,
            'domains': [clean],
            'score': 50
        })
    
    # Write all new targets at once (optimization: batch I/O with efficient string building)
    if new_found:
        os.makedirs(os.path.dirname(GLOBAL_TARGETS_HISTORY), exist_ok=True)
        with open(GLOBAL_TARGETS_HISTORY, 'a') as f:
            f.write('\n'.join(new_found) + '\n')
        ui_log("PREDADOR", f"{len(new_found)} NOVOS ALVOS DETECTADOS!", Colors.SUCCESS)
    
    return valid_targets[:MAX_TARGETS_PER_CYCLE]

def _prioritize_targets_by_bounty_potential(targets):
    """
    Sort targets by bounty program potential using BountyScorer.
    Prioritizes newly added programs over established ones.
    """
    scored_targets = []
    now = time.time()
    
    for target in targets:
        # Extract metadata for scoring
        program_data = {
            'handle': target.get('original_handle', target.get('handle', 'unknown')),
            'platform': 'unknown',
            'created_at': now,
            'bounty_range': (100, 1000),
            'scope_size': 100,
        }
        
        score, breakdown = BountyScorer.score_program(program_data)
        scored_targets.append((target, score, breakdown))
    
    # Sort by score descending
    scored_targets.sort(key=lambda x: x[1], reverse=True)
    
    # Log top priorities
    if scored_targets:
        top_3 = scored_targets[:3]
        ui_log("BOUNTY", "Top targets (by program potential):", Colors.INFO)
        for target, score, breakdown in top_3:
            handle = target.get('original_handle', 'unknown')
            ui_log("BOUNTY", f"  {handle}: {score:.0f}/100", Colors.DIM)
    
    return [t[0] for t in scored_targets]

def _has_changes_since_last_scan(handle):
    """Verifica se houve mudanças desde a última varredura."""
    # Verifica se há baseline para esse handle
    baseline_file = f"recon/baselines/{handle}_sub.txt"
    if not os.path.exists(baseline_file):
        return True  # Primeira varredura, processar
    # Em produção, comparar com baselines atuais
    # Por agora, processar todos
    return True

SCAN_HISTORY_FILE = "recon/baselines/target_scan_history.txt"

def _should_process_target(handle):
    """Decide se deve processar o alvo baseado em execuções anteriores."""
    history_file = SCAN_HISTORY_FILE
    os.makedirs(os.path.dirname(history_file), exist_ok=True)
    
    # Carrega histórico
    history = {}
    if os.path.exists(history_file):
        with open(history_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if len(parts) >= 3:
                    history[parts[0]] = (parts[1], parts[2] == 'True')
    
    # Verifica histórico desse handle
    last_scan, has_changes = history.get(handle, (None, False))
    now = time.time()
    
    # Se foi verificado nas últimas 24h e não houve mudanças, pular
    if last_scan and not has_changes:
        scan_time = time.mktime(time.strptime(last_scan, '%Y-%m-%d %H:%M:%S'))
        if now - scan_time < 86400:  # 24 horas
            return False
    
    return True

def _record_scan_result(handle, has_changes):
    """Registra o resultado da varredura no histórico."""
    history_file = SCAN_HISTORY_FILE
    os.makedirs(os.path.dirname(history_file), exist_ok=True)
    
    # Lê histórico existente
    history = {}
    if os.path.exists(history_file):
        with open(history_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if len(parts) >= 3:
                    history[parts[0]] = (parts[1], parts[2] == 'True')
    
    # Atualiza entrada
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    history[handle] = (now, has_changes)
    
    # Salva
    with open(history_file, 'w') as f:
        for h_key, (timestamp, changed) in history.items():
            f.write(f"{h_key},{timestamp},{changed}\n")
    # No explicit return needed


def _scan_target_parallel_wrapper(args):
    """Wrapper for ThreadPoolExecutor to scan a single target thread-safely."""
    orch, target, idx, total = args
    handle = target.get('handle', 'unknown')
    try:
        if _should_process_target(handle):
            ui_log("WATCHDOG", f"[{idx}/{total}] Processando: {target['original_handle']}", Colors.PRIMARY)
            ui_set_mission_meta(target['original_handle'], idx, total)
            results = _scan_target(orch, target)
            has_changes = bool(results.get('subdomains', 0)) if isinstance(results, dict) else False
            _record_scan_result(handle, has_changes)
            
            # Log scan results
            if results and isinstance(results, dict):
                subs = results.get('subdomains', 0)
                live = results.get('alive', 0)
                endpoints = results.get('endpoints', 0)
                secrets = results.get('js_secrets', 0)
                vulns = results.get('vulns', 0)
                ui_log("RESULTADO", f"[{idx}/{total}] {target['original_handle']}: {subs} subs, {live} live, {endpoints} endpoints, {secrets} secrets, {vulns} vulns", 
                       Colors.SUCCESS if vulns > 0 else Colors.INFO)
            
            return {'success': True, 'handle': handle, 'changes': has_changes}
        else:
            ui_log("WATCHDOG", f"[{idx}/{total}] Pulando (histórico recente): {target['original_handle']}", Colors.DIM)
            return {'success': False, 'handle': handle, 'reason': 'cached'}
    except Exception as e:
        ui_log("ERR", f"Erro em {target.get('original_handle', 'unknown')}: {e}", Colors.ERROR)
        return {'success': False, 'handle': handle, 'reason': str(e)}


def run_watchdog():
    # Disable tool time recording to prevent cache modification on every run
    import core.scanner as scanner_module
    scanner_module._RECORD_TOOL_TIMES = False
    
    ui_enable_watchdog_mode()  # Enable watchdog mode to prevent banner clearing
    ui_clear_and_banner()  # Only clear and show banner once at startup
    ui_log("WATCHDOG", "Modo WATCHDOG PREDADOR ativo.", Colors.SUCCESS)
    while True:
        ts = datetime.now().strftime('%H:%M')
        ui_log("WATCHDOG", f"=== CICLO {ts} ===", Colors.BOLD)
        wildcards = _fetch_global_wildcards()
        if wildcards:
            # Prioritize targets by bounty program potential (recency + budget)
            wildcards = _prioritize_targets_by_bounty_potential(wildcards)
            ui_log("WATCHDOG", f"Processing {len(wildcards)} targets in priority order ({MAX_PARALLEL_WORKERS} parallel)", Colors.DIM)
            
            from core.scanner import ProOrchestrator
            from core.ai import IntelMiner
            from core.ai import AIClient
            
            # Create one orchestrator per worker thread to avoid race conditions
            total = len(wildcards)
            with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
                futures = []
                for idx, target in enumerate(wildcards, 1):
                    orch = ProOrchestrator(IntelMiner(AIClient()))
                    future = executor.submit(_scan_target_parallel_wrapper, (orch, target, idx, total))
                    futures.append(future)
                
                # Collect results as they complete
                completed = 0
                try:
                    for future in as_completed(futures):
                        result = future.result()
                        completed += 1
                        if result.get('success'):
                            ui_log("WATCHDOG", f"✓ Concluído: {result['handle']}", Colors.SUCCESS)
                except KeyboardInterrupt:
                    ui_log("WATCHDOG", "Interrupção recebida. Cancelando workers...", Colors.WARNING)
                    executor.shutdown(wait=False)
                    return
        
        # Sleep between cycles
        secs = random.randint(SLEEP_MIN, SLEEP_MAX)
        ui_log("WATCHDOG", f"Dormindo até {(datetime.now() + timedelta(seconds=secs)).strftime('%H:%M')}", Colors.DIM)
        try:
            time.sleep(secs)
        except KeyboardInterrupt:
            ui_log("WATCHDOG", "Interrupção recebida durante sleep. Encerrando...", Colors.WARNING)
            return

if __name__ == "__main__":
    try:
        run_watchdog()
    except KeyboardInterrupt:
        ui_log("WATCHDOG", "Interrupção recebida (main). Encerrando...", Colors.WARNING)
