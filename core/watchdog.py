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
from datetime import datetime, timedelta

# Adiciona os caminhos de binários ao PATH
home = os.path.expanduser("~")
os.environ["PATH"] += os.pathsep + os.path.join(home, "go", "bin") + os.pathsep + "/usr/local/bin"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Importe apenas o necessário
from core.ui_manager import ui_log, Colors, ui_clear_and_banner

# Configurações
GLOBAL_TARGETS_HISTORY = "recon/baselines/global_targets.txt"
SLEEP_MIN = 14400  # 4h
SLEEP_MAX = 21600  # 6h
MAX_TARGETS_PER_CYCLE = 50

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

    all_raw = set()
    threads = []
    lock = threading.Lock()

    def fetch_task(name, cmd, timeout):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0:
                targets = [l.strip() for l in res.stdout.split('\n') if "*" in l]
                with lock:
                    all_raw.update(targets)
                ui_log("WATCHDOG", f"{name.upper()} pronto ({len(targets)} alvos).", Colors.SUCCESS)
            else:
                ui_log("WATCHDOG", f"Falha no {name.upper()}.", Colors.WARNING)
        except subprocess.TimeoutExpired:
            ui_log("WATCHDOG", f"PULADO: {name.upper()} (Timeout excedido).", Colors.WARNING)

    # Configuração de comandos
    tasks = []
    if h1_u and h1_t:
        tasks.append(("h1", ["bbscope", "h1", "-b", "-o", "t", "-u", h1_u, "-t", h1_t, "--active-only"], 180))
    if bc_t:
        # Timeout reduzido para o BC para não fritar a paciência
        tasks.append(("bc", ["bbscope", "bc", "-b", "-o", "t", "-t", bc_t], 90))
    if it_t:
        tasks.append(("it", ["bbscope", "it", "-b", "-o", "t", "-t", it_t], 120))

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
    history = set()
    if os.path.exists(GLOBAL_TARGETS_HISTORY):
        with open(GLOBAL_TARGETS_HISTORY, 'r') as f: history = {l.strip() for l in f}

    valid_targets = []
    new_found = []

    for raw in raw_list:
        clean = raw.lower().replace('*.', '').strip()
        if not clean or any(b in clean for b in TARGET_BLACKLIST): continue
        
        if clean not in history:
            new_found.append(clean)
            with open(GLOBAL_TARGETS_HISTORY, 'a') as f: f.write(clean + "\n")

        valid_targets.append({
            'handle': clean.replace('.', '_'),
            'original_handle': clean,
            'domains': [clean],
            'score': 50
        })

    if new_found:
        ui_log("PREDADOR", f"{len(new_found)} NOVOS ALVOS DETECTADOS!", Colors.SUCCESS)
    
    return valid_targets[:MAX_TARGETS_PER_CYCLE]

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


def run_watchdog():
    ui_log("WATCHDOG", "Modo WATCHDOG PREDADOR ativo.", Colors.SUCCESS)
    while True:
        ui_clear_and_banner()  # Chama o novo banner aqui
        ts = datetime.now().strftime('%H:%M')
        ui_log("WATCHDOG", f"=== CICLO {ts} ===", Colors.BOLD)
        wildcards = _fetch_global_wildcards()
        if wildcards:
            from core.orchestrator import ProOrchestrator
            from core.intelligence import IntelMiner
            from core.ai_client import AIClient
            orch = ProOrchestrator(IntelMiner(AIClient()))
            for t in wildcards:
                try:
                    handle = t['handle']
                    # Decide se deve processar
                    if _should_process_target(handle):
                        ui_log("WATCHDOG", f"Processando: {t['original_handle']}", Colors.PRIMARY)
                        results = _scan_target(orch, t)
                        # Determine if there were changes based on presence of subdomains
                        has_changes = bool(results.get('subdomains', 0)) if isinstance(results, dict) else False
                        _record_scan_result(handle, has_changes)
                    else:
                        ui_log("WATCHDOG", f"Pulando (histórico recente): {t['original_handle']}", Colors.DIM)
                except KeyboardInterrupt:
                    ui_log("WATCHDOG", "Interrupção recebida. Encerrando o Watchdog...", Colors.WARNING)
                    return
                except Exception as e:
                    ui_log("ERR", f"Erro em {t.get('original_handle', 'unknown')}: {e}", Colors.ERROR)
            # End of processing wildcards
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
