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

def _fetch_global_wildcards():
    """Coleta alvos das APIs com cache de 12h e execução em paralelo."""
    CACHE_FILE = "recon/baselines/api_wildcards.txt"
    
    # 1. Lógica de Cache (Só gasta API e tempo uma vez a cada 12 horas)
    if os.path.exists(CACHE_FILE):
        mtime = os.path.getmtime(CACHE_FILE)
        if (time.time() - mtime) < 43200: # 12 horas
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

def _scan_target(orch, target):
    handle = target['handle']
    ui_log("WATCHDOG", f"Iniciando Scan: {target['original_handle']}", Colors.PRIMARY)
    orch.start_mission(handle, target['domains'], f"recon/db/{handle}", target['score'])
    _cleanup_disk(handle)

def run_watchdog():
    ui_log("WATCHDOG", "Modo WATCHDOG PREDADOR ativo.", Colors.SUCCESS)
    while True:
        # Removida a chamada antiga de ui_live_view_start()
        ui_clear_and_banner() # Chama o novo banner aqui
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
                    _scan_target(orch, t)
                except KeyboardInterrupt:
                    ui_log("WATCHDOG", "Interrupção recebida. Encerrando o Watchdog...", Colors.WARNING)
                    # Removida a chamada antiga de ui_live_view_stop()
                    sys.exit(0) # Encerra o script
                except Exception as e:
                    ui_log("ERR", f"Erro em {t['original_handle']}: {e}", Colors.ERROR)
        
        secs = random.randint(SLEEP_MIN, SLEEP_MAX)
        ui_log("WATCHDOG", f"Dormindo até {(datetime.now() + timedelta(seconds=secs)).strftime('%H:%M')}", Colors.DIM)
        time.sleep(secs)

if __name__ == "__main__":
    run_watchdog()
