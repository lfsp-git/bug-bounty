"""
HUNT3R Watchdog -- Motor de Recon Continuo 24/7 (Logica do Predador)
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
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from core.config import (
    to_set,
    TOOL_TIMEOUTS,
    WATCHDOG_WORKERS,
    WATCHDOG_MAX_TARGETS,
    WATCHDOG_SLEEP_MIN,
    WATCHDOG_SLEEP_MAX,
)

home = os.path.expanduser("~")
os.environ["PATH"] += os.pathsep + os.path.join(home, "go", "bin") + os.pathsep + "/usr/local/bin"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ui import (
    ui_log, Colors, ui_enable_watchdog_mode, ui_set_mission_meta,
    ui_worker_register, ui_worker_done, ui_snapshot, ui_cycle_started,
    set_worker_context, _WORKER_SLOTS,
)
from core.intel import AIClient, IntelMiner, score_watchdog_target

GLOBAL_TARGETS_HISTORY = "recon/baselines/global_targets.txt"
SCAN_HISTORY_FILE = "recon/baselines/target_scan_history.txt"
SLEEP_MIN = WATCHDOG_SLEEP_MIN
SLEEP_MAX = WATCHDOG_SLEEP_MAX
MAX_TARGETS_PER_CYCLE = WATCHDOG_MAX_TARGETS
MAX_PARALLEL_WORKERS = WATCHDOG_WORKERS

TARGET_BLACKLIST = ['ui', 'spotify', 'gitlab', 'coinbase']

_worker_slot_lock = threading.Lock()
_worker_slot_idx = 0
_worker_slot_queue: "queue.Queue[str]" = queue.Queue()
for _wid in _WORKER_SLOTS[:MAX_PARALLEL_WORKERS]:
    _worker_slot_queue.put(_wid)

def _acquire_worker_slot() -> str:
    global _worker_slot_idx
    slots = _WORKER_SLOTS[:MAX_PARALLEL_WORKERS]
    with _worker_slot_lock:
        slot = slots[_worker_slot_idx % len(slots)]
        _worker_slot_idx += 1
    return slot

def _cleanup_disk(handle):
    base_path = f"recon/db/{handle}"
    for folder in ["crawling", "tmp", "logs_raw"]:
        path = os.path.join(base_path, folder)
        if os.path.exists(path):
            try:
                shutil.rmtree(path)
                ui_log("DISK", f"Limpeza: {handle}/{folder} removido.", Colors.DIM)
            except Exception as e:
                logging.error(f"Erro na limpeza de {path}: {e}")

def _scan_target(orch, target):
    try:
        return orch.start_mission(target)
    except Exception as e:
        ui_log("ERR", f"Scan failed for {target.get('original_handle','')}: {e}", Colors.ERROR)
        ui_snapshot("scan_error", f"{target.get('original_handle','unknown')}: {e}")
        return {}

def _fetch_global_wildcards():
    CACHE_FILE = "recon/baselines/api_wildcards.txt"
    if os.path.exists(CACHE_FILE):
        mtime = os.path.getmtime(CACHE_FILE)
        if (time.time() - mtime) < 43600:
            ui_log("WATCHDOG", "Usando cache local de wildcards (Cache < 12h).", Colors.DIM)
            with open(CACHE_FILE, 'r') as f:
                raw_list = [l.strip() for l in f if l.strip()]
            return _process_raw_to_targets(raw_list)

    ui_log("WATCHDOG", "Cache expirado. Sincronizando com APIs em paralelo...", Colors.PRIMARY)
    h1_u, h1_t = os.getenv("H1_USER"), os.getenv("H1_TOKEN")
    bc_t, it_t = os.getenv("BC_TOKEN"), os.getenv("IT_TOKEN")
    h1_u_safe = shlex.quote(h1_u) if h1_u else ""
    h1_t_safe = shlex.quote(h1_t) if h1_t else ""
    bc_t_safe  = shlex.quote(bc_t)  if bc_t  else ""
    it_t_safe  = shlex.quote(it_t)  if it_t  else ""

    all_raw = to_set([])
    threads = []
    lock = threading.Lock()

    def fetch_task(name, cmd, timeout):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0:
                targets = [l.strip() for l in res.stdout.split('\n') if "*" in l]
                with lock:
                    all_raw.update(to_set(targets))
                ui_log("WATCHDOG", f"{name.upper()} pronto ({len(targets)} alvos).", Colors.SUCCESS)
            else:
                ui_log("WATCHDOG", f"Falha no {name.upper()}.", Colors.WARNING)
        except subprocess.TimeoutExpired:
            ui_log("WATCHDOG", f"PULADO: {name.upper()} (Timeout excedido).", Colors.WARNING)

    from recon.tools import find_tool
    bbscope_path = find_tool("bbscope")
    if bbscope_path == "bbscope" and not shutil.which("bbscope"):
        ui_log("WATCHDOG", "bbscope nao encontrado. Pulando coleta de wildcards via API.", Colors.WARNING)
        return []

    tasks = []
    if h1_u_safe and h1_t_safe:
        tasks.append(("h1", [bbscope_path, "h1", "-b", "-o", "t", "-u", h1_u_safe, "-t", h1_t_safe, "--active-only"], TOOL_TIMEOUTS.get("uncover", 90)))
    if bc_t_safe:
        tasks.append(("bc", [bbscope_path, "bc", "-b", "-o", "t", "-t", bc_t_safe], TOOL_TIMEOUTS.get("uncover", 90)))
    if it_t_safe:
        tasks.append(("it", [bbscope_path, "it", "-b", "-o", "t", "-t", it_t_safe], TOOL_TIMEOUTS.get("uncover", 90)))

    for t_name, t_cmd, t_time in tasks:
        th = threading.Thread(target=fetch_task, args=(t_name, t_cmd, t_time))
        th.start()
        threads.append(th)

    for th in threads:
        th.join()

    if all_raw:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            f.write('\n'.join(list(all_raw)))

    return _process_raw_to_targets(list(all_raw))

def _process_raw_to_targets(raw_list):
    history = to_set([])
    if os.path.exists(GLOBAL_TARGETS_HISTORY):
        with open(GLOBAL_TARGETS_HISTORY, 'r') as f:
            history = to_set(f.read().splitlines())

    valid_targets = []
    new_found = []

    for raw in raw_list:
        clean = raw.lower().replace('*.', '').strip()
        if not clean or any(b in clean for b in TARGET_BLACKLIST):
            continue
        if clean not in history:
            new_found.append(clean)
            history.add(clean)
        valid_targets.append({
            'handle': clean.replace('.', '_'),
            'original_handle': clean,
            'domains': [clean],
            'score': 50
        })

    if new_found:
        os.makedirs(os.path.dirname(GLOBAL_TARGETS_HISTORY), exist_ok=True)
        with open(GLOBAL_TARGETS_HISTORY, 'a') as f:
            f.write('\n'.join(new_found) + '\n')
        ui_log("PREDADOR", f"{len(new_found)} NOVOS ALVOS DETECTADOS!", Colors.SUCCESS)

    return valid_targets[:MAX_TARGETS_PER_CYCLE]

def _prioritize_targets_by_bounty_potential(targets):
    scored_targets = []
    for target in targets:
        score, breakdown = score_watchdog_target(target)
        scored_targets.append((target, score, breakdown))

    scored_targets.sort(key=lambda x: x[1], reverse=True)

    if scored_targets:
        for target, score, _ in scored_targets[:3]:
            handle = target.get('original_handle', 'unknown')
            ui_log("BOUNTY", f"  {handle}: {score:.0f}/100", Colors.DIM)

    return [t[0] for t in scored_targets]

def _should_process_target(handle):
    history_file = SCAN_HISTORY_FILE
    os.makedirs(os.path.dirname(history_file), exist_ok=True)
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

    last_scan, has_changes = history.get(handle, (None, False))
    if last_scan and not has_changes:
        try:
            scan_time = time.mktime(time.strptime(last_scan, '%Y-%m-%d %H:%M:%S'))
            if time.time() - scan_time < 86400:
                return False
        except ValueError:
            pass
    return True

def _record_scan_result(handle, has_changes):
    history_file = SCAN_HISTORY_FILE
    os.makedirs(os.path.dirname(history_file), exist_ok=True)
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
    history[handle] = (time.strftime('%Y-%m-%d %H:%M:%S'), has_changes)
    with open(history_file, 'w') as f:
        for h_key, (timestamp, changed) in history.items():
            f.write(f"{h_key},{timestamp},{changed}\n")

def _scan_target_parallel_wrapper(args):
    orch, target, idx, total = args
    handle = target.get('handle', 'unknown')
    worker_id = _worker_slot_queue.get()
    set_worker_context(worker_id)

    try:
        if _should_process_target(handle):
            ui_worker_register(worker_id, target['original_handle'], idx, total)
            results = _scan_target(orch, target)
            has_changes = bool(results.get('subdomains', 0)) if isinstance(results, dict) else False
            _record_scan_result(handle, has_changes)
            if results and isinstance(results, dict):
                ui_worker_done(worker_id, results)
            return {'success': True, 'handle': handle, 'worker': worker_id, 'changes': has_changes}
        else:
            ui_log("WATCHDOG", f"[{idx}/{total}] Pulando (historico recente): {target['original_handle']}", Colors.DIM)
            return {'success': False, 'handle': handle, 'reason': 'cached'}
    except KeyboardInterrupt:
        raise
    except Exception as e:
        ui_log("ERR", f"[{worker_id}] Erro em {target.get('original_handle', 'unknown')}: {e}", Colors.ERROR)
        ui_snapshot("worker_error", f"[{worker_id}] {target.get('original_handle','')}: {e}")
        return {'success': False, 'handle': handle, 'reason': str(e)}
    finally:
        set_worker_context("W0")
        _worker_slot_queue.put(worker_id)

def run_watchdog():
    from core.runner import set_record_tool_times
    set_record_tool_times(False)

    ui_enable_watchdog_mode()
    ui_log("WATCHDOG", f"Modo WATCHDOG PREDADOR ativo. {MAX_PARALLEL_WORKERS} workers paralelos.", Colors.SUCCESS)

    while True:
        ui_cycle_started()
        ts = datetime.now().strftime('%H:%M')
        ui_log("WATCHDOG", f"=== CICLO {ts} ===", Colors.BOLD)
        wildcards = _fetch_global_wildcards()

        if wildcards:
            wildcards = _prioritize_targets_by_bounty_potential(wildcards)
            ui_log("WATCHDOG", f"{len(wildcards)} alvos | {MAX_PARALLEL_WORKERS} workers paralelos", Colors.DIM)

            from core.runner import ProOrchestrator

            total = len(wildcards)
            tasks = []
            for idx, target in enumerate(wildcards, 1):
                orch = ProOrchestrator(IntelMiner(AIClient()))
                tasks.append((orch, target, idx, total))

            with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
                futures = [executor.submit(_scan_target_parallel_wrapper, t) for t in tasks]
                try:
                    for future in as_completed(futures):
                        result = future.result()
                        if result.get('success'):
                            w = result.get('worker', '?')
                            ui_log("WATCHDOG", f"[{w}] Concluido: {result['handle']}", Colors.SUCCESS)
                except KeyboardInterrupt:
                    ui_log("WATCHDOG", "Interrupcao recebida. Cancelando workers...", Colors.WARNING)
                    executor.shutdown(wait=False)
                    return

        secs = random.randint(SLEEP_MIN, SLEEP_MAX)
        wake = (datetime.now() + timedelta(seconds=secs)).strftime('%H:%M')
        ui_log("WATCHDOG", f"Dormindo ate {wake} ({secs//3600}h{(secs%3600)//60}m)", Colors.DIM)
        try:
            time.sleep(secs)
        except KeyboardInterrupt:
            ui_log("WATCHDOG", "Interrupcao durante sleep. Encerrando...", Colors.WARNING)
            return

if __name__ == "__main__":
    try:
        run_watchdog()
    except KeyboardInterrupt:
        ui_log("WATCHDOG", "Interrupcao recebida (main). Encerrando...", Colors.WARNING)
