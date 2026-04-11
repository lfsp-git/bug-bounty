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
    set_worker_context, _WORKER_SLOTS, ui_interrupt_requested,
)
from core.intel import AIClient, IntelMiner, score_watchdog_target
from core.notifier import NotificationDispatcher

GLOBAL_TARGETS_HISTORY = "recon/baselines/global_targets.txt"
SCAN_HISTORY_FILE = "recon/baselines/target_scan_history.txt"
SLEEP_MIN = WATCHDOG_SLEEP_MIN
SLEEP_MAX = WATCHDOG_SLEEP_MAX
MAX_TARGETS_PER_CYCLE = WATCHDOG_MAX_TARGETS
MAX_PARALLEL_WORKERS = WATCHDOG_WORKERS
_ADAPTIVE_SLEEP_MIN = max(1800, SLEEP_MIN // 2)
_ADAPTIVE_SLEEP_MAX = SLEEP_MAX * 2
_EMPTY_CYCLE_RETRY_SECONDS = 900

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
    h1_u = os.getenv("H1_USER", "")
    h1_t = os.getenv("H1_TOKEN", "")
    it_t = os.getenv("IT_TOKEN", "")
    # Note: subprocess list args are passed directly — no shell quoting needed

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
        return _load_targets_from_history()

    tasks = []
    if h1_u and h1_t:
        tasks.append(("h1", [bbscope_path, "h1", "-b", "-o", "t", "-u", h1_u, "-t", h1_t, "--active-only"], TOOL_TIMEOUTS.get("uncover", 90)))
    if it_t:
        tasks.append(("it", [bbscope_path, "it", "-b", "-o", "t", "-t", it_t], TOOL_TIMEOUTS.get("uncover", 90)))

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


def _load_targets_from_history():
    """Fallback targets when API collection is unavailable."""
    if not os.path.exists(GLOBAL_TARGETS_HISTORY):
        return []
    try:
        with open(GLOBAL_TARGETS_HISTORY, "r", encoding="utf-8") as f:
            raw_list = [line.strip() for line in f if line.strip()]
        if raw_list:
            ui_log("WATCHDOG", f"Fallback: usando {len(raw_list)} alvos do historico local.", Colors.WARNING)
        return _process_raw_to_targets(raw_list)
    except OSError as e:
        logging.warning(f"Failed to read watchdog fallback history: {e}")
        return []

def _normalize_target_domain(raw: str) -> list:
    """Normalize a raw bbscope target string into a list of clean domains.
    
    Handles: *.domain.com, https://domain.com/path/*, domain.*, comma-separated lists.
    Returns [] for unparseable or too-broad patterns.
    """
    import re as _re
    raw = raw.lower().strip()
    if not raw:
        return []
    # Split comma-separated domains first
    parts = [p.strip() for p in raw.split(',') if p.strip()]
    result = []
    for part in parts:
        # Strip protocol
        part = _re.sub(r'^https?://', '', part)
        # Strip path/query/fragment (anything after first / or ? or #)
        part = _re.sub(r'[/?#].*$', '', part)
        # Strip port
        part = _re.sub(r':\d+$', '', part)
        part = part.strip()
        if not part:
            continue
        # TLD wildcard like "domain.*" — too broad, skip
        if part.endswith('.*'):
            continue
        # Leading wildcard like "*.domain.com" → "domain.com"
        if part.startswith('*.'):
            part = part[2:]
        # Must look like a valid domain (has at least one dot)
        if '.' not in part:
            continue
        result.append(part)
    return result


def _process_raw_to_targets(raw_list):
    history = to_set([])
    if os.path.exists(GLOBAL_TARGETS_HISTORY):
        with open(GLOBAL_TARGETS_HISTORY, 'r') as f:
            history = to_set(f.read().splitlines())

    valid_targets = []
    new_found = []

    for raw in raw_list:
        domains = _normalize_target_domain(raw)
        if not domains:
            continue
        # Use first domain as the canonical handle
        clean = domains[0]
        if any(b in clean for b in TARGET_BLACKLIST):
            continue
        if clean not in history:
            new_found.append(clean)
            history.add(clean)
        valid_targets.append({
            'handle': clean.replace('.', '_').replace('-', '_'),
            'original_handle': raw.strip(),
            'domains': domains,
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

_SCAN_HISTORY_TTL = 21600  # 6 hours — re-scan targets that weren't recently active

def _should_process_target(handle):
    from core.scanner import _DISABLE_RUNTIME_CACHE
    if _DISABLE_RUNTIME_CACHE:
        return True
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
            if time.time() - scan_time < _SCAN_HISTORY_TTL:
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
        if ui_interrupt_requested():
            return {'success': False, 'handle': handle, 'reason': 'interrupted'}
        if _should_process_target(handle):
            ui_worker_register(worker_id, target['original_handle'], idx, total)
            results = _scan_target(orch, target)
            has_changes = bool(results.get('subdomains', 0)) if isinstance(results, dict) else False
            _record_scan_result(handle, has_changes)
            if results and isinstance(results, dict):
                ui_worker_done(worker_id, results)
            return {'success': True, 'handle': handle, 'worker': worker_id, 'changes': has_changes, 'results': results}
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


def _compute_next_sleep_seconds(cycle_metrics: dict) -> int:
    targets = int(cycle_metrics.get("targets", 0))
    changed = int(cycle_metrics.get("changed", 0))
    errors = int(cycle_metrics.get("errors", 0))
    if targets == 0:
        return _EMPTY_CYCLE_RETRY_SECONDS
    change_ratio = (changed / targets) if targets > 0 else 0.0

    # Adaptive policy:
    # - high change ratio => faster cycle
    # - no changes and errors => slower cycle
    # - default stays around configured midpoint
    if change_ratio >= 0.30:
        return max(_ADAPTIVE_SLEEP_MIN, SLEEP_MIN)
    if change_ratio == 0.0 and errors == 0:
        return min(_ADAPTIVE_SLEEP_MAX, SLEEP_MAX + 1800)
    if errors > max(1, targets // 3):
        return min(_ADAPTIVE_SLEEP_MAX, SLEEP_MAX + 3600)
    return random.randint(SLEEP_MIN, SLEEP_MAX)

def run_watchdog():
    from core.runner import set_record_tool_times, set_runtime_cache_enabled
    set_record_tool_times(False)
    set_runtime_cache_enabled(False)

    ui_enable_watchdog_mode()
    ui_log("WATCHDOG", f"Modo WATCHDOG PREDADOR ativo. {MAX_PARALLEL_WORKERS} workers paralelos.", Colors.SUCCESS)

    _cycle_num = 0
    while not ui_interrupt_requested():
        _cycle_num += 1
        ui_cycle_started()
        ts = datetime.now().strftime('%H:%M')
        ui_log("WATCHDOG", f"=== CICLO {ts} ===", Colors.BOLD)
        wildcards = _fetch_global_wildcards()

        if wildcards:
            wildcards = _prioritize_targets_by_bounty_potential(wildcards)
            ui_log("WATCHDOG", f"{len(wildcards)} alvos | {MAX_PARALLEL_WORKERS} workers paralelos", Colors.DIM)

            from core.runner import ProOrchestrator

            total = len(wildcards)
            cycle_metrics = {"targets": total, "changed": 0, "errors": 0, "phase_seconds": {"recon": 0.0, "vulnerability": 0.0}}
            tasks = []
            for idx, target in enumerate(wildcards, 1):
                orch = ProOrchestrator(IntelMiner(AIClient()))
                tasks.append((orch, target, idx, total))

            executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS)
            futures = [executor.submit(_scan_target_parallel_wrapper, t) for t in tasks]
            try:
                for future in as_completed(futures):
                    result = future.result()
                    if result.get('success'):
                        w = result.get('worker', '?')
                        ui_log("WATCHDOG", f"[{w}] Concluido: {result['handle']}", Colors.SUCCESS)
                        if result.get("changes"):
                            cycle_metrics["changed"] += 1
                        payload = result.get("results", {})
                        metrics = payload.get("metrics", {}).get("phase_duration_seconds", {})
                        cycle_metrics["phase_seconds"]["recon"] += float(metrics.get("recon", 0.0))
                        cycle_metrics["phase_seconds"]["vulnerability"] += float(metrics.get("vulnerability", 0.0))
                    else:
                        if result.get("reason") not in ("cached", "interrupted"):
                            cycle_metrics["errors"] += 1
            except KeyboardInterrupt:
                ui_log("WATCHDOG", "Interrupcao recebida. Cancelando workers...", Colors.WARNING)
                executor.shutdown(wait=False, cancel_futures=True)
                return
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
            if cycle_metrics["targets"] > 0:
                avg_recon = cycle_metrics["phase_seconds"]["recon"] / cycle_metrics["targets"]
                avg_vuln = cycle_metrics["phase_seconds"]["vulnerability"] / cycle_metrics["targets"]
                ui_log(
                    "WATCHDOG",
                    f"Metricas ciclo: changed={cycle_metrics['changed']}/{cycle_metrics['targets']} "
                    f"errors={cycle_metrics['errors']} avg_recon={avg_recon:.1f}s avg_vuln={avg_vuln:.1f}s",
                    Colors.DIM,
                )
        else:
            cycle_metrics = {"targets": 0, "changed": 0, "errors": 0}
            avg_recon = 0.0
            avg_vuln = 0.0

        secs = _compute_next_sleep_seconds(cycle_metrics)
        wake = (datetime.now() + timedelta(seconds=secs)).strftime('%H:%M')
        next_cycle_label = f"{secs//3600}h{(secs%3600)//60}m"
        ui_log("WATCHDOG", f"Dormindo ate {wake} ({next_cycle_label})", Colors.DIM)

        # Discord heartbeat — rain-check after each cycle
        try:
            NotificationDispatcher.alert_watchdog_heartbeat(
                cycle=_cycle_num,
                targets_scanned=cycle_metrics.get("targets", 0),
                errors=cycle_metrics.get("errors", 0),
                avg_recon_s=avg_recon,
                avg_vuln_s=avg_vuln,
                next_cycle_in=next_cycle_label,
            )
        except Exception as _hb_err:
            logging.debug(f"Heartbeat Discord falhou: {_hb_err}")

        for _ in range(secs):
            if ui_interrupt_requested():
                ui_log("WATCHDOG", "Interrupcao durante sleep. Encerrando...", Colors.WARNING)
                return
            time.sleep(1)

if __name__ == "__main__":
    try:
        run_watchdog()
    except KeyboardInterrupt:
        ui_log("WATCHDOG", "Interrupcao recebida (main). Encerrando...", Colors.WARNING)
