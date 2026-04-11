"""Hunt3r Clean Mode — purge all caches and temp files, update tools and deps, run tests."""
import os
import sys
import shutil
import subprocess
import glob as _glob
from core.ui import ui_log, Colors

# ── Files / directories to wipe ──────────────────────────────────────────────

_FILES = [
    "recon/tool_times.json",            # ETA prediction cache
    "recon/cache/notifier_dedup.json",  # notification dedup
    "recon/baselines/target_scan_history.txt",  # watchdog skip-list
    "recon/baselines/api_wildcards.txt",         # platform API cache
    "recon/baselines/global_targets.txt",        # aggregated target list
    ".last_update_cache",               # tool auto-update timestamps
    "resume.cfg",                       # partial mission state
    "activity.log",                     # previous activity log
]

_DIRS = [
    "recon/baselines",  # per-target scan data + intermediate tool outputs
    "__pycache__",
    "core/__pycache__",
    "recon/__pycache__",
    "models/__pycache__",
    "tests/__pycache__",
]

_GLOB_PATTERNS = [
    "recon/baselines/**/*.httpx",
    "recon/baselines/**/*.katana",
    "recon/baselines/**/*.js_secrets",
    "recon/baselines/**/*.dnsx",
    "recon/baselines/**/findings.jsonl",
    "**/__pycache__",
    "**/*.pyc",
]


def _step(label: str, msg: str, color=Colors.INFO):
    ui_log(label, msg, color)


def _remove_file(path: str):
    try:
        if os.path.exists(path):
            os.remove(path)
            _step("CLEAN", f"Removido: {path}", Colors.DIM)
    except OSError as e:
        _step("CLEAN", f"Erro ao remover {path}: {e}", Colors.WARNING)


def _remove_dir(path: str, keep_root=False):
    """Remove all contents of a directory; optionally keep the root."""
    try:
        if not os.path.isdir(path):
            return
        if keep_root:
            for entry in os.scandir(path):
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path, ignore_errors=True)
                else:
                    os.remove(entry.path)
            _step("CLEAN", f"Limpo: {path}/", Colors.DIM)
        else:
            shutil.rmtree(path, ignore_errors=True)
            _step("CLEAN", f"Removido: {path}/", Colors.DIM)
    except OSError as e:
        _step("CLEAN", f"Erro ao limpar {path}: {e}", Colors.WARNING)


def _purge_caches():
    _step("CLEAN", "── Purging caches & temp files ──", Colors.WARNING)

    # Explicit files
    for f in _FILES:
        _remove_file(f)

    # Keep recon/baselines dir but wipe its contents
    # (platform API cache files listed above are already deleted individually)
    if os.path.isdir("recon/baselines"):
        _remove_dir("recon/baselines", keep_root=True)

    # __pycache__ dirs
    for root, dirs, _ in os.walk("."):
        for d in dirs:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)

    # .pyc files
    for pyc in _glob.glob("**/*.pyc", recursive=True):
        try:
            os.remove(pyc)
        except OSError:
            pass

    # Recreate required empty dirs
    os.makedirs("recon/baselines", exist_ok=True)
    os.makedirs("recon/cache", exist_ok=True)

    _step("CLEAN", "Cache limpo.", Colors.SUCCESS)


def _update_tools():
    _step("UPDATE", "── Atualizando ferramentas ──", Colors.WARNING)
    try:
        from core.updater import ToolUpdater
        upd = ToolUpdater()
        upd.update_all(force=True)
    except Exception as e:
        _step("UPDATE", f"Erro no updater: {e}", Colors.WARNING)


def _update_deps():
    _step("DEPS", "── Atualizando dependências Python ──", Colors.WARNING)
    # Priority: .venv pip → venv of current interpreter → pip3
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".venv", "bin", "pip"),
        os.path.join(os.path.dirname(sys.executable), "pip"),
        shutil.which("pip3") or "pip3",
    ]
    pip = next((c for c in candidates if os.path.isfile(c)), candidates[-1])
    result = subprocess.run(
        [pip, "install", "-r", "requirements.txt", "--quiet", "--upgrade"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        _step("DEPS", "requirements.txt instalado/atualizado.", Colors.SUCCESS)
    else:
        _step("DEPS", f"Pip falhou: {result.stderr.strip()[:120]}", Colors.WARNING)


def _run_tests():
    _step("TEST", "── Executando testes ──", Colors.WARNING)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=short"],
        capture_output=False
    )
    if result.returncode == 0:
        _step("TEST", "Todos os testes passaram.", Colors.SUCCESS)
    else:
        _step("TEST", "Alguns testes falharam. Verifique acima.", Colors.ERROR)
    return result.returncode == 0


def run_clean():
    """Full clean run: purge caches → update tools → update deps → run tests."""
    print()
    _step("CLEAN", "╔══ HUNT3R CLEAN MODE ══════════════════════════╗", Colors.SUCCESS)
    _step("CLEAN", "║ Limpeza de cache + update + testes            ║", Colors.SUCCESS)
    _step("CLEAN", "╚══════════════════════════════════════════════╝", Colors.SUCCESS)
    print()

    _purge_caches()
    print()
    _update_tools()
    print()
    _update_deps()
    print()
    ok = _run_tests()
    print()

    if ok:
        _step("CLEAN", "Hunt3r pronto para uma clean run! ✓", Colors.SUCCESS)
    else:
        _step("CLEAN", "Pronto, mas alguns testes falharam. Verifique antes de rodar.", Colors.WARNING)
