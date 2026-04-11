"""Hunt3r Clean Mode — purge all caches and temp files, update tools and deps, run tests."""
import os
import re
import sys
import shutil
import subprocess
import glob as _glob
from typing import Dict, List, Tuple
from core.ui import ui_log, Colors

# ── Files / directories to wipe ──────────────────────────────────────────────

_FILES = [
    "recon/tool_times.json",
    "recon/cache/notifier_dedup.json",
    "recon/baselines/target_scan_history.txt",
    "recon/baselines/api_wildcards.txt",
    "recon/baselines/global_targets.txt",
    ".last_update_cache",
    "resume.cfg",
    "activity.log",
]

_DIRS = [
    "recon/baselines",
    "__pycache__",
    "core/__pycache__",
    "recon/__pycache__",
    "models/__pycache__",
    "tests/__pycache__",
]

# ── Required / optional tools for health check ───────────────────────────────

_REQUIRED_TOOLS = ["subfinder", "dnsx", "httpx", "katana", "nuclei"]
_OPTIONAL_TOOLS = ["uncover", "naabu", "ffuf", "gau", "anew"]

# ── API keys to check (label, env_var, required?) ────────────────────────────

_API_KEYS: List[Tuple[str, str, bool]] = [
    ("OpenAI / OpenRouter", "OPENROUTER_API_KEY", False),
    ("HackerOne Token",     "H1_TOKEN",           True),
    ("Intigriti Token",     "IT_TOKEN",            False),
    ("Shodan",              "SHODAN_API_KEY",       False),
    ("Chaos (pdcp)",        "CHAOS_KEY",            False),
    ("Censys ID",           "CENSYS_API_ID",        False),
    ("Censys Secret",       "CENSYS_API_SECRET",    False),
    ("Telegram Token",      "TELEGRAM_BOT_TOKEN",   False),
    ("Telegram Chat ID",    "TELEGRAM_CHAT_ID",     False),
    ("Discord Webhook",     "DISCORD_WEBHOOK",      False),
]

_ML_MODEL = "models/fp_filter_v1.pkl"

_PDTM = os.environ.get("HUNT3R_PDTM_PATH", os.path.expanduser("~/.pdtm/go/bin/"))


def _step(label: str, msg: str, color=Colors.INFO):
    ui_log(label, msg, color)


def _mask(value: str) -> str:
    """Show first 4 chars + '***' for API key masking."""
    if len(value) <= 4:
        return "****"
    return value[:4] + "***"


# ─────────────────────────────────────────────────────────────────────────────
# Cache purge
# ─────────────────────────────────────────────────────────────────────────────

def _remove_file(path: str):
    try:
        if os.path.exists(path):
            os.remove(path)
            _step("CLEAN", f"Removido: {path}", Colors.DIM)
    except OSError as e:
        _step("CLEAN", f"Erro ao remover {path}: {e}", Colors.WARNING)


def _remove_dir(path: str, keep_root=False):
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
    for f in _FILES:
        _remove_file(f)
    if os.path.isdir("recon/baselines"):
        _remove_dir("recon/baselines", keep_root=True)
    for root, dirs, _ in os.walk("."):
        for d in dirs:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
    for pyc in _glob.glob("**/*.pyc", recursive=True):
        try:
            os.remove(pyc)
        except OSError:
            pass
    os.makedirs("recon/baselines", exist_ok=True)
    os.makedirs("recon/cache", exist_ok=True)
    _step("CLEAN", "Cache limpo.", Colors.SUCCESS)


# ─────────────────────────────────────────────────────────────────────────────
# Tool update
# ─────────────────────────────────────────────────────────────────────────────

def _update_tools():
    _step("UPDATE", "── Atualizando ferramentas ──", Colors.WARNING)
    try:
        from core.updater import ToolUpdater
        upd = ToolUpdater()
        upd.update_all(force=True)
    except Exception as e:
        _step("UPDATE", f"Erro no updater: {e}", Colors.WARNING)


# ─────────────────────────────────────────────────────────────────────────────
# Python deps
# ─────────────────────────────────────────────────────────────────────────────

def _update_deps() -> bool:
    _step("DEPS", "── Atualizando dependências Python ──", Colors.WARNING)
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(_root, ".venv", "bin", "pip"),
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
        return True
    if "externally-managed-environment" in result.stderr:
        result2 = subprocess.run(
            [pip, "install", "-r", "requirements.txt", "--quiet", "--upgrade",
             "--break-system-packages"],
            capture_output=True, text=True
        )
        if result2.returncode == 0:
            _step("DEPS", "requirements.txt instalado/atualizado.", Colors.SUCCESS)
            return True
        _step("DEPS", f"Pip falhou: {result2.stderr.strip()[:120]}", Colors.WARNING)
        return False
    _step("DEPS", f"Pip falhou: {result.stderr.strip()[:120]}", Colors.WARNING)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Tool health check
# ─────────────────────────────────────────────────────────────────────────────

def _tool_version(binary: str) -> str:
    """Try to get a short version string from a binary."""
    for flag in ("-version", "--version", "-v"):
        try:
            r = subprocess.run(
                [binary, flag],
                capture_output=True, text=True, timeout=5
            )
            out = (r.stdout + r.stderr).strip()
            # Extract first version-looking token (e.g. v1.2.3 or 1.2.3)
            m = re.search(r'v?(\d+\.\d+[\.\d]*)', out)
            if m:
                return f"v{m.group(1)}"
        except Exception:
            pass
    return ""


def _find_binary(name: str) -> str:
    """Find a tool binary in PDTM path first, then system PATH."""
    pdtm_path = os.path.join(_PDTM, name)
    if os.path.isfile(pdtm_path):
        return pdtm_path
    return shutil.which(name) or ""


def _check_tools() -> Dict[str, bool]:
    """Check all tools and report status. Returns {name: found} for required tools."""
    _step("TOOLS", "── Verificando ferramentas ──", Colors.WARNING)
    results: Dict[str, bool] = {}
    all_tools = [("required", t) for t in _REQUIRED_TOOLS] + [("optional", t) for t in _OPTIONAL_TOOLS]
    for kind, name in all_tools:
        path = _find_binary(name)
        found = bool(path)
        version = _tool_version(path) if found else ""
        if found:
            label = f"{Colors.SUCCESS}✓{Colors.RESET} {name:<12} {Colors.DIM}{version}{Colors.RESET}"
            _step("TOOLS", label, Colors.SUCCESS)
        elif kind == "required":
            _step("TOOLS", f"{Colors.ERROR}✗{Colors.RESET} {name:<12} {Colors.ERROR}NÃO ENCONTRADO (obrigatório){Colors.RESET}", Colors.ERROR)
        else:
            _step("TOOLS", f"{Colors.WARNING}–{Colors.RESET} {name:<12} {Colors.DIM}não instalado (opcional){Colors.RESET}", Colors.DIM)
        if kind == "required":
            results[name] = found
    return results


# ─────────────────────────────────────────────────────────────────────────────
# API key status
# ─────────────────────────────────────────────────────────────────────────────

def _check_api_keys() -> Dict[str, bool]:
    """Report which API keys are configured. Returns {label: set?} for required keys."""
    _step("APIKEYS", "── Status das chaves de API ──", Colors.WARNING)
    # Load .env if present so keys show even before dotenv is loaded
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    env_values: Dict[str, str] = {}
    if os.path.isfile(env_path):
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, _, v = line.partition("=")
                        env_values[k.strip()] = v.strip()
        except OSError:
            pass

    results: Dict[str, bool] = {}
    for label, var, required in _API_KEYS:
        val = os.getenv(var) or env_values.get(var, "")
        val = val.strip()
        set_flag = bool(val)
        if set_flag:
            _step("APIKEYS", f"{Colors.SUCCESS}✓{Colors.RESET} {label:<22} {Colors.DIM}{_mask(val)}{Colors.RESET}", Colors.SUCCESS)
        elif required:
            _step("APIKEYS", f"{Colors.ERROR}✗{Colors.RESET} {label:<22} {Colors.ERROR}NÃO CONFIGURADA (obrigatória){Colors.RESET}", Colors.ERROR)
        else:
            _step("APIKEYS", f"{Colors.WARNING}–{Colors.RESET} {label:<22} {Colors.DIM}não configurada{Colors.RESET}", Colors.DIM)
        results[label] = set_flag
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Uncover provider re-sync
# ─────────────────────────────────────────────────────────────────────────────

def _sync_providers():
    _step("UNCOVER", "── Sincronizando providers do uncover ──", Colors.WARNING)
    try:
        from recon.engines import _sync_uncover_providers
        enabled = _sync_uncover_providers()
        if enabled:
            _step("UNCOVER", f"Providers ativos: {', '.join(enabled)}", Colors.SUCCESS)
        else:
            _step("UNCOVER", "Nenhum provider configurado (Shodan/Censys não definidos).", Colors.WARNING)
    except Exception as e:
        _step("UNCOVER", f"Erro ao sincronizar providers: {e}", Colors.WARNING)


# ─────────────────────────────────────────────────────────────────────────────
# ML model check
# ─────────────────────────────────────────────────────────────────────────────

def _check_ml_model() -> bool:
    exists = os.path.isfile(_ML_MODEL)
    if exists:
        size_kb = os.path.getsize(_ML_MODEL) // 1024
        _step("ML", f"{Colors.SUCCESS}✓{Colors.RESET} Modelo ML encontrado: {_ML_MODEL} ({size_kb} KB)", Colors.SUCCESS)
    else:
        _step("ML", f"{Colors.WARNING}–{Colors.RESET} Modelo ML não encontrado: {_ML_MODEL} — FP filter rodará sem ML.", Colors.WARNING)
    return exists


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def _get_venv_python() -> str:
    """Return .venv/bin/python3 if it exists, else sys.executable."""
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    venv_py = os.path.join(_root, ".venv", "bin", "python3")
    return venv_py if os.path.isfile(venv_py) else sys.executable


def _run_tests() -> bool:
    _step("TEST", "── Executando testes ──", Colors.WARNING)
    python = _get_venv_python()
    result = subprocess.run(
        [python, "-m", "pytest", "tests/", "-q", "--tb=short"],
        capture_output=True, text=True
    )
    # Stream captured output through Hunt3r logger
    for line in result.stdout.splitlines():
        if line.strip():
            color = Colors.ERROR if ("FAILED" in line or "ERROR" in line) else \
                    Colors.SUCCESS if "passed" in line else Colors.DIM
            _step("TEST", line, color)
    if result.stderr.strip():
        for line in result.stderr.splitlines():
            if line.strip() and "warnings" not in line.lower():
                _step("TEST", line, Colors.DIM)
    ok = result.returncode == 0
    if ok:
        _step("TEST", "Todos os testes passaram. ✓", Colors.SUCCESS)
    else:
        _step("TEST", "Alguns testes falharam — verifique as linhas FAILED acima.", Colors.ERROR)
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(tools_ok: Dict[str, bool], deps_ok: bool, tests_ok: bool, ml_ok: bool):
    _step("SUMMARY", "── Health Report ──", Colors.WARNING)
    missing_tools = [t for t, ok in tools_ok.items() if not ok]
    _step("SUMMARY", f"{'Ferramentas obrigatórias':<30} {'✓ OK' if not missing_tools else '✗ ' + ', '.join(missing_tools)}", Colors.SUCCESS if not missing_tools else Colors.ERROR)
    _step("SUMMARY", f"{'Dependências Python':<30} {'✓ OK' if deps_ok else '✗ FALHOU'}", Colors.SUCCESS if deps_ok else Colors.ERROR)
    _step("SUMMARY", f"{'Modelo ML':<30} {'✓ presente' if ml_ok else '– ausente (opcional)'}", Colors.SUCCESS if ml_ok else Colors.WARNING)
    _step("SUMMARY", f"{'Testes':<30} {'✓ PASS' if tests_ok else '✗ FAIL'}", Colors.SUCCESS if tests_ok else Colors.ERROR)
    ready = not missing_tools and deps_ok and tests_ok
    print()
    if ready:
        _step("CLEAN", "Hunt3r pronto para uma clean run! ✓", Colors.SUCCESS)
    else:
        _step("CLEAN", "Hunt3r com problemas — veja o SUMMARY acima.", Colors.ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run_clean():
    """Full clean run: purge → update tools → update deps → health checks → tests → summary."""
    print()
    _step("CLEAN", "╔══ HUNT3R CLEAN MODE ══════════════════════════╗", Colors.SUCCESS)
    _step("CLEAN", "║ Limpeza de cache + update + health + testes   ║", Colors.SUCCESS)
    _step("CLEAN", "╚══════════════════════════════════════════════╝", Colors.SUCCESS)
    print()

    _purge_caches()
    print()
    _update_tools()
    print()
    deps_ok = _update_deps()
    print()
    tools_ok = _check_tools()
    print()
    _check_api_keys()
    print()
    _sync_providers()
    print()
    ml_ok = _check_ml_model()
    print()
    tests_ok = _run_tests()
    print()
    _print_summary(tools_ok, deps_ok, tests_ok, ml_ok)

