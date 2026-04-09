import os
import sys
import subprocess
import re
import shlex
import logging
import shutil
from core.ui_manager import ui_log, Colors

PDTM = os.environ.get("HUNT3R_PDTM_PATH", os.path.expanduser("~/.pdtm/go/bin/"))

def apply_sniper_filter(inp, outp):
    """Remove lixo de infraestrutura (Cloudflare NS) antes do HTTPX."""
    deny = [r'\.ns\.cloudflare\.com$', r'\.secondary\.cloudflare\.com$', r'^cf-\d{1,3}-', r'^ssl\d+\.cloudflare\.com$']
    rx = re.compile('|'.join(deny))
    juicy = []
    if not os.path.exists(inp): return inp
    with open(inp, 'r', encoding='utf-8', errors='ignore') as f:
        for l in f:
            t = l.strip()
            if t and not rx.search(t): juicy.append(t)
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    with open(outp, 'w', encoding='utf-8') as f: f.write('\n'.join(juicy))
    return outp

def run_cmd(cmd_list, label, outp, stats_pipe=None):
    """Motor de Execução silencioso (Subprocess blindado)"""
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    
    # Prepara a saída de log de estatísticas (para o Nuclei)
    stderr_dest = open(stats_pipe, 'w', encoding='utf-8') if stats_pipe else subprocess.DEVNULL

    try:
        logging.info(f"START {label} | CMD: {' '.join(cmd_list)}")
        subprocess.run(
            cmd_list,
            stdout=subprocess.DEVNULL, # O resultado vai pro arquivo (-o), não pra tela
            stderr=stderr_dest,
            timeout=1800 # Timeout de segurança (30 minutos por ferramenta)
        )
    except Exception as e:
        logging.error(f"{label} error: {e}")
    finally:
        if stats_pipe and not stderr_dest.closed:
            stderr_dest.close()

def run_subfinder(domain, output_file, aggressive=False):
    cmd = [f"{PDTM}subfinder", "-d", domain, "-o", output_file, "-silent"]
    if aggressive:
        cmd.extend(["-all"])
    run_cmd(cmd, "Subfinder", output_file)

def run_dnsx(input_file, output_file):
    cmd = [f"{PDTM}dnsx", "-l", input_file, "-o", output_file, "-silent", "-a", "-cname", "-ptr"]
    run_cmd(cmd, "DNSX", output_file)

def run_uncover(domain, output_file, shodan_key=None, censys_id=None, censys_secret=None):
    if not shodan_key and not censys_id:
        # Cria arquivo vazio se não tiver chaves
        open(output_file, 'w').close()
        return
        
    cmd = [f"{PDTM}uncover", "-q", domain, "-o", output_file, "-silent"]
    
    engines = []
    if shodan_key: engines.append("shodan")
    if censys_id: engines.append("censys")
    
    if engines:
        cmd.extend(["-e", ",".join(engines)])
        
    run_cmd(cmd, "Uncover", output_file)

def run_httpx(input_file, output_file):
    cmd = [
        f"{PDTM}httpx", "-l", input_file, "-o", output_file, "-silent", 
        "-title", "-tech-detect", "-status-code", "-follow-redirects"
    ]
    run_cmd(cmd, "HTTPX", output_file)

def run_katana_surgical(input_file, output_file, score, extra_flags=""):
    """
    Roda o Katana. 
    extra_flags agora são separados com segurança por shlex.split para evitar pastas com nomes bizarros.
    """
    cmd = [f"{PDTM}katana", "-list", input_file, "-o", output_file, "-silent"]
    
    # Injeta as flags extras de forma segura!
    if extra_flags:
        cmd.extend(shlex.split(extra_flags))
        
    run_cmd(cmd, "Katana", output_file)

def run_nuclei(input_file, output_file, tags="", stats_pipe=None, extra_flags=""):
    """
    Roda o Nuclei.
    Separação de tags e flags táticas resolvidas.
    """
    cmd = [f"{PDTM}nuclei", "-l", input_file, "-o", output_file]
    
    if tags:
        cmd.extend(["-tags", tags])
        
    # Injeta as flags do orquestrador (jsonl, silent, max-host-error, etc) de forma segura!
    if extra_flags:
        cmd.extend(shlex.split(extra_flags))

    # O stats-pipe permite que a nossa UI do terminal mostre os reqs/s e o tempo restante!
    run_cmd(cmd, "Nuclei", output_file, stats_pipe)

