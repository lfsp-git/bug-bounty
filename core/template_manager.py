import os
import subprocess
import logging
import shlex
from core.ui_manager import ui_log, Colors

def update_nuclei_templates():
    """Atualiza Nuclei templates oficiais (leve, ~5s). Security: shell=False."""
    try:
        nuclei_bin = os.path.expanduser("~/.pdtm/go/bin/nuclei")
        if not os.path.exists(nuclei_bin):
            nuclei_bin = "nuclei"  # Fallback to PATH
        subprocess.run(
            [nuclei_bin, '-update'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            shell=False
        )
    except Exception as e:
        logging.debug(f"Nuclei update failed: {e}")
        pass

def fetch_custom_templates():
    """Atualiza PayloadsAllTheThings (usado manualmente, não a cada scan)."""
    pat_dir = "recon/custom_templates/payloadsallthethings"
    if not os.path.exists(pat_dir): return
    if os.path.exists(os.path.join(pat_dir, '.git')):
        try:
            subprocess.run(
                ['git', '-C', pat_dir, 'pull', '--quiet'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                shell=False
            )
        except Exception as e:
            logging.debug(f"Git pull failed: {e}")
    else:
        try:
            subprocess.run(
                ['git', 'clone', '--depth', '1', '-q', 'https://github.com/swisskyrepo/PayloadsAllTheThings.git', pat_dir],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
                shell=False
            )
        except Exception as e:
            logging.error(f"Erro clone PAT: {e}")