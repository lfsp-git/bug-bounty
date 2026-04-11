import os, sys, subprocess, time, yaml, shlex, shutil, logging
from datetime import datetime
from typing import Dict
from core.ui import ui_log, Colors, _buffer_append
from recon.tools import find_tool

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

class ToolUpdater:
    def __init__(self, cfg="config/tools_config.yaml"):
        self.cfg_path = cfg
        self.config = self._load_cfg()
        self.pdtm = os.environ.get("HUNT3R_PDTM_PATH", os.path.expanduser("~/.pdtm/go/bin/"))
        self.cache = ".last_update_cache"

    def _load_cfg(self):
        try:
            with open(self.cfg_path) as f: return yaml.safe_load(f)
        except (OSError, ValueError, yaml.YAMLError):
            return {'tools':{},'custom_templates':{},'settings':{'auto_update_on_start':True}}

    def _validate_git_url(self, url: str) -> bool:
        """Validate git URL to prevent injection attacks. Only allow HTTPS github URLs."""
        if not url or not isinstance(url, str):
            return False
        # Only allow HTTPS URLs from trusted sources
        allowed_prefixes = (
            'https://github.com/',
            'https://gitlab.com/',
            'https://bitbucket.org/',
        )
        return any(url.startswith(p) for p in allowed_prefixes)

    def _should_upd(self, name):
        if not os.path.exists(self.cache): return True
        try:
            with open(self.cache) as f: c = yaml.safe_load(f) or {}
            lu = c.get(name)
            if not lu: return True
            return (datetime.now()-datetime.fromisoformat(lu)).total_seconds()/3600 >= 24
        except Exception as e:
            logger.debug(f"Failed to check update cache for {name}: {e}")
            return True

    def _mark_upd(self, name):
        try:
            c = {}
            if os.path.exists(self.cache):
                with open(self.cache) as f: c = yaml.safe_load(f) or {}
            c[name] = datetime.now().isoformat()
            with open(self.cache,'w') as f: yaml.dump(c,f)
        except Exception as e:
            logger.debug(f"Failed to mark update for {name}: {e}")

    def _run_silent(self, cmd, to=120):
        """Execute command array silently. Never use shell=True."""
        try:
            r = subprocess.run(cmd, shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=to)
            return r.returncode == 0
        except KeyboardInterrupt:
            raise  # propagate so update_all can handle CTRL+C cleanly
        except Exception as e:
            logger.debug(f"Silent command failed: {e}")
            return False

    def _tool_exists(self, binary: str) -> bool:
        """Check if binary exists in pdtm dir, go/bin, or system PATH."""
        # Try pdtm path first
        if os.path.exists(os.path.join(self.pdtm, binary)):
            return True
        # Try find_tool (checks go/bin, /usr/local/bin, PATH)
        resolved = find_tool(binary)
        return resolved != binary or shutil.which(binary) is not None

    def _log_updater(self, msg: str):
        """Write to stdout only (no duplicate ui_log)."""
        sys.stdout.write(msg)
        sys.stdout.flush()

    def update_all(self, force=False) -> Dict[str,bool]:
        res = {}
        if not self.config.get('settings',{}).get('auto_update_on_start',True) and not force:
            ui_log("UPDATER","Auto-update desabilitado.",Colors.WARNING); return res

        try:
            for tk,ti in self.config.get('tools',{}).items():
                nm = ti.get('name',tk)
                if not force and not self._should_upd(tk): continue

                self._log_updater(f"  {Colors.WARNING}*{Colors.RESET} {nm}...")

                binary = ti.get('binary', '')
                if self._tool_exists(binary):
                    # Binary found — skip install, just mark OK
                    self._mark_upd(tk)
                    self._log_updater(f"\r  {Colors.SUCCESS}OK{Colors.RESET} {nm} (existente)\n")
                    res[tk] = True
                else:
                    install_cmd = ti.get('install_cmd','')
                    if install_cmd:
                        cmd_args = shlex.split(install_cmd)
                        ok = self._run_silent(cmd_args, self.config.get('settings',{}).get('max_update_time',120))
                    else:
                        ok = False
                    if ok:
                        self._mark_upd(tk)
                        self._log_updater(f"\r  {Colors.SUCCESS}OK{Colors.RESET} {nm}\n")
                    else:
                        self._log_updater(f"\r  {Colors.WARNING}-{Colors.RESET} {nm} (nao encontrado)\n")
                    res[tk] = ok
                time.sleep(0.05)

        except KeyboardInterrupt:
            self._log_updater(f"\r  {Colors.WARNING}!{Colors.RESET} Verificacao interrompida.\n")
            return res

        # Templates Nuclei
        print()
        self._upd_nuc_tpl(force)

        # Custom repos
        print()
        self._upd_custom(force)

        return res

    def _upd_nuc_tpl(self, force=False):
        """Atualiza templates do Nuclei via 'nuclei -update-templates'."""
        if not force and not self._should_upd('nuc_tpl'): return

        self._log_updater(f"  {Colors.WARNING}*{Colors.RESET} Nuclei Templates...")

        exe = find_tool("nuclei")
        td = os.path.expanduser('~/nuclei-templates')

        try:
            result = subprocess.run(
                [exe, "-update-templates"],
                shell=False, timeout=300, capture_output=True, text=True
            )
            ok = result.returncode == 0 or os.path.exists(td)

            if ok:
                self._mark_upd('nuc_tpl')
                count = sum(1 for root, _, files in os.walk(td) for f in files if f.endswith('.yaml'))
                self._log_updater(f"\r  {Colors.SUCCESS}OK{Colors.RESET} Nuclei Templates ({count} templates)\n")
            else:
                self._log_updater(f"\r  {Colors.WARNING}-{Colors.RESET} Nuclei Templates (falha)\n")

        except KeyboardInterrupt:
            self._log_updater(f"\r  {Colors.WARNING}!{Colors.RESET} Nuclei Templates (interrompido)\n")
            raise
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.error(f"Nuclei templates update failed: {e}")
            self._log_updater(f"\r  {Colors.WARNING}-{Colors.RESET} Nuclei Templates ({str(e)[:40]})\n")

    def _upd_custom(self, force=False):
        """Update custom template repositories."""
        for rk, ri in self.config.get('custom_templates',{}).items():
            if not ri.get('enabled', True): continue
            if not force and not self._should_upd(f'cust_{rk}'): continue

            nm = ri.get('name', rk)
            ld = os.path.expanduser(ri.get('local_dir',''))
            self._log_updater(f"  {Colors.WARNING}*{Colors.RESET} {nm}...")

            try:
                os.makedirs(ld, exist_ok=True)
                repo_url = ri.get('repo', '')

                if not self._validate_git_url(repo_url):
                    raise ValueError(f"Invalid git URL: {repo_url}")

                if os.path.exists(os.path.join(ld, '.git')):
                    result = subprocess.run(
                        ['git', '-C', ld, 'pull', '--quiet', 'origin', 'master'],
                        shell=False, timeout=120, capture_output=True
                    )
                else:
                    result = subprocess.run(
                        ['git', 'clone', '--depth', '1', '--quiet', repo_url, ld],
                        shell=False, timeout=300, capture_output=True
                    )

                if os.path.exists(ld):
                    count = sum(len(files) for _,_,files in os.walk(ld))
                    self._mark_upd(f'cust_{rk}')
                    self._log_updater(f"\r  {Colors.SUCCESS}OK{Colors.RESET} {nm} ({count} files)\n")
                else:
                    self._log_updater(f"\r  {Colors.WARNING}-{Colors.RESET} {nm}\n")

            except KeyboardInterrupt:
                self._log_updater(f"\r  {Colors.WARNING}!{Colors.RESET} {nm} (interrompido)\n")
                raise
            except (OSError, ValueError, subprocess.TimeoutExpired) as e:
                logger.error(f"Custom template update failed for {nm}: {e}")
                self._log_updater(f"\r  {Colors.WARNING}-{Colors.RESET} {nm}\n")
            time.sleep(0.05)

def run_auto_update(force=False):
    try:
        u = ToolUpdater(); r = u.update_all(force)
        return True  # Nunca bloqueia
    except Exception as e:
        ui_log("UPDATER",f"Erro (nao critico): {e}",Colors.WARNING); return True
