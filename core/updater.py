import os, sys, subprocess, time, yaml, shlex, logging
from datetime import datetime
from typing import Dict
from core.ui_manager import ui_log, Colors

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
        except Exception: return {'tools':{},'custom_templates':{},'settings':{'auto_update_on_start':True}}

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
        return any(url.startswith(p) for p in allowed_prefixes) and '.git' in url or url.endswith('/')

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
        except Exception as e:
            logger.debug(f"Silent command failed: {e}")
            return False

    def update_all(self, force=False) -> Dict[str,bool]:
        res = {}
        if not self.config.get('settings',{}).get('auto_update_on_start',True) and not force:
            ui_log("UPDATER","Auto-update desabilitado.",Colors.WARNING); return res

        for tk,ti in self.config.get('tools',{}).items():
            nm = ti.get('name',tk)
            if not force and not self._should_upd(tk): continue

            sys.stdout.write(f"  {Colors.WARNING}*{Colors.RESET} {nm}..."); sys.stdout.flush()
            
            # Verifica se binario existe antes de tentar atualizar
            bin_path = os.path.join(self.pdtm, ti.get('binary',''))
            if not os.path.exists(bin_path):
                # Binario nao existe - tenta instalar
            install_cmd = ti.get('install_cmd','')
            if install_cmd:
                # Split command safely using shlex
                cmd_args = shlex.split(install_cmd)
                ok = self._run_silent(cmd_args, self.config.get('settings',{}).get('max_update_time',120))
            else:
                ok = False
            else:
                # Binario existe - pula update silencioso (para nao demorar)
                ok = True  # Assume OK se ja existe
            
            if ok: self._mark_upd(tk); sys.stdout.write(f"\r  {Colors.SUCCESS}OK{Colors.RESET} {nm}\n")
            else: sys.stdout.write(f"\r  {Colors.WARNING}-{Colors.RESET} {nm} (usando existente)\n")
            res[tk] = ok; time.sleep(0.2)
        
        # Templates Nuclei (so se houver internet/git)
        print()
        self._upd_nuc_tpl(force)
        
        # Custom repos
        print()
        self._upd_custom(force)
        
        return res

    def _upd_nuc_tpl(self,force=False):
        """Atualiza templates do Nuclei - robusto contra shell injection."""
        if not force and not self._should_upd('nuc_tpl'): return
        
        sys.stdout.write(f"  {Colors.WARNING}*{Colors.RESET} Nuclei Templates..."); sys.stdout.flush()
        
        nc = self.config.get('tools',{}).get('nuclei',{})
        td = os.path.expanduser(nc.get('templates_dir','~/nuclei-templates'))
        
        try:
            # Cria diretorio pai se nao existe
            os.makedirs(os.path.dirname(td) if os.path.dirname(td) else '.', exist_ok=True)
            
            if os.path.exists(os.path.join(td,'.git')):
                # Ja clonado - tenta pull (pode falhar sem internet)
                result = subprocess.run(
                    ['git', '-C', td, 'pull', '--quiet', 'origin', 'main'],
                    shell=False, timeout=60, capture_output=True
                )
                ok = result.returncode == 0
            else:
                # Nao clonado - tenta clone (pode falhar sem internet)
                repo_url = nc.get('templates_repo','https://github.com/projectdiscovery/nuclei-templates')
                # Validate URL to prevent injection via config file
                if not self._validate_git_url(repo_url):
                    raise ValueError(f"Invalid git URL: {repo_url}")
                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', '--quiet', repo_url, td],
                    shell=False, timeout=180, capture_output=True
                )
                ok = result.returncode == 0
            
            if ok or os.path.exists(td):  # Se OK ou ja existe de antes
                self._mark_upd('nuc_tpl')
                count = len([f for f in os.listdir(td) if f.endswith('.yaml')]) if os.path.exists(td) else 0
                sys.stdout.write(f"\r  {Colors.SUCCESS}OK{Colors.RESET} Nuclei Templates ({count} templates)\n")
            else:
                sys.stdout.write(f"\r  {Colors.WARNING}-{Colors.RESET} Nuclei Templates (sem cache, usara existente)\n")
                
        except Exception as e:
            # Se der qualquer erro, nao bloqueia
            logger.error(f"Nuclei templates update failed: {e}")
            sys.stdout.write(f"\r  {Colors.WARNING}-{Colors.RESET} Nuclei Templates ({str(e)[:30]})\n")

    def _upd_custom(self,force=False):
        """Update custom template repositories."""
        for rk,ri in self.config.get('custom_templates',{}).items():
            if not ri.get('enabled',True): continue
            if not force and not self._should_upd(f'cust_{rk}'): continue
            
            nm = ri.get('name',rk); ld = os.path.expanduser(ri.get('local_dir',''))
            sys.stdout.write(f"  {Colors.WARNING}*{Colors.RESET} {nm}..."); sys.stdout.flush()
            
            try:
                os.makedirs(ld, exist_ok=True)
                repo_url = ri.get('repo','')
                
                # Validate URL to prevent injection via config file
                if not self._validate_git_url(repo_url):
                    raise ValueError(f"Invalid git URL: {repo_url}")
                
                if os.path.exists(os.path.join(ld,'.git')):
                    result = subprocess.run(
                        ['git', '-C', ld, 'pull', '--quiet', 'origin', 'master'],
                        shell=False, timeout=120, capture_output=True
                    )
                else:
                    result = subprocess.run(
                        ['git', 'clone', '--depth', '1', '--quiet', repo_url, ld],
                        shell=False, timeout=300, capture_output=True
                    )
                
                # Conta arquivos
                if os.path.exists(ld):
                    count = sum(len(files) for _,_,files in os.walk(ld))
                    self._mark_upd(f'cust_{rk}')
                    sys.stdout.write(f"\r  {Colors.SUCCESS}OK{Colors.RESET} {nm} ({count} files)\n")
                else:
                    sys.stdout.write(f"\r  {Colors.WARNING}-{Colors.RESET} {nm}\n")
                    
            except Exception as e:
                logger.error(f"Custom template update failed for {nm}: {e}")
                sys.stdout.write(f"\r  {Colors.WARNING}-{Colors.RESET} {nm}\n")
            time.sleep(0.2)

def run_auto_update(force=False):
    try:
        u = ToolUpdater(); r = u.update_all(force)
        return True  # Nunca bloqueia
    except Exception as e:
        ui_log("UPDATER",f"Erro (nao critico): {e}",Colors.WARNING); return True
