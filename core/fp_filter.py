import json, re, os, logging
from core.ui_manager import ui_log, Colors

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

class FalsePositiveKiller:
    OOB=['interact.sh','oast.fun','oast.site','oast.live','canarytokens.com']
    WAF=re.compile(r'(cloudflare|attention required|incident id|request blocked)',re.I)
    SRC=re.compile(r'^\s*<(script|div|html|body)|^\s*(var |const |let |function )',re.I)
    FP_KW=['tech-detect','favicon','header-detect','waf-detect']
    PH=re.compile(r'(example\.com|changeme|test[_-]?token|placeholder|\[.*\])',re.I)
    NULL_VAL=re.compile(r'(?:null|undefined|nil|none|\{\}|\[\]|""|\'\'|<\?\w+\?>|{{.*}})',re.I)

    @classmethod
    def sanitize_findings(cls,fp):
        if not os.path.exists(fp) or os.path.getsize(fp)==0: return False
        cl=[]; kc=0; dc=""
        try:
            with open(fp) as f:
                for line_num, ln in enumerate(f, 1):
                    ln=ln.strip()
                    if not ln: continue
                    try:
                        d=json.loads(ln)
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON parse error at line {line_num}: {e}")
                        continue
                    tu=d.get('template-url','').lower()
                    if any(o in tu for o in cls.OOB):
                        if not d.get('extracted-results') and not d.get('curl-command'): kc+=1;dc="OOB";continue
                        if any(o in d.get('host','').lower() for o in cls.OOB): kc+=1;dc="OOB";continue
                    tid=d.get('template-id','')
                    if any(k in tid for k in cls.FP_KW): kc+=1;dc="FP";continue
                    er=d.get('extracted-results',[])
                    es=" ".join(er) if er else ""
                    if er:
                        if cls.WAF.search(es): kc+=1;dc="WAF";continue
                        fl=er[0].strip() if isinstance(er,list) else er.strip()
                        if cls.SRC.match(fl): kc+=1;dc="HTML";continue
                        if cls.PH.search(es): kc+=1;dc="PH";continue
                    if cls.NULL_VAL.search(es): kc+=1;dc="NULL_VAL";continue
                    if len(es.strip())<6: kc+=1;dc="Micro";continue
                    cl.append(ln)
        except Exception as e:
            logger.error(f"FP sanitization failed: {e}")
            return False
        if kc>0:
            with open(fp,'w') as f: f.write('\n'.join(cl))
            ui_log("FP TITANIUM",f"Eliminados {kc} FPs ({dc}).",Colors.ERROR);return True
        ui_log("FP TITANIUM","100% puro.",Colors.SUCCESS);return False
