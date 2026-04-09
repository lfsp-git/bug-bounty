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
    def sanitize_findings(cls, findings_file):
        """Remove false positives from findings file using structured filter chain."""
        if not os.path.exists(findings_file) or os.path.getsize(findings_file) == 0: 
            return False
        
        valid_findings = []
        fp_count = 0
        last_fp_reason = ""
        
        try:
            with open(findings_file) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line: 
                        continue
                    
                    try:
                        finding = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON parse error at line {line_num}: {e}")
                        continue
                    
                    # Structured filter chain - check each condition
                    fp_reason = cls._check_filters(finding)
                    if fp_reason:
                        fp_count += 1
                        last_fp_reason = fp_reason
                        continue
                    
                    valid_findings.append(line)
        
        except Exception as e:
            logger.error(f"FP sanitization failed: {e}")
            return False
        
        # Write cleaned findings and report
        if fp_count > 0:
            with open(findings_file, 'w') as f: 
                f.write('\n'.join(valid_findings))
            ui_log("FP TITANIUM", f"Eliminados {fp_count} FPs ({last_fp_reason}).", Colors.ERROR)
            return True
        
        ui_log("FP TITANIUM", "100% puro.", Colors.SUCCESS)
        return False
    
    @classmethod
    def _check_filters(cls, finding: dict) -> str:
        """Check all FP filters. Returns filter name if match (reason for rejection), else empty string."""
        template_url = finding.get('template-url', '').lower()
        template_id = finding.get('template-id', '')
        extracted_results = finding.get('extracted-results', [])
        extracted_str = " ".join(extracted_results) if extracted_results else ""
        host = finding.get('host', '').lower()
        
        # Filter 1: OOB detection services (false positives)
        if any(oob in template_url for oob in cls.OOB):
            if not extracted_results and not finding.get('curl-command'):
                return "OOB"
            if any(oob in host for oob in cls.OOB):
                return "OOB"
        
        # Filter 2: Technology/WAF detection templates (not true vulns)
        if any(keyword in template_id for keyword in cls.FP_KW):
            return "FP"
        
        # Filter 3: WAF fingerprints (false positives)
        if extracted_results and cls.WAF.search(extracted_str):
            return "WAF"
        
        # Filter 4: HTML/Script source code leaks (not exploitable)
        if extracted_results:
            first_result = extracted_results[0].strip() if isinstance(extracted_results, list) else extracted_results.strip()
            if cls.SRC.match(first_result):
                return "HTML"
        
        # Filter 5: Placeholder/example strings
        if cls.PH.search(extracted_str):
            return "PH"
        
        # Filter 6: Null/empty values
        if cls.NULL_VAL.search(extracted_str):
            return "NULL_VAL"
        
        # Filter 7: Micro findings (too short to be real)
        if len(extracted_str.strip()) < 6:
            return "Micro"
        
        return ""  # Passed all filters
