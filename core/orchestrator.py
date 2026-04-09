import os, sys, time, threading, math, json, logging
from core.ui_manager import ui_mission_header, ui_log, ui_update_status, ui_scan_summary, Colors

_SPIN = ['-', '\\', '|', '/']

_CACHE_TIMES = "recon/tool_times.json"

def _load_tool_times():
    """Load persisted tool execution times for ETA calculation."""
    if os.path.exists(_CACHE_TIMES):
        try:
            with open(_CACHE_TIMES, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_tool_times(data):
    try:
        os.makedirs(os.path.dirname(_CACHE_TIMES), exist_ok=True)
        with open(_CACHE_TIMES, 'w') as f:
            json.dump(data, f)
    except Exception:
        pass

def _record_tool_time(label, elapsed):
    """Persist elapsed time for future ETA. Keeps last 5 runs per tool."""
    data = _load_tool_times()
    key = label.split(' [')[0]
    history = data.get(key, [])
    history.append(elapsed)
    data[key] = history[-5:]
    _save_tool_times(data)
    return data.get(key, [])

_MOVAVG_CACHE = {}

def _get_tool_times(label):
    """Retrieve running averages for ETA. Loads once per mission."""
    global _MOVAVG_CACHE
    if not _MOVAVG_CACHE:
        _MOVAVG_CACHE = _load_tool_times()
    key = label.split(' [')[0]
    return _MOVAVG_CACHE.get(key, [])

_spin_mutex = threading.Lock()

def _parse_nuclei_stats(stats_path):
    """Extract Nuclei stats JSON. Returns compact display with reqs/total if available."""
    if not stats_path or not os.path.exists(stats_path):
        return None
    try:
        last_json = None
        with open(stats_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith('{'):
                    last_json = line
        if not last_json:
            return None
        stat = json.loads(last_json)
        pct = min(99, stat.get('percent', 0))
        matched = stat.get('matched', 0)
        rps = stat.get('rps', 0)
        reqs = stat.get('requests', 0)
        total = stat.get('total', None)

        if total is None and pct > 0 and reqs > 0:
            total = int(reqs / (pct / 100.0))

        if total is not None:
            req_display = f"{reqs}/{total}"
        else:
            req_display = str(reqs)

        return f"{pct}% | {req_display} reqs | {matched} matched | {rps} rps"
    except Exception:
        return None

def _tool_progress(label, stop_event, live_tail_pipe=None, on_done=None):
    """Single-line spinner with ETA. Nuclei stats are appended inline.
    Uses _spin_mutex to avoid overlapping with ui_log output."""
    idx = 0; st = time.time()
    last_stats = [None] 

    while not stop_event.is_set():
        el = int(time.time() - st)

        eta_from_stats = None
        if live_tail_pipe:
            parsed = _parse_nuclei_stats(live_tail_pipe)
            if parsed:
                last_stats[0] = parsed
                try:
                    last_json = None
                    with open(live_tail_pipe, 'r', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('{'):
                                last_json = line
                    if last_json:
                        stat = json.loads(last_json)
                        rps = stat.get('rps', 0)
                        reqs = stat.get('requests', 0)
                        total = stat.get('total', None)
                        raw_pct = stat.get('percent', 0)
                        pct = min(99, raw_pct)
                        if total is None and raw_pct > 0 and reqs > 0:
                            total = int(reqs / (pct / 100.0))
                        if total is not None and rps > 0:
                            remaining = total - reqs
                            eta_from_stats = int(remaining / rps)
                except Exception:
                    pass

        parts = [f"  [{_SPIN[idx % 4]}] {label.ljust(18)} {el}s"]

        if eta_from_stats is not None and eta_from_stats > 0:
            eta_s = f"{eta_from_stats // 60}m {eta_from_stats % 60}s" if eta_from_stats > 60 else f"{eta_from_stats}s"
            parts.append(f"ETA: {eta_s}")
        else:
            history = _get_tool_times(label)
            avg = int(sum(history) / len(history)) if history else 0
            if avg > 10 and el < avg:
                eta = avg - el
                eta_s = f"{eta // 60}m {eta % 60}s" if eta > 60 else f"{eta}s"
                parts.append(f"ETA: {eta_s}")

        if live_tail_pipe and last_stats[0]:
            parts.append(Colors.DIM + last_stats[0] + Colors.RESET)

        status = "  ".join(parts)

        with _spin_mutex:
            os.write(sys.stdout.fileno(), (f"\r\033[K{status}").encode())

        idx += 1
        time.sleep(1)

    total = int(time.time() - st)
    if on_done:
        on_done(total)

def _run_with_progress(label, fn, live_tail_pipe=None):
    """Run a tool with spinner, ETA, and live tail."""
    ev = threading.Event()
    result_holder = [None]

    def on_done(elapsed):
        result_holder[0] = elapsed

    tw = threading.Thread(target=_tool_progress, args=(label, ev, live_tail_pipe, on_done), daemon=True)
    tw.start()
    try:
        fn()
    except KeyboardInterrupt:
        ev.set()
        tw.join(timeout=2)
        with _spin_mutex:
            os.write(sys.stdout.fileno(), b"\r\033[K")
        raise
    finally:
        ev.set(); tw.join(timeout=2)
        with _spin_mutex:
            os.write(sys.stdout.fileno(), b"\r\033[K")
        if result_holder[0] is not None:
            _record_tool_time(label, result_holder[0])


class ProOrchestrator:
    def __init__(self, intel):
        self.intel = intel
        self.ttl = 1800

    def is_cache_valid(self, fp):
        return os.path.exists(fp) and os.path.getsize(fp) > 0 and (time.time() - os.path.getmtime(fp)) < self.ttl

    def start_mission(self, handle, domains, base_path, score):
        ui_mission_header(handle, score)
        paths = {
            "sub": f"{base_path}/subdomains.txt",
            "sub_alive": f"{base_path}/subdomains_alive.txt",
            "htt": f"{base_path}/httpx.txt",
            "htt_urls": f"{base_path}/httpx_urls.txt",
            "end": f"{base_path}/endpoints.txt",
            "fin": f"{base_path}/findings.txt",
            "rep": f"{base_path}/ia_report.txt",
            "js": f"{base_path}/js_secrets.json",
        }

        ui_update_status("RECON", "Iniciando enumeracao...", Colors.PRIMARY)

        if not os.getenv("SHODAN_API_KEY") and not os.getenv("CENSYS_API_ID"):
            ui_log("PIPELINE", "SHODAN/CENSYS ausentes. Uncover sera ineficiente.", Colors.WARNING)

        shodan_sub = os.path.exists(os.path.expanduser("~/.config/subfinder/provider-config.yaml"))
        if not shodan_sub:
            ui_log("PIPELINE", "Subfinder sem APIs (provider-config.yaml). Resultado sera baixo.", Colors.ERROR)

        from core.diff_engine import ReconDiff
        baseline = ReconDiff.load_baseline(handle)
        if baseline:
            ui_log("DIFF", f"Baseline encontrada ({baseline.get('timestamp', '?')}). Calculando deltas apos scan...", Colors.INFO)

        run_sub = False
        aggressive_mode = score >= 70

        if not self.is_cache_valid(paths["sub"]):
            run_sub = True
        else:
            if aggressive_mode:
                with open(paths["sub"], 'r') as f: cached_count = sum(1 for _ in f)
                if cached_count < 50:
                    ui_log("SUBFINDER", f"Cache fraco ({cached_count} subs). Forcando agressivo...", Colors.WARNING)
                    run_sub = True
                else:
                    ui_log("SUBFINDER", f"Cacheado e robusto ({cached_count} subs).", Colors.SUCCESS)
            else:
                ui_log("SUBFINDER", "Cacheado (1h)", Colors.SUCCESS)

        if run_sub:
            from recon.engines import run_subfinder
            import tldextract

            tld = tldextract.TLDExtract(cache_dir=None)
            unique_roots = set()
            for d in domains:
                ext = tld(d)
                root = f"{ext.domain}.{ext.suffix}"
                unique_roots.add(root)

            total_roots = len(unique_roots)
            unique_subs = set()
            for idx, root in enumerate(list(unique_roots)):
                progress_label = f"SUB [{idx+1}/{total_roots}] {root[:20]}"
                temp_file = f"{base_path}/.sub_raw_{idx}.txt"
                _run_with_progress(progress_label, lambda tf=temp_file, r=root: run_subfinder(r, tf, aggressive=aggressive_mode))
                if os.path.exists(temp_file):
                    try:
                        with open(temp_file, 'r', errors='ignore') as f:
                            for line in f:
                                s = line.strip()
                                if s: unique_subs.add(s)
                        os.remove(temp_file)
                    except Exception as e:
                        logging.error(f"Erro ao ler temp {temp_file}: {e}")

            if unique_subs:
                with open(paths["sub"], 'w') as f:
                    f.write('\n'.join(sorted(unique_subs)))
                ui_log("SUBFINDER", f"Consolidados {len(unique_subs)} subdominios unicos.", Colors.SUCCESS)
            else:
                ui_log("SUBFINDER", "Nenhum subdominio encontrado.", Colors.WARNING)

        sub_count = 0
        if os.path.exists(paths["sub"]):
            with open(paths["sub"], 'r') as f: sub_count = sum(1 for _ in f)

        if sub_count == 0:
            ui_log("ABORTADO", "Nenhum subdominio encontrado.", Colors.ERROR); return

        if score >= 50 and sub_count < 10:
            ui_log("ANOMALIA", f"Apenas {sub_count} subs para alvo CRITICO. Possivel WAF/Api Limit.", Colors.ERROR)
            ui_log("DICA", "Pule este alvo ou use lista manual de subs.", Colors.WARNING)
            return

        if os.path.exists(paths["sub"]) and not self.is_cache_valid(paths["sub_alive"]):
            from recon.engines import run_dnsx
            _run_with_progress("DNSX", lambda: run_dnsx(paths["sub"], paths["sub_alive"]))
            if os.path.exists(paths["sub_alive"]):
                cnt = sum(1 for _ in open(paths["sub_alive"], 'r', errors='ignore'))
                ui_log("DNSX", f"{cnt} hosts ativos.", Colors.SUCCESS)
        else:
            ui_log("DNSX", "Cacheado (1h)", Colors.SUCCESS)

        if not os.path.exists(paths["sub_alive"]) or os.path.getsize(paths["sub_alive"]) == 0:
            ui_log("ABORTADO", "Sem DNS ativo.", Colors.ERROR); return

        from recon.engines import apply_sniper_filter
        pf = f"{base_path}/subdomains_alive_clean.txt"
        apply_sniper_filter(paths["sub_alive"], pf)
        tgt = pf if (os.path.exists(pf) and os.path.getsize(pf) > 0) else paths["sub_alive"]

        unc = f"{base_path}/uncover_urls.txt"
        if self.is_cache_valid(unc):
            ui_log("UNCOVER", "Cacheado (1h)", Colors.SUCCESS)
        else:
            from recon.engines import run_uncover
            _run_with_progress("Uncover", lambda: run_uncover(domains[0], unc, os.getenv("SHODAN_API_KEY"), os.getenv("CENSYS_API_ID"), os.getenv("CENSYS_API_SECRET")))
            if os.path.exists(unc):
                cnt = sum(1 for _ in open(unc, 'r', errors='ignore'))
                if cnt > 0:
                    with open(unc, 'r') as u, open(tgt, 'a') as t:
                        t.write("\n" + u.read())
                    ui_log("UNCOVER", f"+{cnt} URLs mescladas.", Colors.PRIMARY)
                else:
                    ui_log("UNCOVER", "Nenhum resultado.", Colors.DIM)

        try:
            with open(tgt, 'r') as f:
                all_t = [l.strip() for l in f if l.strip()]
            total = len(all_t)
        except Exception:
            total = 0

        if total == 0:
            ui_log("ABORTADO", "Sem alvos validos.", Colors.ERROR); return
        if os.path.exists(paths["fin"]):
            open(paths["fin"], 'w').close()
            import glob
            for f in glob.glob(f"{base_path}/*.shred_tmp_*"):
                os.remove(f)
            for f in glob.glob(f"{base_path}/*.dual_tmp*"):
                os.remove(f)
            for f in glob.glob(f"{base_path}/.nuclei_stats*.log"):
                os.remove(f)

        ui_log("MODE", f"Full-Scan ({total} subs)", Colors.INFO)
        self._scan(tgt, paths, handle, score)

        self._post_process(paths, handle, score)
        self._save_diff_and_baseline(handle, paths)

    def _save_diff_and_baseline(self, handle, paths):
        """Compute diff against baseline and save new baseline."""
        from core.diff_engine import ReconDiff

        subdomains = set()
        endpoints = set()
        js_secrets = set()

        for fpath, container in [(paths["sub"], subdomains), (paths["end"], endpoints)]:
            if os.path.exists(fpath):
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        for line in f:
                            s = line.strip()
                            if s:
                                container.add(s)
                except Exception:
                    pass

        if os.path.exists(paths["js"]):
            try:
                with open(paths["js"], 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                d = json.loads(line)
                                js_secrets.add(f"{d.get('type','?')}:{d.get('source','')}")
                            except ValueError:
                                pass
            except Exception:
                pass

        diff = ReconDiff.compute_diff(handle, subdomains, endpoints, js_secrets)
        baseline = ReconDiff.build_baseline_data(subdomains, endpoints, js_secrets)
        ReconDiff.save_baseline(handle, baseline)

        if diff['has_changes']:
            if diff['added_subs']:
                ui_log("DIFF NOVO", f"{len(diff['added_subs'])} subdominios novos detectados!", Colors.SUCCESS)
            if diff['added_endpoints']:
                ui_log("DIFF NOVO", f"{len(diff['added_endpoints'])} endpoints novos detectados!", Colors.PRIMARY)
            if diff['added_js_secrets']:
                ui_log("DIFF SECRETS", f"{len(diff['added_js_secrets'])} novos segredos JS detectados!", Colors.ERROR)

    def _post_process(self, paths, handle, score):
        def count_lines(f):
            if not os.path.exists(f): return 0
            with open(f, 'r', errors='ignore') as fh: return sum(1 for _ in fh)

        vuln_count = count_lines(paths["fin"])
        endpoint_count = count_lines(paths["end"])
        sub_count = count_lines(paths["sub"])
        alive_count = count_lines(paths["sub_alive"])
        js_secret_count = count_lines(paths["js"]) if "js" in paths else 0

        results = {
            'target': handle, 'score': score,
            'subdomains': sub_count, 'alive': alive_count,
            'endpoints': endpoint_count, 'vulns': vuln_count,
        }
        if js_secret_count > 0:
            results['js_secret_lines'] = js_secret_count

        ui_scan_summary(results)

        if vuln_count > 0:
            ui_update_status("IA", "Analisando vulnerabilidades...", Colors.SECONDARY)
            try:
                from core.fp_filter import FalsePositiveKiller
                FalsePositiveKiller.sanitize_findings(paths["fin"])

                with open(paths['fin'], 'r', encoding='utf-8') as f: findings = f.read(2000)
                report = self.intel.analyze_vulnerability(findings)

                with open(paths['rep'], 'w', encoding='utf-8') as r: r.write(str(report))

                print(f"\n{Colors.ERROR}{'_'*70}{Colors.RESET}")
                print(f"{Colors.BOLD}ANALISE DE IMPACTO:{Colors.RESET}\n")
                print(f"{Colors.INFO}{report}{Colors.RESET}\n")
            except Exception as e:
                logging.error(f"Erro analise IA: {e}")

            try:
                from core.escalator import Escalator, EscalationEngine
                escalator = Escalator()
                routing = escalator.process(paths["fin"], handle)

                from core.notifier import NotificationDispatcher
                NotificationDispatcher.alert_nuclei_telegram(routing["telegram"], handle)
                NotificationDispatcher.alert_nuclei_discord_batch(routing["discord_batch"], handle)

                if os.path.exists(paths.get("js", "")):
                    validated_secrets = []
                    with open(paths["js"], 'r') as f:
                        for line in f:
                            try:
                                secret = json.loads(line)
                                result = EscalationEngine.validate_js_secret(secret['type'], secret['value'])
                                if result['escalated']:
                                    secret['_escalated'] = True
                                    secret['_escalation_report'] = result['report']
                                validated_secrets.append(secret)
                            except: continue

                    if validated_secrets:
                        with open(paths["js"], 'w') as f:
                            for s in validated_secrets:
                                f.write(json.dumps(s) + '\n')

                    NotificationDispatcher.alert_js_secrets(paths["js"], handle)
            except Exception as e:
                logging.error(f"Erro notifier: {e}")
        else:
            ui_log("RESULTADO", "Nenhuma vulnerabilidade encontrada.", Colors.WARNING)

    def _smart_filter(self, inp, outp):
        se = {'.css','.js','.png','.jpg','.jpeg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.mp4','.mp3','.webp','.map'}
        jk = ['api','admin','login','dashboard','user','account','config','v1','v2','graphql','auth','token','password','upload','download','search','debug','ajax','action']
        ke = {'.php','.asp','.aspx','.jsp','.jsf','.do','.json','.xml'}
        intr = []; seen_base = {}; rm = 0; tot = 0
        try:
            with open(inp, 'r', errors='ignore') as f:
                for l in f:
                    url = l.strip()
                    if not url: continue
                    tot += 1; ul = url.lower()
                    pp = url.split('?')[0] if '?' in url else url; ext = ''
                    if '.' in pp.rsplit('/', 1)[-1]: ext = '.' + pp.rsplit('.', 1)[-1].lower()
                    if ext in se:
                        rm += 1; continue
                    if len(url) > 250: rm += 1; continue
                    if '?' in url:
                        base = url.split('?')[0].lower()
                        if base in seen_base:
                            rm += 1; continue
                        seen_base[base] = True
                    dp = url.count('/'); hp = '?' in url or '&' in url; hk = any(k in ul for k in jk); kk = ext in ke
                    sk = hk or hp or kk or dp <= 4
                    if not sk and dp > 4: rm += 1; continue
                    intr.append(url)
        except Exception as e:
            logging.error(f"Filter: {e}"); return False
        try:
            os.makedirs(os.path.dirname(outp), exist_ok=True)
            with open(outp, 'w') as f: f.write('\n'.join(intr))
            pc = (rm/tot*100) if tot > 0 else 0
            ui_log("SMART FILTER", f"Input: {tot} -> Output: {len(intr)} (removidos: {rm} - {pc:.1f}%)", Colors.PRIMARY)
            return True
        except Exception: return False

    def _scan(self, inp, paths, handle, score=0):
        from recon.engines import run_httpx, run_katana_surgical, run_nuclei

        label_httpx = "HTTPX"
        ui_update_status(label_httpx, "Detectando tecnologias...", Colors.PRIMARY)
        if self.is_cache_valid(paths["htt"]):
            ui_log("HTTPX", "Cacheado (1h)", Colors.SUCCESS)
        else:
            _run_with_progress(label_httpx, lambda: run_httpx(inp, paths["htt"]))
            count = sum(1 for _ in open(paths["htt"], 'r', errors='ignore')) if os.path.exists(paths["htt"]) else 0
            ui_log("HTTPX", f"{count} hosts detectados.", Colors.SUCCESS)
        if not os.path.exists(paths["htt"]) or os.path.getsize(paths["htt"]) == 0: return

        ui_update_status("EXTRACTION", "Extraindo URLs...", Colors.PRIMARY)
        try:
            with open(paths['htt'], 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.split()[0] for line in f if line.strip().startswith('http')]
            if not urls: return
            if len(urls) > 15000:
                ui_log("SKIP", f"{len(urls)} URLs - ignorando.", Colors.WARNING); return
            with open(paths['htt_urls'], 'w', encoding='utf-8') as f: f.write('\n'.join(urls))
            ui_log("EXTRACTED", f"{len(urls)} URLs extraidas", Colors.SUCCESS)
        except Exception as e:
            ui_log("ERR EXTRACTION", str(e), Colors.ERROR); return

        if not os.path.exists(paths["htt_urls"]) or os.path.getsize(paths["htt_urls"]) == 0: return

        label_katana = "Katana"
        ui_update_status(label_katana, "Crawling ativo...", Colors.WARNING)
        _run_with_progress(label_katana, lambda: run_katana_surgical(paths["htt_urls"], paths["end"], score, "-headless -concurrency 5 -crawl-duration 10m"), Colors.WARNING)
        count = sum(1 for _ in open(paths["end"], 'r', errors='ignore')) if os.path.exists(paths["end"]) else 0
        ui_log("KATANA", f"{count} URLs coletadas.", Colors.SUCCESS)

        if os.path.exists(paths["end"]) and os.path.getsize(paths["end"]) > 0:
            try:
                with open(paths['end'], 'r') as f: eps = f.readlines()
                cl = set()
                for ep in eps:
                    ep = ep.strip()
                    if not ep or ep.endswith('.js'): continue
                    if '?page=' in ep or '&page=' in ep: cl.add(ep.split('?')[0]); continue
                    if ep.count('&') > 5: continue
                    cl.add(ep)
                with open(paths['end'], 'w') as f: f.write('\n'.join(sorted(cl)))
            except Exception: pass

        js_findings = []
        if "js" in paths:
            from recon.js_hunter import JSHunter
            ui_update_status("JS HUNTER", "Procurando segredos em .js...", Colors.SECONDARY)
            katana_file = paths["end"]
            js_findings, js_scanned = JSHunter.scan_all(katana_file, paths["js"], score)
            if js_scanned > 0:
                found = len(js_findings)
                ui_log("JS HUNTER", f"{js_scanned} arquivos escaneados, {found} segredos encontrados.", Colors.SUCCESS if found > 0 else Colors.DIM)

        fp = paths["end"] + ".filtered"
        ns = fp if self._smart_filter(paths["end"], fp) else paths["end"]

        label_nuclei = "Nuclei"
        ui_update_status(label_nuclei, "Iniciando varredura...", Colors.ERROR)
        try:
            tech_tags = self.intel.select_surgical_arsenal(paths["htt"], score)
            tech_only = set(tech_tags.split(',')) if tech_tags else set()
            infra_base = tech_only - {'exposure', 'takeover'}
            INFRA_FALLBACK = {'cve', 'takeover', 'exposure', 'default-logins', 'misconfig'}
            infra_tags = infra_base | INFRA_FALLBACK

            from core.template_manager import update_nuclei_templates
            update_nuclei_templates()

            _base = os.path.dirname(paths["htt"])
            stats_pipe = f"{_base}/.nuclei_stats.log"

            findings_tmp = f"{paths['fin']}.dual_tmp"
            if os.path.exists(findings_tmp):
                open(findings_tmp, 'w').close()

            # === FASE 1: Nuclei Infra ===
            infra_tags_str = ','.join(infra_tags)
            ui_log("NUCLEI", f"Fase 1: Infra '{infra_tags_str}' em {paths['htt']}", Colors.INFO)
            label_infra = "Nuclei Infra"
            infra_findings = f"{findings_tmp}_infra"
            _run_with_progress(label_infra, lambda: run_nuclei(paths["htt"], infra_findings, infra_tags_str, stats_pipe, "-jsonl -silent -stats -sj -si 5 -max-host-error 100 -c 50 -bs 10 -rl 300"), live_tail_pipe=stats_pipe)
            if os.path.exists(infra_findings) and os.path.getsize(infra_findings) > 0:
                with open(infra_findings, 'r') as src, open(findings_tmp, 'a') as dst:
                    dst.write(src.read())
                infra_count = sum(1 for _ in open(infra_findings, 'r'))
                ui_log("NUCLEI INFRA", f"{infra_count} findings.", Colors.SUCCESS if infra_count > 0 else Colors.DIM)
            try:
                os.remove(infra_findings)
            except Exception: pass

            # === FASE 2: Nuclei Endpoints ===
            if os.path.exists(ns) and os.path.getsize(ns) > 0:
                inj_tags_str = "xss,sqli,ssrf,lfi,dast,fuzzing"
                ep_count = sum(1 for _ in open(ns, 'r'))
                ANTI_TARPIT = "-timeout 5 -retries 1 -jsonl -silent -stats -sj -si 5 -max-host-error 100 -c 50 -bs 10 -rl 300 -timeout 10"
                ui_log("NUCLEI", f"Fase 2: Injection '{inj_tags_str}' em {ep_count} endpoints", Colors.INFO)
                label_endp = "Nuclei Endp"
                endp_findings = f"{findings_tmp}_endp"
                _run_with_progress(label_endp, lambda: run_nuclei(ns, endp_findings, inj_tags_str, stats_pipe, ANTI_TARPIT), live_tail_pipe=stats_pipe)
                if os.path.exists(endp_findings) and os.path.getsize(endp_findings) > 0:
                    with open(endp_findings, 'r') as src, open(findings_tmp, 'a') as dst:
                        dst.write(src.read())
                    endp_count = sum(1 for _ in open(endp_findings, 'r'))
                    ui_log("NUCLEI ENDP", f"{endp_count} findings.", Colors.SUCCESS if endp_count > 0 else Colors.DIM)
                try:
                    os.remove(endp_findings)
                except Exception: pass

            # === FASE 3: Deep Scan ===
            deep_urls = [f['value'] for f in js_findings if f.get('type') == 'generic_url_param' or f.get('value', '').startswith('http')]
            if deep_urls:
                unique_deep = list(set(deep_urls))
                hot_urls = [u for u in unique_deep if self.intel.calculate_hot_score(u) > 3]
                
                history_file = "recon/deep_history.txt"
                history = set()
                if os.path.exists(history_file):
                    with open(history_file, 'r') as hf:
                        history = {l.strip() for l in hf if l.strip()}
                
                new_urls = [u for u in hot_urls if u not in history]
                ignored_count = len(unique_deep) - len(new_urls)

                if new_urls:
                    ui_log("RECURSIVIDADE", f"Injetando {len(new_urls)} alvos de alta prioridade (Ineditos) ignorando {ignored_count} ruidos/repetidos.", Colors.WARNING)
                    
                    deep_input = f"{_base}/.deep_scan_input.txt"
                    deep_findings = f"{findings_tmp}_deep"
                    with open(deep_input, 'w') as f:
                        f.write('\n'.join(new_urls))
                
                    label_deep = "Nuclei Deep"
                    templates = "-t http/exposed-panels,http/vulnerabilities,http/misconfiguration -jsonl -silent -stats -sj -si 5 -max-host-error 100 -c 50 -bs 10 -rl 300 -t"
                    _run_with_progress(label_deep, lambda: run_nuclei(deep_input, deep_findings, "", stats_pipe, templates), live_tail_pipe=stats_pipe)
                    
                    with open(history_file, 'a') as hf:
                        hf.write('\n'.join(new_urls) + '\n')

                    if os.path.exists(deep_findings) and os.path.getsize(deep_findings) > 0:
                        with open(deep_findings, 'r') as src, open(findings_tmp, 'a') as dst:
                            for line in src:
                                try:
                                    d = json.loads(line)
                                    d["_deep_scan"] = True
                                    dst.write(json.dumps(d) + '\n')
                                except Exception:
                                    dst.write(line)
                    try:
                        os.remove(deep_input)
                        os.remove(deep_findings)
                    except Exception: pass

            if os.path.exists(findings_tmp):
                os.replace(findings_tmp, paths["fin"])
            count = sum(1 for _ in open(paths["fin"], 'r', errors='ignore')) if os.path.exists(paths["fin"]) else 0
            ui_log("NUCLEI", f"{count} findings.", Colors.SUCCESS if count > 0 else Colors.WARNING)

        except Exception as e:
            logging.error(f"Nuclei: {e}")
