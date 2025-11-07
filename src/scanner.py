#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import datetime as dt
import json
import logging
import os
import re
import sys
import time
import subprocess
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from shutil import which
import threading

import requests
from bs4 import BeautifulSoup

MAX_URLS_TO_SCAN = 50
DEFAULT_DEPTH = 2
DEFAULT_TOTAL_TIMEOUT = 120
PER_REQUEST_TIMEOUT = 5
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/124 Safari/537.36"
)

_DEADLINE: Optional[float] = None

def _remaining_time() -> int:
    if _DEADLINE is None:
        return 999999
    return max(0, int(_DEADLINE - time.time()))

def _cap_timeout(per_req: int) -> int:
    rem = _remaining_time()
    if rem <= 0:
        return 0
    return max(1, min(per_req, rem))

try:
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    _HAS_RICH = True
except Exception:
    _HAS_RICH = False

class Heartbeat(threading.Thread):
    def __init__(self, getter, interval: float = 2.0, use_rich: bool = False):
        super().__init__(daemon=True)
        self.getter = getter
        self.interval = interval
        self.use_rich = use_rich and _HAS_RICH and sys.stdout.isatty()
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        if self.use_rich:
            with Live(self._render(), refresh_per_second=4) as live:
                while not self._stop.wait(self.interval):
                    live.update(self._render())
        else:
            while not self._stop.wait(self.interval):
                s = self.getter()
                print(
                    f"[.] elapsed:{int(s['elapsed'])}s | rem:{s['remaining']}s | "
                    f"urls:{s['scanned']}/{s['limit']} | q:{s['queue']} | phase:{s['phase']}"
                )

    def _render(self):
        s = self.getter()
        table = Table(box=None, expand=False, show_header=False, pad_edge=False)
        table.add_row("Elapsed", f"{int(s['elapsed'])}s")
        table.add_row("Remaining", f"{s['remaining']}s")
        table.add_row("URLs", f"{s['scanned']}/{s['limit']} (queue:{s['queue']})")
        table.add_row("Phase", s["phase"])
        return Panel(table, title="Scanner status", expand=False)

try:
    from report_generator import save_json, save_md, save_csv
except Exception:
    def save_json(data, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_md(data, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Relatório de Varredura\n\n")
            f.write(f"- Alvo: {data.get('target')}\n")
            f.write(f"- Data/Hora: {data.get('datetime')}\n")
            f.write(f"- Duração: {data.get('duration_seconds')}s\n")
            f.write(f"- URLs analisadas: {data.get('urls_scanned')}\n")
            f.write(f"- Vulnerabilidades: {len(data.get('vulnerabilities') or [])}\n\n")
            f.write("## Resumo por tipo\n\n")
            for k, v in (data.get("vulnerability_summary") or {}).items():
                f.write(f"- {k}: {v}\n")
            f.write("\n## Achados\n\n")
            for v in data.get("vulnerabilities") or []:
                f.write(f"- **{v.get('severity','Info')}** {v.get('type')} – {v.get('url')}\n")

    def save_csv(data, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        rows = data.get("vulnerabilities") or []
        if not rows:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["type", "severity", "url", "parameter", "payload", "tool", "evidence"])
            return
        keys = ["type", "severity", "url", "parameter", "payload", "tool", "evidence"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, "") for k in keys})

try:
    from utils.external_tools import run_tools as _run_tools
    def run_extra_tools(selected, target, timeout=180):
        return _run_tools(selected, target, timeout=timeout)
except Exception:
    def run_extra_tools(selected, target, timeout=180):
        return []

logger = logging.getLogger("scanner")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(handler)

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})
session.verify = True

ERROR_PATTERNS = re.compile(
    r"(SQL syntax|mysql|postgresql|sqlite|odbc|jdbc|ORA-\d+|unterminated|You have an error in your SQL)",
    re.IGNORECASE,
)

SQLI_PAYLOADS = ["'", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--", "admin' --"]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><svg/onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "<svg><script>alert(1)</script>",
]
XSS_PATTERNS = [
    r"<script>alert\(1\)",
    r"onerror=alert\(1\)",
    r"svg/onload=alert\(1\)",
]

def fetch(url: str, timeout: int) -> Optional[requests.Response]:
    eff = _cap_timeout(timeout)
    if eff <= 0:
        return None
    try:
        r = session.get(url, timeout=eff, allow_redirects=True)
        return r
    except Exception:
        return None

def post(url: str, data: Dict[str, str], timeout: int) -> Optional[requests.Response]:
    eff = _cap_timeout(timeout)
    if eff <= 0:
        return None
    try:
        r = session.post(url, data=data, timeout=eff, allow_redirects=True)
        return r
    except Exception:
        return None

def extract_links_forms(base_url: str, html: str) -> Tuple[Set[str], List[Dict]]:
    links: Set[str] = set()
    forms: List[Dict] = []
    try:
        soup = BeautifulSoup(html or "", "html.parser")
    except Exception:
        return links, forms

    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if href and isinstance(href, str):
            full = urljoin(base_url, href)
            if full.startswith(("http://", "https://")):
                links.add(full)

    for f in soup.find_all("form"):
        method = (f.get("method") or "get").lower()
        action = f.get("action") or base_url
        full_action = urljoin(base_url, action)
        inputs = []
        for i in f.find_all(["input", "textarea", "select"]):
            name = i.get("name")
            if name:
                inputs.append(name)
        forms.append({"method": method, "action": full_action, "inputs": inputs})

    return links, forms

def add_vuln(vulns: List[Dict], vtype: str, url: str, severity: str = "Medium",
             parameter: str = "", payload: str = "", evidence: str = "", tool: str = "internal"):
    vulns.append({
        "type": vtype,
        "url": url,
        "severity": severity,
        "parameter": parameter,
        "payload": payload,
        "evidence": evidence,
        "tool": tool,
        "confidence": "Medium",
    })

def scan_csrf(forms: List[Dict], page_url: str, vulns: List[Dict]):
    if _remaining_time() <= 0:
        return
    for f in forms:
        if f["method"] == "post":
            tokens = [n for n in f["inputs"] if re.search(r"(csrf|token|xsrf|nonce)", n, re.I)]
            if not tokens:
                logger.warning("[CSRF] Possible missing token at %s", page_url)
                add_vuln(vulns, "CSRF", page_url, severity="Medium", evidence="Form POST sem token", tool="internal")

def scan_info_disclosure(resp: requests.Response, page_url: str, vulns: List[Dict]):
    if _remaining_time() <= 0 or not resp:
        return
    body = (resp.text or "")[:20000]
    hdrs = "\n".join([f"{k}: {v}" for k, v in (resp.headers or {}).items()])
    patterns = [
        (r"Index of /", "Directory listing"),
        (r"\.env", ".env exposed"),
        (r"Stack trace", "Stack trace"),
        (r"Warning:|Notice:|Fatal error:", "PHP errors"),
        (r"X-Powered-By:", "X-Powered-By header"),
        (r"phpinfo\(", "phpinfo"),
        (r"X-AspNet-Version", "ASP.NET version"),
    ]
    for rx, ev in patterns:
        if re.search(rx, body, re.I) or re.search(rx, hdrs, re.I):
            logger.warning("[InfoDisc] Sensitive data pattern at %s", page_url)
            add_vuln(vulns, "Sensitive Data Exposure", page_url, severity="Low", evidence=ev, tool="internal")
            break

def mutate_params(qparams: Dict[str, List[str]], name: str, value: str) -> Dict[str, List[str]]:
    new = {k: v[:] for k, v in qparams.items()}
    if name in new:
        new[name] = [value]
    else:
        new[name] = [value]
    return new

def scan_sqli_get(url: str, vulns: List[Dict], timeout: int):
    if _remaining_time() <= 0:
        return
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return
    for param in list(qs.keys())[:3]:
        if _remaining_time() <= 0:
            break
        for payload in SQLI_PAYLOADS:
            if _remaining_time() <= 0:
                break
            new_qs = mutate_params(qs, param, payload)
            new_url = parsed._replace(query=urlencode(new_qs, doseq=True)).geturl()
            r = fetch(new_url, timeout)
            if not r:
                continue
            body = r.text or ""
            if ERROR_PATTERNS.search(body):
                logger.warning("Vulnerabilidade encontrada - Tipo: SQL Injection, URL: %s, Payload: %s, Parâmetro: %s",
                               new_url, payload, param)
                add_vuln(vulns, "SQL Injection", new_url, severity="High",
                         parameter=param, payload=payload,
                         evidence="DB error pattern", tool="internal")
                break

def scan_xss_reflected(url: str, vulns: List[Dict], timeout: int):
    if _remaining_time() <= 0:
        return
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return
    for param in list(qs.keys())[:3]:
        if _remaining_time() <= 0:
            break
        for payload in XSS_PAYLOADS:
            if _remaining_time() <= 0:
                break
            new_qs = mutate_params(qs, param, payload)
            new_url = parsed._replace(query=urlencode(new_qs, doseq=True)).geturl()
            r = fetch(new_url, timeout)
            if not r:
                continue
            body = (r.text or "")
            low = body.lower()
            if payload.lower() in low:
                add_vuln(vulns, "XSS Refletido", new_url, severity="High",
                         parameter=param, payload=payload, evidence="payload refletido", tool="internal")
                break
            if any(re.search(rx, body, re.I) for rx in XSS_PATTERNS):
                add_vuln(vulns, "XSS Refletido (heurística)", new_url, severity="Medium",
                         parameter=param, payload=payload, evidence="padrão XSS", tool="internal")
                break

def scan_traversal_lfi(url: str, vulns: List[Dict], timeout: int):
    if _remaining_time() <= 0:
        return
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    candidates = [k for k in qs.keys() if re.search(r"(file|path|page|tpl|template|inc|include)", k, re.I)]
    if not candidates:
        return
    traversal = "../../../../../../../../etc/passwd"
    for p in candidates[:2]:
        if _remaining_time() <= 0:
            break
        new_qs = mutate_params(qs, p, traversal)
        new_url = parsed._replace(query=urlencode(new_qs, doseq=True)).geturl()
        r = fetch(new_url, timeout)
        if r and ("root:x:0:0" in (r.text or "")):
            add_vuln(vulns, "Local File Inclusion / Directory Traversal", new_url,
                     severity="High", parameter=p, payload=traversal, evidence="etc/passwd", tool="internal")
            break

def scan_cmdi(url: str, vulns: List[Dict], timeout: int):
    if _remaining_time() <= 0:
        return
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    suspects = [k for k in qs.keys() if re.search(r"(cmd|exec|pipe|run|process)", k, re.I)]
    if not suspects:
        return
    payload = "id;id"
    for p in suspects[:2]:
        if _remaining_time() <= 0:
            break
        new_qs = mutate_params(qs, p, payload)
        new_url = parsed._replace(query=urlencode(new_qs, doseq=True)).geturl()
        r = fetch(new_url, timeout)
        if r and re.search(r"\buid=\d+", r.text or ""):
            add_vuln(vulns, "Command Injection", new_url, severity="Critical",
                     parameter=p, payload=payload, evidence="uid=", tool="internal")
            break

def _zap_baseline_path() -> Optional[str]:
    p = os.getenv("ZAP_BASELINE_PATH")
    if p and os.path.exists(p):
        return p
    if which("zap-baseline.py"):
        return "zap-baseline.py"
    for c in ("/opt/ZAP/zap-baseline.py", "/usr/share/zaproxy/zap-baseline.py"):
        if os.path.exists(c):
            return c
    return None

def run_zap_baseline(
    target: str,
    timeout: int = 300,
    outdir: Optional[Path] = None,
    minutes: Optional[int] = None,
    flags: Optional[str] = None,
) -> List[str]:
    zap_path = _zap_baseline_path()
    if not zap_path:
        return ["ZAP baseline não encontrado (defina ZAP_BASELINE_PATH ou instale o ZAP). Pulando..."]

    outdir = Path(outdir or ".")
    outdir.mkdir(parents=True, exist_ok=True)
    html = outdir / "zap_report.html"
    jout = outdir / "zap_report.json"

    mins_env = os.getenv("ZAP_BASELINE_MINUTES")
    try:
        mins_val = int(minutes if minutes is not None else (mins_env if mins_env else 3))
    except Exception:
        mins_val = 3

    flags_env = os.getenv("ZAP_BASELINE_FLAGS", "")
    extra_args = []
    if flags:
        extra_args += flags.split()
    if flags_env:
        extra_args += flags_env.split()

    try:
        zap_timeout = int(os.getenv("ZAP_TIMEOUT", str(timeout)))
    except Exception:
        zap_timeout = timeout

    python_bin = os.environ.get("PYTHON", sys.executable or "python3")
    cmd = [
        python_bin, zap_path,
        "-t", target,
        "-m", str(mins_val),
        "-r", str(html),
        "-J", str(jout),
        "-I",
        *extra_args,
    ]
    try:
        res = subprocess.run(
            cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=zap_timeout, text=True
        )
        note = (
            f"ZAP baseline executado (rc={res.returncode}) "
            f"[m={mins_val}min, timeout={zap_timeout}s]. Relatórios: {html.name}, {jout.name}"
        )
        return [note]
    except subprocess.TimeoutExpired:
        return [f"ZAP baseline: timeout após {zap_timeout}s"]
    except Exception as e:
        return [f"ZAP baseline error: {e}"]

def run_nikto(
    target: str,
    timeout: int = 300,
    outdir: Optional[Path] = None,
    maxtime: Optional[int] = None,
    flags: Optional[str] = None,
) -> List[str]:
    if not which("nikto"):
        return ["Nikto não encontrado no PATH. Pulando..."]

    mt_env = os.getenv("NIKTO_MAXTIME")
    try:
        mt_val = int(maxtime if maxtime is not None else (mt_env if mt_env else timeout))
    except Exception:
        mt_val = timeout

    try:
        proc_timeout = int(os.getenv("NIKTO_TIMEOUT", str(timeout)))
    except Exception:
        proc_timeout = timeout

    cmd = ["nikto", "-host", target, "-ask", "no", "-maxtime", str(mt_val)]
    flags_env = os.getenv("NIKTO_FLAGS", "")
    if flags:
        cmd += flags.split()
    if flags_env:
        cmd += flags_env.split()

    try:
        res = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=proc_timeout, text=True)
        note = f"Nikto executado (rc={res.returncode}) [maxtime={mt_val}s, timeout={proc_timeout}s]"
        if outdir:
            outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
            with open(outdir / "nikto_output.txt", "w", encoding="utf-8") as f:
                f.write(res.stdout or "")
                if res.stderr:
                    f.write("\n--- STDERR ---\n"); f.write(res.stderr)
            note += " – saída gravada em nikto_output.txt"
        return [note]
    except subprocess.TimeoutExpired:
        return [f"Nikto: timeout após {proc_timeout}s (subprocess)"]
    except Exception as e:
        return [f"Nikto error: {e}"]

def summarize(vulns: List[Dict]) -> Dict[str, int]:
    cnt = defaultdict(int)
    for v in vulns:
        cnt[v.get("type", "Unknown")] += 1
    sev = defaultdict(int)
    for v in vulns:
        sev[v.get("severity", "Info")] += 1
    out = dict(cnt)
    out.update({f"severity_{k}": v for k, v in sev.items()})
    out["total"] = len(vulns)
    return out

def build_parser():
    p = argparse.ArgumentParser(
        prog="scanner.py",
        description="Ferramenta de varredura OWASP Top 10 (básico) com integrações."
    )
    p.add_argument("-u", "--url", required=True, help="URL alvo (http/https)")
    p.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help="Profundidade do crawl (default: 2)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TOTAL_TIMEOUT, help="Timeout total (s) (default: 120)")
    p.add_argument(
        "--export", nargs="+", choices=["json"], default=["json"],
        help="Formatos de relatório (apenas JSON)"
    )
    p.add_argument(
        "--integrations", nargs="+", choices=["zap", "nikto"],
        help="Ferramentas auxiliares (zap, nikto)"
    )
    p.add_argument(
        "--extra-tools", nargs="+", choices=["nmap", "whatweb", "nuclei"],
        help="Ferramentas extras (se utils.external_tools estiver presente)"
    )
    p.add_argument("--zap-mins", type=int,
                   help="Tempo máximo (em minutos) do spider do ZAP Baseline (default 3; sobrescreve ZAP_BASELINE_MINUTES)")
    p.add_argument("--nikto-maxtime", type=int,
                   help="Tempo máximo (em segundos) do Nikto (-maxtime). Se ausente, usa NIKTO_MAXTIME ou o timeout restante.")
    p.add_argument("--output-dir", default="reports", help="Diretório de saída de relatórios")
    return p

def main():
    global _DEADLINE

    args = build_parser().parse_args()

    target_url = args.url
    depth = max(0, int(args.depth))
    total_timeout = int(args.timeout)
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    start = time.time()
    _DEADLINE = start + total_timeout

    _stats = {
        "phase": "init",
        "scanned": 0,
        "queue": 1,
        "limit": MAX_URLS_TO_SCAN,
        "elapsed": 0.0,
        "remaining": total_timeout,
    }
    def _get_stats():
        now = time.time()
        return {
            **_stats,
            "elapsed": now - start,
            "remaining": max(0, int(total_timeout - (now - start))),
        }

    _hb = Heartbeat(_get_stats, interval=2.0, use_rich=True)
    _hb.start()

    try:
        print(f"[*] Iniciando varredura em {target_url}")
        logger.info("Iniciando varredura em %s", target_url)

        _stats["phase"] = "connect"
        first = fetch(target_url, PER_REQUEST_TIMEOUT)
        if not first:
            print("[!] Alvo inacessível no momento.")
            return

        q = deque([(target_url, 0)])
        scanned_urls: Set[str] = set()
        queued_urls: Set[str] = {target_url}
        vulnerabilities: List[Dict] = []
        urls_seen: List[str] = []
        _stats["queue"] = len(q)

        while q and len(scanned_urls) < MAX_URLS_TO_SCAN and _remaining_time() > 0:
            url, d = q.popleft()
            if url in scanned_urls or d > depth or _remaining_time() <= 0:
                _stats["queue"] = len(q)
                continue

            scanned_urls.add(url)
            urls_seen.append(url)
            _stats["scanned"] = len(scanned_urls)
            _stats["queue"] = len(q)
            _stats["phase"] = f"crawl:depth={d}"

            logger.info("Crawling: %s (Depth: %s)", url, d)
            resp = fetch(url, PER_REQUEST_TIMEOUT)
            if not resp:
                continue

            links, forms = extract_links_forms(url, resp.text)

            if _remaining_time() <= 0: break
            _stats["phase"] = "scan:csrf"
            scan_csrf(forms, url, vulnerabilities)

            if _remaining_time() <= 0: break
            _stats["phase"] = "scan:info_disclosure"
            scan_info_disclosure(resp, url, vulnerabilities)

            if _remaining_time() <= 0: break
            _stats["phase"] = "scan:sqli"
            scan_sqli_get(url, vulnerabilities, PER_REQUEST_TIMEOUT)

            if _remaining_time() <= 0: break
            _stats["phase"] = "scan:xss"
            scan_xss_reflected(url, vulnerabilities, PER_REQUEST_TIMEOUT)

            if _remaining_time() <= 0: break
            _stats["phase"] = "scan:lfi_traversal"
            scan_traversal_lfi(url, vulnerabilities, PER_REQUEST_TIMEOUT)

            if _remaining_time() <= 0: break
            _stats["phase"] = "scan:cmdi"
            scan_cmdi(url, vulnerabilities, PER_REQUEST_TIMEOUT)

            for lk in links:
                if _remaining_time() <= 0:
                    break
                if lk.startswith(("http://", "https://")) and lk not in scanned_urls and lk not in queued_urls:
                    if urlparse(lk).netloc == urlparse(target_url).netloc:
                        q.append((lk, d + 1))
                        queued_urls.add(lk)
            _stats["queue"] = len(q)

        def remaining():
            return max(10, _remaining_time())

        integration_notes: List[str] = []
        if args.integrations and _remaining_time() > 0:
            if "zap" in args.integrations and _remaining_time() > 10:
                _stats["phase"] = "integration:zap"
                integration_notes.extend(
                    run_zap_baseline(
                        target_url,
                        timeout=remaining(),
                        outdir=outdir,
                        minutes=args.zap_mins
                    )
                )
            if "nikto" in args.integrations and _remaining_time() > 10:
                _stats["phase"] = "integration:nikto"
                integration_notes.extend(
                    run_nikto(
                        target_url,
                        timeout=remaining(),
                        outdir=outdir,
                        maxtime=args.nikto_maxtime
                    )
                )

        extra_notes: List[str] = []
        if args.extra_tools and _remaining_time() > 0:
            for tool in args.extra_tools:
                if _remaining_time() <= 0:
                    break
                _stats["phase"] = f"extra:{tool}"
                extra_notes.extend(
                    run_extra_tools([tool], target_url, timeout=remaining())
                )

        _stats["phase"] = "saving"
        summary = summarize(vulnerabilities)
        report = {
            "target": target_url,
            "datetime": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": round(time.time() - start, 2),
            "urls_scanned": len(urls_seen),
            "vulnerability_summary": summary,
            "vulnerabilities": vulnerabilities,
            "integrations": integration_notes,
            "extra_tools": extra_notes,
        }

        json_path = outdir / "report.json"
        md_path = outdir / "report.md"
        csv_path = outdir / "report.csv"

        save_json(report, json_path)

        _stats["phase"] = "done"

    finally:
        _hb.stop()
        time.sleep(0.1)

    print("\n[+] Varredura completa!\n")

    print("\nArquivos gerados em:", outdir.resolve())

if __name__ == "__main__":
    main()
