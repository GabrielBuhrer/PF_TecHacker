#!/usr/bin/env python3
# -*- coding: utf-8 -*-oi

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

import requests
from bs4 import BeautifulSoup

# =========================
# Configurações padrão
# =========================
MAX_URLS_TO_SCAN = 10
DEFAULT_DEPTH = 2
DEFAULT_TOTAL_TIMEOUT = 120
PER_REQUEST_TIMEOUT = 5  # segundos por requisição HTTP (mude se quiser)
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/124 Safari/537.36"
)

# =========================
# Imports do projeto
# =========================
try:
    from report_generator import save_json, save_md, save_csv
except Exception:
    # Fallback simples caso report_generator não esteja acessível
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

# Import opcional do arquivo único com ferramentas extras
try:
    from utils.external_tools import run_tools as run_extra_tools
except Exception:
    def run_extra_tools(selected, target, timeout=180):
        # Se não existir, apenas retorne vazio
        return []

# =========================
# Logging
# =========================
logger = logging.getLogger("scanner")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(handler)

# =========================
# Utilidades HTTP / Parsing
# =========================
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})
session.verify = True  # pode desativar em laboratório, se necessário

ERROR_PATTERNS = re.compile(
    r"(SQL syntax|mysql|postgresql|sqlite|odbc|jdbc|ORA-\d+|unterminated|You have an error in your SQL)",
    re.IGNORECASE,
)

SQLI_PAYLOADS = ["'", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--", "admin' --"]

# --- (NOVO) Payloads/heurísticas para XSS refletido ---
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
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        return r
    except Exception:
        return None


def post(url: str, data: Dict[str, str], timeout: int) -> Optional[requests.Response]:
    try:
        r = session.post(url, data=data, timeout=timeout, allow_redirects=True)
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

    # links
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if href and isinstance(href, str):
            full = urljoin(base_url, href)
            if full.startswith(("http://", "https://")):
                links.add(full)

    # forms
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

# =========================
# Heurísticas de scanners
# =========================

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
    for f in forms:
        if f["method"] == "post":
            tokens = [n for n in f["inputs"] if re.search(r"(csrf|token|xsrf|nonce)", n, re.I)]
            if not tokens:
                logger.warning("[CSRF] Possible missing token at %s", page_url)
                add_vuln(vulns, "CSRF", page_url, severity="Medium", evidence="Form POST sem token", tool="internal")


def scan_info_disclosure(resp: requests.Response, page_url: str, vulns: List[Dict]):
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
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return
    for param in list(qs.keys())[:3]:  # limita para não exagerar
        for payload in SQLI_PAYLOADS:
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
                break  # próximo parâmetro


# --- (NOVO) XSS Refletido ---
def scan_xss_reflected(url: str, vulns: List[Dict], timeout: int):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return
    for param in list(qs.keys())[:3]:
        for payload in XSS_PAYLOADS:
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
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    candidates = [k for k in qs.keys() if re.search(r"(file|path|page|tpl|template|inc|include)", k, re.I)]
    if not candidates:
        return
    traversal = "../../../../../../../../etc/passwd"
    for p in candidates[:2]:
        new_qs = mutate_params(qs, p, traversal)
        new_url = parsed._replace(query=urlencode(new_qs, doseq=True)).geturl()
        r = fetch(new_url, timeout)
        if r and ("root:x:0:0" in (r.text or "")):
            add_vuln(vulns, "Local File Inclusion / Directory Traversal", new_url,
                     severity="High", parameter=p, payload=traversal, evidence="etc/passwd", tool="internal")
            break


def scan_cmdi(url: str, vulns: List[Dict], timeout: int):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    suspects = [k for k in qs.keys() if re.search(r"(cmd|exec|pipe|run|process)", k, re.I)]
    if not suspects:
        return
    payload = "id;id"
    for p in suspects[:2]:
        new_qs = mutate_params(qs, p, payload)
        new_url = parsed._replace(query=urlencode(new_qs, doseq=True)).geturl()
        r = fetch(new_url, timeout)
        if r and re.search(r"\buid=\d+", r.text or ""):
            add_vuln(vulns, "Command Injection", new_url, severity="Critical",
                     parameter=p, payload=payload, evidence="uid=", tool="internal")
            break


# =========================
# Integrações auxiliares
# =========================

def run_zap_baseline(target: str, timeout: int = 300) -> List[str]:
    try:
        cmd = [
            "docker", "run", "--rm",
            "owasp/zap2docker-stable",
            "zap-baseline.py",
            "-t", target,
            "-m", "3",
            "-r", "zap_report.html",
        ]
        subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return ["ZAP baseline executed"]
    except Exception as e:
        return [f"ZAP baseline error: {e}"]


def run_nikto(target: str, timeout: int = 300) -> List[str]:
    try:
        cmd = ["nikto", "-host", target, "-ask", "no"]
        subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return ["Nikto executed"]
    except Exception as e:
        return [f"Nikto error: {e}"]


# =========================
# Consolidação de resultados
# =========================

def summarize(vulns: List[Dict]) -> Dict[str, int]:
    cnt = defaultdict(int)
    for v in vulns:
        cnt[v.get("type", "Unknown")] += 1
    # também sumariza severidades
    sev = defaultdict(int)
    for v in vulns:
        sev[v.get("severity", "Info")] += 1
    # junta em um dict só
    out = dict(cnt)
    out.update({f"severity_{k}": v for k, v in sev.items()})
    out["total"] = len(vulns)
    return out


# =========================
# CLI / Parser
# =========================

def build_parser():
    p = argparse.ArgumentParser(
        prog="scanner.py",
        description="Ferramenta de varredura OWASP Top 10 (básico) com integrações."
    )
    p.add_argument("-u", "--url", required=True, help="URL alvo (http/https)")
    p.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help="Profundidade do crawl (default: 2)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TOTAL_TIMEOUT, help="Timeout total (s) (default: 120)")
    p.add_argument(
        "--export", nargs="+", choices=["json", "md", "csv"], default=["json", "md"],
        help="Formatos de relatório"
    )
    p.add_argument(
        "--integrations", nargs="+", choices=["zap", "nikto"],
        help="Ferramentas auxiliares (zap, nikto)"
    )
    p.add_argument(
        "--extra-tools", nargs="+", choices=["nmap", "whatweb", "nuclei", "wfuzz"],
        help="Ferramentas extras (se utils.external_tools estiver presente)"
    )
    p.add_argument("--output-dir", default="reports", help="Diretório de saída de relatórios")
    return p

# =========================
# Execução principal
# =========================

def main():
    args = build_parser().parse_args()

    target_url = args.url
    depth = max(0, int(args.depth))
    total_timeout = int(args.timeout)
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    start = time.time()

    print(f"[*] Iniciando varredura em {target_url}")
    logger.info("Iniciando varredura em %s", target_url)
    print(f"[*] Limitado a {MAX_URLS_TO_SCAN} URLs, profundidade {depth}")
    print(f"[*] Timeout por requisição: {PER_REQUEST_TIMEOUT}s, Timeout total: {total_timeout}s")

    # 0) checagem inicial do alvo
    first = fetch(target_url, PER_REQUEST_TIMEOUT)
    if not first:
        print("[!] Alvo inacessível no momento.")
        sys.exit(1)

    # 1) BFS crawl simples
    q = deque([(target_url, 0)])
    scanned_urls: Set[str] = set()
    vulnerabilities: List[Dict] = []
    urls_seen: List[str] = []

    while q and len(scanned_urls) < MAX_URLS_TO_SCAN and (time.time() - start) < total_timeout:
        url, d = q.popleft()
        if url in scanned_urls or d > depth:
            continue
        scanned_urls.add(url)
        urls_seen.append(url)

        logger.info("Crawling: %s (Depth: %s)", url, d)
        resp = fetch(url, PER_REQUEST_TIMEOUT)
        if not resp:
            continue

        # 2) Parse links + forms
        links, forms = extract_links_forms(url, resp.text)

        # 3) Scanners internos
        scan_csrf(forms, url, vulnerabilities)
        scan_info_disclosure(resp, url, vulnerabilities)
        scan_sqli_get(url, vulnerabilities, PER_REQUEST_TIMEOUT)
        scan_xss_reflected(url, vulnerabilities, PER_REQUEST_TIMEOUT)  # <--- NOVO
        scan_traversal_lfi(url, vulnerabilities, PER_REQUEST_TIMEOUT)
        scan_cmdi(url, vulnerabilities, PER_REQUEST_TIMEOUT)

        # 4) Expand crawl
        for lk in links:
            if lk.startswith(("http://", "https://")) and lk not in scanned_urls:
                if urlparse(lk).netloc == urlparse(target_url).netloc:
                    q.append((lk, d + 1))

    # 5) Integrações auxiliares (opcionais)
    integration_notes: List[str] = []
    if args.integrations:
        if "zap" in args.integrations:
            integration_notes.extend(run_zap_baseline(target_url, timeout=total_timeout))
        if "nikto" in args.integrations:
            integration_notes.extend(run_nikto(target_url, timeout=total_timeout))

    # 6) Ferramentas extras (quando disponíveis)
    extra_notes: List[str] = []
    if args.extra_tools:
        extra_notes.extend(run_extra_tools(args.extra_tools, target_url, timeout=total_timeout))

    # 7) Montar relatório
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

    # paths
    json_path = outdir / "report.json"
    md_path = outdir / "report.md"
    csv_path = outdir / "report.csv"

    # 8) Salvar
    if "json" in args.export:
        save_json(report, json_path)
    if "md" in args.export:
        save_md(report, md_path)
    if "csv" in args.export:
        save_csv(report, csv_path)

    # 9) Saída no console estilo que você usa
    print("\n[+] Varredura completa!\n")
    print("Relatório de Vulnerabilidades:\n")
    for v in vulnerabilities:
        print(f"Tipo: {v.get('type', '-')}, Severidade: {v.get('severity', '-')}, URL: {v.get('url','-')} ")
        if v.get("parameter"):
            print(f"  - Parâmetro: {v.get('parameter')}")
        if v.get("payload"):
            print(f"  - Payload: {v.get('payload')}")
        if v.get("evidence"):
            print(f"  - Evidência: {v.get('evidence')}")
        print()

    print("Resumo:")
    for k, v in summary.items():
        print(f"  - {k}: {v}")

    print("\nArquivos gerados em:", outdir.resolve())


if __name__ == "__main__":
    main()
