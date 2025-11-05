# src/utils/external_tools.py
# - Nmap: usa hostname (extrai de URL) e T4 para mais velocidade (modo rápido por padrão)
# - WhatWeb: prefere JSON e faz fallback p/ texto, enriquecendo mensagem
# - Wfuzz: threads e wordlist via env (WFUZZ_THREADS, WFUZZ_WORDLIST), tenta JSON e faz fallback p/ texto
# - Nuclei: lê JSONL e normaliza severidade
import json, os, subprocess, shlex, tempfile, re, xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

Finding = Dict[str, Any]

# ---------------- Utils ----------------
def _norm_severity(s: str) -> str:
    s = (s or "").lower()
    if s in ("critical","crit","c"): return "Critical"
    if s in ("high","h"): return "High"
    if s in ("medium","med","m"): return "Medium"
    if s in ("low","l"): return "Low"
    if s in ("info","informational","i"): return "Info"
    return "Unknown"

def _which(bin_name: str) -> Optional[str]:
    from shutil import which
    return which(bin_name)

def _run_cmd(cmd: str, timeout: int = 180) -> subprocess.CompletedProcess:
    # NUNCA usa shell=True; split protege argumentos
    return subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout, check=False)

def _host_from_target(target: str) -> str:
    return urlparse(target).hostname or target

# ---------------- Nmap ----------------
def run_nmap_http(target: str, timeout: int = 180) -> List[Finding]:
    if not _which("nmap"):
        return [{"tool":"nmap","type":"ToolMissing","severity":"Info","message":"nmap not found in PATH"}]
    host = _host_from_target(target)
    with tempfile.NamedTemporaryFile(prefix="nmap_", suffix=".xml", delete=False) as tf:
        xml_path = tf.name

    # Modo rápido por padrão (NMAP_FAST=1) ou quando timeout é curto
    fast = (os.environ.get("NMAP_FAST", "1") == "1") or (timeout <= 120)
    if fast:
        scripts = "http-title,http-server-header,http-headers"
        host_to = max(5, timeout - 5)
        script_to = max(5, timeout // 2)
        cmd = f"nmap -Pn -T4 -p 80,443 --script={scripts} --host-timeout {host_to}s --script-timeout {script_to}s -oX {xml_path} {host}"
    else:
        cmd = f"nmap -Pn -sV -T4 -p 80,443 --script=http-* --host-timeout {max(5, timeout-5)}s --script-timeout {max(5, timeout//2)}s -oX {xml_path} {host}"

    try:
        _ = _run_cmd(cmd, timeout=timeout)
        findings: List[Finding] = []
        try:
            tree = ET.parse(xml_path); root = tree.getroot()
            # Scripts em nível de host
            for s in root.findall(".//hostscript/script"):
                sid = s.attrib.get("id","http-script")
                out = s.attrib.get("output","")
                if out.strip():
                    findings.append({
                        "tool":"nmap","type":sid,"severity":"Info","confidence":"Low",
                        "message":out[:5000],"target":host
                    })
            # Scripts em nível de porta
            for port in root.findall(".//port"):
                for s in port.findall(".//script"):
                    sid = s.attrib.get("id","http-script")
                    out = s.attrib.get("output","")
                    if out.strip():
                        findings.append({
                            "tool":"nmap","type":sid,"severity":"Info","confidence":"Low",
                            "message":out[:5000],"target":host,
                            "port":port.attrib.get("portid"),"proto":port.attrib.get("protocol")
                        })
        finally:
            try: os.remove(xml_path)
            except: pass
        return findings or [{"tool":"nmap","type":"NoFindings","severity":"Info","message":"No Nmap http-script output"}]
    except subprocess.TimeoutExpired:
        return [{"tool":"nmap","type":"Timeout","severity":"Info","message":f"nmap timed out ({timeout}s)"}]
    except Exception as e:
        return [{"tool":"nmap","type":"Error","severity":"Info","message":str(e)}]

# ---------------- WhatWeb ----------------
def _parse_whatweb_jsonl(txt: str, target: str) -> List[Finding]:
    findings: List[Finding] = []
    # Alguns whatweb imprimem JSON por linha, outros um objeto único
    if "\n" in txt:
        for line in txt.splitlines():
            line=line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                plugins = obj.get("plugins", {})
                for name, arr in plugins.items():
                    evs = []
                    if isinstance(arr, list):
                        for v in arr:
                            if isinstance(v, dict):
                                s = v.get("string") or v.get("version") or v.get("name")
                                if s: evs.append(str(s))
                    msg = "; ".join([e for e in evs if e]) or "detected"
                    findings.append({"tool":"whatweb","type":name,"severity":"Info","message":msg,"target":target})
    else:
        try:
            obj = json.loads(txt)
            plugins = obj.get("plugins", {})
            for name, arr in plugins.items():
                evs = []
                if isinstance(arr, list):
                    for v in arr:
                        if isinstance(v, dict):
                            s = v.get("string") or v.get("version") or v.get("name")
                            if s: evs.append(str(s))
                msg = "; ".join([e for e in evs if e]) or "detected"
                findings.append({"tool":"whatweb","type":name,"severity":"Info","message":msg,"target":target})
        except Exception:
            pass
    return findings

def _parse_whatweb_text(txt: str, target: str) -> List[Finding]:
    # Fallback bem simples: "Plugin[detail], Plugin[detail] ..."
    findings: List[Finding] = []
    # Pega depois do primeiro espaço (geralmente é a URL seguida de plugins)
    parts = txt.strip().split(None, 1)
    if len(parts) < 2:
        return []
    plugins = parts[1]
    # Divide por vírgula mas mantém colchetes
    for chunk in plugins.split(","):
        chunk = chunk.strip()
        if not chunk: continue
        m = re.match(r"([A-Za-z0-9_\-]+)(\[(.*?)\])?", chunk)
        if not m: 
            continue
        name = m.group(1)
        detail = (m.group(3) or "").strip()
        findings.append({"tool":"whatweb","type":name,"severity":"Info","message":detail,"target":target})
    return findings

def run_whatweb(target: str, timeout: int = 120) -> List[Finding]:
    if not _which("whatweb"):
        return [{"tool":"whatweb","type":"ToolMissing","severity":"Info","message":"whatweb not found in PATH"}]
    try:
        # Preferimos JSON; alguns builds não suportam --log-json=- corretamente
        cp = _run_cmd(f"whatweb --log-json=- {shlex.quote(target)}", timeout=timeout)
        txt = (cp.stdout or "").strip()
        findings = _parse_whatweb_jsonl(txt, target)
        if not findings:
            # Fallback: saída padrão verbosa
            cp = _run_cmd(f"whatweb -v {shlex.quote(target)}", timeout=timeout)
            findings = _parse_whatweb_text((cp.stdout or "").strip(), target)
        return findings or [{"tool":"whatweb","type":"NoFindings","severity":"Info","message":"No plugins/evidence"}]
    except subprocess.TimeoutExpired:
        return [{"tool":"whatweb","type":"Timeout","severity":"Info","message":f"whatweb timed out ({timeout}s)"}]
    except Exception as e:
        return [{"tool":"whatweb","type":"Error","severity":"Info","message":str(e)}]

# ---------------- Nuclei ----------------
def run_nuclei(target: str, timeout: int = 180) -> List[Finding]:
    if not _which("nuclei"):
        return [{"tool":"nuclei","type":"ToolMissing","severity":"Info","message":"nuclei not found in PATH"}]
    try:
        cp = _run_cmd(f"nuclei -u {shlex.quote(target)} -json", timeout=timeout)
        findings: List[Finding] = []
        for line in (cp.stdout or "").splitlines():
            line=line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            findings.append({
                "tool":"nuclei",
                "type": obj.get("template-id") or obj.get("info",{}).get("name","nuclei-finding"),
                "severity": _norm_severity(obj.get("info",{}).get("severity","Info")),
                "message": obj.get("matcher-name") or obj.get("extracted-results") or obj.get("curl-command") or "",
                "target": obj.get("host") or target,
                "tags": obj.get("info",{}).get("tags",""),
            })
        return findings or [{"tool":"nuclei","type":"NoFindings","severity":"Info","message":"No nuclei results"}]
    except subprocess.TimeoutExpired:
        return [{"tool":"nuclei","type":"Timeout","severity":"Info","message":f"nuclei timed out ({timeout}s)"}]
    except Exception as e:
        return [{"tool":"nuclei","type":"Error","severity":"Info","message":str(e)}]

# ---------------- Wfuzz ----------------
_WFUZZ_TXT_RE = re.compile(r"Code:\s*(\d+).*?\bhttps?://\S+", re.I)

def _parse_wfuzz_json(txt: str, target: str) -> List[Finding]:
    """
    Wfuzz --json geralmente retorna um único objeto com 'results'.
    Cada item pode trazer 'input' e 'response'.
    """
    findings: List[Finding] = []
    if not txt.strip():
        return findings
    try:
        obj = json.loads(txt)
    except Exception:
        return findings
    results = obj.get("results") or []
    for r in results:
        resp = r.get("response", {})
        code = resp.get("code")
        url = resp.get("url") or target
        words = resp.get("words"); lines = resp.get("lines")
        sev = "Low" if code and int(code) in (200, 301, 302) else "Info"
        findings.append({
            "tool":"wfuzz","type":"DirectoryDiscovery","severity":sev,
            "message":f"HTTP {code} w:{words} l:{lines}","target":url
        })
    return findings

def _parse_wfuzz_text(txt: str, target: str) -> List[Finding]:
    findings: List[Finding] = []
    for line in (txt or "").splitlines():
        m = _WFUZZ_TXT_RE.search(line)
        if not m: 
            continue
        code = int(m.group(1))
        sev = "Low" if code in (200, 301, 302) else "Info"
        url_match = re.search(r"(https?://\S+)$", line.strip())
        url = url_match.group(1) if url_match else target
        findings.append({
            "tool":"wfuzz","type":"DirectoryDiscovery","severity":sev,
            "message":f"HTTP {code} (text parse)","target":url
        })
    return findings

def run_wfuzz_dirs(target: str, wordlist: str = None, timeout: int = 180) -> List[Finding]:
    if not _which("wfuzz"):
        return [{"tool":"wfuzz","type":"ToolMissing","severity":"Info","message":"wfuzz not found in PATH"}]
    wl = wordlist or os.environ.get("WFUZZ_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
    threads = os.environ.get("WFUZZ_THREADS", "40")
    url = (target.rstrip("/")) + "/FUZZ"
    cmd_json = f"wfuzz -t {threads} -u {shlex.quote(url)} -w {shlex.quote(wl)} --hc 404,400 --json"
    try:
        cp = _run_cmd(cmd_json, timeout=timeout)
        findings = _parse_wfuzz_json(cp.stdout or "", target)
        if not findings:
            cmd_txt = f"wfuzz -t {threads} -u {shlex.quote(url)} -w {shlex.quote(wl)} --hc 404,400"
            cp2 = _run_cmd(cmd_txt, timeout=timeout)
            findings = _parse_wfuzz_text(cp2.stdout or "", target)
        return findings or [{"tool":"wfuzz","type":"NoFindings","severity":"Info","message":"No wfuzz results"}]
    except subprocess.TimeoutExpired:
        return [{"tool":"wfuzz","type":"Timeout","severity":"Info","message":f"wfuzz timed out ({timeout}s)"}]
    except Exception as e:
        return [{"tool":"wfuzz","type":"Error","severity":"Info","message":str(e)}]

# ---------------- Orquestrador ----------------
def run_tools(selected: list, target: str, timeout: int = 180) -> List[Finding]:
    out: List[Finding] = []
    for t in selected or []:
        t = (t or "").lower().strip()
        if t == "nmap": out += run_nmap_http(target, timeout=timeout)
        elif t == "whatweb": out += run_whatweb(target, timeout=timeout)
        elif t == "nuclei": out += run_nuclei(target, timeout=timeout)
        elif t == "wfuzz": out += run_wfuzz_dirs(target, timeout=timeout)
        else:
            out.append({"tool":t,"type":"UnknownTool","severity":"Info","message":f"Tool not supported: {t}"})
    return out
