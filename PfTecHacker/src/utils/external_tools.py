# src/utils/external_tools.py (fixed)
# - Nmap: usa hostname (extrai de URL) e T4 para mais velocidade
# - Wfuzz: threads e wordlist configuráveis via env (WFUZZ_THREADS, WFUZZ_WORDLIST)
import json, os, subprocess, shlex, tempfile, xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

Finding = Dict[str, Any]

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
    return subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)

# ---------------- Nmap ----------------
def run_nmap_http(target: str, timeout: int = 180) -> List[Finding]:
    if not _which("nmap"):
        return [{"tool":"nmap","type":"ToolMissing","severity":"Info","message":"nmap not found in PATH"}]
    host = urlparse(target).hostname or target  # <<< corrigido
    with tempfile.NamedTemporaryFile(prefix="nmap_", suffix=".xml", delete=False) as tf:
        xml_path = tf.name
    cmd = f"nmap -Pn -sV -T4 -p 80,443 --script=http-* -oX {xml_path} {host}"
    try:
        _ = _run_cmd(cmd, timeout=timeout)
        findings: List[Finding] = []
        try:
            tree = ET.parse(xml_path); root = tree.getroot()
            for hostscript in root.findall(".//hostscript/script"):
                sid = hostscript.attrib.get("id","http-script")
                out = hostscript.attrib.get("output","")
                if out.strip():
                    findings.append({"tool":"nmap","type":sid,"severity":"Info","confidence":"Low","message":out[:5000],"target":host})
            for port in root.findall(".//port"):
                script_elems = port.findall(".//script")
                for s in script_elems:
                    sid = s.attrib.get("id","http-script")
                    out = s.attrib.get("output","")
                    if out.strip():
                        findings.append({"tool":"nmap","type":sid,"severity":"Info","confidence":"Low","message":out[:5000],"target":host,"port":port.attrib.get("portid"),"proto":port.attrib.get("protocol")})
        finally:
            try: os.remove(xml_path)
            except: pass
        return findings or [{"tool":"nmap","type":"NoFindings","severity":"Info","message":"No Nmap http-script output"}]
    except subprocess.TimeoutExpired:
        return [{"tool":"nmap","type":"Timeout","severity":"Info","message":f"nmap timed out ({timeout}s)"}]

# ---------------- WhatWeb ----------------
def run_whatweb(target: str, timeout: int = 120) -> List[Finding]:
    if not _which("whatweb"):
        return [{"tool":"whatweb","type":"ToolMissing","severity":"Info","message":"whatweb not found in PATH"}]
    try:
        cp = _run_cmd(f"whatweb --log-json=- {target}", timeout=timeout)
        findings: List[Finding] = []
        txt = cp.stdout.strip()
        if not txt:
            return [{"tool":"whatweb","type":"NoOutput","severity":"Info","message":"empty stdout"}]
        try:
            # Alguns whatweb imprimem JSON por linha, outros um objeto único
            if "\n" in txt:
                for line in txt.splitlines():
                    line=line.strip()
                    if not line: continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            plugins = obj.get("plugins", {})
                            for name, arr in plugins.items():
                                ev = "; ".join([v.get("string","") for v in arr if isinstance(v, dict)])
                                findings.append({"tool":"whatweb","type":name,"severity":"Info","message":ev,"target":target})
                    except Exception:
                        continue
            else:
                obj = json.loads(txt)
                plugins = obj.get("plugins", {})
                for name, arr in plugins.items():
                    ev = "; ".join([v.get("string","") for v in arr if isinstance(v, dict)])
                    findings.append({"tool":"whatweb","type":name,"severity":"Info","message":ev,"target":target})
        except Exception as e:
            findings.append({"tool":"whatweb","type":"ParseError","severity":"Info","message":str(e)})
        return findings or [{"tool":"whatweb","type":"NoFindings","severity":"Info","message":"No plugins/evidence"}]
    except subprocess.TimeoutExpired:
        return [{"tool":"whatweb","type":"Timeout","severity":"Info","message":f"whatweb timed out ({timeout}s)"}]

# ---------------- Nuclei ----------------
def run_nuclei(target: str, timeout: int = 180) -> List[Finding]:
    if not _which("nuclei"):
        return [{"tool":"nuclei","type":"ToolMissing","severity":"Info","message":"nuclei not found in PATH"}]
    try:
        cp = _run_cmd(f"nuclei -u {shlex.quote(target)} -json", timeout=timeout)
        findings: List[Finding] = []
        for line in cp.stdout.splitlines():
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

# ---------------- Wfuzz ----------------
def run_wfuzz_dirs(target: str, wordlist: str = None, timeout: int = 180) -> List[Finding]:
    if not _which("wfuzz"):
        return [{"tool":"wfuzz","type":"ToolMissing","severity":"Info","message":"wfuzz not found in PATH"}]
    wl = wordlist or os.environ.get("WFUZZ_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
    threads = os.environ.get("WFUZZ_THREADS", "40")
    url = (target.rstrip("/")) + "/FUZZ"
    cmd = f"wfuzz -t {threads} -u {shlex.quote(url)} -w {shlex.quote(wl)} --hc 404,400 --json"
    try:
        cp = _run_cmd(cmd, timeout=timeout)
        findings: List[Finding] = []
        try:
            obj = json.loads(cp.stdout or "{}")
            for r in obj.get("results", []):
                u = r.get("url") or r.get("FUZZ")
                code = r.get("code"); words = r.get("words"); lines = r.get("lines")
                findings.append({"tool":"wfuzz","type":"DirectoryDiscovery","severity":"Info","message":f"HTTP {code} w:{words} l:{lines}","target":u or target})
        except Exception as e:
            findings.append({"tool":"wfuzz","type":"ParseError","severity":"Info","message":str(e)})
        return findings or [{"tool":"wfuzz","type":"NoFindings","severity":"Info","message":"No wfuzz results"}]
    except subprocess.TimeoutExpired:
        return [{"tool":"wfuzz","type":"Timeout","severity":"Info","message":f"wfuzz timed out ({timeout}s)"}]

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