# PfTecHacker — Ferramenta de Varredura de Segurança Web (OWASP Top 10 — Básico)

> **Resumo:** CLI para varredura automática de aplicações web com detecções básicas (OWASP Top 10) e integrações com ferramentas de segurança. Gera relatórios **JSON/CSV/Markdown**, integra **ZAP/Nikto** (opcional) e suporta **Nmap/WhatWeb/Nuclei/Wfuzz**.

![arquitetura](docs/architecture_diagram.png)

---

## 📚 Sumário
- [Visão Geral](#-visão-geral)
- [Arquitetura & Fluxo](#-arquitetura--fluxo)
- [Instalação](#-instalação)
- [Uso Rápido](#-uso-rápido)
- [Opções da CLI](#-opções-da-cli)
- [Integrações & Ferramentas Extras](#-integrações--ferramentas-extras)
- [Relatórios (JSON/CSV/MD)](#-relatórios-jsoncsvmd)
- [Metodologia de Testes](#-metodologia-de-testes)
- [Vulnerabilidades Detectadas](#-vulnerabilidades-detectadas)
- [Recomendações de Mitigação](#-recomendações-de-mitigação)
- [CI/CD (GitHub Actions)](#-cicd-github-actions)
- [Docker](#-docker)
- [Vídeo Demonstrativo](#-vídeo-demonstrativo)
- [Limitações, Escopo & Ética](#-limitações-escopo--ética)
- [Roadmap](#-roadmap)
- [Rubrica & Checklist da Banca](#-rubrica--checklist-da-banca)
- [Créditos & Licença](#-créditos--licença)

---

## 🔎 Visão Geral
Trata-se de uma ferramenta **educacional** de varredura de segurança para aplicações web. Ela executa um **crawl leve** do alvo e aplica uma série de **scanners heurísticos** para identificar vulnerabilidades comuns. Em seguida, consolida os achados, gera relatórios e (opcionalmente) executa integrações de terceiros para compor evidências adicionais.

**Principais recursos**
- CLI única (`src/scanner.py`) com **crawl** controlado
- Scanners internos: **CSRF**, **Exposição de Informações**, **SQL Injection (GET)**, **XSS Refletido**, **Directory Traversal/LFI**, **Command Injection**
- Integrações opcionais: **OWASP ZAP (baseline)**, **Nikto**
- Ferramentas extras (quando disponíveis): **Nmap**, **WhatWeb**, **Nuclei**, **Wfuzz**
- Relatórios automáticos: **JSON**, **Markdown**, **CSV**
- Logs em console e estrutura de pastas organizada

**Requisitos mínimos**
- Python ≥ 3.9
- `pip install -r requirements.txt` (BeautifulSoup4, requests, etc.)
- (Opcional) Docker para ZAP; `nikto`, `nmap`, `whatweb`, `nuclei`, `wfuzz` instalados localmente se quiser usar as integrações/extras

Testado em: Ubuntu 22.04 / Python 3.10

---

## 🧱 Arquitetura & Fluxo
Arquitetura em alto nível (detalhe no diagrama `docs/architecture_diagram.png`):
1. **CLI/Runner** → recebe argumentos e coordena execução
2. **Crawler** → coleta links e formulários (mesmo domínio) com limite de profundidade/URLs
3. **Scanners Internos** → heurísticas rápidas sobre cada URL/HTML
4. **Integrações/Extras (opcional)** → ZAP/Nikto/Nmap/etc.
5. **Consolidador** → sumariza por tipo e severidade
6. **Gerador de Relatórios** → escreve JSON/CSV/MD em `reports/`

Fluxo (detalhe no `docs/flowchart.pdf`): URL de entrada → crawl → testes por categoria → integrações → consolidação → export.

---

## ⚙️ Instalação
```bash
# Clonar e entrar no diretório do projeto
git clone <SEU_REPO>.git
cd <SEU_REPO>

# (Opcional) Ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# Dependências
pip install -r requirements.txt
```

> Para ZAP baseline via Docker: `docker --version` deve funcionar. Para Nikto: instale via gerenciador da sua distro. Ferramentas extras idem.

---

## 🚀 Uso Rápido
Exemplo com alvo de laboratório:
```bash
python src/scanner.py \
  -u http://testphp.vulnweb.com \
  --depth 2 --timeout 300 \
  --export json md csv \
  --extra-tools nmap whatweb wfuzz \
  --output-dir reports
```

Executar com integrações (se instaladas):
```bash
python src/scanner.py -u https://example.com --integrations zap nikto --export md json
```

Saída esperada (console): resumo de achados + pasta `reports/` contendo `report.json`, `report.md` e `report.csv`.

---

## 🧩 Opções da CLI
```
-u, --url            URL alvo (http/https)
--depth              Profundidade do crawl (default: 2)
--timeout            Timeout total em segundos (default: 120)
--export             Formatos: json | md | csv (padrão: json md)
--integrations       zap | nikto (opcional)
--extra-tools        nmap | whatweb | nuclei | wfuzz (opcional)
--output-dir         Diretório para salvar relatórios (default: reports)
```

Limites internos:
- `MAX_URLS_TO_SCAN = 10` (evita abusos)
- `PER_REQUEST_TIMEOUT = 5s` (por requisição)

---

## 🔗 Integrações & Ferramentas Extras
- **ZAP baseline (Docker)** — varredura passiva rápida (gera `zap_report.html` localmente no container). Útil para ampliar cobertura de detecções passivas.
- **Nikto** — checagens de configuração e conteúdos sensíveis.
- **Extras** (se presentes no sistema):
  - **Nmap** — fingerprint/portas;
  - **WhatWeb** — tecnologias e versões;
  - **Nuclei** — templates de vulnerabilidades;
  - **Wfuzz** — fuzzing simplificado.

---

## 📄 Relatórios (JSON/CSV/MD)
Os arquivos são gravados em `reports/`.

**Estrutura `report.json`**
```json
{
  "target": "https://example.com",
  "datetime": "2025-10-30 11:59:59",
  "duration_seconds": 12.34,
  "urls_scanned": 7,
  "vulnerability_summary": {
    "SQL Injection": 1,
    "XSS Refletido": 2,
    "severity_High": 3,
    "total": 4
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "url": "https://example.com/products?id=' OR 1=1--",
      "severity": "High",
      "parameter": "id",
      "payload": "' OR 1=1--",
      "evidence": "DB error pattern",
      "tool": "internal",
      "confidence": "Medium"
    }
  ],
  "integrations": ["ZAP baseline executed"],
  "extra_tools": ["Nikto executed"]
}
```
---

## 🧪 Metodologia de Testes
**Alvos de demonstração (laboratório):**
- `http://testphp.vulnweb.com` (Acunetix Test Site)
- `https://juice-shop.herokuapp.com` (OWASP Juice Shop – instância pública)

**Parâmetros recomendados:** `--depth 2`, `--timeout 300`, `--export json md csv`.

**Critérios de confirmação (heurísticos):**
- **SQLi (GET):** padrão de erro de banco no corpo (ex.: *SQL syntax*, *ORA-...*).
- **XSS Refletido:** reflexão literal do payload/assinaturas típicas (`<script>alert(1)`, `onerror=alert(1)`).
- **Traversal/LFI:** presença de trecho `root:x:0:0` indicando leitura de `/etc/passwd` em ambientes vulneráveis de laboratório.
- **Command Injection:** ocorrência de `uid=\d+` no corpo (resultado de `id`).
- **CSRF:** formulário `POST` sem nenhum campo com `csrf|token|xsrf|nonce`.
- **Exposição de Informações:** *headers* ou corpo contendo `X-Powered-By`, `Stack trace`, `Index of /`, `.env`, etc.

---

## 🛡️ Vulnerabilidades Detectadas
| Categoria | Como detectamos | Evidência típica | Severidade padrão |
|---|---|---|---|
| **SQL Injection (GET)** | Injeta payloads em parâmetros de query e busca padrões de erro SQL | `You have an error in your SQL`, `ORA-...` | High |
| **XSS Refletido** | Injeta payloads XSS e verifica reflexão ou *signatures* | `<script>alert(1)`, `onerror=alert(1)` | High/Medium |
| **Directory Traversal / LFI** | Parâmetros suspeitos (`file`, `path`, etc.) com `../../..` | `root:x:0:0` | High |
| **Command Injection** | Parâmetros suspeitos (`cmd`, `exec`) com `id;id` | `uid=1000` | Critical |
| **CSRF (POST sem token)** | Formulários `POST` sem campos tipo `csrf|token|nonce` | "Form POST sem token" | Medium |
| **Sensitive Data Exposure** | Padrões nos headers/corpo | `X-Powered-By`, `Stack trace`, `.env` | Low |

---

## 🔧 Recomendações de Mitigação
- **SQL Injection:** consultas parametrizadas/ORM, *stored procedures* seguras, *least privilege* no DB, WAF.
- **XSS:** *output encoding*, CSP, validação do lado servidor, *HttpOnly/Secure* em cookies.
- **CSRF:** tokens anti-CSRF com *double submit* ou *SameSite=strict*, *nonce* por sessão.
- **Traversal/LFI:** normalização de caminho, *allowlist* de arquivos, desabilitar *directory listing*.
- **Command Injection:** *whitelist* de comandos/argumentos, usar APIs seguras (sem shell), *no user input → shell*.
- **Exposure/Headers:** remover `X-Powered-By`, ativar `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.

---

## 🏗️ CI/CD (GitHub Actions)
Arquivo exemplo: `.github/workflows/security_scan.yml`
```yaml
name: security-scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - run: pip install -r requirements.txt
      - run: |
          python src/scanner.py \
            -u http://testphp.vulnweb.com \
            --depth 1 --timeout 180 \
            --export json md csv \
            --output-dir reports
      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: reports
          path: reports/*
```

---

## 🐳 Docker
**Dockerfile** (exemplo) instala dependências e define *entrypoint*. Para usar a ferramenta dentro do container:
```bash
docker build -t pftechacker:latest .

docker run --rm -it \
  -v $(pwd)/reports:/app/reports \
  pftechacker:latest \
  python src/scanner.py -u http://testphp.vulnweb.com --export md json csv
```

Para rodar **ZAP baseline** a partir da máquina host (integração da ferramenta usa `docker run` internamente):
```bash
docker run --rm owasp/zap2docker-stable zap-baseline.py -t http://testphp.vulnweb.com -m 3 -r zap_report.html
```

---

## 🎥 Vídeo Demonstrativo

Cole o link aqui: **[Vídeo (YouTube — Não Listado)](https://exemplo.com/SEU_VIDEO)**

---

