# PfTecHacker — Relatório Técnico & Guia de Uso
> **Projeto:** Ferramenta educacional de varredura de segurança web (OWASP Top 10 — Básico), com detecções heurísticas e integrações opcionais.

---

## 1) Descrição do Sistema & Arquitetura
**O que é:** uma CLI (`src/scanner.py`) que realiza um crawl leve do alvo e aplica scanners heurísticos para detectar vulnerabilidades comuns do OWASP Top 10, gerando relatório em **JSON**. Integrações opcionais (ZAP/Nikto) e ferramentas extras (Nmap/WhatWeb/Nuclei) podem enriquecer as evidências.

**Arquitetura (alto nível):**
1. **CLI/Runner** — orquestra tudo, argumentos, timeouts e logs/heartbeat.
2. **Crawler** — coleta links e formulários do mesmo domínio (respeita `--depth` e limite de URLs).
3. **Scanners internos** — heurísticas rápidas:
   - SQL Injection (GET)
   - XSS Refletido
   - CSRF (POST sem token)
   - Directory Traversal / LFI
   - Command Injection
   - Exposure/Info Disclosure
4. **Integrações/Opcionais** — ZAP baseline, Nikto.
5. **Extras** — Nmap/WhatWeb/Nuclei.
6. **Consolidador** — resumo por tipo e severidade.
7. **Gerador de Relatórios** — escreve JSON em `reports/` + outputs do ZAP/Nikto.

**Diagramas (draw.io):**
- `docs/architecture_diagram.png` (Arquitetura, com ligação tracejada “status/métricas” entre CLI e Heartbeat & Logs)
- `docs/flowchart.pdf` (Fluxo: args → crawl → scans → integrações → consolidação → relatórios)

---

## 2) Instalação (Host)

```bash
# Clonar e entrar
git clone <SEU_REPO>.git
cd <SEU_REPO>

# (Opcional) venv
python3 -m venv .venv
source .venv/bin/activate

# Dependências Python (o projeto guarda o requirements dentro de src/)
pip install -r src/requirements.txt
```

**Ferramentas opcionais no host (se quiser usar integrações/extras):**
- ZAP baseline (scripts `zap-baseline.py`)
- `nikto`, `nmap`, `whatweb`, `nuclei` (instale via apt/zip conforme desejar)

---

## 3) Uso Rápido (exemplos)
A seguir estão exemplos prontos de execução da ferramenta **com** e **sem** limites de tempo.  
Os timeouts são **opcionais**; você pode removê-los totalmente ou usar um valor muito alto no `--timeout` para simular “sem limite” prático.

---

## Exemplo simples
```bash
python src/scanner.py \
  -u http://testphp.vulnweb.com \
  --depth 2 --timeout 300 \
  --export json \
  --output-dir reports
```

---

## Executar com tudo (se instalado no host), com **timeouts OPCIONAIS**

```bash
export ZAP_BASELINE_PATH=/opt/ZAP/zap-baseline.py
export ZAP_TIMEOUT=600        # opcional (s) — remova para não limitar o ZAP
export NIKTO_MAXTIME=300      # opcional (s) — remova para não limitar o Nikto

python src/scanner.py \
  -u https://demo.testfire.net \
  --depth 1 --timeout 1800 \
  --integrations zap nikto \
  --extra-tools nmap whatweb nuclei \
  --zap-mins 5 \
  --nikto-maxtime 300 \
  --output-dir "reports/full_$(date +%Y%m%d-%H%M%S)"
```

---

## Executar sem "timeout" prático (global) e **sem** limitar ZAP/Nikto
Se quiser rodar "sem limite" efetivo, use um valor **bem grande** para `--timeout` e **não** defina os timeouts do ZAP/Nikto:

```bash
unset ZAP_TIMEOUT 2>/dev/null || true
unset NIKTO_MAXTIME 2>/dev/null || true

# Se for usar o ZAP baseline, informe apenas o caminho do script
export ZAP_BASELINE_PATH=/opt/ZAP/zap-baseline.py

python src/scanner.py \
  -u https://demo.testfire.net \
  --depth 1 --timeout 999999 \
  --integrations zap nikto \
  --extra-tools nmap whatweb nuclei \
  --zap-mins 5 \
  --output-dir "reports/full_$(date +%Y%m%d-%H%M%S)"
```

---

## 4) Opções da CLI
```
-u, --url            URL alvo (http/https) [obrigatório]
--depth              Profundidade do crawl (default: 2)
--timeout            Timeout total do processo, em s (default: 120)
--export             json (padrão e única opção)
--integrations       zap | nikto (opcional; depende das ferramentas no host)
--extra-tools        nmap | whatweb | nuclei (opcional)
--zap-mins           Minutos de spider para o ZAP baseline (opcional)
--nikto-maxtime      Tempo máximo para o Nikto, em s (opcional)
--output-dir         Diretório de saída (default: reports)
```

---

## 5) Metodologia de Testes
- **Crawl BFS** dentro do mesmo domínio, com profundidade e número de URLs limitados.
- **Scanners heurísticos** aplicados por URL:
  - **SQLi (GET):** injeta payloads nos parâmetros e busca _patterns_ de erro (ex.: `SQL syntax`, `ORA-...`).
  - **XSS Refletido:** injeta payloads comuns (`<script>alert(1)` etc.) e verifica reflexão/assinaturas (onerror, svg/onload).
  - **Traversal/LFI:** força `../../..` em parâmetros suspeitos (`file`, `path`…) e procura `root:x:0:0`.
  - **Command Injection:** injeta `id;id` em parâmetros como `cmd/exec` e procura `uid=\d+`.
  - **CSRF:** formulário `POST` sem campos `csrf|token|xsrf|nonce`.
  - **Exposure/Info:** `X-Powered-By`, `Index of /`, `.env`, _stack trace_, etc., em headers/corpo.
- **Integrações/Extras** (opcional) para evidências adicionais passivas/assinaturas.
- **Relatórios** com sumário e achados detalhados (JSON).

---

## 6) Resultados Obtidos (execução real — 06/Nov/2025)

**Comando executado (exemplo do run real):**
```bash
export ZAP_BASELINE_PATH=/opt/ZAP/zap-baseline.py

python src/scanner.py \
  -u https://demo.testfire.net \
  --depth 1 --timeout 99999 \
  --export json \
  --integrations zap \
  --extra-tools nmap whatweb nuclei \
  --zap-mins 5 \
  --nikto-maxtime 300 \
  --output-dir "reports/full_$(date +%Y%m%d-%H%M%S)"
```

**Achados internos (scanner.py):**

- **CSRF (Medium)** – login.jsp (e também visto em feedback.jsp/subscribe.jsp em execuções anteriores): Form POST sem token.
  - **Mapeamento OWASP 2021:** A01 – Broken Access Control (CSRF foi incorporado em A01).

**Achados ZAP (zap_report.json do mesmo run):**

- **Content Security Policy (CSP) Header Not Set** – várias páginas.  
  - **Mapeamento:** A05 – Security Misconfiguration.

- **Missing Anti-clickjacking Header (X-Frame-Options / frame-ancestors)** – várias páginas.  
  - **Mapeamento:** A05 – Security Misconfiguration.

- **Strict-Transport-Security (HSTS) Header Not Set** – várias páginas.  
  - **Mapeamento:** A02 – Cryptographic Failures.

- **X-Content-Type-Options Header Missing** – várias páginas.  
  - **Mapeamento:** A05 – Security Misconfiguration.

- **Mixed Content (incluindo scripts)** – ex.: `index.jsp?content=personal_investments.htm` carrega `http://demo-analytics.testfire.net/urchin.js`.  
  - **Mapeamento:** A02 – Cryptographic Failures.

- **Cookie without SameSite (JSESSIONID)** – várias respostas.  
  - **Mapeamento:** A05 – Security Misconfiguration (mitigação de CSRF).

- **Subresource Integrity (SRI) ausente** para recurso externo – `urchin.js`.  
  - **Mapeamento:** A08 – Software and Data Integrity Failures.

- **Server header expõe versão** (`Apache-Coyote/1.1`).  
  - **Mapeamento:** A05 – Security Misconfiguration.

- **(Informativos adicionais)** – ex.: `Permissions-Policy` ausente, *Suspicious Comments*, etc.  


**Conclusão:** No conjunto (scanner interno + ZAP), evidenciamos ≥ 4 categorias do OWASP Top 10 (2021):
- A01 Broken Access Control (CSRF),

- A02 Cryptographic Failures (HSTS ausente, mixed content),

- A05 Security Misconfiguration (CSP/XFO/XCTO/Server header),

- A08 Software and Data Integrity Failures (SRI ausente).

---

## 7) Sugestões de Mitigação
- **SQL Injection:** parametrização/ORM, validação server-side, princípio do menor privilégio no DB, WAF.
- **XSS Refletido:** _output encoding_, CSP, validação server-side, `HttpOnly/Secure` em cookies.
- **CSRF:** tokens anti-CSRF por requisição, `SameSite=strict`, *double submit* ou frameworks com proteção nativa.
- **Traversal/LFI:** normalização/saneamento de paths, *allowlist* de arquivos, proibir `..`, desabilitar *directory listing*.
- **Command Injection:** nunca concatenar entrada do usuário em shell; usar APIs seguras; *allowlist* de comandos.
- **Exposure/Headers:** remover `X-Powered-By`; adicionar `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.

---

## 8) Integrações & Ferramentas Extras
- **ZAP baseline (host)**  
  Instale os scripts:
  ```bash
  sudo mkdir -p /opt/ZAP
  sudo curl -L https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap-baseline.py -o /opt/ZAP/zap-baseline.py
  sudo curl -L https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap_common.py   -o /opt/ZAP/zap_common.py
  sudo chmod +x /opt/ZAP/zap-baseline.py
  export ZAP_BASELINE_PATH=/opt/ZAP/zap-baseline.py
  ```
  Flags/vars **opcionais**: `--zap-mins`, `ZAP_TIMEOUT`.

- **Nikto (host)**  
  `sudo apt-get install -y nikto`  
  Var **opcional**: `NIKTO_MAXTIME` (limita a duração interna do Nikto), `--nikto-maxtime` na CLI.

- **Extras (host, opcionais):**  
  `nmap`, `whatweb`, `nuclei` (e.g., `sudo apt-get install -y nmap whatweb`; Nuclei via binário zip oficial).

---

## 9) Relatórios
Gerados em `reports/`:
- **`report.json`** — relatório principal consolidado com alvo, data/hora, duração, URLs escaneadas, sumário por tipo/severidade, lista de vulnerabilidades (com parâmetro, payload, evidência).
- **`zap_report.json`** e **`zap_report.html`** — saídas do ZAP Baseline (quando `--integrations zap` é usado).
- **`nikto_output.txt`** — saída do Nikto (quando `--integrations nikto` é usado).

Exemplo de entrada em `report.json`:
```json
{
  "type": "CSRF",
  "url": "https://demo.testfire.net/subscribe.jsp",
  "severity": "Medium",
  "evidence": "Form POST sem token",
  "tool": "internal",
  "confidence": "Medium"
}
```

---

## 10) CI/CD (GitHub Actions)
Workflow em `.github/workflows/security_scan.yml` (requirements em `src/`):

```yaml
name: security-scan
on:
  push:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.10"
          cache: "pip"
          cache-dependency-path: |
            src/requirements.txt

      - name: Install Python deps
        run: |
          python -m pip install --upgrade pip
          pip install -r src/requirements.txt

      - name: Install host tools (optional)
        run: |
          sudo apt-get update
          sudo apt-get install -y nmap whatweb
          whatweb --version || true
          nmap --version || true

      - name: Run security scan
        run: |
          mkdir -p reports
          python src/scanner.py \
            -u http://testphp.vulnweb.com \
            --depth 1 --timeout 180 \
            --extra-tools nmap whatweb \
            --output-dir reports/ci_${{ github.run_id }}

      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: reports/**
```

---

## 11) Docker (opcional)
O repositório inclui um **Dockerfile** para empacotar a CLI.  
Exemplo de build mínimo:
```bash
docker build -t pftechacker:latest .
docker run --rm -v "$PWD/reports:/app/reports" pftechacker:latest \
  -u http://testphp.vulnweb.com
```
> Para instalar ferramentas externas na imagem, use `--build-arg`.

## 12) Vídeo de demonstração

https://youtu.be/EG_foAJ2JaA