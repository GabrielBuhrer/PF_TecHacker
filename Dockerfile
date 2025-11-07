
FROM python:3.10-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN adduser --disabled-password --gecos "" appuser

COPY src/requirements.txt /app/src/requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip procps \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip \
 && pip install -r /app/src/requirements.txt

COPY src/ /app/src/

ENV PATH="/app/src:${PATH}"

ARG INSTALL_EXTRAS="false"
RUN if [ "$INSTALL_EXTRAS" = "true" ]; then \
      set -eux; \
      apt-get update && apt-get install -y --no-install-recommends \
        nmap whatweb nikto \
      && rm -rf /var/lib/apt/lists/*; \
    fi

ARG INSTALL_NUCLEI="false"
RUN if [ "$INSTALL_NUCLEI" = "true" ]; then \
      set -eux; \
      mkdir -p /usr/local/bin; \
      if curl -fL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_amd64.zip -o /tmp/nuclei.zip; then \
        echo "Baixado nuclei_amd64.zip"; \
      else \
        ASSET_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | \
          grep browser_download_url | grep -E 'linux.*(amd64|x86_64).*zip' | head -n1 | cut -d '"' -f 4 || true); \
        if [ -n "$ASSET_URL" ]; then \
          curl -fL "$ASSET_URL" -o /tmp/nuclei.zip; \
        else \
          echo "Não foi possível localizar artefato do nuclei via API."; \
          exit 1; \
        fi; \
      fi; \
      unzip -o /tmp/nuclei.zip -d /usr/local/bin; \
      rm -f /tmp/nuclei.zip; \
      nuclei -version || true; \
    fi

ARG INSTALL_ZAP="false"
RUN if [ "$INSTALL_ZAP" = "true" ]; then \
      set -eux; \
      mkdir -p /opt/ZAP; \
      curl -fsSL https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap-baseline.py -o /opt/ZAP/zap-baseline.py; \
      curl -fsSL https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap_common.py   -o /opt/ZAP/zap_common.py; \
      chmod +x /opt/ZAP/zap-baseline.py; \
      ln -s /opt/ZAP/zap-baseline.py /usr/local/bin/zap-baseline.py; \
    fi

ENV ZAP_BASELINE_PATH=/opt/ZAP/zap-baseline.py \
    ZAP_TIMEOUT= \
    ZAP_BASELINE_MINUTES= \
    ZAP_BASELINE_FLAGS= \
    NIKTO_MAXTIME= \
    NIKTO_TIMEOUT= \
    NIKTO_FLAGS=

VOLUME ["/app/reports"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import sys; sys.exit(0)"

USER appuser

ENTRYPOINT ["python", "/app/src/scanner.py"]
CMD []

