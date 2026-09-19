FROM python:3.12-slim-bookworm AS api
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 redteam \
    && mkdir -p /app/data && chown redteam:redteam /app/data
COPY main.py database.py models.py worker.py ./
COPY modules/ ./modules/
COPY migrations/ ./migrations/
USER redteam
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM api AS scanner
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl dnsutils traceroute whatweb sslscan sqlmap git wget unzip default-jre-headless \
    && rm -rf /var/lib/apt/lists/*
# Reviewed immutable source revisions. Runtime updates are disabled by policy.
ARG EXPLOITDB_REVISION=150aef0e7c4757c9dff33016c8352671cdc9b454
ARG NUCLEI_TEMPLATES_REVISION=8e200457539ad6a70d0d94cf816935688ea65478
ARG NUCLEI_VERSION=3.11.1
ARG ZAP_VERSION=2.17.0
# Revision of zaproxy/zaproxy that ships the docker/ baseline scripts matching
# the pinned ZAP release (commit touching docker/zap-baseline.py, 2026-07-06).
ARG ZAP_REVISION=d4ccc5801f34107a213fccd548139d191135b8e5
RUN git init /opt/exploitdb && cd /opt/exploitdb \
    && git remote add origin https://gitlab.com/exploit-database/exploitdb.git \
    && git fetch --depth 1 origin ${EXPLOITDB_REVISION} && git checkout FETCH_HEAD \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && rm -rf /opt/exploitdb/.git
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin && rm /tmp/nuclei.zip \
    && git init /home/redteam/nuclei-templates && cd /home/redteam/nuclei-templates \
    && git remote add origin https://github.com/projectdiscovery/nuclei-templates.git \
    && git fetch --depth 1 origin ${NUCLEI_TEMPLATES_REVISION} && git checkout FETCH_HEAD \
    && rm -rf .git && chown -R redteam:redteam /home/redteam
RUN wget -q https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz -O /tmp/zap.tar.gz \
    && tar -xzf /tmp/zap.tar.gz -C /opt && rm /tmp/zap.tar.gz \
    && ln -s /opt/ZAP_${ZAP_VERSION}/zap.sh /usr/local/bin/zap.sh \
    && wget -q https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_REVISION}/docker/zap_common.py -O /usr/local/bin/zap_common.py \
    && wget -q https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_REVISION}/docker/zap-baseline.py -O /usr/local/bin/zap-baseline.py \
    && chmod +x /usr/local/bin/zap-baseline.py \
    && pip install --no-cache-dir zaproxy==0.6.0 pyyaml==6.0.2
RUN printf '{"nuclei":"%s","templates_revision":"%s","exploitdb_revision":"%s","zap":"%s"}\n' "$NUCLEI_VERSION" "$NUCLEI_TEMPLATES_REVISION" "$EXPLOITDB_REVISION" "$ZAP_VERSION" > /opt/tool-versions.json
USER redteam
