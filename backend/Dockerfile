FROM python:3.10-slim

# Install system dependencies including nmap and wget for downloading tools.
# sqlmap is packaged in Debian; the Exploit-DB clone backs searchsploit so
# the offline exploit lookup works with no network dependency at run time.
# msfconsole is deliberately NOT installed: the Metasploit console is a
# VM-only capability (the Kali attacker VM engine), and the execute endpoint
# refuses it in local mode for exactly that reason.
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    dnsutils \
    traceroute \
    whatweb \
    sslscan \
    sqlmap \
    git \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Offline Exploit-DB mirror for the searchsploit exploitation-phase steps.
# Pinned by clone at build time: the database content only affects lookup
# results, never what the framework is allowed to run.
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && rm -rf /opt/exploitdb/.git

# Install Nuclei. Pinned so a rebuild cannot silently change scanner behaviour.
# 3.1.9 died with "fatal error: concurrent map writes" partway through a normal
# tag-filtered run: exit 2, no findings, 149 seconds burned. Do not downgrade.
ARG NUCLEI_VERSION=3.11.1
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip && \
    unzip nuclei_${NUCLEI_VERSION}_linux_amd64.zip -d /usr/local/bin/ && \
    rm nuclei_${NUCLEI_VERSION}_linux_amd64.zip

# Seed the nuclei template library at build time. The default plan runs nuclei
# with -duc (no runtime update check, so scan duration cannot creep past the
# executor's timeout cap), and -duc makes a container without templates die
# with "no templates provided for scan". Note -duc must NOT be passed here:
# it turns the template install itself into a silent no-op.
RUN nuclei -update-templates

# OWASP ZAP for the passive baseline step. Debian's zaproxy package provides
# the ZAP core; the baseline wrapper is the ZAP project's own CI entrypoint
# (Apache-2.0), pinned by tag so a rebuild cannot silently change behaviour.
# The wrapper imports zap_common from its own directory, so both files go to
# the same place on PATH. The wrapper invokes ZAP via zap.sh, which the
# Debian package installs under /usr/share/zaproxy - linked onto PATH.
# Only the PASSIVE baseline is wired into the policy engine; the active
# scanner's flag (-a) is refused by the allowlist, so this install can never
# be turned into a payload-delivery engine through the framework.
ARG ZAP_WRAPPER_VERSION=v2.14.0
RUN apt-get update && apt-get install -y zaproxy \
    && rm -rf /var/lib/apt/lists/* \
    && wget -q https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_WRAPPER_VERSION}/docker/zap_common.py -O /usr/local/bin/zap_common.py \
    && wget -q https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_WRAPPER_VERSION}/docker/zap-baseline.py -O /usr/local/bin/zap-baseline.py \
    && chmod +x /usr/local/bin/zap-baseline.py \
    && ln -sf /usr/share/zaproxy/zap.sh /usr/local/bin/zap.sh

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
