FROM python:3.10-slim

# Install system dependencies including nmap and wget for downloading tools
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    dnsutils \
    traceroute \
    whatweb \
    sslscan \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

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

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
