FROM python:3.10-slim

# Install system dependencies including nmap and wget for downloading tools
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.9/nuclei_3.1.9_linux_amd64.zip && \
    unzip nuclei_3.1.9_linux_amd64.zip -d /usr/local/bin/ && \
    rm nuclei_3.1.9_linux_amd64.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
