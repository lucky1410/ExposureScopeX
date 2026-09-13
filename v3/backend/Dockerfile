FROM golang:1.26.6-bookworm AS nuclei-builder

ARG NUCLEI_VERSION=v3.11.1
ENV GOBIN=/out
WORKDIR /build
RUN mkdir -p /out && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS api
COPY app ./app
RUN useradd --system --uid 10001 --create-home esx && \
    mkdir -p /data/artifacts && chown -R esx:esx /data/artifacts
USER esx
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM base AS runner
ARG NUCLEI_TEMPLATES_VERSION=v10.4.8
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN mkdir -p /ms-playwright && python -m playwright install --with-deps chromium && \
    apt-get update && apt-get install -y --no-install-recommends \
      nmap openssl xvfb xterm scrot xdotool fonts-dejavu-core && \
    rm -rf /var/lib/apt/lists/* && chmod -R a+rX /ms-playwright
COPY --from=nuclei-builder /out/nuclei /usr/local/bin/nuclei
RUN python -c "import io, os, tarfile, urllib.request; version=os.environ.get('NUCLEI_TEMPLATES_VERSION', '${NUCLEI_TEMPLATES_VERSION}'); data=urllib.request.urlopen(f'https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{version}.tar.gz', timeout=120).read(); archive=tarfile.open(fileobj=io.BytesIO(data), mode='r:gz'); root=archive.getmembers()[0].name.split('/')[0]; archive.extractall('/tmp'); os.rename('/tmp/' + root, '/opt/nuclei-templates')" && \
    printf '%s\n' "${NUCLEI_TEMPLATES_VERSION}" > /opt/nuclei-templates/.esx-template-release && \
    chmod -R a+rX /opt/nuclei-templates
COPY app ./app
RUN useradd --system --uid 10001 --create-home esx && \
    mkdir -p /data/artifacts && chown -R esx:esx /data/artifacts
USER esx
CMD ["python", "-m", "app.runner"]
