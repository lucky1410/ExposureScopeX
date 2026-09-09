FROM golang:1.26.6-bookworm AS toolbuilder

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV GOBIN=/out
ENV GOTOOLCHAIN=local
ENV GOFLAGS=-mod=mod
WORKDIR /build

# renovate: datasource=github-releases depName=projectdiscovery/nuclei
ARG NUCLEI_VERSION=v3.11.1
# renovate: datasource=github-releases depName=projectdiscovery/subfinder
ARG SUBFINDER_VERSION=v2.16.0
# renovate: datasource=github-releases depName=projectdiscovery/httpx
ARG HTTPX_VERSION=v1.10.0
# renovate: datasource=github-releases depName=projectdiscovery/dnsx
ARG DNSX_VERSION=v1.3.0
# renovate: datasource=github-releases depName=projectdiscovery/naabu
ARG NAABU_VERSION=v2.6.1
# renovate: datasource=github-releases depName=projectdiscovery/katana
ARG KATANA_VERSION=v1.7.0
# renovate: datasource=github-releases depName=lc/gau
ARG GAU_VERSION=v2.2.4
# renovate: datasource=github-releases depName=tomnomnom/waybackurls
ARG WAYBACKURLS_VERSION=v0.1.0
# renovate: datasource=github-releases depName=tomnomnom/assetfinder
ARG ASSETFINDER_VERSION=v0.1.1
# renovate: datasource=github-commits depName=haccer/subjack
ARG SUBJACK_VERSION=v0.0.0-20260316055456-b53899ce6230
# renovate: datasource=github-releases depName=owasp-amass/amass
ARG AMASS_VERSION=v5.1.1
# renovate: datasource=github-releases depName=ffuf/ffuf
ARG FFUF_VERSION=v2.2.0

# Resolve all source-built tools in one module so security updates to shared Go
# libraries apply consistently instead of being hidden inside each tool graph.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out && go mod init exposurescopex.tools && \
    go get github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} && \
    go get github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} && \
    go get github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} && \
    go get github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION} && \
    go get github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} && \
    go get github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} && \
    go get github.com/lc/gau/v2/cmd/gau@${GAU_VERSION} && \
    go get github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION} && \
    go get github.com/tomnomnom/assetfinder@${ASSETFINDER_VERSION} && \
    go get github.com/haccer/subjack@${SUBJACK_VERSION} && \
    go get github.com/owasp-amass/amass/v5/cmd/amass@${AMASS_VERSION} && \
    go get github.com/ffuf/ffuf/v2@${FFUF_VERSION} && \
    go get golang.org/x/crypto@v0.55.0 golang.org/x/net@v0.58.0 \
      golang.org/x/text@v0.41.0 golang.org/x/mod@v0.40.0 \
      google.golang.org/grpc@v1.83.1 github.com/valyala/fasthttp@v1.69.0 \
      github.com/go-git/go-git/v5@v5.19.2 && \
    go mod download all && \
    go build -o /out/nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei && \
    go build -o /out/subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder && \
    go build -o /out/httpx github.com/projectdiscovery/httpx/cmd/httpx && \
    go build -o /out/dnsx github.com/projectdiscovery/dnsx/cmd/dnsx && \
    go build -o /out/naabu github.com/projectdiscovery/naabu/v2/cmd/naabu && \
    go build -o /out/katana github.com/projectdiscovery/katana/cmd/katana && \
    go build -o /out/gau github.com/lc/gau/v2/cmd/gau && \
    go build -o /out/waybackurls github.com/tomnomnom/waybackurls && \
    go build -o /out/assetfinder github.com/tomnomnom/assetfinder && \
    go build -o /out/subjack github.com/haccer/subjack && \
    go build -o /out/amass github.com/owasp-amass/amass/v5/cmd/amass && \
    go build -o /out/ffuf github.com/ffuf/ffuf/v2

FROM golang:1.26.6-bookworm AS security-tool-base
ENV GOTOOLCHAIN=local
ENV GOFLAGS=-mod=mod
WORKDIR /build

FROM security-tool-base AS trivy
# renovate: datasource=github-releases depName=aquasecurity/trivy
ARG TRIVY_VERSION=v0.74.0
RUN --mount=type=cache,id=exsx-security-go-mod,target=/go/pkg/mod \
    --mount=type=cache,id=exsx-security-go-build,target=/root/.cache/go-build \
    go mod init exposurescopex.trivy && \
    go get github.com/aquasecurity/trivy/cmd/trivy@${TRIVY_VERSION} && \
    go get google.golang.org/grpc@v1.83.1 && \
    GOEXPERIMENT=jsonv2 go build \
      -ldflags "-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION#v}" \
      -o /out/trivy github.com/aquasecurity/trivy/cmd/trivy

FROM security-tool-base AS gitleaks
# renovate: datasource=github-releases depName=gitleaks/gitleaks
ARG GITLEAKS_VERSION=v8.30.1
RUN --mount=type=cache,id=exsx-security-go-mod,target=/go/pkg/mod \
    --mount=type=cache,id=exsx-security-go-build,target=/root/.cache/go-build \
    go mod init exposurescopex.gitleaks && \
    go get github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION} && \
    go get golang.org/x/crypto@v0.55.0 golang.org/x/text@v0.41.0 && \
    go build -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" \
      -o /out/gitleaks github.com/zricethezav/gitleaks/v8

FROM security-tool-base AS syft
# renovate: datasource=github-releases depName=anchore/syft
ARG SYFT_VERSION=v1.51.1
RUN --mount=type=cache,id=exsx-security-go-mod,target=/go/pkg/mod \
    --mount=type=cache,id=exsx-security-go-build,target=/root/.cache/go-build \
    go mod init exposurescopex.syft && \
    go get github.com/anchore/syft/cmd/syft@${SYFT_VERSION} && \
    go get google.golang.org/grpc@v1.83.1 && \
    go build -ldflags "-s -w -X main.version=${SYFT_VERSION#v} -X main.gitDescription=${SYFT_VERSION}" \
      -o /out/syft github.com/anchore/syft/cmd/syft

FROM security-tool-base AS grype
# renovate: datasource=github-releases depName=anchore/grype
ARG GRYPE_VERSION=v0.118.0
RUN --mount=type=cache,id=exsx-security-go-mod,target=/go/pkg/mod \
    --mount=type=cache,id=exsx-security-go-build,target=/root/.cache/go-build \
    go mod init exposurescopex.grype && \
    go get github.com/anchore/grype/cmd/grype@${GRYPE_VERSION} && \
    go get google.golang.org/grpc@v1.83.1 && \
    go build -ldflags "-s -w -X main.version=${GRYPE_VERSION#v} -X main.gitDescription=${GRYPE_VERSION}" \
      -o /out/grype github.com/anchore/grype/cmd/grype

FROM python:3.14-slim

WORKDIR /app

# Install runtime dependencies for scanner tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl jq dnsutils whois nmap netcat-openbsd git openssl ca-certificates wget masscan libpq5 \
    perl libnet-ssleay-perl libio-socket-ssl-perl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY webapp/backend/requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

# renovate: datasource=pypi depName=prowler
ARG PROWLER_VERSION=5.41.0
# renovate: datasource=pypi depName=arjun
ARG ARJUN_VERSION=2.2.7
# renovate: datasource=pypi depName=sqlmap
ARG SQLMAP_VERSION=1.10.9
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/prowler && \
    /opt/prowler/bin/pip install prowler==${PROWLER_VERSION} && \
    ln -s /opt/prowler/bin/prowler /usr/local/bin/prowler
RUN --mount=type=cache,target=/root/.cache/pip \
    /opt/prowler/bin/pip install --no-deps --upgrade cryptography==50.0.1
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/aux-scanners && \
    /opt/aux-scanners/bin/pip install arjun==${ARJUN_VERSION} sqlmap==${SQLMAP_VERSION} && \
    ln -s /opt/aux-scanners/bin/arjun /usr/local/bin/arjun && \
    ln -s /opt/aux-scanners/bin/sqlmap /usr/local/bin/sqlmap
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade setuptools==84.0.0 wheel==0.46.3 jaraco.context==6.1.0 && \
    /opt/prowler/bin/pip install --upgrade setuptools==84.0.0 wheel==0.46.3 jaraco.context==6.1.0 && \
    /opt/aux-scanners/bin/pip install --upgrade setuptools==84.0.0 wheel==0.46.3 jaraco.context==6.1.0 && \
    find /usr/local/lib /opt/prowler /opt/aux-scanners -type d -name __pycache__ -prune \
      -exec rm -rf '{}' +

# Nikto is distributed as a self-contained Perl project. Keep only the working
# tree so runtime scans do not accumulate per-run clones or Git metadata.
ARG NIKTO_REVISION=312645d873478a77986627ab1fc8cffe595e85d4
RUN git clone --filter=blob:none --no-checkout https://github.com/sullo/nikto.git /opt/nikto && \
    git -C /opt/nikto checkout --detach ${NIKTO_REVISION} && \
    rm -rf /opt/nikto/.git && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install Go scanner binaries after pip so Python's httpx console script cannot
# overwrite the ProjectDiscovery httpx binary.
COPY --from=toolbuilder /out/ /usr/local/bin/
COPY --from=trivy /out/trivy /usr/local/bin/trivy
COPY --from=gitleaks /out/gitleaks /usr/local/bin/gitleaks
COPY --from=syft /out/syft /usr/local/bin/syft
COPY --from=grype /out/grype /usr/local/bin/grype

# Copy worker code
COPY webapp/worker/ ./worker/
COPY webapp/backend/app/ ./app/
COPY exposurescopex.sh ./exposurescopex.sh
COPY modules/ ./modules/
COPY config/ ./config/
RUN chmod +x /app/worker/entrypoint.sh /app/exposurescopex.sh /app/modules/*.sh

# Compose mounts framework sources for local development; packaged copies make
# the same image self-contained for isolated Kubernetes Jobs.

ENV PYTHONPATH=/app
ENV HOME=/app/runtime
ENV NUCLEI_TEMPLATES_DIR=/app/runtime/nuclei-templates
ENV NUCLEI_COMMUNITY_TEMPLATES_DIR=/app/runtime/nuclei-templates-community

RUN mkdir -p /app/runtime/nuclei-templates /app/runtime/nuclei-templates-community /app/runtime/.config /app/runtime/.cache && \
    chown -R 65532:20 /app/runtime && chmod -R 0770 /app/runtime

USER 65532:20
ENTRYPOINT ["/app/worker/entrypoint.sh"]
CMD ["celery", "-A", "app.services.celery_app:celery_app", "worker", \
     "--loglevel=info", "--queues=scans,reports,default", \
     "--concurrency=2", "--max-tasks-per-child=10"]
