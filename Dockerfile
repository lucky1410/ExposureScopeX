FROM kalilinux/kali-rolling

# Update and install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    nmap \
    nuclei \
    subfinder \
    assetfinder \
    sqlmap \
    hydra \
    dirsearch \
    whatweb \
    wapiti \
    httpx \
    waybackurls \
    feroxbuster \
    katana \
    pandoc \
    weasyprint \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Make scripts executable
RUN chmod +x exposurescopex.sh modules/*.sh

# Entry point
ENTRYPOINT ["./exposurescopex.sh"]
CMD ["-h"]
