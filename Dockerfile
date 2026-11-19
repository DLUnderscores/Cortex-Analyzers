# check=skip=InvalidDefaultArgInFrom

# Cortex with these analyzers and responders in /opt/Cortex-Analyzers, run by Cortex's process
# runner. Built from this checkout by `task build`, which passes the build arguments; the Taskfile
# pins the Cortex image.

# The Cortex image: <image>:<tag>@<digest>.
ARG CORTEX_IMAGE

FROM ${CORTEX_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

# Tools and libraries the analyzers' Python packages build against or call.
RUN apt-get update && \
    apt-get install -y \
      git \
      python3-pip \
      python3-dev \
      unzip \
      libimage-exiftool-perl \
      libfuzzy-dev \
      python3-setuptools \
      ssdeep \
      libfuzzy2 \
      libmagic1 \
      build-essential \
      libssl-dev \
      cmake \
      wget \
      apt-transport-https && \
    rm -rf /var/lib/apt/lists/*

# PowerShell with the Exchange Online and WS-Management modules, for the responders that drive
# Exchange Online.
RUN wget -q https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb && \
    dpkg -i /tmp/packages-microsoft-prod.deb && \
    rm /tmp/packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y powershell-preview && \
    ln -s /usr/bin/pwsh-preview /usr/bin/pwsh && \
    rm -rf /var/lib/apt/lists/*

RUN pwsh -NoLogo -NoProfile -Command \
      "Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted; \
       Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -Force; \
       Install-Module -Name PSWSMan -Scope AllUsers -RequiredVersion 2.3.0 -Force; \
       Install-WSMan"

COPY . /opt/Cortex-Analyzers
WORKDIR /opt/Cortex-Analyzers

# ELASTICSEARCH_VERSION pins the Elasticsearch client to its major.minor (any patch release).
# stringsifter does not install here.
ARG ELASTICSEARCH_VERSION
RUN test -n "$ELASTICSEARCH_VERSION" && \
    sed -i "s/elasticsearch.*/elasticsearch~=${ELASTICSEARCH_VERSION%.*}/" analyzers/Elasticsearch/requirements.txt && \
    sed -i 's/stringsifter/# stringsifter/' analyzers/FileInfo/requirements.txt && \
    chmod -R 755 /opt/Cortex-Analyzers && \
    chown -R cortex:cortex /opt/Cortex-Analyzers

# A requirement set that fails to install leaves its analyzer or responder broken, not the image.
RUN for dir in analyzers responders; do \
      for subdir in $(ls $dir); do \
        if [ -f "$dir/$subdir/requirements.txt" ]; then \
          echo "Installing requirements for $dir/$subdir..." && \
          (CFLAGS="-fPIC" pip3 install --no-cache-dir --break-system-packages -r "$dir/$subdir/requirements.txt" || \
          echo "WARNING: Failed to install requirements for $dir/$subdir, continuing..."); \
        fi; \
      done; \
    done

RUN chown root:root / /var /var/log && \
    chmod 755 / /var /var/log

WORKDIR /opt/cortex
