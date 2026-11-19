# check=skip=InvalidDefaultArgInFrom

# Cortex with these analyzers and responders in /opt/Cortex-Analyzers, run by Cortex's process
# runner. Built from this checkout by `task build`, which passes the build arguments; the Taskfile
# pins the images.

# The Cortex image and the uv image: <image>:<tag>@<digest>.
ARG CORTEX_IMAGE
ARG UV_IMAGE

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------------------
# The checkout, split for the layers of the image: the requirements.txt files as installed (the
# install layer is rebuilt only when one of them changes), the files of 64 KiB or more (databases,
# report images: pushed again only when one of them changes) and the rest (the code: a change to
# it pushes a layer of a few MB).
# ---------------------------------------------------------------------------
FROM ${CORTEX_IMAGE} AS source

COPY . /small
WORKDIR /small

# ELASTICSEARCH_VERSION pins the Elasticsearch client to its major.minor (any patch release).
# stringsifter does not install here.
ARG ELASTICSEARCH_VERSION
RUN test -n "$ELASTICSEARCH_VERSION" && \
    sed -i "s/elasticsearch.*/elasticsearch~=${ELASTICSEARCH_VERSION%.*}/" analyzers/Elasticsearch/requirements.txt && \
    sed -i 's/stringsifter/# stringsifter/' analyzers/FileInfo/requirements.txt && \
    for f in analyzers/*/requirements.txt responders/*/requirements.txt; do \
      install -D -m 644 "$f" "/requirements/$f"; \
    done && \
    mkdir /large && \
    find . -type f -size +65535c -exec sh -c 'mkdir -p "/large/${1%/*}" && mv "$1" "/large/$1"' _ {} \;

# ---------------------------------------------------------------------------
# The image
# ---------------------------------------------------------------------------
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

RUN chown root:root / /var /var/log && \
    chmod 755 / /var /var/log

# Each requirement set is installed into the system Python on its own, in directory order, so a
# later set overrides the versions of an earlier one. A set that fails to install leaves its analyzer
# or responder broken, not the image: the failed ones are listed at the end of the step. uv is
# mounted for this step only; its cache lives for the step.
COPY --from=source /requirements /opt/Cortex-Analyzers
WORKDIR /opt/Cortex-Analyzers
RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    export UV_CACHE_DIR=/tmp/uv-cache CFLAGS="-fPIC" && \
    failed="" && \
    for f in analyzers/*/requirements.txt responders/*/requirements.txt; do \
      echo "Installing requirements for ${f%/requirements.txt}..." && \
      uv pip install --system --break-system-packages -r "$f" || \
        { echo "WARNING: Failed to install requirements for ${f%/requirements.txt}, continuing..."; \
          failed="$failed ${f%/requirements.txt}"; }; \
    done && \
    rm -rf "$UV_CACHE_DIR" && \
    echo "Requirement sets that failed to install:${failed:- none}"

COPY --from=source --chown=cortex:cortex --chmod=755 /large /opt/Cortex-Analyzers
COPY --from=source --chown=cortex:cortex --chmod=755 /small /opt/Cortex-Analyzers

WORKDIR /opt/cortex
