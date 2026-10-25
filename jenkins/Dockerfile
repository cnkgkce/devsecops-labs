FROM jenkins/jenkins:lts-jdk17

USER root

# Install required OS dependencies & Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    python3-venv \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

# 1. Install Docker CLI
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && apt-get install -y --no-install-recommends docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# 2. Install Trivy (SCA & Container Security)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# 3. Install Semgrep (SAST) in a global venv so it is accessible in PATH
ENV VIRTUAL_ENV=/opt/security-tools-venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN pip install --no-cache-dir semgrep requests

# Ensure jenkins user has permission to use docker socket
RUN groupadd -f docker && usermod -aG docker jenkins

# Ensure the venv and tools are readable & executable by jenkins user
RUN chown -R jenkins:jenkins /opt/security-tools-venv

USER jenkins

# Pre-install recommended Jenkins plugins
COPY --chown=jenkins:jenkins plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli -f /usr/share/jenkins/ref/plugins.txt
