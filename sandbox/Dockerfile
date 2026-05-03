FROM eclipse-temurin:17-jdk-jammy

# 1. Environment & Tools
ENV MAVEN_VERSION=3.9.15
ENV GRADLE_VERSION=9.4.1
ENV PATH="/opt/maven/bin:/opt/gradle/bin:${PATH}"

RUN apt-get update && apt-get install -y \
    python3 python3-pip git curl unzip \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Maven & Gradle
RUN curl -fsSL https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz | tar xzf - -C /opt \
    && ln -s /opt/apache-maven-${MAVEN_VERSION} /opt/maven
RUN curl -fsSL https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip -o gradle.zip \
    && unzip -q gradle.zip -d /opt \
    && ln -s /opt/gradle-${GRADLE_VERSION} /opt/gradle \
    && rm gradle.zip

# 3. OSV-Scanner
RUN curl -fsSL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner

# 4. User Setup (CRITICAL ORDER)
RUN useradd -m agent
WORKDIR /home/agent/workspace

# 5. Requirements (Install as root first to avoid permission warnings)
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# 6. Finalize permissions and switch user
RUN chown -R agent:agent /home/agent/workspace
USER agent

CMD ["/bin/bash"]