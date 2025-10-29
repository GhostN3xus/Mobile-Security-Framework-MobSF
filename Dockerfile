# Base image
FROM python:3.11-slim-bookworm

LABEL \
    name="MobSF" \
    author="Ajin Abraham <ajin25@gmail.com>" \
    maintainer="Ajin Abraham <ajin25@gmail.com>" \
    contributor_1="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    contributor_2="Vincent Nadal <vincent.nadal@orange.fr>" \
    description="Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis."

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    MOBSF_USER=mobsf \
    USER_ID=9901 \
    MOBSF_PLATFORM=docker \
    MOBSF_ADB_BINARY=/usr/bin/adb \
    JAVA_HOME=/opt/jdk-22.0.2 \
    PATH=/opt/jdk-22.0.2/bin:/root/.local/bin:$PATH \
    DJANGO_SUPERUSER_USERNAME=mobsf \
    DJANGO_SUPERUSER_PASSWORD=mobsf

# See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    android-sdk-build-tools \
    android-tools-adb \
    build-essential \
    curl \
    fontconfig \
    fontconfig-config \
    git \
    libfontconfig1 \
    libjpeg62-turbo \
    libxext6 \
    libxrender1 \
    locales \
    python3-dev \
    sqlite3 \
    unzip \
    wget \
    xfonts-75dpi \
    xfonts-base && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    apt-get upgrade -y && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/*

ARG TARGETPLATFORM

# Install wkhtmltopdf, OpenJDK and jadx
COPY scripts/dependencies.sh mobsf/MobSF/tools_download.py ./
RUN ./dependencies.sh

# Install Python dependencies
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false && \
  poetry install --only main --no-root --no-interaction --no-ansi && \
  poetry cache clear . --all --no-interaction && \
  rm -rf /root/.cache/

# Cleanup
RUN \
    apt-get remove -y \
        git \
        python3-dev \
        wget && \
    apt-get clean && \
    apt-get autoclean && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

# Copy source code
WORKDIR /home/mobsf/Mobile-Security-Framework-MobSF
COPY . .

HEALTHCHECK CMD curl --fail http://127.0.0.1:8000/ || exit 1

# Expose MobSF Port and Proxy Port
EXPOSE 8000 1337

# Create mobsf user
RUN groupadd --gid $USER_ID $MOBSF_USER && \
    useradd $MOBSF_USER --uid $USER_ID --gid $MOBSF_USER --shell /bin/false && \
    chown -R $MOBSF_USER:$MOBSF_USER /home/mobsf

# Switch to mobsf user
USER $MOBSF_USER

# Run MobSF
CMD ["/home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh"]
