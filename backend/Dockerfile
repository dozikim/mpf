# MPF backend image.
#
# Carries the full Android reverse-engineering toolchain the pipeline shells
# out to: apktool, jadx, aapt2, apksigner, dexdump, strings. Built on a slim
# Debian + JDK base because every tool here is a JVM app or an SDK build-tool.
FROM eclipse-temurin:21-jdk-jammy

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ANDROID_SDK_ROOT=/opt/android-sdk

# --- OS packages + Python ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        curl unzip wget binutils \
        && rm -rf /var/lib/apt/lists/*

# `strings` ships in binutils (installed above). `binutils` also provides the
# tooling several build-tools rely on.

# --- apktool ---
ARG APKTOOL_VERSION=2.10.0
RUN wget -q -O /usr/local/bin/apktool \
        https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool && \
    wget -q -O /usr/local/bin/apktool.jar \
        https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar && \
    chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar

# --- jadx (Java decompiler) ---
ARG JADX_VERSION=1.5.0
RUN wget -q -O /tmp/jadx.zip \
        https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm /tmp/jadx.zip

# --- Android command-line tools + build-tools (aapt2, apksigner, dexdump) ---
ARG CMDLINE_TOOLS_VERSION=11076708
ARG BUILD_TOOLS_VERSION=34.0.0
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools && \
    wget -q -O /tmp/cmdtools.zip \
        https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip && \
    unzip -q /tmp/cmdtools.zip -d ${ANDROID_SDK_ROOT}/cmdline-tools && \
    mv ${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest && \
    rm /tmp/cmdtools.zip && \
    yes | ${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null 2>&1 || true && \
    ${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager "build-tools;${BUILD_TOOLS_VERSION}" >/dev/null 2>&1
ENV PATH="${PATH}:${ANDROID_SDK_ROOT}/build-tools/${BUILD_TOOLS_VERSION}:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin"

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["sh","-c","alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
