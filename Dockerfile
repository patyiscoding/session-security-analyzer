FROM ghcr.io/gitleaks/gitleaks:latest AS gitleaks-fetch



FROM debian:bookworm-slim AS hashcat-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/hashcat
COPY third-party/hashcat/ .
RUN mkdir -p obj/contrib/minizip && make -j"$(nproc)"



FROM python:3.13-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libsnappy1v5 \
        pocl-opencl-icd \
        ocl-icd-libopencl1 \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /home/analyzer --shell /usr/sbin/nologin analyzer

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboardServer.py sessionAnalyzer.py ./
COPY helpers/ ./helpers/
COPY modules/ ./modules/
COPY third-party/awesome-regex-list/ ./third-party/awesome-regex-list/

COPY --from=hashcat-builder /build/hashcat/hashcat ./third-party/hashcat/hashcat
COPY --from=hashcat-builder /build/hashcat/OpenCL ./third-party/hashcat/OpenCL

COPY --from=gitleaks-fetch /usr/bin/gitleaks ./third-party/gitleaks
RUN chown -R analyzer:analyzer /app

USER analyzer
ENV HOME=/home/analyzer \
    PYTHONUNBUFFERED=1 \
    RUNNING_IN_DOCKER=true

EXPOSE 8888 9999

ENTRYPOINT ["mitmdump", "-s", "sessionAnalyzer.py", "-p", "8888", "--set", "ssl_insecure=true"]