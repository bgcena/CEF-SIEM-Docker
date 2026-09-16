FROM python:3.12-slim-bookworm

ARG CEF_VERSION=1.7.14
ARG CEF_URL=https://raw.githubusercontent.com/akamai/siem-integration-connector-packages/main/CEFConnector-${CEF_VERSION}.zip

RUN apt-get update \
 && apt-get install -y --no-install-recommends openjdk-17-jre-headless curl unzip ca-certificates \
 && curl -fsSL -o /tmp/cef.zip "$CEF_URL" \
 && unzip -q /tmp/cef.zip -d /tmp/cef \
 && mv /tmp/cef/CEFConnector-${CEF_VERSION} /opt/cefconnector \
 && chmod -R a+rX,go-w /opt/cefconnector \
 && rm -rf /tmp/cef /tmp/cef.zip \
 && apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .

RUN useradd --system --uid 10001 --home /data siem \
 && mkdir -p /data && chown siem:siem /data
USER siem
VOLUME /data

ENV DATA_DIR=/data CEF_HOME=/opt/cefconnector JAVA_OPTS="-Xms256m -Xmx1024m" PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fs http://127.0.0.1:8000/healthz || exit 1

# Single worker: the connector process and event receiver live in this process.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--timeout", "180", "main:app"]
