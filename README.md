# Akamai SIEM Collector (Docker)

Runs the **official Akamai CEF Connector** (`CEFConnector-1.7.14`, from
[akamai/siem-integration-connector-packages](https://github.com/akamai/siem-integration-connector-packages))
in a container with a web UI where you:

- enter the SIEM API credentials and security configuration ID(s), or paste an `.edgerc` section
- test the credentials against the SIEM API
- start, stop or restart the connector, and reset its offset DB (`cefconnector.db`)
- view the CEF events it pulled (filterable, click a row for every field plus the raw CEF line)
- optionally forward the same CEF stream to your SIEM or syslog listener over TCP/UDP
- read `cefconnector.log` for troubleshooting

## How it works

```
Akamai SIEM API ──EdgeGrid──► CEF Connector (Java) ──log4j Socket──► UI receiver (127.0.0.1:5140) ──► Web UI + /data/logs/cef-events.log
                                                 └──log4j Socket──► your SIEM / syslog (optional)
```

The UI writes `CEFConnector.properties` and `log4j2.xml` from the templates that ship
in the connector package, so the default CEF header, extension mapping, base64 and URL
decoding stay the same as in the official connector.

## Run

```bash
docker compose up -d --build
# open http://localhost:8000
```

To enable basic auth on the UI (recommended), set `UI_PASSWORD` (and optionally `UI_USERNAME`):

```bash
UI_PASSWORD='change-me' docker compose up -d
```

The UI is published on `127.0.0.1` only. Change the port mapping in `docker-compose.yml`
to expose it more widely, and set a password if you do.

### Lab listener (Machine 2 from the guide)

```bash
docker compose --profile lab up -d --build
docker compose logs -f listener
```

In the UI, turn on forwarding with host `listener`, port `8080` and protocol `TCP`, then Save and Restart.

## Settings

| UI field | Connector property |
|---|---|
| Host (base URL) | `akamai.data.baseurl` (must end in `.luna.akamaiapis.net` or `.cloudsecurity.akamaiapis.net`) |
| Client token / secret / access token | `akamai.data.clienttoken` / `clientsecret` / `accesstoken` |
| Security configuration ID(s) | `akamai.data.configs` (separate several IDs with `;`) |
| Refresh period, Limit | `connector.refresh.period`, `akamai.data.limit` |
| Time based, From, To | `akamai.data.timebased`, `.from`, `.to` (the SIEM API keeps 12 hours of data) |
| Proxy host / port | `connector.proxy.host` / `connector.proxy.port` |
| Consumer threads, Retries | `connector.consumer.count`, `connector.retry` |
| Forward host / port / protocol | Extra log4j2 `Socket` appender |

Saved settings take effect when the connector next starts, so use **Restart** after changing them.

## Data (volume `siem-data` → `/data`)

| Path | Contents |
|---|---|
| `settings.json` | UI settings, including credentials (file mode 0600) |
| `connector/config/` | Generated `CEFConnector.properties` and `log4j2.xml` |
| `connector/work/cefconnector.db` | Saved offset |
| `logs/cef-events.log` | Every CEF event received (rotates at 50 MB × 5) |
| `logs/cefconnector.log` | Connector log |

If the connector was running when the container stopped, it starts again automatically.

## Build options

```bash
docker build --build-arg CEF_VERSION=1.7.14 -t akamai-siem-collector .
```

`JAVA_OPTS` (default `-Xms256m -Xmx1024m`) sets the JVM heap. The packaged start script
uses 2 GB, so raise it for high event volumes.

## Prerequisites on the Akamai side

- An API client with **SIEM** API access (READ-WRITE) for the security configuration(s)
- SIEM integration enabled in the security configuration
- Outbound HTTPS from the container to `*.luna.akamaiapis.net` / `*.cloudsecurity.akamaiapis.net`
