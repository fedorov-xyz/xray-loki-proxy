# xray-core Log Parser

Proxy server for parsing and filtering xray-core access logs. The server accepts logs in Loki logproto format and writes them to a file in JSON format.

## Why This Tool?

This tool is designed to work as part of a reliable log processing pipeline with Grafana Agent. Here's the complete workflow:

1. **Initial Log Collection**:

   - Grafana Agent reads the original Xray access logs
   - Sends them to this server in Loki logproto format

2. **Log Processing**:

   - The server parses each log entry
   - Applies filtering rules (skip rules)
   - Converts logs to a structured JSON format
   - Writes filtered and parsed logs to a new file

3. **Reliable Log Delivery**:
   - Grafana Agent can then read the processed JSON file
   - Uses its built-in log reading capabilities
   - Reliably delivers logs to their final destination (e.g., Grafana)

Flow:

```
Grafana Agent -> proxy -> Output file -> Grafana Agent -> Final Destination
```

The log will be transformed into the following JSON format:

```json
{
  "datetime": "2024-01-01 00:00:00",
  "from": "127.0.0.1",
  "status": "accepted",
  "to": "tcp:www.google.com:443",
  "route": "VLESS - DIRECT",
  "email": "robin@example.com"
}
```

## Usage

Docker Compose:

```yaml
services:
  xray-loki-proxy:
    image: ghcr.io/fedorov-xyz/xray-loki-proxy:latest
    container_name: xray-loki-proxy
    environment:
      - OUTPUT_FILE=/var/log/xray/access.log.json
      - LISTEN_HOST=0.0.0.0 # optional, default 0.0.0.0
      - LISTEN_PORT=8080 # optional, default 8080
    volumes:
      - ./skip-rules.json:/etc/xray-loki-proxy/skip-rules.json
      - /var/log/xray:/var/log/xray
    ports:
      - "8080:8080"
```

Grafana Alloy example:

```alloy
loki.write "proxy" {
    endpoint {
        url = "http://xray-loki-proxy:8080/loki/api/v1/push"
    }
}

local.file_match "xray_access" {
    path_targets = [
        {
            __address__  = "localhost",
            __path__     = "/var/log/xray/access.log",
            category     = "xray",
            job          = "loki.local.xray.access",
        },
    ]
}

loki.source.file "xray_access" {
    targets    = local.file_match.xray_access.targets
    forward_to = [loki.write.proxy.receiver]
}
```

### Skip Rules Configuration

The feature is used to avoid writing logs to the output file in which traffic goes to some hosts or IPs. For example, if you don't want tens of thousands of hits to `google.com` in the logs, you can filter that out.

Mount a `skip-rules.json` file into `/etc/xray-core-loki-proxy/skip-rules.json` with filtering rules:

```json
[
  {
    "domain": ["domain:google.com", "full:example.com", "example.com"]
  },
  {
    "ip": ["1.1.1.1", "0.0.0.0/8", "10.0.0.0/8"]
  }
]
```

### Environment Variables

| Variable           | Description                                          | Default |
| ------------------ | ---------------------------------------------------- | ------- |
| OUTPUT_FILE        | Path to the output JSON file                         | -       |
| LISTEN_HOST        | Host to listen on                                    | 0.0.0.0 |
| LISTEN_PORT        | Port to listen on                                    | 8080    |
| LOG_LEVEL          | Log level (debug/info/warn/error)                    | info    |
| TORRENT_TAG        | Tag to detect torrent traffic in route field         | -       |
| TORRENT_NOTIFY_URL | URL to send POST notifications about torrent traffic | -       |

### Torrent Detection

If both `TORRENT_TAG` and `TORRENT_NOTIFY_URL` are set, the service will send POST notifications
to the specified URL when it detects the tag in the route field. For example:

```yaml
environment:
  - TORRENT_TAG=TORRENT
  - TORRENT_NOTIFY_URL=http://notify:8080/torrent
```

The notification will be sent as a JSON POST request with the full log entry:

```json
{
  "datetime": "2024-01-01 00:00:00",
  "from": "127.0.0.1",
  "status": "accepted",
  "to": "tcp:tracker.example.com:6969",
  "route": "VLESS - BitTorrent",
  "email": "robin@example.com"
}
```
