# xray-core Log Parser

Proxy that accepts raw Xray-core access log lines, parses and filters them, and emits structured NDJSON to either a file or Vector over HTTP.

## Flow

```
Vector (raw lines) -> /vector/ingest -> parse + skip rules -> OUTPUT_FILE or VECTOR_ENDPOINT
```

Example output event (`LogEntry`):

```json
{
  "datetime": "2026-07-23 10:11:12.100000",
  "email": "1204",
  "from_proto": "",
  "from_ip": "203.0.113.47",
  "from_port": 4821,
  "dest_proto": "tcp",
  "dest_host": "google.com",
  "dest_port": 443,
  "status": "accepted",
  "route": "VLESS - DIRECT",
  "to_addr": []
}
```

## Usage

Docker Compose (file sink):

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

Docker Compose (Vector HTTP sink):

```yaml
services:
  xray-loki-proxy:
    image: ghcr.io/fedorov-xyz/xray-loki-proxy:latest
    environment:
      - VECTOR_ENDPOINT=http://vector:8080
      - LISTEN_PORT=8080
```

Set **exactly one** of `OUTPUT_FILE` or `VECTOR_ENDPOINT`.

### Skip Rules Configuration

Mount a `skip-rules.json` file into `/etc/xray-loki-proxy/skip-rules.json` with filtering rules:

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
| OUTPUT_FILE        | Append NDJSON here (mutually exclusive with Vector)  | -       |
| VECTOR_ENDPOINT    | POST NDJSON here (mutually exclusive with file)      | -       |
| LISTEN_HOST        | Host to listen on                                    | 0.0.0.0 |
| LISTEN_PORT        | Port to listen on                                    | 8080    |
| LOG_LEVEL          | Log level (debug/info/warn/error)                    | info    |
| TORRENT_TAG        | Tag to detect torrent traffic in route field         | -       |
| TORRENT_NOTIFY_URL | URL to send POST notifications about torrent traffic | -       |

### Torrent Detection

If both `TORRENT_TAG` and `TORRENT_NOTIFY_URL` are set, the service POSTs batched `LogEntry` arrays when the tag appears in `route` (up to 1000 entries / every 20s).
