# trace_http

The trace_http gadget monitors HTTP and HTTPS traffic at the application layer, capturing requests and responses along with their metadata.

## Getting Started

```bash
$ sudo ig run trace_http
```

## Description

This gadget traces HTTP/HTTPS traffic by hooking into the TCP send and receive functions. It can capture:

- HTTP methods (GET, POST, PUT, DELETE, etc.)
- Request paths and query parameters
- Host headers
- Response status codes
- Request/response latency
- User-Agent headers
- Content length

The gadget automatically detects whether traffic is HTTP or HTTPS based on the destination port (443/8443 for HTTPS).

## Parameters

- `--capture-request` (default: true): Enable capturing HTTP requests
- `--capture-response` (default: true): Enable capturing HTTP responses
- `--max-body-size` (default: 0): Maximum body size to capture in bytes (0 = disabled)
- `--min-latency` (default: 0): Minimum latency in milliseconds to report

## Output Fields

- `timestamp`: When the event occurred
- `proc`: Process information (comm, pid, tid, uid, gid)
- `src`: Source IP address and port
- `dst`: Destination IP address and port
- `proto`: Protocol (HTTP or HTTPS)
- `method`: HTTP method for requests
- `host`: Host header value
- `path`: Request path
- `status_code`: HTTP response status code
- `content_length`: Content-Length header value
- `user_agent`: User-Agent header value (hidden by default)
- `latency_ms`: Request latency in milliseconds

## Examples

### Basic HTTP monitoring

```bash
$ sudo ig run trace_http
TIMESTAMP                           COMM         PID      SRC                  DST                  PROTO METHOD HOST                PATH              STATUS LATENCY
2024-01-15T10:23:45.123456789Z     curl         12345    192.168.1.10:54321  93.184.216.34:80    HTTP  GET    example.com         /               200    45
2024-01-15T10:23:46.234567890Z     wget         12346    192.168.1.10:54322  93.184.216.34:443   HTTPS GET    example.com         /index.html     200    120
```

### Filter by minimum latency

```bash
$ sudo ig run trace_http --min-latency=100
```

This will only show requests that took more than 100ms to complete.

### Capture only requests

```bash
$ sudo ig run trace_http --capture-response=false
```

## Known Limitations

1. HTTPS traffic content is encrypted, so the gadget can only see metadata (ports, IPs, timing)
2. The gadget may miss very short-lived connections
3. HTTP/2 multiplexing is not fully supported
4. Body content capture is limited to prevent performance impact