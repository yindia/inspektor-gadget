# Developer Notes for trace_http

## Architecture

The trace_http gadget works by attaching eBPF programs to kernel functions that handle TCP send and receive operations:

1. **tcp_sendmsg**: Captures outgoing TCP data to detect HTTP requests
2. **tcp_recvmsg**: Captures incoming TCP data to detect HTTP responses

## Implementation Details

### HTTP Detection

The gadget identifies HTTP traffic by:
- Checking for HTTP method keywords (GET, POST, PUT, etc.) at the start of TCP payloads
- Looking for HTTP version strings (HTTP/1.0, HTTP/1.1, HTTP/2.0) in responses
- Using port numbers to distinguish HTTP (80) from HTTPS (443, 8443)

### Request/Response Correlation

To match requests with responses and calculate latency:
1. Requests are stored in a BPF hash map with a key combining PID, source port, and destination port
2. When a response arrives, we look up the matching request using the reversed port combination
3. Latency is calculated as the difference between request and response timestamps

### Data Extraction

The gadget extracts HTTP headers by:
- Parsing the first line for method, path, and status code
- Searching for specific headers (Host, User-Agent, Content-Length) in the payload
- Limiting string operations to prevent excessive CPU usage in kernel space

## Performance Considerations

1. **Map Size**: The http_events map can store up to 10,240 concurrent requests
2. **String Processing**: Limited to MAX_MSG_SIZE (512 bytes) to avoid performance impact
3. **Filtering**: Min-latency parameter helps reduce noise in high-traffic environments

## Testing

### Unit Tests
Located in `test/unit/trace_http_test.go`, these tests verify:
- Basic HTTP request/response capture
- Filter functionality (min-latency, capture flags)
- Container isolation

### Manual Testing
```bash
# Start the gadget
sudo ig run trace_http

# In another terminal, generate test traffic
curl http://example.com
wget https://example.com

# Test with a local server
python3 -m http.server 8000 &
curl http://localhost:8000
```

## Known Issues and Future Improvements

1. **HTTP/2 Support**: Currently limited due to multiplexing complexity
2. **IPv6 Support**: Need to extend the address handling
3. **Chunked Encoding**: Not fully supported for body size calculation
4. **TLS Interception**: Could add SSL_read/SSL_write hooks for better HTTPS visibility

## Debugging Tips

1. Check if the BPF program is loaded:
   ```bash
   sudo bpftool prog list | grep trace_http
   ```

2. Monitor map contents:
   ```bash
   sudo bpftool map dump name http_events
   ```

3. Enable debug output by modifying the BPF program to include `bpf_printk()` statements