// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/sockets.h>

#define MAX_MSG_SIZE 512
#define MAX_HOST_LEN 128
#define MAX_PATH_LEN 256
#define MAX_UA_LEN 256

struct event {
	gadget_timestamp timestamp_raw;
	gadget_mntns_id mntns_id;
	struct gadget_process proc;
	
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	
	char proto[8];
	char method[8];
	char host[MAX_HOST_LEN];
	char path[MAX_PATH_LEN];
	__u16 status_code;
	__u64 content_length;
	char user_agent[MAX_UA_LEN];
	__u32 latency_ms;
};

const volatile __u32 max_body_size = 0;
const volatile bool capture_request = true;
const volatile bool capture_response = true;
const volatile __u32 min_latency_ms = 0;

GADGET_PARAM(max_body_size);
GADGET_PARAM(capture_request);
GADGET_PARAM(capture_response);
GADGET_PARAM(min_latency_ms);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct event);
} http_events SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(http, events, event);

static __always_inline bool is_http_request(const char *data, __u32 data_len)
{
	if (data_len < 4)
		return false;
	
	// Check for common HTTP methods
	return (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') ||
	       (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') ||
	       (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') ||
	       (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E') ||
	       (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') ||
	       (data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I') ||
	       (data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C') ||
	       (data[0] == 'C' && data[1] == 'O' && data[2] == 'N' && data[3] == 'N');
}

static __always_inline bool is_http_response(const char *data, __u32 data_len)
{
	if (data_len < 12)
		return false;
	
	// Check for "HTTP/1.0", "HTTP/1.1", or "HTTP/2.0"
	return (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' &&
	        data[4] == '/' && (data[5] == '1' || data[5] == '2') && data[6] == '.');
}

static __always_inline void extract_http_method(const char *data, char *method)
{
	int i;
#pragma unroll
	for (i = 0; i < 7 && i < MAX_MSG_SIZE && data[i] != ' '; i++) {
		method[i] = data[i];
	}
	method[i] = '\0';
}

static __always_inline void extract_http_path(const char *data, char *path)
{
	int i = 0, j = 0;
	
	// Skip method
	while (i < MAX_MSG_SIZE && data[i] != ' ') i++;
	if (i >= MAX_MSG_SIZE) return;
	i++; // Skip space
	
	// Copy path
	while (j < MAX_PATH_LEN - 1 && i < MAX_MSG_SIZE && data[i] != ' ' && data[i] != '?') {
		path[j++] = data[i++];
	}
	path[j] = '\0';
}

static __always_inline void extract_http_host(const char *data, __u32 data_len, char *host)
{
	const char host_str[] = "Host: ";
	int i = 0, j = 0;
	
	// Find "Host: " header
	for (i = 0; i < data_len - 6 && i < MAX_MSG_SIZE - 6; i++) {
		if (data[i] == 'H' && data[i+1] == 'o' && data[i+2] == 's' && 
		    data[i+3] == 't' && data[i+4] == ':' && data[i+5] == ' ') {
			i += 6;
			break;
		}
	}
	
	if (i >= data_len - 6 || i >= MAX_MSG_SIZE - 6) {
		host[0] = '\0';
		return;
	}
	
	// Copy host value
	while (j < MAX_HOST_LEN - 1 && i < data_len && i < MAX_MSG_SIZE && 
	       data[i] != '\r' && data[i] != '\n') {
		host[j++] = data[i++];
	}
	host[j] = '\0';
}

static __always_inline __u16 extract_status_code(const char *data)
{
	// Skip "HTTP/X.X "
	int i = 9;
	__u16 code = 0;
	
	if (data[i] >= '0' && data[i] <= '9')
		code = (data[i] - '0') * 100;
	if (data[i+1] >= '0' && data[i+1] <= '9')
		code += (data[i+1] - '0') * 10;
	if (data[i+2] >= '0' && data[i+2] <= '9')
		code += (data[i+2] - '0');
	
	return code;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	if (!capture_request)
		return 0;
	
	gadget_mntns_id mntns_id = gadget_get_current_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;
	
	struct event event = {};
	char data[MAX_MSG_SIZE];
	__u32 data_len = size < MAX_MSG_SIZE ? size : MAX_MSG_SIZE;
	
	// Read data from user space
	if (bpf_probe_read_user(data, data_len, msg->msg_iter.iov->iov_base) < 0)
		return 0;
	
	// Check if it's an HTTP request
	if (!is_http_request(data, data_len))
		return 0;
	
	// Fill basic info
	event.timestamp_raw = bpf_ktime_get_boot_ns();
	event.mntns_id = mntns_id;
	gadget_process_populate(&event.proc);
	
	// Filter based on common data
	if (gadget_should_discard_data(&event.proc))
		return 0;
	
	// Extract socket info using gadget helper
	struct gadget_socket_data sock_data = {};
	gadget_socket_lookup(sk, &sock_data);
	event.src = sock_data.src;
	event.dst = sock_data.dst;
	
	// Determine protocol
	__u16 dst_port = event.dst.port;
	if (dst_port == 443 || dst_port == 8443)
		__builtin_memcpy(event.proto, "HTTPS", 6);
	else
		__builtin_memcpy(event.proto, "HTTP", 5);
	
	// Extract HTTP info
	extract_http_method(data, event.method);
	extract_http_path(data, event.path);
	extract_http_host(data, data_len, event.host);
	
	// Store event for matching with response
	__u64 key = bpf_get_current_pid_tgid();
	key = (key << 32) | ((__u64)event.src.port << 16) | event.dst.port;
	bpf_map_update_elem(&http_events, &key, &event, BPF_ANY);
	
	return 0;
}

SEC("kprobe/tcp_recvmsg") 
int BPF_KPROBE(trace_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len)
{
	if (!capture_response)
		return 0;
	
	gadget_mntns_id mntns_id = gadget_get_current_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;
	
	char data[MAX_MSG_SIZE];
	__u32 data_len = len < MAX_MSG_SIZE ? len : MAX_MSG_SIZE;
	
	// Read data from user space
	if (bpf_probe_read_user(data, data_len, msg->msg_iter.iov->iov_base) < 0)
		return 0;
	
	// Check if it's an HTTP response
	if (!is_http_response(data, data_len))
		return 0;
	
	// Try to find matching request
	__u64 key = bpf_get_current_pid_tgid();
	struct gadget_socket_data sock_data = {};
	gadget_socket_lookup(sk, &sock_data);
	
	// Reversed for response lookup
	key = (key << 32) | ((__u64)sock_data.dst.port << 16) | sock_data.src.port;
	
	struct event *req_event = bpf_map_lookup_elem(&http_events, &key);
	if (!req_event) {
		// No matching request found, create new event
		struct event resp_event = {};
		resp_event.timestamp_raw = bpf_ktime_get_boot_ns();
		resp_event.mntns_id = mntns_id;
		gadget_process_populate(&resp_event.proc);
		
		if (gadget_should_discard_data(&resp_event.proc))
			return 0;
		
		// Fill response-specific fields
		resp_event.status_code = extract_status_code(data);
		resp_event.src = sock_data.src;
		resp_event.dst = sock_data.dst;
		
		if (sock_data.src.port == 443 || sock_data.src.port == 8443)
			__builtin_memcpy(resp_event.proto, "HTTPS", 6);
		else
			__builtin_memcpy(resp_event.proto, "HTTP", 5);
		
		gadget_output_buf(ctx, &events, &resp_event, sizeof(resp_event));
	} else {
		// Found matching request, calculate latency
		__u64 now = bpf_ktime_get_boot_ns();
		req_event->latency_ms = (now - req_event->timestamp_raw) / 1000000;
		req_event->status_code = extract_status_code(data);
		
		if (req_event->latency_ms >= min_latency_ms) {
			gadget_output_buf(ctx, &events, req_event, sizeof(*req_event));
		}
		
		bpf_map_delete_elem(&http_events, &key);
	}
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";