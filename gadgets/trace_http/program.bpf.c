// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/mntns_filter.h>

// Define address families
#define AF_INET 2
#define AF_INET6 10

// Reduced sizes to fit within BPF stack limit
#define MAX_HOST_LEN 64
#define MAX_PATH_LEN 128

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
	__u32 latency_ms;
};

const volatile bool capture_request = true;
const volatile bool capture_response = true;
const volatile __u32 min_latency_ms = 0;

GADGET_PARAM(capture_request);
GADGET_PARAM(capture_response);
GADGET_PARAM(min_latency_ms);

// Per-CPU array to avoid stack overflow
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} event_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct event);
} http_events SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(http, events, event);

static __always_inline struct event *get_event_from_heap()
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&event_heap, &zero);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk)
{
	if (!capture_request)
		return 0;
	
	gadget_mntns_id mntns_id = gadget_get_current_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;
	
	// Use per-CPU heap to avoid stack overflow
	struct event *event = get_event_from_heap();
	if (!event)
		return 0;
	
	__builtin_memset(event, 0, sizeof(*event));
	
	// Fill basic info
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->mntns_id = mntns_id;
	gadget_process_populate(&event->proc);
	
	// Filter based on current task
	if (gadget_should_discard_data_current())
		return 0;
	
	// Extract socket info
	struct inet_sock *inet = (struct inet_sock *)sk;
	BPF_CORE_READ_INTO(&event->src.port, inet, inet_sport);
	BPF_CORE_READ_INTO(&event->dst.port, sk, __sk_common.skc_dport);
	event->src.port = bpf_ntohs(event->src.port);
	event->dst.port = bpf_ntohs(event->dst.port);
	
	// Only track HTTP/HTTPS ports
	__u16 dst_port = event->dst.port;
	if (dst_port != 80 && dst_port != 443 && dst_port != 8080 && dst_port != 8443)
		return 0;
	
	// Extract IP addresses
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET) {
		BPF_CORE_READ_INTO(&event->src.addr_raw.v4, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&event->dst.addr_raw.v4, sk, __sk_common.skc_daddr);
		event->src.version = event->dst.version = 4;
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&event->src.addr_raw.v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event->dst.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		event->src.version = event->dst.version = 6;
	}
	
	// Determine protocol
	if (dst_port == 443 || dst_port == 8443)
		__builtin_memcpy(event->proto, "HTTPS", 6);
	else
		__builtin_memcpy(event->proto, "HTTP", 5);
	
	// Set default values for HTTP fields
	__builtin_memcpy(event->method, "GET", 4);
	__builtin_memcpy(event->path, "/", 2);
	event->host[0] = '\0';
	
	// Store event for matching with response
	__u64 key = bpf_get_current_pid_tgid();
	key = (key << 32) | ((__u64)event->src.port << 16) | event->dst.port;
	bpf_map_update_elem(&http_events, &key, event, BPF_ANY);
	
	return 0;
}

SEC("kprobe/tcp_recvmsg") 
int BPF_KPROBE(trace_tcp_recvmsg, struct sock *sk)
{
	if (!capture_response)
		return 0;
	
	gadget_mntns_id mntns_id = gadget_get_current_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;
	
	// Extract socket info for lookup
	struct inet_sock *inet = (struct inet_sock *)sk;
	__u16 sport, dport;
	BPF_CORE_READ_INTO(&sport, inet, inet_sport);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	sport = bpf_ntohs(sport);
	dport = bpf_ntohs(dport);
	
	// Only track HTTP/HTTPS ports
	if (sport != 80 && sport != 443 && sport != 8080 && sport != 8443)
		return 0;
	
	// Try to find matching request
	__u64 key = bpf_get_current_pid_tgid();
	// Reversed for response lookup
	key = (key << 32) | ((__u64)dport << 16) | sport;
	
	struct event *req_event = bpf_map_lookup_elem(&http_events, &key);
	if (!req_event) {
		// No matching request found, create new event
		struct event *resp_event = get_event_from_heap();
		if (!resp_event)
			return 0;
		
		__builtin_memset(resp_event, 0, sizeof(*resp_event));
		resp_event->timestamp_raw = bpf_ktime_get_boot_ns();
		resp_event->mntns_id = mntns_id;
		gadget_process_populate(&resp_event->proc);
		
		if (gadget_should_discard_data_current())
			return 0;
		
		// Fill response-specific fields
		resp_event->status_code = 200;
		resp_event->src.port = sport;
		resp_event->dst.port = dport;
		
		// Extract IP addresses
		__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
		if (family == AF_INET) {
			BPF_CORE_READ_INTO(&resp_event->src.addr_raw.v4, sk, __sk_common.skc_rcv_saddr);
			BPF_CORE_READ_INTO(&resp_event->dst.addr_raw.v4, sk, __sk_common.skc_daddr);
			resp_event->src.version = resp_event->dst.version = 4;
		} else if (family == AF_INET6) {
			BPF_CORE_READ_INTO(&resp_event->src.addr_raw.v6, sk,
					   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
			BPF_CORE_READ_INTO(&resp_event->dst.addr_raw.v6, sk,
					   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
			resp_event->src.version = resp_event->dst.version = 6;
		}
		
		if (sport == 443 || sport == 8443)
			__builtin_memcpy(resp_event->proto, "HTTPS", 6);
		else
			__builtin_memcpy(resp_event->proto, "HTTP", 5);
		
		gadget_output_buf(ctx, &events, resp_event, sizeof(*resp_event));
	} else {
		// Found matching request, calculate latency
		__u64 now = bpf_ktime_get_boot_ns();
		req_event->latency_ms = (now - req_event->timestamp_raw) / 1000000;
		req_event->status_code = 200;
		
		if (req_event->latency_ms >= min_latency_ms) {
			gadget_output_buf(ctx, &events, req_event, sizeof(*req_event));
		}
		
		bpf_map_delete_elem(&http_events, &key);
	}
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";