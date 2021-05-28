/*  XDP redirect to CPUs via cpumap (BPF_MAP_TYPE_CPUMAP)
 *
 *  GPLv2, Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "hash_func01.h"
#include "xdp_sample_kern.h"

#define MAX_CPUS NR_CPUS

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, MAX_CPUS);
} cpu_map SEC(".maps");

/* Set of maps controlling available CPU, and for iterating through
 * selectable redirect CPUs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_CPUS);
} cpus_available SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cpus_count SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cpus_iterator SEC(".maps");

/* Helper parse functions */

/* Parse Ethernet layer 2, extract network layer 3 offset and protocol
 *
 * Returns false on error and non-supported ether-type
 */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __always_inline
bool parse_eth(struct ethhdr *eth, void *data_end,
	       u16 *eth_proto, u64 *l3_offset)
{
	u16 eth_type;
	u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;

	/* Skip non 802.3 Ethertypes */
	if (unlikely(ntohs(eth_type) < ETH_P_802_3_MIN))
		return false;

	/* Handle VLAN tagged packet */
	if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}
	/* Handle double VLAN tagged packet */
	if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	*eth_proto = ntohs(eth_type);
	*l3_offset = offset;
	return true;
}

static __always_inline
u16 get_dest_port_ipv4_udp(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	struct udphdr *udph;
	u16 dport;

	if (iph + 1 > data_end)
		return 0;
	if (!(iph->protocol == IPPROTO_UDP))
		return 0;

	udph = (void *)(iph + 1);
	if (udph + 1 > data_end)
		return 0;

	dport = ntohs(udph->dest);
	return dport;
}

static __always_inline
int get_proto_ipv4(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	return iph->protocol;
}

static __always_inline
int get_proto_ipv6(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return 0;
	return ip6h->nexthdr;
}

SEC("xdp_cpu_map0")
int  xdp_prognum0_no_touch(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct datarec *rec;
	u32 *cpu_selected;
	u32 cpu_dest;
	u32 key = 0;

	/* Only use first entry in cpus_available */
	cpu_selected = bpf_map_lookup_elem(&cpus_available, &key);
	if (!cpu_selected)
		return XDP_ABORTED;
	cpu_dest = *cpu_selected;

	/* Count RX packet in map */
	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_ABORTED;
	rec->processed++;

	if (cpu_dest >= MAX_CPUS) {
		rec->issue++;
		return XDP_ABORTED;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

SEC("xdp_cpu_map1_touch_data")
int  xdp_prognum1_touch_data(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct datarec *rec;
	u32 *cpu_selected;
	u32 cpu_dest;
	u16 eth_type;
	u32 key = 0;

	/* Only use first entry in cpus_available */
	cpu_selected = bpf_map_lookup_elem(&cpus_available, &key);
	if (!cpu_selected)
		return XDP_ABORTED;
	cpu_dest = *cpu_selected;

	/* Validate packet length is minimum Eth header size */
	if (eth + 1 > data_end)
		return XDP_ABORTED;

	/* Count RX packet in map */
	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_ABORTED;
	rec->processed++;

	/* Read packet data, and use it (drop non 802.3 Ethertypes) */
	eth_type = eth->h_proto;
	if (ntohs(eth_type) < ETH_P_802_3_MIN) {
		rec->dropped++;
		return XDP_DROP;
	}

	if (cpu_dest >= MAX_CPUS) {
		rec->issue++;
		return XDP_ABORTED;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

SEC("xdp_cpu_map2_round_robin")
int  xdp_prognum2_round_robin(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct datarec *rec;
	u32 cpu_dest;
	u32 *cpu_lookup;
	u32 key0 = 0;

	u32 *cpu_selected;
	u32 *cpu_iterator;
	u32 *cpu_max;
	u32 cpu_idx;

	cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
	if (!cpu_max)
		return XDP_ABORTED;

	cpu_iterator = bpf_map_lookup_elem(&cpus_iterator, &key0);
	if (!cpu_iterator)
		return XDP_ABORTED;
	cpu_idx = *cpu_iterator;

	*cpu_iterator += 1;
	if (*cpu_iterator == *cpu_max)
		*cpu_iterator = 0;

	cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_idx);
	if (!cpu_selected)
		return XDP_ABORTED;
	cpu_dest = *cpu_selected;

	/* Count RX packet in map */
	rec = bpf_map_lookup_elem(&rx_cnt, &key0);
	if (!rec)
		return XDP_ABORTED;
	rec->processed++;

	if (cpu_dest >= MAX_CPUS) {
		rec->issue++;
		return XDP_ABORTED;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

SEC("xdp_cpu_map3_proto_separate")
int  xdp_prognum3_proto_separate(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u8 ip_proto = IPPROTO_UDP;
	struct datarec *rec;
	u16 eth_proto = 0;
	u64 l3_offset = 0;
	u32 cpu_dest = 0;
	u32 cpu_idx = 0;
	u32 *cpu_lookup;
	u32 key = 0;

	/* Count RX packet in map */
	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_ABORTED;
	rec->processed++;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset)))
		return XDP_PASS; /* Just skip */

	/* Extract L4 protocol */
	switch (eth_proto) {
	case ETH_P_IP:
		ip_proto = get_proto_ipv4(ctx, l3_offset);
		break;
	case ETH_P_IPV6:
		ip_proto = get_proto_ipv6(ctx, l3_offset);
		break;
	case ETH_P_ARP:
		cpu_idx = 0; /* ARP packet handled on separate CPU */
		break;
	default:
		cpu_idx = 0;
	}

	/* Choose CPU based on L4 protocol */
	switch (ip_proto) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		cpu_idx = 2;
		break;
	case IPPROTO_TCP:
		cpu_idx = 0;
		break;
	case IPPROTO_UDP:
		cpu_idx = 1;
		break;
	default:
		cpu_idx = 0;
	}

	cpu_lookup = bpf_map_lookup_elem(&cpus_available, &cpu_idx);
	if (!cpu_lookup)
		return XDP_ABORTED;
	cpu_dest = *cpu_lookup;

	if (cpu_dest >= MAX_CPUS) {
		rec->issue++;
		return XDP_ABORTED;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

SEC("xdp_cpu_map4_ddos_filter_pktgen")
int  xdp_prognum4_ddos_filter_pktgen(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u8 ip_proto = IPPROTO_UDP;
	struct datarec *rec;
	u16 eth_proto = 0;
	u64 l3_offset = 0;
	u32 cpu_dest = 0;
	u32 cpu_idx = 0;
	u16 dest_port;
	u32 *cpu_lookup;
	u32 key = 0;

	/* Count RX packet in map */
	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_ABORTED;
	rec->processed++;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset)))
		return XDP_PASS; /* Just skip */

	/* Extract L4 protocol */
	switch (eth_proto) {
	case ETH_P_IP:
		ip_proto = get_proto_ipv4(ctx, l3_offset);
		break;
	case ETH_P_IPV6:
		ip_proto = get_proto_ipv6(ctx, l3_offset);
		break;
	case ETH_P_ARP:
		cpu_idx = 0; /* ARP packet handled on separate CPU */
		break;
	default:
		cpu_idx = 0;
	}

	/* Choose CPU based on L4 protocol */
	switch (ip_proto) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		cpu_idx = 2;
		break;
	case IPPROTO_TCP:
		cpu_idx = 0;
		break;
	case IPPROTO_UDP:
		cpu_idx = 1;
		/* DDoS filter UDP port 9 (pktgen) */
		dest_port = get_dest_port_ipv4_udp(ctx, l3_offset);
		if (dest_port == 9) {
			if (rec)
				rec->dropped++;
			return XDP_DROP;
		}
		break;
	default:
		cpu_idx = 0;
	}

	cpu_lookup = bpf_map_lookup_elem(&cpus_available, &cpu_idx);
	if (!cpu_lookup)
		return XDP_ABORTED;
	cpu_dest = *cpu_lookup;

	if (cpu_dest >= MAX_CPUS) {
		rec->issue++;
		return XDP_ABORTED;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

/* Hashing initval */
#define INITVAL 15485863

static __always_inline
u32 get_ipv4_hash_ip_pair(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	u32 cpu_hash;

	if (iph + 1 > data_end)
		return 0;

	cpu_hash = iph->saddr + iph->daddr;
	cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL + iph->protocol);

	return cpu_hash;
}

static __always_inline
u32 get_ipv6_hash_ip_pair(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ipv6hdr *ip6h = data + nh_off;
	u32 cpu_hash;

	if (ip6h + 1 > data_end)
		return 0;

	cpu_hash  = ip6h->saddr.s6_addr32[0] + ip6h->daddr.s6_addr32[0];
	cpu_hash += ip6h->saddr.s6_addr32[1] + ip6h->daddr.s6_addr32[1];
	cpu_hash += ip6h->saddr.s6_addr32[2] + ip6h->daddr.s6_addr32[2];
	cpu_hash += ip6h->saddr.s6_addr32[3] + ip6h->daddr.s6_addr32[3];
	cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL + ip6h->nexthdr);

	return cpu_hash;
}

/* Load-Balance traffic based on hashing IP-addrs + L4-proto.  The
 * hashing scheme is symmetric, meaning swapping IP src/dest still hit
 * same CPU.
 */
SEC("xdp_cpu_map5_lb_hash_ip_pairs")
int  xdp_prognum5_lb_hash_ip_pairs(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u8 ip_proto = IPPROTO_UDP;
	struct datarec *rec;
	u16 eth_proto = 0;
	u64 l3_offset = 0;
	u32 cpu_dest = 0;
	u32 cpu_idx = 0;
	u32 *cpu_lookup;
	u32 *cpu_max;
	u32 cpu_hash;
	u32 key = 0;

	/* Count RX packet in map */
	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_ABORTED;
	rec->processed++;

	cpu_max = bpf_map_lookup_elem(&cpus_count, &key);
	if (!cpu_max)
		return XDP_ABORTED;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset)))
		return XDP_PASS; /* Just skip */

	/* Hash for IPv4 and IPv6 */
	switch (eth_proto) {
	case ETH_P_IP:
		cpu_hash = get_ipv4_hash_ip_pair(ctx, l3_offset);
		break;
	case ETH_P_IPV6:
		cpu_hash = get_ipv6_hash_ip_pair(ctx, l3_offset);
		break;
	case ETH_P_ARP: /* ARP packet handled on CPU idx 0 */
	default:
		cpu_hash = 0;
	}

	/* Choose CPU based on hash */
	cpu_idx = cpu_hash % *cpu_max;

	cpu_lookup = bpf_map_lookup_elem(&cpus_available, &cpu_idx);
	if (!cpu_lookup)
		return XDP_ABORTED;
	cpu_dest = *cpu_lookup;

	if (cpu_dest >= MAX_CPUS) {
		rec->issue++;
		return XDP_ABORTED;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

char _license[] SEC("license") = "GPL";
