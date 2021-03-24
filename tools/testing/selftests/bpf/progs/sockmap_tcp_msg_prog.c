#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

int _version SEC("version") = 1;

SEC("sk_msg1")
int bpf_prog1(struct sk_msg_md *msg)
{
	void *data_end = (void *)(long) msg->data_end;
	void *data = (void *)(long) msg->data;

	char *d;

	if (data + 8 > data_end)
		return SK_DROP;

	d = (char *)data;
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
