// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* typically virtio scsi has max SGs of 6 */
#define VIRTIO_MAX_SGS	6

/* Verifier will fail with SG_MAX = 128. The failure can be
 * workarounded with a smaller SG_MAX, e.g. 10.
 */
#define WORKAROUND
#ifdef WORKAROUND
#define SG_MAX		10
#else
/* typically virtio blk has max SEG of 128 */
#define SG_MAX		128
#endif

#define SG_CHAIN	0x01UL
#define SG_END		0x02UL

#define sg_is_chain(sg)		((sg)->page_link & SG_CHAIN)
#define sg_is_last(sg)		((sg)->page_link & SG_END)
#define sg_chain_ptr(sg)	\
	((struct scatterlist *) ((sg)->page_link & ~(SG_CHAIN | SG_END)))

static inline struct scatterlist *__sg_next(struct scatterlist *sgp)
{
	struct scatterlist sg;

	bpf_probe_read_kernel(&sg, sizeof(sg), sgp);
	if (sg_is_last(&sg))
		return NULL;

	sgp++;

	bpf_probe_read_kernel(&sg, sizeof(sg), sgp);
	if (sg_is_chain(&sg))
		sgp = sg_chain_ptr(&sg);

	return sgp;
}

static inline struct scatterlist *get_sgp(struct scatterlist **sgs, int i)
{
	struct scatterlist *sgp;

	bpf_probe_read_kernel(&sgp, sizeof(sgp), sgs + i);
	return sgp;
}

int g_config = 0;
int g_result = 0;

SEC("kprobe/virtqueue_add_sgs")
int BPF_KPROBE(trace_virtqueue_add_sgs, void *unused, struct scatterlist **sgs,
	       unsigned int out_sgs, unsigned int in_sgs)
{
	struct scatterlist *sgp = NULL;
	__u64 length1 = 0, length2 = 0;
	unsigned int i, n, len;

	if (g_config != 0)
		return 0;

	for (i = 0; (i < VIRTIO_MAX_SGS) && (i < out_sgs); i++) {
		for (n = 0, sgp = get_sgp(sgs, i); sgp && (n < SG_MAX);
		     sgp = __sg_next(sgp)) {
			bpf_probe_read_kernel(&len, sizeof(len), &sgp->length);
			length1 += len;
			n++;
		}
	}

	for (i = 0; (i < VIRTIO_MAX_SGS) && (i < in_sgs); i++) {
		for (n = 0, sgp = get_sgp(sgs, i); sgp && (n < SG_MAX);
		     sgp = __sg_next(sgp)) {
			bpf_probe_read_kernel(&len, sizeof(len), &sgp->length);
			length2 += len;
			n++;
		}
	}

	g_config = 1;
	g_result = length2 - length1;
	return 0;
}
