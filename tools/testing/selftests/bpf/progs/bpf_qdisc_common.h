#ifndef _BPF_QDISC_COMMON_H
#define _BPF_QDISC_COMMON_H

#define NET_XMIT_SUCCESS        0x00
#define NET_XMIT_DROP           0x01    /* skb dropped                  */
#define NET_XMIT_CN             0x02    /* congestion notification      */

#define TC_PRIO_CONTROL  7
#define TC_PRIO_MAX      15

u32 bpf_skb_get_hash(struct sk_buff *p) __ksym;
void bpf_skb_release(struct sk_buff *p) __ksym;
void bpf_qdisc_skb_drop(struct sk_buff *p, struct bpf_sk_buff_ptr *to_free) __ksym;
void bpf_qdisc_watchdog_schedule(struct Qdisc *sch, u64 expire, u64 delta_ns) __ksym;

#endif
