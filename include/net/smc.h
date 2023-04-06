/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Definitions for the SMC module (socket related)
 *
 *  Copyright IBM Corp. 2016
 *
 *  Author(s):  Ursula Braun <ubraun@linux.vnet.ibm.com>
 */
#ifndef _SMC_H
#define _SMC_H

#include <net/inet_connection_sock.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include "linux/ism.h"

#ifdef ATOMIC64_INIT
#define KERNEL_HAS_ATOMIC64
#endif

struct sock;

#define SMC_MAX_PNETID_LEN	16	/* Max. length of PNET id */

struct smc_hashinfo {
	rwlock_t lock;
	struct hlist_head ht;
};

int smc_hash_sk(struct sock *sk);
void smc_unhash_sk(struct sock *sk);

/* SMCD/ISM device driver interface */
struct smcd_dmb {
	u64 dmb_tok;
	u64 rgid;
	u32 dmb_len;
	u32 sba_idx;
	u32 vlan_valid;
	u32 vlan_id;
	void *cpu_addr;
	dma_addr_t dma_addr;
};

#define ISM_EVENT_DMB	0
#define ISM_EVENT_GID	1
#define ISM_EVENT_SWR	2

#define ISM_RESERVED_VLANID	0x1FFF

#define ISM_ERROR	0xFFFF

struct smcd_dev;
struct ism_client;

struct smcd_ops {
	int (*query_remote_gid)(struct smcd_dev *dev, u64 rgid, u32 vid_valid,
				u32 vid);
	int (*register_dmb)(struct smcd_dev *dev, struct smcd_dmb *dmb,
			    struct ism_client *client);
	int (*unregister_dmb)(struct smcd_dev *dev, struct smcd_dmb *dmb);
	int (*add_vlan_id)(struct smcd_dev *dev, u64 vlan_id);
	int (*del_vlan_id)(struct smcd_dev *dev, u64 vlan_id);
	int (*set_vlan_required)(struct smcd_dev *dev);
	int (*reset_vlan_required)(struct smcd_dev *dev);
	int (*signal_event)(struct smcd_dev *dev, u64 rgid, u32 trigger_irq,
			    u32 event_code, u64 info);
	int (*move_data)(struct smcd_dev *dev, u64 dmb_tok, unsigned int idx,
			 bool sf, unsigned int offset, void *data,
			 unsigned int size);
	u8* (*get_system_eid)(void);
	u64 (*get_local_gid)(struct smcd_dev *dev);
	u16 (*get_chid)(struct smcd_dev *dev);
	struct device* (*get_dev)(struct smcd_dev *dev);
};

struct smcd_dev {
	const struct smcd_ops *ops;
	void *priv;
	struct list_head list;
	spinlock_t lock;
	struct smc_connection **conn;
	struct list_head vlan;
	struct workqueue_struct *event_wq;
	u8 pnetid[SMC_MAX_PNETID_LEN];
	bool pnetid_by_user;
	struct list_head lgr_list;
	spinlock_t lgr_lock;
	atomic_t lgr_cnt;
	wait_queue_head_t lgrs_deleted;
	u8 going_away : 1;
};

struct smc_wr_rx_hdr {	/* common prefix part of LLC and CDC to demultiplex */
	union {
		u8 type;
#if defined(__BIG_ENDIAN_BITFIELD)
		struct {
			u8 llc_version:4,
			   llc_type:4;
		};
#elif defined(__LITTLE_ENDIAN_BITFIELD)
		struct {
			u8 llc_type:4,
			   llc_version:4;
		};
#endif
	};
} __aligned(1);

struct smc_cdc_conn_state_flags {
#if defined(__BIG_ENDIAN_BITFIELD)
	u8	peer_done_writing : 1;	/* Sending done indicator */
	u8	peer_conn_closed : 1;	/* Peer connection closed indicator */
	u8	peer_conn_abort : 1;	/* Abnormal close indicator */
	u8	reserved : 5;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8	reserved : 5;
	u8	peer_conn_abort : 1;
	u8	peer_conn_closed : 1;
	u8	peer_done_writing : 1;
#endif
};

struct smc_cdc_producer_flags {
#if defined(__BIG_ENDIAN_BITFIELD)
	u8	write_blocked : 1;	/* Writing Blocked, no rx buf space */
	u8	urg_data_pending : 1;	/* Urgent Data Pending */
	u8	urg_data_present : 1;	/* Urgent Data Present */
	u8	cons_curs_upd_req : 1;	/* cursor update requested */
	u8	failover_validation : 1;/* message replay due to failover */
	u8	reserved : 3;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8	reserved : 3;
	u8	failover_validation : 1;
	u8	cons_curs_upd_req : 1;
	u8	urg_data_present : 1;
	u8	urg_data_pending : 1;
	u8	write_blocked : 1;
#endif
};

/* in host byte order */
union smc_host_cursor {	/* SMC cursor - an offset in an RMBE */
	struct {
		u16	reserved;
		u16	wrap;		/* window wrap sequence number */
		u32	count;		/* cursor (= offset) part */
	};
#ifdef KERNEL_HAS_ATOMIC64
	atomic64_t		acurs;	/* for atomic processing */
#else
	u64			acurs;	/* for atomic processing */
#endif
} __aligned(8);

/* in host byte order, except for flag bitfields in network byte order */
struct smc_host_cdc_msg {		/* Connection Data Control message */
	struct smc_wr_rx_hdr		common; /* .type = 0xFE */
	u8				len;	/* length = 44 */
	u16				seqno;	/* connection seq # */
	u32				token;	/* alert_token */
	union smc_host_cursor		prod;		/* producer cursor */
	union smc_host_cursor		cons;		/* consumer cursor,
							 * piggy backed "ack"
							 */
	struct smc_cdc_producer_flags	prod_flags;	/* conn. tx/rx status */
	struct smc_cdc_conn_state_flags	conn_state_flags; /* peer conn. status*/
	u8				reserved[18];
} __aligned(8);

enum smc_urg_state {
	SMC_URG_VALID	= 1,			/* data present */
	SMC_URG_NOTYET	= 2,			/* data pending */
	SMC_URG_READ	= 3,			/* data was already read */
};

struct smc_connection {
	struct rb_node		alert_node;
	struct smc_link_group	*lgr;		/* link group of connection */
	struct smc_link		*lnk;		/* assigned SMC-R link */
	u32			alert_token_local; /* unique conn. id */
	u8			peer_rmbe_idx;	/* from tcp handshake */
	int			peer_rmbe_size;	/* size of peer rx buffer */
	atomic_t		peer_rmbe_space;/* remaining free bytes in peer
						 * rmbe
						 */
	int			rtoken_idx;	/* idx to peer RMB rkey/addr */

	struct smc_buf_desc	*sndbuf_desc;	/* send buffer descriptor */
	struct smc_buf_desc	*rmb_desc;	/* RMBE descriptor */
	int			rmbe_size_short;/* compressed notation */
	int			rmbe_update_limit;
						/* lower limit for consumer
						 * cursor update
						 */

	struct smc_host_cdc_msg	local_tx_ctrl;	/* host byte order staging
						 * buffer for CDC msg send
						 * .prod cf. TCP snd_nxt
						 * .cons cf. TCP sends ack
						 */
	union smc_host_cursor	local_tx_ctrl_fin;
						/* prod crsr - confirmed by peer
						 */
	union smc_host_cursor	tx_curs_prep;	/* tx - prepared data
						 * snd_max..wmem_alloc
						 */
	union smc_host_cursor	tx_curs_sent;	/* tx - sent data
						 * snd_nxt ?
						 */
	union smc_host_cursor	tx_curs_fin;	/* tx - confirmed by peer
						 * snd-wnd-begin ?
						 */
	atomic_t		sndbuf_space;	/* remaining space in sndbuf */
	u16			tx_cdc_seq;	/* sequence # for CDC send */
	u16			tx_cdc_seq_fin;	/* sequence # - tx completed */
	spinlock_t		send_lock;	/* protect wr_sends */
	atomic_t		cdc_pend_tx_wr; /* number of pending tx CDC wqe
						 * - inc when post wqe,
						 * - dec on polled tx cqe
						 */
	wait_queue_head_t	cdc_pend_tx_wq; /* wakeup on no cdc_pend_tx_wr*/
	atomic_t		tx_pushing;     /* nr_threads trying tx push */
	struct delayed_work	tx_work;	/* retry of smc_cdc_msg_send */
	u32			tx_off;		/* base offset in peer rmb */

	struct smc_host_cdc_msg	local_rx_ctrl;	/* filled during event_handl.
						 * .prod cf. TCP rcv_nxt
						 * .cons cf. TCP snd_una
						 */
	union smc_host_cursor	rx_curs_confirmed; /* confirmed to peer
						    * source of snd_una ?
						    */
	union smc_host_cursor	urg_curs;	/* points at urgent byte */
	enum smc_urg_state	urg_state;
	bool			urg_tx_pend;	/* urgent data staged */
	bool			urg_rx_skip_pend;
						/* indicate urgent oob data
						 * read, but previous regular
						 * data still pending
						 */
	char			urg_rx_byte;	/* urgent byte */
	bool			tx_in_release_sock;
						/* flush pending tx data in
						 * sock release_cb()
						 */
	atomic_t		bytes_to_rcv;	/* arrived data,
						 * not yet received
						 */
	atomic_t		splice_pending;	/* number of spliced bytes
						 * pending processing
						 */
#ifndef KERNEL_HAS_ATOMIC64
	spinlock_t		acurs_lock;	/* protect cursors */
#endif
	struct work_struct	close_work;	/* peer sent some closing */
	struct work_struct	abort_work;	/* abort the connection */
	struct tasklet_struct	rx_tsklet;	/* Receiver tasklet for SMC-D */
	u8			rx_off;		/* receive offset:
						 * 0 for SMC-R, 32 for SMC-D
						 */
	u64			peer_token;	/* SMC-D token of peer */
	u8			killed : 1;	/* abnormal termination */
	u8			freed : 1;	/* normal termiation */
	u8			out_of_sync : 1; /* out of sync with peer */
};

struct smc_sock {				/* smc sock container */
	struct sock		sk;
	struct socket		*clcsock;	/* internal tcp socket */
	void			(*clcsk_state_change)(struct sock *sk);
						/* original stat_change fct. */
	void			(*clcsk_data_ready)(struct sock *sk);
						/* original data_ready fct. */
	void			(*clcsk_write_space)(struct sock *sk);
						/* original write_space fct. */
	void			(*clcsk_error_report)(struct sock *sk);
						/* original error_report fct. */
	struct smc_connection	conn;		/* smc connection */
	struct smc_sock		*listen_smc;	/* listen parent */
	struct work_struct	connect_work;	/* handle non-blocking connect*/
	struct work_struct	tcp_listen_work;/* handle tcp socket accepts */
	struct work_struct	smc_listen_work;/* prepare new accept socket */
	struct list_head	accept_q;	/* sockets to be accepted */
	spinlock_t		accept_q_lock;	/* protects accept_q */
	bool			limit_smc_hs;	/* put constraint on handshake */
	bool			use_fallback;	/* fallback to tcp */
	int			fallback_rsn;	/* reason for fallback */
	u32			peer_diagnosis; /* decline reason from peer */
	atomic_t                queued_smc_hs;  /* queued smc handshakes */
	struct inet_connection_sock_af_ops		af_ops;
	const struct inet_connection_sock_af_ops	*ori_af_ops;
						/* original af ops */
	int			sockopt_defer_accept;
						/* sockopt TCP_DEFER_ACCEPT
						 * value
						 */
	u8			wait_close_tx_prepared : 1;
						/* shutdown wr or close
						 * started, waiting for unsent
						 * data to be sent
						 */
	u8			connect_nonblock : 1;
						/* non-blocking connect in
						 * flight
						 */
	struct mutex            clcsock_release_lock;
						/* protects clcsock of a listen
						 * socket
						 */
};

#endif	/* _SMC_H */
