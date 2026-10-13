/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDR types for NFSv3 in nfsd.
 *
 * Copyright (C) 1996-1998, Olaf Kirch <okir@monad.swb.de>
 */

#ifndef _LINUX_NFSD_XDR3_H
#define _LINUX_NFSD_XDR3_H

#include <linux/vfs.h>
#include <linux/sunrpc/xdrgen/nfs3.h>

#include "vfs.h"

#define NF3NON		(0)
#define NF3BAD		(8)

#define NFS3_MAXNAMLEN			NAME_MAX
#define NFS3_MAXPATHLEN			PATH_MAX

struct nfsd3_accessargs {
	struct svc_fh		fh;
	__u32			access;
};

struct nfsd3_getaclargs {
	struct svc_fh		fh;
	__u32			mask;
};

struct posix_acl;
struct nfsd3_setaclargs {
	struct svc_fh		fh;
	__u32			mask;
	struct posix_acl	*acl_access;
	struct posix_acl	*acl_default;
};

struct nfsd3_attrstat {
	__be32			status;
	struct svc_fh		fh;
	struct kstat            stat;
};

struct nfsd3_accessres {
	__be32			status;
	struct svc_fh		fh;
	__u32			access;
	struct kstat		stat;
};

struct nfsd3_writeres {
	struct WRITE3res	xdrgen;
};

static_assert(offsetof(struct nfsd3_writeres, xdrgen) == 0);

/*
 * Declared here rather than in nfs3proc.c with the other proc wrappers
 * because READDIR's encode path in nfs3xdr.c reads the file handle from
 * it during encode and release. The xdrgen field must be first so the
 * struct can be cast to its XDR type for the RPC dispatch layer.
 */
struct READDIR3args_wrapper {
	struct READDIR3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct READDIR3args_wrapper, xdrgen) == 0);

struct nfsd3_readdirres {
	struct READDIR3res	xdrgen;

	/* Streaming state for encoding the reply's entry list */
	struct nfsd_readdir_iter iter;		/* directory reader */
	u32			count;		/* client's reply size hint */
	u32			space_left;	/* remaining entry budget */
	unsigned int		cookie_offset;	/* prev entry's cookie slot */
};

static_assert(offsetof(struct nfsd3_readdirres, xdrgen) == 0);

/*
 * Declared here rather than in nfs3proc.c with the other proc wrappers
 * because READDIRPLUS's encode path in nfs3xdr.c reads the file handle
 * from it during encode and release. The xdrgen field must be first so
 * the struct can be cast to its XDR type for the RPC dispatch layer.
 */
struct READDIRPLUS3args_wrapper {
	struct READDIRPLUS3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct READDIRPLUS3args_wrapper, xdrgen) == 0);

struct nfsd3_readdirplusres {
	struct READDIRPLUS3res	xdrgen;

	/* Streaming state for encoding the reply's entry list */
	struct nfsd_readdir_iter iter;		/* directory reader */
	u32			count;		/* client's reply size hint */
	u32			space_left;	/* remaining entry budget */
	unsigned int		cookie_offset;	/* prev entry's cookie slot */
	struct svc_fh		scratch;	/* per-entry file handle */
	u8			fh_data[NFS3_FHSIZE];	/* per-entry handle bytes */
};

static_assert(offsetof(struct nfsd3_readdirplusres, xdrgen) == 0);

struct nfsd3_fsstatres {
	struct FSSTAT3res	xdrgen;
	struct kstatfs		stats;
};

static_assert(offsetof(struct nfsd3_fsstatres, xdrgen) == 0);

struct nfsd3_fsinfores {
	struct FSINFO3res	xdrgen;
};

static_assert(offsetof(struct nfsd3_fsinfores, xdrgen) == 0);

struct nfsd3_pathconfres {
	struct PATHCONF3res	xdrgen;
};

static_assert(offsetof(struct nfsd3_pathconfres, xdrgen) == 0);

struct nfsd3_commitres {
	struct COMMIT3res	xdrgen;
};

static_assert(offsetof(struct nfsd3_commitres, xdrgen) == 0);

struct nfsd3_getaclres {
	__be32			status;
	struct svc_fh		fh;
	int			mask;
	struct posix_acl	*acl_access;
	struct posix_acl	*acl_default;
	struct kstat		stat;
};

void nfs3svc_release_readdirres(struct svc_rqst *rqstp);
void nfs3svc_release_readdirplusres(struct svc_rqst *rqstp);

void nfs3svc_encode_cookie3(struct xdr_stream *xdr, unsigned int pos,
			    u64 cookie);
void nfsd3_fill_post_op_attr(struct svc_rqst *rqstp, struct post_op_attr *attr,
			     struct svc_fh *fhp);
void nfsd3_fill_post_op_fh3(struct post_op_fh3 *post_op_fh,
			    const struct svc_fh *fhp, u8 *data);
/* Helper functions for NFSv3 ACL code */
bool svcxdr_decode_nfs_fh3(struct xdr_stream *xdr, struct svc_fh *fhp);
bool svcxdr_encode_nfsstat3(struct xdr_stream *xdr, __be32 status);
bool svcxdr_encode_post_op_attr(struct svc_rqst *rqstp, struct xdr_stream *xdr,
				const struct svc_fh *fhp);

#endif /* _LINUX_NFSD_XDR3_H */
