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

struct nfsd3_readdirargs {
	struct svc_fh		fh;
	__u64			cookie;
	__u32			count;
	__be32 *		verf;
};

struct nfsd3_commitargs {
	struct svc_fh		fh;
	__u64			offset;
	__u32			count;
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

struct nfsd3_readdirres {
	/* Components of the reply */
	__be32			status;
	struct svc_fh		fh;
	__be32			verf[2];

	/* Used to encode the reply's entry list */
	struct xdr_stream	xdr;
	struct xdr_buf		dirlist;
	struct svc_fh		scratch;
	struct readdir_cd	common;
	unsigned int		cookie_offset;
	struct svc_rqst *	rqstp;

};

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
	__be32			status;
	struct svc_fh		fh;
	__be32			verf[2];
};

struct nfsd3_getaclres {
	__be32			status;
	struct svc_fh		fh;
	int			mask;
	struct posix_acl	*acl_access;
	struct posix_acl	*acl_default;
	struct kstat		stat;
};

bool nfs3svc_decode_readdirargs(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_decode_readdirplusargs(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_decode_commitargs(struct svc_rqst *rqstp, struct xdr_stream *xdr);

bool nfs3svc_encode_accessres(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_encode_readdirres(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_encode_commitres(struct svc_rqst *rqstp, struct xdr_stream *xdr);

void nfs3svc_release_fhandle(struct svc_rqst *);

void nfs3svc_encode_cookie3(struct nfsd3_readdirres *resp, u64 offset);
int nfs3svc_encode_entry3(void *data, const char *name, int namlen,
			  loff_t offset, u64 ino, unsigned int d_type);
int nfs3svc_encode_entryplus3(void *data, const char *name, int namlen,
			      loff_t offset, u64 ino, unsigned int d_type);
/* Helper functions for NFSv3 ACL code */
bool svcxdr_decode_nfs_fh3(struct xdr_stream *xdr, struct svc_fh *fhp);
bool svcxdr_encode_nfsstat3(struct xdr_stream *xdr, __be32 status);
bool svcxdr_encode_post_op_attr(struct svc_rqst *rqstp, struct xdr_stream *xdr,
				const struct svc_fh *fhp);

#endif /* _LINUX_NFSD_XDR3_H */
