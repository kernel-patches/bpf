// SPDX-License-Identifier: GPL-2.0
/*
 * Process version 3 NFS requests.
 *
 * Copyright (C) 1996, 1997, 1998 Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/magic.h>
#include <linux/namei.h>
#include <linux/sunrpc/svc.h>

#include "auth.h"
#include "nfsd.h"
#include "cache.h"
#include "xdr3.h"
#include "vfs.h"
#include "nfserr.h"
#include "filecache.h"
#include "trace.h"

#include "nfs3xdr_gen.h"

#define NFSDDBG_FACILITY		NFSDDBG_PROC

/*
 * Wrapper structures combine xdrgen types with legacy structures.
 * The xdrgen field must be first so the structure can be cast
 * to its XDR type for the RPC dispatch layer.
 */

struct GETATTR3args_wrapper {
	struct GETATTR3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct GETATTR3args_wrapper, xdrgen) == 0);

struct GETATTR3res_wrapper {
	struct GETATTR3res	xdrgen;
	struct kstat		stat;
};

static_assert(offsetof(struct GETATTR3res_wrapper, xdrgen) == 0);

struct SETATTR3args_wrapper {
	struct SETATTR3args	xdrgen;
	struct svc_fh		fh;
	struct iattr		iattrs;
	struct timespec64	guard;
};

static_assert(offsetof(struct SETATTR3args_wrapper, xdrgen) == 0);

struct LOOKUP3args_wrapper {
	struct LOOKUP3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct LOOKUP3args_wrapper, xdrgen) == 0);

struct LOOKUP3res_wrapper {
	struct LOOKUP3res	xdrgen;
	struct svc_fh		fh;
	u8			fh_data[NFS3_FHSIZE];
};

static_assert(offsetof(struct LOOKUP3res_wrapper, xdrgen) == 0);

struct ACCESS3args_wrapper {
	struct ACCESS3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct ACCESS3args_wrapper, xdrgen) == 0);

struct READLINK3args_wrapper {
	struct READLINK3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct READLINK3args_wrapper, xdrgen) == 0);

struct READ3args_wrapper {
	struct READ3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct READ3args_wrapper, xdrgen) == 0);

struct WRITE3args_wrapper {
	struct WRITE3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct WRITE3args_wrapper, xdrgen) == 0);

struct CREATE3args_wrapper {
	struct CREATE3args	xdrgen;
	struct svc_fh		fh;
	struct iattr		iattrs;
};

static_assert(offsetof(struct CREATE3args_wrapper, xdrgen) == 0);

struct CREATE3res_wrapper {
	struct CREATE3res	xdrgen;
	struct svc_fh		fh;
	u8			fh_data[NFS3_FHSIZE];
};

static_assert(offsetof(struct CREATE3res_wrapper, xdrgen) == 0);

struct MKDIR3args_wrapper {
	struct MKDIR3args	xdrgen;
	struct svc_fh		fh;
	struct iattr		iattrs;
};

static_assert(offsetof(struct MKDIR3args_wrapper, xdrgen) == 0);

struct MKDIR3res_wrapper {
	struct MKDIR3res	xdrgen;
	struct svc_fh		fh;
	u8			fh_data[NFS3_FHSIZE];
};

static_assert(offsetof(struct MKDIR3res_wrapper, xdrgen) == 0);

struct SYMLINK3args_wrapper {
	struct SYMLINK3args	xdrgen;
	struct svc_fh		fh;
	struct iattr		iattrs;
};

static_assert(offsetof(struct SYMLINK3args_wrapper, xdrgen) == 0);

struct SYMLINK3res_wrapper {
	struct SYMLINK3res	xdrgen;
	struct svc_fh		fh;
	u8			fh_data[NFS3_FHSIZE];
};

static_assert(offsetof(struct SYMLINK3res_wrapper, xdrgen) == 0);

struct MKNOD3args_wrapper {
	struct MKNOD3args	xdrgen;
	struct svc_fh		fh;
	struct iattr		iattrs;
};

static_assert(offsetof(struct MKNOD3args_wrapper, xdrgen) == 0);

struct MKNOD3res_wrapper {
	struct MKNOD3res	xdrgen;
	struct svc_fh		fh;
	u8			fh_data[NFS3_FHSIZE];
};

static_assert(offsetof(struct MKNOD3res_wrapper, xdrgen) == 0);

struct REMOVE3args_wrapper {
	struct REMOVE3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct REMOVE3args_wrapper, xdrgen) == 0);

struct RMDIR3args_wrapper {
	struct RMDIR3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct RMDIR3args_wrapper, xdrgen) == 0);

struct RENAME3args_wrapper {
	struct RENAME3args	xdrgen;
	struct svc_fh		ffh;
	struct svc_fh		tfh;
};

static_assert(offsetof(struct RENAME3args_wrapper, xdrgen) == 0);

struct LINK3args_wrapper {
	struct LINK3args	xdrgen;
	struct svc_fh		ffh;
	struct svc_fh		tfh;
};

static_assert(offsetof(struct LINK3args_wrapper, xdrgen) == 0);

struct FSSTAT3args_wrapper {
	struct FSSTAT3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct FSSTAT3args_wrapper, xdrgen) == 0);

struct FSINFO3args_wrapper {
	struct FSINFO3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct FSINFO3args_wrapper, xdrgen) == 0);

struct PATHCONF3args_wrapper {
	struct PATHCONF3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct PATHCONF3args_wrapper, xdrgen) == 0);

struct COMMIT3args_wrapper {
	struct COMMIT3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct COMMIT3args_wrapper, xdrgen) == 0);

static int nfsd3_ftype3_to_mode(ftype3 ftype)
{
	switch (ftype) {
	case NF3REG:  return S_IFREG;
	case NF3DIR:  return S_IFDIR;
	case NF3BLK:  return S_IFBLK;
	case NF3CHR:  return S_IFCHR;
	case NF3LNK:  return S_IFLNK;
	case NF3SOCK: return S_IFSOCK;
	case NF3FIFO: return S_IFIFO;
	default:
		return 0;
	}
}

/*
 * Reject a client-supplied atime or mtime whose nanoseconds field is out
 * of range. Such a value is well-formed on the wire but is not a valid
 * timespec64, and storing it verbatim can corrupt on-disk timestamps.
 * tv_nsec is a long, so it is cast to unsigned long (the same width) to
 * catch both an over-large value and one that became negative when an
 * out-of-range u32 wire nseconds was assigned to a 32-bit long.
 */
static bool nfsd3_time_in_range(const struct iattr *iap)
{
	if ((iap->ia_valid & ATTR_ATIME_SET) &&
	    (unsigned long)iap->ia_atime.tv_nsec >= NSEC_PER_SEC)
		return false;
	if ((iap->ia_valid & ATTR_MTIME_SET) &&
	    (unsigned long)iap->ia_mtime.tv_nsec >= NSEC_PER_SEC)
		return false;
	return true;
}

static const struct nfsd_access_map nfsd3_regaccess[] = {
	{ ACCESS3_READ,		NFSD_MAY_READ				},
	{ ACCESS3_EXECUTE,	NFSD_MAY_EXEC				},
	{ ACCESS3_MODIFY,	NFSD_MAY_WRITE | NFSD_MAY_TRUNC		},
	{ ACCESS3_EXTEND,	NFSD_MAY_WRITE				},
	{ 0,			0					}
};

static const struct nfsd_access_map nfsd3_diraccess[] = {
	{ ACCESS3_READ,		NFSD_MAY_READ				},
	{ ACCESS3_LOOKUP,	NFSD_MAY_EXEC				},
	{ ACCESS3_MODIFY,	NFSD_MAY_EXEC | NFSD_MAY_WRITE | NFSD_MAY_TRUNC },
	{ ACCESS3_EXTEND,	NFSD_MAY_EXEC | NFSD_MAY_WRITE		},
	{ ACCESS3_DELETE,	NFSD_MAY_REMOVE				},
	{ 0,			0					}
};

/*
 * Some clients - Solaris 2.6 at least, make an access call to the NFS
 * server to check for access for things like /dev/null (which really,
 * NFSD doesn't care about).  So NFSD provides simple access checking
 * for those objects, looking mainly at mode bits, ignoring read-only
 * filesystem checks.
 */
static const struct nfsd_access_map nfsd3_otheraccess[] = {
	{ ACCESS3_READ,		NFSD_MAY_READ				},
	{ ACCESS3_EXECUTE,	NFSD_MAY_EXEC				},
	{ ACCESS3_MODIFY,	NFSD_MAY_WRITE | NFSD_MAY_LOCAL_ACCESS	},
	{ ACCESS3_EXTEND,	NFSD_MAY_WRITE | NFSD_MAY_LOCAL_ACCESS	},
	{ 0,			0					}
};

static const struct nfsd_access_maps nfsd3_access_maps = {
	.regular	= nfsd3_regaccess,
	.directory	= nfsd3_diraccess,
	.other		= nfsd3_otheraccess,
};

static int nfsd3_iocb_flags(enum stable_how how)
{
	switch (how) {
	case FILE_SYNC:
		/* persist data and timestamps */
		return IOCB_DSYNC | IOCB_SYNC;
	case DATA_SYNC:
		/* persist data only */
		return IOCB_DSYNC;
	default:
		return 0;
	}
}

static __be32 nfsd3_map_status(__be32 status)
{
	switch (status) {
	case nfs_ok:
		break;
	case nfserr_nofilehandle:
		status = nfserr_badhandle;
		break;
	case nfserr_wrongsec:
	case nfserr_file_open:
		status = nfserr_acces;
		break;
	case nfserr_symlink_not_dir:
		status = nfserr_notdir;
		break;
	case nfserr_symlink:
	case nfserr_wrong_type:
		status = nfserr_inval;
		break;
	}
	return status;
}

/* XDR decoding has already checked that the FH length is valid */
static __always_inline void
nfsd3_fh3_to_svc_fh(struct svc_fh *fhp, const struct nfs_fh3 *fh3)
{
	fh_init(fhp, NFS3_FHSIZE);
	fhp->fh_handle.fh_size = fh3->data.len;
	memcpy(&fhp->fh_handle.fh_raw, fh3->data.data, fh3->data.len);
}

static __always_inline void
nfsd3_svc_fh_to_fh3(struct nfs_fh3 *fh3, const struct svc_fh *fhp, u8 *scratch)
{
	memcpy(scratch, fhp->fh_handle.fh_raw, fhp->fh_handle.fh_size);
	fh3->data.data = scratch;
	fh3->data.len = fhp->fh_handle.fh_size;
}

static __always_inline void
nfsd3_timespec64_to_nfstime3(struct nfstime3 *dst,
			     const struct timespec64 *src)
{
	dst->seconds = src->tv_sec;
	dst->nseconds = src->tv_nsec;
}

static __be32
nfsd3_check_filename(const unsigned char *name, u32 len)
{
	u32 i;

	if (len == 0)
		return nfserr_inval;
	if (len > NFS3_MAXNAMLEN)
		return nfserr_nametoolong;
	for (i = 0; i < len; i++) {
		if (name[i] == '\0' || name[i] == '/')
			return nfserr_inval;
	}
	return nfs_ok;
}

static u32
nfsd3_mode_to_ftype3(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:  return NF3REG;
	case S_IFDIR:  return NF3DIR;
	case S_IFBLK:  return NF3BLK;
	case S_IFCHR:  return NF3CHR;
	case S_IFLNK:  return NF3LNK;
	case S_IFSOCK: return NF3SOCK;
	case S_IFIFO:  return NF3FIFO;
	}
	return NF3REG;
}

static __always_inline void
nfsd3_nfstime3_to_timespec64(struct timespec64 *dst,
			     const struct nfstime3 *src)
{
	dst->tv_sec = src->seconds;
	dst->tv_nsec = src->nseconds;
}

static void
nfsd3_stat_to_fattr3(struct svc_rqst *rqstp, struct fattr3 *fattr,
		     const struct kstat *stat, const struct svc_fh *fhp)
{
	struct user_namespace *userns = nfsd_user_namespace(rqstp);

	fattr->type = nfsd3_mode_to_ftype3(stat->mode);
	fattr->mode = stat->mode & S_IALLUGO;
	fattr->nlink = stat->nlink;
	fattr->uid = from_kuid_munged(userns, stat->uid);
	fattr->gid = from_kgid_munged(userns, stat->gid);
	if (S_ISLNK(stat->mode) && stat->size > NFS3_MAXPATHLEN)
		fattr->size = NFS3_MAXPATHLEN;
	else
		fattr->size = stat->size;
	fattr->used = stat->blocks << 9;
	fattr->rdev.specdata1 = MAJOR(stat->rdev);
	fattr->rdev.specdata2 = MINOR(stat->rdev);

	switch (fsid_source(fhp)) {
	case FSIDSOURCE_FSID:
		fattr->fsid = (u64)fhp->fh_export->ex_fsid;
		break;
	case FSIDSOURCE_UUID:
		fattr->fsid = ((u64 *)fhp->fh_export->ex_uuid)[0];
		fattr->fsid ^= ((u64 *)fhp->fh_export->ex_uuid)[1];
		break;
	default:
		fattr->fsid = (u64)huge_encode_dev(fhp->fh_dentry->d_sb->s_dev);
	}
	fattr->fileid = stat->ino;

	nfsd3_timespec64_to_nfstime3(&fattr->atime, &stat->atime);
	nfsd3_timespec64_to_nfstime3(&fattr->mtime, &stat->mtime);
	nfsd3_timespec64_to_nfstime3(&fattr->ctime, &stat->ctime);
}

static void
nfsd3_fill_wcc_data(struct svc_rqst *rqstp, struct wcc_data *wcc,
		    struct svc_fh *fhp)
{
	/* Pre-op attributes are of no use to the client without post-op ones */
	if (!fhp->fh_post_saved) {
		wcc->before.attributes_follow = false;
		nfsd3_fill_post_op_attr(rqstp, &wcc->after, fhp);
		return;
	}

	wcc->before.attributes_follow = fhp->fh_pre_saved;
	if (fhp->fh_pre_saved) {
		struct wcc_attr *wattr = &wcc->before.u.attributes;

		wattr->size = fhp->fh_pre_size;
		nfsd3_timespec64_to_nfstime3(&wattr->mtime, &fhp->fh_pre_mtime);
		nfsd3_timespec64_to_nfstime3(&wattr->ctime, &fhp->fh_pre_ctime);
	}

	wcc->after.attributes_follow = true;
	nfsd3_stat_to_fattr3(rqstp, &wcc->after.u.attributes,
			     &fhp->fh_post_attr, fhp);
}

static void
nfsd3_sattr3_to_iattr(struct svc_rqst *rqstp, struct iattr *iap,
		      const struct sattr3 *sattr)
{
	/* trace_nfsd_vfs_setattr() records fields ia_valid leaves unset */
	memset(iap, 0, sizeof(*iap));

	if (sattr->mode.set_it) {
		iap->ia_valid |= ATTR_MODE;
		iap->ia_mode = sattr->mode.u.mode;
	}
	if (sattr->uid.set_it) {
		iap->ia_uid = make_kuid(nfsd_user_namespace(rqstp),
					sattr->uid.u.uid);
		if (uid_valid(iap->ia_uid))
			iap->ia_valid |= ATTR_UID;
	}
	if (sattr->gid.set_it) {
		iap->ia_gid = make_kgid(nfsd_user_namespace(rqstp),
					sattr->gid.u.gid);
		if (gid_valid(iap->ia_gid))
			iap->ia_valid |= ATTR_GID;
	}
	if (sattr->size.set_it) {
		iap->ia_valid |= ATTR_SIZE;
		iap->ia_size = sattr->size.u.size;
	}
	switch (sattr->atime.set_it) {
	case DONT_CHANGE:
		break;
	case SET_TO_SERVER_TIME:
		iap->ia_valid |= ATTR_ATIME;
		break;
	case SET_TO_CLIENT_TIME:
		nfsd3_nfstime3_to_timespec64(&iap->ia_atime,
					     &sattr->atime.u.atime);
		iap->ia_valid |= ATTR_ATIME | ATTR_ATIME_SET;
		break;
	}
	switch (sattr->mtime.set_it) {
	case DONT_CHANGE:
		break;
	case SET_TO_SERVER_TIME:
		iap->ia_valid |= ATTR_MTIME;
		break;
	case SET_TO_CLIENT_TIME:
		nfsd3_nfstime3_to_timespec64(&iap->ia_mtime,
					     &sattr->mtime.u.mtime);
		iap->ia_valid |= ATTR_MTIME | ATTR_MTIME_SET;
		break;
	}
}

/*
 * struct kstat is pretty huge. To reduce stack utilization, reuse @fhp's
 * fh_post_attr field as the stat buffer passed to fh_getattr.
 *
 * This is safe to do as long as proc functions that need both WCC and
 * post_op_attrs invoke nfsd3_fill_wcc_data() before invoking
 * nfsd3_fill_post_op_attr() on the same fhp argument.
 */
void
nfsd3_fill_post_op_attr(struct svc_rqst *rqstp, struct post_op_attr *attr,
			struct svc_fh *fhp)
{
	struct kstat *statp = &fhp->fh_post_attr;
	struct dentry *dentry = fhp->fh_dentry;

	/*
	 * The inode may be NULL if the call failed because of a stale
	 * file handle. In this case, no attributes are returned.
	 */
	if (fhp->fh_no_wcc || !dentry || !d_really_is_positive(dentry))
		goto no_post_op_attrs;
	if (fh_getattr(fhp, statp) != nfs_ok)
		goto no_post_op_attrs;

	attr->attributes_follow = true;
	lease_get_mtime(d_inode(dentry), &statp->mtime);
	nfsd3_stat_to_fattr3(rqstp, &attr->u.attributes, statp, fhp);
	return;

no_post_op_attrs:
	attr->attributes_follow = false;
}

void
nfsd3_fill_post_op_fh3(struct post_op_fh3 *post_op_fh,
		       const struct svc_fh *fhp, u8 *data)
{
	if (fhp->fh_handle.fh_size != 0) {
		post_op_fh->handle_follows = true;
		nfsd3_svc_fh_to_fh3(&post_op_fh->u.handle, fhp, data);
	} else {
		post_op_fh->handle_follows = false;
	}
}

/*
 * A full specification of each of the following NFSv3 procedures is
 * available in RFC 1813 Section 3.3.
 */

/**
 * nfsd3_proc_null - NULL: Do nothing
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   void NFSPROC3_NULL(void) = 0;
 */
static __be32 nfsd3_proc_null(struct svc_rqst *rqstp)
{
	return rpc_success;
}

/**
 * nfsd3_proc_getattr - GETATTR: Get file attributes
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   GETATTR3res NFSPROC3_GETATTR(GETATTR3args) = 1;
 */
static __be32 nfsd3_proc_getattr(struct svc_rqst *rqstp)
{
	struct GETATTR3args_wrapper *argp = rqstp->rq_argp;
	struct GETATTR3res_wrapper *resp = rqstp->rq_resp;
	struct kstat *statp = &resp->stat;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.object);
	trace_nfsd_vfs_getattr(rqstp, fhp);
	resp->xdrgen.status = fh_verify(rqstp, fhp, 0, NFSD_MAY_NOP |
					NFSD_MAY_BYPASS_GSS_ON_ROOT);
	if (resp->xdrgen.status != nfs_ok)
		goto out;

	resp->xdrgen.status = fh_getattr(fhp, statp);

out:
	if (resp->xdrgen.status == nfs_ok) {
		lease_get_mtime(d_inode(fhp->fh_dentry), &statp->mtime);
		nfsd3_stat_to_fattr3(rqstp, &resp->xdrgen.u.resok.obj_attributes,
				     statp, fhp);
	} else {
		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_setattr - SETATTR: Set file attributes
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   SETATTR3res NFSPROC3_SETATTR(SETATTR3args) = 2;
 */
static __be32 nfsd3_proc_setattr(struct svc_rqst *rqstp)
{
	struct SETATTR3args_wrapper *argp = rqstp->rq_argp;
	struct SETATTR3res *resp = rqstp->rq_resp;
	const struct timespec64 *guardtime = NULL;
	struct svc_fh *fhp = &argp->fh;
	struct nfsd_attrs nattrs = {
		.na_iattr	= &argp->iattrs,
	};

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.object);
	nfsd3_sattr3_to_iattr(rqstp, &argp->iattrs, &argp->xdrgen.new_attributes);
	if (argp->xdrgen.guard.check) {
		nfsd3_nfstime3_to_timespec64(&argp->guard,
					     &argp->xdrgen.guard.u.obj_ctime);
		guardtime = &argp->guard;
	}

	if (nfsd3_time_in_range(&argp->iattrs))
		resp->status = nfsd_setattr(rqstp, fhp, &nattrs, guardtime);
	else
		resp->status = nfserr_inval;

	if (resp->status == nfs_ok) {
		nfsd3_fill_wcc_data(rqstp, &resp->u.resok.obj_wcc, fhp);
	} else {
		resp->status = nfsd3_map_status(resp->status);
		nfsd3_fill_wcc_data(rqstp, &resp->u.resfail.obj_wcc, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_lookup - LOOKUP: Look up file name
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   LOOKUP3res NFSPROC3_LOOKUP(LOOKUP3args) = 3;
 */
static __be32 nfsd3_proc_lookup(struct svc_rqst *rqstp)
{
	struct LOOKUP3args_wrapper *argp = rqstp->rq_argp;
	struct LOOKUP3res_wrapper *resp = rqstp->rq_resp;
	struct diropargs3 *what = &argp->xdrgen.what;
	struct svc_fh *dirfhp = &argp->fh;
	struct svc_fh *fhp = &resp->fh;

	nfsd3_fh3_to_svc_fh(dirfhp, &what->dir);

	fh_init(fhp, NFS3_FHSIZE);
	resp->xdrgen.status = nfsd3_check_filename(what->name.data,
						   what->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;
	resp->xdrgen.status = nfsd_lookup(rqstp, dirfhp,
					  (char *)what->name.data,
					  what->name.len, fhp);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct LOOKUP3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_svc_fh_to_fh3(&resok->object, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_post_op_attr(rqstp, &resok->dir_attributes, dirfhp);
	} else {
		struct LOOKUP3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->dir_attributes, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_access - ACCESS: Check access permission
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   ACCESS3res NFSPROC3_ACCESS(ACCESS3args) = 4;
 */
static __be32 nfsd3_proc_access(struct svc_rqst *rqstp)
{
	struct ACCESS3args_wrapper *argp = rqstp->rq_argp;
	struct ACCESS3res *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.object);

	resp->status = nfsd_access(rqstp, fhp, &nfsd3_access_maps,
				   &argp->xdrgen.access, NULL);

	if (resp->status == nfs_ok) {
		struct ACCESS3resok *resok = &resp->u.resok;

		resok->access = argp->xdrgen.access;
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
	} else {
		struct ACCESS3resfail *resfail = &resp->u.resfail;

		resp->status = nfsd3_map_status(resp->status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->obj_attributes, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_readlink - READLINK: Read from symbolic link
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   READLINK3res NFSPROC3_READLINK(READLINK3args) = 5;
 */
static __be32 nfsd3_proc_readlink(struct svc_rqst *rqstp)
{
	struct READLINK3args_wrapper *argp = rqstp->rq_argp;
	struct READLINK3res *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;
	struct page *page;
	u32 len;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.symlink);

	len = NFS3_MAXPATHLEN;
	page = *(rqstp->rq_next_page++);
	resp->status = nfsd_readlink(rqstp, fhp, page_address(page), &len);

	if (resp->status == nfs_ok) {
		struct READLINK3resok *resok = &resp->u.resok;

		resok->data.len = len;
		nfsd3_fill_post_op_attr(rqstp, &resok->symlink_attributes, fhp);
	} else {
		struct READLINK3resfail *resfail = &resp->u.resfail;

		resp->status = nfsd3_map_status(resp->status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->symlink_attributes,
					fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_read - READ: Read from file
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   READ3res NFSPROC3_READ(READ3args) = 6;
 */
static __be32 nfsd3_proc_read(struct svc_rqst *rqstp)
{
	struct READ3args_wrapper *argp = rqstp->rq_argp;
	struct READ3res *resp = rqstp->rq_resp;
	unsigned long count = argp->xdrgen.count;
	u64 offset = argp->xdrgen.offset;
	struct svc_fh *fhp = &argp->fh;
	u32 eof;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.file);
	count = min_t(u32, count, svc_max_payload(rqstp));
	count = min_t(u32, count, rqstp->rq_res.buflen);
	if (offset > (u64)OFFSET_MAX)
		offset = (u64)OFFSET_MAX;
	if (offset + count > (u64)OFFSET_MAX)
		count = (u64)OFFSET_MAX - offset;

	/*
	 * Obtain buffer pointer for payload.
	 * 1 (status) + 22 (post_op_attr) + 1 (count) + 1 (eof)
	 * + 1 (xdr opaque byte count) = 26
	 */
	svc_reserve_auth(rqstp, ((1 + NFS3_post_op_attr_sz + 3) << 2) +
			 count + 4);
	resp->status = nfsd_read(rqstp, fhp, offset, &count, &eof);

	if (resp->status == nfs_ok) {
		struct READ3resok *resok = &resp->u.resok;

		resok->count = count;
		resok->eof = !!eof;
		resok->data.len = count;
		nfsd3_fill_post_op_attr(rqstp, &resok->file_attributes, fhp);
	} else {
		struct READ3resfail *resfail = &resp->u.resfail;

		resp->status = nfsd3_map_status(resp->status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->file_attributes, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_write - WRITE: Write to file
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   WRITE3res NFSPROC3_WRITE(WRITE3args) = 7;
 */
static __be32 nfsd3_proc_write(struct svc_rqst *rqstp)
{
	struct WRITE3args_wrapper *argp = rqstp->rq_argp;
	struct nfsd3_writeres *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;
	unsigned long count;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.file);
	if (argp->xdrgen.count != argp->xdrgen.data.len) {
		resp->xdrgen.status = nfserr_inval;
		goto out;
	}
	count = min_t(u32, argp->xdrgen.count, svc_max_payload(rqstp));
	if (argp->xdrgen.offset > (u64)OFFSET_MAX ||
	    argp->xdrgen.offset + count > (u64)OFFSET_MAX) {
		resp->xdrgen.status = nfserr_fbig;
		goto out;
	}

	resp->xdrgen.status = nfsd_write(rqstp, fhp, argp->xdrgen.offset,
					 &argp->xdrgen.data, &count,
					 nfsd3_iocb_flags(argp->xdrgen.stable),
					 (__be32 *)resp->xdrgen.u.resok.verf);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct WRITE3resok *resok = &resp->xdrgen.u.resok;

		resok->count = count;
		resok->committed = argp->xdrgen.stable;
		nfsd3_fill_wcc_data(rqstp, &resok->file_wcc, fhp);
	} else {
		struct WRITE3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->file_wcc, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/*
 * Implement NFSv3's unchecked, guarded, and exclusive CREATE
 * semantics for regular files. Except for the created file,
 * this operation is stateless on the server.
 */
static __be32
nfsd3_create_file(struct svc_rqst *rqstp, struct svc_fh *dirfhp,
		  struct svc_fh *resfhp, struct CREATE3args_wrapper *argp)
{
	struct diropargs3 *where = &argp->xdrgen.where;
	struct createhow3 *how = &argp->xdrgen.how;
	struct iattr *iattrs = &argp->iattrs;
	struct dentry *parent, *child, *mnt_child;
	struct svc_export *exp;
	__u32 v_mtime, v_atime;
	struct inode *inode;
	struct nfsd_attrs nattrs = {
		.na_iattr	= iattrs,
	};
	__be32 status;
	int host_err;

	status = nfsd3_check_filename(where->name.data, where->name.len);
	if (status != nfs_ok)
		return status;

	trace_nfsd_vfs_create(rqstp, dirfhp, S_IFREG, (char *)where->name.data,
			      where->name.len);

	if (name_is_dot_dotdot(where->name.data, where->name.len))
		return nfserr_exist;

	if (how->mode != EXCLUSIVE) {
		nfsd3_sattr3_to_iattr(rqstp, iattrs,
				      &how->u.obj_attributes);
		if (!(iattrs->ia_valid & ATTR_MODE))
			iattrs->ia_mode = 0;
	} else {
		memset(iattrs, 0, sizeof(*iattrs));
	}

	if (!nfsd3_time_in_range(iattrs))
		return nfserr_inval;

	status = fh_verify(rqstp, dirfhp, S_IFDIR, NFSD_MAY_EXEC);
	if (status != nfs_ok)
		return status;

	parent = dirfhp->fh_dentry;
	inode = d_inode(parent);

	host_err = fh_want_write(dirfhp);
	if (host_err)
		return nfserrno(host_err);

	child = start_creating(&nop_mnt_idmap, parent,
			       &QSTR_LEN(where->name.data, where->name.len));
	if (IS_ERR(child)) {
		status = nfserrno(PTR_ERR(child));
		goto out_write;
	}

	if (d_really_is_negative(child)) {
		status = fh_verify(rqstp, dirfhp, S_IFDIR, NFSD_MAY_CREATE);
		if (status != nfs_ok)
			goto out;
	}

	exp = exp_get(dirfhp->fh_export);
	/*
	 * Cross on a separate reference: child must remain the dentry
	 * start_creating() returned so that end_creating() unlocks the
	 * right directory.
	 */
	mnt_child = dget(child);
	if (how->mode == UNCHECKED) {
		/*
		 * If name is already in dcache we need to check for mountpoints
		 */
		if (d_is_reg(child) &&
		    unlikely(nfsd_mountpoint(child, exp))) {
			status = nfsd_cross_mnt(rqstp, &mnt_child, &exp);
			if (status != nfs_ok) {
				dput(mnt_child);
				exp_put(exp);
				goto out;
			}
		}
	}

	status = fh_compose(resfhp, exp, mnt_child, dirfhp);
	dput(mnt_child);
	exp_put(exp);
	if (status != nfs_ok)
		goto out;

	v_mtime = 0;
	v_atime = 0;
	if (how->mode == EXCLUSIVE) {
		u32 *verifier = (u32 *)how->u.verf;

		/*
		 * Solaris 7 gets confused (bugid 4218508) if these have
		 * the high bit set, as do xfs filesystems without the
		 * "bigtime" feature. So just clear the high bits.
		 */
		v_mtime = verifier[0] & 0x7fffffff;
		v_atime = verifier[1] & 0x7fffffff;
	}

	if (d_really_is_positive(child)) {
		status = nfs_ok;

		switch (how->mode) {
		case UNCHECKED:
			if (!d_is_reg(child))
				break;
			iattrs->ia_valid &= ATTR_SIZE;
			goto set_attr;
		case GUARDED:
			status = nfserr_exist;
			break;
		case EXCLUSIVE:
			if (inode_get_mtime_sec(d_inode(child)) == v_mtime &&
			    inode_get_atime_sec(d_inode(child)) == v_atime &&
			    d_inode(child)->i_size == 0) {
				break;
			}
			status = nfserr_exist;
		}
		goto out;
	}

	if (!IS_POSIXACL(inode))
		iattrs->ia_mode &= ~current_umask();

	status = fh_fill_pre_attrs(dirfhp);
	if (status != nfs_ok)
		goto out;
	host_err = vfs_create(&nop_mnt_idmap, child, iattrs->ia_mode, NULL);
	if (host_err < 0) {
		status = nfserrno(host_err);
		goto out;
	}
	fh_fill_post_attrs(dirfhp);

	/* A newly created file already has a file size of zero. */
	if ((iattrs->ia_valid & ATTR_SIZE) && iattrs->ia_size == 0)
		iattrs->ia_valid &= ~ATTR_SIZE;
	if (how->mode == EXCLUSIVE) {
		iattrs->ia_valid = ATTR_MTIME | ATTR_ATIME |
				   ATTR_MTIME_SET | ATTR_ATIME_SET;
		iattrs->ia_mtime.tv_sec = v_mtime;
		iattrs->ia_atime.tv_sec = v_atime;
		iattrs->ia_mtime.tv_nsec = 0;
		iattrs->ia_atime.tv_nsec = 0;
	}

set_attr:
	status = nfsd_create_setattr(rqstp, dirfhp, resfhp, &nattrs);

out:
	end_creating(child);
out_write:
	fh_drop_write(dirfhp);
	return status;
}

/**
 * nfsd3_proc_create - CREATE: Create a file
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   CREATE3res NFSPROC3_CREATE(CREATE3args) = 8;
 */
static __be32 nfsd3_proc_create(struct svc_rqst *rqstp)
{
	struct CREATE3args_wrapper *argp = rqstp->rq_argp;
	struct CREATE3res_wrapper *resp = rqstp->rq_resp;
	struct svc_fh *dirfhp = &argp->fh;
	struct svc_fh *fhp = &resp->fh;

	nfsd3_fh3_to_svc_fh(dirfhp, &argp->xdrgen.where.dir);

	fh_init(fhp, NFS3_FHSIZE);
	resp->xdrgen.status = nfsd3_create_file(rqstp, dirfhp, fhp, argp);

	if (resp->xdrgen.status == nfs_ok) {
		struct CREATE3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_post_op_fh3(&resok->obj, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, dirfhp);
	} else {
		struct CREATE3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_mkdir - MKDIR: Create a directory
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   MKDIR3res NFSPROC3_MKDIR(MKDIR3args) = 9;
 */
static __be32 nfsd3_proc_mkdir(struct svc_rqst *rqstp)
{
	struct MKDIR3args_wrapper *argp = rqstp->rq_argp;
	struct diropargs3 *where = &argp->xdrgen.where;
	struct MKDIR3res_wrapper *resp = rqstp->rq_resp;
	struct iattr *iattrs = &argp->iattrs;
	struct svc_fh *dirfhp = &argp->fh;
	struct svc_fh *fhp = &resp->fh;
	struct nfsd_attrs nattrs = {
		.na_iattr	= iattrs,
	};

	nfsd3_fh3_to_svc_fh(dirfhp, &where->dir);
	resp->xdrgen.status = nfsd3_check_filename(where->name.data,
						   where->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;
	nfsd3_sattr3_to_iattr(rqstp, iattrs, &argp->xdrgen.attributes);
	if (!nfsd3_time_in_range(iattrs)) {
		resp->xdrgen.status = nfserr_inval;
		goto out;
	}

	fh_init(fhp, NFS3_FHSIZE);
	iattrs->ia_valid &= ~ATTR_SIZE;
	resp->xdrgen.status = nfsd_create(rqstp, dirfhp, (char *)where->name.data,
					  where->name.len, &nattrs, S_IFDIR,
					  0, fhp);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct MKDIR3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_post_op_fh3(&resok->obj, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, dirfhp);
	} else {
		struct MKDIR3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_symlink - SYMLINK: Create a symbolic link
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   SYMLINK3res NFSPROC3_SYMLINK(SYMLINK3args) = 10;
 */
static __be32 nfsd3_proc_symlink(struct svc_rqst *rqstp)
{
	struct SYMLINK3args_wrapper *argp = rqstp->rq_argp;
	struct symlinkdata3 *symlink = &argp->xdrgen.symlink;
	struct xdr_buf *to = &symlink->symlink_data;
	struct diropargs3 *where = &argp->xdrgen.where;
	struct SYMLINK3res_wrapper *resp = rqstp->rq_resp;
	struct iattr *iattrs = &argp->iattrs;
	struct svc_fh *dirfhp = &argp->fh;
	struct svc_fh *fhp = &resp->fh;
	struct nfsd_attrs nattrs = {
		.na_iattr	= iattrs,
	};
	char *tname;

	nfsd3_fh3_to_svc_fh(dirfhp, &where->dir);
	resp->xdrgen.status = nfsd3_check_filename(where->name.data,
						   where->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;
	nfsd3_sattr3_to_iattr(rqstp, iattrs, &symlink->symlink_attributes);
	if (!nfsd3_time_in_range(iattrs)) {
		resp->xdrgen.status = nfserr_inval;
		goto out;
	}
	if (to->len == 0) {
		resp->xdrgen.status = nfserr_inval;
		goto out;
	}
	if (to->len > NFS3_MAXPATHLEN) {
		resp->xdrgen.status = nfserr_nametoolong;
		goto out;
	}

	tname = nfsd_symlink_target(to);
	if (IS_ERR(tname)) {
		resp->xdrgen.status = nfserrno(PTR_ERR(tname));
		goto out;
	}

	fh_init(fhp, NFS3_FHSIZE);
	resp->xdrgen.status = nfsd_symlink(rqstp, dirfhp,
					   (char *)where->name.data,
					   where->name.len, tname,
					   &nattrs, fhp);
	kfree(tname);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct SYMLINK3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_post_op_fh3(&resok->obj, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, dirfhp);
	} else {
		struct SYMLINK3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_mknod - MKNOD: Create a special file
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   MKNOD3res NFSPROC3_MKNOD(MKNOD3args) = 11;
 */
static __be32 nfsd3_proc_mknod(struct svc_rqst *rqstp)
{
	struct MKNOD3args_wrapper *argp = rqstp->rq_argp;
	struct diropargs3 *where = &argp->xdrgen.where;
	struct mknoddata3 *what = &argp->xdrgen.what;
	struct MKNOD3res_wrapper *resp = rqstp->rq_resp;
	struct iattr *iattrs = &argp->iattrs;
	struct svc_fh *dirfhp = &argp->fh;
	struct svc_fh *fhp = &resp->fh;
	struct nfsd_attrs nattrs = {
		.na_iattr	= iattrs,
	};
	dev_t rdev = 0;

	nfsd3_fh3_to_svc_fh(dirfhp, &where->dir);
	resp->xdrgen.status = nfsd3_check_filename(where->name.data,
						   where->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;
	switch (what->type) {
	case NF3CHR:
	case NF3BLK:
		rdev = MKDEV(what->u.device.spec.specdata1,
			     what->u.device.spec.specdata2);
		if (MAJOR(rdev) != what->u.device.spec.specdata1 ||
		    MINOR(rdev) != what->u.device.spec.specdata2) {
			resp->xdrgen.status = nfserr_inval;
			goto out;
		}
		nfsd3_sattr3_to_iattr(rqstp, iattrs,
				      &what->u.device.dev_attributes);
		break;
	case NF3SOCK:
	case NF3FIFO:
		nfsd3_sattr3_to_iattr(rqstp, iattrs,
				      &what->u.pipe_attributes);
		break;
	default:
		resp->xdrgen.status = nfserr_badtype;
		goto out;
	}

	if (!nfsd3_time_in_range(iattrs)) {
		resp->xdrgen.status = nfserr_inval;
		goto out;
	}

	fh_init(fhp, NFS3_FHSIZE);
	resp->xdrgen.status = nfsd_create(rqstp, dirfhp,
					  (char *)where->name.data,
					  where->name.len, &nattrs,
					  nfsd3_ftype3_to_mode(what->type),
					  rdev, fhp);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct MKNOD3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_post_op_fh3(&resok->obj, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, dirfhp);
	} else {
		struct MKNOD3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_remove - REMOVE: Remove a file
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   REMOVE3res NFSPROC3_REMOVE(REMOVE3args) = 12;
 */
static __be32 nfsd3_proc_remove(struct svc_rqst *rqstp)
{
	struct REMOVE3args_wrapper *argp = rqstp->rq_argp;
	struct diropargs3 *object = &argp->xdrgen.object;
	struct REMOVE3res *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &object->dir);
	resp->status = nfsd3_check_filename(object->name.data,
					    object->name.len);
	if (resp->status != nfs_ok)
		goto out;

	resp->status = nfsd_unlink(rqstp, fhp, -S_IFDIR,
				   (char *)object->name.data,
				   object->name.len);

out:
	if (resp->status == nfs_ok) {
		nfsd3_fill_wcc_data(rqstp, &resp->u.resok.dir_wcc, fhp);
	} else {
		resp->status = nfsd3_map_status(resp->status);
		nfsd3_fill_wcc_data(rqstp, &resp->u.resfail.dir_wcc, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_rmdir - RMDIR: Remove a directory
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   RMDIR3res NFSPROC3_RMDIR(RMDIR3args) = 13;
 */
static __be32 nfsd3_proc_rmdir(struct svc_rqst *rqstp)
{
	struct RMDIR3args_wrapper *argp = rqstp->rq_argp;
	struct diropargs3 *object = &argp->xdrgen.object;
	struct RMDIR3res *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &object->dir);
	resp->status = nfsd3_check_filename(object->name.data,
					    object->name.len);
	if (resp->status != nfs_ok)
		goto out;

	resp->status = nfsd_unlink(rqstp, fhp, S_IFDIR,
				   (char *)object->name.data,
				   object->name.len);

out:
	if (resp->status == nfs_ok) {
		nfsd3_fill_wcc_data(rqstp, &resp->u.resok.dir_wcc, fhp);
	} else {
		resp->status = nfsd3_map_status(resp->status);
		nfsd3_fill_wcc_data(rqstp, &resp->u.resfail.dir_wcc, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_rename - RENAME: Rename a file or directory
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   RENAME3res NFSPROC3_RENAME(RENAME3args) = 14;
 */
static __be32 nfsd3_proc_rename(struct svc_rqst *rqstp)
{
	struct RENAME3args_wrapper *argp = rqstp->rq_argp;
	struct diropargs3 *from = &argp->xdrgen.from;
	struct diropargs3 *to = &argp->xdrgen.to;
	struct RENAME3res *resp = rqstp->rq_resp;
	struct svc_fh *ffhp = &argp->ffh;
	struct svc_fh *tfhp = &argp->tfh;

	nfsd3_fh3_to_svc_fh(ffhp, &from->dir);
	nfsd3_fh3_to_svc_fh(tfhp, &to->dir);
	resp->status = nfsd3_check_filename(from->name.data,
					    from->name.len);
	if (resp->status != nfs_ok)
		goto out;
	resp->status = nfsd3_check_filename(to->name.data,
					    to->name.len);
	if (resp->status != nfs_ok)
		goto out;

	resp->status = nfsd_rename(rqstp, ffhp, (char *)from->name.data,
				   from->name.len, tfhp,
				   (char *)to->name.data,
				   to->name.len);

out:
	if (resp->status == nfs_ok) {
		struct RENAME3resok *resok = &resp->u.resok;

		nfsd3_fill_wcc_data(rqstp, &resok->fromdir_wcc, ffhp);
		nfsd3_fill_wcc_data(rqstp, &resok->todir_wcc, tfhp);
	} else {
		struct RENAME3resfail *resfail = &resp->u.resfail;

		resp->status = nfsd3_map_status(resp->status);
		nfsd3_fill_wcc_data(rqstp, &resfail->fromdir_wcc, ffhp);
		nfsd3_fill_wcc_data(rqstp, &resfail->todir_wcc, tfhp);
	}

	fh_put(ffhp);
	fh_put(tfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_link - LINK: Create Link to an object
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   LINK3res NFSPROC3_LINK(LINK3args) = 15;
 */
static __be32 nfsd3_proc_link(struct svc_rqst *rqstp)
{
	struct LINK3args_wrapper *argp = rqstp->rq_argp;
	struct diropargs3 *link = &argp->xdrgen.link;
	struct LINK3res *resp = rqstp->rq_resp;
	struct svc_fh *ffhp = &argp->ffh;
	struct svc_fh *tfhp = &argp->tfh;

	nfsd3_fh3_to_svc_fh(ffhp, &argp->xdrgen.file);
	nfsd3_fh3_to_svc_fh(tfhp, &link->dir);
	resp->status = nfsd3_check_filename(link->name.data,
					    link->name.len);
	if (resp->status != nfs_ok)
		goto out;

	resp->status = nfsd_link(rqstp, tfhp, (char *)link->name.data,
				 link->name.len, ffhp);

out:
	if (resp->status == nfs_ok) {
		struct LINK3resok *resok = &resp->u.resok;

		nfsd3_fill_post_op_attr(rqstp, &resok->file_attributes, ffhp);
		nfsd3_fill_wcc_data(rqstp, &resok->linkdir_wcc, tfhp);
	} else {
		struct LINK3resfail *resfail = &resp->u.resfail;

		resp->status = nfsd3_map_status(resp->status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->file_attributes, ffhp);
		nfsd3_fill_wcc_data(rqstp, &resfail->linkdir_wcc, tfhp);
	}

	fh_put(ffhp);
	fh_put(tfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_readdir - READDIR: Read from directory
 * @rqstp: RPC transaction context
 *
 * The directory is opened here so the reply status reflects any open
 * error before the generated encoder writes the status word.  The
 * entry list is streamed from the reply's directory reader during
 * encode; nfs3svc_release_readdirres() closes the reader and releases
 * the file handle.
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   READDIR3res NFSPROC3_READDIR(READDIR3args) = 16;
 */
static __be32 nfsd3_proc_readdir(struct svc_rqst *rqstp)
{
	struct READDIR3args_wrapper *argp = rqstp->rq_argp;
	struct nfsd3_readdirres *resp = rqstp->rq_resp;
	loff_t offset = argp->xdrgen.cookie;
	struct svc_fh *fhp = &argp->fh;
	__be32 status;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.dir);
	trace_nfsd_vfs_readdir(rqstp, fhp, argp->xdrgen.count,
			       argp->xdrgen.cookie);

	resp->count = argp->xdrgen.count;
	status = nfsd_readdir_open(rqstp, fhp, &offset, &resp->iter);

	if (status == nfs_ok) {
		struct READDIR3resok *resok = &resp->xdrgen.u.resok;

		memcpy(resok->cookieverf, argp->xdrgen.cookieverf,
		       NFS3_COOKIEVERFSIZE);
		nfsd3_fill_post_op_attr(rqstp, &resok->dir_attributes, fhp);
	} else {
		struct READDIR3resfail *resfail = &resp->xdrgen.u.resfail;

		nfsd3_fill_post_op_attr(rqstp, &resfail->dir_attributes, fhp);
	}

	resp->xdrgen.status = nfsd3_map_status(status);
	return rpc_success;
}

/**
 * nfsd3_proc_readdirplus - READDIRPLUS: Extended read from directory
 * @rqstp: RPC transaction context
 *
 * The directory is opened here so the reply status reflects any open
 * error before the generated encoder writes the status word.  The
 * entry list is streamed from the reply's directory reader during
 * encode; nfs3svc_release_readdirplusres() closes the reader and
 * releases the file handle.
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   READDIRPLUS3res NFSPROC3_READDIRPLUS(READDIRPLUS3args) = 17;
 */
static __be32 nfsd3_proc_readdirplus(struct svc_rqst *rqstp)
{
	struct READDIRPLUS3args_wrapper *argp = rqstp->rq_argp;
	struct nfsd3_readdirplusres *resp = rqstp->rq_resp;
	loff_t offset = argp->xdrgen.cookie;
	struct svc_fh *fhp = &argp->fh;
	__be32 status;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.dir);
	trace_nfsd_vfs_readdir(rqstp, fhp, argp->xdrgen.maxcount,
			       argp->xdrgen.cookie);

	resp->count = argp->xdrgen.maxcount;
	status = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_NOP);
	if (status == nfs_ok &&
	    fhp->fh_export->ex_flags & NFSEXP_NOREADDIRPLUS)
		status = nfserr_notsupp;
	if (status == nfs_ok)
		status = nfsd_readdir_open(rqstp, fhp, &offset, &resp->iter);

	if (status == nfs_ok) {
		struct READDIRPLUS3resok *resok = &resp->xdrgen.u.resok;

		memcpy(resok->cookieverf, argp->xdrgen.cookieverf,
		       NFS3_COOKIEVERFSIZE);
		nfsd3_fill_post_op_attr(rqstp, &resok->dir_attributes, fhp);
	} else {
		struct READDIRPLUS3resfail *resfail = &resp->xdrgen.u.resfail;

		nfsd3_fill_post_op_attr(rqstp, &resfail->dir_attributes, fhp);
	}

	resp->xdrgen.status = nfsd3_map_status(status);
	return rpc_success;
}

/**
 * nfsd3_proc_fsstat - FSSTAT: Get dynamic file system information
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   FSSTAT3res NFSPROC3_FSSTAT(FSSTAT3args) = 18;
 */
static __be32 nfsd3_proc_fsstat(struct svc_rqst *rqstp)
{
	struct FSSTAT3args_wrapper *argp = rqstp->rq_argp;
	struct nfsd3_fsstatres *resp = rqstp->rq_resp;
	struct kstatfs *statp = &resp->stats;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.fsroot);

	resp->xdrgen.status = nfsd_statfs(rqstp, fhp, statp, 0);

	if (resp->xdrgen.status == nfs_ok) {
		struct FSSTAT3resok *resok = &resp->xdrgen.u.resok;
		u64 bs = statp->f_bsize;

		resok->obj_attributes.attributes_follow = false;
		resok->tbytes = bs * statp->f_blocks;
		resok->fbytes = bs * statp->f_bfree;
		resok->abytes = bs * statp->f_bavail;
		resok->tfiles = statp->f_files;
		resok->ffiles = statp->f_ffree;
		resok->afiles = statp->f_ffree;
		resok->invarsec = 0;
	} else {
		struct FSSTAT3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		resfail->obj_attributes.attributes_follow = false;
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_fsinfo - FSINFO: Get static file system information
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   FSINFO3res NFSPROC3_FSINFO(FSINFO3args) = 19;
 */
static __be32 nfsd3_proc_fsinfo(struct svc_rqst *rqstp)
{
	struct FSINFO3args_wrapper *argp = rqstp->rq_argp;
	struct nfsd3_fsinfores *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.fsroot);

	resp->xdrgen.status = fh_verify(rqstp, fhp, 0, NFSD_MAY_NOP |
					NFSD_MAY_BYPASS_GSS_ON_ROOT);

	if (resp->xdrgen.status == nfs_ok) {
		struct FSINFO3resok *resok = &resp->xdrgen.u.resok;
		struct super_block *sb = fhp->fh_dentry->d_sb;
		u32 max_blocksize = svc_max_payload(rqstp);

		resok->obj_attributes.attributes_follow = false;
		resok->rtmax = max_blocksize;
		resok->rtpref = max_blocksize;
		resok->rtmult = PAGE_SIZE;
		resok->wtmax = max_blocksize;
		resok->wtpref = max_blocksize;
		resok->wtmult = PAGE_SIZE;
		resok->dtpref = max_blocksize;
		resok->maxfilesize = ~(u32)0;
		/* NFSD is accurate to the nearest second. */
		resok->time_delta.seconds = 1;
		resok->time_delta.nseconds = 0;
		resok->properties = FSF3_LINK | FSF3_SYMLINK |
				    FSF3_HOMOGENEOUS | FSF3_CANSETTIME;

		/*
		 * Check special features of the file system. May
		 * request different read/write sizes for file systems
		 * known to have problems with large blocks.
		 */
		if (sb->s_magic == MSDOS_SUPER_MAGIC)
			resok->properties = FSF3_HOMOGENEOUS | FSF3_CANSETTIME;
		resok->maxfilesize = sb->s_maxbytes;
	} else {
		struct FSINFO3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		resfail->obj_attributes.attributes_follow = false;
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_pathconf - PATHCONF: Retrieve POSIX information
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   PATHCONF3res NFSPROC3_PATHCONF(PATHCONF3args) = 20;
 */
static __be32 nfsd3_proc_pathconf(struct svc_rqst *rqstp)
{
	struct PATHCONF3args_wrapper *argp = rqstp->rq_argp;
	struct nfsd3_pathconfres *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.object);

	resp->xdrgen.status = fh_verify(rqstp, fhp, 0, NFSD_MAY_NOP);

	if (resp->xdrgen.status == nfs_ok) {
		struct PATHCONF3resok *resok = &resp->xdrgen.u.resok;
		struct super_block *sb = fhp->fh_dentry->d_sb;
		int err;

		resok->obj_attributes.attributes_follow = false;
		resok->linkmax = 255;
		resok->name_max = NAME_MAX;
		resok->no_trunc = false;
		resok->chown_restricted = true;
		resok->case_insensitive = false;
		resok->case_preserving = true;

		if (sb->s_magic == EXT2_SUPER_MAGIC) {
			resok->linkmax = EXT2_LINK_MAX;
			resok->name_max = EXT2_NAME_LEN;
		}

		err = nfsd_get_case_info(fhp->fh_dentry,
					 &resok->case_insensitive,
					 &resok->case_preserving);
		/*
		 * RFC 1813 lists NFS3ERR_STALE, NFS3ERR_BADHANDLE, and
		 * NFS3ERR_SERVERFAULT as the only PATHCONF errors.
		 */
		switch (err) {
		case 0:
		case -EOPNOTSUPP:
			/* Both arms leave the output booleans valid. */
			break;
		case -EACCES:
		case -EPERM:
			/*
			 * Policy denied the query. Report STALE so the
			 * handle is unusable without implying a server
			 * malfunction.
			 */
			resp->xdrgen.status = nfserr_stale;
			break;
		case -ESTALE:
			resp->xdrgen.status = nfserr_stale;
			break;
		default:
			resp->xdrgen.status = nfserr_serverfault;
			break;
		}
	} else {
		struct PATHCONF3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		resfail->obj_attributes.attributes_follow = false;
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_commit - COMMIT: Commit cached data on a server to stable storage
 * @rqstp: RPC transaction context
 *
 * Return:
 *   %rpc_success:		RPC executed successfully
 *
 * RPC synopsis:
 *   COMMIT3res NFSPROC3_COMMIT(COMMIT3args) = 21;
 */
static __be32 nfsd3_proc_commit(struct svc_rqst *rqstp)
{
	struct COMMIT3args_wrapper *argp = rqstp->rq_argp;
	struct nfsd3_commitres *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;
	struct nfsd_file *nf;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.file);

	resp->xdrgen.status = nfsd_file_acquire_gc(rqstp, fhp, NFSD_MAY_WRITE |
						   NFSD_MAY_NOT_BREAK_LEASE, &nf);
	if (resp->xdrgen.status)
		goto out;
	resp->xdrgen.status = nfsd_commit(rqstp, fhp, nf,
					  argp->xdrgen.offset, argp->xdrgen.count,
					  (__be32 *)resp->xdrgen.u.resok.verf);
	nfsd_file_put(nf);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct COMMIT3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_wcc_data(rqstp, &resok->file_wcc, fhp);
	} else {
		struct COMMIT3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->file_wcc, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}


/*
 * NFSv3 Server procedures.
 * Only the results of non-idempotent operations are cached.
 */
static const struct svc_procedure nfsd_procedures3[22] = {
	[NFSPROC3_NULL] = {
		.pc_func	= nfsd3_proc_null,
		.pc_decode	= xdrgen_svc_decode_void,
		.pc_encode	= xdrgen_svc_encode_void,
		.pc_argsize	= XDR_void,
		.pc_argzero	= 0,
		.pc_ressize	= 0,
		.pc_cachetype	= RC_NOCACHE,
		.pc_xdrressize	= XDR_void,
		.pc_name	= "NULL",
	},
	[NFSPROC3_GETATTR] = {
		.pc_func	= nfsd3_proc_getattr,
		.pc_decode	= nfs_svc_decode_GETATTR3args,
		.pc_encode	= nfs_svc_encode_GETATTR3res,
		.pc_argsize	= sizeof(struct GETATTR3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct GETATTR3res_wrapper),
		.pc_cachetype	= RC_NOCACHE,
		.pc_xdrressize	= NFS3_GETATTR3res_sz,
		.pc_name	= "GETATTR",
	},
	[NFSPROC3_SETATTR] = {
		.pc_func	= nfsd3_proc_setattr,
		.pc_decode	= nfs_svc_decode_SETATTR3args,
		.pc_encode	= nfs_svc_encode_SETATTR3res,
		.pc_argsize	= sizeof(struct SETATTR3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct SETATTR3res),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_SETATTR3res_sz,
		.pc_name	= "SETATTR",
	},
	[NFSPROC3_LOOKUP] = {
		.pc_func	= nfsd3_proc_lookup,
		.pc_decode	= nfs_svc_decode_LOOKUP3args,
		.pc_encode	= nfs_svc_encode_LOOKUP3res,
		.pc_argsize	= sizeof(struct LOOKUP3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct LOOKUP3res_wrapper),
		.pc_cachetype	= RC_NOCACHE,
		.pc_xdrressize	= NFS3_LOOKUP3res_sz,
		.pc_name	= "LOOKUP",
	},
	[NFSPROC3_ACCESS] = {
		.pc_func	= nfsd3_proc_access,
		.pc_decode	= nfs_svc_decode_ACCESS3args,
		.pc_encode	= nfs_svc_encode_ACCESS3res,
		.pc_argsize	= sizeof(struct ACCESS3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct ACCESS3res),
		.pc_cachetype	= RC_NOCACHE,
		.pc_xdrressize	= NFS3_ACCESS3res_sz,
		.pc_name	= "ACCESS",
	},
	[NFSPROC3_READLINK] = {
		.pc_func	= nfsd3_proc_readlink,
		.pc_decode	= nfs_svc_decode_READLINK3args,
		.pc_encode	= nfs_svc_encode_READLINK3res,
		.pc_argsize	= sizeof(struct READLINK3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct READLINK3res),
		.pc_cachetype	= RC_NOCACHE,
		/* _sz omits the payload, which nfs3.x leaves unbounded */
		.pc_xdrressize	= NFS3_READLINK3res_sz +
				  XDR_QUADLEN(NFS3_MAXPATHLEN),
		.pc_name	= "READLINK",
	},
	[NFSPROC3_READ] = {
		.pc_func	= nfsd3_proc_read,
		.pc_decode	= nfs_svc_decode_READ3args,
		.pc_encode	= nfs_svc_encode_READ3res,
		.pc_argsize	= sizeof(struct READ3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct READ3res),
		.pc_cachetype	= RC_NOCACHE,
		.pc_xdrressize	= NFS3_READ3res_sz +
				  XDR_QUADLEN(NFSSVC_MAXBLKSIZE),
		.pc_name	= "READ",
	},
	[NFSPROC3_WRITE] = {
		.pc_func	= nfsd3_proc_write,
		.pc_decode	= nfs_svc_decode_WRITE3args,
		.pc_encode	= nfs_svc_encode_WRITE3res,
		.pc_argsize	= sizeof(struct WRITE3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct nfsd3_writeres),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_WRITE3res_sz,
		.pc_name	= "WRITE",
	},
	[NFSPROC3_CREATE] = {
		.pc_func	= nfsd3_proc_create,
		.pc_decode	= nfs_svc_decode_CREATE3args,
		.pc_encode	= nfs_svc_encode_CREATE3res,
		.pc_argsize	= sizeof(struct CREATE3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct CREATE3res_wrapper),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_CREATE3res_sz,
		.pc_name	= "CREATE",
	},
	[NFSPROC3_MKDIR] = {
		.pc_func	= nfsd3_proc_mkdir,
		.pc_decode	= nfs_svc_decode_MKDIR3args,
		.pc_encode	= nfs_svc_encode_MKDIR3res,
		.pc_argsize	= sizeof(struct MKDIR3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct MKDIR3res_wrapper),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_MKDIR3res_sz,
		.pc_name	= "MKDIR",
	},
	[NFSPROC3_SYMLINK] = {
		.pc_func	= nfsd3_proc_symlink,
		.pc_decode	= nfs_svc_decode_SYMLINK3args,
		.pc_encode	= nfs_svc_encode_SYMLINK3res,
		.pc_argsize	= sizeof(struct SYMLINK3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct SYMLINK3res_wrapper),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_SYMLINK3res_sz,
		.pc_name	= "SYMLINK",
	},
	[NFSPROC3_MKNOD] = {
		.pc_func	= nfsd3_proc_mknod,
		.pc_decode	= nfs_svc_decode_MKNOD3args,
		.pc_encode	= nfs_svc_encode_MKNOD3res,
		.pc_argsize	= sizeof(struct MKNOD3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct MKNOD3res_wrapper),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_MKNOD3res_sz,
		.pc_name	= "MKNOD",
	},
	[NFSPROC3_REMOVE] = {
		.pc_func	= nfsd3_proc_remove,
		.pc_decode	= nfs_svc_decode_REMOVE3args,
		.pc_encode	= nfs_svc_encode_REMOVE3res,
		.pc_argsize	= sizeof(struct REMOVE3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct REMOVE3res),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_REMOVE3res_sz,
		.pc_name	= "REMOVE",
	},
	[NFSPROC3_RMDIR] = {
		.pc_func	= nfsd3_proc_rmdir,
		.pc_decode	= nfs_svc_decode_RMDIR3args,
		.pc_encode	= nfs_svc_encode_RMDIR3res,
		.pc_argsize	= sizeof(struct RMDIR3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct RMDIR3res),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_RMDIR3res_sz,
		.pc_name	= "RMDIR",
	},
	[NFSPROC3_RENAME] = {
		.pc_func	= nfsd3_proc_rename,
		.pc_decode	= nfs_svc_decode_RENAME3args,
		.pc_encode	= nfs_svc_encode_RENAME3res,
		.pc_argsize	= sizeof(struct RENAME3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct RENAME3res),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_RENAME3res_sz,
		.pc_name	= "RENAME",
	},
	[NFSPROC3_LINK] = {
		.pc_func	= nfsd3_proc_link,
		.pc_decode	= nfs_svc_decode_LINK3args,
		.pc_encode	= nfs_svc_encode_LINK3res,
		.pc_argsize	= sizeof(struct LINK3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct LINK3res),
		.pc_cachetype	= RC_REPLBUFF,
		.pc_xdrressize	= NFS3_LINK3res_sz,
		.pc_name	= "LINK",
	},
	[NFSPROC3_READDIR] = {
		.pc_func	= nfsd3_proc_readdir,
		.pc_decode	= nfs_svc_decode_READDIR3args,
		.pc_encode	= nfs_svc_encode_READDIR3res,
		.pc_release	= nfs3svc_release_readdirres,
		.pc_argsize	= sizeof(struct READDIR3args_wrapper),
		.pc_argzero	= sizeof(struct READDIR3args_wrapper),
		.pc_ressize	= sizeof(struct nfsd3_readdirres),
		.pc_cachetype	= RC_NOCACHE,
		.pc_name	= "READDIR",
	},
	[NFSPROC3_READDIRPLUS] = {
		.pc_func	= nfsd3_proc_readdirplus,
		.pc_decode	= nfs_svc_decode_READDIRPLUS3args,
		.pc_encode	= nfs_svc_encode_READDIRPLUS3res,
		.pc_release	= nfs3svc_release_readdirplusres,
		.pc_argsize	= sizeof(struct READDIRPLUS3args_wrapper),
		.pc_argzero	= sizeof(struct READDIRPLUS3args_wrapper),
		.pc_ressize	= sizeof(struct nfsd3_readdirplusres),
		.pc_cachetype	= RC_NOCACHE,
		.pc_name	= "READDIRPLUS",
	},
	[NFSPROC3_FSSTAT] = {
		.pc_func	= nfsd3_proc_fsstat,
		.pc_decode	= nfs_svc_decode_FSSTAT3args,
		.pc_encode	= nfs_svc_encode_FSSTAT3res,
		.pc_argsize	= sizeof(struct FSSTAT3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct nfsd3_fsstatres),
		.pc_cachetype	= RC_NOCACHE,
		.pc_xdrressize	= NFS3_FSSTAT3res_sz,
		.pc_name	= "FSSTAT",
	},
	[NFSPROC3_FSINFO] = {
		.pc_func	= nfsd3_proc_fsinfo,
		.pc_decode	= nfs_svc_decode_FSINFO3args,
		.pc_encode	= nfs_svc_encode_FSINFO3res,
		.pc_argsize	= sizeof(struct FSINFO3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct nfsd3_fsinfores),
		.pc_cachetype	= RC_NOCACHE,
		.pc_xdrressize	= NFS3_FSINFO3res_sz,
		.pc_name	= "FSINFO",
	},
	[NFSPROC3_PATHCONF] = {
		.pc_func	= nfsd3_proc_pathconf,
		.pc_decode	= nfs_svc_decode_PATHCONF3args,
		.pc_encode	= nfs_svc_encode_PATHCONF3res,
		.pc_argsize	= sizeof(struct PATHCONF3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct nfsd3_pathconfres),
		.pc_cachetype	= RC_NOCACHE,
		.pc_xdrressize	= NFS3_PATHCONF3res_sz,
		.pc_name	= "PATHCONF",
	},
	[NFSPROC3_COMMIT] = {
		.pc_func	= nfsd3_proc_commit,
		.pc_decode	= nfs_svc_decode_COMMIT3args,
		.pc_encode	= nfs_svc_encode_COMMIT3res,
		.pc_argsize	= sizeof(struct COMMIT3args_wrapper),
		.pc_argzero	= 0,
		.pc_ressize	= sizeof(struct nfsd3_commitres),
		.pc_cachetype	= RC_NOCACHE,
		.pc_xdrressize	= NFS3_COMMIT3res_sz,
		.pc_name	= "COMMIT",
	},
};

/*
 * Storage requirements for XDR arguments and results.
 */
union nfsd3_xdrstore {
	struct GETATTR3args_wrapper	getattrargs;
	struct GETATTR3res_wrapper	getattrres;
	struct SETATTR3args_wrapper	setattrargs;
	struct SETATTR3res		setattrres;
	struct LOOKUP3args_wrapper	lookupargs;
	struct LOOKUP3res_wrapper	lookupres;
	struct ACCESS3args_wrapper	accessargs;
	struct ACCESS3res		accessres;
	struct READLINK3args_wrapper	readlinkargs;
	struct READ3args_wrapper	readargs;
	struct WRITE3args_wrapper	writeargs;
	struct CREATE3args_wrapper	createargs;
	struct CREATE3res_wrapper	createres;
	struct MKDIR3args_wrapper	mkdirargs;
	struct MKDIR3res_wrapper	mkdirres;
	struct SYMLINK3args_wrapper	symlinkargs;
	struct SYMLINK3res_wrapper	symlinkres;
	struct MKNOD3args_wrapper	mknodargs;
	struct MKNOD3res_wrapper	mknodres;
	struct REMOVE3args_wrapper	removeargs;
	struct REMOVE3res		removeres;
	struct RMDIR3args_wrapper	rmdirargs;
	struct RMDIR3res		rmdirres;
	struct RENAME3args_wrapper	renameargs;
	struct RENAME3res		renameres;
	struct LINK3args_wrapper	linkargs;
	struct LINK3res			linkres;
	struct READDIR3args_wrapper	readdirargs;
	struct READDIRPLUS3args_wrapper	readdirplusargs;
	struct READLINK3res		readlinkres;
	struct READ3res			readres;
	struct nfsd3_writeres		writeres;
	struct nfsd3_readdirres		readdirres;
	struct nfsd3_readdirplusres	readdirplusres;
	struct FSSTAT3args_wrapper	fsstatargs;
	struct nfsd3_fsstatres		fsstatres;
	struct FSINFO3args_wrapper	fsinfoargs;
	struct nfsd3_fsinfores		fsinfores;
	struct PATHCONF3args_wrapper	pathconfargs;
	struct nfsd3_pathconfres	pathconfres;
	struct COMMIT3args_wrapper	commitargs;
	struct nfsd3_commitres		commitres;
	struct nfsd3_getaclres		getaclres;
};

const struct svc_version nfsd_version3 = {
	.vs_vers	= 3,
	.vs_nproc	= ARRAY_SIZE(nfsd_procedures3),
	.vs_proc	= nfsd_procedures3,
	.vs_dispatch	= nfsd_dispatch,
	.vs_xdrsize	= sizeof(union nfsd3_xdrstore),
};
