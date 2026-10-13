// SPDX-License-Identifier: GPL-2.0
/*
 * XDR support for nfsd/protocol version 3.
 *
 * Copyright (C) 1995, 1996, 1997 Olaf Kirch <okir@monad.swb.de>
 *
 * 2003-08-09 Jamie Lokier: Use htonl() for nanoseconds, not htons()!
 */

#include <linux/namei.h>
#include <linux/sunrpc/svc_xprt.h>

#include "nfsd.h"
#include "xdr3.h"
#include "auth.h"
#include "netns.h"
#include "vfs.h"
#include "nfserr.h"
#include "trace.h"

#include "nfs3xdr_gen.h"

/*
 * Mapping of S_IF* types to NFS file types
 */
static const u32 nfs3_ftypes[] = {
	NF3NON,  NF3FIFO, NF3CHR, NF3BAD,
	NF3DIR,  NF3BAD,  NF3BLK, NF3BAD,
	NF3REG,  NF3BAD,  NF3LNK, NF3BAD,
	NF3SOCK, NF3BAD,  NF3LNK, NF3BAD,
};


/*
 * Basic NFSv3 data types (RFC 1813 Sections 2.5 and 2.6)
 */

static __be32 *
encode_nfstime3(__be32 *p, const struct timespec64 *time)
{
	*p++ = cpu_to_be32((u32)time->tv_sec);
	*p++ = cpu_to_be32(time->tv_nsec);

	return p;
}

/**
 * svcxdr_decode_nfs_fh3 - Decode an NFSv3 file handle
 * @xdr: XDR stream positioned at an undecoded NFSv3 FH
 * @fhp: OUT: filled-in server file handle
 *
 * Return values:
 *  %false: The encoded file handle was not valid
 *  %true: @fhp has been initialized
 */
bool
svcxdr_decode_nfs_fh3(struct xdr_stream *xdr, struct svc_fh *fhp)
{
	__be32 *p;
	u32 size;

	if (xdr_stream_decode_u32(xdr, &size) < 0)
		return false;
	if (size == 0 || size > NFS3_FHSIZE)
		return false;
	p = xdr_inline_decode(xdr, size);
	if (!p)
		return false;
	fh_init(fhp, NFS3_FHSIZE);
	fhp->fh_handle.fh_size = size;
	memcpy(&fhp->fh_handle.fh_raw, p, size);

	return true;
}

/**
 * svcxdr_encode_nfsstat3 - Encode an NFSv3 status code
 * @xdr: XDR stream
 * @status: status value to encode
 *
 * Return values:
 *   %false: Send buffer space was exhausted
 *   %true: Success
 */
bool
svcxdr_encode_nfsstat3(struct xdr_stream *xdr, __be32 status)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, sizeof(status));
	if (!p)
		return false;
	*p = status;

	return true;
}

static bool
svcxdr_encode_nfs_fh3(struct xdr_stream *xdr, const struct svc_fh *fhp)
{
	u32 size = fhp->fh_handle.fh_size;
	__be32 *p;

	p = xdr_reserve_space(xdr, XDR_UNIT + size);
	if (!p)
		return false;
	*p++ = cpu_to_be32(size);
	if (size)
		p[XDR_QUADLEN(size) - 1] = 0;
	memcpy(p, &fhp->fh_handle.fh_raw, size);

	return true;
}

static bool
svcxdr_encode_post_op_fh3(struct xdr_stream *xdr, const struct svc_fh *fhp)
{
	if (xdr_stream_encode_item_present(xdr) < 0)
		return false;
	if (!svcxdr_encode_nfs_fh3(xdr, fhp))
		return false;

	return true;
}

static bool
svcxdr_encode_cookieverf3(struct xdr_stream *xdr, const __be32 *verf)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, NFS3_COOKIEVERFSIZE);
	if (!p)
		return false;
	memcpy(p, verf, NFS3_COOKIEVERFSIZE);

	return true;
}

static bool
svcxdr_encode_fattr3(struct svc_rqst *rqstp, struct xdr_stream *xdr,
		     const struct svc_fh *fhp, const struct kstat *stat)
{
	struct user_namespace *userns = nfsd_user_namespace(rqstp);
	__be32 *p;
	u64 fsid;

	p = xdr_reserve_space(xdr, XDR_UNIT * 21);
	if (!p)
		return false;

	*p++ = cpu_to_be32(nfs3_ftypes[(stat->mode & S_IFMT) >> 12]);
	*p++ = cpu_to_be32((u32)(stat->mode & S_IALLUGO));
	*p++ = cpu_to_be32((u32)stat->nlink);
	*p++ = cpu_to_be32((u32)from_kuid_munged(userns, stat->uid));
	*p++ = cpu_to_be32((u32)from_kgid_munged(userns, stat->gid));
	if (S_ISLNK(stat->mode) && stat->size > NFS3_MAXPATHLEN)
		p = xdr_encode_hyper(p, (u64)NFS3_MAXPATHLEN);
	else
		p = xdr_encode_hyper(p, (u64)stat->size);

	/* used */
	p = xdr_encode_hyper(p, ((u64)stat->blocks) << 9);

	/* rdev */
	*p++ = cpu_to_be32((u32)MAJOR(stat->rdev));
	*p++ = cpu_to_be32((u32)MINOR(stat->rdev));

	switch(fsid_source(fhp)) {
	case FSIDSOURCE_FSID:
		fsid = (u64)fhp->fh_export->ex_fsid;
		break;
	case FSIDSOURCE_UUID:
		fsid = ((u64 *)fhp->fh_export->ex_uuid)[0];
		fsid ^= ((u64 *)fhp->fh_export->ex_uuid)[1];
		break;
	default:
		fsid = (u64)huge_encode_dev(fhp->fh_dentry->d_sb->s_dev);
	}
	p = xdr_encode_hyper(p, fsid);

	/* fileid */
	p = xdr_encode_hyper(p, stat->ino);

	p = encode_nfstime3(p, &stat->atime);
	p = encode_nfstime3(p, &stat->mtime);
	encode_nfstime3(p, &stat->ctime);

	return true;
}

/**
 * svcxdr_encode_post_op_attr - Encode NFSv3 post-op attributes
 * @rqstp: Context of a completed RPC transaction
 * @xdr: XDR stream
 * @fhp: File handle to encode
 *
 * Return values:
 *   %false: Send buffer space was exhausted
 *   %true: Success
 */
bool
svcxdr_encode_post_op_attr(struct svc_rqst *rqstp, struct xdr_stream *xdr,
			   const struct svc_fh *fhp)
{
	struct dentry *dentry = fhp->fh_dentry;
	struct kstat stat;

	/*
	 * The inode may be NULL if the call failed because of a
	 * stale file handle. In this case, no attributes are
	 * returned.
	 */
	if (fhp->fh_no_wcc || !dentry || !d_really_is_positive(dentry))
		goto no_post_op_attrs;
	if (fh_getattr(fhp, &stat) != nfs_ok)
		goto no_post_op_attrs;

	if (xdr_stream_encode_item_present(xdr) < 0)
		return false;
	lease_get_mtime(d_inode(dentry), &stat.mtime);
	if (!svcxdr_encode_fattr3(rqstp, xdr, fhp, &stat))
		return false;

	return true;

no_post_op_attrs:
	return xdr_stream_encode_item_absent(xdr) > 0;
}

/*
 * XDR encode functions
 */

/*
 * READDIR reply entry list (RFC 1813).  The entry list is the
 * value-follows form of "entry3 *entries": each entry prefixed by
 * TRUE, the sequence closed by FALSE.  xdrgen's aggregate codec owns
 * that framing; the hooks below stream one entry at a time straight
 * from the directory into the live reply, mirroring
 * nfsd4_encode_dirlist4.  The directory was opened in
 * nfsd3_proc_readdir(), so reading and encoding happen together here
 * during reply encoding.
 */

/**
 * nfs3_dirlist3_encode_begin - size the streaming entry budget
 * @c: aggregate cursor for the entry list
 *
 * Derive the entry byte budget from the space left in the live reply
 * and the client's count hint, reserving room for the list terminator
 * and the eof flag that follow the entries.
 *
 * Return: true.
 */
bool nfs3_dirlist3_encode_begin(struct xdrgen_aggregate_cursor *c)
{
	struct svc_rqst *rqstp = c->ctx;
	struct nfsd3_readdirres *resp = rqstp->rq_resp;
	struct xdr_stream *xdr = c->xdr;
	int bytes_left;

	/* Reserve the terminator FALSE and the eof bool (two words). */
	bytes_left = xdr->buf->buflen - xdr->buf->len - XDR_UNIT * 2;
	if (bytes_left < 0)
		bytes_left = 0;
	resp->space_left = min_t(u32, bytes_left,
				 clamp(resp->count, (u32)(XDR_UNIT * 2),
				       (u32)svc_max_payload(rqstp)) -
				 XDR_UNIT * 2);
	resp->cookie_offset = 0;
	return true;
}

/**
 * nfs3_dirlist3_encode - stream the next READDIR entry
 * @c: aggregate cursor for the entry list
 * @out: OUT: entry the framing encodes when one is produced
 *
 * Back-patch the previous entry's placeholder cookie with this entry's
 * resume offset, then, if the reply budget allows, project the next
 * directory entry into @out for the generated per-entry encoder.
 *
 * Return: true when @out holds an entry to encode; false to end the
 * list -- because the directory is exhausted, a host error struck, or
 * the reply budget filled.  On budget exhaustion the previous entry's
 * cookie already points at the rejected entry, the client's resume
 * point.
 */
bool nfs3_dirlist3_encode(struct xdrgen_aggregate_cursor *c,
			  struct entry3 *out)
{
	struct svc_rqst *rqstp = c->ctx;
	struct nfsd3_readdirres *resp = rqstp->rq_resp;
	struct xdr_stream *xdr = c->xdr;
	struct buffered_dirent *de;
	int namlen;
	u32 need;

	/*
	 * The previous entry was just encoded; commit the stream and note
	 * its cookie slot -- the entry's last two XDR words -- so it can be
	 * back-patched once this entry's resume offset is known.
	 */
	if (c->index) {
		xdr_commit_encode(xdr);
		resp->cookie_offset = xdr->buf->len - XDR_UNIT * 2;
	}

	de = nfsd_readdir_next(&resp->iter);
	if (!de)
		return false;

	/* The previous entry's cookie is this entry's resume offset. */
	nfs3svc_encode_cookie3(xdr, resp->cookie_offset, de->offset);

	namlen = min_t(int, de->namlen, NFS3_MAXNAMLEN);

	/* value-follows + fileid + name (length + data) + cookie */
	need = XDR_UNIT * (6 + XDR_QUADLEN(namlen));
	if (need > resp->space_left)
		return false;
	resp->space_left -= need;

	out->fileid = de->ino;
	out->name.len = namlen;
	out->name.data = (unsigned char *)de->name;
	out->cookie = 0;	/* back-patched later */

	trace_nfsd_dirent(resp->iter.fhp, de->ino, de->name, namlen);
	return true;
}

/*
 * The xdr_stream primitives do not advance rq_next_page, and svcrdma
 * retains only the pages below it for Send completion. The eof word that
 * follows the entry list starts a new page when this one is full.
 */
static void nfs3svc_update_next_page(struct svc_rqst *rqstp,
				     struct xdr_stream *xdr)
{
	rqstp->rq_next_page = xdr->page_ptr + 1;
	if (xdr->p == xdr->end)
		rqstp->rq_next_page++;
}

/**
 * nfs3_dirlist3_encode_end - finish the streamed entry list
 * @c: aggregate cursor for the entry list
 * @ok: false if the framing hit a wire error while encoding the list
 *
 * Back-patch the final entry's cookie with the directory's resume
 * offset and report eof.  A list cut short by the reply budget or a
 * host error reports eof false, so the client reads the rest with a
 * follow-up request.
 *
 * Return: true.
 */
bool nfs3_dirlist3_encode_end(struct xdrgen_aggregate_cursor *c, bool ok)
{
	struct svc_rqst *rqstp = c->ctx;
	struct nfsd3_readdirres *resp = rqstp->rq_resp;
	struct xdr_stream *xdr = c->xdr;

	if (ok)
		nfs3svc_encode_cookie3(xdr, resp->cookie_offset,
				       resp->iter.offset);
	resp->xdrgen.u.resok.reply.eof = resp->iter.eof;
	nfs3svc_update_next_page(rqstp, xdr);
	return true;
}

bool
nfs3svc_encode_readdirplusres(struct svc_rqst *rqstp, struct xdr_stream *xdr)
{
	struct nfsd3_readdirplusres *resp = rqstp->rq_resp;
	struct xdr_buf *dirlist = &resp->dirlist;

	if (!svcxdr_encode_nfsstat3(xdr, resp->status))
		return false;
	switch (resp->status) {
	case nfs_ok:
		if (!svcxdr_encode_post_op_attr(rqstp, xdr, &resp->fh))
			return false;
		if (!svcxdr_encode_cookieverf3(xdr, resp->verf))
			return false;
		svcxdr_encode_opaque_pages(rqstp, xdr, dirlist->pages, 0,
					   dirlist->len);
		/* no more entries */
		if (xdr_stream_encode_item_absent(xdr) < 0)
			return false;
		if (xdr_stream_encode_bool(xdr, resp->common.err == nfserr_eof) < 0)
			return false;
		break;
	default:
		if (!svcxdr_encode_post_op_attr(rqstp, xdr, &resp->fh))
			return false;
	}

	return true;
}

static __be32
compose_entry_fh(struct nfsd3_readdirplusres *cd, struct svc_fh *fhp,
		 const char *name, int namlen, u64 ino)
{
	struct svc_export	*exp;
	struct dentry		*dparent, *dchild;
	__be32 rv = nfserr_noent;

	dparent = cd->fh.fh_dentry;
	exp  = cd->fh.fh_export;

	if (name_is_dot_dotdot(name, namlen)) {
		if (namlen == 2) {
			dchild = dget_parent(dparent);
			/*
			 * Don't return filehandle for ".." if we're at
			 * the filesystem or export root:
			 */
			if (dchild == dparent)
				goto out;
			if (dparent == exp->ex_path.dentry)
				goto out;
		} else
			dchild = dget(dparent);
	} else
		dchild = lookup_one_positive_unlocked(&nop_mnt_idmap,
						      &QSTR_LEN(name, namlen),
						      dparent);
	if (IS_ERR(dchild))
		return rv;
	if (d_mountpoint(dchild))
		goto out;
	if (dchild->d_inode->i_ino != ino)
		goto out;
	rv = fh_compose(fhp, exp, dchild, &cd->fh);
out:
	dput(dchild);
	return rv;
}

/**
 * nfs3svc_encode_cookie3 - Encode a directory cookie
 * @xdr: stream into which to encode the cookie
 * @pos: byte position in the stream
 * @cookie: cookie to be encoded
 *
 * The buffer space for the offset cookie has already been reserved
 * by nfs3_dirlist3_encode() or nfs3svc_encode_entryplus3().
 */
void nfs3svc_encode_cookie3(struct xdr_stream *xdr, unsigned int pos,
			    u64 cookie)
{
	__be64 wire_cookie = cpu_to_be64(cookie);

	if (!pos)
		return;
	write_bytes_to_xdr_buf(xdr->buf, pos, &wire_cookie, XDR_UNIT * 2);
}

static bool
svcxdr_encode_entry3_plus(struct nfsd3_readdirplusres *resp, const char *name,
			  int namlen, u64 ino)
{
	struct xdr_stream *xdr = &resp->xdr;
	struct svc_fh *fhp = &resp->scratch;
	bool result;

	result = false;
	fh_init(fhp, NFS3_FHSIZE);
	if (compose_entry_fh(resp, fhp, name, namlen, ino) != nfs_ok)
		goto out_noattrs;

	if (!svcxdr_encode_post_op_attr(resp->rqstp, xdr, fhp))
		goto out;
	if (!svcxdr_encode_post_op_fh3(xdr, fhp))
		goto out;
	result = true;

out:
	fh_put(fhp);
	return result;

out_noattrs:
	if (xdr_stream_encode_item_absent(xdr) < 0)
		return false;
	if (xdr_stream_encode_item_absent(xdr) < 0)
		return false;
	return true;
}

/**
 * nfs3svc_encode_entryplus3 - encode one NFSv3 READDIRPLUS entry
 * @data: directory context
 * @name: name of the object to be encoded
 * @namlen: length of that name, in bytes
 * @offset: the offset of the previous entry
 * @ino: the fileid of this entry
 * @d_type: unused
 *
 * Return values:
 *   %0: Entry was successfully encoded.
 *   %-EINVAL: An encoding problem occurred, secondary status code in resp->common.err
 *
 * On exit, the following fields are updated:
 *   - resp->xdr
 *   - resp->common.err
 *   - resp->cookie_offset
 */
int nfs3svc_encode_entryplus3(void *data, const char *name, int namlen,
			      loff_t offset, u64 ino, unsigned int d_type)
{
	struct readdir_cd *ccd = data;
	struct nfsd3_readdirplusres *resp =
		container_of(ccd, struct nfsd3_readdirplusres, common);
	unsigned int starting_length = resp->dirlist.len;
	struct xdr_stream *xdr = &resp->xdr;

	/* The offset cookie for the previous entry */
	nfs3svc_encode_cookie3(xdr, resp->cookie_offset, offset);

	if (xdr_stream_encode_item_present(xdr) < 0)
		goto out_toosmall;
	/* fileid */
	if (xdr_stream_encode_u64(xdr, ino) < 0)
		goto out_toosmall;
	/* name */
	if (xdr_stream_encode_opaque(xdr, name, min(namlen, NFS3_MAXNAMLEN)) < 0)
		goto out_toosmall;
	/* cookie */
	resp->cookie_offset = resp->dirlist.len;
	if (xdr_stream_encode_u64(xdr, OFFSET_MAX) < 0)
		goto out_toosmall;

	if (!svcxdr_encode_entry3_plus(resp, name, namlen, ino))
		goto out_toosmall;

	xdr_commit_encode(xdr);
	resp->common.err = nfs_ok;
	return 0;

out_toosmall:
	resp->cookie_offset = 0;
	resp->common.err = nfserr_toosmall;
	resp->dirlist.len = starting_length;
	return -EINVAL;
}

/*
 * XDR release functions
 */
void
nfs3svc_release_fhandle(struct svc_rqst *rqstp)
{
	struct nfsd3_attrstat *resp = rqstp->rq_resp;

	fh_put(&resp->fh);
}

void
nfs3svc_release_readdirres(struct svc_rqst *rqstp)
{
	struct nfsd3_readdirres *resp = rqstp->rq_resp;
	struct READDIR3args_wrapper *argp = rqstp->rq_argp;

	/* argp->fh is zeroed by pc_argzero when argument decoding fails */
	nfsd_readdir_close(&resp->iter);
	fh_put(&argp->fh);
}
