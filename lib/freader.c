// SPDX-License-Identifier: GPL-2.0

#include <linux/freader.h>
#include <linux/cache.h>
#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/secretmem.h>

void freader_init_from_file(struct freader *r, void *buf, u32 buf_sz,
			    struct file *file, bool may_fault)
{
	memset(r, 0, sizeof(*r));
	r->buf = buf;
	r->buf_sz = buf_sz;
	r->file = file;
	r->may_fault = may_fault;
}

void freader_init_from_mem(struct freader *r, const char *data, u64 data_sz)
{
	memset(r, 0, sizeof(*r));
	r->data = data;
	r->data_sz = data_sz;
}

static void freader_put_folio(struct freader *r)
{
	if (!r->folio)
		return;
	kunmap_local(r->addr);
	folio_put(r->folio);
	r->folio = NULL;
}

static int freader_get_folio(struct freader *r, loff_t file_off)
{
	/* check if we can just reuse current folio */
	if (r->folio && file_off >= r->folio_off &&
	    file_off < r->folio_off + folio_size(r->folio))
		return 0;

	freader_put_folio(r);

	/* reject secretmem folios created with memfd_secret() */
	if (secretmem_mapping(r->file->f_mapping))
		return -EFAULT;

	r->folio = filemap_get_folio(r->file->f_mapping, file_off >> PAGE_SHIFT);

	/* if sleeping is allowed, wait for the page, if necessary */
	if (r->may_fault && (IS_ERR(r->folio) || !folio_test_uptodate(r->folio))) {
		filemap_invalidate_lock_shared(r->file->f_mapping);
		r->folio = read_cache_folio(r->file->f_mapping, file_off >> PAGE_SHIFT,
					    NULL, r->file);
		filemap_invalidate_unlock_shared(r->file->f_mapping);
	}

	if (IS_ERR(r->folio) || !folio_test_uptodate(r->folio)) {
		if (!IS_ERR(r->folio))
			folio_put(r->folio);
		r->folio = NULL;
		return -EFAULT;
	}

	r->folio_off = folio_pos(r->folio);
	r->addr = kmap_local_folio(r->folio, 0);

	return 0;
}

const void *freader_fetch(struct freader *r, loff_t file_off, size_t sz)
{
	size_t folio_sz;

	/* provided internal temporary buffer should be sized correctly */
	if (WARN_ON(r->buf && sz > r->buf_sz)) {
		r->err = -E2BIG;
		return NULL;
	}

	if (unlikely(file_off + sz < file_off)) {
		r->err = -EOVERFLOW;
		return NULL;
	}

	/* working with memory buffer is much more straightforward */
	if (!r->buf) {
		if (file_off + sz > r->data_sz) {
			r->err = -ERANGE;
			return NULL;
		}
		return r->data + file_off;
	}

	/* fetch or reuse folio for given file offset */
	r->err = freader_get_folio(r, file_off);
	if (r->err)
		return NULL;

	/* if requested data is crossing folio boundaries, we have to copy
	 * everything into our local buffer to keep a simple linear memory
	 * access interface
	 */
	folio_sz = folio_size(r->folio);
	if (file_off + sz > r->folio_off + folio_sz) {
		int part_sz = r->folio_off + folio_sz - file_off;
		size_t dst_off = 0, src_off = file_off - r->folio_off;

		do {
			memcpy(r->buf + dst_off, r->addr + src_off, part_sz);
			sz -= part_sz;
			if (sz == 0)
				break;
			/* fetch next folio */
			r->err = freader_get_folio(r, r->folio_off + folio_sz);
			if (r->err)
				return NULL;
			folio_sz = folio_size(r->folio);
			src_off = 0; /* read from the beginning, starting second folio */
			dst_off += part_sz;
			part_sz = min_t(u64, sz, folio_sz);
		} while (sz);

		return r->buf;
	}

	/* if data fits in a single folio, just return direct pointer */
	return r->addr + (file_off - r->folio_off);
}

void freader_cleanup(struct freader *r)
{
	if (!r->buf)
		return; /* non-file-backed mode */

	freader_put_folio(r);
}
