// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mmap.c
 *
 * Code to deal with the mess that is clustered mmap.
 *
 * Copyright (C) 2002, 2004 Oracle.  All rights reserved.
 */

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/uio.h>
#include <linux/signal.h>
#include <linux/rbtree.h>
#include <linux/dax.h>

#include <cluster/masklog.h>

#include "ocfs2.h"

#include "aops.h"
#include "dlmglue.h"
#include "file.h"
#include "inode.h"
#include "mmap.h"
#include "super.h"
#include "ocfs2_trace.h"


static vm_fault_t ocfs2_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	sigset_t oldset;
	vm_fault_t ret;

	ocfs2_block_signals(&oldset);
	ret = filemap_fault(vmf);
	ocfs2_unblock_signals(&oldset);

	trace_ocfs2_fault(OCFS2_I(vma->vm_file->f_mapping->host)->ip_blkno,
			  vma, vmf->page, vmf->pgoff);
	return ret;
}

static vm_fault_t __ocfs2_page_mkwrite(struct file *file,
			struct buffer_head *di_bh, struct page *page)
{
	int err;
	vm_fault_t ret = VM_FAULT_NOPAGE;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	loff_t pos = page_offset(page);
	unsigned int len = PAGE_SIZE;
	pgoff_t last_index;
	struct page *locked_page = NULL;
	void *fsdata;
	loff_t size = i_size_read(inode);

	last_index = (size - 1) >> PAGE_SHIFT;

	/*
	 * There are cases that lead to the page no longer belonging to the
	 * mapping.
	 * 1) pagecache truncates locally due to memory pressure.
	 * 2) pagecache truncates when another is taking EX lock against 
	 * inode lock. see ocfs2_data_convert_worker.
	 * 
	 * The i_size check doesn't catch the case where nodes truncated and
	 * then re-extended the file. We'll re-check the page mapping after
	 * taking the page lock inside of ocfs2_write_begin_nolock().
	 *
	 * Let VM retry with these cases.
	 */
	if ((page->mapping != inode->i_mapping) ||
	    (!PageUptodate(page)) ||
	    (page_offset(page) >= size))
		goto out;

	/*
	 * Call ocfs2_write_begin() and ocfs2_write_end() to take
	 * advantage of the allocation code there. We pass a write
	 * length of the whole page (chopped to i_size) to make sure
	 * the whole thing is allocated.
	 *
	 * Since we know the page is up to date, we don't have to
	 * worry about ocfs2_write_begin() skipping some buffer reads
	 * because the "write" would invalidate their data.
	 */
	if (page->index == last_index)
		len = ((size - 1) & ~PAGE_MASK) + 1;

	err = ocfs2_write_begin_nolock(mapping, pos, len, OCFS2_WRITE_MMAP,
				       &locked_page, &fsdata, di_bh, page);
	if (err) {
		if (err != -ENOSPC)
			mlog_errno(err);
		ret = vmf_error(err);
		goto out;
	}

	if (!locked_page) {
		ret = VM_FAULT_NOPAGE;
		goto out;
	}
	err = ocfs2_write_end_nolock(mapping, pos, len, len, fsdata);
	BUG_ON(err != len);
	ret = VM_FAULT_LOCKED;
out:
	return ret;
}

static vm_fault_t ocfs2_page_mkwrite(struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct buffer_head *di_bh = NULL;
	sigset_t oldset;
	int err;
	vm_fault_t ret;

	sb_start_pagefault(inode->i_sb);
	ocfs2_block_signals(&oldset);

	/*
	 * The cluster locks taken will block a truncate from another
	 * node. Taking the data lock will also ensure that we don't
	 * attempt page truncation as part of a downconvert.
	 */
	err = ocfs2_inode_lock(inode, &di_bh, 1);
	if (err < 0) {
		mlog_errno(err);
		ret = vmf_error(err);
		goto out;
	}

	/*
	 * The alloc sem should be enough to serialize with
	 * ocfs2_truncate_file() changing i_size as well as any thread
	 * modifying the inode btree.
	 */
	down_write(&OCFS2_I(inode)->ip_alloc_sem);

	ret = __ocfs2_page_mkwrite(vmf->vma->vm_file, di_bh, page);

	up_write(&OCFS2_I(inode)->ip_alloc_sem);

	brelse(di_bh);
	ocfs2_inode_unlock(inode, 1);

out:
	ocfs2_unblock_signals(&oldset);
	sb_end_pagefault(inode->i_sb);
	return ret;
}

#ifdef CONFIG_FS_DAX
static vm_fault_t ocfs2_dax_huge_fault(struct vm_fault *vmf,
				       unsigned int order)
{
	int error = 0;
	vm_fault_t result;
	int retries = 0;
	handle_t *handle = NULL;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;

	/*
	 * We have to distinguish real writes from writes which will result in a
	 * COW page; COW writes should *not* poke the journal (the file will not
	 * be changed). Doing so would cause unintended failures when mounted
	 * read-only.
	 *
	 * We check for VM_SHARED rather than vmf->cow_page since the latter is
	 * unset for order != 0 (i.e. only in do_cow_fault); for
	 * other sizes, dax_iomap_fault will handle splitting / fallback so that
	 * we eventually come back with a COW page.
	 */
	bool write = (vmf->flags & FAULT_FLAG_WRITE) &&
		(vmf->vma->vm_flags & VM_SHARED);
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	pfn_t pfn;
#ifdef NOT_YET
	if (write) {
		sb_start_pagefault(sb);
		file_update_time(vmf->vma->vm_file);
		filemap_invalidate_lock_shared(mapping);
retry:
		handle = ext4_journal_start_sb(sb, EXT4_HT_WRITE_PAGE,
					       EXT4_DATA_TRANS_BLOCKS(sb));
		if (IS_ERR(handle)) {
			filemap_invalidate_unlock_shared(mapping);
			sb_end_pagefault(sb);
			return VM_FAULT_SIGBUS;
		}
	} else {
		filemap_invalidate_lock_shared(mapping);
	}
#endif
	result = dax_iomap_fault(vmf, order, &pfn, &error, &ocfs2_iomap_ops);
	if (write) {
#ifdef NOT_YET
		ext4_journal_stop(handle);

		if ((result & VM_FAULT_ERROR) && error == -ENOSPC &&
		    ext4_should_retry_alloc(sb, &retries))
			goto retry;
#endif
		/* Handling synchronous page fault? */
		if (result & VM_FAULT_NEEDDSYNC)
			result = dax_finish_sync_fault(vmf, order, pfn);
		filemap_invalidate_unlock_shared(mapping);
		sb_end_pagefault(sb);
	} else {
		filemap_invalidate_unlock_shared(mapping);
	}

	return result;
}

static vm_fault_t ocfs2_dax_fault(struct vm_fault *vmf)
{
	return ocfs2_dax_huge_fault(vmf, 0);
}

static const struct vm_operations_struct ocfs2_dax_vm_ops = {
	.fault		= ocfs2_dax_fault,
	.huge_fault	= ocfs2_dax_huge_fault,
	.page_mkwrite	= ocfs2_dax_fault,
	.pfn_mkwrite	= ocfs2_dax_fault,
};
#else
#define ocfs2_dax_vm_ops ocfs2_file_vm_ops
#endif

static const struct vm_operations_struct ocfs2_file_vm_ops = {
	.fault		= ocfs2_fault,
	.page_mkwrite	= ocfs2_page_mkwrite,
};

int ocfs2_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret = 0, lock_level = 0;
	struct inode *inode = file->f_mapping->host;
	struct ocfs2_super *osb = OCFS2_SB(inode->i_sb);
	struct dax_device *dax_dev = osb->s_daxdev;

	if (!daxdev_mapping_supported(vma, dax_dev))
		return -EOPNOTSUPP;

	ret = ocfs2_inode_lock_atime(file_inode(file),
				    file->f_path.mnt, &lock_level, 1);
	if (ret < 0) {
		mlog_errno(ret);
		goto out;
	}
	ocfs2_inode_unlock(file_inode(file), lock_level);
out:
	if (IS_DAX(file_inode(file))) {
		vma->vm_ops = &ocfs2_dax_vm_ops;
		vm_flags_set(vma, VM_HUGEPAGE);
	} else {
		vma->vm_ops = &ocfs2_file_vm_ops;
	}
	return 0;
}

