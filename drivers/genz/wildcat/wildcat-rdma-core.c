/*
 * Copyright (C) 2017-2019 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/genz.h>

#include "wildcat.h"
#include "wildcat-rdma.h"

const char wildcat_rdma_driver_name[] = DRIVER_NAME;

static union zpages            *global_shared_zpage;
struct zhpe_global_shared_data *global_shared_data;

static DECLARE_WAIT_QUEUE_HEAD(poll_wqh);

static inline void _put_file_data(const char *callf, uint line,
                                  struct file_data *fdata)
{
	int                 count;

	if (fdata) {
		count = atomic_dec_return(&fdata->count);
		pr_debug("%s,%u:fdata 0x%px count %d\n",
			 callf, line, fdata, count);
		if (!count && fdata->free)
			fdata->free(callf, line, fdata);
	}
}

#define put_file_data(...) \
    _put_file_data(__func__, __LINE__, __VA_ARGS__)

static inline struct file_data *_get_file_data(const char *callf, uint line,
                                               struct file_data *fdata)
{
	int                 count;

	if (!fdata)
		return NULL;

	count = atomic_inc_return(&fdata->count);
	/* Override unused variable warning. */
	(void)count;
	pr_debug("%s,%u:%s:fdata 0x%px count %d\n",
		 callf, line, __func__, fdata, count);

	return fdata;
}

#define get_file_data(...) \
	_get_file_data(__func__, __LINE__, __VA_ARGS__)

static inline void _put_io_entry(const char *callf, uint line,
                                 struct io_entry *entry)
{
	int                 count;

	if (entry) {
		count = atomic_dec_return(&entry->count);
		pr_debug("entry 0x%px count %d\n", entry, count);
		if (!count && entry->free)
			entry->free(callf, line, entry);
	}
}

#define put_io_entry(...) \
	_put_io_entry(__func__, __LINE__, __VA_ARGS__)

static inline struct io_entry *_get_io_entry(const char *callf, uint line,
                                             struct io_entry *entry)
{
	int                 count;

	if (!entry)
		return NULL;

	count = atomic_inc_return(&entry->count);
	/* Override unused variable warning. */
	(void)count;
	pr_debug("%s,%u:entry 0x%px count %d\n", callf, line, entry, count);

	return entry;
}

#define get_io_entry(...) \
	_get_io_entry(__func__, __LINE__, __VA_ARGS__)

static void _free_io_lists(const char *callf, uint line,
                           struct file_data *fdata)
{
	struct io_entry     *next;
	struct io_entry     *entry;
	int i = 0;

	pr_debug("fdata 0x%px\n", fdata);

	list_for_each_entry_safe(entry, next, &fdata->rd_list, list) {
		pr_debug("%s,%u:i %d entry 0x%px idx 0x%04x\n",
			 callf, line, i, entry, entry->op.hdr.index);
		list_del_init(&entry->list);
		put_io_entry(entry);
		i++;
	}
}

#define free_io_lists(...) \
	_free_io_lists(__func__, __LINE__, __VA_ARGS__)


static inline void queue_io_entry_locked(struct file_data *fdata,
                                         struct list_head *head,
                                         struct io_entry *entry)
{
	bool                wake = list_empty(head);

	list_add_tail(&entry->list, head);
	spin_unlock(&fdata->io_lock);
	wake_up(&fdata->io_wqh);
	if (wake)
		wake_up_all(&poll_wqh);
}

static inline int queue_io_entry(struct file_data *fdata,
                                 struct list_head *head,
                                 struct io_entry *entry)
{
	int                 ret = 0;

	spin_lock(&fdata->io_lock);
	if (fdata->state & STATE_CLOSED) {
		ret = -EIO;
		spin_unlock(&fdata->io_lock);
	} else
		queue_io_entry_locked(fdata, head, entry);

	return ret;
}

static void io_free(const char *callf, uint line, void *ptr)
{
	struct io_entry     *entry = ptr;

	_put_file_data(callf, line, entry->fdata);
	_do_kfree(callf, line, entry);
}

static inline struct io_entry *_io_alloc(
	const char *callf, uint line, size_t size, bool nonblock,
	struct file_data *fdata,
	void (*free)(const char *callf, uint line, void *ptr))
{
	struct io_entry     *ret = NULL;

	if (size < sizeof(ret->op))
		size = sizeof(ret->op);
	size += sizeof(*ret);
	ret = do_kmalloc(size, (nonblock ? GFP_ATOMIC : GFP_KERNEL), false);
	if (!ret)
		goto done;

	ret->free = free;
	atomic_set(&ret->count, 1);
	ret->nonblock = nonblock;
	ret->fdata = get_file_data(fdata);
	INIT_LIST_HEAD(&ret->list);

done:

	return ret;
}

#define io_alloc(...) \
    _io_alloc(__func__, __LINE__, __VA_ARGS__)


int queue_io_rsp(struct io_entry *entry, size_t data_len, int status)
{
	int                 ret = 0;
	struct file_data    *fdata = entry->fdata;
	struct wildcat_hdr *op_hdr = &entry->op.hdr;

	op_hdr->version = WILDCAT_OP_VERSION;
	op_hdr->opcode = entry->hdr.opcode | WILDCAT_OP_RESPONSE;
	op_hdr->index = entry->hdr.index;
	op_hdr->status = status;
	if (!data_len)
		data_len = sizeof(*op_hdr);
	entry->data_len = data_len;

	if (fdata)
		ret = queue_io_entry(fdata, &fdata->rd_list, entry);

	return ret;
}

void _zmap_free(const char *callf, uint line, struct zmap *zmap)
{
	if (!zmap)
		return;

	pr_debug("zmap 0x%px offset 0x%lx\n", zmap, zmap->offset);

	if (zmap->zpages)
		zpages_free(zmap->zpages);
	do_kfree(zmap);
}

struct zmap *_zmap_alloc(
	const char *callf,
	uint line,
	struct file_data *fdata,
	union zpages *zpages)
{
	struct zmap         *ret;
	struct zmap         *cur;
	ulong               coff;
	size_t              size;

	pr_debug("zpages 0x%px\n", zpages);
	ret = _do_kmalloc(callf, line, sizeof(*ret), GFP_KERNEL, true);
	if (!ret) {
		ret = ERR_PTR(-ENOMEM);
		goto done;
	}

	INIT_LIST_HEAD(&ret->list);
	ret->zpages = zpages;
	/* Set bad owner to keep entry from being used until ready. */
	ret->owner = ZMAP_BAD_OWNER;
	/*
	 * Look for a hole in betwen entries; allow space for unmapped pages
	 * between entries.
	 */
	size = zpages->hdr.size + PAGE_SIZE;
	coff = 0;
	spin_lock(&fdata->zmap_lock);
	list_for_each_entry(cur, &fdata->zmap_list, list) {
		if (cur->offset - coff >= size)
			break;
		coff = cur->offset + cur->zpages->hdr.size;
	}
	/*
	 * cur will either point to a real entry before which we want to insert
	 * ret or &cur->list == head and we want to add ourselves at the tail.
	 *
	 * Can we wrap around in real life? Probably not.
	 */
	if (coff < coff + size) {
		ret->offset = coff;
		if (coff)
			ret->offset += PAGE_SIZE;
		list_add_tail(&ret->list, &cur->list);
	}
	spin_unlock(&fdata->zmap_lock);
	if (list_empty(&ret->list)) {
		_zmap_free(callf, line, ret);
		pr_err("%s,%u:Out of file space.\n", __func__, __LINE__);
		ret = ERR_PTR(-ENOSPC);
		goto done;
	}

done:
	return ret;
}

bool _free_zmap_list(const char *callf, uint line,
		     struct file_data *fdata)
{
	bool                ret = true;
	struct zmap         *zmap;
	struct zmap         *next;

	pr_debug("fdata 0x%px\n", fdata);

	spin_lock(&fdata->zmap_lock);
	list_for_each_entry_safe(zmap, next, &fdata->zmap_list, list) {
		/* global_shared_zmap zpages are not free'ed until exit */
		if (zmap == fdata->global_shared_zmap) {
			list_del_init(&zmap->list);
			do_kfree(zmap);
		} else if (!fdata || zmap->owner == fdata ||
			   zmap == fdata->local_shared_zmap) {
			list_del_init(&zmap->list);
			zmap_free(zmap);
		}
	}
	spin_unlock(&fdata->zmap_lock);
	return ret;
}

static void file_data_free(const char *callf, uint line, void *ptr)
{
	_do_kfree(callf, line, ptr);
}

static int wildcat_rdma_user_req_INIT(struct io_entry *entry)
{
	union wildcat_rsp      *rsp = &entry->op.rsp;
	struct file_data    *fdata = entry->fdata;
	struct uuid_tracker *uu;
	uint32_t            ro_rkey, rw_rkey;
	int                 status = 0;
	ulong               flags;
	char                str[UUID_STRING_LEN+1];

	rsp->init.global_shared_offset = fdata->global_shared_zmap->offset;
	rsp->init.global_shared_size =
		fdata->global_shared_zmap->zpages->hdr.size;
	rsp->init.local_shared_offset = fdata->local_shared_zmap->offset;
	rsp->init.local_shared_size =
		fdata->local_shared_zmap->zpages->hdr.size;

	zhpe_generate_uuid(fdata->md.bridge, &rsp->init.uuid);
	uu = zhpe_uuid_tracker_alloc_and_insert(&rsp->init.uuid, UUID_TYPE_LOCAL,
						0, &fdata->md, GFP_KERNEL, &status);
	if (!uu)
		goto out;

	status = zhpe_rkey_alloc(&ro_rkey, &rw_rkey);
	if (status < 0) {
		zhpe_uuid_remove(uu);
		goto out;
	}

	spin_lock(&fdata->io_lock);
	if (fdata->state & STATE_INIT) {  /* another INIT */
		status = -EBADRQC;
		spin_unlock(&fdata->io_lock);
		zhpe_rkey_free(ro_rkey, rw_rkey);
		zhpe_uuid_remove(uu);
		goto out;
	}
	fdata->state |= STATE_INIT;
	fdata->md.ro_rkey = ro_rkey;
	fdata->md.rw_rkey = rw_rkey;
	spin_unlock(&fdata->io_lock);

	spin_lock_irqsave(&fdata->md.uuid_lock, flags);
	fdata->md.local_uuid = uu;
	spin_unlock_irqrestore(&fdata->md.uuid_lock, flags);

out:
	debug(DEBUG_IO, "%s:%s,%u:ret = %d uuid = %s, ro_rkey=0x%08x, rw_rkey=0x%08x\n",
	      zhpe_driver_name, __func__, __LINE__, status,
	      zhpe_uuid_str(&rsp->init.uuid, str, sizeof(str)), ro_rkey, rw_rkey);
	return queue_io_rsp(entry, sizeof(rsp->init), status);
}

static int alloc_map_shared_data(struct file_data *fdata)
{
	int                 ret = 0;
	int                 i;
	struct wildcat_local_shared_data *local_shared_data;

	fdata->local_shared_zpage =
		shared_zpage_alloc(sizeof(*local_shared_data),
				   LOCAL_SHARED_PAGE);
	if (!fdata->local_shared_zpage) {
		pr_debug("queue_zpages_alloc failed.\n");
		ret = -ENOMEM;
		goto done;
	}
	/* Add shared data to the zmap_list */
	fdata->local_shared_zmap = zmap_alloc(fdata, fdata->local_shared_zpage);
	if (IS_ERR(fdata->local_shared_zmap)) {
		pr_debug("zmap_alloc failed\n");
		ret = PTR_ERR(fdata->local_shared_zmap);
		fdata->local_shared_zmap = NULL;
		goto err_zpage_free;
	}
	/* Initialize the counters to 0 */
	local_shared_data = (struct wildcat_local_shared_data *)
		fdata->local_shared_zpage->queue.pages[0];
	local_shared_data->magic = WILDCAT_MAGIC;
	local_shared_data->version = WILDCAT_LOCAL_SHARED_VERSION;
	for (i = 0; i < MAX_IRQ_VECTORS; i++)
		local_shared_data->handled_counter[i] = 0;

	fdata->local_shared_zmap->owner = NULL;
	smp_wmb();

	/* Map the global shared page for this process's address space. */
	fdata->global_shared_zmap = zmap_alloc(fdata, global_shared_zpage);
	if (IS_ERR(fdata->global_shared_zmap)) {
		pr_debug("zmap_alloc failed\n");
		ret = PTR_ERR(fdata->global_shared_zmap);
		fdata->global_shared_zmap = NULL;
		goto err_zpage_free;
	}

	fdata->global_shared_zmap->owner = NULL;
	smp_wmb();
	goto done;

err_zpage_free:
	if (fdata->local_shared_zpage) {
		queue_zpages_free(fdata->local_shared_zpage);
		do_kfree(fdata->local_shared_zpage);
	}
done:
	return ret;
}

static int wildcat_rdma_open(struct inode *inode, struct file *file)
{
	int                 ret = -ENOMEM;
	struct file_data    *fdata = NULL;
	size_t              size;

	size = sizeof(*fdata);
	fdata = do_kmalloc(size, GFP_KERNEL, true);
	if (!fdata)
		goto done;

	fdata->pid = task_pid_nr(current); /* Associate this fdata with pid */
	fdata->free = file_data_free;
	atomic_set(&fdata->count, 1);
	spin_lock_init(&fdata->io_lock);
	init_waitqueue_head(&fdata->io_wqh);
	INIT_LIST_HEAD(&fdata->rd_list);
	wildcat_init_mem_data(&fdata->md, &wildcat_bridge);  /* Revisit MultiBridge: support multiple bridges */
	INIT_LIST_HEAD(&fdata->zmap_list);
	spin_lock_init(&fdata->zmap_lock);
	spin_lock_init(&fdata->xdm_queue_lock);
	/* xdm_queues tracks what queues are owned by this file_data */
	/* Revisit Perf: what is the tradeoff of size of bitmap vs. rbtree? */
	bitmap_zero(fdata->xdm_queues, XDM_QUEUES_PER_SLICE*SLICES);
	spin_lock_init(&fdata->rdm_queue_lock);
	bitmap_zero(fdata->rdm_queues, RDM_QUEUES_PER_SLICE*SLICES);
	/* we only allow one open per pid */
	if (wildcat_pid_to_fdata(fdata->md.bridge, fdata->pid)) {
		ret = -EBUSY;
		goto done;
	}
	/* Allocate and map the local shared data page. Map the global page. */
	ret = alloc_map_shared_data(fdata);
	if (ret != 0) {
		pr_debug("alloc_map_shared_data:failed with ret = %d\n", ret);
		goto done;
	}
	ret = wildcat_pasid_alloc(&fdata->pasid);
	if (ret < 0)
		goto free_shared_data;
	/* Bind the task to the PASID on the device, if there is an IOMMU. */
	ret = wildcat_bind_iommu(fdata);
	if (ret < 0)
		goto free_pasid;

	/* Add this fdata to the bridge's fdata_list */
	spin_lock(&fdata->md.bridge->fdata_lock);
	list_add(&fdata->fdata_list, &fdata->md.bridge->fdata_list);
	spin_unlock(&fdata->md.bridge->fdata_lock);
	ret = 0;
	goto done;

free_pasid:
	wildcat_pasid_free(fdata->pasid);

free_shared_data:
	zmap_free(fdata->local_shared_zmap);
	zmap_free(fdata->global_shared_zmap);

done:
	if (ret < 0 && fdata) {
		put_file_data(fdata);
		fdata = NULL;
	}
	file->private_data = fdata;

	pr_debug("ret = %d, pid = %d, pasid = %u\n",
		 ret, task_pid_vnr(current), (fdata) ? fdata->pasid : 0);

	return ret;
}

static int wildcat_rdma_release(struct inode *inode, struct file *file)
{
	struct file_data    *fdata = file->private_data;
	ulong               flags;

	spin_lock(&fdata->io_lock);
	fdata->state &= ~STATE_INIT;
	fdata->state |= STATE_CLOSED;
	spin_unlock(&fdata->io_lock);
	zhpe_release_owned_xdm_queues(fdata);
	zhpe_release_owned_rdm_queues(fdata);
	free_zmap_list(fdata);
	free_io_lists(fdata);
	zhpe_rmr_free_all(&fdata->md);
	zhpe_notify_remote_uuids(&fdata->md);
	zhpe_umem_free_all(&fdata->md, &fdata->humongous_zmmu_rsp_pte);
	zhpe_free_remote_uuids(&fdata->md);
	spin_lock_irqsave(&fdata->md.uuid_lock, flags);
	(void)zhpe_free_local_uuid(&fdata->md, true); /* also frees associated R-keys */
	spin_unlock_irqrestore(&fdata->md.uuid_lock, flags);
	zhpe_unbind_iommu(fdata);
	zhpe_pasid_free(fdata->pasid);
	spin_lock(&fdata->md.bridge->fdata_lock);
	list_del(&fdata->fdata_list);
	if (fdata == helper_fdata)
		helper_fdata = NULL;
	spin_unlock(&fdata->md.bridge->fdata_lock);
	put_file_data(fdata);

	pr_debug("ret = %d pid = %d\n", 0, task_pid_vnr(current));
	return 0;
}

static ssize_t wildcat_rdma_read(struct file *file, char __user *buf,
				 size_t len, loff_t *ppos)
{
	ssize_t             ret = 0;
	struct file_data    *fdata = file->private_data;
	struct io_entry     *entry;

	if (!len)
		goto done;

	/*
	 * Weird semantics: read must be big enough to read entire packet
	 * at once; if not, return -EINVAL;
	 */
	for (;;) {
		entry = NULL;
		spin_lock(&fdata->io_lock);
		if (!list_empty(&fdata->rd_list)) {
			entry = list_first_entry(&fdata->rd_list,
						 struct io_entry, list);
			if (len >= entry->data_len) {
				list_del_init(&entry->list);
				len = entry->data_len;
			} else {
				pr_debug("len %ld entry->data_len %ld\n",
					 len, entry->data_len);
				ret = -EINVAL;
			}
		}
		spin_unlock(&fdata->io_lock);
		if (ret < 0)
			goto done;
		if (entry)
			break;
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto done;
		}
		ret = wait_event_interruptible(fdata->io_wqh,
					       !list_empty(&fdata->rd_list));
		if (ret < 0)
			goto done;
	}
	ret = copy_to_user(buf, entry->data, len);
	put_io_entry(entry);

done:
	if (ret /* != -EAGAIN */)
		pr_debug("ret = %ld len = %ld pid = %d\n",
			 ret, len, task_pid_vnr(current));

	return (ret < 0 ? ret : len);
}

static ssize_t wildcat_rdma_write(struct file *file, const char __user *buf,
				  size_t len, loff_t *ppos)
{
	ssize_t             ret = 0;
	struct file_data    *fdata = file->private_data;
	bool                nonblock = !!(file->f_flags & O_NONBLOCK);
	struct io_entry     *entry = NULL;
	struct wildcat_hdr  *op_hdr;
	size_t              op_len;

	if (!len)
		goto done;

	/*
	 * Weird semantics: requires write be a packet containing a single
	 * request.
	 */
	if (len < sizeof(*op_hdr)) {
		ret = -EINVAL;
		pr_err("%s:%s,%u:Unexpected short write %lu\n",
		       wildcat_rdma_driver_name, __func__, __LINE__, len);
		goto done;
	}

	entry = io_alloc(0, nonblock, fdata, io_free);
	if (!entry) {
		ret = (nonblock ? -EAGAIN : -ENOMEM);
		goto done;
	}
	op_hdr = &entry->op.hdr;

	op_len = sizeof(union wildcat_req);
	if (op_len > len)
		op_len = len;
	ret = copy_from_user(op_hdr, buf, op_len);
	if (ret < 0)
		goto done;
	entry->hdr = *op_hdr;

	ret = -EINVAL;
	if (!expected_saw("version", WILDCAT_OP_VERSION, op_hdr->version))
		goto done;

#define USER_REQ_HANDLER(_op)					  \
	case WILDCAT_OP_ ## _op:				  \
		pr_debug("WILDCAT_OP_" # _op);			  \
		op_len = sizeof(struct wildcat_rdma_req_ ## _op); \
		if (len != op_len)				  \
			goto done;				  \
		ret = wildcat_rdma_user_req_ ## _op(entry);	  \
		break;

	switch (op_hdr->opcode) {
		USER_REQ_HANDLER(INIT);
		USER_REQ_HANDLER(MR_REG);
		USER_REQ_HANDLER(MR_FREE);
		USER_REQ_HANDLER(QALLOC);
		USER_REQ_HANDLER(QFREE);
		USER_REQ_HANDLER(RMR_IMPORT);
		USER_REQ_HANDLER(RMR_FREE);
		USER_REQ_HANDLER(ZMMU_REG);
		USER_REQ_HANDLER(ZMMU_FREE);
		USER_REQ_HANDLER(UUID_IMPORT);
		USER_REQ_HANDLER(UUID_FREE);
		USER_REQ_HANDLER(XQALLOC);
		USER_REQ_HANDLER(XQFREE);
		USER_REQ_HANDLER(RQALLOC);
		USER_REQ_HANDLER(RQFREE);
	default:
		pr_err("%s:%s,%u:Unexpected opcode 0x%02x\n",
		       wildcat_rdma_driver_name, __func__, __LINE__,
		       op_hdr->opcode);
		ret = -EIO;
		break;
	}

#undef USER_REQ_HANDLER

	/*
	 * If handler accepts op, it is no longer our responsibility to free
	 * the entry.
	 */
	if (ret >= 0)
		entry = NULL;

done:
	put_io_entry(entry);
	if (ret != -EAGAIN)
		pr_debug("ret = %ld len = %ld pid = %d\n",
			 ret, len, task_pid_vnr(current));

	return (ret < 0 ? ret : len);
}

static uint wildcat_rdma_poll(struct file *file, struct poll_table_struct *wait)
{
	uint                ret = 0;
	struct file_data    *fdata = file->private_data;

	poll_wait(file, &poll_wqh, wait);
	ret |= (list_empty(&fdata->rd_list) ? 0 : POLLIN | POLLRDNORM);

	return ret;
}

static int wildcat_rdma_mmap(struct file *file, struct vm_area_struct *vma)
{
	int                 ret = -ENOENT;
	struct file_data    *fdata = file->private_data;
	struct zmap         *zmap;
	union zpages        *zpages;
	struct zhpe_rmr     *rmr;
	ulong               vaddr, offset, length, i, pgoff;
	uint32_t            cache_flags;

	vma->vm_flags |= VM_MIXEDMAP | VM_DONTCOPY;
	vma->vm_private_data = NULL;

	offset = vma->vm_pgoff << PAGE_SHIFT;
	length = vma->vm_end - vma->vm_start;
	pr_debug("vm_start=0x%lx, vm_end=0x%lx, offset=0x%lx\n",
		 vma->vm_start, vma->vm_end, offset);
	spin_lock(&fdata->zmap_lock);
	list_for_each_entry(zmap, &fdata->zmap_list, list) {
		if (offset == zmap->offset &&
		    length == zmap->zpages->hdr.size) {
			if (!zmap->owner || zmap->owner == fdata)
				ret = 0;
			break;
		}
	}
	spin_unlock(&fdata->zmap_lock);
	if (ret < 0) {
		pr_debug("ret < 0 - zmap not found in zmap_list\n");
		goto done;
	}
	if (!(vma->vm_flags & VM_SHARED)) {
		pr_err("%s:%s,%u:vm_flags !VM_SHARED\n",
		       wildcat_rdma_driver_name, __func__, __LINE__);
		goto done;
	}
	if (vma->vm_flags & VM_EXEC) {
		pr_err("%s:%s,%u:vm_flags VM_EXEC\n",
		       wildcat_rdma_driver_name, __func__, __LINE__);
		goto done;
	}
	vma->vm_flags &= ~VM_MAYEXEC;
	if (zmap == fdata->local_shared_zmap) {
		if (vma->vm_flags & VM_WRITE) {
			pr_err("%s:%s,%u:vm_flags VM_WRITE\n",
			       wildcat_rdma_driver_name, __func__, __LINE__);
		}
		vma->vm_flags &= ~VM_MAYWRITE;
	}

	zpages = zmap->zpages;
	vma->vm_private_data = zmap;

	switch (zpages->hdr.page_type) {
	case LOCAL_SHARED_PAGE:
	case GLOBAL_SHARED_PAGE:
		for (vaddr = vma->vm_start, i = 0; vaddr < vma->vm_end;
		     vaddr += PAGE_SIZE, i++) {
			ret = vm_insert_page(vma, vaddr,
					     virt_to_page(zpages->queue.pages[i]));
			if (ret < 0) {
				pr_err("%s:%s,%u:vm_insert_page() ret=%d\n",
				       wildcat_rmda_driver_name, __func__,
				       __LINE__, ret);
				goto done;
			}
		}
		ret = 0;
		break;
	case DMA_PAGE:
		/* temporarily zero vm_pgoff so dma_mmap_coherent does what we want */
		pgoff = vma->vm_pgoff;
		vma->vm_pgoff = 0;
		ret = dma_mmap_coherent(zpages->dma.dev, vma,
					zpages->dma.cpu_addr,
					zpages->dma.dma_addr,
					length);
		vma->vm_pgoff = pgoff;
		if (ret < 0) {
			pr_err("%s:%s,%u:dma_mmap_coherent() returned %d\n",
			       wildcat_rdma_driver_name, __func__, __LINE__, ret);
			goto done; /* BUG to break */
		}
		break;
	case HSR_PAGE:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		ret = io_remap_pfn_range(vma, vma->vm_start,
					 zpages->hsr.base_addr >> PAGE_SHIFT,
					 length,
					 vma->vm_page_prot);
		if (ret) {
			pr_err("%s:%s,%u:HSR io_remap_pfn_range failed\n",
			       wildcat_rdma_driver_name, __func__, __LINE__);
			goto done;
		}
		break;
	case RMR_PAGE:
		rmr = zpages->rmrz.rmr;
		cache_flags = rmr->pte_info->access & WILDCAT_MR_REQ_CPU_CACHE;
		switch (cache_flags) {
			/* WILDCAT_MR_REQ_CPU_WB is the default, so nothing to do */
		case WILDCAT_MR_REQ_CPU_WC:
			vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
			break;
		case WILDCAT_MR_REQ_CPU_WT:
			vma->vm_page_prot = pgprot_writethrough(vma->vm_page_prot);
			break;
		case WILDCAT_MR_REQ_CPU_UC:
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
			break;
		}
		if (!rmr->writable) {
			vma->vm_flags &= ~(VM_WRITE | VM_MAYWRITE);
			vma_set_page_prot(vma);
		}
		pr_debug("RMR mmap_pfn=0x%lx, vm_page_prot=0x%lx\n",
			 zpages->rmrz.rmr->mmap_pfn,
			 pgprot_val(vma->vm_page_prot));
		ret = io_remap_pfn_range(vma, vma->vm_start,
					 zpages->rmrz.rmr->mmap_pfn,
					 length, vma->vm_page_prot);
		if (ret) {
			pr_err("%s:%s,%u:RMR io_remap_pfn_range returned %d\n",
			       wildcat_rdma_driver_name, __func__, __LINE__, ret);
			goto done;
		}
		break;
	}

done:
	if (ret < 0) {
		if (vma->vm_private_data) {
			vma->vm_private_data = NULL;
		}
		pr_err("%s:%s,%u:ret = %d:start 0x%lx end 0x%lx off 0x%lx\n",
		       wildcat_rdma_driver_name, __func__, __LINE__, ret,
		       vma->vm_start, vma->vm_end, vma->vm_pgoff);
	}

	return ret;
}

static const struct file_operations wildcat_rdma_fops = {
	.owner              =       THIS_MODULE,
	.open               =       wildcat_rdma_open,
	.release            =       wildcat_rdma_release,
	.read               =       wildcat_rdma_read,
	.write              =       wildcat_rdma_write,
	.poll               =       wildcat_rdma_poll,
	.mmap               =       wildcat_rdma_mmap,
	/* Revisit: implement get_unmapped_area to enforce pg_ps alignment */
	.llseek             =       no_llseek,
};

static struct miscdevice miscdev = {
	.name               = wildcat_rdma_driver_name,
	.fops               = &wildcat_rdma_fops,
	.minor              = MISC_DYNAMIC_MINOR,
	.mode               = 0666,
};

static int __init wildcat_rdma_init(void)
{
	int                 ret;

	/* Create device. */
	pr_debug("creating device\n");
	ret = misc_register(&miscdev);
	if (ret < 0) {
		printk(KERN_WARNING "%s:%s:misc_register() returned %d\n",
		       wildcat_rdma_driver_name, __func__, ret);
		goto err_pci_unregister_driver;
	}
}
