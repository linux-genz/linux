/*
 * Copyright (C) 2017-2020 Hewlett Packard Enterprise Development LP.
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
#include <linux/cdev.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/mm.h>
#include <linux/genz.h>

#include "wildcat.h"
#include "wildcat-rdma.h"

const char wildcat_rdma_driver_name[] = DRIVER_NAME;

static union zpages            *global_shared_zpage;
struct wildcat_global_shared_data *global_shared_data;

static DECLARE_WAIT_QUEUE_HEAD(poll_wqh);

static int __init wildcat_rdma_init(void);
static void wildcat_rdma_exit(void);

module_init(wildcat_rdma_init);
module_exit(wildcat_rdma_exit);

MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(drivers/genz/genz);
MODULE_IMPORT_NS(drivers/genz/wildcat/wildcat);

static struct genz_device_id wildcat_rdma_id_table[] = {
	{ .uuid_str = "0ee8c862-7713-43d5-b973-60eb7fd93334" },
	{ },
};

MODULE_DEVICE_TABLE(genz, wildcat_rdma_id_table);

static bool _expected_saw(const char *callf, uint line,
			  const char *label, uintptr_t expected, uintptr_t saw)
{
	if (expected == saw)
		return true;

	pr_err("%s,%u:%s:%s:expected 0x%lx saw 0x%lx\n",
	       callf, line, __func__, label, expected, saw);

	return false;
}

#define expected_saw(...) \
	_expected_saw(__func__, __LINE__, __VA_ARGS__)

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
	kfree(entry);
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
	ret = kmalloc(size, (nonblock ? GFP_ATOMIC : GFP_KERNEL));
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
	struct wildcat_rdma_hdr *op_hdr = &entry->op.hdr;

	op_hdr->version = WILDCAT_RDMA_OP_VERSION;
	op_hdr->opcode = entry->hdr.opcode | WILDCAT_RDMA_OP_RESPONSE;
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
		wildcat_zpages_free(zmap->zpages);
	kfree(zmap);
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
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
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
			kfree(zmap);
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
	kfree(ptr);
}

static struct file_data *pid_to_fdata(struct wildcat_rdma_state *rstate,
				      pid_t pid)
{
	struct file_data *cur, *ret = NULL;

	spin_lock(&rstate->fdata_lock);
	list_for_each_entry(cur, &rstate->fdata_list, fdata_list) {
		if (cur->pid == pid) {
			ret = cur;
			break;
		}
	}
	spin_unlock(&rstate->fdata_lock);
	return ret;
}

static int wildcat_rdma_user_req_INIT(struct io_entry *entry)
{
	union wildcat_rdma_rsp *rsp = &entry->op.rsp;
	struct file_data       *fdata = entry->fdata;
	struct uuid_tracker    *uu;
	uint32_t               ro_rkey, rw_rkey;
	int                    status = 0;
	ulong                  flags;

	rsp->init.global_shared_offset = fdata->global_shared_zmap->offset;
	rsp->init.global_shared_size =
		fdata->global_shared_zmap->zpages->hdr.size;
	rsp->init.local_shared_offset = fdata->local_shared_zmap->offset;
	rsp->init.local_shared_size =
		fdata->local_shared_zmap->zpages->hdr.size;

	genz_generate_uuid(fdata->md.bridge, &rsp->init.uuid);
	uu = genz_uuid_tracker_alloc_and_insert(
		&rsp->init.uuid, UUID_TYPE_LOCAL,
		0, &fdata->md, GFP_KERNEL, &status);
	if (!uu)
		goto out;

	status = genz_rkey_alloc(&ro_rkey, &rw_rkey);
	if (status < 0) {
		genz_uuid_remove(uu);
		goto out;
	}

	spin_lock(&fdata->io_lock);
	if (fdata->state & STATE_INIT) {  /* another INIT */
		status = -EBADRQC;
		spin_unlock(&fdata->io_lock);
		genz_rkey_free(ro_rkey, rw_rkey);
		genz_uuid_remove(uu);
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
	pr_debug("ret=%d, uuid=%pUb, ro_rkey=0x%08x, rw_rkey=0x%08x\n",
		 status, &rsp->init.uuid, ro_rkey, rw_rkey);
	return queue_io_rsp(entry, sizeof(rsp->init), status);
}

static int alloc_map_shared_data(struct file_data *fdata)
{
	int                 ret = 0;
	int                 i;
	struct wildcat_local_shared_data *local_shared_data;

	fdata->local_shared_zpage =
		wildcat_shared_zpage_alloc(sizeof(*local_shared_data),
					   LOCAL_SHARED_PAGE);
	if (!fdata->local_shared_zpage) {
		pr_debug("local shared page alloc failed.\n");
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
		wildcat_queue_zpages_free(fdata->local_shared_zpage);
		kfree(fdata->local_shared_zpage);
	}
done:
	return ret;
}

static int wildcat_rdma_xqueue_free(
	struct file_data               *fdata,
	struct wildcat_rdma_req_XQFREE *free_req)
{
	int              slice = free_req->info.slice;
	int              queue = free_req->info.queue;
	int              ret;
	struct bridge    *br = wildcat_gzbr_to_br(fdata->md.bridge);

	spin_lock(&fdata->xdm_queue_lock);
	if (test_bit((slice*XDM_QUEUES_PER_SLICE) + queue,
					fdata->xdm_queues) == 0 ) {
		pr_debug("Cannot free un-owned queue %d on slice %d\n",
			 queue, slice);
		ret = -1;
		goto unlock;
	}
	/* Release ownership of the queue from this file_data */
	clear_bit((slice*XDM_QUEUES_PER_SLICE) + queue, fdata->xdm_queues);

	ret = wildcat_xqueue_free(br, slice, queue);

 unlock:
	spin_unlock(&fdata->xdm_queue_lock);
	return ret;
}

static int dma_alloc_zpage_and_zmap(
	struct slice *sl,
	size_t q_size,
	struct file_data *fdata,
	union zpages **ret_zpage,
	struct zmap **ret_zmap)
{
	int ret = 0;

	ret = wildcat_dma_alloc_zpage(sl, q_size, ret_zpage);
	if (ret) {
		pr_debug("wildcat_dma_alloc_zpage failed\n");
		return ret;
	}
	if (ret_zmap) {  /* allocating and returning zmap is optional */
		*ret_zmap = zmap_alloc(fdata, *ret_zpage);
		if (IS_ERR(*ret_zmap)) {
			pr_debug("zmap_alloc failed\n");
			ret = PTR_ERR(*ret_zmap);
			wildcat_zpages_free(*ret_zpage);
		}
	}
	return ret;
}

#define POLL_DEV_NAME	"wildcat_rdma_poll"
static dev_t wildcat_rdma_poll_dev;
static struct cdev *poll_cdev;
static struct class *poll_class;
static int wildcat_rdma_poll_dev_major;
LIST_HEAD(rstate_list);

static struct slice *wildcat_rdma_irq_index_to_slice(struct file_data *fdata,
					      int irq_index)
{
	struct bridge *br = wildcat_gzbr_to_br(fdata->md.bridge);
	int           slice_id;

	slice_id = irq_index / VECTORS_PER_SLICE;
	return (&br->slice[slice_id]);
}

static struct wildcat_rdma_state *irq_index_to_rstate(int irq_index)
{
	struct wildcat_rdma_state *rstate;

	/* Revisit: locking */
	list_for_each_entry(rstate, &rstate_list, rstate_node) {
		if (irq_index >= rstate->min_irq_index &&
		    irq_index <= rstate->max_irq_index)
			goto out;
	}

	rstate = NULL;

out:
	return rstate;
}

static int wildcat_rdma_poll_open(struct inode *inode, struct file *file)
{
	struct file_data *fdata;
	pid_t  pid = task_pid_nr(current);
	struct slice *sl;
	int irq_index = iminor(inode);
	struct wildcat_rdma_state *rstate = irq_index_to_rstate(irq_index);
	struct list_head *pos;
	struct rdm_vector_list *entry;
	int found_queue = 0;
	int vector;

	/* Find the fdata associated with this open's pid */
	fdata = pid_to_fdata(rstate, pid);
	if (fdata == NULL) {
		pr_debug("Failed to match poll open pid (%d) to fdata pid\n",
			 pid);
		return -ENOENT;
	}

	/* check that this pid owns an rqueue in this irq_index */
	sl = wildcat_rdma_irq_index_to_slice(fdata, irq_index);
	vector = irq_index % VECTORS_PER_SLICE; /* per slice vector */
	pr_debug("slice=%d, irq_index=%d, vector=%d\n",
		 sl->id, irq_index, vector);
	list_for_each(pos, &(sl->irq_vectors[vector])) {
		entry = list_entry(pos, struct rdm_vector_list, list);
		pr_debug("entry->irq_index=%d\n", entry->irq_index);
		if (entry->irq_index == irq_index) {
			found_queue = 1;
			break;
		}
	}
	if (!found_queue) {
		pr_debug("trying to open a file without owning a queue on that vector %d\n",
			 vector);
		return -ENXIO;
	}
	file->private_data = fdata;
	return 0;
}

static int wildcat_rdma_poll_close(struct inode *inode, struct file *file)
{
	return 0;
}

static unsigned int wildcat_rdma_poll_poll(struct file *file,
					   struct poll_table_struct *wait)
{
	struct file_data *fdata = file->private_data;
	int irq_index = iminor(file_inode(file));
	int handled, triggered;
	struct wildcat_local_shared_data *local_shared_data;
	struct wildcat_rdma_state *rstate;

	if (fdata == NULL) {
		pr_debug("fdata is NULL\n");
		return 0;
	}

	rstate = fdata->rstate;
	poll_wait(file, &(rstate->rdma_poll_wq[irq_index]), wait);

	/* Compare trigggered to handled */
	local_shared_data = (struct wildcat_local_shared_data *)
		fdata->local_shared_zpage->queue.pages[0];
	handled = READ_ONCE(local_shared_data->handled_counter[irq_index]);
	triggered = READ_ONCE(global_shared_data->triggered_counter[irq_index]);

	if (triggered != handled)
		return (POLLIN | POLLRDNORM);
	return 0;
}

int wildcat_rdma_poll_devices_create(struct wildcat_rdma_state *rstate)
{
	struct device *dev;
	int minor, err = 0;

	for (minor = rstate->min_irq_index;
	     minor <= rstate->max_irq_index; minor++) {
		pr_debug("device create for /dev/wildcat_rdma_poll_%d class=%px, major=%d, minor=%d\n",
			 minor, poll_class, wildcat_rdma_poll_dev_major, minor);

		dev = device_create(poll_class, NULL,
				    MKDEV(wildcat_rdma_poll_dev_major, minor),
				    rstate, "wildcat_rdma_poll_%d", minor);
		if (IS_ERR(dev)) {
			err = PTR_ERR(dev);
			pr_debug("device_create failed with %d\n", err);
			goto destroy_devices;
		}
	}

	return 0;

 destroy_devices:
	for (; minor >= rstate->min_irq_index; minor--) {
		device_destroy(poll_class,
			       MKDEV(wildcat_rdma_poll_dev_major, minor));
	}
	return err;
}

static int __match_devt(struct device *dev, const void *data)
{
	const dev_t *devt = data;

	return dev->devt == *devt;
}

void wildcat_rdma_poll_devices_destroy(struct wildcat_rdma_state *rstate)
{
	int minor;
	struct device *dev;
	dev_t poll_devt;

	if (rstate == NULL)
		return;
	for (minor = rstate->min_irq_index;
	     minor <= rstate->max_irq_index; minor++) {
		poll_devt = MKDEV(wildcat_rdma_poll_dev_major, minor);
		dev = class_find_device(poll_class, NULL, &poll_devt,
					__match_devt);
		pr_debug("device destroy for /dev/wildcat_rdma_poll_%d class=%px, major=%d, minor=%d\n",
			 minor, poll_class, wildcat_rdma_poll_dev_major, minor);
		device_destroy(poll_class,
			       MKDEV(wildcat_rdma_poll_dev_major, minor));
	}
	return;
}

void wildcat_rdma_poll_init_waitqueues(struct wildcat_rdma_state *rstate)
{
	int i;

	/* Initialize wait queues for each poll device */
	for (i = 0; i < MAX_IRQ_VECTORS; i++) {
		init_waitqueue_head(&(rstate->rdma_poll_wq[i]));
	}
}

static char *poll_devnode(struct device *dev, umode_t *mode)
{
	if (!mode)
		return NULL;
	*mode = 0666;
	return NULL;
}

static const struct file_operations wildcat_rdma_poll_fops = {
	.owner      = THIS_MODULE,
	.open       = wildcat_rdma_poll_open,
	.release    = wildcat_rdma_poll_close,
	.poll       = wildcat_rdma_poll_poll,
};

int wildcat_rdma_setup_poll_devs(void)
{
	int ret = -1;

	ret = alloc_chrdev_region(&wildcat_rdma_poll_dev, 0, MAX_IRQ_VECTORS,
				  POLL_DEV_NAME);
	if (ret != 0) {
		pr_debug("alloc_chrdev_region failed, ret=%d\n", ret);
		return ret;
	}

	wildcat_rdma_poll_dev_major = MAJOR(wildcat_rdma_poll_dev);
	pr_debug("wildcat_rdma_poll_dev_major=%d\n",
		 wildcat_rdma_poll_dev_major);
	poll_class = class_create(THIS_MODULE, POLL_DEV_NAME);
	if (IS_ERR(poll_class)) {
		pr_debug("class_create failed\n");
		goto unreg_region;
	}
	poll_class->devnode = poll_devnode;
	pr_debug("poll_class=%px\n", poll_class);
	poll_cdev = cdev_alloc();
	if (poll_cdev == NULL) {
		pr_debug("cdev_alloc failed\n");
		goto destroy_class;
	}
	cdev_init(poll_cdev, &wildcat_rdma_poll_fops);

	ret = cdev_add(poll_cdev, wildcat_rdma_poll_dev, MAX_IRQ_VECTORS);
	if (ret < 0) {
		pr_debug("cdev_add failed, ret=%d\n", ret);
		goto del_cdev;
	}

	ret = 0;
	goto done;

del_cdev:
	cdev_del(poll_cdev);

destroy_class:
	class_destroy(poll_class);

unreg_region:
	unregister_chrdev_region(wildcat_rdma_poll_dev, MAX_IRQ_VECTORS);

done:
	return ret;
}

void wildcat_rdma_cleanup_poll_devs(void)
{
	cdev_del(poll_cdev);
	class_destroy(poll_class);
	unregister_chrdev_region(wildcat_rdma_poll_dev, MAX_IRQ_VECTORS);
}

int wildcat_rdma_trigger(int irq_index, int *triggered)
{
	/* Update the triggered count in the shared page */
	if (irq_index < 0 || irq_index >= MAX_IRQ_VECTORS) {
		pr_debug("out of range irq_index %d\n", irq_index);
		return -1;
	}

	/* Use atomic fetch and add. */
	*triggered = __sync_add_and_fetch(
		&global_shared_data->triggered_counter[irq_index], 1);

	return 0;
}

int wildcat_req_XQALLOC(
	struct wildcat_rdma_req_XQALLOC *req,
	struct wildcat_rdma_rsp_XQALLOC *rsp,
	struct file_data                *fdata)
{
	int	 		  ret;
	uint32_t                  cmdq_ent, cmplq_ent;
	struct wildcat_xdm_qcm    *hw_qcm_addr, *app_qcm_addr;
	phys_addr_t               app_qcm_physaddr;
	union zpages		  *qcm_zpage, *cmdq_zpage, *cmplq_zpage;
	struct zmap		  *qcm_zmap, *cmdq_zmap, *cmplq_zmap;
	size_t			  qcm_size = 0, cmdq_size = 0, cmplq_size = 0;
	struct slice		  *sl;
	int			  slice, queue;
	struct bridge             *br = wildcat_gzbr_to_br(fdata->md.bridge);

	pr_debug("xqalloc req cmdq_ent %d, cmplq_ent %d, traffic_class %d, priority %d, slice_mask 0x%x\n",
		 req->cmdq_ent, req->cmplq_ent, req->traffic_class,
		 req->priority, req->slice_mask);

	cmdq_ent = req->cmdq_ent;
	cmplq_ent = req->cmplq_ent;
	ret = wildcat_xdm_queue_sizes(&cmdq_ent, &cmplq_ent, &cmdq_size,
				      &cmplq_size, &qcm_size);
	if (ret)
		goto done;

	rsp->info.cmdq.ent = cmdq_ent;
	rsp->info.cmplq.ent = cmplq_ent;
	rsp->info.cmdq.size = cmdq_size;
	rsp->info.cmplq.size = cmplq_size;
	rsp->info.qcm.size = qcm_size;

	pr_debug("compute sizes cmdq_ent=%u cmdq_size=0x%lx "
		 "cmplq_ent=%u cmplq_size=0x%lx\n",
		 cmdq_ent, cmdq_size, cmplq_ent, cmplq_size);

	/* Pick which slice has a free queue based on the slice_mask */
	ret = wildcat_alloc_xqueue(br, req->slice_mask, &slice, &queue);
	rsp->hdr.status = ret;
	pr_debug("xqalloc rsp slice %d queue %d\n", slice, queue);
	if (ret) {
		pr_debug("Request for slice_mask 0x%x failed\n",
			 req->slice_mask);
		goto done;
	}
	/* set bit in this file_data as owner */
	spin_lock(&fdata->xdm_queue_lock);
	set_bit((slice*XDM_QUEUES_PER_SLICE)+queue, fdata->xdm_queues);
	spin_unlock(&fdata->xdm_queue_lock);
	rsp->info.slice = slice;
	rsp->info.queue = queue;

	/* Get a pointer to the qcm chosen to initialize it's fields */
	sl = &(br->slice[slice]);
	hw_qcm_addr = &(sl->bar->xdm[queue*2]);

	pr_debug("hw_qcm_addr for slice %d queue %d queue init 0x%px\n",
		 slice, queue, hw_qcm_addr);

	/* Allocate pages and map for qcm, cmdq, and cmplq */
	ret = -ENOMEM;
	/* Use the App Page in the zpage_alloc which is +1 from kernel page */
	// app_qcm_addr = hw_qcm_addr + 1;
	app_qcm_addr = hw_qcm_addr; /* Revisit: map kern page for debug */
	app_qcm_physaddr = sl->phys_base +
		((void *)app_qcm_addr - (void *)sl->bar);
	pr_debug("app_qcm_physaddr %pxa\n", &app_qcm_physaddr);
	qcm_zpage = wildcat_hsr_zpage_alloc(app_qcm_physaddr);
	if (!qcm_zpage) {
		pr_debug("zpage_alloc failed for qcm\n");
		goto release_queue;
	}
	qcm_zmap = zmap_alloc(fdata, qcm_zpage);
	if (IS_ERR(qcm_zmap)) {
		pr_debug("zmap_alloc failed for qcm\n");
		ret = PTR_ERR(qcm_zmap);
		qcm_zmap = NULL;
		goto free_qcm_zpage;
	}
	rsp->info.qcm.off = qcm_zmap->offset;

	ret = dma_alloc_zpage_and_zmap(sl, cmdq_size, fdata,
				       &cmdq_zpage, &cmdq_zmap);
	if (ret != 0) {
		pr_debug("dma_alloc_zpage_and_zmap failed for cmdq\n");
		goto free_qcm_zmap;
	}
	rsp->info.cmdq.off = cmdq_zmap->offset;

	ret = dma_alloc_zpage_and_zmap(sl, cmplq_size, fdata,
				       &cmplq_zpage, &cmplq_zmap);
	if (ret != 0) {
		pr_debug("dma_alloc_zpage_and_zmap failed for cmplq\n");
		goto free_cmdq_zmap;
	}
	rsp->info.cmplq.off = cmplq_zmap->offset;

	wildcat_xdm_qcm_setup(
		hw_qcm_addr,
		cmdq_zpage->dma.dma_addr, cmplq_zpage->dma.dma_addr,
		rsp->info.cmdq.ent, rsp->info.cmplq.ent,
		req->traffic_class, req->priority, 1, fdata->pasid);

	/* Set owner fields to valid value; can't fail after this. */
	qcm_zmap->owner = fdata;
	cmdq_zmap->owner = fdata;
	cmplq_zmap->owner = fdata;

	/* Make sure owner is seen before we advertise the queue anywhere. */
	smp_wmb();
	ret = 0;
	goto done;

	/* Handle errors */
 free_cmdq_zmap:
	zmap_free(cmdq_zmap);
 free_qcm_zmap:
	zmap_free(qcm_zmap);
	/* zmap_free also frees the zpage */
	goto release_queue;
 free_qcm_zpage:
	wildcat_zpages_free(qcm_zpage);
 release_queue:
	wildcat_xdm_release_slice_queue(br, slice, queue);
	spin_lock(&fdata->xdm_queue_lock);
	clear_bit((slice*XDM_QUEUES_PER_SLICE)+queue, fdata->xdm_queues);
	spin_unlock(&fdata->xdm_queue_lock);
done:
	return ret;
}

#define CHECK_INIT_STATE(_entry, _ret, _label)			\
	do {                                                    \
		spin_lock(&(_entry)->fdata->io_lock);		\
		if (!((_entry)->fdata->state & STATE_INIT)) {	\
			(_ret) = -EBADRQC;			\
			spin_unlock(&(_entry)->fdata->io_lock);	\
			goto _label;				\
		}						\
		spin_unlock(&(_entry)->fdata->io_lock);		\
	} while (0)

int wildcat_rdma_user_req_XQALLOC(struct io_entry *entry)
{
	int	 		        ret = -EINVAL;
	struct wildcat_rdma_rsp_XQALLOC	rsp;

	CHECK_INIT_STATE(entry, ret, done);

	ret = wildcat_req_XQALLOC(&entry->op.req.xqalloc, &rsp, entry->fdata);

 done:
	/* Copy the response to the req/rsp union */
	entry->op.rsp.xqalloc = rsp;
	return queue_io_rsp(entry, sizeof(rsp), ret);
}

int wildcat_req_XQFREE(union wildcat_rdma_req *req,
			union wildcat_rdma_rsp *rsp, struct file_data *fdata)
{
	int			ret = 0;
	int			count = 3;
	struct zmap		*zmap;
	struct zmap		*next;

	pr_debug("xqfree req slice %d queue %d qcm.off 0x%llx cmd.off 0x%llx cmpl.off 0x%llx\n",
		 req->xqfree.info.slice, req->xqfree.info.queue,
		 req->xqfree.info.qcm.off, req->xqfree.info.cmdq.off,
		 req->xqfree.info.cmplq.off);
	if (wildcat_rdma_xqueue_free(fdata, &req->xqfree)) {
		/* zphe_xqueue_free can fail if the queue doesn't drain. */
		ret = -EBUSY;
		goto done;
	}

	spin_lock(&fdata->zmap_lock);
	list_for_each_entry_safe(zmap, next, &fdata->zmap_list, list) {
		if (zmap->offset == req->xqfree.info.qcm.off ||
			zmap->offset == req->xqfree.info.cmdq.off ||
			zmap->offset == req->xqfree.info.cmplq.off) {
			if (zmap->owner != fdata) {
				if (ret >= 0)
					ret = -EACCES;
			} else {
				list_del_init(&zmap->list);
				zmap_free(zmap);
			}
			if (--count == 0)
				break;
		}
	}
	spin_unlock(&fdata->zmap_lock);
	if (ret >= 0 && count)
		ret = -ENOENT;

 done:
	return ret;
}

int wildcat_rdma_user_req_XQFREE(struct io_entry *entry)
{
	int			ret = 0;

	CHECK_INIT_STATE(entry, ret, done);

	ret = wildcat_req_XQFREE(&entry->op.req, &entry->op.rsp, entry->fdata);

done:
	return queue_io_rsp(entry, sizeof(&entry->op.rsp.xqfree), ret);

}

static int wildcat_rdma_rqueue_free(
	struct file_data               *fdata,
	struct wildcat_rdma_req_RQFREE *free_req)
{
	int              slice = free_req->info.slice;
	int              queue = free_req->info.queue;
	int              ret;
	struct slice     *sl;
	struct bridge    *br = wildcat_gzbr_to_br(fdata->md.bridge);

	sl = wildcat_slice_id_to_slice(br, slice);
	if (sl)
		wildcat_unregister_rdm_interrupt(sl, queue);
	spin_lock(&fdata->rdm_queue_lock);
	if (test_bit((slice*RDM_QUEUES_PER_SLICE) + queue,
		     fdata->rdm_queues) == 0 ) {
		pr_debug("Cannot free un-owned queue %d on slice %d\n",
			 queue, slice);
		ret = -1;
		goto unlock;
	}
	/* Release ownership of the queue from this file_data */
	clear_bit((slice*RDM_QUEUES_PER_SLICE) + queue, fdata->rdm_queues);

	ret = wildcat_rqueue_free(br, slice, queue);

 unlock:
	spin_unlock(&fdata->rdm_queue_lock);
	return ret;
}

irqreturn_t wildcat_rdma_rdm_interrupt_handler(int irq_index, void *data)
{
	struct wildcat_rdma_state *rstate = (struct wildcat_rdma_state *)data;
	struct genz_dev *zdev;
	int wq_index;

	if (rstate == NULL) {
		pr_debug("rstate is NULL\n");
		return IRQ_NONE;
	}

	zdev = rstate->zdev;
	if (zdev == NULL) {
		pr_debug("zdev is NULL\n");
		return IRQ_NONE;
	}

	wq_index = irq_index - rstate->min_irq_index;
	dev_dbg(&zdev->dev, "irq_index=%d, wq_index=%d\n",
		irq_index, wq_index);

	/* wake up the wait queue to process the interrupt */
	wake_up_interruptible_all(&(rstate->rdma_poll_wq[wq_index]));
	return IRQ_HANDLED;
}

int wildcat_req_RQALLOC(struct wildcat_rdma_req_RQALLOC *req,
			struct wildcat_rdma_rsp_RQALLOC *rsp,
			struct file_data *fdata)
{
	int	 		  ret = -EINVAL;
	uint32_t                  cmplq_ent;
	size_t			  qcm_size = 0, cmplq_size = 0;
	int			  slice, queue, irq_vector;
	struct wildcat_rdm_qcm    *hw_qcm_addr, *app_qcm_addr;
	phys_addr_t               app_qcm_physaddr;
	struct slice		  *sl;
	union zpages		  *qcm_zpage, *cmplq_zpage;
	struct zmap		  *qcm_zmap, *cmplq_zmap;
	struct bridge             *br = wildcat_gzbr_to_br(fdata->md.bridge);

	pr_debug("rqalloc req cmplq_ent %d, slice_mask 0x%x\n",
		 req->cmplq_ent, req->slice_mask);

	cmplq_ent = req->cmplq_ent;
	ret = wildcat_rdm_queue_sizes(&cmplq_ent, &cmplq_size, &qcm_size);
	if (ret)
		goto done;

	rsp->info.cmplq.ent = cmplq_ent;
	rsp->info.cmplq.size = cmplq_size;
	rsp->info.qcm.size = qcm_size;

	pr_debug("compute sizes cmplq_ent=%u cmplq_size=0x%lx\n",
		 cmplq_ent, cmplq_size);

	/* Pick which slice has a free queue based on the slice_mask */
	ret = wildcat_alloc_rqueue(br, req->slice_mask,
				   &slice, &queue, &irq_vector);
	rsp->hdr.status = ret;
	pr_debug("rqalloc rsp slice %d queue %d irq_vector %d\n",
		 slice, queue, irq_vector);
	if (ret) {
		pr_debug("Request for slice_mask 0x%x failed\n",
			 req->slice_mask);
		goto done;
	}
	/* set bit in this file_data as owner */
	spin_lock(&fdata->rdm_queue_lock);
	set_bit((slice*RDM_QUEUES_PER_SLICE)+queue, fdata->rdm_queues);
	spin_unlock(&fdata->rdm_queue_lock);
	rsp->info.slice = slice;
	rsp->info.queue = queue;
	rsp->info.irq_vector = irq_vector;
	rsp->info.rspctxid = wildcat_rspctxid_alloc(slice, queue);

	/* Get a pointer to the qcm chosen to initialize it's fields */
	sl = &(br->slice[slice]);
	hw_qcm_addr = &(sl->bar->rdm[queue*2]);

	pr_debug("hw_qcm_addr for slice %d queue %d queue init 0x%px\n",
		 slice, queue, hw_qcm_addr);

	/* Allocate pages and map for qcm and cmplq */
	ret = -ENOMEM;
	/* Use the App Page in the zpage_alloc which is +1 from kernel page */
	// app_qcm_addr = hw_qcm_addr + 1;
	app_qcm_addr = hw_qcm_addr; /* Revisit: map kern page for debug */
	app_qcm_physaddr = sl->phys_base +
		((void *)app_qcm_addr - (void *)sl->bar);
	pr_debug("app_qcm_physaddr %pxa\n", &app_qcm_physaddr);
	qcm_zpage = wildcat_hsr_zpage_alloc(app_qcm_physaddr);
	if (!qcm_zpage) {
		pr_debug("zpage_alloc failed for qcm\n");
		goto release_queue;
	}
	qcm_zmap = zmap_alloc(fdata, qcm_zpage);
	if (IS_ERR(qcm_zmap)) {
		pr_debug("zmap_alloc failed for qcm\n");
		ret = PTR_ERR(qcm_zmap);
		qcm_zmap = NULL;
		goto free_qcm_zpage;
	}
	rsp->info.qcm.off = qcm_zmap->offset;

	ret = dma_alloc_zpage_and_zmap(sl, cmplq_size, fdata,
				       &cmplq_zpage, &cmplq_zmap);
	if (ret != 0) {
		pr_debug("dma_alloc_zpage_and_zmap failed for cmplq\n");
		goto free_qcm_zmap;
	}
	rsp->info.cmplq.off = cmplq_zmap->offset;

	wildcat_rdm_qcm_setup(hw_qcm_addr, cmplq_zpage->dma.dma_addr,
			      rsp->info.cmplq.ent, 1, fdata->pasid);

	/* Register the rdm second level interrupt handler */
	ret = wildcat_register_rdm_interrupt(sl, queue,
			wildcat_rdma_rdm_interrupt_handler, fdata->rstate);
	if (ret != 0) {
		pr_debug("wildcat_register_rdm_interrupt failed with %d\n",
			 ret);
		goto free_cmplq_zmap;
	}

	/* Set owner fields to valid value; can't fail after this. */
	qcm_zmap->owner = fdata;
	cmplq_zmap->owner = fdata;

	/* Make sure owner is seen before we advertise the queue anywhere. */
	smp_wmb();

	ret = 0;
	goto done;

	/* Handle errors */
 free_cmplq_zmap:
	zmap_free(cmplq_zmap);
 free_qcm_zmap:
	zmap_free(qcm_zmap);
	/* zmap_free also frees the zpage */
	goto release_queue;
 free_qcm_zpage:
	wildcat_zpages_free(qcm_zpage);
 release_queue:
	wildcat_rdm_release_slice_queue(br, slice, queue);
	spin_lock(&fdata->rdm_queue_lock);
	clear_bit((slice*RDM_QUEUES_PER_SLICE)+queue, fdata->rdm_queues);
	spin_unlock(&fdata->rdm_queue_lock);
 done:
	return ret;
}

int wildcat_rdma_user_req_RQALLOC(struct io_entry *entry)
{
	int	 		  ret = -EINVAL;
	struct wildcat_rdma_req_RQALLOC	  *req = &entry->op.req.rqalloc;
	struct wildcat_rdma_rsp_RQALLOC	  rsp;

	CHECK_INIT_STATE(entry, ret, done);

	ret = wildcat_req_RQALLOC(req, &rsp, entry->fdata);

done:
	/* Copy the response to the req/rsp union */
	entry->op.rsp.rqalloc = rsp;
	return queue_io_rsp(entry, sizeof(rsp), ret);
}

int wildcat_req_RQFREE(struct wildcat_rdma_req_RQFREE *req,
			struct wildcat_rdma_rsp_RQFREE *rsp,
			struct file_data *fdata)
{
	int			ret = 0;
	struct zmap		*zmap;
	struct zmap		*next;
	int			count = 2; /* qcm and cmplq */

	pr_debug("rqfree req slice %d queue %d qcm.off 0x%llx cmpl.off 0x%llx\n",
		 req->info.slice, req->info.queue,
		 req->info.qcm.off, req->info.cmplq.off);
	if (wildcat_rdma_rqueue_free(fdata, req)) {
		/* zphe_rqueue_free can fail if the queue doesn't drain. */
		ret = -EBUSY;
		goto done;
	}

	spin_lock(&fdata->zmap_lock);
	list_for_each_entry_safe(zmap, next, &fdata->zmap_list, list) {
		if (zmap->offset == req->info.qcm.off ||
			zmap->offset == req->info.cmplq.off) {
			if (zmap->owner != fdata) {
				if (ret >= 0)
					ret = -EACCES;
			} else {
				list_del_init(&zmap->list);
				zmap_free(zmap);
			}
			if (--count == 0)
				break;
		}
	}
	spin_unlock(&fdata->zmap_lock);
	if (ret >= 0 && count)
		ret = -ENOENT;

 done:
	return ret;
}

int wildcat_rdma_user_req_RQFREE(struct io_entry *entry)
{
	int			ret = 0;
	struct wildcat_rdma_rsp_RQFREE	rsp;

	CHECK_INIT_STATE(entry, ret, done);
	ret = wildcat_req_RQFREE(&entry->op.req.rqfree, &rsp, entry->fdata);

done:
	entry->op.rsp.rqfree = rsp;
	return queue_io_rsp(entry, sizeof(rsp), ret);
}

static void release_owned_xdm_queues(struct file_data *fdata)
{
	int ret = 0;
	int bits = SLICES * XDM_QUEUES_PER_SLICE;
	int slice, queue, bit;
	struct bridge *br = wildcat_gzbr_to_br(fdata->md.bridge);

	spin_lock(&fdata->xdm_queue_lock);
	bit = find_first_bit(fdata->xdm_queues, bits);
	while (1) {
		if (bit >= bits)
			break;
		slice = bit / XDM_QUEUES_PER_SLICE;
		queue = bit % XDM_QUEUES_PER_SLICE;
		ret = wildcat_xqueue_free(br, slice, queue);
		if (ret) {
			pr_debug("failed to free queue %d on slice %d\n",
				 queue, slice);
		}
		clear_bit(bit, fdata->xdm_queues);
		bit = find_next_bit(fdata->xdm_queues, bits, bit);
	}
	spin_unlock(&fdata->xdm_queue_lock);

	return;
}

static void release_owned_rdm_queues(struct file_data *fdata)
{
	int ret = 0;
	int bits = SLICES * RDM_QUEUES_PER_SLICE;
	int slice, queue, bit;
	struct bridge *br = wildcat_gzbr_to_br(fdata->md.bridge);

	spin_lock(&fdata->rdm_queue_lock);
	bit = find_first_bit(fdata->rdm_queues, bits);
	while (1) {
		if (bit >= bits)
			break;
		slice = bit / RDM_QUEUES_PER_SLICE;
		queue = bit % RDM_QUEUES_PER_SLICE;
		ret = wildcat_rqueue_free(br, slice, queue);
		if (ret) {
			pr_debug("failed to free queue %d on slice %d\n",
				 queue, slice);
		}
		clear_bit(bit, fdata->rdm_queues);
		bit = find_next_bit(fdata->rdm_queues, bits, bit);
	}
	spin_unlock(&fdata->rdm_queue_lock);

	return;
}

static struct zmap *rmr_zmap_alloc(struct file_data *fdata,
				   struct genz_rmr *rmr)
{
	union zpages            *zpages;
	struct zmap             *zmap;

	zpages = wildcat_rmr_zpages_alloc(rmr);
	if (!zpages)
		return ERR_PTR(-ENOMEM);

	zmap = zmap_alloc(fdata, zpages);
	if (IS_ERR(zmap)) {
		wildcat_zpages_free(zpages);
		goto out;
	}

	rmr->zmap = zmap;
	zmap->owner = fdata;

 out:
	return zmap;
}

int wildcat_rdma_user_req_MR_REG(struct io_entry *entry)
{
	union wildcat_rdma_req  *req = &entry->op.req;
	union wildcat_rdma_rsp  *rsp = &entry->op.rsp;
	int                     status = 0;
	uint64_t                vaddr, len, access;
	uint64_t                rsp_zaddr = GENZ_BASE_ADDR_ERROR;
	uint32_t                pg_ps = 0;
	bool                    local, remote, cpu_visible, individual;
	struct genz_umem        *umem;
	struct file_data        *fdata = entry->fdata;
	struct genz_mem_data    *mdata = &fdata->md;
	ulong                   flags;

	CHECK_INIT_STATE(entry, status, out);
	vaddr = req->mr_reg.vaddr;
	len = req->mr_reg.len;
	access = req->mr_reg.access;
	local = !!(access & (WILDCAT_MR_GET|WILDCAT_MR_PUT));
	remote = !!(access & (WILDCAT_MR_GET_REMOTE|WILDCAT_MR_PUT_REMOTE));
	cpu_visible = !!(access & WILDCAT_MR_REQ_CPU);
	individual = !!(access & WILDCAT_MR_INDIVIDUAL);

	pr_debug("vaddr=0x%016llx, len=0x%llx, access=0x%llx, "
		 "local=%u, remote=%u, cpu_visible=%u, individual=%u\n",
		 vaddr, len, access, local, remote, cpu_visible, individual);

	if (!(local || remote) || cpu_visible) {
		status = -EINVAL;
		goto out;
	}

	if (!can_do_mlock()) {
		status = -EPERM;
		goto out;
	}

	/* pin memory range and create IOMMU entries */
	umem = genz_umem_get(mdata, vaddr, len, access, fdata->pasid,
			     mdata->ro_rkey, mdata->rw_rkey, false);
	if (IS_ERR(umem)) {
		status = PTR_ERR(umem);
		goto out;
	}

	/* create responder ZMMU entries, if necessary */
	if (remote) {
		if (individual) {
			status = genz_zmmu_rsp_pte_alloc(
				umem->pte_info, &rsp_zaddr, &pg_ps);
		} else {
			/* make sure a humongous responder ZMMU entry exists */
			status = wildcat_humongous_zmmu_rsp_pte_alloc(
				&umem->pte_info, &fdata->humongous_zmmu_rsp_pte,
				&fdata->md.md_lock, &rsp_zaddr, &pg_ps);
		}

		if (status < 0) {
			spin_lock_irqsave(&mdata->md_lock, flags);
			genz_umem_remove(umem);
			spin_unlock_irqrestore(&mdata->md_lock, flags);
			goto out;
		}
	}

	rsp->mr_reg.rsp_zaddr = rsp_zaddr;
	rsp->mr_reg.pg_ps = pg_ps;

 out:
	pr_debug("ret=%d rsp_zaddr=0x%016llx, pg_ps=%u\n",
		 status, rsp_zaddr, pg_ps);
	return queue_io_rsp(entry, sizeof(rsp->mr_reg), status);
}

int wildcat_rdma_user_req_MR_FREE(struct io_entry *entry)
{
	union wildcat_rdma_req  *req = &entry->op.req;
	union wildcat_rdma_rsp  *rsp = &entry->op.rsp;
	int                     status = 0;
	struct genz_umem        *umem;
	uint64_t                vaddr, len, access, rsp_zaddr;
	ulong                   flags;

	vaddr = req->mr_free.vaddr;
	len = req->mr_free.len;
	access = req->mr_free.access;
	rsp_zaddr = req->mr_free.rsp_zaddr;
	CHECK_INIT_STATE(entry, status, out);

	spin_lock_irqsave(&entry->fdata->md.md_lock, flags);
	umem = genz_umem_search(&entry->fdata->md, vaddr, len, access,
				rsp_zaddr);
	if (!umem) {
		status = -EINVAL;
		goto unlock;
	}
	genz_umem_remove(umem);

unlock:
	spin_unlock_irqrestore(&entry->fdata->md.md_lock, flags);
out:
	pr_debug("ret=%d, vaddr=0x%016llx, "
		 "len=0x%llx, access=0x%llx, rsp_zaddr=0x%016llx\n",
		 status, vaddr, len, access, rsp_zaddr);
	return queue_io_rsp(entry, sizeof(rsp->mr_free), status);
}

int wildcat_rdma_user_req_RMR_IMPORT(struct io_entry *entry)
{
	union wildcat_rdma_req  *req = &entry->op.req;
	union wildcat_rdma_rsp  *rsp = &entry->op.rsp;
	int                     status = 0;
	uuid_t                  *uuid = &req->rmr_import.uuid;
	struct genz_mem_data    *mdata = &entry->fdata->md;
	struct genz_rmr         *rmr;
	struct zmap             *zmap;
	struct genz_rmr_info    rmri;
	uint64_t                len, access, rsp_zaddr;
	uint32_t                dgcid;
	off_t                   offset = GENZ_BASE_ADDR_ERROR;
	bool                    remote, cpu_visible, writable, individual;
	struct genz_bridge_info *br_info = &mdata->bridge->br_info;
	uint64_t cpuvisible_offset = br_info->cpuvisible_phys_offset;

	CHECK_INIT_STATE(entry, status, out);
	rsp_zaddr = req->rmr_import.rsp_zaddr;
	len = req->rmr_import.len;
	access = req->rmr_import.access;
	remote = !!(access & (WILDCAT_MR_GET_REMOTE|WILDCAT_MR_PUT_REMOTE));
	writable = !!(access & WILDCAT_MR_PUT_REMOTE);
	cpu_visible = !!(access & WILDCAT_MR_REQ_CPU);
	individual = !!(access & WILDCAT_MR_INDIVIDUAL);

	pr_debug("uuid=%pUb, rsp_zaddr=0x%016llx, len=0x%llx, access=0x%llx, "
		 "remote=%u, writable=%u, cpu_visible=%u, individual=%u\n",
		 uuid, rsp_zaddr,
		 len, access, remote, writable, cpu_visible, individual);

	if (!remote || (wildcat_uuid_is_local(mdata->bridge, uuid) &&
			!wildcat_loopback)) {
		status = -EINVAL;  /* only remote access & UUIDs allowed */
		goto out;
	}

	/* Revisit: should there be an rlimit to prevent a user from consuming
	 * too much physical address space (RLIMIT_PAS?), similar to "max
	 * locked memory" (RLIMIT_MEMLOCK) or "max address space" (RLIMIT_AS)?
	 */
	dgcid = wildcat_gcid_from_uuid(uuid);
	rmr = genz_rmr_get(mdata, uuid, dgcid, rsp_zaddr, len, access,
			   entry->fdata->pasid, 0, &rmri);
	if (IS_ERR(rmr)) {
		status = PTR_ERR(rmr);
		if (status == -EEXIST)
			goto addr;
		else
			goto out;
	}

	/* create requester ZMMU entries, if necessary */
	if (individual) {
		status = genz_zmmu_req_pte_alloc(rmr->pte_info, &rmri);
		if (status < 0) {
			genz_rmr_remove(rmr, true);
			goto out;
		}
	} else {
		/* make sure a humongous requester ZMMU entry exists */
		; /* Revisit: finish this */
	}

	rmr->req_addr = rmri.req_addr;
	rmr->mmap_pfn = (rmr->req_addr + cpuvisible_offset) >> PAGE_SHIFT;

	if (cpu_visible) {
		zmap = rmr_zmap_alloc(entry->fdata, rmr);
		if (IS_ERR(zmap)) {
			genz_rmr_remove(rmr, true);
			status = PTR_ERR(zmap);
			goto out;
		}
		offset = zmap->offset;
	}

addr:
	rsp->rmr_import.req_addr = rmri.req_addr;
	rsp->rmr_import.offset = offset;
	rsp->rmr_import.pg_ps = rmri.pg_ps;

out:
	pr_debug("ret=%d, req_addr=0x%016llx, offset=0x%lx, pg_ps=%u\n",
		 status, rmri.req_addr, offset, rmri.pg_ps);
	return queue_io_rsp(entry, sizeof(rsp->rmr_import), status);
}

int wildcat_rdma_user_req_RMR_FREE(struct io_entry *entry)
{
	union wildcat_rdma_req  *req = &entry->op.req;
	union wildcat_rdma_rsp  *rsp = &entry->op.rsp;
	uuid_t                  *uuid = &req->rmr_free.uuid;
	struct genz_mem_data    *mdata = &entry->fdata->md;
	int                     status = 0;
	struct genz_rmr         *rmr;
	uint64_t                len, access, rsp_zaddr, req_addr;
	uint32_t                dgcid;
	ulong                   flags;

	rsp_zaddr = req->rmr_free.rsp_zaddr;
	len = req->rmr_free.len;
	access = req->rmr_free.access;
	req_addr = req->rmr_free.req_addr;
	dgcid = wildcat_gcid_from_uuid(uuid);
	CHECK_INIT_STATE(entry, status, out);

	spin_lock_irqsave(&mdata->md_lock, flags);
	rmr = genz_rmr_search(mdata, dgcid, rsp_zaddr, len, access, req_addr);
	if (!rmr) {
		status = -EINVAL;
		goto unlock;
	}
	genz_rmr_remove(rmr, false);

unlock:
	spin_unlock_irqrestore(&mdata->md_lock, flags);
out:
	pr_debug("ret=%d, uuid=%pUb, rsp_zaddr=0x%016llx, "
		 "len=0x%llx, access=0x%llx\n",
		 status, uuid, rsp_zaddr, len, access);
	return queue_io_rsp(entry, sizeof(rsp->mr_free), status);
}

int wildcat_rdma_user_req_UUID_IMPORT(struct io_entry *entry)
{
	union wildcat_rdma_req          *req = &entry->op.req;
	union wildcat_rdma_rsp          *rsp = &entry->op.rsp;
	struct file_data        *fdata = entry->fdata;
	struct genz_mem_data    *mdata = &fdata->md;
	uuid_t                  *uuid = &req->uuid_import.uuid;
	uint32_t                uu_flags = req->uuid_import.uu_flags;
	int                     status;

	CHECK_INIT_STATE(entry, status, out);
	status = wildcat_common_UUID_IMPORT(mdata, uuid, wildcat_loopback,
					    uu_flags, GFP_KERNEL);

out:
	pr_debug("ret=%d, uuid=%pUb, uu_flags=0x%x\n", status, uuid, uu_flags);
	return queue_io_rsp(entry, sizeof(rsp->uuid_import), status);
}

int wildcat_rdma_user_req_UUID_FREE(struct io_entry *entry)
{
	union wildcat_rdma_req          *req = &entry->op.req;
	union wildcat_rdma_rsp          *rsp = &entry->op.rsp;
	struct file_data        *fdata = entry->fdata;
	struct genz_mem_data    *mdata = &fdata->md;
	uuid_t                  *uuid = &req->uuid_free.uuid;
	uint32_t                uu_flags = 0;
	int                     status;
	bool                    local;

	CHECK_INIT_STATE(entry, status, out);
	status = wildcat_common_UUID_FREE(mdata, uuid, &uu_flags, &local);
	if (local) {
		spin_lock(&fdata->io_lock);
		fdata->state &= ~STATE_INIT;
		spin_unlock(&fdata->io_lock);
	}

out:
	pr_debug("ret=%d, uuid=%pUb, uu_flags=0x%x\n", status, uuid, uu_flags);
	return queue_io_rsp(entry, sizeof(rsp->uuid_free), status);
}

static int wildcat_rdma_open(struct inode *inode, struct file *file)
{
	int                 ret = -ENOMEM;
	struct file_data    *fdata = NULL;
	size_t              size;

	size = sizeof(*fdata);
	fdata = kzalloc(size, GFP_KERNEL);
	if (!fdata)
		goto done;

	fdata->rstate = to_wildcat_rdma_state(file->private_data);
	pr_debug("fdata=%px, rstate=%px\n", fdata, fdata->rstate);
	fdata->pid = task_pid_nr(current); /* Associate this fdata with pid */
	fdata->free = file_data_free;
	atomic_set(&fdata->count, 1);
	spin_lock_init(&fdata->io_lock);
	init_waitqueue_head(&fdata->io_wqh);
	INIT_LIST_HEAD(&fdata->rd_list);
	genz_init_mem_data(&fdata->md, fdata->rstate->zdev->zbdev);
	INIT_LIST_HEAD(&fdata->zmap_list);
	spin_lock_init(&fdata->zmap_lock);
	spin_lock_init(&fdata->xdm_queue_lock);
	/* xdm_queues tracks what queues are owned by this file_data */
	/* Revisit Perf: what is the tradeoff of size of bitmap vs. rbtree? */
	bitmap_zero(fdata->xdm_queues, XDM_QUEUES_PER_SLICE*SLICES);
	spin_lock_init(&fdata->rdm_queue_lock);
	bitmap_zero(fdata->rdm_queues, RDM_QUEUES_PER_SLICE*SLICES);
	/* we only allow one open per pid */
	if (pid_to_fdata(fdata->rstate, fdata->pid)) {
		ret = -EBUSY;
		goto done;
	}
	/* Allocate and map the local shared data page. Map the global page. */
	ret = alloc_map_shared_data(fdata);
	if (ret != 0) {
		pr_debug("alloc_map_shared_data:failed with ret=%d\n", ret);
		goto done;
	}
	ret = genz_pasid_alloc(&fdata->pasid);
	if (ret < 0) {
		pr_debug("genz_pasid_alloc:failed with ret=%d\n", ret);
		goto free_shared_data;
	}
	/* Bind the task to the PASID on the device, if there is an IOMMU. */
	ret = wildcat_bind_iommu(fdata->rstate->zdev->zbdev,
				 &fdata->io_lock, fdata->pasid);
	if (ret < 0) {
		pr_debug("wildcat_bind_iommu:failed with ret=%d\n", ret);
		goto free_pasid;
	}

	/* Add this fdata to the bridge's fdata_list */
	spin_lock(&fdata->rstate->fdata_lock);
	list_add(&fdata->fdata_list, &fdata->rstate->fdata_list);
	spin_unlock(&fdata->rstate->fdata_lock);
	ret = 0;
	goto done;

free_pasid:
	genz_pasid_free(fdata->pasid);

free_shared_data:
	zmap_free(fdata->local_shared_zmap);
	zmap_free(fdata->global_shared_zmap);

done:
	if (ret < 0 && fdata) {
		put_file_data(fdata);
		fdata = NULL;
	}
	file->private_data = fdata;

	pr_debug("ret=%d, pid=%d, pasid=%u\n",
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
	release_owned_xdm_queues(fdata);
	release_owned_rdm_queues(fdata);
	free_zmap_list(fdata);
	free_io_lists(fdata);
	genz_rmr_free_all(&fdata->md);
	wildcat_notify_remote_uuids(&fdata->md);
	genz_umem_free_all(&fdata->md, &fdata->humongous_zmmu_rsp_pte);
	genz_free_remote_uuids(&fdata->md);
	spin_lock_irqsave(&fdata->md.uuid_lock, flags);
	(void)genz_free_local_uuid(&fdata->md, true); /* also frees associated R-keys */
	spin_unlock_irqrestore(&fdata->md.uuid_lock, flags);
	wildcat_unbind_iommu(fdata->rstate->zdev->zbdev,
			     &fdata->io_lock, fdata->pasid);
	genz_pasid_free(fdata->pasid);
	spin_lock(&fdata->rstate->fdata_lock);
	list_del(&fdata->fdata_list);
#ifdef OLD_ZHPE
	if (fdata == helper_fdata)
		helper_fdata = NULL;
#endif
	spin_unlock(&fdata->rstate->fdata_lock);
	put_file_data(fdata);

	pr_debug("ret=%d, pid=%d\n", 0, task_pid_vnr(current));
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
		pr_debug("ret=%ld, len=%ld, pid=%d\n",
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
	struct wildcat_rdma_hdr  *op_hdr;
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

	op_len = sizeof(union wildcat_rdma_req);
	if (op_len > len)
		op_len = len;
	ret = copy_from_user(op_hdr, buf, op_len);
	if (ret < 0)
		goto done;
	entry->hdr = *op_hdr;

	ret = -EINVAL;
	if (!expected_saw("version", WILDCAT_RDMA_OP_VERSION, op_hdr->version))
		goto done;

#define USER_REQ_HANDLER(_op)					  \
	case WILDCAT_RDMA_OP_ ## _op:				  \
		pr_debug("WILDCAT_RDMA_OP_" # _op);			  \
		op_len = sizeof(struct wildcat_rdma_req_ ## _op); \
		if (len != op_len)				  \
			goto done;				  \
		ret = wildcat_rdma_user_req_ ## _op(entry);	  \
		break;

	switch (op_hdr->opcode) {
		USER_REQ_HANDLER(INIT);
		USER_REQ_HANDLER(MR_REG);
		USER_REQ_HANDLER(MR_FREE);
		USER_REQ_HANDLER(RMR_IMPORT);
		USER_REQ_HANDLER(RMR_FREE);
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
		pr_debug("ret=%ld, len=%ld, pid=%d\n",
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

/* Revisit: delete this when vma_set_page_prot is exported */
#define vma_set_page_prot wildcat_vma_set_page_prot

static int wildcat_rdma_mmap(struct file *file, struct vm_area_struct *vma)
{
	int                 ret = -ENOENT;
	struct file_data    *fdata = file->private_data;
	struct zmap         *zmap;
	union zpages        *zpages;
	struct genz_rmr     *rmr;
	ulong               vaddr, offset, length, i, pgoff;
	uint32_t            cache_flags;

	vma->vm_flags |= VM_MIXEDMAP | VM_DONTCOPY;
	vma->vm_private_data = NULL;

	offset = vma->vm_pgoff << PAGE_SHIFT;
	length = vma->vm_end - vma->vm_start;
	pr_debug("vm_start=0x%lx, vm_end=0x%lx, offset=0x%lx, length=%lu\n",
		 vma->vm_start, vma->vm_end, offset, length);
	spin_lock(&fdata->zmap_lock);
	list_for_each_entry(zmap, &fdata->zmap_list, list) {
		if (offset == zmap->offset &&
		    length == zmap->zpages->hdr.size) {
			if (!zmap->owner || zmap->owner == fdata)
				ret = 0;
			break;
		} else {
			if (offset == zmap->offset &&
			    length != zmap->zpages->hdr.size)
				pr_debug("offset=0x%lx match but length=%lu != zmap size=%lu\n",
					 offset, length,
					 zmap->zpages->hdr.size);
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
				       wildcat_rdma_driver_name, __func__,
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
		pr_err("%s:%s,%u:ret=%d, start=0x%lx, end=0x%lx, off=0x%lx\n",
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

static struct miscdevice miscdev_template = {
	.name               = wildcat_rdma_driver_name,
	.fops               = &wildcat_rdma_fops,
	.minor              = MISC_DYNAMIC_MINOR,
	.mode               = 0666,
};

static int wildcat_rdma_probe(struct genz_dev *zdev,
			      const struct genz_device_id *zdev_id)
{
	struct wildcat_rdma_state *rstate;
	int ret = 0, vecs;

	/* allocate & initialize state structure */
	dev_dbg(&zdev->dev, "allocating rstate\n");
	dev_dbg(&zdev->dev, "zdev->dev is %s zdev->dev->parent is %s\n", dev_name(&zdev->dev), dev_name(zdev->dev.parent));
	rstate = kzalloc(sizeof(*rstate), GFP_KERNEL);
	if (!rstate) {
		ret = -ENOMEM;
		goto out;
	}
	/* Revisit: MultiBridge - allocate & init unique miscdev name */
	memcpy(&rstate->miscdev, &miscdev_template, sizeof(miscdev_template));
	spin_lock_init(&rstate->fdata_lock);
	INIT_LIST_HEAD(&rstate->fdata_list);
	rstate->zdev = zdev;
	genz_set_drvdata(zdev, rstate);
	/* Revisit: locking */
	list_add_tail(&rstate->rstate_node, &rstate_list);

	/* Create device. */
	dev_dbg(&zdev->dev, "creating device %s\n", rstate->miscdev.name);
	ret = misc_register(&rstate->miscdev);
	if (ret < 0) {
		dev_warn(&zdev->dev, "%s:%s:misc_register() returned %d\n",
			 wildcat_rdma_driver_name, __func__, ret);
		goto free_rstate;
	}
	wildcat_rdma_poll_init_waitqueues(rstate);
	vecs = wildcat_intr_vectors_count(zdev->zbdev);
	if (vecs < 0) {
		ret = vecs;
		goto misc_dereg;
	}
	/* Revisit: MultiBridge */
	rstate->min_irq_index = 0;
	rstate->max_irq_index = vecs - 1;
	ret = wildcat_rdma_poll_devices_create(rstate);
	if (ret < 0)
		goto misc_dereg;

out:
	return ret;

misc_dereg:
	misc_deregister(&rstate->miscdev);

free_rstate:
	/* Revisit: locking */
	list_del(&rstate->rstate_node);
	genz_set_drvdata(zdev, NULL);
	kfree(rstate);
	goto out;
}

static int wildcat_rdma_remove(struct genz_dev *zdev)
{
	struct wildcat_rdma_state *rstate;

	rstate = genz_get_drvdata(zdev);
	pr_debug("zdev=%px, rstate=%px\n", zdev, rstate);
	if (rstate) {
		wildcat_rdma_poll_devices_destroy(rstate);
		misc_deregister(&rstate->miscdev);
		list_del(&rstate->rstate_node);
		genz_set_drvdata(zdev, NULL);
		kfree(rstate);
	}
	return 0;
}

static struct genz_driver wildcat_rdma_genz_driver = {
	.name      = wildcat_rdma_driver_name,
	.id_table  = wildcat_rdma_id_table,
	.probe     = wildcat_rdma_probe,
	.remove    = wildcat_rdma_remove,
};

static int __init wildcat_rdma_init(void)
{
	int i, ret = 0;
	struct wildcat_attr default_attr = {
		.max_tx_queues    = 1024,
		.max_rx_queues    = 1024,
		.max_hw_qlen      = 65535,
		.max_sw_qlen      = 65535,
		.max_dma_len      = (1U << 31),
	};

	pr_debug("init\n");
	/* Revisit: MultiBridge */
	global_shared_zpage = wildcat_shared_zpage_alloc(
		sizeof(*global_shared_data), GLOBAL_SHARED_PAGE);
	if (!global_shared_zpage) {
		pr_warn("%s:%s:wildcat_shared_zpage_alloc failed.\n",
		       wildcat_rdma_driver_name, __func__);
		ret = -ENOMEM;
		goto out;
	}
	global_shared_data = global_shared_zpage->queue.pages[0];
	global_shared_data->magic = WILDCAT_MAGIC;
	global_shared_data->version = WILDCAT_GLOBAL_SHARED_VERSION;

	global_shared_data->default_attr = default_attr;
	for (i = 0; i < MAX_IRQ_VECTORS; i++)
		global_shared_data->triggered_counter[i] = 0;

	if (wildcat_register_rdm_trigger(wildcat_rdma_trigger) < 0)
		goto err_zpage_free;

	/* Create 128 polling devices for interrupt notification to userspace */
	if (wildcat_rdma_setup_poll_devs() != 0)
		goto err_unregister_trigger;

	ret = genz_register_driver(&wildcat_rdma_genz_driver);
	if (ret < 0) {
		pr_warn("%s:%s:genz_register_driver returned %d\n",
			wildcat_rdma_driver_name, __func__, ret);
		goto err_cleanup_poll_devs;
	}

out:
	return ret;

err_cleanup_poll_devs:
	wildcat_rdma_cleanup_poll_devs();

err_unregister_trigger:
	wildcat_unregister_rdm_trigger(wildcat_rdma_trigger);

err_zpage_free:
	if (global_shared_zpage) {
		wildcat_queue_zpages_free(global_shared_zpage);
		kfree(global_shared_zpage);
	}

	goto out;
}

static void wildcat_rdma_exit(void)
{
	pr_debug("entered\n");
	genz_unregister_driver(&wildcat_rdma_genz_driver);
	wildcat_rdma_cleanup_poll_devs();
	wildcat_unregister_rdm_trigger(wildcat_rdma_trigger);

	/* free shared data page. */
	/* Revisit: MultiBridge */
	if (global_shared_zpage) {
		wildcat_queue_zpages_free(global_shared_zpage);
		kfree(global_shared_zpage);
	}
	/* Revisit: finish this */
}
