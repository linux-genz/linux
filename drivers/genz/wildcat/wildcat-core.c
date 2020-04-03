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

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/pci.h>
#include <linux/genz.h>
#include <linux/amd-iommu.h>
#include <linux/interrupt.h>
#include <linux/cdev.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>

#include "wildcat.h"

#define DRIVER_NAME                   "wildcat"

module_param_named(kmsg_timeout, wildcat_kmsg_timeout, uint, 0644);
MODULE_PARM_DESC(kmsg_timeout, "kernel-to-kernel message timeout in seconds");

const char wildcat_driver_name[] = DRIVER_NAME;

static atomic64_t mem_total = ATOMIC64_INIT(0);

static atomic_t slice_id = ATOMIC_INIT(0);

static struct pci_device_id wildcat_id_table[] = {
	{ PCI_VDEVICE(HP_3PAR, 0x028f), }, /* Function 0 */
	{ PCI_VDEVICE(HP_3PAR, 0x0290), }, /* Function 1 */
	{ 0 },
};

MODULE_DEVICE_TABLE(pci, wildcat_id_table);


/* Revisit Carbon: Workaround for Carbon simulator not having AVX instructions
 * and ymm registers, but also not requiring 16/32-byte accesses
 */
uint wildcat_no_avx = 0;
module_param_named(no_avx, wildcat_no_avx, uint, S_IRUGO);
MODULE_PARM_DESC(no_avx, "Workaround for lack of AVX instructions/registers");

uint wildcat_no_rkeys = 1;
module_param_named(no_rkeys, wildcat_no_rkeys, uint, S_IRUGO);
MODULE_PARM_DESC(no_rkeys, "Disable Gen-Z R-keys");

static int __init wildcat_init(void);
static void wildcat_exit(void);

module_init(wildcat_init);
module_exit(wildcat_exit);

MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(drivers/genz/genz);

struct bridge    wildcat_bridge = { 0 };
static uint64_t  wildcat_slink_base_offset;

#define TRACKER_MAX     (256)

uint wildcat_loopback = 1;
module_param(wildcat_loopback, uint, S_IRUGO);
MODULE_PARM_DESC(wildcat_loopback, "Wildcat Gen-Z loopback mode (default=1)");
EXPORT_SYMBOL(wildcat_loopback); /* Revisit: should not export */

static char *helper_path = "/sbin/wildcat_helper";
module_param(helper_path, charp, 0444);
MODULE_PARM_DESC(helper_path, "path-to-helper");

static DECLARE_WAIT_QUEUE_HEAD(helper_wq);
static uint             helper_state = HELPER_STATE_INIT;
static pid_t            helper_pid;
#ifdef OLD_ZHPE
static uint32_t         helper_req_len;
static struct file_data *helper_fdata = NULL;
#endif

/* Revisit: convert to standard kernel memory allocation API */
void _do_kfree(const char *callf, uint line, void *ptr)
{
	size_t              size;

	if (!ptr)
		return;

	ptr -= sizeof(void *);
	size = *(uintptr_t *)ptr;
	atomic64_sub(size, &mem_total);
	pr_debug("%s,%u:ptr 0x%px size %lu\n", callf, line, ptr, size);
	kfree(ptr);
}

void *_do_kmalloc(const char *callf, uint line,
		  size_t size, gfp_t flags, bool zero)
{
	void                *ret, *ptr;

	/* kmalloc alignment is sizeof(void *) */
	ptr = kmalloc(size + sizeof(void *), flags);
	if (!ptr) {
		if (flags != GFP_ATOMIC)
			pr_err("%s,%u:%s:failed to allocate %lu bytes\n",
			       callf, line, __func__, size);
		return NULL;
	}
	ret = ptr + sizeof(void *);
	if (zero)
		memset(ret, 0, size);
	pr_debug("%s,%u:ptr 0x%px ret 0x%px size %lu\n", callf, line,
		 ptr, ret, size);
	atomic64_add(size, &mem_total);
	*(uintptr_t *)ptr = size;

	return ret;
}

void _do_free_pages(const char *callf, uint line, void *ptr, int order)
{
	size_t              size;
	struct page         *page;

	if (!ptr)
		return;

	size = 1UL << (order + PAGE_SHIFT);
	atomic64_sub(size, &mem_total);
	page = virt_to_page(ptr);
	(void)page;
	pr_debug("%s:%u:ptr/page/pfn 0x%px/0x%px/0x%lx size %lu\n",
		 callf, line, ptr, page, page_to_pfn(page), size);
	free_pages((ulong)ptr, order);
}

void *_do__get_free_pages(const char *callf, uint line,
			  int order, gfp_t flags, bool zero)
{
	void                *ret;
	size_t              size = 1UL << (order + PAGE_SHIFT);
	struct page         *page;

	ret = (void *)__get_free_pages(flags, order);
	if (!ret) {
		if (flags != GFP_ATOMIC)
			pr_err("%s,%u:%s:failed to allocate %lu bytes\n",
			       callf, line, __func__, size);
		return NULL;
	}
	if (zero)
		memset(ret, 0, size);
	atomic64_add(size, &mem_total);
	page = virt_to_page(ret);
	(void)page;
	pr_debug("ret/page/pfn 0x%px/0x%px/0x%lx size %lu\n",
		 ret, page, page_to_pfn(page), size);

	return ret;
}

void wildcat_queue_zpages_free(union zpages *zpages)
{
	size_t              npages;
	size_t              i;
	struct page         *page;

	npages = zpages->queue.size >> PAGE_SHIFT;
	for (i = 0; i < npages; i++) {
		page = virt_to_page(zpages->queue.pages[i]);
		if (page_count(page) != 1 || page_mapcount(page) != 0)
			pr_warn("%s,%u:i %lu ptr/page/pfn 0x%p/0x%p/0x%lx c %d/%d\n",
				__func__, __LINE__,
				i, zpages->queue.pages[i],
				page, page_to_pfn(page), page_count(page),
				page_mapcount(page));
		do_free_pages(zpages->queue.pages[i], 0);
	}
}
EXPORT_SYMBOL(wildcat_queue_zpages_free);

void _wildcat_zpages_free(const char *callf, uint line, union zpages *zpages)
{
	if (!zpages)
		return;

	pr_debug("zpages 0x%px\n", zpages);

	/* Revisit: most of these need zap_vma_ptes(vma, addr, size); */
	switch (zpages->hdr.page_type) {
	case QUEUE_PAGE:
	case LOCAL_SHARED_PAGE:
		wildcat_queue_zpages_free(zpages);
		break;
	case GLOBAL_SHARED_PAGE:
	case HSR_PAGE:
	case RMR_PAGE:
		/* Nothing to do */
		break;
	case DMA_PAGE:
		dma_free_coherent(zpages->dma.dev, zpages->dma.size,
				  zpages->dma.cpu_addr, zpages->dma.dma_addr);
		break;
	}

	kfree(zpages);
}
EXPORT_SYMBOL(_wildcat_zpages_free);

/*
 * wildcat_hsr_zpage_alloc - allocate a zpages structure for a single page of
 * HSR registers. This is used to map the QCM application data for queues.
 * The space for the HSRs is already allocated and mapped by the pci probe
 * function.
 * 	base_addr - pointer to the start of the QCM app first 64 bytes
 */
union zpages *_wildcat_hsr_zpage_alloc(
	const char  *callf,
	uint        line,
	phys_addr_t base_addr)
{
	union zpages       *ret = NULL;

	pr_debug("page_type HSR_PAGE\n");

	/* kmalloc space for the return and an array of pages in the zpage struct */
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		goto done;

	ret->hsr.page_type = HSR_PAGE;
	ret->hsr.size = PAGE_SIZE; /* always 1 page of HSRs */
	ret->hsr.base_addr = base_addr;

done:
	pr_debug("ret 0x%px\n", ret);
	return ret;
}
EXPORT_SYMBOL(_wildcat_hsr_zpage_alloc);

/*
 * dma_zpages_alloc - allocate a zpages structure that can be used for the
 * contiguous physical address space for queues. It uses dma_alloc_coherent()
 * to allocate the space.
 *	sl - slice structure for the pci_dev->device.
	size - size in bytes to be allocated for the dma
 */
union zpages *_dma_zpages_alloc(
	const char *callf, uint line,
	struct slice * sl,
	size_t size)
{
	union zpages       *ret = NULL;
	int                 order = 0;
	size_t              npages;

	pr_debug("page_type DMA_PAGE\n");

	order = get_order(size);
	npages = 1UL << order;

	/* kmalloc space for the return structure. */
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		goto done;

	ret->dma.cpu_addr = dma_alloc_coherent(&sl->pdev->dev, npages*PAGE_SIZE,
					       &ret->dma.dma_addr, GFP_KERNEL);
	pr_debug("dma_alloc_coherent(size=%u, pa returned=0x%llx, va returned=0x%px\n",
		 (unsigned int)(npages*PAGE_SIZE),
		 ret->dma.dma_addr, ret->dma.cpu_addr);
	/* RAM memory will always be WB unless you set the memory type. */
	ret->dma.page_type = DMA_PAGE;
	ret->dma.size = size;
	ret->dma.dev = &sl->pdev->dev;
	if (!ret->dma.cpu_addr) {
		kfree(ret);
		ret = NULL;
	}

done:
	pr_debug("ret 0x%px\n", ret);
	return ret;
}

/*
 * wildcat_shared_zpage_alloc - allocate a single page for the shared data.
 * It is allocated at init and only free'ed at exit.
 */

union zpages *wildcat_shared_zpage_alloc(size_t size, int type)
{
	union zpages       *ret = NULL;

	/* Use the queue type alloc to get a zpage */
	ret = queue_zpages_alloc(size, false);
	if (!ret)
		return ret;
	/* Mark this page as special SHARED_PAGE type. */
	ret->queue.page_type = type;
	return ret;
}
EXPORT_SYMBOL(wildcat_shared_zpage_alloc);

/*
 * queue_zpages_alloc - allocate a zpages structure that can be used for
 * kmalloced space shared with user space.
 */
union zpages *_queue_zpages_alloc(
	const char *callf, uint line,
	size_t size,
	bool contig)
{
	union zpages       *ret = NULL;
	int                 order = 0;
	size_t              npages;
	size_t              i;

	pr_debug("page_type QUEUE_PAGE size %lu contig %d\n", size, contig);

	if (contig) {
		order = get_order(size);
		npages = 1UL << order;
		size = npages << PAGE_SHIFT;
	} else {
		size = PAGE_ALIGN(size);
		npages = size >> PAGE_SHIFT;
	}

	/* kmalloc space for the return and an array of pages in the zpage struct */
	ret = kzalloc(sizeof(*ret) + npages * sizeof(ret->queue.pages[0]),
			 GFP_KERNEL);
	if (!ret || !npages)
		goto done;

	ret->queue.size = size;
	ret->queue.page_type = QUEUE_PAGE;
	if (contig) {
		ret->queue.pages[0] = _do__get_free_pages(
			callf, line,
			order, GFP_KERNEL | __GFP_ZERO, true);
		i = 1;
		if (ret->queue.pages[0]) {
			split_page(virt_to_page(ret->queue.pages[0]), order);
			for (; i < npages; i++)
				ret->queue.pages[i] =
					ret->queue.pages[i - 1] + PAGE_SIZE;
		}
	} else {
		for (i = 0; i < npages; i++) {
			ret->queue.pages[i] = _do__get_free_pages(
				callf, line,

				0, GFP_KERNEL | __GFP_ZERO, true);
			if (!ret->queue.pages[i])
				break;
		}
	}
	if (!ret->queue.pages[i-1]) {
		for (i = 0; i < npages; i++)
			do_free_pages(ret->queue.pages[i], 0);
		kfree(ret);
		ret = NULL;
	}

done:
	pr_debug("ret 0x%px\n", ret);
	return ret;
}

/*
 * wildcat_rmr_zpages_alloc - allocate a zpages structure for a
 * cpu-visible RMR_IMPORT.
 * This is used to map the requester ZMMU PTE.
 * 	rmr - pointer to the corresponding rmr structure
 */
union zpages *_wildcat_rmr_zpages_alloc(const char *callf, uint line,
					struct genz_rmr *rmr)
{
	union zpages       *ret = NULL;

	pr_debug("page_type RMR_PAGE\n");

	/* kmalloc space for the return struct */
	ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		goto done;

	ret->rmrz.page_type = RMR_PAGE;
	ret->rmrz.size = rmr->pte_info->length;
	ret->rmrz.rmr = rmr;

done:
	pr_debug("ret 0x%px\n", ret);
	return ret;
}
EXPORT_SYMBOL(_wildcat_rmr_zpages_alloc);

#ifdef OLD_ZHPE
/* Revisit: convert to netlink interface */
static int zhpe_user_req_HELPER_WAIT(struct io_entry *entry)
{
	int                 ret = 0;
	struct file_data    *fdata = entry->fdata;
	union zhpe_rsp      *rsp = &entry->op.rsp;

	CHECK_INIT_STATE(entry, ret, done);
	if (fdata != helper_fdata) {
		ret = -EINVAL;
		goto done;
	}

	/* Revisit: locking */
	helper_state = HELPER_STATE_WAIT;
	debug(DEBUG_HELPER, "%s:%s,%u: calling wait_event_interruptible\n",
	      zhpe_driver_name, __func__, __LINE__);
	ret = wait_event_interruptible(helper_wq,
				       helper_state != HELPER_STATE_WAIT);
	rsp->helper_wait.req = helper_op.req;
	rsp->helper_wait.req_len = helper_req_len;
	rsp->helper_wait.next_state = helper_state;

done:
	debug(DEBUG_HELPER, "%s:%s,%u: ret = %d, req_len=%u, next_state=%u\n",
	      zhpe_driver_name, __func__, __LINE__, ret,
	      helper_req_len, helper_state);
	return queue_io_rsp(entry, sizeof(rsp->helper_wait), ret);
}

static int zhpe_user_req_HELPER_MMAP(struct io_entry *entry)
{
	int                 ret = 0;
	struct file_data    *fdata = entry->fdata;
	union zhpe_req      *req = &entry->op.req;
	union zhpe_rsp      *rsp = &entry->op.rsp;

	CHECK_INIT_STATE(entry, ret, done);
	if (fdata != helper_fdata) {
		ret = -EINVAL;
		goto done;
	}

	debug(DEBUG_HELPER, "%s:%s,%u: offset=0x%llx, len=%llu, vaddr=0x%llx\n",
	      zhpe_driver_name, __func__, __LINE__, req->helper_mmap.offset,
	      req->helper_mmap.len, req->helper_mmap.vaddr);
	/* Revisit: locking */
	helper_op.req = *req;
	helper_state = HELPER_STATE_MMAP_DONE;
	wake_up_interruptible(&helper_wq);

done:
	return queue_io_rsp(entry, sizeof(rsp->helper_wait), ret);
}
#endif

/* This function called by IOMMU driver on PPR failure */
static int iommu_invalid_ppr_cb(struct pci_dev *pdev, int pasid,
				unsigned long address, u16 flags)

{
	pr_warn("%s:%s IOMMU PRR failure device = %s, pasid = %d address = 0x%lx flags = %ux\n",
		wildcat_driver_name, __func__, pci_name(pdev), pasid,
		address, flags);

	return AMD_IOMMU_INV_PRI_RSP_INVALID;
}

int wildcat_bind_iommu(struct genz_bridge_dev *gzbr,
		       spinlock_t *io_lock, uint pasid)
{
	int s, ret = 0;
	struct pci_dev *pdev;
	struct bridge  *br = wildcat_gzbr_to_br(gzbr);

	if (gzbr == NULL || br == NULL)
		return -EINVAL;
	spin_lock(io_lock);
	for (s=0; s<SLICES; s++) {
		if (!SLICE_VALID(&(br->slice[s])))
			continue;
		pdev = br->slice[s].pdev;
		ret = amd_iommu_bind_pasid(pdev, pasid, current);
		if (ret < 0) {
			pr_debug("amd_iommu_bind_pasid failed for slice %d with return %d\n",
				 s, ret);
		}
		amd_iommu_set_invalid_ppr_cb(pdev, iommu_invalid_ppr_cb);
	}
	spin_unlock(io_lock);
	return ret;
}
EXPORT_SYMBOL(wildcat_bind_iommu);

void wildcat_unbind_iommu(struct genz_bridge_dev *gzbr,
			  spinlock_t *io_lock, uint pasid)
{
	int s;
	struct pci_dev *pdev;
	struct bridge  *br = wildcat_gzbr_to_br(gzbr);

	spin_lock(io_lock);
	for (s=0; s<SLICES; s++) {
		if (!SLICE_VALID(&(br->slice[s])))
			continue;
		pdev = br->slice[s].pdev;
		amd_iommu_unbind_pasid(pdev, pasid);
		amd_iommu_set_invalid_ppr_cb(pdev, NULL);
	}
	spin_unlock(io_lock);
	return;
}
EXPORT_SYMBOL(wildcat_unbind_iommu);

#ifdef OLD_ZHPE
static int zhpe_helper_cmd(union zhpe_req *req, uint32_t req_len,
			   uint next_state, uint wait_state)
{
	int                 ret;
	ktime_t timeout;

	timeout = ktime_set(2, 0);  /* Revisit: make tunable */

	/* sleep waiting for helper to enter STATE_WAIT */
	ret = wait_event_interruptible_hrtimeout(
		helper_wq, helper_state == HELPER_STATE_WAIT, timeout);
	if (ret < 0)
		goto out;

	/* set helper request & helper state, and wake waiters */
	helper_op.req = *req;
	helper_req_len = req_len;
	helper_state = next_state;
	wake_up_interruptible(&helper_wq);

	/* sleep again, if caller wants to wait for a particular state */
	if (wait_state < HELPER_STATE_NO_WAIT) {
		ret = wait_event_interruptible_hrtimeout(
			helper_wq, helper_state == wait_state, timeout);
		*req = helper_op.req;
	}

out:
	return ret;
}
#endif

/* Revisit: if vma_set_page_prot was exported by mm/mmap.c, we'd just use
 * it, but it's not, so we do it ourselves here.
 */

#define vma_set_page_prot wildcat_vma_set_page_prot
#define vm_pgprot_modify wildcat_pgprot_modify
#define vma_wants_writenotify wildcat_vma_wants_writenotify

/* Revisit: copy actual vma_wants_writenotify? */
static inline int wildcat_vma_wants_writenotify(struct vm_area_struct *vma,
						pgprot_t vm_page_prot)
{
	return 0;
}

/* identical to vm_pgprot_modify, except for function name */
static pgprot_t wildcat_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
{
	return pgprot_modify(oldprot, vm_get_page_prot(vm_flags));
}

/* identical to vma_set_page_prot, except for function name */
void wildcat_vma_set_page_prot(struct vm_area_struct *vma)
{
	unsigned long vm_flags = vma->vm_flags;
	pgprot_t vm_page_prot;

	vm_page_prot = vm_pgprot_modify(vma->vm_page_prot, vm_flags);
	if (vma_wants_writenotify(vma, vm_page_prot)) {
		vm_flags &= ~VM_SHARED;
		vm_page_prot = vm_pgprot_modify(vm_page_prot, vm_flags);
	}
	/* remove_protection_ptes reads vma->vm_page_prot without mmap_sem */
	WRITE_ONCE(vma->vm_page_prot, vm_page_prot);
}
EXPORT_SYMBOL(wildcat_vma_set_page_prot);

struct slice *wildcat_slice_id_to_slice(struct bridge *bridge, int slice)
{
	struct slice *sl;
	int i;

	for (i = 0; i < SLICES; i++) {
		if (bridge->slice[i].id == slice)
			return sl;
	}
	return NULL;
}
EXPORT_SYMBOL(wildcat_slice_id_to_slice);

#ifdef ZHPE_ENIC  /* Revisit: convert to Gen-Z subsystem interface */
LIST_HEAD(zhpe_core_driver_list);

static struct zhpe_core_info *zhpe_core_get_info(void *hw)
{
	struct bridge *br = (struct bridge *)hw;
	struct zhpe_core_info *info = &br->core_info;

	if (!info->pdev) {
		info->pdev = br->slice[0].pdev;  /* Revisit: slice[0] */
		info->gcid = br->gcid;
	}
	return info;
}

static int zhpe_core_generate_uuid(void *hw, uuid_t *uuid)
{
	struct bridge *br = (struct bridge *)hw;
	struct enic *enic = br->enic;
	struct uuid_tracker *uu;
	uint32_t ro_rkey, rw_rkey;
	int status;

	if (!enic) {
		status = -EINVAL;
		goto out;
	}
	zhpe_generate_uuid(br, uuid);
	uu = zhpe_uuid_tracker_alloc_and_insert(uuid, UUID_TYPE_LOCAL,
					0, &enic->md, GFP_KERNEL, &status);
	if (!uu)
		goto out;

	status = zhpe_rkey_alloc(&ro_rkey, &rw_rkey);
	if (status < 0) {
		zhpe_uuid_remove(uu);
		goto out;
	}

	enic->md.local_uuid = uu;
	enic->md.ro_rkey = ro_rkey;
	enic->md.rw_rkey = rw_rkey;  /* buffers are RO, so this is unused */

out:
	return status;
}

static int zhpe_core_request_irq(void *hw, uint irq_index,
				 irq_handler_t handler,
				 ulong irqflags, const char *devname,
				 void *dev_id)
{
	struct bridge *br = (struct bridge *)hw;
	struct rdm_info *rdmi;

	if (!br || !br->enic ||
	    !(irq_index == ReqMsgRecvInt || irq_index == RspMsgRecvInt))
		return -EINVAL;

	if (irq_index == ReqMsgRecvInt)
		rdmi = &br->enic->req_rdmi;
	else  /* RspMsgRecvInt */
		rdmi = &br->enic->rsp_rdmi;
	return zhpe_register_rdm_interrupt(rdmi->sl, rdmi->queue,
					   handler, dev_id);
}

static int zhpe_core_free_irq(void *hw, uint irq_index, void *dev_id)
{
	struct bridge *br = (struct bridge *)hw;
	struct rdm_info *rdmi;

	if (!br || !br->enic ||
	    !(irq_index == ReqMsgRecvInt || irq_index == RspMsgRecvInt))
		return -EINVAL;

	if (irq_index == ReqMsgRecvInt)
		rdmi = &br->enic->req_rdmi;
	else  /* RspMsgRecvInt */
		rdmi = &br->enic->rsp_rdmi;
	zhpe_unregister_rdm_interrupt(rdmi->sl, rdmi->queue);
	return 0;
}

static union zpages *zhpe_core_dma_alloc(void *hw, size_t size)
{
	struct bridge   *br = (struct bridge *)hw;
	struct xdm_info *xdmi;
	union zpages    *zpages;
	struct zmap     *zmap;
	union zhpe_req  req;
	int             ret;

	if (!br || !br->enic || !helper_fdata)
		return ERR_PTR(-EINVAL);

	xdmi = &br->enic->xdmi;
	zpages = dma_zpages_alloc(xdmi->sl, size);
	if (!zpages)
		goto out;
	zmap = zmap_alloc(helper_fdata, zpages);
	if (IS_ERR(zmap)) {
		wildcat_zpages_free(zpages);
		zpages = NULL;
		goto out;
	}
	zmap->owner = helper_fdata;
	req.hdr.opcode = ZHPE_OP_HELPER_MMAP;
	req.helper_mmap.offset = zmap->offset;
	req.helper_mmap.len = size;
	ret = zhpe_helper_cmd(&req, sizeof(req.helper_mmap), HELPER_STATE_MMAP,
			      HELPER_STATE_MMAP_DONE);
	zpages->dma.user_vaddr = (void *)req.helper_mmap.vaddr;

out:
	return zpages;
}

static void zhpe_core_dma_free(void *hw, union zpages *zpage)
{
	struct bridge *br = (struct bridge *)hw;

	if (!br || !br->enic)
		return;

	/* Revisit: fix this - HELPER_FREE? */
	wildcat_zpages_free(zpage);
}

static int zhpe_core_mr_reg(void *hw, union zpages *zpage,
			    uint64_t *rsp_zaddr, uint32_t *pg_ps,
			    uint32_t *ro_rkey, uint32_t *rw_rkey)
{
	struct bridge *br = (struct bridge *)hw;
	uint64_t vaddr;
	uint64_t len;
	uint32_t pasid;
	uint64_t access = ZHPE_MR_GET_REMOTE|ZHPE_MR_INDIVIDUAL|ZHPE_MR_INDIV_RKEYS;

	if (!br || !br->enic || !zpage || !rsp_zaddr || !pg_ps)
		return -EINVAL;

	vaddr = (uint64_t)zpage->dma.user_vaddr;
	pasid = helper_fdata->pasid;
	len = zpage->dma.size;
	return zhpe_kernel_MR_REG(&br->enic->md, vaddr, len, access, pasid,
				  rsp_zaddr, pg_ps, ro_rkey, rw_rkey);
}

static int zhpe_core_rmr_import(void *hw, struct enic_mrreg *mrreg,
				uint64_t *req_addr, void **cpu_addr,
				uint32_t *pg_ps)
{
	struct bridge *br = (struct bridge *)hw;
#ifdef XDM_ER
	uint64_t access = ZHPE_MR_GET_REMOTE|ZHPE_MR_INDIVIDUAL;
#else
	uint64_t access = ZHPE_MR_GET_REMOTE|ZHPE_MR_INDIVIDUAL|ZHPE_MR_REQ_CPU;
#endif

	if (!br || !br->enic || !mrreg || !req_addr || !pg_ps)
		return -EINVAL;

	return zhpe_kernel_RMR_IMPORT(&br->enic->md, &mrreg->uuid,
				      mrreg->rsp_zaddr, mrreg->size,
				      access, mrreg->ro_rkey,
				      req_addr, cpu_addr, pg_ps);
}

static struct zhpe_bus zhpe_bus_info = {  /* Revisit: finish this */
	.info = zhpe_core_get_info,
	.generate_uuid = zhpe_core_generate_uuid,
	.alloc_queues = zhpe_core_alloc_queues,
	.free_queues = zhpe_core_free_queues,
	.request_irq = zhpe_core_request_irq,
	.free_irq = zhpe_core_free_irq,
	.dma_alloc = zhpe_core_dma_alloc,
	.dma_free = zhpe_core_dma_free,
	.mr_reg = zhpe_core_mr_reg,
	.rmr_import = zhpe_core_rmr_import,
	.enic_alloc_msgid = zhpe_msg_alloc_msgid,
	.send_enic_info = zhpe_msg_send_ENIC_INFO,
	.send_enic_mrreg = zhpe_msg_send_ENIC_MRREG,
	.send_enic_send = zhpe_msg_send_ENIC_SEND,
	.send_enic_er = zhpe_msg_send_ENIC_ER,
	.resp_enic_er = zhpe_msg_resp_ENIC_ER,
	.enic_xdm_space = zhpe_msg_enic_xdm_space,
#ifdef XDM_ER
	.enic_er_read = zhpe_msg_enic_er_read,
#endif
	.recv_enic_cmpl = zhpe_msg_enic_cmpl,
	.recv_enic_more = zhpe_msg_enic_more,
};

int zhpe_register_driver(struct zhpe_driver *drv, struct zhpe_bus **bus)
{
	int ret = 0;
	struct bridge *br = &zhpe_bridge;
	struct enic *enic;

	if (!drv || !bus) {
		ret = -EINVAL;
		goto done;
	}
	pr_info("zhpe registering driver %s\n", drv->name);
	*bus = &zhpe_bus_info;
	if (drv->recv_enic_info) {  /* must be an enic driver */
		enic = kzalloc(sizeof(*enic), GFP_KERNEL);
		if (!enic) {
			ret = -ENOMEM;
			goto done;
		}
		enic->drv = drv;
		zhpe_init_mem_data(&enic->md, br);
		br->enic = enic;
	}
	/* Revisit: locking */
	list_add_tail(&drv->list, &zhpe_core_driver_list);
	/* call probe function for each bridge */
	drv->probe(br, br->enic);  /* Revisit MultiBridge: fix this */
 done:
	return ret;
}
EXPORT_SYMBOL(zhpe_register_driver);

static void zhpe_enic_cleanup(struct enic *enic)
{
	struct bridge *br = enic->md.bridge;
	struct genz_mem_data *mdata = &enic->md;

	zhpe_rmr_free_all(mdata);
	zhpe_notify_remote_uuids(mdata);
	zhpe_umem_free_all(mdata, NULL);
	zhpe_free_remote_uuids(mdata);
	(void)genz_free_local_uuid(mdata, true); /* also frees associated R-keys */
	/* Revisit: what else do we need to clean up? */
	if (br)
		br->enic = 0;
	kfree(enic);
}

void zhpe_unregister_driver(struct zhpe_driver *drv)
{
	struct bridge *br = &zhpe_bridge;
	struct enic *enic;

	if (!drv)
		return;

	pr_info("zhpe unregistering driver %s\n", drv->name);
	/* call remove function for each bridge */
	drv->remove(br);  /* Revisit MultiBridge: fix this */
	enic = br->enic;
	if (enic && enic->drv == drv) {
		zhpe_enic_cleanup(enic);
	}
	list_del_init(&drv->list);
}
EXPORT_SYMBOL(zhpe_unregister_driver);
#endif /* ZHPE_ENIC */

#ifndef PCI_EXT_CAP_ID_DVSEC
#define PCI_EXT_CAP_ID_DVSEC 0x23  /* Revisit: should be in pci.h */
#endif

/* Revisit: make these dynamic based on bridge HW */
static struct genz_bridge_info wildcat_br_info = {
	.req_zmmu            = 1,
	.rsp_zmmu            = 1,
	.xdm                 = 1,
	.rdm                 = 1,
	.xdm_cmpl_intr       = 0,
	.rdm_cmpl_intr       = 1,
	.nr_xdm_queues       = XDM_QUEUES_PER_SLICE,
	.nr_rdm_queues       = RDM_QUEUES_PER_SLICE,
	.xdm_qlen            = MAX_SW_XDM_QLEN,
	.rdm_qlen            = MAX_SW_RDM_QLEN,
	.xdm_max_xfer        = WILDCAT_XDM_MAX_XFER,
	.nr_req_page_grids   = WILDCAT_PAGE_GRID_ENTRIES,
	.nr_rsp_page_grids   = WILDCAT_PAGE_GRID_ENTRIES,
	.nr_req_ptes         = WILDCAT_REQ_ZMMU_ENTRIES,
	.nr_rsp_ptes         = WILDCAT_RSP_ZMMU_ENTRIES,
	.min_cpuvisible_addr = WILDCAT_MIN_CPUVISIBLE_ADDR,
	.max_cpuvisible_addr = WILDCAT_MAX_CPUVISIBLE_ADDR,
	.min_nonvisible_addr = WILDCAT_MIN_NONVISIBLE_ADDR,
	.max_nonvisible_addr = WILDCAT_MAX_NONVISIBLE_ADDR,
};

static int wildcat_bridge_info(struct genz_dev *zdev,
			       struct genz_bridge_info *info)
{
	if (!zdev_is_local_bridge(zdev))
		return -EINVAL;

	wildcat_br_info.loopback = wildcat_loopback != 0;
	/* workaround for S-link translation: the Wildcat bridge does not
	 * receive the full CPU physical address, but only an offset from
	 * the start of the S-link region
	 */
	wildcat_br_info.cpuvisible_phys_offset = wildcat_slink_base_offset;
	/* load/store requires non-zero S-link base offset */
	wildcat_br_info.load_store = wildcat_slink_base_offset != 0;
	*info = wildcat_br_info;
	return 0;
}

static struct genz_bridge_driver wildcat_genz_bridge_driver = {
	.bridge_info = wildcat_bridge_info,
	.control_read = wildcat_control_read,
	.control_write = wildcat_control_write,
	.req_page_grid_write = wildcat_req_page_grid_write,
	.rsp_page_grid_write = wildcat_rsp_page_grid_write,
	.req_pte_write = wildcat_req_pte_write,
	.rsp_pte_write = wildcat_rsp_pte_write,
	.dma_map_sg_attrs = wildcat_dma_map_sg_attrs,
	.dma_unmap_sg_attrs = wildcat_dma_unmap_sg_attrs,
	.alloc_queues = wildcat_alloc_queues,
	.free_queues = wildcat_free_queues,
	.sgl_request = wildcat_sgl_request,
	.generate_uuid = wildcat_generate_uuid,
	.uuid_import = wildcat_kernel_UUID_IMPORT,
	.uuid_free = wildcat_common_UUID_FREE,
	.control_structure_pointers = wildcat_control_structure_pointers,
};

#define WILDCAT_ZMMU_XDM_RDM_HSR_BAR 0

static int wildcat_probe(struct pci_dev *pdev,
			 const struct pci_device_id *pdev_id)
{
	int ret, pos;
	int l_slice_id;
	void __iomem *base_addr;
	struct genz_bridge_dev *gzbr = NULL;
	struct bridge *br = &wildcat_bridge; /* Revisit: MultiBridge */
	struct slice *sl;
	phys_addr_t phys_base;
	uint16_t devctl2;

	/* No setup for function 0 */
	if (PCI_FUNC(pdev->devfn) == 0) {
		return 0;
	}

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DVSEC);
#if 0
	if (!pos) {
		dev_warn(&pdev->dev, "%s: No DVSEC capability found\n",
			 wildcat_driver_name);
	}
#endif

	/* Set atomic operations enable capability */
	pcie_capability_set_word(pdev, PCI_EXP_DEVCTL2,
				 PCI_EXP_DEVCTL2_ATOMIC_REQ);
	ret = pcie_capability_read_word(pdev, PCI_EXP_DEVCTL2, &devctl2);
	if (ret) {
		dev_warn(&pdev->dev,
			 "%s:%s PCIe AtomicOp pcie_capability_read_word failed. ret = 0x%x\n",
			 wildcat_driver_name, __func__, ret);
	} else if (!(devctl2 & PCI_EXP_DEVCTL2_ATOMIC_REQ)) {
		dev_warn(&pdev->dev,
			 "%s:%s PCIe AtomicOp capability enable failed. devctl2 = 0x%x\n",
			 wildcat_driver_name, __func__, (uint) devctl2);
	}

	/* Zero based slice ID */
	l_slice_id = atomic_inc_return(&slice_id) - 1;
	sl = &br->slice[l_slice_id];
	dev_dbg(&pdev->dev, "slice=%u\n", l_slice_id);

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_dbg(&pdev->dev,
			"pci_enable_device probe error %d for device %s\n",
			ret, pci_name(pdev));
		goto err_out;
	}

	if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
		ret = -ENOSPC;
		dev_warn(&pdev->dev, "%s: No 64-bit DMA available\n",
			 wildcat_driver_name);
		goto err_pci_disable_device;
	}

	ret = pci_request_regions(pdev, DRIVER_NAME);
	if (ret < 0) {
		dev_dbg(&pdev->dev,
			"pci_request_regions error %d for device %s\n",
			ret, pci_name(pdev));
		goto err_pci_disable_device;
	}

	base_addr = pci_iomap(pdev, WILDCAT_ZMMU_XDM_RDM_HSR_BAR,
			      sizeof(struct func1_bar0));
	if (!base_addr) {
		dev_dbg(&pdev->dev,
		      "cannot iomap bar %u registers of size %lu (requested size = %lu)\n",
		      WILDCAT_ZMMU_XDM_RDM_HSR_BAR,
		      (unsigned long) pci_resource_len(
			      pdev, WILDCAT_ZMMU_XDM_RDM_HSR_BAR),
		      sizeof(struct func1_bar0));
		ret = -EINVAL;
		goto err_pci_release_regions;
	}
	phys_base = pci_resource_start(pdev, 0);

	dev_dbg(&pdev->dev,
		"bar=%u, start=0x%lx, actual len=%lu, requested len=%lu, base_addr=0x%lx\n",
		0,
		(unsigned long) phys_base,
		(unsigned long) pci_resource_len(pdev, 0),
		sizeof(struct func1_bar0),
		(unsigned long) base_addr);

	sl->bar = base_addr;
	sl->phys_base = phys_base;
	sl->id = l_slice_id;
	sl->pdev = pdev;
	sl->valid = true;

	wildcat_zmmu_clear_slice(sl);
	wildcat_xqueue_init(sl);
	if (wildcat_clear_xdm_qcm(sl->bar->xdm)) {
		dev_dbg(&pdev->dev, "wildcat_clear_xdm_qcm failed\n");
		ret = -1;
		goto err_pci_release_regions;
	}

	wildcat_rqueue_init(sl);
	if (wildcat_clear_rdm_qcm(sl->bar->rdm)) {
		dev_dbg(&pdev->dev, "wildcat_clear_rdm_qcm failed\n");
		ret = -1;
		goto err_pci_release_regions;
	}

	pci_set_drvdata(pdev, sl);

	/* Initialize this pci_dev with the AMD iommu */
	ret = amd_iommu_init_device(pdev, GENZ_NUM_PASIDS);
	if (ret < 0) {
		dev_dbg(&pdev->dev,
			"amd_iommu_init_device failed with error %d\n",
			ret);
		goto err_pci_release_regions;
	}

	ret = wildcat_register_interrupts(pdev, sl);
	if (ret) {
		dev_dbg(&pdev->dev,
		      "wildcat_register_interrupts failed with ret=%d\n", ret);
		goto err_iommu_free;
	}

	if (sl->id == 0) {
		wildcat_slink_base_offset = wildcat_slink_base(br);
		dev_dbg(&pdev->dev,
			"wildcat_slink_base_offset=0x%llx\n",
			wildcat_slink_base_offset);
		/* register with Gen-Z subsystem on slice 0 only */
		ret = genz_register_bridge(&pdev->dev,
					   &wildcat_genz_bridge_driver, br);
		if (ret) {
			dev_dbg(&pdev->dev,
			      "genz_register_bridge failed with error %d\n",
			      ret);
			goto err_msg_qfree;
		}
		/* allocate driver-driver msg queues on slice 0 only */
		gzbr = genz_find_bridge(&pdev->dev);
		ret = wildcat_msg_qalloc(gzbr);
		if (ret) {
			dev_dbg(&pdev->dev,
			      "wildcat_msg_qalloc failed with error %d\n", ret);
			goto err_free_interrupts;
		}
	}
	pci_set_master(pdev);
	return 0;

err_msg_qfree:
	wildcat_msg_qfree(gzbr);

err_free_interrupts:
	wildcat_free_interrupts(pdev);

err_iommu_free:
	amd_iommu_free_device(pdev);

err_pci_release_regions:
	pci_release_regions(pdev);

err_pci_disable_device:
	pci_disable_device(pdev);

err_out:
	sl->valid = false;

	return ret;
}

static void wildcat_remove(struct pci_dev *pdev)
{
	struct slice *sl;
	struct genz_bridge_dev *gzbr;

	/* No teardown for function 0 */
	if (PCI_FUNC(pdev->devfn) == 0) {
		return;
	}

	sl = (struct slice *)pci_get_drvdata(pdev);

	dev_dbg(&pdev->dev, "device=%s, slice=%u\n",
		pci_name(pdev), sl->id);

	if (sl->id == 0) {
		gzbr = genz_find_bridge(&pdev->dev);
		wildcat_msg_qfree(gzbr);
		genz_unregister_bridge(&pdev->dev);
	}
	wildcat_free_interrupts(pdev);
	pci_clear_master(pdev);

	/* Remove our use of the IOMMU */
	amd_iommu_free_device(pdev);

	wildcat_zmmu_clear_slice(sl);
	pci_iounmap(pdev, sl->bar);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static int helper_init(struct subprocess_info *info, struct cred *new)
{
	pid_t               *pidp = info->data;

	*pidp = task_pid_vnr(current);
	return 0;
}

static void wildcat_helper_exit(void)
{
#ifdef OLD_ZHPE
	if (!helper_fdata)  /* Revisit: fix this */
		return;
#endif
	/* Revisit: finish this */
}

static struct pci_driver wildcat_pci_driver = {
	.name      = DRIVER_NAME,
	.id_table  = wildcat_id_table,
	.probe     = wildcat_probe,
	.remove    = wildcat_remove,
};

bool wildcat_mcommit;

/* Revisit: this should be in cpufeatures.h */
#ifndef X86_FEATURE_MCOMMIT
#define X86_FEATURE_MCOMMIT     (13*32+ 8) /* MCOMMIT instruction */
#endif

/* Revisit: this should be in msr-index.h */
#ifndef _EFER_MCOMMIT
#define _EFER_MCOMMIT           (17)
#define EFER_MCOMMIT            (1ULL<<_EFER_MCOMMIT)
#endif

static void __init wildcat_enable_mcommit(void *dummy)
{
	uint64_t            efer;

	/* Revisit: locking? */
	rdmsrl(MSR_EFER, efer);
	if (!(efer & EFER_MCOMMIT)) {
		efer |= EFER_MCOMMIT;
		wrmsrl(MSR_EFER, efer);
	}
}

static int __init wildcat_init(void)
{
	int                 ret;
	char                *argv[] = { helper_path, NULL };
	char                *envp[] = { NULL };
	struct subprocess_info *helper_info;
	uint                sl;

	ret = -ENOSYS;
	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD) {
		pr_warn("%s:%s:AMD CPU required\n",
			wildcat_driver_name, __func__);
		goto err_out;
	}
	ret = -EINVAL;
	if (!(wildcat_no_avx || boot_cpu_has(X86_FEATURE_AVX))) {
		pr_warn("%s:%s:missing required AVX CPU feature\n",
			wildcat_driver_name, __func__);
		goto err_out;
	}
	if (boot_cpu_has(X86_FEATURE_MCOMMIT)) {
		on_each_cpu(wildcat_enable_mcommit, NULL, 1);
		wildcat_mcommit = true;
		pr_info("%s:%s:mcommit supported and enabled\n",
			wildcat_driver_name, __func__);
	} else {
		pr_warn("%s:%s:mcommit not supported\n",
			wildcat_driver_name, __func__);
	}
	ret = -ENOMEM;
	spin_lock_init(&wildcat_bridge.zmmu_lock);
	mutex_init(&wildcat_bridge.csr_mutex);
	for (sl = 0; sl < SLICES; sl++) {
		spin_lock_init(&wildcat_bridge.slice[sl].zmmu_lock);
	}

	/* Create msg workqueue */
	wildcat_bridge.wildcat_msg_workq = create_workqueue("wildcat_wq");
	if (!wildcat_bridge.wildcat_msg_workq)
		goto err_out;

	/* Initiate call to wildcat_probe() for each wildcat PCI function */
	ret = pci_register_driver(&wildcat_pci_driver);
	if (ret < 0) {
		pr_warn("%s:%s:pci_register_driver ret = %d\n",
			wildcat_driver_name, __func__, ret);
		goto err_delete_workq;
	}

	/* Launch helper. */
	helper_info = call_usermodehelper_setup(helper_path, argv, envp,
						GFP_KERNEL, helper_init, NULL,
						&helper_pid);
	if (!helper_info) {
		pr_warn("%s:%s:call_usermodehelper_setup(%s) returned NULL\n",
			wildcat_driver_name, __func__, helper_path);
		ret = -ENOMEM;
		goto err_pci_unregister_driver;
	}
	ret = call_usermodehelper_exec(helper_info, UMH_WAIT_EXEC);
	if (ret < 0) {
		pr_warn("%s:%s:call_usermodehelper_exec(%s) returned %d\n",
			wildcat_driver_name, __func__, helper_path, ret);
		goto err_wildcat_helper_exit;
	}

	pr_info("%s:%s: helper_pid=%d, ret=%d\n",
		wildcat_driver_name, __func__,
		helper_pid, ret);

	return 0;

err_wildcat_helper_exit:
	wildcat_helper_exit();

err_pci_unregister_driver:
	/* Initiate call to wildcat_remove() for each wildcat PCI function */
	pci_unregister_driver(&wildcat_pci_driver);

err_delete_workq:
	destroy_workqueue(wildcat_bridge.wildcat_msg_workq);

err_out:
	return ret;
}

static void wildcat_exit(void)
{
	destroy_workqueue(wildcat_bridge.wildcat_msg_workq);

	/* Initiate call to wildcat_remove() for each wildcat PCI function */
	pci_unregister_driver(&wildcat_pci_driver);

	pr_info("%s:%s mem_total %lld\n",
		wildcat_driver_name, __func__, (long long)atomic64_read(&mem_total));
}
