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

MODULE_LICENSE("GPL");

struct bridge    wildcat_bridge = { 0 };

uint no_iommu = 0;
module_param(no_iommu, uint, S_IRUGO);
MODULE_PARM_DESC(no_iommu, "System does not have an IOMMU (default=0)");

#define TRACKER_MAX     (256)

/* Revisit Carbon: Gen-Z Global CID should come from bridge Core
 * Structure, but for now, it's a module parameter
 */
uint genz_gcid = 0x0000001;  /* Revisit Carbon: carbon node 1 */
module_param(genz_gcid, uint, S_IRUGO);
MODULE_PARM_DESC(genz_gcid, "Gen-Z bridge global CID");

uint genz_loopback = 1;
module_param(genz_loopback, uint, S_IRUGO);
MODULE_PARM_DESC(genz_loopback, "Gen-Z loopback mode (default=1)");

static char *helper_path = "/sbin/wildcat_helper";
module_param(helper_path, charp, 0444);
MODULE_PARM_DESC(helper_path, "path-to-helper");

static DECLARE_WAIT_QUEUE_HEAD(helper_wq);
static uint             helper_state = HELPER_STATE_INIT;
static uint32_t         helper_req_len;
static union wildcat_op helper_op;
static pid_t            helper_pid;
static struct file_data *helper_fdata = NULL;

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

void queue_zpages_free(union zpages *zpages)
{
	size_t              npages;
	size_t              i;
	struct page         *page;

	npages = zpages->queue.size >> PAGE_SHIFT;
	for (i = 0; i < npages; i++) {
		page = virt_to_page(zpages->queue.pages[i]);
		if (page_count(page) != 1 || page_mapcount(page) != 0)
			pr_warning("%s,%u:i %lu ptr/page/pfn 0x%p/0x%p/0x%lx c %d/%d\n",
				   __func__, __LINE__,
				   i, zpages->queue.pages[i],
				   page, page_to_pfn(page), page_count(page),
				   page_mapcount(page));
		do_free_pages(zpages->queue.pages[i], 0);
	}
}

void _zpages_free(const char *callf, uint line, union zpages *zpages)
{
	if (!zpages)
		return;

	pr_debug("zpages 0x%px\n", zpages);

	/* Revisit: most of these need zap_vma_ptes(vma, addr, size); */
	switch (zpages->hdr.page_type) {
	case QUEUE_PAGE:
	case LOCAL_SHARED_PAGE:
		queue_zpages_free(zpages);
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

	do_kfree(zpages);
}

/*
 * hsr_zpages_alloc - allocate a zpages structure for a single page of
 * HSR registers. This is used to map the QCM application data for queues.
 * The space for the HSRs is already allocated and mapped by the pci probe
 * function.
 * 	base_addr - pointer to the start of the QCM app first 64 bytes
 */
union zpages *_hsr_zpage_alloc(
	const char  *callf,
	uint        line,
	phys_addr_t base_addr)
{
	union zpages       *ret = NULL;

	pr_debug("page_type HSR_PAGE\n");

	/* kmalloc space for the return and an array of pages in the zpage struct */
	ret = do_kmalloc(sizeof(*ret), GFP_KERNEL, true);
	if (!ret)
		goto done;

	ret->hsr.page_type = HSR_PAGE;
	ret->hsr.size = PAGE_SIZE; /* always 1 page of HSRs */
	ret->hsr.base_addr = base_addr;

done:
	pr_debug("ret 0x%px\n", ret);
	return ret;
}

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
	ret = do_kmalloc(sizeof(*ret), GFP_KERNEL, true);
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
		do_kfree(ret);
		ret = NULL;
	}

done:
	pr_debug("ret 0x%px\n", ret);
	return ret;
}

/*
 * shared_zpage_alloc - allocate a single page for the shared data. It is
 * allocated at init and only free'ed at exit.
 */

union zpages *shared_zpage_alloc(size_t size, int type)
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
	ret = do_kmalloc(sizeof(*ret) + npages * sizeof(ret->queue.pages[0]),
			 GFP_KERNEL, true);
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
		do_kfree(ret);
		ret = NULL;
	}

done:
	pr_debug("ret 0x%px\n", ret);
	return ret;
}

/*
 * rmr_zpages_alloc - allocate a zpages structure for a cpu-visible RMR_IMPORT.
 * This is used to map the requester ZMMU PTE.
 * 	rmr - pointer to the corresponding rmr structure
 */
union zpages *_rmr_zpages_alloc(const char *callf, uint line,
                                struct zhpe_rmr *rmr)
{
	union zpages       *ret = NULL;

	pr_debug("page_type RMR_PAGE\n");

	/* kmalloc space for the return struct */
	ret = do_kmalloc(sizeof(*ret), GFP_KERNEL, true);
	if (!ret)
		goto done;

	ret->rmrz.page_type = RMR_PAGE;
	ret->rmrz.size = rmr->pte_info->length_adjusted;
	ret->rmrz.rmr = rmr;

done:
	pr_debug("ret 0x%px\n", ret);
	return ret;
}

#ifdef OLD_ZHPE
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
    pr_warning("%s:%s IOMMU PRR failure device = %s, pasid = %d address = 0x%lx flags = %ux\n",
          wildcat_driver_name, __func__, pci_name(pdev), pasid,
          address, flags);

    return AMD_IOMMU_INV_PRI_RSP_INVALID;
}

static int zhpe_bind_iommu(struct file_data *fdata)
{
    int s, ret = 0;
    struct pci_dev *pdev;

    if (!no_iommu) {
        spin_lock(&fdata->io_lock);
        for (s=0; s<SLICES; s++) {
            if (!SLICE_VALID(&(fdata->md.bridge->slice[s])))
                continue;
            pdev = fdata->md.bridge->slice[s].pdev;
            ret = amd_iommu_bind_pasid(pdev, fdata->pasid, current);
            if (ret < 0) {
                pr_debug("amd_iommu_bind_pasid failed for slice %d with return %d\n", s, ret);
            }
            amd_iommu_set_invalid_ppr_cb(pdev, iommu_invalid_ppr_cb);
        }
        spin_unlock(&fdata->io_lock);
    }
    return (ret);
}

static void zhpe_unbind_iommu(struct file_data *fdata)
{
    int s;
    struct pci_dev *pdev;

    spin_lock(&fdata->io_lock);
    if (!no_iommu) {
	for (s=0; s<SLICES; s++) {
            if (!SLICE_VALID(&(fdata->md.bridge->slice[s])))
                continue;
            pdev = fdata->md.bridge->slice[s].pdev;
            amd_iommu_unbind_pasid(pdev, fdata->pasid);
            amd_iommu_set_invalid_ppr_cb(pdev, NULL);
        }
    }
    spin_unlock(&fdata->io_lock);
    return;
}

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

#define vma_set_page_prot zhpe_vma_set_page_prot
#define vm_pgprot_modify zhpe_pgprot_modify
#define vma_wants_writenotify zhpe_vma_wants_writenotify

/* Revisit: copy actual vma_wants_writenotify? */
static inline int zhpe_vma_wants_writenotify(struct vm_area_struct *vma,
                                             pgprot_t vm_page_prot)
{
    return 0;
}

/* identical to vm_pgprot_modify, except for function name */
static pgprot_t zhpe_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
{
        return pgprot_modify(oldprot, vm_get_page_prot(vm_flags));
}

/* identical to vma_set_page_prot, except for function name */
void zhpe_vma_set_page_prot(struct vm_area_struct *vma)
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

struct file_data *wildcat_pid_to_fdata(struct bridge *br, pid_t pid)
{
    struct file_data *cur, *ret = NULL;

    spin_lock(&br->fdata_lock);
    list_for_each_entry(cur, &br->fdata_list, fdata_list) {
        if (cur->pid == pid) {
            ret = cur;
            break;
        }
    }
    spin_unlock(&br->fdata_lock);
    return ret;
}

void wildcat_init_mem_data(struct mem_data *mdata, struct bridge *br)
{
    mdata->bridge = br;
    spin_lock_init(&mdata->uuid_lock);
    mdata->local_uuid = NULL;
    mdata->md_remote_uuid_tree = RB_ROOT;
    spin_lock_init(&mdata->md_lock);
    mdata->md_mr_tree = RB_ROOT;
    mdata->md_rmr_tree = RB_ROOT;
}

struct slice *slice_id_to_slice(struct file_data *fdata, int slice)
{
    struct slice *sl;
    int i;

    for (i = 0; i < SLICES; i++) {
        if (fdata->md.bridge->slice[i].id == slice)
            return sl;
    }
    return NULL;
}

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
static int zhpe_core_alloc_queues(void *hw, uint xdm_cmdq_ent,
				  uint xdm_cmplq_ent, uint rdm_cmplq_ent)
{
	int ret = 0;
	struct bridge *br = (struct bridge *)hw;
	struct enic *enic;
	struct xdm_info *xdmi;
	struct rdm_info *req_rdmi, *rsp_rdmi;

	/* Revisit: locking */
	if (!br || !br->enic) {
		ret = -EINVAL;
		goto done;
	}

	enic = br->enic;
	xdmi = &enic->xdmi;
	req_rdmi = &enic->req_rdmi;
	rsp_rdmi = &enic->rsp_rdmi;

	/* Set up the XDM info structure */
	xdmi->br = br;
	xdmi->cmdq_ent = xdm_cmdq_ent;
	xdmi->cmplq_ent = xdm_cmplq_ent;
	xdmi->traffic_class = ZHPE_TC_0;
	xdmi->priority = 0;
	xdmi->slice_mask = ALL_SLICES;
	xdmi->cur_valid = 1;
	ret = zhpe_kernel_XQALLOC(xdmi);
	if (ret)
		goto done;

	/* Set up the request RDM info structure */
	req_rdmi->br = br;
	req_rdmi->cmplq_ent = rdm_cmplq_ent;
	/* any slice other than the XDM slice */
	req_rdmi->slice_mask = ~(1u << xdmi->slice) & ALL_SLICES;
	req_rdmi->cur_valid = 1;
	ret = zhpe_kernel_RQALLOC(req_rdmi);
	if (ret)
		goto xqfree;

	/* Set up the response RDM info structure */
	rsp_rdmi->br = br;
	rsp_rdmi->cmplq_ent = rdm_cmplq_ent;
	/* any slice other than the XDM or request RDM slices */
	rsp_rdmi->slice_mask = ~((1u << xdmi->slice) | (1u << req_rdmi->slice))
            & ALL_SLICES;
	rsp_rdmi->cur_valid = 1;
	ret = zhpe_kernel_RQALLOC(rsp_rdmi);
	if (ret)
		goto rqfree;

	/* clear stop bits - queues are now ready */
	xdm_qcm_write_val(0, xdmi->hw_qcm_addr, XDM_STOP_OFFSET);
	rdm_qcm_write_val(0, req_rdmi->hw_qcm_addr, RDM_STOP_OFFSET);
	rdm_qcm_write_val(0, rsp_rdmi->hw_qcm_addr, RDM_STOP_OFFSET);

	return 0;

rqfree:
	zhpe_kernel_RQFREE(req_rdmi);
xqfree:
	zhpe_kernel_XQFREE(xdmi);

done:
	return ret;
}

static int zhpe_core_free_queues(void *hw)
{
	struct bridge *br = (struct bridge *)hw;
	int ret = 0;

	if (!br->enic) {
		ret = -EINVAL;
		goto done;
	}

	zhpe_kernel_XQFREE(&br->enic->xdmi);
	zhpe_kernel_RQFREE(&br->enic->req_rdmi);
	zhpe_kernel_RQFREE(&br->enic->rsp_rdmi);

 done:
	return ret;
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
		zpages_free(zpages);
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
	zpages_free(zpage);
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
		enic = do_kmalloc(sizeof(*enic), GFP_KERNEL, true);
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
	struct mem_data *mdata = &enic->md;

	zhpe_rmr_free_all(mdata);
	zhpe_notify_remote_uuids(mdata);
	zhpe_umem_free_all(mdata, NULL);
	zhpe_free_remote_uuids(mdata);
	(void)zhpe_free_local_uuid(mdata, true); /* also frees associated R-keys */
	/* Revisit: what else do we need to clean up? */
	if (br)
		br->enic = 0;
	do_kfree(enic);
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

static struct genz_bridge_info wildcat_br_info = {
	.req_zmmu            = 1,
	.rsp_zmmu            = 1,
	.xdm                 = 1,
	.rdm                 = 1,
	.nr_req_page_grids   = WILDCAT_PAGE_GRID_ENTRIES,
	.nr_rsp_page_grids   = WILDCAT_PAGE_GRID_ENTRIES,
	.nr_req_ptes         = REQ_ZMMU_ENTRIES,
	.nr_rsp_ptes         = RSP_ZMMU_ENTRIES,
	.min_cpuvisible_addr = WILDCAT_MIN_CPUVISIBLE_ADDR,
	.max_cpuvisible_addr = WILDCAT_MAX_CPUVISIBLE_ADDR,
};

static int wildcat_bridge_info(struct genz_dev *zdev,
			       struct genz_bridge_info *info)
{
	if (!zdev_is_local_bridge(zdev))
		return -EINVAL;

	*info = wildcat_br_info;
	return 0;
}

static struct genz_bridge_driver wildcat_genz_bridge_driver = {
	.bridge_info = wildcat_bridge_info;
};

#define WILDCAT_ZMMU_XDM_RDM_HSR_BAR 0

static int wildcat_probe(struct pci_dev *pdev,
			 const struct pci_device_id *pdev_id)
{
	int ret, pos;
	int l_slice_id;
	void __iomem *base_addr;
	struct bridge *br = &wildcat_bridge;
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

	debug(DEBUG_PCI, "%s:%s device = %s, slice = %u\n",
	      wildcat_driver_name, __func__, pci_name(pdev), l_slice_id);

	ret = pci_enable_device(pdev);
	if (ret) {
		debug(DEBUG_PCI,
		      "%s:%s:pci_enable_device probe error %d for device %s\n",
		      wildcat_driver_name, __func__, ret, pci_name(pdev));
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
		debug(DEBUG_PCI,
		      "%s:%s:pci_request_regions error %d for device %s\n",
		      wildcat_driver_name, __func__, ret, pci_name(pdev));
		goto err_pci_disable_device;
	}

	base_addr = pci_iomap(pdev, WILDCAT_ZMMU_XDM_RDM_HSR_BAR,
			      sizeof(struct func1_bar0));
	if (!base_addr) {
		debug(DEBUG_PCI,
		      "%s:%s:cannot iomap bar %u registers of size %lu (requested size = %lu)\n",
		      wildcat_driver_name, __func__,
		      WILDCAT_ZMMU_XDM_RDM_HSR_BAR,
		      (unsigned long) pci_resource_len(
			      pdev, WILDCAT_ZMMU_XDM_RDM_HSR_BAR),
		      sizeof(struct func1_bar0));
		ret = -EINVAL;
		goto err_pci_release_regions;
	}
	phys_base = pci_resource_start(pdev, 0);

	debug(DEBUG_PCI,
	      "%s:%s bar = %u, start = 0x%lx, actual len = %lu, requested len = %lu, base_addr = 0x%lx\n",
	      wildcat_driver_name, __func__, 0,
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
	wildcat_zmmu_setup_slice(sl);

	wildcat_xqueue_init(sl);
	if (wildcat_clear_xdm_qcm(sl->bar->xdm)) {
		debug(DEBUG_PCI, "wildcat_clear_xdm_qcm failed\n");
		ret = -1;
		goto err_pci_release_regions;
	}

	wildcat_rqueue_init(sl);
	if (wildcat_clear_rdm_qcm(sl->bar->rdm)) {
		debug(DEBUG_PCI, "wildcat_clear_rdm_qcm failed\n");
		ret = -1;
		goto err_pci_release_regions;
	}

	pci_set_drvdata(pdev, sl);

	/* Initialize this pci_dev with the AMD iommu */
	if (!no_iommu) {
		ret = amd_iommu_init_device(pdev, WILDCAT_NUM_PASIDS);
		if (ret < 0) {
			debug(DEBUG_PCI,
			      "amd_iommu_init_device failed with error %d\n",
			      ret);
			goto err_pci_release_regions;
		}
	}

	ret = wildcat_register_interrupts(pdev, sl);
	if (ret) {
		debug(DEBUG_PCI,
		      "wildcat_register_interrupts failed with ret=%d\n", ret);
		goto err_iommu_free;
	}

	if (sl->id == 0) {
		/* allocate driver-driver msg queues on slice 0 only */
		ret = wildcat_msg_qalloc(br);
		if (ret) {
			debug(DEBUG_PCI,
			      "wildcat_msg_qalloc failed with error %d\n", ret);
			goto err_free_interrupts;
		}
		/* register with Gen-Z subsystem on slice 0 only */
		ret = genz_register_bridge(&pdev->dev,
					   &wildcat_genz_bridge_driver);
		if (ret) {
			debug(DEBUG_PCI,
			      "genz_register_bridge failed with error %d\n",
			      ret);
			goto err_msg_qfree;
		}
	}
	pci_set_master(pdev);
	return 0;

err_msg_qfree:
        wildcat_msg_qfree(br);

err_free_interrupts:
	wildcat_free_interrupts(pdev);

err_iommu_free:
	if (!no_iommu) {
		amd_iommu_free_device(pdev);
	}

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

	/* No teardown for function 0 */
	if (PCI_FUNC(pdev->devfn) == 0) {
		return;
	}

	sl = (struct slice *)pci_get_drvdata(pdev);

	debug(DEBUG_PCI, "%s:%s device = %s, slice = %u\n",
	      wildcat_driver_name, __func__, pci_name(pdev), sl->id);

	if (sl->id == 0) {
		genz_unregister_bridge(&pdev->dev);
		wildcat_msg_qfree(BRIDGE_FROM_SLICE(sl));
	}
	wildcat_free_interrupts(pdev);
	pci_clear_master(pdev);

	/* If we are using the IOMMU, free the device */
	if (!no_iommu) {
		amd_iommu_free_device(pdev);
	}

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
	if (!helper_fdata)
		return;

	/* Revisit: finish this */
}

static struct miscdevice miscdev = {
	.name               = wildcat_driver_name,
	.fops               = &wildcat_fops,
	.minor              = MISC_DYNAMIC_MINOR,
	.mode               = 0600,
};

static struct pci_driver wildcat_pci_driver = {
	.name      = DRIVER_NAME,
	.id_table  = wildcat_id_table,
	.probe     = wildcat_probe,
	.remove    = wildcat_remove,
};

static int __init wildcat_init(void)
{
    int                 ret;
    char                *argv[] = { helper_path, NULL };
    char                *envp[] = { NULL };
    int                 i;
    struct wildcat_attr default_attr = {
        .max_tx_queues      = 1024,
        .max_rx_queues      = 1024,
        .max_hw_qlen        = 65535,
        .max_sw_qlen        = 65535,
        .max_dma_len        = (1U << 31),
    };
    struct subprocess_info *helper_info;
    uint                sl, pg, cnt, pg_index;

    ret = -EINVAL;
    if (!(wildcat_no_avx || boot_cpu_has(X86_FEATURE_AVX))) {
        pr_warning("%s:%s:missing required AVX CPU feature.\n",
               wildcat_driver_name, __func__);
        goto err_out;
    }
    ret = -ENOMEM;
    global_shared_zpage = shared_zpage_alloc(sizeof(*global_shared_data), GLOBAL_SHARED_PAGE);
    if (!global_shared_zpage) {
        pr_warning("%s:%s:queue_zpages_alloc failed.\n",
               wildcat_driver_name, __func__);
        goto err_out;
    }
    global_shared_data = global_shared_zpage->queue.pages[0];
    global_shared_data->magic = WILDCAT_MAGIC;
    global_shared_data->version = WILDCAT_GLOBAL_SHARED_VERSION;
    global_shared_data->debug_flags = wildcat_debug_flags;
    global_shared_data->default_attr = default_attr;
    for (i = 0; i < MAX_IRQ_VECTORS; i++)
	global_shared_data->triggered_counter[i] = 0;

    wildcat_bridge.gcid = genz_gcid;
    spin_lock_init(&wildcat_bridge.zmmu_lock);
    for (sl = 0; sl < SLICES; sl++) {
        spin_lock_init(&wildcat_bridge.slice[sl].zmmu_lock);
    }
    spin_lock_init(&wildcat_bridge.fdata_lock);
    INIT_LIST_HEAD(&wildcat_bridge.fdata_list);

    debug(DEBUG_ZMMU, "%s:%s,%u: calling wildcat_zmmu_clear_all\n",
          wildcat_driver_name, __func__, __LINE__);
    wildcat_zmmu_clear_all(&wildcat_bridge, false);
    debug(DEBUG_ZMMU, "%s:%s,%u: calling wildcat_pasid_init\n",
          wildcat_driver_name, __func__, __LINE__);
    wildcat_pasid_init();
    debug(DEBUG_RKEYS, "%s:%s,%u: calling wildcat_rkey_init\n",
          wildcat_driver_name, __func__, __LINE__);
    wildcat_rkey_init();

    /* Create 128 polling devices for interrupt notification to user space */
    if (wildcat_setup_poll_devs() != 0)
        goto err_zpage_free;

    /* Create msg workqueue */
    wildcat_bridge.wildcat_msg_workq = create_workqueue("wildcat_wq");
    if (!wildcat_bridge.wildcat_msg_workq)
	goto err_cleanup_poll_devs;

    /* Initiate call to wildcat_probe() for each wildcat PCI function */
    ret = pci_register_driver(&wildcat_pci_driver);
    if (ret < 0) {
        pr_warning("%s:%s:pci_register_driver ret = %d\n",
               wildcat_driver_name, __func__, ret);
        goto err_delete_workq;
    }

    /* Create device. */
    debug(DEBUG_IO, "%s:%s,%u: creating device\n",
          wildcat_driver_name, __func__, __LINE__);
    ret = misc_register(&miscdev);
    if (ret < 0) {
        pr_warning("%s:%s:misc_register() returned %d\n",
               wildcat_driver_name, __func__, ret);
        goto err_pci_unregister_driver;
    }

    wildcat_poll_init_waitqueues(&wildcat_bridge);

    /* Launch helper. */
    helper_info = call_usermodehelper_setup(helper_path, argv, envp,
                                            GFP_KERNEL, helper_init, NULL,
                                            &helper_pid);
    if (!helper_info) {
        pr_warning("%s:%s:call_usermodehelper_setup(%s) returned NULL\n",
               wildcat_driver_name, __func__, helper_path);
        ret = -ENOMEM;
        goto err_misc_deregister;
    }
    ret = call_usermodehelper_exec(helper_info, UMH_WAIT_EXEC);
    if (ret < 0) {
        pr_warning("%s:%s:call_usermodehelper_exec(%s) returned %d\n",
               wildcat_driver_name, __func__, helper_path, ret);
        goto err_wildcat_helper_exit;
    }

    pr_info("%s:%s:%s %s, helper_pid = %d, ret = %d\n",
           wildcat_driver_name, __func__, __DATE__, __TIME__, helper_pid, ret);

    return 0;

err_wildcat_helper_exit:
    wildcat_helper_exit();

err_misc_deregister:
    misc_deregister(&miscdev);

err_pci_unregister_driver:
    /* Initiate call to wildcat_remove() for each wildcat PCI function */
    pci_unregister_driver(&wildcat_pci_driver);

err_delete_workq:
    destroy_workqueue(wildcat_bridge.wildcat_msg_workq);

err_cleanup_poll_devs:
    wildcat_cleanup_poll_devs();

err_zpage_free:
    if (global_shared_zpage) {
        queue_zpages_free(global_shared_zpage);
        do_kfree(global_shared_zpage);
    }

err_out:
    return ret;
}

static void wildcat_exit(void)
{
    if (miscdev.minor != MISC_DYNAMIC_MINOR)
        misc_deregister(&miscdev);

    wildcat_cleanup_poll_devs();

    /* free shared data page. */
    if (global_shared_zpage) {
        queue_zpages_free(global_shared_zpage);
        do_kfree(global_shared_zpage);
    }

    destroy_workqueue(wildcat_bridge.wildcat_msg_workq);

    /* Initiate call to wildcat_remove() for each wildcat PCI function */
    pci_unregister_driver(&wildcat_pci_driver);

    wildcat_zmmu_clear_all(&wildcat_bridge, true);
    wildcat_rkey_exit();
    wildcat_pasid_exit();
    wildcat_uuid_exit();

    pr_info("%s:%s mem_total %lld\n",
           wildcat_driver_name, __func__, (llong)atomic64_read(&mem_total));
}
