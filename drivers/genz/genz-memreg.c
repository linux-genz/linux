// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2018-2019 Hewlett Packard Enterprise Development LP.
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
#include <linux/pci.h>
#include <linux/hugetlb.h>
#include <linux/sched/signal.h>

#include "genz.h"

#define USER_ACCESS(_acc)  ((_acc) & ~(GENZ_MR_REQ|GENZ_MR_RSP))

static void umem_free(struct kref *ref);  /* forward references */
static void pte_info_free(struct kref *ref);

bool genz_gcid_is_local(struct genz_bridge_dev *br, uint32_t gcid)
{
	/* Revisit: handle multiple bridge CIDs */
	return (genz_dev_gcid(&br->zdev, 0) == gcid);
}

void genz_init_mem_data(struct genz_mem_data *mdata,
			struct genz_bridge_dev *br)
{
	mdata->bridge = br;
	spin_lock_init(&mdata->uuid_lock);
	mdata->local_uuid = NULL;
	mdata->md_remote_uuid_tree = RB_ROOT;
	spin_lock_init(&mdata->md_lock);
	mdata->md_mr_tree = RB_ROOT;
	mdata->md_rmr_tree = RB_ROOT;
}
EXPORT_SYMBOL(genz_init_mem_data);

static inline int umem_cmp(uint64_t vaddr, uint64_t length, uint64_t access,
			   const struct genz_umem *u)
{
	int cmp;
	const struct genz_pte_info *info = u->pte_info;

	cmp = arithcmp(vaddr, u->vaddr);
	if (cmp)
		return cmp;
	cmp = arithcmp(length, info->length);
	if (cmp)
		return cmp;
	return arithcmp(USER_ACCESS(access), USER_ACCESS(info->access));
}

struct genz_umem *genz_umem_search(struct genz_mem_data *mdata,
				   uint64_t vaddr, uint64_t length,
				   uint64_t access, uint64_t rsp_zaddr)
{
	struct genz_umem *unode;
	struct rb_node *rnode;
	struct rb_root *root = &mdata->md_mr_tree;

	/* caller must already hold mdata->md_lock */
	rnode = root->rb_node;

	while (rnode) {
		int64_t result;

		unode = container_of(rnode, struct genz_umem, node);
		result = umem_cmp(vaddr, length, access, unode);
		if (result < 0) {
			rnode = rnode->rb_left;
		} else if (result > 0) {
			rnode = rnode->rb_right;
		} else {
			if (rsp_zaddr == genz_zmmu_pte_addr(unode->pte_info,
							    unode->vaddr))
				goto out;
			else
				goto fail;
		}
	}

 fail:
	unode = NULL;

 out:
	return unode;
}
EXPORT_SYMBOL(genz_umem_search);

static struct genz_umem *umem_insert(struct genz_umem *umem)
{
	struct genz_pte_info *info = umem->pte_info;
	struct genz_mem_data *mdata = umem->mdata;
	struct rb_root *root;
	struct rb_node **new, *parent = NULL;
	ulong flags;

	spin_lock_irqsave(&mdata->md_lock, flags);
	root = &mdata->md_mr_tree;
	new = &root->rb_node;

	/* figure out where to put new node */
	while (*new) {
		struct genz_umem *this =
			container_of(*new, struct genz_umem, node);
		int64_t result = umem_cmp(umem->vaddr, info->length,
					  info->access, this);

		parent = *new;
		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {  /* already there */
			umem = this;
			kref_get(&umem->refcount);
			goto out;
		}
	}

	/* add new node and rebalance tree */
	rb_link_node(&umem->node, parent, new);
	rb_insert_color(&umem->node, root);
	umem->erase = true;

 out:
	spin_unlock_irqrestore(&mdata->md_lock, flags);
	return umem;
}

void genz_umem_remove(struct genz_umem *umem)
{
	/* caller must already hold mdata->md_lock */
	kref_put(&umem->refcount, umem_free);
}
EXPORT_SYMBOL(genz_umem_remove);

static inline void pte_info_remove(struct genz_pte_info *info)
{
	if (info)
		kref_put(&info->refcount, pte_info_free);
}

/* Returns the offset of the umem start relative to the first page */
static inline int genz_umem_offset(struct genz_umem *umem)
{
	return umem->vaddr & (BIT(umem->page_shift) - 1);
}

/* Returns the first page of a umem */
static inline unsigned long genz_umem_start(struct genz_umem *umem)
{
	return umem->vaddr - genz_umem_offset(umem);
}

/* Returns the address of the page after the last one of a umem */
static inline unsigned long genz_umem_end(struct genz_umem *umem)
{
	return ALIGN(umem->vaddr + umem->pte_info->length,
		     BIT(umem->page_shift));
}

static inline size_t genz_umem_num_pages(struct genz_umem *umem)
{
	return (genz_umem_end(umem) - genz_umem_start(umem)) >>
		umem->page_shift;
}

/**
 * genz_dma_map_sg_attrs - Map a scatter/gather list to DMA addresses
 * @br: The genz_bridge_dev for which the DMA addresses are to be created
 * @sg: The array of scatter/gather entries
 * @nents: The number of scatter/gather entries
 * @direction: The direction of the DMA
 * @dma_attrs: The DMA attributes
 */
static inline int genz_dma_map_sg_attrs(struct genz_bridge_dev *br,
					struct scatterlist *sg, int nents,
					enum dma_data_direction direction,
					unsigned long dma_attrs)
{
	int ret = 0;

	/* Revisit: add default implementation for "normal" bridges */
	if (!br->zbdrv->dma_map_sg_attrs) {
		ret = -EINVAL;
		goto out;
	}

	ret = br->zbdrv->dma_map_sg_attrs(br, sg, nents, direction, dma_attrs);

out:
	return ret;
}

/**
 * genz_dma_unmap_sg_attrs - Unmap a scatter/gather list of DMA addresses
 * @br: The genz_bridge_dev for which the DMA addresses were created
 * @sg: The array of scatter/gather entries
 * @nents: The number of scatter/gather entries
 * @direction: The direction of the DMA
 * @dma_attrs: The DMA attributes
 */
static inline void genz_dma_unmap_sg_attrs(struct genz_bridge_dev *br,
					   struct scatterlist *sg, int nents,
					   enum dma_data_direction direction,
					   unsigned long dma_attrs)
{
	/* Revisit: add default implementation for "normal" bridges */
	if (!br->zbdrv->dma_unmap_sg_attrs) {
		return;
	}

	br->zbdrv->dma_unmap_sg_attrs(br, sg, nents, direction, dma_attrs);
}

static void _genz_umem_release(struct genz_umem *umem)
{
	struct genz_mem_data  *mdata = umem->mdata;
	struct scatterlist    *sg;
	struct page           *page;
	int                   i;

	if (!umem->need_release)
		return;

	if (umem->nmap > 0)
		genz_dma_unmap_sg_attrs(mdata->bridge, umem->sg_head.sgl,
					umem->npages,
					DMA_BIDIRECTIONAL, 0);

	for_each_sg(umem->sg_head.sgl, sg, umem->npages, i) {
		page = sg_page(sg);
		if (!PageDirty(page) && umem->writable && umem->dirty)
			set_page_dirty_lock(page);
		put_page(page);
	}

	sg_free_table(&umem->sg_head);
	if (current->mm) {  /* No mm if called from process cleanup */
		atomic64_sub(umem->npages, &current->mm->pinned_vm);
	}
}

static inline long genz_get_user_pages(
	unsigned long start, unsigned long nr_pages, bool write, bool force,
	struct page **pages, struct vm_area_struct **vmas)
{
	unsigned int        gup_flags;

	gup_flags = (write ? FOLL_WRITE : 0) | (force ? FOLL_FORCE : 0);
	/* Revisit: new code shouldn't call get_user_pages */
	return get_user_pages(start, nr_pages, gup_flags, pages, vmas);
}

static int genz_umem_pin(struct genz_umem *umem)
{
	struct page **page_list;
	struct vm_area_struct **vma_list;
	uint64_t vaddr;
	unsigned long locked;
	unsigned long lock_limit;
	unsigned long cur_base;
	unsigned long npages;
	int ret;
	int i;
	struct scatterlist *sg, *sg_list_start;
	unsigned long dma_attrs = 0;

	page_list = (struct page **)__get_free_page(GFP_KERNEL);
	if (!page_list) {
		kfree(umem);
		pr_debug("failed to allocate page_list\n");
		return -ENOMEM;
	}

	/*
	 * if we can't alloc the vma_list, it's not so bad;
	 * just assume the memory is not hugetlb memory
	 */
	vma_list = (struct vm_area_struct **)__get_free_page(GFP_KERNEL);
	if (!vma_list)
		umem->hugetlb = 0;

	vaddr = umem->vaddr;
	npages = genz_umem_num_pages(umem);
	down_write(&current->mm->mmap_sem);
	locked     = atomic64_add_return(npages, &current->mm->pinned_vm);
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	if ((locked > lock_limit) && !capable(CAP_IPC_LOCK)) {
		atomic64_sub(npages, &current->mm->pinned_vm);
		ret = -ENOMEM;
		pr_debug("locked (%lu) > lock_limit (%lu)\n",
			 locked, lock_limit);
		goto out;
	}

	cur_base = vaddr & PAGE_MASK;

	if (npages == 0 || npages > UINT_MAX) {
		ret = -EINVAL;
		pr_debug("invalid npages (%lu)\n", npages);
		goto out;
	}

	ret = sg_alloc_table(&umem->sg_head, npages, GFP_KERNEL);
	if (ret) {
		pr_debug("sg_alloc_table failed\n");
		goto out;
	}

	umem->need_release = true;
	sg_list_start = umem->sg_head.sgl;

	while (npages) {
		ret = genz_get_user_pages(
			cur_base, min_t(unsigned long, npages,
					PAGE_SIZE / sizeof (struct page *)),
			true, !umem->writable, page_list, vma_list);
		if (ret < 0) {
			pr_debug("genz_get_user_pages(0x%lx, %lu) failed\n",
				 cur_base, npages);
			goto out;
		}

		umem->npages += ret;
		//current->mm->pinned_vm += ret; /* Revisit */
		cur_base += ret * PAGE_SIZE;
		npages   -= ret;

		for_each_sg(sg_list_start, sg, ret, i) {
			if (vma_list && !is_vm_hugetlb_page(vma_list[i]))
				umem->hugetlb = 0;

			sg_set_page(sg, page_list[i], PAGE_SIZE, 0);
		}

		/* preparing for next loop */
		sg_list_start = sg;
	}

	/* Revisit: set DMA direction based on access flags? */
	umem->nmap = genz_dma_map_sg_attrs(
		umem->mdata->bridge, umem->sg_head.sgl, umem->npages,
		DMA_BIDIRECTIONAL, dma_attrs);
	if (umem->nmap <= 0) {
		ret = -ENOMEM;
		pr_debug("genz_dma_map_sg_attrs failed\n");
		goto out;
	}

	ret = 0;

 out:
	up_write(&current->mm->mmap_sem);
	if (vma_list)
		free_page((unsigned long)vma_list);
	free_page((unsigned long)page_list);
	return ret;
}

/**
 * genz_umem_get - Pin and DMA map userspace memory.
 *
 * @mdata:   memory context to pin memory for
 * @vaddr:   virtual address to start at
 * @size:    length of region to pin
 * @access:  GENZ_MR_xxx flags for memory being pinned
 * @pasid:   userspace PASID to use, or NO_PASID
 * @kernel:  request is for kernel, not userspace
 */
struct genz_umem *genz_umem_get(struct genz_mem_data *mdata, uint64_t vaddr,
				size_t size, uint64_t access,
				uint pasid, uint32_t ro_rkey, uint32_t rw_rkey,
				bool kernel)
{
	struct genz_umem *umem, *found;
	struct genz_pte_info *info;
	int ret = 0;
	ulong flags;

	/*
	 * If the combination of the addr and size requested for this memory
	 * region causes an integer overflow, return error.
	 */
	if (((vaddr + size) < vaddr) ||
	    PAGE_ALIGN(vaddr + size) < (vaddr + size))
		return ERR_PTR(-EINVAL);

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return ERR_PTR(-ENOMEM);
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		kfree(umem);
		return ERR_PTR(-ENOMEM);
	}

	umem->pte_info    = info;
	umem->mdata       = mdata;
	info->bridge      = mdata->bridge;
	umem->vaddr       = vaddr;
	info->addr        = vaddr;
	umem->size        = size;
	info->length      = size;
	info->access      = USER_ACCESS(access) | GENZ_MR_RSP;
	info->space_type  = GENZ_DATA;  /* the only supported type */
	info->pasid       = pasid;
	info->rsp.ro_rkey = ro_rkey;
	info->rsp.rw_rkey = rw_rkey;
	umem->page_shift  = PAGE_SHIFT;
	umem->writable    = !!(access & (GENZ_MR_GET|GENZ_MR_PUT_REMOTE));
	/* We assume the memory is from hugetlb until proven otherwise */
	umem->hugetlb     = 1;
	kref_init(&umem->refcount);
	kref_init(&info->refcount);

	pr_debug("vaddr=0x%016llx, size=0x%zx, access=0x%llx, pasid=%u, kernel=%u\n",
		 vaddr, size, access, pasid, kernel);

	found = umem_insert(umem);
	if (found != umem) {
		kfree(umem);
		return found;
	}

	if (!kernel)
		ret = genz_umem_pin(umem);
	if (ret < 0) {
		spin_lock_irqsave(&mdata->md_lock, flags);
		genz_umem_remove(umem);
		spin_unlock_irqrestore(&mdata->md_lock, flags);
	} else
		umem->dirty = true;

	return ret < 0 ? ERR_PTR(ret) : umem;
}
EXPORT_SYMBOL(genz_umem_get);

static void pte_info_free(struct kref *ref)
{
	/* caller must already hold mdata->md_lock */
	struct genz_pte_info *info = container_of(
		ref, struct genz_pte_info, refcount);
	uint64_t             access;
	bool                 local, remote, cpu_visible, individual, req, rsp;

	access = info->access;
	local = !!(access & (GENZ_MR_GET|GENZ_MR_PUT));
	remote = !!(access & (GENZ_MR_GET_REMOTE|GENZ_MR_PUT_REMOTE));
	cpu_visible = !!(access & GENZ_MR_REQ_CPU);
	individual = !!(access & GENZ_MR_INDIVIDUAL);
	req = !!(access & GENZ_MR_REQ);
	rsp = !!(access & GENZ_MR_RSP);
	if (remote && rsp) {
		genz_zmmu_rsp_pte_free(info);
		/* Revisit: do TAKE_SNAPSHOT IOMMU teardown sequence */
	}
	if (remote && req) {
		genz_zmmu_req_pte_free(info);
	}
	kfree(info);
}

static void umem_free(struct kref *ref)
{
	/* caller must already hold mdata->md_lock */
	struct genz_umem *umem = container_of(ref, struct genz_umem, refcount);
	struct genz_pte_info *info = umem->pte_info;
	struct genz_mem_data *mdata = umem->mdata;
	struct rb_root   *root = &mdata->md_mr_tree;

	pte_info_remove(info);
	if (umem->erase)
		rb_erase(&umem->node, root);
	_genz_umem_release(umem);
	kfree(umem);
}

void genz_umem_free_all(struct genz_mem_data *mdata,
			struct genz_pte_info **humongous_zmmu_rsp_pte)
{
	struct rb_node *rb, *next;
	struct genz_umem *umem;
	struct genz_pte_info *info;
	ulong flags;

	spin_lock_irqsave(&mdata->md_lock, flags);

	for (rb = rb_first_postorder(&mdata->md_mr_tree); rb; rb = next) {
		umem = container_of(rb, struct genz_umem, node);
		info = umem->pte_info;
		pr_debug("vaddr=0x%016llx, len=0x%zx, access=0x%llx\n",
			 umem->vaddr, info->length, info->access);
		next = rb_next_postorder(rb);  /* must precede umem_free() */
		umem->erase = false;
		umem_free(&umem->refcount);
	}

	mdata->md_mr_tree = RB_ROOT;
	if (humongous_zmmu_rsp_pte && *humongous_zmmu_rsp_pte) {
		pte_info_remove(*humongous_zmmu_rsp_pte);
		*humongous_zmmu_rsp_pte = NULL;
	}
	spin_unlock_irqrestore(&mdata->md_lock, flags);
}
EXPORT_SYMBOL(genz_umem_free_all);

static inline int rmr_cmp(uint32_t dgcid, uint64_t rsp_zaddr,
			  uint64_t length, uint64_t access,
			  const struct genz_rmr *r)
{
	int cmp;
	const struct genz_pte_info *info = r->pte_info;

	cmp = arithcmp(dgcid, info->req.dgcid);
	if (cmp)
		return cmp;
	cmp = arithcmp(rsp_zaddr, r->rsp_zaddr);
	if (cmp)
		return cmp;
	cmp = arithcmp(length, info->length);
	if (cmp)
		return cmp;
	return arithcmp(USER_ACCESS(access), USER_ACCESS(info->access));
}

static inline int rmr_uu_cmp(uint64_t rsp_zaddr,
			     uint64_t length, uint64_t access,
			     struct uuid_tracker *local_uuid,
			     const struct genz_rmr *r)
{
	int cmp;
	const struct genz_pte_info *info = r->pte_info;

	cmp = arithcmp(rsp_zaddr, r->rsp_zaddr);
	if (cmp)
		return cmp;
	cmp = arithcmp(length, info->length);
	if (cmp)
		return cmp;
	cmp = arithcmp(USER_ACCESS(access), USER_ACCESS(info->access));
	if (cmp)
		return cmp;
	return genz_uuid_cmp(&local_uuid->uuid,
			     &r->mdata->local_uuid->uuid);
}

struct genz_rmr *genz_rmr_search(
	struct genz_mem_data *mdata, uint32_t dgcid, uint64_t rsp_zaddr,
	uint64_t length, uint64_t access, uint64_t req_addr)
{
	struct genz_rmr *rmr;
	struct rb_node *rnode;
	struct rb_root *root = &mdata->md_rmr_tree;

	/* caller must already hold mdata->md_lock */
	rnode = root->rb_node;

	while (rnode) {
		int64_t result;

		rmr = container_of(rnode, struct genz_rmr, md_node);
		result = rmr_cmp(dgcid, rsp_zaddr, length, access, rmr);
		if (result < 0) {
			rnode = rnode->rb_left;
		} else if (result > 0) {
			rnode = rnode->rb_right;
		} else {
			if (req_addr == rmr->req_addr)
				goto out;
			else
				goto fail;
		}
	}

 fail:
	rmr = NULL;

 out:
	return rmr;
}
EXPORT_SYMBOL(genz_rmr_search);

static struct genz_rmr *rmr_insert(struct genz_rmr *rmr)
{
	struct genz_pte_info *info = rmr->pte_info;
	struct genz_mem_data *mdata = rmr->mdata;
	struct rb_root *root;
	struct rb_node **new, *parent = NULL;
	ulong flags;

	spin_lock_irqsave(&mdata->md_lock, flags);
	root = &mdata->md_rmr_tree;
	new = &root->rb_node;

	/* figure out where to put new node in mdata->md_rmr_tree */
	while (*new) {
		struct genz_rmr *this =
			container_of(*new, struct genz_rmr, md_node);
		int64_t result = rmr_cmp(info->req.dgcid, rmr->rsp_zaddr,
					 info->length, info->access, this);

		parent = *new;
		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {  /* already there */
			rmr = this;
			kref_get(&rmr->refcount);
			goto unlock;
		}
	}

	/* add new node and rebalance tree */
	rb_link_node(&rmr->md_node, parent, new);
	rb_insert_color(&rmr->md_node, root);
	rmr->fd_erase = true;
	rmr->un_erase = true;

	/* figure out where to put new node in unode->un_rmr_tree */
	root = &rmr->unode->un_rmr_tree;
	new = &root->rb_node;
	parent = NULL;
	while (*new) {
		struct genz_rmr *this =
			container_of(*new, struct genz_rmr, un_node);
		int result = rmr_uu_cmp(rmr->rsp_zaddr, info->length,
					info->access, mdata->local_uuid, this);

		parent = *new;
		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {  /* already there - should never happen */
			goto unlock;
		}
	}

	/* add new node and rebalance tree */
	rb_link_node(&rmr->un_node, parent, new);
	rb_insert_color(&rmr->un_node, root);

 unlock:
	spin_unlock_irqrestore(&mdata->md_lock, flags);
	return rmr;
}

static void rmr_free(struct kref *ref)
{
	/* caller must already hold mdata->md_lock */
	struct genz_rmr *rmr = container_of(ref, struct genz_rmr, refcount);
	struct genz_pte_info *info = rmr->pte_info;
	struct genz_mem_data *mdata = rmr->mdata;

	pte_info_remove(info);
	if (rmr->fd_erase)
		rb_erase(&rmr->md_node, &mdata->md_rmr_tree);
	if (rmr->un_erase) {
		rb_erase(&rmr->un_node, &rmr->unode->un_rmr_tree);
	}
	genz_uuid_remove(rmr->uu);  /* remove reference to uu */
	kfree(rmr);
}

void genz_rmr_remove(struct genz_rmr *rmr, bool lock)
{
	struct genz_mem_data *mdata = rmr->mdata;
	ulong flags;

	if (lock)
		spin_lock_irqsave(&mdata->md_lock, flags);
	kref_put(&rmr->refcount, rmr_free);
	if (lock)
		spin_unlock_irqrestore(&mdata->md_lock, flags);
}
EXPORT_SYMBOL(genz_rmr_remove);

void genz_rmr_remove_unode(struct genz_mem_data *mdata, struct uuid_node *unode)
{
	struct rb_root *root = &unode->un_rmr_tree;
	struct rb_node *rb, *next;
	struct genz_rmr *rmr;
	struct genz_pte_info *info;
	ulong flags;
	char str[GCID_STRING_LEN+1];

	spin_lock_irqsave(&mdata->md_lock, flags);

	for (rb = rb_first_postorder(root); rb; rb = next) {
		rmr = container_of(rb, struct genz_rmr, un_node);
		info = rmr->pte_info;
		pr_debug("dgcid=%s, rsp_zaddr=0x%016llx, "
			 "len=0x%zx, access=0x%llx\n",
			 genz_gcid_str(info->req.dgcid, str, sizeof(str)),
			 rmr->rsp_zaddr, info->length, info->access);
		next = rb_next_postorder(rb);  /* must precede rmr_free() */
		rmr->fd_erase = true;
		rmr->un_erase = false;
		rmr_free(&rmr->refcount);
	}

	spin_unlock_irqrestore(&mdata->md_lock, flags);
}

void genz_rmr_free_all(struct genz_mem_data *mdata)
{
	struct rb_node *rb, *next;
	struct genz_rmr *rmr;
	struct genz_pte_info *info;
	char str[GCID_STRING_LEN+1];
	ulong flags;

	spin_lock_irqsave(&mdata->md_lock, flags);

	for (rb = rb_first_postorder(&mdata->md_rmr_tree); rb; rb = next) {
		rmr = container_of(rb, struct genz_rmr, md_node);
		info = rmr->pte_info;
		pr_debug("dgcid = %s, rsp_zaddr = 0x%016llx, "
			 "len = 0x%zx, access = 0x%llx\n",
			 genz_gcid_str(info->req.dgcid, str, sizeof(str)),
			 rmr->rsp_zaddr, info->length, info->access);
		next = rb_next_postorder(rb);  /* must precede rmr_free() */
		rmr->fd_erase = false;
		rmr->un_erase = true;
		rmr_free(&rmr->refcount);
	}

	mdata->md_rmr_tree = RB_ROOT;

	spin_unlock_irqrestore(&mdata->md_lock, flags);
}
EXPORT_SYMBOL(genz_rmr_free_all);

struct genz_rmr *genz_rmr_get(
	struct genz_mem_data *mdata, uuid_t *uuid, uint32_t dgcid,
	uint64_t rsp_zaddr, uint64_t len, uint64_t access, uint pasid,
	uint32_t rkey, struct genz_rmr_info *rmri)
{
	struct genz_rmr         *rmr, *found;
	struct genz_pte_info    *info;
	struct uuid_node        *unode;
	struct uuid_tracker     *uu;
	bool                    writable, indiv_rkeys;
	int                     ret = 0;
	char                    gcstr[GCID_STRING_LEN+1];

	writable = !!(access & GENZ_MR_PUT_REMOTE);
	indiv_rkeys = !!(access & GENZ_MR_INDIV_RKEYS);
	rmr = kzalloc(sizeof(*rmr), GFP_KERNEL);
	if (!rmr) {
		ret = -ENOMEM;
		goto out;
	}
	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		kfree(rmr);
		ret = -ENOMEM;
		goto out;
	}
	pr_debug("rmr=%p\n", rmr);
	unode = genz_remote_uuid_get(mdata, uuid);
	if (!unode) {
		kfree(rmr);
		kfree(info);
		ret = -EINVAL;  /* UUID must have been imported */
		goto out;
	}
	/* we now hold a reference to uu */
	uu = unode->tracker;
	if (!indiv_rkeys && uu->remote->rkeys_valid)
		rkey = (writable) ? uu->remote->rw_rkey : uu->remote->ro_rkey;
	rmr->mdata       = mdata;
	rmr->pte_info    = info;
	rmr->rsp_zaddr   = rsp_zaddr;
	rmr->uu          = uu;
	rmr->unode       = unode;
	rmr->writable    = writable;
	kref_init(&rmr->refcount);
	kref_init(&info->refcount);
	info->bridge     = mdata->bridge;
	info->addr       = rsp_zaddr;
	info->access     = USER_ACCESS(access) | GENZ_MR_REQ;
	info->length     = len;
	info->space_type = GENZ_DATA;  /* Revisit: add CONTROL */
	info->pasid      = pasid;
	info->req.rkey   = rkey;
	info->req.dgcid  = dgcid;
	pr_debug("rmr: info=%p, addr=0x%llx, dgcid=%s, rkey=0x%x, uu=%p\n",
		 info, info->addr,
		 genz_gcid_str(info->req.dgcid, gcstr, sizeof(gcstr)),
		 info->req.rkey, rmr->uu);

	found = rmr_insert(rmr);
	if (found != rmr) {
		genz_rmr_remove(rmr, true);
		ret = -EEXIST;
		rmri->req_addr = found->req_addr;
		rmri->pg_ps = found->pte_info->pg->page_grid.page_size_0;
	}

 out:
	return ret < 0 ? ERR_PTR(ret) : rmr;
}
EXPORT_SYMBOL(genz_rmr_get);

int genz_mr_reg(struct genz_mem_data *mdata, uint64_t vaddr,
		uint64_t len, uint64_t access, uint32_t pasid,
		uint64_t *rsp_zaddr, uint32_t *pg_ps,
		uint32_t *ro_rkey, uint32_t *rw_rkey)
{
	int               status = 0;
	bool              local, remote, cpu_visible, individual, indiv_rkeys;
	struct genz_umem  *umem;
	ulong             flags;

	*rsp_zaddr = GENZ_BASE_ADDR_ERROR;
	*pg_ps = 0;
	local = !!(access & (GENZ_MR_GET|GENZ_MR_PUT));
	remote = !!(access & (GENZ_MR_GET_REMOTE|GENZ_MR_PUT_REMOTE));
	cpu_visible = !!(access & GENZ_MR_REQ_CPU);
	individual = !!(access & GENZ_MR_INDIVIDUAL);
	indiv_rkeys = !!(access & GENZ_MR_INDIV_RKEYS);

	pr_debug("vaddr=0x%016llx, len=0x%llx, access=0x%llx, pasid=%u, "
		 "local=%u, remote=%u, cpu_visible=%u, "
		 "individual=%u, indiv_rkeys=%u\n",
		 vaddr, len, access, pasid,
		 local, remote, cpu_visible, individual, indiv_rkeys);

	if (!(local || remote) || cpu_visible || !individual) {
		status = -EINVAL;
		goto out;
	}

	if (indiv_rkeys) {
		status = genz_rkey_alloc(ro_rkey, rw_rkey);
		if (status < 0)
			goto out;
	} else {
		*ro_rkey = mdata->ro_rkey;
		*rw_rkey = mdata->rw_rkey;
	}
	umem = genz_umem_get(mdata, vaddr, len, access, pasid,
			     *ro_rkey, *rw_rkey, true);
	if (IS_ERR(umem)) {
		status = PTR_ERR(umem);
		goto out;
	}

	/* create responder ZMMU entries, if necessary */
	if (remote) {
		status = genz_zmmu_rsp_pte_alloc(umem->pte_info,
						 rsp_zaddr, pg_ps);
		if (status < 0) {
			spin_lock_irqsave(&mdata->md_lock, flags);
			genz_umem_remove(umem);
			spin_unlock_irqrestore(&mdata->md_lock, flags);
			goto out;
		}
	}

 out:
	pr_debug("ret=%d rsp_zaddr=0x%016llx, pg_ps=%u\n",
		 status, *rsp_zaddr, *pg_ps);
	return status;
}
EXPORT_SYMBOL(genz_mr_reg);

int genz_rmr_import(
	struct genz_mem_data *mdata, uuid_t *uuid, uint32_t dgcid,
	uint64_t rsp_zaddr, uint64_t len, uint64_t access, uint32_t rkey,
	const char *rmr_name, struct genz_rmr_info *rmri)
{
	struct genz_bridge_dev  *br = mdata->bridge;
	struct genz_bridge_info *br_info = &br->br_info;
	int                     status = 0;
	struct genz_rmr         *rmr;
	bool                    remote, cpu_visible, writable, individual, kmap;
	uint64_t cpuvisible_offset = br_info->cpuvisible_phys_offset;

	rmri->rsp_zaddr = rsp_zaddr;
	rmri->len = len;
	rmri->access = access;
	rmri->gcid = dgcid;
	rmri->req_addr = GENZ_BASE_ADDR_ERROR;
	rmri->cpu_addr = NULL;
	rmri->pg_ps = 0;
	remote = !!(access & (GENZ_MR_GET_REMOTE|GENZ_MR_PUT_REMOTE));
	writable = !!(access & GENZ_MR_PUT_REMOTE);
	cpu_visible = !!(access & GENZ_MR_REQ_CPU);
	individual = !!(access & GENZ_MR_INDIVIDUAL);
	kmap = !!(access & GENZ_MR_KERN_MAP);

	pr_debug("uuid=%pUb, rsp_zaddr=0x%016llx, "
		 "len=0x%llx, access=0x%llx, rkey=0x%x, "
		 "remote=%u, writable=%u, cpu_visible=%u, individual=%u, "
		 "kmap=%u\n",
		 uuid, rsp_zaddr, len, access, rkey, remote, writable,
		 cpu_visible, individual, kmap);

	if (!remote || !individual || /* Revisit: allow !individual */
	    (genz_gcid_is_local(mdata->bridge, dgcid) && !br_info->loopback)) {
		status = -EINVAL;  /* only individual remote access allowed */
		goto out;
	}

	rmr = genz_rmr_get(mdata, uuid, dgcid, rsp_zaddr, len, access,
			   NO_PASID, rkey, rmri);
	if (IS_ERR(rmr)) {
		status = PTR_ERR(rmr);
		goto out;
	}

	/* create requester ZMMU entries */
	status = genz_zmmu_req_pte_alloc(rmr->pte_info, rmri);
	if (status < 0) {
		genz_rmr_remove(rmr, true);
		goto out;
	}

	rmr->req_addr = rmri->req_addr;
	rmr->mmap_pfn = PHYS_PFN(rmr->req_addr + cpuvisible_offset);

	if (cpu_visible) {
		if (kmap)
			rmri->cpu_addr = memremap(PFN_PHYS(rmr->mmap_pfn),
						  len, MEMREMAP_WB);
		rmri->res.start = PFN_PHYS(rmr->mmap_pfn);
		rmri->res.end = rmri->res.start + rmri->len - 1;
		rmri->res.flags = IORESOURCE_MEM;
		rmri->res.name = rmr_name;
		insert_resource(&br->ld_st_res, &rmri->res);
	}

 out:
	pr_debug("ret=%d, req_addr=0x%016llx, cpu_addr=%px, pg_ps=%u\n",
		 status, rmri->req_addr, rmri->cpu_addr, rmri->pg_ps);
	return status;
}
EXPORT_SYMBOL(genz_rmr_import);

int genz_rmr_free(struct genz_mem_data *mdata, struct genz_rmr_info *rmri)
{
	int                     status = 0;
	struct genz_rmr         *rmr;
	ulong                   flags;

	spin_lock_irqsave(&mdata->md_lock, flags);
	rmr = genz_rmr_search(mdata, rmri->gcid, rmri->rsp_zaddr, rmri->len,
			      rmri->access, rmri->req_addr);
	if (!rmr) {
		status = -EINVAL;
		goto unlock;
	}
	genz_rmr_remove(rmr, false);

unlock:
	spin_unlock_irqrestore(&mdata->md_lock, flags);
	pr_debug("ret=%d, rsp_zaddr=0x%016llx, "
		 "len=0x%llx, access=0x%llx\n",
		 status, rmri->rsp_zaddr, rmri->len, rmri->access);
	return status;
}
EXPORT_SYMBOL(genz_rmr_free);
