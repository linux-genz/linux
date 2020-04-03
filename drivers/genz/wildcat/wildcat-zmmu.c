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
#include <linux/bitops.h>
#include <linux/genz.h>
#include <asm/fpu/api.h>

#include "wildcat.h"

static void zmmu_page_grid_clear_all(struct wildcat_page_grid *pg, bool sync)
{
	struct wildcat_page_grid zero = { 0 }, tmp;
	uint i;

	/* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
	for (i = 0; i < WILDCAT_PAGE_GRID_ENTRIES; i++) {
		iowrite16by(&zero, &pg[i]);
	}

	if (sync)  /* ensure visibility */
		ioread16by(&tmp, &pg[0]);
}

static void zmmu_req_clear_all(struct wildcat_req_zmmu *reqz, bool sync)
{
	struct wildcat_req_pte zero = { 0 }, tmp;
	uint i;

	/* caller must hold slice zmmu_lock & have done kernel_fpu_save() */

	/* Revisit: temporary HW debug */
	zero.pasid = 0x12345;
	zero.dgcid = 0x6789abc;
	zero.addr = 0xdeadbeefabcd7;
	zero.rkey = 0x01020304;
	zero.v = 0;

	zmmu_page_grid_clear_all(reqz->page_grid, NO_SYNC);
	for (i = 0; i < WILDCAT_REQ_ZMMU_ENTRIES; i++) {
		iowrite32by(&zero, &reqz->pte[i]);
	}

	if (sync)  /* ensure visibility */
		ioread32by(&tmp, &reqz->pte[0]);
}

static void zmmu_rsp_clear_all(struct wildcat_rsp_zmmu *rspz, bool sync)
{
	struct wildcat_rsp_pte zero = { 0 }, tmp;
	uint i;

	/* caller must hold slice zmmu_lock & have done kernel_fpu_save() */

	/* Revisit: temporary HW debug */
	zero.pasid = 0x54321;
	zero.va = 0xbeefdeadbadc;
	zero.ro_rkey = 0x02040608;
	zero.rw_rkey = 0x01030507;
	zero.window_sz = 0xeb12deadbaca;
	zero.v = 0;

	zmmu_page_grid_clear_all(rspz->page_grid, NO_SYNC);
	for (i = 0; i < WILDCAT_RSP_ZMMU_ENTRIES; i++) {
		iowrite32by(&zero, &rspz->pte[i]);
	}

	if (sync)  /* ensure visibility */
		ioread32by(&tmp, &rspz->pte[0]);
}

void wildcat_zmmu_clear_slice(struct slice *sl)
{
	ulong flags;

	pr_debug("sl=%px, slice_valid=%u\n", sl, SLICE_VALID(sl));
	if (!SLICE_VALID(sl))
		return;

	if (!wildcat_no_avx)
		kernel_fpu_begin();
	spin_lock_irqsave(&sl->zmmu_lock, flags);
	zmmu_req_clear_all(&sl->bar->req_zmmu, SYNC);
	zmmu_rsp_clear_all(&sl->bar->rsp_zmmu, SYNC);
	spin_unlock_irqrestore(&sl->zmmu_lock, flags);
	if (!wildcat_no_avx)
		kernel_fpu_end();
}

static void wildcat_convert_genz_page_grid(struct genz_page_grid *genz_pg,
					   struct wildcat_page_grid *wc_pg)
{
	/* convert "generic" Gen-Z page grid to wildcat HW format */
	wc_pg->base_addr = genz_pg_addr(genz_pg);
	wc_pg->page_count = genz_pg->page_grid.page_count_0;
	wc_pg->page_size = genz_pg->page_grid.page_size_0;
	wc_pg->base_pte_idx = genz_pg->page_grid.base_pte_index_0;
	wc_pg->smo = genz_pg->page_grid.res;
}

static void _zmmu_req_pte_write(struct genz_pte_info *info,
				struct wildcat_req_zmmu *reqz,
				bool valid, bool sync)
{
	struct wildcat_req_pte pte = { 0 }, tmp;
	uint i, first = info->pte_index, last = first + info->zmmu_pages - 1;
	uint64_t addr, ps, pa;
	char str[GCID_STRING_LEN+1];

	/* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
	if (info->zmmu_pages == 0 || info->pg == NULL)
		return;  /* no PTEs to write */
	pte.pasid = info->pasid;
	pte.space_type = info->space_type;
	/* Revisit: traffic_class, dc_grp */
	pte.dgcid = info->req.dgcid;
	pte.ctn = N;
	pte.rke = !wildcat_no_rkeys && (info->req.rkey != 0);
	pte.rkey = info->req.rkey;
	pte.v = valid;
	ps = BIT_ULL(info->pg->page_grid.page_size_0);
	pa = genz_zmmu_pte_addr(info, info->addr_aligned);
	addr = info->addr_aligned;

	for (i = first; i <= last; i++) {
		pte.addr = addr >> 12;
		pr_debug("pte[%u]@pa=0x%llx:za=0x%llx, pasid=0x%x, "
			 "dgcid=%s, space_type=%u, rke=%u, rkey=0x%x, "
			 "traffic_class=%u, dc_grp=%u, v=%u\n",
			 i, pa,
			 (uint64_t)pte.addr << 12, pte.pasid,
			 genz_gcid_str(pte.dgcid, str, sizeof(str)),
			 pte.space_type, pte.rke, pte.rkey,
			 pte.traffic_class, pte.dc_grp, pte.v);
		iowrite32by(&pte, &reqz->pte[i]);
		addr += ps;
		pa += ps;
	}

	if (sync)  /* ensure visibility */
		ioread32by(&tmp, &reqz->pte[first]);
}

static void _zmmu_rsp_pte_write(struct genz_pte_info *info,
				struct wildcat_rsp_zmmu *rspz,
				bool valid, bool sync)
{
	struct wildcat_rsp_pte pte = { 0 }, tmp;
	uint i, first = info->pte_index, last = first + info->zmmu_pages - 1;
	uint64_t va, za, window_sz, length, ps, offset;
	bool writable = !!(info->access & WILDCAT_MR_PUT_REMOTE);  /* Revisit */

	/* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
	if (info->zmmu_pages == 0 || info->pg == NULL)
		return;  /* no PTEs to write */
	pte.pasid = info->pasid;
	pte.space_type = info->space_type;
	pte.rke = !wildcat_no_rkeys;
	pte.ro_rkey = info->rsp.ro_rkey;
	pte.rw_rkey = (writable) ? info->rsp.rw_rkey : GENZ_UNUSED_RKEY;
	pte.v = valid;
	va = info->addr;
	ps = BIT_ULL(info->pg->page_grid.page_size_0);
	length = info->length;
	offset = info->addr - info->addr_aligned;
	za = genz_zmmu_pte_addr(info, info->addr_aligned);
	for (i = first; i <= last; i++) {
		pte.va = va;
		window_sz = min(ps - offset, length);
		pte.window_sz = window_sz %
			BIT_ULL(WILDCAT_PAGE_GRID_MAX_PAGESIZE);
		pr_debug("pte[%u]@za=0x%llx:va=0x%llx, pasid=0x%x, "
			 "rke=%u, ro_rkey=0x%x, rw_rkey=0x%x, "
			 "window_sz=0x%llx, v=%u\n",
			 i, za,
			 (uint64_t)pte.va, pte.pasid,
			 pte.rke, pte.ro_rkey, pte.rw_rkey,
			 (uint64_t)pte.window_sz, pte.v);
		iowrite32by(&pte, &rspz->pte[i]);
		va = ROUND_DOWN_PAGE(va, ps) + ps;
		za += ps;
		length -= (ps - offset);
		offset = 0;
	}

	if (sync)  /* ensure visibility */
		ioread32by(&tmp, &rspz->pte[first]);
}

static void _zmmu_req_page_grid_write_slice(struct slice *sl,
					    struct wildcat_page_grid *wc_pg,
					    uint pg_index, bool sync)
{
	struct wildcat_req_zmmu *reqz;
	struct wildcat_page_grid tmp;
	ulong flags;

	/* don't call this function, as it only does
	 * one slice - use wildcat_req_page_grid_write() instead
	 */

	/* caller must have done kernel_fpu_save() */

	if (!SLICE_VALID(sl))
		return;

	spin_lock_irqsave(&sl->zmmu_lock, flags);
	reqz = &sl->bar->req_zmmu;

	/* write HW page grid */
	iowrite16by(wc_pg, &reqz->page_grid[pg_index]);
	if (sync)  /* ensure visibility */
		ioread16by(&tmp, &reqz->page_grid[pg_index]);

	spin_unlock_irqrestore(&sl->zmmu_lock, flags);
}

int wildcat_req_page_grid_write(struct genz_bridge_dev *gzbr, uint pg_index,
				struct genz_page_grid genz_pg[])
{
	int                      sl;
	struct wildcat_page_grid wc_pg = { 0 };
	struct bridge            *br = wildcat_gzbr_to_br(gzbr);

	/* convert "generic" Gen-Z page grid to wildcat HW format */
	wildcat_convert_genz_page_grid(&genz_pg[pg_index], &wc_pg);
	dev_dbg(gzbr->bridge_dev,
		"wc_pg[%u]: base_addr=0x%llx, page_count=%d, page_size=%u, "
		"base_pte_idx=%u, smo=%u\n", pg_index,
		wc_pg.base_addr, wc_pg.page_count,
		wc_pg.page_size, wc_pg.base_pte_idx, wc_pg.smo);

	/* write all requester ZMMU slices */
	if (!wildcat_no_avx)
		kernel_fpu_begin();
	for (sl = 0; sl < SLICES; sl++)
		_zmmu_req_page_grid_write_slice(&br->slice[sl], &wc_pg,
						pg_index, SYNC);
	if (!wildcat_no_avx)
		kernel_fpu_end();

	return 0;
}

static void _zmmu_rsp_page_grid_write_slice(struct slice *sl,
					    struct wildcat_page_grid *wc_pg,
					    uint pg_index, bool sync)
{
	struct wildcat_rsp_zmmu *rspz;
	struct wildcat_page_grid tmp;
	ulong flags;

	/* don't call this function, as it only does
	 * one slice - use wildcat_rsp_page_grid_write() instead
	 */

	/* caller must have done kernel_fpu_save() */

	if (!SLICE_VALID(sl))
		return;

	spin_lock_irqsave(&sl->zmmu_lock, flags);
	rspz = &sl->bar->rsp_zmmu;

	/* write HW page grid */
	iowrite16by(wc_pg, &rspz->page_grid[pg_index]);
	if (sync)  /* ensure visibility */
		ioread16by(&tmp, &rspz->page_grid[pg_index]);

	spin_unlock_irqrestore(&sl->zmmu_lock, flags);
}

int wildcat_rsp_page_grid_write(struct genz_bridge_dev *gzbr, uint pg_index,
				struct genz_page_grid genz_pg[])
{
	int                      sl;
	struct wildcat_page_grid wc_pg = { 0 };
	struct bridge            *br = wildcat_gzbr_to_br(gzbr);

	/* convert "generic" Gen-Z page grid to wildcat HW format */
	wildcat_convert_genz_page_grid(&genz_pg[pg_index], &wc_pg);

	/* write all responder ZMMU slices */
	if (!wildcat_no_avx)
		kernel_fpu_begin();
	for (sl = 0; sl < SLICES; sl++)
		_zmmu_rsp_page_grid_write_slice(&br->slice[sl], &wc_pg,
						pg_index, SYNC);
	if (!wildcat_no_avx)
		kernel_fpu_end();

	return 0;
}

static void _zmmu_req_pte_write_slice(struct slice *sl,
				      struct genz_pte_info *info,
				      bool valid,
				      bool sync)
{
	struct wildcat_req_zmmu *reqz;
	ulong flags;

	/* don't call this function, as it only does
	 * one slice - use wildcat_req_pte_write() or
	 * wildcat_req_pte_free() instead
	 */

	/* caller must have done kernel_fpu_save() */

	if (!SLICE_VALID(sl))
		return;

	spin_lock_irqsave(&sl->zmmu_lock, flags);
	reqz = &sl->bar->req_zmmu;

	/* write HW PTEs */
	_zmmu_req_pte_write(info, reqz, valid, sync);

	spin_unlock_irqrestore(&sl->zmmu_lock, flags);
}

int wildcat_req_pte_write(struct genz_bridge_dev *gzbr,
			  struct genz_pte_info *info)
{
	struct bridge         *br = wildcat_gzbr_to_br(gzbr);
	uint                  sl;

	if (!wildcat_no_avx)
		kernel_fpu_begin();
	for (sl = 0; sl < SLICES; sl++)
		_zmmu_req_pte_write_slice(&br->slice[sl], info, VALID, SYNC);
	if (!wildcat_no_avx)
		kernel_fpu_end();
	return 0;
}

void wildcat_req_pte_free(struct genz_bridge_dev *gzbr,
			  struct genz_pte_info *info)
{
	struct bridge         *br = wildcat_gzbr_to_br(gzbr);
	uint                  sl;

	pr_debug("pte_index=%u, zmmu_pages=%u\n",
		 info->pte_index, info->zmmu_pages);

	if (!wildcat_no_avx)
		kernel_fpu_begin();
	for (sl = 0; sl < SLICES; sl++)
		_zmmu_req_pte_write_slice(&br->slice[sl], info,
					  INVALID, NO_SYNC);

	if (!wildcat_no_avx)
		kernel_fpu_end();
}

static void _zmmu_rsp_pte_write_slice(struct slice *sl,
				      struct genz_pte_info *info,
				      bool valid,
				      bool sync)
{
	struct wildcat_rsp_zmmu *rspz;
	ulong flags;

	/* don't call this function, as it only does
	 * one slice - use wildcat_rsp_pte_write() or
	 * wildcat_rsp_pte_free() instead
	 */

	/* caller must have done kernel_fpu_save() */

	if (!SLICE_VALID(sl))
		return;

	spin_lock_irqsave(&sl->zmmu_lock, flags);
	rspz = &sl->bar->rsp_zmmu;

	/* write HW PTEs */
	_zmmu_rsp_pte_write(info, rspz, valid, sync);

	spin_unlock_irqrestore(&sl->zmmu_lock, flags);
}

int wildcat_rsp_pte_write(struct genz_bridge_dev *gzbr,
			  struct genz_pte_info *info)
{
	struct bridge         *br = wildcat_gzbr_to_br(gzbr);
	uint                  sl;

	if (!wildcat_no_avx)
		kernel_fpu_begin();
	for (sl = 0; sl < SLICES; sl++)
		_zmmu_rsp_pte_write_slice(&br->slice[sl], info, VALID, SYNC);
	if (!wildcat_no_avx)
		kernel_fpu_end();
	return 0;
}

void wildcat_rsp_pte_free(struct genz_bridge_dev *gzbr,
			  struct genz_pte_info *info)
{
	struct bridge         *br = wildcat_gzbr_to_br(gzbr);
	uint                  sl;

	pr_debug("pte_index=%u, zmmu_pages=%u\n",
		 info->pte_index, info->zmmu_pages);

	if (!wildcat_no_avx)
		kernel_fpu_begin();
	for (sl = 0; sl < SLICES; sl++)
		_zmmu_rsp_pte_write_slice(&br->slice[sl], info,
					  INVALID, NO_SYNC);
	/* Revisit: perform TAKE_SNAPSHOT sequence */
	if (!wildcat_no_avx)
		kernel_fpu_end();
}

/* Revisit: make this genz_ ? */
int wildcat_humongous_zmmu_rsp_pte_alloc(
	struct genz_pte_info **infop,
	struct genz_pte_info **humongous_zmmu_rsp_pte,
	spinlock_t *md_lock,
	uint64_t *rsp_zaddr,
	uint32_t *pg_ps)
{
	struct genz_pte_info *info = *infop;
	uint64_t vaddr = info->addr;
	int ret = 0;
	ulong flags;

	spin_lock_irqsave(md_lock, flags);
	if (!humongous_zmmu_rsp_pte) {
		ret = -EINVAL;
		goto unlock;
	} else if (!*humongous_zmmu_rsp_pte) { /* allocate new humongous pte */
		info->humongous = true;
		ret = genz_zmmu_rsp_pte_alloc(info, rsp_zaddr, pg_ps);
		if (ret < 0)
			goto unlock;
		*rsp_zaddr = genz_zmmu_pte_addr(info, vaddr);
		*humongous_zmmu_rsp_pte = info;
		kref_get(&info->refcount);
		spin_unlock_irqrestore(md_lock, flags);
	} else {  /* use existing humongous pte */
		*infop = *humongous_zmmu_rsp_pte;
		kref_get(&(*infop)->refcount);
		spin_unlock_irqrestore(md_lock, flags);
		*rsp_zaddr = genz_zmmu_pte_addr(*infop, vaddr);
		*pg_ps = (*infop)->pg->page_grid.page_size_0;
		kfree(info); /* free original pte_info */
	}

out:
	return ret;

unlock:
	spin_unlock_irqrestore(md_lock, flags);
	goto out;
}
EXPORT_SYMBOL(wildcat_humongous_zmmu_rsp_pte_alloc);
