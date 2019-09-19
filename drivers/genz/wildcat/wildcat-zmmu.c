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

static void zmmu_page_grid_clear_all(struct page_grid *pg, bool sync)
{
	struct page_grid zero = { 0 }, tmp;
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

static void zmmu_rsp_clear_all(struct rsp_zmmu *rspz, bool sync)
{
	struct rsp_pte zero = { 0 }, tmp;
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
	for (i = 0; i < RSP_ZMMU_ENTRIES; i++) {
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

static void zmmu_page_grid_setup_all(struct page_grid_info *pgi,
                                     struct page_grid *pg, bool sync, char *nm)
{
    struct page_grid tmp;
    struct sw_page_grid *sw_pg = pgi->pg;
    uint i;

    /* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
    for (i = 0; i < WILDCAT_PAGE_GRID_ENTRIES; i++) {
        debug(DEBUG_ZMMU, "%s:%s,%u:%s pg[%u]@%px:base_addr=0x%llx, "
              "page_size=%u, page_count=%u, base_pte_idx=%u\n",
              zhpe_driver_name, __func__, __LINE__, nm, i, &pg[i],
              sw_pg[i].page_grid.base_addr,
              sw_pg[i].page_grid.page_size,
              sw_pg[i].page_grid.page_count,
              sw_pg[i].page_grid.base_pte_idx);
        iowrite16by(&sw_pg[i].page_grid, &pg[i]);
    }

    if (sync)  /* ensure visibility */
        ioread16by(&tmp, &pg[0]);
}

void wildcat_zmmu_setup_slice(struct slice *sl)
{
    struct bridge *br = BRIDGE_FROM_SLICE(sl);
    ulong flags;

    debug(DEBUG_ZMMU, "%s:%s,%u:sl=%px, br=%px, slice_valid=%u\n",
          zhpe_driver_name, __func__, __LINE__, sl, br, SLICE_VALID(sl));
    if (!SLICE_VALID(sl))
        return;

    if (!wildcat_no_avx)
        kernel_fpu_begin();
    spin_lock_irqsave(&sl->zmmu_lock, flags);
    zmmu_page_grid_setup_all(&br->req_zmmu_pg, sl->bar->req_zmmu.page_grid,
                             SYNC, "req");
    zmmu_page_grid_setup_all(&br->rsp_zmmu_pg, sl->bar->rsp_zmmu.page_grid,
                             SYNC, "rsp");
    /* Revisit: setup req/rsp PTEs too */
    spin_unlock_irqrestore(&sl->zmmu_lock, flags);
    if (!wildcat_no_avx)
        kernel_fpu_end();
}

static void zmmu_req_pte_write(struct zhpe_pte_info *info,
                               struct wildcat_req_zmmu *reqz, bool valid, bool sync)
{
    struct wildcat_req_pte pte = { 0 }, tmp;
    uint i, first = info->pte_index, last = first + info->zmmu_pages - 1;
    uint64_t addr, ps;
    char str[GCID_STRING_LEN+1];

    /* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
    if (info->zmmu_pages == 0 || info->pg == NULL)
        return;  /* no PTEs to write */
    pte.pasid = info->pasid;
    pte.space_type = info->space_type;
    /* Revisit: traffic_class, dc_grp */
    pte.dgcid = info->req.dgcid;
    pte.ctn = N;
    pte.rke = !zhpe_no_rkeys && (info->req.rkey != 0);
    pte.rkey = info->req.rkey;
    pte.v = valid;
    ps = BIT_ULL(info->pg->page_grid.page_size);
    addr = info->addr_aligned;

    for (i = first; i <= last; i++) {
        pte.addr = addr >> 12;
        debug(DEBUG_ZMMU, "%s:%s,%u:pte[%u]@%px:addr=0x%llx, pasid=0x%x, "
              "dgcid=%s, space_type=%u, rke=%u, rkey=0x%x, "
              "traffic_class=%u, dc_grp=%u, v=%u\n",
              zhpe_driver_name, __func__, __LINE__, i, &reqz->pte[i],
              (uint64_t)pte.addr, pte.pasid,
              zhpe_gcid_str(pte.dgcid, str, sizeof(str)),
              pte.space_type, pte.rke, pte.rkey,
              pte.traffic_class, pte.dc_grp, pte.v);
        iowrite32by(&pte, &reqz->pte[i]);
        addr += ps;
    }

    if (sync)  /* ensure visibility */
        ioread32by(&tmp, &reqz->pte[first]);
}

static void zmmu_rsp_pte_write(struct zhpe_pte_info *info,
                               struct rsp_zmmu *rspz, bool valid, bool sync)
{
    struct rsp_pte pte = { 0 }, tmp;
    uint i, first = info->pte_index, last = first + info->zmmu_pages - 1;
    uint64_t va, za, window_sz, length, ps, offset;
    bool writable = !!(info->access & ZHPE_MR_PUT_REMOTE);

    /* caller must hold slice zmmu_lock & have done kernel_fpu_save() */
    if (info->zmmu_pages == 0 || info->pg == NULL)
        return;  /* no PTEs to write */
    pte.pasid = info->pasid;
    pte.space_type = info->space_type;
    pte.rke = !zhpe_no_rkeys;
    pte.ro_rkey = info->rsp.ro_rkey;
    pte.rw_rkey = (writable) ? info->rsp.rw_rkey : ZHPE_UNUSED_RKEY;
    pte.v = valid;
    va = info->addr;
    ps = BIT_ULL(info->pg->page_grid.page_size);
    length = info->length;
    offset = info->addr - info->addr_aligned;
    za = zhpe_zmmu_pte_addr(info, info->addr_aligned);
    for (i = first; i <= last; i++) {
        pte.va = va;
        window_sz = min(ps - offset, length);
        pte.window_sz = window_sz % BIT_ULL(PAGE_GRID_MAX_PAGESIZE);
        debug(DEBUG_ZMMU, "%s:%s,%u:pte[%u]@za=0x%llx:va=0x%llx, pasid=0x%x, "
              "rke=%u, ro_rkey=0x%x, rw_rkey=0x%x, "
              "window_sz=0x%llx, v=%u\n",
              zhpe_driver_name, __func__, __LINE__, i, za,
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

int wildcat_req_page_grid_write(struct genz_bridge_dev *br, uint pg_index,
				struct genz_page_grid genz_pg[])
{
    int sl, err;
    struct wildcat_page_grid wc_pg = { 0 };

    /* convert "generic" Gen-Z page grid to wildcat HW format */
    wc_pg.base_addr = genz_pg[pg_index].page_grid.pg_base_address_0 <<
	    GENZ_PAGE_GRID_MIN_PAGESIZE;
    wc_pg.page_count = genz_pg[pg_index].page_grid.page_count_0;
    wc_pg.page_size = genz_pg[pg_index].page_grid.page_size_0;
    wc_pg.base_pte_idx = genz_pg[pg_index].page_grid.base_pte_index_0;
    wc_pg.smo = genz_pg[pg_index].page_grid.res;

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

int wildcat_rsp_page_grid_write(struct genz_bridge_dev *br, uint pg_index,
				struct genz_page_grid genz_pg[])
{
    int sl, err;
    struct wildcat_page_grid wc_pg = { 0 };

    /* convert "generic" Gen-Z page grid to wildcat HW format */
    wc_pg.base_addr = genz_pg[pg_index].page_grid.pg_base_address_0 <<
	    GENZ_PAGE_GRID_MIN_PAGESIZE;
    wc_pg.page_count = genz_pg[pg_index].page_grid.page_count_0;
    wc_pg.page_size = genz_pg[pg_index].page_grid.page_size_0;
    wc_pg.base_pte_idx = genz_pg[pg_index].page_grid.base_pte_index_0;
    wc_pg.smo = genz_pg[pg_index].page_grid.res;

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

uint64_t zhpe_zmmu_pte_addr(const struct zhpe_pte_info *info, uint64_t addr)
{
    uint64_t base_addr, ps, pte_off;
    struct sw_page_grid *pg = info->pg;

    if (!pg)
        return GENZ_BASE_ADDR_ERROR;

    base_addr = pg->page_grid.base_addr;
    ps = BIT_ULL(pg->page_grid.page_size);
    pte_off = info->pte_index - pg->page_grid.base_pte_idx;
    return base_addr + (pte_off * ps) + (addr - info->addr_aligned);
}

static struct sw_page_grid *zmmu_pg_page_size(struct zhpe_pte_info *info,
                                              struct page_grid_info *pgi)
{
    uint64_t addr_aligned, length_adjusted;
    struct sw_page_grid *sw_pg;
    int ps;
    unsigned long key;
    bool cpu_visible = !!(info->access & ZHPE_MR_REQ_CPU);

    /* Revisit: make this more general */
    if (info->humongous) {
        sw_pg = pgi->humongous_pg;
        ps = sw_pg->page_grid.page_size;
        info->length = BIT_ULL(ps);
        info->addr &= ~(BIT_ULL(ps) - 1ull);
    } else {
        length_adjusted = roundup_pow_of_two(info->length);
        ps = clamp(ilog2(length_adjusted),
                   PAGE_GRID_MIN_PAGESIZE, PAGE_GRID_MAX_PAGESIZE);
        ps = find_next_bit(
            (cpu_visible) ? pgi->pg_cpu_visible_ps_bitmap :
            pgi->pg_non_visible_ps_bitmap, 64, ps);
        key = ps + ((cpu_visible) ? PAGE_GRID_MAX_PAGESIZE : 0);
        sw_pg = radix_tree_lookup(&pgi->pg_pagesize_tree, key);
    }

    if (sw_pg) {
        addr_aligned = ROUND_DOWN_PAGE(info->addr, BIT_ULL(ps));
        info->addr_aligned = addr_aligned;
        info->zmmu_pages = ROUND_UP_PAGE(
            info->length + (info->addr - addr_aligned), BIT_ULL(ps)) >> ps;
        info->length_adjusted = info->zmmu_pages * BIT_ULL(ps);
        if (info->humongous)
            info->length = info->length_adjusted;
    } else {
        ps = -ENOSPC;
    }

    debug(DEBUG_ZMMU, "%s:%s,%u:addr_aligned=0x%llx, length_adjusted=0x%llx, "
          "page_size=%d, sw_pg=%px\n",
          zhpe_driver_name, __func__, __LINE__,
          info->addr_aligned, info->length_adjusted, ps, sw_pg);
    return (ps < 0) ? ERR_PTR(ps) : sw_pg;
}

static int zmmu_pte_insert(struct zhpe_pte_info *info, struct sw_page_grid *pg)
{
    struct rb_root *root = &pg->pte_tree;
    struct rb_node **new = &root->rb_node, *parent = NULL;

    /* caller must hold bridge zmmu lock */

    /* figure out where to put new node */
    while (*new) {
        struct zhpe_pte_info *this =
            container_of(*new, struct zhpe_pte_info, node);
        int result = arithcmp(info->pte_index, this->pte_index);

        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else  /* already there */
            return -EEXIST;
    }

    /* add new node and rebalance tree */
    rb_link_node(&info->node, parent, new);
    rb_insert_color(&info->node, root);
    info->pg = pg;
    return 0;
}

static void zmmu_pte_erase(struct zhpe_pte_info *info)
{
    /* caller must hold bridge zmmu lock */
    if (info->pg != NULL) {
        rb_erase(&info->node, &info->pg->pte_tree);
        info->pg = NULL;
    }
}

static int zmmu_find_pte_range(struct zhpe_pte_info *info,
                               struct sw_page_grid *pg)
{
    struct rb_node *rb;
    struct zhpe_pte_info *this;
    uint page_count = info->zmmu_pages;
    uint min_pte = pg->page_grid.base_pte_idx;
    uint max_pte = min_pte + pg->page_grid.page_count - 1;
    uint end_pte;
    int ret = -ENOSPC;

    /* caller must hold bridge zmmu lock */

    for (rb = rb_last(&pg->pte_tree); rb; rb = rb_prev(rb)) {
        this = container_of(rb, struct zhpe_pte_info, node);
        end_pte = this->pte_index + this->zmmu_pages - 1;
        if ((max_pte - end_pte) >= page_count) {  /* range above this works */
            min_pte = end_pte + 1;
            break;
        } else {
            max_pte = this->pte_index - 1;
        }
    }

    if ((max_pte - min_pte + 1) >= page_count) {  /* found a range */
        /* set pte_index */
        info->pte_index = min_pte;
        /* add info to rbtree */
        ret = zmmu_pte_insert(info, pg);
        if (ret == 0)
            ret = min_pte;
    }

    debug(DEBUG_ZMMU, "%s:%s,%u:ret=%d, addr=0x%llx\n",
          zhpe_driver_name, __func__, __LINE__,
          ret, info->addr);
    return ret;
}

static void _zmmu_req_pte_write_slice(struct slice *sl,
                                      struct zhpe_pte_info *info,
                                      bool valid,
                                      bool sync)
{
    struct req_zmmu *reqz;
    ulong flags;

    /* don't call this function, as it only does
     * one slice - use zhpe_zmmu_req_pte_alloc() or
     * zhpe_zmmu_req_pte_free() instead
     */

    /* caller must have done kernel_fpu_save() */

    if (!SLICE_VALID(sl))
        return;

    spin_lock_irqsave(&sl->zmmu_lock, flags);
    reqz = &sl->bar->req_zmmu;

    /* write HW PTEs */
    zmmu_req_pte_write(info, reqz, valid, sync);

    spin_unlock_irqrestore(&sl->zmmu_lock, flags);
}

int zhpe_zmmu_req_pte_alloc(struct zhpe_pte_info *info, uint64_t *req_addr,
                            uint32_t *pg_ps)
{
    struct bridge         *br = info->bridge;
    struct page_grid_info *pgi = &br->req_zmmu_pg;
    struct sw_page_grid   *sw_pg;
    uint                  sl;
    int                   ret;
    ulong                 flags;

    spin_lock_irqsave(&br->zmmu_lock, flags);
    sw_pg = zmmu_pg_page_size(info, pgi);
    if (IS_ERR(sw_pg)) {
        ret = PTR_ERR(sw_pg);
        goto unlock;
    }

    ret = zmmu_find_pte_range(info, sw_pg);
    if (ret < 0)
        goto unlock;

    *req_addr = zhpe_zmmu_pte_addr(info, info->addr);
    *pg_ps = sw_pg->page_grid.page_size;
    spin_unlock_irqrestore(&br->zmmu_lock, flags);
    debug(DEBUG_ZMMU, "%s:%s,%u:pte_index=%u, zmmu_pages=%u, pg_ps=%u\n",
          zhpe_driver_name, __func__, __LINE__,
          info->pte_index, info->zmmu_pages, *pg_ps);

    if (!zhpe_no_avx)
        kernel_fpu_begin();
    for (sl = 0; sl < SLICES; sl++)
        _zmmu_req_pte_write_slice(&br->slice[sl], info, VALID, SYNC);
    if (!zhpe_no_avx)
        kernel_fpu_end();
    return 0;

 unlock:
    spin_unlock_irqrestore(&br->zmmu_lock, flags);

    debug(DEBUG_ZMMU, "%s:%s,%u:ret=%d, addr=0x%llx\n",
          zhpe_driver_name, __func__, __LINE__,
          ret, info->addr);
    return ret;
}

void zhpe_zmmu_req_pte_free(struct zhpe_pte_info *info)
{
    struct bridge         *br = info->bridge;
    uint                  sl;
    ulong                 flags;

    debug(DEBUG_ZMMU, "%s:%s,%u:pte_index=%u, zmmu_pages=%u\n",
          zhpe_driver_name, __func__, __LINE__,
          info->pte_index, info->zmmu_pages);

    if (!zhpe_no_avx)
        kernel_fpu_begin();
    for (sl = 0; sl < SLICES; sl++)
        _zmmu_req_pte_write_slice(&br->slice[sl], info, INVALID, NO_SYNC);

    if (!zhpe_no_avx)
        kernel_fpu_end();

    spin_lock_irqsave(&br->zmmu_lock, flags);
    zmmu_pte_erase(info);
    spin_unlock_irqrestore(&br->zmmu_lock, flags);
}

static void _zmmu_rsp_pte_write_slice(struct slice *sl,
                                      struct zhpe_pte_info *info,
                                      bool valid,
                                      bool sync)
{
    struct rsp_zmmu *rspz;
    ulong flags;

    /* don't call this function, as it only does
     * one slice - use zhpe_zmmu_rsp_pte_alloc() or
     * zhpe_zmmu_rsp_pte_free() instead
     */

    /* caller must have done kernel_fpu_save() */

    if (!SLICE_VALID(sl))
        return;

    spin_lock_irqsave(&sl->zmmu_lock, flags);
    rspz = &sl->bar->rsp_zmmu;

    /* write HW PTEs */
    zmmu_rsp_pte_write(info, rspz, valid, sync);

    spin_unlock_irqrestore(&sl->zmmu_lock, flags);
}

int zhpe_zmmu_rsp_pte_alloc(struct zhpe_pte_info *info, uint64_t *rsp_zaddr,
                            uint32_t *pg_ps)
{
    struct bridge         *br = info->bridge;
    struct page_grid_info *pgi = &br->rsp_zmmu_pg;
    struct sw_page_grid   *sw_pg;
    uint                  sl;
    int                   ret;
    ulong                 flags;

    spin_lock_irqsave(&br->zmmu_lock, flags);
    sw_pg = zmmu_pg_page_size(info, pgi);
    if (IS_ERR(sw_pg)) {
        ret = PTR_ERR(sw_pg);
        goto unlock;
    }

    ret = zmmu_find_pte_range(info, sw_pg);
    if (ret < 0)
        goto unlock;

    *rsp_zaddr = zhpe_zmmu_pte_addr(info, info->addr);
    *pg_ps = sw_pg->page_grid.page_size;
    spin_unlock_irqrestore(&br->zmmu_lock, flags);
    debug(DEBUG_ZMMU, "%s:%s,%u:pte_index=%u, zmmu_pages=%u\n",
          zhpe_driver_name, __func__, __LINE__,
          info->pte_index, info->zmmu_pages);

    if (!zhpe_no_avx)
        kernel_fpu_begin();
    for (sl = 0; sl < SLICES; sl++)
        _zmmu_rsp_pte_write_slice(&br->slice[sl], info, VALID, SYNC);
    if (!zhpe_no_avx)
        kernel_fpu_end();
    return 0;

 unlock:
    spin_unlock_irqrestore(&br->zmmu_lock, flags);

    debug(DEBUG_ZMMU, "%s:%s,%u:ret=%d, addr=0x%llx\n",
          zhpe_driver_name, __func__, __LINE__,
          ret, info->addr);
    return ret;
}

void zhpe_zmmu_rsp_pte_free(struct zhpe_pte_info *info)
{
    struct bridge         *br = info->bridge;
    uint                  sl;
    ulong                 flags;

    debug(DEBUG_ZMMU, "%s:%s,%u:pte_index=%u, zmmu_pages=%u\n",
          zhpe_driver_name, __func__, __LINE__,
          info->pte_index, info->zmmu_pages);

    if (!zhpe_no_avx)
        kernel_fpu_begin();
    for (sl = 0; sl < SLICES; sl++)
        _zmmu_rsp_pte_write_slice(&br->slice[sl], info, INVALID, NO_SYNC);
    /* Revisit: perform TAKE_SNAPSHOT sequence */
    if (!zhpe_no_avx)
        kernel_fpu_end();

    spin_lock_irqsave(&br->zmmu_lock, flags);
    zmmu_pte_erase(info);
    spin_unlock_irqrestore(&br->zmmu_lock, flags);
}

void zhpe_humongous_zmmu_rsp_pte_get(struct file_data *fdata,
                                     struct zhpe_pte_info **infop,
                                     uint64_t *rsp_zaddr,
                                     uint32_t *pg_ps)
{
    struct zhpe_pte_info *old;
    ulong flags;

    spin_lock_irqsave(&fdata->md.md_lock, flags);
    old = *infop;
    *infop = fdata->humongous_zmmu_rsp_pte;
    kref_get(&(*infop)->refcount);
    spin_unlock_irqrestore(&fdata->md.md_lock, flags);
    *rsp_zaddr = zhpe_zmmu_pte_addr(*infop, old->addr);
    *pg_ps = (*infop)->pg->page_grid.page_size;
    do_kfree(old);
}

int zhpe_humongous_zmmu_rsp_pte_alloc(struct file_data *fdata,
                                      struct zhpe_pte_info *info,
                                      uint64_t *rsp_zaddr,
                                      uint32_t *pg_ps)
{
    uint64_t vaddr = info->addr;
    int ret;

    info->humongous = true;
    ret = zhpe_zmmu_rsp_pte_alloc(info, rsp_zaddr, pg_ps);
    if (ret < 0)
        goto out;

    *rsp_zaddr = zhpe_zmmu_pte_addr(info, vaddr);
    fdata->humongous_zmmu_rsp_pte = info;
    kref_get(&info->refcount);

 out:
    return ret;
}
