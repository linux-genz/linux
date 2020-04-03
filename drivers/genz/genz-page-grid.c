// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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

#include <linux/slab.h>
#include <linux/bitops.h>
#include "genz.h"

/* Revisit: genz_pg_restricted_pg_table_array field names */
#define page_size page_size_0
#define page_count page_count_0
#define pg_base_address pg_base_address_0
#define base_pte_index base_pte_index_0

uint64_t genz_zmmu_pte_addr(const struct genz_pte_info *info, uint64_t addr)
{
	uint64_t base_addr, ps, pte_off;
	struct genz_page_grid *pg = info->pg;

	if (!pg)
		return GENZ_BASE_ADDR_ERROR;

	base_addr = genz_pg_addr(pg);
	ps = BIT_ULL(pg->page_grid.page_size);
	pte_off = info->pte_index - pg->page_grid.base_pte_index;
	return base_addr + (pte_off * ps) + (addr - info->addr_aligned);
}
EXPORT_SYMBOL(genz_zmmu_pte_addr);

static void zmmu_clear_pg_info(struct genz_page_grid_info *pgi,
			       uint pte_entries, bool free_radix_tree)
{
	struct radix_tree_iter iter;
	void **slot;

	if (free_radix_tree) {
		radix_tree_for_each_slot(slot, &pgi->pg_pagesize_tree, &iter,
					 GENZ_PAGE_GRID_MIN_PAGESIZE) {
			radix_tree_iter_delete(&pgi->pg_pagesize_tree, &iter,
					       slot);
		}
	} else {
		INIT_RADIX_TREE(&pgi->pg_pagesize_tree, GFP_KERNEL);
	}
	bitmap_zero(pgi->pg_bitmap, PAGE_GRID_ENTRIES);
	bitmap_zero(pgi->pg_cpu_visible_ps_bitmap, 64);
	bitmap_zero(pgi->pg_non_visible_ps_bitmap, 64);
	pgi->pte_entries = pte_entries;
	pgi->base_pte_tree = RB_ROOT;
	pgi->base_addr_tree = RB_ROOT;
	pgi->humongous_pg = NULL;
}

void genz_zmmu_clear_all(struct genz_bridge_dev *br, bool free_radix_tree)
{
	ulong flags;

	pr_debug("br=%px, free_radix_tree=%u\n", br, free_radix_tree);
	spin_lock_irqsave(&br->zmmu_lock, flags);
	zmmu_clear_pg_info(&br->zmmu_info.req_zmmu_pg,
			   br->br_info.nr_req_ptes, free_radix_tree);
	zmmu_clear_pg_info(&br->zmmu_info.rsp_zmmu_pg,
			   br->br_info.nr_rsp_ptes, free_radix_tree);
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
}

static int parse_page_grid_one(char *str, uint64_t max_page_count,
			       bool allow_cpu_visible,
			       bool allow_humongous,
			       struct genz_page_grid *pg)
{
	char     *orig = str;
	uint64_t page_size, page_count;

	page_size = memparse(str, &str);
	if (str == orig || !(*str == ':' || *str == '*' || *str == '^'))
		goto err;
	if (!is_power_of_2(page_size))
		goto err;
	page_size = ilog2(page_size);
	if (page_size < GENZ_PAGE_GRID_MIN_PAGESIZE ||
	    page_size > GENZ_PAGE_GRID_MAX_PAGESIZE)
		goto err;
	pg->page_grid.page_size = page_size;

	if (*str == '^' && !allow_humongous)
		goto err;
	pg->humongous = (*str == '^');
	if (*str == '*' && !allow_cpu_visible)
		goto err;
	pg->cpu_visible = (*str++ == '*');

	orig = str;
	page_count = memparse(str, &str);
	if (str == orig || *str != '\0')
		goto err;
	if (page_count > max_page_count)
		goto err;
	pg->page_grid.page_count = page_count;

	return 0;

err:
	return -EINVAL;
}

uint genz_parse_page_grid_opt(char *str, uint64_t max_page_count,
			      bool allow_cpu_visible,
			      struct genz_page_grid pg[])
{
	uint cnt = 0;
	int ret;
	char *str_copy, *s, *k;
	bool bit, allow_humongous = true;
	DECLARE_BITMAP(non_visible_ps_bitmap,
		       GENZ_PAGE_GRID_MAX_PAGESIZE+1) = { 0 };
	DECLARE_BITMAP(cpu_visible_ps_bitmap,
		       GENZ_PAGE_GRID_MAX_PAGESIZE+1) = { 0 };

	/* make a writable copy of str */
	str_copy = kmalloc(strlen(str) + 1, GFP_KERNEL);
	strcpy(str_copy, str);

	for (s = str_copy; s; s = k) {
		k = strchr(s, ',');
		pr_debug("str=%px,s=%px,k=%px\n", str_copy, s, k);

		if (k)
			*k++ = 0;
		pr_debug("calling parse_page_grid_one(s=%s,max_page_count=%llu, &pg[cnt]=%px)\n",
			 s, max_page_count, &pg[cnt]);
		ret = parse_page_grid_one(s, max_page_count, allow_cpu_visible,
					  allow_humongous, &pg[cnt]);
		pr_debug("ret=%d, page_size=%u, page_count=%u, "
			 "cpu_visible=%d, humongous=%d\n",
			 ret, pg[cnt].page_grid.page_size,
			 pg[cnt].page_grid.page_count,
			 pg[cnt].cpu_visible, pg[cnt].humongous);
		if (pg[cnt].humongous)
			allow_humongous = false;  /* only allowed once */
		if (pg[cnt].cpu_visible) {
			bit = test_and_set_bit(pg[cnt].page_grid.page_size,
					       cpu_visible_ps_bitmap);
		} else {
			bit = test_and_set_bit(pg[cnt].page_grid.page_size,
					       non_visible_ps_bitmap);
		}
		if (!bit && ret == 0)
			cnt++;
		else
			pr_warn("%s:%s:invalid page_grid parameter - %s\n",
				"genz", __func__, s);
		if (cnt == PAGE_GRID_ENTRIES)
			break;
	}

	kfree(str_copy);
	return cnt;
}

static uint64_t zmmu_base_addr_insert(struct genz_page_grid_info *pgi,
				      uint pg_index)
{
	struct rb_root *root = &pgi->base_addr_tree;
	struct rb_node **new = &root->rb_node, *parent = NULL;
	struct genz_page_grid *node = &pgi->pg[pg_index];
	int result;

	/* caller must hold bridge zmmu lock */

	/* figure out where to put new node */
	while (*new) {
		struct genz_page_grid *this =
			container_of(*new, struct genz_page_grid, base_addr_node);

		result = arithcmp(node->page_grid.pg_base_address,
				  this->page_grid.pg_base_address);
		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else  /* already there */
			return GENZ_BASE_ADDR_ERROR;
	}

	/* add new node and rebalance tree */
	rb_link_node(&node->base_addr_node, parent, new);
	rb_insert_color(&node->base_addr_node, root);
	return 0;
}

static int zmmu_base_pte_insert(struct genz_page_grid_info *pgi, uint pg_index)
{
	struct rb_root *root = &pgi->base_pte_tree;
	struct rb_node **new = &root->rb_node, *parent = NULL;
	struct genz_page_grid *node = &pgi->pg[pg_index];

	/* caller must hold bridge zmmu lock */

	/* figure out where to put new node */
	while (*new) {
		struct genz_page_grid *this =
			container_of(*new, struct genz_page_grid, base_pte_node);
		int result = arithcmp(node->page_grid.base_pte_index,
				      this->page_grid.base_pte_index);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else  /* already there */
			return -EEXIST;
	}

	/* add new node and rebalance tree */
	rb_link_node(&node->base_pte_node, parent, new);
	rb_insert_color(&node->base_pte_node, root);
	return 0;
}

static int zmmu_find_pg_addr_range(struct genz_page_grid_info *pgi,
				   uint pg_index,
				   struct genz_bridge_info *bri)
{
	struct genz_page_grid *pg;
	struct rb_node *rb;
	bool cpu_visible    = pgi->pg[pg_index].cpu_visible;
	uint64_t page_count = pgi->pg[pg_index].page_grid.page_count;
	uint64_t page_size  = BIT_ULL(pgi->pg[pg_index].page_grid.page_size);
	uint64_t range      = page_size * page_count;
	uint64_t min_addr   = (cpu_visible) ?
		ROUND_UP_PAGE(bri->min_cpuvisible_addr, page_size) :
		ROUND_UP_PAGE(bri->min_nonvisible_addr, page_size);
	uint64_t max_addr   = (cpu_visible) ?
		bri->max_cpuvisible_addr : bri->max_nonvisible_addr;
	uint64_t ret        = GENZ_BASE_ADDR_ERROR;
	uint64_t base_addr, next_addr, pg_addr;
	uint64_t prev_base = 0; /* Revisit: debug */

	/* caller must hold bridge dev zmmu lock */

	pr_debug("pg[%d]:page_size=%llu, page_count=%llu, cpu_visible=%d, "
		 "min_addr=0x%llx, max_addr=0x%llx\n",
		 pg_index, page_size, page_count, cpu_visible,
		 min_addr, max_addr);

	for (rb = rb_first(&pgi->base_addr_tree); rb; rb = rb_next(rb)) {
		pg = container_of(rb, struct genz_page_grid, base_addr_node);
		pg_addr = genz_pg_addr(pg);
		if (pg_addr < prev_base)  /* Revisit: debug */
			pr_debug("base_addr out of order (0x%llx < 0x%llx)\n",
				 pg_addr, prev_base);
		prev_base = pg_addr;
		base_addr = ROUND_DOWN_PAGE(pg_addr, page_size);
		next_addr = ROUND_UP_PAGE(pg_addr +
					  (pg->page_grid.page_count *
					   BIT_ULL(pg->page_grid.page_size)),
					  page_size);
		pr_debug("pg[0x%llx*%u@0x%llx]:base_addr=0x%llx, "
			 "next_addr=0x%llx\n",
			 BIT_ULL(pg->page_grid.page_size),
			 pg->page_grid.page_count,
			 pg_addr, base_addr, next_addr);
		if (base_addr < min_addr) {
			if (min_addr < next_addr)
				min_addr = next_addr;
			continue;
		} else if ((base_addr - min_addr) >= range) { /* range below pg works */
			max_addr = base_addr - 1;
			break;
		} else {
			min_addr = next_addr;
		}
	}

	if ((max_addr - min_addr + 1) >= range) {  /* found a range */
		/* set base_addr */
		pgi->pg[pg_index].page_grid.pg_base_address =
			min_addr >> GENZ_PAGE_GRID_MIN_PAGESIZE;
		/* add genz_pg to rbtree */
		ret = zmmu_base_addr_insert(pgi, pg_index);
		if (ret == 0)
			ret = min_addr;
	}

	return ret;
}

static int zmmu_find_pg_pte_range(struct genz_page_grid_info *pgi,
				  uint pg_index)
{
	struct genz_page_grid *pg;
	struct rb_node *rb;
	uint page_count = pgi->pg[pg_index].page_grid.page_count;
	uint min_pte = 0, max_pte = pgi->pte_entries - 1, end_pte;
	int ret = -ENOSPC;

	/* caller must hold bridge zmmu lock */

	for (rb = rb_last(&pgi->base_pte_tree); rb; rb = rb_prev(rb)) {
		pg = container_of(rb, struct genz_page_grid, base_pte_node);
		end_pte = pg->page_grid.base_pte_index +
			pg->page_grid.page_count - 1;
		if ((max_pte - end_pte) >= page_count) {  /* use range above pg */
			min_pte = end_pte + 1;
			break;
		} else {
			max_pte = pg->page_grid.base_pte_index - 1;
		}
	}

	if ((max_pte - min_pte + 1) >= page_count) {  /* found a range */
		/* set base_pte_index */
		pgi->pg[pg_index].page_grid.base_pte_index = min_pte;
		/* add genz_pg to rbtree */
		ret = zmmu_base_pte_insert(pgi, pg_index);
		if (ret == 0)
			ret = min_pte;
	}

	return ret;
}

static struct genz_page_grid *zmmu_pg_pte_search(
	struct genz_page_grid_info *pgi, uint pg_index)
{
	struct genz_page_grid *pg;
	struct rb_node *node;
	struct rb_root *root = &pgi->base_pte_tree;
	uint pte_index = pgi->pg[pg_index].page_grid.base_pte_index;

	/* caller must hold bridge zmmu lock */
	node = root->rb_node;

	while (node) {
		int result;

		pg = container_of(node, struct genz_page_grid, base_pte_node);
		result = arithcmp(pte_index, pg->page_grid.base_pte_index);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return pg;
	}

	return NULL;
}

static void zmmu_free_pg_pte_range(struct genz_page_grid_info *pgi,
				   uint pg_index)
{
	struct genz_page_grid *pg;

	/* caller must hold bridge dev zmmu lock */
	pg = zmmu_pg_pte_search(pgi, pg_index);
	rb_erase(&pg->base_pte_node, &pgi->base_pte_tree);
	pgi->pg[pg_index].page_grid.page_count = 0;
}

static struct genz_page_grid *zmmu_pg_addr_search(
	struct genz_page_grid_info *pgi, uint pg_index)
{
	struct genz_page_grid *pg;
	struct rb_node *node;
	struct rb_root *root = &pgi->base_addr_tree;
	uint64_t base_addr = pgi->pg[pg_index].page_grid.pg_base_address;

	/* caller must hold bridge dev zmmu lock */
	node = root->rb_node;

	while (node) {
		int result;

		pg = container_of(node, struct genz_page_grid, base_addr_node);
		result = arithcmp(base_addr, pg->page_grid.pg_base_address);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return pg;
	}

	return NULL;
}

static void zmmu_free_pg_addr_range(struct genz_page_grid_info *pgi,
				    uint pg_index)
{
	struct genz_page_grid *pg;

	/* caller must hold bridge dev zmmu lock */
	pg = zmmu_pg_addr_search(pgi, pg_index);
	rb_erase(&pg->base_addr_node, &pgi->base_addr_tree);
	pgi->pg[pg_index].page_grid.pg_base_address = 0;
}

static uint get_uint_len(uint val)
{
	uint l = 1;

	while (val > 9) {
		l++;
		val /= 10;
	}

	return l;
}

char *genz_page_grid_name(uint pg_index)
{
	char *name, *base = "Req Page Grid ";
	size_t len, base_len = strlen(base);

	len = base_len + get_uint_len(pg_index) + 1;
	name = kmalloc(len, GFP_KERNEL);
	if (name) {
		strcpy(name, base);
		sprintf(&name[base_len], "%u", pg_index);
	}
	return name;
}

void genz_set_page_grid_res(struct genz_page_grid_info *pgi, uint pg_index,
			    struct genz_bridge_dev *br)
{
	struct genz_bridge_info *bri = &br->br_info;
	struct genz_page_grid   *pg = &pgi->pg[pg_index];
	uint64_t ps;

	if (!pg->cpu_visible)
		return;

	ps = BIT_ULL(pg->page_grid.page_size);
	pg->res.start = genz_pg_addr(pg) + bri->cpuvisible_phys_offset;
	pg->res.end = pg->res.start + (pg->page_grid.page_count * ps) - 1;
	pg->res.flags = IORESOURCE_MEM;
	pg->res.name = genz_page_grid_name(pg_index);
	insert_resource(&br->ld_st_res, &pg->res);
}

int genz_req_page_grid_alloc(struct genz_bridge_dev *br,
			     struct genz_page_grid *grid)
{
	int pg_index, pte_index, err;
	uint64_t base_addr;
	unsigned long key;
	uint entries = br->br_info.nr_req_page_grids;
	struct genz_page_grid *req_pg;
	ulong flags;

	if (!br->br_info.req_zmmu || entries == 0) {
		err = -EINVAL;
		goto out;
	}

	/* allocates memory and may sleep */
	err = radix_tree_preload(GFP_KERNEL);
	if (err < 0)
		goto out;

	spin_lock_irqsave(&br->zmmu_lock, flags);
	/* find & allocate a free page grid */
	pg_index = bitmap_find_free_region(br->zmmu_info.req_zmmu_pg.pg_bitmap,
					   entries, 0);
	if (pg_index < 0) {
		err = pg_index;
		goto unlock;
	}

	/* we assume caller has already checked validity of grid */
	req_pg = &br->zmmu_info.req_zmmu_pg.pg[pg_index];
	*req_pg = *grid;
	req_pg->pte_tree = RB_ROOT;
	/* find & allocate free PTE range */
	pte_index = zmmu_find_pg_pte_range(&br->zmmu_info.req_zmmu_pg,
					   pg_index);
	if (pte_index < 0) {
		err = pte_index;
		goto clear;
	}
	/* find & allocate free phys addr range */
	base_addr = zmmu_find_pg_addr_range(&br->zmmu_info.req_zmmu_pg,
					    pg_index, &br->br_info);
	if (base_addr == GENZ_BASE_ADDR_ERROR) {
		err = -ENOSPC;
		goto free_pte;
	}
	genz_set_page_grid_res(&br->zmmu_info.req_zmmu_pg, pg_index, br);
	set_bit(grid->page_grid.page_size,
		(grid->cpu_visible) ?
		br->zmmu_info.req_zmmu_pg.pg_cpu_visible_ps_bitmap :
		br->zmmu_info.req_zmmu_pg.pg_non_visible_ps_bitmap);
	key = grid->page_grid.page_size +
		((grid->cpu_visible) ? GENZ_PAGE_GRID_MAX_PAGESIZE : 0);
	err = radix_tree_insert(&br->zmmu_info.req_zmmu_pg.pg_pagesize_tree,
				key, &br->zmmu_info.req_zmmu_pg.pg[pg_index]);
	if (err < 0)
		goto free_addr;
	if (grid->humongous)
		br->zmmu_info.req_zmmu_pg.humongous_pg =
			&br->zmmu_info.req_zmmu_pg.pg[pg_index];
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
	radix_tree_preload_end();

	/* call bridge driver to write page grid entry */
	err = br->zbdrv->req_page_grid_write(br, pg_index,
					     br->zmmu_info.req_zmmu_pg.pg);
	if (err < 0) {
		dev_dbg(br->bridge_dev, "req_page_grid_write failed, err=%d\n",
			err);
		/* Revisit: error handling */
	}

	pr_debug("pg[%d]:addr=0x%llx-0x%llx, page_size=%u, page_count=%u, "
		 "base_pte_index=%u, cpu_visible=%d, humongous=%d\n",
		 pg_index, genz_pg_addr(req_pg),
		 genz_pg_addr(req_pg) +
		 (BIT_ULL(req_pg->page_grid.page_size) *
		  req_pg->page_grid.page_count) - 1,
		 req_pg->page_grid.page_size, req_pg->page_grid.page_count,
		 req_pg->page_grid.base_pte_index, req_pg->cpu_visible,
		 req_pg->humongous);

	return pg_index;

free_addr:
	zmmu_free_pg_addr_range(&br->zmmu_info.req_zmmu_pg, pg_index);

free_pte:
	zmmu_free_pg_pte_range(&br->zmmu_info.req_zmmu_pg, pg_index);

clear:
	bitmap_clear(br->zmmu_info.req_zmmu_pg.pg_bitmap, pg_index, 1);

unlock:
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
	radix_tree_preload_end();

out:
	return err;
}

int genz_rsp_page_grid_alloc(struct genz_bridge_dev *br,
			     struct genz_page_grid *grid)
{
	int pg_index, pte_index, err;
	uint64_t base_addr;
	uint entries = br->br_info.nr_rsp_page_grids;
	struct genz_page_grid *rsp_pg;
	ulong flags;

	if (!br->br_info.rsp_zmmu || entries == 0) {
		err = -EINVAL;
		goto out;
	}

	/* allocates memory and may sleep */
	err = radix_tree_preload(GFP_KERNEL);
	if (err < 0)
		goto out;

	spin_lock_irqsave(&br->zmmu_lock, flags);
	/* find & allocate a free page grid */
	pg_index = bitmap_find_free_region(br->zmmu_info.rsp_zmmu_pg.pg_bitmap,
					   entries, 0);
	if (pg_index < 0) {
		err = pg_index;
		goto unlock;
	}

	/* cpu_visible does not apply to responder ZMMU */
	grid->cpu_visible = 0;
	/* we assume caller has already checked validity of grid */
	rsp_pg = &br->zmmu_info.rsp_zmmu_pg.pg[pg_index];
	*rsp_pg = *grid;
	rsp_pg->pte_tree = RB_ROOT;
	/* find & allocate free PTE range */
	pte_index = zmmu_find_pg_pte_range(&br->zmmu_info.rsp_zmmu_pg,
					   pg_index);
	if (pte_index < 0) {
		err = pte_index;
		goto clear;
	}
	/* find & allocate free zaddr range */
	base_addr = zmmu_find_pg_addr_range(&br->zmmu_info.rsp_zmmu_pg,
					    pg_index, &br->br_info);
	if (base_addr == GENZ_BASE_ADDR_ERROR) {
		err = -ENOSPC;
		goto free_pte;
	}

	set_bit(grid->page_grid.page_size,
		br->zmmu_info.rsp_zmmu_pg.pg_non_visible_ps_bitmap);
	err = radix_tree_insert(&br->zmmu_info.rsp_zmmu_pg.pg_pagesize_tree,
				grid->page_grid.page_size,
				&br->zmmu_info.rsp_zmmu_pg.pg[pg_index]);
	if (err < 0)
		goto free_addr;
	if (grid->humongous)
		br->zmmu_info.rsp_zmmu_pg.humongous_pg =
			&br->zmmu_info.rsp_zmmu_pg.pg[pg_index];
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
	radix_tree_preload_end();

	/* call bridge driver to write page grid entry */
	err = br->zbdrv->rsp_page_grid_write(br, pg_index,
					     br->zmmu_info.rsp_zmmu_pg.pg);
	if (err < 0) {
		dev_dbg(br->bridge_dev, "rsp_page_grid_write failed, err=%d\n",
			err);
		/* Revisit: error handling */
	}

	pr_debug("pg[%d]:addr=0x%llx-0x%llx, page_size=%u, page_count=%u, "
		 "base_pte_index=%u, humongous=%d\n",
		 pg_index, genz_pg_addr(rsp_pg),
		 genz_pg_addr(rsp_pg) +
		 (BIT_ULL(rsp_pg->page_grid.page_size) *
		  rsp_pg->page_grid.page_count) - 1,
		 rsp_pg->page_grid.page_size, rsp_pg->page_grid.page_count,
		 rsp_pg->page_grid.base_pte_index,
		 rsp_pg->humongous);

	return pg_index;

free_addr:
	zmmu_free_pg_addr_range(&br->zmmu_info.rsp_zmmu_pg, pg_index);

free_pte:
	zmmu_free_pg_pte_range(&br->zmmu_info.rsp_zmmu_pg, pg_index);

clear:
	bitmap_clear(br->zmmu_info.rsp_zmmu_pg.pg_bitmap, pg_index, 1);

unlock:
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
	radix_tree_preload_end();

out:
	return err;
}

static struct genz_page_grid *zmmu_pg_page_size(struct genz_pte_info *ptei,
						struct genz_page_grid_info *pgi)
{
	uint64_t addr_aligned, length_adjusted;
	struct genz_page_grid *gz_pg;
	int ps;
	unsigned long key;
	bool cpu_visible = !!(ptei->access & GENZ_MR_REQ_CPU);

	/* Revisit: make this more general */
	if (ptei->humongous) {
		gz_pg = pgi->humongous_pg;
		ps = gz_pg->page_grid.page_size;
		ptei->length = BIT_ULL(ps);
		ptei->addr &= ~(BIT_ULL(ps) - 1ull);
	} else {
		length_adjusted = roundup_pow_of_two(ptei->length);
		addr_aligned = ROUND_DOWN_PAGE(ptei->addr, length_adjusted);
		if (addr_aligned != ptei->addr)
			length_adjusted <<= 1;
		ps = clamp(ilog2(length_adjusted),
			   GENZ_PAGE_GRID_MIN_PAGESIZE,
			   GENZ_PAGE_GRID_MAX_PAGESIZE);
		/* try to find a page the fits the (adjusted) length */
		ps = find_next_bit(
			(cpu_visible) ? pgi->pg_cpu_visible_ps_bitmap :
			pgi->pg_non_visible_ps_bitmap, PAGE_GRID_PS_BITS, ps);
		/* if that fails, then the largest available */
		if (ps == PAGE_GRID_PS_BITS)
			ps = find_last_bit((cpu_visible) ?
					   pgi->pg_cpu_visible_ps_bitmap :
					   pgi->pg_non_visible_ps_bitmap,
					   PAGE_GRID_PS_BITS);
		key = ps + ((cpu_visible) ? GENZ_PAGE_GRID_MAX_PAGESIZE : 0);
		gz_pg = radix_tree_lookup(&pgi->pg_pagesize_tree, key);
	}

	if (gz_pg) {
		addr_aligned = ROUND_DOWN_PAGE(ptei->addr, BIT_ULL(ps));
		ptei->addr_aligned = addr_aligned;
		ptei->zmmu_pages = ROUND_UP_PAGE(
			ptei->length + (ptei->addr - addr_aligned),
			BIT_ULL(ps)) >> ps;
		ptei->length_adjusted = ptei->zmmu_pages * BIT_ULL(ps);
		if (ptei->humongous)
			ptei->length = ptei->length_adjusted;
	} else {
		ps = -ENOSPC;
	}

	pr_debug("addr_aligned=0x%llx, length_adjusted=0x%llx, page_size=%d, gz_pg=%px\n",
	       ptei->addr_aligned, ptei->length_adjusted, ps, gz_pg);
	return (ps < 0) ? ERR_PTR(ps) : gz_pg;
}

static int zmmu_pte_insert(struct genz_pte_info *ptei,
			   struct genz_page_grid *pg)
{
	struct rb_root *root = &pg->pte_tree;
	struct rb_node **new = &root->rb_node, *parent = NULL;

	/* caller must hold bridge zmmu lock */

	/* figure out where to put new node */
	while (*new) {
		struct genz_pte_info *this =
			container_of(*new, struct genz_pte_info, node);
		int result = arithcmp(ptei->pte_index, this->pte_index);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else  /* already there */
			return -EEXIST;
	}

	/* add new node and rebalance tree */
	rb_link_node(&ptei->node, parent, new);
	rb_insert_color(&ptei->node, root);
	ptei->pg = pg;
	return 0;
}

static void zmmu_pte_erase(struct genz_pte_info *ptei)
{
	/* caller must hold bridge zmmu lock */
	if (ptei->pg != NULL) {
		rb_erase(&ptei->node, &ptei->pg->pte_tree);
		ptei->pg = NULL;
	}
}

static int zmmu_find_pte_range(struct genz_pte_info *ptei,
			       struct genz_page_grid *pg)
{
	struct rb_node *rb;
	struct genz_pte_info *this;
	uint page_count = ptei->zmmu_pages;
	uint min_pte = pg->page_grid.base_pte_index;
	uint max_pte = min_pte + pg->page_grid.page_count - 1;
	uint end_pte;
	int ret = -ENOSPC;

	/* caller must hold bridge zmmu lock */

	for (rb = rb_last(&pg->pte_tree); rb; rb = rb_prev(rb)) {
		this = container_of(rb, struct genz_pte_info, node);
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
		ptei->pte_index = min_pte;
		/* add ptei to rbtree */
		ret = zmmu_pte_insert(ptei, pg);
		if (ret == 0)
			ret = min_pte;
	}

	pr_debug("ret=%d, addr=0x%llx\n", ret, ptei->addr);
	return ret;
}

int genz_zmmu_req_pte_alloc(struct genz_pte_info *ptei,
			    struct genz_rmr_info *rmri)
{
	struct genz_bridge_dev      *br = ptei->bridge;
	struct genz_page_grid_info  *pgi = &br->zmmu_info.req_zmmu_pg;
	struct genz_page_grid       *gz_pg;
	int                         ret;
	ulong                       flags;

	spin_lock_irqsave(&br->zmmu_lock, flags);
	gz_pg = zmmu_pg_page_size(ptei, pgi);
	if (IS_ERR(gz_pg)) {
		ret = PTR_ERR(gz_pg);
		goto unlock;
	}

	ret = zmmu_find_pte_range(ptei, gz_pg);
	if (ret < 0)
		goto unlock;

	rmri->req_addr = genz_zmmu_pte_addr(ptei, ptei->addr);
	rmri->pg_ps = gz_pg->page_grid.page_size;
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
	pr_debug("pte_index=%u, zmmu_pages=%u, pg_ps=%u\n",
		 ptei->pte_index, ptei->zmmu_pages, rmri->pg_ps);

	if (br->zbdrv->req_pte_write) { /* call bridge driver to write HW PTE */
		ret = br->zbdrv->req_pte_write(br, ptei);
	} else {
		ret = -EINVAL;
		goto out;
	}

	if (ret < 0) {
		/* Revisit: deallocate PTE? */
	}

out:
	pr_debug("ret=%d, addr=0x%llx\n", ret, ptei->addr);
	return ret;

unlock:
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
	goto out;
}
EXPORT_SYMBOL(genz_zmmu_req_pte_alloc);

void genz_zmmu_req_pte_free(struct genz_pte_info *ptei)
{
	struct genz_bridge_dev *br = ptei->bridge;
	ulong                  flags;

	pr_debug("pte_index=%u, zmmu_pages=%u\n",
		 ptei->pte_index, ptei->zmmu_pages);

	if (br->zbdrv->req_pte_clear) { /* call bridge driver to clear HW PTE */
		br->zbdrv->req_pte_clear(br, ptei);
	}

	spin_lock_irqsave(&br->zmmu_lock, flags);
	zmmu_pte_erase(ptei);
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
}
EXPORT_SYMBOL(genz_zmmu_req_pte_free);

int genz_zmmu_rsp_pte_alloc(struct genz_pte_info *ptei, uint64_t *rsp_zaddr,
			    uint32_t *pg_ps)
{
	struct genz_bridge_dev      *br = ptei->bridge;
	struct genz_page_grid_info  *pgi = &br->zmmu_info.rsp_zmmu_pg;
	struct genz_page_grid       *gz_pg;
	int                         ret;
	ulong                       flags;

	spin_lock_irqsave(&br->zmmu_lock, flags);
	gz_pg = zmmu_pg_page_size(ptei, pgi);
	if (IS_ERR(gz_pg)) {
		ret = PTR_ERR(gz_pg);
		goto unlock;
	}

	ret = zmmu_find_pte_range(ptei, gz_pg);
	if (ret < 0)
		goto unlock;

	*rsp_zaddr = genz_zmmu_pte_addr(ptei, ptei->addr);
	*pg_ps = gz_pg->page_grid.page_size;
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
	pr_debug("pte_index=%u, zmmu_pages=%u, pg_ps=%u\n",
		 ptei->pte_index, ptei->zmmu_pages, *pg_ps);

	if (br->zbdrv->rsp_pte_write) { /* call bridge driver to write HW PTE */
		ret = br->zbdrv->rsp_pte_write(br, ptei);
	} else {
		ret = -EINVAL;
		goto out;
	}

	if (ret < 0) {
		/* Revisit: deallocate PTE? */
	}

out:
	pr_debug("ret=%d, addr=0x%llx\n", ret, ptei->addr);
	return ret;

unlock:
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
	goto out;
}
EXPORT_SYMBOL(genz_zmmu_rsp_pte_alloc);

void genz_zmmu_rsp_pte_free(struct genz_pte_info *ptei)
{
	struct genz_bridge_dev *br = ptei->bridge;
	ulong                  flags;

	pr_debug("pte_index=%u, zmmu_pages=%u\n",
		 ptei->pte_index, ptei->zmmu_pages);

	if (br->zbdrv->rsp_pte_clear) { /* call bridge driver to clear HW PTE */
		br->zbdrv->rsp_pte_clear(br, ptei);
	}

	spin_lock_irqsave(&br->zmmu_lock, flags);
	zmmu_pte_erase(ptei);
	spin_unlock_irqrestore(&br->zmmu_lock, flags);
}
EXPORT_SYMBOL(genz_zmmu_rsp_pte_free);
