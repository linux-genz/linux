// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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

#include <linux/slab.h>
#include <linux/bitops.h>
#include "genz-control.h"
#include "genz.h"

/* Revisit: genz_pg_restricted_pg_table_array field names */
#define page_size page_size_0
#define page_count page_count_0
#define pg_base_address pg_base_address_0
#define base_pte_index base_pte_index_0


struct genz_zmmu_info *genz_zdev_zmmu_info(struct genz_dev *zdev)
{
	struct genz_zmmu_info *zi = NULL;

	if (zdev != NULL && zdev->zcomp != NULL)
		zi = zdev->zcomp->zmmu_info;

	return zi;
}
EXPORT_SYMBOL(genz_zdev_zmmu_info);

uint64_t genz_zmmu_pte_addr(const struct genz_pte_info *ptei, uint64_t addr)
{
	uint64_t base_addr, ps, pte_off;
	struct genz_page_grid *pg = ptei->pg;

	if (!pg)
		return GENZ_BASE_ADDR_ERROR;

	base_addr = genz_pg_addr(pg);
	ps = genz_pg_ps(pg);
	pte_off = ptei->pte_index - pg->page_grid.base_pte_index;
	return base_addr + (pte_off * ps) + (addr - ptei->addr_aligned);
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

void genz_zmmu_clear_all(struct genz_zmmu_info *zi, bool free_radix_tree)
{
	ulong flags;

	pr_debug("zi=%px, free_radix_tree=%u\n", zi, free_radix_tree);
	spin_lock_irqsave(&zi->zmmu_lock, flags);
	zmmu_clear_pg_info(&zi->req_zmmu_pg,
			   zi->pg_config->nr_req_ptes, free_radix_tree);
	zmmu_clear_pg_info(&zi->rsp_zmmu_pg,
			   zi->pg_config->nr_rsp_ptes, free_radix_tree);
	spin_unlock_irqrestore(&zi->zmmu_lock, flags);
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
		pr_debug("calling parse_page_grid_one(s=%s,max_page_count=%llu, &pg[%u]=%px)\n",
			 s, max_page_count, cnt, &pg[cnt]);
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

	/* caller must hold zmmu lock */

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

	/* caller must hold zmmu lock */

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

static uint64_t zmmu_find_pg_addr_range(struct genz_page_grid_info *pgi,
					uint pg_index,
					struct genz_page_grid_config *pgc)
{
	struct genz_page_grid *pg;
	struct rb_node *rb;
	bool cpu_visible    = pgi->pg[pg_index].cpu_visible;
	uint64_t page_count = pgi->pg[pg_index].page_grid.page_count;
	uint64_t page_size  = genz_pg_ps(&pgi->pg[pg_index]);
	uint64_t range      = page_size * page_count;
	uint64_t min_addr   = (cpu_visible) ?
		ROUND_UP_PAGE(pgc->min_cpuvisible_addr, page_size) :
		ROUND_UP_PAGE(pgc->min_nonvisible_addr, page_size);
	uint64_t max_addr   = (cpu_visible) ?
		pgc->max_cpuvisible_addr : pgc->max_nonvisible_addr;
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
		prev_base = pg_addr;  /* Revisit: debug */
		base_addr = ROUND_DOWN_PAGE(pg_addr, page_size);
		next_addr = ROUND_UP_PAGE(pg_addr + genz_pg_size(pg),
					  page_size);
		pr_debug("pg[0x%llx*%u@0x%llx]:base_addr=0x%llx, "
			 "min_addr=0x%llx, next_addr=0x%llx\n",
			 genz_pg_ps(pg),
			 pg->page_grid.page_count,
			 pg_addr, base_addr, min_addr, next_addr);
		if (base_addr < min_addr) {
			if (min_addr < next_addr)
				min_addr = next_addr;
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

	/* caller must hold zmmu lock */

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

	/* caller must hold zmmu lock */
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

	/* caller must hold zmmu lock */
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

	/* caller must hold zmmu lock */
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

	/* caller must hold zmmu lock */
	pg = zmmu_pg_addr_search(pgi, pg_index);
	rb_erase(&pg->base_addr_node, &pgi->base_addr_tree);
	pgi->pg[pg_index].page_grid.pg_base_address = 0;
}

char *genz_page_grid_name(uint ps, uint pg_index)
{
	char *name, *base = "Req Page Grid ";
	char ps_str[5];
	size_t len, base_len = strlen(base);
	struct {
		uint min;
		uint max;
		uint base;
		char *suffix;
	} sz_data[] = {
		{  0,  11,  0, "" },  /* should not happen */
		{ 12,  19, 10, "K " },
		{ 20,  29, 20, "M " },
		{ 30,  39, 30, "G " },
		{ 40,  49, 40, "T " },
		{ 50,  59, 50, "P " },
		{ 60,  63, 60, "E " },
		{ 64, -1u, 60, "? " } /* should not happen */
	};
	uint i;

	for (i = 0; i < sizeof(sz_data)/sizeof(sz_data[0]); i++) {
		if (ps >= sz_data[i].min && ps <= sz_data[i].max)
			break;
	}
	ps = BIT(ps - sz_data[i].base);
	sprintf(ps_str, "%u%s", ps, sz_data[i].suffix);
	len = 5 + base_len + get_uint_len(pg_index) + 1;
	name = kmalloc(len, GFP_KERNEL);  /* Revisit: never freed */
	if (name) {
		sprintf(name, "%s%s%u", ps_str, base, pg_index);
	}
	return name;
}

void genz_set_page_grid_res(struct genz_page_grid_info *pgi, uint pg_index,
			    struct genz_bridge_dev *br)
{
	struct genz_page_grid_config *pgc = &br->br_info.pg_config;
	struct genz_page_grid        *pg = &pgi->pg[pg_index];
	uint64_t ps;

	if (!pg->cpu_visible)
		return;

	ps = genz_pg_ps(pg);
	pg->res.start = genz_pg_addr(pg) + pgc->cpuvisible_phys_offset;
	pg->res.end = pg->res.start + genz_pg_size(pg) - 1;
	pg->res.flags = IORESOURCE_MEM;
	pg->res.name = genz_page_grid_name(pg->page_grid.page_size, pg_index);
	insert_resource(&br->ld_st_res, &pg->res);
}

void genz_release_page_grid_res(struct genz_page_grid_info *pgi, uint pg_index)
{
	struct genz_page_grid   *pg = &pgi->pg[pg_index];

	remove_resource(&pg->res);
	/* Revisit: free res.name */
}

void genz_release_page_grid_res_all(struct genz_bridge_dev *br)
{
	uint entries = br->br_info.pg_config.nr_req_page_grids;
	struct genz_page_grid_info *pgi = &br->zmmu_info.req_zmmu_pg;
	uint pg_index;

	if (!(br->br_info.req_zmmu && entries > 0))
		return;

	for_each_set_bit(pg_index,
			 br->zmmu_info.req_zmmu_pg.pg_bitmap, entries) {
		genz_release_page_grid_res(pgi, pg_index);
	}
}

int genz_req_page_grid_alloc(struct genz_dev *zdev,
			     struct genz_zmmu_info *zi,
			     struct genz_page_grid *grid)
{
	int pg_index, pte_index, err;
	uint64_t base_addr;
	unsigned long key;
	uint entries = zi->pg_config->nr_req_page_grids;
	struct genz_bridge_dev *br = zdev->zbdev;
	struct device *dev = &zdev->dev;
	struct genz_page_grid *req_pg;
	struct genz_rmr_info *rmri;
	ulong flags;

	if (entries == 0) {
		err = -EINVAL;
		goto out;
	}

	/* allocates memory and may sleep */
	err = radix_tree_preload(GFP_KERNEL);
	if (err < 0)
		goto out;

	spin_lock_irqsave(&zi->zmmu_lock, flags);
	/* find & allocate a free page grid */
	pg_index = bitmap_find_free_region(zi->req_zmmu_pg.pg_bitmap,
					   entries, 0);
	if (pg_index < 0) {
		err = pg_index;
		goto unlock;
	}

	/* we assume caller has already checked validity of grid */
	req_pg = &zi->req_zmmu_pg.pg[pg_index];
	*req_pg = *grid;
	req_pg->pte_tree = RB_ROOT;
	/* find & allocate free PTE range */
	pte_index = zmmu_find_pg_pte_range(&zi->req_zmmu_pg, pg_index);
	if (pte_index < 0) {
		err = pte_index;
		goto clear;
	}
	/* find & allocate free phys addr range */
	base_addr = zmmu_find_pg_addr_range(&zi->req_zmmu_pg,
					    pg_index, zi->pg_config);
	if (base_addr == GENZ_BASE_ADDR_ERROR) {
		err = -ENOSPC;
		goto free_pte;
	}
	rmri = zi->req_zmmu_pg.pg_rmri[GENZ_PG_TABLE];
	if (genz_is_local_bridge(br, rmri))
		genz_set_page_grid_res(&zi->req_zmmu_pg, pg_index, br);
	set_bit(grid->page_grid.page_size,
		(grid->cpu_visible) ?
		zi->req_zmmu_pg.pg_cpu_visible_ps_bitmap :
		zi->req_zmmu_pg.pg_non_visible_ps_bitmap);
	key = grid->page_grid.page_size +
		((grid->cpu_visible) ? GENZ_PAGE_GRID_MAX_PAGESIZE : 0);
	err = radix_tree_insert(&zi->req_zmmu_pg.pg_pagesize_tree,
				key, &zi->req_zmmu_pg.pg[pg_index]);
	if (err < 0)
		goto free_addr;
	if (grid->humongous)
		zi->req_zmmu_pg.humongous_pg =
			&zi->req_zmmu_pg.pg[pg_index];
	spin_unlock_irqrestore(&zi->zmmu_lock, flags);
	radix_tree_preload_end();

	/* call bridge driver to write page grid entry */
	if (!br->zbdrv->req_page_grid_write) {
		dev_dbg(dev, "req_page_grid_write is NULL\n");
		err = -EINVAL;
		goto free_radix;
	}
	err = br->zbdrv->req_page_grid_write(br, pg_index,
					     zi->req_zmmu_pg.pg, zi);
	if (err < 0) {
		dev_dbg(dev, "req_page_grid_write failed, err=%d\n", err);
		goto free_radix;
	}

	dev_dbg(dev, "pg[%d]:addr=0x%llx-0x%llx, page_size=%u, page_count=%u, "
		"base_pte_index=%u, cpu_visible=%d, humongous=%d\n",
		pg_index, genz_pg_addr(req_pg),
		genz_pg_addr(req_pg) + genz_pg_size(req_pg) - 1,
		req_pg->page_grid.page_size, req_pg->page_grid.page_count,
		req_pg->page_grid.base_pte_index, req_pg->cpu_visible,
		req_pg->humongous);

	return pg_index;

free_radix:
	radix_tree_delete(&zi->req_zmmu_pg.pg_pagesize_tree, key);
free_addr:
	genz_release_page_grid_res(&zi->req_zmmu_pg, pg_index);
	clear_bit(grid->page_grid.page_size,
		  (grid->cpu_visible) ?
		  zi->req_zmmu_pg.pg_cpu_visible_ps_bitmap :
		  zi->req_zmmu_pg.pg_non_visible_ps_bitmap);
	zmmu_free_pg_addr_range(&zi->req_zmmu_pg, pg_index);
free_pte:
	zmmu_free_pg_pte_range(&zi->req_zmmu_pg, pg_index);
clear:
	bitmap_clear(zi->req_zmmu_pg.pg_bitmap, pg_index, 1);
unlock:
	spin_unlock_irqrestore(&zi->zmmu_lock, flags);
	radix_tree_preload_end();
out:
	return err;
}
EXPORT_SYMBOL(genz_req_page_grid_alloc);

int genz_rsp_page_grid_alloc(struct genz_bridge_dev *br,
			     struct genz_page_grid *grid)
{
	int pg_index, pte_index, err;
	uint64_t base_addr;
	uint entries = br->br_info.pg_config.nr_rsp_page_grids;
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

	spin_lock_irqsave(&br->zmmu_info.zmmu_lock, flags);
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
					    pg_index, &br->br_info.pg_config);
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
	spin_unlock_irqrestore(&br->zmmu_info.zmmu_lock, flags);
	radix_tree_preload_end();

	/* call bridge driver to write page grid entry */
	if (!br->zbdrv->rsp_page_grid_write) {
		dev_dbg(br->bridge_dev, "rsp_page_grid_write is NULL\n");
		err = -EINVAL;
		goto free_radix;
	}
	err = br->zbdrv->rsp_page_grid_write(br, pg_index,
					     br->zmmu_info.rsp_zmmu_pg.pg);
	if (err < 0) {
		dev_dbg(br->bridge_dev, "rsp_page_grid_write failed, err=%d\n",
			err);
		goto free_radix;
	}

	pr_debug("pg[%d]:addr=0x%llx-0x%llx, page_size=%u, page_count=%u, "
		 "base_pte_index=%u, humongous=%d\n",
		 pg_index, genz_pg_addr(rsp_pg),
		 genz_pg_addr(rsp_pg) + genz_pg_size(rsp_pg) - 1,
		 rsp_pg->page_grid.page_size, rsp_pg->page_grid.page_count,
		 rsp_pg->page_grid.base_pte_index,
		 rsp_pg->humongous);

	return pg_index;

free_radix:
	radix_tree_delete(&br->zmmu_info.rsp_zmmu_pg.pg_pagesize_tree,
			  grid->page_grid.page_size);
free_addr:
	zmmu_free_pg_addr_range(&br->zmmu_info.rsp_zmmu_pg, pg_index);
	clear_bit(grid->page_grid.page_size,
		  br->zmmu_info.rsp_zmmu_pg.pg_non_visible_ps_bitmap);
free_pte:
	zmmu_free_pg_pte_range(&br->zmmu_info.rsp_zmmu_pg, pg_index);
clear:
	bitmap_clear(br->zmmu_info.rsp_zmmu_pg.pg_bitmap, pg_index, 1);
unlock:
	spin_unlock_irqrestore(&br->zmmu_info.zmmu_lock, flags);
	radix_tree_preload_end();
out:
	return err;
}

static struct genz_page_grid *zmmu_pg_page_size(struct genz_pte_info *ptei,
						struct genz_page_grid_info *pgi)
{
	uint64_t addr_aligned, length_adjusted, len_ps;
	struct genz_page_grid *gz_pg;
	int ps, ps8;
	unsigned long key;
	bool cpu_visible = !!(ptei->access & GENZ_MR_REQ_CPU);
	const unsigned long *bm = (cpu_visible) ?
		pgi->pg_cpu_visible_ps_bitmap : pgi->pg_non_visible_ps_bitmap;

	if (ptei->humongous) {
		gz_pg = pgi->humongous_pg;
		ps = gz_pg->page_grid.page_size;
		ptei->length = BIT_ULL(ps);
		ptei->addr &= ~(BIT_ULL(ps) - 1ull);
	} else {
		// Revisit: this fails if length is 0
		length_adjusted = roundup_pow_of_two(ptei->length);
		addr_aligned = ROUND_DOWN_PAGE(ptei->addr, length_adjusted);
		if ((addr_aligned + length_adjusted - 1) <
		    (ptei->addr + ptei->length - 1))
			length_adjusted <<= 1;
		len_ps = clamp(ilog2(length_adjusted),
			       GENZ_PAGE_GRID_MIN_PAGESIZE,
			       GENZ_PAGE_GRID_MAX_PAGESIZE);
		/* try to find a page that exactly fits the (adjusted) length */
		ps = find_next_bit(bm, PAGE_GRID_PS_BITS, len_ps);
		if (ps > len_ps) {
			/* or a (smaller) page size requiring <= 8 PTEs */
			ps8 = find_next_bit(bm, PAGE_GRID_PS_BITS, len_ps - 3);
			ps = (ps8 < ps) ? ps8 : ps;
		}
		/* if that fails, then the largest available */
		if (ps == PAGE_GRID_PS_BITS)
			ps = find_last_bit(bm, PAGE_GRID_PS_BITS);
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

	/* caller must zmmu lock */

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

int genz_zmmu_req_pte_update(struct genz_pte_info *ptei)
{
	struct genz_bridge_dev *br = ptei->bridge;
	int                    ret;

	pr_debug("pte_index=%u, zmmu_pages=%u, zi=%px\n",
		 ptei->pte_index, ptei->zmmu_pages, ptei->zi);

	if (br->zbdrv->req_pte_write) { /* call bridge driver to write HW PTE */
		ret = br->zbdrv->req_pte_write(br, ptei, ptei->zi);
	} else {
		ret = genz_req_pte_write(br, ptei, ptei->zi);
	}

	pr_debug("ret=%d, addr=0x%llx\n", ret, ptei->addr);
	return ret;
}
EXPORT_SYMBOL(genz_zmmu_req_pte_update);

int genz_zmmu_req_pte_alloc(struct genz_pte_info *ptei,
			    struct genz_rmr_info *rmri)
{
	struct genz_bridge_dev      *br = ptei->bridge;
	struct genz_page_grid_info  *pgi = &br->zmmu_info.req_zmmu_pg;
	struct genz_page_grid       *gz_pg;
	int                         ret;
	ulong                       flags;

	spin_lock_irqsave(&br->zmmu_info.zmmu_lock, flags);
	gz_pg = zmmu_pg_page_size(ptei, pgi);
	if (IS_ERR(gz_pg)) {
		ret = PTR_ERR(gz_pg);
		goto unlock;
	}

	ret = zmmu_find_pte_range(ptei, gz_pg);
	if (ret < 0)
		goto err_pte;

	rmri->req_addr = genz_zmmu_pte_addr(ptei, ptei->addr);
	rmri->pg_ps = gz_pg->page_grid.page_size;
	spin_unlock_irqrestore(&br->zmmu_info.zmmu_lock, flags);
	pr_debug("pte_index=%u, zmmu_pages=%u, pg_ps=%u\n",
		 ptei->pte_index, ptei->zmmu_pages, rmri->pg_ps);

	ret = genz_zmmu_req_pte_update(ptei); /* update PTEs */
	if (ret < 0) {
		/* Revisit: deallocate PTE? */
		goto out;
	}

	rmri->access |= GENZ_MR_MAPPED;

out:
	pr_debug("ret=%d, addr=0x%llx\n", ret, ptei->addr);
	return ret;

err_pte:
	ptei->zmmu_pages = 0;
unlock:
	spin_unlock_irqrestore(&br->zmmu_info.zmmu_lock, flags);
	goto out;
}
EXPORT_SYMBOL(genz_zmmu_req_pte_alloc);

void genz_zmmu_req_pte_free(struct genz_pte_info *ptei)
{
	struct genz_bridge_dev *br = ptei->bridge;
	ulong                  flags;

	pr_debug("pte_index=%u, zmmu_pages=%u\n",
		 ptei->pte_index, ptei->zmmu_pages);
	if (ptei->zmmu_pages == 0)
		return;
	ptei->pte.req.v = 0;
	if (br->zbdrv->req_pte_write) { /* call bridge driver to clear HW PTE */
		br->zbdrv->req_pte_write(br, ptei, ptei->zi);
	}

	spin_lock_irqsave(&br->zmmu_info.zmmu_lock, flags);
	zmmu_pte_erase(ptei);
	spin_unlock_irqrestore(&br->zmmu_info.zmmu_lock, flags);
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

	spin_lock_irqsave(&br->zmmu_info.zmmu_lock, flags);
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
	spin_unlock_irqrestore(&br->zmmu_info.zmmu_lock, flags);
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
	spin_unlock_irqrestore(&br->zmmu_info.zmmu_lock, flags);
	goto out;
}
EXPORT_SYMBOL(genz_zmmu_rsp_pte_alloc);

void genz_zmmu_rsp_pte_free(struct genz_pte_info *ptei)
{
	struct genz_bridge_dev *br = ptei->bridge;
	ulong                  flags;

	pr_debug("pte_index=%u, zmmu_pages=%u\n",
		 ptei->pte_index, ptei->zmmu_pages);
	if (ptei->zmmu_pages == 0)
		return;
	ptei->pte.rsp.v = 0;
	if (br->zbdrv->rsp_pte_write) { /* call bridge driver to clear HW PTE */
		br->zbdrv->rsp_pte_write(br, ptei);
	}

	spin_lock_irqsave(&br->zmmu_info.zmmu_lock, flags);
	zmmu_pte_erase(ptei);
	spin_unlock_irqrestore(&br->zmmu_info.zmmu_lock, flags);
}
EXPORT_SYMBOL(genz_zmmu_rsp_pte_free);

static void genz_req_pte_field_cfg(struct genz_req_pte_config *cfg,
				   struct genz_req_pte_attr_63_0 attr, bool et)
{
	uint16_t pos = 0;
	bool sup;

	cfg->valid.width = 1;             // valid always bit 0
	cfg->valid.start = pos++;

	cfg->et.width = et;               // ET only for page table PTEs
	cfg->et.start = pos;
	pos += et;

	cfg->d_attr.width = 3;            // d-attr always 3 bits
	cfg->d_attr.start = pos;
	pos += 3;

	cfg->st.width = attr.st_drc_sup;  // ST is 1 bit if st_drc_sup
	cfg->st.start = pos;
	pos += attr.st_drc_sup;

	cfg->drc.width = attr.st_drc_sup; // DRC is 1 bit if st_drc_sup
	cfg->drc.start = pos;
	pos += attr.st_drc_sup;

	cfg->pp = cfg->drc;               // PP shares bit with DRC

	cfg->cce.width = attr.cce_sup;    // CCE is 1 bit if cce_sup
	cfg->cce.start = pos;
	pos += attr.cce_sup;

	cfg->ce.width = attr.ce_sup;      // CE is 1 bit if ce_sup
	cfg->ce.start = pos;
	pos += attr.ce_sup;

	cfg->wpe.width = attr.wpe_sup;    // WPE is 1 bit if wpe_sup
	cfg->wpe.start = pos;
	pos += attr.wpe_sup;

	sup = attr.pasid_sz > 0;          // PSE is 1 bit if pasid_sz > 0
	cfg->pse.width = sup;
	cfg->pse.start = pos;
	pos += sup;

	cfg->pfme.width = attr.pfme_sup;  // PFME is 1 bit if pfme_sup
	cfg->pfme.start = pos;
	pos += attr.pfme_sup;

	cfg->pec.width = attr.pec_sup;    // PEC is 1 bit if pec_sup
	cfg->pec.start = pos;
	pos += attr.pec_sup;

	cfg->lpe.width = attr.lpe_sup;    // LPE is 1 bit if lpe_sup
	cfg->lpe.start = pos;
	pos += attr.lpe_sup;

	cfg->nse.width = attr.nse_sup;    // NSE is 1 bit if nse_sup
	cfg->nse.start = pos;
	pos += attr.nse_sup;

	cfg->wr_mode.width = 3;           // Write Mode always 3 bits
	cfg->wr_mode.start = pos;
	pos += 3;

	cfg->tc.width = 4 * attr.tc_sup;  // TC is 4 bits if tc_sup
	cfg->tc.start = pos;
	pos += 4 * attr.tc_sup;

	cfg->pasid.width = attr.pasid_sz; // PASID is 0 - 20 bits
	cfg->pasid.start = pos;
	pos += attr.pasid_sz;

	cfg->loc_dest.width = 12;         // Local Dest always 12 bits
	cfg->loc_dest.start = pos;
	pos += 12;

	cfg->glb_dest.width = attr.pte_gd_sz; // Global Dest is 0 - 16 bits
	cfg->glb_dest.start = pos;
	pos += attr.pte_gd_sz;

	cfg->tr_idx.width = 4 * attr.tr_idx_sup; // TR Index is 4 bits if tr_index_sup
	cfg->tr_idx.start = pos;
	pos += 4 * attr.tr_idx_sup;

	cfg->co.width = 2 * attr.co_sup;  // CO is 2 bits if co_sup
	cfg->co.start = pos;
	pos += 2 * attr.co_sup;

	cfg->rkey.width = 32 * attr.rkey_sup;  // RKey is 32 bits if rkey_sup
	cfg->rkey.start = pos;
	pos += 32 * attr.rkey_sup;

	cfg->addr.width = 52;             // Address always 52 bits
	cfg->addr.start = pos;
	pos += 40;                        // DR Iface overlaps upper addr bits

	cfg->dr_iface.width = 12;         // DR Iface is 12 bits
	cfg->dr_iface.start = pos;
}

static struct genz_zmmu_info *genz_alloc_zmmu_info(struct genz_dev *zdev)
{
	struct device *dev = &zdev->dev;
	struct genz_zmmu_info *zi;
	struct genz_page_grid_config *pgc;

	zi = devm_kzalloc(dev, sizeof(*zi), GFP_KERNEL);
	if (!zi)
		return zi;
	spin_lock_init(&zi->zmmu_lock);
	pgc = devm_kzalloc(dev, sizeof(*pgc), GFP_KERNEL);
	if (!pgc) {
		devm_kfree(dev, zi);
		return 0;
	}
	zi->pg_config = pgc;
	return zi;
}

static int genz_clone_req_page_grid(struct genz_dev *zdev,
				    struct genz_zmmu_info *fr_zi,
				    struct genz_zmmu_info *to_zi)
{
	struct genz_page_grid_config *to_pgc = to_zi->pg_config;
	struct genz_page_grid_info *fr_pgi = &fr_zi->req_zmmu_pg;
	uint fr_pg_index, fr_pg_used, page_count;
	struct device *dev = &zdev->dev;
	int ret = 0;

	fr_pg_used = bitmap_weight(fr_pgi->pg_bitmap, PAGE_GRID_ENTRIES);
	dev_dbg(dev, "fr_pg_used=%u\n", fr_pg_used);
	if (fr_pg_used > to_pgc->nr_req_page_grids)
		return -ENOSPC;
	// Revisit: check to_pgc->nr_req_ptes
	for (fr_pg_index = 0; fr_pg_index < PAGE_GRID_ENTRIES; fr_pg_index++) {
		page_count = fr_pgi->pg[fr_pg_index].page_grid.page_count;
		if (page_count == 0)
			continue;
		ret = genz_req_page_grid_alloc(zdev, to_zi, &fr_pgi->pg[fr_pg_index]);
		if (ret < 0) {
			dev_dbg(dev, "genz_req_page_grid_alloc[fr_pg_index=%u] failed, ret=%d\n",
				fr_pg_index, ret);
			goto out;
		}
		ret = 0; /* map positive pg_index values to 0 */
	}

out:
	return ret;
}

int genz_req_zmmu_setup(struct genz_dev *zdev, struct genz_resource *zres[])
{
	struct genz_component_page_grid_structure pg;
	struct genz_req_pte_attr_63_0 attr;
	struct genz_bridge_dev *zbdev = zdev->zbdev;
	struct genz_page_grid_config *pgc;
	struct device *dev = &zdev->dev;
	struct genz_zmmu_info *zi;
	struct genz_rmr_info *rmri;
	uint64_t access;
	int i, ret = -EINVAL;

	zi = genz_alloc_zmmu_info(zdev);
	if (!zi)
		return -ENOMEM;
	zdev->zcomp->zmmu_info = zi;
	pgc = zi->pg_config;
	access = GENZ_MR_WRITE_REMOTE|GENZ_MR_INDIVIDUAL|GENZ_MR_REQ_CPU|
		 GENZ_MR_CONTROL|GENZ_MR_REQ_CPU_UC|GENZ_MR_PEC;
	/* Revisit: support page-table ZMMUs */
	/* import PGStruct, PGTable, PTETable */
	for (i = 0; i < 3; i++) {  // Revisit: constants
		rmri = devm_genz_rmr_import_zres(zdev, zres[i], access);
		if (IS_ERR(rmri)) {
			ret = PTR_ERR(rmri);
			dev_dbg(dev, "devm_genz_rmr_import_zres failed, ret=%d\n", ret);
			goto out;
		}
		zi->req_zmmu_pg.pg_rmri[i] = rmri;
	}
	/* read component page grid structure */
	rmri = zi->req_zmmu_pg.pg_rmri[GENZ_PG_STRUCT];
	ret = genz_control_read(zbdev, rmri->rsp_zaddr, sizeof(pg), &pg, rmri, 0);
	if (ret != 0)
		goto out;
	attr = *(struct genz_req_pte_attr_63_0 *)&pg.pte_attr_63_0;
	pgc->nr_req_page_grids = genz_sz_0_special(pg.pg_table_sz, 8);
	pgc->nr_req_ptes = genz_sz_0_special(pg.pte_table_sz, 32);
	pgc->req_page_grid_page_sizes = pg.zmmu_supported_page_sizes;
	pgc->pte_sz = pg.pte_sz / 8; /* convert bits to bytes */
	/* genz_zmmu_clear_all depends on pgc->nr_req_ptes */
	genz_zmmu_clear_all(zi, false);
	genz_req_pte_field_cfg(&pgc->req_pte_cfg, attr, /*et*/false);
	/* Revisit: major hack - copy min/max visible_addr values from local bridge */
	pgc->min_cpuvisible_addr = zbdev->br_info.pg_config.min_cpuvisible_addr;
	pgc->max_cpuvisible_addr = zbdev->br_info.pg_config.max_cpuvisible_addr;
	/* Revisit: need nonvisible values too? */
	dev_dbg(dev, "nr_req_page_grids=%u, nr_req_ptes=%llu, req_page_grid_page_sizes=0x%llx, pte_sz=%u, min_cpuvisible_addr=0x%llx, max_cpuvisible_addr=0x%llx\n",
		pgc->nr_req_page_grids, pgc->nr_req_ptes, pgc->req_page_grid_page_sizes,
		pgc->pte_sz, pgc->min_cpuvisible_addr, pgc->max_cpuvisible_addr);
	ret = genz_clone_req_page_grid(zdev, &zbdev->zmmu_info, zi);
	if (ret < 0)
		goto out;
	ret = genz_clone_zdev_ref_ptes(zdev);

out:
	return ret;
}
EXPORT_SYMBOL(genz_req_zmmu_setup);

static void genz_pte_field(uint64_t field, uint16_t st_bit, uint16_t width,
			   uint64_t *pte_buf)
{
	uint16_t end_bit = st_bit + width - 1;
	uint16_t lo = st_bit % 64;
	uint16_t hi = end_bit % 64;
	uint16_t st_idx = st_bit / 64;
	uint16_t end_idx = end_bit / 64;
	uint16_t width0 = 64 - lo;
	uint64_t data0, mask0, data1, mask1;
	bool single = (st_idx == end_idx); /* entire field is in 1 uint64_t */
	uint16_t hi0 = (single) ? hi : 63;

	if (width == 0)  /* nothing to do */
		return;

	data0 = pte_buf[st_idx];
	mask0 = GENMASK_ULL(hi0, lo);
	pte_buf[st_idx] = (data0 & ~mask0) | ((field << lo) & mask0);
	if (!single) {  /* field spans 2 uint64_t's (not more, as field < 64 bits) */
		data1 = pte_buf[end_idx];
		mask1 = GENMASK_ULL(hi, 0); /* mask1 always starts at bit 0 */
		pte_buf[end_idx] = (data1 & ~mask1) | ((field >> width0) & mask1);
	}
}

static void genz_req_pte_format(struct genz_req_pte *pte,
				struct genz_req_pte_config *cfg,
				uint64_t *pte_buf)
{
	uint64_t addr = pte->data.addr >> 12; /* for control, includes dr_iface */
	uint16_t gdest = genz_gcid_sid(pte->dgcid);
	uint16_t ldest = genz_gcid_cid(pte->dgcid);

	/* build PTE in order, from low bit to high */
	genz_pte_field(pte->v,       cfg->valid.start,    cfg->valid.width,    pte_buf);
	genz_pte_field(pte->et,      cfg->et.start,       cfg->et.width,       pte_buf);
	genz_pte_field(pte->d_attr,  cfg->d_attr.start,   cfg->d_attr.width,   pte_buf);
	genz_pte_field(pte->st,      cfg->st.start,       cfg->st.width,       pte_buf);
	genz_pte_field(pte->drc,     cfg->drc.start,      cfg->drc.width,      pte_buf);
	genz_pte_field(pte->pp,      cfg->pp.start,       cfg->pp.width,       pte_buf);
	genz_pte_field(pte->cce,     cfg->cce.start,      cfg->cce.width,      pte_buf);
	genz_pte_field(pte->ce,      cfg->ce.start,       cfg->ce.width,       pte_buf);
	genz_pte_field(pte->wpe,     cfg->wpe.start,      cfg->wpe.width,      pte_buf);
	genz_pte_field(pte->pse,     cfg->pse.start,      cfg->pse.width,      pte_buf);
	genz_pte_field(pte->pfme,    cfg->pfme.start,     cfg->pfme.width,     pte_buf);
	genz_pte_field(pte->pec,     cfg->pec.start,      cfg->pec.width,      pte_buf);
	genz_pte_field(pte->lpe,     cfg->lpe.start,      cfg->lpe.width,      pte_buf);
	genz_pte_field(pte->nse,     cfg->nse.start,      cfg->nse.width,      pte_buf);
	genz_pte_field(pte->wr_mode, cfg->wr_mode.start,  cfg->wr_mode.width,  pte_buf);
	genz_pte_field(pte->tc,      cfg->tc.start,       cfg->tc.width,       pte_buf);
	genz_pte_field(pte->pasid,   cfg->pasid.start,    cfg->pasid.width,    pte_buf);
	genz_pte_field(ldest,        cfg->loc_dest.start, cfg->loc_dest.width, pte_buf);
	genz_pte_field(gdest,        cfg->glb_dest.start, cfg->glb_dest.width, pte_buf);
	genz_pte_field(pte->tr_idx,  cfg->tr_idx.start,   cfg->tr_idx.width,   pte_buf);
	genz_pte_field(pte->co,      cfg->co.start,       cfg->co.width,       pte_buf);
	genz_pte_field(pte->rkey,    cfg->rkey.start,     cfg->rkey.width,     pte_buf);
	genz_pte_field(addr,         cfg->addr.start,     cfg->addr.width,     pte_buf);
}

int genz_req_pte_write(struct genz_bridge_dev *br,
		       struct genz_pte_info *ptei,
		       struct genz_zmmu_info *zi)
{
	struct genz_req_pte *pte = &ptei->pte.req;
	uint64_t ps = genz_pg_ps(ptei->pg);
	struct genz_page_grid_config *pgc;
	struct genz_rmr_info *rmri;
	uint first = ptei->pte_index;
	uint last = first + ptei->zmmu_pages - 1;
	uint64_t pte_buf[1024 / 64]; /* max Gen-Z HW PTE is 1024 bits */
	uint64_t addr = ptei->addr; /* full byte address */
	uint pte_sz; /* in bytes */
	uint64_t offset;
	int ret;
	uint i;

	if (!zi)
		return -EINVAL;
	pgc = zi->pg_config;
	pte_sz = zi->pg_config->pte_sz; /* in bytes */
	rmri = zi->req_zmmu_pg.pg_rmri[GENZ_PTE_TABLE];
	offset = rmri->rsp_zaddr + ((uint64_t)first * pte_sz);
	// Revisit: optimize by formatting entire PTE once and only updating addr
	for (i = first; i <= last; i++) {
		if (pte->st == GENZ_DATA)
			pte->data.addr = addr;
		else
			pte->control.addr = addr;
		genz_req_pte_format(pte, &pgc->req_pte_cfg, pte_buf);
		ret = genz_control_write(br, offset, pte_sz, pte_buf, rmri, 0);
		if (ret < 0)
			goto out;
		addr += ps;
		offset += pte_sz;
	}

out:
	return ret;
}
EXPORT_SYMBOL(genz_req_pte_write);

int genz_clone_req_pg_ptes(struct genz_dev *zdev, struct genz_pte_info *ptei,
			   struct genz_zmmu_info *zi)
{
	struct genz_page_grid_info *pgi;
	struct genz_page_grid *gz_pg;
	ulong flags;
	int ret;

	if (!zi)
		return -EINVAL;
	pgi = &zi->req_zmmu_pg;
	spin_lock_irqsave(&zi->zmmu_lock, flags);
	gz_pg = zmmu_pg_page_size(ptei, pgi);
	if (IS_ERR(gz_pg)) {
		ret = PTR_ERR(gz_pg);
		goto unlock;
	}
	ptei->pg = gz_pg;
	spin_unlock_irqrestore(&zi->zmmu_lock, flags);
	ret = genz_req_pte_write(zdev->zbdev, ptei, zi);
	return ret;

unlock:
	spin_unlock_irqrestore(&zi->zmmu_lock, flags);
	return ret;
}
