/*
 * Copyright (C) 2019 Hewlett Packard Enterprise Development LP.
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

#ifndef LINUX_GENZ_H
#define LINUX_GENZ_H

#include <linux/mod_devicetable.h>

#include <linux/types.h>
#include <linux/device.h>
#include <linux/uuid.h>
#include <linux/genz-types.h>

struct genz_resource;
struct genz_control_info;
struct genz_driver;
struct genz_bridge_dev;
struct genz_component;

struct genz_dev {
	struct list_head	fab_dev_node; /* Node in the per-fabric list */
	uuid_t 			uuid;      /* component/service/virtual UUID */
	int                     zres_count;
	struct list_head	zres_list;
	struct genz_resource 	*zres;	      /* array of device's resources */
	struct genz_control_info *root_control_info;
	struct kobject		*root_kobj; /* kobj for /sys/devices/genz<N> */
	struct genz_driver	*zdrv;
	struct genz_bridge_dev	*zbdev;
	struct genz_component	*zcomp;     /* parent component */
	struct device		dev;	    /* Generic device interface */
};
#define to_genz_dev(n) container_of(n, struct genz_dev, dev)

struct genz_driver {
	const char			*name;
	struct genz_device_id		*id_table; /* Null terminated array */
	int (*probe)(struct genz_dev *zdev, const struct genz_device_id *id);
	int (*remove)(struct genz_dev *zdev);
	int (*suspend)(struct genz_dev *zdev);
	int (*resume)(struct genz_dev *zdev);
	struct device_driver		driver;
};
#define to_genz_driver(d) container_of(d, struct genz_driver, driver)

typedef loff_t genz_control_cookie;

struct genz_bridge_info {
	uint64_t req_zmmu       : 1;
	uint64_t rsp_zmmu       : 1;
	uint64_t xdm            : 1;
	uint64_t rdm            : 1;
	uint64_t load_store     : 1;
	uint     nr_req_page_grids;
	uint     nr_rsp_page_grids;
	uint64_t nr_req_ptes;
	uint64_t nr_rsp_ptes;
	uint64_t req_page_grid_page_sizes;
	uint64_t rsp_page_grid_page_sizes;
	uint64_t min_cpuvisible_addr;
	uint64_t max_cpuvisible_addr;
	uint64_t min_nonvisible_addr;
	uint64_t max_nonvisible_addr;
};

struct genz_page_grid {
	struct genz_pg_restricted_pg_table_array page_grid;
	struct rb_node   base_pte_node;  /* rbtree ordered on base_pte_idx */
	struct rb_node   base_addr_node; /* and another on base_addr */
	struct rb_root   pte_tree;       /* rbtree root of allocated ptes */
	bool             humongous;      /* only allowed once */
	bool             cpu_visible;    /* only for requester page_grids */
};

struct genz_bridge_driver {
	struct genz_driver	zdrv; /* Revisit: need this or is it all in native driver? */
	int (*bridge_info)(struct genz_dev *zdev,
			   struct genz_bridge_info *info);
	int (*control_mmap)(struct genz_dev *zdev); /* Revisit: need flags? */
	int (*control_read)(struct genz_dev *zdev, loff_t offset, size_t size,
			    void *data, uint flags);
	int (*control_write)(struct genz_dev *zdev, loff_t offset, size_t size,
			     void *data, uint flags);
	int (*control_write_msg)(struct genz_dev *zdev, uint32_t rspctxid,
				 size_t size, void *data, uint flags);
	int (*data_mmap)(struct genz_dev *zdev);
	int (*data_read)(struct genz_dev *zdev, loff_t offset, size_t size,
			 void *data);
	int (*data_write)(struct genz_dev *zdev, loff_t offset, size_t size,
			  void *data);
	int (*req_page_grid_write)(struct genz_bridge_dev *br, uint pg_index,
				   struct genz_page_grid genz_pg[]);
	int (*rsp_page_grid_write)(struct genz_bridge_dev *br, uint pg_index,
				   struct genz_page_grid genz_pg[]);
};
#define to_genz_bridge_driver(d) container_of(d, struct genz_bridge_driver, driver)

struct genz_req_pte_info {
    uint32_t              dgcid;
    uint32_t              rkey;
};

struct genz_rsp_pte_info {
    uint32_t              ro_rkey;
    uint32_t              rw_rkey;
};

struct genz_pte_info {
    struct genz_bridge_dev *bridge;
    uint64_t               addr;
    uint64_t               access;
    size_t                 length;
    uint64_t               addr_aligned;    /* rounded down to pg page size */
    uint64_t               length_adjusted; /* rounded up to pg page size */
    struct genz_page_grid  *pg;
    unsigned int           pte_index;
    unsigned int           zmmu_pages;
    uint8_t                space_type;
    bool                   humongous;
    uint32_t               pasid;
    union {
        struct genz_req_pte_info req;
        struct genz_rsp_pte_info rsp;
    };
    struct rb_node         node;  /* within pgi->pte_tree */
    struct kref            refcount;
};

#define PAGE_GRID_ENTRIES (16)  /* Revisit: make dynamic */
struct genz_page_grid_info {
	/* Revisit: make pg and pg_bitmap dynamic */
	struct genz_page_grid pg[PAGE_GRID_ENTRIES];
	DECLARE_BITMAP(pg_bitmap, PAGE_GRID_ENTRIES);
	DECLARE_BITMAP(pg_cpu_visible_ps_bitmap, 64); /* req page grids only */
	DECLARE_BITMAP(pg_non_visible_ps_bitmap, 64);
	struct radix_tree_root pg_pagesize_tree;
	uint                   pte_entries;
	struct rb_root         base_pte_tree;
	struct rb_root         base_addr_tree;
	struct genz_page_grid  *humongous_pg;
};

union genz_zmmu_info {
	struct {
		struct genz_page_grid_info req_zmmu_pg;
		struct genz_page_grid_info rsp_zmmu_pg;
	};
	/* struct genz_pt_info;  Revisit: define this */
};

struct genz_bridge_dev {
	struct list_head	fab_bridge_node;	/* node in list of bridges on fabric */
	struct genz_dev		zdev;
	struct genz_bridge_driver *zbdrv;
	struct device		*bridge_dev; /* native device pointer */
	struct genz_fabric	*fabric;
	struct genz_bridge_info br_info;
	spinlock_t              zmmu_lock;  /* global bridge zmmu lock */
	union genz_zmmu_info    zmmu_info;
	/* Revisit: add address space */
};

static inline bool zdev_is_local_bridge(struct genz_dev *zdev)
{
	return ((zdev != NULL && zdev->zbdev != NULL) ?
		(zdev == &zdev->zbdev->zdev) : 0);
}

#define GENZ_ANY_VERSION  (0xffff)

#define GENZ_RKEY_RKD_SHIFT    20
#define GENZ_RKEY_OS_TOTAL     BIT(GENZ_RKEY_RKD_SHIFT)
#define GENZ_RKEY_OS_MASK      (GENZ_RKEY_OS_TOTAL - 1)
#define GENZ_RKEY_RKD_MASK     (~GENZ_RKEY_OS_MASK)

#define GENZ_DEFAULT_RKEY 0  /* from Gen-Z Core spec */
/* Revisit: needs to come from fabric manager */
#define GENZ_UNUSED_RKEY  0x00100000  /* RKD 1, key 0 */

static inline uint32_t genz_rkey_rkd(uint32_t rkey)
{
	return (rkey & GENZ_RKEY_RKD_MASK) >> GENZ_RKEY_RKD_SHIFT;
}

static inline uint32_t genz_rkey_os(uint32_t rkey)
{
	return rkey & GENZ_RKEY_OS_MASK;
}

extern uint32_t genz_unused_rkey;

#define GENZ_PAGE_GRID_MIN_PAGESIZE  12
#define GENZ_PAGE_GRID_MAX_PAGESIZE  64
#define GENZ_BASE_ADDR_ERROR         (-1ull)

void genz_rkey_init(void);
void genz_rkey_exit(void);
int genz_rkey_alloc(uint32_t *ro_rkey, uint32_t *rw_rkey);
void genz_rkey_free(uint32_t ro_rkey, uint32_t rw_rkey);

#endif /* LINUX_GENZ_H */
