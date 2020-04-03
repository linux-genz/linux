/*
 * Copyright (C) 2019-2020 Hewlett Packard Enterprise Development LP.
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

#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/uuid.h>
#include <linux/genz-types.h>

struct genz_resource;
struct genz_control_info;
struct genz_driver;
struct genz_bridge_dev;
struct genz_component;
struct genz_pte_info;
struct genz_mem_data;
struct genz_driver_aux;
struct genz_driver_aux;

/**
 * GENZ_DEVICE - macro used to describe a specific GENZ device
 * @uuid: the 16 byte UUID
 *
 * This macro is used to create a struct genz_device_id that matches a
 * specific device.  
 */
#define GENZ_DEVICE(uuid) \
        .uuid = (uuid), .driver_data = (NULL)

struct genz_dev {
	struct list_head	fab_dev_node; /* Node in the per-fabric list */
	uuid_t 			class_uuid;      /* component/service/virtual UUID */
	uuid_t 			instance_uuid;
	uint16_t		class;
	struct list_head	zres_list;  /* head of zres list */
	struct list_head	uu_node;   /* list of zdevs with same UUID */
	struct genz_control_info *root_control_info;
	struct kobject		*root_kobj; /* kobj for /sys/devices/genz<N> */
	struct genz_driver	*zdrv;
	struct genz_bridge_dev	*zbdev;
	struct genz_component	*zcomp;     /* parent component */
	struct device		dev;	    /* Generic device interface */
	uint16_t 		resource_count[2]; /* control 0; data 1 */
};
#define to_genz_dev(n) container_of(n, struct genz_dev, dev)

struct genz_driver {
	const char			*name;
	struct genz_device_id		*id_table; /* terminated by entry with NULL values */
	int (*probe)(struct genz_dev *zdev, const struct genz_device_id *id);
	int (*remove)(struct genz_dev *zdev);  /* Revisit: pci returns void */
	int (*suspend)(struct genz_dev *zdev);
	int (*resume)(struct genz_dev *zdev);
	struct device_driver		driver;
	struct genz_driver_aux		*zaux;
};
#define to_genz_driver(d) container_of(d, struct genz_driver, driver)

struct genz_resource {
	struct resource res;
	uint32_t ro_rkey;
	uint32_t rw_rkey;
};

struct genz_resource *genz_get_first_resource(struct genz_dev *zdev);
struct genz_resource *genz_get_next_resource(struct genz_dev *zdev,
		struct genz_resource *res);
bool genz_is_data_resource(struct genz_resource *res);
bool genz_is_control_resource(struct genz_resource *res);
const char *genz_resource_name(struct genz_resource *res);

/** genz_for_each_resource  -       iterate over list of resources
 * @pos:        the struct genz_resource
 * @zdev:       the struct genz_dev with resources
 */
#define genz_for_each_resource(pos, zdev)                          \
	for (pos = genz_get_first_resource(zdev);                  \
		pos != NULL;                                       \
		pos = genz_get_next_resource(zdev, pos))


/*
 * Use these macros so that KBUILD_MODNAME and THIS_MODULE can be expanded
 */
#define genz_register_driver(driver)             \
        __genz_register_driver(driver, THIS_MODULE, KBUILD_MODNAME)
#define genz_unregister_driver(driver)             \
        __genz_unregister_driver(driver)

/* 
 * Don't call these directly - use the macros. 
 */
int __genz_register_driver(struct genz_driver *driver, struct module *, 
				const char *mod_name);
void __genz_unregister_driver(struct genz_driver *driver);

typedef loff_t genz_control_cookie;

struct genz_bridge_info {
	uint     req_zmmu       : 1;
	uint     rsp_zmmu       : 1;
	uint     xdm            : 1;
	uint     rdm            : 1;
	uint     xdm_cmpl_intr  : 1;
	uint     rdm_cmpl_intr  : 1;
	uint     load_store     : 1;
	uint     loopback       : 1;
	uint     nr_xdm_queues;
	uint     nr_rdm_queues;
	uint     xdm_qlen;
	uint     rdm_qlen;
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
	uint64_t cpuvisible_phys_offset;
	uint64_t xdm_max_xfer;
};

struct genz_page_grid {
	struct genz_page_grid_restricted_page_grid_table_array page_grid;
	struct rb_node   base_pte_node;  /* rbtree ordered on base_pte_idx */
	struct rb_node   base_addr_node; /* and another on base_addr */
	struct rb_root   pte_tree;       /* rbtree root of allocated ptes */
	struct resource  res;            /* only for requester page_grids */
	bool             humongous;      /* only allowed once */
	bool             cpu_visible;    /* only for requester page_grids */
};

struct genz_xdm_info {
	struct genz_bridge_dev *br;
	uint32_t               cmdq_ent, cmplq_ent;
	uint8_t                traffic_class, priority;
	struct device          *dma_dev;
	void                   *br_driver_data;
	uint64_t               br_driver_flags;
	void                   *driver_data;
	spinlock_t             xdm_info_lock;
};

struct genz_rdm_info {
	struct genz_bridge_dev *br;
	uint32_t               cmplq_ent;
	uint32_t               rspctxid;
	struct device          *dma_dev;
	void                   *br_driver_data;
	uint64_t               br_driver_flags;
	void                   *driver_data;
	spinlock_t             rdm_info_lock;
};

struct genz_rmr_info;
struct genz_sgl_info;
typedef void (*sgl_cmpl_fn)(struct genz_dev *zdev, struct genz_sgl_info *sgli);

struct genz_sgl_info {
	struct genz_rmr_info *rmri;
	struct genz_xdm_info *xdmi;
	uint cmd;
	uint tag;
	loff_t offset;
	struct scatterlist *sg;
	int nr_sg;
	int status;
	atomic_t nr_cmpls;
	sgl_cmpl_fn cmpl_fn;
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
	int (*sgl_request)(struct genz_dev *zdev, struct genz_sgl_info *sgli);
	int (*req_page_grid_write)(struct genz_bridge_dev *br, uint pg_index,
				   struct genz_page_grid genz_pg[]);
	int (*rsp_page_grid_write)(struct genz_bridge_dev *br, uint pg_index,
				   struct genz_page_grid genz_pg[]);
	int (*req_pte_write)(struct genz_bridge_dev *br,
			     struct genz_pte_info *info);
	int (*rsp_pte_write)(struct genz_bridge_dev *br,
			     struct genz_pte_info *info);
	int (*req_pte_clear)(struct genz_bridge_dev *br,
			     struct genz_pte_info *info);
	int (*rsp_pte_clear)(struct genz_bridge_dev *br,
			     struct genz_pte_info *info);
	int (*dma_map_sg_attrs)(    /* for genz_umem_pin */
		struct genz_bridge_dev *br, struct scatterlist *sg, int nents,
		enum dma_data_direction direction, unsigned long dma_attrs);
	void (*dma_unmap_sg_attrs)( /* for genz_umem_release */
		struct genz_bridge_dev *br, struct scatterlist *sg, int nents,
		enum dma_data_direction direction, unsigned long dma_attrs);
	int (*alloc_queues)(struct genz_bridge_dev *br,
			    struct genz_xdm_info *xdmi,
			    struct genz_rdm_info *rdmi);
	int (*free_queues)(struct genz_xdm_info *xdmi,
			   struct genz_rdm_info *rdmi);
	void (*generate_uuid)(struct genz_bridge_dev *br, uuid_t *uuid);
	int (*uuid_import)(struct genz_mem_data *mdata, uuid_t *uuid,
			   uint32_t uu_flags, gfp_t alloc_flags);
	int (*uuid_free)(struct genz_mem_data *mdata, uuid_t *uuid,
			 uint32_t *uu_flags, bool *local);
	int (*control_structure_pointers) (int vers, int structure_type,
			const struct genz_control_structure_ptr **csp,
			int *num_ptrs);
};
#define to_genz_bridge_driver(d) container_of(d, struct genz_bridge_driver, driver)

struct genz_req_pte_data {
	uint64_t           addr;            /* 64-bit data space address */
};

struct genz_req_pte_ctl {
	uint64_t           addr    :52;     /* 52-bit control space address */
	uint64_t           dr_intf :12;     /* 12-bit DR interface (drc=1) */
};

struct genz_req_pte {
	uint64_t           v          : 1;  /* valid */
	uint64_t           et         : 1;  /* entry type (page table) */
	uint64_t           d_attr     : 3;  /* dest attribute */
	uint64_t           st         : 1;  /* space type: 0=control, 1=data */
	uint64_t           drc        : 1;  /* control: directed relay */
	uint64_t           pp         : 1;  /* data: proxy page */
	uint64_t           cce        : 1;  /* cache coherence enable */
	uint64_t           ce         : 1;  /* capabilities enable */
	uint64_t           wpe        : 1;  /* write poison enable */
	uint64_t           pse        : 1;  /* PASID enable */
	uint64_t           pfme       : 1;  /* perf marker enable */
	uint64_t           pec        : 1;  /* processor exception control */
	uint64_t           lpe        : 1;  /* LPD field enable */
	uint64_t           nse        : 1;  /* no-snoop enable */
	uint64_t           write_mode : 3;
	uint64_t           tc         : 4;  /* traffic class */
	uint64_t           pasid      : 20;
	uint64_t           dgcid      : 28; /* dest global CID */
	uint64_t           tr_index   : 4;  /* TR-only */
	uint64_t           co         : 2;  /* TR-only */
	uint32_t           rkey;
	union {
		struct genz_req_pte_data data;
		struct genz_req_pte_ctl  control;
	};
};

struct genz_rsp_pte {
	uint64_t           v          : 1;  /* valid */
	uint64_t           et         : 1;  /* entry type (page table) */
	uint64_t           pa         : 1;  /* persistent access */
	uint64_t           cce        : 1;  /* cache coherence enable */
	uint64_t           ce         : 1;  /* capabilities enable */
	uint64_t           wpe        : 1;  /* write poison enable */
	uint64_t           pse        : 1;  /* PASID enable */
	uint64_t           lpe        : 1;  /* LPD field enable */
	uint64_t           ie         : 1;  /* interrupt enable */
	uint64_t           pfer       : 1;  /* persistent flush error */
	uint64_t           rkmgr      : 2;  /* R-Key manager CID/SID enable */
	uint64_t           pasid      : 20;
	uint64_t           rkmgcid    : 28; /* R-Key manager global CID */
	uint32_t           ro_rkey;         /* Read-only R-Key */
	uint32_t           rw_rkey;         /* Read-write R-Key */
	uint64_t           addr;            /* 64-bit address */
	uint64_t           win_sz;          /* 64-bit window size */
};

union genz_pte {
	struct genz_req_pte req;
	struct genz_rsp_pte rsp;
};

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
	uint64_t               addr_aligned;    /* rounded down to pg page sz */
	uint64_t               length_adjusted; /* rounded up to pg page sz */
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
#define PAGE_GRID_PS_BITS (64)

struct genz_page_grid_info {
	/* Revisit: make pg and pg_bitmap dynamic */
	struct genz_page_grid pg[PAGE_GRID_ENTRIES];
	DECLARE_BITMAP(pg_bitmap, PAGE_GRID_ENTRIES);
	DECLARE_BITMAP(pg_cpu_visible_ps_bitmap, PAGE_GRID_PS_BITS); /* req page grids only */
	DECLARE_BITMAP(pg_non_visible_ps_bitmap, PAGE_GRID_PS_BITS);
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
	/* struct genz_page_table_info;  Revisit: define this */
};

struct genz_bridge_dev {
	struct list_head	fab_bridge_node; /* node in list of bridges on fabric */
	struct list_head	bridge_node;	 /* node in global list of bridges */
	struct genz_dev		zdev;
	struct genz_bridge_driver *zbdrv;
	struct device		*bridge_dev; /* native device pointer */
	uint16_t		bridge_num;
	struct genz_fabric	*fabric;
	struct genz_bridge_info br_info;
	spinlock_t              zmmu_lock;  /* global bridge zmmu lock */
	union genz_zmmu_info    zmmu_info;
	struct resource         ld_st_res;
	/* Revisit: add address space */
	struct kobject		genzN_dir;
	struct kobject		*control_dir;
	struct kset		*genz_control_kset;
};
#define to_zbdev(d) container_of(d, struct genz_bridge_dev, bridge_dev)
#define kobj_to_zbdev(kobj) container_of(kobj, struct genz_bridge_dev, genzN_dir)

static inline bool zdev_is_local_bridge(struct genz_dev *zdev)
{
	return ((zdev != NULL && zdev->zbdev != NULL) ?
		(zdev == &zdev->zbdev->zdev) : false);
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

static inline uint64_t genz_pg_addr(struct genz_page_grid *genz_pg)
{
	return genz_pg->page_grid.pg_base_address_0 <<
		GENZ_PAGE_GRID_MIN_PAGESIZE;
}

#define GENZ_INVALID_GCID       (-1u)
#define GCID_STRING_LEN              8

#define GENZ_MR_GET             ((uint32_t)1 << 0)
#define GENZ_MR_PUT             ((uint32_t)1 << 1)
#define GENZ_MR_SEND            GENZ_MR_PUT
#define GENZ_MR_RECV            GENZ_MR_GET
#define GENZ_MR_GET_REMOTE      ((uint32_t)1 << 2)
#define GENZ_MR_PUT_REMOTE      ((uint32_t)1 << 3)
#define GENZ_MR_READ            GENZ_MR_GET
#define GENZ_MR_WRITE           GENZ_MR_PUT
#define GENZ_MR_READ_REMOTE     GENZ_MR_GET_REMOTE
#define GENZ_MR_WRITE_REMOTE    GENZ_MR_PUT_REMOTE
#define GENZ_MR_FLAG0           ((uint32_t)1 << 4) /* Usable by user-space */
#define GENZ_MR_FLAG1           ((uint32_t)1 << 5)
#define GENZ_MR_FLAG2           ((uint32_t)1 << 6)
#define GENZ_MR_FLAG3           ((uint32_t)1 << 7)
#define GENZ_MR_REQ             ((uint32_t)1 << 16) /* driver internal */
#define GENZ_MR_RSP             ((uint32_t)1 << 17) /* driver internal */
#define GENZ_MR_KERN_MAP        ((uint32_t)1 << 26) /* kernel mapping */
#define GENZ_MR_REQ_CPU         ((uint32_t)1 << 27) /* CPU visible mapping */
#define GENZ_MR_REQ_CPU_CACHE   ((uint32_t)3 << 28) /* CPU cache mode */
#define GENZ_MR_REQ_CPU_WB      ((uint32_t)0 << 28)
#define GENZ_MR_REQ_CPU_WC      ((uint32_t)1 << 28)
#define GENZ_MR_REQ_CPU_WT      ((uint32_t)2 << 28)
#define GENZ_MR_REQ_CPU_UC      ((uint32_t)3 << 28)
#define GENZ_MR_INDIVIDUAL      ((uint32_t)1 << 30) /* individual rsp ZMMU */
#define GENZ_MR_INDIV_RKEYS     ((uint32_t)1 << 31) /* per mrreg rkeys */

#define GENZ_NUM_PASIDS  BIT(16)
#define NO_PASID         0

#define GENZ_CONTROL_SIZE_UNIT  16 /* control structs are in 16-byte units */

enum space_type {
	GENZ_DATA    = 0,
	GENZ_CONTROL = 1
};

enum genz_xdm_cmd {
	GENZ_XDM_READ      = 0x1,
	GENZ_XDM_WRITE     = 0x2
};

enum uuid_type {
	UUID_TYPE_LOCAL    = 0x1,
	UUID_TYPE_REMOTE   = 0x2,
	UUID_TYPE_LOOPBACK = (UUID_TYPE_LOCAL | UUID_TYPE_REMOTE),
	UUID_TYPE_ZBRIDGE  = 0x4,
	UUID_TYPE_FABRIC   = 0x8
};

#define UUID_TYPE_REMOTE_LOCAL (UUID_TYPE_REMOTE | UUID_TYPE_LOCAL)

struct uuid_tracker_remote {
	uint32_t                ro_rkey;
	uint32_t                rw_rkey;
	uint32_t                uu_flags;
	bool                    rkeys_valid;
	bool                    torndown;  /* UUID is being torndown */
	/* Revisit: add bool to distinguish "alias" vs "real" loopback */
	/* local users of this remote UUID - protected by local_uuid_lock */
	struct rb_root          local_uuid_tree;
	spinlock_t              local_uuid_lock;
};

struct uuid_tracker_local {
	struct genz_mem_data *mdata;
	/* remote users of this local UUID - protected by mdata->uuid_lock */
	struct rb_root   uu_remote_uuid_tree;
};

struct uuid_tracker_fabric {
	int fabric_num;
	struct genz_fabric *fabric;
};

struct uuid_tracker {
	uuid_t                      uuid;
	struct rb_node              node;
	struct kref                 refcount;
	enum uuid_type		uutype;
	struct uuid_tracker_remote  *remote;
	struct uuid_tracker_local   *local;
	struct uuid_tracker_fabric	*fabric;
	struct list_head 		*zbr_list;
};

struct uuid_node {
	struct uuid_tracker *tracker;
	struct rb_node      node;
	struct rb_root      un_rmr_tree;
};

extern spinlock_t genz_uuid_rbtree_lock;

struct genz_mem_data {
	struct genz_bridge_dev *bridge;
	spinlock_t          uuid_lock;  /* protects local_uuid, md_remote_uuid_tree */
	struct uuid_tracker *local_uuid;
	struct rb_root      md_remote_uuid_tree;  /* UUIDs imported by this mdata */
	spinlock_t          md_lock;    /* protects md_mr_tree, md_rmr_tree */
	struct rb_root      md_mr_tree;
	struct rb_root      md_rmr_tree;
	uint32_t            ro_rkey;
	uint32_t            rw_rkey;
};

struct genz_umem {
	struct genz_mem_data  *mdata;
	struct genz_pte_info  *pte_info;
	struct rb_node        node;  /* within mdata->md_mr_tree */
	struct kref           refcount;
	uint64_t              vaddr;
	size_t                size;
	int                   page_shift;
	bool                  writable;
	bool                  hugetlb;
	bool                  need_release;
	bool                  dirty;
	bool                  erase;
	struct work_struct    work;  /* Revisit: these next 3 were copied from */
	struct mm_struct      *mm;   /* ib_umem and are currently unused */
	unsigned long         diff;
	struct sg_table       sg_head;
	int                   nmap;
	int                   npages;
};

/* Revisit: embed this in genz_rmr? */
struct genz_rmr_info {
	uint64_t        rsp_zaddr;
	uint64_t        req_addr;
	uint64_t        len;
	uint64_t        access;
	void            *cpu_addr;
	uint32_t        pg_ps;
	uint32_t        gcid;
	struct resource res;
};

/* Revisit: probably should have equivalent genz_mr_info */

struct uuid_node;  /* Revisit: define */
struct zmap;       /* Revisit: define */
struct genz_rmr {
	struct genz_mem_data  *mdata;
	struct genz_pte_info  *pte_info;
	struct rb_node        md_node;  /* within mdata->md_rmr_tree */
	struct rb_node        un_node;  /* within mdata->md_remote_uuid_tree->un_rmr_tree */
	struct kref           refcount;
	struct uuid_tracker   *uu;    /* the remote UUID this rmr belongs to */
	struct uuid_node      *unode; /* the local unode this rmr belongs to */
	struct zmap           *zmap;
	uint64_t              rsp_zaddr;
	uint64_t              req_addr;
	ulong                 mmap_pfn;
	bool                  writable;
	bool                  fd_erase;
	bool                  un_erase;
};

/*
 * Traffic class abstraction for user space.
 * Mapping to actual Gen-Z traffic class is undefined in user space.
 */
enum {
	GENZ_TC_0 = 0,
	GENZ_TC_1 = 1,
	GENZ_TC_2 = 2,
	GENZ_TC_3 = 3,
	GENZ_TC_4 = 4,
	GENZ_TC_5 = 5,
	GENZ_TC_6 = 6,
	GENZ_TC_7 = 7,
	GENZ_TC_8 = 8,
	GENZ_TC_9 = 9,
	GENZ_TC_10 = 10,
	GENZ_TC_11 = 11,
	GENZ_TC_12 = 12,
	GENZ_TC_13 = 13,
	GENZ_TC_14 = 14,
	GENZ_TC_15 = 15
};

static inline int genz_uuid_cmp(const uuid_t *u1, const uuid_t *u2)
{
    return memcmp(u1, u2, sizeof(uuid_t));
}

static inline bool genz_umem_empty(struct genz_mem_data *mdata)
{
	return RB_EMPTY_ROOT(&mdata->md_mr_tree);
}

static inline bool genz_rmr_empty(struct genz_mem_data *mdata)
{
	return RB_EMPTY_ROOT(&mdata->md_rmr_tree);
}

static inline bool genz_remote_uuid_empty(struct genz_mem_data *mdata)
{
	return RB_EMPTY_ROOT(&mdata->md_remote_uuid_tree);
}

static inline bool genz_uu_remote_uuid_empty(struct genz_mem_data *mdata)
{
	return (!mdata->local_uuid ||
		RB_EMPTY_ROOT(&mdata->local_uuid->local->uu_remote_uuid_tree));
}

static inline bool genz_unode_rmr_empty(struct uuid_node *node)
{
	return RB_EMPTY_ROOT(&node->un_rmr_tree);
}

static inline void *genz_get_drvdata(struct genz_dev *zdev)
{
        return dev_get_drvdata(&zdev->dev);
}

static inline void genz_set_drvdata(struct genz_dev *zdev, void *data)
{
        dev_set_drvdata(&zdev->dev, data);
}

static inline const char *genz_name(const struct genz_dev *zdev)
{
        return dev_name(&zdev->dev);
}

void genz_rkey_init(void);
void genz_rkey_exit(void);
int genz_rkey_alloc(uint32_t *ro_rkey, uint32_t *rw_rkey);
void genz_rkey_free(uint32_t ro_rkey, uint32_t rw_rkey);
int genz_pasid_alloc(unsigned int *pasid);
void genz_pasid_free(unsigned int pasid);
int genz_register_bridge(struct device *dev, struct genz_bridge_driver *zbdrv,
			 void *driver_data);
struct genz_bridge_dev *genz_find_bridge(struct device *dev);
int genz_unregister_bridge(struct device *dev);
char *genz_gcid_str(const uint32_t gcid, char *str, const size_t len);
uint32_t genz_dev_gcid(struct genz_dev *zdev, uint index);
void genz_init_mem_data(struct genz_mem_data *mdata,
			struct genz_bridge_dev *br);
void genz_zmmu_clear_all(struct genz_bridge_dev *br, bool free_radix_tree);
int genz_zmmu_req_pte_alloc(struct genz_pte_info *ptei,
                            struct genz_rmr_info *rmri);
int genz_zmmu_rsp_pte_alloc(struct genz_pte_info *info, uint64_t *rsp_zaddr,
                            uint32_t *pg_ps);
void genz_zmmu_req_pte_free(struct genz_pte_info *info);
void genz_zmmu_rsp_pte_free(struct genz_pte_info *info);
void genz_zmmu_req_pte_clear(struct genz_pte_info *info);
void genz_zmmu_rsp_pte_clear(struct genz_pte_info *info);
uint64_t genz_zmmu_pte_addr(const struct genz_pte_info *info, uint64_t addr);
struct uuid_tracker *genz_uuid_search(uuid_t *uuid);
struct uuid_tracker *genz_uuid_tracker_alloc(
	uuid_t *uuid, uint type, gfp_t alloc_flags, int *status);
struct uuid_tracker *genz_uuid_tracker_insert(struct uuid_tracker *uu,
					      int *status);
struct uuid_tracker *genz_uuid_tracker_alloc_and_insert(
	uuid_t *uuid, uint type, uint32_t uu_flags, struct genz_mem_data *mdata,
	gfp_t alloc_flags, int *status);
struct uuid_tracker *genz_fabric_uuid_tracker_alloc_and_insert(uuid_t *uuid);
void genz_fabric_uuid_tracker_free(uuid_t *uuid);
struct uuid_node *genz_remote_uuid_alloc_and_insert(
	struct uuid_tracker *uu, spinlock_t *lock, struct rb_root *root,
	gfp_t alloc_flags, int *status);
void genz_uuid_tracker_free(struct kref *ref);
void genz_uuid_remove(struct uuid_tracker *uu);
int genz_free_local_uuid(struct genz_mem_data *mdata, bool teardown);
int genz_free_uuid_node(struct genz_mem_data *mdata, spinlock_t *lock,
                        struct rb_root *root,
                        uuid_t *uuid, bool teardown);
int genz_free_local_or_remote_uuid(struct genz_mem_data *mdata, uuid_t *uuid,
				   struct uuid_tracker *uu, bool *local);
void genz_free_remote_uuids(struct genz_mem_data *mdata);
struct uuid_node *genz_remote_uuid_get(struct genz_mem_data *mdata,
                                       uuid_t *uuid);
void genz_rmr_remove(struct genz_rmr *rmr, bool lock);
void genz_rmr_free_all(struct genz_mem_data *mdata);
void genz_rmr_remove_unode(struct genz_mem_data *mdata,
			   struct uuid_node *unode);
int genz_teardown_remote_uuid(uuid_t *src_uuid);
struct genz_rmr *genz_rmr_search(
	struct genz_mem_data *mdata, uint32_t dgcid, uint64_t rsp_zaddr,
	uint64_t length, uint64_t access, uint64_t req_addr);
struct genz_rmr *genz_rmr_get(
	struct genz_mem_data *mdata, uuid_t *uuid, uint32_t dgcid,
	uint64_t rsp_zaddr, uint64_t len, uint64_t access, uint pasid,
	uint32_t rkey, struct genz_rmr_info *rmri);
void genz_umem_free_all(struct genz_mem_data *mdata,
                        struct genz_pte_info **humongous_zmmu_rsp_pte);
struct genz_umem *genz_umem_search(struct genz_mem_data *mdata,
				   uint64_t vaddr, uint64_t length,
				   uint64_t access, uint64_t rsp_zaddr);
struct genz_umem *genz_umem_get(struct genz_mem_data *mdata, uint64_t vaddr,
                                size_t size, uint64_t access,
                                uint pasid, uint32_t ro_rkey, uint32_t rw_rkey,
                                bool kernel);
void genz_umem_remove(struct genz_umem *umem);
int genz_mr_reg(struct genz_mem_data *mdata, uint64_t vaddr,
		uint64_t len, uint64_t access, uint32_t pasid,
		uint64_t *rsp_zaddr, uint32_t *pg_ps,
		uint32_t *ro_rkey, uint32_t *rw_rkey);
/* Revisit: add genz_mr_free */
int genz_rmr_import(
	struct genz_mem_data *mdata, uuid_t *uuid, uint32_t dgcid,
	uint64_t rsp_zaddr, uint64_t len, uint64_t access, uint32_t rkey,
	const char *rmr_name, struct genz_rmr_info *rmri);
int genz_rmr_free(struct genz_mem_data *mdata, struct genz_rmr_info *rmri);
bool genz_gcid_is_local(struct genz_bridge_dev *br, uint32_t gcid);
int genz_alloc_queues(struct genz_bridge_dev *br,
		      struct genz_xdm_info *xdmi, struct genz_rdm_info *rdmi);
int genz_free_queues(struct genz_xdm_info *xdmi, struct genz_rdm_info *rdmi);
int genz_sgl_request(struct genz_dev *zdev, struct genz_sgl_info *sgli);
void genz_generate_uuid(struct genz_bridge_dev *br, uuid_t *uuid);
int genz_uuid_import(struct genz_mem_data *mdata, uuid_t *uuid,
		     uint32_t uu_flags, gfp_t alloc_flags);
int genz_uuid_free(struct genz_mem_data *mdata, uuid_t *uuid,
		   uint32_t *uu_flags, bool *local);

#endif /* LINUX_GENZ_H */
