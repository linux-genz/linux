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
struct genz_os_comp;
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
	uuid_t 			class_uuid;   /* component/service/virtual UUID */
	uuid_t 			instance_uuid;
	uint16_t		class;
	uint16_t 		resource_count[2]; /* control 0; data 1 */
	uint64_t                driver_flags; /* from netlink */
	struct list_head	zres_list;  /* head of zres list */
	struct list_head	uu_node;    /* list of zdevs with same UUID */
	struct genz_driver	*zdrv;
	struct genz_bridge_dev	*zbdev;     /* bridge used to reach this dev */
	struct genz_os_comp	*zcomp;     /* component containing this dev */
	struct device		dev;	    /* Generic device interface */
};
#define to_genz_dev(n) container_of(n, struct genz_dev, dev)
#define kobj_to_genz_dev(n) to_genz_dev(kobj_to_dev(n))

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
	uint     kern_map_data  : 1;
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
	uint64_t block_max_xfer;
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
	uint data_dir;
	uint tag;
	loff_t offset;
	size_t len;
	struct scatterlist *sgl;
	int nents;
	int nr_sg;
	int status;
	atomic_t nr_cmpls;
	sgl_cmpl_fn cmpl_fn;
};

/**
 * struct genz_bridge_driver - The main interface between the the Gen-Z
 * subsystem and Gen-Z bridge drivers.
 *
 * Each bridge driver defines one of these and passes a pointer to it in the
 * @zbdrv parameter of genz_register_bridge().
 */
struct genz_bridge_driver {
	/** bridge_info: Fill in @info about the bridge @br. Required. */
	int (*bridge_info)(struct genz_bridge_dev *br,
			   struct genz_bridge_info *info);
	/** control_mmap: Return page offset of local bridge control structure
	 * from @offset/@size. If mapping can be write_combine, set @wc true,
	 * otherwise it will be uncachable. Returns 0 on success, -error on failure,
	 * e.g., the offset/offset+size is out of range.
	 */
	int (*control_mmap)(struct genz_bridge_dev *br, off_t offset, size_t size,
			    ulong *pgoff, bool *wc);
	/**
	 * control_read: Read control space via bridge @br from @offset/@size
	 * into kernel buffer @data using mapping @rmri. One @flags
	 * currently defined, %GENZ_CONTROL_FENCE. Required.
	 * If bridge does not support in-band management, then any @rmri
	 * that is not %NULL and with a gcid not matching the bridge itself
	 * must return -%ENODEV.
	 */
	int (*control_read)(struct genz_bridge_dev *br, loff_t offset,
			    size_t size, void *data,
			    struct genz_rmr_info *rmri, uint flags);
	/**
	 * control_write: Write control space via bridge @br at @offset/@size
	 * from kernel buffer @data using mapping @rmri. Two @flags currently
	 * defined, %GENZ_CONTROL_FLUSH, %GENZ_CONTROL_FENCE. Required.
	 * If bridge does not support in-band management, then any @rmri
	 * that is not %NULL and with a gcid not matching the bridge itself
	 * must return -%ENODEV.
	 */
	int (*control_write)(struct genz_bridge_dev *br, loff_t offset,
			     size_t size, void *data,
			     struct genz_rmr_info *rmri, uint flags);
	/**
	 * control_write_msg: Send a Control Write MSG via bridge @br targeting
	 * @gcid, @rspctxid, @instid, @dr_iface, with data @size from kernel
	 * buffer @data.
	 * The @flags currently defined are %GENZ_CONTROL_MSG_UNRELIABLE,
	 * %GENZ_CONTROL_MSG_DR, %GENZ_CONTROL_MSG_CH, %GENZ_CONTROL_MSG_IV,
	 * %GENZ_CONTROL_FLUSH, %GENZ_CONTROL_FENCE.
	 * Required on bridges supporting in-band management.
	 */
	int (*control_write_msg)(struct genz_bridge_dev *br,
				 uint32_t gcid, uint32_t rspctxid,
				 uint32_t instid, uint16_t dr_iface,
				 size_t size, void *data, uint flags);
	/** data_mmap: Optional. Currently unused. */
	int (*data_mmap)(struct genz_bridge_dev *br,
			 struct genz_rmr_info *rmri);
	/**
	 * data_read: Read data space via bridge @br from @offset/@size
	 * into kernel buffer @data using mapping @rmri.
	 * No @flags currently defined. Required.
	 */
	int (*data_read)(struct genz_bridge_dev *br, loff_t offset,
			 size_t size, void *data,
			 struct genz_rmr_info *rmri, uint flags);
	/**
	 * data_write: Write data space via bridge @br at @offset/@size
	 * from kernel buffer @data using mapping @rmri. Required.
	 */
	int (*data_write)(struct genz_bridge_dev *br, loff_t offset,
			  size_t size, void *data,
			  struct genz_rmr_info *rmri, uint flags);
	int (*sgl_request)(struct genz_dev *zdev, struct genz_sgl_info *sgli);
	int (*req_page_grid_write)(struct genz_bridge_dev *br, uint pg_index,
				   struct genz_page_grid genz_pg[]);
	int (*rsp_page_grid_write)(struct genz_bridge_dev *br, uint pg_index,
				   struct genz_page_grid genz_pg[]);
	int (*req_pte_write)(struct genz_bridge_dev *br,
			     struct genz_pte_info *info);
	int (*rsp_pte_write)(struct genz_bridge_dev *br,
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
	int (*control_structure_pointers)(struct genz_bridge_dev *br,
			int vers, int structure_type,
			const struct genz_control_structure_ptr **csp,
			int *num_ptrs);
	/* private: subsystem use only */
	struct genz_driver zdrv; /* Revisit: need this or is it all in native driver? */
};
#define to_genz_bridge_driver(d) container_of(d, struct genz_bridge_driver, driver)

/* in Gen-Z Core spec, low 12 bits of addr do not appear and are assumed 0 */
struct genz_req_pte_data {
	uint64_t           addr;            /* 64-bit data space address */
};

struct genz_req_pte_ctl {
	uint64_t           addr     :52;    /* 52-bit control space address */
	uint64_t           dr_iface :12;    /* 12-bit DR interface (drc=1) */
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
	uint16_t               dr_iface;
	bool                   humongous;
	union genz_pte         pte;
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
	//struct kset		*genz_control_kset;
	struct genz_mem_data    *control_mdata;
};
#define to_zbdev(d) container_of(d, struct genz_bridge_dev, zdev)
#define kobj_to_zbdev(kobj) container_of(kobj, struct genz_bridge_dev, genzN_dir)

#define GENZ_ANY_VERSION  (0xffff)
#define GENZ_UNKNOWN_SID  (0xffff)

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
#define GENZ_PAGE_GRID_MAX_PAGESIZE  63
#define GENZ_BASE_ADDR_ERROR         (-1ull)

static inline uint64_t genz_pg_addr(struct genz_page_grid *genz_pg)
{
	return (uint64_t)genz_pg->page_grid.pg_base_address_0 <<
		GENZ_PAGE_GRID_MIN_PAGESIZE;
}

static inline uint64_t genz_pg_ps(struct genz_page_grid *genz_pg)
{
	return BIT_ULL(genz_pg->page_grid.page_size_0);
}

static inline uint64_t genz_pg_size(struct genz_page_grid *genz_pg)
{
	return (uint64_t)genz_pg->page_grid.page_count_0 * genz_pg_ps(genz_pg);
}

#define GENZ_INVALID_GCID       (-1u)

static inline bool genz_valid_gcid(uint32_t gcid)
{
	return (gcid != GENZ_INVALID_GCID);
}

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
#define GENZ_MR_PEC             ((uint32_t)1 << 15) /* proc exception ctl */
#define GENZ_MR_REQ             ((uint32_t)1 << 16) /* subsystem internal */
#define GENZ_MR_RSP             ((uint32_t)1 << 17) /* subsystem internal */
#define GENZ_MR_MAPPED          ((uint32_t)1 << 18) /* subsystem internal */
#define GENZ_MR_CONTROL         ((uint32_t)1 << 25) /* control space */
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
	GENZ_CONTROL = 0,
	GENZ_DATA    = 1
};

enum d_attr {
	GENZ_DA_INTERLEAVE   = 1,
	GENZ_DA_UNICAST      = 2,
	GENZ_DA_MULTICAST_SS = 4,
	GENZ_DA_MULTICAST_MS = 5
};

enum write_mode {
	GENZ_WM_EARLY_ACK   = 0,
	GENZ_WM_LATE_ACK    = 1,
	GENZ_WM_LATE_ACK_PU = 2,
	GENZ_WM_NO_ACK      = 3,
	GENZ_WM_SOD         = 4,
	GENZ_WM_INTERRUPT   = 5,
	GENZ_WM_LATE_ACK_PF = 6
};

enum genz_control_flag {
	GENZ_CONTROL_FLUSH          = 0x01,
	GENZ_CONTROL_FENCE          = 0x02,
	GENZ_CONTROL_MSG_UNRELIABLE = 0x10,
	GENZ_CONTROL_MSG_DR         = 0x20,
	GENZ_CONTROL_MSG_CH         = 0x40,
	GENZ_CONTROL_MSG_IV         = 0x80
};

enum genz_data_flag {
	GENZ_DATA_FLUSH             = 0x01,
};

enum uuid_type {
	UUID_TYPE_LOCAL    = 0x1,
	UUID_TYPE_REMOTE   = 0x2,
	UUID_TYPE_LOOPBACK = (UUID_TYPE_LOCAL | UUID_TYPE_REMOTE),
	UUID_TYPE_ZBRIDGE  = 0x4,
	UUID_TYPE_FABRIC   = 0x8,
	UUID_TYPE_ZDEV     = 0x10
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

struct uuid_tracker_zdev {
	struct genz_dev *zdev;
};

struct uuid_tracker {
	uuid_t                      uuid;
	struct rb_node              node;
	struct kref                 refcount;
	enum uuid_type		uutype;
	struct uuid_tracker_remote  *remote;
	struct uuid_tracker_local   *local;
	union {
		struct uuid_tracker_fabric  *fabric;
		struct uuid_tracker_zdev    *zdev;
	};
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

#define GENZ_DR_IFACE_NONE  (0xffff)

/* Revisit: embed this in genz_rmr? */
struct genz_rmr_info {
	uint64_t             rsp_zaddr;
	uint64_t             req_addr;
	uint64_t             len;
	uint64_t             access;
	void                 *cpu_addr;
	uint32_t             pg_ps;
	uint32_t             gcid;
	uint16_t             dr_iface;  /* directed-relay interface */
	struct genz_mem_data *mdata;  /* Revisit: duplicate of rmr->mdata */
	struct genz_resource zres;
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
	struct genz_resource  *zres;
	bool                  writable;
	bool                  fd_erase;
	bool                  un_erase;
};

struct genz_uuid_info {
	struct genz_mem_data *mdata;
	uuid_t *uuid;
	uint32_t uu_flags;
	uuid_t loc_uuid;
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

enum genz_pfn_mode {
	PFN_MODE_NONE,
	PFN_MODE_RAM,
	PFN_MODE_FAM,
};

struct genz_uep_pkt {  /* UEP: Unsolicited Event Packet */
	uint32_t DCIDl:     5; /* Byte 0 */
	uint32_t LENl:      3;
	uint32_t DCIDm:     4;
	uint32_t LENh:      4;
	uint32_t DCIDh:     3;
	uint32_t VC:        5;
	uint32_t OpCodel:   2;
	uint32_t PCRC:      6;
	uint32_t OpCodeh:   3; /* Byte 4 */
	uint32_t OCL:       5;
	uint32_t R0:       12;
	uint32_t SCID:     12;
	uint32_t AKey:      6; /* Byte 8 */
	uint32_t Deadline: 10;
	uint32_t ECN:       1;
	uint32_t GC:        1;
	uint32_t NH:        1;
	uint32_t PM:        1;
	uint32_t CV:        1;
	uint32_t SV:        1;
	uint32_t IV:        1;
	uint32_t Event:     8;
	uint32_t R1:        1;
	union {
		struct {  /* NH=0, GC=0 */
			uint32_t RCCID:    12; /* Byte 12 */
			uint32_t IfaceID:  12;
			uint32_t RCSIDl:    8;
			uint32_t RCSIDh:    8; /* Byte 16 */
			uint32_t R2:        8;
			uint32_t EventID:  16;
			uint32_t ES:       32; /* Byte 20 */
			uint32_t R3:        8; /* Byte 24 */
			uint32_t ECRC:     24;
		} u00;
		struct {  /* NH=0, GC=1 */
			uint32_t DSID:     16; /* Byte 12 */
			uint32_t SSID:     16;
			uint32_t RCCID:    12; /* Byte 16 */
			uint32_t IfaceID:  12;
			uint32_t RCSIDl:    8;
			uint32_t RCSIDh:    8; /* Byte 20 */
			uint32_t R2:        8;
			uint32_t EventID:  16;
			uint32_t ES:       32; /* Byte 24 */
			uint32_t R3:        8; /* Byte 28 */
			uint32_t ECRC:     24;
		} u01;
		struct {  /* NH=1, GC=0 */
			uint32_t RCCID:    12; /* Byte 12 */
			uint32_t IfaceID:  12;
			uint32_t RCSIDl:    8;
			uint32_t RCSIDh:    8; /* Byte 16 */
			uint32_t R2:        8;
			uint32_t EventID:  16;
			uint32_t ES:       32; /* Byte 20 */
			uint32_t NextHdr0: 32; /* Byte 24 */
			uint32_t NextHdr1: 32; /* Byte 28 */
			uint32_t NextHdr2: 32; /* Byte 32 */
			uint32_t NextHdr3: 32; /* Byte 36 */
			uint32_t R3:        8; /* Byte 40 */
			uint32_t ECRC:     24;
		} u10;
		struct {  /* NH=1, GC=1 */
			uint32_t DSID:     16; /* Byte 12 */
			uint32_t SSID:     16;
			uint32_t RCCID:    12; /* Byte 16 */
			uint32_t IfaceID:  12;
			uint32_t RCSIDl:    8;
			uint32_t RCSIDh:    8; /* Byte 20 */
			uint32_t R2:        8;
			uint32_t EventID:  16;
			uint32_t ES:       32; /* Byte 24 */
			uint32_t NextHdr0: 32; /* Byte 28 */
			uint32_t NextHdr1: 32; /* Byte 32 */
			uint32_t NextHdr2: 32; /* Byte 36 */
			uint32_t NextHdr3: 32; /* Byte 40 */
			uint32_t R3:        8; /* Byte 44 */
			uint32_t ECRC:     24;
		} u11;
	} u;
};

struct genz_uep_info {
	union {
		uint64_t flags;
		struct {
			uint64_t version:   4;  /* set by br driver */
			uint64_t local:     1;  /* set by br driver */
			uint64_t ts_valid:  1;  /* set by br driver or subsys */
			uint64_t rv:       58;
		};
	};
	struct timespec64 ts;    /* set by br driver or subsys */
	struct genz_uep_pkt uep; /* set by br driver */
};

static inline void genz_set_uep_timestamp(struct genz_uep_info *uepi)
{
	ktime_get_real_ts64(&uepi->ts);
	uepi->ts_valid = 1;
}

#define GENZ_UEP_INFO_VERS 1

uint32_t genz_dev_gcid(struct genz_dev *zdev, uint index);

/* SID is 16 bits starting at bit 13 of a GCID */
static inline int genz_gcid_sid(int gcid)
{
	return (0xFFFF & (gcid >> 12));
}

/* CID is first 12 bits of a GCID */
static inline int genz_gcid_cid(int gcid)
{
	return (0xFFF & gcid);
}

static inline int genz_gcid(int sid, int cid)
{
	return ((sid<<12) | cid);
}

static inline bool genz_is_local_bridge(struct genz_bridge_dev *br,
					struct genz_rmr_info *rmri)
{
	return ((rmri == NULL) ? true :
		((genz_dev_gcid(&br->zdev, 0) == rmri->gcid) &&
		 (rmri->dr_iface == GENZ_DR_IFACE_NONE)));
}

static inline uint32_t genz_rmri_to_gcid(struct genz_bridge_dev *br,
					 struct genz_rmr_info *rmri)
{
	return (genz_is_local_bridge(br, rmri)) ?
		genz_dev_gcid(&br->zdev, 0) : rmri->gcid;
}

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

static inline int genz_data_read(struct genz_bridge_dev *br, loff_t offset,
				 size_t size, void *data,
				 struct genz_rmr_info *rmri, uint flags)
{
	/* Revisit: need req ZMMU mapping */
	if (!br->zbdrv->data_read)  /* data_read is required */
		return -EINVAL;
	return br->zbdrv->data_read(br, offset, size, data, rmri, flags);
}

static inline int genz_data_write(struct genz_bridge_dev *br, loff_t offset,
				  size_t size, void *data,
				  struct genz_rmr_info *rmri, uint flags)
{
	/* Revisit: need req ZMMU mapping */
	if (!br->zbdrv->data_write)  /* data_write is required */
		return -EINVAL;
	return br->zbdrv->data_write(br, offset, size, data, rmri, flags);
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
void genz_init_mem_data(struct genz_mem_data *mdata,
			struct genz_bridge_dev *br);
void genz_zmmu_clear_all(struct genz_bridge_dev *br, bool free_radix_tree);
int genz_zmmu_req_pte_update(struct genz_pte_info *ptei);
int genz_zmmu_req_pte_alloc(struct genz_pte_info *ptei,
                            struct genz_rmr_info *rmri);
int genz_zmmu_rsp_pte_alloc(struct genz_pte_info *info, uint64_t *rsp_zaddr,
                            uint32_t *pg_ps);
void genz_zmmu_req_pte_free(struct genz_pte_info *info);
void genz_zmmu_rsp_pte_free(struct genz_pte_info *info);
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
struct uuid_tracker *genz_zdev_uuid_tracker_alloc_and_insert(
	uuid_t *uuid, struct genz_dev *zdev);
void genz_zdev_uuid_tracker_free(uuid_t *uuid);
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
	uint64_t length, uint16_t dr_iface, uint64_t access, uint64_t req_addr);
struct genz_rmr *genz_rmr_get(
	struct genz_mem_data *mdata, uuid_t *uuid, uint32_t dgcid,
	uint64_t rsp_zaddr, uint64_t len, uint64_t access, uint pasid,
	uint32_t rkey, uint16_t dr_iface, struct genz_rmr_info *rmri);
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
	uint16_t dr_iface, const char *rmr_name, struct genz_rmr_info *rmri);
int genz_rmr_free(struct genz_rmr_info *rmri);
int genz_rmr_update(uint32_t rkey, struct genz_rmr_info *rmri);
int genz_rmr_change_dr(uuid_t *uuid, uint32_t new_gcid, uint16_t new_dr_iface,
		       struct genz_rmr_info *rmri);
int genz_rmr_resize(uuid_t *uuid, uint64_t new_len, struct genz_rmr_info *rmri);
struct genz_rmr_info *devm_genz_rmr_import(struct genz_dev *zdev,
	struct genz_uuid_info *uui, uint32_t dgcid,
	uint64_t rsp_zaddr, uint64_t len, uint64_t access, uint32_t rkey,
	uint16_t dr_iface, const char *rmr_name);
void devm_genz_rmr_free(struct genz_dev *zdev, struct genz_rmr_info *rmri);
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
struct genz_uuid_info *devm_genz_uuid_import(
	struct genz_dev *zdev, uuid_t *uuid,
	uint32_t uu_flags, gfp_t alloc_flags);
bool genz_validate_structure_type(int type);
bool genz_validate_structure_size(struct genz_control_structure_header *hdr);
int genz_control_read(struct genz_bridge_dev *br, loff_t offset,
		      size_t size, void *data,
		      struct genz_rmr_info *rmri, uint flags);
int genz_control_write(struct genz_bridge_dev *br, loff_t offset,
		       size_t size, void *data,
		       struct genz_rmr_info *rmri, uint flags);
int genz_handle_uep(struct genz_bridge_dev *zbdev, struct genz_uep_info *uepi);
void genz_dev_put(struct genz_dev *zdev);
struct genz_dev *genz_dev_get(struct genz_dev *zdev);

#endif /* LINUX_GENZ_H */
