/*
 * Copyright (C) 2018 Hewlett Packard Enterprise Development LP.
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

#ifndef _WILDCAT_H_
#define _WILDCAT_H_

#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#define SLICES                        4
#define VECTORS_PER_SLICE             32
#define MAX_IRQ_VECTORS               (VECTORS_PER_SLICE * SLICES)

struct xdm_qcm_header {
	uint64_t cmd_q_base_addr  : 64; /* byte 0 */
	uint64_t cmpl_q_base_addr : 64;
	uint64_t cmd_q_size       : 16;
	uint64_t rv2              : 16;
	uint64_t cmpl_q_size      : 16;
	uint64_t rv3              : 16;
	uint64_t local_pasid      : 20;
	uint64_t traffic_class    : 4;
	uint64_t priority         : 1;
	uint64_t rv4              : 5;
	uint64_t virt_addr        : 1;
	uint64_t q_virt_addr      : 1;
	uint64_t fabric_pasid     : 20;
	uint64_t rv5              : 12;
	uint64_t master_stop      : 1;
	uint64_t rv6              : 63;
	uint64_t active_cmd_cnt   : 11;
	uint64_t rv7              : 4;
	uint64_t active           : 1;
	uint64_t status           : 3;
	uint64_t rv8              : 12;
	uint64_t error            : 1;
	uint64_t rv9              : 32;
	uint64_t rv10[2];
	uint64_t stop             : 1;
	uint64_t rv11             : 63;
	uint64_t rv12[7];
	uint64_t cmd_q_tail_idx   : 16;
	uint64_t rv13             : 48;
	uint64_t rv14[7];
	uint64_t cmd_q_head_idx   : 16;
	uint64_t rv15             : 48;
	uint64_t rv16[7];
	uint64_t cmpl_q_tail_idx  : 16;
	uint64_t rv17             : 15;
	uint64_t toggle_valid     : 1;
	uint64_t rv18             : 32;
};

struct xdm_qcm {
	struct xdm_qcm_header     hdr;
	uint64_t rv19[8159];
};

struct rdm_qcm_header {
	uint64_t cmpl_q_base_addr : 64;
	uint64_t cmpl_q_size      : 20;
	uint64_t rv1              : 12;
	uint64_t pasid            : 20;
	uint64_t rv2              : 10;
	uint64_t intr_enable      : 1;
	uint64_t q_virt_addr      : 1;
	uint64_t master_stop      : 1;
	uint64_t rv3              : 63;
	uint64_t active           : 1;
	uint64_t rv4              : 63;
	uint64_t rv5[4];		   /* end of first 64 bytes */
	uint64_t stop             : 1;
	uint64_t rv6              : 63;
	uint64_t rv7[7];
	uint64_t rcv_q_tail_idx   : 20;
	uint64_t rv8              : 11;
	uint64_t toggle_valid     : 1;
	uint64_t rv9              : 32;
	uint64_t rv10[7];
	uint64_t rcv_q_head_idx   : 20;
	uint64_t rv11             : 44;
};

struct rdm_qcm {
	struct rdm_qcm_header     hdr;
	uint64_t rv12[8167];
};

struct wildcat_req_pte {
	uint64_t pasid         : 20;  /* byte  0 */
	uint64_t space_type    :  3;
	uint64_t rke           :  1;
	uint64_t traffic_class :  4;
	uint64_t dc_grp        :  2;
	uint64_t rv0           :  6;
	uint64_t dgcid         : 28;  /* in HW, dsid:16, dcid:12 */
	uint64_t ctn           :  2;  /* byte  8 */
	uint64_t rv8           : 10;
	uint64_t addr          : 52;
	uint64_t rkey          : 32;  /* byte 16 */
	uint64_t rv20          : 32;
	uint64_t rv24          : 32;  /* byte 24 */
	uint64_t rv28          : 31;
	uint64_t v             :  1;
} __attribute__ ((aligned (32)));

struct wildcat_rsp_pte {
	uint64_t pasid         : 20;  /* byte  0 */
	uint64_t space_type    :  3;  /* only DATA (0) allowed */
	uint64_t rke           :  1;
	uint64_t rv0           : 40;
	uint64_t va            : 48;  /* byte  8 */
	uint64_t rv12          : 16;
	uint64_t ro_rkey       : 32;  /* byte 16 */
	uint64_t rw_rkey       : 32;
	uint64_t window_sz     : 48;  /* byte 24 */
	uint64_t rv28          : 15;
	uint64_t v             :  1;
} __attribute__ ((aligned (32)));

struct wildcat_page_grid {
	uint64_t base_addr     : 64;  /* byte 0 */
	uint64_t page_count    : 18;  /* byte 8 */  /* 0 disables grid */
	uint64_t rv8a          :  6;
	uint64_t page_size     :  6;  /* min 12 (4KiB), max 48 (256TiB) */
	uint64_t rv8b          :  2;
	uint64_t base_pte_idx  : 17;  /* byte 12 */
	uint64_t rv12a         :  7;
	uint64_t smo           :  1;  /* secure mode only */
	uint64_t rv12b         :  7;
} __attribute__ ((aligned (16)));

struct containment_counter {
	uint64_t counter       : 16;  /* byte  0 */
	uint64_t rv0           : 48;
	uint64_t rv1[7];              /* bytes 8 - 63 */
} __attribute__ ((aligned (64)));

struct big_hammer_containment {
	uint64_t bhc           :  1;  /* byte  0 */
	uint64_t rv0           : 63;
	uint64_t rv1[3];              /* bytes 8 - 31 */
} __attribute__ ((aligned (32)));

#define GB(_x)            ((_x)*BIT_ULL(30))
#define TB(_x)            ((_x)*BIT_ULL(40))

#define WILDCAT_MIN_CPUVISIBLE_ADDR  (GB(4)+TB(1))
#define WILDCAT_MAX_CPUVISIBLE_ADDR  (GENZ_MIN_CPUVISIBLE_ADDR+TB(250)-1ull)

#define REQ_ZMMU_ENTRIES             (1024)
#define RSP_ZMMU_ENTRIES             (1024)
#define MAX_REQ_ZMMU_ENTRIES         (128*1024)
#define MAX_RSP_ZMMU_ENTRIES         (64*1024)
#define DUMMY_REQ_ZMMU_ENTRIES       (MAX_REQ_ZMMU_ENTRIES - REQ_ZMMU_ENTRIES)
#define DUMMY_RSP_ZMMU_ENTRIES       (MAX_RSP_ZMMU_ENTRIES - RSP_ZMMU_ENTRIES)
#define CONTAINMENT_COUNTER_ALIASES  (128*1024)
#define WILDCAT_PAGE_GRID_ENTRIES    (16)

#define REQ_PTE_SZ   (REQ_ZMMU_ENTRIES*sizeof(struct wildcat_req_pte))
#define PAGE_GRID_SZ (WILDCAT_PAGE_GRID_ENTRIES * \
		      sizeof(struct wildcat_page_grid))
#define REQ_RV0_SZ       (DUMMY_REQ_ZMMU_ENTRIES*sizeof(struct wildcat_req_pte))
#define REQ_RV1_SZ       (0x500000 - (REQ_PTE_SZ + REQ_RV0_SZ + PAGE_GRID_SZ))
#define REQ_BHC_SZ       (sizeof(struct big_hammer_containment))
#define REQ_RV2_SZ       (0x800000 - 0x500000 - REQ_BHC_SZ)
#define REQ_RV3_SZ       (0x2000000 - 0x1000000)

#define WILDCAT_PAGE_GRID_MIN_PAGESIZE       12
#define WILDCAT_PAGE_GRID_MAX_PAGESIZE       48

struct wildcat_req_zmmu {
	struct wildcat_req_pte        pte[REQ_ZMMU_ENTRIES];
#if REQ_ZMMU_ENTRIES < MAX_REQ_ZMMU_ENTRIES
	uint8_t                       rv0[REQ_RV0_SZ];
#endif
	struct wildcat_page_grid      page_grid[WILDCAT_PAGE_GRID_ENTRIES];
	uint8_t                       rv1[REQ_RV1_SZ];
	struct big_hammer_containment bhc;
	uint8_t                       rv2[REQ_RV2_SZ];
	struct containment_counter    contain_cntr[CONTAINMENT_COUNTER_ALIASES];
	uint8_t                       rv3[REQ_RV3_SZ];
};

#define RSP_RV0_SZ       (DUMMY_RSP_ZMMU_ENTRIES*sizeof(struct wildcat_rsp_pte))
#define RSP_RV1_SZ       (0x400000 - 0x200000)
#define RSP_RV2_SZ       (0x2000000 - 0x400000 - PAGE_GRID_SZ)

struct wildcat_rsp_zmmu {
	struct wildcat_rsp_pte        pte[RSP_ZMMU_ENTRIES];
#if RSP_ZMMU_ENTRIES < MAX_RSP_ZMMU_ENTRIES
	uint8_t                       rv0[RSP_RV0_SZ];
#endif
	uint8_t                       rv1[RSP_RV1_SZ];
	struct wildcat_page_grid      page_grid[WILDCAT_PAGE_GRID_ENTRIES];
	uint8_t                       rv2[RSP_RV2_SZ];
};

/* Can be useful for testing to reduce the queues per slice. 256 in hw */
#define XDM_QUEUES_PER_SLICE	16  /* Revisit: temporary */
#define RDM_QUEUES_PER_SLICE	16
#define MAX_RDM_QUEUES_PER_SLICE	256  /* for crazy HW intr mapping */

struct rdm_vector_list {
	struct list_head list;
	int              irq_index;
	int              queue;
	irqreturn_t      (*handler)(int, void *);
	void             *data;
};

struct slice {
	struct func1_bar0   *bar;        /* kernel mapping of BAR */
	phys_addr_t         phys_base;   /* physical address of BAR */
	spinlock_t          zmmu_lock;   /* per-slice zmmu lock */
	bool                valid;       /* slice is fully initialized */
	unsigned int        id;          /* zero based, unique slice id */
	struct pci_dev	*pdev;
	/* Revisit: add s_link boolean */
	spinlock_t           xdm_slice_lock; /* locks alloc_count, alloced_bitmap */
	int                  xdm_alloc_count;
	DECLARE_BITMAP(xdm_alloced_bitmap, XDM_QUEUES_PER_SLICE);
	spinlock_t           rdm_slice_lock; /* locks alloc_count, alloced_bitmap */
	int                  rdm_alloc_count;
	DECLARE_BITMAP(rdm_alloced_bitmap, RDM_QUEUES_PER_SLICE);
	uint16_t             irq_vectors_count; /* number of interrupt vectors */
	struct list_head     irq_vectors[VECTORS_PER_SLICE]; /* per vector list
								of queues sharing
								a vector */
};

#define SLICE_VALID(s) ((s)->valid) /* bool SLICE_VALID(struct slice *s) */

struct bridge;  /* tentative declarations */
struct queue_zpage {  /* also used for LOCAL_SHARED_PAGE/GLOBAL_SHARED_PAGE */
	int		page_type;
	size_t		size;	/* in bytes */
	void		*pages[0];
};

struct hsr_zpage {
	int		page_type;
	size_t		size;	/* in bytes */
	phys_addr_t	base_addr;
};

struct dma_zpage {
	int		page_type;
	size_t		size;	/* in bytes */
	struct device   *dev;
	void 		*cpu_addr;
	dma_addr_t	dma_addr;
	void 		*user_vaddr; /* set by HELPER_MMAP */
};

struct rmr_zpage {
	int		page_type;
	size_t		size;	/* in bytes */
	struct zhpe_rmr *rmr;
};

struct hdr_zpage {
	int		page_type;
	size_t		size;	/* in bytes */
};

union zpages {
	struct hdr_zpage    hdr;
	struct queue_zpage  queue;
	struct hsr_zpage    hsr;
	struct dma_zpage    dma;
	struct rmr_zpage    rmrz;
};

struct xdm_info {
	struct bridge  *br;
	uint32_t       cmdq_ent, cmplq_ent;
	uint8_t        slice_mask, traffic_class, priority;
	bool           cur_valid;
	size_t         cmdq_size, cmplq_size, qcm_size;
	struct slice   *sl;
	struct xdm_qcm *hw_qcm_addr;
	union zpages   *cmdq_zpage, *cmplq_zpage;
	int            slice, queue;
	uint           cmdq_tail_shadow, cmdq_head_shadow; /* shadow of HW reg */
	uint           cmplq_tail_shadow;                  /* shadow of HW reg */
	uint           cmplq_head;                         /* SW-only */
	uint           active_cmds;                        /* SW-only */
	spinlock_t     xdm_info_lock;
};

struct rdm_info {
	struct bridge  *br;
	uint32_t       cmplq_ent;
	uint8_t        slice_mask;
	bool           cur_valid;
	size_t         cmplq_size, qcm_size;
	struct slice   *sl;
	struct rdm_qcm *hw_qcm_addr;
	union zpages   *cmplq_zpage;
	int            slice, queue, vector;
	uint32_t       rspctxid;
	uint           cmplq_tail_shadow, cmplq_head_shadow; /* shadow of HW reg */
	spinlock_t     rdm_info_lock;
};

struct bridge {
	uint32_t                gcid;
	struct slice            slice[SLICES];
	spinlock_t              zmmu_lock;  /* global bridge zmmu lock */
	struct xdm_info         msg_xdm;
	struct rdm_info         msg_rdm;
#ifdef OLD_ZHPE
	struct page_grid_info   req_zmmu_pg;
	struct page_grid_info   rsp_zmmu_pg;
	struct zhpe_core_info   core_info;
	spinlock_t              fdata_lock;  /* protects fdata_list */
	struct list_head        fdata_list;
#endif
	struct workqueue_struct *wildcat_msg_workq;
	wait_queue_head_t       wildcat_poll_wq[MAX_IRQ_VECTORS];
};

struct mem_data;

enum {
	HELPER_STATE_OPEN      = 0,
	HELPER_STATE_INIT      = 1,
	HELPER_STATE_WAIT      = 2,
	HELPER_STATE_CMD       = 3,
	HELPER_STATE_EXIT      = 4,
	HELPER_STATE_MMAP      = 5,
	HELPER_STATE_MMAP_DONE = 6,
	HELPER_STATE_COUNT,
	HELPER_STATE_NO_WAIT = HELPER_STATE_COUNT  /* must be last */
};

union wildcat_op;

struct helper_state {
	uint next_state;
	int (*func)(uint cur_state, union wildcat_op *op, uint *next_state);
};

#define do_kmalloc(...) \
    _do_kmalloc(__func__, __LINE__, __VA_ARGS__)
void *_do_kmalloc(const char *callf, uint line,
                         size_t size, gfp_t flags, bool zero);
#define do_kfree(...) \
    _do_kfree(__func__, __LINE__, __VA_ARGS__)
void _do_kfree(const char *callf, uint line, void *ptr);

#define do_free_pages(...) \
    _do_free_pages(__func__, __LINE__, __VA_ARGS__)
void _do_free_pages(const char *callf, uint line, void *ptr, int order);

#define do_free_page(_ptr) \
    _do_free_pages(__func__, __LINE__, (_ptr), 0)

#define do__get_free_pages(...) \
    _do__get_free_pages(__func__, __LINE__, __VA_ARGS__)
void *_do__get_free_pages(const char *callf, uint line,
                          int order, gfp_t flags, bool zero);

#define do__get_free_page(_flags, _zero)                        \
    _do__get_free_pages(__func__, __LINE__, 0, (_flags), (_zero))

void _zpages_free(const char *callf, uint line, union zpages *zpages);
#define zpages_free(...) \
    _zpages_free(__func__, __LINE__, __VA_ARGS__)

enum {
	QUEUE_PAGE =           1,
	HSR_PAGE =             2,
	DMA_PAGE =             3,
	RMR_PAGE =             4,
	LOCAL_SHARED_PAGE =    5,
	GLOBAL_SHARED_PAGE =   6
};

union zpages *_queue_zpages_alloc(const char *callf, uint line, 
	size_t size, bool contig);
#define queue_zpages_alloc(...) \
    _queue_zpages_alloc(__func__, __LINE__, __VA_ARGS__)

union zpages *_dma_zpages_alloc(const char *callf, uint line, 
	struct slice * sl, size_t size);
#define dma_zpages_alloc(...) \
    _dma_zpages_alloc(__func__, __LINE__, __VA_ARGS__)

union zpages *_hsr_zpage_alloc(const char *callf, uint line,
                               phys_addr_t base_addr);
#define hsr_zpage_alloc(...) \
    _hsr_zpage_alloc(__func__, __LINE__, __VA_ARGS__)

union zpages *_rmr_zpages_alloc(const char *callf, uint line,
                                struct zhpe_rmr *rmr);
#define rmr_zpages_alloc(...) \
    _rmr_zpages_alloc(__func__, __LINE__, __VA_ARGS__)

/* Revisit: these should go away */
extern uint wildcat_debug_flags;
extern uint wildcat_kmsg_timeout;

extern struct bridge wildcat_bridge;
extern void wildcat_init_mem_data(struct mem_data *mdata, struct bridge *br);
extern struct file_data *wildcat_pid_to_fdata(struct bridge *br, pid_t pid);
extern union zpages *shared_zpage_alloc(size_t size, int type);
void queue_zpages_free(union zpages *zpages);

#endif /* _WILDCAT_H_ */
