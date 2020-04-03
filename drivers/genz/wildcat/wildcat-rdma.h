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

#ifndef _WILDCAT_RDMA_H_
#define _WILDCAT_RDMA_H_

/* this file is shared between KERNEL and user-space RDMA code */
#ifdef __KERNEL__

#include <linux/uio.h>
#include <linux/uuid.h>
#include <linux/socket.h>
#include <asm/byteorder.h>

typedef long long          llong;  /* Revisit: get rid of these */
typedef unsigned long long ullong;

#else

#include <endian.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <uuid/uuid.h>

#endif

#include "wildcat.h"
#include "wildcat-uapi.h"

/* Do extern "C" without goofing up emacs. */
#ifndef _EXTERN_C_SET
#define _EXTERN_C_SET
#ifdef  __cplusplus
#define _EXTERN_C_BEG extern "C" {
#define _EXTERN_C_END }
#else
#define _EXTERN_C_BEG
#define _EXTERN_C_END
#endif
#endif

_EXTERN_C_BEG

#define DRIVER_NAME     "wildcat-rdma"

enum {
	WILDCAT_RDMA_OP_INIT        = 0,
	WILDCAT_RDMA_OP_MR_REG      = 1,
	WILDCAT_RDMA_OP_MR_FREE     = 2,
	WILDCAT_RDMA_OP_NOP         = 3,
				   /* 4 was QALLOC */
				   /* 5 was QFREE */
	WILDCAT_RDMA_OP_RMR_IMPORT  = 6,
	WILDCAT_RDMA_OP_RMR_FREE    = 7,
				   /* 8 was ZMMU_REG */
				   /* 9 was ZMMU_FREE */
	WILDCAT_RDMA_OP_UUID_IMPORT = 10,
	WILDCAT_RDMA_OP_UUID_FREE   = 11,
	WILDCAT_RDMA_OP_XQALLOC     = 12,
	WILDCAT_RDMA_OP_XQFREE      = 13,
	WILDCAT_RDMA_OP_RQALLOC     = 14,
	WILDCAT_RDMA_OP_RQFREE      = 15,
	WILDCAT_RDMA_OP_RESPONSE    = 0x80,
	WILDCAT_RDMA_OP_VERSION     = 1,
};

/* WILDCAT_MAGIC == 'WILD' */
#define WILDCAT_MAGIC                 (0x57494C44)
#define WILDCAT_ENTRY_LEN             (64U)
#define WILDCAT_GLOBAL_SHARED_VERSION (1)
#define MAX_IRQ_VECTORS               (VECTORS_PER_SLICE * SLICES)

struct wildcat_info {
	uint32_t            qlen;
	uint32_t            rsize;
	uint32_t            qsize;
	uint64_t            reg_off;
	uint64_t            wq_off;
	uint64_t            cq_off;
};

struct wildcat_rdma_state {
	struct genz_dev         *zdev;
	struct miscdevice       miscdev;
	spinlock_t              fdata_lock;  /* protects fdata_list */
	struct list_head        fdata_list;
	wait_queue_head_t       rdma_poll_wq[MAX_IRQ_VECTORS];
	int                     min_irq_index;
	int                     max_irq_index;
	struct list_head        rstate_node;
};
#define to_wildcat_rdma_state(n) container_of(n, struct wildcat_rdma_state, \
					      miscdev)

struct wildcat_rdma_hdr {
	uint8_t             version;
	uint8_t             opcode;
	uint16_t            index;
	int                 status;
};

struct wildcat_rdma_req_INIT {
	struct wildcat_rdma_hdr  hdr;
};

struct wildcat_rdma_rsp_INIT {
	struct wildcat_rdma_hdr hdr;
	uuid_t              uuid;
	uint64_t            global_shared_offset; /* triggered counters */
	uint32_t            global_shared_size;
	uint64_t            local_shared_offset;  /* handled counters */
	uint32_t            local_shared_size;
};

struct wildcat_rdma_req_MR_REG {
	struct wildcat_rdma_hdr hdr;
	uint64_t                vaddr;
	uint64_t                len;
	uint64_t                access;
};

struct wildcat_rdma_rsp_MR_REG {
	struct wildcat_rdma_hdr hdr;
	uint64_t                rsp_zaddr;
	uint32_t                pg_ps;
	uint64_t                physaddr;  /* Revisit: remove when IOMMU works */
};

struct wildcat_rdma_req_MR_FREE {
	struct wildcat_rdma_hdr hdr;
	uint64_t                vaddr;
	uint64_t                len;
	uint64_t                access;
	uint64_t                rsp_zaddr;
};

struct wildcat_rdma_rsp_MR_FREE {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_rdma_req_RMR_IMPORT {
	struct wildcat_rdma_hdr hdr;
	uuid_t                  uuid;
	uint64_t                rsp_zaddr;
	uint64_t                len;
	uint64_t                access;
};

struct wildcat_rdma_rsp_RMR_IMPORT {
	struct wildcat_rdma_hdr hdr;
	uint64_t                req_addr;
	off_t                   offset;  /* if cpu-visible */
	uint32_t                pg_ps;
};

struct wildcat_rdma_req_RMR_FREE {
	struct wildcat_rdma_hdr hdr;
	uuid_t                  uuid;
	uint64_t                rsp_zaddr;
	uint64_t                len;
	uint64_t                access;
	uint64_t                req_addr;
};

struct wildcat_rdma_rsp_RMR_FREE {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_rdma_req_NOP {
	struct wildcat_rdma_hdr hdr;
	uint64_t                seq;
};

struct wildcat_rdma_rsp_NOP {
	struct wildcat_rdma_hdr hdr;
	uint64_t                seq;
};

struct wildcat_rdma_req_UUID_IMPORT {
	struct wildcat_rdma_hdr hdr;
	uuid_t                  uuid;
	uuid_t                  mgr_uuid;
	uint32_t                uu_flags;
};

struct wildcat_rdma_rsp_UUID_IMPORT {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_rdma_req_UUID_FREE {
	struct wildcat_rdma_hdr hdr;
	uuid_t                  uuid;
};

struct wildcat_rdma_rsp_UUID_FREE {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_qcm {
	uint32_t           size;   /* Bytes allocated for the QCM */
	uint64_t           off;    /* File descriptor offset to the QCM */
};

struct wildcat_queue {
	uint32_t           ent;    /* Number of entries in the queue */
	uint32_t           size;   /* Bytes allocated for the queue */
	uint64_t           off;    /* File descriptor offset to the queue */
};

struct wildcat_xqinfo {
	struct wildcat_qcm     qcm;   /* XDM Queue Control Memory */
	struct wildcat_queue   cmdq;  /* XDM Command Queue */
	struct wildcat_queue   cmplq; /* XDM Completion Queue */
	uint8_t                slice; /* HW slice number which allocated
					 the queues */
	uint8_t                queue; /* HW queue number */
};

struct wildcat_rdma_req_XQALLOC {
	struct wildcat_rdma_hdr hdr;
	uint32_t            cmdq_ent;       /* Minimum entries in the cmdq */
	uint32_t            cmplq_ent;      /* Minimum entries in the cmplq */
	uint8_t             traffic_class;  /* Traffic class for this queue */
	uint8_t             priority;       /* Priority for this queue */
	uint8_t             slice_mask;     /* Control HW slice allocation */
};

struct wildcat_rdma_rsp_XQALLOC {
	struct wildcat_rdma_hdr	hdr;
	struct wildcat_xqinfo   info;
};

struct wildcat_rdma_req_XQFREE {
	struct wildcat_rdma_hdr	hdr;
	struct wildcat_xqinfo	info;
};

struct wildcat_rdma_rsp_XQFREE {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_rqinfo {
	struct wildcat_qcm    qcm;   /* XDM Queue Control Memory */
	struct wildcat_queue  cmplq; /* XDM Completion Queue */
	uint8_t               slice; /* HW slice number which allocated
					the queues */
	uint8_t               queue; /* HW queue number */
	uint32_t              rspctxid; /* RSPCTXID to use with EnqA */
	uint32_t              irq_vector; /* interrupt vector that maps to poll dev */
};

struct wildcat_rdma_req_RQALLOC {
	struct wildcat_rdma_hdr hdr;
	uint32_t            cmplq_ent;          /* Entries in the cmplq minus 1.
						 * e.g. use 1 for 2 entries.  */
	uint8_t             slice_mask;         /* Control HW slice allocation */
};

struct wildcat_rdma_rsp_RQALLOC {
	struct wildcat_rdma_hdr hdr;
	struct wildcat_rqinfo   info;
};

struct wildcat_rdma_req_RQFREE {
	struct wildcat_rdma_hdr hdr;
	struct wildcat_rqinfo   info;
};

struct wildcat_rdma_rsp_RQFREE {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_rdma_req_HELPER_MMAP {
	struct wildcat_rdma_hdr hdr;
	uint64_t                offset;  /* provided by driver */
	uint64_t                len;     /* provided by driver */
	uint64_t                vaddr;   /* returned by helper */
};

struct wildcat_rdma_rsp_HELPER_MMAP {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_rdma_req_HELPER_WAIT {
	struct wildcat_rdma_hdr hdr;
};

union wildcat_rdma_req {
	struct wildcat_rdma_hdr             hdr;
	struct wildcat_rdma_req_INIT        init;
	struct wildcat_rdma_req_MR_REG      mr_reg;
	struct wildcat_rdma_req_MR_FREE     mr_free;
	struct wildcat_rdma_req_RMR_IMPORT  rmr_import;
	struct wildcat_rdma_req_RMR_FREE    rmr_free;
	struct wildcat_rdma_req_NOP         nop;
	struct wildcat_rdma_req_UUID_IMPORT uuid_import;
	struct wildcat_rdma_req_UUID_FREE   uuid_free;
	struct wildcat_rdma_req_XQALLOC     xqalloc;
	struct wildcat_rdma_req_XQFREE      xqfree;
	struct wildcat_rdma_req_RQALLOC     rqalloc;
	struct wildcat_rdma_req_RQFREE      rqfree;
	struct wildcat_rdma_req_HELPER_WAIT helper_wait;
	struct wildcat_rdma_req_HELPER_MMAP helper_mmap;
};

/* contains a wildcat_rdma_req, so must be defined after it */
struct wildcat_rdma_rsp_HELPER_WAIT {
	struct wildcat_rdma_hdr hdr;
	union wildcat_rdma_req  req;
	uint32_t                req_len;
	uint32_t                next_state;
};

union wildcat_rdma_rsp {
	struct wildcat_rdma_hdr             hdr;
	struct wildcat_rdma_rsp_INIT        init;
	struct wildcat_rdma_rsp_MR_REG      mr_reg;
	struct wildcat_rdma_rsp_MR_FREE     mr_free;
	struct wildcat_rdma_rsp_RMR_IMPORT  rmr_import;
	struct wildcat_rdma_rsp_RMR_FREE    rmr_free;
	struct wildcat_rdma_rsp_NOP         nop;
	struct wildcat_rdma_rsp_UUID_IMPORT uuid_import;
	struct wildcat_rdma_rsp_UUID_FREE   uuid_free;
	struct wildcat_rdma_rsp_XQALLOC     xqalloc;
	struct wildcat_rdma_rsp_XQFREE      xqfree;
	struct wildcat_rdma_rsp_RQALLOC     rqalloc;
	struct wildcat_rdma_rsp_RQFREE      rqfree;
	struct wildcat_rdma_rsp_HELPER_WAIT helper_wait;
	struct wildcat_rdma_rsp_HELPER_MMAP helper_mmap;
};

union wildcat_rdma_op {
	struct wildcat_rdma_hdr hdr;
	union wildcat_rdma_req  req;
	union wildcat_rdma_rsp  rsp;
};

struct wildcat_global_shared_data {
	uint                magic;
	uint                version;
	uint                debug_flags;
	struct wildcat_attr default_attr;
	uint32_t            triggered_counter[MAX_IRQ_VECTORS];
};

#define WILDCAT_LOCAL_SHARED_VERSION    (1)
struct wildcat_local_shared_data {
	uint                magic;
	uint                version;
	uint32_t            handled_counter[MAX_IRQ_VECTORS];
};

struct zmap {
	struct list_head    list;
	struct file_data    *owner;
	ulong               offset;
	union zpages       *zpages;
};

#define ZMAP_BAD_OWNER  (ERR_PTR(-EACCES))

/* Revisit: these are kernel only - move to another header? */
void _zmap_free(const char *callf, uint line, struct zmap *zmap);
#define zmap_free(...) \
	_zmap_free(__func__, __LINE__, __VA_ARGS__)

struct zmap *_zmap_alloc(
	const char *callf,
	uint line,
	struct file_data *fdata,
	union zpages *zpages);
#define zmap_alloc(...) \
	_zmap_alloc(__func__, __LINE__, __VA_ARGS__)

bool _free_zmap_list(const char *callf, uint line, struct file_data *fdata);
#define free_zmap_list(...) \
	_free_zmap_list(__func__, __LINE__, __VA_ARGS__)

struct file_data {
	void                 (*free)(const char *callf, uint line, void *ptr);
	atomic_t             count;
	uint8_t              state;
	unsigned int         pasid;
	spinlock_t           io_lock;
	wait_queue_head_t    io_wqh;
	struct list_head     fdata_list;
	struct list_head     rd_list;
	struct genz_mem_data md;
	spinlock_t           zmap_lock;  /* protects zmap_list */
	struct list_head     zmap_list;
	struct zmap          *shared_zmap;
	union zpages         *local_shared_zpage;
	struct zmap          *local_shared_zmap;
	struct zmap          *global_shared_zmap;
	struct genz_pte_info *humongous_zmmu_rsp_pte;
	spinlock_t           xdm_queue_lock;
	DECLARE_BITMAP(xdm_queues, XDM_QUEUES_PER_SLICE*SLICES);
	spinlock_t           rdm_queue_lock;
	DECLARE_BITMAP(rdm_queues, RDM_QUEUES_PER_SLICE*SLICES);
	pid_t                pid;        /* pid that allocated this file_data */
	struct wildcat_rdma_state *rstate;
};

struct io_entry {
	void                (*free)(const char *callf, uint line, void *ptr);
	atomic_t            count;
	bool                nonblock;
	struct wildcat_rdma_hdr  hdr;
	struct file_data    *fdata;
	struct list_head    list;
	size_t              data_len;
	union {
		uint8_t          data[0];
		union wildcat_rdma_op op;
	};
};

enum {
	STATE_CLOSED        = 0x1,
	STATE_READY         = 0x2,
	STATE_INIT          = 0x4,
};

/* Function Prototypes */
int wildcat_user_req_XQFREE(struct io_entry *entry);
int wildcat_user_req_XQALLOC(struct io_entry *entry);
int wildcat_user_req_RQFREE(struct io_entry *entry);
int wildcat_user_req_RQALLOC(struct io_entry *entry);
int wildcat_req_XQALLOC(struct wildcat_rdma_req_XQALLOC *req,
			struct wildcat_rdma_rsp_XQALLOC	*rsp,
			struct file_data *fdata);
int wildcat_req_XQFREE(union wildcat_rdma_req *req,
			union wildcat_rdma_rsp *rsp, struct file_data *fdata);
int wildcat_req_RQALLOC(struct wildcat_rdma_req_RQALLOC *req,
			struct wildcat_rdma_rsp_RQALLOC *rsp,
			struct file_data *fdata);
int wildcat_req_RQFREE(struct wildcat_rdma_req_RQFREE *req,
		       struct wildcat_rdma_rsp_RQFREE *rsp,
			struct file_data *fdata);
/* Revisit: delete this when vma_set_page_prot is exported */
void wildcat_vma_set_page_prot(struct vm_area_struct *vma);
_EXTERN_C_END

#ifdef _EXTERN_C_SET
#undef _EXTERN_C_SET
#undef _EXTERN_C_BEG
#undef _EXTERN_C_END
#endif

#endif /* _WILDCAT_RDMA_H_ */
