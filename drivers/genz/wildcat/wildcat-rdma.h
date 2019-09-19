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
	WILDCAT_RDMA_OP_INIT,
	WILDCAT_RDMA_OP_MR_REG,
	WILDCAT_RDMA_OP_MR_FREE,
	WILDCAT_RDMA_OP_NOP,
	WILDCAT_RDMA_OP_RMR_IMPORT,
	WILDCAT_RDMA_OP_RMR_FREE,
	WILDCAT_RDMA_OP_ZMMU_REG,
	WILDCAT_RDMA_OP_ZMMU_FREE,
	WILDCAT_RDMA_OP_UUID_IMPORT,
	WILDCAT_RDMA_OP_UUID_FREE,
	WILDCAT_RDMA_OP_XQALLOC,
	WILDCAT_RDMA_OP_XQFREE,
	WILDCAT_RDMA_OP_RQALLOC,
	WILDCAT_RDMA_OP_RQFREE,
	WILDCAT_RDMA_OP_HELPER_WAIT,
	WILDCAT_RDMA_OP_HELPER_MMAP,
	WILDCAT_RDMA_OP_RESPONSE = 0x80,
	WILDCAT_RDMA_OP_VERSION = 1,
};

/* WILDCAT_MAGIC == 'WILD' */
#define WILDCAT_MAGIC      (0x57494C44)

#define WILDCAT_ENTRY_LEN  (64U)

struct wildcat_info {
	uint32_t            qlen;
	uint32_t            rsize;
	uint32_t            qsize;
	uint64_t            reg_off;
	uint64_t            wq_off;
	uint64_t            cq_off;
};

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

struct wildcat_rdma_req_ZMMU_REG {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_rdma_rsp_ZMMU_REG {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_rdma_req_ZMMU_FREE {
	struct wildcat_rdma_hdr hdr;
};

struct wildcat_rdma_rsp_ZMMU_FREE {
	struct wildcat_rdma_hdr hdr;
};

enum {
	UUID_IS_FAM  = 0x1,
	UUID_IS_ENIC = 0x2,
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

/* Defines for the XQALLOC/RQALLOC slice_mask */
#define SLICE_DEMAND 0x80
#define ALL_SLICES   0x0f

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

/*
 * Traffic class abstraction for user space. Used in wildcat_rdma_req_XQALLOC
 * traffic_class field. Mapping to actual Gen-Z traffic class is
 * undefined to user space.
 */
enum {
	WILDCAT_TC_0 = 0,
	WILDCAT_TC_1 = 1,
	WILDCAT_TC_2 = 2,
	WILDCAT_TC_3 = 3,
	WILDCAT_TC_4 = 4,
	WILDCAT_TC_5 = 5,
	WILDCAT_TC_6 = 6,
	WILDCAT_TC_7 = 7,
	WILDCAT_TC_8 = 8,
	WILDCAT_TC_9 = 9,
	WILDCAT_TC_10 = 10,
	WILDCAT_TC_11 = 11,
	WILDCAT_TC_12 = 12,
	WILDCAT_TC_13 = 13,
	WILDCAT_TC_14 = 14,
	WILDCAT_TC_15 = 15
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
	struct wildcat_rdma_req_ZMMU_REG    zmmu_reg;
	struct wildcat_rdma_req_ZMMU_FREE   zmmu_free;
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
	struct wildcat_rdma_rsp_ZMMU_REG    zmmu_reg;
	struct wildcat_rdma_rsp_ZMMU_FREE   zmmu_free;
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

#define WILDCAT_GLOBAL_SHARED_VERSION (1)
#define SLICES                         4
#define VECTORS_PER_SLICE              32
#define MAX_IRQ_VECTORS                (VECTORS_PER_SLICE * SLICES)

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

/* XDM QCM access macros and structures. Reads and writes must be 64 bits */

struct wildcat_xdm_active_status_error {
	uint64_t active_cmd_cnt   : 11;
	uint64_t rv1              : 4;
	uint64_t active           : 1;
	uint64_t status           : 3;
	uint64_t rv2              : 12;
	uint64_t error            : 1;
	uint64_t rv3              : 32;
};
#define WILDCAT_XDM_QCM_ACTIVE_STATUS_ERROR_OFFSET	0x28
#define WILDCAT_XDM_QCM_STOP_OFFSET		0x40
#define WILDCAT_XDM_QCM_CMD_QUEUE_TAIL_OFFSET	0x80
#define WILDCAT_XDM_QCM_CMD_QUEUE_HEAD_OFFSET	0xc0
struct wildcat_xdm_cmpl_queue_tail_toggle {
	uint64_t cmpl_q_tail_idx  : 16;
	uint64_t rv1              : 15;
	uint64_t toggle_valid     : 1;
	uint64_t rv2              : 32;
};
#define WILDCAT_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET	0x100

/* RDM QCM access macros and structures. Reads and writes must be 64 bits */
#define WILDCAT_RDM_QCM_ACTIVE				0x18
#define WILDCAT_RDM_QCM_STOP_OFFSET			0x40
struct wildcat_rdm_rcv_queue_tail_toggle {
	uint64_t rcv_q_tail_idx   : 20;
	uint64_t rv1              : 11;
	uint64_t toggle_valid     : 1;
	uint64_t rv2              : 32;
};
#define WILDCAT_RDM_QCM_RCV_QUEUE_TAIL_TOGGLE_OFFSET	0x80
#define WILDCAT_RDM_QCM_RCV_QUEUE_HEAD_OFFSET		0xc0

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

/* Revisit: make this generic, not wildcat-specific */
struct mem_data {
	struct bridge       *bridge;
	spinlock_t          uuid_lock;  /* protects local_uuid, remote_uuid_tree */
	struct uuid_tracker *local_uuid;
	struct rb_root      md_remote_uuid_tree;  /* UUIDs imported by this mdata */
	spinlock_t          md_lock;    /* protects md_mr_tree, md_rmr_tree */
	struct rb_root      md_mr_tree;
	struct rb_root      md_rmr_tree;
	uint32_t            ro_rkey;
	uint32_t            rw_rkey;
};

struct file_data {
	void                 (*free)(const char *callf, uint line, void *ptr);
	atomic_t             count;
	uint8_t              state;
	unsigned int         pasid;
	spinlock_t           io_lock;
	wait_queue_head_t    io_wqh;
	struct list_head     fdata_list;
	struct list_head     rd_list;
	struct mem_data      md;
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

_EXTERN_C_END

#ifdef _EXTERN_C_SET
#undef _EXTERN_C_SET
#undef _EXTERN_C_BEG
#undef _EXTERN_C_END
#endif

#endif /* _WILDCAT_RDMA_H_ */
