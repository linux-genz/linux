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

#ifndef _WILDCAT_UAPI_H_
#define _WILDCAT_UAPI_H_

#ifndef __KERNEL__

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#endif

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

#define WILDCAT_IMM_MAX            (32)
#define WILDCAT_ENQA_MAX           (52)

/* Revisit: get rid of these WILDCAT versions */
#define WILDCAT_MR_GET            GENZ_MR_GET
#define WILDCAT_MR_PUT            GENZ_MR_PUT
#define WILDCAT_MR_SEND           WILDCAT_MR_PUT
#define WILDCAT_MR_RECV           WILDCAT_MR_GET
#define WILDCAT_MR_GET_REMOTE     GENZ_MR_GET_REMOTE
#define WILDCAT_MR_PUT_REMOTE     GENZ_MR_PUT_REMOTE
#define WILDCAT_MR_FLAG0          GENZ_MR_FLAG0 /* Usable by user-space */
#define WILDCAT_MR_FLAG1          GENZ_MR_FLAG1
#define WILDCAT_MR_FLAG2          GENZ_MR_FLAG2
#define WILDCAT_MR_FLAG3          GENZ_MR_FLAG3
#define WILDCAT_MR_REQ            GENZ_MR_REQ
#define WILDCAT_MR_RSP            GENZ_MR_RSP
#define WILDCAT_MR_REQ_CPU        GENZ_MR_REQ_CPU
#define WILDCAT_MR_REQ_CPU_CACHE  GENZ_MR_REQ_CPU_CACHE
#define WILDCAT_MR_REQ_CPU_WB     GENZ_MR_REQ_CPU_WB
#define WILDCAT_MR_REQ_CPU_WC     GENZ_MR_REQ_CPU_WC
#define WILDCAT_MR_REQ_CPU_WT     GENZ_MR_REQ_CPU_WT
#define WILDCAT_MR_REQ_CPU_UC     GENZ_MR_REQ_CPU_UC
#define WILDCAT_MR_INDIVIDUAL     GENZ_MR_INDIVIDUAL  /* individual rsp ZMMU */
#define WILDCAT_MR_INDIV_RKEYS    GENZ_MR_INDIV_RKEYS /* per mrreg rkeys */

enum wildcat_hw_atomic {
	WILDCAT_HW_ATOMIC_RETURN       = 0x01,
	WILDCAT_HW_ATOMIC_SIZE_32      = 0x02,
	WILDCAT_HW_ATOMIC_SIZE_64      = 0x04,
	WILDCAT_HW_ATOMIC_SIZE_MASK    = 0x0E,
};

union wildcat_atomic {
	int32_t             s32;
	int64_t             s64;
	uint32_t            u32;
	uint64_t            u64;
};

enum wildcat_hw_cq {
	WILDCAT_HW_CQ_STATUS_SUCCESS               = 0x00,
	WILDCAT_HW_CQ_STATUS_CMD_TRUNCATED         = 0x01,
	WILDCAT_HW_CQ_STATUS_BAD_CMD               = 0x02,
	WILDCAT_HW_CQ_STATUS_LOCAL_UNRECOVERABLE   = 0x11,
	WILDCAT_HW_CQ_STATUS_FABRIC_UNRECOVERABLE  = 0x21,
	WILDCAT_HW_CQ_STATUS_FABRIC_NO_RESOURCES   = 0x22,
	WILDCAT_HW_CQ_STATUS_FABRIC_ACCESS         = 0x23,

	WILDCAT_HW_CQ_VALID                        = 0x01,
};

struct wildcat_result {
	char                data[WILDCAT_IMM_MAX];
};

struct wildcat_cq_entry {
	uint8_t                valid : 1;
	uint8_t                rv1   : 4;
	uint8_t                qd    : 3;  /* EnqA only */
	uint8_t                status;
	uint16_t               index;
	uint8_t                filler1[4];
	void                   *context;
	uint8_t                filler2[16];
	struct wildcat_result  result;
};

#define WILDCAT_HW_ENTRY_LEN (64)

enum wildcat_hw_opcode {
	WILDCAT_HW_OPCODE_NOP          = 0x0,
	WILDCAT_HW_OPCODE_ENQA         = 0x1,
	WILDCAT_HW_OPCODE_PUT          = 0x2,
	WILDCAT_HW_OPCODE_GET          = 0x3,
	WILDCAT_HW_OPCODE_PUTIMM       = 0x4,
	WILDCAT_HW_OPCODE_GETIMM       = 0x5,
	WILDCAT_HW_OPCODE_SYNC         = 0x1f,
	WILDCAT_HW_OPCODE_ATM_SWAP     = 0x20,
	WILDCAT_HW_OPCODE_ATM_ADD      = 0x22,
	WILDCAT_HW_OPCODE_ATM_AND      = 0x24,
	WILDCAT_HW_OPCODE_ATM_OR       = 0x25,
	WILDCAT_HW_OPCODE_ATM_XOR      = 0x26,
	WILDCAT_HW_OPCODE_ATM_SMIN     = 0x28,
	WILDCAT_HW_OPCODE_ATM_SMAX     = 0x29,
	WILDCAT_HW_OPCODE_ATM_UMIN     = 0x2a,
	WILDCAT_HW_OPCODE_ATM_UMAX     = 0x2b,
	WILDCAT_HW_OPCODE_ATM_CAS      = 0x2c,
	WILDCAT_HW_OPCODE_FENCE        = 0x100,
};

struct wildcat_hw_wq_hdr {
	uint16_t            opcode;
	uint16_t            cmp_index;
};

struct wildcat_hw_wq_nop {
	struct wildcat_hw_wq_hdr hdr;
};

struct wildcat_hw_wq_dma {
	struct wildcat_hw_wq_hdr hdr;
	uint32_t                 len;
	uint64_t                 rd_addr;
	uint64_t                 wr_addr;
	void                     *driver_data;
};

struct wildcat_hw_wq_imm {
	struct wildcat_hw_wq_hdr hdr;
	uint32_t                 len;
	uint64_t                 rem_addr;
	uint8_t                  filler[16];
	uint8_t                  data[WILDCAT_IMM_MAX];
};

struct wildcat_hw_wq_atomic {
	struct wildcat_hw_wq_hdr hdr;
	uint8_t                  size;
	uint8_t                  filler1[3];
	uint64_t                 rem_addr;
	uint8_t                  filler2[16];
	union wildcat_atomic     operands[2];
};

struct wildcat_hw_wq_enqa {
	struct wildcat_hw_wq_hdr hdr;
	uint32_t                 rv1      :  4;
	uint32_t                 dgcid    : 28;
	uint32_t                 rspctxid : 24;
	uint32_t                 rv2      :  8;
	uint8_t                  payload[WILDCAT_ENQA_MAX];
};

union wildcat_hw_wq_entry {
	struct wildcat_hw_wq_hdr    hdr;
	struct wildcat_hw_wq_nop    nop;
	struct wildcat_hw_wq_dma    dma;
	struct wildcat_hw_wq_imm    imm;
	struct wildcat_hw_wq_atomic atm;
	struct wildcat_hw_wq_enqa   enqa;
	uint8_t                     filler[WILDCAT_HW_ENTRY_LEN];
};

union wildcat_hw_cq_entry {
	struct wildcat_cq_entry entry;
	uint8_t                 filler[WILDCAT_HW_ENTRY_LEN];
};

struct wildcat_rdm_hdr {
	uint64_t            valid     :  1;
	uint64_t            rv1       :  3;
	uint64_t            sgcid     : 28;
	uint64_t            reqctxid  : 24;
	uint64_t            rv2       :  8;
};

struct wildcat_rdm_entry {
	struct wildcat_rdm_hdr hdr;
	uint8_t                filler1[4];
	uint8_t                payload[WILDCAT_ENQA_MAX];
};

union wildcat_hw_rdm_entry {
	struct wildcat_rdm_entry entry;
	uint8_t                  filler[WILDCAT_HW_ENTRY_LEN];
};

enum wildcat_backend {
	WILDCAT_BACKEND_WILDCAT = 1,
	WILDCAT_BACKEND_LIBFABRIC,
	WILDCAT_BACKEND_MAX,
};

struct wildcat_attr {
	enum wildcat_backend backend;
	uint32_t             max_tx_queues;
	uint32_t             max_rx_queues;
	uint32_t             max_hw_qlen;
	uint32_t             max_sw_qlen;
	uint64_t             max_dma_len;
};

struct wildcat_key_data {
	uint64_t            vaddr;
	uint64_t            zaddr;
	uint64_t            len;
	uint64_t            key;
	uint8_t             access;
};

_EXTERN_C_END

#ifdef _EXTERN_C_SET
#undef _EXTERN_C_SET
#undef _EXTERN_C_BEG
#undef _EXTERN_C_END
#endif

#endif /* _WILDCAT_UAPI_H_ */
