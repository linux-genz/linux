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

#ifndef _WILDCAT_QUEUE_H_
#define _WILDCAT_QUEUE_H_

#include <linux/bitmap.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/pci.h>

/* Revisit: this is ugly - also defined in wildcat-uapi.h */
#ifndef WILDCAT_HW_ENTRY_LEN
#define WILDCAT_HW_ENTRY_LEN (64)
#endif

/* Hardware limits */
#define MAX_TX_QUEUES      1024
#define MAX_RX_QUEUES      1024
#define MAX_SW_XDM_QLEN    BIT(16)
#define MAX_HW_XDM_QLEN    (MAX_SW_XDM_QLEN-1)
#define MAX_SW_RDM_QLEN    BIT(20)
#define MAX_HW_RDM_QLEN    (MAX_SW_RDM_QLEN-1)
#define MAX_DMA_LEN        (1U << 31)

#define XDM_CMD_ADDR_OFFSET     0x00
#define XDM_CMPL_ADDR_OFFSET    0x10
#define XDM_PASID_OFFSET        0x18
#define XDM_PASID_QVIRT_FLAG    (1ULL << 31)
#define XDM_MASTER_STOP_OFFSET 	0x20
#define XDM_STOP_OFFSET		0x40
#define XDM_A_OFFSET 		0x28
#define XDM_DUMP_08_START       0x10
#define XDM_DUMP_08_END         0x28
#define XDM_DUMP_40_START       0x40
#define XDM_DUMP_40_END         0x100

#define RDM_CMPL_ADDR_OFFSET    0x00
#define RDM_SIZE_OFFSET         0x08
#define RDM_SIZE_QVIRT_FLAG     (1ULL << 63)
#define RDM_MASTER_STOP_OFFSET 	0x10
#define RDM_STOP_OFFSET		0x40
#define RDM_A_OFFSET		0x18
#define RDM_DUMP_08_START       0x08
#define RDM_DUMP_08_END         0x18
#define RDM_DUMP_40_START       0x40
#define RDM_DUMP_40_END         0xC0

/* Defines for the XQALLOC/RQALLOC slice_mask */
#define SLICE_DEMAND 0x80
#define ALL_SLICES   0x0f

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

static inline uint64_t qcm_val(void *qcm, int offset)
{
	return *((uint64_t *)(qcm + offset));
}

static inline uint64_t *qcm_ptr(void *hw_qcm_addr, int offset)
{
	return ((uint64_t *)(hw_qcm_addr + offset));
}

static inline void xdm_qcm_write(struct xdm_qcm_header *qcm,
				 struct wildcat_xdm_qcm *hw_qcm_addr,
				 int offset)
{
	iowrite64(qcm_val(qcm, offset), qcm_ptr(hw_qcm_addr, offset));
}

static inline void xdm_qcm_write_val(uint64_t val,
				     struct wildcat_xdm_qcm *hw_qcm_addr,
				     int offset)
{
	iowrite64(val, qcm_ptr(hw_qcm_addr, offset));
}

static inline uint64_t xdm_qcm_read(struct wildcat_xdm_qcm *hw_qcm_addr,
				    int offset)
{
	return ioread64(qcm_ptr(hw_qcm_addr, offset));
}

static inline void rdm_qcm_write(struct rdm_qcm_header *qcm,
				 struct wildcat_rdm_qcm *hw_qcm_addr,
				 int offset)
{
	iowrite64(qcm_val(qcm, offset), qcm_ptr(hw_qcm_addr, offset));
}

static inline void rdm_qcm_write_val(uint64_t val,
				     struct wildcat_rdm_qcm *hw_qcm_addr,
				     int offset)
{
	iowrite64(val, qcm_ptr(hw_qcm_addr, offset));
}

static inline uint64_t rdm_qcm_read(struct wildcat_rdm_qcm *hw_qcm_addr,
				    int offset)
{
	return ioread64(qcm_ptr(hw_qcm_addr, offset));
}

/* Function Prototypes */
int wildcat_kernel_XQALLOC(struct xdm_info *xdmi);
int wildcat_kernel_RQALLOC(struct rdm_info *rdmi);
int wildcat_kernel_XQFREE(struct xdm_info *xdmi);
int wildcat_kernel_RQFREE(struct rdm_info *rdmi);
void wildcat_xqueue_init(struct slice *sl);
void wildcat_rqueue_init(struct slice *sl);
int wildcat_xqueue_free(struct bridge *br, int slice, int queue);
int wildcat_rqueue_free(struct bridge *br, int slice, int queue);
int wildcat_dma_alloc_zpage(struct slice *sl, size_t q_size,
			    union zpages **ret_zpage);
int wildcat_clear_xdm_qcm(struct wildcat_xdm_qcm *xdm_qcm_base);
int wildcat_clear_rdm_qcm(struct wildcat_rdm_qcm *rdm_qcm_base);
int wildcat_rdm_queue_to_irq(int queue, struct slice *sl);
int wildcat_rdm_queue_to_vector(int queue, struct slice *sl);
void wildcat_debug_xdm_qcm(const char *func, uint line, const void *cqcm);
void wildcat_debug_rdm_qcm(const char *func, uint line, const void *cqcm);
int wildcat_xdm_queue_sizes(uint32_t *cmdq_ent, uint32_t *cmplq_ent,
			    size_t *cmdq_size, size_t *cmplq_size,
			    size_t *qcm_size);
int wildcat_rdm_queue_sizes(uint32_t *cmplq_ent, size_t *cmplq_size,
			    size_t *qcm_size);
int wildcat_alloc_xqueue(struct bridge *br, uint8_t slice_mask,
			 int *slice, int *queue);
int wildcat_alloc_rqueue(struct bridge *br, uint8_t slice_mask,
			 int *slice, int *queue, int *irq_vector);
void wildcat_xdm_qcm_setup(struct wildcat_xdm_qcm *hw_qcm_addr,
			   uint64_t cmdq_dma_addr, uint64_t cmplq_dma_addr,
			   uint cmdq_ent, uint cmplq_ent,
			   int traffic_class, int priority,
			   bool cur_valid, uint pasid);
void wildcat_rdm_qcm_setup(struct wildcat_rdm_qcm *hw_qcm_addr,
			   uint64_t dma_addr, uint cmplq_ent,
			   bool cur_valid, uint pasid);
void wildcat_xdm_release_slice_queue(
	struct bridge *br, int slice, int queue);
void wildcat_rdm_release_slice_queue(
	struct bridge *br, int slice, int queue);
uint32_t wildcat_rspctxid_alloc(int slice, int queue);
int wildcat_alloc_queues(struct genz_bridge_dev *gzbr,
			 struct genz_xdm_info *xdmi,
			 struct genz_rdm_info *rdmi);
int wildcat_free_queues(struct genz_xdm_info *gzxi, struct genz_rdm_info *gzri);
int wildcat_sgl_request(struct genz_dev *zdev, struct genz_sgl_info *sgli);

#endif /* _WILDCAT_QUEUE_H_ */
