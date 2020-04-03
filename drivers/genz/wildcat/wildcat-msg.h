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

#ifndef _WILDCAT_MSG_H_
#define _WILDCAT_MSG_H_

enum {
	WILDCAT_MSG_NOP = 1,
	WILDCAT_MSG_UUID_IMPORT,
	WILDCAT_MSG_UUID_FREE,
	WILDCAT_MSG_UUID_TEARDOWN,
	WILDCAT_MSG_ENIC_INFO,
	WILDCAT_MSG_ENIC_MRREG,
	WILDCAT_MSG_ENIC_SEND,
	WILDCAT_MSG_ENIC_SEND1,
	WILDCAT_MSG_ENIC_SEND2,
	WILDCAT_MSG_ENIC_SEND3,
	WILDCAT_MSG_ENIC_ER,
	WILDCAT_MSG_ENIC_ER_CMPL,
	WILDCAT_MSG_RESPONSE = 0x80,
	WILDCAT_MSG_VERSION = 1,
};

enum {
	/* range limited to -128..127 by int8_t */
	WILDCAT_MSG_OK                      =  0,
	WILDCAT_MSG_ERR_NO_MEMORY           = -1,
	WILDCAT_MSG_ERR_UNKNOWN_VERSION     = -2,
	WILDCAT_MSG_ERR_UNKNOWN_OPCODE      = -3,
	WILDCAT_MSG_ERR_NO_UUID             = -4,
	WILDCAT_MSG_ERR_UUID_NOT_LOCAL      = -5,
	WILDCAT_MSG_ERR_UUID_GCID_MISMATCH  = -6,
	WILDCAT_MSG_ERR_UUID_ALREADY_THERE  = -7,
	WILDCAT_MSG_ERR_NO_ENIC_DRIVER      = -8,
	WILDCAT_MSG_ERR_UNKNOWN_MACADDR     = -9,
};

struct wildcat_msg_hdr {  /* the first 8 bytes of the payload */
	uint8_t             version;
	int8_t              status;
	uint16_t            msgid;
	uint32_t            opcode   :  8;
	uint32_t            rspctxid : 24;
} __attribute__ ((packed));

#define WILDCAT_MSG_MAX  ((uint)(WILDCAT_ENQA_MAX - sizeof(struct wildcat_msg_hdr)))
#define WILDCAT_ER_MAX   (WILDCAT_MSG_MAX - sizeof(struct wildcat_enic_er_hdr))

struct wildcat_msg_req_NOP {
	struct wildcat_msg_hdr  hdr;
	uint64_t                seq;
} __attribute__ ((packed));

struct wildcat_msg_rsp_NOP {
	struct wildcat_msg_hdr  hdr;
	uint64_t                seq;
} __attribute__ ((packed));

struct wildcat_msg_req_UUID_IMPORT {
	struct wildcat_msg_hdr  hdr;
	uuid_t                  src_uuid;
	uuid_t                  tgt_uuid;
} __attribute__ ((packed));

struct wildcat_msg_rsp_UUID_IMPORT {
	struct wildcat_msg_hdr  hdr;
	uuid_t                  src_uuid;  /* Revisit: do we need UUIDs? */
	uuid_t                  tgt_uuid;
	uint32_t                ro_rkey;
	uint32_t                rw_rkey;
} __attribute__ ((packed));

struct wildcat_msg_req_UUID_FREE {
	struct wildcat_msg_hdr  hdr;
	uuid_t                  src_uuid;
	uuid_t                  tgt_uuid;
} __attribute__ ((packed));

struct wildcat_msg_rsp_UUID_FREE {
	struct wildcat_msg_hdr  hdr;
	uuid_t                  src_uuid;  /* Revisit: do we need UUIDs? */
	uuid_t                  tgt_uuid;
} __attribute__ ((packed));

struct wildcat_msg_req_UUID_TEARDOWN {
	struct wildcat_msg_hdr  hdr;
	uuid_t                  src_uuid;
} __attribute__ ((packed));

struct wildcat_msg_rsp_UUID_TEARDOWN {
	struct wildcat_msg_hdr  hdr;
	uuid_t                  src_uuid;  /* Revisit: do we need UUID? */
} __attribute__ ((packed));

struct wildcat_msg_req_ENIC_INFO {  /* send eNIC capabilities */
	struct wildcat_msg_hdr  msg_hdr;
	struct enic_info        src_info;
} __attribute__ ((packed));

struct wildcat_msg_rsp_ENIC_INFO {
	struct wildcat_msg_hdr  msg_hdr;
	struct enic_info        tgt_info;
} __attribute__ ((packed));

struct wildcat_msg_req_ENIC_MRREG {  /* send eNIC memory registration */
	struct wildcat_msg_hdr  msg_hdr;
	struct enic_mrreg       mrreg;
} __attribute__ ((packed));

struct wildcat_msg_rsp_ENIC_MRREG {
	struct wildcat_msg_hdr  msg_hdr;
	struct enic_mrreg       mrreg;
} __attribute__ ((packed));

/* ENIC_SEND* & ENIC_ER* flow over dedicated eNIC channel */
struct wildcat_msg_req_ENIC_SEND {  /* the send request; data_len <= 44 */
	struct wildcat_msg_hdr  msg_hdr;
	uint8_t                 data[WILDCAT_MSG_MAX];  /* len is in msg_hdr.status */
} __attribute__ ((packed));

/* wildcat_msg_rsp_ENIC_SEND reply sent only to replenish credits */
struct wildcat_msg_rsp_ENIC_SEND {
	struct wildcat_msg_hdr  msg_hdr;
	uint32_t                credits;
	u8                      macaddr[ETH_ALEN];
} __attribute__ ((packed));

struct wildcat_enic_er_hdr {  /* the embedded-read hdr */
	uint64_t            er_tgt_zaddr;
	uint32_t            er_rd_sz;
	uint32_t            er_rd_rkey;
} __attribute__ ((packed));

struct wildcat_msg_req_ENIC_ER {  /* the embedded-read request; data_len > 44 */
	struct wildcat_msg_hdr     msg_hdr;
	struct wildcat_enic_er_hdr enic_er_hdr;
	uint8_t                    data[WILDCAT_ER_MAX];  /* all bytes valid */
} __attribute__ ((packed));

struct wildcat_msg_rsp_ENIC_ER {
	struct wildcat_msg_hdr  msg_hdr;
	uint32_t                credits;
} __attribute__ ((packed));

struct wildcat_msg_req_ENIC_ER_CMPL {  /* embedded-read completion to self */
	struct wildcat_msg_hdr  msg_hdr;
} __attribute__ ((packed));

/* There is no wildcat_msg_rsp_ENIC_ER_CMPL */

union wildcat_msg_req {
	struct wildcat_msg_hdr              hdr;
	struct wildcat_msg_req_NOP          nop;
	struct wildcat_msg_req_UUID_IMPORT  uuid_import;
	struct wildcat_msg_req_UUID_FREE    uuid_free;
	struct wildcat_msg_req_UUID_FREE    uuid_teardown;
	struct wildcat_msg_req_ENIC_INFO    enic_info;
	struct wildcat_msg_req_ENIC_MRREG   enic_mrreg;
	struct wildcat_msg_req_ENIC_SEND    enic_send;
	struct wildcat_msg_req_ENIC_ER      enic_er;
	struct wildcat_msg_req_ENIC_ER_CMPL enic_er_cmpl;
};

union wildcat_msg_rsp {
	struct wildcat_msg_hdr             hdr;
	struct wildcat_msg_rsp_NOP         nop;
	struct wildcat_msg_rsp_UUID_IMPORT uuid_import;
	struct wildcat_msg_rsp_UUID_FREE   uuid_free;
	struct wildcat_msg_rsp_UUID_FREE   uuid_teardown;
	struct wildcat_msg_rsp_ENIC_INFO   enic_info;
	struct wildcat_msg_rsp_ENIC_MRREG  enic_mrreg;
	struct wildcat_msg_rsp_ENIC_SEND   enic_send;
	struct wildcat_msg_rsp_ENIC_ER     enic_er;
};

union wildcat_msg {
	struct wildcat_msg_hdr             hdr;
	union wildcat_msg_req              req;
	union wildcat_msg_rsp              rsp;
};

struct wildcat_msg_state {
	uint32_t               dgcid;
	uint32_t               rspctxid;
	union wildcat_msg      req_msg;
	union wildcat_msg      rsp_msg;
	bool                   ready;
	wait_queue_head_t      wq;
	struct rb_node         node;
	struct list_head       msg_list;
};

struct wildcat_msg_work {
	struct bridge          *br;
	struct wildcat_rdm_hdr msg_hdr;
	union wildcat_msg      msg;
	struct work_struct     work;
};

extern uint wildcat_kmsg_timeout;

/* Function Prototypes */
void wildcat_msg_list_wait(struct list_head *msg_wait_list, ktime_t start);
int wildcat_xdm_get_cmpl(struct xdm_info *xdmi, struct wildcat_cq_entry *entry);
int wildcat_xdm_queue_cmd(struct xdm_info *xdmi,
			  union wildcat_hw_wq_entry *cmd, bool discard_cmpls);
int wildcat_msg_send_UUID_IMPORT(struct bridge *br,
				 uuid_t *src_uuid, uuid_t *tgt_uuid,
				 uint32_t *ro_rkey, uint32_t *rw_rkey);
struct wildcat_msg_state *wildcat_msg_send_UUID_FREE(
	struct bridge *br, uuid_t *src_uuid, uuid_t *tgt_uuid, bool wait);
struct wildcat_msg_state *wildcat_msg_send_UUID_TEARDOWN(
	struct bridge *br, uuid_t *src_uuid, uuid_t *tgt_uuid);
uint16_t wildcat_msg_alloc_msgid(struct enic *enic);
int wildcat_msg_send_ENIC_INFO(struct enic *enic, uint32_t dgcid);
int wildcat_msg_send_ENIC_MRREG(struct enic *enic, uuid_t *tgt_uuid,
				struct enic_mrreg *mrreg);
int wildcat_msg_send_ENIC_SEND(struct enic *enic, uuid_t *tgt_uuid,
			       const uint32_t tgt_ctxid,
			       const u8 *data, uint data_len);
int wildcat_msg_send_ENIC_ER(struct enic *enic, uuid_t *tgt_uuid,
			     const uint32_t tgt_ctxid,
			     struct wildcat_enic_er_hdr *er_hdr,
			     const u8 *data, uint data_len, uint16_t msgid);
int wildcat_msg_resp_ENIC_ER(struct enic *enic,
			     struct wildcat_rdm_hdr *req_hdr,
			     union wildcat_msg *req_msg, uint32_t credits);
int wildcat_msg_enic_xdm_space(struct enic *enic, uint32_t *cmd,
			       uint32_t *cmpl);
int wildcat_msg_enic_er_read(struct enic *enic, struct wildcat_rdm_hdr *req_hdr,
			     union wildcat_msg *req_msg, uint64_t from,
			     dma_addr_t dma_addr, uint16_t msgid,
			     uint32_t credits);
int wildcat_msg_enic_cmpl(struct enic *enic, uint q,
			  struct wildcat_rdm_hdr *hdr, union wildcat_msg *msg);
bool wildcat_msg_enic_more(struct enic *enic, uint q);
int wildcat_msg_qalloc(struct genz_bridge_dev *gzbr);
int wildcat_msg_qfree(struct genz_bridge_dev *gzbr);

#endif /* _WILDCAT_MSG_H_ */
