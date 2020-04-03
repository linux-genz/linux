/*
 * Copyright (C) 2018-2020 Hewlett Packard Enterprise Development LP.
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

#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/genz.h>

#include "wildcat.h"

uint wildcat_kmsg_timeout;

/* msg_state & msgid's are global */
static struct rb_root msg_rbtree = RB_ROOT;
DEFINE_SPINLOCK(wildcat_msg_rbtree_lock);
static atomic_t msgid = ATOMIC_INIT(0);

static inline ktime_t get_timeout(void)
{
	return ktime_set((wildcat_kmsg_timeout > 0 ? wildcat_kmsg_timeout : 2),
			 0);
}

static inline uint16_t msg_alloc_msgid(void)
{
	return (uint16_t)atomic_inc_return(&msgid);
}

uint16_t wildcat_msg_alloc_msgid(struct enic *enic)
{
	return msg_alloc_msgid();
}

static struct wildcat_msg_state *msg_state_alloc(void)
{
	struct wildcat_msg_state *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (state) {
		init_waitqueue_head(&state->wq);
		INIT_LIST_HEAD(&state->msg_list);
	}
	return state;
}

static struct wildcat_msg_state *msg_state_search(uint16_t msgid)
{
	struct wildcat_msg_state *state;
	struct rb_node           *node;
	struct rb_root           *root = &msg_rbtree;
	ulong                    flags;

	spin_lock_irqsave(&wildcat_msg_rbtree_lock, flags);
	node = root->rb_node;

	while (node) {
		int result;

		state = container_of(node, struct wildcat_msg_state, node);
		result = arithcmp(msgid, state->req_msg.hdr.msgid);
		if (result < 0) {
			node = node->rb_left;
		} else if (result > 0) {
			node = node->rb_right;
		} else {
			goto out;
		}
	}

	state = NULL;

out:
	spin_unlock_irqrestore(&wildcat_msg_rbtree_lock, flags);
	return state;
}

static struct wildcat_msg_state *msg_state_insert(struct wildcat_msg_state *ms)
{
	struct rb_root *root = &msg_rbtree;
	struct rb_node **new = &root->rb_node, *parent = NULL;
	ulong flags;

	spin_lock_irqsave(&wildcat_msg_rbtree_lock, flags);

	/* figure out where to put new node */
	while (*new) {
		struct wildcat_msg_state *this =
			container_of(*new, struct wildcat_msg_state, node);
		int result = arithcmp(ms->req_msg.hdr.msgid,
				      this->req_msg.hdr.msgid);

		parent = *new;
		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {
			ms = this;
			goto out;  /* already there */
		}
	}

	/* add new node and rebalance tree */
	rb_link_node(&ms->node, parent, new);
	rb_insert_color(&ms->node, root);

out:
	spin_unlock_irqrestore(&wildcat_msg_rbtree_lock, flags);
	return ms;
}

static void msg_state_free(struct wildcat_msg_state *ms)
{
	struct rb_root *root = &msg_rbtree;
	ulong flags;

	spin_lock_irqsave(&wildcat_msg_rbtree_lock, flags);
	rb_erase(&ms->node, root);
	spin_unlock_irqrestore(&wildcat_msg_rbtree_lock, flags);
	kfree(ms);
}

static int _msg_xdm_get_cmpl(struct xdm_info *xdmi,
			     struct wildcat_cq_entry *entry)
{
	struct genz_xdm_info *gzxi = xdmi->gzxi;
	int ret = 0;
	uint head, next_head, cmdq_ent, cmpl_index;
	struct wildcat_cq_entry *xdm_entry, *next_entry;
	void *cpu_addr;

	/* caller must hold xdm_info_lock */

	cmdq_ent = gzxi->cmdq_ent;
	head = xdmi->cmplq_head;
	cpu_addr = xdmi->cmplq_zpage->dma.cpu_addr;
	xdm_entry = &(((struct wildcat_cq_entry *)cpu_addr)[head]);

	/* check valid bit */
	if (xdm_entry->valid != xdmi->cur_valid) {
		ret = -EBUSY;
		goto out;
	}
	xdmi->active_cmds--;
	/* copy XDM completion entry to caller */
	*entry = *xdm_entry;
	/* do mod-add to compute next head value */
	next_head = (head + 1) % gzxi->cmplq_ent;
	/* toggle cur_valid on wrap */
	if (next_head < head)
		xdmi->cur_valid = !xdmi->cur_valid;
	/* update cmplq_head - SW-only */
	xdmi->cmplq_head = next_head;
	/* update cmdq_head_shadow if this completion moves it forward */
	cmpl_index = entry->index;
	if (cmpl_index < cmdq_ent) {
		if (((xdmi->cmdq_tail_shadow - cmpl_index) % cmdq_ent) <
		    ((xdmi->cmdq_tail_shadow - xdmi->cmdq_head_shadow) %
		     cmdq_ent))
			xdmi->cmdq_head_shadow = cmpl_index;
	}  /* Revisit: add support for cmd buffers */
	/* peek at next entry to determine if it is valid */
	next_entry = &(((struct wildcat_cq_entry *)cpu_addr)[next_head]);
	ret = (next_entry->valid == xdmi->cur_valid);

out:
	return ret;
}

/* Revisit: no longer msg-specific - move elsewhere */
int wildcat_xdm_get_cmpl(struct xdm_info *xdmi, struct wildcat_cq_entry *entry)
{
	struct genz_xdm_info *gzxi = xdmi->gzxi;
	int ret;
	ulong flags;

	spin_lock_irqsave(&gzxi->xdm_info_lock, flags);
	ret = _msg_xdm_get_cmpl(xdmi, entry);
	spin_unlock_irqrestore(&gzxi->xdm_info_lock, flags);
	return ret;
}

static int _msg_xdm_get_cmpls(struct xdm_info *xdmi)
{
	int ret = 0, cmpl_ret;
	struct wildcat_cq_entry cq_entry;
	bool more = 0;

	/* caller must hold xdm_info_lock */

	do {  /* process completions */
		/* Revisit: cmpls discarded - ok for EnqA but not in general */
		cmpl_ret = _msg_xdm_get_cmpl(xdmi, &cq_entry);
		if (cmpl_ret == -EBUSY) {
			if (more == 0)
				ret = -EBUSY;
			break;
		} else {
			ret++;  /* count of cmpls found */
		}
		/* Revisit: examine status */
		if (cq_entry.status != 0) {
			pr_err("%s: xdm cmpl error, status=0x%x, index=%u\n",
			       __func__, cq_entry.status, cq_entry.index);
		}
		more = cmpl_ret;
	} while (more);

	return ret;
}

/* Revisit: no longer msg-specific - move elsewhere */
int wildcat_xdm_queue_cmd(struct xdm_info *xdmi,
			  union wildcat_hw_wq_entry *cmd, bool discard_cmpls)
{
	struct genz_xdm_info *gzxi = xdmi->gzxi;
	int ret = 0, this_cpu;
	uint head, tail, next_tail;
	union wildcat_hw_wq_entry *xdm_entry;
	void *cpu_addr;
	ulong flags;

	spin_lock_irqsave(&gzxi->xdm_info_lock, flags);
	this_cpu = smp_processor_id();
	/* Revisit: add support for cmd buffers */
	tail = xdmi->cmdq_tail_shadow;
	/* do mod-add to compute next tail value */
	next_tail = (tail + 1) % gzxi->cmdq_ent;
restart_head:
	head = xdmi->cmdq_head_shadow;
	/* Revisit: debug */
	dev_dbg_ratelimited(&gzxi->br->zdev.dev,
			    "spin_lock, head=%u, tail=%u, cpu=%d\n",
			    head, tail, this_cpu);
	if (next_tail == head) {  /* cmdq appears to be full */
		/* our cmdq_head_shadow might be out-of-date - read HW */
		xdmi->cmdq_head_shadow =
			xdm_qcm_read(xdmi->hw_qcm_addr,
				     WILDCAT_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
		if (head != xdmi->cmdq_head_shadow)
			goto restart_head;
		ret = -EBUSY;
	} else if (xdmi->active_cmds + 1 >= gzxi->cmplq_ent) {
		if (discard_cmpls)
			ret = _msg_xdm_get_cmpls(xdmi);
		else
			ret = -EXFULL;
	}
	if (ret < 0) {
		/* Revisit: add to workqueue for later processing */
		goto out;
	}
	cmd->hdr.cmp_index = tail;
	cpu_addr = xdmi->cmdq_zpage->dma.cpu_addr;
	xdm_entry = &(((union wildcat_hw_wq_entry *)cpu_addr)[tail]);
	*xdm_entry = *cmd;
	xdmi->active_cmds++;
	/* update cmdq_tail_shadow & write to HW */
	xdmi->cmdq_tail_shadow = next_tail;
	xdm_qcm_write_val(next_tail, xdmi->hw_qcm_addr,
			  WILDCAT_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
	ret = tail;

out:
	/* Revisit: debug */
	dev_dbg_ratelimited(&gzxi->br->zdev.dev,
			    "spin_unlock, head=%u, next_tail=%u, ret=%d, cpu=%d\n",
			    head, next_tail, ret, this_cpu);
	spin_unlock_irqrestore(&gzxi->xdm_info_lock, flags);
	return ret;
}

static inline int msg_xdm_free_space(uint head, uint tail, uint cmdq_ent)
{
	return cmdq_ent - 1 - ((tail - head) % cmdq_ent);
}

#ifdef XDM_ER
static int msg_xdm_queue_cmds(struct xdm_info *xdmi,
			      union wildcat_hw_wq_entry cmd[], uint cmd_cnt)
{
	int ret = 0;
	uint head, tail, next_tail;
	uint before_cnt, after_cnt, space, x, i = 0;
	uint cmdq_ent = xdmi->cmdq_ent;
	union wildcat_hw_wq_entry *xdm_entry;
	void *cpu_addr;
	ulong flags;

	spin_lock_irqsave(&xdmi->xdm_info_lock, flags);
	if (cmd_cnt == 0 || cmd_cnt > (cmdq_ent - 1)) {
		ret = -EINVAL;
		goto out;
	}
	/* Revisit: add support for cmd buffers? */
	tail = xdmi->cmdq_tail_shadow;
	/* do mod-add to compute next tail value */
	next_tail = (tail + cmd_cnt) % cmdq_ent;
	/* compute before/after wrap counts */
	if (next_tail < tail) {  /* wrap */
		before_cnt = cmdq_ent - tail;
		after_cnt = cmd_cnt - before_cnt;
	} else {  /* no wrap */
		before_cnt = cmd_cnt;
		after_cnt = 0;
	}
restart_head:
	head = xdmi->cmdq_head_shadow;
	space = msg_xdm_free_space(head, tail, cmdq_ent);
	pr_debug("cmd_cnt=%u, tail=%u, next_tail=%u, before_cnt=%u, after_cnt=%u, head=%u, space=%u\n",
		 cmd_cnt, tail, next_tail, before_cnt, after_cnt, head, space);
	if (space < cmd_cnt) {  /* cmdq appears to be full */
		/* our cmdq_head_shadow might be out-of-date - read HW */
		xdmi->cmdq_head_shadow =
			xdm_qcm_read(xdmi->hw_qcm_addr,
				     WILDCAT_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
		if (head != xdmi->cmdq_head_shadow)
			goto restart_head;
		ret = -EBUSY;
	} else if (xdmi->active_cmds + cmd_cnt >= xdmi->cmplq_ent) {
		ret = _msg_xdm_get_cmpls(xdmi);
		if (ret == -EBUSY ||
		    xdmi->active_cmds + cmd_cnt >= xdmi->cmplq_ent)
			ret = -EBUSY;
	}
	if (ret < 0) {
		goto out;
	}
	cpu_addr = xdmi->cmdq_zpage->dma.cpu_addr;
	if (before_cnt) {
		for (i = 0; i < before_cnt; i++) {
			x = tail + i;
			cmd[i].hdr.cmp_index = x;
			xdm_entry = &(((union wildcat_hw_wq_entry *)cpu_addr)[x]);
			*xdm_entry = cmd[i];
		}
		xdmi->active_cmds += before_cnt;
	}
	if (after_cnt) {
		for ( ; i < cmd_cnt; i++) {
			x = i - before_cnt;
			cmd[i].hdr.cmp_index = x;
			xdm_entry = &(((union wildcat_hw_wq_entry *)cpu_addr)[x]);
			*xdm_entry = cmd[i];
		}
		xdmi->active_cmds += after_cnt;
	}
	/* update cmdq_tail_shadow & write to HW */
	xdmi->cmdq_tail_shadow = next_tail;
	xdm_qcm_write_val(next_tail, xdmi->hw_qcm_addr,
			  WILDCAT_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
	ret = tail;

out:
	spin_unlock_irqrestore(&xdmi->xdm_info_lock, flags);
	return ret;
}
#endif

static int msg_rdm_get_cmpl(struct rdm_info *rdmi, struct wildcat_rdm_hdr *hdr,
			    union wildcat_msg *msg)
{
	struct genz_rdm_info *gzri = rdmi->gzri;
	int ret = 0;
	uint head, next_head;
	struct wildcat_rdm_entry *rdm_entry, *next_entry;
	void *cpu_addr;
	ulong flags;

	spin_lock_irqsave(&gzri->rdm_info_lock, flags);
	head = rdmi->cmplq_head_shadow;
	cpu_addr = rdmi->cmplq_zpage->dma.cpu_addr;
	rdm_entry = &(((struct wildcat_rdm_entry *)cpu_addr)[head]);

	/* check valid bit */
	if (rdm_entry->hdr.valid != rdmi->cur_valid) {
		ret = -EBUSY;
		goto out;
	}
	/* copy RDM completion entry to caller */
	*hdr = rdm_entry->hdr;
	memcpy(msg, rdm_entry->payload, sizeof(*msg));
	/* do mod-add to compute next head value */
	next_head = (head + 1) % gzri->cmplq_ent;
	/* toggle cur_valid on wrap */
	if (next_head < head)
		rdmi->cur_valid = !rdmi->cur_valid;
	/* update cmplq_head_shadow & write to HW */
	rdmi->cmplq_head_shadow = next_head;
	rdm_qcm_write_val(next_head, rdmi->hw_qcm_addr,
			  WILDCAT_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);
	/* peek at next entry to determine if it is valid */
	next_entry = &(((struct wildcat_rdm_entry *)cpu_addr)[next_head]);
	ret = (next_entry->hdr.valid == rdmi->cur_valid);

out:
	spin_unlock_irqrestore(&gzri->rdm_info_lock, flags);
	return ret;
}

static inline void msg_setup_req_hdr(union wildcat_msg *msg,
				     uint8_t opcode, uint32_t rspctxid)
{
	msg->hdr.version  = WILDCAT_MSG_VERSION;
	msg->hdr.status   = WILDCAT_MSG_OK;
	msg->hdr.msgid    = msg_alloc_msgid();
	msg->hdr.opcode   = opcode;
	msg->hdr.rspctxid = rspctxid;
}

static inline void msg_setup_req_hdr_msgid(union wildcat_msg *msg,
					   uint8_t opcode, uint32_t rspctxid,
					   uint16_t msgid)
{
	msg->hdr.version  = WILDCAT_MSG_VERSION;
	msg->hdr.status   = WILDCAT_MSG_OK;
	msg->hdr.msgid    = msgid;
	msg->hdr.opcode   = opcode;
	msg->hdr.rspctxid = rspctxid;
}

static inline void msg_setup_rsp_hdr(union wildcat_msg *rsp_msg,
				     union wildcat_msg *req_msg,
				     int8_t status, uint32_t rspctxid)
{
	rsp_msg->hdr.version  = WILDCAT_MSG_VERSION;
	rsp_msg->hdr.status   = status;
	rsp_msg->hdr.msgid    = req_msg->hdr.msgid;
	rsp_msg->hdr.opcode   = req_msg->hdr.opcode | WILDCAT_MSG_RESPONSE;
	rsp_msg->hdr.rspctxid = rspctxid;
}

static inline int msg_send_cmd(struct xdm_info *xdmi,
			       union wildcat_msg *msg,
			       uint32_t dgcid, uint32_t rspctxid)
{
	union wildcat_hw_wq_entry cmd = { 0 };
	size_t size;

	/* fill in cmd */
	cmd.hdr.opcode = WILDCAT_HW_OPCODE_ENQA;
	cmd.enqa.dgcid = dgcid;
	cmd.enqa.rspctxid = rspctxid;
	size = min(sizeof(*msg), sizeof(cmd.enqa.payload));
	memcpy(&cmd.enqa.payload, msg, size);
	/* send cmd */
	return wildcat_xdm_queue_cmd(xdmi, &cmd, true);
}

static int msg_insert_send_cmd(struct xdm_info *xdmi,
			       struct wildcat_msg_state *state,
			       uint32_t dgcid, uint32_t rspctxid)
{
	int                      ret;
	union wildcat_msg        *req_msg;
	struct wildcat_msg_state *found;

	state->dgcid = dgcid;
	state->rspctxid = rspctxid;
	req_msg = &state->req_msg;
	/* add state to msg state rbtree */
	found = msg_state_insert(state);
	if (found != state) {
		ret = -EEXIST;
		goto out;
	}
	/* send cmd */
	ret = msg_send_cmd(xdmi, req_msg, dgcid, rspctxid);

out:
	return ret;
}

static int msg_wait_timeout(struct wildcat_msg_state *state, ktime_t timeout)
{
	int ret;

	pr_debug("waiting for reply to msgid=%u, timeout %lld\n",
		 state->req_msg.hdr.msgid, (unsigned long long)timeout);
	ret = wait_event_hrtimeout(state->wq, state->ready, timeout);
	if (ret < 0) {  /* interrupted or timout expired */
		pr_debug("wait on msgid=%u returned ret=%d\n",
			 state->req_msg.hdr.msgid, ret);
		goto out;
	}

	if (state->rsp_msg.hdr.status != 0) {
		pr_debug("response for msgid=%u returned status=%d\n",
			 state->rsp_msg.hdr.msgid, state->rsp_msg.hdr.status);
		ret = -EINVAL;
	}

out:
	return ret;
}

static int msg_wait(struct wildcat_msg_state *state)
{
	return msg_wait_timeout(state, get_timeout());
}

void wildcat_msg_list_wait(struct list_head *msg_wait_list, ktime_t start)
{
	int                      status = 0;
	ktime_t                  timeout = get_timeout();
	struct wildcat_msg_state *state, *next;
	ktime_t                  now, remaining;

	list_for_each_entry_safe(state, next, msg_wait_list, msg_list) {
		if (status >= 0) {
			now = ktime_sub(ktime_get(), start);
			if (ktime_compare(timeout, now) > 0) {
				remaining = ktime_sub(timeout, now);
				status = msg_wait_timeout(state, remaining);
			} else
				status = -ETIME;
		}
		list_del(&state->msg_list);
		msg_state_free(state);
	}
}

static int msg_insert_send_cmd_wait(struct xdm_info *xdmi,
				    struct wildcat_msg_state *state,
				    uint32_t dgcid, uint32_t rspctxid)
{
	int                     ret;

	ret = msg_insert_send_cmd(xdmi, state, dgcid, rspctxid);
	if (ret < 0)
		goto out;

	ret = msg_wait(state);

out:
	return ret;
}

static int msg_req_NOP(struct rdm_info *rdmi, struct xdm_info *xdmi,
		       struct wildcat_rdm_hdr *req_hdr,
		       union wildcat_msg *req_msg)
{
	struct genz_rdm_info *gzri = rdmi->gzri;
	uint32_t          rspctxid = req_msg->hdr.rspctxid;
	union wildcat_msg rsp_msg = { 0 };
	uint64_t          seq;
	char              str[GCID_STRING_LEN+1];

	seq = req_msg->req.nop.seq;
	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, seq=%llu\n",
		 genz_gcid_str(req_hdr->sgcid, str, sizeof(str)),
		 req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid, seq);
	/* fill in rsp_msg */
	msg_setup_rsp_hdr(&rsp_msg, req_msg, WILDCAT_MSG_OK, gzri->rspctxid);
	rsp_msg.rsp.nop.seq = req_msg->req.nop.seq;
	/* send cmd */
	return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_NOP(struct rdm_info *rdmi, struct wildcat_rdm_hdr *rsp_hdr,
		       union wildcat_msg *rsp_msg)
{
	int ret = 0;
	uint32_t rspctxid = rsp_msg->hdr.rspctxid;
	uint64_t seq;
	char str[GCID_STRING_LEN+1];

	seq = rsp_msg->rsp.nop.seq;
	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, seq=%llu\n",
		 genz_gcid_str(rsp_hdr->sgcid, str, sizeof(str)),
		 rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid, seq);
	return ret;
}

static int msg_req_UUID_IMPORT(struct rdm_info *rdmi, struct xdm_info *xdmi,
			       struct wildcat_rdm_hdr *req_hdr,
			       union wildcat_msg *req_msg)
{
	struct genz_rdm_info   *gzri = rdmi->gzri;
	int                    status = WILDCAT_MSG_OK;
	uint32_t               rspctxid = req_msg->hdr.rspctxid;
	uint32_t               ro_rkey = 0, rw_rkey = 0;
	uuid_t                 *src_uuid = &req_msg->req.uuid_import.src_uuid;
	uuid_t                 *tgt_uuid = &req_msg->req.uuid_import.tgt_uuid;
	struct uuid_tracker    *suu, *tuu;
	struct genz_mem_data   *mdata;
	struct uuid_node       *node;
	union wildcat_msg      rsp_msg = { 0 };
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, src_uuid=%pUb, tgt_uuid=%pUb\n",
		 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
		 req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid,
		 src_uuid, tgt_uuid);
	if (req_hdr->sgcid != wildcat_gcid_from_uuid(src_uuid)) {
		status = WILDCAT_MSG_ERR_UUID_GCID_MISMATCH;
		pr_debug("src_uuid=%pUb GCID mismatch (%s)\n",
			 src_uuid,
			 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)));
		goto respond;
	}
	if (!wildcat_uuid_is_local(gzri->br, tgt_uuid)) {
		status = WILDCAT_MSG_ERR_UUID_NOT_LOCAL;
		pr_debug("tgt_uuid=%pUb not local\n", tgt_uuid);
		goto respond;
	}
	tuu = genz_uuid_search(tgt_uuid);
	if (!tuu) {
		status = WILDCAT_MSG_ERR_NO_UUID;
		pr_debug("tgt_uuid=%pUb not found\n", tgt_uuid);
		goto respond;
	}
	/* we now hold a reference to tuu */
	mdata = tuu->local->mdata;
	suu = genz_uuid_tracker_alloc_and_insert(
		src_uuid, UUID_TYPE_REMOTE, 0, mdata, GFP_KERNEL, &status);
	if (status == -EEXIST) {  /* duplicates ok */
		status = 0;
	} else if (status < 0) {
		status = WILDCAT_MSG_ERR_NO_MEMORY;
		goto tuu_remove;
	}
	/* and we hold a reference to suu */
	node = genz_remote_uuid_alloc_and_insert(
		suu, &mdata->uuid_lock,
		&tuu->local->uu_remote_uuid_tree, GFP_KERNEL, &status);
	if (status < 0) {
		status = (status == -EEXIST) ?
			WILDCAT_MSG_ERR_UUID_ALREADY_THERE :
			WILDCAT_MSG_ERR_NO_MEMORY;
		genz_uuid_remove(suu);
		goto tuu_remove;
	}

	ro_rkey = mdata->ro_rkey;
	rw_rkey = mdata->rw_rkey;

tuu_remove:
	genz_uuid_remove(tuu);

respond:
	/* fill in rsp_msg */
	msg_setup_rsp_hdr(&rsp_msg, req_msg, status, gzri->rspctxid);
	uuid_copy(&rsp_msg.rsp.uuid_import.src_uuid, src_uuid);
	uuid_copy(&rsp_msg.rsp.uuid_import.tgt_uuid, tgt_uuid);
	rsp_msg.rsp.uuid_import.ro_rkey = ro_rkey;
	rsp_msg.rsp.uuid_import.rw_rkey = rw_rkey;
	/* send cmd */
	return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_UUID_IMPORT(struct rdm_info *rdmi,
			       struct wildcat_rdm_hdr *rsp_hdr,
			       union wildcat_msg *rsp_msg)
{
	int                    ret = 0;
	uint32_t               rspctxid = rsp_msg->hdr.rspctxid;
	uuid_t                 *src_uuid = &rsp_msg->rsp.uuid_import.src_uuid;
	uuid_t                 *tgt_uuid = &rsp_msg->rsp.uuid_import.tgt_uuid;
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, src_uuid=%pUb, tgt_uuid=%pUb, ro_rkey=0x%08x, rw_rkey=0x%08x\n",
		 genz_gcid_str(rsp_hdr->sgcid, gcstr, sizeof(gcstr)),
		 rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid,
		 src_uuid, tgt_uuid,
		 rsp_msg->rsp.uuid_import.ro_rkey,
		 rsp_msg->rsp.uuid_import.rw_rkey);

	return ret;
}

static int msg_req_UUID_FREE(struct rdm_info *rdmi, struct xdm_info *xdmi,
			     struct wildcat_rdm_hdr *req_hdr,
			     union wildcat_msg *req_msg)
{
	struct genz_rdm_info   *gzri = rdmi->gzri;
	int                    status = WILDCAT_MSG_OK;
	uint32_t               rspctxid = req_msg->hdr.rspctxid;
	uuid_t                 *src_uuid = &req_msg->req.uuid_free.src_uuid;
	uuid_t                 *tgt_uuid = &req_msg->req.uuid_free.tgt_uuid;
	struct uuid_tracker    *tuu;
	struct genz_mem_data   *mdata;
	union wildcat_msg      rsp_msg = { 0 };
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, src_uuid=%pUb, tgt_uuid=%pUb\n",
		 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
		 req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid,
		 src_uuid, tgt_uuid);
	if (req_hdr->sgcid != wildcat_gcid_from_uuid(src_uuid)) {
		status = WILDCAT_MSG_ERR_UUID_GCID_MISMATCH;
		pr_debug("src_uuid=%pUb GCID mismatch (%s)\n",
		      src_uuid,
		      genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)));
		goto respond;
	}
	if (!wildcat_uuid_is_local(gzri->br, tgt_uuid)) {
		status = WILDCAT_MSG_ERR_UUID_NOT_LOCAL;
		pr_debug("tgt_uuid=%pUb not local\n", tgt_uuid);
		goto respond;
	}
	tuu = genz_uuid_search(tgt_uuid);
	if (!tuu) {
		status = WILDCAT_MSG_ERR_NO_UUID;
		pr_debug("tgt_uuid=%pUb not found\n", tgt_uuid);
		goto respond;
	}
	/* we now hold a reference to tuu */
	mdata = tuu->local->mdata;
	status = genz_free_uuid_node(mdata, &mdata->uuid_lock,
				     &tuu->local->uu_remote_uuid_tree,
				     src_uuid, false);
	if (status < 0) {
		status = WILDCAT_MSG_ERR_NO_UUID;  /* Revisit: unique error? */
		goto tuu_remove;
	}

tuu_remove:
	genz_uuid_remove(tuu);

respond:
	/* fill in rsp_msg */
	msg_setup_rsp_hdr(&rsp_msg, req_msg, status, gzri->rspctxid);
	uuid_copy(&rsp_msg.rsp.uuid_free.src_uuid, src_uuid);
	uuid_copy(&rsp_msg.rsp.uuid_free.tgt_uuid, tgt_uuid);
	/* send cmd */
	return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_UUID_FREE(struct rdm_info *rdmi,
			     struct wildcat_rdm_hdr *rsp_hdr,
			     union wildcat_msg *rsp_msg)
{
	int                    ret = 0;
	uint32_t               rspctxid = rsp_msg->hdr.rspctxid;
	uuid_t                 *src_uuid = &rsp_msg->rsp.uuid_free.src_uuid;
	uuid_t                 *tgt_uuid = &rsp_msg->rsp.uuid_free.tgt_uuid;
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, src_uuid=%pUb, tgt_uuid=%pUb\n",
		 genz_gcid_str(rsp_hdr->sgcid, gcstr, sizeof(gcstr)),
		 rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid,
		 src_uuid, tgt_uuid);

	return ret;
}

static int msg_req_UUID_TEARDOWN(struct rdm_info *rdmi, struct xdm_info *xdmi,
				 struct wildcat_rdm_hdr *req_hdr,
				 union wildcat_msg *req_msg)
{
	struct genz_rdm_info   *gzri = rdmi->gzri;
	int                    status = WILDCAT_MSG_OK;
	uint32_t               rspctxid = req_msg->hdr.rspctxid;
	uuid_t                 *src_uuid = &req_msg->req.uuid_teardown.src_uuid;
	union wildcat_msg      rsp_msg = { 0 };
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, src_uuid=%pUb\n",
		 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
		 req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid,
		 src_uuid);
	if (req_hdr->sgcid != wildcat_gcid_from_uuid(src_uuid)) {
		status = WILDCAT_MSG_ERR_UUID_GCID_MISMATCH;
		pr_debug("src_uuid=%pUb GCID mismatch (%s)\n",
			 src_uuid,
			 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)));
		goto respond;
	}
	status = genz_teardown_remote_uuid(src_uuid);
	if (status < 0)
		status = WILDCAT_MSG_ERR_NO_UUID;

respond:
	/* fill in rsp_msg */
	msg_setup_rsp_hdr(&rsp_msg, req_msg, status, gzri->rspctxid);
	uuid_copy(&rsp_msg.rsp.uuid_teardown.src_uuid, src_uuid);
	/* send cmd */
	return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_UUID_TEARDOWN(struct rdm_info *rdmi,
				 struct wildcat_rdm_hdr *rsp_hdr,
				 union wildcat_msg *rsp_msg)
{
	int                    ret = 0;
	uint32_t               rspctxid = rsp_msg->hdr.rspctxid;
	uuid_t                 *src_uuid = &rsp_msg->rsp.uuid_teardown.src_uuid;
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, src_uuid=%pUb\n",
		 genz_gcid_str(rsp_hdr->sgcid, gcstr, sizeof(gcstr)),
		 rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid,
		 src_uuid);

	return ret;
}

#ifdef ZHPE_ENIC
static int msg_req_ENIC_INFO(struct rdm_info *rdmi, struct xdm_info *xdmi,
			     struct wildcat_rdm_hdr *req_hdr,
			     union wildcat_msg *req_msg)
{
	int                    status = WILDCAT_MSG_OK;
	uint32_t               rspctxid = req_msg->hdr.rspctxid;
	struct bridge          *br = rdmi->br;
	struct enic            *enic = br->enic;
	struct enic_info       *src_info = &req_msg->req.enic_info.src_info;
	uuid_t                 *src_uuid = &src_info->uuid;
	union wildcat_msg         rsp_msg = { 0 };
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, src_uuid=%pUb\n",
		 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
		 req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid,
		 src_uuid);
	if (req_hdr->sgcid != wildcat_gcid_from_uuid(src_uuid)) {
		status = WILDCAT_MSG_ERR_UUID_GCID_MISMATCH;
		pr_debug("src_uuid=%pUb GCID mismatch (%s)\n",
			 src_uuid,
			 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)));
		goto respond;
	}
	if (!enic) {
		status = WILDCAT_MSG_ERR_NO_ENIC_DRIVER;
		pr_debug("src_uuid=%pUb no eNIC driver registered\n",
			 src_uuid);
		goto respond;
	}

	/* import the remote eNIC UUID */
	status = wildcat_kernel_UUID_IMPORT(&enic->md, src_uuid,
					 UUID_IS_ENIC, GFP_KERNEL);
	if (status < 0) {
		/* Revisit: map errors to proper msg status */
		status = WILDCAT_MSG_ERR_NO_UUID;
		goto respond;
	}
	/* call eNIC driver to process eNIC info */
	status = enic->drv->recv_enic_info(br, src_info);
	/* fill in rsp_msg */
	rsp_msg.rsp.enic_info.tgt_info = enic->src_info;

respond:
	/* fill in rsp_msg header */
	msg_setup_rsp_hdr(&rsp_msg, req_msg, status, rdmi->rspctxid);
	/* send cmd */
	return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_ENIC_INFO(struct rdm_info *rdmi,
			     struct wildcat_rdm_hdr *rsp_hdr,
			     union wildcat_msg *rsp_msg)
{
	int                    ret = 0;
	uint32_t               rspctxid = rsp_msg->hdr.rspctxid;
	struct bridge          *br = rdmi->br;
	struct enic            *enic = br->enic;
	struct enic_info       *tgt_info = &rsp_msg->rsp.enic_info.tgt_info;
	uuid_t                 *tgt_uuid = &tgt_info->uuid;
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, tgt_uuid=%pUb, status=%d\n",
		 genz_gcid_str(rsp_hdr->sgcid, gcstr, sizeof(gcstr)),
		 rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid,
		 tgt_uuid, rsp_msg->hdr.status);

	if (rsp_msg->hdr.status < 0) {
		ret = rsp_msg->hdr.status;
		goto out;
	}

	/* import the remote eNIC UUID */
	ret = wildcat_kernel_UUID_IMPORT(&enic->md, tgt_uuid,
					 UUID_IS_ENIC, GFP_KERNEL);
	if (ret < 0)
		goto out;

	/* call eNIC driver to process eNIC info */
	ret = enic->drv->recv_enic_info(br, tgt_info);

out:
	return ret;
}

static int msg_req_ENIC_MRREG(struct rdm_info *rdmi, struct xdm_info *xdmi,
			      struct wildcat_rdm_hdr *req_hdr,
			      union wildcat_msg *req_msg)
{
	int                    status = WILDCAT_MSG_OK;
	uint32_t               rspctxid = req_msg->hdr.rspctxid;
	struct bridge          *br = rdmi->br;
	struct enic            *enic = br->enic;
	struct enic_mrreg      *src_mrreg = &req_msg->req.enic_mrreg.mrreg;
	uuid_t                 *src_uuid = &src_mrreg->uuid;
	union wildcat_msg      rsp_msg = { 0 };
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, src_uuid=%pUb, rsp_zaddr=0x%llx, size=%u, ro_rkey=0x%x\n",
		 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
		 req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid,
		 src_uuid,
		 src_mrreg->rsp_zaddr, src_mrreg->size, src_mrreg->ro_rkey);
	if (req_hdr->sgcid != wildcat_gcid_from_uuid(src_uuid)) {
		status = WILDCAT_MSG_ERR_UUID_GCID_MISMATCH;
		pr_debug("src_uuid=%pUb GCID mismatch (%s)\n",
			 src_uuid,
			 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)));
		goto respond;
	}
	if (!enic) {
		status = WILDCAT_MSG_ERR_NO_ENIC_DRIVER;
		pr_debug("src_uuid=%pUb no eNIC driver registered\n",
			 src_uuid);
		goto respond;
	}

	/* call eNIC driver to process eNIC mrreg and fill in rsp_msg */
	status = enic->drv->recv_enic_mrreg(br, src_mrreg,
					    &rsp_msg.rsp.enic_mrreg.mrreg);

respond:
	/* fill in rsp_msg header */
	msg_setup_rsp_hdr(&rsp_msg, req_msg, status, rdmi->rspctxid);
	/* send cmd */
	return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static int msg_rsp_ENIC_MRREG(struct rdm_info *rdmi,
			      struct wildcat_rdm_hdr *rsp_hdr,
			      union wildcat_msg *rsp_msg)
{
	int                    ret = 0;
	uint32_t               rspctxid = rsp_msg->hdr.rspctxid;
	struct bridge          *br = rdmi->br;
	struct enic            *enic = br->enic;
	struct enic_mrreg      *tgt_mrreg = &rsp_msg->rsp.enic_mrreg.mrreg;
	uuid_t                 *tgt_uuid = &tgt_mrreg->uuid;
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u, tgt_uuid=%pUb, rsp_zaddr=0x%llx, size=%u, ro_rkey=0x%x, status=%d\n",
		 genz_gcid_str(rsp_hdr->sgcid, gcstr, sizeof(gcstr)),
		 rsp_hdr->reqctxid, rspctxid, rsp_msg->hdr.msgid,
		 tgt_uuid,
		 tgt_mrreg->rsp_zaddr, tgt_mrreg->size, tgt_mrreg->ro_rkey,
		 rsp_msg->hdr.status);

	if (rsp_msg->hdr.status < 0) {
		ret = rsp_msg->hdr.status;
		goto out;
	}

	/* call eNIC driver to process eNIC mrreg */
	ret = enic->drv->recv_enic_mrreg(br, tgt_mrreg, NULL);

out:
	return ret;
}
#endif /* ZHPE_ENIC */

static int msg_req_ERROR(struct rdm_info *rdmi, struct xdm_info *xdmi,
			 struct wildcat_rdm_hdr *req_hdr,
			 union wildcat_msg *req_msg, int status)
{
	struct genz_rdm_info   *gzri = rdmi->gzri;
	uint32_t               rspctxid;
	uint                   msgid;
	union wildcat_msg         rsp_msg = { 0 };
	char                   gcstr[GCID_STRING_LEN+1];

	if (status == WILDCAT_MSG_ERR_UNKNOWN_VERSION) {
		rspctxid = gzri->rspctxid;
		msgid    = 0;
	} else {
		rspctxid = req_msg->hdr.rspctxid;
		msgid    = req_msg->hdr.msgid;
	}

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=%u, msgid=%u\n",
		 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
		 req_hdr->reqctxid, rspctxid, msgid);

	/* fill in rsp_msg */
	msg_setup_rsp_hdr(&rsp_msg, req_msg, status, gzri->rspctxid);
	/* send cmd */
	return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

static void msg_work_handler(struct work_struct *w)
{
	struct wildcat_msg_work  *msg_work;
	struct wildcat_rdm_hdr   *msg_hdr;
	union  wildcat_msg       *msg;
	struct wildcat_msg_state *state;
	struct genz_xdm_info  *gzxi;
	struct genz_rdm_info  *gzri;
	struct xdm_info       *xdmi;
	struct rdm_info       *rdmi;
	uint32_t              rspctxid;
	bool                  response;
	uint                  opcode;
	int                   ret;
	char                  sgstr[GCID_STRING_LEN+1];
	char                  dgstr[GCID_STRING_LEN+1];

	msg_work = container_of(w, struct wildcat_msg_work, work);
	gzxi     = &msg_work->br->msg_xdm;
	gzri     = &msg_work->br->msg_rdm;
	xdmi     = (struct xdm_info *)gzxi->br_driver_data;
	rdmi     = (struct rdm_info *)gzri->br_driver_data;
	msg      = &msg_work->msg;
	msg_hdr  = &msg_work->msg_hdr;
	rspctxid = msg->hdr.rspctxid;
	pr_debug("sgcid=%s, reqctxid=%u, version=%u, opcode=0x%x, status=%d, rspctxid=%u\n",
		 genz_gcid_str(msg_hdr->sgcid, sgstr, sizeof(sgstr)),
		 msg_hdr->reqctxid, msg->hdr.version, msg->hdr.opcode,
		 msg->hdr.status, rspctxid);
	/* Revisit: verify that msg came from reqctxid 0? */
	if (msg->hdr.version != WILDCAT_MSG_VERSION) {
		/* if we don't recognize the version, we can't know anything
		 * else about the message (status, opcode, rspctxid), so we
		 * can't do anything
		 */
		pr_debug("UNKNOWN_VERSION\n");
		goto out;
	}
	response = (msg->hdr.opcode & WILDCAT_MSG_RESPONSE) != 0;
	opcode   = msg->hdr.opcode & ~WILDCAT_MSG_RESPONSE;
	if (response) {
		state = msg_state_search(msg->hdr.msgid);
		if (!state) {
			pr_debug("msg_state_search for msgid=%u failed\n",
				 msg->hdr.msgid);
			goto out;
		}
		switch (opcode) {
		case WILDCAT_MSG_NOP:
			ret = msg_rsp_NOP(rdmi, msg_hdr, msg);
			break;
		case WILDCAT_MSG_UUID_IMPORT:
			ret = msg_rsp_UUID_IMPORT(rdmi, msg_hdr, msg);
			break;
		case WILDCAT_MSG_UUID_FREE:
			ret = msg_rsp_UUID_FREE(rdmi, msg_hdr, msg);
			break;
		case WILDCAT_MSG_UUID_TEARDOWN:
			ret = msg_rsp_UUID_TEARDOWN(rdmi, msg_hdr, msg);
			break;
#ifdef ZHPE_ENIC
		case WILDCAT_MSG_ENIC_INFO:
			ret = msg_rsp_ENIC_INFO(rdmi, msg_hdr, msg);
			break;
		case WILDCAT_MSG_ENIC_MRREG:
			ret = msg_rsp_ENIC_MRREG(rdmi, msg_hdr, msg);
			break;
#endif
		default:
			pr_debug("unknown opcode 0x%x for msgid=%u\n",
				 msg->hdr.opcode, msg->hdr.msgid);
			goto out;
		}

		if (msg_hdr->sgcid != state->dgcid) {
			pr_debug("msg SGCID (%s) != state DGCID (%s) for msgid=%u\n",
				 genz_gcid_str(msg_hdr->sgcid, sgstr,
					       sizeof(sgstr)),
				 genz_gcid_str(state->dgcid, dgstr,
					       sizeof(dgstr)),
				 msg->hdr.msgid);
			goto out;
		}
		state->rsp_msg = *msg;  /* Revisit: avoid copy? */
		state->ready = true;
		wake_up(&state->wq);
	} else {  /* request */
		switch (opcode) {
		case WILDCAT_MSG_NOP:
			ret = msg_req_NOP(rdmi, xdmi, msg_hdr, msg);
			break;
		case WILDCAT_MSG_UUID_IMPORT:
			ret = msg_req_UUID_IMPORT(rdmi, xdmi, msg_hdr, msg);
			break;
		case WILDCAT_MSG_UUID_FREE:
			ret = msg_req_UUID_FREE(rdmi, xdmi, msg_hdr, msg);
			break;
		case WILDCAT_MSG_UUID_TEARDOWN:
			ret = msg_req_UUID_TEARDOWN(rdmi, xdmi, msg_hdr, msg);
			break;
#ifdef ZHPE_ENIC
		case WILDCAT_MSG_ENIC_INFO:
			ret = msg_req_ENIC_INFO(rdmi, xdmi, msg_hdr, msg);
			break;
		case WILDCAT_MSG_ENIC_MRREG:
			ret = msg_req_ENIC_MRREG(rdmi, xdmi, msg_hdr, msg);
			break;
#endif
		default:
			ret = msg_req_ERROR(rdmi, xdmi, msg_hdr, msg,
					    WILDCAT_MSG_ERR_UNKNOWN_OPCODE);
			break;
		}
	}

out:
	kfree(msg_work);
}

static irqreturn_t msg_rdm_interrupt_handler(int irq_index, void *data)
{
	struct bridge *br = (struct bridge *)data;
	struct genz_rdm_info *gzri = &br->msg_rdm;
	struct rdm_info *rdmi = (struct rdm_info *)gzri->br_driver_data;
	struct wildcat_msg_work *msg_work;
	int ret;
	bool more;
	uint handled = 0, tail;

	do {
		do {
			/* assume we have work to do - free later if not */
			msg_work = kmalloc(sizeof(*msg_work), GFP_ATOMIC);
			if (!msg_work) {
				pr_debug("msg_work kmalloc failed\n");
				goto out;
			}
			msg_work->br = br;
			ret = msg_rdm_get_cmpl(rdmi, &msg_work->msg_hdr, &msg_work->msg);
			if (ret == -EBUSY) {  /* no cmpl - spurious interrupt */
				pr_debug("spurious, ret=%d\n", ret);
				goto free;
			} else if (ret < 0) {
				pr_debug("unknown error, ret=%d\n", ret);
				goto free;
			}
			more = ret;
			handled++;

			INIT_WORK(&msg_work->work, msg_work_handler);
			queue_work(br->wildcat_msg_workq, &msg_work->work);
		} while (more);
		/* read tail to prevent race with HW writing new completions */
		tail = rdm_qcm_read(
			rdmi->hw_qcm_addr,
			WILDCAT_RDM_QCM_RCV_QUEUE_TAIL_TOGGLE_OFFSET) &
			MAX_HW_RDM_QLEN;
	} while (rdmi->cmplq_head_shadow != tail);

out:
	return IRQ_RETVAL(handled);

free:
	kfree(msg_work);
	goto out;
}

int wildcat_msg_send_UUID_IMPORT(struct bridge *br,
				 uuid_t *src_uuid, uuid_t *tgt_uuid,
				 uint32_t *ro_rkey, uint32_t *rw_rkey)
{
	struct genz_xdm_info    *gzxi = &br->msg_xdm;
	struct xdm_info         *xdmi = (struct xdm_info *)gzxi->br_driver_data;
	struct genz_rdm_info    *gzri = &br->msg_rdm;
	int                     ret = 0;
	uint32_t                dgcid = wildcat_gcid_from_uuid(tgt_uuid);
	uint32_t                rspctxid = gzri->rspctxid;
	struct wildcat_msg_state   *state;
	union wildcat_msg          *req_msg;
	char                    gcstr[GCID_STRING_LEN+1];

	state = msg_state_alloc();
	if (!state) {
		pr_debug("msg_state_alloc failed, "
			 "dgcid=%s, rspctxid=%u, src_uuid=%pUb, tgt_uuid=%pUb\n",
			 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
			 src_uuid, tgt_uuid);
		ret = -ENOMEM;
		goto out;
	}
	/* fill in req_msg */
	req_msg = &state->req_msg;
	msg_setup_req_hdr(req_msg, WILDCAT_MSG_UUID_IMPORT, rspctxid);
	uuid_copy(&req_msg->req.uuid_import.src_uuid, src_uuid);
	uuid_copy(&req_msg->req.uuid_import.tgt_uuid, tgt_uuid);
	pr_debug("dgcid=%s, rspctxid=%u, src_uuid=%pUb, tgt_uuid=%pUb, msgid=%u\n",
	      genz_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
	      src_uuid, tgt_uuid, req_msg->hdr.msgid);
	/* send cmd and wait for reply */
	ret = msg_insert_send_cmd_wait(xdmi, state, dgcid, rspctxid);
	if (ret < 0)
		goto state_free;

	*ro_rkey = state->rsp_msg.rsp.uuid_import.ro_rkey;
	*rw_rkey = state->rsp_msg.rsp.uuid_import.rw_rkey;

state_free:
	msg_state_free(state);
out:
	return ret;
}

struct wildcat_msg_state *wildcat_msg_send_UUID_FREE(
	struct bridge *br, uuid_t *src_uuid, uuid_t *tgt_uuid, bool wait)
{
	struct genz_xdm_info    *gzxi = &br->msg_xdm;
	struct xdm_info         *xdmi = (struct xdm_info *)gzxi->br_driver_data;
	struct genz_rdm_info    *gzri = &br->msg_rdm;
	int                     ret = 0;
	uint32_t                dgcid = wildcat_gcid_from_uuid(tgt_uuid);
	uint32_t                rspctxid = gzri->rspctxid;
	struct wildcat_msg_state   *state;
	union wildcat_msg          *req_msg;
	char                    gcstr[GCID_STRING_LEN+1];

	state = msg_state_alloc();
	if (!state) {
		pr_debug("msg_state_alloc failed, "
			 "dgcid=%s, rspctxid=%u, src_uuid=%pUb, tgt_uuid=%pUb\n",
			 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
			 src_uuid, tgt_uuid);
		ret = -ENOMEM;
		goto out;
	}
	/* fill in req_msg */
	req_msg = &state->req_msg;
	msg_setup_req_hdr(req_msg, WILDCAT_MSG_UUID_FREE, rspctxid);
	uuid_copy(&req_msg->req.uuid_free.src_uuid, src_uuid);
	uuid_copy(&req_msg->req.uuid_free.tgt_uuid, tgt_uuid);
	pr_debug("dgcid=%s, rspctxid=%u, src_uuid=%pUb, tgt_uuid=%pUb, msgid=%u\n",
		 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
		 src_uuid, tgt_uuid, req_msg->hdr.msgid);
	if (wait) {
		/* send cmd and wait for reply */
		ret = msg_insert_send_cmd_wait(xdmi, state, dgcid, rspctxid);
		msg_state_free(state);
		state = NULL;
	} else {
		/* send cmd (no wait) */
		ret = msg_insert_send_cmd(xdmi, state, dgcid, rspctxid);
	}

out:
	if (ret < 0 && state)
		msg_state_free(state);
	return (ret < 0) ? ERR_PTR(ret) : state;
}

struct wildcat_msg_state *wildcat_msg_send_UUID_TEARDOWN(struct bridge *br,
							 uuid_t *src_uuid,
							 uuid_t *tgt_uuid)
{
	struct genz_xdm_info    *gzxi = &br->msg_xdm;
	struct xdm_info         *xdmi = (struct xdm_info *)gzxi->br_driver_data;
	struct genz_rdm_info    *gzri = &br->msg_rdm;
	int                     ret = 0;
	uint32_t                dgcid = wildcat_gcid_from_uuid(tgt_uuid);
	uint32_t                rspctxid = gzri->rspctxid;
	struct wildcat_msg_state   *state;
	union wildcat_msg          *req_msg;
	char                    gcstr[GCID_STRING_LEN+1];

	state = msg_state_alloc();
	if (!state) {
		pr_debug("msg_state_alloc failed, "
			 "dgcid=%s, rspctxid=%u, src_uuid=%pUb, tgt_uuid=%pUb\n",
			 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
			 src_uuid, tgt_uuid);
		ret = -ENOMEM;
		goto out;
	}
	/* fill in req_msg */
	req_msg = &state->req_msg;
	msg_setup_req_hdr(req_msg, WILDCAT_MSG_UUID_TEARDOWN, rspctxid);
	uuid_copy(&req_msg->req.uuid_teardown.src_uuid, src_uuid);
	uuid_copy(&req_msg->req.uuid_teardown.tgt_uuid, tgt_uuid);
	pr_debug("dgcid=%s, rspctxid=%u, src_uuid=%pUb, tgt_uuid=%pUb, msgid=%u\n",
		 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
		 src_uuid, tgt_uuid, req_msg->hdr.msgid);
	/* send cmd (no wait) */
	ret = msg_insert_send_cmd(xdmi, state, dgcid, rspctxid);

out:
	if (ret < 0 && state)
		msg_state_free(state);
	return (ret < 0) ? ERR_PTR(ret) : state;
}

#ifdef ZHPE_ENIC
int wildcat_msg_send_ENIC_INFO(struct enic *enic, uint32_t dgcid)
{
	struct bridge           *br = enic->req_rdmi.br;
	struct xdm_info         *xdmi = &br->msg_xdm;
	struct rdm_info         *rdmi = &br->msg_rdm;
	int                     ret = 0;
	uint32_t                rspctxid = rdmi->rspctxid;
	struct wildcat_msg_state   *state;
	union wildcat_msg          *req_msg;
	uuid_t                  *src_uuid = &enic->src_info.uuid;
	char                    gcstr[GCID_STRING_LEN+1];

	state = msg_state_alloc();
	if (!state) {
		pr_debug("msg_state_alloc failed, "
			 "dgcid=%s, rspctxid=%u, src_uuid=%pUb\n",
			 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid,
			 src_uuid);
		ret = -ENOMEM;
		goto out;
	}
	/* fill in req_msg */
	req_msg = &state->req_msg;
	msg_setup_req_hdr(req_msg, WILDCAT_MSG_ENIC_INFO, rspctxid);
	req_msg->req.enic_info.src_info = enic->src_info;
	pr_debug("dgcid=%s, rspctxid=%u, src_uuid=%pUb, credits=%u, enic_req_ctxid=%u, enic_rsp_ctxid=%u, msgid=%u\n",
		 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)), rspctxid, src_uuid,
		 enic->src_info.credits, enic->src_info.req_ctxid,
		 enic->src_info.rsp_ctxid, req_msg->hdr.msgid);
	/* send cmd */
	ret = msg_insert_send_cmd_wait(xdmi, state, dgcid, rspctxid);
	msg_state_free(state);

out:
	return ret;
}

int wildcat_msg_send_ENIC_MRREG(struct enic *enic, uuid_t *tgt_uuid,
				struct enic_mrreg *mrreg)
{
	struct bridge           *br = enic->req_rdmi.br;
	struct xdm_info         *xdmi = &br->msg_xdm;
	struct rdm_info         *rdmi = &br->msg_rdm;
	int                     ret = 0;
	uint32_t                rspctxid = rdmi->rspctxid;
	uint32_t                dgcid;
	struct wildcat_msg_state *state;
	union wildcat_msg        *req_msg;
	uuid_t                  *src_uuid = &enic->src_info.uuid;
	char                    gcstr[GCID_STRING_LEN+1];

	dgcid = wildcat_gcid_from_uuid(tgt_uuid);
	state = msg_state_alloc();
	if (!state) {
		pr_debug("msg_state_alloc failed, "
			 "dgcid=%s, src_uuid=%pUb, tgt_uuid=%pUb\n",
			 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)),
			 src_uuid, tgt_uuid);
		ret = -ENOMEM;
		goto out;
	}
	/* fill in req_msg */
	req_msg = &state->req_msg;
	msg_setup_req_hdr(req_msg, WILDCAT_MSG_ENIC_MRREG, rspctxid);
	req_msg->req.enic_mrreg.mrreg = *mrreg;
	pr_debug("dgcid=%s, src_uuid=%pUb, tgt_uuid=%pUb, rsp_zaddr=0x%llx, size=%u, ro_rkey=0x%x, msgid=%u\n",
		 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)),
		 src_uuid, tgt_uuid,
		 mrreg->rsp_zaddr, mrreg->size, mrreg->ro_rkey,
		 req_msg->hdr.msgid);
	/* send cmd */
	ret = msg_insert_send_cmd_wait(xdmi, state, dgcid, rspctxid);
	msg_state_free(state);

out:
	return ret;
}

int wildcat_msg_send_ENIC_SEND(struct enic *enic, uuid_t *tgt_uuid,
			       const uint32_t tgt_ctxid,
			       const u8 *data, uint data_len)
{
	struct xdm_info         *xdmi = &enic->xdmi;
	struct rdm_info         *rdmi = &enic->rsp_rdmi;
	int                     ret = 0;
	uint32_t                dgcid;
	uint16_t                msgid;
	union wildcat_msg       req_msg, *req_msg_p;
	uint                    cmd_cnt, i, op, rem_len;
	union wildcat_hw_wq_entry  cmd[3] = { 0 };
	uuid_t                  *src_uuid = &enic->src_info.uuid;
	char                    gcstr[GCID_STRING_LEN+1];

	if (data_len > 3*WILDCAT_MSG_MAX) {
		ret = -EINVAL;
		goto out;
	}
	dgcid = wildcat_gcid_from_uuid(tgt_uuid);
	if (data_len <= WILDCAT_MSG_MAX) {  /* single ENIC_SEND packet */
		/* no state tracking - handled by caller */
		/* fill in req_msg */
		msg_setup_req_hdr(&req_msg, WILDCAT_MSG_ENIC_SEND, rdmi->rspctxid);
		req_msg.hdr.status = data_len;
		memcpy(&req_msg.req.enic_send.data, data, data_len);
		memset(&req_msg.req.enic_send.data[data_len], 0, WILDCAT_MSG_MAX - data_len);
		pr_debug("dgcid=%s, src_uuid=%pUb, tgt_uuid=%pUb, data_len=%u, msgid=0x%x\n",
			 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)),
			 src_uuid, tgt_uuid, data_len, req_msg.hdr.msgid);
		/* send cmd */
		ret = msg_send_cmd(xdmi, &req_msg, dgcid, tgt_ctxid);
	} else {  /* multiple ENIC_SEND* packets */
		cmd_cnt = (data_len + (WILDCAT_MSG_MAX-1)) / WILDCAT_MSG_MAX;
		msgid = wildcat_msg_alloc_msgid(enic);
		rem_len = data_len;
		for (i = 0, op = WILDCAT_MSG_ENIC_SEND1; i < cmd_cnt; i++, op++) {
			cmd[i].hdr.opcode = WILDCAT_HW_OPCODE_ENQA;
			cmd[i].enqa.dgcid = dgcid;
			cmd[i].enqa.rspctxid = tgt_ctxid;
			req_msg_p = (union wildcat_msg *)&cmd[i].enqa.payload;
			msg_setup_req_hdr_msgid(req_msg_p, op, rdmi->rspctxid, msgid);
			req_msg_p->hdr.status = data_len;
			memcpy(req_msg_p->req.enic_send.data,
			       &data[i*WILDCAT_MSG_MAX], min(rem_len, WILDCAT_MSG_MAX));
			rem_len -= WILDCAT_MSG_MAX;
		}
		pr_debug("dgcid=%s, src_uuid=%pUb, tgt_uuid=%pUb, data_len=%u, cmd_cnt=%u, msgid=0x%x\n",
			 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)),
			 src_uuid, tgt_uuid, data_len, cmd_cnt, msgid);
		/* send cmds */
		return msg_xdm_queue_cmds(xdmi, cmd, cmd_cnt);
	}

out:
	return ret;
}

int wildcat_msg_resp_ENIC_ER(struct enic *enic,
			     struct wildcat_rdm_hdr *req_hdr,
			     union wildcat_msg *req_msg, uint32_t credits)
{
	struct xdm_info        *xdmi = &enic->xdmi;
	struct rdm_info        *rdmi = &enic->rsp_rdmi;
	int                    status = WILDCAT_MSG_OK;
	uint32_t               rspctxid = req_msg->hdr.rspctxid;
	union wildcat_msg      rsp_msg = { 0 };
	char                   gcstr[GCID_STRING_LEN+1];

	pr_debug("sgcid=%s, reqctxid=%u, rspctxid=0x%x, msgid=%u, credits=%u\n",
		 genz_gcid_str(req_hdr->sgcid, gcstr, sizeof(gcstr)),
		 req_hdr->reqctxid, rspctxid, req_msg->hdr.msgid, credits);

	/* fill in rsp_msg header */
	msg_setup_rsp_hdr(&rsp_msg, req_msg, status, rdmi->rspctxid);
	rsp_msg.rsp.enic_er.credits = credits;
	/* send cmd */
	return msg_send_cmd(xdmi, &rsp_msg, req_hdr->sgcid, rspctxid);
}

int wildcat_msg_send_ENIC_ER(struct enic *enic, uuid_t *tgt_uuid,
			     const uint32_t tgt_ctxid,
			     struct wildcat_enic_er_hdr *er_hdr,
			     const u8 *data, uint data_len, uint16_t msgid)
{
	struct xdm_info         *xdmi = &enic->xdmi;
	struct rdm_info         *rdmi = &enic->rsp_rdmi;
	int                     ret = 0;
	uint32_t                dgcid;
	union wildcat_msg       req_msg;
	uuid_t                  *src_uuid = &enic->src_info.uuid;
	char                    gcstr[GCID_STRING_LEN+1];

	if (data_len != WILDCAT_ER_MAX) {
		ret = -EINVAL;
		goto out;
	}
	/* no state tracking - handled by caller */
	dgcid = wildcat_gcid_from_uuid(tgt_uuid);
	/* fill in req_msg */
	msg_setup_req_hdr_msgid(&req_msg, WILDCAT_MSG_ENIC_ER, rdmi->rspctxid, msgid);
	req_msg.req.enic_er.enic_er_hdr = *er_hdr;
	memcpy(&req_msg.req.enic_er.data, data, WILDCAT_ER_MAX);
	pr_debug("dgcid=%s, src_uuid=%pUb, tgt_uuid=%pUb, er_tgt_zaddr=0x%llx, er_rd_sz=%u, er_rd_rkey=0x%x, msgid=0x%x\n",
		 genz_gcid_str(dgcid, gcstr, sizeof(gcstr)),
		 src_uuid, tgt_uuid,
		 er_hdr->er_tgt_zaddr, er_hdr->er_rd_sz, er_hdr->er_rd_rkey,
		 req_msg.hdr.msgid);
	/* send cmd */
	ret = msg_send_cmd(xdmi, &req_msg, dgcid, tgt_ctxid);

out:
	return ret;
}

int wildcat_msg_enic_xdm_space(struct enic *enic, uint32_t *cmd, uint32_t *cmpl)
{
	struct xdm_info         *xdmi = &enic->xdmi;
	int                     ret;
	uint                    head, tail;
	ulong                   flags;

	spin_lock_irqsave(&xdmi->xdm_info_lock, flags);
	ret = _msg_xdm_get_cmpls(xdmi);
	if (ret < 0)
		goto unlock;

	/* our cmdq_head_shadow might be out-of-date - read HW */
	xdmi->cmdq_head_shadow =
		xdm_qcm_read(xdmi->hw_qcm_addr,
			     WILDCAT_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
	head = xdmi->cmdq_head_shadow;
	tail = xdmi->cmdq_tail_shadow;
	*cmd = msg_xdm_free_space(head, tail, xdmi->cmdq_ent);
	*cmpl = xdmi->cmplq_ent - xdmi->active_cmds;
	ret = ((8 * *cmd > xdmi->cmdq_ent) && (8 * *cmpl > xdmi->cmplq_ent));

unlock:
	spin_unlock_irqrestore(&xdmi->xdm_info_lock, flags);
	return ret;
}

#ifdef XDM_ER
int wildcat_msg_enic_er_read(struct enic *enic, struct wildcat_rdm_hdr *req_hdr,
			     union wildcat_msg *req_msg, uint64_t from,
			     dma_addr_t dma_addr,
			     uint16_t msgid, uint32_t credits)
{
	struct xdm_info         *xdmi = &enic->xdmi;
	struct rdm_info         *req_rdmi = &enic->req_rdmi;
	struct rdm_info         *rsp_rdmi = &enic->rsp_rdmi;
	struct wildcat_enic_er_hdr *er_hdr = &req_msg->req.enic_er.enic_er_hdr;
	int                     ret = 0;
	int                     status = WILDCAT_MSG_OK;
	union wildcat_msg       *rsp_msg;
	union wildcat_hw_wq_entry cmd[4] = { 0 };
	uint                    rd_len;
	char                    gcstr1[GCID_STRING_LEN+1];
	char                    gcstr2[GCID_STRING_LEN+1];

	rd_len = er_hdr->er_rd_sz;
	if (rd_len <= 0) {  /* Revisit: check > MTU? */
		ret = -EINVAL;
		goto out;
	}

	/* fill in cmd[0] - GET */
	cmd[0].hdr.opcode = WILDCAT_HW_OPCODE_GET;
	cmd[0].dma.len = rd_len;
	cmd[0].dma.rd_addr = from;
	cmd[0].dma.wr_addr = dma_addr;
	/* fill in cmd[1] - ENQA to peer */
	cmd[1].hdr.opcode = WILDCAT_HW_OPCODE_ENQA|WILDCAT_HW_OPCODE_FENCE;
	cmd[1].enqa.dgcid = req_hdr->sgcid;
	cmd[1].enqa.rspctxid = req_msg->hdr.rspctxid;
	/* fill in rsp_msg header */
	rsp_msg = (union wildcat_msg *)&cmd[1].enqa.payload;
	msg_setup_rsp_hdr(rsp_msg, req_msg, status, rsp_rdmi->rspctxid);
	rsp_msg->rsp.enic_er.credits = credits;
	/* fill in cmd[2] - SYNC */
	cmd[2].hdr.opcode = WILDCAT_HW_OPCODE_SYNC|WILDCAT_HW_OPCODE_FENCE;
	/* fill in cmd[3] - ENQA to ourselves to signal completion */
	cmd[3].hdr.opcode = WILDCAT_HW_OPCODE_ENQA|WILDCAT_HW_OPCODE_FENCE;
	cmd[3].enqa.dgcid = req_rdmi->br->gcid;
	cmd[3].enqa.rspctxid = req_rdmi->rspctxid;
	/* fill in rsp_msg */
	rsp_msg = (union wildcat_msg *)&cmd[3].enqa.payload;
	msg_setup_req_hdr_msgid(rsp_msg, WILDCAT_MSG_ENIC_ER_CMPL,
				rsp_rdmi->rspctxid, msgid);
	pr_debug("src_dgcid=%s, src_rspctxid=%u, rd_addr=0x%llx, wr_addr=0x%llx, rd_len=%u, our_gcid=%s, our_rspctxid=%u, our_msgid=0x%x, credits=%u, msgid=0x%x\n",
		 genz_gcid_str(req_hdr->sgcid, gcstr1, sizeof(gcstr1)),
		 req_msg->hdr.rspctxid, cmd[0].dma.rd_addr, cmd[0].dma.wr_addr,
		 rd_len,
		 genz_gcid_str(req_rdmi->br->gcid, gcstr2, sizeof(gcstr2)),
		 req_rdmi->rspctxid, msgid, credits, req_msg->hdr.msgid);
	/* send cmds */
	return msg_xdm_queue_cmds(xdmi, cmd, 4);

out:
	return ret;
}
#endif

int wildcat_msg_enic_cmpl(struct enic *enic, uint q,
			  struct wildcat_rdm_hdr *hdr, union wildcat_msg *msg)
{
	struct rdm_info *rdmi;

	if (!enic || !hdr || !msg)
		return -EINVAL;

	if (q == ReqMsgRecvInt)
		rdmi = &enic->req_rdmi;
	else /* RspMsgRecvInt */
		rdmi = &enic->rsp_rdmi;

	return msg_rdm_get_cmpl(rdmi, hdr, msg);
}

bool wildcat_msg_enic_more(struct enic *enic, uint q)
{
	uint tail;
	struct rdm_info *rdmi;

	if (q == ReqMsgRecvInt)
		rdmi = &enic->req_rdmi;
	else /* RspMsgRecvInt */
		rdmi = &enic->rsp_rdmi;

	/* read tail to prevent race with HW writing new completions */
	tail = rdm_qcm_read(rdmi->hw_qcm_addr,
			    WILDCAT_RDM_QCM_RCV_QUEUE_TAIL_TOGGLE_OFFSET) &
		MAX_HW_RDM_QLEN;
	return (rdmi->cmplq_head_shadow != tail);
}
#endif /* ZHPE_ENIC */

int wildcat_msg_qalloc(struct genz_bridge_dev *gzbr)
{
	int                   ret = 0;
	struct bridge         *br = wildcat_gzbr_to_br(gzbr);
	struct genz_xdm_info  *gzxi = &br->msg_xdm;
	struct genz_rdm_info  *gzri = &br->msg_rdm;
	struct xdm_info       *xdmi;
	struct rdm_info       *rdmi;

	/* Set up the XDM info structure */
	gzxi->cmdq_ent = 64;
	gzxi->cmplq_ent = 64;
	gzxi->traffic_class = GENZ_TC_0;
	gzxi->priority = 0;

	/* Set up the RDM info structure */
	gzri->cmplq_ent = 128;
	gzri->br_driver_flags = SLICE_DEMAND|0x1;  /* slice 0 only */

	ret = genz_alloc_queues(gzbr, gzxi, gzri);
	if (ret < 0)
		goto done;
	if (gzri->rspctxid != 0) { /* must be 0 for driver-driver msg RDM */
		ret = -EBUSY;
		goto qfree;
	}

	xdmi = (struct xdm_info *)gzxi->br_driver_data;
	rdmi = (struct rdm_info *)gzri->br_driver_data;
	ret = wildcat_register_rdm_interrupt(rdmi->sl, rdmi->queue,
					     msg_rdm_interrupt_handler, br);
	if (ret < 0)
		goto qfree;

	return 0;

qfree:
	genz_free_queues(gzxi, gzri);
done:
	return ret;
}

int wildcat_msg_qfree(struct genz_bridge_dev *gzbr)
{
	int                   ret = 0;
	struct bridge         *br = wildcat_gzbr_to_br(gzbr);
	struct genz_xdm_info  *gzxi = &br->msg_xdm;
	struct genz_rdm_info  *gzri = &br->msg_rdm;
	struct rdm_info       *rdmi = (struct rdm_info *)gzri->br_driver_data;

	wildcat_unregister_rdm_interrupt(rdmi->sl, rdmi->queue);
	ret = genz_free_queues(gzxi, gzri);

	return ret;
}
