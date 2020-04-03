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

#include <linux/genz.h>
#include "wildcat.h"

void wildcat_generate_uuid(struct genz_bridge_dev *gzbr, uuid_t *uuid)
{
	uint32_t cid = genz_dev_gcid(&gzbr->zdev, 0);

	uuid_gen(uuid);
	/* insert local bridge 28-bit Global CID */
	uuid->b[0] = (cid >> 20) & 0xff;
	uuid->b[1] = (cid >> 12) & 0xff;
	uuid->b[2] = (cid >>  4) & 0xff;
	uuid->b[3] = ((cid & 0x0f) << 4) | (uuid->b[3] & 0x0f);
}

uint32_t wildcat_gcid_from_uuid(const uuid_t *uuid)
{
	return (uuid->b[0] << 20) | (uuid->b[1] << 12) |
		(uuid->b[2] <<  4) | (uuid->b[3] >> 4);
}
EXPORT_SYMBOL(wildcat_gcid_from_uuid);

void wildcat_notify_remote_uuids(struct genz_mem_data *mdata)
{
	struct rb_node           *rb;
	struct uuid_node         *node;
	struct uuid_tracker      *uu;
	struct wildcat_msg_state *state;
	int                      status;
	struct list_head         free_msg_list, teardown_msg_list;
	ktime_t                  start;
	uint32_t                 prev_gcid, gcid;
	struct bridge            *br = wildcat_gzbr_to_br(mdata->bridge);
	ulong                    flags;

	/* caller must hold no spinlocks (we are going to sleep) */
	INIT_LIST_HEAD(&free_msg_list);
	INIT_LIST_HEAD(&teardown_msg_list);

	start = ktime_get();

	/* special case for loopback UUIDs */
	spin_lock_irqsave(&mdata->uuid_lock, flags);
	for (rb = rb_first(&mdata->md_remote_uuid_tree); rb; rb = rb_next(rb)) {
		node = container_of(rb, struct uuid_node, node);
		uu = node->tracker;
		if (uu->local && uu->remote) {  /* loopback UUID */
			pr_debug("TEARDOWN loopback uuid=%pUb\n", &uu->uuid);
			state = wildcat_msg_send_UUID_TEARDOWN(
				br, &uu->uuid, &mdata->local_uuid->uuid);
			if (IS_ERR(state)) {
				status = PTR_ERR(state);
				pr_debug("wildcat_msg_send_UUID_TEARDOWN status=%d\n",
					 status);
				continue;
			}
			list_add_tail(&state->msg_list, &teardown_msg_list);
		}
	}
	spin_unlock_irqrestore(&mdata->uuid_lock, flags);

	if (genz_uu_remote_uuid_empty(mdata)) {
		pr_debug("no remote UUIDs to TEARDOWN\n");
		goto teardown_done;
	}

	spin_lock_irqsave(&mdata->uuid_lock, flags);
	prev_gcid = -1u;
	for (rb = rb_first(&mdata->local_uuid->local->uu_remote_uuid_tree); rb;
	     rb = rb_next(rb)) {
		node = container_of(rb, struct uuid_node, node);
		uu = node->tracker;
		gcid = wildcat_gcid_from_uuid(&uu->uuid);
		if (gcid == prev_gcid)  /* skip send if GCID same as previous */
			continue;
		prev_gcid = gcid;
		pr_debug("TEARDOWN uuid=%pUb\n", &uu->uuid);
		state = wildcat_msg_send_UUID_TEARDOWN(
			br, &mdata->local_uuid->uuid, &uu->uuid);
		if (IS_ERR(state)) {
			status = PTR_ERR(state);
			pr_debug("wildcat_msg_send_UUID_TEARDOWN status=%d\n",
				 status);
			continue;
		}
		list_add_tail(&state->msg_list, &teardown_msg_list);
	}
	spin_unlock_irqrestore(&mdata->uuid_lock, flags);

teardown_done:
	/* wait for replies to all TEARDOWN messages - may sleep */
	wildcat_msg_list_wait(&teardown_msg_list, start);

	spin_lock_irqsave(&mdata->uuid_lock, flags);
	for (rb = rb_first(&mdata->md_remote_uuid_tree); rb; rb = rb_next(rb)) {
		node = container_of(rb, struct uuid_node, node);
		uu = node->tracker;
		if (uu->remote->uu_flags & UUID_IS_FAM) { /* skip send if this is FAM */
			pr_debug("IS_FAM skipping FREE uuid=%pUb\n", &uu->uuid);
			continue;
		}
		pr_debug("FREE uuid=%pUb\n", &uu->uuid);
		state = wildcat_msg_send_UUID_FREE(
			br, &mdata->local_uuid->uuid, &uu->uuid,
			false);
		if (IS_ERR(state)) {
			status = PTR_ERR(state);
			pr_debug("wildcat_msg_send_UUID_FREE status=%d\n",
				 status);
			continue;
		}
		list_add_tail(&state->msg_list, &free_msg_list);
	}
	spin_unlock_irqrestore(&mdata->uuid_lock, flags);

	/* wait for replies to all the FREE messages - may sleep */
	wildcat_msg_list_wait(&free_msg_list, start);
}
EXPORT_SYMBOL(wildcat_notify_remote_uuids);

/* Revisit: most of this is not wildcat-specific */
int wildcat_common_UUID_IMPORT(struct genz_mem_data *mdata, uuid_t *uuid,
			       bool loopback, uint32_t uu_flags,
			       gfp_t alloc_flags)
{
	struct uuid_tracker     *uu;
	int                     status = 0;
	uint                    type = UUID_TYPE_REMOTE;
	struct uuid_node        *md_node, *uu_node;
	uint32_t                ro_rkey, rw_rkey;
	struct bridge           *br = wildcat_gzbr_to_br(mdata->bridge);

	if (!br) {
		pr_debug("br is NULL!\n");
		status = -EINVAL;
		goto out;
	}
	if (wildcat_uuid_is_local(mdata->bridge, uuid)) {
		if (loopback) {
			type = UUID_TYPE_LOOPBACK;
		} else {  /* only remote UUIDs can be imported */
			status = -EINVAL;
			goto out;
		}
	}
	uu = genz_uuid_tracker_alloc_and_insert(uuid, type, uu_flags,
						mdata, alloc_flags, &status);
	if (status == -EEXIST) {  /* duplicates ok - even expected */
		status = 0;
	} else if (status < 0) {
		goto out;
	}
	/* we now hold a reference to uu */
	/* add uu to mdata->md_remote_uuid_tree */
	md_node = genz_remote_uuid_alloc_and_insert(uu, &mdata->uuid_lock,
						    &mdata->md_remote_uuid_tree,
						    alloc_flags, &status);
	if (status < 0)
		goto err_md_node;

	/* add mdata->local_uuid to uu->remote->local_uuid_tree */
	if (!mdata->local_uuid) {
		status = -EINVAL;
		pr_debug("mdata->local_uuid is NULL!\n");
		goto err_md_node;
	}
	kref_get(&mdata->local_uuid->refcount);
	uu_node = genz_remote_uuid_alloc_and_insert(
		mdata->local_uuid, &uu->remote->local_uuid_lock,
		&uu->remote->local_uuid_tree, alloc_flags, &status);
	if (status < 0)
		goto err_uu_node;

	/* send msg to retrieve R-keys from remote node - this can sleep a while */
	if (!(uu_flags & UUID_IS_FAM) && !(uu_flags & UUID_IS_ENIC)) {
		status = wildcat_msg_send_UUID_IMPORT(
			br, &mdata->local_uuid->uuid, uuid, &ro_rkey, &rw_rkey);
		if (status < 0)
			goto err_msg_send;

		uu->remote->ro_rkey = ro_rkey;
		uu->remote->rw_rkey = rw_rkey;
		smp_wmb();
		uu->remote->rkeys_valid = true;
	}

out:
	return status;

	/* error cases */
err_msg_send:
	genz_free_uuid_node(mdata, &uu->remote->local_uuid_lock,
			    &uu->remote->local_uuid_tree,
			    &mdata->local_uuid->uuid, false);
err_uu_node:
	genz_free_uuid_node(mdata, &mdata->uuid_lock,
			    &mdata->md_remote_uuid_tree, uuid, false);
	genz_uuid_remove(mdata->local_uuid);
	goto out;

err_md_node:
	genz_uuid_remove(uu);
	goto out;
}
EXPORT_SYMBOL(wildcat_common_UUID_IMPORT);

int wildcat_kernel_UUID_IMPORT(struct genz_mem_data *mdata, uuid_t *uuid,
			       uint32_t uu_flags, gfp_t alloc_flags)
{
	int                     status = 0;

	status = wildcat_common_UUID_IMPORT(mdata, uuid, wildcat_loopback,
					    uu_flags, alloc_flags);
	pr_debug("ret = %d uuid = %pUb uu_flags = 0x%x\n",
		 status, uuid, uu_flags);
	return status;
}

int wildcat_common_UUID_FREE(struct genz_mem_data *mdata, uuid_t *uuid,
			     uint32_t *uu_flags, bool *local)
{
	struct uuid_tracker      *uu;
	int                      status = 0;
	struct wildcat_msg_state *state;
	struct bridge            *br = wildcat_gzbr_to_br(mdata->bridge);

	uu = genz_uuid_search(uuid);
	if (!uu) {
		status = -EINVAL;
		goto out;
	}

	/* we now hold an extra reference to uu - release it */
	genz_uuid_remove(uu);
	status = genz_free_local_or_remote_uuid(mdata, uuid, uu, local);
	if (status < 0)
		goto out;

	if (!*local) {
		status = genz_free_uuid_node(
			mdata, &uu->remote->local_uuid_lock,
			&uu->remote->local_uuid_tree,
			&mdata->local_uuid->uuid, false);
		/* send msg to release UUID on remote node - this can sleep a while */
		*uu_flags = uu->remote->uu_flags;
		if (!(*uu_flags & UUID_IS_FAM)) {
			state = wildcat_msg_send_UUID_FREE(
				br, &mdata->local_uuid->uuid, uuid, true);
			if (IS_ERR(state)) {
				status = PTR_ERR(state);
				pr_debug("wildcat_msg_send_UUID_FREE status=%d\n",
					 status);
			}
		}
	}

out:
	return status;
}
EXPORT_SYMBOL(wildcat_common_UUID_FREE);
