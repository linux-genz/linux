// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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

#include <linux/slab.h>

#include "genz.h"
#include "genz-probe.h"
#include "genz-control.h"

static struct rb_root   uuid_rbtree = RB_ROOT;
DEFINE_SPINLOCK(genz_uuid_rbtree_lock);

struct uuid_tracker *genz_uuid_search(uuid_t *uuid)
{
	struct uuid_tracker *uu;
	struct rb_node      *node;
	struct rb_root      *root = &uuid_rbtree;
	ulong               flags;

	spin_lock_irqsave(&genz_uuid_rbtree_lock, flags);
	node = root->rb_node;

	while (node) {
		int result;

		uu = container_of(node, struct uuid_tracker, node);
		result = genz_uuid_cmp(uuid, &uu->uuid);
		if (result < 0) {
			node = node->rb_left;
		} else if (result > 0) {
			node = node->rb_right;
		} else {
			kref_get(&uu->refcount);
			pr_debug("get uuid=%pUb, refcount=%u\n",
				 &uu->uuid,
				 kref_read(&uu->refcount));
			goto out;
		}
	}

	uu = NULL;

 out:
	spin_unlock_irqrestore(&genz_uuid_rbtree_lock, flags);
	return uu;
}
EXPORT_SYMBOL(genz_uuid_search);

static struct uuid_tracker *uuid_insert(struct uuid_tracker *uu)
{
	struct rb_root *root = &uuid_rbtree;
	struct rb_node **new = &root->rb_node, *parent = NULL;
	ulong          flags;

	spin_lock_irqsave(&genz_uuid_rbtree_lock, flags);

	/* figure out where to put new node */
	while (*new) {
		struct uuid_tracker *this =
			container_of(*new, struct uuid_tracker, node);
		int result = genz_uuid_cmp(&uu->uuid, &this->uuid);

		parent = *new;
		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {
			uu = this;
			kref_get(&uu->refcount);
			pr_debug("get uuid=%pUb, refcount=%u\n",
				 &uu->uuid,
				 kref_read(&uu->refcount));
			goto out;  /* already there */
		}
	}

	/* add new node and rebalance tree */
	rb_link_node(&uu->node, parent, new);
	rb_insert_color(&uu->node, root);

 out:
	spin_unlock_irqrestore(&genz_uuid_rbtree_lock, flags);
	return uu;
}

static inline void _uuid_tracker_free(struct uuid_tracker *uu)
{
	if (uu->local)
		kfree(uu->local);
	if (uu->remote)
		kfree(uu->remote);
	if (uu->zbr_list)
		kfree(uu->zbr_list);
	if (uu->fabric)
		kfree(uu->fabric);
	kfree(uu);
}

struct uuid_tracker *genz_uuid_tracker_alloc(uuid_t *uuid,
					     uint type,
					     gfp_t alloc_flags,
					     int *status)
{
	struct uuid_tracker *uu;
	int                 ret = 0;

	uu = kzalloc(sizeof(struct uuid_tracker), alloc_flags);
	if (!uu) {
		ret = -ENOMEM;
		goto done;
	}
	uuid_copy(&uu->uuid, uuid);
	kref_init(&uu->refcount);
	uu->uutype = type;

	if (type & UUID_TYPE_LOCAL) {
		uu->local = kzalloc(sizeof(struct uuid_tracker_local),
				    alloc_flags);
		if (!uu->local) {
			ret = -ENOMEM;
			goto error;
		}
	}

	if (type & UUID_TYPE_REMOTE) {
		uu->remote = kzalloc(sizeof(struct uuid_tracker_remote),
				     alloc_flags);
		if (!uu->remote) {
			ret = -ENOMEM;
			goto error;
		}
	}
	if (type & UUID_TYPE_ZBRIDGE) {
		uu->zbr_list = kzalloc(sizeof(struct list_head),
				     alloc_flags);
		if (!uu->zbr_list) {
			ret = -ENOMEM;
			goto error;
		}
		INIT_LIST_HEAD(uu->zbr_list);
	}
	if (type & UUID_TYPE_FABRIC) {
		uu->fabric = kzalloc(sizeof(struct uuid_tracker_fabric),
				     alloc_flags);
		if (!uu->fabric) {
			ret = -ENOMEM;
			goto error;
		}
	}

 done:
	*status = ret;
	pr_debug("alloc uuid=%pUb, refcount=%u, local=%px, remote=%px, zbr_list=%px, tracker_fabric=%px, ret=%d\n",
		 &uu->uuid,
		 kref_read(&uu->refcount), uu->local, uu->remote,
		 uu->zbr_list, uu->fabric, ret);

	return uu;
 error:
	*status = ret;
	_uuid_tracker_free(uu);
	return NULL;
}

struct uuid_tracker *genz_uuid_tracker_insert(struct uuid_tracker *uu,
					      int *status)
{
	struct uuid_tracker *found;
	int ret = 0;

	found = uuid_insert(uu);
	if (found != uu) {  /* already there */
		ret = -EEXIST;
		/* make sure found has union of found+uu local & remote */
		if (uu->local && !found->local) {
			found->local = uu->local;
			uu->local = NULL;  /* so _uuid_tracker_free won't free it */
		}
		if (uu->remote && !found->remote) {
			found->remote = uu->remote;
			uu->remote = NULL;  /* so _uuid_tracker_free won't free it */
		}
		_uuid_tracker_free(uu);
	}

	*status = ret;
	return found;
}

void genz_uuid_tracker_free(struct kref *ref)
{
	/* caller must already hold genz_uuid_rbtree_lock */
	struct rb_root *root = &uuid_rbtree;
	struct uuid_tracker *uu = container_of(
		ref, struct uuid_tracker, refcount);

	rb_erase(&uu->node, root);
	_uuid_tracker_free(uu);
}

void genz_uuid_remove(struct uuid_tracker *uu)
{
	bool  gone;
	ulong flags;

	spin_lock_irqsave(&genz_uuid_rbtree_lock, flags);
	gone = kref_put(&uu->refcount, genz_uuid_tracker_free);
	if (gone)
		pr_debug("freed uuid=%pUb\n", &uu->uuid);
	else
		pr_debug("removed uuid=%pUb, refcount=%u\n", &uu->uuid,
			 kref_read(&uu->refcount));
	spin_unlock_irqrestore(&genz_uuid_rbtree_lock, flags);
}
EXPORT_SYMBOL(genz_uuid_remove);

static void teardown_local_uuid(struct uuid_tracker *local_uu)
{
	struct rb_node          *rb, *next;
	struct uuid_node        *node;
	struct uuid_tracker     *uu;

	/* caller must already hold uuid_lock */

	pr_debug("uuid=%pUb\n", &local_uu->uuid);

	for (rb = rb_first_postorder(&local_uu->local->uu_remote_uuid_tree);
	     rb; rb = next) {
		node = container_of(rb, struct uuid_node, node);
		uu = node->tracker;
		pr_debug("uu_remote_uuid_tree uuid=%pUb\n", &uu->uuid);
		next = rb_next_postorder(rb);  /* must precede kfree() */
		kfree(node);
		genz_uuid_remove(uu); /* remove local_uuid reference */
	}

	local_uu->local->uu_remote_uuid_tree = RB_ROOT;
}

int genz_free_local_uuid(struct genz_mem_data *mdata, bool teardown)
{
	struct uuid_tracker     *local_uu;
	int                     ret = 0;

	/* caller must already hold uuid_lock */
	local_uu = mdata->local_uuid;
	if (!local_uu) {
		ret = -EINVAL;
		goto out;
	}

	if (teardown) {
		teardown_local_uuid(local_uu);
	} else {
		if (!(genz_umem_empty(mdata) &&
		      genz_remote_uuid_empty(mdata))) {
			ret = -EBUSY;
			goto out;
		}
	}

	genz_rkey_free(mdata->ro_rkey, mdata->rw_rkey);
	genz_uuid_remove(local_uu); /* remove local_uuid reference */
	mdata->local_uuid = NULL;

 out:
	return ret;
}
EXPORT_SYMBOL(genz_free_local_uuid);

static struct uuid_node *uuid_node_search(struct rb_root *root,
					  uuid_t *uuid, bool teardown)
{
	struct uuid_node *unode;
	struct rb_node   *rnode;

	/* caller must already hold the appropriate spinlock for root */
	rnode = root->rb_node;

	while (rnode) {
		int result;

		unode = container_of(rnode, struct uuid_node, node);
		result = genz_uuid_cmp(uuid, &unode->tracker->uuid);
		if (result < 0) {
			rnode = rnode->rb_left;
		} else if (result > 0) {
			rnode = rnode->rb_right;
		} else {
			if (!teardown && unode->tracker->remote &&
			    READ_ONCE(unode->tracker->remote->torndown)) {
				pr_debug("returning NULL because torndown=true, uuid=%pUb\n",
					 uuid);
				goto null;
			}
			goto out;
		}
	}

 null:
	unode = NULL;

 out:
	return unode;
}

struct uuid_node *genz_remote_uuid_get(struct genz_mem_data *mdata,
				       uuid_t *uuid)
{
	struct uuid_node        *unode;
	struct uuid_tracker     *uu;
	ulong                   flags;

	pr_debug("uuid = %pUb\n", uuid);
	spin_lock_irqsave(&mdata->uuid_lock, flags);
	unode = uuid_node_search(&mdata->md_remote_uuid_tree, uuid, false);
	if (unode) {
		uu = unode->tracker;
		kref_get(&uu->refcount);
		pr_debug("get uuid=%pUb, refcount=%u\n",
			 &uu->uuid, kref_read(&uu->refcount));
	}
	spin_unlock_irqrestore(&mdata->uuid_lock, flags);
	pr_debug("unode = %px\n", unode);

	return unode;
}

struct uuid_node *genz_remote_uuid_insert(spinlock_t *lock,
					  struct rb_root *root,
					  struct uuid_node *node)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;
	ulong flags;

	spin_lock_irqsave(lock, flags);

	/* figure out where to put new node */
	while (*new) {
		struct uuid_node *this =
			container_of(*new, struct uuid_node, node);
		int result = genz_uuid_cmp(&node->tracker->uuid,
					   &this->tracker->uuid);

		parent = *new;
		if (result < 0) {
			new = &((*new)->rb_left);
		} else if (result > 0) {
			new = &((*new)->rb_right);
		} else {  /* already there */
			node = this;
			goto out;
		}
	}

	/* add new node and rebalance tree */
	rb_link_node(&node->node, parent, new);
	rb_insert_color(&node->node, root);

 out:
	spin_unlock_irqrestore(lock, flags);
	return node;
}

static int _free_uuid_node(struct genz_mem_data *mdata, struct rb_root *root,
			   uuid_t *uuid, bool teardown)
{
	struct uuid_node *node;
	struct uuid_tracker *uu;
	int ret = 0;

	/* caller must already hold the appropriate spinlock for root */
	node = uuid_node_search(root, uuid, teardown);
	if (!node) {
		ret = -EINVAL;
		goto out;
	}

	uu = node->tracker;
	if (teardown) {
		genz_rmr_remove_unode(mdata, node);
	} else if (!genz_unode_rmr_empty(node)) {
		ret = -EBUSY;
		pr_debug("ret=%d, uuid=%pUb\n", ret, &uu->uuid);
		goto out;
	}

	rb_erase(&node->node, root);
	kfree(node);
	genz_uuid_remove(uu); /* remove remote_uuid reference */

 out:
	return ret;
}

int genz_free_uuid_node(struct genz_mem_data *mdata, spinlock_t *lock,
			struct rb_root *root,
			uuid_t *uuid, bool teardown)
{
	int ret;
	ulong flags;

	spin_lock_irqsave(lock, flags);
	ret = _free_uuid_node(mdata, root, uuid, teardown);
	spin_unlock_irqrestore(lock, flags);

	return ret;
}
EXPORT_SYMBOL(genz_free_uuid_node);

int genz_free_local_or_remote_uuid(struct genz_mem_data *mdata, uuid_t *uuid,
				   struct uuid_tracker *uu, bool *local)
{
	int    status;
	ulong  flags;

	spin_lock_irqsave(&mdata->uuid_lock, flags);
	*local = (uu == mdata->local_uuid);
	if (*local) {
		status = genz_free_local_uuid(mdata, false);
	} else {
		status = _free_uuid_node(mdata, &mdata->md_remote_uuid_tree,
					 uuid, false);
	}
	spin_unlock_irqrestore(&mdata->uuid_lock, flags);

	return status;
}
EXPORT_SYMBOL(genz_free_local_or_remote_uuid);

void genz_free_remote_uuids(struct genz_mem_data *mdata)
{
	struct rb_node          *rb, *next;
	struct rb_root          md_remote_uuid_tree;
	struct uuid_node        *node;
	struct uuid_tracker     *uu;
	ulong                   flags;

	spin_lock_irqsave(&mdata->uuid_lock, flags);
restart:
	md_remote_uuid_tree = mdata->md_remote_uuid_tree;
	mdata->md_remote_uuid_tree = RB_ROOT;
	spin_unlock_irqrestore(&mdata->uuid_lock, flags);

	/* must not hold mdata->uuid_lock to avoid lock order inversion with
	   uu->remote->local_uuid_lock */
	for (rb = rb_first_postorder(&md_remote_uuid_tree); rb; rb = next) {
		node = container_of(rb, struct uuid_node, node);
		uu = node->tracker;
		pr_debug("uuid = %pUb\n", &uu->uuid);
		genz_free_uuid_node(mdata, &uu->remote->local_uuid_lock,
				    &uu->remote->local_uuid_tree,
				    &mdata->local_uuid->uuid, false);
		next = rb_next_postorder(rb);  /* must precede kfree() */
		kfree(node);
		genz_uuid_remove(uu); /* remove remote_uuid reference */
	}

	spin_lock_irqsave(&mdata->uuid_lock, flags);
	if (!RB_EMPTY_ROOT(&mdata->md_remote_uuid_tree))
		goto restart;
	spin_unlock_irqrestore(&mdata->uuid_lock, flags);
}
EXPORT_SYMBOL(genz_free_remote_uuids);

struct uuid_tracker *genz_uuid_tracker_alloc_and_insert(
	uuid_t *uuid,
	uint type,
	uint32_t uu_flags,
	struct genz_mem_data *mdata,
	gfp_t alloc_flags,
	int *status)
{
	struct uuid_tracker *uu;

	uu = genz_uuid_tracker_alloc(uuid, type, alloc_flags, status);
	if (uu) {
		if (type & UUID_TYPE_LOCAL) {
			uu->local->mdata = mdata;
			uu->local->uu_remote_uuid_tree = RB_ROOT;
		}
		if (type & UUID_TYPE_REMOTE) {
			uu->remote->rkeys_valid = false;
			uu->remote->uu_flags = uu_flags;
			uu->remote->local_uuid_tree = RB_ROOT;
			spin_lock_init(&uu->remote->local_uuid_lock);
		}

		uu = genz_uuid_tracker_insert(uu, status);
	}

	return uu;
}
EXPORT_SYMBOL(genz_uuid_tracker_alloc_and_insert);

struct uuid_node *genz_remote_uuid_alloc_and_insert(
	struct uuid_tracker *uu,
	spinlock_t *lock,
	struct rb_root *root,
	gfp_t alloc_flags,
	int *status)
{
	struct uuid_node *node, *found;
	int ret = 0;

	node = kmalloc(sizeof(struct uuid_node), alloc_flags);
	if (!node) {
		ret = -ENOMEM;
		goto out;
	}
	node->tracker = uu;
	node->un_rmr_tree = RB_ROOT;
	found = genz_remote_uuid_insert(lock, root, node);
	if (found != node) {  /* already there */
		kfree(node);
		ret = -EEXIST;
		node = found;
		goto out;
	}

 out:
	*status = ret;
	return node;
}
EXPORT_SYMBOL(genz_remote_uuid_alloc_and_insert);

static atomic_t __fabric_number = ATOMIC_INIT(5); /* Revisit: debug start@5 */
static int get_new_fabric_number(void)
{
	return atomic_inc_return(&__fabric_number) - 1;
}

struct uuid_tracker *genz_fabric_uuid_tracker_alloc_and_insert(
		uuid_t *uuid)
{
	int status;
	struct uuid_tracker *uu;
	int ret;

	uu = genz_uuid_tracker_alloc(uuid, UUID_TYPE_FABRIC, GFP_KERNEL,
			&status);
	if (uu) {
		uu = genz_uuid_tracker_insert(uu, &status);
		if (status == 0) { /* New uuid_tracker */
			pr_debug("tracker insert new mgr_uuid\n");
			uu->fabric->fabric_num = get_new_fabric_number();
			uu->fabric->fabric = genz_find_fabric(uu->fabric->fabric_num);
			memcpy(&uu->fabric->fabric->mgr_uuid, uuid, UUID_SIZE);
			ret = genz_create_mgr_uuid_file(&uu->fabric->fabric->dev);
			if (ret) {
				pr_debug("genz_create_mgr_uuid_file failed\n");
			}
		} else { /* -EEXIST */
			pr_debug("tracker insert prev != uu already in the tracker mgr_uuid\n");
		}
		pr_debug("fabric_num=%d, fabric=%px\n",
			 uu->fabric->fabric_num, uu->fabric->fabric);
	}
	return uu;
}
EXPORT_SYMBOL(genz_fabric_uuid_tracker_alloc_and_insert);

void genz_fabric_uuid_tracker_free(uuid_t *uuid)
{
	struct uuid_tracker *uu;
	int gone;

	pr_debug("tracker free of fabric_uuid %pUb\n", uuid);
	uu = genz_uuid_search(uuid);
	if (uu == NULL) {
		pr_debug("genz_uuid_search returned NULL meaning it was already freed\n");
		return;
	}
	/* genz_uuid_search gets the refcount, so we need to put it */
	gone = kref_put(&uu->refcount, genz_uuid_tracker_free);
	if (gone)
		pr_debug("freed uuid=%pUb\n", &uu->uuid);
	else
		pr_debug("removed uuid=%pUb, refcount=%u\n", &uu->uuid,
			 kref_read(&uu->refcount));
	genz_uuid_remove(uu);
	return;
}

static inline bool uuid_tree_empty(void)
{
	return RB_EMPTY_ROOT(&uuid_rbtree);
}

int genz_teardown_remote_uuid(uuid_t *src_uuid)
{
	int                    status = 0;
	struct uuid_tracker    *suu, *tuu;
	struct rb_node         *rb, *next;
	struct uuid_node       *node;
	struct genz_mem_data   *mdata;
	ulong                  flags;

	suu = genz_uuid_search(src_uuid);
	if (!suu) {
		status = -EINVAL;
		pr_debug("src_uuid=%pUb not found\n", src_uuid);
		goto out;
	}
	/* we now hold an extra reference to suu */

	pr_debug("uuid=%pUb\n", &suu->uuid);

	if (!suu->remote) {
		pr_debug("unexpected null ptr, suu->remote=%px, uuid=%pUb\n",
			 suu->remote, &suu->uuid);
		goto local;
	}
	WRITE_ONCE(suu->remote->torndown, true);
	spin_lock_irqsave(&suu->remote->local_uuid_lock, flags);
	for (rb = rb_first_postorder(&suu->remote->local_uuid_tree);
	     rb; rb = next) {
		node = container_of(rb, struct uuid_node, node);
		tuu = node->tracker;
		pr_debug("local_uuid_tree uuid=%pUb\n", &tuu->uuid);
		next = rb_next_postorder(rb);  /* must precede kfree() */
		mdata = tuu->local->mdata;
		status = genz_free_uuid_node(mdata, &mdata->uuid_lock,
					     &mdata->md_remote_uuid_tree,
					     src_uuid, true);
		kfree(node);
		genz_uuid_remove(tuu); /* remove local_uuid reference */
	}
	suu->remote->local_uuid_tree = RB_ROOT;
	spin_unlock_irqrestore(&suu->remote->local_uuid_lock, flags);

local:
	/* special case for alias loopback UUIDs */
	if (suu->local) {
		spin_lock_irqsave(&suu->local->mdata->uuid_lock, flags);
		teardown_local_uuid(suu);
		spin_unlock_irqrestore(&suu->local->mdata->uuid_lock, flags);
	}

	genz_uuid_remove(suu);  /* release extra reference */

out:
	return status;
}
EXPORT_SYMBOL(genz_teardown_remote_uuid);

void genz_generate_uuid(struct genz_bridge_dev *br, uuid_t *uuid)
{
	if (br->zbdrv->generate_uuid) {
		return br->zbdrv->generate_uuid(br, uuid);
	}

	uuid_gen(uuid);
}
EXPORT_SYMBOL(genz_generate_uuid);

int genz_uuid_import(struct genz_mem_data *mdata, uuid_t *uuid,
		     uint32_t uu_flags, gfp_t alloc_flags)
{
	struct genz_bridge_dev *br;

	if (!mdata)
		return -EINVAL;
	br = mdata->bridge;
	if (!br || !br->zbdrv || !br->zbdrv->uuid_import)
		return -EINVAL;
	/* Revisit: add default implementation */
	return br->zbdrv->uuid_import(mdata, uuid, uu_flags, alloc_flags);
}
EXPORT_SYMBOL(genz_uuid_import);

int genz_uuid_free(struct genz_mem_data *mdata, uuid_t *uuid,
		   uint32_t *uu_flags, bool *local)
{
	struct genz_bridge_dev *br;

	if (!mdata)
		return -EINVAL;
	br = mdata->bridge;
	if (!br || !br->zbdrv || !br->zbdrv->uuid_free)
		return -EINVAL;
	/* Revisit: add default implementation */
	return br->zbdrv->uuid_free(mdata, uuid, uu_flags, local);
}
EXPORT_SYMBOL(genz_uuid_free);

void genz_uuid_exit(void)
{
	struct rb_node          *rb;
	struct uuid_tracker     *uu;
	ulong                   flags;

	spin_lock_irqsave(&genz_uuid_rbtree_lock, flags);

	if (!uuid_tree_empty()) {
		pr_debug("uuid_tree not empty\n");
		for (rb = rb_first(&uuid_rbtree); rb; rb = rb_next(rb)) {
			uu = container_of(rb, struct uuid_tracker, node);
			pr_debug("orphaned uuid=%pUb, refcount=%u\n",
				 &uu->uuid, kref_read(&uu->refcount));
		}
	}

	spin_unlock_irqrestore(&genz_uuid_rbtree_lock, flags);
}
EXPORT_SYMBOL(genz_uuid_exit);
