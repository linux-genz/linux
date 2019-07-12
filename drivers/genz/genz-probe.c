/*
 * Copyright (C) 2019 Hewlett Packard Enterprise Development LP.
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

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "genz.h"
#include "genz-types.h"
#include "genz-probe.h"
#include "genz-sysfs.h"

/* Global list of struct genz_fabric. Protected by semaphore XXX. */
LIST_HEAD(genz_fabrics);
DECLARE_RWSEM(genz_fabrics_sem);

static struct genz_fabric *genz_alloc_fabric(void)
{
	struct genz_fabric *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return NULL;

        INIT_LIST_HEAD(&f->devices);
        INIT_LIST_HEAD(&f->bridges);
        return f;
}

void genz_free_fabric(struct kref *kref)
{
	struct genz_fabric *f;

	f = container_of(kref, struct genz_fabric, kref);
	down_write(&genz_fabrics_sem);
	list_del(&f->node);
	up_write(&genz_fabrics_sem);
	kfree(f);
}

struct genz_fabric *genz_find_fabric(uint32_t fabric_num)
{
	struct genz_fabric *f, *found = NULL;
	
	down_read(&genz_fabrics_sem);
	list_for_each_entry(f, &genz_fabrics, node) {
		if (f->number == fabric_num) {
			found = f;
			kref_get(&found->kref);
			break;
		}
	}
	up_read(&genz_fabrics_sem);
	if (!found) {
		/* Allocate a new genz_fabric and add to list */
		found = genz_alloc_fabric();
		if (!found) {
			up_write(&genz_fabrics_sem);
			return found;
		}
		found->number = fabric_num;
		kref_init(&found->kref);
		down_write(&genz_fabrics_sem);
		list_add_tail(&found->node, &genz_fabrics);
		up_write(&genz_fabrics_sem);
	}
	return found;
}

/**
 * genz_release_dev - Free a Gen-Z device structure when all users of it are
 *                   finished
 * @dev: device that's been disconnected
 *
 * Will be called only by the device core when all users of this Gen-Z
 * device are done.
 */
static void genz_release_dev(struct device *dev)
{
        struct genz_dev *zdev;

        zdev = to_genz_dev(dev);
        kfree(zdev);
}

struct genz_dev *genz_alloc_dev(struct genz_fabric *fabric)
{
        struct genz_dev *zdev;

        zdev = kzalloc(sizeof(*zdev), GFP_KERNEL);
        if (!zdev)
                return NULL;

        INIT_LIST_HEAD(&zdev->fabric_list);
        zdev->dev.type = &genz_dev_type;
	zdev->res.name = "Gen-Z MEM";
	zdev->res.start = 0;
	zdev->res.end = -1;
	zdev->res.flags = 0;
	zdev->desc = IORES_DESC_NONE;

        return zdev;
}
EXPORT_SYMBOL(genz_alloc_dev);

