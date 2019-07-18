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

static ssize_t fabric_attr_show(struct kobject *kobj,
                             struct attribute *attr,
                             char *buf)
{
        struct genz_fabric_attribute *attribute;
        struct genz_fabric *fab;

        attribute = to_genz_fabric_attr(attr);
        fab = to_genz_fabric(kobj);

        if (!attribute->show)
                return -EIO;

        return attribute->show(fab, attribute, buf);
}

static void fabric_release(struct kobject *kobj)
{
	struct genz_fabric *fab;

	fab = to_genz_fabric(kobj);
	kfree(fab);
}

static const struct sysfs_ops fabric_sysfs_ops = {
	.show = fabric_attr_show,
};
static struct kobj_type fabric_ktype = {
	.sysfs_ops = &fabric_sysfs_ops,
	.release = fabric_release,
};

static struct genz_fabric *genz_alloc_fabric(void)
{
	struct genz_fabric *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return NULL;

        INIT_LIST_HEAD(&f->devices);
        INIT_LIST_HEAD(&f->bridges);

	/* Create /sys/devices/genz<N> directory kobject */
	
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
		kobject_init(&found->kobj, &fabric_ktype);
		kref_init(&found->kref);
		down_write(&genz_fabrics_sem);
		list_add_tail(&found->node, &genz_fabrics);
		up_write(&genz_fabrics_sem);
	}
	return found;
}

static ssize_t component_attr_show(struct kobject *kobj,
                             struct attribute *attr,
                             char *buf)
{
        struct genz_component_attribute *attribute;
        struct genz_component *comp;

        attribute = to_genz_component_attr(attr);
        comp = to_genz_component(kobj);

        if (!attribute->show)
                return -EIO;

        return attribute->show(comp, attribute, buf);
}

static void component_release(struct kobject *kobj)
{
	struct genz_component *comp;

	comp = to_genz_component(kobj);
	kfree(comp);
}

static const struct sysfs_ops component_sysfs_ops = {
	.show = component_attr_show,
};
static struct kobj_type component_ktype = {
	.sysfs_ops = &component_sysfs_ops,
	.release = component_release,
};

struct genz_component *genz_alloc_component(void)
{
	struct genz_component *zcomp;

	zcomp = kzalloc(sizeof(*zcomp), GFP_KERNEL);
	if (!zcomp)
		return NULL;
	kobject_init(&zcomp->kobj, &component_ktype);
	kref_init(&zcomp->kref);
	return(zcomp);
}

void genz_free_component(struct kref *kref)
{
	struct genz_component *c;

	c = container_of(kref, struct genz_component, kref);
	kfree(c);
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
	if (zdev == NULL)
		return;
	if (zdev->zcomp)
		kref_put(&zdev->zcomp->kref, genz_free_component);
        kfree(zdev);
}

struct genz_dev *genz_alloc_dev(struct genz_fabric *fabric)
{
        struct genz_dev *zdev;
        struct genz_component *zcomp;

        zdev = kzalloc(sizeof(*zdev), GFP_KERNEL);
        if (!zdev)
                return NULL;

        /* Allocate a genz_component */
        zcomp = genz_alloc_component();
        if (zcomp == NULL) {
		kfree(zdev);
                return NULL;
        }
        zdev->zcomp = zcomp;
        list_add_tail(&zdev->fab_dev_node, &fabric->devices);
        zdev->dev.type = &genz_dev_type;
        INIT_LIST_HEAD(&zdev->zres_list);

        return zdev;
}
EXPORT_SYMBOL(genz_alloc_dev);

