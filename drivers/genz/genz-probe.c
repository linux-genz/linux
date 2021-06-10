// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2019-2020 Hewlett Packard Enterprise Development LP.
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
#include "genz-probe.h"
#include "genz-sysfs.h"
#include "genz-netlink.h"
#include "genz-control.h"

/* Global list of struct genz_fabric. Protected by spinlock genz_fabrics_lock */
LIST_HEAD(genz_fabrics);
DEFINE_SPINLOCK(genz_fabrics_lock);

static void genz_fabric_release(struct kobject *kobj)
{
	/* Revisit: implement this */
}

static struct kobj_type genz_fabric_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = genz_fabric_release
};

static int call_probe(struct genz_dev *zdev, struct genz_driver *zdrv, const struct genz_device_id *zid);

/**
 * genz_dev_get - increments the reference count of the genz device structure
 * @zdev: the device being referenced
 *
 * Each live reference to a device should be refcounted.
 *
 * Drivers for Gen-Z devices should normally record such references in
 * their probe() methods, when they bind to a device, and release
 * them by calling genz_dev_put(), in their disconnect() methods.
 *
 * A pointer to the device with the incremented reference counter is returned.
 */
struct genz_dev *genz_dev_get(struct genz_dev *zdev)
{
	if (zdev)
		get_device(&zdev->dev);
	return zdev;
}
EXPORT_SYMBOL(genz_dev_get);

/**
 * genz_dev_put - release a use of the genz device structure
 * @zdev: device that's been disconnected
 *
 * Must be called when a user of a device is finished with it.  When the last
 * user of the device calls this function, the memory of the device is freed.
 */
void genz_dev_put(struct genz_dev *zdev)
{
	if (zdev)
		put_device(&zdev->dev);
}
EXPORT_SYMBOL(genz_dev_put);

/**
 * genz_match_one_device - Tell if a Gen-Z device structure has a matching
 *                        Gen-Z device id structure
 * @zid: single Gen-Z device id structure to match
 * @zdev: the Gen-Z device structure to match against
 *
 * Returns the matching genz_device_id structure or %NULL if there is no match.
 */
static inline const struct genz_device_id *
genz_match_one_device(const struct genz_device_id *zid,
		const struct genz_dev *zdev)
{
	if (uuid_equal(&zid->uuid, &zdev->class_uuid))
		return zid;
	if (uuid_equal(&zid->uuid, &zdev->instance_uuid))
		return zid;
	return NULL;
}


/**
 * genz_match_id - See if a Gen-Z device matches a given genz id_table
 * @zids: array of Gen-Z device id structures to search in
 * @zdev: the Gen-Z device structure to match against.
 *
 * Used by a driver to check whether a Gen-Z device present in the
 * system is in its list of supported devices.  Returns the matching
 * genz_device_id structure or %NULL if there is no match.
 */
const struct genz_device_id *genz_match_id(const struct genz_device_id *zids,
					   struct genz_dev *zdev)
{
	if (zids) {
		while (!uuid_is_null(&zids->uuid)) {
			if (genz_match_one_device(zids, zdev))
				return zids;
			zids++;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(genz_match_id);

/**
 * genz_match_device - Tell if a Gen-Z device structure has a matching Gen-Z device id structure
 * @zdrv: the Gen-Z driver to match against
 * @zdev: the Gen-Z device structure to match against
 *
 * Used by a driver to check whether a Gen-Z device present in the
 * system is in its list of supported devices.  Returns the matching
 * genz_device_id structure or %NULL if there is no match.
 */
const struct genz_device_id *genz_match_device(struct genz_driver *zdrv,
					       struct genz_dev *zdev)
{
	const struct genz_device_id *found_zid = NULL;

	found_zid = genz_match_id(zdrv->id_table, zdev);

	return found_zid;
}


/**
 * __genz_device_probe - check if a driver wants to claim a specific Gen-Z device
 * @zdrv: driver to call to check if it wants the Gen-Z device
 * @zdev: Gen-Z device being probed
 *
 * returns 0 on success, else error.
 * side-effect: zdev->driver is set to drv when drv claims zdev.
 */
static int __genz_device_probe(struct genz_driver *zdrv, struct genz_dev *zdev)
{
	const struct genz_device_id *zid;
	int ret = 0;

	if (!zdev->zdrv && zdrv->probe) {
		ret = -ENODEV;

		zid = genz_match_device(zdrv, zdev);
		if (zid)
			ret = call_probe(zdev, zdrv, zid);
	}
	return ret;
}

int genz_device_probe(struct device *dev)
{
	struct genz_dev *zdev = to_genz_dev(dev);
	struct genz_driver *zdrv = to_genz_driver(dev->driver);
	int ret;

	genz_dev_get(zdev);
	ret = __genz_device_probe(zdrv, zdev);
	if (ret) {
		genz_dev_put(zdev);
	}
	return ret;
}

int genz_device_remove(struct device *dev)
{
	struct genz_dev *zdev = to_genz_dev(dev);
	struct genz_driver *zdrv = to_genz_driver(dev->driver);

	if (zdrv) {
		if (zdrv->remove) {
			zdrv->remove(zdev);
		}
		zdev->zdrv = NULL;
	}

	genz_dev_put(zdev);
	return 0;
}

static struct genz_fabric *genz_alloc_fabric(uint32_t fabric_num)
{
	struct genz_fabric *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return NULL;

	INIT_LIST_HEAD(&f->subnets);
	INIT_LIST_HEAD(&f->components);
	INIT_LIST_HEAD(&f->os_subnets);
	INIT_LIST_HEAD(&f->os_components);
	INIT_LIST_HEAD(&f->devices);
	INIT_LIST_HEAD(&f->bridges);
	spin_lock_init(&f->devices_lock);
	spin_lock_init(&f->components_lock);
	spin_lock_init(&f->subnets_lock);
	spin_lock_init(&f->bridges_lock);
	kref_init(&f->kref);
	f->status = GENZ_FABRIC_STATUS_UNINIT;
	f->number = fabric_num;

	return f;
}

static int genz_init_fabric(struct genz_fabric *f)
{
	int ret = 0;
	unsigned long flags;

	/*
	 * The /sys/devices/genz<N> directory is created by adding a
	 * struct device. This is not claimed by driver. We use the device's
	 * kobject as the parent for the sysfs tree. Use device_del on this
	 * fabric device when the fabric is done being used.
	 */
	/* setting the bus and id uses simple enumeration to get genz<N> */
	f->dev.bus = &genz_bus_type;
	f->dev.id = f->number;
	f->dev.release = genz_release_fabric;
	f->dev.parent = NULL;
	dev_set_name(&f->dev, "genz%u", f->number);

	ret = device_register(&f->dev);
	if (ret) {
		dev_dbg(&f->dev, "device_register failed with %d\n", ret);
		put_device(&f->dev);
		return ret;
	}

	/*
	 * The /sys/bus/genz/fabrics/fabric<N> directory is created using
	 * bus_kobj.
	 */
	f->bus_kobj.kset = genz_fabrics_kset;
	ret = kobject_init_and_add(&f->bus_kobj, &genz_fabric_ktype, NULL,
				   "fabric%u", f->number);
	if (ret < 0) {
		kobject_put(&f->bus_kobj);
		return ret;
	}
	spin_lock_irqsave(&genz_fabrics_lock, flags);
	f->status = GENZ_FABRIC_STATUS_INITED;
	spin_unlock_irqrestore(&genz_fabrics_lock, flags);
	return ret;
}

void genz_release_fabric(struct device *dev)
{
	struct genz_fabric *f;
	unsigned long flags;

	f = dev_to_genz_fabric(dev);

	pr_debug("%s\n", dev_name(dev));
	kobject_put(&f->bus_kobj);
	spin_lock_irqsave(&genz_fabrics_lock, flags);
	list_del(&f->node);
	spin_unlock_irqrestore(&genz_fabrics_lock, flags);
	kfree(f);
}

struct genz_fabric *genz_find_fabric(uint32_t fabric_num)
{
	struct genz_fabric *f, *found = NULL;
	int ret = 0;
	unsigned long flags;

	pr_debug("entered");
	spin_lock_irqsave(&genz_fabrics_lock, flags);
	list_for_each_entry(f, &genz_fabrics, node) {
		if (f->number == fabric_num) {
			found = f;
			goto unlock;
		}
	}
	pr_debug("fabric_num %d is not in the list\n", fabric_num);
	spin_unlock_irqrestore(&genz_fabrics_lock, flags);

	/* alloc_fabric does memory alloc - no spinlock */
	found = genz_alloc_fabric(fabric_num);
	if (!found) {
		pr_debug("genz_alloc_fabric returned NULL\n");
		goto out;
	}

	/* check if someone else added this fabric while we were unlocked */
	spin_lock_irqsave(&genz_fabrics_lock, flags);
	list_for_each_entry(f, &genz_fabrics, node) {
		if (f->number == fabric_num) {  /* already there */
			pr_debug("fabric_num %d already in the list\n",
				 fabric_num);
			kfree(found);
			found = f;
			goto unlock;
		}
	}
	/* add to list - status is UNINIT*/
	list_add_tail(&found->node, &genz_fabrics);
	spin_unlock_irqrestore(&genz_fabrics_lock, flags);

	/* initialize - status set to INITED */
	ret = genz_init_fabric(found);
	if (ret) {
		pr_debug("genz_init_fabric returned %d\n", ret);
		found = NULL;
		goto out;
	}

	return found;

unlock:
	spin_unlock_irqrestore(&genz_fabrics_lock, flags);
out:
	return found;

}

/* Revisit: never called - delete? */
struct genz_fabric *genz_dev_to_fabric(struct device *dev)
{
	struct genz_fabric *fab;
	unsigned long flags;

	spin_lock_irqsave(&genz_fabrics_lock, flags);
	list_for_each_entry(fab, &genz_fabrics, node) {
		if (&fab->dev == dev) {
			return fab;
		}
	}
	spin_unlock_irqrestore(&genz_fabrics_lock, flags);
	return NULL;
}

static struct genz_subnet *genz_alloc_subnet(void)
{
	struct genz_subnet *s;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;
	INIT_LIST_HEAD(&s->node);
	return s;
}

static struct genz_os_subnet *genz_alloc_os_subnet(void)
{
	struct genz_os_subnet *s;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;
	INIT_LIST_HEAD(&s->subnet.node);
	return s;
}

void genz_release_os_subnet(struct device *dev)
{
	struct genz_os_subnet *s;
	struct genz_fabric    *f;
	unsigned long         flags;

	pr_debug("%s\n", dev_name(dev));
	s = dev_to_genz_os_subnet(dev);
	f = s->subnet.fabric;

	spin_lock_irqsave(&f->subnets_lock, flags);
	list_del(&s->subnet.node);
	spin_unlock_irqrestore(&f->subnets_lock, flags);
	kfree(s);
}

static void genz_release_subnet(struct kobject *kobj)
{
	struct genz_subnet *s;

	pr_debug("entered\n");
	s = container_of(kobj, struct genz_subnet, kobj);
	kfree(s);
}

static struct kobj_type genz_subnet_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = genz_release_subnet
};

static int genz_init_subnet(struct genz_subnet *s,
			    uint32_t sid, struct genz_fabric *f, bool add_kobj)
{
	int ret = 0;

	s->sid = sid;
	s->fabric = f;
	kobject_init(&s->kobj, &genz_subnet_ktype);
	if (add_kobj) {
		ret = kobject_add(&s->kobj, &f->bus_kobj,
				  "%u:%04x", f->number, s->sid);
	}
	return ret;
}

static int genz_init_os_subnet(struct genz_os_subnet *s,
			       uint32_t sid, struct genz_fabric *f)
{
	int ret = 0;

	ret = genz_init_subnet(&s->subnet, sid, f, false);
	if (ret != 0)
		return ret;
	s->dev.bus = &genz_bus_type;
	s->dev.id = sid;
	s->dev.release = genz_release_os_subnet;
	s->dev.parent = &f->dev;
	dev_set_name(&s->dev, "%u:%04x", f->number, sid);

	ret = device_register(&s->dev);
	if (ret) {
		pr_debug("device_register failed with %d\n", ret);
		put_device(&s->dev);
		return ret;
	}
	return ret;
}

struct genz_subnet *genz_lookup_subnet(uint32_t sid, struct genz_fabric *f)
{
	struct genz_subnet *s, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&f->subnets_lock, flags);
	list_for_each_entry(s, &f->subnets, node) {
		pr_debug("subnets list genz_subnet %px\n", s);
		pr_debug("\tsubnet fabric is %px \n", s->fabric);
		pr_debug("\ts->sid is %d looking for sid %d\n", s->sid, sid);
		if (s->sid == sid) {
			found = s;
			/* Revisit: kref? */
			break;
		}
	}
	spin_unlock_irqrestore(&f->subnets_lock, flags);

	return found;
}

struct genz_os_subnet *genz_lookup_os_subnet(uint32_t sid, struct genz_fabric *f)
{
	struct genz_os_subnet *s, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&f->subnets_lock, flags);
	list_for_each_entry(s, &f->os_subnets, subnet.node) {
		pr_debug("subnets list genz_subnet %px\n", s);
		pr_debug("\tsubnet fabric is %px \n", s->subnet.fabric);
		pr_debug("\ts->sid is %d looking for sid %d\n", s->subnet.sid, sid);
		if (s->subnet.sid == sid) {
			found = s;
			/* Revisit: kref? */
			break;
		}
	}
	spin_unlock_irqrestore(&f->subnets_lock, flags);

	return found;
}

struct genz_subnet *genz_add_subnet(uint32_t sid, struct genz_fabric *f)
{
	struct genz_subnet *found;
	int ret = 0;
	unsigned long flags;

	pr_debug("entered\n");
	found = genz_lookup_subnet(sid, f);

	if (!found) {
		pr_debug("sid %d is not in the subnets list yet\n", sid);
		/* Allocate a new genz_subnet and add to list */
		found = genz_alloc_subnet();
		if (!found) {
			pr_debug("alloc_subnet failed\n");
			return found;
		}
		ret = genz_init_subnet(found, sid, f, true);
		if (ret) {
			pr_debug("init_subnet failed\n");
			return NULL;
		}
		/* Revisit: make sure this has not already been added. */
		spin_lock_irqsave(&f->subnets_lock, flags);
		list_add_tail(&found->node, &f->subnets);
		spin_unlock_irqrestore(&f->subnets_lock, flags);
		pr_debug("added to the subnet list\n");
	}
	return found;
}

struct genz_os_subnet *genz_add_os_subnet(uint32_t sid, struct genz_fabric *f)
{
	struct genz_os_subnet *found;
	int ret = 0;
	unsigned long flags;

	pr_debug("entered\n");
	found = genz_lookup_os_subnet(sid, f);

	if (!found) {
		pr_debug("sid %d is not in the os subnets list yet\n", sid);
		/* Allocate a new genz_os_subnet and add to list */
		found = genz_alloc_os_subnet();
		if (!found) {
			pr_debug("alloc_os_subnet failed\n");
			return found;
		}
		ret = genz_init_os_subnet(found, sid, f);
		if (ret) {
			pr_debug("init_subnet failed\n");
			return NULL;
		}
		/* Revisit: make sure this has not already been added. */
		spin_lock_irqsave(&f->subnets_lock, flags);
		list_add_tail(&found->subnet.node, &f->os_subnets);
		spin_unlock_irqrestore(&f->subnets_lock, flags);
		pr_debug("added to the subnet list\n");
	}
	return found;
}

/* Component Attributes */
static ssize_t cclass_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct genz_os_comp *comp;

	comp = dev_to_genz_os_comp(dev);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	return snprintf(buf, PAGE_SIZE, "%d\n", comp->comp.cclass);
}
static DEVICE_ATTR(cclass, (S_IRUGO), cclass_show, NULL);

static ssize_t serial_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct genz_os_comp *comp;

	comp = dev_to_genz_os_comp(dev);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	return snprintf(buf, PAGE_SIZE, "0x%llx\n", comp->comp.serial);
}
static DEVICE_ATTR(serial, (S_IRUGO), serial_show, NULL);

static ssize_t gcid_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct genz_os_comp *comp;
	uint32_t                 gcid;
	char                     str[GCID_STRING_LEN+1];

	comp = dev_to_genz_os_comp(dev);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	if (comp->subnet == NULL) {
		pr_debug("comp->subnet is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component subnet\n"));
	}
	gcid = genz_gcid(comp->subnet->subnet.sid, comp->comp.cid);
	return snprintf(buf, PAGE_SIZE, "%s\n",
			genz_gcid_str(gcid, str, sizeof(str)));
}
static DEVICE_ATTR(gcid, (S_IRUGO), gcid_show, NULL);

static ssize_t fru_uuid_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct genz_os_comp *comp;

	comp = dev_to_genz_os_comp(dev);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	return snprintf(buf, PAGE_SIZE, "%pUb\n", &comp->comp.fru_uuid);
}
static DEVICE_ATTR(fru_uuid, (S_IRUGO), fru_uuid_show, NULL);

static ssize_t c_uuid_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct genz_os_comp *comp;

	comp = dev_to_genz_os_comp(dev);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	return snprintf(buf, PAGE_SIZE, "%pUb\n", &comp->comp.c_uuid);
}
static DEVICE_ATTR(c_uuid, (S_IRUGO), c_uuid_show, NULL);

static int genz_create_os_comp_files(struct device *dev)
{
	int ret;

	pr_debug("create files for device %s\n", dev_name(dev));
	ret  = device_create_file(dev, &dev_attr_gcid);
	ret |= device_create_file(dev, &dev_attr_cclass);
	ret |= device_create_file(dev, &dev_attr_serial);
	ret |= device_create_file(dev, &dev_attr_fru_uuid);
	ret |= device_create_file(dev, &dev_attr_c_uuid);
	return ret;
}

struct genz_comp *genz_alloc_comp(void)
{
	struct genz_comp *zcomp;

	zcomp = kzalloc(sizeof(*zcomp), GFP_KERNEL);
	return zcomp;
}

struct genz_os_comp *genz_alloc_os_comp(void)
{
	struct genz_os_comp *ocomp;

	ocomp = kzalloc(sizeof(*ocomp), GFP_KERNEL);
	return ocomp;
}

void genz_release_os_comp(struct device *dev)
{
	struct genz_os_comp *c;
	unsigned long flags;

	pr_debug("%s\n", dev_name(dev));
	c = dev_to_genz_os_comp(dev);

	spin_lock_irqsave(&c->comp.subnet->fabric->components_lock, flags);
	list_del(&c->comp.fab_comp_node);
	spin_unlock_irqrestore(&c->comp.subnet->fabric->components_lock, flags);
	kfree(c);
}

static void genz_release_comp(struct kobject *kobj)
{
	struct genz_comp *c;

	pr_debug("entered\n");
	c = container_of(kobj, struct genz_comp, kobj);
	kfree(c);
}

static struct kobj_type genz_comp_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = genz_release_comp
};

int genz_init_comp(struct genz_comp *zcomp,
		   struct genz_subnet *s, uint32_t cid, bool add_kobj)
{
	struct genz_fabric *f = s->fabric;
	int ret = 0;

	zcomp->subnet = s;
	zcomp->cid = cid;
	if (add_kobj && !zcomp->add_kobj) {
		ret = kobject_init_and_add(&zcomp->kobj, &genz_comp_ktype,
			 &s->kobj, "%u:%04x:%03x", f->number, s->sid, cid);
		if (ret == 0)
			zcomp->add_kobj = true;  /* Revisit: locking */
		else
			kobject_put(&zcomp->kobj);
	}
	return ret;
}

int genz_init_os_comp(struct genz_os_comp *ocomp,
		      struct genz_os_subnet *s, uint32_t cid)
{
	struct genz_fabric *f = s->subnet.fabric;
	int ret = 0;

	ret = genz_init_comp(&ocomp->comp, &s->subnet, cid, false);
	if (ret != 0)
		return ret;
	ocomp->subnet = s;
	ocomp->dev.bus = &genz_bus_type;
	ocomp->dev.id = cid;
	ocomp->dev.release = genz_release_os_comp;
	ocomp->dev.parent = &s->dev;
	dev_set_name(&ocomp->dev, "%u:%04x:%03x",
		     f->number, s->subnet.sid, cid);
	ret = device_register(&ocomp->dev);
	if (ret) {
		pr_debug("device_register failed with %d\n", ret);
		put_device(&ocomp->dev);
		return ret;
	}
	genz_create_os_comp_files(&ocomp->dev);
	return ret;
}

void print_components(struct genz_fabric *f)
{
	struct genz_comp *c;
	int i = 0;

	pr_debug("components list dump for fabric %px\n", f);
	list_for_each_entry(c, &f->components, fab_comp_node) {
		pr_debug("components list item %d: genz_comp %px\n", i++, c);
		pr_debug("\t subnet is %px gcid is %d:%d cclass is %d fru_uuid is %pUb\n", c->subnet, c->subnet->sid, c->cid, c->cclass, &c->fru_uuid);
	}

}

struct genz_comp *genz_lookup_comp(struct genz_subnet *s, uint32_t cid)
{
	struct genz_comp *c, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&s->fabric->components_lock, flags);
	list_for_each_entry(c, &s->fabric->components, fab_comp_node) {
		if (c->cid == cid && s->sid == c->subnet->sid) {
			found = c;
			if (c->add_kobj)
				kobject_get(&c->kobj);
			break;
		}
	}
	spin_unlock_irqrestore(&s->fabric->components_lock, flags);
	return found;
}

struct genz_os_comp *genz_lookup_os_comp(struct genz_os_subnet *s,
					 uint32_t cid)
{
	struct genz_os_comp *c, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&s->subnet.fabric->components_lock, flags);
	list_for_each_entry(c, &s->subnet.fabric->os_components, comp.fab_comp_node) {
		if (c->comp.cid == cid && s->subnet.sid == c->subnet->subnet.sid) {
			found = c;
			break;
		}
	}
	spin_unlock_irqrestore(&s->subnet.fabric->components_lock, flags);
	return found;
}

struct genz_comp *genz_add_comp(struct genz_subnet *s,
				uint32_t cid, bool add_kobj)
{
	struct genz_comp *found = NULL;
	int ret = 0;
	unsigned long flags;

	pr_debug("cid=%u, add_kobj=%u\n", cid, add_kobj);
	found = genz_lookup_comp(s, cid);
	if (!found) {
		pr_debug("cid %d is not in the components list yet\n", cid);
		/* Allocate a new genz_comp and add to list */
		found = genz_alloc_comp();
		if (!found) {
			pr_debug("alloc_comp failed\n");
			return found;
		}
		ret = genz_init_comp(found, s, cid, add_kobj);
		if (ret) {
			pr_debug("genz_init_comp failed, ret=%d\n", ret);
			kfree(found);
			return NULL;
		}
		/* Revisit: make sure this has not already been added. */
		spin_lock_irqsave(&s->fabric->components_lock, flags);
		list_add_tail(&found->fab_comp_node, &s->fabric->components);
		spin_unlock_irqrestore(&s->fabric->components_lock, flags);
		pr_debug("added component %px to the component list\n", found);
	} else {
		pr_debug("cid %d found in the components list, %px\n", cid, found);
		if (add_kobj && !found->add_kobj) {
			ret = genz_init_comp(found, s, cid, add_kobj);
			if (ret) {
				pr_debug("genz_init_comp failed, ret=%d\n", ret);
			}
		}
	}
	return found;
}

struct genz_os_comp *genz_add_os_comp(struct genz_os_subnet *s,
				   uint32_t cid)
{
	struct genz_os_comp *found = NULL;
	int ret = 0;
	unsigned long flags;

	found = genz_lookup_os_comp(s, cid);
	if (!found) {
		pr_debug("cid %d is not in the os_comp list yet\n", cid);
		/* Allocate a new genz_os_comp and add to list */
		found = genz_alloc_os_comp();
		if (!found) {
			pr_debug("alloc_os_comp failed\n");
			return found;
		}
		ret = genz_init_os_comp(found, s, cid);
		if (ret) {
			pr_debug("init_comp failed\n");
			return NULL;
		}
		/* Revisit: make sure this has not already been added. */
		spin_lock_irqsave(&s->subnet.fabric->components_lock, flags);
		list_add_tail(&found->comp.fab_comp_node, &s->subnet.fabric->os_components);
		spin_unlock_irqrestore(&s->subnet.fabric->components_lock, flags);
		pr_debug("added component %px to the os_comp list\n", found);
	}
	return found;
}

struct genz_comp *genz_lookup_gcid(struct genz_fabric *f, uint32_t gcid)
{
	struct genz_subnet *s;
	struct genz_comp   *c = NULL;

	s = genz_lookup_subnet(genz_gcid_sid(gcid), f);
	if (s != NULL)
		c = genz_lookup_comp(s, genz_gcid_cid(gcid));
	return c;
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
	struct genz_dev *zdev = to_genz_dev(dev);
	unsigned long flags;
	struct genz_fabric *f;

	pr_debug("%s\n", dev_name(dev));
	f = zdev->zcomp->subnet->subnet.fabric;
	if (f == NULL) {
		pr_debug("zdev->zcomp->subnet->fabric is NULL\n");
		return;
	}

	/* remove from the list of devices in the genz_fabric */
	spin_lock_irqsave(&f->devices_lock, flags);
	list_del(&zdev->fab_dev_node);
	spin_unlock_irqrestore(&f->devices_lock, flags);
	/* Revisit: this free's the dev and causes NULL pointer defererence? */
	kfree(zdev);
	pr_debug("returning\n");
}

int genz_init_dev(struct genz_dev *zdev, struct genz_fabric *fabric)
{
	unsigned long flags;

	spin_lock_irqsave(&fabric->devices_lock, flags);
	list_add_tail(&zdev->fab_dev_node, &fabric->devices);
	spin_unlock_irqrestore(&fabric->devices_lock, flags);
	zdev->dev.type = &genz_dev_type;
	pr_debug("INIT_LIST_HEAD(&zdev->zres_list) for zdev %px\n", zdev);
	INIT_LIST_HEAD(&zdev->zres_list);

	return 0;
}

struct genz_dev *genz_alloc_dev(struct genz_fabric *fabric)
{
	struct genz_dev *zdev;
	int ret;

	zdev = kzalloc(sizeof(*zdev), GFP_KERNEL);
	if (!zdev)
		return NULL;
	ret = genz_init_dev(zdev, fabric);
	if (ret) {
		kfree(zdev);
		return NULL;
	}

	pr_debug("fabric=%px, zdev=%px\n", fabric, zdev);

	return zdev;
}

void genz_device_initialize(struct genz_dev *zdev)
{
	zdev->dev.bus = &genz_bus_type;
	zdev->dev.parent = &zdev->zcomp->dev;
	zdev->dev.release = genz_release_dev;
	zdev->zbdev = genz_zdev_bridge(zdev);
	if (zdev->zbdev == NULL) {
		pr_debug("genz_device_initialize failed to find a bridge\n");
	}
	device_initialize(&zdev->dev);
}

int genz_device_add(struct genz_dev *zdev)
{
	int ret = 0;

	genz_device_initialize(zdev);
	ret = device_add(&zdev->dev);
	if (ret)
		pr_debug("device_add failed with %d\n", ret);
	return ret;
}

static int call_probe (struct genz_dev *zdev,
		struct genz_driver *zdrv,
		const struct genz_device_id *zid)
{
	int ret = 0;

	/* call driver probe */
	if (!zdev->zdrv && zdrv->probe) {
		zdev->zdrv = zdrv;
		ret = zdrv->probe(zdev, zid);
		if (ret < 0) {
			/* a probe failed - but keep matching uuids */
			zdev->zdrv = NULL;
			return ret;
		} else if (ret > 0) {
			/* Revisit better message with driver name */
			dev_warn(&zdev->dev, "Driver probe function unexpectedly returned %d\n", ret);
		}
	}
	return ret;
}
