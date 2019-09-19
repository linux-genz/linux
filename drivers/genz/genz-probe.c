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
#include "genz-probe.h"
#include "genz-sysfs.h"

/* Global list of struct genz_fabric. Protected by semaphore genz_fabrics_sem */
LIST_HEAD(genz_fabrics);
DECLARE_RWSEM(genz_fabrics_sem);

static void fabric_release(struct kref *kref)
{
	struct genz_fabric *fab;

	fab = to_genz_fabric(kref);
	kfree(fab);
}

static struct genz_fabric *genz_alloc_fabric(void)
{
	struct genz_fabric *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return NULL;

        INIT_LIST_HEAD(&f->subnets);
        INIT_LIST_HEAD(&f->components);
        INIT_LIST_HEAD(&f->devices);
        INIT_LIST_HEAD(&f->bridges);

        return f;
}

static int genz_init_fabric(struct genz_fabric *f,
		uint32_t fabric_num)
{
	int ret = 0;

	f->number = fabric_num;
//	init_rwsem(&f->subnet_sem);
//	kref_init(&f->kref);
//	kref_get(&f->kref);

	/*
         * The /sys/devices/genz<N> directory is created by adding a
         * struct device. This is not claimed by driver. We use the device's
         * kobject as the parent for the sysfs tree. Use device_put on this
         * fabric device when the zdev is done being used.
         */
        /* setting the bus and id uses simple enumeration to get genz<N> */
        f->dev.bus = &genz_bus_type;
        f->dev.id = fabric_num;
	f->dev.release = genz_free_fabric;
	f->dev.parent = NULL;
	dev_set_name(&f->dev, "genz%d", fabric_num);

        ret = device_register(&f->dev);
	if (ret) {
		pr_debug( "device_register failed with %d\n", ret);
		put_device(&f->dev);
		return ret;
	}
	
	return ret;
}


void genz_free_fabric(struct device *dev)
{
	struct genz_fabric *f;

	f = container_of(dev, struct genz_fabric, dev);

// Revisit:	down_write(&genz_fabrics_sem);
	list_del(&f->node);
// Revisit:	up_write(&genz_fabrics_sem);
//	kref_put(&f->kref, fabric_release);
}

struct genz_fabric *genz_find_fabric(uint32_t fabric_num)
{
	struct genz_fabric *f, *found = NULL;
	int ret = 0;
	
	pr_debug( "entering %s", __func__);
//	down_read(&genz_fabrics_sem);
	list_for_each_entry(f, &genz_fabrics, node) {
		if (f->number == fabric_num) {
			found = f;
//			kref_get(&found->kref);
			break;
		}
	}
//	up_read(&genz_fabrics_sem);
	if (!found) {
		pr_debug( "fabric_num %d is not in the list\n", fabric_num);
		/* make sure this has not already been added. */
		list_for_each_entry(f, &genz_fabrics, node) {
			if (f->number == fabric_num) {
				/* Already got added */
				found = f;
//				kref_get(&found->kref);
				goto out;
			}
		}
		pr_debug( "fabric_num %d is still not in the list\n", fabric_num);
		/* Allocate a new genz_fabric and add to list */
		/* Revisit: add a flag that is it initialized. Set to UNINIT in the alloc call. take lock and add to list. do init_fabric. Take lock, Set to INITED in init_fabric, release lock.  */
		found = genz_alloc_fabric();
		if (!found) {
			pr_debug( "genz_alloc_fabric returned %d\n", ret);
			goto out;
		}
		ret = genz_init_fabric(found, fabric_num);
		if (ret) {
			/* Revisit: free everything up */
			pr_debug( "genz_init_fabric returned %d\n", ret);
			found = NULL;
			goto out;
		}
//		down_write(&genz_fabrics_sem);
		list_add_tail(&found->node, &genz_fabrics);
//		up_write(&genz_fabrics_sem);
	}
	return found;
out:
//	up_write(&genz_fabrics_sem);
	return found;

}

struct genz_fabric * genz_dev_to_fabric(struct device *dev)
{
	struct genz_fabric *fab;

	list_for_each_entry(fab, &genz_fabrics, node) {
		if (&fab->dev == dev) {
			return fab;
		}
	}
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

static ssize_t subnet_attr_show(struct kobject *kobj,
                             struct attribute *attr,
                             char *buf)
{
        struct genz_subnet_attribute *attribute;
        struct genz_subnet *s;

        attribute = to_genz_subnet_attr(attr);
        s = to_genz_subnet(kobj);

        if (!attribute->show)
                return -EIO;

        return attribute->show(s, attribute, buf);
}

static void subnet_release(struct kobject *kobj)
{
	struct genz_subnet *s;

	s = to_genz_subnet(kobj);
//	down_write(&s->fabric->subnet_sem);
	list_del(&s->node);
//	up_write(&s->fabric->subnet_sem);
	kfree(s);
}

static const struct sysfs_ops subnet_sysfs_ops = {
	.show = subnet_attr_show,
};
static struct kobj_type subnet_ktype = {
	.sysfs_ops = &subnet_sysfs_ops,
	.release = subnet_release,
};

static int genz_init_subnet(struct genz_subnet *s,
		uint32_t sid, struct genz_fabric *f)
{
	int ret = 0;

        s->sid = sid;
	s->fabric = f;

        ret = kobject_init_and_add(&s->kobj, &subnet_ktype, &f->dev.kobj, "%04d", sid);
	if (ret) {
		kobject_put(&s->kobj);
		pr_debug( "%s: sid %d is not in the subnets list yet\n", __func__, sid);
		return ret;
	}
	kobject_uevent(&s->kobj, KOBJ_ADD);
	/* Revisit: add the node to the fabric subnets list */
	
	return ret;
}

struct genz_subnet *genz_find_subnet(uint32_t sid, struct genz_fabric *f)
{
	struct genz_subnet *s, *found = NULL;
	int ret = 0;
	
	pr_debug( "in %s\n", __func__);
//	down_read(&f->subnet_sem);
	list_for_each_entry(s, &f->subnets, node) {
		if (s->sid == sid) {
			found = s;
//			kobject_get(&found->kobj);
			break;
		}
	}
	pr_debug( "sid %d is not in the subnets list yet\n", sid);
//	up_read(&f->subnet_sem);
	if (!found) {
		/* Allocate a new genz_subnet and add to list */
		found = genz_alloc_subnet();
		if (!found) {
//			up_write(&f->subnet_sem);
			pr_debug( "alloc_subnet failed\n");
			return found;
		}
		ret = genz_init_subnet(found, sid, f);
		if (ret) {
//		down_write(&f->subnet_sem);
		/* make sure this has not already been added. */
			pr_debug( "init_subnet failed\n");
			return NULL;
		}
		list_add_tail(&found->node, &f->subnets);
		pr_debug( "added to the subnet list\n");
//		up_write(&f->subnet_sem);
	}
	return found;
}

#ifdef NOT_YET
static struct genz_fru *genz_alloc_fru(void)
{
	struct genz_fru *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return NULL;

        INIT_LIST_HEAD(&f->node);

        return f;
}

static ssize_t fru_attr_show(struct kobject *kobj,
                             struct attribute *attr,
                             char *buf)
{
        struct genz_fru_attribute *attribute;
        struct genz_fru *f;

        attribute = to_genz_fru_attr(attr);
        f = to_genz_fru(kobj);

        if (!attribute->show)
                return -EIO;

        return attribute->show(f, attribute, buf);
}

static void fru_release(struct kobject *kobj)
{
	struct genz_fru *f;

	f = to_genz_fru(kobj);
//	down_write(&f->fabric->fru_sem);
	list_del(&f->node);
//	up_write(&f->fabric->fru_sem);
	kfree(f);
}

void destroy_genz_fru(struct genz_fru *f)
{
	kobject_put(&f->kobj);
}

static const struct sysfs_ops fru_sysfs_ops = {
	.show = fru_attr_show,
};
static struct kobj_type fru_ktype = {
	.sysfs_ops = &fru_sysfs_ops,
	.release = fru_release,
};

static int genz_init_fru(struct genz_fru *f,
		uuid_t fru_uuid, struct genz_subnet *s)
{
	int ret = 0;

        f->fru_uuid = fru_uuid;
	f->subnet = s;

        ret = kobject_init_and_add(&f->kobj, &fru_ktype, &s->kobj, "%pUb", &fru_uuid);
	if (ret) {
		kobject_put(&f->kobj);
		pr_debug("%s: fru %pUb is not in the frus list yet\n", __func__, &fru_uuid);
		return ret;
	}
	kobject_uevent(&f->kobj, KOBJ_ADD);
	
	/* Revisit: locking on this list? */
	list_add_tail(&f->node, &s->frus);

	return ret;
}

struct genz_fru *genz_find_fru(uuid_t fru_uuid, struct genz_subnet *s)
{
	struct genz_fru *f, *found = NULL;
	int ret = 0;
	
	pr_debug( "entering %s", __func__);
	list_for_each_entry(f, &s->frus, node) {
		if (uuid_equal(&f->fru_uuid, &fru_uuid)) {
			found = f;
			kobject_get(&found->kobj);
			break;
		}
	}
	if (!found) {
		/* Allocate a new genz_fru and add to list */
		/* Revisit: add a flag that is it initialized. Set to UNINIT in the alloc call. take lock and add to list. do init_fru. Take lock, Set to INITED in init_fru, release lock.  */
		found = genz_alloc_fru();
		if (!found) {
			pr_debug( "genz_alloc_fru returned %d\n", ret);
			goto out;
		}
		ret = genz_init_fru(found, fru_uuid, s);
		if (ret) {
			pr_debug( "genz_init_fru returned %d\n", ret);
			kfree(found);
			found = NULL;
			goto out;
		}
	}
	return found;
out:
	return found;
}
#endif

/* Component Attributes */
static ssize_t cclass_show(struct genz_component *comp,
		struct genz_component_attribute *attr,
		char *buf)
{
	if (comp == NULL) {
		printk(KERN_ERR "comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%d\n", comp->cclass));
}

static struct genz_component_attribute cclass_attribute =
	__ATTR(cclass, (S_IRUGO), cclass_show, NULL);

static ssize_t gcid_show(struct genz_component *comp,
		struct genz_component_attribute *attr,
		char *buf)
{
	printk(KERN_ERR "comp is %px\n", comp);

	if (comp == NULL) {
		printk(KERN_ERR "comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	if (comp->subnet == NULL) {
		printk(KERN_ERR "comp->subnet is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component subnet\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%04x:%03x\n", comp->subnet->sid, comp->cid));
}

static struct genz_component_attribute gcid_attribute =
	__ATTR(gcid, (S_IRUGO), gcid_show, NULL);

int genz_create_gcid_file(struct kobject *kobj)
{
	int ret = 0;

	printk(KERN_ERR "%s: create_file for kobj %px\n", __func__, kobj);
	ret = sysfs_create_file(kobj, &gcid_attribute.attr);
	return ret;
}

static ssize_t fru_uuid_show(struct genz_component *comp,
		struct genz_component_attribute *attr,
		char *buf)
{
	printk(KERN_ERR "comp is %px\n", comp);

	if (comp == NULL) {
		printk(KERN_ERR "comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%pUb\n", &comp->fru_uuid));
}

static struct genz_component_attribute fru_uuid_attribute =
	__ATTR(fru_uuid, (S_IRUGO), fru_uuid_show, NULL);

int genz_create_fru_uuid_file(struct kobject *kobj)
{
	int ret = 0;

	printk(KERN_ERR "%s: create_file for kobj %px\n", __func__, kobj);
	ret = sysfs_create_file(kobj, &fru_uuid_attribute.attr);
	return ret;
}

static struct attribute *component_attrs[] = {
	&gcid_attribute.attr,
	&cclass_attribute.attr,
	&fru_uuid_attribute.attr,
	NULL,
};
ATTRIBUTE_GROUPS(component);

static ssize_t component_attr_show(struct kobject *kobj,
                             struct attribute *attr,
                             char *buf)
{
        struct genz_component_attribute *attribute;
        struct genz_component *comp;

        attribute = to_genz_component_attr(attr);
        comp = kobj_to_genz_component(kobj);

        if (!attribute->show)
                return -EIO;

        return attribute->show(comp, attribute, buf);
}
static void component_release(struct kobject *kobj)
{
	struct genz_component *comp;

	comp = kobj_to_genz_component(kobj);
	/* Revisit: remove from fabric list */
	kfree(comp);
}

static const struct sysfs_ops component_sysfs_ops = {
	.show = component_attr_show,
};
static struct kobj_type component_ktype = {
	.sysfs_ops = &component_sysfs_ops,
	.release = component_release,
	.default_groups = component_groups,
};

struct genz_component *genz_alloc_component(void)
{
	struct genz_component *zcomp;

	zcomp = kzalloc(sizeof(*zcomp), GFP_KERNEL);
	if (!zcomp)
		return NULL;

	kref_init(&zcomp->kref);
        INIT_LIST_HEAD(&zcomp->control_zres_list);
        INIT_LIST_HEAD(&zcomp->data_zres_list);
	return(zcomp);
}

int genz_init_component(struct genz_component *zcomp,
		struct genz_subnet *s,
		uint32_t cid)
{
	int ret = 0;

	zcomp->subnet = s;
	zcomp->cid = cid;
        ret = kobject_init_and_add(&zcomp->kobj, &component_ktype, &s->kobj, "%03x", cid);
	if (ret) {
		pr_debug( "%s: kobject_init_and_add failed for cid %d\n",
			 __func__, cid);
		kobject_put(&zcomp->kobj);
		return ret;
	}

	kobject_uevent(&zcomp->kobj, KOBJ_ADD);

	printk(KERN_ERR "component kobj is %px\n", &(zcomp->kobj));
	printk(KERN_ERR "subnet kobj is %px\n", &(s->kobj));
	/* Revisit: add the fab_comp_node to the fabric component list */
	kref_init(&zcomp->kref);
	return(ret);
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

int genz_device_add(struct genz_dev *zdev)
{
	int ret;
	
	device_initialize(&zdev->dev);
	zdev->dev.release = genz_release_dev;

	ret = device_add(&zdev->dev);
	return ret;
}
EXPORT_SYMBOL(genz_device_add);
