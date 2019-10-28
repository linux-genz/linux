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
#include "genz-netlink.h"
#include "genz-control.h"

/* Global list of struct genz_fabric. Protected by semaphore genz_fabrics_sem */
LIST_HEAD(genz_fabrics);
DECLARE_RWSEM(genz_fabrics_sem);

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

	pr_debug("genz_free_fabric %s\n", dev_name(dev));
	list_del(&f->node);
}

struct genz_fabric *genz_find_fabric(uint32_t fabric_num)
{
	struct genz_fabric *f, *found = NULL;
	int ret = 0;
	
	pr_debug( "entering %s", __func__);
	list_for_each_entry(f, &genz_fabrics, node) {
		if (f->number == fabric_num) {
			found = f;
			break;
		}
	}
	if (!found) {
		pr_debug( "fabric_num %d is not in the list\n", fabric_num);
		/* make sure this has not already been added. */
		list_for_each_entry(f, &genz_fabrics, node) {
			if (f->number == fabric_num) {
				/* Already got added */
				found = f;
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
		list_add_tail(&found->node, &genz_fabrics);
	}
	return found;
out:
	return found;

}

struct genz_fabric *genz_dev_to_fabric(struct device *dev)
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

void genz_free_subnet(struct device *dev)
{
	struct genz_subnet *s;

	pr_debug("genz_free_subnet %s\n", dev_name(dev));
	s = container_of(dev, struct genz_subnet, dev);

	list_del(&s->node);
	kfree(s);
}

static int genz_init_subnet(struct genz_subnet *s,
		uint32_t sid, struct genz_fabric *f)
{
	int ret = 0;

        s->sid = sid;
	s->fabric = f;
        s->dev.bus = &genz_bus_type;
        s->dev.id = sid;
	s->dev.release = genz_free_subnet;
	s->dev.parent = &f->dev;
	dev_set_name(&s->dev, "%04x", sid);

        ret = device_register(&s->dev);
	if (ret) {
		pr_debug( "device_register failed with %d\n", ret);
		put_device(&s->dev);
		return ret;
	}
	return ret;
}

struct genz_subnet *genz_find_subnet(uint32_t sid, struct genz_fabric *f)
{
	struct genz_subnet *s, *found = NULL;
	int ret = 0;
	
	pr_debug( "in %s\n", __func__);
	list_for_each_entry(s, &f->subnets, node) {
		if (s->sid == sid) {
			found = s;
			break;
		}
	}
	pr_debug( "sid %d is not in the subnets list yet\n", sid);
	if (!found) {
		/* Allocate a new genz_subnet and add to list */
		found = genz_alloc_subnet();
		if (!found) {
			pr_debug( "alloc_subnet failed\n");
			return found;
		}
		ret = genz_init_subnet(found, sid, f);
		if (ret) {
		/* make sure this has not already been added. */
			pr_debug( "init_subnet failed\n");
			return NULL;
		}
		list_add_tail(&found->node, &f->subnets);
		pr_debug( "added to the subnet list\n");
	}
	return found;
}

/* Component Attributes */
static ssize_t cclass_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct genz_component *comp;

	comp = dev_to_genz_component(dev);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%d\n", comp->cclass));
}
static DEVICE_ATTR(cclass, (S_IRUGO), cclass_show, NULL);

static ssize_t gcid_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct genz_component *comp;

	comp = dev_to_genz_component(dev);
	pr_debug("comp is %px\n", comp);

	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	if (comp->subnet == NULL) {
		pr_debug("comp->subnet is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component subnet\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%04x:%03x\n", comp->subnet->sid, comp->cid));
}
static DEVICE_ATTR(gcid, (S_IRUGO), gcid_show, NULL);

static ssize_t fru_uuid_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct genz_component *comp;

	comp = dev_to_genz_component(dev);
	pr_debug("comp is %px\n", comp);

	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%pUb\n", &comp->fru_uuid));
}
static DEVICE_ATTR(fru_uuid, (S_IRUGO), fru_uuid_show, NULL);

static int genz_create_component_files(struct device *dev)
{
	int ret = 0;

	pr_debug("%s: create_file for device %px\n", __func__, dev);
	ret = device_create_file(dev, &dev_attr_gcid);
	ret = device_create_file(dev, &dev_attr_cclass);
	ret = device_create_file(dev, &dev_attr_fru_uuid);
	return ret;
}

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

void genz_free_comp(struct device *dev)
{
	struct genz_component *c;

	pr_debug("genz_free_comp %s\n", dev_name(dev));

	c = container_of(dev, struct genz_component, dev);

	list_del(&c->fab_comp_node);
	kfree(c);
}


int genz_init_component(struct genz_component *zcomp,
		struct genz_subnet *s,
		uint32_t cid)
{
	int ret = 0;

	zcomp->subnet = s;
	zcomp->cid = cid;
        zcomp->dev.bus = &genz_bus_type;
        zcomp->dev.id = cid;
	zcomp->dev.release = genz_free_comp;
	zcomp->dev.parent = &s->dev;
	dev_set_name(&zcomp->dev, "%03x", cid);
	pr_debug("in genz_init_component name is cid %03x\n", cid);
        ret = device_register(&zcomp->dev);
	if (ret) {
		pr_debug( "device_register failed with %d\n", ret);
		put_device(&zcomp->dev);
		return ret;
	}
	pr_debug("component kobj is %px\n", &(zcomp->dev.kobj));
	pr_debug("subnet kobj is %px\n", &(s->dev.kobj));

	/* Revisit: add the fab_comp_node to the fabric component list */
	kref_init(&zcomp->kref);
	genz_create_component_files(&zcomp->dev);
	return(ret);
}

struct genz_component *genz_find_component(struct genz_subnet *s,
               uint32_t cid)
{
       struct genz_component *c, *found = NULL;
       int ret = 0;
       
       pr_debug( "in %s\n", __func__);
       list_for_each_entry(c, &s->fabric->components, fab_comp_node) {
               if (c->cid == cid) {
                       found = c;
                       break;
               }
       }
       pr_debug( "cid %d is not in the components list yet\n", cid);
       if (!found) {
               /* Allocate a new genz_component and add to list */
               found = genz_alloc_component();
               if (!found) {
                       pr_debug( "alloc_componenet failed\n");
                       return found;
               }
               ret = genz_init_component(found, s, cid);
               if (ret) {
               /* make sure this has not already been added. */
                       pr_debug( "init_component failed\n");
                       return NULL;
               }
               list_add_tail(&found->fab_comp_node, &s->fabric->components);
               pr_debug( "added to the component list\n");
       }
       return found;
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

	pr_debug("genz_release_dev %s\n", dev_name(dev));
        zdev = to_genz_dev(dev);
	if (zdev == NULL)
		return;

	/* remove from the list of devices in the genz_fabric */
        list_del(&zdev->fab_dev_node);

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

int genz_device_add(struct genz_dev *zdev)
{
	int ret;
	
        zdev->dev.bus = &genz_bus_type;
	zdev->dev.parent = &zdev->zcomp->dev;
	zdev->dev.release = genz_release_dev;
	device_initialize(&zdev->dev);

	ret = device_add(&zdev->dev);
	if (ret)
		pr_debug("device_add failed with %d\n", ret);
	return ret;
}

int genz_device_uuid_add(struct genz_dev *zdev)
{
	int status = 0;
	struct uuid_tracker *uu;

	/* Revisit: validate uuid is set */
	uu = genz_uuid_tracker_alloc(&zdev->uuid,
			UUID_TYPE_ZDEVICE,
			GFP_KERNEL,
			&status);
	if (status) {
		return(status);
	}

	uu = genz_uuid_tracker_insert(uu, &status);
	if (status) {
		return(status);
	}
	/* add this device to the zdev_list */
	/* Revisit: locking this list */
	list_add(&zdev->uu_node, uu->zdev_list);

	/* match with driver and call probe if a match is found */
	return 0;
}

int genz_driver_uuid_remove(struct genz_driver *zdrv)
{
	/* Revisit: free zaux ++ */
	return 0;
}

int genz_driver_uuid_add(struct genz_driver *zdrv)
{
	int ret = 0;
	int status = 0;
	struct uuid_tracker *uu;
	struct genz_device_id *zid;
	struct genz_driver_aux *zaux;
	int count = 0;

	for (zid = zdrv->id_table; zid != NULL; zid++) {
		count++;
	}
	zdrv->zaux = kzalloc(sizeof(*zdrv->zaux)*count, GFP_KERNEL);
	if (!zdrv->zaux) {
		return -ENOMEM;
	}
	for (zid = zdrv->id_table, zaux = zdrv->zaux; zid != NULL;
				zid++, zaux++) {
		ret = uuid_parse(zid->uuid_str, &zaux->uuid);
		zaux->zdrv = zdrv;
		zaux->zid = zid;

		if (ret) {
			pr_debug("%pUb uuid_parse failed in genz_driver_uuid_add\n", zid->uuid_str);
			continue;
		}
		/* Revisit: validate uuid is set */
		uu = genz_uuid_tracker_alloc(&zaux->uuid,
				UUID_TYPE_ZDEVICE,
				GFP_KERNEL,
				&status);
		if (status) {
			return(status);
		}
	
		uu = genz_uuid_tracker_insert(uu, &status);
		if (status) {
			return(status);
		}
		/* add this device to the zdrv_list */
		/* Revisit: locking this list */
		list_add(&zaux->uu_node, uu->zdrv_list);
	}

	/* match with driver and call probe if a match is found */
	return 0;
}

static int call_probe (struct genz_dev *zdev,
		struct genz_driver *zdrv,
		struct genz_device_id *zid)
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

int genz_match_driver_uuid(struct genz_driver *zdrv)
{
	struct uuid_tracker *uu;
	struct genz_device_id *zid;
	struct genz_dev *zdev;
	struct genz_driver_aux *zaux;
	int ret = 0;

	for (zid = zdrv->id_table, zaux = zdrv->zaux; zid != NULL;
				zid++, zaux++) {
		uu = genz_uuid_search(&zaux->uuid);
		if (!uu) {
			dev_warn(&zdev->dev, "%pUb zdev uuid not in uuid tracker\n",
					&zaux->uuid);
			continue;
		}
		/* uuid tracker has a list of devices */
		list_for_each_entry(zdev, uu->zdev_list, uu_node) {
			/* call driver probe */
			ret = call_probe(zdev, zdrv, zid);
			/* Revisit better message with driver name */
			dev_dbg(&zdev->dev, "Driver probe function returned %d\n", ret);
		}
	}
	/* Revisit: what should it return? Maybe be a void function? */
	return 0;
}

int genz_match_device_uuid(struct genz_dev *zdev)
{
	struct uuid_tracker *uu;
	struct genz_driver_aux *zaux;
	int ret = 0;

	/* for each driver look for match of this zdev->uuid */
	uu = genz_uuid_search(&zdev->uuid);
	if (!uu) {
		dev_warn(&zdev->dev, "%pUb zdev uuid not in uuid tracker\n",
				&zdev->uuid);
		return -EINVAL;
	}
	list_for_each_entry(zaux, uu->zdrv_list, uu_node) {
		ret = call_probe(zdev, zaux->zdrv, zaux->zid);
		/* Revisit better message with driver name */
		dev_dbg(&zdev->dev, "Driver probe function returned %d\n", ret);
	}
	/* Revisit: what should it return? Maybe be a void function? */
	return 0;
}

