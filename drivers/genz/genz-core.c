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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "genz.h"
#include "genz-control.h"
#include "genz-netlink.h"
#include "genz-probe.h"

/* Revisit: make these dynamic and per-bridge somehow */
#define REQ_ZMMU_ENTRIES             (1024)
#define RSP_ZMMU_ENTRIES             (1024)

static int no_genz;
module_param(no_genz, int, 0444);
MODULE_PARM_DESC(no_genz, "Disable genz (default 0)");

static char *req_page_grid = "4K:384,2M:256,1G:256,128T^128";
module_param(req_page_grid, charp, 0444);
MODULE_PARM_DESC(req_page_grid, "requester page grid allocations - page_sz{^*:}page_cnt[, ...]");

static char *rsp_page_grid = "4K:448,128T^64,1G:256,2M:256";
module_param(rsp_page_grid, charp, 0444);
MODULE_PARM_DESC(rsp_page_grid, "responder page grid allocations - page_sz{^:}page_cnt[, ...]");

/**
 * genz_disabled - determine if the Gen-Z sub-system is disabled
 *
 * The Gen-Z sub-system can abe disabled through a module parameter
 * called "no_genz". This function returns the state of that parameter.
 *
 * Return:
 * 0 - Gen-Z is enabled
 * 1 - Gen-Z is disabled
 */
int genz_disabled(void)
{
	return no_genz;
}
EXPORT_SYMBOL_GPL(genz_disabled);

char *genz_gcid_str(const uint32_t gcid, char *str, const size_t len)
{
	snprintf(str, len, "%04x", gcid >> 12);
	if (len > 4)
		str[4] = ':';
	snprintf(str+5, len-5, "%03x", gcid & 0xfff);
	return str;
}
EXPORT_SYMBOL_GPL(genz_gcid_str);

/**
 * genz_validate_structure_type - check structure type
 * @int type: the structure type field
 *
 * The Gen-Z control space structures contains a 12 bit type field
 * at bit 0. The type identifies the Gen-Z control structure.
 * This function validates that the type field is a known value.
 *
 * Return:
 * 0 - the given type is invalid
 * 1 - the given type is valid
 */
int genz_validate_structure_type(int type)
{
	/* Use the genz_struct_type_to_ptrs array to check type */
	if (type < 0 || type > genz_struct_type_to_ptrs_nelems)
		return(0);
	/*
	 * If there is a hole in the array, then it has a NULL entry. Make
	 * sure this type has a valid entry.
	 */
	return (genz_struct_type_to_ptrs[type].ptr != NULL);
}
EXPORT_SYMBOL_GPL(genz_validate_structure_type);

static int genz_bus_match(struct device *dev, struct device_driver *drv)
{
	struct genz_dev    *zdev = to_genz_dev(dev);
	struct genz_driver *zdrv = to_genz_driver(drv);
	const struct genz_device_id *match;

	pr_debug("entered\n");
	match = genz_match_device(zdrv, zdev);
	if (match)
		return 1;
	return 0;
}

static int genz_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct genz_dev *zdev;

	/* Revisit: use this for hot-add/delete */
	if (!dev)
		return -ENODEV;
	zdev = to_genz_dev(dev);
	if (add_uevent_var(env, "GENZ_CLASS_UUID=%pUb", &zdev->class_uuid))
		return -ENOMEM;
	if (add_uevent_var(env, "GENZ_INSTANCE_UUID=%pUb",
				&zdev->instance_uuid))
		return -ENOMEM;
	if (add_uevent_var(env, "GENZ_CLASS=%04x", zdev->class))
		return -ENOMEM;
	if (add_uevent_var(env, "MODALIAS=genz:%pUb", &zdev->class_uuid))
		return -ENOMEM;
	/* Revisit */
	//dev_dbg(dev, "uuid=%pUb class=%u\n", &zdev->uuid, zdev->class);
	return 0;
}

static void genz_shutdown(struct device *dev)
{
	dev_dbg(dev, "entered\n");
	/* Revisit: finish this */
}

struct bus_type genz_bus_type = {
	.name     =	"genz",
	.match    =	genz_bus_match,
	.uevent   =	genz_uevent,
	.probe    =	genz_device_probe,
	.remove   =	genz_device_remove,
	.shutdown =	genz_shutdown,
};
EXPORT_SYMBOL(genz_bus_type);

/**
 * __genz_register_driver - register a new Gen-Z driver
 * @struct genz_driver *zdrv: the driver structure to register
 * @struct module *module: owner module of the driver
 * @const char *mod_name: module name string
 *
 * Adds the driver structure to the list of registered Gen-Z drivers.
 *
 * Return:
 * Returns 0 on success. Returns a negative value on error.
 */

/* Revisit: change driver to zdrv */
int __genz_register_driver(struct genz_driver *zdrv, struct module *module,
				const char *mod_name)
{
	int ret;
	struct genz_device_id *zids;

	if (genz_disabled())
		return -ENODEV;

	zdrv->driver.name = zdrv->name;
	zdrv->driver.bus = &genz_bus_type;
	zdrv->driver.owner = module;
	zdrv->driver.mod_name = mod_name;

	/* Initialize the uuid_t in the genz_device_id list */
	zids = zdrv->id_table;
	if (zids) {
		while (!uuid_is_null(&zids->uuid) ||
			(zids->uuid_str && uuid_is_valid(zids->uuid_str))) {
			if (uuid_is_null(&zids->uuid))
				uuid_parse(zids->uuid_str, &zids->uuid);
			zids++;
		}
	}

	ret = driver_register(&zdrv->driver);
	if (ret) {
		/* Revisit: undo the uuid_add too */
		pr_debug("driver_register for genz driver %s failed with %d\n",
			zdrv->name, ret);
		return ret;
	}

	pr_info("Registered new genz driver %s\n", zdrv->name);
	return 0;
}
EXPORT_SYMBOL(__genz_register_driver);

/**
 * __genz_unregister_driver - unregister a Gen-Z driver
 * @struct genz_driver *zdrv: the driver structure to unregister
 *
 * Deletes the driver structure from the list of registered Gen-Z drivers.
 * The driver's remove function will be called for each device it was
 * responsible for. Those devices are then marked as driverless.
 */
void __genz_unregister_driver(struct genz_driver *zdrv)
{
	driver_unregister(&zdrv->driver);
}
EXPORT_SYMBOL(__genz_unregister_driver);

static atomic_t __bridge_number = ATOMIC_INIT(0);
static int get_new_bridge_number(void)
{
        return atomic_inc_return(&__bridge_number) - 1;
}

static int initialize_zbdev(struct genz_bridge_dev *zbdev,
			    struct device *dev,
			    struct genz_bridge_driver *zbdrv,
			    void *driver_data)
{
	struct uuid_tracker *uu;
	uuid_t mgr_uuid;
	uint16_t sid, cid;
	int ret = 0;
	struct genz_subnet *s;
	unsigned long flags;
	struct genz_fabric *f;

	zbdev->zbdrv = zbdrv;
	zbdev->zdev.zdrv = &zbdrv->zdrv;
	zbdev->zdev.zbdev = zbdev;
	zbdev->bridge_dev = dev;
	zbdev->bridge_num = get_new_bridge_number();
	spin_lock_init(&zbdev->zmmu_lock);
	dev_set_drvdata(&zbdev->zdev.dev, driver_data);

	genz_control_read_structure(&zbdev->zdev, &mgr_uuid, 0,
			offsetof(struct genz_core_structure, mgr_uuid),
			sizeof(mgr_uuid));
	uu = genz_fabric_uuid_tracker_alloc_and_insert(&mgr_uuid);
	if (!uu) {
		return -ENOMEM;
	}
	f = zbdev->fabric = uu->fabric->fabric;
	if (f == NULL) {
		pr_debug("fabric is NULL\n");
		ret = -ENODEV;
		goto error;
	}
	spin_lock_irqsave(&f->bridges_lock, flags);
	list_add_tail(&zbdev->fab_bridge_node, &f->bridges);
	spin_unlock_irqrestore(&f->bridges_lock, flags);
	spin_lock_irqsave(&f->devices_lock, flags);
	list_add_tail(&zbdev->zdev.fab_dev_node, &f->devices);
	spin_unlock_irqrestore(&f->devices_lock, flags);
	ret = genz_control_read_sid(&zbdev->zdev, &sid);
	if (ret) {
		pr_debug("genz_control_read_sid returned %d\n", ret);
		goto error;
	}
	s = genz_add_subnet(sid, f);
	if (s == NULL) {
		pr_debug("genz_add_subnet failed\n");
		ret = -ENOMEM;
		goto error;
	}
	ret = genz_control_read_cid0(&zbdev->zdev, &cid);
	if (ret) {
		pr_debug("genz_control_read_cid returned %d\n", ret);
		goto error;
	}
	zbdev->zdev.zcomp = genz_add_component(s, cid);
	if (zbdev->zdev.zcomp == NULL) {
		pr_debug("genz_add_component failed\n");
		ret = -ENOMEM;
		goto error;
	}
	ret = genz_init_dev(&zbdev->zdev, f);
	if (ret) {
		pr_debug("genz_init_dev failed %d\n", ret);
		goto error;
	}
	/* Revisit: add the bridge number */
	dev_set_name(&zbdev->zdev.dev, "bridge0");
	ret = genz_device_add(&zbdev->zdev);
	if (ret) {
		pr_debug("genz_device_add failed %d\n", ret);
		goto error;
	}
	ret = genz_control_read_cclass(&zbdev->zdev, &zbdev->zdev.zcomp->cclass);
	if (ret) {
		pr_debug("genz_control_read_cclass returned %d\n", ret);
		goto error;
	}
	ret = genz_control_read_fru_uuid(&zbdev->zdev, &zbdev->zdev.zcomp->fru_uuid);
	if (ret) {
		pr_debug("genz_control_read_fru_uuid returned %d\n", ret);
		goto error;
	}
	return ret;
error:
	genz_free_component(&zbdev->zdev.zcomp->kref);
	return ret;
}

static int genz_bridge_zmmu_setup(struct genz_bridge_dev *br);
static int genz_bridge_zmmu_clear(struct genz_bridge_dev *br);
LIST_HEAD(genz_bridge_list);

/**
 * genz_register_bridge - register a new Gen-Z bridge driver
 * @struct device *dev: the device structure to register
 * @struct genz_driver *zbdrv: the Gen-Z driver structure to register
 * @void *driver_data: pointer to private driver data
 *
 * A driver calls genz_register_bridge() during probe of a device that
 * is a bridge component. This marks the bridge component as a bridge
 * so that a fabric manager can discover it through sysfs files named
 * 'bridgeN'. Typically a bridge device driver is a PCI device (for example)
 * and the driver is both a PCI driver and a Gen-Z driver. The driver_data
 * will be installed into the genz_bridge_dev before any callbacks are called.
 *
 * Return:
 * Returns 0 on success. Returns a negative value on error.
 */
int genz_register_bridge(struct device *dev, struct genz_bridge_driver *zbdrv,
			 void *driver_data)
{
	int ret = 0;
	struct genz_bridge_dev *zbdev;
	struct genz_bridge_info *info;

	/* Allocate a genz_bridge_dev */
	/* Revisist: need an genz_allocate_bridge_dev() */
	zbdev = kzalloc(sizeof(*zbdev), GFP_KERNEL);
	if (zbdev == NULL)
		return -ENOMEM;

	dev_dbg(dev, "entered, zbdrv=%px, driver_data=%px, zbdev=%px\n",
		zbdrv, driver_data, zbdev);
	/* Initialize the genz_bridge_dev */
	ret = initialize_zbdev(zbdev, dev, zbdrv, driver_data);
	if (ret < 0) {
		kfree(zbdev);
		return ret;
	}

	info = &zbdev->br_info;
	ret = zbdrv->bridge_info(&zbdev->zdev, &zbdev->br_info);
	dev_dbg(dev,
		"bridge_info: ret=%d, req_zmmu=%u, rsp_zmmu=%u, xdm=%u, rdm=%u, nr_req_page_grids=%u, nr_rsp_page_grids=%u, nr_req_ptes=%llu, nr_rsp_ptes=%llu\n",
		ret, info->req_zmmu, info->rsp_zmmu, info->xdm, info->rdm,
		info->nr_req_page_grids, info->nr_rsp_page_grids,
		info->nr_req_ptes, info->nr_rsp_ptes);
	if (ret < 0)
		goto out; /* Revisit: properly undo stuff */

	if (info->load_store) {
		zbdev->ld_st_res.start = info->min_cpuvisible_addr +
			info->cpuvisible_phys_offset;
		zbdev->ld_st_res.end = info->max_cpuvisible_addr +
			info->cpuvisible_phys_offset;
		zbdev->ld_st_res.name = "Gen-Z bridge0";  /* Revisit: bridge number */
		zbdev->ld_st_res.flags = IORESOURCE_MEM;
		ret = insert_resource(&iomem_resource, &zbdev->ld_st_res);
		if (ret < 0) {
			pr_debug("insert_resource failed: ret=%d, iomem_resource=%px, ld_st_res=%px, iomem_resource.start=0x%llx, iomem_resource.end=0x%llx, ld_st_res.start=0x%llx, ld_st_res.end=0x%llx\n",
				 ret, &iomem_resource, &zbdev->ld_st_res,
				 iomem_resource.start, iomem_resource.end,
				 zbdev->ld_st_res.start, zbdev->ld_st_res.end);
			/* Revisit: error handling */
		}
	}
	ret = genz_bridge_zmmu_setup(zbdev);
	if (ret < 0) {
		pr_debug("genz_bridge_zmmu_setup failed, ret=%d\n", ret);
		goto out; /* Revisit: properly undo stuff */
	}

	ret = genz_bridge_create_control_files(zbdev);
	/* Revisit: handle errors */

	/* add zbdev to global list */
	/* Revisit: locking */
	list_add(&zbdev->bridge_node, &genz_bridge_list);

out:
	return ret;
}
EXPORT_SYMBOL(genz_register_bridge);

struct genz_bridge_dev *genz_find_bridge(struct device *dev)
{
	struct genz_bridge_dev *zbdev = NULL, *cur;

	/* dev is the native bridge dev - find corresponding genz_bridge_dev */
	/* Revisit: locking */
	list_for_each_entry(cur, &genz_bridge_list, bridge_node) {
		if (cur->bridge_dev == dev) {
			zbdev = cur;
			break;
		}
	}

	return zbdev;
}
EXPORT_SYMBOL(genz_find_bridge);

/**
 * genz_unregister_bridge - unregister a Gen-Z bridge driver
 * @struct device *dev: the native device originally passed to
 *		genz_register_bridge
 *
 * A driver calls genz_unregister_bridge() to unregister a bridge
 * device with the Gen-Z sub-system. Typically a bridge device driver
 * is a PCI device (for example) and the driver is both a PCI driver and
 * a Gen-Z driver. The driver must call the appropriate native bus "unregister"
 * function after calling genz_unregister_bridge(), e.g.
 * pci_unregister_driver().
 *
 * Return:
 * Returns 0 on success. Returns a negative value on error.
 */
int genz_unregister_bridge(struct device *dev)
{
	int ret = 0;
	struct genz_bridge_dev *zbdev;

	/* dev is the native bridge dev - find corresponding genz_bridge_dev */
	/* Revisit: locking */
	zbdev = genz_find_bridge(dev);
	if (zbdev) {
		genz_bridge_zmmu_clear(zbdev);
		list_del(&zbdev->bridge_node);
		list_del(&zbdev->zdev.fab_dev_node);
		genz_fabric_uuid_tracker_free(&zbdev->fabric->mgr_uuid);
		genz_bridge_remove_control_files(zbdev);
		genz_bridge_zmmu_clear(zbdev);
		remove_resource(&zbdev->ld_st_res);
		kfree(zbdev);
	} else {
		ret = -ENODEV;
	}

	return ret;
}
EXPORT_SYMBOL(genz_unregister_bridge);

struct genz_bridge_dev *genz_zdev_bridge(struct genz_dev *zdev)
{
	struct genz_bridge_dev *zbdev = NULL;
	struct genz_fabric *fabric;
	unsigned long flags;

	pr_debug("zdev->zcomp is %px\n", zdev->zcomp);
	pr_debug("zdev->zcomp->subnet is %px\n", zdev->zcomp->subnet);
	pr_debug("zdev->zcomp->subnet->fabric is %px\n", zdev->zcomp->subnet->fabric);

	fabric = zdev->zcomp->subnet->fabric;
	dev_dbg(&zdev->dev, "fabric=%px\n", fabric);

	/* Revisit: do something smarter than "first_entry" */
	spin_lock_irqsave(&fabric->bridges_lock, flags);
	if (fabric && !list_empty(&fabric->bridges)) {
		zbdev = list_first_entry(&fabric->bridges,
					 struct genz_bridge_dev,
					 fab_bridge_node);
	}
	spin_unlock_irqrestore(&fabric->bridges_lock, flags);

	dev_dbg(&zdev->dev, "zbdev=%px\n", zbdev);
	return zbdev;
}

static struct genz_page_grid req_parse_pg[PAGE_GRID_ENTRIES];
static struct genz_page_grid rsp_parse_pg[PAGE_GRID_ENTRIES];
static uint req_pg_cnt, rsp_pg_cnt;

static void __init genz_parse_page_grids(void)
{
	pr_debug("req calling parse_page_grid_opt(%s, %u, %px)\n",
		 req_page_grid, REQ_ZMMU_ENTRIES, req_parse_pg);
	req_pg_cnt = genz_parse_page_grid_opt(req_page_grid, REQ_ZMMU_ENTRIES,
					      true, req_parse_pg);
	pr_debug("rsp calling parse_page_grid_opt(%s, %u, %px)\n",
		 rsp_page_grid, RSP_ZMMU_ENTRIES, rsp_parse_pg);
	rsp_pg_cnt = genz_parse_page_grid_opt(rsp_page_grid, RSP_ZMMU_ENTRIES,
					      false, rsp_parse_pg);
}

static int genz_bridge_zmmu_setup(struct genz_bridge_dev *br)
{
	uint pg;
	int pg_index, err = 0;
	bool cleared = false;

	if (br->br_info.req_zmmu) {
		if (br->br_info.nr_req_page_grids) {
			genz_zmmu_clear_all(br, false);
			cleared = true;
			for (pg = 0; pg < req_pg_cnt; pg++) {
				pg_index = genz_req_page_grid_alloc(
					br, &req_parse_pg[pg]);
				if (pg_index < 0) {
					pr_debug("genz_req_page_grid_alloc failed, ret=%d\n",
						 pg_index);
					err = (err == 0) ? pg_index : err;
				}
			}
		}
		/* Revisit: add page table support */
	}

	if (br->br_info.rsp_zmmu) {
		if (br->br_info.nr_rsp_page_grids) {
			if (!cleared)
				genz_zmmu_clear_all(br, false);
			for (pg = 0; pg < rsp_pg_cnt; pg++) {
				pg_index = genz_rsp_page_grid_alloc(
					br, &rsp_parse_pg[pg]);
				if (pg_index < 0) {
					pr_debug("genz_rsp_page_grid_alloc failed, ret=%d\n",
						 pg_index);
					err = (err == 0) ? pg_index : err;
				}
			}
		}
		/* Revisit: add page table support */
	}

	return err;
}

static int genz_bridge_zmmu_clear(struct genz_bridge_dev *br)
{
	if ((br->br_info.req_zmmu && br->br_info.nr_req_page_grids) ||
	    (br->br_info.rsp_zmmu && br->br_info.nr_rsp_page_grids))
		genz_zmmu_clear_all(br, true);
	/* Revisit: finish this */

	return 0;
}

struct genz_resource *genz_get_first_resource(struct genz_dev *zdev)
{
	struct genz_zres *zres;

	if (zdev == NULL)
		return NULL;
	zres = list_first_entry_or_null(&zdev->zres_list,
					struct genz_zres, zres_node);
	if (zres == NULL)
		return NULL;
	return &zres->zres;
}
EXPORT_SYMBOL(genz_get_first_resource);

struct genz_resource *genz_get_next_resource(struct genz_dev *zdev,
		struct genz_resource *res)
{
	struct genz_zres *pos, *zres, *last;

	pos = to_genz_res(res);
	if (pos == NULL) {
		pr_debug("to_genz_res failed\n");
		return NULL;
	}
	last = list_last_entry(&zdev->zres_list, struct genz_zres, zres_node);
	if (pos == last)
		return NULL;
	zres = list_next_entry(pos, zres_node);
	if (zres == NULL)
		return NULL;
	return &zres->zres;
}
EXPORT_SYMBOL(genz_get_next_resource);

/* Revisit: these next 3 should probably be "static inline" in genz.h */
bool genz_is_data_resource(struct genz_resource *res)
{
	return(!(res->res.flags & IORESOURCE_GENZ_CONTROL));
}
EXPORT_SYMBOL(genz_is_data_resource);

bool genz_is_control_resource(struct genz_resource *res)
{
	return(res->res.flags & IORESOURCE_GENZ_CONTROL);
}
EXPORT_SYMBOL(genz_is_control_resource);

const char *genz_resource_name(struct genz_resource *res)
{
	return res->res.name;
}
EXPORT_SYMBOL(genz_resource_name);

uint32_t genz_dev_gcid(struct genz_dev *zdev, uint index)
{
	/* Revisit: handle multiple CIDs */
	if (index != 0 || !zdev->zcomp || !zdev->zcomp->subnet)
		return GENZ_INVALID_GCID;

	return genz_get_gcid(zdev->zcomp->subnet->sid, zdev->zcomp->cid);
}
EXPORT_SYMBOL(genz_dev_gcid);

static void force_dev_cleanup(void)
{
	struct genz_fabric *f, *f_tmp;
	struct genz_bridge_dev *cur, *cur_tmp;

	pr_debug("entered\n");
	/* go through each bridge */
	list_for_each_entry_safe(cur, cur_tmp, &genz_bridge_list, bridge_node) {
		genz_fabric_uuid_tracker_free(&cur->fabric->mgr_uuid);
		genz_bridge_remove_control_files(cur);
		genz_bridge_zmmu_clear(cur);
		/* Revisit: is this done twice?
		device_unregister(&cur->zdev.dev);
		*/
		list_del(&cur->bridge_node);
		kfree(cur);
	}
	/* go through each fabric */
	list_for_each_entry_safe(f, f_tmp, &genz_fabrics, node) {
		struct genz_dev *zdev, *zdev_tmp;
		struct genz_component *zcomp, *zcomp_tmp;
		struct genz_subnet *zsub, *zsub_tmp;

		/* Each fabric has a reference to the mgr_uuid */
		if (&f->mgr_uuid)
			genz_fabric_uuid_tracker_free(&f->mgr_uuid);

		/* remove each genz_dev */
		list_for_each_entry_safe(zdev, zdev_tmp, &f->devices,
				fab_dev_node) {
			device_unregister(&zdev->dev);
		}

		/* remove each component */
		list_for_each_entry_safe(zcomp, zcomp_tmp, &f->components,
				fab_comp_node) {
			device_unregister(&zcomp->dev);
		}

		/* remove each subnet */
		list_for_each_entry_safe(zsub, zsub_tmp, &f->subnets, node) {
			device_unregister(&zsub->dev);
		}

		/* finally remove the fabric device */
		device_unregister(&f->dev);
	}
}

static int __init genz_init(void)
{
	int ret = 0;

	pr_debug("entered\n");

	if (genz_disabled())
		return -ENODEV;

	ret = bus_register(&genz_bus_type);
	if (ret) {
		pr_err("bus_register failed (%d)\n", ret);
		goto error_bus;
	}

	ret = genz_nl_init();
	if (ret) {
		pr_err("genz_nl_init failed (%d)\n", ret);
		goto error_nl;
	}

	genz_parse_page_grids();
	genz_pasid_init();
	genz_rkey_init();

	return ret;
error_nl:
	bus_unregister(&genz_bus_type);
error_bus:
	return ret;
}
module_init(genz_init);

static void __exit genz_exit(void)
{
	pr_debug("entered\n");
	force_dev_cleanup();
	bus_unregister(&genz_bus_type);
	genz_nl_exit();
	genz_rkey_exit();
	genz_pasid_exit();
	genz_uuid_exit();
}

module_exit(genz_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Betty Dall <betty.dall@hpe.com>");
MODULE_AUTHOR("Jim Hull <jim.hull@hpe.com>");
