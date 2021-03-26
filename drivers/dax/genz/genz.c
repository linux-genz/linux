// SPDX-License-Identifier: GPL-2.0
/* © Copyright 2021 IntelliProp Inc. All rights reserved. */
#include <linux/percpu-refcount.h>
#include <linux/memremap.h>
#include <linux/module.h>
#include <linux/pfn_t.h>
#include <linux/genz.h>
#include "../bus.h"

#define DAX_GENZ_DRV_NAME "dax-genz"

static struct genz_device_id dax_genz_id_table[] = {
	{ .uuid_str = "f147276b-c2c1-431e-91af-3031d0039768" },
	{ },
};

MODULE_DEVICE_TABLE(genz, dax_genz_id_table);

static inline void __dax_genz_pfn_size(struct genz_dev *zdev,
			 struct genz_resource *zres,
			 unsigned long *align_p, u32 *end_trunc_p,
			 phys_addr_t *offset_p, unsigned long *npfns_p)
{
	resource_size_t start, size;
	unsigned long npfns, align;
	phys_addr_t offset;
	u32 end_trunc;

	/* Revisit: use zdev->driver_flags to choose PFN_MODE */
	start = zres->res.start;
	size = resource_size(&zres->res);
	npfns = PHYS_PFN(size);
	align = (1UL << SUBSECTION_SHIFT);
	end_trunc = start + size - ALIGN_DOWN(start + size, align);

	offset = ALIGN(start + sizeof(struct page) * npfns, align) - start;
	npfns = PHYS_PFN(size - offset - end_trunc);
	*align_p = align;
	*end_trunc_p = end_trunc;
	*offset_p = offset;
	*npfns_p = npfns;
}

static unsigned long init_altmap_base(resource_size_t base)
{
	unsigned long base_pfn = PHYS_PFN(base);

	return SUBSECTION_ALIGN_DOWN(base_pfn);
}

static unsigned long init_altmap_reserve(resource_size_t base)
{
	unsigned long reserve = 0;
	unsigned long base_pfn = PHYS_PFN(base);

	reserve += base_pfn - SUBSECTION_ALIGN_DOWN(base_pfn);
	return reserve;
}

static int __dax_genz_setup_pfn(struct genz_dev *zdev, struct genz_resource *zres,
				unsigned long align, u32 end_trunc,
				phys_addr_t offset, unsigned long npfns,
				struct dev_pagemap *pgmap)
{
	struct resource *res = &pgmap->res;
	struct vmem_altmap *altmap = &pgmap->altmap;
	resource_size_t base = zres->res.start;
	resource_size_t end = zres->res.end - end_trunc;
	struct vmem_altmap __altmap = {
		.base_pfn = init_altmap_base(base),
		.reserve = init_altmap_reserve(base),
		.end_pfn = PHYS_PFN(end),
	};

	/* Revisit: add support for PFN_MODEs */
	memcpy(res, &zres->res, sizeof(*res));
	res->end -= end_trunc;
	memcpy(altmap, &__altmap, sizeof(*altmap));
	altmap->free = PHYS_PFN(offset);
	altmap->alloc = 0;
	pgmap->flags |= PGMAP_ALTMAP_VALID;
	return 0;
}

struct dev_dax *__dax_genz_probe(struct genz_dev *zdev,
				 struct genz_resource *zres,
				 enum dev_dax_subsys subsys)
{
	struct resource res;
	int ret, id, region_id, target_node;
	resource_size_t offset;
	unsigned long align, npfns;
	struct dev_dax *dev_dax;
	struct dax_region *dax_region;
	struct dev_pagemap pgmap = { };
	struct genz_rmr_info *rmri;
	struct genz_uuid_info *uui;
	struct device *dev = &zdev->dev;
	uint32_t gcid = genz_dev_gcid(zdev, 0);
	uint64_t access;
	u32 end_trunc;

	id = zdev->driver_flags & 0xff;
	region_id = (zdev->driver_flags >> 8) & 0xff;
	target_node = (zdev->driver_flags >> 16) & 0xff;
	dev_dbg(dev, "instance_uuid=%pUb, region_id=%d, id=%d, target_node=%d\n",
		&zdev->instance_uuid, region_id, id, target_node);
	uui = devm_genz_uuid_import(zdev, &zdev->instance_uuid,
				    /* Revisit */0, GFP_KERNEL);
	if (IS_ERR(uui)) {
		ret = PTR_ERR(uui);
		dev_dbg(dev, "devm_genz_uuid_import failed, ret=%d\n", ret);
		return ERR_PTR(ret);
	}
	access = GENZ_MR_WRITE_REMOTE|GENZ_MR_INDIVIDUAL|GENZ_MR_REQ_CPU;
	rmri = devm_genz_rmr_import(zdev, uui, gcid,
				    zres->res.start, resource_size(&zres->res),
				    access, zres->rw_rkey, GENZ_DR_IFACE_NONE,
				    zres->res.name);
	if (IS_ERR(rmri)) {
		ret = PTR_ERR(rmri);
		dev_dbg(dev, "devm_genz_uuid_import failed, ret=%d\n", ret);
		return ERR_PTR(ret);
	}
	__dax_genz_pfn_size(zdev, &rmri->zres, &align, &end_trunc, &offset, &npfns);
	ret = __dax_genz_setup_pfn(zdev, &rmri->zres, align, end_trunc, offset,
				   npfns, &pgmap);
	if (ret < 0)
		return ERR_PTR(ret);
#ifdef REVISIT
	/* reserve the metadata area, device-dax will reserve the data */
	if (!devm_request_mem_region(dev, nsio->res.start, offset,
				dev_name(&ndns->dev))) {
		dev_warn(dev, "could not reserve metadata\n");
		return ERR_PTR(-EBUSY);
	}
#endif
	/* adjust the dax_region resource to the start of data */
	memcpy(&res, &pgmap.res, sizeof(res));
	res.start += offset;
	dax_region = alloc_dax_region(dev, region_id, &res,
				      target_node, align, PFN_DEV|PFN_MAP);
	if (!dax_region)
		return ERR_PTR(-ENOMEM);

	dev_dax = __devm_create_dev_dax(dax_region, id, &pgmap, subsys);

	/* child dev_dax instances now own the lifetime of the dax_region */
	dax_region_put(dax_region);

	return dev_dax;
}

static int dax_genz_probe(struct genz_dev *zdev,
			  const struct genz_device_id *zdev_id)
{
	struct genz_bridge_dev *zbdev = zdev->zbdev;
	struct genz_bridge_info *br_info = &zbdev->br_info;
	struct genz_resource *zres;
	struct dev_dax *dax = ERR_PTR(-EINVAL);
	bool first = true;

	if (!br_info->load_store) {
		dev_err(&zdev->dev, "device DAX requires load/store-capable bridge\n");
		return -EOPNOTSUPP;
	}
	genz_for_each_resource(zres, zdev) {
		dev_dbg(&zdev->dev, "resource %s\n", zres->res.name);
		if (first) {
			first = false;
		} else {
			/* only 1 because device DAX uses dev->driver_data */
			dev_warn(&zdev->dev, "device DAX allows only 1 data resource - ignoring %s\n", zres->res.name);
			break;
		}
		if (genz_is_data_resource(zres)) {
			dax = __dax_genz_probe(zdev, zres, DEV_DAX_BUS);
		} else {
			dev_warn(&zdev->dev, "ignoring unexpected control resource %s\n", zres->res.name);
		}
	}
	return PTR_ERR_OR_ZERO(dax);
}

static int dax_genz_remove(struct genz_dev *zdev)
{
	dev_dbg(&zdev->dev, "entered\n");
	/* everything is devm-managed, so nothing to do here */
	return 0;
}

static struct genz_driver dax_genz_driver = {
	.name      = DAX_GENZ_DRV_NAME,
	.id_table  = dax_genz_id_table,
	.probe     = dax_genz_probe,
	.remove    = dax_genz_remove,
};

static int __init dax_genz_init(void)
{
	return genz_register_driver(&dax_genz_driver);
}

static void __exit dax_genz_exit(void)
{
	genz_unregister_driver(&dax_genz_driver);
}

module_init(dax_genz_init);
module_exit(dax_genz_exit);

MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(drivers/genz/genz);
MODULE_DESCRIPTION("Device DAX driver for Gen-Z");
