// SPDX-License-Identifier: GPL-2.0
/* © Copyright 2021-2023 IntelliProp Inc. All rights reserved. */
#include <linux/percpu-refcount.h>
#include <linux/memremap.h>
#include <linux/module.h>
#include <linux/genz.h>

#define GENZ_CTL_DRV_NAME "genz-ctl"
#define GENZ_CTL_FL_PEC    0x40000000ull

static struct genz_device_id genz_ctl_id_table[] = {
	{ .uuid_str = "76d1ce79-1a28-49c8-befa-b4ef5c458b9f" },
	{ },
};

MODULE_DEVICE_TABLE(genz, genz_ctl_id_table);

struct genz_rmr_info *__genz_ctl_probe(struct genz_dev *zdev,
				       struct genz_resource *zres)
{
	int ret;
	struct genz_rmr_info *rmri;
	struct device *dev = &zdev->dev;
	uint64_t access;
	bool pec;

	pec = zdev->driver_flags & GENZ_CTL_FL_PEC;
	dev_dbg(dev, "instance_uuid=%pUb, pec=%u\n",
		&zdev->instance_uuid, pec);
	access = GENZ_MR_WRITE_REMOTE|GENZ_MR_INDIVIDUAL|GENZ_MR_REQ_CPU|
		 GENZ_MR_CONTROL|GENZ_MR_REQ_CPU_UC;
	access |= pec ? GENZ_MR_PEC : 0;
	rmri = devm_genz_rmr_import_zres(zdev, zres, access);
	if (IS_ERR(rmri)) {
		ret = PTR_ERR(rmri);
		dev_dbg(dev, "devm_genz_rmr_import_zres failed, ret=%d\n", ret);
	}
	return rmri;
}

static int genz_ctl_probe(struct genz_dev *zdev,
			  const struct genz_device_id *zdev_id)
{
	struct genz_bridge_dev *zbdev = zdev->zbdev;
	struct genz_bridge_info *br_info = &zbdev->br_info;
	struct genz_resource *zres;
	struct genz_rmr_info *rmri = ERR_PTR(-EINVAL);

	if (!br_info->load_store) { // Revisit: needed?
		dev_err(&zdev->dev, "genz-ctl requires load/store-capable bridge\n");
		return -EOPNOTSUPP;
	}
	dev_dbg(&zdev->dev, "entered\n");
	genz_for_each_resource(zres, zdev) {
		dev_dbg(&zdev->dev, "resource %s\n", zres->res.name);
		if (genz_is_control_resource(zres)) {
			rmri = __genz_ctl_probe(zdev, zres);
		} else {
			dev_warn(&zdev->dev, "ignoring unexpected data resource %s\n", zres->res.name);
		}
	}
	return PTR_ERR_OR_ZERO(rmri);
}

static int genz_ctl_remove(struct genz_dev *zdev)
{
	dev_dbg(&zdev->dev, "entered\n");
	/* everything is devm-managed, so nothing to do here */
	return 0;
}

static struct genz_driver genz_ctl_driver = {
	.name      = GENZ_CTL_DRV_NAME,
	.id_table  = genz_ctl_id_table,
	.probe     = genz_ctl_probe,
	.remove    = genz_ctl_remove,
};

static int __init genz_ctl_init(void)
{
	return genz_register_driver(&genz_ctl_driver);
}

static void __exit genz_ctl_exit(void)
{
	genz_unregister_driver(&genz_ctl_driver);
}

module_init(genz_ctl_init);
module_exit(genz_ctl_exit);

MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(drivers/genz/genz);
MODULE_DESCRIPTION("Gen-Z Control Space Mapping Driver");
