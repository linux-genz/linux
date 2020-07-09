// SPDX-License-Identifier: GPL-2.0
/*
 * IntelliProp Orthus Gen-Z Bridge Driver
 *
 * Author: Jim Hull <jim.hull@hpe.com>
 *
 * Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/clk.h>
#include <linux/genz.h>

#include "orthus.h"

/* Revisit: these clk_bulk functions are not in v4.19 - copied from v5.4 */
#include <linux/clk-provider.h>
struct clk_bulk_devres {
	struct clk_bulk_data *clks;
	int num_clks;
};

static int __must_check of_clk_bulk_get(struct device_node *np, int num_clks,
                                        struct clk_bulk_data *clks)
{
        int ret;
        int i;

        for (i = 0; i < num_clks; i++) {
                clks[i].id = NULL;
                clks[i].clk = NULL;
        }

        for (i = 0; i < num_clks; i++) {
                of_property_read_string_index(np, "clock-names", i, &clks[i].id);
                clks[i].clk = of_clk_get(np, i);
                if (IS_ERR(clks[i].clk)) {
                        ret = PTR_ERR(clks[i].clk);
                        pr_err("%pOF: Failed to get clk index: %d ret: %d\n",
                               np, i, ret);
                        clks[i].clk = NULL;
                        goto err;
                }
        }

        return 0;

err:
        clk_bulk_put(i, clks);

        return ret;
}

static int __must_check of_clk_bulk_get_all(struct device_node *np,
                                            struct clk_bulk_data **clks)
{
        struct clk_bulk_data *clk_bulk;
        int num_clks;
        int ret;

        num_clks = of_clk_get_parent_count(np);
        if (!num_clks)
                return 0;

        clk_bulk = kmalloc_array(num_clks, sizeof(*clk_bulk), GFP_KERNEL);
        if (!clk_bulk)
                return -ENOMEM;

        ret = of_clk_bulk_get(np, num_clks, clk_bulk);
        if (ret) {
                kfree(clk_bulk);
                return ret;
        }

        *clks = clk_bulk;

        return num_clks;
}

void clk_bulk_put_all(int num_clks, struct clk_bulk_data *clks)
{
        if (IS_ERR_OR_NULL(clks))
                return;

        clk_bulk_put(num_clks, clks);

        kfree(clks);
}

int __must_check clk_bulk_get_all(struct device *dev,
                                  struct clk_bulk_data **clks)
{
        struct device_node *np = dev_of_node(dev);

        if (!np)
                return 0;

        return of_clk_bulk_get_all(np, clks);
}

static void devm_clk_bulk_release(struct device *dev, void *res)
{
	struct clk_bulk_devres *devres = res;

	clk_bulk_put(devres->num_clks, devres->clks);
}

static int __must_check devm_clk_bulk_get_all(struct device *dev,
					      struct clk_bulk_data **clks)
{
	struct clk_bulk_devres *devres;
	int ret;

	devres = devres_alloc(devm_clk_bulk_release,
			      sizeof(*devres), GFP_KERNEL);
	if (!devres)
		return -ENOMEM;

	ret = clk_bulk_get_all(dev, &devres->clks);
	if (ret > 0) {
		*clks = devres->clks;
		devres->num_clks = ret;
		devres_add(dev, devres);
	} else {
		devres_free(devres);
	}

	return ret;
}
/* end of Revisit */

static int orthus_control_read(struct genz_bridge_dev *gzbr, loff_t offset,
			       size_t size, void *data,
			       struct genz_rmr_info *rmri, uint flags)
{
	int ret = -EOPNOTSUPP; /* Revisit: temporary */

	/* Revisit: implement this */
	return ret;
}

static int orthus_control_write(struct genz_bridge_dev *gzbr, loff_t offset,
				size_t size, void *data,
				struct genz_rmr_info *rmri, uint flags)
{
	int ret = -EOPNOTSUPP; /* Revisit: temporary */

	/* Revisit: implement this */
	return ret;
}

static irqreturn_t orthus_raw_cb_isr(int irq, void *data_ptr)
{
	int ret = IRQ_HANDLED;

	pr_debug("irq=%d\n", irq);
	/* Revisit: implement this */
	return ret;
}

static int orthus_dna_probe(struct platform_device *pdev,
			    struct orthus_bridge *obr)
{
	struct iprop_dna *const dna = &obr->dna;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	dna->dev = dev;
	dna->clk = devm_clk_get(dev, "s_axi_aclk");
	if (IS_ERR(dna->clk)) {
		ret = PTR_ERR(dna->clk);
		dev_err(dev, "clk_get of s_axi_aclk failed, ret=%d\n", ret);
		return ret;
	}
	dna->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(dna->base)) {
		ret = PTR_ERR(dna->base);
		dev_err(dev, "mapping dna registers failed, ret=%d\n", ret);
		return ret;
	}
	ret = clk_prepare_enable(dna->clk);
	if (ret < 0) {
		dev_err(dev, "enabling s_axi_aclk failed, ret=%d\n", ret);
	}

	/* Revisit: add other dna init */

	return ret;
}

static int orthus_dna_remove(struct platform_device *pdev,
			     struct orthus_bridge *obr)
{
	struct iprop_dna *const dna = &obr->dna;

	clk_disable_unprepare(dna->clk);
	return 0;
}

static int orthus_genz_phy_probe(struct platform_device *pdev,
				 struct orthus_bridge *obr)
{
	struct iprop_genz_phy *const phy = &obr->phy;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	phy->dev = dev;
	ret = devm_clk_bulk_get_all(dev, &phy->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get genz_phy clocks, ret=%d\n", ret);
		return ret;
	}
	phy->num_clks = ret;
	phy->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(phy->base)) {
		ret = PTR_ERR(phy->base);
		dev_err(dev, "mapping genz_phy registers failed, ret=%d\n", ret);
		return ret;
	}
	ret = clk_bulk_prepare_enable(phy->num_clks, phy->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_phy clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other phy init */

	return ret;
}

static int orthus_genz_phy_remove(struct platform_device *pdev,
				  struct orthus_bridge *obr)
{
	struct iprop_genz_phy *const phy = &obr->phy;

	clk_bulk_disable_unprepare(phy->num_clks, phy->clks);
	return 0;
}

static int orthus_genz_link_layer_probe(struct platform_device *pdev,
					struct orthus_bridge *obr)
{
	struct iprop_genz_link_layer *const link = &obr->link;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	link->dev = dev;
	ret = devm_clk_bulk_get_all(dev, &link->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get genz_link_layer clocks, ret=%d\n", ret);
		return ret;
	}
	link->num_clks = ret;
	link->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(link->base)) {
		ret = PTR_ERR(link->base);
		dev_err(dev, "mapping genz_link_layer registers failed, ret=%d\n", ret);
		return ret;
	}
	ret = clk_bulk_prepare_enable(link->num_clks, link->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_link_layer clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other link layer init */

	return ret;
}

static int orthus_genz_link_layer_remove(struct platform_device *pdev,
				  struct orthus_bridge *obr)
{
	struct iprop_genz_link_layer *const link = &obr->link;

	clk_bulk_disable_unprepare(link->num_clks, link->clks);
	return 0;
}

static int orthus_genz_raw_cb_layer_probe(struct platform_device *pdev,
					  struct orthus_bridge *obr)
{
	struct iprop_genz_raw_cb_layer *const raw_cb = &obr->raw_cb;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	raw_cb->dev = dev;
	ret = devm_clk_bulk_get_all(dev, &raw_cb->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get raw_cb clocks, ret=%d\n", ret);
		return ret;
	}
	raw_cb->num_clks = ret;
	raw_cb->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(raw_cb->base)) {
		ret = PTR_ERR(raw_cb->base);
		dev_err(dev, "mapping raw_cb registers failed, ret=%d\n", ret);
		return ret;
	}
	ret = clk_bulk_prepare_enable(raw_cb->num_clks, raw_cb->clks);
	if (ret < 0) {
		dev_err(dev, "enabling raw_cb clocks failed, ret=%d\n", ret);
		return ret;
	}
	/* Revisit: interrupts */
	raw_cb->irq = irq_of_parse_and_map(np, 0);
	if (!raw_cb->irq) {
		dev_err(dev, "mapping raw_cb irq failed\n");
		raw_cb->irq = -1;
		ret = -EINVAL;
		goto clk_disable;
	}
	ret = devm_request_irq(dev, raw_cb->irq, orthus_raw_cb_isr, 0, "orthus", obr);
	if (ret < 0) {
		dev_err(dev, "enabling raw_cb irq failed, ret=%d\n", ret);
		raw_cb->irq = -1;
		goto clk_disable;
	}

	/* Revisit: add other raw_cb init */

	return ret;

clk_disable:
	clk_bulk_disable_unprepare(raw_cb->num_clks, raw_cb->clks);
	return ret;
}

static int orthus_genz_raw_cb_layer_remove(struct platform_device *pdev,
					   struct orthus_bridge *obr)
{
	struct iprop_genz_raw_cb_layer *const raw_cb = &obr->raw_cb;

	clk_bulk_disable_unprepare(raw_cb->num_clks, raw_cb->clks);
	return 0;
}

static int orthus_genz_req_zmmu_probe(struct platform_device *pdev,
				      struct orthus_bridge *obr)
{
	struct iprop_genz_req_zmmu *const req_zmmu = &obr->req_zmmu;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	req_zmmu->dev = dev;
	ret = devm_clk_bulk_get_all(dev, &req_zmmu->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get genz_req_zmmu clocks, ret=%d\n", ret);
		return ret;
	}
	req_zmmu->num_clks = ret;
	req_zmmu->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(req_zmmu->base)) {
		ret = PTR_ERR(req_zmmu->base);
		dev_err(dev, "mapping genz_req_zmmu registers failed, ret=%d\n", ret);
		return ret;
	}
	ret = clk_bulk_prepare_enable(req_zmmu->num_clks, req_zmmu->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_req_zmmu clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other req_zmmu init */

	return ret;
}

static int orthus_genz_req_zmmu_remove(struct platform_device *pdev,
				       struct orthus_bridge *obr)
{
	struct iprop_genz_req_zmmu *const req_zmmu = &obr->req_zmmu;

	clk_bulk_disable_unprepare(req_zmmu->num_clks, req_zmmu->clks);
	return 0;
}

static int orthus_genz_req_layer_probe(struct platform_device *pdev,
				       struct orthus_bridge *obr)
{
	struct iprop_genz_req_layer *const req_layer = &obr->req_layer;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	req_layer->dev = dev;
	ret = devm_clk_bulk_get_all(dev, &req_layer->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get genz_req_layer clocks, ret=%d\n", ret);
		return ret;
	}
	req_layer->num_clks = ret;
	req_layer->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(req_layer->base)) {
		ret = PTR_ERR(req_layer->base);
		dev_err(dev, "mapping genz_req_layer registers failed, ret=%d\n", ret);
		return ret;
	}
	ret = clk_bulk_prepare_enable(req_layer->num_clks, req_layer->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_req_layer clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other req_layer init */

	return ret;
}

static int orthus_genz_req_layer_remove(struct platform_device *pdev,
					struct orthus_bridge *obr)
{
	struct iprop_genz_req_layer *const req_layer = &obr->req_layer;

	clk_bulk_disable_unprepare(req_layer->num_clks, req_layer->clks);
	return 0;
}

static int orthus_genz_thin_sw_layer_probe(struct platform_device *pdev,
					       struct orthus_bridge *obr)
{
	struct iprop_genz_thin_sw_layer *const thin_sw_layer = &obr->thin_sw_layer;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	thin_sw_layer->dev = dev;
	ret = devm_clk_bulk_get_all(dev, &thin_sw_layer->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get genz_thin_sw_layer clocks, ret=%d\n", ret);
		return ret;
	}
	thin_sw_layer->num_clks = ret;
	thin_sw_layer->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(thin_sw_layer->base)) {
		ret = PTR_ERR(thin_sw_layer->base);
		dev_err(dev, "mapping genz_thin_sw_layer registers failed, ret=%d\n", ret);
		return ret;
	}
	ret = clk_bulk_prepare_enable(thin_sw_layer->num_clks, thin_sw_layer->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_thin_sw_layer clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other thin_sw_layer init */

	return ret;
}

static int orthus_genz_thin_sw_layer_remove(struct platform_device *pdev,
						struct orthus_bridge *obr)
{
	struct iprop_genz_thin_sw_layer *const thin_sw_layer = &obr->thin_sw_layer;

	clk_bulk_disable_unprepare(thin_sw_layer->num_clks, thin_sw_layer->clks);
	return 0;
}

static const struct iprop_block_data iprop_dna_data = {
	.type = IPROP_DNA,
	.block_probe = orthus_dna_probe,
	.block_remove = orthus_dna_remove,
};

static const struct iprop_block_data iprop_genz_phy_data = {
	.type = IPROP_GENZ_PHY,
	.block_probe = orthus_genz_phy_probe,
	.block_remove = orthus_genz_phy_remove,
};

static const struct iprop_block_data iprop_genz_link_layer_data = {
	.type = IPROP_GENZ_LINK_LAYER,
	.block_probe = orthus_genz_link_layer_probe,
	.block_remove = orthus_genz_link_layer_remove,
};

static const struct iprop_block_data iprop_genz_raw_cb_layer_data = {
	.type = IPROP_GENZ_RAW_CB_LAYER,
	.block_probe = orthus_genz_raw_cb_layer_probe,
	.block_remove = orthus_genz_raw_cb_layer_remove,
};

static const struct iprop_block_data iprop_genz_req_zmmu_data = {
	.type = IPROP_GENZ_REQ_ZMMU,
	.block_probe = orthus_genz_req_zmmu_probe,
	.block_remove = orthus_genz_req_zmmu_remove,
};

static const struct iprop_block_data iprop_genz_req_layer_data = {
	.type = IPROP_GENZ_REQ_LAYER,
	.block_probe = orthus_genz_req_layer_probe,
	.block_remove = orthus_genz_req_layer_remove,
};

static const struct iprop_block_data iprop_genz_thin_sw_layer_data = {
	.type = IPROP_GENZ_THIN_SW_LAYER,
	.block_probe = orthus_genz_thin_sw_layer_probe,
	.block_remove = orthus_genz_thin_sw_layer_remove,
};

static const struct of_device_id orthus_dt_ids[] = {
	{ .compatible = "xlnx,iprop-dna-1.0",
	  .data = &iprop_dna_data },
	{ .compatible = "xlnx,iprop-genz-802-3-phy-layer-1.0",
	  .data = &iprop_genz_phy_data },
	{ .compatible = "xlnx,iprop-genz-link-layer-1.0",
	  .data = &iprop_genz_link_layer_data },
	{ .compatible = "xlnx,iprop-genz-raw-cb-layer-1.0",
	  .data = &iprop_genz_raw_cb_layer_data },
	{ .compatible = "xlnx,iprop-genz-requester-zmmu-1.0",
	  .data = &iprop_genz_req_zmmu_data },
	{ .compatible = "xlnx,iprop-genz-requester-layer-1.0",
	  .data = &iprop_genz_req_layer_data },
	{ .compatible = "xlnx,iprop-genz-thin-switch-layer-1.0",
	  .data = &iprop_genz_thin_sw_layer_data },
	{ }
};
MODULE_DEVICE_TABLE(of, orthus_dt_ids);

static struct orthus_bridge bridge = { 0 };  /* only 1 supported */

/* Revisit: make these dynamic based on bridge HW */
static struct genz_bridge_info orthus_br_info = {
	.req_zmmu            = 1,
	.rsp_zmmu            = 0,
	.xdm                 = 0,
	.rdm                 = 0,
	.load_store          = 1,
	.loopback            = 0,
	.nr_req_page_grids   = ORTHUS_PAGE_GRID_ENTRIES,
	.nr_req_ptes         = ORTHUS_REQ_ZMMU_ENTRIES,
	.min_cpuvisible_addr = ORTHUS_MIN_CPUVISIBLE_ADDR,
	.max_cpuvisible_addr = ORTHUS_MAX_CPUVISIBLE_ADDR,
};

static int orthus_bridge_info(struct genz_bridge_dev *gzbr,
			      struct genz_bridge_info *info)
{
	struct orthus_bridge *obr = genz_get_drvdata(&gzbr->zdev);

	if (obr != &bridge)  /* not our bridge */
		return -EINVAL;

	*info = orthus_br_info;
	return 0;
}

static struct genz_bridge_driver orthus_genz_bridge_driver = {
	.bridge_info = orthus_bridge_info,
	.control_read = orthus_control_read,
	.control_write = orthus_control_write,
#ifdef REVISIT
	.data_read = orthus_data_read,
	.data_write = orthus_data_write,
	.req_page_grid_write = orthus_req_page_grid_write,
	.rsp_page_grid_write = orthus_rsp_page_grid_write,
	.req_pte_write = orthus_req_pte_write,
	.rsp_pte_write = orthus_rsp_pte_write,
	.dma_map_sg_attrs = orthus_dma_map_sg_attrs,
	.dma_unmap_sg_attrs = orthus_dma_unmap_sg_attrs,
	.alloc_queues = orthus_alloc_queues,
	.free_queues = orthus_free_queues,
	.sgl_request = orthus_sgl_request,
	.generate_uuid = orthus_generate_uuid,
	.uuid_import = orthus_kernel_UUID_IMPORT,
	.uuid_free = orthus_common_UUID_FREE,
	.control_structure_pointers = orthus_control_structure_pointers,
#endif /* REVISIT */
};

static int orthus_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct of_device_id *of_id = of_match_device(orthus_dt_ids, dev);
	struct orthus_bridge *obr = &bridge;
	const struct iprop_block_data *bdata;
	int bcnt, ret;

	dev_dbg(dev, "entered\n");
	if (!of_id) {
		dev_dbg(dev, "of_id is NULL\n");
		ret = -ENODEV;
		goto err;
	}
	bdata = of_id->data;
	if (!bdata) {
		dev_dbg(dev, "bdata is NULL\n");
		ret = -ENODEV;
		goto err;
	}
	if (!bdata->block_probe) {
		dev_dbg(dev, "block_probe is NULL\n");
		ret = -ENODEV;
		goto err;
	}
	bdata->block_probe(pdev, obr);
	/* Revisit: finish this */
	bcnt = atomic_inc_return(&obr->block_cnt);
	if (bcnt == IPROP_BLOCK_CNT) {
		ret = genz_register_bridge(dev,
					   &orthus_genz_bridge_driver, obr);
		if (ret) {
			dev_dbg(dev,
				"genz_register_bridge failed with error %d\n",
				ret);
			goto err;
		}
	}
	return 0;

err:
	return ret;
}

static int orthus_remove(struct platform_device *pdev)
{
	const struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
	/* Revisit: implement this */
	return 0;
}

static struct platform_driver orthus_driver = {
	.probe = orthus_probe,
	.remove = orthus_remove,
	.driver = {
		.name = "orthus",
		.of_match_table = orthus_dt_ids,
	},
};

static int __init orthus_init(void)
{
	int ret;

	spin_lock_init(&bridge.obr_lock);
	atomic_set(&bridge.block_cnt, 0);
	ret = platform_driver_register(&orthus_driver);
	return ret;
}

static void __exit orthus_exit(void)
{
	platform_driver_unregister(&orthus_driver);
}

module_init(orthus_init);
module_exit(orthus_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IntelliProp Orthus Gen-Z Bridge Driver");
