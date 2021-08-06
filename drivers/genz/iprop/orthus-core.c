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

static inline bool within_res(loff_t addr, struct resource *res)
{
	return (addr >= res->start) &&
		(addr < (res->start + resource_size(res)));
}

static int orthus_control_offset_to_base(struct orthus_bridge *obr,
					 loff_t offset, loff_t *blk_offset,
					 void __iomem **base)
{
	loff_t res_addr = offset + obr->thin_sw_layer.res.start;
	struct resource *res;
	int ret = 0;

	if (within_res(res_addr, &obr->thin_sw_layer.res)) {
		*base = obr->thin_sw_layer.base;
		res = &obr->thin_sw_layer.res;
	} else if (within_res(res_addr, &obr->req_layer.res)) {
		*base = obr->req_layer.base;
		res = &obr->req_layer.res;
	} else if (within_res(res_addr, &obr->req_zmmu.res)) {
		*base = obr->req_zmmu.base;
		res = &obr->req_zmmu.res;
	} else if (within_res(res_addr, &obr->raw_cb.res)) {
		*base = obr->raw_cb.base;
		res = &obr->raw_cb.res;
	} else if (within_res(res_addr, &obr->link.res)) {
		*base = obr->link.base;
		res = &obr->link.res;
	} else if (within_res(res_addr, &obr->phy.res)) {
		*base = obr->phy.base;
		res = &obr->phy.res;
	} else if (within_res(res_addr, &obr->pte_table.res)) {
		*base = obr->pte_table.base;
		res = &obr->pte_table.res;
	} else if (within_res(res_addr, &obr->raw_cb_table.res)) {
		*base = obr->raw_cb_table.base;
		res = &obr->raw_cb_table.res;
	} else {
		ret = EINVAL;  /* warn for bad offset, not error */
	}
	if (ret == 0)
		*blk_offset = res_addr - res->start;

	return ret;
}

//#define ORTHUS_FIXUPS_V0P5
/* Revisit: temporary - fill in some PTRs & Vdef Hdrs missing in HW */
static int orthus_local_control_read_fixup(struct orthus_bridge *obr, loff_t offset,
					   size_t size, void *data, uint flags)
{
#if defined(ORTHUS_FIXUPS_V0P4P2)
	if (offset == 0x60 && size == 4) {            /* Struct PTR6 */
		*((uint32_t *)data) = 0x6000;
		return 1;
	} else if (offset == 0x7c && size == 4) {     /* Interface0 PTR */
		*((uint32_t *)data) = 0x2000;
		return 1;
	} else if (offset == 0x8000 && size == 4) {   /* Vdef Hdr */
		*((uint32_t *)data) = 0x0010100a;
		return 1;
	} else if (offset == 0x20080 && size == 4) {  /* Interface0 IPHY PTR */
		*((uint32_t *)data) = 0x3000;
		return 1;
	} else if (offset == 0x2008c && size == 4) {  /* Interface0 VD PTR */
		*((uint32_t *)data) = 0x2010;
		return 1;
	} else if (offset == 0x20100 && size == 4) {   /* Interface0 Vdef Hdr */
		*((uint32_t *)data) = 0x0010100a;
		return 1;
	} else if (offset == 0x60000 && size == 4) {   /* RawCB Vdef Hdr */
		*((uint32_t *)data) = 0x0100100a;
		return 1;
	}
#elif defined(ORTHUS_FIXUPS_V0P5)
	if (offset == 0x48 && size == 4) {            /* Core StructPTR0 */
		*((uint32_t *)data) = 0x0000;
		return 1;
	} else if (offset == 0x4c && size == 4) {     /* Core StructPTR1 */
		*((uint32_t *)data) = 0x4000;
		return 1;
	} else if (offset == 0x50 && size == 4) {     /* Core StructPTR2 */
		*((uint32_t *)data) = 0x5000;
		return 1;
	} else if (offset == 0x54 && size == 4) {     /* Core StructPTR3 */
		*((uint32_t *)data) = 0x6000;
		return 1;
	} else if (offset == 0x58 && size == 4) {     /* Core StructPTR4 */
		*((uint32_t *)data) = 0x6100;
		return 1;
	} else if (offset == 0x20080 && size == 4) {  /* Interface0 IPHY PTR */
		*((uint32_t *)data) = 0x3000;
		return 1;
	} else if (offset == 0x2008c && size == 4) {  /* Interface0 VD PTR */
		*((uint32_t *)data) = 0x2010;
		return 1;
	} else if (offset == 0x50000 && size == 4) {   /* Comp PG Hdr */
		*((uint32_t *)data) = 0x00061021;
		return 1;
	} else if (offset == 0x50018 && size == 4) {   /* PGBasePTR */
		*((uint32_t *)data) = 0x00005400;
		return 1;
	} else if (offset == 0x5001c && size == 4) {   /* PTEBasePTR */
		*((uint32_t *)data) = 0x00008000;
		return 1;
	} else if (offset == 0x60000 && size == 4) {   /* RawCB Vdef Hdr */
		*((uint32_t *)data) = 0x0100100a;
		return 1;
	}
#endif
	return 0;
}

static int orthus_local_control_read(struct orthus_bridge *obr,
				     struct device *dev, loff_t offset,
				     size_t size, void *data, uint flags)
{
	uint64_t               csr_val = 0, val;
	uint64_t               csr;
	uint                   csr_align;
	uint                   shift;
	ssize_t                write;
	loff_t                 blk_offset;
	void __iomem           *base;
	int                    ret;

	if (!obr)
		return -EINVAL;
	ret = orthus_local_control_read_fixup(obr, offset, size, data, flags);
	if (ret == 1)
		return 0;
	ret = orthus_control_offset_to_base(obr, offset, &blk_offset, &base);
	if (ret != 0)
		return ret;

	csr = blk_offset & ~7ull;
	csr_align = (uint)blk_offset & 7u;

	/* Revisit: mostly copied from wildcat */
	/* Revisit: does orthus have these same size/alignment restrictions? */
	/* control space accessible only with 8-byte size & alignment */
	shift = csr_align * 8;                       /* 0 - 56 */
	write = min((size_t)(8 - csr_align), size);  /* 1 - 8 */
	dev_dbg(dev, "obr=%px, offset=0x%llx, size=%lu, shift=%u, write=%ld, csr=0x%llx, base=%px\n",
		obr, offset, size, shift, write, csr, base);

	/* Revisit: locking */
	while (size > 0) {
		csr_val = ioread64(base + csr);
		dev_dbg(dev, "csr=0x%llx, csr_val=0x%llx, shifted val=0x%llx, size=%zu\n",
			csr, csr_val, csr_val >> shift, size);
		val = csr_val >> shift;
		/* Revisit: endianness */
		memcpy(data, &val, write);
		size -= write;
		data += write;
		write = min((size_t)8, size);
		shift = 0;
		csr += 8;
	}

	return ret;
}

static int orthus_control_read(struct genz_bridge_dev *gzbr, loff_t offset,
			       size_t size, void *data,
			       struct genz_rmr_info *rmri, uint flags)
{
	struct orthus_bridge *obr = orthus_gzbr_to_obr(gzbr);
	struct device *dev = &gzbr->zdev.dev;
	void *src;

	if (genz_is_local_bridge(gzbr, rmri)) {
		return orthus_local_control_read(obr, dev, offset, size, data, flags);
	}

	src = rmri->cpu_addr + offset;  /* Revisit: CAccess */
	memcpy(data, src, size);
	/* Revisit: flush/fence flags */
	return 0;
}

static int orthus_local_control_write(struct orthus_bridge *obr,
				      struct device *dev, loff_t offset,
				      size_t size, void *data, uint flags)
{
	uint64_t               val;
	uint32_t               val4;
	uint16_t               val2;
	uint8_t                val1;
	uint                   csr_align;
	loff_t                 blk_offset;
	void __iomem           *base;
	int                    ret;

	if (!obr)
		return -EINVAL;
	if (size == 0)
		return 0;
	ret = orthus_control_offset_to_base(obr, offset, &blk_offset, &base);
	if (ret < 0)
		return ret;

	csr_align = (uint)blk_offset & 7u;
	dev_dbg(dev, "offset=0x%llx, size=%lu\n", offset, size);

	/* Revisit: locking */
	/* do small writes until csr is 8-byte aligned */
	if (csr_align & 0x1) {  /* do 1-byte write */
		val1 = *((uint8_t *)data);
		dev_dbg(dev, "val1=0x%x, blk_offset=0x%llx\n",
			val1, blk_offset);
		iowrite8(val1, base + blk_offset);
		data++;
		blk_offset++;
		size--;
	}
	if ((size > 0) && (csr_align & 0x2)) {  /* do 2-byte write */
		val2 = *((uint16_t *)data);  /* Revisit: endianness */
		dev_dbg(dev, "val2=0x%x, blk_offset=0x%llx\n",
			val2, blk_offset);
		iowrite16(val2, base + blk_offset);
		data += 2;
		blk_offset += 2;
		size -= 2;
	}
	if ((size > 0) && (csr_align & 0x4)) {  /* do 4-byte write */
		val4 = *((uint32_t *)data);  /* Revisit: endianness */
		dev_dbg(dev, "val4=0x%x, blk_offset=0x%llx\n",
			val4, blk_offset);
		iowrite32(val4, base + blk_offset);
		data += 4;
		blk_offset += 4;
		size -= 4;
	}

	while (size >= 8) {  /* do aligned 8-byte writes */
		memcpy(&val, data, 8);
		dev_dbg(dev, "val=0x%llx, blk_offset=0x%llx\n",
			val, blk_offset);
		iowrite64(val, base + blk_offset);
		data += 8;
		blk_offset += 8;
		size -= 8;
	}

	if (size & 0x4) {  /* do 4-byte write */
		val4 = *((uint32_t *)data);  /* Revisit: endianness */
		dev_dbg(dev, "val4=0x%x, blk_offset=0x%llx\n",
			val4, blk_offset);
		iowrite32(val4, base + blk_offset);
		data += 4;
		blk_offset += 4;
		size -= 4;
	}
	if (size & 0x2) {  /* do 2-byte write */
		val2 = *((uint16_t *)data);  /* Revisit: endianness */
		dev_dbg(dev, "val2=0x%x, blk_offset=0x%llx\n",
			val2, blk_offset);
		iowrite16(val2, base + blk_offset);
		data += 2;
		blk_offset += 2;
		size -= 2;
	}
	if (size & 0x1) {  /* do 1-byte write */
		val1 = *((uint8_t *)data);
		dev_dbg(dev, "val1=0x%x, blk_offset=0x%llx\n",
			val1, blk_offset);
		iowrite8(val1, base + blk_offset);
		data++;
		blk_offset++;
		size--;
	}

	pr_debug("returning ret=%d\n", ret);
	return ret;
}

static int orthus_control_write(struct genz_bridge_dev *gzbr, loff_t offset,
				size_t size, void *data,
				struct genz_rmr_info *rmri, uint flags)
{
	struct orthus_bridge *obr = orthus_gzbr_to_obr(gzbr);
	struct device *dev = &gzbr->zdev.dev;
	void *dest;

	if (genz_is_local_bridge(gzbr, rmri)) {
		return orthus_local_control_write(obr, dev, offset, size, data, flags);
	}

	dest = rmri->cpu_addr + offset;  /* Revisit: CAccess */
	memcpy(dest, data, size);
	/* Revisit: flush/fence flags */
	return 0;
}

static int orthus_req_page_grid_write(struct genz_bridge_dev *gzbr, uint pg_index,
				      struct genz_page_grid genz_pg[])
{
	struct orthus_bridge *obr = orthus_gzbr_to_obr(gzbr);
	struct device *dev = &gzbr->zdev.dev;
	struct iprop_genz_req_zmmu *const req_zmmu = &obr->req_zmmu;
	struct genz_page_grid_restricted_page_grid_table_array *pg;
	uint32_t offset;
	int ret = 0;

	pg = &genz_pg[pg_index].page_grid;
	offset = pg_index * sizeof(*pg);
	dev_dbg(dev,
		"pg[%u]: base_addr=0x%llx, page_count=%d, page_size=%u, "
		"base_pte_idx=%u, res=%u, sizeof=%u\n", pg_index,
		(uint64_t)pg->pg_base_address_0, pg->page_count_0,
		pg->page_size_0, pg->base_pte_index_0, pg->res,
		(uint)sizeof(*pg));
	orthus_local_control_write(obr, dev, req_zmmu->pg_base_offset + offset,
				   sizeof(*pg), pg, 0);
	return ret;
}

static irqreturn_t orthus_raw_cb_isr(int irq, void *data_ptr)
{
	int ret = IRQ_HANDLED;

	pr_debug("irq=%d\n", irq);
	/* Revisit: implement this */
	return ret;
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
	of_address_to_resource(np, 0, &phy->res);
	dev_dbg(dev, "phy->base(%px)=0x%llx\n", phy->base, ioread64(phy->base));
	ret = clk_bulk_prepare_enable(phy->num_clks, phy->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_phy clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other phy init */

	return ret;
}

static void orthus_unmap_and_release(struct device *dev, void __iomem *base)
{
	struct device_node *const np = dev->of_node;
	struct resource res;

	iounmap(base);
	of_address_to_resource(np, 0, &res);
	release_mem_region(res.start, resource_size(&res));
}

static int orthus_genz_phy_remove(struct platform_device *pdev,
				  struct orthus_bridge *obr)
{
	struct iprop_genz_phy *const phy = &obr->phy;
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
	clk_bulk_disable_unprepare(phy->num_clks, phy->clks);
	orthus_unmap_and_release(dev, phy->base);
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
	of_address_to_resource(np, 0, &link->res);
	dev_dbg(dev, "link->base(%px)=0x%llx\n", link->base, ioread64(link->base));
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
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
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
	of_address_to_resource(np, 0, &raw_cb->res);
	dev_dbg(dev, "raw_cb->base(%px)=0x%llx\n", raw_cb->base, ioread64(raw_cb->base));
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
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
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
	of_address_to_resource(np, 0, &req_zmmu->res);
	dev_dbg(dev, "req_zmmu->base(%px)=0x%llx\n", req_zmmu->base, ioread64(req_zmmu->base));
	ret = clk_bulk_prepare_enable(req_zmmu->num_clks, req_zmmu->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_req_zmmu clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other req_zmmu init */

	return ret;
}

static int orthus_genz_req_zmmu_setup(struct orthus_bridge *obr)
{
	struct iprop_genz_req_zmmu *const req_zmmu = &obr->req_zmmu;
	struct device *dev = req_zmmu->dev;
	uint32_t pg_base_ptr;
	loff_t blk_offset;
	int ret;

	/* compute req zmmu pg_base_offset */
	/* Revisit: hardcoded offset */
	ret = orthus_local_control_read(obr, dev, 0x50018, 4, &pg_base_ptr, 0);
	if (ret < 0)
		return ret;
	req_zmmu->pg_base_offset = (loff_t)pg_base_ptr << 4;
	dev_dbg(dev, "req_zmmu->pg_base_offset=0x%llx\n",
		req_zmmu->pg_base_offset);
	return ret;
}

static int orthus_genz_req_zmmu_remove(struct platform_device *pdev,
				       struct orthus_bridge *obr)
{
	struct iprop_genz_req_zmmu *const req_zmmu = &obr->req_zmmu;
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
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
	of_address_to_resource(np, 0, &req_layer->res);
	dev_dbg(dev, "req_layer->base(%px)=0x%llx\n", req_layer->base, ioread64(req_layer->base));
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
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
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
	of_address_to_resource(np, 0, &thin_sw_layer->res);
	dev_dbg(dev, "thin_sw_layer->base(%px)=0x%llx, res.start=0x%llx\n", thin_sw_layer->base, ioread64(thin_sw_layer->base), thin_sw_layer->res.start);
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
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
	clk_bulk_disable_unprepare(thin_sw_layer->num_clks, thin_sw_layer->clks);
	return 0;
}

static int orthus_genz_pte_table_probe(struct platform_device *pdev,
				       struct orthus_bridge *obr)
{
	struct iprop_genz_pte_table *pte_table = &obr->pte_table;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	pte_table->dev = dev;
	ret = devm_clk_bulk_get_all(dev, &pte_table->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get genz_pte_table clocks, ret=%d\n", ret);
		return ret;
	}
	pte_table->num_clks = ret;
	pte_table->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(pte_table->base)) {
		ret = PTR_ERR(pte_table->base);
		dev_err(dev, "mapping genz_pte_table failed, ret=%d\n", ret);
		return ret;
	}
	of_address_to_resource(np, 0, &pte_table->res);
	dev_dbg(dev, "pte_table->base(%px)=0x%llx, res.start=0x%llx\n", pte_table->base, ioread64(pte_table->base), pte_table->res.start);
	ret = clk_bulk_prepare_enable(pte_table->num_clks, pte_table->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_pte_table clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other pte_table init */

	return ret;
}

static int orthus_genz_pte_table_remove(struct platform_device *pdev,
					struct orthus_bridge *obr)
{
	struct iprop_genz_pte_table *const pte_table = &obr->pte_table;
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
	clk_bulk_disable_unprepare(pte_table->num_clks, pte_table->clks);
	return 0;
}

static int orthus_genz_raw_cb_table_probe(struct platform_device *pdev,
					  struct orthus_bridge *obr)
{
	struct iprop_genz_raw_cb_table *raw_cb_table = &obr->raw_cb_table;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	raw_cb_table->dev = dev;
	ret = devm_clk_bulk_get_all(dev, &raw_cb_table->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get genz_raw_cb_table clocks, ret=%d\n", ret);
		return ret;
	}
	raw_cb_table->num_clks = ret;
	raw_cb_table->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(raw_cb_table->base)) {
		ret = PTR_ERR(raw_cb_table->base);
		dev_err(dev, "mapping genz_raw_cb_table failed, ret=%d\n", ret);
		return ret;
	}
	of_address_to_resource(np, 0, &raw_cb_table->res);
	dev_dbg(dev, "raw_cb_table->base(%px)=0x%llx, res.start=0x%llx\n", raw_cb_table->base, ioread64(raw_cb_table->base), raw_cb_table->res.start);
	ret = clk_bulk_prepare_enable(raw_cb_table->num_clks, raw_cb_table->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_raw_cb_table clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other raw_cb_table init */

	return ret;
}

static int orthus_genz_raw_cb_table_remove(struct platform_device *pdev,
					   struct orthus_bridge *obr)
{
	struct iprop_genz_raw_cb_table *const raw_cb_table = &obr->raw_cb_table;
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
	clk_bulk_disable_unprepare(raw_cb_table->num_clks, raw_cb_table->clks);
	return 0;
}

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

static const struct iprop_block_data iprop_genz_pte_table_data = {
	.type = IPROP_GENZ_PTE_TABLE,
	.block_probe = orthus_genz_pte_table_probe,
	.block_remove = orthus_genz_pte_table_remove,
};

static const struct iprop_block_data iprop_genz_raw_cb_table_data = {
	.type = IPROP_GENZ_RAW_CB_TABLE,
	.block_probe = orthus_genz_raw_cb_table_probe,
	.block_remove = orthus_genz_raw_cb_table_remove,
};

static const struct of_device_id orthus_dt_ids[] = {
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
	{ .compatible = "xlnx,iprop-genz-pte-table",
	  .data = &iprop_genz_pte_table_data },
	{ .compatible = "xlnx,iprop-genz-raw-cb-table",
	  .data = &iprop_genz_raw_cb_table_data },
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
	struct orthus_bridge *obr = orthus_gzbr_to_obr(gzbr);

	if (obr != &bridge)  /* not our bridge */
		return -EINVAL;

	*info = orthus_br_info;
	return 0;
}

static struct genz_bridge_driver orthus_genz_bridge_driver = {
	.bridge_info = orthus_bridge_info,
	.control_read = orthus_control_read,
	.control_write = orthus_control_write,
	.req_page_grid_write = orthus_req_page_grid_write,
#ifdef REVISIT
	.data_read = orthus_data_read,
	.data_write = orthus_data_write,
	.req_pte_write = orthus_req_pte_write,
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
	dev_dbg(dev, "bcnt is %d of %d\n", bcnt, IPROP_BLOCK_CNT);
	if (bcnt == IPROP_BLOCK_CNT) {
		obr->obr_dev = dev;
		orthus_genz_req_zmmu_setup(obr);
		dev_dbg(dev, "calling genz_register_bridge\n");
		ret = genz_register_bridge(dev,
					   &orthus_genz_bridge_driver, obr);
		if (ret) {
			dev_dbg(dev,
				"genz_register_bridge failed with error %d\n",
				ret);
			goto err;
		}
		obr->gzbr = genz_find_bridge(dev);
	}
	return 0;

err:
	return ret;
}

static int orthus_remove(struct platform_device *pdev)
{
	const struct device *dev = &pdev->dev;
	const struct of_device_id *of_id = of_match_device(orthus_dt_ids, dev);
	struct orthus_bridge *obr = &bridge;
	const struct iprop_block_data *bdata;
	int bcnt, ret = 0;

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
	if (!bdata->block_remove) {
		dev_dbg(dev, "block_remove is NULL\n");
		ret = -ENODEV;
		goto err;
	}
	bcnt = atomic_dec_return(&obr->block_cnt);
	if (bcnt == IPROP_BLOCK_CNT-1) {
		dev_dbg(dev, "calling genz_unregister_bridge\n");
		genz_unregister_bridge(obr->obr_dev);
		if (ret) {
			dev_dbg(dev,
				"genz_unregister_bridge failed with error %d\n",
				ret);
			goto err;
		}
	}
	bdata->block_remove(pdev, obr);
	/* Revisit: finish this */
	return 0;

err:
	return ret;
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
