// SPDX-License-Identifier: GPL-2.0
/*
 * IntelliProp Orthus Gen-Z Bridge Driver
 *
 * Author: Jim Hull <jim.hull@hpe.com>
 * Author: Jim Hull <jmhull@intelliprop.com>
 *
 * Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 * © Copyright 2021 IntelliProp Inc. All rights reserved.
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

#ifndef pmem_wmb
#define pmem_wmb() wmb()
#endif

static int managed = 1;
module_param(managed, int, 0444);
MODULE_PARM_DESC(managed, "enable managed mode (default 1)");

struct orthus_bridge bridge = { 0 };  /* only 1 supported */

/* Revisit: make these dynamic based on bridge HW */
static struct genz_bridge_info orthus_br_info = {
	.req_zmmu            = 1,
	.rsp_zmmu            = 0,
	.xdm                 = 1,
	.rdm                 = 0,
	.load_store          = 1,
	.kern_map_data       = 1,
	.loopback            = 0,
	.block_max_xfer      = BIT_ULL(16), /* 64KiB */
};

static int orthus_bridge_info(struct genz_bridge_dev *gzbr,
			      struct genz_bridge_info *info)
{
	struct orthus_bridge *obr = orthus_gzbr_to_obr(gzbr);

	if (obr != &bridge)  /* not our bridge */
		return -EINVAL;

	*info = orthus_br_info;
	info->min_cpuvisible_addr = obr->req_zmmu.cpu_res.start;
	info->max_cpuvisible_addr = obr->req_zmmu.cpu_res.end;
	info->nr_req_page_grids = obr->req_zmmu.num_pgs;
	info->nr_req_ptes = obr->req_zmmu.num_ptes;
	return 0;
}

static inline bool within_res(loff_t start, loff_t end, struct resource *res)
{
	return (end > start) && (start >= res->start) && (end <= res->end);
}

static int orthus_control_offset_to_base(struct orthus_bridge *obr,
					 loff_t offset, size_t size,
					 loff_t *blk_offset, void __iomem **base,
					 ulong *pgoff)
{
	loff_t res_start = offset + obr->sw_layer.res.start;
	loff_t res_end = res_start + size - 1;
	struct resource *res;
	int ret = 0;

	pr_debug("offset=0x%llx, res_start=0x%llx\n", offset, res_start);

	if (within_res(res_start, res_end, &obr->sw_layer.res)) {
		*base = obr->sw_layer.base;
		res = &obr->sw_layer.res;
	} else if (within_res(res_start, res_end, &obr->req_layer.res)) {
		*base = obr->req_layer.base;
		res = &obr->req_layer.res;
	} else if (within_res(res_start, res_end, &obr->req_zmmu.res)) {
		*base = obr->req_zmmu.base;
		res = &obr->req_zmmu.res;
	} else if (within_res(res_start, res_end, &obr->raw_cb.res)) {
		*base = obr->raw_cb.base;
		res = &obr->raw_cb.res;
	} else if (within_res(res_start, res_end, &obr->link_0.res)) {
		*base = obr->link_0.base;
		res = &obr->link_0.res;
	} else if (within_res(res_start, res_end, &obr->phy_0.res)) {
		*base = obr->phy_0.base;
		res = &obr->phy_0.res;
	} else if (within_res(res_start, res_end, &obr->link_1.res)) {
		*base = obr->link_1.base;
		res = &obr->link_1.res;
	} else if (within_res(res_start, res_end, &obr->phy_1.res)) {
		*base = obr->phy_1.base;
		res = &obr->phy_1.res;
	} else if (within_res(res_start, res_end, &obr->pte_table.res)) {
		*base = obr->pte_table.base;
		res = &obr->pte_table.res;
	} else if (within_res(res_start, res_end, &obr->raw_cb_table.res)) {
		*base = obr->raw_cb_table.base;
		res = &obr->raw_cb_table.res;
	} else {
		pr_debug("Bad offset 0x%llx, res_start=0x%llx", offset, res_start);
		ret = EINVAL;  /* warn for bad offset, not error */
	}
	if (ret == 0) {
		*blk_offset = res_start - res->start;
		if (pgoff)
			*pgoff = PHYS_PFN(res_start);
		pr_debug("base=0x%px, res_start=0x%llx, res->start=0x%llx", *base, res_start, res->start);
	}

	return ret;
}

#define ORTHUS_FIXUPS_V0P12
/* Revisit: temporary - fill in some PTRs & Vdef Hdrs missing in HW */
static int orthus_local_control_read_fixup(struct orthus_bridge *obr, loff_t offset,
					   size_t size, void *data, uint flags)
{
#if defined(ORTHUS_FIXUPS_V0P12)
	if (offset == 0x130 && size == 4) {            /* Core StructPTR9 */
		*((uint32_t *)data) = 0x6b00;
		return 1;
	} else if (offset == 0x134 && size == 4) {     /* Core StructPTR10 */
		*((uint32_t *)data) = 0x6c00;
		return 1;
	}
#endif
	return 0;
}

int orthus_local_control_read(struct orthus_bridge *obr,
			      loff_t offset,
			      size_t size, void *data, uint flags)
{
	struct device          *dev;
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
	dev = obr->obr_dev;
	ret = orthus_local_control_read_fixup(obr, offset, size, data, flags);
	if (ret == 1)
		return 0;
	ret = orthus_control_offset_to_base(obr, offset, size,
					    &blk_offset, &base, NULL);
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
	char gcstr[GCID_STRING_LEN+1];
	void *src;

	if (genz_is_local_bridge(gzbr, rmri)) {
		return orthus_local_control_read(obr, offset, size, data, flags);
	}

	src = rmri->cpu_addr + offset;  /* Revisit: CAccess */
	dev_dbg(dev, "%s offset=0x%llx, size=0x%lx, src=%px\n",
		genz_gcid_str(rmri->gcid, gcstr, sizeof(gcstr)),
		offset, size, src);
	memcpy(data, src, size);
	/* Revisit: flush/fence flags */
	return 0;
}

int orthus_local_control_write(struct orthus_bridge *obr,
			       loff_t offset,
			       size_t size, void *data, uint flags)
{
	struct device          *dev;
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
	dev = obr->obr_dev;
	if (size == 0)
		return 0;
	ret = orthus_control_offset_to_base(obr, offset, size,
					    &blk_offset, &base, NULL);
	if (ret < 0)
		return ret;

	csr_align = (uint)blk_offset & 7u;
	dev_dbg(dev, "base=0x%px, offset=0x%llx, size=%lu, blk_offset=0x%llx\n", base, offset, size, blk_offset);

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
	char gcstr[GCID_STRING_LEN+1];
	void *dest;

	if (genz_is_local_bridge(gzbr, rmri)) {
		return orthus_local_control_write(obr, offset, size, data, flags);
	}

	dest = rmri->cpu_addr + offset;  /* Revisit: CAccess */
	dev_dbg(dev, "%s offset=0x%llx, size=0x%lx, dest=%px\n",
		genz_gcid_str(rmri->gcid, gcstr, sizeof(gcstr)),
		offset, size, dest);
	memcpy(dest, data, size);
	/* Revisit: flush/fence flags */
	return 0;
}

static int orthus_control_mmap(struct genz_bridge_dev *gzbr,
			       off_t offset, size_t size,
			       ulong *pgoff, bool *wc)
{
	struct orthus_bridge *obr = orthus_gzbr_to_obr(gzbr);
	loff_t blk_offset;
	void __iomem *base;
	int ret;

	ret = orthus_control_offset_to_base(obr, offset, size,
					    &blk_offset, &base, pgoff);
	ret = -abs(ret);  /* force negative error */
	*wc = true;
	return ret;
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
	orthus_local_control_write(obr, req_zmmu->pg_base_offset + offset,
				   sizeof(*pg), pg, 0);
	return ret;
}

static int orthus_req_pte_write(struct genz_bridge_dev *gzbr, struct genz_pte_info *info)
{
	struct orthus_bridge *obr = orthus_gzbr_to_obr(gzbr);
	uint i, first = info->pte_index, last = first + info->zmmu_pages - 1;
	uint64_t addr = info->pte.req.control.addr;
	uint64_t ps = BIT_ULL(info->pg->page_grid.page_size_0);
	int ret = 0;

	struct iprop_genz_req_zmmu *const req_zmmu = &obr->req_zmmu;

	uint8_t pte_dw_width = req_zmmu->pte_sz / 32; //pte_sz must be 32 bit multiple
	uint8_t pte_byte_width = req_zmmu->pte_sz / 8;
	uint32_t offset = (info->pte_index) * pte_byte_width; //Arithmetic???
	uint32_t pte_buf[pte_dw_width];

	pr_debug("pte_sz=%d, pte_dw_width=%d, pte_byte_width=%d", req_zmmu->pte_sz, pte_dw_width, pte_byte_width);
	pr_debug("index=%d pte_base=0x%llX offset=%d\n", info->pte_index, req_zmmu->pte_base_offset, offset);

	//Create PTE buffer
	memset(pte_buf, 0, sizeof(pte_buf));

	for (i = first; i <= last; i++) {
		write_pte( &req_zmmu->pte_cfg,
			   &pte_buf[0],
			   0,
			   req_zmmu->pte_sz,
			   info->pte.req.v,
			   info->pte.req.et,
			   info->pte.req.d_attr,
			   info->pte.req.st,
			   info->pte.req.drc,
			   info->pte.req.pp,
			   info->pte.req.cce,
			   info->pte.req.ce,
			   info->pte.req.wpe,
			   info->pte.req.pse,
			   info->pte.req.pfme,
			   info->pte.req.pec,
			   info->pte.req.lpe,
			   info->pte.req.nse,
			   info->pte.req.write_mode,
			   info->pte.req.tc,
			   info->pte.req.pasid,
			   genz_gcid_cid(info->pte.req.dgcid),
			   genz_gcid_sid(info->pte.req.dgcid),
			   info->pte.req.tr_index,
			   info->pte.req.co,
			   info->pte.req.rkey,
			   addr >> 12, //Remove bottom 12 bits
			   info->pte.req.control.dr_iface);

		print_pte(&req_zmmu->pte_cfg, &pte_buf[0], 0, req_zmmu->pte_sz);

		//Write the PTE
		orthus_local_control_write(obr, req_zmmu->pte_base_offset + offset,
					   pte_byte_width, &pte_buf, 0);
		addr += ps;
		offset += pte_byte_width;
	}

	return ret;
}

/* Revisit: this is a copy of sg_copy_buffer, except using
 * memcpy_flushcache instead of memcpy */
/**
 * sg_copy_buffer_flush - Copy data between a linear buffer and an SG list
 * @sgl:		 The SG list
 * @nents:		 Number of SG entries
 * @buf:		 Where to copy from
 * @buflen:		 The number of bytes to copy
 * @skip:		 Number of bytes to skip before copying
 * @to_buffer:		 transfer direction (true == from an sg list to a
 *			 buffer, false == from a buffer to an sg list
 *
 * Returns the number of copied bytes.
 *
 **/
static size_t sg_copy_buffer_flush(struct scatterlist *sgl, unsigned int nents, void *buf,
		      size_t buflen, off_t skip, bool to_buffer)
{
	unsigned int offset = 0;
	struct sg_mapping_iter miter;
	unsigned int sg_flags = SG_MITER_ATOMIC;

	if (to_buffer)
		sg_flags |= SG_MITER_FROM_SG;
	else
		sg_flags |= SG_MITER_TO_SG;

	sg_miter_start(&miter, sgl, nents, sg_flags);

	if (!sg_miter_skip(&miter, skip))
		return false;

	while ((offset < buflen) && sg_miter_next(&miter)) {
		unsigned int len;

		len = min(miter.length, buflen - offset);

		if (to_buffer)
			memcpy_flushcache(buf + offset, miter.addr, len);
		else
			memcpy_flushcache(miter.addr, buf + offset, len);

		offset += len;
	}

	sg_miter_stop(&miter);

	return offset;
}

static int orthus_sgl_request(struct genz_dev *zdev, struct genz_sgl_info *sgli)
{
	int ret = 0;
	size_t copied;
	void *zaddr;

	/* Revisit: Just to get something to work, use memcpy().
	 * Change to XDM with interrupts for perf.
	 */
	zaddr = sgli->rmri->cpu_addr + sgli->offset;

	if (sgli->data_dir == WRITE) {
		/* Revisit: debug */
		dev_dbg_ratelimited(&zdev->dev,
				    "%s: tag=%#x, wr_addr=%px, len=%lu\n",
				    "WR", sgli->tag, zaddr, sgli->len);
		copied = sg_copy_buffer_flush(sgli->sgl, sgli->nents,
					      zaddr, sgli->len, 0, true);
		/* Revisit: check copied == sgli->len */
		pmem_wmb();
	} else {  /* READ */
		dev_dbg_ratelimited(&zdev->dev,
				    "%s: tag=%#x, rd_addr=%px, len=%lu\n",
				    "RD", sgli->tag, zaddr, sgli->len);
		copied = sg_copy_from_buffer(sgli->sgl, sgli->nents,
					     zaddr, sgli->len);
		/* Revisit: check copied == sgli->len */
	}

	/* Revisit: poll for completion */
	sgli->cmpl_fn(zdev, sgli);
	return ret;
}

static irqreturn_t orthus_raw_cb_isr(int irq, void *data_ptr)
{
	int ret = IRQ_HANDLED;

	pr_debug("irq=%d\n", irq);
	/* Revisit: implement this */
	return ret;
}

static int phys_registered = 0;
static int orthus_genz_phy_probe(struct platform_device *pdev,
				 struct orthus_bridge *obr)
{
	struct iprop_genz_phy *phy = NULL;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	if (phys_registered == 0){
		phy = &obr->phy_0;
		phys_registered++;
	} else {
		phy = &obr->phy_1;
	}

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
	struct iprop_genz_phy *const phy = &obr->phy_0;
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
	clk_bulk_disable_unprepare(phy->num_clks, phy->clks);
	orthus_unmap_and_release(dev, phy->base);
	return 0;
}

static int links_registered = 0;
static int orthus_genz_link_layer_probe(struct platform_device *pdev,
					struct orthus_bridge *obr)
{
	struct iprop_genz_link_layer * link = NULL;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	if (links_registered == 0){
		link = &obr->link_0;
		links_registered++;
	} else {
		link = &obr->link_1;
	}

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
	struct iprop_genz_link_layer *const link = &obr->link_0;
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
	of_address_to_resource(np, 1, &req_zmmu->cpu_res);
	dev_dbg(dev, "req_zmmu->base(%px)=0x%llx, cpu_res=0x%llx-0x%llx\n",
		req_zmmu->base, ioread64(req_zmmu->base),
		req_zmmu->cpu_res.start, req_zmmu->cpu_res.end);
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
	struct genz_component_page_grid_structure gz_cpgs;
	struct device *dev = req_zmmu->dev;
	uint32_t cpgs_ptr;
	int ret;

	/* compute req zmmu pg_base_offset */
	/* Revisit: hardcoded offset */
	ret = orthus_local_control_read(obr, 0x48, 4, &cpgs_ptr, 0);
	if (ret < 0)
		return ret;

	ret = orthus_local_control_read(obr, cpgs_ptr << 4,
					sizeof(gz_cpgs), &gz_cpgs, 0);
	if (ret < 0)
		return ret;

	req_zmmu->pg_base_offset = (loff_t)gz_cpgs.pg_base_ptr << 4;
	req_zmmu->pte_base_offset = (loff_t)gz_cpgs.pte_base_ptr << 4;
	req_zmmu->pte_sz = gz_cpgs.pte_sz;
	req_zmmu->num_pgs = (gz_cpgs.pg_table_sz == 0) ? 256 : gz_cpgs.pg_table_sz;
	req_zmmu->num_ptes = (gz_cpgs.pte_table_sz == 0) ? (1ULL << 32) : gz_cpgs.pte_table_sz;

	dev_dbg(dev, "req_zmmu->pg_base_offset=0x%llx\n",
		req_zmmu->pg_base_offset);
	dev_dbg(dev, "req_zmmu->pte_base_offset=0x%llx\n",
		req_zmmu->pte_base_offset);
	dev_dbg(dev, "req_zmmu->pte_sz=0x%x\n",
		req_zmmu->pte_sz);

	iprop_genz_calc_pte_width(&gz_cpgs, &req_zmmu->pte_cfg);
	//dump_pte_bit_positions(&pte_cfg);

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

static int orthus_genz_sw_layer_probe(struct platform_device *pdev,
					       struct orthus_bridge *obr)
{
	struct iprop_genz_sw_layer *const sw_layer = &obr->sw_layer;
	struct device *dev = &pdev->dev;
	struct device_node *const np = dev->of_node;
	int ret;

	sw_layer->dev = dev;
	ret = devm_clk_bulk_get_all(dev, &sw_layer->clks);
	if (ret < 0) {
		dev_err(dev, "failed to get genz_sw_layer clocks, ret=%d\n", ret);
		return ret;
	}
	sw_layer->num_clks = ret;
	sw_layer->base = of_io_request_and_map(np, 0, of_node_full_name(np));
	if (IS_ERR(sw_layer->base)) {
		ret = PTR_ERR(sw_layer->base);
		dev_err(dev, "mapping genz_sw_layer registers failed, ret=%d\n", ret);
		return ret;
	}
	of_address_to_resource(np, 0, &sw_layer->res);
	dev_dbg(dev, "sw_layer->base(%px)=0x%llx, res.start=0x%llx\n", sw_layer->base, ioread64(sw_layer->base), sw_layer->res.start);
	ret = clk_bulk_prepare_enable(sw_layer->num_clks, sw_layer->clks);
	if (ret < 0) {
		dev_err(dev, "enabling genz_sw_layer clocks failed, ret=%d\n", ret);
	}

	/* Revisit: add other sw_layer init */

  return ret;
}

static int orthus_genz_sw_layer_remove(struct platform_device *pdev,
						struct orthus_bridge *obr)
{
	struct iprop_genz_sw_layer *const sw_layer = &obr->sw_layer;
	struct device *dev = &pdev->dev;

	dev_dbg(dev, "entered\n");
	clk_bulk_disable_unprepare(sw_layer->num_clks, sw_layer->clks);
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

static const struct iprop_block_data iprop_genz_sw_layer_data = {
	.type = IPROP_GENZ_SW_LAYER,
	.block_probe = orthus_genz_sw_layer_probe,
	.block_remove = orthus_genz_sw_layer_remove,
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
	{ .compatible = "xlnx,iprop-genz-standard-switch-layer-1.0",
	  .data = &iprop_genz_sw_layer_data },
	{ .compatible = "xlnx,iprop-genz-pte-table",
	  .data = &iprop_genz_pte_table_data },
	{ .compatible = "xlnx,iprop-genz-raw-cb-table",
	  .data = &iprop_genz_raw_cb_table_data },
	{ }
};
MODULE_DEVICE_TABLE(of, orthus_dt_ids);

static struct genz_bridge_driver orthus_genz_bridge_driver = {
	.bridge_info = orthus_bridge_info,
	.control_read = orthus_control_read,
	.control_write = orthus_control_write,
	.control_mmap = orthus_control_mmap,
	.req_page_grid_write = orthus_req_page_grid_write,
	.req_pte_write = orthus_req_pte_write,
	.sgl_request = orthus_sgl_request,
#ifdef REVISIT
	.data_read = orthus_data_read,
	.data_write = orthus_data_write,
	.dma_map_sg_attrs = orthus_dma_map_sg_attrs,
	.dma_unmap_sg_attrs = orthus_dma_unmap_sg_attrs,
	.alloc_queues = orthus_alloc_queues,
	.free_queues = orthus_free_queues,
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
MODULE_IMPORT_NS(drivers/genz/genz);
MODULE_DESCRIPTION("IntelliProp Orthus Gen-Z Bridge Driver");
