// SPDX-License-Identifier: GPL-2.0
/*
 * IntelliProp Sphinx CXL to Gen-Z Bridge Driver
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
#include <linux/pci.h>
#include <linux/genz.h>
#include <linux/interrupt.h>

#include "sphinx.h"

#define DRIVER_NAME                   "sphinx"

#ifndef pmem_wmb
#define pmem_wmb() wmb()
#endif

static int managed = 1;
module_param(managed, int, 0444);
MODULE_PARM_DESC(managed, "enable managed mode (default 1)");

static int no_genz = 0;
module_param(no_genz, int, 0444);
MODULE_PARM_DESC(no_genz, "do not register bridge with genz (default 0)");

static int cpuvisible_phys_offset = 0;
module_param(cpuvisible_phys_offset, int, 0444);
MODULE_PARM_DESC(cpuvisible_phys_offset, "apply the cpuvisible_phys_offset to req zmmu (default 0)");

//#define SPHINX_FIXUPS_V20210830
/* Revisit: temporary - fill in some PTRs & Vdef Hdrs missing in HW */
static int sphinx_local_control_read_fixup(struct sphinx_bridge *sbr, loff_t offset,
					   size_t size, void *data, uint flags)
{
#if defined(SPHINX_FIXUPS_V20210830)
	if (offset == 0x40070 && size == 4) {         /* Interface1 Next PTR */
		*((uint32_t *)data) = 0x0;
		return 1;
	} else if (offset == 0x40080 && size == 4) {  /* Interface1 IPHY PTR */
		*((uint32_t *)data) = 0x5000;
		return 1;
	} else if (offset == 0x8001c && size == 4) {   /* PTEBasePTR */
		*((uint32_t *)data) = 0x00030000;
		return 1;
	}
#endif
	return 0;
}

static inline bool sphinx_bad_local_cs_offset_size(struct sphinx_bridge *sbr,
						   loff_t offset, size_t size)
{
	return ((offset >= sbr->bar_size) ||
		((offset + size) >= sbr->bar_size));
}

static int sphinx_local_control_read(struct sphinx_bridge *sbr,
				     struct device *dev, loff_t offset,
				     size_t size, void *data, uint flags)
{
	uint64_t               csr_val = 0, val;
	uint32_t               csr = (uint32_t)offset & ~7u;
	uint                   csr_align = (uint)offset & 7u;
	uint                   shift;
	ssize_t                copy;
	void __iomem           *base;
	int                    ret;

	if (!sbr)
		return -EINVAL;
	ret = sphinx_local_control_read_fixup(sbr, offset, size, data, flags);
	if (ret == 1)
		return 0;

	if (sphinx_bad_local_cs_offset_size(sbr, offset, size)) {
		dev_dbg(dev, "bad local offset size, offset=0x%llx, size=%lu\n",
			offset, size);
		return -EINVAL;
	}

	/* Revisit: mostly copied from wildcat */
	/* Revisit: does sphinx have these same size/alignment restrictions? */
	/* control space accessible only with 8-byte size & alignment */
	base = sbr->bar;
	shift = csr_align * 8;                       /* 0 - 56 */
	copy = min((size_t)(8 - csr_align), size);   /* 1 - 8 */
	dev_dbg(dev, "sbr=%px, offset=0x%llx, size=%lu, shift=%u, copy=%ld, csr=0x%x, base=%px\n",
		sbr, offset, size, shift, copy, csr, base);

	/* Revisit: locking */
	while (size > 0) {
		csr_val = ioread64(base + csr);
		dev_dbg(dev, "csr=0x%x, csr_val=0x%llx, shifted val=0x%llx, size=%zu\n",
			csr, csr_val, csr_val >> shift, size);
		val = csr_val >> shift;
		/* Revisit: endianness */
		memcpy(data, &val, copy);
		size -= copy;
		data += copy;
		copy = min((size_t)8, size);
		shift = 0;
		csr += 8;
	}

	return ret;
}

static int sphinx_control_read(struct genz_bridge_dev *gzbr, loff_t offset,
			       size_t size, void *data,
			       struct genz_rmr_info *rmri, uint flags)
{
	struct sphinx_bridge *sbr = sphinx_gzbr_to_sbr(gzbr);
	struct device *dev = &gzbr->zdev.dev;
	char gcstr[GCID_STRING_LEN+1];
	void *src;

	if (genz_is_local_bridge(gzbr, rmri)) {
		return sphinx_local_control_read(sbr, dev, offset, size, data, flags);
	}

	src = rmri->cpu_addr + offset;  /* Revisit: CAccess */
	dev_dbg(dev, "%s offset=0x%llx, size=0x%lx, src=%px\n",
		genz_gcid_str(rmri->gcid, gcstr, sizeof(gcstr)),
		offset, size, src);
	memcpy(data, src, size);
	/* Revisit: flush/fence flags */
	return 0;
}

static int sphinx_local_control_write(struct sphinx_bridge *sbr,
				      struct device *dev, loff_t offset,
				      size_t size, void *data, uint flags)
{
	uint64_t               val;
	uint32_t               val4;
	uint16_t               val2;
	uint8_t                val1;
	uint                   csr_align = (uint)offset & 7u;
	void __iomem           *base;
	int                    ret = 0;

	if (!sbr)
		return -EINVAL;
	base = sbr->bar;
	dev_dbg(dev, "base=0x%px, offset=0x%llx, size=%lu\n", base, offset, size);
	if (size == 0)
		return 0;

	if (sphinx_bad_local_cs_offset_size(sbr, offset, size)) {
		ret = -EINVAL;
		goto out;
	}

	/* Revisit: locking */
	/* do small writes until csr is 8-byte aligned */
	if (csr_align & 0x1) {  /* do 1-byte write */
		val1 = *((uint8_t *)data);
		dev_dbg(dev, "val1=0x%x, offset=0x%llx\n",
			val1, offset);
		iowrite8(val1, base + offset);
		data++;
		offset++;
		size--;
		csr_align = (uint)offset & 7u;
	}
	if ((size >= 2) && (csr_align & 0x2)) {  /* do 2-byte write */
		val2 = *((uint16_t *)data);  /* Revisit: endianness */
		dev_dbg(dev, "val2=0x%x, offset=0x%llx\n",
			val2, offset);
		iowrite16(val2, base + offset);
		data += 2;
		offset += 2;
		size -= 2;
		csr_align = (uint)offset & 7u;
	}
	if ((size >= 4) && (csr_align & 0x4)) {  /* do 4-byte write */
		val4 = *((uint32_t *)data);  /* Revisit: endianness */
		dev_dbg(dev, "val4=0x%x, offset=0x%llx\n",
			val4, offset);
		iowrite32(val4, base + offset);
		data += 4;
		offset += 4;
		size -= 4;
	}

	while (size >= 8) {  /* do aligned 8-byte writes */
		memcpy(&val, data, 8);
		dev_dbg(dev, "val=0x%llx, offset=0x%llx\n",
			val, offset);
		iowrite64(val, base + offset);
		data += 8;
		offset += 8;
		size -= 8;
	}

	if (size & 0x4) {  /* do 4-byte write */
		val4 = *((uint32_t *)data);  /* Revisit: endianness */
		dev_dbg(dev, "val4=0x%x, offset=0x%llx\n",
			val4, offset);
		iowrite32(val4, base + offset);
		data += 4;
		offset += 4;
		size -= 4;
	}
	if (size & 0x2) {  /* do 2-byte write */
		val2 = *((uint16_t *)data);  /* Revisit: endianness */
		dev_dbg(dev, "val2=0x%x, offset=0x%llx\n",
			val2, offset);
		iowrite16(val2, base + offset);
		data += 2;
		offset += 2;
		size -= 2;
	}
	if (size & 0x1) {  /* do 1-byte write */
		val1 = *((uint8_t *)data);
		dev_dbg(dev, "val1=0x%x, offset=0x%llx\n",
			val1, offset);
		iowrite8(val1, base + offset);
		data++;
		offset++;
		size--;
	}

 out:
	pr_debug("returning ret=%d\n", ret);
	return ret;
}

static int sphinx_control_write(struct genz_bridge_dev *gzbr, loff_t offset,
				size_t size, void *data,
				struct genz_rmr_info *rmri, uint flags)
{
	struct sphinx_bridge *sbr = sphinx_gzbr_to_sbr(gzbr);
	struct device *dev = &gzbr->zdev.dev;
	char gcstr[GCID_STRING_LEN+1];
	void *dest;

	if (genz_is_local_bridge(gzbr, rmri)) {
		return sphinx_local_control_write(sbr, dev, offset, size, data, flags);
	}

	dest = rmri->cpu_addr + offset;  /* Revisit: CAccess */
	dev_dbg(dev, "%s offset=0x%llx, size=0x%lx, dest=%px\n",
		genz_gcid_str(rmri->gcid, gcstr, sizeof(gcstr)),
		offset, size, dest);
	memcpy(dest, data, size);
	/* Revisit: flush/fence flags */
	return 0;
}

static int sphinx_control_mmap(struct genz_bridge_dev *gzbr,
			       off_t offset, size_t size,
			       ulong *pgoff, bool *wc)
{
	struct sphinx_bridge *sbr = sphinx_gzbr_to_sbr(gzbr);
	int ret = 0;

	if (sphinx_bad_local_cs_offset_size(sbr, offset, size))
		ret = -EINVAL;
	*pgoff = PHYS_PFN(sbr->phys_base + offset);
	*wc = true;
	return ret;
}

static int sphinx_req_page_grid_write(struct genz_bridge_dev *gzbr, uint pg_index,
				      struct genz_page_grid genz_pg[])
{
	struct sphinx_bridge *sbr = sphinx_gzbr_to_sbr(gzbr);
	struct device *dev = &gzbr->zdev.dev;
	struct iprop_genz_req_zmmu *const req_zmmu = &sbr->req_zmmu;
	struct genz_page_grid_restricted_page_grid_table_array *pg;
	uint32_t offset;

	pg = &genz_pg[pg_index].page_grid;
	offset = pg_index * sizeof(*pg);
	dev_dbg(dev,
		"pg[%u]: base_addr=0x%llx, page_count=%d, page_size=%u, "
		"base_pte_idx=%u, res=%u, sizeof=%u\n", pg_index,
		(uint64_t)pg->pg_base_address_0, pg->page_count_0,
		pg->page_size_0, pg->base_pte_index_0, pg->res,
		(uint)sizeof(*pg));
	return sphinx_local_control_write(sbr, dev,
					  req_zmmu->pg_base_offset + offset,
					  sizeof(*pg), pg, 0);
}

static int sphinx_req_pte_write(struct genz_bridge_dev *gzbr, struct genz_pte_info *info)
{
	struct sphinx_bridge *sbr = sphinx_gzbr_to_sbr(gzbr);
	struct iprop_genz_req_zmmu *const req_zmmu = &sbr->req_zmmu;
	struct device *dev = &gzbr->zdev.dev;
	uint i, first = info->pte_index, last = first + info->zmmu_pages - 1;
	uint64_t addr = info->pte.req.control.addr;
	uint64_t ps = BIT_ULL(info->pg->page_grid.page_size_0);
	int ret = 0;
	uint8_t pte_dw_width = req_zmmu->pte_sz / 32; //pte_sz must be 32 bit multiple
	uint8_t pte_byte_width = req_zmmu->pte_sz / 8;
	uint32_t offset = (info->pte_index) * pte_byte_width; //Arithmetic???
	uint32_t pte_buf[pte_dw_width];

	pr_debug("pte_sz=%d, pte_dw_width=%d, pte_byte_width=%d", req_zmmu->pte_sz, pte_dw_width, pte_byte_width);
	pr_debug("index=%d pte_base=0x%llX offset=%d\n", info->pte_index, req_zmmu->pte_base_offset, offset);

	//Create PTE buffer
	memset(pte_buf, 0, sizeof(pte_buf));

	for (i = first; i <= last; i++) {
		write_pte(&req_zmmu->pte_cfg,
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
		ret |= sphinx_local_control_write(sbr, dev,
						  req_zmmu->pte_base_offset + offset,
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

static int sphinx_sgl_request(struct genz_dev *zdev, struct genz_sgl_info *sgli)
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

#ifdef REVISIT
static irqreturn_t sphinx_raw_cb_isr(int irq, void *data_ptr)
{
	int ret = IRQ_HANDLED;

	pr_debug("irq=%d\n", irq);
	/* Revisit: implement this */
	return ret;
}
#endif

static int sphinx_genz_req_zmmu_setup(struct sphinx_bridge *sbr)
{
	struct iprop_genz_req_zmmu *const req_zmmu = &sbr->req_zmmu;
	struct genz_component_page_grid_structure gz_cpgs;
	struct device *dev = sbr->sbr_dev;
	uint32_t cpgs_ptr;
	int ret;

	/* compute req zmmu pg_base_offset */
	/* Revisit: hardcoded offset */
	ret = sphinx_local_control_read(sbr, dev, 0x48, 4, &cpgs_ptr, 0);
	if (ret < 0)
		return ret;

	ret = sphinx_local_control_read(sbr, dev, cpgs_ptr << 4,
					sizeof(gz_cpgs), &gz_cpgs, 0);
	if (ret < 0)
		return ret;

	req_zmmu->pg_base_offset = (loff_t)gz_cpgs.pg_base_ptr << 4;
	req_zmmu->pte_base_offset = (loff_t)gz_cpgs.pte_base_ptr << 4;
	req_zmmu->pte_sz = gz_cpgs.pte_sz;
	/* Revisit: create an inline func to do this 0 checking */
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

static int sphinx_find_cxl_mem_range(struct pci_dev *pdev,
				     uint64_t *base, uint64_t *size)
{
	int ret = -ENODATA, dvsec = 0;
	u16 vid, dvid;
	u32 size_l, size_h, base_l, base_h;
	u64 mask28 = ~((1ULL << 28) - 1); /* low 28 bits clear */

	do {
		dvsec = pci_find_next_ext_capability(pdev, dvsec,
						     PCI_EXT_CAP_ID_DVSEC);
		if (!dvsec)
			break;
		pci_read_config_word(pdev, dvsec + PCI_DVSEC_HEADER1, &vid);
		if (vid != PCI_VENDOR_ID_CXL)
			continue;
		pci_read_config_word(pdev, dvsec + PCI_DVSEC_HEADER2, &dvid);
		if (dvid != 0)
			continue;
		pci_read_config_dword(pdev, dvsec + 0x18, &size_h);
		pci_read_config_dword(pdev, dvsec + 0x1c, &size_l);
		pci_read_config_dword(pdev, dvsec + 0x20, &base_h);
		pci_read_config_dword(pdev, dvsec + 0x24, &base_l);
		*size = (((u64)size_h << 32) | size_l) & mask28;
		*base = (((u64)base_h << 32) | base_l) & mask28;
		/* Revisit: should we be setting Memory_Active here? */
		ret = 0;
		break;
	} while (true);

	return ret;
}

static struct pci_device_id sphinx_id_table[] = {
	{ PCI_DEVICE_DATA(INTELLIPROP, SPHINX, 0), },
	{ 0 },
};
MODULE_DEVICE_TABLE(pci, sphinx_id_table);

/* Revisit: make these dynamic based on bridge HW */
static struct genz_bridge_info sphinx_br_info = {
	.req_zmmu            = 1,
	.rsp_zmmu            = 0,
	.xdm                 = 0,
	.rdm                 = 0,
	.load_store          = 1,
	.kern_map_data       = 1,
	.loopback            = 0,
	.block_max_xfer      = BIT_ULL(16), /* Revisit: 64KiB */
};

static int sphinx_bridge_info(struct genz_bridge_dev *gzbr,
			      struct genz_bridge_info *info)
{
	struct sphinx_bridge *sbr = sphinx_gzbr_to_sbr(gzbr);
	uint64_t base = 0, size = 1;
	int ret;

	*info = sphinx_br_info;
	ret = sphinx_find_cxl_mem_range(sbr->pdev, &base, &size);
	info->min_cpuvisible_addr = base;
	info->max_cpuvisible_addr = base + size - 1;
	if (cpuvisible_phys_offset)
		info->cpuvisible_phys_offset = base;
	info->nr_req_page_grids = sbr->req_zmmu.num_pgs;
	info->nr_req_ptes = sbr->req_zmmu.num_ptes;
	return ret;
}

static struct genz_bridge_driver sphinx_genz_bridge_driver = {
	.bridge_info = sphinx_bridge_info,
	.control_read = sphinx_control_read,
	.control_write = sphinx_control_write,
	.control_mmap = sphinx_control_mmap,
	.req_page_grid_write = sphinx_req_page_grid_write,
	.req_pte_write = sphinx_req_pte_write,
	.sgl_request = sphinx_sgl_request,
#ifdef REVISIT
	.data_read = sphinx_data_read,
	.data_write = sphinx_data_write,
	.dma_map_sg_attrs = sphinx_dma_map_sg_attrs,
	.dma_unmap_sg_attrs = sphinx_dma_unmap_sg_attrs,
	.alloc_queues = sphinx_alloc_queues,
	.free_queues = sphinx_free_queues,
	.generate_uuid = sphinx_generate_uuid,
	.uuid_import = sphinx_kernel_UUID_IMPORT,
	.uuid_free = sphinx_common_UUID_FREE,
	.control_structure_pointers = sphinx_control_structure_pointers,
#endif /* REVISIT */
};

#define SPHINX_CONTROL_SPACE_BAR 2

static int sphinx_probe(struct pci_dev *pdev,
			const struct pci_device_id *pdev_id)
{
	struct device *dev = &pdev->dev;
	struct sphinx_bridge *sbr;
	void __iomem *base_addr;
	phys_addr_t phys_base;
	int ret;

	dev_dbg(dev, "entered\n");
	sbr = kzalloc(sizeof(*sbr), GFP_KERNEL);
	if (!sbr) {
		dev_warn(dev, "%s: No memory\n", DRIVER_NAME);
		return -ENOMEM;
	}
	spin_lock_init(&sbr->sbr_lock);

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_dbg(&pdev->dev,
			"pci_enable_device probe error %d for device %s\n",
			ret, pci_name(pdev));
		goto err_mem;
	}

	if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
		ret = -ENOSPC;
		dev_warn(dev, "%s: No 64-bit DMA available\n",
			 DRIVER_NAME);
		goto err_pci_disable_device;
	}

	ret = pci_request_regions(pdev, DRIVER_NAME);
	if (ret < 0) {
		dev_dbg(&pdev->dev,
			"pci_request_regions error %d for device %s\n",
			ret, pci_name(pdev));
		goto err_pci_disable_device;
	}

	/* Revisit: pci_iomap_wc()? */
	base_addr = pci_iomap(pdev, SPHINX_CONTROL_SPACE_BAR, 0/*all*/);
	if (!base_addr) {
		dev_dbg(&pdev->dev,
		      "cannot iomap bar %u registers of size %lu (requested size = %u)\n",
		      SPHINX_CONTROL_SPACE_BAR,
		      (unsigned long)pci_resource_len(
			      pdev, SPHINX_CONTROL_SPACE_BAR),
		      0);
		ret = -EINVAL;
		goto err_pci_release_regions;
	}
	phys_base = pci_resource_start(pdev, SPHINX_CONTROL_SPACE_BAR);

	dev_dbg(&pdev->dev,
		"bar=%u, phys_base=0x%lx, actual len=%lu, requested len=%u, base_addr=0x%lx\n",
		SPHINX_CONTROL_SPACE_BAR,
		(unsigned long)phys_base,
		(unsigned long)pci_resource_len(pdev, SPHINX_CONTROL_SPACE_BAR),
		0,
		(unsigned long)base_addr);

	sbr->bar = base_addr;
	sbr->phys_base = phys_base;
	sbr->sbr_dev = dev; /* Revisit: shouldn't need both this and pdev */
	sbr->pdev = pdev;
	sbr->bar_size = (size_t)pci_resource_len(pdev,
						 SPHINX_CONTROL_SPACE_BAR);
	sbr->valid = true;
	pci_set_drvdata(pdev, sbr);
	if (no_genz) {
		dev_dbg(dev, "not calling genz_register_bridge (no_genz=1)\n");
	} else {
		dev_dbg(dev, "calling sphinx_genz_req_zmmu_setup\n");
		sphinx_genz_req_zmmu_setup(sbr);
		/* Revisit: finish this */

		dev_dbg(dev, "calling genz_register_bridge\n");
		ret = genz_register_bridge(dev, &sphinx_genz_bridge_driver, sbr);
		if (ret) {
			dev_dbg(dev,
				"genz_register_bridge failed with error %d\n",
				ret);
			goto err_free_interrupts;
		}
		sbr->gzbr = genz_find_bridge(dev);
	}
	/* Revisit: call pci_set_master() or CXL equivalent? */
	return 0;

err_unreg_br:
	if (!no_genz)
		genz_unregister_bridge(dev);
err_free_interrupts:
	/* Revisit: sphinx_free_interrupts(pdev); */
err_iommu_free:
	/* Revisit: amd_iommu_free_device(pdev); */
err_pci_release_regions:
	pci_release_regions(pdev);
err_pci_disable_device:
	pci_disable_device(pdev);
err_mem:
	kfree(sbr);
err_out:
	return ret;
}

static void sphinx_remove(struct pci_dev *pdev)
{
	struct sphinx_bridge *sbr = sphinx_pdev_to_sbr(pdev);
	const struct device *dev = &pdev->dev;
	int ret;

	dev_dbg(dev, "entered\n");
	if (!no_genz) {
		dev_dbg(dev, "calling genz_unregister_bridge\n");
		ret = genz_unregister_bridge(sbr->sbr_dev);
		if (ret) {
			dev_dbg(dev,
				"genz_unregister_bridge failed with error %d\n", ret);
			return;
		}
	}
	pci_iounmap(pdev, sbr->bar);
	pci_disable_device(pdev);
	pci_release_regions(pdev);
	/* Revisit: finish this */
	kfree(sbr);
}

static struct pci_driver sphinx_pci_driver = {
	.name      = DRIVER_NAME,
	.id_table  = sphinx_id_table,
	.probe     = sphinx_probe,
	.remove    = sphinx_remove,
};

static int __init sphinx_init(void)
{
	int ret;

	ret = pci_register_driver(&sphinx_pci_driver);
	if (ret < 0) {
		pr_warn("%s:%s: pci_register_driver error, ret = %d\n",
			DRIVER_NAME, __func__, ret);
	}
	return ret;
}

static void __exit sphinx_exit(void)
{
	pci_unregister_driver(&sphinx_pci_driver);
}

module_init(sphinx_init);
module_exit(sphinx_exit);

MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(drivers/genz/genz);
MODULE_DESCRIPTION("IntelliProp Sphinx CXL to Gen-Z Bridge Driver");
