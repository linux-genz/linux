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

#include <linux/slab.h>
#include <linux/sysfs.h>

#include "genz.h"
#include "genz-control.h"
#include "genz-probe.h"
#include "genz-netlink.h"
#include "genz-sysfs.h"

static ssize_t uuid_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct device *dev;
	struct genz_dev *zdev;

	dev = kobj_to_dev(kobj);
	zdev = to_genz_dev(dev);
	if (zdev == NULL) {
		pr_debug("zdev is NULL\n");
		return snprintf(buf, PAGE_SIZE, "bad zdev\n");
	}
	return snprintf(buf, PAGE_SIZE, "%pUb\n", &zdev->class_uuid);
}

static struct kobj_attribute uuid_attribute =
	__ATTR(uuid, (0444), uuid_show, NULL);

int genz_create_uuid_file(struct genz_dev *zdev)
{
	int ret = 0;

	ret = sysfs_create_file(&zdev->dev.kobj, &uuid_attribute.attr);
	return ret;
}

void genz_remove_uuid_file(struct genz_dev *zdev)
{
	sysfs_remove_file(&zdev->dev.kobj, &uuid_attribute.attr);
}

static ssize_t mgr_uuid_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct genz_fabric *fab;

	fab = dev_to_genz_fabric(dev);
	pr_debug("fab is %px\n", fab);
	if (fab == NULL) {
		pr_debug("fab is NULL\n");
		return snprintf(buf, PAGE_SIZE, "bad fabric\n");
	}
	return snprintf(buf, PAGE_SIZE, "%pUb\n", &fab->mgr_uuid);
}
static DEVICE_ATTR(mgr_uuid, (S_IRUGO), mgr_uuid_show, NULL);

int genz_create_mgr_uuid_file(struct device *dev)
{
	int ret = 0;

	pr_debug("create_file for dev %px\n", dev);
	ret = device_create_file(dev, &dev_attr_mgr_uuid);
	return ret;
}

static int traverse_control_pointers(struct genz_bridge_dev *zbdev,
	struct genz_rmr_info *rmri,
	struct genz_control_info *parent,
	int struct_type,
	int struct_vers,
	struct kobject *dir,
	uint order[]);

/**
 * genz_valid_table_type - determines if a control table type is valid
 * Returns true when the control table type is valid
 * Returns false when the control table type is not valid
 */
static bool genz_validate_table_type(int type)
{
	if (type < GENZ_TABLE_ENUM_START ||
	    type >= (genz_table_type_to_ptrs_nelems+GENZ_TABLE_ENUM_START))
		return false;
	return true;
}

/**
 * genz_table_name - return the name of a given control table ptr_type
 * int type - the control table type
 * Returns the name of a table type or "unknown" if the type is not vaild.
 */
static inline const char *genz_table_name(int type,
				const struct genz_control_structure_ptr *csp)
{
	if (!genz_validate_table_type(type))
		return "unknown";
	if (csp)
		return csp->ptr_name;

	return genz_table_type_to_ptrs[type-GENZ_TABLE_ENUM_START].name;
}

/**
 * genz_structure_name - return the name of a given control structure ptr_type
 * int type - the control structure type
 * Returns the name of a structure type or "unknown" if the type is not vaild.
 */
static inline const char *genz_structure_name(int type)
{
	if (!genz_validate_structure_type(type))
		return "unknown";

	return genz_struct_type_to_ptrs[type].name;
}

/* is_struct_type - return true if the type is a struct (vs. table) */
static inline bool is_struct_type(int type)
{
	return (type < GENZ_TABLE_ENUM_START);
}

/**
 * genz_control_name - return the name of a given control structure/table
 * int type - the control structure/table type
 * csp - pointer to the genz_control_structure_ptr
 * Returns the name or "unknown" if the type is not vaild.
 */
static inline const char *genz_control_name(int type,
				const struct genz_control_structure_ptr *csp)
{
	if (is_struct_type(type))
		return genz_structure_name(type);
	else
		return genz_table_name(type, csp);
}

static void control_info_release(struct kobject *kobj)
{
	struct genz_control_info *ci = to_genz_control_info(kobj);

	pr_debug("kobj %s, ci=%px\n", kobject_name(kobj), ci);
	if (ci->battr.private) {
		pr_debug("sysfs_remove_bin_file for %s\n", ci->battr.attr.name);
		sysfs_remove_bin_file(&ci->kobj, &ci->battr);
	}
	kfree(ci);
}

static ssize_t control_info_attr_show(struct kobject *kobj,
			     struct attribute *attr,
			     char *buf)
{
	struct genz_control_info_attribute *attribute;
	struct genz_control_info *info;

	attribute = to_genz_control_info_attr(attr);
	info = to_genz_control_info(kobj);

	if (!attribute->show)
		return -EIO;

	pr_debug("calling show for genz_control_info %s start 0x%lx size 0x%lx\n", info->kobj.name,
			info->start, info->size);
	return attribute->show(info, attribute, buf);
}

static ssize_t control_info_attr_store(struct kobject *kobj,
			      struct attribute *attr,
			      const char *buf, size_t len)
{
	struct genz_control_info_attribute *attribute;
	struct genz_control_info *info;

	attribute = to_genz_control_info_attr(attr);
	info = to_genz_control_info(kobj);

	if (!attribute->store)
		return -EIO;

	return attribute->store(info, attribute, buf, len);
}

static int validate_ci(struct genz_control_info *ci,
		loff_t offset,
		size_t size,
		char *data,
		struct genz_bridge_dev **zbdev)
{
	struct genz_bridge_driver *zdriver;

	*zbdev = ci->zbdev;
	if (*zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return -EINVAL;
	}
	zdriver = (*zbdev)->zbdrv;
	if (zdriver == NULL) {
		pr_debug("zdriver is NULL\n");
		return -EINVAL;
	}
	if (zdriver->control_read == NULL) {
		pr_debug("zdriver has NULL control_read function\n");
		return -EINVAL;
	}
	if (offset > ci->size) {
		pr_debug("requested offset (%lld) is outside control structure size (%ld)\n",
			offset, ci->size);
		return -EINVAL;
	}
	if (offset+size > ci->size) {
		pr_debug(
			"requested offset+size (%lld + %ld) is outside control structure size (%ld)\n",
			offset, size, ci->size);
		return -EINVAL;
	}
	if (data == NULL) {
		pr_debug("data pointer is NULL\n");
		return -EINVAL;
	}
	return 0;
}

static ssize_t read_control_structure(struct file *fd,
		struct kobject *kobj,
		struct bin_attribute *battr,
		char *data,
		loff_t offset,
		size_t size)
{
	struct genz_control_info *ci = to_genz_control_info(kobj);
	struct genz_rmr_info *rmri = ci->rmri;
	struct genz_bridge_dev *zbdev;
	char gcstr[GCID_STRING_LEN+1];
	uint32_t gcid;
	ssize_t ret = 0;
	int err;

	err = validate_ci(ci, offset, size, data, &zbdev);
	if (err < 0) {
		pr_debug("arguments invalid error: %d\n", err);
		/* Revisit: what should it return on error? */
		return err;
	}
	gcid = genz_rmri_to_gcid(zbdev, rmri);
	pr_debug("reading %s %s, offset=0x%llx, size=0x%lx, ci->start=0x%lx, ci->size=0x%lx\n",
		 genz_gcid_str(gcid, gcstr, sizeof(gcstr)), kobject_name(kobj),
		 offset, size, ci->start, ci->size);

	ret = genz_control_read(zbdev, ci->start+offset, size, data, rmri, 0);
	if (ret) {
		pr_debug("genz_control_read failed with %ld\n", ret);
		return ret;
	}
	return size;
}

static ssize_t write_control_structure(struct file *fd,
		struct kobject *kobj,
		struct bin_attribute *battr,
		char *data,
		loff_t offset,
		size_t size)
{
	struct genz_control_info *ci = to_genz_control_info(kobj);
	struct genz_rmr_info *rmri = ci->rmri;
	struct genz_bridge_dev *zbdev;
	char gcstr[GCID_STRING_LEN+1];
	uint32_t gcid;
	ssize_t ret = 0;
	int err;

	err = validate_ci(ci, offset, size, data, &zbdev);
	if (err < 0) {
		pr_debug("arguments invalid error: %d\n", err);
		return err;
	}
	gcid = genz_rmri_to_gcid(zbdev, rmri);
	pr_debug("writing %s %s, offset=0x%llx, size=0x%lx, ci->start=0x%lx, ci->size=0x%lx\n",
		 genz_gcid_str(gcid, gcstr, sizeof(gcstr)), kobject_name(kobj),
		 offset, size, ci->start, ci->size);

	ret = genz_control_write(zbdev, ci->start+offset, size, data, rmri, 0);
	if (ret) {
		pr_debug("genz_control_write failed with %ld\n", ret);
		return ret;
	}
	return size;
}

static const struct vm_operations_struct genz_phys_vm_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys,
#endif
};

int genz_mmap_resource_range(ulong gz_pgoff, struct vm_area_struct *vma,
			     bool write_combine)
{
	if (write_combine)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	else
		vma->vm_page_prot = pgprot_device(vma->vm_page_prot);

	vma->vm_pgoff += gz_pgoff;
	vma->vm_ops = &genz_phys_vm_ops;
	pr_debug("vm_start=0x%lx, vm_pgoff=0x%lx, vm_size=0x%lx\n",
		 vma->vm_start, vma->vm_pgoff,
		 vma->vm_end - vma->vm_start);
	return io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
				  vma->vm_end - vma->vm_start,
				  vma->vm_page_prot);
}

static bool genz_ci_mmap_fits(struct genz_control_info *ci,
			      struct vm_area_struct *vma)
{
	ulong pages, start, size;

	if (ci->size == 0)
		return false;
	pages = vma_pages(vma);
	start = vma->vm_pgoff;
	size = PHYS_PFN(ci->size - 1) + 1;
	return (start < size && start + pages <= size);
}

static int mmap_control_structure(struct file *fd,
		struct kobject *kobj,
		struct bin_attribute *battr,
		struct vm_area_struct *vma)
{
	struct genz_control_info *ci = to_genz_control_info(kobj);
	struct genz_rmr_info *rmri = ci->rmri;
	struct genz_bridge_dev *br = ci->zbdev;
	ulong cs_pgoff;
	bool wc;
	int ret = 0;

	/* Revisit: add security_locked_down check (like PCI) */
	if (!genz_ci_mmap_fits(ci, vma))
		return -EINVAL;
	if (genz_is_local_bridge(br, rmri)) {
		if (!br->zbdrv->control_mmap)
			return -EINVAL;
		ret = br->zbdrv->control_mmap(br, ci->start, ci->size,
					      &cs_pgoff, &wc);
		if (ret < 0)
			return ret;
	} else {  /* fabric */
		if (!is_genz_range_mapped(ci->start, ci->size, rmri))
			return -ENOSPC;
		cs_pgoff = PHYS_PFN(rmri->zres.res.start);
		wc = true;
	}

	/* Revisit: PCI has iomem_is_exclusive check */
	return genz_mmap_resource_range(cs_pgoff, vma, wc);
}

static const struct sysfs_ops control_info_sysfs_ops = {
	.show = control_info_attr_show,
	.store = control_info_attr_store,
};
static struct kobj_type control_info_ktype = {
	.sysfs_ops = &control_info_sysfs_ops,
	.release = control_info_release,
};

static void genz_dir_release(struct kobject *kobj)
{
	struct genz_bridge_dev *zbdev;

	/* the genzN dir is embedded in zbdev which is free'd separately,
	 * so nothing to do here but print debug messages
	 */
	if (kobj == NULL) {
		pr_debug("NULL kobj\n");
		return;
	}
	zbdev = kobj_to_zbdev(kobj);
	if (zbdev == NULL) {
		pr_debug("failed to find zbdev from kobject\n");
		return;
	}
	dev_dbg(zbdev->bridge_dev, "kobj %s\n", kobject_name(kobj));
	/* Revisit: kobject_cleanup() should be doing this */
	kobj->state_initialized = 0;
	/* Revisit: prevent double-free when kobj is reinitialized */
	kobj->name = NULL;
}

static struct kobj_type genz_dir_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = genz_dir_release
};

static void control_dir_release(struct kobject *kobj)
{
	/* Revisit: Is this just a debug function? It doesn't do anything */
	if (kobj == NULL) {
		pr_debug("NULL kobj\n");
		return;
	}
	pr_debug("kobj %s\n", kobject_name(kobj));
}

static struct kobj_type control_dir_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = control_dir_release
};

static void chain_dir_release(struct kobject *kobj)
{
	if (kobj == NULL) {
		pr_debug("NULL kobj\n");
		return;
	}
	pr_debug("freeing %s\n", kobject_name(kobj));
	kfree(kobj);
}

static struct kobj_type chain_dir_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = chain_dir_release
};

static ssize_t gcid_br_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct genz_bridge_dev *zbdev;
	struct genz_os_comp *comp;

	zbdev = kobj_to_zbdev(kobj);
	if (zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad zbdev\n"));
	}
	comp = zbdev->zdev.zcomp;
	if (comp->comp.subnet == NULL) {
		pr_debug("comp->subnet is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component subnet\n"));
	}
	return snprintf(buf, PAGE_SIZE, "%04x:%03x\n",
			comp->comp.subnet->sid, comp->comp.cid);
}

static struct kobj_attribute gcid_br_attribute =
	__ATTR(gcid, (0444), gcid_br_show, NULL);

static ssize_t cclass_br_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct genz_bridge_dev *zbdev;
	struct genz_os_comp *comp;

	zbdev = kobj_to_zbdev(kobj);
	if (zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad zbdev\n"));
	}
	comp = zbdev->zdev.zcomp;
	return snprintf(buf, PAGE_SIZE, "%u\n", comp->comp.cclass);
}

static struct kobj_attribute cclass_br_attribute =
	__ATTR(cclass, (0444), cclass_br_show, NULL);

static ssize_t serial_br_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct genz_bridge_dev *zbdev;
	struct genz_os_comp *comp;

	zbdev = kobj_to_zbdev(kobj);
	if (zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad zbdev\n"));
	}
	comp = zbdev->zdev.zcomp;
	return snprintf(buf, PAGE_SIZE, "0x%016llx\n", comp->comp.serial);
}

static struct kobj_attribute serial_br_attribute =
	__ATTR(serial, (0444), serial_br_show, NULL);

static ssize_t cuuid_br_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct genz_bridge_dev *zbdev;
	struct genz_os_comp *comp;

	zbdev = kobj_to_zbdev(kobj);
	if (zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad zbdev\n"));
	}
	comp = zbdev->zdev.zcomp;
	return snprintf(buf, PAGE_SIZE, "%pUb\n", &comp->comp.c_uuid);
}

static struct kobj_attribute cuuid_br_attribute =
	__ATTR(c_uuid, (0444), cuuid_br_show, NULL);

static ssize_t fru_uuid_br_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct genz_bridge_dev *zbdev;
	struct genz_os_comp *comp;

	zbdev = kobj_to_zbdev(kobj);
	if (zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad zbdev\n"));
	}
	comp = zbdev->zdev.zcomp;
	return snprintf(buf, PAGE_SIZE, "%pUb\n", &comp->comp.fru_uuid);
}

static struct kobj_attribute fru_uuid_br_attribute =
	__ATTR(fru_uuid, (0444), fru_uuid_br_show, NULL);

static int genz_create_bridge_files(struct kobject *genz_dir)
{
	int ret;

	ret  = sysfs_create_file(genz_dir, &gcid_br_attribute.attr);
	ret |= sysfs_create_file(genz_dir, &cclass_br_attribute.attr);
	ret |= sysfs_create_file(genz_dir, &serial_br_attribute.attr);
	ret |= sysfs_create_file(genz_dir, &fru_uuid_br_attribute.attr);
	ret |= sysfs_create_file(genz_dir, &cuuid_br_attribute.attr);
	return ret;
}

static void genz_remove_bridge_files(struct kobject *genz_dir)
{
	sysfs_remove_file(genz_dir, &gcid_br_attribute.attr);
	sysfs_remove_file(genz_dir, &cclass_br_attribute.attr);
	sysfs_remove_file(genz_dir, &serial_br_attribute.attr);
	sysfs_remove_file(genz_dir, &fru_uuid_br_attribute.attr);
	sysfs_remove_file(genz_dir, &cuuid_br_attribute.attr);
}

static ssize_t gcid_fab_show(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	struct genz_comp *comp;

	comp = kobj_to_genz_comp(kobj);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad comp\n"));
	}
	if (comp->subnet == NULL) {
		pr_debug("comp->subnet is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component subnet\n"));
	}
	return snprintf(buf, PAGE_SIZE, "%04x:%03x\n",
			comp->subnet->sid, comp->cid);
}

static struct kobj_attribute gcid_fab_attribute =
	__ATTR(gcid, (0444), gcid_fab_show, NULL);

static ssize_t cclass_fab_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct genz_comp *comp;

	comp = kobj_to_genz_comp(kobj);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad comp\n"));
	}
	return snprintf(buf, PAGE_SIZE, "%u\n", comp->cclass);
}

static struct kobj_attribute cclass_fab_attribute =
	__ATTR(cclass, (0444), cclass_fab_show, NULL);

static ssize_t serial_fab_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct genz_comp *comp;

	comp = kobj_to_genz_comp(kobj);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad comp\n"));
	}
	return snprintf(buf, PAGE_SIZE, "0x%016llx\n", comp->serial);
}

static struct kobj_attribute serial_fab_attribute =
	__ATTR(serial, (0444), serial_fab_show, NULL);

static ssize_t cuuid_fab_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	struct genz_comp *comp;

	comp = kobj_to_genz_comp(kobj);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad comp\n"));
	}
	return snprintf(buf, PAGE_SIZE, "%pUb\n", &comp->c_uuid);
}

static struct kobj_attribute cuuid_fab_attribute =
	__ATTR(c_uuid, (0444), cuuid_fab_show, NULL);

static ssize_t fru_uuid_fab_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct genz_comp *comp;

	comp = kobj_to_genz_comp(kobj);
	if (comp == NULL) {
		pr_debug("comp is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad comp\n"));
	}
	return snprintf(buf, PAGE_SIZE, "%pUb\n", &comp->fru_uuid);
}

static struct kobj_attribute fru_uuid_fab_attribute =
	__ATTR(fru_uuid, (0444), fru_uuid_fab_show, NULL);

static int genz_create_fab_files(struct kobject *comp_dir)
{
	int ret;

	ret  = sysfs_create_file(comp_dir, &gcid_fab_attribute.attr);
	ret |= sysfs_create_file(comp_dir, &cclass_fab_attribute.attr);
	ret |= sysfs_create_file(comp_dir, &serial_fab_attribute.attr);
	ret |= sysfs_create_file(comp_dir, &fru_uuid_fab_attribute.attr);
	ret |= sysfs_create_file(comp_dir, &cuuid_fab_attribute.attr);
	return ret;
}

static void genz_remove_fab_files(struct kobject *comp_dir)
{
	sysfs_remove_file(comp_dir, &gcid_fab_attribute.attr);
	sysfs_remove_file(comp_dir, &cclass_fab_attribute.attr);
	sysfs_remove_file(comp_dir, &serial_fab_attribute.attr);
	sysfs_remove_file(comp_dir, &fru_uuid_fab_attribute.attr);
	sysfs_remove_file(comp_dir, &cuuid_fab_attribute.attr);
}

#ifdef NOT_YET

/*
 * genz_create_control_chain_siblings
 *  A control structure can have a linked list of the same structure. We call
 *  this a chain. The chained structures are all represented at the same
 *  level in the hierarchy and given names with an index representing where
 *  they are in the chain list. As an example, the Core structure has a
 *  pointer to an Interface structure called interface0_ptr. The Interface
 *  structure has a pointer called next_i_ptr that points to the next
 *  interface structure in the list. When next_i_ptr is NULL, that indicates
 *  the end of the list.
 */
static int genz_create_control_chain_siblings(
	struct genz_dev *zdev,
	struct genz_control_info *sibling,
	int type_id,
	off_t start,
	genz_control_pointer_type ptr_type,
	off_t chain_ptr_offset)
{
	struct genz_control_info *s;
	struct genz_control_header hdr;
	int chain_index = 1; /* 0 is the orginal one found in genz_create_control_children() */

	do {
		sibling_offset = genz_control_structure_pointers[type_id][].offset;
		sibling_id_type = genz_control_structure_pointers[type_id][i].pointer_type_id;
		sibling_type = genz_control_structure_pointers[type_id][i].ptr_type;
		ret = read_ptr(zdev, start+child_offset, &ptr_offset);
		if (ret < 0) {
			pr_debug("read_ptr failed\n");
			return ret;
		}
		ptr_byte_offset = chain_ptr_offset<<PTR_SHIFT;
		ret = read_control_structure_header(zdev, ptr_byte_offset, &hdr);
		if (ret < 0) {
			pr_debug("read_control_structure_header failed\n");
			return ret;
		}

		/* Validate the header type matches what we expect */
		if (hdr->type_id != type_id) {
			pr_debug("type_id doesn't match %d != %d\n", hdr->type_id, type_id);
			return -EINVAL;
		}
		s = alloc_control_info(hdr->size, offset);
		if (s == NULL) {
			pr_debug("failed to allocate control_info\n");
			return -ENOMEM;
		}
		s->parent = parent;
		if (parent->child == NULL) { /* first child */
			parent->child = s;
		} else { /* link to sibling */
			sibling->sibling = s;
		}
		sibling = s;
		kobject_init(&s->kobj, &control_info_ktype);
		kobject_add(&s->kobj, &parent->kobj, genz_structure_name(sibling_id_type));


		/* Create the children of this structure */
		ret = genz_create_control_children(zdev, s);
	} while (s != NULL);

	return ret;
}

static int genz_create_control_children(
	struct genz_dev *zdev,
	struct genz_control_info *parent,
	int type_id,
	off_t start) /* the start of this control space structure */
{
	int i;
	int ret = 0;
	int num_children = sizeof(genz_control_structure_pointers[type_id]);
	struct genz_control_info *c;
	struct genz_control_info *sibling = NULL;
	off_t child_id_type;
	off_t child_type;
	off_t ptr_byte_offset;
	off_t ptr_offset;

	for (i = 0; i < num_children; i++) {
		child_offset = genz_control_structure_pointers[type_id][i].offset;
		child_id_type = genz_control_structure_pointers[type_id][i].pointer_type_id;
		child_type = genz_control_structure_pointers[type_id][i].ptr_type;
		ret = read_ptr(zdev, start+child_offset, &ptr_offset);
		if (ret < 0) {
			pr_debug("read_ptr failed\n");
			return ret;
		}
		ptr_byte_offset = ptr_offset<<PTR_SHIFT;
		ret = read_control_structure_header(zdev, ptr_byte_offset, &hdr);
		if (ret < 0) {
			pr_debug("read_control_structure_header failed\n");
			return ret;
		}

		/* Validate the header type matches what we expect */
		if (hdr->type_id != child_id_type && child_id_type != GENERIC_STRUCT_TYPE) {
			pr_debug("type_id doesn't match %d != %d\n", hdr->type_id, child_id_type);
			return -EINVAL;
		}
		c = alloc_control_info(hdr->size, offset);
		if (c == NULL) {
			pr_debug("failed to allocate control_info\n");
			return -ENOMEM;
		}
		c->parent = parent;
		if (parent->child == NULL) { /* first child */
			parent->child = c;
		} else { /* link to sibling */
			sibling->sibling = c;
		}
		sibling = c;
		kobject_init(&c->kobj, &control_info_ktype);
		kobject_add(&c->kobj, &parent->kobj, genz_structure_name(child_id_type));

		/*
		 * Some pointers (e.g. Interface Structures) are chained and all of that list of structure
		 * are siblings.
		 */
		/* REVISIT: add a GENZ_CONTRL_POINTER_ARRAY type - complicated - see Component LPD Structure */
		if (child_type & GENZ_CONTROL_POINTER_CHAINED) {
			ret = genz_create_control_chain_siblings(zdev, sibling, child_offset, child_id_type, child_type,
				genz_control_structure_pointers[type_id][i].chain_ptr_offset);

		} else {
			/* Recurse to create any children */
			ret = genz_create_control_children(zdev, c, hdr->type_id, ptr_byte_offset);
			if (!ret) {
				kobject_put(&c->kobj);
				return ret;
			}
		}
	}

	return ret;
}

#ifdef NOT_YET
/*
 * genz_create_control_hierarchy -
 *  Start with reading the control space at offset 0 to find the core
 *  structure. Each structure in the control space is represented by
 *  a struct genz_control_info. The genz_control_info has a tree
 *  representation with pointers to a parent, sibling, and child. The
 *  table genz_control_pointers
 *  defines the offset to each pointer for each structure ptr_type. This
 *  includes pointers to tables.
 *
 */
static int genz_create_control_hierarchy(struct genz_dev *zdev)
{
	int ret = 0;
	int offset;

	/*
	 * Start at offset 0 in control space and read what should be
	 * the Core Structure.
	 */
	offset = 0;
	ret = read_control_structure_header(zdev, offset, &hdr);
	if (ret < 0) {
		pr_debug("read_control_structure_header failed\n");
		return ret;
	}

	/* Check that the type matches expected core structure type 0 */
	if (hdr.ptr_type != 0) {
		pr_debug("Core Structure header type is not core. Found %d\n",
			hdr.ptr_type);
		return -ENOENT;
	}

	/* Create the root of the control space hierarchy */
	zdev->root_control_info = alloc_control_info(hdr->size, offset);
	if (!zdev->root_control_info) {
		pr_debug("alloc_control_info() failed\n");
		return -ENOMEM;
	}
	zdev->root_control_info->parent = NULL; /*indicates the root */
	kobject_init(&zdev->root_control_info->kobj, &control_info_ktype);
	kobject_add(&zdev->root_control_info->kobj, &zdev->dev.kobj, genz_structure_name(CORE_STRUCTURE));

	/* Now we have the root set up, follow all the pointers */

	ret = genz_create_control_children(zdev, zdev->root_control_info, CORE_STRUCTURE, offset);
	if (!ret) {
		kobject_put(&zdev->root_control_info->kobj);
		zdev->root_control_info = NULL;
	}

	/*
	 * REVISIT: Traverse the control_hierarchy and add a symlink to each structure's
	 * directory that links the appropriate C-Access Structure. Also, calculate the
	 * row that each structure uses in the Component C-Access R-Key Table and the
	 * Component C-Access L-P@P Table and add an attribute called "c_access_row" to
	 * each Structure.
	 */
}

static int genz_destroy_control_hierarchy(struct genz_dev *zdev)
{
	return 0;
}
#endif

static int find_opcode_set_structure(struct genz_dev *zdev, int version);
{
	int count = 0;
	struct opcode_set_structure *oss, *next_oss;

	if (zdev->core->opcode_set_structure_ptr == NULL)
		return 0;

	/* Map the OpCode Set Structure */
	oss = zmm_map(zdev->core->opcode_set_structure_ptr);
	if (!oss) {
		pr_debug("zmmu_map of the opcode set structure failed\n");
		return -ENOENT;
	}

	/* OpCode Set Structures are in a linked list */
	while (1) {
		if (oss->vers == version || version == -1)
			count++;
		if (!oss->opcode_set_ptr) {
			zmm_unmap(oss);
			break;
		}
		next_oss = zmm_map(oss->opcode_set_ptr);
		zmm_unmap(oss);
		if (!next_oss) /* the map failed */
			break;
		oss = next_oss;
	}

	return count;
}

/*
 * Search from the core structure and extensions for control structures
 * that match the given type and version.  Version of -1 finds any
 * control structure that matches the given type.
 * Returns the number of matching control structures
 */
int genz_find_control_structure(
	struct genz_dev *zdev,
	int ptr_type,
	int version)
{
	int count = 0;
	int mapped = 0;

	if (zdev->core == NULL) {
		/* Map the core structure. */
		zdev->core = zmmu_map(zdev->control_space);
		mapped = 1;
		if (!zdev->core) {
			pr_debug("zmmu_map of the core structure failed\n");
			return -ENOENT;
		}
	}
	if (!genz_validate_structure_type(ptr_type)) {
		/* Not a standard control structure. Search the extensions */
		find_vendor_defined_structure(zdev, ptr_type, version);
	}
	switch (ptr_type) {
	case CORE_STRUCTURE:
		/* There is only one core structure. Match the version */
		if (zdev->core->vers == version || version == -1)
			count = 1;
		break;
	case OPCODE_SET_STRUCTURE:
		count = find_opcode_set_structure(zdev, version);
		break;
	case INTERFACE_STRUCTURE:
		count = find_interface_structure(zdev, version);
		break;
	case INTERFACE_PHY_STRUCTURE:
		count = find_interface_phy_structure(zdev, version);
		break;
	case INTERFACE_STATISTICS_STRUCTURE:
		count = find_interface_statistics_structure(zdev, version);
		break;
		/* add the rest */
	}

	if (mapped)
		zmmu_unmap(zdev->core);
	return count;
}
EXPORT_SYMBOL_GPL(genz_find_control_structure);
#endif

/* Request the Nth control structure that matches the given ptr_type and
 * version and return a cookie that can be used to map the structure.
 * This creates the ZMMU entry required for access.  Creates a struct
 * resource behind the scenes.
 */
int genz_request_control_structure(
	struct genz_dev *zdev,
	int index,
	int ptr_type,
	int version,
	genz_control_cookie *cookie)
{
	return 0;
}
EXPORT_SYMBOL_GPL(genz_request_control_structure);

/*
 * Release a control structure.  Releases the Gen-Z control structure
 * resources reserved by a successful call to
 * genz_request_control_structure(). Call this function only after all
 * use of the control structure has ceased.
 */
void genz_release_control_structure(
	struct genz_dev *zdev,
	genz_control_cookie cookie)
{
}
EXPORT_SYMBOL_GPL(genz_release_control_structure);

/*
 * Map the Nth control structure that matches the given ptr_type and version
 * and return the size and pointer.
 */
int genz_map_control_structure(
	struct genz_dev *zdev,
	genz_control_cookie cookie,
	size_t *size,
	void **ctrl_struct)
{
	return 0;
}
EXPORT_SYMBOL_GPL(genz_map_control_structure);

/*
 * Request the control table pointed to by a control structure field at
 * table_offset with a given table_ptr_size, and returns a cookie that
 * can be used to map the structure.  This function creates the ZMMU entry
 * required for access of the table.
 */
int genz_request_control_table(
	struct genz_dev *zdev,
	genz_control_cookie cookie,
	int table_offset,
	int table_ptr_size,
	genz_control_cookie *table_cookie)
{
	return 0;
}
EXPORT_SYMBOL_GPL(genz_request_control_table);

/*
 * Release a control table.  Releases the Gen-Z control table resources
 * reserved by a successful call to genz_request_control_table(). Call
 * this function only after all use of the control table has ceased.
 */
void genz_release_control_table(
	struct genz_dev *zdev,
	genz_control_cookie cookie)
{
}
EXPORT_SYMBOL_GPL(genz_release_control_table);

/*
 * Map the control table that matches the given genz_control_cookie from
 * a call to genz_request_control_table() and return the size and pointer
 * to the control_table. This function creates the ZMMU entry required
 * for access of the table.
 */
int genz_map_control_table(
	struct genz_dev *zdev,
	genz_control_cookie cookie,
	size_t *size,
	void **control_table)
{
	return 0;
}
EXPORT_SYMBOL_GPL(genz_map_control_table);

/**
 * genz_discover_gcid - find a new gcid on the fabric and create sysfs files
 *
 */
int genz_discover_gcid(uint32_t gcid, uuid_t cuuid, uuid_t mgruuid)
{

	/* Convert a gcid to a sid/cid pair */

	return 0;
}

static int read_pointer_at_offset(struct genz_bridge_dev *zbdev,
			struct genz_rmr_info *rmri,
			off_t start,
			enum genz_pointer_size psize,
			off_t offset,
			off_t *ptr_offset)
{
	int ret;

	pr_debug("start=0x%lx, offset=0x%lx, start+offset=0x%lx\n",
		 start, offset, start+offset);
	*ptr_offset = 0;
	/* Read the given offset to get the pointer to the control structure */
	ret = genz_control_read(zbdev, start+offset,
				(int)psize, ptr_offset, rmri, 0);
	if (ret) {
		pr_debug("genz_control_read of pointer failed with %d\n", ret);
		return ret;
	}

	pr_debug("found the raw pointer value@0x%lx is 0x%lx\n", start+offset, *ptr_offset);
	
	/* It is ok for many pointers to be NULL. Everything is optional. */
	if (*ptr_offset == 0)
		return ENOENT;

	/* Shift the offset to get the byte address */
	*ptr_offset <<= 4;
	return ret;
}

static int read_header_at_offset(struct genz_bridge_dev *zbdev,
			struct genz_rmr_info *rmri,
			off_t start,
			enum genz_pointer_size psize,
			off_t offset,
			struct genz_control_structure_header *hdr,
			off_t *hdr_offset)
{
	int ret;

	ret = read_pointer_at_offset(zbdev, rmri, start, psize,
				     offset, hdr_offset);
	if (ret)
		return ret;

	/* Read a control structure header at that pointer location */
	pr_debug("reading the header from the pointer byte offset 0x%lx, size = 0x%lx\n", *hdr_offset, sizeof(struct genz_control_structure_header));
	ret = genz_control_read(zbdev, *hdr_offset,
		sizeof(struct genz_control_structure_header), hdr, rmri, 0);
	if (ret) {
		pr_debug("genz_control_read of structure header failed with %d\n",
			ret);
		return ret;
	}
	pr_debug("hdr->type=0x%x, hdr->vers=%d, hdr->size=0x%x\n",
		 hdr->type, hdr->vers, hdr->size);
	return ret;
}

static int read_and_validate_header(struct genz_bridge_dev *zbdev,
			struct genz_rmr_info *rmri,
			off_t start,
			const struct genz_control_structure_ptr *csp,
			struct genz_control_structure_header *hdr,
			off_t *hdr_offset)
{
	int ret = 0;
	uint8_t expected_vers;

	ret = read_header_at_offset(zbdev, rmri, start, csp->ptr_size,
				csp->pointer_offset, hdr, hdr_offset);
	/* Revisit: if the pointer is required, issue a warning */
	if (ret == ENOENT) {  /* This pointer is NULL. Not an error. */
		return ENOENT;
	} else if (ret) {
		pr_debug("read_header_at_offset returned %d\n", ret);
		return ret;
	}

	/* Validate the header is as expected */
	if ((csp->struct_type != GENZ_GENERIC_STRUCTURE) &&
	    (hdr->type != csp->struct_type)) {
		pr_debug("expected structure type %d but found %d\n",
			csp->struct_type, hdr->type);
		return EINVAL;
	} else if ((csp->struct_type == GENZ_GENERIC_STRUCTURE) &&
		   ((hdr->type == GENZ_OPCODE_SET_STRUCTURE) ||
		    (hdr->type == GENZ_COMPONENT_C_ACCESS_STRUCTURE) ||
		    (hdr->type == GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE) ||
		    (hdr->type == GENZ_INTERFACE_STRUCTURE) ||
		    (hdr->type == GENZ_COMPONENT_ERROR_AND_SIGNAL_EVENT_STRUCTURE) ||
		    (hdr->type == GENZ_INTERFACE_PHY_STRUCTURE) ||
		    (hdr->type == GENZ_INTERFACE_STATISTICS_STRUCTURE) ||
		    (hdr->type == GENZ_COMPONENT_MECHANICAL_STRUCTURE) ||
		    (hdr->type == GENZ_COMPONENT_EXTENSION_STRUCTURE))) {
		pr_debug("found structure type %d in generic PTR\n", hdr->type);
		return EINVAL;
	}
	/* Check if this is a known type */
	if (!genz_validate_structure_type(hdr->type)) {
		pr_debug("unknown structure type 0x%x\n", hdr->type);
		return EINVAL;
	}
	/* Validate the structure size */
	if (!genz_validate_structure_size(hdr)) {
		pr_debug("structure size is wrong\n");
		return EINVAL;
	}
	/* Validate the version */
	expected_vers = genz_struct_type_to_ptrs[hdr->type].vers;
	if (hdr->vers != expected_vers) {
		pr_debug("structure version mismatch expected %d but found %d.\n", expected_vers, hdr->vers);
		/* Revisit: don't fail on version mismatch because of quirks */
	} else {
		pr_debug("versions match: hdr->vers is %d\n", hdr->vers);
	}

	return 0;
}

/*
 * is_head_of_chain - determines if a GENZ_CONTROL_POINTER_STRUCTURE
 * or GENZ_CONTROL_POINTER_TABLE points to a type that has a chain.
 * If this is the case, then
 * there is a sysfs directory created with that structure name and in
 * that directory, a set of directories for each element of the
 * chain starting at 0.
 */
static int is_head_of_chain(struct genz_bridge_dev *zbdev, struct genz_rmr_info *rmri,
			    off_t start, const struct genz_control_structure_ptr *csp)
{
	enum genz_control_structure_type target_type;
	struct genz_control_structure_header hdr;
	off_t hdr_offset;
	bool is_table;
	int ret;

	/*
	 * If we are in the midst of following a chain, the ptr_type
	 * will be GENZ_CONTROL_POINTER_CHAINED. Only the potental
	 * head of a chain has GENZ_CONTROL_POINTER_STRUCTURE or
	 * GENZ_CONTROL_POINTER_TABLE.
	 */
	if (csp->ptr_type == GENZ_CONTROL_POINTER_STRUCTURE)
		is_table = false;
	else if (csp->ptr_type == GENZ_CONTROL_POINTER_TABLE)
		is_table = true;
	else
		return 0;

	/* Get the structure type that we need to see if chained. */
	if (csp->struct_type == GENZ_GENERIC_STRUCTURE) {
		/* must follow pointer to get type from structure header */
		ret = read_and_validate_header(zbdev, rmri, start, csp,
					       &hdr, &hdr_offset);
		if (ret)
			return 0;
		target_type = hdr.type;
	} else {
		target_type = (is_table) ? csp->struct_type-GENZ_TABLE_ENUM_START :
			csp->struct_type;
	}

	/*
	 * The table indicates if this type is chained in the static
	 * genz_control_ptr_info structure. If it is marked chained then
	 * this must be the head of the chain.
	 */
	return (is_table) ? genz_table_type_to_ptrs[target_type].chained :
		genz_struct_type_to_ptrs[target_type].chained;
}

static struct genz_control_info *alloc_control_info(
	struct genz_bridge_dev *zbdev,
	struct genz_control_structure_header *hdr,
	off_t offset,
	struct genz_control_info *parent, struct genz_control_info **sibling,
	const struct genz_control_structure_ptr *csp, struct genz_rmr_info *rmri)
{
	struct genz_control_info *ci;

	/* Allocate a genz_control_info/kobject for this directory */
	ci = kzalloc(sizeof(*ci), GFP_KERNEL);
	if (!ci) {
		pr_debug("failed to allocate genz_control_info.\n");
		return NULL;
	}

	ci->zbdev = zbdev;
	ci->start = offset;
	ci->csp = csp;
	ci->rmri = rmri;
	if (hdr) { /* root control dir and chained dirs have no header. */
		ci->type = hdr->type;
		ci->vers = hdr->vers;
		ci->size = hdr->size * GENZ_CONTROL_SIZE_UNIT;
	}
	ci->parent = parent;
	if (parent && parent->child == NULL) { /* first child */
		pr_debug("ci=%px, child of %px\n", ci, parent);
		parent->child = ci;
	} else if (*sibling) { /* link to sibling */
		(*sibling)->sibling = ci;
		pr_debug("ci=%px, sibling of %px\n", ci, *sibling);
	} else {
		pr_debug("ci=%px, no parent or sibling\n", ci);
	}
	*sibling = ci;

	/* The kobject is associated with the control kset for cleanup */
	//ci->kobj.kset = zdev->zbdev->genz_control_kset; /* Revisit */

	/* Revisit: fill out remaining fields.
	 * ci->c_access_res =;
	 * ci->zmmu = ;
	 */

	return ci;
}

static struct genz_mem_data *alloc_mdata(struct genz_bridge_dev *zbdev,
					 uuid_t *mgr_uuid)
{
	struct genz_mem_data     *mdata;
	struct uuid_tracker      *uu;
	struct uuid_node         *md_node;
	int                      ret;
	bool                     local;
	ulong                    flags;

	spin_lock_irqsave(&zbdev->zmmu_lock, flags);
	if (zbdev->control_mdata == NULL) {
		mdata = kzalloc(sizeof(*mdata), GFP_ATOMIC);
		if (!mdata) {
			pr_debug("failed to allocate genz_mem_data\n");
			goto unlock;
		}
		genz_init_mem_data(mdata, zbdev);
		zbdev->control_mdata = mdata;
		/* Need mgr_uuid REMOTE tracker to do rmr_imports against
		 * and LOCAL tracker for mdata */
		uu = genz_uuid_tracker_alloc_and_insert(
			mgr_uuid, UUID_TYPE_LOOPBACK, 0, mdata, GFP_ATOMIC, &ret);
		if (!uu) {
			pr_debug("genz_uuid_tracker_alloc_and_insert error ret=%d\n", ret);
			goto err_uu;
		}
		/* we now hold a reference to uu */
		mdata->local_uuid = uu;
		/* add uu to mdata->md_remote_uuid_tree */
		md_node = genz_remote_uuid_alloc_and_insert(
			uu, &mdata->uuid_lock, &mdata->md_remote_uuid_tree,
			GFP_ATOMIC, &ret);
		if (ret == -EEXIST) {
			pr_debug("mgr_uuid %pUb already exists\n", mgr_uuid);
		} else if (ret < 0) {
			pr_debug("genz_remote_uuid_alloc_and_insert error ret=%d\n", ret);
			goto err_md;
		}
	} else {
		mdata = zbdev->control_mdata;
	}

unlock:
	spin_unlock_irqrestore(&zbdev->zmmu_lock, flags);
	return mdata;
err_md:
	genz_free_local_or_remote_uuid(mdata, mgr_uuid, uu, &local);
	mdata->local_uuid = NULL;
err_uu:
	kfree(mdata);
	zbdev->control_mdata = mdata = NULL;
	goto unlock;
}

static void remove_mdata(struct genz_bridge_dev *zbdev)
{
	struct genz_mem_data *mdata = zbdev->control_mdata;
	uuid_t *mgr_uuid = &mdata->local_uuid->uuid;
	bool local;

	genz_free_uuid_node(mdata, &mdata->uuid_lock,
			    &mdata->md_remote_uuid_tree, mgr_uuid, false);
	genz_free_local_or_remote_uuid(mdata, mgr_uuid,
				       mdata->local_uuid, &local);
	/* Revisit: this is wrong - mdata needs reference counting */
	kfree(mdata);
	zbdev->control_mdata = NULL;
}

static int genz_control_create_bin_file(struct genz_control_info *ci,
					const char *name)
{
	int ret;

	pr_debug("creating file %s\n", name);
	/* initialize the binary attribute file */
	sysfs_bin_attr_init(&ci->battr);
	ci->battr.attr.name = name;
	ci->battr.attr.mode = 0600;
	ci->battr.size = ci->size;
	ci->battr.read = read_control_structure;
	ci->battr.write = write_control_structure;
	//ci->battr.mmap = mmap_control_structure; /* Revisit: not quite ready */
	ci->battr.private = ci; /* Used to indicate valid battr */

	ret = sysfs_create_bin_file(&ci->kobj, &ci->battr);
	if (ret) {
		pr_debug("sysfs_create_bin_file failed with %d for file %s\n",
				ret, ci->battr.attr.name);
	}

	return ret;
}

static int traverse_table(struct genz_bridge_dev *zbdev,
			  struct genz_rmr_info *rmri,
			  struct genz_control_info *parent,
			  struct genz_control_info **sibling,
			  struct kobject *struct_dir,
			  const struct genz_control_structure_ptr *csp)
{
	struct genz_control_info *ci;
	int ret = 0;
	off_t table_ptr;
	const char *table_name;

	/* Read the pointer to this table */
	ret = read_pointer_at_offset(zbdev, rmri, parent->start,
			(int)csp->ptr_size, csp->pointer_offset, &table_ptr);
	if (ret == ENOENT) {  /* This pointer is NULL. Not an error.*/
		return 0;
	} else if (ret < 0) {
		pr_debug("read_pointer_at_offset failed with %d\n", ret);
		return ret;
	}

	/* Allocate a genz_control_info/kobject for this directory */
	ci = alloc_control_info(zbdev, NULL, table_ptr, parent, sibling, csp, rmri);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}
	ci->type = csp->struct_type;
	ci->size = (*csp->size_fn)(ci);
	table_name = genz_table_name(ci->type, csp);

	pr_debug("table type 0x%x size 0x%lx name %s\n", ci->type, ci->size, table_name);

	ret = kobject_init_and_add(&ci->kobj, &control_info_ktype, struct_dir,
				   "%s@0x%lx", table_name, ci->start);
	if (ret < 0) {
		kobject_put(&ci->kobj);
		return ret;
	}

	ret = genz_control_create_bin_file(ci, table_name);
	if (ret) {
		/* Revisit: handle error */
		pr_debug("genz_control_create_bin_file failed with %d for file %s\n",
				ret, ci->battr.attr.name);
		return ret;
	}
	/* Recursively traverse any pointers in this table */
	pr_debug("calling traverse_control_pointers for any pointers in table %s\n", ci->battr.attr.name);
	ret = traverse_control_pointers(zbdev, rmri, ci, ci->type, 0, &ci->kobj, NULL);
	if (ret < 0) {
		/* Revisit: handle error */
		pr_debug("traverse_control_pointers for %s failed with %d\n", ci->battr.attr.name, ret);
		return ret;
	}
	return 0;
}

static inline int get_control_structure_ptr(
		struct genz_bridge_dev *zbdev, int struct_type, int struct_vers,
		const struct genz_control_structure_ptr **csp, int *num_ptrs)
{
	pr_debug("struct type=0x%x, vers=%d\n", struct_type, struct_vers);
	if (!genz_validate_structure_type(struct_type)) {
		pr_debug("unknown structure type 0x%x\n", struct_type);
		*csp = NULL;
		*num_ptrs = 0;
		return ENOENT;
	}
	if (genz_struct_type_to_ptrs[struct_type].vers == struct_vers) {
		*csp = genz_struct_type_to_ptrs[struct_type].ptr;
		*num_ptrs = genz_struct_type_to_ptrs[struct_type].num_ptrs;
		return 0;
	}
	if (!zbdev->zbdrv)
		return -EINVAL;
	if (!zbdev->zbdrv->control_structure_pointers)
		return -EINVAL;
	pr_debug("not found in genz_struct_type_to_ptrs - calling bridge driver\n");
	/* Revisit: this only works for the local bridge itself */
	return zbdev->zbdrv->control_structure_pointers(zbdev, struct_vers,
			struct_type, csp, num_ptrs);
}

static inline int get_control_table_ptr(
		struct genz_bridge_dev *zbdev, int table_type,
		const struct genz_control_structure_ptr **csp, int *num_ptrs)
{
	pr_debug("table type=0x%x\n", table_type);
	if (!genz_validate_table_type(table_type)) {
		pr_debug("unknown table type 0x%x\n", table_type);
		*csp = NULL;
		*num_ptrs = 0;
		return ENOENT;
	}
	*csp = genz_table_type_to_ptrs[table_type-GENZ_TABLE_ENUM_START].ptr;
	*num_ptrs = genz_table_type_to_ptrs[table_type-GENZ_TABLE_ENUM_START].num_ptrs;
	return 0;
	/* Revisit: should zbdrv have a control_table_pointers interface? */
}

static int get_control_ptr(
		struct genz_bridge_dev *zbdev, int type, int vers,
		const struct genz_control_structure_ptr **csp, int *num_ptrs)
{
	if (is_struct_type(type))
		return get_control_structure_ptr(zbdev, type, vers, csp, num_ptrs);
	else  /* table */
		return get_control_table_ptr(zbdev, type, csp, num_ptrs);
}

/*
 * Search the list of pointers for this structure/table to find the
 * one marked "CHAINED". That is the offset for the next pointer
 * in the list. Complain if it is not found or more than one is
 * found.
 */
static off_t find_chain_offset(struct genz_bridge_dev *zbdev,
	int struct_type, int struct_vers,
	const struct genz_control_structure_ptr **chain_csp)
{
	int chain_offset = -ENOENT;
	int i;
	int num_ptrs;
	int ret = 0;
	const struct genz_control_structure_ptr *csp;

	ret = get_control_ptr(zbdev, struct_type, struct_vers, &csp, &num_ptrs);
	if (ret) {
		pr_debug("failed to get control_structure_ptr for type %d\n",
			 struct_type);
		return -ENOENT;
	}
	for (i = 0; i < num_ptrs; i++) {
		if (csp[i].ptr_type == GENZ_CONTROL_POINTER_CHAINED) {
			if (chain_offset != -ENOENT) {
				/* Already found a CHAIN. */
				pr_debug("Already found a CHAIN offset %d. New one: %d\n", chain_offset, csp[i].pointer_offset);
				return -EINVAL;
			}
			chain_offset = csp[i].pointer_offset;
			*chain_csp = &csp[i];
		}
	}
	if (chain_offset == -ENOENT) {
		/* Failed to find a CHAIN. */
		pr_debug("Did not find a CHAIN offset for structure\n");
		return -ENOENT;
	}
	return chain_offset;
}

static int chain_container_dir(struct genz_control_info *ci, const char *name,
			       struct kobject *parent_dir)
{
	int ret;

	/* Create the container directory for all the chained structures */
	ci->cont_dir = kzalloc(sizeof(*ci->cont_dir), GFP_KERNEL);
	if (ci->cont_dir == NULL) {
		pr_debug("failed to allocate cont_dir\n");
		return -ENOMEM;
	}

	ret = kobject_init_and_add(ci->cont_dir, &chain_dir_ktype,
				   parent_dir, "%s", name);
	if (ret < 0) {
		kobject_put(ci->cont_dir);
	}

	return ret;
}

/*
 * The parent genz_control_info is the directory that contains
 * the chained control structures directories named <structure><N>.
 * The genz_control_info for each chained control structure
 * is added to the sibling list of the given parent genz_control_info.
 * The pointer to the next control structure in the chain is
 * found by looking for the single entry in the pointer list that is
 * marked "CHAINED". The end of the chain is when that pointer is
 * NULL.
 */
static int traverse_chained_control_pointers(struct genz_bridge_dev *zbdev,
			struct genz_rmr_info *rmri,
			struct genz_control_info *parent,
			struct genz_control_info **sibling,
			struct kobject *dir,
			const struct genz_control_structure_ptr *csp)
{
	int chain_num = 0;
	struct genz_control_structure_header hdr, *hdrp;
	off_t hdr_offset;
	int chain_offset = -1;
	int done = 0;
	int ret, type, vers;
	const char *name;
	struct genz_control_info *ci;
	const struct genz_control_structure_ptr *chain_csp;
	bool is_struct = (csp->ptr_type == GENZ_CONTROL_POINTER_STRUCTURE);
	struct kobject *cont_dir = NULL;

	/*
	 * Read the first pointer in the chain to make sure there is
	 * one before creating the directory to contain the chained structures.
	 */
	pr_debug("entered, is_struct=%d\n", is_struct);
	if (is_struct) {
		ret = read_and_validate_header(zbdev, rmri, parent->start, csp,
					       &hdr, &hdr_offset);
		type = hdr.type;
		vers = hdr.vers;
		hdrp = &hdr;
	} else {  /* table */
		ret = read_pointer_at_offset(zbdev, rmri, parent->start,
			(int)csp->ptr_size, csp->pointer_offset, &hdr_offset);
		type = csp->struct_type;
		vers = 0;
		hdrp = NULL;
	}

	if (ret == ENOENT) /* This pointer is NULL. Not an error - just nothing to follow. */
		return 0;
	else if (ret > 0)  /* Unexpected struct header - a warning condition */
		return ret;
	else if (ret < 0)  /* Error reading control space */
		return ret;

	/* Find the offset for the chained field in this structure type. */
	chain_offset = find_chain_offset(zbdev, type, vers, &chain_csp);
	if (chain_offset < 0) {
		pr_debug("could not find the chain pointer\n");
		return chain_offset;
	}

	name = genz_control_name(type, csp);

	while (!done) {
		pr_debug("%s, chain_num=%d\n", name, chain_num);
		/* Allocate a genz_control_info/kobject for this directory */
		ci = alloc_control_info(zbdev, hdrp, hdr_offset, parent, sibling, csp, rmri);
		if (ci == NULL) {
			pr_debug("failed to allocate control_info\n");
			return -ENOMEM;
		}
		if (!hdrp) {  /* table - set type/size */
			ci->type = csp->struct_type;
			ci->size = (*csp->size_fn)(ci);
		}

		pr_debug("%s type 0x%x start 0x%lx size 0x%lx name %s\n",
			 is_struct ? "struct" : "table",
			 ci->type, ci->start, ci->size, name);
		if (cont_dir == NULL) {  /* create chain container directory */
			ret = chain_container_dir(ci, name, dir);
			if (ret < 0) {
				/* Revisit: undo stuff */
				return ret;
			}
			cont_dir = ci->cont_dir;
		}
		ret = kobject_init_and_add(&ci->kobj, &control_info_ktype,
					   cont_dir, "%s%d@0x%lx",
					   name, chain_num++, ci->start);
		if (ret < 0) {
			kobject_put(&ci->kobj);
			return ret;
		}

		ret = genz_control_create_bin_file(ci, name);
		/* Revisit: handle error */

		/*
		 * Now traverse all of the pointers in the structure. The
		 * chain pointer will be skipped there and handled here in
		 * this while loop.
		 */
		ret = traverse_control_pointers(zbdev, rmri, ci, type, vers,
						&ci->kobj, NULL);
		if (ret < 0) {
			pr_debug("traverse_control_pointers error, ret=%d\n", ret);
			/* Handle error! */
			return ret;
		}

		/* Follow chain pointer to read the next struct/table */
		if (is_struct) {
			ret = read_and_validate_header(zbdev, rmri, ci->start,
				chain_csp, hdrp, &hdr_offset);
			type = hdr.type;
			vers = hdr.vers;
		} else {  /* table */
			ret = read_pointer_at_offset(zbdev, rmri, ci->start,
				(int)chain_csp->ptr_size,
				chain_csp->pointer_offset, &hdr_offset);
			type = chain_csp->struct_type;
			vers = 0;
		}

		/* The pointer is NULL - the end of the list - or some problem */
		if (ret != 0) {
			pr_debug("exiting loop, ret=%d\n", ret);
			done = 1;
		}
	}
	return ret;
}

/* Revisit: this is ugly */
/* Process generic PTRs before special, and be sure to do all Interfaces before
 * Component Destination, so that max_iface_hvs() works.
 */
static uint core_ptr_order[] = {0, 1, 2, 3, 4, 5, 6, 7, 8,  /* StructPTR 0-8 */
				16, 17, 18, 19, 20, 21, 22, /* StructPTR 9-15 */
				14, 11, 13, 10, 12, 9, 15};

static int start_core_structure(struct genz_bridge_dev *zbdev,
			struct genz_rmr_info *rmri,
			struct genz_control_info **root,
			struct genz_control_ptr_info *pi,
			struct kobject *con_dir)
{
	int ret;
	struct genz_core_structure core;
	struct genz_control_structure_header *hdr =
		(struct genz_control_structure_header *)&core;
	struct genz_control_info *ci, *sibling = NULL;
	uint64_t max_ctl;

	if (zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return -1;
	}

	pr_debug("reading core structure\n");
	/* Read the first 64 bytes of core struct at control space offset 0 */
	ret = genz_control_read(zbdev, 0x0, 64, &core, rmri, 0);
	if (ret) {
		pr_debug("genz_control_read of core structure failed with %d\n", ret);
		return ret;
	}

	/* Validate the header is as expected */
	if (core.type != GENZ_CORE_STRUCTURE) {
		pr_debug("expected type 0 but found %u\n", core.type);
		return -EINVAL;
	}
	/*  Validate the structure size */
	if (core.size * GENZ_CONTROL_SIZE_UNIT != pi->struct_bytes) {
		pr_debug("structure size mismatch, expected %ld but found %u\n",
			 pi->struct_bytes, core.size * GENZ_CONTROL_SIZE_UNIT);
		return -EINVAL;
	}
	/* Validate the version. */
	if (core.vers != pi->vers) {
		pr_debug("structure version mismatch expected %u but found %u\n", pi->vers, core.vers);
		return -EINVAL;
	}

	/* Allocate a genz_control_info with a kobject for this directory */
	ci = alloc_control_info(zbdev, hdr, 0x0, NULL, &sibling, NULL, rmri);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}

	ret = kobject_init_and_add(&ci->kobj, &control_info_ktype, con_dir,
			"%s@0x%lx", genz_structure_name(core.type), ci->start);
	if (ret < 0) {
		pr_debug("kobject_add failed with %d\n", ret);
		kobject_put(&ci->kobj);
		return ret;
	}
	*root = ci;

	ret = genz_control_create_bin_file(ci, genz_structure_name(core.type));
	if (ret) {
		/* Revisit: handle error */
		pr_debug("genz_control_create_bin_file failed with %d for file %s\n",
			 ret, ci->battr.attr.name);
		return ret;
	}
	/* Revisit: temporary hack to workaround incorrect mamba value */
	max_ctl = max((uint64_t)core.max_ctl, 0xd0000ull);
	/* Resize the requester ZMMU mapping to cover all of control space */
	ret = genz_rmr_resize(&zbdev->fabric->mgr_uuid, max_ctl, rmri);
	if (ret < 0) {
		/* Revisit: handle error */
		pr_debug("genz_rmr_resize for %s failed with %d\n",
			 ci->battr.attr.name, ret);
		return ret;
	}
	/* Recursively traverse any pointers in this structure */
	ret = traverse_control_pointers(zbdev, rmri, ci, core.type, core.vers,
					con_dir, core_ptr_order);
	if (ret < 0) {
		/* Revisit: handle error */
		pr_debug("traverse_control_pointers for %s failed with %d\n",
			 ci->battr.attr.name, ret);
		return ret;
	}
	return 0;
}

static int traverse_structure(struct genz_bridge_dev *zbdev,
			struct genz_rmr_info *rmri,
			struct genz_control_info *parent,
			struct genz_control_info **sibling,
			struct kobject *struct_dir,
			const struct genz_control_structure_ptr *csp)
{
	int ret;
	struct genz_control_structure_header hdr;
	off_t hdr_offset;
	struct genz_control_info *ci;

	pr_debug("in traverse_structure\n");
	ret = read_and_validate_header(zbdev, rmri, parent->start, csp,
		&hdr, &hdr_offset);
	if (ret == ENOENT) {
		pr_debug("pointer is NULL, which is ok\n");
		return 0;
	} else if (ret) {
		pr_debug("read_and_validate_header returned with %d\n", ret);
		return ret;
	}

	/* Allocate a genz_control_info with a kobject for this directory */
	ci = alloc_control_info(zbdev, &hdr, hdr_offset, parent, sibling, csp, rmri);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}
	pr_debug("after alloc_control_info hdr_offset is 0x%lx ci->start is 0x%lx\n", hdr_offset, ci->start);

	/* Revisit: the directory is supposed to be the field name not the structure name. */
	pr_debug("calling kobject_init_and_add for %s\n", genz_structure_name(hdr.type));
	ret = kobject_init_and_add(&ci->kobj, &control_info_ktype, struct_dir,
			"%s@0x%lx", genz_structure_name(hdr.type), ci->start);
	if (ret < 0) {
		pr_debug("kobject_init_and_add failed with %d\n", ret);
		kobject_put(&ci->kobj);
		return ret;
	}

	ret = genz_control_create_bin_file(ci, genz_structure_name(hdr.type));
	if (ret) {
		/* Revisit: handle error */
		pr_debug("genz_control_create_bin_file failed with %d for file %s\n",
				ret, ci->battr.attr.name);
		return ret;
	}
	/* Recursively traverse any pointers in this structure */
	pr_debug("calling traverse_control_pointers for any pointers in struct %s\n", ci->battr.attr.name);
	ret = traverse_control_pointers(zbdev, rmri, ci, hdr.type, hdr.vers,
					&ci->kobj, NULL);
	if (ret < 0) {
		/* Revisit: handle error */
		pr_debug("traverse_control_pointers for %s failed with %d\n", ci->battr.attr.name, ret);
		return ret;
	}
	return 0;
}

static const char *ptr_type_name(uint type) {
	static const char *name[] = {
		"GENZ_CONTROL_POINTER_NONE",
		"GENZ_CONTROL_POINTER_STRUCTURE",
		"GENZ_CONTROL_POINTER_CHAINED",
		"GENZ_CONTROL_POINTER_ARRAY",
		"GENZ_CONTROL_POINTER_TABLE",
		"GENZ_CONTROL_POINTER_TABLE_WITH_HEADER"
	};

	/* Revisit: range check */
	return name[type];
}

static int traverse_control_pointers(struct genz_bridge_dev *zbdev,
	struct genz_rmr_info *rmri,
	struct genz_control_info *parent,
	int struct_type,
	int struct_vers,
	struct kobject *dir,
	uint order[])
{
	const struct genz_control_structure_ptr *csp, *csp_entry;
	struct genz_control_info *sibling = NULL;
	bool is_chain;
	int i, ret, num_ptrs;
	const char *tname;

	ret = get_control_ptr(zbdev, struct_type, struct_vers, &csp, &num_ptrs);
	if (ret < 0) {
		pr_debug("get_control_ptr failed with %d\n", ret);
		return ret;
	}
	for (i = 0; i < num_ptrs; i++) {
		if (order)  /* caller specified a traversal order */
			csp_entry = &csp[order[i]];
		else  /* increasing order */
			csp_entry = &csp[i];
		tname = ptr_type_name(csp_entry->ptr_type);
		switch (csp_entry->ptr_type) {
		case GENZ_CONTROL_POINTER_NONE:
			pr_debug("%s, ignoring ptr_type %s\n",
				 csp_entry->ptr_name, tname);
			break;
		case GENZ_CONTROL_POINTER_STRUCTURE:
			is_chain = is_head_of_chain(zbdev, rmri, parent->start, csp_entry);
			pr_debug("%s, ptr_type %s, is_chain=%d\n",
				 (csp_entry->ptr_name) ? csp_entry->ptr_name :
				 "generic PTR", tname, is_chain);
			if (is_chain)
				ret = traverse_chained_control_pointers(
					zbdev, rmri, parent, &sibling, dir,
					csp_entry);
			else
				ret = traverse_structure(zbdev, rmri, parent,
							 &sibling, dir, csp_entry);
			break;
		case GENZ_CONTROL_POINTER_CHAINED:
			pr_debug("%s, caller will handle ptr_type %s\n",
				 csp_entry->ptr_name, tname);
			break;
		case GENZ_CONTROL_POINTER_ARRAY:
			pr_debug("%s, ptr_type %s\n",
				 csp_entry->ptr_name, tname);
			ret = traverse_table(zbdev, rmri, parent, &sibling,
					     dir, csp_entry);
			break;
		case GENZ_CONTROL_POINTER_TABLE:
			is_chain = is_head_of_chain(zbdev, rmri, parent->start, csp_entry);
			pr_debug("%s, ptr_type %s, is_chain=%d\n",
				 (csp_entry->ptr_name) ? csp_entry->ptr_name :
				 "generic PTR", tname, is_chain);
			if (is_chain) {
				ret = traverse_chained_control_pointers(
					zbdev, rmri, parent, &sibling, dir,
					csp_entry);
			} else {
				/* Revisit: special case for Route Control Table
				 * symlink for 2nd reference (CompDest/Switch)
				 */
				ret = traverse_table(zbdev, rmri, parent,
						     &sibling, dir, csp_entry);
			}
			break;
		case GENZ_CONTROL_POINTER_TABLE_WITH_HEADER:
			pr_debug("%s, ptr_type %s\n",
				 csp_entry->ptr_name, tname);
			ret = traverse_table(zbdev, rmri, parent, &sibling,
					     dir, csp_entry);
			break;
		}
		if (ret < 0) {
			/* Revisit: Undo everything and fail */
			return ret;
		}
	}
	return 0;
}

void *genz_control_structure_buffer_alloc(
		enum genz_control_structure_type stype,
		int flags)
{
	void *buf;
	int sbytes;

	if (!genz_validate_structure_type(stype))
		return NULL;
	sbytes = genz_struct_type_to_ptrs[stype].struct_bytes;
	if (!sbytes)
		return NULL;

	buf = kzalloc(sbytes, flags);
	return buf;
}

int genz_control_read(struct genz_bridge_dev *br, loff_t offset,
		      size_t size, void *data,
		      struct genz_rmr_info *rmri, uint flags)
{
	if (!is_genz_range_mapped(offset, size, rmri))
		return ENOSPC;
	if (!br->zbdrv->control_read)  /* control_read is required */
		return -EINVAL;
	return br->zbdrv->control_read(br, offset, size, data, rmri, flags);
}

int genz_control_write(struct genz_bridge_dev *br, loff_t offset,
		       size_t size, void *data,
		       struct genz_rmr_info *rmri, uint flags)
{
	if (!is_genz_range_mapped(offset, size, rmri))
		return ENOSPC;
	if (!br->zbdrv->control_write)  /* control_write is required */
		return -EINVAL;
	return br->zbdrv->control_write(br, offset, size, data, rmri, flags);
}

int genz_control_read_structure(struct genz_bridge_dev *zbdev,
		struct genz_rmr_info *rmri,
		void *buf, off_t cs_offset,
		off_t field_offset, size_t field_size)
{
	int ret;

	if (buf == NULL) {
		pr_debug("buf is NULL\n");
		return -EINVAL;
	}
	if (field_size == 0) {
		pr_debug("field_size is 0\n");
		return -EINVAL;
	}
	ret = genz_control_read(
		zbdev, cs_offset+field_offset, field_size, buf, rmri, 0);
	if (ret)
		pr_debug("genz_control_read failed with %d\n", ret);

	return ret;
}

int genz_control_write_structure(struct genz_bridge_dev *zbdev,
		struct genz_rmr_info *rmri,
		void *buf, off_t cs_offset,
		off_t field_offset, size_t field_size)
{
	int ret;

	if (buf == NULL) {
		pr_debug("buf is NULL\n");
		return -EINVAL;
	}
	if (field_size == 0) {
		pr_debug("field_size is 0\n");
		return -EINVAL;
	}
	ret = genz_control_write(
		zbdev, cs_offset+field_offset, field_size, buf, rmri, 0);
	if (ret)
		pr_debug("genz_control_write failed with %d\n", ret);

	return ret;
}

int genz_control_read_cid0(struct genz_bridge_dev *zbdev,
			   struct genz_rmr_info *rmri, uint16_t *cid0)
{
	int ret;
	uint32_t buf;

	/*
	 * CID0 is 16 bits in the middle of a word. The word starts
	 * with the CV field. So read 32 bits and mask off the CID0
	 */
	ret = genz_control_read_structure(zbdev, rmri, &buf, 0,
			0xC0, /* Revisit: how to get offsets better */
			sizeof(buf));
	if (ret)
		return ret;
	*cid0 = ((buf >> 8) & 0xFFF);
	pr_debug("0x%x\n", *cid0);
	return ret;
}

int genz_control_read_sid(struct genz_bridge_dev *zbdev,
			  struct genz_rmr_info *rmri, uint16_t *sid)
{
	int ret;

	ret = genz_control_read_structure(zbdev, rmri, sid, 0,
			0xB8, /* Revisit: how to get offsets better */
			sizeof(*sid));
	pr_debug("0x%x\n", *sid);
	return ret;
}

int genz_control_read_serial(struct genz_bridge_dev *zbdev,
			     struct genz_rmr_info *rmri, uint64_t *serial)
{
	int ret;

	ret = genz_control_read_structure(zbdev, rmri, serial, 0,
			offsetof(struct genz_core_structure, serial_number),
			sizeof(*serial));
	pr_debug("offset=0x%lx, serial=0x%llx\n",
		 offsetof(struct genz_core_structure, serial_number), *serial);
	return ret;
}

int genz_control_read_cclass(struct genz_bridge_dev *zbdev,
			     struct genz_rmr_info *rmri, uint16_t *cclass)
{
	int ret;

	ret = genz_control_read_structure(zbdev, rmri, cclass, 0,
			0x18, /* Revisit: how to get offsets better */
			sizeof(*cclass));
	pr_debug("0x%x\n", *cclass);
	return ret;
}

int genz_control_read_fru_uuid(struct genz_bridge_dev *zbdev,
			       struct genz_rmr_info *rmri, uuid_t *fru_uuid)
{
	uuid_t zero_uuid = { 0 };
	int ret;

	ret = genz_control_read_structure(zbdev, rmri, fru_uuid, 0,
			offsetof(struct genz_core_structure, fru_uuid),
			sizeof(*fru_uuid));
	if (ret == 0)
		ret = abs(genz_uuid_cmp(fru_uuid, &zero_uuid));
	pr_debug("%pUb, ret=%d\n", fru_uuid, ret);
	return ret;
}

int genz_control_read_c_uuid(struct genz_bridge_dev *zbdev,
			     struct genz_rmr_info *rmri, uuid_t *c_uuid)
{
	uuid_t zero_uuid = { 0 };
	int ret;

	ret = genz_control_read_structure(zbdev, rmri, c_uuid, 0,
			offsetof(struct genz_core_structure, c_uuid),
			sizeof(*c_uuid));
	if (ret == 0)
		ret = abs(genz_uuid_cmp(c_uuid, &zero_uuid));
	pr_debug("%pUb, ret=%d\n", c_uuid, ret);
	return ret;
}

int genz_control_read_mgr_uuid(struct genz_bridge_dev *zbdev,
			       struct genz_rmr_info *rmri, uuid_t *mgr_uuid)
{
	uuid_t zero_uuid = { 0 };
	int ret;

	ret = genz_control_read_structure(zbdev, rmri, mgr_uuid, 0,
			offsetof(struct genz_core_structure, mgr_uuid),
			sizeof(*mgr_uuid));
	if (ret == 0)
		ret = abs(genz_uuid_cmp(mgr_uuid, &zero_uuid));
	pr_debug("%pUb, ret=%d\n", mgr_uuid, ret);
	return ret;
}

int genz_control_read_c_control(struct genz_bridge_dev *zbdev,
				struct genz_rmr_info *rmri, uint64_t *c_control)
{
	int ret;

	ret = genz_control_read_structure(zbdev, rmri, c_control, 0,
			offsetof(struct genz_core_structure, c_control),
			sizeof(*c_control));
	pr_debug("offset=0x%lx, c_control=0x%llx\n",
		 offsetof(struct genz_core_structure, c_control), *c_control);
	return ret;
}

int genz_control_write_c_control(struct genz_bridge_dev *zbdev,
				 struct genz_rmr_info *rmri, uint64_t c_control)
{
	int ret;

	ret = genz_control_write_structure(zbdev, rmri, &c_control, 0,
			offsetof(struct genz_core_structure, c_control),
			sizeof(c_control));
	pr_debug("offset=0x%lx, c_control=0x%llx\n",
		 offsetof(struct genz_core_structure, c_control), c_control);
	return ret;
}

/**
 * genz_bridge_create_control_files() - read control space for a local bridge
 */
int genz_bridge_create_control_files(struct genz_bridge_dev *zbdev)
{
	int                      ret;
	struct genz_dev          *zdev = &zbdev->zdev;
	struct device            *bdev = zbdev->bridge_dev;
	char                     bridgeN[MAX_GENZ_NAME];
	uint                     fabric_num;
	struct kobject           *genz_dir;

	/* Make the genzN directory under the native device */
	genz_dir = &zbdev->genzN_dir;
	/* Use actual fabric number if known, else 0 */
	fabric_num = (zbdev->fabric) ? zbdev->fabric->number : 0;
	ret = kobject_init_and_add(genz_dir, &genz_dir_ktype, &bdev->kobj,
				   "genz%u", fabric_num);
	if (ret < 0) {
		pr_debug("unable to create genz%u directory\n", fabric_num);
		goto err_genz_dir;
	}
	/* Create a symlink from genzN to /sys/devices/genzN/bridgeN */
	snprintf(bridgeN, MAX_GENZ_NAME, "bridge%d", zbdev->bridge_num);
	/* Revisit: check all those pointers are not NULL */
	ret = sysfs_create_link(&zbdev->zdev.zcomp->subnet->subnet.fabric->dev.kobj,
			genz_dir, bridgeN);
	if (ret < 0) {
		pr_debug("unable to create %s symlink\n", bridgeN);
		goto err_kobj;
	}

	/* Make control directory under genzN */
	/* Revisit: error handling */
	//zdev->root_control_info->kobj.kset = zbdev->genz_kset; /* Revisit */
	ret = kobject_init_and_add(&zdev->zcomp->comp.ctl_kobj,
				   &control_dir_ktype, genz_dir, "control");
	if (ret < 0) {
		pr_debug("unable to create bridge control directory\n");
		goto err_control;
	}

	/* Make gcid/cclass/serial files under native device/genzN directory */
	ret = genz_create_bridge_files(genz_dir);
	if (ret < 0) {
		pr_debug("unable to create bridge files\n");
		goto err_control;
	}

	/* Populate native device/genzN/control directory */
	/* Revisit: error handling */
	pr_debug("calling start_core_structure\n");
	ret = start_core_structure(zbdev, NULL,
			&zdev->zcomp->comp.root_control_info,
			&genz_struct_type_to_ptrs[GENZ_CORE_STRUCTURE],
			&zdev->zcomp->comp.ctl_kobj); /* control dir */
	return 0;

err_control:
	kobject_put(&zdev->zcomp->comp.root_control_info->kobj);
err_kobj:
err_genz_dir:
	kobject_put(genz_dir);
	return ret;
}

static struct kobject *genz_comp_iface_dir(struct genz_comp *dr_comp,
					   uint16_t dr_iface)
{
	struct genz_control_info *ci, *core;
	uint num = 0;

	core = dr_comp->root_control_info;
	/* Find the interface structure matching dr_iface */
	for (ci = genz_first_struct_of_type(core, GENZ_INTERFACE_STRUCTURE);
	     ci != NULL;
	     ci = genz_next_struct_of_type(ci, GENZ_INTERFACE_STRUCTURE)) {
		if (num == dr_iface)
			break;
		num++;
	}

	if (ci)
		return &ci->kobj;
	return 0;
}

/**
 * genz_dr_create_control_files() - read control space for a directed-relay component
 */
int genz_dr_create_control_files(struct genz_bridge_dev *zbdev,
				 struct genz_comp *f_comp,
				 struct genz_comp *dr_comp,
				 uint16_t dr_iface, uuid_t *mgr_uuid)
{
	uint32_t                 gcid;
	struct kobject           *dr_dir, *iface_dir;
	struct genz_rmr_info     *dr_rmri;
	struct genz_mem_data     *mdata;
	uint64_t                 access;
	uint32_t                 rkey;
	int                      ret;
	bool                     br_is_dr;

	mdata = alloc_mdata(zbdev, mgr_uuid);
	if (!mdata) {
		pr_debug("failed to allocate genz_mem_data\n");
		return -ENOMEM;
	}
	br_is_dr = (dr_comp == &zbdev->zdev.zcomp->comp);
	gcid = genz_comp_gcid((br_is_dr) ? f_comp : dr_comp);
	dr_dir = &f_comp->ctl_kobj;
	dr_rmri = &f_comp->ctl_rmr_info;
	iface_dir = genz_comp_iface_dir(dr_comp, dr_iface);
	if (!iface_dir) {
		pr_debug("dr_iface %u not found\n", dr_iface);
		ret = -EINVAL;
		goto err_mdata;
	}
	/* Make the dr directory under interfaceN of the relaying component */
	ret = kobject_init_and_add(dr_dir, &control_dir_ktype, iface_dir, "dr");
	if (ret < 0) {
		pr_debug("unable to create dr directory\n");
		goto err_kobj;
	}

	access = GENZ_MR_READ_REMOTE|GENZ_MR_WRITE_REMOTE|
		 GENZ_MR_INDIVIDUAL|GENZ_MR_CONTROL;
	access |= (zbdev->br_info.load_store) ?
		(GENZ_MR_REQ_CPU|GENZ_MR_KERN_MAP) : 0;
	rkey = 0;  /* Revisit */
	pr_debug("calling genz_rmr_import\n");
	/* initial mapping is for one 4KiB page covering the core struct */
	/* Revisit: change fixed "control" rmr_name to something with GCID */
	ret = genz_rmr_import(mdata, mgr_uuid, gcid, 0, 4096,
			      access, rkey, dr_iface, "control", dr_rmri);
	if (ret < 0) {
		pr_debug("genz_rmr_import error ret=%d\n", ret);
		goto err_kobj;
	}
	pr_debug("calling start_core_structure\n");
	ret = start_core_structure(zbdev, dr_rmri,
			&f_comp->root_control_info,
			&genz_struct_type_to_ptrs[GENZ_CORE_STRUCTURE],
			dr_dir);
	if (ret < 0) {
		pr_debug("start_core_structure error ret=%d\n", ret);
		goto err_rmr;
	}
	return 0;

err_rmr:
	genz_rmr_free(dr_rmri);
err_kobj:
	kobject_put(dr_dir);
err_mdata:
	remove_mdata(zbdev);
	return ret;
}

int genz_comp_read_attrs(struct genz_bridge_dev *zbdev,
			 struct genz_rmr_info *rmri, struct genz_comp *comp)
{
	int ret;

	/* gcid has already been read */
	ret = genz_control_read_cclass(zbdev, rmri, &comp->cclass);
	if (ret) {
		pr_debug("genz_control_read_cclass returned %d\n", ret);
		return ret;
	}
	ret = genz_control_read_serial(zbdev, rmri, &comp->serial);
	if (ret) {
		pr_debug("genz_control_read_serial returned %d\n", ret);
		return ret;
	}
	ret =  genz_control_read_c_uuid(zbdev, rmri, &comp->c_uuid);
	if (ret < 0) {
		pr_debug("genz_control_read_c_uuid returned %d\n", ret);
		return ret;
	}
	ret = genz_control_read_fru_uuid(zbdev, rmri, &comp->fru_uuid);
	if (ret < 0) {
		pr_debug("genz_control_read_fru_uuid returned %d\n", ret);
	}
	return ret;
}

/**
 * genz_fab_create_control_files() - read control space for a "normal" fabric component
 */
int genz_fab_create_control_files(struct genz_bridge_dev *zbdev,
				  struct genz_comp *f_comp,
				  uint16_t dr_iface, uuid_t *mgr_uuid)
{
	uint32_t                 gcid = genz_comp_gcid(f_comp);
	struct genz_rmr_info     *rmri;
	struct genz_mem_data     *mdata;
	uint64_t                 access;
	uint32_t                 rkey;
	int                      ret;

	rmri = &f_comp->ctl_rmr_info;
	mdata = alloc_mdata(zbdev, mgr_uuid);
	if (!mdata) {
		pr_debug("failed to allocate genz_mem_data\n");
		return -ENOMEM;
	}
	if (dr_iface != GENZ_DR_IFACE_NONE) {
		/* we already have (dr) control space - move/update it */
		ret = kobject_move(&f_comp->ctl_kobj, &f_comp->kobj);
		if (ret < 0) {
			pr_debug("genz_kobject_move error ret=%d\n", ret);
			goto err_mdata;
		}
		ret = kobject_rename(&f_comp->ctl_kobj, "control");
		if (ret < 0) {
			pr_debug("genz_kobject_rename error ret=%d\n", ret);
			goto err_mdata;
		}
		/* update rmr to disable DR */
		ret = genz_rmr_change_dr(&zbdev->fabric->mgr_uuid, gcid,
					 GENZ_DR_IFACE_NONE, rmri);
		if (ret < 0) {
			pr_debug("genz_rmr_change_dr error ret=%d\n", ret);
			goto err_mdata;
		}
		ret = genz_comp_read_attrs(zbdev, rmri, f_comp);
		if (ret < 0) {
			pr_debug("genz_comp_read_attrs error ret=%d\n", ret);
			goto err_mdata;
		}
		ret = genz_create_fab_files(&f_comp->kobj);
		return ret;
	}
	/* Make the control directory under the component */
	ret = kobject_init_and_add(&f_comp->ctl_kobj, &control_dir_ktype,
				   &f_comp->kobj, "control");
	if (ret < 0) {
		pr_debug("unable to create control directory\n");
		goto err_mdata;
	}

	access = GENZ_MR_READ_REMOTE|GENZ_MR_WRITE_REMOTE|
		 GENZ_MR_INDIVIDUAL|GENZ_MR_CONTROL;
	access |= (zbdev->br_info.load_store) ?
		(GENZ_MR_REQ_CPU|GENZ_MR_KERN_MAP) : 0;
	rkey = 0;  /* Revisit */
	pr_debug("calling genz_rmr_import\n");
	/* initial mapping is for one 4KiB page covering the core struct */
	/* Revisit: change fixed "control" rmr_name to something with GCID */
	ret = genz_rmr_import(mdata, mgr_uuid, gcid, 0, 4096,
			      access, rkey, dr_iface, "control", rmri);
	if (ret < 0) {
		pr_debug("genz_rmr_import error ret=%d\n", ret);
		goto err_kobj;
	}
	ret = genz_comp_read_attrs(zbdev, rmri, f_comp);
	if (ret < 0) {
		pr_debug("genz_comp_read_attrs error ret=%d\n", ret);
		goto err_rmr;
	}
	ret = genz_create_fab_files(&f_comp->kobj);
	if (ret < 0) {
		pr_debug("genz_create_fab_files error ret=%d\n", ret);
		goto err_rmr;
	}
	pr_debug("calling start_core_structure\n");
	ret = start_core_structure(zbdev, rmri,
			&f_comp->root_control_info,
			&genz_struct_type_to_ptrs[GENZ_CORE_STRUCTURE],
			&f_comp->ctl_kobj);
	if (ret < 0) {
		pr_debug("start_core_structure error ret=%d\n", ret);
		goto err_fab_files;
	}
	return 0;

err_fab_files:
	genz_remove_fab_files(&f_comp->kobj);
err_rmr:
	genz_rmr_free(rmri);
err_kobj:
	kobject_put(&f_comp->ctl_kobj);
err_mdata:
	remove_mdata(zbdev);
	return ret;
}

struct genz_control_info *genz_first_struct_of_type(
	struct genz_control_info *parent, uint type)
{
	struct genz_control_info *ci;

	if (parent == NULL)
		return NULL;

	for (ci = parent->child; ci != NULL; ci = ci->sibling) {
		if (ci->type == type)
			break;
	}

	pr_debug("parent=%px, type=%d, ci=%px\n", parent, type, ci);
	return ci;
}

struct genz_control_info *genz_next_struct_of_type(
	struct genz_control_info *prev, uint type)
{
	struct genz_control_info *ci;

	if (prev == NULL)
		return NULL;

	for (ci = prev->sibling; ci != NULL; ci = ci->sibling) {
		if (ci->type == type)
			break;
	}

	pr_debug("prev=%px, type=%d, ci=%px\n", prev, type, ci);
	return ci;
}

#ifdef BROKEN
static void remove_all_ci(struct kset *kset)
{
	struct kobject *kobj, *ktmp;
	struct list_head *klist;
	struct kobject *first = NULL;

	pr_debug("doing kobject_put on all objects in kset %s\n", kobject_name(&kset->kobj));
	if (kset) {
		klist = &kset->list;
		list_for_each_entry_safe(kobj, ktmp, klist, entry)  {
			pr_debug("kobject_put on kobject %s next %p prev %p\n", kobject_name(kobj), kobj->entry.next, kobj->entry.prev);
			if (first == NULL) {
			       	first = kobj;
			} else if (kobj == first) {
				/* break the loop */
				return;
			}
			if (kobj == NULL)
				return;

			if (kobj)
				kobject_put(kobj);
		}
	}
}
#endif

/**
 * genz_bridge_remove_control_files() - remove sysfs files for a local bridge
 */
int genz_bridge_remove_control_files(struct genz_bridge_dev *zbdev)
{
	char                   bridgeN[MAX_GENZ_NAME];
	struct genz_dev        *zdev = &zbdev->zdev;
	struct kobject         *dir;

	dev_dbg(zbdev->bridge_dev, "entered\n");
#ifdef BROKEN
	/*
	 * The struct genz_control_infos are removed when the kobject
	 * release() is called.
	 */
	remove_all_ci(zbdev->genz_control_kset);
#endif
	/* remove the genzN/{gcid,cclass,serial,fru_uuid,c_uuid} files */
	genz_remove_bridge_files(&zbdev->genzN_dir);
	/* remove the control directory */
	kobject_del(&zdev->zcomp->comp.ctl_kobj);
	kobject_put(&zdev->zcomp->comp.ctl_kobj);
	/* remove the symlink associated with this genzN directory */
	dir = &zbdev->zdev.zcomp->comp.subnet->fabric->dev.kobj;
	snprintf(bridgeN, MAX_GENZ_NAME, "bridge%d", zbdev->bridge_num);
	dev_dbg(zbdev->bridge_dev, "removing %s symlink for kobj %s\n",
		bridgeN, kobject_name(dir));
	sysfs_remove_link(dir, bridgeN);
	/* remove the genzN directory */
	kobject_del(&zbdev->genzN_dir);
#ifdef BROKEN
	pr_debug("kset_unregister %s\n", kobject_name(&zbdev->genz_control_kset->kobj));
	kset_unregister(zbdev->genz_control_kset);
#endif
	kobject_put(&zbdev->genzN_dir); /* free the genzN directory */
	return 0;
}

/**
 * genz_create_sysfs_dev_files(struct genz_dev *zdev)
 * zdev - a struct genz_dev for a new device
 *
 * populate the sysfs /sys/devices/genz0 hierarchy for a new device.
 */
/* Revisit: this is in a private header. figure out the right way... */
#ifdef NOT_YET
extern struct kset *devices_kset;
int genz_create_sysfs_dev_files(struct genz_dev *zdev)
{
	int ret = 0;
	struct kobject *sid, *cid, *attrib_dir;
	struct device *fab_dev;

	if (zdev == NULL) {
		pr_debug("zdev is NULL\n");
		return -EINVAL;
	}

	/* Next parse the gcid to get the SID for the next directory */
	sid = kobject_create();
	if (sid == NULL)
		goto err_genz;
	ret = kobject_init_and_add(sid, &control_info_ktype, zdev->ctl_kobj,
			"%04d", genz_gcid_sid(zdev->zcomp->gcid));
	if (ret < 0)
		goto err_sid;

	/* Next parse the gcid to get the CID for the next directory */
	cid = kobject_create();
	if (cid == NULL)
		goto err_sid;
	ret = kobject_init_and_add(cid, &control_info_ktype, sid,
			"%03d", genz_gcid_cid(zdev->zcomp->gcid));
	if (ret < 0)
		goto err_cid;

	/* Add the attribs directory */
	attrib_dir = kobject_create();
	if (attrib_dir == NULL)
		goto err_cid;
	ret = kobject_init_and_add(attrib_dir, &control_info_ktype, cid,
			"attribs");
	if (ret < 0)
		goto err_attrib;

err_attrib:
	kobject_put(attrib_dir);
err_cid:
	kobject_put(cid);
err_sid:
	kobject_put(sid);
err_genz:
	kobject_put(zdev->ctl_kobj);
	return ret;
}
#endif
