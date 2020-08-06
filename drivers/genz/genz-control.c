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

/*
 * is_head_of_chain - determines if a GENZ_CONTROL_POINTER_STRUCTURE
 * or GENZ_CONTROL_POINTER_TABLE points to a type that has a chain.
 * If this is the case, then
 * there is a sysfs directory created with that structure name and in
 * that directory, a set of directories for each element of the
 * chain starting at 0.
 */
static int is_head_of_chain(const struct genz_control_structure_ptr *csp)
{
	enum genz_control_structure_type target_type;
	bool is_table;

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
	target_type = (is_table) ? csp->struct_type-GENZ_TABLE_ENUM_START :
		csp->struct_type;

	/*
	 * The table indicates if this type is chained in the static
	 * genz_control_ptr_info structure. If it is marked chained then
	 * this must be the head of the chain.
	 */
	return (is_table) ? genz_table_type_to_ptrs[target_type].chained :
		genz_struct_type_to_ptrs[target_type].chained;
}

static int traverse_control_pointers(struct genz_bridge_dev *zbdev,
	struct genz_rmr_info *rmri,
	struct genz_control_info *parent,
	int struct_type,
	int struct_vers,
	struct kobject *dir);

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
static inline const char *genz_table_name(int type)
{
	if (!genz_validate_table_type(type))
		return "unknown";

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
 * Returns the name or "unknown" if the type is not vaild.
 */
static inline const char *genz_control_name(int type)
{
	if (is_struct_type(type))
		return genz_structure_name(type);
	else
		return genz_table_name(type);
}

static void control_info_release(struct kobject *kobj)
{
	struct genz_control_info *ci = to_genz_control_info(kobj);

	pr_debug("kobj %s\n", kobj->name);
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
	ssize_t ret = 0;
	int err;

	err = validate_ci(ci, offset, size, data, &zbdev);
	if (err < 0) {
		pr_debug("arguments invalid error: %d\n", err);
		/* Revisit: what should it return on error? */
		return err;
	}
	pr_debug("reading %s at offset=0x%llx, size=0x%lx, ci->start=0x%lx, ci->size=0x%lx\n", kobj->name, offset, size, ci->start, ci->size);

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
	ssize_t ret = 0;
	int err;

	err = validate_ci(ci, offset, size, data, &zbdev);
	if (err < 0) {
		pr_debug("arguments invalid error: %d\n", err);
		return err;
	}
	ret = genz_control_write(zbdev, ci->start+offset, size, data, rmri, 0);
	if (ret) {
		pr_debug("genz_control_write failed with %ld\n", ret);
		return ret;
	}
	return size;
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
	struct device          *bdev;

	/* Revisit: Is this just a debug function? It doesn't do anything */
	if (kobj == NULL) {
		pr_debug("NULL kobj\n");
		return;
	}
	bdev = kobj_to_dev(kobj->parent);
	if (bdev == NULL) {
		pr_debug("failed to find bdev from kobject parent\n");
		return;
	}
	dev_dbg(bdev, "kobj %s\n", kobj->name);
}

static struct kobj_type genz_dir_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = genz_dir_release
};

static ssize_t gcid_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct genz_bridge_dev *zbdev;
	struct genz_component *comp;

	zbdev = kobj_to_zbdev(kobj);
	if (zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad zbdev\n"));
	}
	comp = zbdev->zdev.zcomp;
	if (comp->subnet == NULL) {
		pr_debug("comp->subnet is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component subnet\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%04x:%03x\n", comp->subnet->sid, comp->cid));
}

static struct kobj_attribute gcid_attribute =
	__ATTR(gcid, (0444), gcid_show, NULL);

static ssize_t cuuid_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	struct genz_bridge_dev *zbdev;
	struct genz_component *comp;

	zbdev = kobj_to_zbdev(kobj);
	if (zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad zbdev\n"));
	}
	comp = zbdev->zdev.zcomp;
	if (comp->subnet == NULL) {
		pr_debug("comp->subnet is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad component subnet\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%pUb\n", &comp->c_uuid));
}

static struct kobj_attribute cuuid_attribute =
	__ATTR(cuuid, (0444), cuuid_show, NULL);

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

	pr_debug("start+offset 0x%lx\n", start+offset);
	*ptr_offset = 0;
	/* Read the given offset to get the pointer to the control structure */
	ret = genz_control_read(zbdev, start+offset,
				(int)psize, ptr_offset, rmri, 0);
	if (ret) {
		pr_debug("genz_control_read of pointer failed with %d\n", ret);
		return ret;
	}

	pr_debug("found the pointer is 0x%lx\n", *ptr_offset);
	
	/* It is ok for many pointers to be NULL. Everything is optional. */
	if (*ptr_offset == 0) {
		pr_debug("pointer field at 0x%lx is NULL\n", start+offset);
		return ENOENT;
	}

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
	pr_debug("reading the header from the pointer offset 0x%lx, size = 0x%lx\n", *hdr_offset, sizeof(struct genz_control_structure_header));
	ret = genz_control_read(zbdev, *hdr_offset,
		sizeof(struct genz_control_structure_header), hdr, rmri, 0);
	if (ret) {
		pr_debug("genz_control_read of structure header failed with %d\n",
			ret);
		return ret;
	}
	pr_debug("hdr->type=%d, hdr->vers=%d, hdr->size=0x%x\n",
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
		pr_debug("read_header_at_offset returned ENOENT\n");
		return ENOENT;
	} else if (ret) {
		pr_debug("read_header_at_offset returned %d\n", ret);
		return ret;
	}

	/* Validate the header is as expected */
	if ((csp->struct_type != GENZ_GENERIC_STRUCTURE) &&
	    (hdr->type != csp->struct_type)) {
		pr_debug("expected type %d but found %d\n",
			csp->struct_type, hdr->type);
		return -EINVAL;
	}
	/* Check if this is a known type */
	if (!genz_validate_structure_type(hdr->type)) {
		pr_debug("unknown structure type %u\n", hdr->type);
		goto out;
	}
	/*  Validate the structure size.
	 */
	if (!genz_validate_structure_size(hdr)) {
		pr_debug("structure size is wrong\n");
		return -EINVAL;
	}
	/* Validate the version. */
	expected_vers = genz_struct_type_to_ptrs[hdr->type].vers;
	if (hdr->vers != expected_vers) {
		pr_debug("structure version mismatch expected %d but found %d.\n", expected_vers, hdr->vers);
		/* Revisit: don't fail on version mismatch because of quirks */
	} else {
		pr_debug("versions match: hdr->vers is %d\n", hdr->vers);
	}
out:
	return 0;
}

static struct genz_control_info *alloc_control_info(
	struct genz_bridge_dev *zbdev,
	struct genz_control_structure_header *hdr,
	off_t offset,
	struct genz_control_info *parent)
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
	if (hdr) { /* root control dir and chained dirs have no header. */
		ci->type = hdr->type;
		ci->vers = hdr->vers;
		ci->size = hdr->size * GENZ_CONTROL_SIZE_UNIT;
	}
	ci->parent = parent;

	/* The kobject is associated with the control kset for cleanup */
	//ci->kobj.kset = zdev->zbdev->genz_control_kset; /* Revisit */

	/* Revisit: fill out remaining fields.
	 * ci->c_access_res =;
	 * ci->zmmu = ;
	 */

	return ci;
}

static int traverse_table(struct genz_bridge_dev *zbdev,
			  struct genz_rmr_info *rmri,
			  struct genz_control_info *parent,
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
	ci = alloc_control_info(zbdev, NULL, csp->pointer_offset, parent);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}
	ci->type = csp->struct_type;
	ci->size = (*csp->size_fn)(ci->parent);
	table_name = genz_table_name(ci->type);

	pr_debug("table type 0x%x size 0x%lx name %s\n", ci->type, ci->size, table_name);

	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, struct_dir, "%s", table_name);
	if (ret < 0) {
		kobject_put(&ci->kobj);
		return ret;
	}

	/* Now initialize the binary attribute file. */
	sysfs_bin_attr_init(&ci->battr);
	ci->battr.attr.name = table_name;
	ci->battr.attr.mode = 0400;
	ci->battr.size = ci->size;
	ci->battr.read =  read_control_structure;
	ci->battr.write = write_control_structure;
	ci->battr.private = ci; /* Used to indicate valid battr */

	ret = sysfs_create_bin_file(&ci->kobj, &ci->battr);
	if (ret) {
		/* Revisit: handle error */
		pr_debug("sysfs_create_bin_file failed with %d for file %s\n",
				ret, ci->battr.attr.name);
		return ret;
	}
	/* Recursively traverse any pointers in this table */
	pr_debug("calling traverse_control_pointers for any pointers in table %s\n", ci->battr.attr.name);
	ret = traverse_control_pointers(zbdev, rmri, ci, ci->type, 0, &ci->kobj);
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
	pr_debug("struct type=%d, vers=%d\n", struct_type, struct_vers);
	if (!genz_validate_structure_type(struct_type)) {
		pr_debug("unknown structure type %u\n", struct_type);
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
	pr_debug("table type=%d\n", table_type);
	if (!genz_validate_table_type(table_type)) {
		pr_debug("unknown table type %u\n", table_type);
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
		}
	}
	if (chain_offset == -ENOENT) {
		/* Failed to find a CHAIN. */
		pr_debug("Did not find a CHAIN offset for structure\n");
		return -ENOENT;
	}
	*chain_csp = csp;
	return chain_offset;
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
			struct kobject *dir,
			const struct genz_control_structure_ptr *csp,
			int num_ptrs)
{
	int chain_num = 0;
	struct genz_control_structure_header hdr, *hdrp;
	off_t hdr_offset;
	int chain_offset = -1;
	int done = 0;
	struct genz_control_info *struct_dir;
	int ret, type, vers;
	const char *name;
	struct genz_control_info *ci;
	const struct genz_control_structure_ptr *chain_csp;
	bool is_struct = (csp->ptr_type == GENZ_CONTROL_POINTER_STRUCTURE);

	/*
	 * Read the first pointer in the chain to make sure there is
	 * one before creating the directory to contain the chained structures.
	 */
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

	/* This pointer is NULL. Not an error - just nothing to follow. */
	if (ret == ENOENT)
		return 0;
	else if (ret < 0)
		return ret;

	/* Find the offset for the chained field in this structure type. */
	chain_offset = find_chain_offset(zbdev, type, vers, &chain_csp);
	if (chain_offset < 0) {
		pr_debug("could not find the chain pointer\n");
		return chain_offset;
	}

	/* Create the container directory for all the chained structures */
	struct_dir = alloc_control_info(zbdev, hdrp, hdr_offset, parent);
	if (struct_dir == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}
	if (!hdrp) {  /* table - set type/size */
		struct_dir->type = csp->struct_type;
		struct_dir->size = (*csp->size_fn)(struct_dir->parent);
	}

	name = genz_control_name(type);
	kobject_init(&struct_dir->kobj, &control_info_ktype);
	ret = kobject_add(&struct_dir->kobj, dir, "%s", name);
	if (ret < 0) {
		kobject_put(&struct_dir->kobj);
		return ret;
	}

	while (!done) {
		/* Allocate a genz_control_info/kobject for this directory */
		ci = alloc_control_info(zbdev, hdrp, hdr_offset, struct_dir);
		if (ci == NULL) {
			pr_debug("failed to allocate control_info\n");
			return -ENOMEM;
		}
		if (!hdrp) {  /* table - set type/size */
			ci->type = csp->struct_type;
			ci->size = (*csp->size_fn)(ci->parent);
		}

		pr_debug("%s type 0x%x size 0x%lx name %s\n",
			 is_struct ? "struct" : "table", ci->type, ci->size, name);
		kobject_init(&ci->kobj, &control_info_ktype);
		ret = kobject_add(&ci->kobj, &struct_dir->kobj, "%s%d",
				  name, chain_num++);
		if (ret < 0) {
			kobject_put(&ci->kobj);
			return ret;
		}

		/* Now initialize the binary attribute file. */
		sysfs_bin_attr_init(&ci->battr);
		ci->battr.attr.name = name;
		ci->battr.attr.mode = 0400;
		ci->battr.size = ci->size;
		ci->battr.read =  read_control_structure;
		ci->battr.write = write_control_structure;
		ci->battr.private = ci; /* Revisit: is this used/needed? */

		ret = sysfs_create_bin_file(&ci->kobj, &ci->battr);
		/*
		 * Now traverse all of the pointers in the structure. The
		 * chain pointer will be skipped there and handled here in
		 * this while loop.
		 */
		ret = traverse_control_pointers(zbdev, rmri, ci, type, vers,
						&ci->kobj);
		if (ret < 0) {
			/* Handle error! */
			return ret;
		}

		/* Follow chain pointer to read the next struct/table */
		if (is_struct) {
			ret = read_and_validate_header(zbdev, rmri, hdr_offset,
				chain_csp, hdrp, &hdr_offset);
			type = hdr.type;
			vers = hdr.vers;
		} else {  /* table */
			ret = read_pointer_at_offset(zbdev, rmri, hdr_offset,
				(int)chain_csp->ptr_size,
				chain_csp->pointer_offset, &hdr_offset);
			type = chain_csp->struct_type;
			vers = 0;
		}

		/* The pointer is NULL - this is the end of the list */
		if (ret == ENOENT)
			done = 1;
		/* Revisit: ret < 0 */
	}
	return ret;
}

static int start_core_structure(struct genz_bridge_dev *zbdev,
			struct genz_control_info *parent,
			struct genz_control_ptr_info *pi,
			struct kobject *con_dir)
{
	int ret;
	struct genz_control_structure_header hdr;
	struct genz_control_info *ci;
	struct genz_rmr_info *rmri = parent->rmri;

	if (zbdev == NULL) {
		pr_debug("zbdev is NULL\n");
		return -1;
	}

	/* Read the core structure header at offset 0 of control space */
	ret = genz_control_read(zbdev, 0x0,
				sizeof(struct genz_control_structure_header),
				&hdr, rmri, 0);
	if (ret) {
		pr_debug("genz_control_read of core structure header failed with %d\n", ret);
		return ret;
	}

	/* Validate the header is as expected */
	if (hdr.type != GENZ_CORE_STRUCTURE) {
		pr_debug("expected type 0 but found %u\n", hdr.type);
		return -EINVAL;
	}
	/*  Validate the structure size */
	if (hdr.size * GENZ_CONTROL_SIZE_UNIT != pi->struct_bytes) {
		pr_debug("structure size mismatch, expected %ld but found %u\n",
			 pi->struct_bytes, hdr.size * GENZ_CONTROL_SIZE_UNIT);
		return -EINVAL;
	}
	/* Validate the version. */
	if (hdr.vers != pi->vers) {
		pr_debug("structure version mismatch expected %u but found %u\n", pi->vers, hdr.vers);
		return -EINVAL;
	}

	/* Allocate a genz_control_info with a kobject for this directory */
	ci = alloc_control_info(zbdev, &hdr, 0x0, parent);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}

	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, con_dir, "%s",
			genz_structure_name(hdr.type));
	if (ret < 0) {
		pr_debug("kobject_add failed with %d\n", ret);
		kobject_put(&ci->kobj);
		return ret;
	}

	/* Now initialize the binary attribute file. */
	sysfs_bin_attr_init(&ci->battr);
	ci->battr.attr.name = genz_structure_name(hdr.type);
	ci->battr.attr.mode = 0400;
	ci->battr.size = ci->size;
	ci->battr.read =  read_control_structure;
	ci->battr.write = write_control_structure;
	ci->battr.private = ci; /* Revisit: is this used/needed? */

	ret = sysfs_create_bin_file(&ci->kobj, &ci->battr);
	if (ret) {
		/* Revisit: handle error */
		pr_debug("sysfs_create_bin_file failed with %d for file %s\n",
			 ret, ci->battr.attr.name);
		return ret;
	}
	/* Recursively traverse any pointers in this structure */
	ret = traverse_control_pointers(zbdev, rmri, ci,
					hdr.type, hdr.vers, con_dir);
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
			struct kobject *dir,
			const struct genz_control_structure_ptr *csp)
{
	int ret;
	struct genz_control_structure_header hdr;
	off_t hdr_offset;
	struct genz_control_info *ci;

	pr_debug("in traverse_structure\n");
	ret = read_and_validate_header(zbdev, rmri, parent->start, csp,
		&hdr, &hdr_offset);

	/* This pointer is NULL. Not an error.*/
	if (ret == ENOENT) {
		pr_debug("pointer is NULL. Not an error.\n");
		return 0;
	} else if (ret) {
		pr_debug("read_and_validate_header failed with %d\n", ret);
		return ret;
	}

	/* Allocate a genz_control_info with a kobject for this directory */
	ci = alloc_control_info(zbdev, &hdr, hdr_offset, parent);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}
	pr_debug("after alloc_control_info hdr_offset is 0x%lx ci->start is 0x%lx\n", hdr_offset, ci->start);

	/* Revisit: the directory is supposed to be the field name not the structure name. */
	pr_debug("calling kobject_init and kobject_add for %s\n", genz_structure_name(hdr.type));
	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, dir, "%s",
			genz_structure_name(hdr.type));
	if (ret < 0) {
		pr_debug("kobject_add failed with %d\n", ret);
		kobject_put(&ci->kobj);
		return ret;
	}

	/* Now initialize the binary attribute file. */
	sysfs_bin_attr_init(&ci->battr);
	ci->battr.attr.name = genz_structure_name(hdr.type);
	ci->battr.attr.mode = 0400;
	ci->battr.size = ci->size;
	ci->battr.read =  read_control_structure;
	ci->battr.write = write_control_structure;
	ci->battr.private = ci; /* Revisit: is this used/needed? */

	pr_debug("calling sysfs_create_bin_file %s\n", ci->battr.attr.name);
	ret = sysfs_create_bin_file(&ci->kobj, &ci->battr);
	if (ret) {
		/* Revisit: handle error */
		pr_debug("sysfs_create_bin_file failed with %d for file %s\n",
				ret, ci->battr.attr.name);
		return ret;
	}
	/* Recursively traverse any pointers in this structure */
	pr_debug("calling traverse_control_pointers for any pointers in struct %s\n", ci->battr.attr.name);
	ret = traverse_control_pointers(zbdev, rmri, ci,
		hdr.type, hdr.vers,
		&ci->kobj);
	if (ret < 0) {
		/* Revisit: handle error */
		pr_debug("traverse_control_pointers for %s failed with %d\n", ci->battr.attr.name, ret);
		return ret;
	}
	return 0;
}
#ifdef NOT_YET
static struct genz_control_info * create_chain_directory(
	const struct genz_control_structure_ptr *csp,
	struct genz_dev *zdev,
	struct genz_control_info *parent,
	struct genz_control_ptr_info *pi,
	struct kobject *dir)
{
	struct genz_control_info *ci;
	int ret;

	/* Allocate a genz_control_info with a kobject for this directory */
	ci = alloc_control_info(zdev, NULL, 0x0, zdev->root_control_info);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return NULL;
	}

	/* The chained directory is named for the structure name. */
	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, dir, "%s",
			genz_structure_name(csp->struct_type));
	if (ret < 0) {
		pr_debug("kobject_add failed with %d\n", ret);
		kobject_put(&ci->kobj);
		return NULL;
	}

	return ci;
}
#endif 

static int traverse_control_pointers(struct genz_bridge_dev *zbdev,
	struct genz_rmr_info *rmri,
	struct genz_control_info *parent,
	int struct_type,
	int struct_vers,
	struct kobject *dir)
{
	const struct genz_control_structure_ptr *csp, *csp_entry;
	int i, ret, num_ptrs;

	ret = get_control_ptr(zbdev, struct_type, struct_vers, &csp, &num_ptrs);
	if (ret < 0) {
		pr_debug("get_control_ptr failed with %d\n", ret);
		return ret;
	}
	for (i = 0; i < num_ptrs; i++) {
		csp_entry = &csp[i];
		switch (csp_entry->ptr_type) {
		case GENZ_CONTROL_POINTER_NONE:
			pr_debug("%s, ptr_type GENZ_CONTROL_POINTER_NONE\n",
				 csp_entry->ptr_name);
			break;
		case GENZ_CONTROL_POINTER_STRUCTURE:
			pr_debug("%s, ptr_type GENZ_CONTROL_POINTER_STRUCTURE\n",
				 csp_entry->ptr_name);
			if (is_head_of_chain(csp_entry)) {
				pr_debug("is_head_of_chain is true\n");
				ret = traverse_chained_control_pointers(
					zbdev, rmri, parent, dir,
					csp_entry, num_ptrs);
			} else {
				ret = traverse_structure(zbdev, rmri, parent,
							 dir, csp_entry);
			}
			break;
		case GENZ_CONTROL_POINTER_CHAINED:
			pr_debug("%s, skipping ptr_type GENZ_CONTROL_POINTER_CHAINED\n",
				 csp_entry->ptr_name);
			break;
		case GENZ_CONTROL_POINTER_ARRAY:
			pr_debug("%s, ptr_type GENZ_CONTROL_POINTER_ARRAY\n",
				 csp_entry->ptr_name);
			ret = traverse_table(zbdev, rmri, parent,
					     dir, csp_entry);
			break;
		case GENZ_CONTROL_POINTER_TABLE:
			pr_debug("%s, ptr_type GENZ_CONTROL_POINTER_TABLE\n",
				 csp_entry->ptr_name);
			if (is_head_of_chain(csp_entry)) {
				pr_debug("is_head_of_chain is true\n");
				ret = traverse_chained_control_pointers(
					zbdev, rmri, parent, dir,
					csp_entry, num_ptrs);
			} else {
				ret = traverse_table(zbdev, rmri, parent,
						     dir, csp_entry);
			}
			break;
		case GENZ_CONTROL_POINTER_TABLE_WITH_HEADER:
			pr_debug("%s, ptr_type GENZ_CONTROL_POINTER_TABLE_WITH_HEADER\n",
				 csp_entry->ptr_name);
			ret = traverse_table(zbdev, rmri, parent,
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

/**
 * genz_bridge_create_control_files() - read control space for a local bridge
 */
int genz_bridge_create_control_files(struct genz_bridge_dev *zbdev)
{
	int                 ret;
	struct genz_dev     *zdev = &zbdev->zdev;
	struct device       *bdev = zbdev->bridge_dev;
	char                bridgeN[MAX_GENZ_NAME];
	uint                fabric_num;
	struct kobject      *genz_dir;

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
	ret = sysfs_create_link(&zbdev->zdev.zcomp->subnet->fabric->dev.kobj,
			genz_dir, bridgeN);
	if (ret < 0) {
		pr_debug("unable to create %s symlink\n", bridgeN);
		goto err_kobj;
	}

	/* Make control directory under native device/genzN */
	zdev->root_control_info = alloc_control_info(zbdev, NULL, 0, NULL);
	/* Revisit: error handling */
	//zdev->root_control_info->kobj.kset = zbdev->genz_kset; /* Revisit */
	ret = kobject_init_and_add(
		&zdev->root_control_info->kobj,
		&control_info_ktype, genz_dir, "control");
	if (ret < 0) {
		pr_debug("unable to create bridge control directory\n");
		goto err_control;
	}

	/* Make gcid file under native device/genzN directory */
	ret = sysfs_create_file(genz_dir, &gcid_attribute.attr);
	if (ret < 0) {
		pr_debug("unable to create bridge gcid file\n");
		goto err_control;
	}

	/* Make cuuid file under native device/genzN directory */
	ret = sysfs_create_file(genz_dir, &cuuid_attribute.attr);
	if (ret < 0) {
		pr_debug("unable to create bridge cuuid file\n");
		goto err_control;
	}

	/* Populate native device/genzN/control directory */

#ifdef NOT_YET
	/* Read the GCID from control space to create subnet/component dirs */
	ret = genz_control_read_sid(zbdev, NULL, &sid);
	if (ret) {
		pr_debug("couldn't read sid for bridge\n");
		return -EINVAL;
	}
	f = zbdev->fabric;
	s = genz_add_subnet(sid, f);
	if (s == NULL) {
		pr_debug("genz_add_subnet failed\n");
		return -ENOMEM;
	}
	ret =  genz_control_read_cid0(zbdev, NULL, &cid);
	if (ret) {
		pr_debug("couldn't read cid for bridge\n");
		return -EINVAL;
	}
	zcomp = genz_add_component(s, cid);
	if (zcomp == NULL) {
		pr_debug("genz_add_component failed\n");
		return -ENOMEM;
	}
#endif

	/* Revisit: error handling */

	pr_debug("calling start_core_structure for the core structure\n");
	ret = start_core_structure(zbdev,
			zdev->root_control_info,
			&genz_struct_type_to_ptrs[GENZ_CORE_STRUCTURE],
			&zdev->root_control_info->kobj); /* control dir */
	return 0;

err_control:
	kobject_put(&zdev->root_control_info->kobj);
err_kobj:
err_genz_dir:
	kobject_put(genz_dir);
	return ret;
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
	struct kobject         *dir;

	dev_dbg(zbdev->bridge_dev, "entered\n");
#ifdef BROKEN
	/*
	 * The struct genz_control_infos are removed when the kobject
	 * release() is called.
	 */
	remove_all_ci(zbdev->genz_control_kset);
#endif
	/* remove the genzN/gcid file */
	sysfs_remove_file(&zbdev->genzN_dir, &gcid_attribute.attr);
	/* remove the symlink associated with this genzN directory */
	dir = &zbdev->zdev.zcomp->subnet->fabric->dev.kobj;
	snprintf(bridgeN, MAX_GENZ_NAME, "bridge%d", zbdev->bridge_num);
	dev_dbg(zbdev->bridge_dev, "removing %s symlink for kobj %s\n",
		bridgeN, dir->name);
	sysfs_remove_link(dir, bridgeN);
	/* remove the genzN directory */
	kobject_del(&zbdev->genzN_dir);
#ifdef BROKEN
	pr_debug("kset_unregister %s\n", kobject_name(&zbdev->genz_control_kset->kobj));
	kset_unregister(zbdev->genz_control_kset);
	kobject_put(&zbdev->genzN_dir); /* the genzN directory under PCI */
#endif
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
	ret = kobject_init_and_add(sid, &control_info_ktype, zdev->root_kobj,
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
	kobject_put(zdev->root_kobj);
	return ret;
}
#endif
