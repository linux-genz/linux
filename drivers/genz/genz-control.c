// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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
 * points to a type that has a chain. If this is the case, then
 * there is a sysfs directory created with that structure name and in
 * that directory, as set of directories for each element of the
 * chain starting at 0.
 */
int is_head_of_chain(const struct genz_control_structure_ptr *csp)
{
	enum genz_control_structure_type target_type;

	/*
	 * If we are in the midst of following a chain, this ptr_type
	 * will be GENZ_CONTROL_POINTER_CHAINED. Only the potental
	 * head of a chain has GENZ_CONTROL_POINTER_STRUCTURE.
	 */
	if (csp->ptr_type != GENZ_CONTROL_POINTER_STRUCTURE)
		return 0;

	/* Get the structure type that we need to see if chained. */
	target_type = csp->struct_type;

	/*
	 * The table indicates if this type is chained in the static
	 * genz_control_ptr_info structure. If it is chained then
	 * this must be the head of the chain.
	 */
	return genz_struct_type_to_ptrs[target_type].chained;
}

static int traverse_control_pointers(struct genz_dev *zdev,
	struct genz_control_info *parent,
	int struct_type,
	int struct_vers,
	struct kobject *dir);
/**
 * genz_valid_table_type - determines if a control table type is valid
 * Returns 1 when the control table type is valid
 * Returns 0 when the control table type is not valid
 */
int genz_valid_table_type(int type)
{
	if (type < GENZ_TABLE_ENUM_START ||
			type > (genz_table_type_to_ptrs_nelems+GENZ_TABLE_ENUM_START))
		return 0;
	return 1;
}

/**
 * genz_valid_struct_type - determines if a control structure type is valid
 * Returns 1 when the control structure type is valid
 * Returns 0 when the control structure type is not valid
 */
int genz_valid_struct_type(int type)
{
	if (type < 0 || type > genz_struct_type_to_ptrs_nelems)
		return 0;
	if (genz_struct_type_to_ptrs[type].ptr != NULL)
		return 1;
	else
		return 0;
}

/**
 * genz_table_name - return the name of a given control table ptr_type
 * int type - the control table type
 * Returns the name of a table type or NULL if the type is not vaild.
 */
static const char *genz_table_name(int type)
{
	pr_debug("type %d type-GENZ_TABLE_ENUM_START is %d\n", type, 
			(type-GENZ_TABLE_ENUM_START));
	if (!genz_valid_table_type(type)) {
		pr_debug("type %d is invalid\n", type);
		return "";
	}

	return genz_table_type_to_ptrs[(type-GENZ_TABLE_ENUM_START)].name;
}

/**
 * genz_structure_name - return the name of a given control structure ptr_type
 * int type - the control structure type
 * Returns the name of a structure type or NULL if the type is not vaild.
 */
static const char *genz_structure_name(int type)
{
	if (!genz_valid_struct_type(type))
		return "";

	return genz_struct_type_to_ptrs[type].name;
}

static void control_info_release(struct kobject *kobj)
{
	struct genz_control_info *ci;

	ci = to_genz_control_info(kobj);
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
		struct genz_dev **zdev,
		struct genz_bridge_dev **bridge_zdev)
{
	struct genz_bridge_driver *zdriver;

	*zdev = ci->zdev;
	if (ci->zdev == NULL) {
		pr_debug("genz_control_info has NULL zdev\n");
		return -EINVAL;
	}
	*bridge_zdev = (*zdev)->zbdev;
	if (*bridge_zdev == NULL) {
		pr_debug("bridge_zdev is NULL\n");
		return -EINVAL;
	}
	zdriver = (*bridge_zdev)->zbdrv;
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
	struct genz_control_info *ci;
	struct genz_dev *zdev;
	struct genz_bridge_dev *bridge_zdev;
	ssize_t ret = 0;
	int err;

	ci = to_genz_control_info(kobj);
	err = validate_ci(ci, offset, size, data, &zdev, &bridge_zdev);
	if (err < 0) {
		pr_debug("arguments invalid error: %d\n", err);
		/* Revisit: what should it return on error? */
		return err;
	}
	pr_debug("reading structure %s at offset 0x%llx size 0x%lx ci->start 0x%lx ci->size 0x%lx\n", kobj->name, offset, size, ci->start, ci->size);

	ret = bridge_zdev->zbdrv->control_read(zdev, ci->start+offset,
				       size,
				       (void *)data, 0);
	if (ret) {
		pr_debug("control read failed with %ld\n", ret);
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
	struct genz_control_info *ci;
	struct genz_dev *zdev;
	struct genz_bridge_dev *bridge_zdev;
	ssize_t ret = 0;
	int err;

	ci = to_genz_control_info(kobj);
	err = validate_ci(ci, offset, size, data, &zdev, &bridge_zdev);
	if (err < 0) {
		pr_debug("arguments invalid error: %d\n", err);
		return err;
	}
	ret = bridge_zdev->zbdrv->control_write(zdev, ci->start+offset,
						size, (void *)data, 0);
	if (ret) {
		pr_debug("control write failed with %ld\n", ret);
		return ret;
	}
	return size;
}

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
	char bridgeN[10];
	struct genz_bridge_dev *zbdev;
	struct device *bdev;

	/* remove the symlink associated with this genN directory */
	if (kobj == NULL) {
		pr_debug("NULL kobj\n");
		return;
	}
	bdev = kobj_to_dev(kobj->parent);
	if (bdev == NULL) {
		pr_debug("failed to find bdev from kobject parent\n");
		return;
	}
	zbdev = to_zbdev(&bdev); 
	if (zbdev == NULL) {
		pr_debug("conversion from kobj to zbdev failed\n");
		return;
	}
	snprintf(bridgeN, 10, "bridge%d", zbdev->bridge_num);
	sysfs_remove_link(kobj, bridgeN);
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

	/* Check that the type matches expected core structre type 0 */
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
	if (!genz_validate_control_space_structure_type(ptr_type)) {
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

static int read_header_at_offset(struct genz_dev *zdev,
			off_t start,
			enum genz_pointer_size psize,
			off_t offset,
			struct genz_control_structure_header *hdr,
			off_t *hdr_offset)
{
	int ret;

	pr_debug("in read_header_at_offset offset 0x%lx\n", start+offset);
	*hdr_offset = 0;
	/* Read the given offset to get the pointer to the control structure */
	ret = zdev->zbdev->zbdrv->control_read(zdev, start+offset,
				(int)psize, (void *)hdr_offset, 0);
	if (ret) {
		pr_debug("control read of pointer failed with %d\n", ret);
		return ret;
	}

	pr_debug("found the pointer is 0x%lx\n", *hdr_offset);
	
	/* It is ok for many fields to be NULL. Everything is optional. */
	if (*hdr_offset == 0) {
		pr_debug("pointer field at 0x%lx is NULL\n", start+offset);
		return ENOENT;
	}

	/* Shift the offset a byte to get the address */
	*hdr_offset = (*hdr_offset) << 4;

	/* Read a control structure header at that pointer location */
	pr_debug("reading the header from the pointer offset 0x%lx, size = 0x%lx\n", *hdr_offset, sizeof(struct genz_control_structure_header));
	ret = zdev->zbdev->zbdrv->control_read(zdev, *hdr_offset,
		sizeof(struct genz_control_structure_header), (void *)hdr, 0);
	if (ret) {
		pr_debug("control read of header structure offset failed with %d\n",
			ret);
		return ret;
	}
	pr_debug("hdr->type %d, hdr->vers %d, hdr->size 0x%x\n", 
				hdr->type, hdr->vers, hdr->size);
	return ret;
}

static int read_and_validate_header(struct genz_dev *zdev,
			off_t start,
			const struct genz_control_structure_ptr *csp,
			struct genz_control_structure_header *hdr,
			off_t *hdr_offset)
{
	int ret = 0;
	uint8_t expected_vers;

	ret = read_header_at_offset(zdev, start, csp->ptr_size,
				csp->pointer_offset, hdr, hdr_offset);

	/* This pointer is NULL. Not an error.*/
	if (ret == ENOENT) {
		pr_debug("read_header_at_offset returned ENOENT\n");
		return ENOENT;
	} else if (ret) {
		pr_debug("read_header_at_offset returned %d\n", ret);
		return ret;
	}

	/* Validate the header is as expected */
	if (hdr->type != csp->struct_type) {
		pr_debug("expected type %d but found %d\n",
			csp->struct_type, hdr->type);
		return -EINVAL;
	}
	/*  Validate the structure size.
	 *  Revisit: Could get the structure from the type and then
	 *  compare to the sizeof(struct...). Would need to be version
	 *  aware. Could have ptr_type that say it is fixed size or
	 *  variable size minimum.
	 */
	if (hdr->size == 0) {
		pr_debug("structure size is 0.\n");
		return -EINVAL;
	}
	/* Validate the version. */
	expected_vers = genz_struct_type_to_ptrs[hdr->type].vers;
	if (hdr->vers != expected_vers) {
		pr_debug("structure version mismatch expected %d but found %d.\n", expected_vers, hdr->vers);
		/* Revisit: don't fail on version mismatch because of quirks */
	}
	else {
		pr_debug("versions match: hdr->vers is %d\n", hdr->vers);
	}
	return 0;
}

static struct genz_control_info *alloc_control_info(struct genz_dev *zdev,
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

	ci->zdev = zdev;
	ci->start = offset;
	if (hdr) { /* root control dir and chained dirs have no header. */
		ci->type = hdr->type;
		ci->vers = hdr->vers;
		ci->size = hdr->size * GENZ_CONTROL_SIZE_UNIT;
	}
	ci->parent = parent;

	/* The kobject is associated with the control kset for cleanup */
	ci->kobj.kset = zdev->zbdev->genz_control_kset;

	/* Revisit: fill out remaining fields.
	 * ci->c_access_res =;
	 * ci->zmmu = ;
	 */

	return ci;
}

static int traverse_array(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct kobject *struct_dir,
			const struct genz_control_structure_ptr *csp)
{
	struct genz_control_info *ci;
	int ret = 0;
	uint32_t table_ptr;

	/* Read the pointer to this array */
	ret = zdev->zbdev->zbdrv->control_read(zdev,
			parent->start+csp->pointer_offset,
			(int)csp->ptr_size, (void *)&table_ptr, 0);
	if (ret) {
		pr_debug("control_read failed with %d\n", ret);
		return ret;
	}

	/* This pointer is NULL. Not an error.*/
	if (table_ptr == 0)
		return 0;

	/* Allocate a genz_control_info/kobject for this directory */
	ci = alloc_control_info(zdev, NULL, csp->pointer_offset, parent);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}
	ci->type = csp->struct_type;
	ci->size = (*csp->size_fn)(ci->parent);

	pr_debug("table type 0x%x size 0x%lx name %s\n", ci->type, ci->size, genz_table_name(ci->type));

	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, struct_dir, "%s",
				genz_table_name(ci->type));
	if (ret < 0) {
		kobject_put(&ci->kobj);
		kfree(ci);
		return ret;
	}

	/* Now initialize the binary attribute file. */
	sysfs_bin_attr_init(&ci->battr);
	ci->battr.attr.name = genz_table_name(ci->type);
	ci->battr.attr.mode = 0400;
	ci->battr.size = ci->size;
	ci->battr.read =  read_control_structure;
	ci->battr.write = write_control_structure;
	ci->battr.private = ci; /* Used to indicate valid battr */

	ret = sysfs_create_bin_file(&ci->kobj, &ci->battr);
	return 0;
}

static int traverse_table(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct kobject *dir,
			const struct genz_control_structure_ptr *csp)
{
	pr_debug("Revisit: implement traverse_table\n");
	return 0;
}

static int traverse_table_with_header(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct kobject *dir,
			const struct genz_control_structure_ptr *csp)
{
	int ret;
	struct genz_control_structure_header hdr;
	off_t hdr_offset;
	struct genz_control_info *ci;

	pr_debug("in traverse_table_with_header\n");
	ret = read_and_validate_header(zdev, parent->start, csp,
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
	ci = alloc_control_info(zdev, &hdr, hdr_offset, parent);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}

	/* Revisit: the directory is supposed to be the field name not the structure name. */
	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, dir, "%s",
			genz_structure_name(hdr.type));
	if (ret < 0) {
		pr_debug("kobject_add failed with %d\n", ret);
		kobject_put(&ci->kobj);
		kfree(ci);
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
	ret = traverse_control_pointers(zdev, ci,
		hdr.type, hdr.vers,
		&ci->kobj);
	if (ret < 0) {
		/* Revisit: handle error */
		pr_debug("traverse_control_poitners for %s failed with %d\n", ci->battr.attr.name, ret);
		return ret;
	}
	return 0;
}

#ifdef NOT_YET
static int type_is_chained(int type)
{
	const struct genz_control_structure_ptr *csp;
	size_t num_ptrs;
	int i;

	csp = genz_control_structure_type_to_ptrs[type].ptr;
	num_ptrs = genz_control_structure_type_to_ptrs[type].num_ptrs;
	for (i = 0; i < num_ptrs; i++) {
		if (csp[i].type == GENZ_CONTROL_POINTER_CHAINED)
			return 1;
	}
	return 0;
}
#endif

static int get_control_structure_ptr(
		struct genz_dev *zdev,
		int struct_type,
		int struct_vers,
		const struct genz_control_structure_ptr **csp,
		int *num_ptrs)
{
	int ret;

	if (genz_struct_type_to_ptrs[struct_type].vers == struct_vers) {
		*csp = genz_struct_type_to_ptrs[struct_type].ptr;
		*num_ptrs = genz_struct_type_to_ptrs[struct_type].num_ptrs;
		pr_debug("found in subsystem genz_struct_type_to_ptrs\n");
		return 0;
	}
	if (!zdev)
		return -EINVAL;
	if (!zdev->zbdev)
		return -EINVAL;
	if (!zdev->zbdev->zbdrv)
		return -EINVAL;
	if (!zdev->zbdev->zbdrv->control_structure_pointers)
		return -EINVAL;
	ret = zdev->zbdev->zbdrv->control_structure_pointers(struct_vers,
			struct_type,
			csp,
			num_ptrs);
	return ret;
}

/*
 * Search the list of pointers for this structure to find the
 * one marked "CHAINED". That is the offset for the next pointer
 * in the list. Complain if it is not found or more than one is
 * found.
 */
static off_t find_chain_offset(struct genz_dev *zdev,
	struct genz_control_structure_header *hdr,
	const struct genz_control_structure_ptr **chain_csp)
{
	int chain_offset = -ENOENT;
	int i;
	int num_ptrs;
	int ret = 0;
	const struct genz_control_structure_ptr *csp;

	ret = get_control_structure_ptr(zdev, hdr->type, hdr->vers,
			&csp, &num_ptrs);
	if (ret) {
		pr_debug("failed to get control_structure_ptr for type %d\n",
				hdr->type);
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
static int traverse_chained_control_pointers(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct kobject *dir,
			const struct genz_control_structure_ptr *csp,
			int num_ptrs)
{
	int chain_num = 0;
	struct genz_control_structure_header hdr;
	off_t hdr_offset;
	int chain_offset = -1;
	int done = 0;
	struct genz_control_info *struct_dir;
	int ret;
	struct genz_control_info *ci;
	const struct genz_control_structure_ptr *chain_csp;

	/*
	 * Read the first pointer in the chain to make sure there is
	 * one before creating the directory to contain the chained structures.
	 */
	ret = read_and_validate_header(zdev, parent->start, csp,
		&hdr, &hdr_offset);

	/* This pointer is NULL. Not an error - just nothing to follow. */
	if (ret == ENOENT)
		return 0;

	/* Find the offset for the chained field in this structure type. */
	chain_offset = find_chain_offset(zdev, &hdr, &chain_csp);
	if (chain_offset < 0) {
		pr_debug("could not find the chain pointer\n");
		return (int)chain_offset;
	}

	/* Create the container directory for all the chained structures */
	if (dir == NULL) {
		struct_dir = alloc_control_info(zdev, &hdr, hdr_offset,
				zdev->root_control_info);
		if (struct_dir == NULL) {
			pr_debug("failed to allocate control_info\n");
			return -ENOMEM;
		}

		kobject_init(&struct_dir->kobj, &control_info_ktype);
		ret = kobject_add(&struct_dir->kobj,
				&zdev->zbdev->genz_control_kset->kobj, "%s",
				genz_structure_name(hdr.type));
		if (ret < 0) {
			kobject_put(&struct_dir->kobj);
			kfree(struct_dir);
			return ret;
		}
		dir = &struct_dir->kobj;
	}
	else {
		struct_dir = to_genz_control_info(dir);
	}

	while (!done) {
		/* Allocate a genz_control_info/kobject for this directory */
		ci = alloc_control_info(zdev, &hdr, hdr_offset, struct_dir);
		if (ci == NULL) {
			pr_debug("failed to allocate control_info\n");
			return -ENOMEM;
		}

		kobject_init(&ci->kobj, &control_info_ktype);
		ret = kobject_add(&ci->kobj, dir, "%s%d",
				genz_structure_name(hdr.type), chain_num++);
		if (ret < 0) {
			kobject_put(&ci->kobj);
			kfree(ci);
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
		/*
		 * Now traverse all of the pointers in the structure. The
		 * chain pointer will be skipped here and handled here in
		 * this while loop.
		 */
		ret = traverse_control_pointers(zdev, ci,
			hdr.type, hdr.vers,
			&ci->kobj);
		if (ret < 0) {
			/* Handle error! */
			return ret;
		}

		/* Follow chain pointer to read the next control struct */
		ret = read_and_validate_header(zdev, hdr_offset,
			chain_csp, &hdr, &hdr_offset);

		/* The pointer is NULL- this is the end of the list */
		if (ret == ENOENT)
			done = 1;
	}
	return ret;
}

extern struct genz_control_structure_ptr *base_structure_ptr;

static int start_core_structure(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct genz_control_ptr_info *pi,
			struct kobject *dir)
{
	int ret;
	struct genz_control_structure_header hdr;
	struct genz_control_info *ci;
	const struct genz_control_structure_ptr *csp;
	uint8_t expected_vers;

	csp = base_structure_ptr;

	ret = zdev->zbdev->zbdrv->control_read(zdev, 0x0,
				sizeof(struct genz_control_structure_header),
				(void *)&hdr, 0);
	if (ret) {
		pr_debug("control read of pointer failed with %d\n", ret);
		return ret;
	}

	/* Validate the header is as expected */
	if (hdr.type != GENZ_CORE_STRUCTURE) {
		pr_debug("expected type 0 but found %d\n", hdr.type);
		return -EINVAL;
	}
	/*  Validate the structure size.
	 *  Revisit: Could get the structure from the type and then
	 *  compare to the sizeof(struct...). Would need to be version
	 *  aware. Could have ptr_type that say it is fixed size or
	 *  variable size minimum.
	 */
	if (hdr.size == 0) {
		pr_debug("structure size is 0.\n");
		return -EINVAL;
	}
	/* Validate the version. */
	expected_vers = 1;
	if (hdr.vers != expected_vers) {
		pr_debug("structure version mismatch expected %d but found %d.\n", expected_vers, hdr.vers);
		return -EINVAL;
	}

	/* Allocate a genz_control_info with a kobject for this directory */
	ci = alloc_control_info(zdev, &hdr, 0x0, parent);
	if (ci == NULL) {
		pr_debug("failed to allocate control_info\n");
		return -ENOMEM;
	}

	/* Revisit: the directory is supposed to be the field name not the structure name. */
	if (zdev == NULL) {
		pr_debug("zdev is NULL\n");
		return -1;
	}
	if (zdev->zbdev == NULL) {
		pr_debug("zdev->zbdev is NULL\n");
		return -1;
	}
	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, dir, "%s",
			genz_structure_name(hdr.type));
	if (ret < 0) {
		pr_debug("kobject_add failed with %d\n", ret);
		kobject_put(&ci->kobj);
		kfree(ci);
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
	ret = traverse_control_pointers(zdev, ci,
		hdr.type, hdr.vers,
		dir);
	if (ret < 0) {
		/* Revisit: handle error */
		pr_debug("traverse_control_poitners for %s failed with %d\n", ci->battr.attr.name, ret);
		return ret;
	}
	return 0;
}

static int traverse_structure(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct kobject *dir,
			const struct genz_control_structure_ptr *csp)
{
	int ret;
	struct genz_control_structure_header hdr;
	off_t hdr_offset;
	struct genz_control_info *ci;

	pr_debug("in traverse_structure\n");
	ret = read_and_validate_header(zdev, parent->start, csp,
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
	ci = alloc_control_info(zdev, &hdr, hdr_offset, parent);
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
		kfree(ci);
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
	ret = traverse_control_pointers(zdev, ci,
		hdr.type, hdr.vers,
		&ci->kobj);
	if (ret < 0) {
		/* Revisit: handle error */
		pr_debug("traverse_control_poitners for %s failed with %d\n", ci->battr.attr.name, ret);
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
		kfree(ci);
		return NULL;
	}

	return ci;
}
#endif 

static int traverse_control_pointers(struct genz_dev *zdev,
	struct genz_control_info *parent,
	int struct_type,
	int struct_vers,
	struct kobject *dir)
{
	int i;
	int ret = 0;
	const struct genz_control_structure_ptr *csp, *csp_entry;
	int num_ptrs;

	ret = get_control_structure_ptr(zdev, struct_type, struct_vers,
				&csp, &num_ptrs);
	if (ret) {
		pr_debug("get_control_structure_prt failed with %d\n", ret);
		return ret;
	}
	pr_debug("in traverse_control_pointers for struct type %d\n", struct_type);
	for (i = 0; i < num_ptrs; i++) {
		csp_entry = &csp[i];
		switch (csp_entry->ptr_type) {
		case GENZ_CONTROL_POINTER_NONE:
			pr_debug("ptr_type GENZ_CONTROL_POINTER_NONE\n");
			break;
		case GENZ_CONTROL_POINTER_STRUCTURE:
			pr_debug("ptr_type GENZ_CONTROL_POINTER_STRUCTURE\n");
			if (is_head_of_chain(csp_entry)) {
				pr_debug("actually it is ptr_type GENZ_CONTROL_POINTER_CHAINED\n");
				/* passing NULL dir indicates start of chain */
				ret = traverse_chained_control_pointers(zdev,
					parent, NULL, csp_entry, num_ptrs);
				break;
			}
			ret = traverse_structure(zdev, parent,
				dir, csp_entry);
			break;
		case GENZ_CONTROL_POINTER_CHAINED:
			pr_debug("skipping ptr_type GENZ_CONTROL_POINTER_CHAINED\n");
			/*
			ret = traverse_chained_control_pointers(zdev,
				parent, pi, dir, csp_entry, num_ptrs);
			*/
			break;
		case GENZ_CONTROL_POINTER_ARRAY:
			pr_debug("ptr_type GENZ_CONTROL_POINTER_ARRAY\n");
			ret = traverse_array(zdev, parent, dir, csp_entry);
			break;
		case GENZ_CONTROL_POINTER_TABLE:
			pr_debug("ptr_type GENZ_CONTROL_POINTER_TABLE\n");
			ret = traverse_table(zdev, parent,
				dir, csp_entry);
			break;
		case GENZ_CONTROL_POINTER_TABLE_WITH_HEADER:
			pr_debug("ptr_type GENZ_CONTROL_POINTER_TABLE_WITH_HEADER\n");
			ret = traverse_table_with_header(zdev, parent,
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

	/* Revisit: validate stype */
	sbytes = genz_struct_type_to_ptrs[stype].struct_bytes;
	if (!sbytes)
		return NULL;

	buf = kzalloc(sbytes, flags);
	return buf;
}

int genz_control_read_structure(struct genz_dev *zdev,
		void *buf, off_t cs_offset,
		off_t field_offset, size_t field_size)
{
	int ret;
	struct genz_bridge_dev *zbdev;
	struct genz_bridge_driver *zbdrv;

	if (zdev == NULL) {
		pr_debug("zdev is NULL\n");
		return -EINVAL;
	}
	zbdev = zdev->zbdev;
	if (!zdev_is_local_bridge(zdev)) {
		pr_debug("zbdev not a bridge\n");
		return -EINVAL;
	}
	zbdrv = zbdev->zbdrv;
	if (zbdrv == NULL) {
		pr_debug("zbdrv is NULL\n");
		return -EINVAL;
	}
	if (zbdrv->control_read == NULL) {
		pr_debug("missing control_read()\n");
		return -EINVAL;
	}
	if (buf == NULL) {
		pr_debug("buf is NULL\n");
		return -EINVAL;
	}
	if (field_size == 0) {
		pr_debug("field_size is 0\n");
		return -EINVAL;
	}
	ret = zbdrv->control_read(zdev, cs_offset+field_offset, field_size, buf, 0);
	if (ret) {
		pr_debug("control read failed with %d\n", ret);
		return ret;
	}

	return 0;
}

int genz_control_read_cid0(struct genz_dev *zdev, uint16_t *cid0)
{
	int ret;
	uint32_t buf;

	/*
	 * CID0 is 16 bits in the middle of a word. The word starts
	 * with the CV field. So read 32 bits and mask off the CID0
	 */
	ret = genz_control_read_structure(zdev, &buf, 0,
			0xC0, /* Revisit: how to get offsets better */
			sizeof(buf));
	if (ret)
		return ret;
	*cid0 = ((buf >> 8) & 0xFFF);
	pr_debug("0x%x\n", *cid0);
	return ret;
}

int genz_control_read_sid(struct genz_dev *zdev, uint16_t *sid)
{
	int ret;

	ret = genz_control_read_structure(zdev, sid, 0,
			0xB8, /* Revisit: how to get offsets better */
			sizeof(*sid));
	pr_debug("0x%x\n", *sid);
	return ret;
}

int genz_control_read_cclass(struct genz_dev *zdev, uint16_t *cclass)
{
	int ret;

	ret = genz_control_read_structure(zdev, cclass, 0,
			0x18, /* Revisit: how to get offsets better */
			sizeof(*cclass));
	pr_debug("0x%x\n", *cclass);
	return ret;
}

int genz_control_read_fru_uuid(struct genz_dev *zdev, uuid_t *fru_uuid)
{
	int ret;

	ret = genz_control_read_structure(zdev, fru_uuid, 0,
			0x1F0, /* Revisit: how to get offsets better */
			sizeof(*fru_uuid));
	pr_debug("%pUb\n", fru_uuid);
	return ret;
}

int genz_control_read_c_uuid(struct genz_dev *zdev, uuid_t *c_uuid)
{
	int ret;

	ret = genz_control_read_structure(zdev, c_uuid, 0,
			0x1E0, /* Revisit: how to get offsets better */
			sizeof(*c_uuid));
	pr_debug("%pUb\n", c_uuid);
	return ret;
}


/**
 * genz_bridge_create_control_files() - read control space for a local bridge
 */
#define MAX_GENZ_NAME	16
int genz_bridge_create_control_files(struct genz_bridge_dev *zbdev)
{
	int ret;
	struct genz_dev *zdev;
	struct device *dev;
	char bridgeN[10];
	struct kobject *genz_dir;

	dev = zbdev->bridge_dev;
	zdev = &zbdev->zdev;
	/* Make the genzN directory under the native device */
	genz_dir = &zbdev->genzN_dir;
	ret = kobject_init_and_add(genz_dir, &genz_dir_ktype, &dev->kobj,
			"genz%d", zbdev->fabric->number);
	/*
	snprintf(genzN, 10, "genz%d", zbdev->fabric->number);
	zbdev->genz_kset = kset_create_and_add(genzN, NULL, &dev->kobj);
	if (zbdev->genz_kset < 0)
		goto err_kset;
	*/
	/* Create a symlink from genzN to /sys/devices/genzN/bridgeN */
	snprintf(bridgeN, 10, "bridge%d", zbdev->bridge_num);
	/* Revisit: check all those pointers are not NULL */
	ret = sysfs_create_link(&zbdev->zdev.zcomp->subnet->fabric->dev.kobj,
			genz_dir, bridgeN);
	if (ret < 0) {
		pr_debug("unable to create bridgeN symlink \n");
		goto err_kobj;
	}

	/* Make control directory under native device/genzN */
	zbdev->genz_control_kset = kset_create_and_add("control",
			NULL, genz_dir);
	if (zbdev->genz_control_kset < 0)
		goto err_kset;
	/*
	zdev->root_control_info = alloc_control_info(zdev, NULL, 0, NULL);
	zdev->root_control_info->kobj.kset = zbdev->genz_kset;
	ret = kobject_init_and_add(
			&zdev->root_control_info->kobj,
			&control_info_ktype, &zbdev->genz_kset->kobj, "control");

	if (ret < 0) {
		pr_debug("unable to create bridge control directory\n");
		goto err_kobj;
	}
	*/

	/* Make gcid file under native device/genzN directory */
	ret = sysfs_create_file(genz_dir, &gcid_attribute.attr);
	if (ret < 0) {
		pr_debug("unable to create bridge gcid file\n");
		goto err_kobj;
	}

	/* Populate native deivce/genzN/control directory */

	/* Read the core header at offset 0 of control space */
#ifdef NOT_YET
	ret = genz_control_read_structure(zdev, &hdr, 0, 0,
			sizeof(hdr));
	if (ret) {
		pr_debug("failed to read core control structure header %d\n",
			 ret);
		return ret;
	}

	cpi = &genz_struct_type_to_ptrs[GENZ_CORE_STRUCTURE];

	/* Validate this is the expected structure type */
	if (hdr.type != GENZ_CORE_STRUCTURE) {
		pr_debug("control_read of structure %s header is not expected type: %d expected %d\n",
			 cpi->name, hdr.type, GENZ_CORE_STRUCTURE);
		return -EINVAL;
	}

	/* Validate the structure size */
	if (hdr.size * GENZ_CONTROL_SIZE_UNIT != cpi->struct_bytes) {
		pr_debug("control_read of structure %s header is not expected size: %d expected %ld\n",
			 cpi->name, hdr.size, cpi->struct_bytes);
		return -EINVAL;
	}

	/* Validate the version */
	if (hdr.vers != cpi->vers) {
		pr_debug("control_read of structure %s version mismatch expected %d but found %d.\n",
			 cpi->name, cpi->vers, hdr.vers);
		return -EINVAL;
	}

	/* Read the GCID from control space to create subnet/component dirs */
	ret = genz_control_read_sid(zdev, &sid);
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
	ret =  genz_control_read_cid0(zdev, &cid);
	if (ret) {
		pr_debug("couldn't read cid for bridge\n");
		return -EINVAL;
	}
	zcomp = genz_add_component(s, cid);
	if (zcomp == NULL) {
		pr_debug("genz_add_component failed\n");
		return -ENOMEM;
	}

	/* Read C-Class from control space */
	ret =  genz_control_read_cclass(zdev, &cclass);
	if (ret) {
		pr_debug("couldn't read cclass for bridge\n");
		return -EINVAL;
	}
	zcomp->cclass = cclass;
	/* Read the FRU_UUID from control space */
	ret =  genz_control_read_fru_uuid(zdev, &zcomp->fru_uuid);
	if (ret) {
		pr_debug("couldn't read fru_uuid for bridge\n");
		return -EINVAL;
	}
	/* Read the C_UUID from control space */
	ret =  genz_control_read_c_uuid(zdev, &zdev->class_uuid);
	if (ret) {
		pr_debug("couldn't read class_uuid for bridge\n");
		return -EINVAL;
	}
	/* Make a control memory region for the bridge's control space */
	if (zdev == NULL) {
		pr_debug("zdev is NULL before genz_alloc_and_add_zres\n");
		return -EINVAL;
	}
	zres = genz_alloc_and_add_zres(zdev);
	if (zres == NULL) {
		pr_debug("genz_alloc_and_add_zres returned NULL\n");
		return -EINVAL;
	}
	zres->zres.res.start = 0;
	zres->zres.res.end = 4096; /* Revisit: What is the size of control space? */
	zres->zres.res.flags = IORESOURCE_GENZ_CONTROL;
	zres->zres.res.desc = IORESOURCE_GENZ_CONTROL;
	pr_debug("calling genz_setup_zres returned NULL\n");
	ret = genz_setup_zres(zres, zdev, GENZ_CONTROL,
			      (zres->zres.res.flags | IORESOURCE_GENZ_CONTROL),
			      GENZ_CONTROL_STR_LEN,
			      "control%d",
			      &zdev->zres_list);
	if (ret) {
		pr_debug("genz_setup_zres failed with %d\n", ret);
		return ret;
	}
	ret = genz_create_attr(zdev, zres);
	if (ret) {
		pr_debug("genz_create_attr failed with %d\n", ret);
		return ret;
	}
#endif

	/* Revisit: error handling */

	pr_debug("calling start_core_structure for the core structure\n");
	ret = start_core_structure(zdev,
			zdev->root_control_info,
			&genz_struct_type_to_ptrs[0], /* 0 for Core */
			&zbdev->genz_control_kset->kobj); /* control dir */
	return 0;
err_kobj:
err_kset:
	return ret;
}

static void remove_all_ci(struct kset *kset)
{
	struct kobject *kobj, *ktmp;
	struct list_head *klist;
	struct kobject *first = NULL;

	pr_debug("doing kobject_put on all objects in kest %s\n", kobject_name(&kset->kobj));
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

/**
 * genz_bridge_remove_control_files() - remove sysfs files for a local bridge
 */
int genz_bridge_remove_control_files(struct genz_bridge_dev *zbdev)
{
	dev_dbg(zbdev->bridge_dev, "genz_bridge_remove_control_files");
	/*
	 * The struct genz_control_infos are removed when the kobject
	 * release() is called.
	 */
	remove_all_ci(zbdev->genz_control_kset);
	/* remove the genzN/gcid file */
	sysfs_remove_file(&zbdev->genzN_dir, &gcid_attribute.attr);
	/*
	kobject_put(&zbdev->genzN_dir);
	*/
	pr_debug("kset_unregister %s\n", kobject_name(&zbdev->genz_control_kset->kobj));
	kset_unregister(zbdev->genz_control_kset);
	kobject_put(&zbdev->genzN_dir); /* the genzN directory under PCI */
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
			"%04d", genz_get_sid(zdev->zcomp->gcid));
	if (ret < 0)
		goto err_sid;

	/* Next parse the gcid to get the CID for the next directory */
	cid = kobject_create();
	if (cid == NULL)
		goto err_sid;
	ret = kobject_init_and_add(cid, &control_info_ktype, sid,
			"%03d", genz_get_cid(zdev->zcomp->gcid));
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
