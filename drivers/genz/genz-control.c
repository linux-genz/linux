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


static ssize_t mgr_uuid_show(struct genz_fabric *fab,
		struct genz_fabric_attribute *attr,
		char *buf)
{
	printk(KERN_ERR "fab is %px\n", fab);

	if (fab == NULL) {
		printk(KERN_ERR "fab is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad fabric\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%pUb\n", &fab->mgr_uuid));
}

static struct genz_fabric_attribute mgr_uuid_attribute =
	__ATTR(mgr_uuid, (S_IRUGO), mgr_uuid_show, NULL);

int genz_create_mgr_uuid_file(struct kobject *kobj)
{
	int ret = 0;

	printk(KERN_ERR "%s: create_file for kobj %px\n", __func__, kobj);
	ret = sysfs_create_file(kobj, &mgr_uuid_attribute.attr);
	return ret;
}

static ssize_t sid_show(struct genz_subnet *s,
		struct genz_subnet_attribute *attr,
		char *buf)
{
	printk(KERN_ERR "subnet is %px\n", s);

	if (s == NULL) {
		printk(KERN_ERR "s is NULL\n");
		return(snprintf(buf, PAGE_SIZE, "bad subnet\n"));
	}
	return(snprintf(buf, PAGE_SIZE, "%04x\n", s->sid));
}

static struct genz_subnet_attribute sid_attribute =
	__ATTR(sid, (S_IRUGO), sid_show, NULL);

int genz_create_sid_file(struct genz_subnet *s)
{
	int ret = 0;

	printk(KERN_ERR "%s: create_file for kobj %px\n", __func__, &s->kobj);
	ret = sysfs_create_file(&s->kobj, &sid_attribute.attr);
	return ret;
}

static int traverse_control_pointers(struct genz_dev *zdev,
	struct genz_control_info *parent,
	struct genz_control_ptr_info *pi,
	struct kobject *dir);
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
 * genz_structure_name - return the name of a given control structure ptr_type
 * int type - the control structure type
 * Returns the name of a structure type or NULL if the type is not vaild.
 */
static const char * genz_structure_name(int type)
{
	if (!genz_valid_struct_type(type))
		return "";
		
	return(genz_struct_type_to_ptrs[type].name);
}

static void control_info_release(struct kobject *kobj)
{
	struct genz_control_info *info;

	info = to_genz_control_info(kobj);
	kfree(info);
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
		char * data,
		struct genz_dev **zdev,
		struct genz_bridge_dev **bridge_zdev)
{
	struct genz_bridge_driver *zdriver;

	*zdev = ci->zdev;
	if (ci->zdev == NULL) {
		pr_debug("%s: genz_control_info has NULL zdev\n", __func__);
		return -EINVAL;
	}
	*bridge_zdev = (*zdev)->zbdev;
	if (*bridge_zdev == NULL) {
		pr_debug("%s: bridge_zdev is NULL\n", __func__);
		return -EINVAL;
	} 
	zdriver = (*bridge_zdev)->zbdrv;
	if (zdriver == NULL) {
		pr_debug("%s: zdriver is NULL\n", __func__);
		return -EINVAL;
	} 
	if (zdriver->control_read == NULL) {
		pr_debug("%s: zdriver has NULL control_read function\n", __func__);
		return -EINVAL;
	}
	if (offset > ci->size) {
		pr_debug("%s: requested offset (%lld) is outside control structure size (%ld)\n", __func__, offset, ci->size);
		return -EINVAL;
	}
	if (offset+size > ci->size) {
		pr_debug("%s: requested offset+size (%lld + %ld) is outside control structure size (%ld)\n", __func__, offset, size, ci->size);
		return -EINVAL;
	}
	if (data == NULL) {
		pr_debug("%s: data pointer is NULL\n", __func__);
		return -EINVAL;
	}
	return(0);
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
		pr_debug("%s: arguments invalid error: %d\n", __func__, err);
		/* Revisit: what should it return on error? */
		return err;
	}
	ret = bridge_zdev->zbdrv->control_read(zdev, ci->start+offset,
			(int)size, (void *)data, 0);
	if (ret) {
		pr_debug("%s: control read failed with %ld\n",
			__func__, ret);
		return ret;
	}
	return ret;
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
		pr_debug("%s: arguments invalid error: %d\n", __func__, err);
		return err;
	}
	ret = bridge_zdev->zbdrv->control_write(zdev, ci->start+offset,
			(int)size, (void *)data, 0);
	if (ret) {
		pr_debug("%s: control write failed with %ld\n",
			__func__, ret);
		return ret;
	}
	return 0;
}

/*
 * genz_create_control_hierarchy - 
 *  Start with reading the control space a offset 0 to find the core
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

#ifdef NOT_YET

/*
 * genz_create_control_chain_siblings
 *  A control structure can have a linked list of the same structure. We call this
 *  a chain. The chained structures are all represented at the same level in the
 *  hierarchy and given names with an index representing where they are in the chain
 *  list. As an example, the Core structure has a pointer to an Interface structure
 *  called interface0_ptr. The Interface structure has a pointer called next_i_ptr
 *  that points to the next interface structure in the list. When next_i_ptr is NULL,
 *  that indicates the end of the list. 
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
		ret = genz_create_control_children(zdev, s, );
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
	genz_control_cookie * cookie)
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
	return;
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
	return;
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
	
	*hdr_offset = 0;
	/* Read the given offset to get the pointer to the control structure */
	ret = zdev->zbdev->zbdrv->control_read(zdev, start+offset,
				(int)psize, (void *)hdr_offset, 0);
	if (ret) {
		pr_debug("%s: control read of pointer failed with %d\n",
			__func__, ret);
		return ret;
	}

	/* It is ok for many fields to be NULL. Everything is optional. */
	if (*hdr_offset == 0)
		return ENOENT;

	/* Read a control structure header at that pointer location */
	ret = zdev->zbdev->zbdrv->control_read(zdev, *hdr_offset,
		sizeof(struct genz_control_structure_header), (void *)hdr, 0);
	if (ret) {
		pr_debug("%s: control read of header structure failed with %d\n",
			__func__, ret);
		return ret;
	}
	return ret;
}

static int read_and_validate_header(struct genz_dev *zdev,
			off_t start,
			struct genz_control_structure_ptr *csp,
			struct genz_control_structure_header *hdr,
			off_t *hdr_offset)
{
	int ret = 0;
	uint8_t expected_vers;

	ret = read_header_at_offset(zdev, start, csp->ptr_size,
				csp->pointer_offset, hdr, hdr_offset);

	/* This pointer is NULL. Not an error.*/
	if (ret == ENOENT)
		return ENOENT;

	/* Validate the header is as expected */
	if (csp->struct_type != GENZ_GENERIC_STRUCTURE) {
		if (hdr->type != csp->struct_type) {
			pr_debug("%s: expected type %d but found %d\n",
				__func__, csp->struct_type, hdr->type);
			return -EINVAL;
		}
	}
	/* Validate the structure size. 
	   Revisit: Could get the structure from the type and then
	   compare to the sizeof(struct...). Would need to be version
	   aware. Could have ptr_type that say it is fixed size or
	   variable size minimum. */
	if (hdr->size == 0) {
		pr_debug("%s: structure size is 0.\n", __func__);
		return -EINVAL;
	}
	/* Validate the version. */
	expected_vers = genz_struct_type_to_ptrs[hdr->type].vers;
	if (hdr->vers != expected_vers) {
		pr_debug("%s: structure version mismatch expected %d but found %d.\n", __func__, expected_vers, hdr->vers);
		return -EINVAL;
	}
	return ret;
}

static struct genz_control_info * alloc_control_info(struct genz_dev *zdev,
		struct genz_control_structure_header *hdr,
		off_t offset,
		struct genz_control_info *parent)
{
	struct genz_control_info *ci;

	/* Allocate a genz_control_info/kobject for this directory */
	ci = kzalloc(sizeof(*ci), GFP_KERNEL);
	if (!ci) {
		pr_debug("%s: failed to allocate genz_control_info.\n", __func__);
		return NULL;
	}
		
	ci->zdev = zdev;
	ci->start = offset;
	ci->type = hdr->type;
	ci->vers = hdr->vers;
	ci->size = hdr->size;
	ci->parent = parent;
	/* Revisit: fill out remaining fields.
	ci->c_access_res =;
	ci->zmmu = ; */
	
	return ci;
}

static int traverse_array(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct genz_control_ptr_info *pi,
			struct kobject *struct_dir,
			struct genz_control_structure_ptr *csp)
{
	struct genz_control_info *ci;
	struct genz_control_structure_header hdr;
	int ret = 0;

	/* Allocate a genz_control_info/kobject for this directory */
	ci = alloc_control_info(zdev, &hdr, csp->pointer_offset, parent);
	if (ci == NULL) {
		pr_debug("%s: failed to allocate control_info\n", __func__);
		return -ENOMEM;
	}

	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, struct_dir, "%s",
				genz_structure_name(hdr.type));
	if (ret < 0) {
		kobject_put(&ci->kobj);
		kfree(ci);
		return ret;
	}

	/* Now initialize the binary attribute file. */
	ci->battr.attr.name = genz_structure_name(hdr.type);
	ci->battr.attr.mode = S_IRUSR;
	ci->battr.size = ci->size;
	ci->battr.read =  read_control_structure;
	ci->battr.write = write_control_structure;
	ci->battr.private = ci; /* Revisit: is this used/needed? */

	ret = sysfs_create_bin_file(&ci->kobj, &ci->battr);
	return 0;
}

static int traverse_table(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct genz_control_ptr_info *pi,
			struct kobject *dir,
			struct genz_control_structure_ptr *csp)
{
	return 0;
}

static int traverse_table_with_header(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct genz_control_ptr_info *pi,
			struct kobject *dir,
			struct genz_control_structure_ptr *csp)
{
	return 0;
}

#ifdef NOT_YET
static int type_is_chained(int type)
{
	struct genz_control_structure_ptr *csp;
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

/*
 * Search the list of pointers for this structure to find the
 * one marked "CHAINED". That is the offset for the next pointer
 * in the list. Complain if it is not found or more than one is
 * found.
 */
static off_t find_chain_offset(struct genz_control_ptr_info *pinfo)
{
	struct genz_control_structure_ptr *csp;
	size_t num_ptrs;
	int chain_offset = -ENOENT;
	int i;

	csp = pinfo->ptr;
	num_ptrs = pinfo->num_ptrs;
	for (i = 0; i < num_ptrs; i++) {
		if (csp[i].ptr_type == GENZ_CONTROL_POINTER_CHAINED) {
			if (chain_offset != -ENOENT) {
				/* Already found a CHAIN. */
				pr_debug("%s: Already found a CHAIN offset %d. New one: %d\n", __func__, chain_offset, csp[i].pointer_offset);
				return -EINVAL;
			}
			chain_offset = csp[i].pointer_offset;
		}
	}
	if (chain_offset == -ENOENT) {
		/* Failed to find a CHAIN. */
		pr_debug("%s: Did not find a CHAIN offset for structure %s.\n", __func__, pinfo->name);
		return -ENOENT;
	}
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
			struct genz_control_ptr_info *pi,
			struct kobject *dir,
			struct genz_control_structure_ptr *csp)
{
	int chain_num = 0;
	struct genz_control_structure_header hdr;
	off_t hdr_offset;
	int chain_offset = -1;
	int done = 0;
	struct genz_control_info *struct_dir;
	int ret;
	struct genz_control_info *ci;
	
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
	chain_offset = find_chain_offset(&genz_struct_type_to_ptrs[hdr.type]);
	if (chain_offset < 0) {
		pr_debug("%s: could not find the chain pointer\n", __func__);
		return (int)chain_offset;
	}

	/* Create the container directory for all the chained structures */
	struct_dir = alloc_control_info(zdev, &hdr, hdr_offset, parent);
	if (struct_dir == NULL) {
		pr_debug("%s: failed to allocate control_info\n", __func__);
		return -ENOMEM;
	}

	kobject_init(&struct_dir->kobj, &control_info_ktype);
	ret = kobject_add(&struct_dir->kobj, dir, "%s",
			genz_structure_name(hdr.type));
	if (ret < 0) {
		kobject_put(&struct_dir->kobj);
		kfree(struct_dir);
		return ret;
	}

	while (!done) {
		/* Allocate a genz_control_info/kobject for this directory */
		ci = alloc_control_info(zdev, &hdr, hdr_offset, struct_dir);
		if (ci == NULL) {
			pr_debug("%s: failed to allocate control_info\n", __func__);
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
		ci->battr.attr.name = genz_structure_name(hdr.type);
		ci->battr.attr.mode = S_IRUSR;
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
			&genz_struct_type_to_ptrs[hdr.type],
			&ci->kobj);
		if (ret < 0) {
			/* Handle error! */
			return ret;
		}

		/* Follow chain pointer to read the next control struct */
		ret = read_and_validate_header(zdev, chain_offset,
			csp, &hdr, &hdr_offset);

		/* The pointer is NULL- this is the end of the list */
		if (ret == ENOENT)
			done = 1;
	}
	return ret;
}

static int traverse_structure(struct genz_dev *zdev,
			struct genz_control_info *parent,
			struct genz_control_ptr_info *pi,
			struct kobject *dir,
			struct genz_control_structure_ptr *csp)
{
	int ret;
	struct genz_control_structure_header hdr;
	off_t hdr_offset;
	struct genz_control_info *ci;

	ret = read_and_validate_header(zdev, parent->start, csp,
		&hdr, &hdr_offset);

	/* This pointer is NULL. Not an error.*/
	if (ret == ENOENT)
		return 0;

	/* Allocate a genz_control_info with a kobject for this directory */
	ci = alloc_control_info(zdev, &hdr, hdr_offset, parent);
	if (ci == NULL) {
		pr_debug("%s: failed to allocate control_info\n", __func__);
		return -ENOMEM;
	}

	/* Revisit: the directory is supposed to be the field name not the structure name. */
	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, dir, "%s",
			genz_structure_name(hdr.type));
	if (ret < 0) {
		kobject_put(&ci->kobj);
		kfree(ci);
		return ret;
	}
	
	/* Now initialize the binary attribute file. */
	ci->battr.attr.name = genz_structure_name(hdr.type);
	ci->battr.attr.mode = S_IRUSR;
	ci->battr.size = ci->size;
	ci->battr.read =  read_control_structure;
	ci->battr.write = write_control_structure;
	ci->battr.private = ci; /* Revisit: is this used/needed? */
	
	ret = sysfs_create_bin_file(&ci->kobj, &ci->battr);
	if (ret) {
		/* Revisit: handle error */
		return ret;
	}
	/* Recursively traverse any pointers in this structure */
	ret = traverse_control_pointers(zdev, ci,
		&genz_struct_type_to_ptrs[hdr.type],
		&ci->kobj);
	if (ret < 0) {
		/* Revisit: handle error */
		return ret;
	}
	return 0;
}

static int traverse_control_pointers(struct genz_dev *zdev,
	struct genz_control_info *parent,
	struct genz_control_ptr_info *pi,
	struct kobject *dir)
{
	int i;
	int ret = 0;
	struct genz_control_structure_ptr *csp;

	for (i = 0; i < pi->num_ptrs; i++) {
		csp = &(pi->ptr[i]);

		switch (csp->ptr_type) {
			case GENZ_CONTROL_POINTER_NONE:
				break;
			case GENZ_CONTROL_POINTER_STRUCTURE:
				ret = traverse_structure(zdev, parent, 
					pi, dir, csp);
				break;
			case GENZ_CONTROL_POINTER_CHAINED:
				ret = traverse_chained_control_pointers(zdev,
					parent, pi, dir, csp);
				break;
			case GENZ_CONTROL_POINTER_ARRAY:
				ret = traverse_array(zdev, parent,
					pi, dir, csp);
				break;
			case GENZ_CONTROL_POINTER_TABLE:
				ret = traverse_table(zdev, parent,
					pi, dir, csp);
				break;
			case GENZ_CONTROL_POINTER_TABLE_WITH_HEADER:
				ret = traverse_table_with_header(zdev, parent,
					pi, dir, csp);
				break;
		}
		if (ret < 0) {
			/* Revisit: Undo everything and fail */
			return ret;
		}
	}
	return 0;
}

/**
 * genz_bridge_create_control_files() - read control space for a local bridge
 */
int genz_bridge_create_control_files(struct genz_bridge_dev *zbdev)
{
	int ret;
	struct genz_control_structure_header hdr;
	struct genz_control_info *ci;
	struct genz_control_ptr_info *cpi;
	struct kobject *control_dir, *attribs_dir;
	struct genz_dev *zdev;

	if (zbdev == NULL) {
                pr_debug("%s: zbdev is NULL\n", __func__);
		return -EINVAL;
	}

	zdev = &zbdev->zdev;
	if (!zdev_is_local_bridge(zdev)) {
                pr_debug("%s: zbdev not a bridge\n", __func__);
		return -EINVAL;
	}

	/* A bridge must have control_read function */
	if (zdev->zbdev->zbdrv->control_read == NULL) {
                pr_debug("%s: missing control_read()\n", __func__);
		return -EINVAL;
	}

	/* Start at offset 0 for the core structure */
	ret = zdev->zbdev->zbdrv->control_read(zdev, 0, sizeof(hdr), (void *)&hdr, 0);
	if (ret) {
		pr_debug("%s: initial control read of core structure failed with %d\n",
			__func__, ret);
		return ret;
	}

	cpi = &genz_struct_type_to_ptrs[0];

	/* Validate this the expected structure type */
	/* Revisit: Get Core type from enum instead of hardcoding 0 */
	if (hdr.type != 0) {
		pr_debug("%s: control offset 0 is not core structure. Type is %d\n", __func__, hdr.type);
		return -EINVAL;
	}

	/* Validate the core structure size. 
	   Revisit: Could get the structure from the ptr_type and then compare
	   to the sizeof(struct...). Would need to be version aware. Could
	   have ptr_type that say it is fixed size or variable size minimum. */
	if (hdr.size == 0) {
		pr_debug("%s: core structure size is 0.\n", __func__);
		return -EINVAL;
	}

	/* Validate the version. */
	if (hdr.vers != cpi->vers) {
		pr_debug("%s: core structure version mismatch expected %d but found %d.\n", __func__, hdr.vers, cpi->vers);
		return -EINVAL;
	}

	/* Allocate the genz_control_info that contains the kobject */
	ci = alloc_control_info(zdev, &hdr, 0, NULL);
	if (ci == NULL) {
		pr_debug("%s: failed to allocate control_info\n", __func__);
		return -ENOMEM;
	}

	/*
	 * Create kobject hierarchy under the local bridge devices for
	 * <device>/genzN/attribs and <device>/genzN/control
	 */
	/* Revisit: use a bridge number instead of hardcoded 0 for genz0. */
	zdev->root_kobj = kobject_create_and_add("genz0", &zdev->dev.kobj);
	if (zdev->root_kobj == NULL) {
		pr_debug("%s: failed to create kobject for genz0\n", __func__);
		return -ENOMEM;
	}

	control_dir = kobject_create_and_add("control", zdev->root_kobj);
	if (control_dir == NULL) {
		pr_debug("%s: failed to create kobject for genz0/control\n", __func__);
		return -ENOMEM;
	}

	attribs_dir = kobject_create_and_add("attribs", zdev->root_kobj);
	if (attribs_dir == NULL) {
		pr_debug("%s: failed to create kobject for genz0/attribs\n", __func__);
		kobject_put(zdev->root_kobj);
		kobject_put(control_dir);
		return -ENOMEM;
	}
		
	kobject_init(&ci->kobj, &control_info_ktype);
	ret = kobject_add(&ci->kobj, control_dir, "%s",
			genz_structure_name(hdr.type));
	if (ret < 0) {
		kobject_put(&ci->kobj);
		kfree(ci);
		kobject_put(zdev->root_kobj);
		kobject_put(control_dir);
		kobject_put(attribs_dir);
		return ret;
	}

	/* Now initialize the binary attribute file for the core structure. */
	ci->battr.attr.name = genz_structure_name(hdr.type);
	ci->battr.attr.mode = S_IRUSR;
	ci->battr.size = ci->size;
	ci->battr.read =  read_control_structure;
	ci->battr.write = write_control_structure;
	ci->battr.private = ci; /* Revisit: is this used/needed? */

	ret = sysfs_create_bin_file(&ci->kobj, &ci->battr);

	
	zdev->root_control_info = ci;
	traverse_control_pointers(zdev, ci,
			&genz_struct_type_to_ptrs[hdr.type], 
			control_dir);
	return 0;
}
EXPORT_SYMBOL_GPL(genz_bridge_create_control_files);


/**
 * genz_bridge_remove_control_files() - remove sysfs files for a local bridge
 */
int genz_bridge_remove_control_files(struct genz_bridge_dev *zbdev)
{
	return 0;
}
EXPORT_SYMBOL_GPL(genz_bridge_remove_control_files);

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
                pr_debug("%s: zdev is NULL\n", __func__);
		return -EINVAL;
	}

	/* Next parse the gcid to get the SID for the next directory */
	sid = kobject_create();
	if (sid == NULL) {
		goto err_genz;
	}
	ret = kobject_init_and_add(sid, &control_info_ktype, zdev->root_kobj,
			"%04d", genz_get_sid(zdev->zcomp->gcid));
	if (ret < 0) {
		goto err_sid;
	}
	
	/* Next parse the gcid to get the CID for the next directory */
	cid = kobject_create();
	if (cid == NULL) {
		goto err_sid;
	}
	ret = kobject_init_and_add(cid, &control_info_ktype, sid,
			"%03d", genz_get_cid(zdev->zcomp->gcid));
	if (ret < 0) {
		goto err_cid;
	}

	/* Add the attribs directory */
	attrib_dir = kobject_create();
	if (attrib_dir == NULL) {
		goto err_cid;
	}
	ret = kobject_init_and_add(attrib_dir, &control_info_ktype, cid,
			"attribs");
	if (ret < 0) {
		goto err_attrib;
	}

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
