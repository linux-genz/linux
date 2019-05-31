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
MODULE_LICENSE("GPL v2");

#include <linux/slab.h>
#include "genz.h"
#include "genz-types.h"
#include "genz-control.h"

/*
 * genz_structure_name - 
 *  Look up the name of a structure type
 * 
 */
char * genz_structure_name(int type)
{
	int n = sizeof(genz_structure_names);
	int i;

	for (i = 0; i < n; i++) {
		if (genz_structure_names[i].struct_type == type)
			return (genz_structure_names[i].struct_name);
	}
	return (char *)0;
}

static int read_control_structure_header(struct genz_dev *zdev,
		struct genz_control_cookie *cookie,
		struct control_structure_header *hdr)
{
	int ret = 0;

	/* Must pass the buffer to be filled in */
	if (!hdr)
		return -EINVAL;
	ret = zdev->genz_driver->control_read(zdev, cookie,
						sizeof(*hdr), (void *)hdr);
	return ret;
}

static int is_genz_structure(int type_id)
{
	return(type_id >= GENZ_MIN_STRUCTURE && type_id <= GENZ_MAX_STRUCTURE);
}

static int is_genz_table(int type_id)
{
	return(type_id >= GENZ_MIN_TABLE && type_id <= GENZ_MAX_TABLE);
}

static int is_generic_structure(int type_id)
{
	return(type_id == GENERIC_STRUCT_TYPE);
}

static void control_info_release(struct kobject *kobj)
{
	struct genz_control_info *info;

	info = to_genz_control_info_obj(kobj);
	kfree(info);
}

static ssize_t control_info_attr_show(struct kobject *kobj,
                             struct attribute *attr,
                             char *buf)
{
        struct genz_control_info_attribute *attribute;
        struct genz_control_info *info;

        attribute = to_control_info_attr(attr);
        info = to_control_info_obj(kobj);

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

        attribute = to_control_info_attr(attr);
        info = to_control_info_obj(kobj);

        if (!attribute->store)
                return -EIO;

        return attribute->store(info, attribute, buf, len);
}

/*
 * genz_create_control_hierarchy - 
 *  Start with reading the control space a offset 0 to find the core
 *  structure. Each structure in the control space is represented by
 *  a struct genz_control_info. The genz_control_info has a tree
 *  representation with pointers to a parent, sibling, and child. The
 *  table genz_control_pointers
 *  defines the offset to each pointer for each structure type. This
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

static genz_control_info * alloc_control_info(int size, off_t offset)
{
	struct genz_control_info *control_info;

        control_info = kzmalloc(sizeof(*control_info), GFP_KERNEL);
        if (!control_info)
                pr_debug("kmalloc control_info failed\n");
                return NULL;
        }

        control_info->size = size;
        control_info->offset = offset;

	return control_info;
}

static char * genz_type_name(int type_id)
{
	int i;
	int num_names = sizeof(genz_structure_names);

	for (i = 0; i < num_names; i++) {
		if (genz_structure_names[i].struct_type == type_id)
			return genz_structure_names[i].struct_name;
	}
	return "UNKNOWN";
}
	
/*
 * genz_create_control_chain_siblings
 *  A control structure can have a linked list of the same structure. We call this
 *  a chain. The chained structures are all represented at the same level in the
 *  hierarchy and given names with an index representing where they are in the chain
 *  list. As an example, the Core structure has a pointer to an Interface structure
 *  called interface0_ptr. The Interface structure has a pointer called next_i_ptr
 *  that points to the next interface structure in the list. When next_i_ptr is NULL,
 *  that indicates the end of the list. 
static int genz_create_control_chain_siblings(
	struct genz_dev *zdev,
	struct genz_control_info *sibling,
	int type_id,
	off_t start,
	genz_control_pointer_flags flags,
	off_t chain_ptr_offset)
{
	struct genz_control_info *s;
	struct genz_control_header hdr;
	int chain_index = 1; /* 0 is the orginal one found in genz_create_control_children() */
	do {
		sibling_offset = genz_control_structure_pointers[type_id][].offset;
		sibling_id_type = genz_control_structure_pointers[type_id][i].pointer_type_id;
		sibling_flags = genz_control_structure_pointers[type_id][i].flags;
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
		kobject_add(&s->kobj, &parent->kobj, genz_type_name(sibling_id_type));


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
	struct genz_control_header hdr;
	off_t child_struct_start;
	off_t child_id_type;
	off_t child_flags;
	off_t ptr_byte_offset;
	off_t ptr_offset;
	
	for (i = 0; i < num_children; i++) {
		child_offset = genz_control_structure_pointers[type_id][i].offset;
		child_id_type = genz_control_structure_pointers[type_id][i].pointer_type_id;
		child_flags = genz_control_structure_pointers[type_id][i].flags;
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
		kobject_add(&c->kobj, &parent->kobj, genz_type_name(child_id_type));

		/*
		 * Some pointers (e.g. Interface Structures) are chained and all of that list of structure
		 * are siblings.
		 */
		/* REVISIT: add a GENZ_CONTRL_POINTER_ARRAY type - complicated - see Component LPD Structure */
		if (child_flags & GENZ_CONTROL_POINTER_CHAINED) {
			ret = genz_create_control_chain_siblings(zdev, sibling, child_offset, child_id_type, child_flags, 
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
	struct genz_control_header hdr;
	int i;
	int num_structs = sizeof(genz_control_structures);
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

	/* Check that the type matches */
	if (hdr.type != CORE_STRUCTURE) {
		pr_debug("Core Structure header type is not core. Found %d\n",
			hdr.type);
		return -ENOENT;
	}

	/* Create the root of the control space hierarchy */
	zdev->root_control_info = alloc_control_info(hdr->size, offset);
	if (!zdev->root_control_info)
		pr_debug("alloc_control_info() failed\n");
		return -ENOMEM;
	}
	zdev->root_control_info->parent = NULL; /*indicates the root */
	kobject_init(&zdev->root_control_info->kobj, &control_info_ktype);
	kobject_add(&zdev->root_control_info->kobj, &zdev->dev.kobj, genz_type_name(CORE_STRUCTURE));

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
	
}


static int read_control_structure(struct genz_dev *zdev,
		struct genz_control_cookie *cookie,
		off_t offset, /* relative to the start of this control struct */
		size_t *size,
		void **data)
{
	
}

static int write_control_structure(struct genz_dev *zdev,
		off_t offset,
		size_t *size,
		void **data)
{
	
}


static int find_opcode_set_structure(struct genz_dev *zdev, version);
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
	int type,
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
	if (!genz_validate_control_space_structure_type(type)) {
		/* Not a standard control structure. Search the extensions */
		find_vendor_defined_structure(zdev, type, version);
	}
	switch (type) {
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
  
/* Request the Nth control structure that matches the given type and
 * version and return a cookie that can be used to map the structure.
 * This creates the ZMMU entry required for access.  Creates a struct
 * resource behind the scenes.
 */
int genz_request_control_structure(
	struct genz_dev *zdev,
	int index,
	int type,
	int version,
	struct genz_control_cookie * cookie)
{
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
	struct genz_control_cookie cookie)
{
}
EXPORT_SYMBOL_GPL(genz_release_control_structure);

/*
 * Map the Nth control structure that matches the given type and version
 * and return the size and pointer.
 */
int genz_map_control_structure(
	struct genz_dev *zdev,
	struct genz_control_cookie cookie,
	size_t *size,
	void **ctrl_struct)
{
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
	struct genz_control_cookie cookie,
	int table_offset,
	int table_ptr_size,
	struct genz_control_cookie * table_cookie)
{
}
EXPORT_SYMBOL_GPL(genz_request_control_table);

/*
 * Release a control table.  Releases the Gen-Z control table resources
 * reserved by a successful call to genz_request_control_table(). Call
 * this function only after all use of the control table has ceased.
 */
void genz_release_control_table(
	struct genz_dev *zdev,
	struct genz_control_cookie cookie)
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
	struct genz_control_cookie cookie,
	size_t *size,
	void **control_table)
{
}
EXPORT_SYMBOL_GPL(genz_map_control_table);
