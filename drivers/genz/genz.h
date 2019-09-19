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

#ifndef DRIVERS_GENZ_H
#define DRIVERS_GENZ_H

#include <linux/bitmap.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/genz.h>

/* Value of Z-UUID in control space that indicates a Gen-Z device */
#define GENZ_Z_UUID	0x4813ea5f074e4be2a355a354145c9927
#define GENZ_CAST_UUID(u) *((uuid_t *)&(u))

extern struct bus_type genz_bus_type;

/*
 * Gen-Z resources can be control or data space in the struct resources 
 * IORESOURCE_BITS.
 */
struct genz_resource {
	struct list_head component_list;
	struct list_head dev_list;
	struct resource res;
	uint32_t ro_rkey;
	uint32_t rw_rkey;
};
#define to_genz_res(n) container_of(n, struct genz_resource, res)

struct genz_fabric {
	struct list_head node;  	/* node in list of fabrics */
	uint32_t number;		/* fabric_number */
	uuid_t mgr_uuid;
	struct list_head devices;	/* List of devices on this fabric */
	struct list_head components;	/* List of components on this fabric */
	struct rw_semaphore subnet_sem; /* protects subnets list */
	struct list_head subnets;	/* List of subnets on this fabric */
	struct list_head bridges;	/* List of local bridges on fabric */
	struct kref	kref;
	struct device   dev;		/* /sys/devices/genz<N> */
	struct kset	*zkset;
};
#define to_genz_fabric(x) container_of(x, struct genz_fabric, kref)

struct genz_fabric_attribute {
	struct attribute attr;
        ssize_t (*show)(struct genz_fabric *fab,
		struct genz_fabric_attribute *attr, char *buf);
        ssize_t (*store)(struct genz_fabric *fab,
		struct genz_fabric_attribute *attr,
		const char *buf, size_t count);
};
#define to_genz_fabric_attr(x) container_of(x, struct genz_fabric_attribute, attr)

struct genz_subnet {
	uint32_t		sid;
	struct genz_fabric 	*fabric;
	struct list_head	node; /* per-fabric list of subnets*/
	struct list_head	frus; /* list of frus in this subnet */
	struct kobject		kobj; /* /sys/devices/genz<N>/SID */
};
#define to_genz_subnet(x) container_of(x, struct genz_subnet, kobj)

struct genz_subnet_attribute {
	struct attribute attr;
        ssize_t (*show)(struct genz_subnet *s,
		struct genz_subnet_attribute *attr, char *buf);
        ssize_t (*store)(struct genz_subnet *s,
		struct genz_subnet_attribute *attr,
		const char *buf, size_t count);
};
#define to_genz_subnet_attr(x) container_of(x, struct genz_subnet_attribute, attr)

struct genz_fru {
	uuid_t			fru_uuid;
	struct genz_subnet	*subnet;
	struct list_head	node; /* per-subnet list of frus*/
	struct kobject		kobj; /* /sys/devices/genz<N>/<SID>/<FRU> */
};
#define to_genz_fru(x) container_of(x, struct genz_fru, kobj)

struct genz_fru_attribute {
	struct attribute attr;
        ssize_t (*show)(struct genz_fru *f,
		struct genz_fru_attribute *attr, char *buf);
        ssize_t (*store)(struct genz_fru *f,
		struct genz_fru_attribute *attr,
		const char *buf, size_t count);
};
#define to_genz_fru_attr(x) container_of(x, struct genz_fru_attribute, attr)

struct genz_component {
	uint32_t		cid;
	struct kobject		kobj;  /* /sys/devices/genz<N>/SID/CID */
	uint8_t			cclass;
	uuid_t			fru_uuid;
	struct genz_subnet	*subnet;
	struct list_head	fab_comp_node; /* Node in the per-fabric list */
	struct list_head	control_zres_list; /* head of zres list */
	struct list_head	data_zres_list;    /* head of zres list */
	struct kref		kref;
};

static inline struct genz_component *kobj_to_genz_component(struct kobject *kobj)
{
        return container_of(kobj, struct genz_component, kobj);
}


struct genz_component_attribute {
	struct attribute attr;
        ssize_t (*show)(struct genz_component *c,
		struct genz_component_attribute *attr, char *buf);
        ssize_t (*store)(struct genz_component *c,
		struct genz_component_attribute *attr,
		const char *buf, size_t count);
};
#define to_genz_component_attr(x) container_of(x, struct genz_component_attribute, attr)

/* SID is 16 bits starting at bit 13 of a GCID */
static inline int genz_get_sid(int gcid)
{
	return(0xFFFF & (gcid >> 12));
}

/* CID is first 12 bits of a GCID */
static inline int genz_get_cid(int gcid)
{
	return(0xFFF & gcid);
}

static inline int genz_get_gcid(int sid, int cid)
{
	return((sid<<12) | cid);
}

/*
 * Use these macros so that KBUILD_MODNAME and THIS_MODULE can be expanded
 */
#define genz_register_driver(driver)             \
        __genz_register_driver(driver, THIS_MODULE, KBUILD_MODNAME)
#define genz_unregister_driver(driver)             \
        __genz_unregister_driver(driver)

/* 
 * Don't call these directly - use the macros. 
 */
int __genz_register_driver(struct genz_driver *driver, struct module *, 
				const char *mod_name);
void __genz_unregister_driver(struct genz_driver *driver);


extern struct device_type genz_bridge_type;

static inline int is_genz_bridge_device(struct device *dev)
{
	return dev->type == &genz_bridge_type;
}

/* Control space structure used to represent the /sys hierarchy. */
struct genz_control_info {
	struct kobject          kobj;
	struct resource         *c_access_res; /* points into the c-access
						* tree- may not end up being 
						* a struct resource *.
							*/
	struct genz_control_info *parent, *sibling, *child; /* control structure hierarchy used for creating /sys hierarchy */
	struct genz_dev		*zdev;
	off_t                   start;
	uint32_t		type;		/* type from the control_structure_header */
	uint8_t			vers;		/* version from the control_structure_header */
	size_t                  size;		/* size in bytes */
	struct req_zmmu         *zmmu;  	/* placeholder for zmmu entry */
	struct bin_attribute	battr;
};

#define to_genz_control_info(x) container_of(x, struct genz_control_info, kobj)

struct genz_control_info_attribute {
	struct attribute attr;
        ssize_t (*show)(struct genz_control_info *info,
		struct genz_control_info_attribute *attr, char *buf);
        ssize_t (*store)(struct genz_control_info *info,
		struct genz_control_info_attribute *attr,
		const char *buf, size_t count);
};
#define to_genz_control_info_attr(x) container_of(x, struct genz_control_info_attribute, attr)

#define GENZ_NUM_PASIDS  BIT(16)
#define NO_PASID         0

#define arithcmp(_a, _b)        ((_a) < (_b) ? -1 : ((_a) > (_b) ? 1 : 0))

/* Global Variables */
extern struct list_head genz_fabrics;

/* Function Prototypes */
void genz_lock_rescan_remove(void);
void genz_unlock_rescan_remove(void);
void genz_pasid_init(void);
void genz_pasid_exit(void);
int genz_pasid_alloc(unsigned int *pasid);
void genz_pasid_free(unsigned int pasid);
uint genz_parse_page_grid_opt(char *str, uint64_t max_page_count,
			      bool allow_cpu_visible,
			      struct genz_page_grid pg[]);

int genz_req_page_grid_alloc(struct genz_bridge_dev *br,
			     struct genz_page_grid *grid);
int genz_rsp_page_grid_alloc(struct genz_bridge_dev *br,
			     struct genz_page_grid *grid);
#endif /* DRIVERS_GENZ_H */
