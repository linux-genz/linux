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

#ifndef LINUX_GENZ_H
#define LINUX_GENZ_H

#include <linux/device.h>
#include <linux/uuid.h>

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/uuid.h>
typedef unsigned long kernel_ulong_t;
#endif

typedef unsigned char uuid_str_t[37];	/* UUID string of format:
                                           1b4e28ba-2fa1-11d2-883f-b9a761bde3fb
                                           including a trailing NULL */

/* Value of Z-UUID in control space that indicates a Gen-Z device */
#define GENZ_Z_UUID	0x4813ea5f074e4be2a355a354145c9927

typedef loff_t genz_control_cookie;

/* Revisit: does this belong in mod_devicetable.h? */
struct genz_device_id {
	uuid_str_t	uuid_str;	/* Vendor assigned component or
					   service UUID */
	kernel_ulong_t	driver_data;	/* Data private to the driver */
};

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
	struct list_head devices;	/* List of devices on this fabric */
	struct list_head bridges;	/* List of local bridges on fabric */
	struct kref	kref;
};

struct genz_component {
	uint32_t		gcid;
	uint8_t			cclass;
	uuid_t			fru_uuid;
	struct list_head	control_zres_list;
	struct list_head	data_zres_list;
};

struct genz_dev {
	struct list_head	fabric_list; /* Node in the per-fabric list */
	uuid_t 		uuid; /* UUID of this component/service/virtual UUID */
	int                     zres_count;
	struct list_head	zres_list;
	struct genz_resource 	*zres;	/* pointer to dynamic array of resources for this device */
	struct genz_control_info *root_control_info;
	struct kobject		*root_kobj; /* kobj for /sys/devices/genz/ */
	struct genz_driver	*zdriver;
	struct genz_bridge_dev	*zbdev;
	struct genz_component	*zcomp; /* parent component */
	struct device		dev;		/* Generic device interface */
};
#define to_genz_dev(n) container_of(n, struct genz_dev, dev)


struct genz_bridge_dev {
	struct list_head	node;		/* node in list of bridges on fabric */
	struct genz_dev		zdev;
	struct device		*bridge_dev; /* native device pointer */
	struct genz_fabric	*fabric;
	void 			*private;    /* for bridge driver */
	/* Revisit: add address space */
};

struct genz_driver {
	const char			*name;
	struct genz_device_id		*id_table; /* Null terminated array */
	int (*probe)(struct genz_dev *dev, const struct genz_device_id *id);
	int (*remove)(struct genz_dev *dev);
	int (*suspend)(struct genz_dev *dev);
	int (*resume)(struct genz_dev *dev);
	int (*control_mmap)(struct genz_dev *dev); /* REVISIT: need flags? */
	int (*control_read)(struct genz_dev *dev, genz_control_cookie offset, size_t size, void *data, uint flags);
	int (*control_write)(struct genz_dev *dev, genz_control_cookie offset, size_t size, void *data, uint flags);
	int (*data_mmap)(struct genz_dev *dev);
	int (*data_read)(struct genz_dev *dev, genz_control_cookie offset, size_t size, void *data);
	int (*data_write)(struct genz_dev *dev, genz_control_cookie offset, size_t size, void *data);
	struct device_driver		driver;
};
#define to_genz_driver(d) container_of(d, struct genz_driver, driver)

static inline bool zdev_is_local_bridge(struct genz_dev *zdev)
{
	return ((zdev != NULL && zdev->zbdev != NULL) ?
			(&zdev->dev == zdev->zbdev->bridge_dev) : 0);
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

/* Global Variables */
extern struct list_head genz_fabrics;

/* Function Prototypes */
void genz_lock_rescan_remove(void);
void genz_unlock_rescan_remove(void);

#endif /* LINUX_GENZ_H */
