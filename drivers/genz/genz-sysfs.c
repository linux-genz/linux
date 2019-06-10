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

#include <linux/sysfs.h>
#include <linux/module.h>
#include "genz.h"

MODULE_LICENSE("GPL v2");
static int sysfs_initialized; /* = 0 */

static ssize_t genz_read_control(struct file * file,
		struct kobject *kobj,
		struct bin_attribute * battr,
		char *buffer,
		loff_t pos,
		size_t size)
{
	return 0;
}

static ssize_t genz_write_control(struct file * file,
		struct kobject *kobj,
		struct bin_attribute * battr,
		char *buffer,
		loff_t pos,
		size_t size)
{
	return 0;
}

static struct bin_attribute genz_config_attr = {
	.attr = {
		.name = "core",
		.mode = S_IRUGO | S_IWUSR,
	},
	.read = genz_read_control,
	.write = genz_write_control,
};

static int genz_create_structure_files(struct kobject *kobj,
		struct bin_attribute *battr)
{
	return 0;
}

static int genz_remove_structure_files(struct kobject *kobj,
		struct bin_attribute *battr)
{
	return 0;
}

static int genz_create_vendor_defined_files(struct genz_dev *zdev)
{
	return 0;
}

static int genz_remove_vendor_defined_files(struct genz_dev *zdev)
{
	return 0;
}

static int genz_create_capabilities_sysfs(struct genz_dev *zdev)
{
	return 0;
}

int __must_check genz_create_sysfs_dev_files(struct genz_dev *zdev)
{
	int retval;
	int rom_size;
	struct bin_attribute *attr;

	if (!sysfs_initialized)
		return -EACCES;

	retval = genz_create_structure_files(&zdev->dev.kobj, &genz_config_attr);
	if (retval)
		goto err;

	retval = genz_create_vendor_defined_files(zdev);
	if (retval)
		goto err_create_structure_files;

	/* add sysfs entries for various capabilities */
	retval = genz_create_capabilities_sysfs(zdev);
	if (retval)
		goto err_vendor_defined_files;

	return 0;

err_vendor_defined_files:
	genz_remove_vendor_defined_files(zdev);
err_create_structure_files:
	genz_remove_structure_files(&zdev->dev.kobj, &genz_config_attr);
err:
	return retval;
}

/* not for modules. We will add sysfs as the drivers are loaded. 
static int __init genz_sysfs_init(void)
{
	struct genz_dev *zdev = NULL;
	int retval = 0;

	sysfs_initialized = 1;
	for_each_genz_dev(zdev) {
		retval = genz_create_sysfs_dev_files(zdev);
		if (retval) {
			genz_dev_put(zdev);
			return retval;
		}
	}
	return retval;
}
*/
