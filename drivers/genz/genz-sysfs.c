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

#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "genz.h"

static ssize_t read_control(struct file *file,
		struct kobject *kobj,
		struct bin_attribute *battr,
		char *buffer,
		loff_t pos,
		size_t size)
{
	struct genz_dev *zdev = kobj_to_genz_dev(kobj);
	struct genz_zres *zres = res_attr_to_zres(battr);
	struct genz_rmr_info *rmri = zres->rmri;
	loff_t offset = zres->zres.res.start + pos;
	uint flags = 0;  /* Revisit */

	dev_dbg(&zdev->dev, "pos=%llx, size=%zu, offset=%llx\n",
		pos, size, offset);
	return genz_control_read(zdev->zbdev, offset, size, buffer,
				 rmri, flags);
}

static ssize_t write_control(struct file *file,
		struct kobject *kobj,
		struct bin_attribute *battr,
		char *buffer,
		loff_t pos,
		size_t size)
{
	struct genz_dev *zdev = kobj_to_genz_dev(kobj);
	struct genz_zres *zres = res_attr_to_zres(battr);
	struct genz_rmr_info *rmri = zres->rmri;
	loff_t offset = zres->zres.res.start + pos;
	uint flags = 0;  /* Revisit */

	dev_dbg(&zdev->dev, "pos=%llx, size=%zu, offset=%llx\n",
		pos, size, offset);
	return genz_control_write(zdev->zbdev, offset, size, buffer,
				  rmri, flags);
}

static ssize_t read_data(struct file *file,
		struct kobject *kobj,
		struct bin_attribute *battr,
		char *buffer,
		loff_t pos,
		size_t size)
{
	struct genz_dev *zdev = kobj_to_genz_dev(kobj);
	struct genz_zres *zres = res_attr_to_zres(battr);
	struct genz_rmr_info *rmri = zres->rmri;
	loff_t offset = zres->zres.res.start + pos;
	uint flags = 0;  /* Revisit */

	dev_dbg(&zdev->dev, "pos=%llx, size=%zu, offset=%llx\n",
		pos, size, offset);
	return genz_data_read(zdev->zbdev, offset, size, buffer, rmri, flags);
}

static ssize_t write_data(struct file *file,
		struct kobject *kobj,
		struct bin_attribute *battr,
		char *buffer,
		loff_t pos,
		size_t size)
{
	struct genz_dev *zdev = kobj_to_genz_dev(kobj);
	struct genz_zres *zres = res_attr_to_zres(battr);
	struct genz_rmr_info *rmri = zres->rmri;
	loff_t offset = zres->zres.res.start + pos;
	uint flags = 0;  /* Revisit */

	dev_dbg(&zdev->dev, "pos=%llx, size=%zu, offset=%llx\n",
		pos, size, offset);
	return genz_data_write(zdev->zbdev, offset, size, buffer, rmri, flags);
}

int genz_create_attr(struct genz_dev *zdev, struct genz_zres *zres)
{
	struct bin_attribute *res_attr;
	int ret;

	res_attr = &zres->res_attr;

	sysfs_bin_attr_init(res_attr);

	res_attr->attr.name = zres->zres.res.name;
	res_attr->attr.mode = (S_IRUSR | S_IWUSR);
	res_attr->size = zres->zres.res.end - zres->zres.res.start + 1;
	res_attr->private = zres;  /* Revisit: unused */
	if (zres->zres.res.flags & IORESOURCE_GENZ_CONTROL) {
		res_attr->read = read_control;
		res_attr->write = write_control;
	} else {
		res_attr->read = read_data;
		res_attr->write = write_data;
	}
	res_attr->mmap = NULL;  /* Revisit */
	pr_debug("zdev->dev.kobj is %px res_attr %s\n", &zdev->dev.kobj, zres->zres.res.name);
	ret = sysfs_create_bin_file(&zdev->dev.kobj, res_attr);
	if (ret) {
		printk(KERN_ERR "sysfs_create_bin_file failed with %d\n", ret);
	}
	return ret;
}

int genz_create_attrs(struct genz_dev *zdev)
{
	int ret = 0;
	struct genz_zres *zres;

	if (zdev == NULL) {
		pr_debug("error zdev is NULL\n");
		return -EINVAL;
	}
	genz_for_each_zres(zres, zdev) {
		ret = genz_create_attr(zdev, zres);
		if (ret)
			return ret;
	}

	return ret;
}

void genz_remove_attr(struct genz_dev *zdev, struct genz_zres *zres)
{
	sysfs_remove_bin_file(&zdev->dev.kobj, &zres->res_attr);
}

const struct device_type genz_dev_type = {
//	.groups = genz_dev_attr_groups,
};
