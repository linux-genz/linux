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
#include <linux/slab.h>
#include "genz.h"

MODULE_LICENSE("GPL v2");

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

int genz_create_attr(struct genz_dev *zdev, struct genz_resource *zres)
{
	struct bin_attribute *res_attr;
	int ret;

	res_attr = kzalloc(sizeof(*res_attr), GFP_ATOMIC);
	if (!res_attr)
		return -ENOMEM;

	sysfs_bin_attr_init(res_attr);

	res_attr->attr.name = zres->res.name;
	res_attr->attr.mode = (S_IRUSR | S_IWUSR);
	res_attr->size = zres->res.end - zres->res.start + 1;
	res_attr->private = zres;
	res_attr->read = genz_read_control;
	res_attr->write = genz_write_control;
	res_attr->mmap = NULL;
	ret = sysfs_create_bin_file(&zdev->dev.kobj, res_attr);
	if (ret) {
		printk(KERN_ERR "sysfs_create_bin_file failed with %d\n", ret);
		kfree(res_attr);
	}
	/* Add res_attr to list in zdev so it can be cleaned up later */
	return ret;
}

int genz_remove_attr(struct genz_dev *zdev)
{
	struct bin_attribute *res_attr;

	/* for each res_attr in zdev res_list */
	/* Remove from res_list*/
	if (res_attr) {
		sysfs_remove_bin_file(&zdev->dev.kobj, res_attr);
		kfree(res_attr);
	}
}

const struct device_type genz_dev_type = {
//	.groups = genz_dev_attr_groups,
};
