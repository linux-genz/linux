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

#include <linux/kernel.h>
#include "genz.h"

/*
 * genz_rescan_bus(), genz_rescan_bus_bridge_resize() and Gen-Z device removal
 * routines should always be executed under this mutex.
 */
static DEFINE_MUTEX(genz_rescan_remove_lock);

void genz_lock_rescan_remove(void)
{
	mutex_lock(&genz_rescan_remove_lock);
}
EXPORT_SYMBOL_GPL(genz_lock_rescan_remove);

void genz_unlock_rescan_remove(void)
{
	mutex_unlock(&genz_rescan_remove_lock);
}
EXPORT_SYMBOL_GPL(genz_unlock_rescan_remove);

static ssize_t bridge_rescan_store(struct bus_type *bus, const char *buf,
				size_t count)
{
	unsigned long val;
	struct genz_bridge *b = NULL;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val) {
		genz_lock_rescan_remove();
		while ((b = genz_find_next_bridge(b)) != NULL)
			genz_rescan_bridge(b);
		genz_unlock_rescan_remove();
	}
}

static BUS_ATTR(rescan, (0220), NULL, bridge_rescan_store);

static struct attribute *genz_bridge_attrs[] = {
	&bridge_attr_rescan.attr,
	NULL,
};

static const struct attribute_group genz_bridge_group = {
	.attrs = genz_bridge_attrs,
};

static const struct attribute_group *genz_bridge_groups[] = {
	&genz_bridge_group,
	NULL,
};

struct void genz_bridge_release(struct device *dev)
{
}

struct device_type genz_bridge_type = {
	.name		= "genz_bridge_device",
	.release	= genz_bridge_release,
	.dev_groups	= genz_bridge_groups,
};

/* Increment the reference count on the bus device object */
struct genz_bus *genz_bus_get(struct genz_bus *bus)
{
	if (bus)
		get_device(&bus->dev);
	return bus;
}
EXPORT_SYMBOL(genz_bus_get);

void genz_bus_put(struct genz_bus *bus)
{
	if (bus)
		put_device(&bus->dev);
}
EXPORT_SYMBOL(genz_bus_put);
