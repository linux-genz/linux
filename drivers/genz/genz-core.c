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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "genz.h"
#include "genz-types.h"
#include "genz-control.h"

static bool no_genz;
module_param(no_genz, bool, 0444);
MODULE_PARM_DESC(no_genz, "Disable genz (default 0)");

/**
 * genz_disabled - determine if the Gen-Z sub-system is disabled
 *
 * The Gen-Z sub-system can abe disabled through a module parameter
 * called "no_genz". This function returns the state of that parameter.
 * 
 * Return:
 * 0 - Gen-Z is enabled
 * 1 - Gen-Z is disabled
 */
int genz_disabled(void)
{
	return no_genz;
}
EXPORT_SYMBOL_GPL(genz_disabled);

/**
 * genz_validate_control_space_structure_type - check structure type
 * @int type: the structure type field
 *
 * The Gen-Z control space structures contains a 12 bit type field
 * at bit 0. The type identifies the Gen-Z control structure. 
 * This function validates that the type field is a known value.
 * 
 * Return:
 * 0 - the given type is invalid
 * 1 - the given type is valid
 */
int genz_validate_control_space_structure_type(int type)
{
	int valid = 0;
	switch (type) {
		case GENZ_CORE_STRUCTURE:
		case GENZ_OPCODE_SET_STRUCTURE:
		case GENZ_INTERFACE_STRUCTURE:
		case GENZ_INTERFACE_PHY_STRUCTURE:
		case GENZ_INTERFACE_STATISTICS_STRUCTURE:
		/* add them all once we have the enum */
			valid = 1;
	}
	return valid;
}
EXPORT_SYMBOL_GPL(genz_validate_control_space_structure_type);

static int is_genz_device(struct genz_core_structure *core)
{
	/* Check that the Z-UUID is the Gen-Z spec value */
	if (core == NULL)
		return 0;
	/* return (core->z_uuid == GENZ_Z_UUID);  */
	return 1;
}

static int genz_match_id(
	struct device *dev,
	struct genz_core_structure *core,
	struct genz_device_id *id)
{
	/*
	 * Compare the device's C-UUID and any Service-UUIDs to the
	 * list of UUID's in the genz_divice_id table
	 */

	return 0;
}

static struct genz_core_structure * genz_read_core(struct device *dev)
{
	return (struct genz_core_structure *) NULL;
}

static int genz_match_device(struct device *dev, struct device_driver *drv)
{
        struct genz_driver *driver = to_genz_driver(drv);
	struct genz_core_structure *core;
	int match;

	core = genz_read_core(dev);
	if (core == 0)
                return 0;

        if (!is_genz_device(core))
                return 0;

        match = genz_match_id(dev, core, driver->id_table);
        if (match)
                return 1;
        return 0;
}

static int genz_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	return 0;
}

static void genz_shutdown(struct device *dev)
{
}

struct bus_type genz_bus_type = {
	.name = 	"genz",
	.match =	genz_match_device,
	.uevent =	genz_uevent,
	.shutdown =	genz_shutdown,
};

static int genz_probe(struct device *dev)
{
	return 0;
}

static int genz_remove(struct device *dev)
{
	return 0;
}

/**
 * __genz_register_driver - register a new Gen-Z driver
 * @struct genz_driver *driver: the driver structure to register
 * @struct module *module: owner module of the driver
 * @const char *mod_name: module name string
 *
 * Adds the driver structure to the list of registered Gen-Z drivers.
 *
 * Return:
 * Returns 0 on success. Returns a negative value on error.
 */
int __genz_register_driver(struct genz_driver *driver, struct module *module, 
				const char *mod_name)
{
	int ret;

	if (genz_disabled())
		return -ENODEV;

        driver->driver.name = driver->name;
        driver->driver.bus = &genz_bus_type;
        driver->driver.probe = genz_probe;
        driver->driver.remove = genz_remove;
        driver->driver.owner = module;
        driver->driver.mod_name = mod_name;

	ret = driver_register(&driver->driver);
	if (ret) {
		pr_debug( "driver_register for genz driver %s failed with %d\n",
			driver->name, ret);
		return ret;
	}

	pr_info("Registered new genz driver %s\n", driver->name);
	return 0;
}
EXPORT_SYMBOL(__genz_register_driver);

/**
 * __genz_unregister_driver - register a Gen-Z driver
 * @struct genz_driver *driver: the driver structure to unregister
 *
 * Deletes the driver structure from the list of registered Gen-Z drivers.
 * The driver's remove function will be called for each device it was
 * responsible for. Those devices are then marked as driverless.
 */
void __genz_unregister_driver(struct genz_driver *driver)
{
        driver_unregister(&driver->driver);
}
EXPORT_SYMBOL(__genz_unregister_driver);

static int initialize_zdev(struct genz_dev *zdev,
			struct genz_driver *driver,
			struct module *module,
			const char *mod_name)
{
	/* zdev->uuid = NULL; */
	zdev->res = NULL;
	zdev->root_control_info = NULL;
	zdev->root_kobj = NULL; /* kobj for /sys/devices/genz/ */
	/* zdev->zdriver = driver; */
	zdev->bridge_zdev = NULL;
	/* zdev->dev = driver; */		/* Generic device interface */
	zdev->gcid = 0;
	return 0;
}

/**
 * genz_register_bridge - register a new Gen-Z bridge driver
 * @struct device *dev: the device structure to register
 * @struct genz_driver *driver: the Gen-Z driver structure to register
 * @struct module *module: owner module of the driver
 * @const char *mod_name: module name string
 *
 * A driver calls genz_register_bridge() during probe of a device that
 * is a bridge component. This marks the bridge component as a bridge
 * so that a fabric manager can discover it through sysfs files named
 * 'brigeN'. Typically a bridge device driver is a PCI device (for example)
 * and the driver is both a PCI driver and a Gen-Z driver. 
 *
 * Return:
 * Returns 0 on success. Returns a negative value on error.
 */
int genz_register_bridge(struct device *dev, struct genz_driver *driver,
		struct module *module, const char *mod_name)
{
	int ret = 0;
	struct genz_bridge_dev *zbdev;

	/* Allocate a genz_bridge_dev */

	/* Initialize the genz_bridge_dev */
	initialize_zdev(&zbdev->zdev, driver, module, mod_name);
	zbdev->bridge_dev = dev;

	ret = genz_bridge_create_control_files(zbdev);
	return ret;
}
EXPORT_SYMBOL(genz_register_bridge);

/**
 * genz_unregister_bridge - unregister a Gen-Z bridge driver
 * @struct genz_driver *driver: the Gen-Z driver structure to register
 *
 * A driver calls genz_unregister_bridge() to unregister a bridge
 * driver with the Gen-Z sub-system. Typically a bridge device driver
 * is a PCI device (for example) and the driver is both a PCI driver and
 * a Gen-Z driver. The driver must call the appropriate native bus "unregister"
 * function after calling genz_unregister_bridge(), e.g.
 * pci_unregister_driver(). 
 *
 * Return:
 * Returns 0 on success. Returns a negative value on error.
 */
int genz_unregister_bridge(struct genz_driver *driver)
{
	int ret = 0;

	return ret;
}
EXPORT_SYMBOL(genz_unregister_bridge);

static int __init genz_init(void) {
	int ret;

	if (genz_disabled())
		return -ENODEV;

	ret = bus_register(&genz_bus_type);
	if (ret) {
		pr_err("bus_register failed (%d)\n", ret);
		goto error_bus;
	}

error_bus:
	
	return ret;
}
module_init(genz_init);

static void __exit genz_exit(void) {
	bus_unregister(&genz_bus_type);
}

module_exit(genz_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Betty Dall <betty.dall@hpe.com>");
MODULE_AUTHOR("Jim Hull <jim.hull@hpe.com>");
