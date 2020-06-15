# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Gen-Z bus specific drivers.

genz-y := genz-core.o \
	  genz-types.o \
	  genz-sysfs.o \
	  genz-control.o \
	  genz-size.o \
	  genz-netlink.o \
	  genz-page-grid.o \
	  genz-pasid.o \
	  genz-rkey.o \
	  genz-uuid.o \
	  genz-memreg.o \
	  genz-probe.o \
	  genz-queue.o

obj-$(CONFIG_GENZ)           += genz.o
obj-$(CONFIG_GENZ_BLK)       += genz-blk.o

# Object files in subdirectories
obj-$(CONFIG_GENZ_WILDCAT)   += wildcat/
