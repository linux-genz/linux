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
          genz-probe.o

obj-$(CONFIG_GENZ)           += genz.o

# Object files in subdirectories
obj-$(CONFIG_GENZ_WILDCAT)   += wildcat/
