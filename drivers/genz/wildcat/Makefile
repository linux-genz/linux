# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Gen-Z Wildcat bridge driver.

obj-$(CONFIG_GENZ_WILDCAT)		+= wildcat.o wildcat-rdma.o
wildcat-objs += wildcat-core.o wildcat-queue.o wildcat-zmmu.o wildcat-intr.o wildcat-msg.o \
		wildcat-memreg.o wildcat-uuid.o wildcat-control.o
wildcat-rdma-objs += wildcat-rdma-core.o
