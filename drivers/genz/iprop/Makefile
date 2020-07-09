# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Gen-Z IntelliProp Orthus bridge driver.

obj-$(CONFIG_GENZ_ORTHUS)		+= orthus.o
orthus-objs += orthus-core.o
ccflags-y := -DEN_LINUX -DNO_DYNAMIC_ALLOC -DOHB_CONNECT -DXPAR_CPU_CORE_CLOCK_FREQ_HZ=1500000000 -DDEBUG_PRINT -DPACKET_RELAY_EN #-DIPROP_GZ_LOG_VERBOSITY=DEBUG -DIPROP_GZ_VERBOSE_ERRORS -DIPROP_GZ_EXTRA_VERBOSE_ERRORS

orthus-y := iprop_genz_page_grid_pte_util.o
