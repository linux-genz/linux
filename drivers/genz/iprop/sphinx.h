// SPDX-License-Identifier: GPL-2.0
/*
 * IntelliProp Sphinx CXL to Gen-Z Bridge Driver
 *
 * Author: Jim Hull <jim.hull@hpe.com>
 * Author: Jim Hull <jmhull@intelliprop.com>
 *
 * Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 * © Copyright 2021 IntelliProp Inc. All rights reserved.
 */

#ifndef _SPHINX_H_
#define _SPHINX_H_

#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/genz.h>

#include "iprop_genz_page_grid_pte_util.h" //for pte_cfg

struct iprop_genz_req_zmmu {
	void __iomem            *base;
	loff_t                  pg_base_offset;  /* control space offset */
	loff_t                  pte_base_offset; /* control space offset */
	struct genz_reqr_pte_config pte_cfg;     /* for pte info */
	uint16_t                pte_sz;          /* in bits */
	uint64_t                num_pgs;         /* number of page grids */
	uint64_t                num_ptes;        /* number of PTEs */
	struct resource         res;     /* local control space */
	struct resource         cpu_res; /* cpu-visible space */
};

struct sphinx_bridge {
	spinlock_t                      sbr_lock;  /* global bridge lock */
	struct device                   *sbr_dev;
	struct pci_dev                  *pdev;
	struct genz_bridge_dev          *gzbr;
	void __iomem                    *bar;
	size_t                          bar_size;
	phys_addr_t                     phys_base;
	struct iprop_genz_req_zmmu      req_zmmu;
	bool                            valid;
	/* Revisit: finish this */
};

static inline struct sphinx_bridge *sphinx_gzbr_to_sbr(struct genz_bridge_dev *gzbr)
{
	struct sphinx_bridge *sbr = NULL;

	if (gzbr) {
		sbr = genz_get_drvdata(&gzbr->zdev);
	}

	return sbr;
}

static inline struct sphinx_bridge *sphinx_pdev_to_sbr(struct pci_dev *pdev)
{
	struct sphinx_bridge *sbr = NULL;

	if (pdev) {
		sbr = pci_get_drvdata(pdev);
	}

	return sbr;
}

#endif /* _SPHINX_H_ */
