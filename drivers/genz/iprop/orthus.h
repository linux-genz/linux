// SPDX-License-Identifier: GPL-2.0
/*
 * IntelliProp Orthus Gen-Z Bridge Driver
 *
 * Author: Jim Hull <jim.hull@hpe.com>
 * Author: Jim Hull <jmhull@intelliprop.com>
 *
 * Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 * © Copyright 2021 IntelliProp Inc. All rights reserved.
 */

#ifndef _ORTHUS_H_
#define _ORTHUS_H_

#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/genz.h>

#include "iprop_genz_page_grid_pte_util.h" //for pte_cfg

enum iprop_genz_block_type {
	IPROP_GENZ_PHY,
	IPROP_GENZ_PHY_1,
	IPROP_GENZ_LINK_LAYER,
	IPROP_GENZ_LINK_LAYER_1,
	IPROP_GENZ_RAW_CB_LAYER,
	IPROP_GENZ_REQ_ZMMU,
	IPROP_GENZ_REQ_LAYER,
	IPROP_GENZ_SW_LAYER,
	IPROP_GENZ_PTE_TABLE,
	IPROP_GENZ_RAW_CB_TABLE,
	IPROP_BLOCK_CNT  /* must be last */
};

/* Revisit: fix these, or better yet, read values from HW/FW */
#define GB(_x)                      ((_x)*BIT_ULL(30))
#define NUM_CDMAS                   4

struct iprop_genz_phy {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
	void __iomem            *base;
	struct resource         res;
};

struct iprop_genz_link_layer {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
	void __iomem            *base;
	struct resource         res;
};

struct iprop_genz_raw_cb_layer {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
	void __iomem            *base;
	int                     irq;
	struct resource         res;
};

struct iprop_genz_req_zmmu {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
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

struct iprop_genz_req_layer {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
	void __iomem            *base;
	struct resource         res;
};

struct iprop_genz_sw_layer {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
	void __iomem            *base;
	struct resource         res;
};

struct iprop_genz_pte_table {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
	void __iomem            *base;
	struct resource         res;
};

struct iprop_genz_raw_cb_table {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
	void __iomem            *base;
	struct resource         res;
};

struct orthus_bridge {
	atomic_t                        block_cnt;
	struct iprop_genz_phy           phy_0;
	struct iprop_genz_link_layer    link_0;
	struct iprop_genz_phy           phy_1;
	struct iprop_genz_link_layer    link_1;
	struct iprop_genz_raw_cb_layer  raw_cb;
	struct iprop_genz_req_zmmu      req_zmmu;
	struct iprop_genz_req_layer     req_layer;
	struct iprop_genz_sw_layer      sw_layer;
	struct iprop_genz_raw_cb_table  raw_cb_table;
	struct iprop_genz_pte_table     pte_table;
	spinlock_t                      obr_lock;  /* global bridge lock */
	struct device                   *obr_dev;
	struct genz_bridge_dev          *gzbr;
};

struct iprop_block_data {
	int type;
	int (*block_probe)(struct platform_device *pdev,
			   struct orthus_bridge *obr);
	int (*block_remove)(struct platform_device *pdev,
			    struct orthus_bridge *obr);
};

int orthus_local_control_write(struct orthus_bridge *obr,
				      loff_t offset,
				      size_t size, void *data, uint flags);

int orthus_local_control_read(struct orthus_bridge *obr,
				     loff_t offset,
				     size_t size, void *data, uint flags);

static inline struct orthus_bridge *orthus_gzbr_to_obr(struct genz_bridge_dev *gzbr)
{
	struct orthus_bridge *obr = NULL;

	if (gzbr) {
		obr = genz_get_drvdata(&gzbr->zdev);
	}

	return obr;
}

#endif /* _ORTHUS_H_ */
