// SPDX-License-Identifier: GPL-2.0
/*
 * IntelliProp Orthus Gen-Z Bridge Driver
 *
 * Author: Jim Hull <jim.hull@hpe.com>
 *
 * Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 */

#ifndef _ORTHUS_H_
#define _ORTHUS_H_

#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

enum iprop_genz_block_type {
	IPROP_GENZ_PHY,
	IPROP_GENZ_LINK_LAYER,
	IPROP_GENZ_RAW_CB_LAYER,
	IPROP_GENZ_REQ_ZMMU,
	IPROP_GENZ_REQ_LAYER,
	IPROP_GENZ_THIN_SW_LAYER,
	IPROP_BLOCK_CNT  /* must be last */
};

/* Revisit: fix these, or better yet, read values from HW/FW */
#define GB(_x)                      ((_x)*BIT_ULL(30))
#define ORTHUS_PAGE_GRID_ENTRIES    32
#define ORTHUS_REQ_ZMMU_ENTRIES     1024
#define ORTHUS_MIN_CPUVISIBLE_ADDR  GB(6)
#define ORTHUS_MAX_CPUVISIBLE_ADDR  GB(250)

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
	struct resource         res;
};

struct iprop_genz_req_layer {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
	void __iomem            *base;
	struct resource         res;
};

struct iprop_genz_thin_sw_layer {
	struct device           *dev;
	struct clk_bulk_data    *clks;
	int                     num_clks;
	void __iomem            *base;
	struct resource         res;
};

struct orthus_bridge {
	atomic_t                        block_cnt;
	struct iprop_genz_phy           phy;
	struct iprop_genz_link_layer    link;
	struct iprop_genz_raw_cb_layer  raw_cb;
	struct iprop_genz_req_zmmu      req_zmmu;
	struct iprop_genz_req_layer     req_layer;
	struct iprop_genz_thin_sw_layer thin_sw_layer;
	spinlock_t                      obr_lock;  /* global bridge lock */
	struct device                   *obr_dev;
	/* Revisit: finish this */
};

struct iprop_block_data {
	int type;
	int (*block_probe)(struct platform_device *pdev,
			   struct orthus_bridge *obr);
	int (*block_remove)(struct platform_device *pdev,
			    struct orthus_bridge *obr);
};

static inline struct orthus_bridge *orthus_gzbr_to_obr(struct genz_bridge_dev *gzbr)
{
	struct orthus_bridge *obr = NULL;

	if (gzbr) {
		obr = genz_get_drvdata(&gzbr->zdev);
	}

	return obr;
}

#endif /* _ORTHUS_H_ */
