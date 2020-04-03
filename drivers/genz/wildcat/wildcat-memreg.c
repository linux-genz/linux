/*
 * Copyright (C) 2018-2019 Hewlett Packard Enterprise Development LP.
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
#include <linux/pci.h>
#include <linux/hugetlb.h>
#include <linux/sched/signal.h>
#include <linux/genz.h>

#include "wildcat.h"

/**
 * wildcat_dma_map_sg_attrs - Map a scatter/gather list to DMA addresses
 * @gzbr: The genz_bridge_dev for which the DMA addresses are to be created
 * @sg: The array of scatter/gather entries
 * @nents: The number of scatter/gather entries
 * @direction: The direction of the DMA
 * @dma_attrs: The DMA attributes
 */
int wildcat_dma_map_sg_attrs(
	struct genz_bridge_dev *gzbr, struct scatterlist *sg, int nents,
	enum dma_data_direction direction, unsigned long dma_attrs)
{
	int sl, ret = 0;
	unsigned long attrs = dma_attrs;
	struct bridge *br = wildcat_gzbr_to_br(gzbr);

	/* Revisit: add PASID support */
	for (sl = 0; sl < SLICES; sl++) {
		if (!SLICE_VALID(&br->slice[sl]))
			continue;
		ret = dma_map_sg_attrs(&br->slice[sl].pdev->dev, sg, nents,
				       direction, attrs);
		/* Revisit: handle ret > 0 but different amongst the slices? */
		if (ret <= 0) {
			while (--sl >= 0)  /* undo the ones we already did */
				dma_unmap_sg_attrs(&br->slice[sl].pdev->dev, sg,
						   nents, direction, attrs);
			break;
		}
	}

	return ret;
}

/**
 * wildcat_dma_unmap_sg_attrs - Unmap a scatter/gather list of DMA addresses
 * @gzbr: The genz_bridge_dev for which the DMA addresses were created
 * @sg: The array of scatter/gather entries
 * @nents: The number of scatter/gather entries
 * @direction: The direction of the DMA
 * @dma_attrs: The DMA attributes
 */
void wildcat_dma_unmap_sg_attrs(
	struct genz_bridge_dev *gzbr, struct scatterlist *sg, int nents,
	enum dma_data_direction direction, unsigned long dma_attrs)
{
	int sl;
	struct bridge *br = wildcat_gzbr_to_br(gzbr);

	for (sl = 0; sl < SLICES; sl++)
		if (SLICE_VALID(&br->slice[sl]))
			dma_unmap_sg_attrs(&br->slice[sl].pdev->dev, sg,
					   nents, direction, dma_attrs);
}
