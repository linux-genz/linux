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
#include "genz.h"

int genz_alloc_queues(struct genz_bridge_dev *br,
		      struct genz_xdm_info *xdmi, struct genz_rdm_info *rdmi)
{
	if (!br || (xdmi && xdmi->cmdq_ent < 1) ||
	    (xdmi && xdmi->cmplq_ent < 1) ||
	    (rdmi && rdmi->cmplq_ent < 1)) {
		return -EINVAL;
	}

	/* Set up the "generic" XDM info */
	if (xdmi) {
		xdmi->br = br;
		spin_lock_init(&xdmi->xdm_info_lock);
	}

	/* Set up the "generic" RDM info */
	if (rdmi) {
		rdmi->br = br;
		spin_lock_init(&rdmi->rdm_info_lock);
	}

	/* Call bridge driver to do any bridge-specific work */
	return br->zbdrv->alloc_queues(br, xdmi, rdmi);
}
EXPORT_SYMBOL(genz_alloc_queues);

int genz_free_queues(struct genz_xdm_info *xdmi, struct genz_rdm_info *rdmi)
{
	struct genz_bridge_dev *br;
	int ret;

	if (!xdmi && !rdmi)
		return -EINVAL;
	if (xdmi && rdmi && xdmi->br != rdmi->br)
		return -EINVAL;

	br = (xdmi) ? xdmi->br : rdmi->br;

	/* Revisit: finish this */
	ret = br->zbdrv->free_queues(xdmi, rdmi);

	return ret;
}
EXPORT_SYMBOL(genz_free_queues);

int genz_sgl_request(struct genz_dev *zdev, struct genz_sgl_info *sgli)
{
	struct genz_bridge_dev *zbr = zdev->zbdev;

	if (!zbr || !zbr->zbdrv || !zbr->zbdrv->sgl_request)
		return -EOPNOTSUPP;

	return zbr->zbdrv->sgl_request(zdev, sgli);
}
EXPORT_SYMBOL(genz_sgl_request);
