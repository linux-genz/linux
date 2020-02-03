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

#include <linux/genz.h>
#include <linux/delay.h>

#include "wildcat.h"

#ifndef PCI_EXT_CAP_ID_DVSEC
#define PCI_EXT_CAP_ID_DVSEC 0x23  /* Revisit: should be in pci.h */
#endif

#define WILDCAT_DVSEC_MBOX_CTRL_OFF  (0x30)
#define WILDCAT_DVSEC_MBOX_CTRL_TRIG (0x1)
#define WILDCAT_DVSEC_MBOX_CTRL_BE   (0xFF00)
#define WILDCAT_DVSEC_MBOX_CTRL_ERR  (0x4)
#define WILDCAT_DVSEC_MBOX_ADDR_OFF  (0x34)
#define WILDCAT_DVSEC_MBOX_DATAL_OFF (0x38)
#define WILDCAT_DVSEC_MBOX_DATAH_OFF (0x3C)

static int csr_access_rd(struct bridge *br, uint32_t csr, uint64_t *data)
{
	int                 ret = -EIO;
	struct slice        *sl = &br->slice[0];
	int                 pos;
	uint32_t            val, val_lo, val_hi;
	int                 i;

	/* caller must hold br->csr_mutex */
	pos = pci_find_ext_capability(sl->pdev, PCI_EXT_CAP_ID_DVSEC);
	if (!pos) {
		pr_debug("pci_find_ext_capability failed\n");
		goto out;
	}
	pci_read_config_dword(sl->pdev, pos + WILDCAT_DVSEC_MBOX_CTRL_OFF,
			      &val);
	if (val & WILDCAT_DVSEC_MBOX_CTRL_TRIG) {
		pr_debug("mailbox busy\n");
		goto out;
	}
	pci_write_config_dword(sl->pdev, pos + WILDCAT_DVSEC_MBOX_ADDR_OFF,
			       csr);
	pci_write_config_dword(sl->pdev, pos + WILDCAT_DVSEC_MBOX_CTRL_OFF,
			       WILDCAT_DVSEC_MBOX_CTRL_BE |
			       WILDCAT_DVSEC_MBOX_CTRL_TRIG);
	/* Wait up to 1-2 ms for completion. */
	for (i = 0; i < 100; i++) {
		pci_read_config_dword(
			sl->pdev, pos + WILDCAT_DVSEC_MBOX_CTRL_OFF, &val);
		pr_debug("val=0x%x, loops=%d\n", val, i);
		if (!(val & WILDCAT_DVSEC_MBOX_CTRL_TRIG)) {
			if (val & WILDCAT_DVSEC_MBOX_CTRL_ERR) {
				pr_debug("WILDCAT_DVSEC_MBOX_CTRL_ERR set\n");
				break;
			}
			/* Success */
			ret = 0;
			pci_read_config_dword(
				sl->pdev, pos + WILDCAT_DVSEC_MBOX_DATAL_OFF,
					      &val_lo);
			pci_read_config_dword(
				sl->pdev, pos + WILDCAT_DVSEC_MBOX_DATAH_OFF,
					      &val_hi);
			*data = (((uint64_t)val_hi) << 32) | (uint64_t)val_lo;
			break;
		}
		usleep_range(10, 20);
	}

 out:
	return ret;
}

int wildcat_control_read(struct genz_dev *zdev, loff_t offset, size_t size,
			 void *data, uint flags)
{
	struct genz_bridge_dev *gzbr;
	struct bridge          *br;
	uint64_t               csr_val = 0, val;
	uint32_t               csr = (uint32_t)offset & ~7u;
	uint                   csr_align = (uint)offset & 7u;
	uint                   shift;
	ssize_t                write;
	int                    ret = 0;

	if (!zdev_is_local_bridge(zdev)) { /* no in-band fabric mgmt */
		ret = -ENODEV;
		goto out;
	}
	/* Revisit: only Core Structure for now 
	else if (offset >= 0x200) { 
		ret = -EPERM;
		goto out;
	}
	*/

	gzbr = zdev->zbdev;
	br = wildcat_gzbr_to_br(gzbr);

	/* wildcat control space accessible only with 8-byte size & alignment */
	shift = csr_align * 8;                       /* 0 - 56 */
	write = min((size_t)(8 - csr_align), size);  /* 1 - 8 */

	dev_dbg(&zdev->dev, "zdev=%px, br=%px, offset=0x%llx, size=%lu, shift=%u, write=%ld, csr=0x%x\n",
		zdev, br, offset, size, shift, write, csr);
	while (size > 0) {
		/* Revisit: lock optimization */
		mutex_lock(&br->csr_mutex);
		ret = csr_access_rd(br, csr, &csr_val);
		mutex_unlock(&br->csr_mutex);
		dev_dbg(&zdev->dev, "ret=%d, csr=0x%x, csr_val=0x%llx shifted val = 0x%llx size = %lu\n",
			ret, csr, csr_val, csr_val >> shift, size);
		if (ret < 0)
			goto out;
		if (csr >= 0xD0 && csr <= 0x140)
			csr_val = 0;
		val = csr_val >> shift;
		/* Revisit: endianness */
		memcpy(data, &val, write);
		size -= write;
		data += write;
		write = min((size_t)8, size);
		shift = 0;
		csr += 8;
	}

out:
	pr_debug("returning ret = %d val = 0x%llx\n", ret, val);
	return ret;
}

int wildcat_control_write(struct genz_dev *zdev, loff_t offset, size_t size,
			  void *data, uint flags)
{
	/* Revisit: implement this */
	return -ENOSYS;
}
