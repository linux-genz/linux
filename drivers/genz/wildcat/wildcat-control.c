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
#define WILDCAT_DVSEC_SLINK_BASE_OFF (0x40)

uint64_t wildcat_slink_base(struct bridge *br)
{
	struct slice        *sl = &br->slice[0];
	int                 pos;
	uint32_t            val;
	uint64_t            slink_base = 0;

	pos = pci_find_ext_capability(sl->pdev, PCI_EXT_CAP_ID_DVSEC);
	if (!pos)
		goto out;
	pci_read_config_dword(sl->pdev, pos + WILDCAT_DVSEC_SLINK_BASE_OFF,
			      &val);
	/* S-link base is in GiB */
	slink_base = GB((uint64_t)val);
out:
	return slink_base;
}


/*
 * Revisit: the PF FPGA has the wrong size for the structures
 * and the dvsec.pl command cannot write the value. This is a
 * workaround to intercept the read of the interface and interface
 * statistics structure headers and return the correct size/vers/type.
 */
struct wildcat_quirk {
	loff_t offset;
	uint64_t value;
};

static struct wildcat_quirk quirks[] = {
	{ 0x100000, 0x0000000000031001},
	{ 0x1C0000, 0x00003001000a0002},
	{ 0x1C0100, 0x00003001000a0002},
	{ 0x200000, 0x00010002002d0004},
	{ 0x201000, 0x00010002002d0004},
};

static int wildcat_is_quirk_offset(loff_t offset, uint64_t *data) {
	int i;
	int num_quirks = sizeof(quirks)/sizeof(quirks[0]);

	for (i = 0; i < num_quirks; i++) {
		if (quirks[i].offset == offset) {
			*data = quirks[i].value;
			return 1;
		}
	}
	return 0;
}

static int csr_access_rd(struct bridge *br, uint32_t csr, uint64_t *data)
{
	int                 ret = -EIO;
	struct slice        *sl = &br->slice[0];
	int                 pos;
	uint32_t            val, val_lo, val_hi;
	int                 i;

	if (wildcat_is_quirk_offset(csr, data)) {
		return 0;
	}

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

static struct genz_control_structure_ptr wildcat_interface_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x60, GENZ_INTERFACE_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x68, GENZ_UNKNOWN_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x6c, GENZ_UNKNOWN_STRUCTURE },
    /*
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x70, GENZ_INTERFACE_PHY_STRUCTURE },
    */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x74, GENZ_INTERFACE_STATISTICS_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x78, GENZ_COMPONENT_MECHANICAL_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x7c, GENZ_VENDOR_DEFINED_STRUCTURE },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x80, GENZ_VCAT_TABLE },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x84, GENZ_LPRT_MPRT_TABLE },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x88, GENZ_LPRT_MPRT_TABLE },
};

struct genz_control_structure_ptr wildcat_interface_statistics_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8, GENZ_VENDOR_DEFINED_STRUCTURE },
};

static struct genz_control_ptr_info wildcat_struct_type_to_ptrs[] = {
     {},
     {},
     { wildcat_interface_structure_ptrs, sizeof(wildcat_interface_structure_ptrs)/sizeof(wildcat_interface_structure_ptrs[0]), sizeof(struct genz_interface_structure), true, 0x0, "interface" },
     {},
     { wildcat_interface_statistics_structure_ptrs, sizeof(wildcat_interface_statistics_structure_ptrs)/sizeof(wildcat_interface_statistics_structure_ptrs[0]), sizeof(struct genz_interface_statistics_structure), false, 0x0, "interface_statistics" },
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
     {},
};

int wildcat_control_structure_pointers(int vers, int struct_type,
			const struct genz_control_structure_ptr **csp,
			int *num_ptrs)
{
	/* Is there a wildcat specific genz_control_structure_ptr? */
	if (!wildcat_struct_type_to_ptrs[struct_type].ptr)
		return -ENOENT;
	/* Does its version match the one we are lookig for? */
	if (wildcat_struct_type_to_ptrs[struct_type].vers != vers)
		return -ENOENT;
	*csp = wildcat_struct_type_to_ptrs[struct_type].ptr;
	*num_ptrs = wildcat_struct_type_to_ptrs[struct_type].num_ptrs;
	return 0;
}
