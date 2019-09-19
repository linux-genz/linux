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
#include <linux/module.h>
#include "genz.h"

ssize_t genz_control_structure_size(struct genz_control_info *ci)
{
	if (ci == NULL) {
		pr_debug("%s: genz_control_info is NULL\n", __func__);
		return 0;
	}
	/*
	 * The genz_control_info already read the structure header to 
	 * get the size.
	 */
	return(ci->size);
}
EXPORT_SYMBOL_GPL(genz_control_structure_size);

ssize_t genz_c_access_r_key_size(struct genz_control_info *ci)
{
	ssize_t sz = 0;
	uint64_t num_entries;
	int ret;
	struct genz_component_c_access_structure c_access;

	if (ci == NULL) {
		pr_debug("%s: genz_control_info is NULL\n", __func__);
		return 0;
	}
	if (ci->type != GENZ_COMPONENT_C_ACCESS_STRUCTURE) {
		pr_debug("%s: expected Component C-Access Structure and got %d\n",
			__func__, ci->type);
		return 0;
	}
	/* Read the 40 bit C-Access Table Size field at offset 0x18 */
	/* Revisit: defines for the field size (5 bytes) and offset (0x18)? */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->start, sizeof(c_access), &c_access, 0);
	if (ret) {
                pr_debug("%s: control read of c_access structure failed with %d\n",
                        __func__, ret);
                return -1;
	}
	num_entries = c_access.c_access_table_size;
	if (num_entries == 0) {
		/* If C-Access Table Size is 0 then the size is 2^40 */
		num_entries = (uint64_t)BIT(40);
	}
	/*
	 * The num_entries is not the number of bytes in the table. In
	 * this case, each table entry is 8 bytes.
	 * Revisit: use a define for 8 bytes/entry? Use sizeof(struct <XXX>_entry
	 */
	sz = num_entries * 8;
	return(sz);
}
EXPORT_SYMBOL_GPL(genz_c_access_r_key_size);

ssize_t genz_oem_data_size(struct genz_control_info *ci)
{
	ssize_t sz;
	off_t oem_data_ptr;
	int ret;

	if (ci == NULL) {
		pr_debug("%s: genz_control_info is NULL\n", __func__);
		return -1;
	}
	if (ci->type != GENZ_COMPONENT_MEDIA_STRUCTURE) {
		pr_debug("%s: expected Component Media Structure and got %d\n",
			__func__, ci->type);
		return -1;
	}

	/* Read the 4 byte pointer to the OEM Data table at offset 0x90 */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->start+0x90, 4, &oem_data_ptr, 0);
	if (ret || !oem_data_ptr) {
                pr_debug("%s: control read of OEM Data PTR failed with %d\n",
                        __func__, ret);
                return -1;
	}
	/* Read the table size in bytes from the first 2 bytes of the table */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			oem_data_ptr, 2, &sz, 0);
	if (ret) {
                pr_debug("%s: control read of OEM Data table size failed with %d\n",
                        __func__, ret);
                return -1;
	}
	return sz;
}
EXPORT_SYMBOL_GPL(genz_oem_data_size);

ssize_t genz_elog_size(struct genz_control_info *ci)
{
	ssize_t sz;
	uint32_t num_entries;
	off_t elog_ptr;
	int ret;

	if (ci == NULL) {
		pr_debug("%s: genz_control_info is NULL\n", __func__);
		return -1;
	}
	if (ci->type != GENZ_COMPONENT_ERROR_AND_SIGNAL_EVENT_STRUCTURE) {
		pr_debug("%s: expected Component Error and Signal Event Structure and got %d\n",
			__func__, ci->type);
		return -1;
	}

	/* Read the 4 byte pointer to the Elog table at offset 0x14 */
	/* Revisit: add a macro/inline to call control_read more easily */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->start+0x14, 4, &elog_ptr, 0);
	if (ret || !elog_ptr) {
                pr_debug("%s: control read of ELog PTR failed with %d\n",
                        __func__, ret);
                return -1;
	}
	/* Read the table size in bytes from the first 2 bytes of the table */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			elog_ptr, 2, &num_entries, 0);
	if (ret) {
                pr_debug("%s: control read of ELog table size failed with %d\n",
                        __func__, ret);
                return -1;
	}
	if (num_entries == 0) {
		/* If ELog Table Size is 0 then the size is 2^16 */
		num_entries = (uint32_t)BIT(16);
	}
	/*
	 * The num_entries is not the number of bytes in the table. In
	 * this case, each table entry is 8 bytes. Add the 8 byte header
	 * to the size of the overall table.
	 * Revisit: use a define for 8 bytes/entry?
	 */
	sz = (num_entries * 8) + 8;
	return(sz);
}
EXPORT_SYMBOL_GPL(genz_elog_size);

ssize_t genz_lprt_size(struct genz_control_info *ci)
{
	/* LPRT pointer is in the interface structure but the LPRT size is
	 * in the Component Switch structure. Use the driver interfaces
	 * to read the switch structure LPRT_size field (offset 0x10).
	 */
	return 0;
}
