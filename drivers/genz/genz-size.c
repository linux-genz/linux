// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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
		pr_debug("genz_control_info is NULL\n");
		return -1;
	}
	/*
	 * The genz_control_info already read the structure header to
	 * get the size.
	 */
	return(ci->size);
}

ssize_t genz_route_control_table_size(struct genz_control_info *ci)
{
	/*
	 * The size of the Route Control Table is fixed as the size
	 * of the struct genz_route_control_table.
	 */
	return (sizeof(struct genz_route_control_table));
}

ssize_t genz_requester_vcat_table_size(struct genz_control_info *ci)
{
	uint32_t req_vcatsz;
	uint32_t entry_sz;
#define VCAT_REQ_ROWS	16
	struct genz_component_destination_table_structure cdt;
	int ret;
	
	if (ci == NULL) {
		pr_debug("genz_control_info is NULL\n");
		return -1;
	}

	/*
	 * The requester VCAT table contains 16 rows. Each row is
	 * K VCAT entries. A VCAT entry is 8 bytes. The number of
	 * entries (K) is found in the Component Destination Table
	 * Structure REQ-VCATSZ field
	 */
	 
	entry_sz = sizeof(struct genz_vcat_entry);
	pr_debug("genz_vcat_entry size is %u\n", entry_sz);

	/* Find the component destination table structure req_vcatsz field */
	if (ci->type != GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE) {
		pr_debug("expected ci->type to be GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE but it was 0x%x\n", ci->type);
		return -1;
	}

	/* Revisit: make a macro/inline for the read ci_read(struct genz_control_info *ci, ... */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->start, sizeof(cdt), &cdt, 0);
	if (ret) {
		pr_debug("control read of component destination table structure failed with %d\n",
			 ret);
		return -1;
	}
	req_vcatsz = cdt.req_vcatsz;
	pr_debug("cdt.req_vcatsz is %u\n", req_vcatsz);
	if (req_vcatsz == 0)
		req_vcatsz = 1 << 5; /* Spec says default is 2^5 */

	return(VCAT_REQ_ROWS * entry_sz * req_vcatsz);
}

ssize_t genz_responder_vcat_table_size(struct genz_control_info *ci)
{
	uint32_t rsp_vcatsz;
	uint32_t entry_sz;
	uint32_t max_vcs;
	struct genz_component_destination_table_structure cdt;
	int ret;
	
	if (ci == NULL) {
		pr_debug("genz_control_info is NULL\n");
		return -1;
	}

	/*
	 * The responder VCAT table contains N rows where N is the maximum
	 * number of provisioned VCs. Each row is K VCAT entries. A VCAT
	 * entry is 8 bytes. The number of  entries (K) is found in the
	 * Component Destination Table Structure RSP-VCATSZ field
	 */
	 
	entry_sz = sizeof(struct genz_vcat_entry);

	/* Find the component destination table structure req_vcatsz field */
	if (ci->type != GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE) {
		pr_debug("expected ci->type to be GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE but it was 0x%x\n", ci->type);
		return -1;
	}

	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->start, sizeof(cdt), &cdt, 0);
	if (ret) {
		pr_debug("control read of component destination table structure failed with %d\n",
			 ret);
		return -1;
	}
	rsp_vcatsz = cdt.rsp_vcatsz;
	if (rsp_vcatsz == 0)
		rsp_vcatsz = 1 << 5; /* Spec says default is 2^5 */

	/*
	 * Revisit: how to find maximum number of VCs supported on any
	 * Responder interface? Find the interface structures and use
	 * the max HVS field (highest VC Supported) field of all the
	 * interfaces. 
	 */
	max_vcs = 1;

	return(max_vcs * entry_sz * rsp_vcatsz);
}

ssize_t genz_rit_table_size(struct genz_control_info *ci)
{
	uint32_t rit_pad_size;
	uint32_t max_interface;
	uint32_t eim_size;
	uint32_t rit_size;
	int ret;
	struct genz_component_destination_table_structure cdt;
	struct genz_core_structure core;
	
	if (ci == NULL) {
		pr_debug("genz_control_info is NULL\n");
		return -1;
	}

	/*
	 * The RIT table contains N EIM (Egress Interface Masks).
	 * N is the rit_size field in the Component Destination Table
	 * Structure. Each EIM is I bits long where I is the Core Structure's
	 * Max Interface field. The Component Destination Table Structure's
	 * RIT Pad Size field is added to the EIM size to maintain integer
	 * 4-byte alignment.
	 */
	 
	/* Find the component destination table structure rit_pad_size field */
	if (ci->type != GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE) {
		pr_debug("expected ci->type to be GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE but it was 0x%x\n", ci->type);
		return -1;
	}

	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->start, sizeof(cdt), &cdt, 0);
	if (ret) {
		pr_debug("control read of component destination table structure failed with %d\n",
			 ret);
		return -1;
	}
	rit_pad_size = cdt.rit_pad_size;

	/* Find the core structure max_interface field */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			0, sizeof(core), &core, 0);
	if (ret) {
		pr_debug("control read of core structure failed with %d\n",
			 ret);
		return -1;
	}
	max_interface = core.max_interface;

	eim_size = (max_interface + rit_pad_size) / 8; /* bits to bytes */
	/* Revisit: check that eim_sz is 4-byte aligned */

	rit_size = cdt.rit_size;

	return (eim_size * rit_size);
}

ssize_t genz_ssdt_msdt_table_size(struct genz_control_info *ci)
{
	struct genz_component_destination_table_structure cdt;
	int ret;
	int num_rows = 0;
	int ssdt_msdt_row_size;

	if (ci == NULL) {
		pr_debug("genz_control_info is NULL\n");
		return -1;
	}

	/*
	 * The SSDT and MSDT tables contains K rows. Each row has
	 * N 4-byte route entries.
	 * The number of rows (K) is found in the Component
	 * Destination Table Structure SSDT Size or MSDT Size field
	 * (depending on the table type.)
	 * The size of rows (N) is found in the Component
	 * Destination Table Structure SSDT MSDT Row Size field.
	 */
	 
	/*
	 * Find the SSDT Size field and the SSDT MSDT Row Size field of
	 * the Component Destination Table Structure.
	 */
	if (ci->parent->type != GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE) {
		pr_debug("expected ci->type to be GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE but it was 0x%x\n", ci->parent->type);
		return -1;
	}

	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->parent->start, sizeof(cdt), &cdt, 0);
	if (ret) {
		pr_debug("control read of component destination table structure failed with %d\n",
			 ret);
		return -1;
	}
#define GENZ_SSDT_TABLE_OFFSET 0x20
#define GENZ_MSDT_TABLE_OFFSET 0x24
	if (ci->start == GENZ_SSDT_TABLE_OFFSET)
		num_rows = cdt.ssdt_size;
	else if (ci->start == GENZ_MSDT_TABLE_OFFSET)
		num_rows = cdt.msdt_size;
	else {
		pr_debug("unexpected offset does not match SSDT or MSDT 0x%lx\n", ci->start);
	}

	if (num_rows == 0)
		num_rows = 1 << 12; /* Spec says default is 2^12 */
	ssdt_msdt_row_size = cdt.ssdt_msdt_row_size;

	return (num_rows * ssdt_msdt_row_size);
}

ssize_t genz_c_access_r_key_size(struct genz_control_info *ci)
{
	ssize_t sz = 0;
	uint64_t num_entries;
	int ret;
	struct genz_component_c_access_structure c_access;

	if (ci == NULL) {
		pr_debug("genz_control_info is NULL\n");
		return 0;
	}
	if (ci->type != GENZ_COMPONENT_C_ACCESS_STRUCTURE) {
		pr_debug("expected Component C-Access Structure and got %d\n",
			ci->type);
		return 0;
	}
	/* Read the 40 bit C-Access Table Size field at offset 0x18 */
	/* Revisit: defines for the field size (5 bytes) and offset (0x18)? */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->start, sizeof(c_access), &c_access, 0);
	if (ret) {
		pr_debug("control read of c_access structure failed with %d\n",
			 ret);
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

ssize_t genz_oem_data_size(struct genz_control_info *ci)
{
	ssize_t sz;
	off_t oem_data_ptr;
	int ret;

	if (ci == NULL) {
		pr_debug("genz_control_info is NULL\n");
		return -1;
	}
	if (ci->type != GENZ_COMPONENT_MEDIA_STRUCTURE) {
		pr_debug("expected Component Media Structure and got %d\n",
			ci->type);
		return -1;
	}

	/* Read the 4 byte pointer to the OEM Data table at offset 0x90 */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->start+0x90, 4, &oem_data_ptr, 0);
	if (ret || !oem_data_ptr) {
		pr_debug("control read of OEM Data PTR failed with %d\n",
			 ret);
		return -1;
	}
	/* Read the table size in bytes from the first 2 bytes of the table */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			oem_data_ptr, 2, &sz, 0);
	if (ret) {
		pr_debug("control read of OEM Data table size failed with %d\n",
			 ret);
		return -1;
	}
	return sz;
}

ssize_t genz_elog_size(struct genz_control_info *ci)
{
	ssize_t sz;
	uint32_t num_entries;
	off_t elog_ptr;
	int ret;

	if (ci == NULL) {
		pr_debug("genz_control_info is NULL\n");
		return -1;
	}
	if (ci->type != GENZ_COMPONENT_ERROR_AND_SIGNAL_EVENT_STRUCTURE) {
		pr_debug("expected Component Error and Signal Event Structure and got %d\n",
			ci->type);
		return -1;
	}

	/* Read the 4 byte pointer to the Elog table at offset 0x14 */
	/* Revisit: add a macro/inline to call control_read more easily */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			ci->start+0x14, 4, &elog_ptr, 0);
	if (ret || !elog_ptr) {
		pr_debug("control read of ELog PTR failed with %d\n",
			 ret);
		return -1;
	}
	/* Read the table size in bytes from the first 2 bytes of the table */
	ret = ci->zdev->zbdev->zbdrv->control_read(ci->zdev,
			elog_ptr, 2, &num_entries, 0);
	if (ret) {
		pr_debug("control read of ELog table size failed with %d\n",
			 ret);
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

ssize_t genz_lprt_size(struct genz_control_info *ci)
{
	/* LPRT pointer is in the interface structure but the LPRT size is
	 * in the Component Switch structure. Use the driver interfaces
	 * to read the switch structure LPRT_size field (offset 0x10).
	 */
	return 0;
}

ssize_t genz_core_lpd_bdf_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_unreliable_multicast_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_tr_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_pa_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_service_uuid_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_ssod_msod_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_oem_data_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_re_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_media_log_table_size(struct genz_control_info *ci)
{
	return 0;
}


ssize_t genz_label_data_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_mcprt_msmcprt_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_c_access_r_key_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_image_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_firmware_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_page_grid_restricted_page_grid_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_pte_restricted_pte_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_pm_backup_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_sm_backup_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_vendor_defined_structure_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_c_access_l_p2p_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_resource_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_backup_mgmt_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_mvcat_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_opcode_set_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_opcode_set_uuid_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_ssap_mcap_msap_and_msmcap_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_type_1_interleave_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_reliable_multicast_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_vcat_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_lprt_mprt_table_size(struct genz_control_info *ci)
{
	return 0;
}

ssize_t genz_vendor_defined_with_uuid_structure_size(struct genz_control_info *ci)
{
	return 0;
}
