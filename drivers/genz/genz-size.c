// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2019-2020 Hewlett Packard Enterprise Development LP.
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
#include "genz-control.h"

ssize_t genz_control_structure_size(struct genz_control_info *ci)
{
	/*
	 * The genz_control_info already read the structure header to
	 * get the size.
	 */
	return ci->size;
}

ssize_t genz_route_control_table_size(struct genz_control_info *ci)
{
	/*
	 * The size of the Route Control Table is fixed as the size
	 * of the struct genz_route_control_table.
	 */
	return (sizeof(struct genz_route_control_table));
}

static uint32_t vcat_entry_sz(struct genz_control_info *ci,
			struct genz_component_destination_table_structure *cdt,
			struct genz_component_switch_structure *sw)
{
	uint32_t entry_sz = sizeof(struct genz_vcat_entry);
	loff_t rct_off = 0;
	struct genz_route_control_table rct;
	union genz_rc_cap_1 rc_cap1;
	int ret;

	/* Find the route control table PTR, from either cdt or sw */
	if (sw != NULL)
		rct_off = sw->route_control_ptr << 4;
	else if (cdt != NULL)
		rct_off = cdt->route_control_ptr << 4;

	/* Find the route control table hcs field */
	if (rct_off == 0) {
		pr_debug("route_control_ptr is NULL - assuming HCS==0");
		entry_sz = 4;
	} else {
		ret = genz_control_read(ci->zbdev,
				rct_off, sizeof(rct), &rct, ci->rmri, 0);
		if (ret) {
			pr_debug("control read of route control table failed with %d\n",
				 ret);
			entry_sz = 4;
		} else {
			rc_cap1.val = rct.rc_cap_1;
			if (rc_cap1.hcs_support == 0)
				entry_sz = 4;
		}
	}

	return entry_sz;
}

ssize_t genz_requester_vcat_table_size(struct genz_control_info *ci)
{
	uint32_t req_vcatsz;
	uint32_t entry_sz;
#define VCAT_REQ_ROWS	16
	struct genz_component_destination_table_structure cdt;
	struct genz_control_info *parent;
	int ret;

	parent = ci->parent;  /* Component Destination Table */

	/*
	 * The requester VCAT table contains 16 rows. Each row is
	 * K VCAT entries. A VCAT entry is either 4 or 8 bytes, depending
	 * on HCS. The number of entries (K) is found in the Component
	 * Destination Table Structure REQ-VCATSZ field.
	 */
	 
	/* Find the component destination table structure req_vcatsz field */
	if (parent->type != GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}

	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(cdt), &cdt, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component destination table structure failed with %d\n",
			 ret);
		return -1;
	}
	req_vcatsz = cdt.req_vcatsz;
	if (req_vcatsz == 0)
		req_vcatsz = BIT(5); /* Spec says 0 means 2^5 */

	/* Get the entry size based on the route control table hcs field */
	entry_sz = vcat_entry_sz(ci, &cdt, NULL);
	pr_debug("entry_sz=%u, req_vcatsz=%u\n", entry_sz, req_vcatsz);
	return(VCAT_REQ_ROWS * entry_sz * req_vcatsz);
}

static uint max_iface_hvs(struct genz_control_info *core)
{
	uint max_hvs = 0;
	struct genz_control_info *ci;
	struct genz_interface_structure iface;
	int ret;

	/*
	 * Find the interface structures and return the max
	 * HVS (highest VC Supported) field of all the interfaces.
	 */
	for (ci = genz_first_struct_of_type(core, GENZ_INTERFACE_STRUCTURE);
	     ci != NULL;
	     ci = genz_next_struct_of_type(ci, GENZ_INTERFACE_STRUCTURE)) {
		/* HVS is in the first 8 bytes, so only read that much */
		ret = genz_control_read(ci->zbdev, ci->start, 8, &iface,
					ci->rmri, 0);
		if (ret) {
			pr_debug("control read of interface HVS failed with %d\n",
				 ret);
			continue;  /* ignore this iface */
		}
		pr_debug("interface %u, hvs=%u\n", iface.interface_id, iface.hvs);
		max_hvs = max(max_hvs, (uint)iface.hvs);
	}
	return max_hvs;
}

ssize_t genz_responder_vcat_table_size(struct genz_control_info *ci)
{
	uint32_t rsp_vcatsz;
	uint32_t entry_sz;
	uint32_t num_vcs;
	struct genz_component_destination_table_structure cdt;
	struct genz_control_info *parent, *core;
	int ret;
	
	parent = ci->parent;   /* Component Destination Table */
	core = parent->parent; /* Core Structure */

	/*
	 * The responder VCAT table contains N rows where N is the maximum
	 * number of provisioned VCs. Each row is K VCAT entries. A VCAT
	 * entry is either 4 or 8 bytes, depending on HCS.
	 * The number of entries (K) is found in the
	 * Component Destination Table Structure RSP-VCATSZ field.
	 */
	 
	/* Find the component destination table structure rsp_vcatsz field */
	if (parent->type != GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}

	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(cdt), &cdt, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component destination table structure failed with %d\n",
			 ret);
		return -1;
	}
	rsp_vcatsz = cdt.rsp_vcatsz;
	if (rsp_vcatsz == 0)
		rsp_vcatsz = BIT(5); /* Spec says 0 means 2^5 */

	/* Get the entry size based on the route control table hcs field */
	entry_sz = vcat_entry_sz(ci, &cdt, NULL);

	num_vcs = max_iface_hvs(core) + 1;
	pr_debug("num_vcs=%u, entry_sz=%u, rsp_vcatsz=%u\n",
		 num_vcs, entry_sz, rsp_vcatsz);
	return (num_vcs * entry_sz * rsp_vcatsz);
}

static uint num_interfaces(struct genz_control_info *core_ci)
{
	uint num_ifaces;
	struct genz_core_structure core;
	int ret;

	/*
	 * Read the number of component interfaces from the Max Interface
	 * field of the Core Structure (which is misnamed - it is the
	 * number of interfaces, not the max).
	 */
	/* Max Interface is in the first 32 bytes, so only read that much */
	ret = genz_control_read(core_ci->zbdev, core_ci->start, 32, &core,
				core_ci->rmri, 0);
	if (ret) {
		pr_debug("control read of core Max Interface failed with %d\n",
			 ret);
		return 1;
	}
	num_ifaces = core.max_interface;
	if (num_ifaces == 0)
		num_ifaces = BIT(12);  /* Spec says 0 means 2^12 */
	pr_debug("num_ifaces=%d\n", num_ifaces);
	return num_ifaces;
}

ssize_t genz_rit_table_size(struct genz_control_info *ci)
{
	uint32_t rit_pad_size;
	uint32_t num_ifaces;
	uint32_t eim_size;
	uint32_t rit_size;
	int ret;
	struct genz_control_info *parent, *core_ci;
	struct genz_component_destination_table_structure cdt;
	
	parent = ci->parent;      /* Component Destination Table */
	core_ci = parent->parent; /* Core Structure */

	/*
	 * The RIT table contains N EIM (Egress Interface Masks).
	 * N is the rit_size field in the Component Destination Table
	 * Structure. Each EIM is I bits long where I is the Core Structure's
	 * Max Interface field. The Component Destination Table Structure's
	 * RIT Pad Size field is added to the EIM size to maintain integer
	 * 4-byte alignment.
	 */
	 
	/* Find the component destination table structure rit_pad_size field */
	if (parent->type != GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}

	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(cdt), &cdt, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component destination table structure failed with %d\n",
			 ret);
		return -1;
	}
	rit_pad_size = cdt.rit_pad_size;

	/* Get the core structure max_interface field */
	num_ifaces = num_interfaces(core_ci);

	eim_size = (num_ifaces + rit_pad_size) / 8; /* bits to bytes */
	/* Revisit: check that eim_sz is 4-byte aligned */

	rit_size = cdt.rit_size;
	pr_debug("eim_size=%u, rit_size=%u\n", eim_size, rit_size);
	return (eim_size * rit_size);
}

ssize_t genz_ssdt_msdt_table_size(struct genz_control_info *ci)
{
	struct genz_component_destination_table_structure cdt;
	struct genz_control_info *parent;
	int ret;
	int num_rows = 0;
	int row_size;

	parent = ci->parent;      /* Component Destination Table */

	/*
	 * The SSDT and MSDT tables contain K rows. Each row has
	 * N 4-byte route entries.
	 * The number of rows (K) is found in the Component
	 * Destination Table Structure SSDT Size or MSDT Size field
	 * (depending on the table type).
	 * The size of each row (in bytes) is found in the Component
	 * Destination Table Structure SSDT MSDT Row Size field.
	 */
	 
	/*
	 * Find the SSDT Size field and the SSDT MSDT Row Size field of
	 * the Component Destination Table Structure.
	 */
	if (parent->type != GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}

	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(cdt), &cdt, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component destination table structure failed with %d\n",
			 ret);
		return -1;
	}
#define GENZ_SSDT_TABLE_OFFSET 0x20
#define GENZ_MSDT_TABLE_OFFSET 0x24
	if (ci->csp->pointer_offset == GENZ_SSDT_TABLE_OFFSET) {
		num_rows = cdt.ssdt_size;
		if (num_rows == 0)
			num_rows = BIT(12); /* Spec says 0 means 2^12 */
	} else if (ci->csp->pointer_offset == GENZ_MSDT_TABLE_OFFSET) {
		num_rows = cdt.msdt_size;
		if (num_rows == 0)
			num_rows = BIT(16); /* Spec says 0 means 2^16 */
	} else {
		pr_debug("unexpected offset does not match SSDT or MSDT 0x%x\n", ci->csp->pointer_offset);
	}

	row_size = cdt.ssdt_msdt_row_size;
	pr_debug("num_rows=%u, row_size=%u\n", num_rows, row_size);
	return (num_rows * row_size);
}

/* common function for c_access_rkey/c_access_l_p2p */
static ssize_t genz_c_access_table_entries(struct genz_control_info *ci)
{
	uint64_t num_entries;
	int ret;
	struct genz_component_c_access_structure c_access;
	struct genz_control_info *parent;

	parent = ci->parent;      /* Component C-Access Structure */
	if (parent->type != GENZ_COMPONENT_C_ACCESS_STRUCTURE) {
		pr_debug("expected Component C-Access Structure and got %d\n",
			parent->type);
		return 0;
	}
	/* Read the C-Access Structure */
	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(c_access), &c_access, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of c_access structure failed with %d\n",
			 ret);
		return -1;
	}
	num_entries = c_access.c_access_table_size;
	if (num_entries == 0)
		num_entries = BIT(40); /* Spec says 0 means 2^40 */
	return num_entries;
}

ssize_t genz_c_access_r_key_table_size(struct genz_control_info *ci)
{
	ssize_t sz = genz_c_access_table_entries(ci);

	if (sz > 0) /* convert entries to bytes */
		sz *= sizeof(struct genz_c_access_r_key_table_array);
	return sz;
}

ssize_t genz_c_access_l_p2p_table_size(struct genz_control_info *ci)
{
	ssize_t sz = genz_c_access_table_entries(ci);

	sz = genz_c_access_table_entries(ci);
	return sz;  /* entries == bytes because sizeof(struct) is 1 */
}

ssize_t genz_oem_data_size(struct genz_control_info *ci)
{
	struct genz_oem_data_table odt;
	ssize_t sz;
	int ret;

	/* Read the table size in bytes from the table header */
	/* The size is in the first 8 bytes, so only read that much */
	ret = genz_control_read(ci->zbdev, ci->start, 8, &odt, ci->rmri, 0);
	if (ret) {
		pr_debug("control read of OEM Data table size failed with %d\n",
			 ret);
		return -1;
	}
	sz = odt.oem_data_size;
	if (sz == 0)
		sz = BIT(16); /* Spec says 0 means 2^16 */
	return sz;
}

ssize_t genz_elog_table_size(struct genz_control_info *ci)
{
	struct genz_elog_table elog;
	uint64_t num_entries;
	int ret;

	/* Read the Elog entries from the table header */
	ret = genz_control_read(ci->zbdev, ci->start,
				sizeof(elog), &elog, ci->rmri, 0);
	if (ret) {
		pr_debug("control read of ELog table size failed with %d\n",
			 ret);
		return -1;
	}
	num_entries = elog.elog_size;
	if (num_entries == 0)
		num_entries = BIT(16); /* Spec says 0 means 2^16 */
	/* Convert num_entries to bytes and add table header size */
	return (num_entries * sizeof(struct genz_component_error_elog_entry))
		+ sizeof(elog);
}

ssize_t genz_core_lpd_bdf_table_size(struct genz_control_info *ci)
{
	return sizeof(struct genz_core_lpd_bdf_table);
}

ssize_t genz_unreliable_multicast_table_size(struct genz_control_info *ci)
{
	uint32_t u_pad_size;
	uint32_t num_ifaces;
	uint32_t row_size;
	uint32_t cmt_size;
	struct genz_component_multicast_structure cms;
	struct genz_control_info *parent, *core_ci;
	int ret;

	parent = ci->parent;      /* Component Multicast Structure */
	core_ci = parent->parent; /* Core Structure */

	/*
	 * The CMT table contains N EM (Egress Masks), plus V & VC fields.
	 * N is the CMT Size field in the Component Multicast Structure.
	 * Each EM is I bits long where I is the Core Structure's
	 * Max Interface field. The Component Multicast Structure's
	 * U-Pad Size field is added to the EM size to maintain integer
	 * 4-byte alignment.
	 */

	/* Find the component multicast structure cmt_size field */
	if (parent->type != GENZ_COMPONENT_MULTICAST_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_MULTICAST_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}

	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(cms), &cms, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component multicast structure failed with %d\n",
			 ret);
		return -1;
	}
	u_pad_size = cms.u_pad_size;

	/* Get the core structure max_interface field */
	num_ifaces = num_interfaces(core_ci);

	row_size = (num_ifaces + u_pad_size + 6) / 8; /* bits to bytes */

	cmt_size = cms.cmt_size;
	if (cmt_size == 0)
		cmt_size = BIT(12);  /* Spec says 0 means 2^12 */
	pr_debug("row_size=%u, cmt_size=%u\n", row_size, cmt_size);
	return (row_size * cmt_size);
}

ssize_t genz_tr_table_size(struct genz_control_info *ci)
{
	struct genz_component_tr_structure tr;
	struct genz_control_info *parent;
	uint32_t tr_cnt;
	int ret;

	parent = ci->parent;      /* Component TR Structure */

	/* Find the component tr structure tr_table_size field */
	if (parent->type != GENZ_COMPONENT_TR_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_TR_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}

	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(tr), &tr, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component tr structure failed with %d\n",
			 ret);
		return -1;
	}
	tr_cnt = tr.tr_table_size;
	if (tr_cnt == 0)
		tr_cnt = BIT(16);  /* Spec says 0 means 2^16 */
	pr_debug("tr_cnt=%u\n", tr_cnt);
	return (tr_cnt * sizeof(struct genz_tr_table_array));
}

ssize_t genz_pa_table_size(struct genz_control_info *ci)
{
	uint64_t num_entries;
	int ret;
	struct genz_component_pa_structure pa;
	struct genz_control_info *parent;

	parent = ci->parent;      /* Component PA Structure */

	/* Read the Component PA Structure */
	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(pa), &pa, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of PA structure failed with %d\n", ret);
		return -1;
	}
	num_entries = pa.pa_size;
	if (num_entries == 0)
		num_entries = BIT(16); /* Spec says 0 means 2^16 */
	return (num_entries * sizeof(struct genz_pa_table_array));
}

ssize_t genz_service_uuid_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_ssod_msod_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_oem_data_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_re_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_media_log_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_label_data_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_image_table_size(struct genz_control_info *ci)
{
	struct genz_component_image_structure img;
	struct genz_control_info *parent;
	uint64_t img_cnt;
	int ret;

	parent = ci->parent;      /* Component Image Structure */

	/* Find the component image structure image_table_size field */
	if (parent->type != GENZ_COMPONENT_IMAGE_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_IMAGE_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}

	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(img), &img, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component image structure failed with %d\n",
			 ret);
		return -1;
	}
	img_cnt = img.image_table_size;
	if (img_cnt == 0)
		img_cnt = BIT(32);  /* Spec says 0 means 2^32 */
	pr_debug("img_cnt=%llu\n", img_cnt);
	return (img_cnt * sizeof(struct genz_image_table_array));
}

ssize_t genz_firmware_table_size(struct genz_control_info *ci)
{
	struct genz_component_firmware_structure fw;
	struct genz_control_info *parent;
	uint32_t fw_cnt;
	int ret;

	parent = ci->parent;      /* Component Firmware Structure */

	/* Find the component firmware structure fw_table_sz field */
	if (parent->type != GENZ_COMPONENT_FIRMWARE_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_FIRMWARE_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}

	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(fw), &fw, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component firmware structure failed with %d\n",
			 ret);
		return -1;
	}
	fw_cnt = fw.fw_table_sz;
	if (fw_cnt == 0)
		fw_cnt = BIT(8);  /* Spec says 0 means 2^8 */
	pr_debug("fw_cnt=%u\n", fw_cnt);
	return (fw_cnt * sizeof(struct genz_firmware_table_array));
}

ssize_t genz_page_grid_restricted_page_grid_table_size(
	struct genz_control_info *ci)
{
	uint64_t num_entries;
	int ret;
	struct genz_component_page_grid_structure pg;
	struct genz_control_info *parent;

	parent = ci->parent;      /* Component Page Grid Structure */

	/* Read the Component Page Grid Structure */
	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(pg), &pg, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of PG structure failed with %d\n", ret);
		return -1;
	}
	num_entries = pg.pg_table_sz;
	if (num_entries == 0)
		num_entries = BIT(8); /* Spec says 0 means 2^8 */
	pr_debug("num_entries=%llu\n", num_entries);
	return (num_entries *
		sizeof(struct genz_page_grid_restricted_page_grid_table_array));
}

ssize_t genz_pte_restricted_pte_table_size(struct genz_control_info *ci)
{
	uint64_t num_ptes;
	uint32_t pte_sz;
	int ret;
	struct genz_component_page_grid_structure pg;
	struct genz_control_info *parent;

	parent = ci->parent;      /* Component Page Grid Structure */

	/* Read the Component Page Grid Structure */
	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(pg), &pg, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of PG structure failed with %d\n", ret);
		return -1;
	}
	num_ptes = pg.pte_table_sz;
	if (num_ptes == 0)
		num_ptes = BIT(32); /* Spec says 0 means 2^32 */
	pte_sz = pg.pte_sz;
	if (pte_sz == 0)
		pte_sz = BIT(10); /* Spec says 0 means 2^10 */
	pte_sz /= 8;  /* bits to bytes */
	pr_debug("num_ptes=%llu, pte_sz=%u\n", num_ptes, pte_sz);
	return (num_ptes * pte_sz);
}

ssize_t genz_pm_backup_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_sm_backup_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_resource_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_backup_mgmt_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_mvcat_table_size(struct genz_control_info *ci)
{
	uint32_t num_entries;
	int ret;
	struct genz_component_switch_structure sw;
	struct genz_control_info *parent;

	parent = ci->parent;      /* Component Switch Structure */

	/* Read the Component Switch Structure */
	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(sw), &sw, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of switch structure failed with %d\n", ret);
		return -1;
	}
	num_entries = sw.mvcatsz;
	if (num_entries == 0)
		num_entries = BIT(5); /* Spec says 0 means 2^5 */
	pr_debug("num_entries=%u\n", num_entries);
	return (num_entries * sizeof(struct genz_mvcat_table_array));
}

ssize_t genz_opcode_set_table_size(struct genz_control_info *ci)
{
	return sizeof(struct genz_opcode_set_table);
}

ssize_t genz_opcode_set_uuid_table_size(struct genz_control_info *ci)
{
	return sizeof(struct genz_opcode_set_uuid_table);
}

ssize_t genz_ssap_mcap_msap_and_msmcap_table_size(struct genz_control_info *ci)
{
	uint32_t num_rows = 0;
	int ret;
	struct genz_control_info *parent;
	struct genz_component_pa_structure pa;

	parent = ci->parent;      /* Component PA Structure */

	/*
	 * The SSAP/MSAP/MCAP/MSMCAP tables contain N entries, where
	 * N is the corresponding size field in the Component PA
	 * Structure. Each entry is 4 bytes long.
	 */

	if (parent->type != GENZ_COMPONENT_PA_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_PA_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}

	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(pa), &pa, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component pa structure failed with %d\n",
			 ret);
		return -1;
	}
#define GENZ_SSAP_TABLE_OFFSET   0x20
#define GENZ_MSAP_TABLE_OFFSET   0x24
#define GENZ_MCAP_TABLE_OFFSET   0x28
#define GENZ_MSMCAP_TABLE_OFFSET 0x2c
	if (ci->csp->pointer_offset == GENZ_SSAP_TABLE_OFFSET) {
		num_rows = pa.ssap_size;
		if (num_rows == 0)
			num_rows = BIT(12); /* Spec says 0 means 2^12 */
	} else if (ci->csp->pointer_offset == GENZ_MSAP_TABLE_OFFSET) {
		num_rows = pa.msap_size;
		if (num_rows == 0)
			num_rows = BIT(28); /* Spec says 0 means 2^28 */
	} else if (ci->csp->pointer_offset == GENZ_MCAP_TABLE_OFFSET) {
		num_rows = pa.mcap_size;
		if (num_rows == 0)
			num_rows = BIT(12); /* Spec says 0 means 2^12 */
	} else if (ci->csp->pointer_offset == GENZ_MSMCAP_TABLE_OFFSET) {
		num_rows = pa.msmcap_size;
		if (num_rows == 0)
			num_rows = BIT(28); /* Spec says 0 means 2^28 */
	} else {
		pr_debug("unexpected offset does not match SSAP/MSAP/MCAP/MSMCAP 0x%x\n", ci->csp->pointer_offset);
	}

	pr_debug("num_rows=%u\n", num_rows);
	return (num_rows * 4);
}

ssize_t genz_type_1_interleave_table_size(struct genz_control_info *ci)
{
	uint32_t entries;
	uint32_t entry_sz;
	int ret;
	struct genz_component_interleave_structure ilv;
	struct genz_control_info *parent;

	parent = ci->parent;      /* Component Interleave Structure */

	/* Read the Component Interleave Structure */
	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(ilv), &ilv, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of interleave structure failed with %d\n", ret);
		return -1;
	}
	entries = ilv.max_it_entries;
	entry_sz = ilv.it_entry_size;
	if (entry_sz == 0)
		entry_sz = BIT(11); /* Spec says 0 means 2^11 */
	pr_debug("entries=%u, entry_sz=%u\n", entries, entry_sz);
	return (entries * entry_sz);
}

ssize_t genz_reliable_multicast_table_size(struct genz_control_info *ci)
{
	return 0;  /* Revisit: implement this */
}

ssize_t genz_vcat_table_size(struct genz_control_info *ci)
{
	uint32_t uvcatsz;
	uint32_t entry_sz;
	uint32_t num_vcs;
	struct genz_control_info *sw_ci, *parent, *core;
	struct genz_component_switch_structure sw;
	int ret;

	parent = ci->parent;   /* Interface Structure */
	core = parent->parent; /* Core Structure */

	/*
	 * The VCAT table contains N rows where N is the maximum
	 * number of provisioned VCs. Each row is K VCAT entries. A VCAT
	 * entry is either 4 or 8 bytes, depending on HCS.
	 * The number of entries (K) is found in the
	 * Component Switch Structure UVCATSZ field.
	 */
	/* for this to work, Switch must be processed before Interfaces */
	sw_ci = genz_first_struct_of_type(core, GENZ_COMPONENT_SWITCH_STRUCTURE);
	if (sw_ci == NULL) {
		pr_debug("have VCAT but no Component Switch Structure\n");
		return 0;
	}
	ret = genz_control_read(sw_ci->zbdev, sw_ci->start,
				sizeof(sw), &sw, sw_ci->rmri, 0);
	if (ret) {
		pr_debug("control read of component switch structure failed with %d\n",
			 ret);
		return -1;
	}
	uvcatsz = sw.uvcatsz;
	if (uvcatsz == 0)
		uvcatsz = BIT(5); /* Spec says 0 means 2^5 */

	/* Get the entry size based on the route control table hcs field */
	entry_sz = vcat_entry_sz(sw_ci, NULL, &sw);

	num_vcs = max_iface_hvs(core) + 1;
	pr_debug("num_vcs=%u, entry_sz=%u, uvcatsz=%u\n",
		 num_vcs, entry_sz, uvcatsz);
	return (num_vcs * entry_sz * uvcatsz);
}

ssize_t genz_lprt_mprt_table_size(struct genz_control_info *ci)
{
	struct genz_control_info *sw_ci, *parent, *core;
	struct genz_component_switch_structure sw;
	int ret;
	int num_rows = 0;
	int row_size;

	parent = ci->parent;   /* Interface Structure */
	core = parent->parent; /* Core Structure */

	/*
	 * The LPRT and MPRT tables contain K rows. Each row has
	 * N 4-byte route entries. The number of rows (K) is found in the
	 * Component Switch Structure LPRT Size or MPRT Size field
	 * (depending on the table type).
	 * The size of each row (in bytes) is found in the Component
	 * Switch Structure LPRT MPRT Row Size field.
	 */
	/* for this to work, Switch must be processed before Interfaces */
	sw_ci = genz_first_struct_of_type(core, GENZ_COMPONENT_SWITCH_STRUCTURE);
	if (sw_ci == NULL) {
		pr_debug("have LPRT/MPRT but no Component Switch Structure\n");
		return 0;
	}
	ret = genz_control_read(sw_ci->zbdev, sw_ci->start,
				sizeof(sw), &sw, sw_ci->rmri, 0);
	if (ret) {
		pr_debug("control read of component switch structure failed with %d\n",
			 ret);
		return -1;
	}
#define GENZ_LPRT_TABLE_OFFSET 0x94
#define GENZ_MPRT_TABLE_OFFSET 0x98
	if (ci->csp->pointer_offset == GENZ_LPRT_TABLE_OFFSET) {
		num_rows = sw.lprt_size;
		if (num_rows == 0)
			num_rows = BIT(12); /* Spec says 0 means 2^12 */
	} else if (ci->csp->pointer_offset == GENZ_MPRT_TABLE_OFFSET) {
		num_rows = sw.mprt_size;
		if (num_rows == 0)
			num_rows = BIT(16); /* Spec says 0 means 2^16 */
	} else {
		pr_debug("unexpected offset does not match LPRT or MPRT 0x%x\n", ci->csp->pointer_offset);
	}
	row_size = sw.lprt_mprt_row_size;
	pr_debug("num_rows=%u, row_size=%u\n", num_rows, row_size);
	return (num_rows * row_size);
}

ssize_t genz_mcprt_msmcprt_table_size(struct genz_control_info *ci)
{
	struct genz_control_info *parent;
	struct genz_component_switch_structure sw;
	int ret;
	int num_rows = 0;
	int row_size;

	parent = ci->parent;   /* Component Switch Structure */

	/*
	 * The MCPRT and MSMCPRT tables contain K rows. Each row has
	 * N 1-byte route entries. The number of rows (K) is found in the
	 * Component Switch Structure MCPRT Size or MSMCPRT Size field
	 * (depending on the table type).
	 * The size of each row (in bytes) is found in the Component
	 * Switch Structure MCPRT MSMCPRT Row Size field.
	 */
	if (parent->type != GENZ_COMPONENT_SWITCH_STRUCTURE) {
		pr_debug("expected parent->type to be GENZ_COMPONENT_SWITCH_STRUCTURE but it was 0x%x\n", parent->type);
		return -1;
	}
	ret = genz_control_read(parent->zbdev, parent->start,
				sizeof(sw), &sw, parent->rmri, 0);
	if (ret) {
		pr_debug("control read of component switch structure failed with %d\n",
			 ret);
		return -1;
	}
#define GENZ_MCPRT_TABLE_OFFSET 0x38
#define GENZ_MSMCPRT_TABLE_OFFSET 0x3c
	if (ci->csp->pointer_offset == GENZ_MCPRT_TABLE_OFFSET) {
		num_rows = sw.mcprt_size;
		if (num_rows == 0)
			num_rows = BIT(12); /* Spec says 0 means 2^12 */
	} else if (ci->csp->pointer_offset == GENZ_MSMCPRT_TABLE_OFFSET) {
		num_rows = sw.msmcprt_size;
		if (num_rows == 0)
			num_rows = BIT(28); /* Spec says 0 means 2^28 */
	} else {
		pr_debug("unexpected offset does not match MCPRT or MSMCPRT 0x%x\n", ci->csp->pointer_offset);
	}
	row_size = sw.mcprt_msmcprt_row_size;
	pr_debug("num_rows=%u, row_size=%u\n", num_rows, row_size);
	return (num_rows * row_size);
}
