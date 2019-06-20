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
//FIXME: ifdef here around kernel
#include <linux/kernel.h>
#include "genz-types.h"
#define YY 0  //FIXME

/* *************************************************************************** */

struct genz_control_structure_ptr core_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x48 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4c },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x50 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x54 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x58 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x5c },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x60 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x64 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x68 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x6c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x70 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x74 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x78 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x7c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x80 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x84 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x130 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x134 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x138 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x13c },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x140 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x146 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x14c },
};

struct genz_control_structure_ptr opcode_set_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr interface_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x70 },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x78 },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x7c },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x80 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x84 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x88 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr interface_phy_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x8 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr interface_statistics_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_error_and_signal_event_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x14 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_media_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0xc },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x74 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x78 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x7c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x80 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x84 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x88 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x90 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x94 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x98 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x9c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_switch_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x30 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x34 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x38 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x3c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_statistics_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x8 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_extension_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x10 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x14 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x24 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x28 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x2c },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x30 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x38 },
};

struct genz_control_structure_ptr component_multicast_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x24 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x28 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_security_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_tr_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_image_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x10 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x18 },
};

struct genz_control_structure_ptr component_precision_time_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x1c },
};

struct genz_control_structure_ptr component_mechanical_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_destination_table_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x24 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x28 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x2c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x30 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr service_uuid_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_c_access_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18, GENZ_C_ACCESS_R_KEY_TABLE, genz_c_access_r_key_size }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr requester_p2p_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x38 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x3c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_pa_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x24 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x28 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x2c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x34 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x48 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_lpd_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x54 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_sod_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x14 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr congestion_management_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_pm_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_re_table_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x10 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_6_BYTE_POINTER, 0x18 },
};

struct genz_control_structure_ptr component_lph_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x54 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x60 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_page_grid_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x24 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x28 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x2c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_page_table_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x34 },
};

struct genz_control_structure_ptr component_interleave_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4 },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_firmware_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr component_sw_management_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr c_cert_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x0 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, YY }, //FIXME: incorrec hex value! /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, -1 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr reliable_multicast_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x0 }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr opcode_set_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4 },
};

struct genz_control_structure_ptr elog_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4 },
};

struct genz_control_structure_ptr sec_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x0 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, YY }, //FIXME: incorrec hex value! /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr backup_mgmt_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x68 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x6c }, /* FIXME: Unknwon pointer type! */
};

struct genz_control_structure_ptr packet_relay_access_key_interface_structure_fields_optional_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x90 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x94 }, /* FIXME: Unknwon pointer type! */
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x98 }, /* FIXME: Unknwon pointer type! */
};


struct genz_control_ptr_info genz_control_structure_type_to_ptrs[] = {
    // { ptr_to_a_struct, ptr size, <struct vers="THIS VALUE">, size_of_struct }
    { core_structure_ptrs, sizeof(core_structure_ptrs)/sizeof(core_structure_ptrs[0]), sizeof(struct genz_core_structure), "core" },
    { opcode_set_structure_ptrs, sizeof(opcode_set_structure_ptrs)/sizeof(opcode_set_structure_ptrs[0]), sizeof(struct genz_opcode_set_structure), "opcode_set" },
    { interface_structure_ptrs, sizeof(interface_structure_ptrs)/sizeof(interface_structure_ptrs[0]), sizeof(struct genz_interface_structure), "interface" },
    { interface_phy_structure_ptrs, sizeof(interface_phy_structure_ptrs)/sizeof(interface_phy_structure_ptrs[0]), sizeof(struct genz_interface_phy_structure), "interface_phy" },
    { interface_statistics_structure_ptrs, sizeof(interface_statistics_structure_ptrs)/sizeof(interface_statistics_structure_ptrs[0]), sizeof(struct genz_interface_statistics_structure), "interface_statistics" },
    { component_error_and_signal_event_structure_ptrs, sizeof(component_error_and_signal_event_structure_ptrs)/sizeof(component_error_and_signal_event_structure_ptrs[0]), sizeof(struct genz_component_error_and_signal_event_structure), "component_error_and_signal_event" },
    { component_media_structure_ptrs, sizeof(component_media_structure_ptrs)/sizeof(component_media_structure_ptrs[0]), sizeof(struct genz_component_media_structure), "component_media" },
    { component_switch_structure_ptrs, sizeof(component_switch_structure_ptrs)/sizeof(component_switch_structure_ptrs[0]), sizeof(struct genz_component_switch_structure), "component_switch" },
    { component_statistics_structure_ptrs, sizeof(component_statistics_structure_ptrs)/sizeof(component_statistics_structure_ptrs[0]), sizeof(struct genz_component_statistics_structure), "component_statistics" },
    { component_extension_structure_ptrs, sizeof(component_extension_structure_ptrs)/sizeof(component_extension_structure_ptrs[0]), sizeof(struct genz_component_extension_structure), "component_extension" },
    { component_multicast_structure_ptrs, sizeof(component_multicast_structure_ptrs)/sizeof(component_multicast_structure_ptrs[0]), sizeof(struct genz_component_multicast_structure), "component_multicast" },
    { component_security_structure_ptrs, sizeof(component_security_structure_ptrs)/sizeof(component_security_structure_ptrs[0]), sizeof(struct genz_component_security_structure), "component_security" },
    { component_tr_structure_ptrs, sizeof(component_tr_structure_ptrs)/sizeof(component_tr_structure_ptrs[0]), sizeof(struct genz_component_tr_structure), "component_tr" },
    { component_image_structure_ptrs, sizeof(component_image_structure_ptrs)/sizeof(component_image_structure_ptrs[0]), sizeof(struct genz_component_image_structure), "component_image" },
    { component_precision_time_structure_ptrs, sizeof(component_precision_time_structure_ptrs)/sizeof(component_precision_time_structure_ptrs[0]), sizeof(struct genz_component_precision_time_structure), "component_precision_time" },
    { component_mechanical_structure_ptrs, sizeof(component_mechanical_structure_ptrs)/sizeof(component_mechanical_structure_ptrs[0]), sizeof(struct genz_component_mechanical_structure), "component_mechanical" },
    { component_destination_table_structure_ptrs, sizeof(component_destination_table_structure_ptrs)/sizeof(component_destination_table_structure_ptrs[0]), sizeof(struct genz_component_destination_table_structure), "component_destination_table" },
    { service_uuid_structure_ptrs, sizeof(service_uuid_structure_ptrs)/sizeof(service_uuid_structure_ptrs[0]), sizeof(struct genz_service_uuid_structure), "service_uuid" },
    { component_c_access_structure_ptrs, sizeof(component_c_access_structure_ptrs)/sizeof(component_c_access_structure_ptrs[0]), sizeof(struct genz_component_c_access_structure), "component_c_access" },
    { requester_p2p_structure_ptrs, sizeof(requester_p2p_structure_ptrs)/sizeof(requester_p2p_structure_ptrs[0]), sizeof(struct genz_requester_p2p_structure), "requester_p2p" },
    { component_pa_structure_ptrs, sizeof(component_pa_structure_ptrs)/sizeof(component_pa_structure_ptrs[0]), sizeof(struct genz_component_pa_structure), "component_pa" },
    { component_lpd_structure_ptrs, sizeof(component_lpd_structure_ptrs)/sizeof(component_lpd_structure_ptrs[0]), sizeof(struct genz_component_lpd_structure), "component_lpd" },
    { component_sod_structure_ptrs, sizeof(component_sod_structure_ptrs)/sizeof(component_sod_structure_ptrs[0]), sizeof(struct genz_component_sod_structure), "component_sod" },
    { congestion_management_structure_ptrs, sizeof(congestion_management_structure_ptrs)/sizeof(congestion_management_structure_ptrs[0]), sizeof(struct genz_congestion_management_structure), "congestion_management" },
    { component_pm_structure_ptrs, sizeof(component_pm_structure_ptrs)/sizeof(component_pm_structure_ptrs[0]), sizeof(struct genz_component_pm_structure), "component_pm" },
    { component_re_table_structure_ptrs, sizeof(component_re_table_structure_ptrs)/sizeof(component_re_table_structure_ptrs[0]), sizeof(struct genz_component_re_table_structure), "component_re_table" },
    { component_lph_structure_ptrs, sizeof(component_lph_structure_ptrs)/sizeof(component_lph_structure_ptrs[0]), sizeof(struct genz_component_lph_structure), "component_lph" },
    { component_page_grid_structure_ptrs, sizeof(component_page_grid_structure_ptrs)/sizeof(component_page_grid_structure_ptrs[0]), sizeof(struct genz_component_page_grid_structure), "component_page_grid" },
    { component_page_table_structure_ptrs, sizeof(component_page_table_structure_ptrs)/sizeof(component_page_table_structure_ptrs[0]), sizeof(struct genz_component_page_table_structure), "component_page_table" },
    { component_interleave_structure_ptrs, sizeof(component_interleave_structure_ptrs)/sizeof(component_interleave_structure_ptrs[0]), sizeof(struct genz_component_interleave_structure), "component_interleave" },
    { component_firmware_structure_ptrs, sizeof(component_firmware_structure_ptrs)/sizeof(component_firmware_structure_ptrs[0]), sizeof(struct genz_component_firmware_structure), "component_firmware" },
    { component_sw_management_structure_ptrs, sizeof(component_sw_management_structure_ptrs)/sizeof(component_sw_management_structure_ptrs[0]), sizeof(struct genz_component_sw_management_structure), "component_sw_management" },
    { c_cert_table_ptrs, sizeof(c_cert_table_ptrs)/sizeof(c_cert_table_ptrs[0]), sizeof(struct genz_c_cert_table), "c_cert_table_ptrs" },
    { reliable_multicast_table_ptrs, sizeof(reliable_multicast_table_ptrs)/sizeof(reliable_multicast_table_ptrs[0]), sizeof(struct genz_reliable_multicast_table), "reliable_multicast_table_ptrs" },
    { opcode_set_table_ptrs, sizeof(opcode_set_table_ptrs)/sizeof(opcode_set_table_ptrs[0]), sizeof(struct genz_opcode_set_table), "opcode_set_table_ptrs" },
    { elog_table_ptrs, sizeof(elog_table_ptrs)/sizeof(elog_table_ptrs[0]), sizeof(struct genz_elog_table), "log_table_ptrs" },
    { sec_table_ptrs, sizeof(sec_table_ptrs)/sizeof(sec_table_ptrs[0]), sizeof(struct genz_sec_table), "sec_table_ptrs" },
    { backup_mgmt_table_ptrs, sizeof(backup_mgmt_table_ptrs)/sizeof(backup_mgmt_table_ptrs[0]), sizeof(struct genz_backup_mgmt_table), "backup_mgmt_table_ptrs" },
    { packet_relay_access_key_interface_structure_fields_optional_ptrs, sizeof(packet_relay_access_key_interface_structure_fields_optional_ptrs)/sizeof(packet_relay_access_key_interface_structure_fields_optional_ptrs[0]), sizeof(struct genz_packet_relay_access_key_interface_structure_fields_optional), "packet_relay_access_key_interface" },
};


EXPORT_SYMBOL(genz_control_structure_type_to_ptrs);

size_t genz_control_structure_type_to_ptrs_nelems =
    sizeof(genz_control_structure_type_to_ptrs) /
    sizeof(genz_control_structure_type_to_ptrs[0]);

EXPORT_SYMBOL(genz_control_structure_type_to_ptrs_nelems);
