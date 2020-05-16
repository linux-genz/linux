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
 /*
 * This file is machine generated in conjunction with the .h file based of XML
 * GenZ Specs.
 *
 * XML file meta based of which this file was generated:
 *     Version   : N/A
 *     Date      : 2020-03-09 15:27:23.558578
 *     ctl_file  : gen-z-spec-control.vsdx
 *     pkt_file  : gen-z-spec-protocol.vsdx
 *     word_file : gen-z-core-specification-v1.1.docx
 *
 * Generator Script Meta:
 *     Version      : v0.8
 *     Generated On : 2020-05-13 13:10:39.213746
 */
#include <linux/kernel.h>
#include <linux/genz-types.h>

struct genz_hardware_classes genz_hardware_classes[] = {
     { "Reserved—shall not be used",                           "reserved_shall_not_be_used", GENZ_RESERVED_SHALL_NOT_BE_USED },
     { "Memory ( P2P 64 )",                                    "memory", GENZ_MEMORY },
     { "Memory (Explicit OpClass)",                            "memory", GENZ_MEMORY },
     { "Integrated Switch",                                    "switch", GENZ_SWITCH },
     { "Enclosure / Expansion Switch",                         "switch", GENZ_SWITCH },
     { "Fabric Switch",                                        "switch", GENZ_SWITCH },
     { "Processor (Bootable)",                                 "processor", GENZ_PROCESSOR },
     { "Processor (Non-boot)",                                 "processor", GENZ_PROCESSOR },
     { "Accelerator (Non-coherent, non-boot)",                 "accelerator", GENZ_ACCELERATOR },
     { "Accelerator (Coherent, non-boot)",                     "accelerator", GENZ_ACCELERATOR },
     { "Accelerator (Non-coherent, bootable)",                 "accelerator", GENZ_ACCELERATOR },
     { "Accelerator (Coherent, bootable)",                     "accelerator", GENZ_ACCELERATOR },
     { "I/O (Non-coherent, non-boot)",                         "io", GENZ_IO },
     { "I/O (Coherent, non-boot)",                             "io", GENZ_IO },
     { "I/O (Non-coherent, bootable)",                         "io", GENZ_IO },
     { "I/O (Coherent, bootable)",                             "io", GENZ_IO },
     { "Block Storage (Bootable)",                             "block_storage", GENZ_BLOCK_STORAGE },
     { "Block Storage (Non-boot)",                             "block_storage", GENZ_BLOCK_STORAGE },
     { "Transparent Router",                                   "transparent_router", GENZ_TRANSPARENT_ROUTER },
     { "Multi-class Component (see  Service UUID Structure )", "multiclass_component", GENZ_MULTICLASS_COMPONENT },
     { "Discrete Gen-Z Bridge",                                "bridge", GENZ_BRIDGE },
     { "Integrated Gen-Z Bridge",                              "bridge", GENZ_BRIDGE },
     { "Compliance Test Board",                                "compliance_test_board", GENZ_COMPLIANCE_TEST_BOARD },
     { "Logical PCIe Hierarchy (LPH)",                         "logical_pcie_hierarchy", GENZ_LOGICAL_PCIE_HIERARCHY },
};

struct genz_control_structure_ptr core_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x48, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4c, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x50, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x54, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x58, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x5c, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x60, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x64, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x68, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x6c, GENZ_CORE_LPD_BDF_TABLE, "core_lpd_bdf_table", genz_core_lpd_bdf_table_size },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x70, GENZ_OPCODE_SET_STRUCTURE, "opcode_set" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x74, GENZ_COMPONENT_C_ACCESS_STRUCTURE, "component_c_access" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x78, GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE, "component_destination_table" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x7c, GENZ_INTERFACE_STRUCTURE, "interface_0" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x80, GENZ_COMPONENT_EXTENSION_STRUCTURE, "component_extension" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x84, GENZ_COMPONENT_ERROR_AND_SIGNAL_EVENT_STRUCTURE, "component_error_and_signal_event" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x130, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x134, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x138, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x13c, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x140, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x146, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x14c, GENZ_GENERIC_STRUCTURE, NULL },
};

struct genz_control_structure_ptr opcode_set_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x18, GENZ_OPCODE_SET_UUID_TABLE, "opcode_set_uuid", genz_opcode_set_uuid_table_size },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_OPCODE_SET_TABLE, "opcode_set", genz_opcode_set_table_size },
};

struct genz_control_structure_ptr interface_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x70, GENZ_INTERFACE_STRUCTURE, "next_interface" },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x78, GENZ_UNKNOWN_STRUCTURE, "next_ai" },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x7c, GENZ_UNKNOWN_STRUCTURE, "next_ig" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x80, GENZ_INTERFACE_PHY_STRUCTURE, "i_phy" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x84, GENZ_INTERFACE_STATISTICS_STRUCTURE, "i_stats" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x88, GENZ_COMPONENT_MECHANICAL_STRUCTURE, "mechanical" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8c, GENZ_VENDOR_DEFINED_STRUCTURE, "vd" },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x90, GENZ_VCAT_TABLE, "vcat", genz_vcat_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x94, GENZ_LPRT_MPRT_TABLE, "lprt", genz_lprt_mprt_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x98, GENZ_LPRT_MPRT_TABLE, "mprt", genz_lprt_mprt_table_size },
};

struct genz_control_structure_ptr interface_phy_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x8, GENZ_INTERFACE_PHY_STRUCTURE, "next_interface_phy" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc, GENZ_VENDOR_DEFINED_STRUCTURE, "vd" },
};

struct genz_control_structure_ptr interface_statistics_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8, GENZ_VENDOR_DEFINED_STRUCTURE, "vendor_defined" },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0xc, GENZ_UNKNOWN_STRUCTURE, "i_snapshot" },
};

struct genz_control_structure_ptr component_error_and_signal_event_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x14, GENZ_ELOG_TABLE, "elog", genz_elog_table_size },
};

struct genz_control_structure_ptr component_media_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE, "vendor_defined" },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0xc, GENZ_COMPONENT_MEDIA_STRUCTURE, "next_media" },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x74, GENZ_BACKUP_MGMT_TABLE, "backup_mgmt", genz_backup_mgmt_table_size },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x78, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE, "primary_namespace" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x7c, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE, "primary_sit" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x80, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE, "secondary_namespace" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x84, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE, "secondary_sit" },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x88, GENZ_MEDIA_LOG_TABLE, "primary_log", genz_media_log_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x8c, GENZ_MEDIA_LOG_TABLE, "secondary_log", genz_media_log_table_size },
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x90, GENZ_OEM_DATA_TABLE, "oem_data", genz_oem_data_table_size },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x94, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE, "se_vendor_defined" },
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x98, GENZ_LABEL_DATA_TABLE, "primary_label_data", genz_label_data_table_size },
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x9c, GENZ_LABEL_DATA_TABLE, "secondary_label_data", genz_label_data_table_size },
};

struct genz_control_structure_ptr component_switch_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x30, GENZ_MVCAT_TABLE, "mvcat", genz_mvcat_table_size },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x34, GENZ_ROUTE_CONTROL_TABLE, "route_control", genz_route_control_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x38, GENZ_MCPRT_MSMCPRT_TABLE, "mcprt", genz_mcprt_msmcprt_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x3c, GENZ_MCPRT_MSMCPRT_TABLE, "msmcprt", genz_mcprt_msmcprt_table_size },
};

struct genz_control_structure_ptr component_statistics_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x8, GENZ_COMPONENT_STATISTICS_STRUCTURE, "next_statistics" },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0xc, GENZ_UNKNOWN_STRUCTURE, "c_snapshot" },
};

struct genz_control_structure_ptr component_extension_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_EXTENSION_STRUCTURE, "next_component_extension" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x10, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x14, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x24, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x28, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x2c, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x30, GENZ_GENERIC_STRUCTURE, NULL },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x38, GENZ_GENERIC_STRUCTURE, NULL },
};

struct genz_control_structure_ptr component_multicast_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x1c, GENZ_UNRELIABLE_MULTICAST_TABLE, "cmt", genz_unreliable_multicast_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x20, GENZ_UNRELIABLE_MULTICAST_TABLE, "mscmt", genz_unreliable_multicast_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x24, GENZ_RELIABLE_MULTICAST_TABLE, "rcmt", genz_reliable_multicast_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x28, GENZ_RELIABLE_MULTICAST_TABLE, "msrcmt", genz_reliable_multicast_table_size },
};

struct genz_control_structure_ptr component_tr_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x8, GENZ_TR_TABLE, "tr_table", genz_tr_table_size },
};

struct genz_control_structure_ptr component_image_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_6_BYTE_POINTER, 0x10, GENZ_IMAGE_TABLE, "image_table", genz_image_table_size },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x18, GENZ_COMPONENT_IMAGE_STRUCTURE, "next_image" },
};

struct genz_control_structure_ptr component_precision_time_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x1c, GENZ_COMPONENT_PRECISION_TIME_STRUCTURE, "next_pt" },
};

struct genz_control_structure_ptr component_mechanical_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_VENDOR_DEFINED_STRUCTURE, "mech_vendor_def" },
};

struct genz_control_structure_ptr component_destination_table_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_ROUTE_CONTROL_TABLE, "route_control", genz_route_control_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x20, GENZ_SSDT_MSDT_TABLE, "ssdt", genz_ssdt_msdt_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x24, GENZ_SSDT_MSDT_TABLE, "msdt", genz_ssdt_msdt_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x28, GENZ_REQUESTER_VCAT_TABLE, "req_vcat", genz_requester_vcat_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x2c, GENZ_RIT_TABLE, "rit", genz_rit_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x30, GENZ_RESPONDER_VCAT_TABLE, "rsp_vcat", genz_responder_vcat_table_size },
};

struct genz_control_structure_ptr service_uuid_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x8, GENZ_SERVICE_UUID_TABLE, "s_uuid", genz_service_uuid_table_size },
};

struct genz_control_structure_ptr component_c_access_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_C_ACCESS_STRUCTURE, "next_c_access" },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x18, GENZ_C_ACCESS_R_KEY_TABLE, "c_access_r_key", genz_c_access_r_key_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x1c, GENZ_C_ACCESS_L_P2P_TABLE, "c_access_l_p2p", genz_c_access_l_p2p_table_size },
};

struct genz_control_structure_ptr requester_p2p_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x38, GENZ_REQUESTER_P2P_STRUCTURE, "next_requester_p2p" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x3c, GENZ_VENDOR_DEFINED_STRUCTURE, "vendor_defined" },
};

struct genz_control_structure_ptr component_pa_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x1c, GENZ_PA_TABLE, "pa", genz_pa_table_size },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x20, GENZ_SSAP_MCAP_MSAP_AND_MSMCAP_TABLE, "ssap", genz_ssap_mcap_msap_and_msmcap_table_size },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x24, GENZ_SSAP_MCAP_MSAP_AND_MSMCAP_TABLE, "msap", genz_ssap_mcap_msap_and_msmcap_table_size },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x28, GENZ_SSAP_MCAP_MSAP_AND_MSMCAP_TABLE, "mcap", genz_ssap_mcap_msap_and_msmcap_table_size },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x2c, GENZ_SSAP_MCAP_MSAP_AND_MSMCAP_TABLE, "msmcap", genz_ssap_mcap_msap_and_msmcap_table_size },
};

struct genz_control_structure_ptr component_lpd_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_LPD_STRUCTURE, "next_component_lpd" },
};

struct genz_control_structure_ptr component_lpd_structure_array_ptrs[] = {
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x54, GENZ_UNKNOWN_STRUCTURE, "function" },
};

struct genz_control_structure_ptr component_sod_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x14, GENZ_SSOD_MSOD_TABLE, "ssod", genz_ssod_msod_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x18, GENZ_SSOD_MSOD_TABLE, "msod", genz_ssod_msod_table_size },
};

struct genz_control_structure_ptr congestion_management_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8, GENZ_VENDOR_DEFINED_STRUCTURE, "vendor_defined" },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0xc, GENZ_RESOURCE_TABLE, "resource_array", genz_resource_table_size },
};

struct genz_control_structure_ptr component_pm_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x8, GENZ_UNKNOWN_STRUCTURE, "performance_log" },
};

struct genz_control_structure_ptr component_re_table_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_6_BYTE_POINTER, 0x10, GENZ_RE_TABLE, "re_table", genz_re_table_size },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_6_BYTE_POINTER, 0x18, GENZ_COMPONENT_RE_TABLE_STRUCTURE, "next_re_table" },
};

struct genz_control_structure_ptr component_lph_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_LPH_STRUCTURE, "next_component_lph" },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x54, GENZ_UNKNOWN_STRUCTURE, "lph_ecam" },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x60, GENZ_UNKNOWN_STRUCTURE, "lph_rcrb" },
};

struct genz_control_structure_ptr component_page_grid_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x18, GENZ_PAGE_GRID_RESTRICTED_PAGE_GRID_TABLE, "pg_base", genz_page_grid_restricted_page_grid_table_size },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_PTE_RESTRICTED_PTE_TABLE, "pte_base", genz_pte_restricted_pte_table_size },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE, "vendor_defined" },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x24, GENZ_COMPONENT_PAGE_GRID_STRUCTURE, "next_component_page_grid" },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x28, GENZ_PAGE_GRID_RESTRICTED_PAGE_GRID_TABLE, "restricted_pg_base", genz_page_grid_restricted_page_grid_table_size },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x2c, GENZ_PTE_RESTRICTED_PTE_TABLE, "restricted_pte_base", genz_pte_restricted_pte_table_size },
};

struct genz_control_structure_ptr component_page_table_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE, "vendor_defined" },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x10, GENZ_UNKNOWN_STRUCTURE, "pte_cache" },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x34, GENZ_COMPONENT_PAGE_TABLE_STRUCTURE, "next_component_page_table" },
};

struct genz_control_structure_ptr component_interleave_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_INTERLEAVE_STRUCTURE, "next_component_interleave" },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x20, GENZ_TYPE_1_INTERLEAVE_TABLE, "interleave_table", genz_type_1_interleave_table_size },
};

struct genz_control_structure_ptr component_firmware_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x8, GENZ_FIRMWARE_TABLE, "fw_table", genz_firmware_table_size },
};

struct genz_control_structure_ptr component_sw_management_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x18, GENZ_UNKNOWN_STRUCTURE, "swm" },
};

struct genz_control_structure_ptr backup_mgmt_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x68, GENZ_PM_BACKUP_TABLE, "pm_backup_table", genz_pm_backup_table_size },
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x6c, GENZ_SM_BACKUP_TABLE, "sm_backup_table", genz_sm_backup_table_size },
};

struct genz_control_structure_ptr elog_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_ELOG_TABLE, "next_elog" },
};

struct genz_control_structure_ptr opcode_set_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_OPCODE_SET_TABLE, "next_opcode_set" },
};

struct genz_control_structure_ptr tr_table_array_ptrs[] = {
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x0, GENZ_UNKNOWN_STRUCTURE, "tr_zmmu_sub_0" },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x4, GENZ_UNKNOWN_STRUCTURE, "tr_rtr_sub_0" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8, GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE, "tr_dt_sub_0" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc, GENZ_COMPONENT_PA_STRUCTURE, "tr_pa_sub_0" },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x10, GENZ_OPCODE_SET_STRUCTURE, "tr_opcode_set_sub_0" },
};


struct genz_control_ptr_info genz_struct_type_to_ptrs[] = {
     { core_structure_ptrs, sizeof(core_structure_ptrs)/sizeof(core_structure_ptrs[0]), sizeof(struct genz_core_structure), false, 0x1, "core" },
     { opcode_set_structure_ptrs, sizeof(opcode_set_structure_ptrs)/sizeof(opcode_set_structure_ptrs[0]), sizeof(struct genz_opcode_set_structure), false, 0x1, "opcode_set" },
     { interface_structure_ptrs, sizeof(interface_structure_ptrs)/sizeof(interface_structure_ptrs[0]), sizeof(struct genz_interface_structure), true, 0x1, "interface" },
     { interface_phy_structure_ptrs, sizeof(interface_phy_structure_ptrs)/sizeof(interface_phy_structure_ptrs[0]), sizeof(struct genz_interface_phy_structure), true, 0x1, "interface_phy" },
     { interface_statistics_structure_ptrs, sizeof(interface_statistics_structure_ptrs)/sizeof(interface_statistics_structure_ptrs[0]), sizeof(struct genz_interface_statistics_structure), false, 0x1, "interface_statistics" },
     { component_error_and_signal_event_structure_ptrs, sizeof(component_error_and_signal_event_structure_ptrs)/sizeof(component_error_and_signal_event_structure_ptrs[0]), sizeof(struct genz_component_error_and_signal_event_structure), false, 0x1, "component_error_and_signal_event" },
     { component_media_structure_ptrs, sizeof(component_media_structure_ptrs)/sizeof(component_media_structure_ptrs[0]), sizeof(struct genz_component_media_structure), true, 0x1, "component_media" },
     { component_switch_structure_ptrs, sizeof(component_switch_structure_ptrs)/sizeof(component_switch_structure_ptrs[0]), sizeof(struct genz_component_switch_structure), false, 0x1, "component_switch" },
     { component_statistics_structure_ptrs, sizeof(component_statistics_structure_ptrs)/sizeof(component_statistics_structure_ptrs[0]), sizeof(struct genz_component_statistics_structure), true, 0x1, "component_statistics" },
     { component_extension_structure_ptrs, sizeof(component_extension_structure_ptrs)/sizeof(component_extension_structure_ptrs[0]), sizeof(struct genz_component_extension_structure), true, 0x1, "component_extension" },
     { NULL, 0, sizeof(struct genz_vendor_defined_structure), false, 0x1, "vendor_defined" },
     { NULL, 0, sizeof(struct genz_vendor_defined_with_uuid_structure), false, 0x1, "vendor_defined_with_uuid" },
     { component_multicast_structure_ptrs, sizeof(component_multicast_structure_ptrs)/sizeof(component_multicast_structure_ptrs[0]), sizeof(struct genz_component_multicast_structure), false, 0x1, "component_multicast" },
    {},
     { component_tr_structure_ptrs, sizeof(component_tr_structure_ptrs)/sizeof(component_tr_structure_ptrs[0]), sizeof(struct genz_component_tr_structure), false, 0x1, "component_tr" },
     { component_image_structure_ptrs, sizeof(component_image_structure_ptrs)/sizeof(component_image_structure_ptrs[0]), sizeof(struct genz_component_image_structure), true, 0x1, "component_image" },
     { component_precision_time_structure_ptrs, sizeof(component_precision_time_structure_ptrs)/sizeof(component_precision_time_structure_ptrs[0]), sizeof(struct genz_component_precision_time_structure), true, 0x1, "component_precision_time" },
     { component_mechanical_structure_ptrs, sizeof(component_mechanical_structure_ptrs)/sizeof(component_mechanical_structure_ptrs[0]), sizeof(struct genz_component_mechanical_structure), false, 0x1, "component_mechanical" },
     { component_destination_table_structure_ptrs, sizeof(component_destination_table_structure_ptrs)/sizeof(component_destination_table_structure_ptrs[0]), sizeof(struct genz_component_destination_table_structure), false, 0x1, "component_destination_table" },
     { service_uuid_structure_ptrs, sizeof(service_uuid_structure_ptrs)/sizeof(service_uuid_structure_ptrs[0]), sizeof(struct genz_service_uuid_structure), false, 0x1, "service_uuid" },
     { component_c_access_structure_ptrs, sizeof(component_c_access_structure_ptrs)/sizeof(component_c_access_structure_ptrs[0]), sizeof(struct genz_component_c_access_structure), true, 0x1, "component_c_access" },
    {},
     { requester_p2p_structure_ptrs, sizeof(requester_p2p_structure_ptrs)/sizeof(requester_p2p_structure_ptrs[0]), sizeof(struct genz_requester_p2p_structure), true, 0x1, "requester_p2p" },
     { component_pa_structure_ptrs, sizeof(component_pa_structure_ptrs)/sizeof(component_pa_structure_ptrs[0]), sizeof(struct genz_component_pa_structure), false, 0x1, "component_pa" },
     { NULL, 0, sizeof(struct genz_component_event_structure), false, 0x1, "component_event" },
     { component_lpd_structure_ptrs, sizeof(component_lpd_structure_ptrs)/sizeof(component_lpd_structure_ptrs[0]), sizeof(struct genz_component_lpd_structure), true, 0x1, "component_lpd" },
     { component_sod_structure_ptrs, sizeof(component_sod_structure_ptrs)/sizeof(component_sod_structure_ptrs[0]), sizeof(struct genz_component_sod_structure), false, 0x1, "component_sod" },
     { congestion_management_structure_ptrs, sizeof(congestion_management_structure_ptrs)/sizeof(congestion_management_structure_ptrs[0]), sizeof(struct genz_congestion_management_structure), false, 0x1, "congestion_management" },
     { NULL, 0, sizeof(struct genz_component_rkd_structure), false, 0x1, "component_rkd" },
     { component_pm_structure_ptrs, sizeof(component_pm_structure_ptrs)/sizeof(component_pm_structure_ptrs[0]), sizeof(struct genz_component_pm_structure), false, 0x1, "component_pm" },
     { NULL, 0, sizeof(struct genz_component_atp_structure), false, 0x1, "component_atp" },
     { component_re_table_structure_ptrs, sizeof(component_re_table_structure_ptrs)/sizeof(component_re_table_structure_ptrs[0]), sizeof(struct genz_component_re_table_structure), true, 0x1, "component_re_table" },
     { component_lph_structure_ptrs, sizeof(component_lph_structure_ptrs)/sizeof(component_lph_structure_ptrs[0]), sizeof(struct genz_component_lph_structure), true, 0x1, "component_lph" },
     { component_page_grid_structure_ptrs, sizeof(component_page_grid_structure_ptrs)/sizeof(component_page_grid_structure_ptrs[0]), sizeof(struct genz_component_page_grid_structure), true, 0x1, "component_page_grid" },
     { component_page_table_structure_ptrs, sizeof(component_page_table_structure_ptrs)/sizeof(component_page_table_structure_ptrs[0]), sizeof(struct genz_component_page_table_structure), true, 0x1, "component_page_table" },
     { component_interleave_structure_ptrs, sizeof(component_interleave_structure_ptrs)/sizeof(component_interleave_structure_ptrs[0]), sizeof(struct genz_component_interleave_structure), true, 0x1, "component_interleave" },
     { component_firmware_structure_ptrs, sizeof(component_firmware_structure_ptrs)/sizeof(component_firmware_structure_ptrs[0]), sizeof(struct genz_component_firmware_structure), false, 0x1, "component_firmware" },
     { component_sw_management_structure_ptrs, sizeof(component_sw_management_structure_ptrs)/sizeof(component_sw_management_structure_ptrs[0]), sizeof(struct genz_component_sw_management_structure), false, 0x1, "component_sw_management" },
};

struct genz_control_ptr_info genz_table_type_to_ptrs[] = {
     { backup_mgmt_table_ptrs, sizeof(backup_mgmt_table_ptrs)/sizeof(backup_mgmt_table_ptrs[0]), sizeof(struct genz_backup_mgmt_table), false, 0x0, "backup_mgmt_table" },
     { NULL, 0, 0, false, 0x0, "c_access_l_p2p_table" },
     { NULL, 0, 0, false, 0x0, "c_access_r_key_table" },
     { NULL, 0, 0, false, 0x0, "component_error_elog_entry" },
     { NULL, 0, 0, false, 0x0, "core_lpd_bdf_table" },
     { elog_table_ptrs, sizeof(elog_table_ptrs)/sizeof(elog_table_ptrs[0]), sizeof(struct genz_elog_table), true, 0x0, "elog_table" },
     { NULL, 0, 0, false, 0x0, "event_record" },
     { NULL, 0, 0, false, 0x0, "firmware_table" },
     { NULL, 0, 0, false, 0x0, "image_format_0xc86ed8c24bed49bda5143dd11950de9d_header_format" },
     { NULL, 0, 0, false, 0x0, "image_table" },
     { NULL, 0, 0, false, 0x0, "interface_error_elog_entry" },
     { NULL, 0, 0, false, 0x0, "lprt_mprt_table" },
     { NULL, 0, 0, false, 0x0, "label_data_table" },
     { NULL, 0, 0, false, 0x0, "mcprt_msmcprt_table" },
     { NULL, 0, 0, false, 0x0, "mcprt_msmcptr_row" },
     { NULL, 0, 0, false, 0x0, "mvcat_table" },
     { NULL, 0, 0, false, 0x0, "media_log_table" },
     { NULL, 0, 0, false, 0x0, "oem_data_table" },
     { opcode_set_table_ptrs, sizeof(opcode_set_table_ptrs)/sizeof(opcode_set_table_ptrs[0]), sizeof(struct genz_opcode_set_table), true, 0x0, "opcode_set_table" },
     { NULL, 0, 0, false, 0x0, "opcode_set_uuid_table" },
     { NULL, 0, 0, false, 0x0, "pa_table" },
     { NULL, 0, 0, false, 0x0, "pm_backup_table" },
     { NULL, 0, 0, false, 0x0, "pte_restricted_pte_table" },
     { NULL, 0, 0, false, 0x0, "page_grid_restricted_page_grid_table" },
     { NULL, 0, 0, false, 0x0, "page_table_pointer_pair_table_entry" },
     { NULL, 0, 0, false, 0x0, "performance_log_record_0" },
     { NULL, 0, 0, false, 0x0, "performance_log_record_1" },
     { NULL, 0, 0, false, 0x0, "re_table" },
     { NULL, 0, 0, false, 0x0, "rit_table" },
     { NULL, 0, 0, false, 0x0, "reliable_multicast_responder_table" },
     { NULL, 0, 0, false, 0x0, "reliable_multicast_table" },
     { NULL, 0, 0, false, 0x0, "reliable_multicast_table_entry_row" },
     { NULL, 0, 0, false, 0x0, "requester_vcat_table" },
     { NULL, 0, 0, false, 0x0, "resource_table" },
     { NULL, 0, 0, false, 0x0, "responder_vcat_table" },
     { NULL, 0, 0, false, 0x0, "route_control_table" },
     { NULL, 0, 0, false, 0x0, "sm_backup_table" },
     { NULL, 0, 0, false, 0x0, "ssap_mcap_msap_and_msmcap_table" },
     { NULL, 0, 0, false, 0x0, "ssdt_msdt_table" },
     { NULL, 0, 0, false, 0x0, "ssod_msod_table" },
     { NULL, 0, 0, false, 0x0, "service_uuid_table" },
     { NULL, 0, 0, false, 0x0, "tr_table" },
     { NULL, 0, 0, false, 0x0, "type_1_interleave_table" },
     { NULL, 0, 0, false, 0x0, "unreliable_multicast_table" },
     { NULL, 0, 0, false, 0x0, "unreliable_multicast_table_entry_row" },
     { NULL, 0, 0, false, 0x0, "vcat_table" },
};

EXPORT_SYMBOL(genz_struct_type_to_ptrs);

size_t genz_struct_type_to_ptrs_nelems = sizeof(genz_struct_type_to_ptrs) / sizeof(genz_struct_type_to_ptrs[0]);

EXPORT_SYMBOL(genz_struct_type_to_ptrs_nelems);

EXPORT_SYMBOL(genz_table_type_to_ptrs);

size_t genz_table_type_to_ptrs_nelems = sizeof(genz_table_type_to_ptrs) / sizeof(genz_table_type_to_ptrs[0]);

EXPORT_SYMBOL(genz_table_type_to_ptrs_nelems);

EXPORT_SYMBOL(genz_hardware_classes);

size_t genz_hardware_classes_nelems = sizeof(genz_hardware_classes) / sizeof(genz_hardware_classes[0]);

EXPORT_SYMBOL(genz_hardware_classes_nelems);
