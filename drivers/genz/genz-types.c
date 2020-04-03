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
 *     Generated On : 2020-03-18 09:38:02.238138
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
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x48, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4c, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x50, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x54, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x58, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x5c, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x60, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x64, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x68, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x6c, GENZ_CORE_LPD_BDF_TABLE, genz_core_lpd_bdf_table_size },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x70, GENZ_OPCODE_SET_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x74, GENZ_COMPONENT_C_ACCESS_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x78, GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x7c, GENZ_INTERFACE_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x80, GENZ_COMPONENT_EXTENSION_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x84, GENZ_COMPONENT_ERROR_AND_SIGNAL_EVENT_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x130, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x134, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x138, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x13c, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x140, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x146, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x14c, GENZ_GENERIC_STRUCTURE },
};

struct genz_control_structure_ptr opcode_set_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x18, GENZ_OPCODE_SET_UUID_TABLE, genz_opcode_set_uuid_table_size },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_OPCODE_SET_TABLE, genz_opcode_set_table_size },
};

struct genz_control_structure_ptr interface_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x70, GENZ_INTERFACE_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x78, GENZ_UNKNOWN_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x7c, GENZ_UNKNOWN_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x80, GENZ_INTERFACE_PHY_STRUCTURE },
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x84, GENZ_INTERFACE_STATISTICS_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x88, GENZ_COMPONENT_MECHANICAL_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8c, GENZ_VENDOR_DEFINED_STRUCTURE },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x90, GENZ_VCAT_TABLE, genz_vcat_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x94, GENZ_LPRT_MPRT_TABLE, genz_lprt_mprt_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x98, GENZ_LPRT_MPRT_TABLE, genz_lprt_mprt_table_size },
};

struct genz_control_structure_ptr interface_phy_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x8, GENZ_INTERFACE_PHY_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc, GENZ_VENDOR_DEFINED_STRUCTURE },
};

struct genz_control_structure_ptr interface_statistics_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8, GENZ_VENDOR_DEFINED_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0xc, GENZ_UNKNOWN_STRUCTURE },
};

struct genz_control_structure_ptr component_error_and_signal_event_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x14, GENZ_ELOG_TABLE },
};

struct genz_control_structure_ptr component_media_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0xc, GENZ_COMPONENT_MEDIA_STRUCTURE },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x74, GENZ_BACKUP_MGMT_TABLE, genz_backup_mgmt_table_size },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x78, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x7c, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x80, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x84, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x88, GENZ_MEDIA_LOG_TABLE, genz_media_log_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x8c, GENZ_MEDIA_LOG_TABLE, genz_media_log_table_size },
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x90, GENZ_OEM_DATA_TABLE, genz_oem_data_table_size },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x94, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE },
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x98, GENZ_LABEL_DATA_TABLE, genz_label_data_table_size },
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x9c, GENZ_LABEL_DATA_TABLE, genz_label_data_table_size },
};

struct genz_control_structure_ptr component_switch_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x30, GENZ_MVCAT_TABLE, genz_mvcat_table_size },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x34, GENZ_ROUTE_CONTROL_TABLE, genz_route_control_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x38, GENZ_MCPRT_MSMCPRT_TABLE, genz_mcprt_msmcprt_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x3c, GENZ_MCPRT_MSMCPRT_TABLE, genz_mcprt_msmcprt_table_size },
};

struct genz_control_structure_ptr component_statistics_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x8, GENZ_COMPONENT_STATISTICS_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0xc, GENZ_UNKNOWN_STRUCTURE },
};

struct genz_control_structure_ptr component_extension_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_EXTENSION_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x10, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x14, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x18, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x24, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x28, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x2c, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x30, GENZ_GENERIC_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_6_BYTE_POINTER, 0x38, GENZ_GENERIC_STRUCTURE },
};

struct genz_control_structure_ptr component_multicast_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x1c, GENZ_UNRELIABLE_MULTICAST_TABLE, genz_unreliable_multicast_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x20, GENZ_UNRELIABLE_MULTICAST_TABLE, genz_unreliable_multicast_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x24, GENZ_RELIABLE_MULTICAST_TABLE, genz_reliable_multicast_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x28, GENZ_RELIABLE_MULTICAST_TABLE, genz_reliable_multicast_table_size },
};

struct genz_control_structure_ptr component_tr_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x8, GENZ_TR_TABLE, genz_tr_table_size },
};

struct genz_control_structure_ptr component_image_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_6_BYTE_POINTER, 0x10, GENZ_IMAGE_TABLE, genz_image_table_size },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x18, GENZ_COMPONENT_IMAGE_STRUCTURE },
};

struct genz_control_structure_ptr component_precision_time_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x1c, GENZ_COMPONENT_PRECISION_TIME_STRUCTURE },
};

struct genz_control_structure_ptr component_mechanical_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_VENDOR_DEFINED_STRUCTURE },
};

struct genz_control_structure_ptr component_destination_table_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_ROUTE_CONTROL_TABLE, genz_route_control_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x20, GENZ_SSDT_MSDT_TABLE, genz_ssdt_msdt_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x24, GENZ_SSDT_MSDT_TABLE, genz_ssdt_msdt_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x28, GENZ_REQUESTER_VCAT_TABLE, genz_requester_vcat_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x2c, GENZ_RIT_TABLE, genz_rit_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x30, GENZ_RESPONDER_VCAT_TABLE, genz_responder_vcat_table_size },
};

struct genz_control_structure_ptr service_uuid_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x8, GENZ_SERVICE_UUID_TABLE, genz_service_uuid_table_size },
};

struct genz_control_structure_ptr component_c_access_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_C_ACCESS_STRUCTURE },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x18, GENZ_C_ACCESS_R_KEY_TABLE, genz_c_access_r_key_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x1c, GENZ_C_ACCESS_L_P2P_TABLE, genz_c_access_l_p2p_table_size },
};

struct genz_control_structure_ptr requester_p2p_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x38, GENZ_REQUESTER_P2P_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x3c, GENZ_VENDOR_DEFINED_STRUCTURE },
};

struct genz_control_structure_ptr component_pa_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x1c, GENZ_PA_TABLE, genz_pa_table_size },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x20, GENZ_SSAP_MCAP_MSAP_AND_MSMCAP_TABLE, genz_ssap_mcap_msap_and_msmcap_table_size },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x24, GENZ_SSAP_MCAP_MSAP_AND_MSMCAP_TABLE, genz_ssap_mcap_msap_and_msmcap_table_size },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x28, GENZ_SSAP_MCAP_MSAP_AND_MSMCAP_TABLE, genz_ssap_mcap_msap_and_msmcap_table_size },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x2c, GENZ_SSAP_MCAP_MSAP_AND_MSMCAP_TABLE, genz_ssap_mcap_msap_and_msmcap_table_size },
};

struct genz_control_structure_ptr component_lpd_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_LPD_STRUCTURE },
};

struct genz_control_structure_ptr component_lpd_structure_array_ptrs[] = {
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x54, GENZ_UNKNOWN_STRUCTURE },
};

struct genz_control_structure_ptr component_sod_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x14, GENZ_SSOD_MSOD_TABLE, genz_ssod_msod_table_size },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x18, GENZ_SSOD_MSOD_TABLE, genz_ssod_msod_table_size },
};

struct genz_control_structure_ptr congestion_management_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8, GENZ_VENDOR_DEFINED_STRUCTURE },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0xc, GENZ_RESOURCE_TABLE, genz_resource_table_size },
};

struct genz_control_structure_ptr component_pm_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x8, GENZ_UNKNOWN_STRUCTURE },
};

struct genz_control_structure_ptr component_re_table_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_6_BYTE_POINTER, 0x10, GENZ_RE_TABLE, genz_re_table_size },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_6_BYTE_POINTER, 0x18, GENZ_COMPONENT_RE_TABLE_STRUCTURE },
};

struct genz_control_structure_ptr component_lph_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_LPH_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x54, GENZ_UNKNOWN_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x60, GENZ_UNKNOWN_STRUCTURE },
};

struct genz_control_structure_ptr component_page_grid_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x18, GENZ_PAGE_GRID_RESTRICTED_PAGE_GRID_TABLE, genz_page_grid_restricted_page_grid_table_size },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x1c, GENZ_PTE_RESTRICTED_PTE_TABLE, genz_pte_restricted_pte_table_size },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x20, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x24, GENZ_COMPONENT_PAGE_GRID_STRUCTURE },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x28, GENZ_PAGE_GRID_RESTRICTED_PAGE_GRID_TABLE, genz_page_grid_restricted_page_grid_table_size },
    { GENZ_CONTROL_POINTER_TABLE, GENZ_4_BYTE_POINTER, 0x2c, GENZ_PTE_RESTRICTED_PTE_TABLE, genz_pte_restricted_pte_table_size },
};

struct genz_control_structure_ptr component_page_table_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x4, GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x10, GENZ_UNKNOWN_STRUCTURE },
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x34, GENZ_COMPONENT_PAGE_TABLE_STRUCTURE },
};

struct genz_control_structure_ptr component_interleave_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_COMPONENT_INTERLEAVE_STRUCTURE },
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x20, GENZ_TYPE_1_INTERLEAVE_TABLE, genz_type_1_interleave_table_size },
};

struct genz_control_structure_ptr component_firmware_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_ARRAY, GENZ_4_BYTE_POINTER, 0x8, GENZ_FIRMWARE_TABLE, genz_firmware_table_size },
};

struct genz_control_structure_ptr component_sw_management_structure_ptrs[] = {
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x18, GENZ_UNKNOWN_STRUCTURE },
};

struct genz_control_structure_ptr backup_mgmt_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x68, GENZ_PM_BACKUP_TABLE, genz_pm_backup_table_size },
    { GENZ_CONTROL_POINTER_TABLE_WITH_HEADER, GENZ_4_BYTE_POINTER, 0x6c, GENZ_SM_BACKUP_TABLE, genz_sm_backup_table_size },
};

struct genz_control_structure_ptr elog_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_ELOG_TABLE },
};

struct genz_control_structure_ptr opcode_set_table_ptrs[] = {
    { GENZ_CONTROL_POINTER_CHAINED, GENZ_4_BYTE_POINTER, 0x4, GENZ_OPCODE_SET_TABLE },
};

struct genz_control_structure_ptr tr_table_array_ptrs[] = {
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x0, GENZ_UNKNOWN_STRUCTURE },
    { GENZ_CONTROL_POINTER_NONE, GENZ_4_BYTE_POINTER, 0x4, GENZ_UNKNOWN_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x8, GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0xc, GENZ_COMPONENT_PA_STRUCTURE },
    { GENZ_CONTROL_POINTER_STRUCTURE, GENZ_4_BYTE_POINTER, 0x10, GENZ_OPCODE_SET_STRUCTURE },
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
    {},
    {},
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
    {},
     { component_lpd_structure_ptrs, sizeof(component_lpd_structure_ptrs)/sizeof(component_lpd_structure_ptrs[0]), sizeof(struct genz_component_lpd_structure), true, 0x1, "component_lpd" },
     { component_sod_structure_ptrs, sizeof(component_sod_structure_ptrs)/sizeof(component_sod_structure_ptrs[0]), sizeof(struct genz_component_sod_structure), false, 0x1, "component_sod" },
     { congestion_management_structure_ptrs, sizeof(congestion_management_structure_ptrs)/sizeof(congestion_management_structure_ptrs[0]), sizeof(struct genz_congestion_management_structure), false, 0x1, "congestion_management" },
    {},
     { component_pm_structure_ptrs, sizeof(component_pm_structure_ptrs)/sizeof(component_pm_structure_ptrs[0]), sizeof(struct genz_component_pm_structure), false, 0x1, "component_pm" },
    {},
     { component_re_table_structure_ptrs, sizeof(component_re_table_structure_ptrs)/sizeof(component_re_table_structure_ptrs[0]), sizeof(struct genz_component_re_table_structure), true, 0x1, "component_re_table" },
     { component_lph_structure_ptrs, sizeof(component_lph_structure_ptrs)/sizeof(component_lph_structure_ptrs[0]), sizeof(struct genz_component_lph_structure), true, 0x1, "component_lph" },
     { component_page_grid_structure_ptrs, sizeof(component_page_grid_structure_ptrs)/sizeof(component_page_grid_structure_ptrs[0]), sizeof(struct genz_component_page_grid_structure), true, 0x1, "component_page_grid" },
     { component_page_table_structure_ptrs, sizeof(component_page_table_structure_ptrs)/sizeof(component_page_table_structure_ptrs[0]), sizeof(struct genz_component_page_table_structure), true, 0x1, "component_page_table" },
     { component_interleave_structure_ptrs, sizeof(component_interleave_structure_ptrs)/sizeof(component_interleave_structure_ptrs[0]), sizeof(struct genz_component_interleave_structure), true, 0x1, "component_interleave" },
     { component_firmware_structure_ptrs, sizeof(component_firmware_structure_ptrs)/sizeof(component_firmware_structure_ptrs[0]), sizeof(struct genz_component_firmware_structure), false, 0x1, "component_firmware" },
     { component_sw_management_structure_ptrs, sizeof(component_sw_management_structure_ptrs)/sizeof(component_sw_management_structure_ptrs[0]), sizeof(struct genz_component_sw_management_structure), false, 0x1, "component_sw_management" },
};

struct genz_control_ptr_info genz_table_type_to_ptrs[] = {
     { backup_mgmt_table_ptrs, sizeof(backup_mgmt_table_ptrs)/sizeof(backup_mgmt_table_ptrs[0]), sizeof(struct genz_backup_mgmt_table), false, 0x0, "backup_mgmt_table_ptrs" },
    {},
    {},
    {},
    {},
     { elog_table_ptrs, sizeof(elog_table_ptrs)/sizeof(elog_table_ptrs[0]), sizeof(struct genz_elog_table), true, 0x0, "log_table_ptrs" },
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
     { opcode_set_table_ptrs, sizeof(opcode_set_table_ptrs)/sizeof(opcode_set_table_ptrs[0]), sizeof(struct genz_opcode_set_table), true, 0x0, "opcode_set_table_ptrs" },
    {},
    {},
    {},
    {},
    {},
    {},
    {},
    {},
    {},
    { NULL, 0, 0, false, 0x0, "rit"},
    { NULL, 0, 0, false, 0x0, "reliable_multicast_responder"},
    { NULL, 0, 0, false, 0x0, "reliable_multicast"},
    { NULL, 0, 0, false, 0x0, "reliable_multicast_table_entry_row"},
    { NULL, 0, 0, false, 0x0, "requester_vcat"},
    { NULL, 0, 0, false, 0x0, "resource_table"},
    { NULL, 0, 0, false, 0x0, "responder_vcat"},
    { NULL, 0, 0, false, 0x0, "route_control"},
    { NULL, 0, 0, false, 0x0, "sm_backup"},
    { NULL, 0, 0, false, 0x0, "ssap_mcap_msap_and_msmcap" },
    { NULL, 0, 0, false, 0x0, "ssdt_msdt" },
    { NULL, 0, 0, false, 0x0, "ssod_msod" },
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

EXPORT_SYMBOL(genz_struct_type_to_ptrs);

size_t genz_struct_type_to_ptrs_nelems = sizeof(genz_struct_type_to_ptrs) / sizeof(genz_struct_type_to_ptrs[0]);

EXPORT_SYMBOL(genz_struct_type_to_ptrs_nelems);

EXPORT_SYMBOL(genz_table_type_to_ptrs);

size_t genz_table_type_to_ptrs_nelems = sizeof(genz_table_type_to_ptrs) / sizeof(genz_table_type_to_ptrs[0]);

EXPORT_SYMBOL(genz_table_type_to_ptrs_nelems);

EXPORT_SYMBOL(genz_hardware_classes);

size_t genz_hardware_classes_nelems = sizeof(genz_hardware_classes) / sizeof(genz_hardware_classes[0]);

EXPORT_SYMBOL(genz_hardware_classes_nelems);
