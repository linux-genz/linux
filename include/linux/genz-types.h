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
 * This file is machine generated based of XML GenZ Specs.
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
 *
 * **************************************************************
 *
 * Struct        -----------------------------------  83
 * Struct entries(declared inside structs and enums)  2485
 * Unions        -----------------------------------  167
 * Enums         -----------------------------------  281
 */
#ifndef __GENZH__
#define __GENZH__


#ifndef __KERNEL__

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <uuid/uuid.h>

#define UUID_SIZE 16
typedef struct {
    unsigned char b[UUID_SIZE];
} uuid_t;

#else

#include <linux/uuid.h>

#endif

struct genz_control_structure_header {
    uint32_t type   : 12;
    uint32_t vers   : 4;
    uint32_t size   : 16;
};

struct genz_vcat_entry {
    uint32_t vcm : 32;
    uint32_t th : 7;
    uint32_t r0 : 25;
};

struct genz_control_info;

#define GENZ_TABLE_ENUM_START 0x1000

enum genz_control_ptr_flags {
    GENZ_CONTROL_POINTER_NONE = 0,
    GENZ_CONTROL_POINTER_STRUCTURE = 1,
    GENZ_CONTROL_POINTER_CHAINED = 2,
    GENZ_CONTROL_POINTER_ARRAY = 3,
    GENZ_CONTROL_POINTER_TABLE = 4,
    GENZ_CONTROL_POINTER_TABLE_WITH_HEADER = 5
};

enum genz_pointer_size {
    GENZ_4_BYTE_POINTER = 4,
    GENZ_6_BYTE_POINTER = 6
};

struct genz_control_ptr_info{
    const struct genz_control_structure_ptr * const ptr;
    const size_t num_ptrs;
    const ssize_t struct_bytes;
    const bool chained;
    const uint8_t vers;
    const char * const name;
};

enum genz_control_structure_type {
    GENZ_UNKNOWN_STRUCTURE = -2,
    GENZ_GENERIC_STRUCTURE = -1,
    GENZ_CORE_STRUCTURE = 0x0,
    GENZ_OPCODE_SET_STRUCTURE = 0x1,
    GENZ_INTERFACE_STRUCTURE = 0x2,
    GENZ_INTERFACE_PHY_STRUCTURE = 0x3,
    GENZ_INTERFACE_STATISTICS_STRUCTURE = 0x4,
    GENZ_COMPONENT_ERROR_AND_SIGNAL_EVENT_STRUCTURE = 0x5,
    GENZ_COMPONENT_MEDIA_STRUCTURE = 0x6,
    GENZ_COMPONENT_SWITCH_STRUCTURE = 0x7,
    GENZ_COMPONENT_STATISTICS_STRUCTURE = 0x8,
    GENZ_COMPONENT_EXTENSION_STRUCTURE = 0x9,
    GENZ_VENDOR_DEFINED_STRUCTURE = 0xa,
    GENZ_VENDOR_DEFINED_WITH_UUID_STRUCTURE = 0xb,
    GENZ_COMPONENT_MULTICAST_STRUCTURE = 0xc,
    GENZ_COMPONENT_TR_STRUCTURE = 0xe,
    GENZ_COMPONENT_IMAGE_STRUCTURE = 0xf,
    GENZ_COMPONENT_PRECISION_TIME_STRUCTURE = 0x10,
    GENZ_COMPONENT_MECHANICAL_STRUCTURE = 0x11,
    GENZ_COMPONENT_DESTINATION_TABLE_STRUCTURE = 0x12,
    GENZ_SERVICE_UUID_STRUCTURE = 0x13,
    GENZ_COMPONENT_C_ACCESS_STRUCTURE = 0x14,
    GENZ_REQUESTER_P2P_STRUCTURE = 0x16,
    GENZ_COMPONENT_PA_STRUCTURE = 0x17,
    GENZ_COMPONENT_EVENT_STRUCTURE = 0x18,
    GENZ_COMPONENT_LPD_STRUCTURE = 0x19,
    GENZ_COMPONENT_SOD_STRUCTURE = 0x1a,
    GENZ_CONGESTION_MANAGEMENT_STRUCTURE = 0x1b,
    GENZ_COMPONENT_RKD_STRUCTURE = 0x1c,
    GENZ_COMPONENT_PM_STRUCTURE = 0x1d,
    GENZ_COMPONENT_ATP_STRUCTURE = 0x1e,
    GENZ_COMPONENT_RE_TABLE_STRUCTURE = 0x1f,
    GENZ_COMPONENT_LPH_STRUCTURE = 0x20,
    GENZ_COMPONENT_PAGE_GRID_STRUCTURE = 0x21,
    GENZ_COMPONENT_PAGE_TABLE_STRUCTURE = 0x22,
    GENZ_COMPONENT_INTERLEAVE_STRUCTURE = 0x23,
    GENZ_COMPONENT_FIRMWARE_STRUCTURE = 0x24,
    GENZ_COMPONENT_SW_MANAGEMENT_STRUCTURE = 0x25,
    GENZ_BACKUP_MGMT_TABLE = GENZ_TABLE_ENUM_START,
    GENZ_C_ACCESS_L_P2P_TABLE = GENZ_TABLE_ENUM_START + 1,
    GENZ_C_ACCESS_R_KEY_TABLE = GENZ_TABLE_ENUM_START + 2,
    GENZ_COMPONENT_ERROR_ELOG_ENTRY = GENZ_TABLE_ENUM_START + 3,
    GENZ_CORE_LPD_BDF_TABLE = GENZ_TABLE_ENUM_START + 4,
    GENZ_ELOG_TABLE = GENZ_TABLE_ENUM_START + 5,
    GENZ_EVENT_RECORD = GENZ_TABLE_ENUM_START + 6,
    GENZ_FIRMWARE_TABLE = GENZ_TABLE_ENUM_START + 7,
    GENZ_IMAGE_FORMAT_0XC86ED8C24BED49BDA5143DD11950DE9D_HEADER_FORMAT = GENZ_TABLE_ENUM_START + 8,
    GENZ_IMAGE_TABLE = GENZ_TABLE_ENUM_START + 9,
    GENZ_INTERFACE_ERROR_ELOG_ENTRY = GENZ_TABLE_ENUM_START + 10,
    GENZ_LPRT_MPRT_TABLE = GENZ_TABLE_ENUM_START + 11,
    GENZ_LABEL_DATA_TABLE = GENZ_TABLE_ENUM_START + 12,
    GENZ_MCPRT_MSMCPRT_TABLE = GENZ_TABLE_ENUM_START + 13,
    GENZ_MCPRT_MSMCPTR_ROW = GENZ_TABLE_ENUM_START + 14,
    GENZ_MVCAT_TABLE = GENZ_TABLE_ENUM_START + 15,
    GENZ_MEDIA_LOG_TABLE = GENZ_TABLE_ENUM_START + 16,
    GENZ_OEM_DATA_TABLE = GENZ_TABLE_ENUM_START + 17,
    GENZ_OPCODE_SET_TABLE = GENZ_TABLE_ENUM_START + 18,
    GENZ_OPCODE_SET_UUID_TABLE = GENZ_TABLE_ENUM_START + 19,
    GENZ_PA_TABLE = GENZ_TABLE_ENUM_START + 20,
    GENZ_PM_BACKUP_TABLE = GENZ_TABLE_ENUM_START + 21,
    GENZ_PTE_RESTRICTED_PTE_TABLE = GENZ_TABLE_ENUM_START + 22,
    GENZ_PAGE_GRID_RESTRICTED_PAGE_GRID_TABLE = GENZ_TABLE_ENUM_START + 23,
    GENZ_PAGE_TABLE_POINTER_PAIR_TABLE_ENTRY = GENZ_TABLE_ENUM_START + 24,
    GENZ_PERFORMANCE_LOG_RECORD_0 = GENZ_TABLE_ENUM_START + 25,
    GENZ_PERFORMANCE_LOG_RECORD_1 = GENZ_TABLE_ENUM_START + 26,
    GENZ_RE_TABLE = GENZ_TABLE_ENUM_START + 27,
    GENZ_RIT_TABLE = GENZ_TABLE_ENUM_START + 28,
    GENZ_RELIABLE_MULTICAST_RESPONDER_TABLE = GENZ_TABLE_ENUM_START + 29,
    GENZ_RELIABLE_MULTICAST_TABLE = GENZ_TABLE_ENUM_START + 30,
    GENZ_RELIABLE_MULTICAST_TABLE_ENTRY_ROW = GENZ_TABLE_ENUM_START + 31,
    GENZ_REQUESTER_VCAT_TABLE = GENZ_TABLE_ENUM_START + 32,
    GENZ_RESOURCE_TABLE = GENZ_TABLE_ENUM_START + 33,
    GENZ_RESPONDER_VCAT_TABLE = GENZ_TABLE_ENUM_START + 34,
    GENZ_ROUTE_CONTROL_TABLE = GENZ_TABLE_ENUM_START + 35,
    GENZ_SM_BACKUP_TABLE = GENZ_TABLE_ENUM_START + 36,
    GENZ_SSAP_MCAP_MSAP_AND_MSMCAP_TABLE = GENZ_TABLE_ENUM_START + 37,
    GENZ_SSDT_MSDT_TABLE = GENZ_TABLE_ENUM_START + 38,
    GENZ_SSOD_MSOD_TABLE = GENZ_TABLE_ENUM_START + 39,
    GENZ_SERVICE_UUID_TABLE = GENZ_TABLE_ENUM_START + 40,
    GENZ_TR_TABLE = GENZ_TABLE_ENUM_START + 41,
    GENZ_TYPE_1_INTERLEAVE_TABLE = GENZ_TABLE_ENUM_START + 42,
    GENZ_UNRELIABLE_MULTICAST_TABLE = GENZ_TABLE_ENUM_START + 43,
    GENZ_UNRELIABLE_MULTICAST_TABLE_ENTRY_ROW = GENZ_TABLE_ENUM_START + 44,
    GENZ_VCAT_TABLE = GENZ_TABLE_ENUM_START + 45
};

struct genz_control_structure_ptr{
    const enum genz_control_ptr_flags ptr_type;
    const enum genz_pointer_size ptr_size;
    const uint32_t pointer_offset;
    const enum genz_control_structure_type struct_type;
    ssize_t (*size_fn)(struct genz_control_info *ci);
};


union genz_c_status {
    uint64_t val;
    struct {
        uint64_t unsolicited_event_ue_packet_status         : 1;
        uint64_t non_fatal_internal_error_detected          : 1;
        uint64_t fatal_internal_error_detected              : 1;
        uint64_t non_transient_protocol_error_detected      : 1;
        uint64_t bist_failure_detected                      : 1;
        uint64_t component_containment_detected             : 1;
        uint64_t emergency_power_reduction_detected         : 1;
        uint64_t power_off_transition_completed             : 1;
        uint64_t component_thermal_throttled                : 1;
        uint64_t component_thermal_throttled_restoration    : 1;
        uint64_t cannot_execute_persistent_flush            : 1;
        uint64_t refresh_component_configuration_completed  : 1;
        uint64_t operational_error_detected                 : 1;
        uint64_t maximum_outstanding_control_no_op_detected : 1;
        uint64_t rsvdz                                      : 44;
        uint64_t padding                                    : 6;
    };
};


union genz_c_control {
    uint64_t val;
    struct {
        uint64_t component_enable                                  : 1;
        uint64_t upper_thermal_limit_performance_throttle_enable   : 1;
        uint64_t caution_thermal_limit_performance_throttle_enable : 1;
        uint64_t transmit_subnet_local_control_no_op               : 1;
        uint64_t transmit_global_subnet_control_no_op              : 1;
        uint64_t transmit_subnet_local_control_aead                : 1;
        uint64_t transmit_global_subnet_control_aead               : 1;
        uint64_t rsvdp                                             : 45;
        uint64_t padding                                           : 12;
    };
};


union genz_c_state_transition_latency {
    uint32_t val;
    struct {
        uint32_t time_from_c_up_to_c_lp  : 4;
        uint32_t time_from_c_up_to_c_dlp : 4;
        uint32_t time_from_c_lp_to_c_up  : 4;
        uint32_t time_from_c_dlp_to_c_up : 4;
        uint32_t time_from_c_lp_to_c_dlp : 4;
        uint32_t rsvdz                   : 12;
    };
};


union genz_c_idle_times {
    uint16_t val;
    struct {
        uint16_t idle_time_before_transitioning_from_c_up_to_c_lp  : 4;
        uint16_t idle_time_before_transitioning_from_c_lp_to_c_dlp : 4;
        uint16_t rsvdz                                             : 8;
    };
};


union genz_cv {
    uint8_t val;
    struct {
        uint8_t determines_if_cid_0_is_configured       : 1;
        uint8_t determines_if_cid_1_is_configured       : 1;
        uint8_t determines_if_cid_2_is_configured       : 1;
        uint8_t determines_if_cid_3_is_configured       : 1;
        uint8_t rsvdp                                   : 3;
        uint8_t determines_if_sid_0_has_been_configured : 1;
    };
};


union genz_component_cap_1 {
    uint64_t val;
    struct {
        uint64_t no_snoop_support                                                             : 1;
        uint64_t content_component_reset_support_see_component_reset                          : 1; //FIXME: name too long.
        uint64_t built_in_self_test_bist_support                                              : 1;
        uint64_t component_containment_support_see_component_error_and_signal_event_structure : 1; //FIXME: name too long.
        uint64_t next_header_support                                                          : 1;
        uint64_t rsvdz                                                                        : 1;
        uint64_t precision_time_support                                                       : 1;
        uint64_t in_band_management_support                                                   : 1;
        uint64_t out_of_band_management_support                                               : 1;
        uint64_t primary_manager_support                                                      : 1;
        uint64_t fabric_manager_support                                                       : 1;
        uint64_t power_manager_support                                                        : 1;
        uint64_t automatic_c_state_support                                                    : 1;
        uint64_t vendor_defined_power_management_support                                      : 1;
        uint64_t emergency_power_reduction_support                                            : 1;
        uint64_t emergency_power_reduction_relay_support                                      : 1;
        uint64_t power_disable_support                                                        : 1;
        uint64_t mctp_over_gen_z_support                                                      : 1;
        uint64_t multi_subnet_support                                                         : 1;
        uint64_t reserved                                                                     : 2;
        uint64_t nirt_support                                                                 : 1;
        uint64_t emergency_power_reduction_signal_support                                     : 1;
        uint64_t power_disable_signal_support                                                 : 1;
        uint64_t responder_zmmu_interrupt_translation_support                                 : 1;
        uint64_t shared_emergency_signal_support                                              : 1;
        uint64_t management_directed_c_lp_support                                             : 1;
        uint64_t management_directed_c_dlp_support                                            : 1;
        uint64_t fps_support                                                                  : 1;
        uint64_t pco_fps_support                                                              : 1;
        uint64_t component_authentication_support                                             : 1;
        uint64_t management_services_support                                                  : 1;
        uint64_t p2p_next_header_support                                                      : 1;
        uint64_t p2p_aead_support                                                             : 1;
        uint64_t explicit_aead_support                                                        : 1;
        uint64_t component_loopback_support                                                   : 1;
        uint64_t padding                                                                      : 28;
    };
};


union genz_component_cap_1_control {
    uint64_t val;
    struct {
        uint64_t primary_manager_transition_enable      : 1;
        uint64_t fabric_manager_transition_enable       : 1;
        uint64_t next_header_enable                     : 1;
        uint64_t rsvdp                                  : 1;
        uint64_t next_header_precision_time_enable      : 1;
        uint64_t automatic_c_state_enable               : 1;
        uint64_t vendor_defined_power_management_enable : 1;
        uint64_t emergency_power_reduction_enable       : 1;
        uint64_t notify_peer_c_state_change_enable      : 1;
        uint64_t mctp_over_gen_z_enable                 : 1;
        uint64_t meta_read_write_header_enable          : 1;
        uint64_t mgr_uuid_enable                        : 1;
        uint64_t component_loopback_enable              : 1;
        uint64_t software_defined_management_bit_0      : 1;
        uint64_t software_defined_management_bit_1      : 1;
        uint64_t software_defined_management_bit_2      : 1;
        uint64_t software_defined_management_bit_3      : 1;
        uint64_t software_defined_management_bit_4      : 1;
        uint64_t software_defined_management_bit_5      : 1;
        uint64_t software_defined_management_bit_6      : 1;
        uint64_t software_defined_management_bit_7      : 1;
        uint64_t padding                                : 43;
    };
};


union genz_component_cap_2 {
    uint64_t val;
    struct {
        uint64_t responder_memory_interleave_support                  : 1;
        uint64_t requester_memory_interleave_support                  : 1;
        uint64_t sod_support                                          : 1;
        uint64_t write_msg_embedded_read_support                      : 1;
        uint64_t host_lpd_field_type_1_and_type_2_support             : 1;
        uint64_t host_lpd_field_type_0_support                        : 1;
        uint64_t max_perf_records                                     : 5;
        uint64_t host_lpd_field_type_3_support                        : 1;
        uint64_t host_lpd_field_type_4_support                        : 1;
        uint64_t t10_dif_support                                      : 1;
        uint64_t t10_pi_support                                       : 1;
        uint64_t di_pi_block_size_support                             : 8;
        uint64_t reserved                                             : 1;
        uint64_t write_msg_receive_tag_filter_support                 : 1;
        uint64_t write_msg_receive_tag_posting_support                : 1;
        uint64_t write_msg_and_enqueue_dequeue_shared_queue_supported : 1; //FIXME: name too long.
        uint64_t persistent_flush_page_support                        : 1;
        uint64_t rsp_lpd_field_type_5_support                         : 1;
        uint64_t req_lpd_field_type_5_support                         : 1;
        uint64_t enqueue_embedded_read_support                        : 1;
        uint64_t no_op_core_initiation_support                        : 1;
        uint64_t padding                                              : 32;
    };
};


union genz_component_cap_2_control {
    uint64_t val;
    struct {
        uint64_t rsvdp                                   : 1;
        uint64_t pmcid_valid                             : 1;
        uint64_t pfmcid_valid                            : 1;
        uint64_t sfmcid_valid                            : 1;
        uint64_t pfmsid_valid                            : 1;
        uint64_t sfmsid_valid                            : 1;
        uint64_t responder_memory_interleave_enable      : 1;
        uint64_t performance_log_record_enable           : 1;
        uint64_t clear_performance_marker_log            : 1;
        uint64_t host_lpd_field_type_1_and_type_2_enable : 1;
        uint64_t host_lpd_field_type_3_enable            : 1;
        uint64_t host_lpd_field_type_0_enable            : 1;
        uint64_t host_lpd_field_type_4_enable            : 1;
        uint64_t bufreq_t10_dif_pi_enable                : 1;
        uint64_t rsp_lpd_field_type_5_enable             : 1;
        uint64_t req_lpd_field_type_5_enable             : 1;
        uint64_t enqueue_embedded_read_enable            : 1;
        uint64_t padding                                 : 47;
    };
};


union genz_component_cap_3 {
    uint64_t val;
    struct {
        uint64_t reserved                     : 11;
        uint64_t max_supported_home_agents    : 4;
        uint64_t max_supported_caching_agents : 4;
        uint64_t dequeue_16_byte_size_support : 1;
        uint64_t dequeue_32_byte_size_support : 1;
        uint64_t dequeue_64_byte_size_support : 1;
        uint64_t padding                      : 42;
    };
};


union genz_component_cap_3_control {
    uint64_t val;
    struct {
        uint64_t rsvdp                : 4;
        uint64_t home_agent_enable    : 1;
        uint64_t caching_agent_enable : 1;
        uint64_t padding              : 58;
    };
};


union genz_component_cap_4 {
    uint64_t val;
    struct {
        uint64_t reserved : 64;
    };
};


union genz_component_cap_4_control {
    uint64_t val;
    struct {
        uint64_t rsvdp : 64;
    };
};


union genz_thermal_attributes {
    uint16_t val;
    struct {
        uint16_t afi_air_flow_impedance_level    : 4;
        uint16_t max_therm_maximum_thermal_level : 4;
        uint16_t dtherm_degraded_thermal_level   : 4;
        uint16_t maxambient_max_ambient          : 4;
    };
};


union genz_opcode_set_cap_1_control {
    uint32_t val;
    struct {
        uint32_t rsvdp   : 27;
        uint64_t padding : 5;
    };
};


union genz_opcode_set_cap_1 {
    uint64_t val;
    struct {
        uint64_t p2p_vendor_defined_support         : 1;
        uint64_t vdo_opclass_1_support              : 1;
        uint64_t vdo_opclass_2_support              : 1;
        uint64_t vdo_opclass_3_support              : 1;
        uint64_t vdo_opclass_4_support              : 1;
        uint64_t vdo_opclass_5_support              : 1;
        uint64_t vdo_opclass_6_support              : 1;
        uint64_t vdo_opclass_7_support              : 1;
        uint64_t vdo_opclass_8_support              : 1;
        uint64_t per_destination_opcode_set_support : 1;
        uint64_t ldm_1_read_response_meta_support   : 1;
        uint64_t reserved                           : 43;
        uint64_t padding                            : 10;
    };
};


union genz_cache_line_sizes {
    uint8_t val;
    struct {
        uint8_t bytes_32  : 1;
        uint8_t bytes_64  : 1;
        uint8_t bytes_128 : 1;
        uint8_t bytes_256 : 1;
    };
};


union genz_write_poison_sizes {
    uint8_t val;
    struct {
        uint8_t bytes_32   : 1;
        uint8_t bytes_64   : 1;
        uint8_t bytes_128  : 1;
        uint8_t bytes_256  : 1;
        uint8_t bytes_4096 : 1;
        uint8_t reserved   : 3;
    };
};


union genz_arithmetic_atomic_sizes {
    uint8_t val;
    struct {
        uint8_t _8_bit_atomics   : 1;
        uint8_t _16_bit_atomics  : 1;
        uint8_t _32_bit_atomics  : 1;
        uint8_t _64_bit_atomics  : 1;
        uint8_t _128_bit_atomics : 1;
        uint8_t _256_bit_atomics : 1;
        uint8_t _512_bit_atomics : 1;
        uint8_t reserved         : 1;
    };
};


union genz_logical_fetch_atomic_sizes {
    uint8_t val;
    struct {
        uint8_t _8_bit_atomics   : 1;
        uint8_t _16_bit_atomics  : 1;
        uint8_t _32_bit_atomics  : 1;
        uint8_t _64_bit_atomics  : 1;
        uint8_t _128_bit_atomics : 1;
        uint8_t _256_bit_atomics : 1;
        uint8_t _512_bit_atomics : 1;
        uint8_t reserved         : 1;
    };
};


union genz_floating_atomic_sizes {
    uint8_t val;
    struct {
        uint8_t _8_bit_atomics   : 1;
        uint8_t _16_bit_atomics  : 1;
        uint8_t _32_bit_atomics  : 1;
        uint8_t _64_bit_atomics  : 1;
        uint8_t _128_bit_atomics : 1;
        uint8_t _256_bit_atomics : 1;
        uint8_t _512_bit_atomics : 1;
        uint8_t reserved         : 1;
    };
};


union genz_swap_compare_atomic_sizes {
    uint8_t val;
    struct {
        uint8_t _8_bit_atomics   : 1;
        uint8_t _16_bit_atomics  : 1;
        uint8_t _32_bit_atomics  : 1;
        uint8_t _64_bit_atomics  : 1;
        uint8_t _128_bit_atomics : 1;
        uint8_t _256_bit_atomics : 1;
        uint8_t _512_bit_atomics : 1;
        uint8_t reserved         : 1;
    };
};


union genz_supported_un {
    uint16_t val;
    struct {
        uint16_t core_64_write         : 1;
        uint16_t core_64_write_partial : 1;
        uint16_t core_64_interrupt     : 1;
        uint16_t reserved              : 13;
    };
};


union genz_supported_fl {
    uint8_t val;
    struct {
        uint8_t add        : 1;
        uint8_t sum_memory : 1;
        uint8_t vector_sum : 1;
        uint8_t load_min   : 1;
        uint8_t load_max   : 1;
        uint8_t reserved   : 3;
    };
};


union genz_phy_power_enable {
    uint8_t val;
    struct {
        uint8_t phy_lp_1_state_enable    : 1;
        uint8_t phy_lp_2_state_enable    : 1;
        uint8_t phy_lp_3_state_enable    : 1;
        uint8_t phy_lp_4_state_enable    : 1;
        uint8_t phy_up_lp_1_state_enable : 1;
        uint8_t phy_up_lp_2_state_enable : 1;
        uint8_t phy_up_lp_3_state_enable : 1;
        uint8_t phy_up_lp_4_state_enable : 1;
    };
};


union genz_i_status {
    uint32_t val;
    struct {
        uint32_t full_interface_reset                     : 1;
        uint32_t warm_interface_reset                     : 1;
        uint32_t link_rfc_status                          : 1;
        uint32_t peer_link_rfc_ready                      : 1;
        uint32_t peer_link_rfc_ttc                        : 1;
        uint32_t exceeded_transient_error_threshold       : 1;
        uint32_t l_up_to_l_lp_transition_failed           : 1;
        uint32_t link_ctl_completed                       : 1;
        uint32_t interface_containment_detected           : 1;
        uint32_t interface_component_containment_detected : 1;
        uint32_t peer_interface_incompatibility_detected  : 1;
        uint32_t rsvdz                                    : 11;
        uint64_t padding                                  : 10;
    };
};


union genz_i_control {
    uint32_t val;
    struct {
        uint32_t interface_enable                       : 1;
        uint32_t link_rfc_packet_disable                : 1;
        uint32_t interface_access_key_validation_enable : 1;
        uint32_t initiate_l_up_transition               : 1;
        uint32_t p2p_next_header_enable                 : 1;
        uint32_t initiate_peer_nonce_request            : 1;
        uint32_t p2p_aead_enable                        : 1;
        uint32_t p2p_aead_e_key_update_enable           : 1;
        uint32_t rsvdp                                  : 7;
        uint64_t padding                                : 17;
    };
};


union genz_i_cap_1 {
    uint32_t val;
    struct {
        uint32_t interface_containment_support           : 1;
        uint32_t interface_error_fields_support          : 1;
        uint32_t interface_error_logging_support         : 1;
        uint32_t transient_error_threshold_support       : 1;
        uint32_t i_error_fault_injection_support         : 1;
        uint32_t lprt_wildcard_packet_relay_support      : 1;
        uint32_t mprt_wildcard_packet_relay_support      : 1;
        uint32_t interface_loopback_support              : 1;
        uint32_t rsvdz                                   : 1;
        uint32_t p2p_64_support                          : 1;
        uint32_t p2p_vendor_defined_support              : 1;
        uint32_t explicit_opclass_support                : 1;
        uint32_t dr_opclass_support                      : 1;
        uint32_t interface_access_key_validation_support : 1;
        uint32_t link_level_reliability_llr_support      : 1;
        uint32_t tr_interface_support                    : 1;
        uint32_t source_cid_packet_validation_support    : 1;
        uint32_t source_sid_packet_validation_support    : 1;
        uint32_t adaptive_fc_credit_support              : 1;
        uint32_t pco_communications_support              : 1;
        uint32_t peer_nonce_validation_support           : 1;
        uint32_t interface_group_support                 : 1;
        uint32_t point_to_point_backup_support           : 1;
        uint64_t padding                                 : 9;
    };
};


union genz_i_cap_1_control {
    uint32_t val;
    struct {
        uint32_t rsvdp                                                : 1;
        uint32_t transient_error_threshold_enable                     : 1;
        uint32_t i_error_fault_injection_enable                       : 1;
        uint32_t wildcard_packet_relay_enable                         : 1;
        uint32_t interface_loopback_enable                            : 1;
        uint32_t control_opclass_packet_filtering_enable              : 1;
        uint32_t unreliable_control_write_msg_packet_filtering_enable : 1; //FIXME: name too long.
        uint32_t lprt_enable                                          : 1;
        uint32_t mprt_enable                                          : 1;
        uint32_t source_cid_packet_validation_enable                  : 1;
        uint32_t source_sid_packet_validation_enable                  : 1;
        uint32_t adaptive_fc_credit_enable                            : 1;
        uint32_t interface_component_containment_enable               : 1;
        uint32_t peer_nonce_validation_enable                         : 1;
        uint32_t pcie_compatible_ordering_pco_communications_enable   : 1;
        uint32_t link_level_reliability_llr_enable                    : 1;
        uint32_t tr_cid_valid                                         : 1;
        uint32_t precision_time_enable                                : 1;
        uint64_t padding                                              : 14;
    };
};


union genz_i_cap_2 {
    uint32_t val;
    struct {
        uint32_t reserved : 29;
        uint64_t padding  : 3;
    };
};


union genz_i_cap_2_control {
    uint32_t val;
    struct {
        uint32_t software_defined_i_bit_0 : 1;
        uint32_t software_defined_i_bit_1 : 1;
        uint32_t rsvdp                    : 30;
    };
};


union genz_i_error_status {
    uint16_t val;
    struct {
        uint16_t excessive_physical_layer_retraining_events_recorded : 1; //FIXME: name too long.
        uint16_t non_transient_link_error_recorded                   : 1;
        uint16_t interface_containment_recorded                      : 1;
        uint16_t interface_access_key_violation_recorded             : 1;
        uint16_t interface_fc_fwd_progress_violation_recorded        : 1;
        uint16_t unexpected_physical_layer_failure                   : 1;
        uint16_t p2p_sece_recorded                                   : 1;
        uint16_t interface_ae_recorded                               : 1;
        uint16_t switch_packet_relay_failure_recorded                : 1;
        uint16_t rsvdz                                               : 7;
    };
};


union genz_i_error_detect {
    uint16_t val;
    struct {
        uint16_t excessive_physical_layer_retraining_events_detect : 1;
        uint16_t non_transient_link_error_detect                   : 1;
        uint16_t interface_containment_detect                      : 1;
        uint16_t interface_access_key_violation_detect             : 1;
        uint16_t interface_fc_fwd_progress_violation_detect        : 1;
        uint16_t unexpected_physical_layer_failure                 : 1;
        uint16_t p2p_sece_detect                                   : 1;
        uint16_t interface_ae_detect                               : 1;
        uint16_t switch_packet_relay_failure_detect                : 1;
        uint16_t rsvdp                                             : 7;
    };
};


union genz_i_error_fault_injection {
    uint16_t val;
    struct {
        uint16_t test_excessive_physical_layer_retraining_events_error : 1; //FIXME: name too long.
        uint16_t test_non_transient_link_error                         : 1;
        uint16_t rsvdz_shall_be_hardwired_to_0b                        : 1;
        uint16_t test_interface_access_key_violation_error             : 1;
        uint16_t test_interface_fc_fwd_progress_violation_error        : 1;
        uint16_t test_unexpected_physical_layer_failure                : 1;
        uint16_t test_p2p_sece                                         : 1;
        uint16_t test_interface_ae                                     : 1;
        uint16_t test_switch_packet_relay_failure                      : 1;
        uint16_t rsvdz                                                 : 7;
    };
};


union genz_i_error_trigger {
    uint16_t val;
    struct {
        uint16_t excessive_physical_layer_retraining_events_trigger : 1;
        uint16_t non_transient_link_error_trigger                   : 1;
        uint16_t interface_containment_trigger                      : 1;
        uint16_t interface_access_key_violation_trigger             : 1;
        uint16_t interface_fc_fwd_progress_violation_trigger        : 1;
        uint16_t unexpected_physical_layer_failure                  : 1;
        uint16_t p2p_sece_trigger                                   : 1;
        uint16_t interface_ae_trigger                               : 1;
        uint16_t switch_packet_relay_failure_trigger                : 1;
        uint16_t rsvdp                                              : 7;
    };
};


union genz_peer_state {
    uint32_t val;
    struct {
        uint32_t peer_cid_valid                                    : 1;
        uint32_t peer_sid_valid                                    : 1;
        uint32_t peer_interface_id_valid                           : 1;
        uint32_t rsvdp                                             : 1;
        uint32_t peer_interface_p2p_64_opclass_support             : 1;
        uint32_t peer_interface_p2p_vendor_defined_opclass_support : 1;
        uint32_t peer_interface_explicit_opclass_support           : 1;
        uint32_t peer_component_home_agent_support                 : 1;
        uint32_t peer_component_caching_agent_support              : 1;
        uint32_t peer_base_c_class_valid                           : 1;
        uint32_t peer_uniform_opclass_support                      : 1;
        uint32_t peer_link_level_reliability_llr_support           : 1;
        uint32_t peer_p2p_aead_support                             : 1;
        uint32_t peer_p2p_next_header_support                      : 1;
        uint32_t peer_dr_opclass_support                           : 1;
        uint64_t padding                                           : 17;
    };
};


union genz_aggregation_support {
    uint8_t val;
    struct {
        uint8_t interfaces_2   : 1;
        uint8_t interfaces_4   : 1;
        uint8_t interfaces_8   : 1;
        uint8_t interfaces_16  : 1;
        uint8_t interfaces_32  : 1;
        uint8_t interfaces_64  : 1;
        uint8_t interfaces_128 : 1;
        uint8_t interfaces_256 : 1;
    };
};


union genz_c_lp_ctl {
    uint8_t val;
    struct {
        uint8_t link_state_transition_enable : 1;
        uint64_t padding                     : 3;
    };
};


union genz_c_dlp_ctl {
    uint8_t val;
    struct {
        uint8_t link_state_transition_enable : 1;
        uint64_t padding                     : 3;
    };
};


union genz_link_ctl_control {
    uint32_t val;
    struct {
        uint32_t rsvdp                            : 1;
        uint32_t transmit_peer_c_up_enable        : 1;
        uint32_t receive_peer_c_up_enable         : 1;
        uint32_t transmit_peer_c_reset_enable     : 1;
        uint32_t receive_peer_c_reset_enable      : 1;
        uint32_t transmit_enter_link_up_lp_enable : 1;
        uint32_t receive_enter_link_up_lp_enable  : 1;
        uint32_t transmit_enter_link_lp_enable    : 1;
        uint32_t receive_enter_link_lp_enable     : 1;
        uint32_t transmit_link_reset_event_enable : 1;
        uint32_t receive_link_reset_event_enable  : 1;
        uint64_t padding                          : 21;
    };
};


union genz_phy_status {
    uint32_t val;
    struct {
        uint32_t rsvdz   : 16;
        uint64_t padding : 16;
    };
};


union genz_phy_control {
    uint32_t val;
    struct {
        uint32_t rsvdp   : 24;
        uint64_t padding : 8;
    };
};


union genz_phy_cap_1 {
    uint32_t val;
    struct {
        uint32_t auto_train_support      : 1;
        uint32_t level_1_retrain_support : 1;
        uint32_t level_2_retrain_support : 1;
        uint32_t level_3_retrain_support : 1;
        uint32_t level_4_retrain_support : 1;
        uint32_t retrain_level_1         : 4;
        uint32_t retrain_level_2         : 4;
        uint32_t retrain_level_3         : 4;
        uint32_t retrain_level_4         : 4;
        uint32_t reserved                : 10;
        uint64_t padding                 : 1;
    };
};


union genz_phy_cap_1_control {
    uint32_t val;
    struct {
        uint32_t extended_feature_enable : 1;
        uint32_t rsvdp                   : 26;
        uint64_t padding                 : 5;
    };
};


union genz_phy_events {
    uint32_t val;
    struct {
        uint32_t phy_low_power_events  : 16;
        uint32_t phy_retraining_events : 16;
    };
};


union genz_phy_lane_status {
    uint32_t val;
    struct {
        uint32_t rsvdz        : 2;
        uint32_t tx_num_lanes : 12;
        uint32_t rx_num_lanes : 12;
        uint64_t padding      : 6;
    };
};


union genz_phy_lane_control {
    uint32_t val;
    struct {
        uint32_t rsvdp          : 2;
        uint32_t tx_lane_enable : 12;
        uint32_t rx_lane_enable : 12;
        uint64_t padding        : 6;
    };
};


union genz_phy_lane_cap {
    uint32_t val;
    struct {
        uint32_t asymmetric_lane_with_reversal_support : 1;
        uint32_t rsvdp                                 : 2;
        uint32_t tx_lane_support                       : 12;
        uint32_t rx_lane_support                       : 12;
        uint64_t padding                               : 5;
    };
};


union genz_phy_remote_lane_cap {
    uint32_t val;
    struct {
        uint32_t remote_asymmetric_lane_with_reversal_support : 1;
        uint32_t rsvdp                                        : 2;
        uint32_t remote_tx_lane_enable                        : 12;
        uint32_t remote_rx_lane_enable                        : 12;
        uint64_t padding                                      : 5;
    };
};


union genz_phy_lp_cap {
    uint32_t val;
    struct {
        uint32_t phy_lp_1_support : 1;
        uint32_t phy_lp_2_support : 1;
        uint32_t phy_lp_3_support : 1;
        uint32_t phy_lp_4_support : 1;
        uint32_t rsvdp            : 28;
    };
};


union genz_phy_lp_timing_cap {
    uint32_t val;
    struct {
        uint32_t entry_latency_from_phy_up_to_phy_lp1 : 4;
        uint32_t exit_latency_from_phy_lp1_to_phy_up  : 4;
        uint32_t entry_latency_from_phy_up_to_phy_lp2 : 4;
        uint32_t exit_latency_from_phy_lp2_to_phy_up  : 4;
        uint32_t entry_latency_from_phy_up_to_phy_lp3 : 4;
        uint32_t exit_latency_from_phy_lp3_to_phy_up  : 4;
        uint32_t entry_latency_from_phy_up_to_phy_lp4 : 4;
        uint32_t exit_latency_from_phy_lp4_to_phy_up  : 4;
    };
};


union genz_phy_up_lp_cap {
    uint32_t val;
    struct {
        uint32_t phy_up_lp_1_support : 1;
        uint32_t phy_up_lp_2_support : 1;
        uint32_t phy_up_lp_3_support : 1;
        uint32_t phy_up_lp_4_support : 1;
        uint32_t rsvdp               : 28;
    };
};


union genz_phy_up_lp_timing_cap {
    uint32_t val;
    struct {
        uint32_t entry_latency_from_phy_up_to_phy_up_lp1 : 4;
        uint32_t exit_latency_from_phy_up_lp1_to_phy_up  : 4;
        uint32_t entry_latency_from_phy_up_to_phy_up_lp2 : 4;
        uint32_t exit_latency_from_phy_up_lp2_to_phy_up  : 4;
        uint32_t entry_latency_from_phy_up_to_phy_up_lp3 : 4;
        uint32_t exit_latency_from_phy_up_lp3_to_phy_up  : 4;
        uint32_t entry_latency_from_phy_up_to_phy_up_lp4 : 4;
        uint32_t exit_latency_from_phy_up_lp4_to_phy_up  : 4;
    };
};


union genz_i_stat_cap_1 {
    uint16_t val;
    struct {
        uint16_t rsvdz   : 12;
        uint64_t padding : 4;
    };
};


union genz_i_stat_control {
    uint8_t val;
    struct {
        uint8_t statistics_gathering_enable : 1;
        uint8_t rsvdp                       : 5;
        uint64_t padding                    : 2;
    };
};


union genz_i_stat_status {
    uint8_t val;
    struct {
        uint8_t rsvdz    : 6;
        uint64_t padding : 2;
    };
};


union genz_e_control {
    uint16_t val;
    struct {
        uint16_t rsvdp                         : 3;
        uint16_t trigger_component_containment : 1;
        uint16_t error_fault_injection_enable  : 1;
        uint64_t padding                       : 11;
    };
};


union genz_e_status {
    uint16_t val;
    struct {
        uint16_t logging_failed             : 1;
        uint16_t critical_log_entry_consume : 1;
        uint16_t rsvdz                      : 14;
    };
};


union genz_error_signal_cap_1 {
    uint16_t val;
    struct {
        uint16_t signal_interrupt_address_0_support : 1;
        uint16_t signal_interrupt_address_1_support : 1;
        uint16_t c_event_detect_support             : 1;
        uint16_t c_event_injection_support          : 1;
        uint16_t i_event_detect_support             : 1;
        uint16_t i_event_injection_support          : 1;
        uint16_t rsvdz                              : 8;
        uint64_t padding                            : 2;
    };
};


union genz_error_signal_cap_1_control {
    uint16_t val;
    struct {
        uint16_t signal_interrupt_0_enable : 1;
        uint16_t signal_interrupt_1_enable : 1;
        uint16_t c_event_injection_enable  : 1;
        uint16_t i_event_injection_enable  : 1;
        uint16_t rsvdp                     : 12;
    };
};


union genz_c_error_status {
    uint64_t val;
    struct {
        uint64_t component_containment_recorded                                     : 1;
        uint64_t non_fatal_internal_component_error_recorded                        : 1;
        uint64_t fatal_internal_component_error_recorded                            : 1;
        uint64_t end_to_end_unicast_ur_recorded                                     : 1;
        uint64_t end_to_end_unicast_mp_recorded                                     : 1;
        uint64_t end_to_end_unicast_packet_execution_error_exe_non_fatal_recorded   : 1; //FIXME: name too long.
        uint64_t end_to_end_unicast_packet_execution_error_exe_fatal_recorded       : 1; //FIXME: name too long.
        uint64_t end_to_end_unicast_up_recorded                                     : 1;
        uint64_t ae_invalid_access_key_recorded                                     : 1;
        uint64_t ae_invalid_access_permission_recorded                              : 1;
        uint64_t end_to_end_unicast_packet_execution_error_exe_abort_recorded       : 1; //FIXME: name too long.
        uint64_t maximum_request_packet_retransmission_exceeded_recorded            : 1; //FIXME: name too long.
        uint64_t fatal_media_error_containment_triggered_recorded                   : 1;
        uint64_t security_error_sece_recorded                                       : 1;
        uint64_t end_to_end_multicast_ur_recorded                                   : 1;
        uint64_t end_to_end_multicast_mp_recorded                                   : 1;
        uint64_t end_to_end_multicast_packet_execution_error_exe_non_fatal_recorded : 1; //FIXME: name too long.
        uint64_t end_to_end_multicast_packet_execution_error_exe_fatal_recorded     : 1; //FIXME: name too long.
        uint64_t end_to_end_multicast_up_recorded                                   : 1;
        uint64_t sod_up_recorded                                                    : 1;
        uint64_t unexpected_component_power_loss_recorded                           : 1;
        uint64_t insufficient_space_error_recorded                                  : 1;
        uint64_t unsupported_service_for_address_resource_recorded                  : 1;
        uint64_t insufficient_responder_resources_recorded                          : 1;
        uint64_t wake_failure_recorded                                              : 1;
        uint64_t persistent_flush_update_failure_recorded                           : 1;
        uint64_t interface_containment_operational_error_recorded                   : 1;
        uint64_t buffer_aead_failure_recorded                                       : 1;
        uint64_t secured_session_failure_recorded                                   : 1;
        uint64_t security_encryption_key_update_failure_recorded                    : 1;
        uint64_t rsvdz                                                              : 26;
        uint64_t vendor_defined_error_status_bits                                   : 8;
    };
};


union genz_c_error_detect {
    uint64_t val;
    struct {
        uint64_t component_containment_detect                                     : 1;
        uint64_t non_fatal_internal_component_error_detect                        : 1;
        uint64_t fatal_internal_component_error_detect                            : 1;
        uint64_t end_to_end_unicast_ur_detect                                     : 1;
        uint64_t end_to_end_unicast_mp_detect                                     : 1;
        uint64_t end_to_end_unicast_packet_execution_error_exe_non_fatal_detect   : 1; //FIXME: name too long.
        uint64_t end_to_end_unicast_packet_execution_error_exe_fatal_detect       : 1; //FIXME: name too long.
        uint64_t end_to_end_unicast_up_detect                                     : 1;
        uint64_t ae_invalid_access_key_detect                                     : 1;
        uint64_t ae_invalid_access_permission_detect                              : 1;
        uint64_t end_to_end_unicast_packet_execution_error_exe_abort_detect       : 1; //FIXME: name too long.
        uint64_t maximum_request_packet_retransmission_exceeded                   : 1;
        uint64_t fatal_media_error_containment_triggered_detect                   : 1;
        uint64_t security_error_sece_detect                                       : 1;
        uint64_t end_to_end_multicast_ur_detect                                   : 1;
        uint64_t end_to_end_multicast_mp_detect                                   : 1;
        uint64_t end_to_end_multicast_packet_execution_error_exe_non_fatal_detect : 1; //FIXME: name too long.
        uint64_t end_to_end_multicast_packet_execution_error_exe_fatal_detect     : 1; //FIXME: name too long.
        uint64_t end_to_end_multicast_up_detect                                   : 1;
        uint64_t sod_up_detect                                                    : 1;
        uint64_t unexpected_component_power_loss_detect                           : 1;
        uint64_t insufficient_space_error_detect                                  : 1;
        uint64_t unsupported_service_for_address_resource_detect                  : 1;
        uint64_t insufficient_responder_resources_detect                          : 1;
        uint64_t wake_failure_detect                                              : 1;
        uint64_t persistent_flush_update_failure_detect                           : 1;
        uint64_t interface_containment_operational_error_detect                   : 1;
        uint64_t buffer_aead_failure_detect                                       : 1;
        uint64_t security_session_failure_detect                                  : 1;
        uint64_t security_encryption_key_update_failure_detect                    : 1;
        uint64_t rsvdz                                                            : 26;
        uint64_t vendor_defined_error_detect_bits                                 : 8;
    };
};


union genz_c_error_trigger {
    uint64_t val;
    struct {
        uint64_t component_containment_trigger                                     : 1;
        uint64_t non_fatal_internal_component_error_trigger                        : 1;
        uint64_t fatal_internal_component_error_trigger                            : 1;
        uint64_t end_to_end_unicast_ur_trigger                                     : 1;
        uint64_t end_to_end_unicast_mp_trigger                                     : 1;
        uint64_t end_to_end_unicast_packet_execution_error_exe_non_fatal_trigger   : 1; //FIXME: name too long.
        uint64_t end_to_end_unicast_packet_execution_error_exe_fatal_trigger       : 1; //FIXME: name too long.
        uint64_t end_to_end_unicast_up_trigger                                     : 1;
        uint64_t ae_invalid_access_key_trigger                                     : 1;
        uint64_t ae_invalid_access_permission_trigger                              : 1;
        uint64_t end_to_end_unicast_packet_execution_error_exe_abort_trigger       : 1; //FIXME: name too long.
        uint64_t maximum_request_packet_retransmission_exceeded_trigger            : 1; //FIXME: name too long.
        uint64_t fatal_media_error_containment_trigger                             : 1;
        uint64_t security_error_sece_trigger                                       : 1;
        uint64_t end_to_end_multicast_ur_trigger                                   : 1;
        uint64_t end_to_end_multicast_mp_trigger                                   : 1;
        uint64_t end_to_end_multicast_packet_execution_error_exe_non_fatal_trigger : 1; //FIXME: name too long.
        uint64_t end_to_end_multicast_packet_execution_error_exe_fatal_trigger     : 1; //FIXME: name too long.
        uint64_t end_to_end_multicast_up_trigger                                   : 1;
        uint64_t sod_up_trigger                                                    : 1;
        uint64_t unexpected_component_power_loss_trigger                           : 1;
        uint64_t insufficient_space_error_trigger                                  : 1;
        uint64_t unsupported_service_for_address_resource_trigger                  : 1;
        uint64_t insufficient_responder_resources_trigger                          : 1;
        uint64_t wake_failure_trigger                                              : 1;
        uint64_t persistent_flush_update_failure_trigger                           : 1;
        uint64_t interface_containment_operational_error_trigger                   : 1;
        uint64_t buffer_aead_failure_trigger                                       : 1;
        uint64_t security_session_failure_trigger                                  : 1;
        uint64_t security_encryption_key_update_failure_trigger                    : 1;
        uint64_t rsvdp                                                             : 26;
        uint64_t vendor_defined_error_trigger_bits                                 : 8;
    };
};


union genz_c_error_fault_injection {
    uint64_t val;
    struct {
        uint64_t rsvdz_shall_be_hardwired_to_0b                                       : 1;
        uint64_t test_non_fatal_internal_component_error                              : 1;
        uint64_t test_fatal_internal_component_error                                  : 1;
        uint64_t test_end_to_end_unicast_ur_error                                     : 1;
        uint64_t test_end_to_end_unicast_mp_error                                     : 1;
        uint64_t test_end_to_end_unicast_packet_execution_error_exe_non_fatal_error   : 1; //FIXME: name too long.
        uint64_t test_end_to_end_unicast_packet_execution_error_exe_fatal_error       : 1; //FIXME: name too long.
        uint64_t test_end_to_end_unicast_up_error                                     : 1;
        uint64_t test_ae_invalid_access_key_error                                     : 1;
        uint64_t test_ae_invalid_access_permission_error                              : 1;
        uint64_t test_end_to_end_unicast_packet_execution_error_exe_abort             : 1; //FIXME: name too long.
        uint64_t test_maximum_request_packet_retransmission_exceeded_error            : 1; //FIXME: name too long.
        uint64_t rsvdz                                                                : 1;
        uint64_t security_error_sece                                                  : 1;
        uint64_t test_end_to_end_multicast_ur_error                                   : 1;
        uint64_t test_end_to_end_multicast_mp_error                                   : 1;
        uint64_t test_end_to_end_multicast_packet_execution_error_exe_non_fatal_error : 1; //FIXME: name too long.
        uint64_t test_end_to_end_multicast_packet_execution_error_exe_fatal_error     : 1; //FIXME: name too long.
        uint64_t test_end_to_end_multicast_up_error                                   : 1;
        uint64_t test_sod_up_error                                                    : 1;
        uint64_t test_unexpected_component_power_loss                                 : 1;
        uint64_t test_insufficient_space_error                                        : 1;
        uint64_t test_unsupported_service_for_address_resource_error                  : 1; //FIXME: name too long.
        uint64_t test_insufficient_responder_resources_error                          : 1;
        uint64_t test_wake_failure_error                                              : 1;
        uint64_t test_persistent_flush_update_failure_error                           : 1;
        uint64_t test_interface_containment_operational_error                         : 1;
        uint64_t test_buffer_aead_failure_error                                       : 1;
        uint64_t test_security_session_failure_error                                  : 1;
        uint64_t test_security_encryption_key_update_failure_error                    : 1;
        uint64_t test_vendor_defined_error                                            : 8;
        uint64_t padding                                                              : 26;
    };
};


union genz_c_event_detect {
    uint64_t val;
    struct {
        uint64_t bist_failure_event_detect                                         : 1;
        uint64_t unable_to_communicate_with_an_authorized_destination_event_detect : 1; //FIXME: name too long.
        uint64_t excessive_rnr_nak_responses_event_detect                          : 1;
        uint64_t peer_component_c_dlp_exit_event_detect                            : 1;
        uint64_t component_thermal_shutdown_event_detect                           : 1;
        uint64_t possible_malicious_packet_event_detect                            : 1;
        uint64_t invalid_component_image_event_detect                              : 1;
        uint64_t c_lp_entry_event_detect                                           : 1;
        uint64_t c_lp_exit_event_detect                                            : 1;
        uint64_t c_dlp_entry_event_detect_inform_management_prior_to_c_dlp_entry   : 1; //FIXME: name too long.
        uint64_t c_dlp_exit_event_detect                                           : 1;
        uint64_t peer_component_c_dlp_entry_event_detect                           : 1;
        uint64_t emergency_power_reduction_triggered_event_detect                  : 1;
        uint64_t rsvdp                                                             : 1;
        uint64_t component_power_off_transition_completed_event_detect             : 1; //FIXME: name too long.
        uint64_t component_power_restoration_event_detect                          : 1;
        uint64_t primary_media_maintenance_required_event_detect                   : 1;
        uint64_t primary_media_maintenance_override_event_detect                   : 1;
        uint64_t secondary_media_maintenance_required_event_detect                 : 1;
        uint64_t secondary_media_maintenance_override_event_detect                 : 1;
        uint64_t component_thermal_throttle_event_detect                           : 1;
        uint64_t component_thermal_throttle_restoration_event_detect               : 1; //FIXME: name too long.
        uint64_t p2p                                                               : 1;
        uint64_t peer_component_c_lp_entry_event_detect                            : 1;
        uint64_t peer_component_c_lp_exit_event_detect                             : 1;
        uint64_t vendor_defined_event_detect                                       : 4;
        uint64_t padding                                                           : 35;
    };
};


union genz_i_event_detect {
    uint64_t val;
    struct {
        uint64_t full_interface_reset_event_detect                                                                                          : 1;
        uint64_t warm_interface_reset_event_detect                                                                                          : 1;
        uint64_t new_peer_component_detected_event_detect_link_rfc_os_15_0_0x0_packet_received_out_of_band_signal_or_event_notification_etc : 1; //FIXME: name too long.
        uint64_t exceeded_transient_error_threshold_event_detect_see_interface_structure                                                    : 1; //FIXME: name too long.
        uint64_t rsvdp                                                                                                                      : 1;
        uint64_t interface_performance_degradation_event_detect                                                                             : 1;
        uint64_t vendor_defined_i_event_detect                                                                                              : 4;
        uint64_t padding                                                                                                                    : 54;
    };
};


union genz_i_event_injection {
    uint64_t val;
    struct {
        uint64_t inject_full_interface_reset_event                        : 1;
        uint64_t inject_warm_interface_reset_event                        : 1;
        uint64_t inject_new_peer_component_detected_event                 : 1;
        uint64_t inject_exceeded_transient_error_threshold_event          : 1;
        uint64_t rsvdz                                                    : 1;
        uint64_t inject_interface_performance_degradation_event           : 1;
        uint64_t inject_vendor_defined_i_event                            : 1;
        uint64_t inject_the_vendor_defined_i_event_associated_with_bit_60 : 1; //FIXME: name too long.
        uint64_t inject_the_vendor_defined_i_event_associated_with_bit_61 : 1; //FIXME: name too long.
        uint64_t inject_the_vendor_defined_i_event_associated_with_bit_62 : 1; //FIXME: name too long.
        uint64_t inject_the_vendor_defined_i_event_associated_with_bit_63 : 1; //FIXME: name too long.
        uint64_t padding                                                  : 53;
    };
};


union genz_e_control_2 {
    uint32_t val;
    struct {
        uint32_t rsvdp   : 30;
        uint64_t padding : 2;
    };
};


union genz_c_event_status {
    uint64_t val;
    struct {
        uint64_t bist_failure_event_recorded                                         : 1;
        uint64_t unable_to_communicate_with_an_authorized_destination_event_recorded : 1; //FIXME: name too long.
        uint64_t excessive_rnr_nak_responses_event_recorded                          : 1;
        uint64_t peer_component_c_dlp_exit_event_recorded                            : 1;
        uint64_t component_thermal_shutdown_event_recorded                           : 1;
        uint64_t possible_malicious_packet_event_recorded                            : 1;
        uint64_t invalid_component_image_event_recorded                              : 1;
        uint64_t c_lp_entry_event_recorded                                           : 1;
        uint64_t c_lp_exit_event_recorded                                            : 1;
        uint64_t c_dlp_entry_event_recorded                                          : 1;
        uint64_t c_dlp_exit_event_recorded                                           : 1;
        uint64_t peer_component_c_dlp_entry_event_recorded                           : 1;
        uint64_t emergency_power_reduction_triggered_event_recorded                  : 1;
        uint64_t rsvdz                                                               : 1;
        uint64_t component_power_off_transition_completed_event_recorded             : 1; //FIXME: name too long.
        uint64_t component_power_restoration_event_recorded                          : 1;
        uint64_t primary_media_maintenance_required_event_recorded                   : 1;
        uint64_t primary_media_maintenance_override_event_recorded                   : 1;
        uint64_t secondary_media_maintenance_required_event_recorded                 : 1; //FIXME: name too long.
        uint64_t secondary_media_maintenance_override_event_recorded                 : 1; //FIXME: name too long.
        uint64_t component_thermal_throttle_event_recorded                           : 1;
        uint64_t component_thermal_throttle_restoration_event_recorded               : 1; //FIXME: name too long.
        uint64_t p2p                                                                 : 1;
        uint64_t peer_component_c_lp_entry_event_recorded                            : 1;
        uint64_t peer_component_c_lp_exit_event_recorded                             : 1;
        uint64_t vendor_defined_event_recorded                                       : 4;
        uint64_t padding                                                             : 35;
    };
};


union genz_i_event_status {
    uint64_t val;
    struct {
        uint64_t full_interface_reset_event_recorded               : 1;
        uint64_t warm_interface_reset_event_recorded               : 1;
        uint64_t new_peer_component_detected_event_recorded        : 1;
        uint64_t exceeded_transient_error_threshold_event_recorded : 1;
        uint64_t rsvdz                                             : 1;
        uint64_t interface_performance_degradation_event_recorded  : 1;
        uint64_t vendor_defined_i_event_recorded                   : 4;
        uint64_t padding                                           : 54;
    };
};


union genz_component_media_control {
    uint32_t val;
    struct {
        uint32_t media_fault_injection_enable : 1;
        uint32_t rsvdp                        : 17;
        uint64_t padding                      : 14;
    };
};


union genz_primary_media_status {
    uint64_t val;
    struct {
        uint64_t primary_media_uninitialized                                                 : 1;
        uint64_t primary_media_initialization_in_progress                                    : 1;
        uint64_t primary_media_initialization_failed_invalid_cryptographic_key               : 1; //FIXME: name too long.
        uint64_t primary_media_initialization_failed_media_controller_error_or_media_failure : 1; //FIXME: name too long.
        uint64_t primary_media_initialization_succeeded                                      : 1;
        uint64_t primary_fatal_media_error_containment                                       : 1;
        uint64_t primary_media_patrol_scrubbing_in_progress                                  : 1;
        uint64_t primary_media_patrol_scrubbing_completed                                    : 1;
        uint64_t primary_media_demand_scrubbing_in_progress                                  : 1;
        uint64_t primary_media_maintenance_in_progress                                       : 1;
        uint64_t primary_media_maintenance_completed                                         : 1;
        uint64_t primary_media_maintenance_partial_completion                                : 1;
        uint64_t primary_media_maintenance_required                                          : 1;
        uint64_t primary_media_maintenance_override                                          : 1;
        uint64_t primary_media_deallocate_primary_range_in_progress                          : 1;
        uint64_t primary_media_deallocate_primary_range_succeeded                            : 1;
        uint64_t primary_media_deallocate_primary_range_failed                               : 1;
        uint64_t primary_media_logging_failed                                                : 1;
        uint64_t primary_media_row_remapping_in_progress                                     : 1;
        uint64_t primary_media_row_remapping_succeeded                                       : 1;
        uint64_t primary_media_no_row_remapping_resources_available                          : 1;
        uint64_t primary_media_row_remapping_failed_media_controller_error                   : 1; //FIXME: name too long.
        uint64_t primary_media_reached_90_spare_row_consumption                              : 1;
        uint64_t primary_media_reached_100_spare_row_consumption                             : 1;
        uint64_t primary_media_device_sparing_in_progress                                    : 1;
        uint64_t primary_media_device_sparing_succeeded                                      : 1;
        uint64_t primary_media_device_sparing_failed_no_spare_device                         : 1; //FIXME: name too long.
        uint64_t primary_media_device_sparing_failed_media_controller_error                  : 1; //FIXME: name too long.
        uint64_t primary_media_current_number_of_spare_memory_devices                        : 4; //FIXME: name too long.
        uint64_t primary_media_se_in_progress                                                : 1;
        uint64_t primary_media_se_succeeded                                                  : 1;
        uint64_t primary_media_se_failed                                                     : 1;
        uint64_t primary_media_read_endurance_reached_10                                     : 1;
        uint64_t primary_media_read_endurance_reached_0                                      : 1;
        uint64_t primary_media_read_endurance_notification_event                             : 1;
        uint64_t primary_media_write_endurance_reached_10                                    : 1;
        uint64_t primary_media_write_endurance_reached_0                                     : 1;
        uint64_t primary_media_write_endurance_notification_event                            : 1;
        uint64_t factory_default_success                                                     : 1;
        uint64_t factory_default_error                                                       : 1;
        uint64_t factory_default_abort_success                                               : 1;
        uint64_t factory_default_abort_error                                                 : 1;
        uint64_t factory_default_in_progress                                                 : 1;
        uint64_t media_controller_error                                                      : 1;
        uint64_t voltage_regulator_failed                                                    : 1;
        uint64_t rsvdz                                                                       : 16;
    };
};


union genz_secondary_media_status {
    uint64_t val;
    struct {
        uint64_t secondary_media_uninitialized                                           : 1;
        uint64_t secondary_media_initialization_in_progress                              : 1;
        uint64_t secondary_media_initialization_failed_invalid_cryptographic_key         : 1; //FIXME: name too long.
        uint64_t secondary_media_initialization_failed_media_controller_error_or_failure : 1; //FIXME: name too long.
        uint64_t secondary_media_initialization_succeeded                                : 1;
        uint64_t secondary_fatal_media_error_containment                                 : 1;
        uint64_t secondary_media_patrol_scrubbing_in_progress                            : 1;
        uint64_t secondary_media_patrol_scrubbing_completed                              : 1;
        uint64_t secondary_media_demand_scrubbing_in_progress                            : 1;
        uint64_t secondary_media_maintenance_in_progress                                 : 1;
        uint64_t secondary_media_maintenance_completed                                   : 1;
        uint64_t secondary_media_maintenance_partial_completion                          : 1;
        uint64_t secondary_media_maintenance_required                                    : 1;
        uint64_t secondary_media_maintenance_override                                    : 1;
        uint64_t secondary_media_deallocate_secondary_range_in_progress                  : 1; //FIXME: name too long.
        uint64_t secondary_media_deallocate_secondary_range_succeeded                    : 1; //FIXME: name too long.
        uint64_t secondary_media_deallocate_secondary_range_failed                       : 1;
        uint64_t secondary_media_logging_failed                                          : 1;
        uint64_t secondary_media_row_remapping_in_progress                               : 1;
        uint64_t secondary_media_row_remapping_succeeded                                 : 1;
        uint64_t secondary_media_no_row_remapping_resources_available                    : 1; //FIXME: name too long.
        uint64_t secondary_media_row_remapping_failed_media_controller_error             : 1; //FIXME: name too long.
        uint64_t secondary_media_reached_90_spare_row_consumption                        : 1;
        uint64_t secondary_media_reached_100_spare_row_consumption                       : 1;
        uint64_t secondary_media_device_sparing_in_progress                              : 1;
        uint64_t secondary_media_device_sparing_succeeded                                : 1;
        uint64_t secondary_media_no_spare_device                                         : 1;
        uint64_t secondary_media_device_sparing_failed_media_controller_error            : 1; //FIXME: name too long.
        uint64_t secondary_media_current_number_of_spare_memory_devices                  : 4; //FIXME: name too long.
        uint64_t secondary_media_se_in_progress                                          : 1;
        uint64_t secondary_media_se_succeeded                                            : 1;
        uint64_t secondary_media_se_failed                                               : 1;
        uint64_t secondary_media_read_endurance_reached_10                               : 1;
        uint64_t secondary_media_read_endurance_reached_0                                : 1;
        uint64_t secondary_media_read_endurance_notification_event                       : 1;
        uint64_t secondary_media_write_endurance_reached_10                              : 1;
        uint64_t secondary_media_write_endurance_reached_0                               : 1;
        uint64_t secondary_media_write_endurance_notification_event                      : 1;
        uint64_t secondary_media_persistency_lost                                        : 1;
        uint64_t media_controller_error                                                  : 1;
        uint64_t secondary_media_specific_controller_error                               : 1;
        uint64_t secondary_media_error                                                   : 1;
        uint64_t rsvdz                                                                   : 19;
    };
};


union genz_primary_media_cap_1_63_0 {
    uint64_t val;
    struct {
        uint64_t primary_read_latency_base         : 7;
        uint64_t primary_write_latency_base        : 7;
        uint64_t primary_read_endurance_base       : 8;
        uint64_t primary_write_endurance_base      : 8;
        uint64_t primary_maximum_media_power_level : 10;
        uint64_t padding                           : 24;
    };
};


union genz_primary_media_cap_1_127_64 {
    uint64_t val;
    struct {
        uint64_t primary_demand_scrubbing_support              : 1;
        uint64_t primary_patrol_scrubbing_support              : 1;
        uint64_t primary_poison_support                        : 1;
        uint64_t primary_max_error_detection_bits              : 7;
        uint64_t primary_max_error_corrected_bits              : 7;
        uint64_t primary_factory_default_support               : 1;
        uint64_t rsvdz                                         : 1;
        uint64_t primary_media_fault_injection_support         : 1;
        uint64_t primary_se_zero_media_support                 : 1;
        uint64_t primary_se_zero_media_range_support           : 1;
        uint64_t primary_se_cryptographic_key_support          : 1;
        uint64_t primary_se_overwrite_media_support            : 1;
        uint64_t primary_se_vendor_defined_support             : 1;
        uint64_t primary_se_vendor_defined_range_support       : 1;
        uint64_t primary_fatal_media_error_containment_support : 1;
        uint64_t primary_spare_media_devices                   : 4;
        uint64_t padding                                       : 33;
    };
};


union genz_secondary_media_cap_1_63_0 {
    uint64_t val;
    struct {
        uint64_t secondary_read_latency_base                                                                                                      : 7;
        uint64_t secondary_write_latency_base                                                                                                     : 7;
        uint64_t secondary_read_endurance_base                                                                                                    : 8;
        uint64_t secondary_write_endurance_base_an_unsigned_integer_used_to_calculate_the_maximum_write_endurance_associated_with_this_media_type : 8; //FIXME: name too long.
        uint64_t secondary_maximum_media_power_level                                                                                              : 10;
        uint64_t rsvdz                                                                                                                            : 1;
        uint64_t padding                                                                                                                          : 23;
    };
};


union genz_secondary_media_cap_1_127_64 {
    uint64_t val;
    struct {
        uint64_t secondary_demand_scrubbing_support              : 1;
        uint64_t secondary_patrol_scrubbing_support              : 1;
        uint64_t secondary_poison_support                        : 1;
        uint64_t secondary_max_error_detection_bits              : 7;
        uint64_t secondary_max_error_corrected_bits              : 7;
        uint64_t secondary_media_fault_injection_support         : 1;
        uint64_t secondary_se_zero_media_support                 : 1;
        uint64_t secondary_se_zero_media_range_support           : 1;
        uint64_t secondary_se_cryptographic_key_support          : 1;
        uint64_t secondary_se_overwrite_media_support            : 1;
        uint64_t secondary_se_vendor_defined_support             : 1;
        uint64_t secondary_se_vendor_defined_range_support       : 1;
        uint64_t secondary_fatal_media_error_containment_support : 1;
        uint64_t primary_media_backup_operations_support         : 1;
        uint64_t rsvdz                                           : 1;
        uint64_t secondary_media_caching_support                 : 1;
        uint64_t secondary_spare_media_devices                   : 4;
        uint64_t padding                                         : 32;
    };
};


union genz_primary_media_cap_1_control {
    uint64_t val;
    struct {
        uint64_t primary_correctable_error_reporting_enable   : 1;
        uint64_t primary_uncorrectable_error_reporting_enable : 1;
        uint64_t primary_demand_scrubbing_enable              : 1;
        uint64_t primary_patrol_scrubbing_enable              : 1;
        uint64_t primary_device_sparing_enable                : 1;
        uint64_t primary_poison_forwarding_enable             : 1;
        uint64_t primary_fault_injection_enable               : 1;
        uint64_t primary_initiate_factory_default             : 1;
        uint64_t deallocate_primary_range                     : 1;
        uint64_t primary_abort_factory_default                : 1;
        uint64_t rsvdp                                        : 35;
        uint64_t padding                                      : 19;
    };
};


union genz_secondary_media_cap_1_control {
    uint64_t val;
    struct {
        uint64_t secondary_correctable_error_reporting_enable   : 1;
        uint64_t secondary_uncorrectable_error_reporting_enable : 1;
        uint64_t secondary_demand_scrubbing_enable              : 1;
        uint64_t secondary_patrol_scrubbing_enable              : 1;
        uint64_t secondary_device_sparing_enable                : 1;
        uint64_t secondary_poison_forwarding_enable             : 1;
        uint64_t secondary_fault_injection_enable               : 1;
        uint64_t rsvdp                                          : 1;
        uint64_t secondary_media_caching_enable                 : 1;
        uint64_t deallocate_secondary_range                     : 1;
        uint64_t padding                                        : 54;
    };
};


union genz_primary_media_fault_injection {
    uint64_t val;
    struct {
        uint64_t primary_media_initialization_failed_invalid_cryptographic_key         : 1; //FIXME: name too long.
        uint64_t primary_media_initialization_failed_media_controller_error_or_failure : 1; //FIXME: name too long.
        uint64_t primary_media_initialization_succeeded                                : 1;
        uint64_t primary_media_fatal_media_error_containment                           : 1;
        uint64_t primary_media_patrol_scrubbing_completed                              : 1;
        uint64_t primary_media_patrol_scrubbing_failed                                 : 1;
        uint64_t primary_media_maintenance_partial_completion                          : 1;
        uint64_t primary_media_maintenance_required                                    : 1;
        uint64_t primary_media_maintenance_override                                    : 1;
        uint64_t primary_media_deallocate_range_succeeded                              : 1;
        uint64_t primary_media_deallocate_range_failed                                 : 1;
        uint64_t primary_media_row_remapping_succeeded                                 : 1;
        uint64_t primary_media_no_row_remapping_resources_available                    : 1;
        uint64_t primary_media_row_remapping_failed_media_controller_error             : 1; //FIXME: name too long.
        uint64_t primary_media_reached_90_spare_row_consumption                        : 1;
        uint64_t primary_media_reached_100_spare_row_consumption                       : 1;
        uint64_t primary_media_device_sparing_succeeded                                : 1;
        uint64_t primary_media_no_device_sparing_resources_available                   : 1; //FIXME: name too long.
        uint64_t primary_media_device_sparing_failed_media_controller_error            : 1; //FIXME: name too long.
        uint64_t primary_media_se_succeeded                                            : 1;
        uint64_t primary_media_se_failed                                               : 1;
        uint64_t primary_media_read_endurance_reached_10                               : 1;
        uint64_t primary_media_read_endurance_reached_0                                : 1;
        uint64_t primary_media_read_endurance_notification_event                       : 1;
        uint64_t primary_media_write_endurance_reached_10                              : 1;
        uint64_t primary_media_write_endurance_reached_0                               : 1;
        uint64_t primary_media_write_endurance_notification_event                      : 1;
        uint64_t primary_media_unstable_insufficient_main_power                        : 1;
        uint64_t primary_media_unexpected_main_power_loss                              : 1;
        uint64_t primary_media_fatal_media_device_error                                : 1;
        uint64_t primary_media_controller_internal_error                               : 1;
        uint64_t primary_media_uncorrectable_error_detected                            : 1;
        uint64_t primary_media_poison_event                                            : 1;
        uint64_t rsvdz                                                                 : 27;
        uint64_t inject_vendor_defined_event                                           : 4;
    };
};


union genz_secondary_media_fault_injection {
    uint64_t val;
    struct {
        uint64_t secondary_media_initialization_failed_invalid_cryptographic_key         : 1; //FIXME: name too long.
        uint64_t secondary_media_initialization_failed_media_controller_error_or_failure : 1; //FIXME: name too long.
        uint64_t secondary_media_initialization_succeeded                                : 1;
        uint64_t secondary_media_fatal_media_error_containment                           : 1;
        uint64_t secondary_media_patrol_scrubbing_completed                              : 1;
        uint64_t secondary_media_patrol_scrubbing_failed                                 : 1;
        uint64_t secondary_media_maintenance_partial_completion                          : 1;
        uint64_t secondary_media_maintenance_required                                    : 1;
        uint64_t secondary_media_maintenance_override                                    : 1;
        uint64_t secondary_media_deallocate_range_succeeded                              : 1;
        uint64_t secondary_media_deallocate_range_failed                                 : 1;
        uint64_t secondary_media_row_remapping_succeeded                                 : 1;
        uint64_t secondary_media_no_row_remapping_resources_available                    : 1; //FIXME: name too long.
        uint64_t secondary_media_row_remapping_failed_media_controller_error             : 1; //FIXME: name too long.
        uint64_t secondary_media_reached_90_spare_row_consumption                        : 1;
        uint64_t secondary_media_reached_100_spare_row_consumption                       : 1;
        uint64_t secondary_media_device_sparing_succeeded                                : 1;
        uint64_t secondary_media_no_device_sparing_resources_available                   : 1; //FIXME: name too long.
        uint64_t secondary_media_device_sparing_failed_media_controller_error            : 1; //FIXME: name too long.
        uint64_t secondary_media_se_succeeded                                            : 1;
        uint64_t secondary_media_se_failed                                               : 1;
        uint64_t secondary_media_read_endurance_reached_10                               : 1;
        uint64_t secondary_media_read_endurance_reached_0                                : 1;
        uint64_t secondary_media_read_endurance_notification_event                       : 1;
        uint64_t secondary_media_write_endurance_reached_10                              : 1;
        uint64_t secondary_media_write_endurance_reached_0                               : 1;
        uint64_t secondary_media_write_endurance_notification_event                      : 1;
        uint64_t secondary_media_unstable_insufficient_main_power                        : 1;
        uint64_t secondary_media_unexpected_main_power_loss                              : 1;
        uint64_t secondary_media_fatal_media_device_error                                : 1;
        uint64_t secondary_media_controller_internal_error                               : 1;
        uint64_t secondary_media_uncorrectable_error_detected                            : 1;
        uint64_t secondary_media_poison_event                                            : 1;
        uint64_t rsvdz                                                                   : 27;
        uint64_t inject_vendor_defined_event                                             : 4;
    };
};


union genz_power_status {
    uint16_t val;
    struct {
        uint16_t module_power_good           : 1;
        uint16_t unstable_insufficient_power : 1;
        uint16_t unexpected_power_loss       : 1;
        uint16_t rsvdz                       : 13;
    };
};


union genz_switch_cap_1 {
    uint32_t val;
    struct {
        uint32_t control_opclass_packet_filtering_support              : 1;
        uint32_t pco_communications_support                            : 1;
        uint32_t unreliable_control_write_msg_packet_filtering_support : 1; //FIXME: name too long.
        uint32_t default_collective_packet_relay_support               : 1;
        uint32_t reserved                                              : 26;
        uint64_t padding                                               : 2;
    };
};


union genz_switch_cap_1_control {
    uint32_t val;
    struct {
        uint32_t mcprt_enable                           : 1;
        uint32_t msmcprt_enable                         : 1;
        uint32_t default_multicast_packet_relay_enable  : 1;
        uint32_t default_collective_packet_relay_enable : 1;
        uint32_t rsvdp                                  : 28;
    };
};


union genz_switch_status {
    uint16_t val;
    struct {
        uint16_t rsvdz : 16;
    };
};


union genz_switch_op_ctl {
    uint16_t val;
    struct {
        uint16_t packet_relay_enable : 1;
        uint16_t rsvdp               : 15;
    };
};


union genz_cstat_cap_1 {
    uint8_t val;
    struct {
        uint8_t rsvdp : 8;
    };
};


union genz_cstat_control {
    uint8_t val;
    struct {
        uint8_t statistics_gathering_enable : 1;
        uint8_t rsvdp                       : 5;
        uint64_t padding                    : 2;
    };
};


union genz_cstat_status {
    uint8_t val;
    struct {
        uint8_t rsvdz    : 6;
        uint64_t padding : 2;
    };
};


union genz_mcast_cap_1 {
    uint16_t val;
    struct {
        uint16_t reliable_multicast_support : 1;
        uint16_t rsvdz                      : 9;
        uint64_t padding                    : 6;
    };
};


union genz_mcast_cap_1_control {
    uint16_t val;
    struct {
        uint16_t unreliable_multicast_enable : 1;
        uint16_t reliable_multicast_enable   : 1;
        uint16_t rsvdp                       : 13;
        uint64_t padding                     : 1;
    };
};


union genz_tr_status {
    uint32_t val;
    struct {
        uint32_t request_packet_relay_failure  : 1;
        uint32_t response_packet_relay_failure : 1;
        uint32_t access_key_status             : 1;
        uint32_t rsvdz                         : 29;
    };
};


union genz_image_cap_1 {
    uint16_t val;
    struct {
        uint16_t crc16_support                        : 1;
        uint16_t image_hash_digest_support            : 1;
        uint16_t image_encryption_support             : 1;
        uint16_t control_space_image_location_support : 1;
        uint16_t data_space_image_location_support    : 1;
        uint16_t image_fault_injection_support        : 1;
        uint16_t rsvdz                                : 9;
        uint64_t padding                              : 1;
    };
};


union genz_image_cap_1_control {
    uint16_t val;
    struct {
        uint16_t image_fault_injection_enable : 1;
        uint16_t rsvdp                        : 15;
    };
};


union genz_image_table_control {
    uint16_t val;
    struct {
        uint16_t rsvdp : 16;
    };
};


union genz_image_fault_injection {
    uint16_t val;
    struct {
        uint16_t image_checksum_failure  : 1;
        uint16_t image_hash_digest_error : 1;
        uint16_t image_encryption_error  : 1;
        uint16_t rsvdz                   : 13;
    };
};


union genz_image_detect {
    uint16_t val;
    struct {
        uint16_t image_checksum_failure_detect  : 1;
        uint16_t image_hash_digest_error_detect : 1;
        uint16_t image_encryption_error_detect  : 1;
        uint16_t rsvdp                          : 13;
    };
};


union genz_pt_cap_1 {
    uint16_t val;
    struct {
        uint16_t precision_time_requester_support : 1;
        uint16_t precision_time_responder_support : 1;
        uint16_t precision_time_gtc_support       : 1;
        uint16_t rsvdz                            : 12;
        uint64_t padding                          : 1;
    };
};


union genz_pt_ctl {
    uint16_t val;
    struct {
        uint16_t rsvdp   : 10;
        uint64_t padding : 6;
    };
};


union genz_mechanical_event_status {
    uint32_t val;
    struct {
        uint32_t runtime_module_insertion_recorded               : 1;
        uint32_t runtime_module_removal_recorded                 : 1;
        uint32_t attention_button_pressed_recorded               : 1;
        uint32_t attention_indicator_on_continuously_recorded    : 1;
        uint32_t module_power_up_recorded                        : 1;
        uint32_t module_power_off_recorded                       : 1;
        uint32_t mrl_open_recorded                               : 1;
        uint32_t mrl_close_recorded                              : 1;
        uint32_t module_indicator_activated_recorded             : 1;
        uint32_t controller_cmd_completion_notification_recorded : 1;
        uint32_t power_fault_recorded                            : 1;
        uint32_t auxiliary_power_up_recorded                     : 1;
        uint32_t auxiliary_power_off_recorded                    : 1;
        uint32_t rsvdz                                           : 19;
    };
};


union genz_mechanical_cap_1 {
    uint64_t val;
    struct {
        uint64_t attention_button_support                                                               : 1;
        uint64_t attention_indicator_support                                                            : 1;
        uint64_t power_controller_support                                                               : 1;
        uint64_t power_indicator_support                                                                : 1;
        uint64_t mrl_sensor_support                                                                     : 1;
        uint64_t electromechanical_interlock_support                                                    : 1;
        uint64_t common_reference_clock_support                                                         : 1;
        uint64_t controller_cmd_completion_notification_support                                         : 1;
        uint64_t max_mech_power_lvl_is_used_to_calculate_the_maximum_power_a_mechanical_module_supports : 10; //FIXME: name too long.
        uint64_t main_power_voltage_support                                                             : 8;
        uint64_t module_indicator_present_notification_support                                          : 1;
        uint64_t module_indicator_locate_notification_support                                           : 1;
        uint64_t module_indicator_failure_notification_support                                          : 1;
        uint64_t module_indicator_notification_1_support                                                : 1;
        uint64_t module_indicator_notification_2_support                                                : 1;
        uint64_t module_indicator_notification_3_support                                                : 1;
        uint64_t module_indicator_notification_4_support                                                : 1;
        uint64_t module_indicator_notification_5_support                                                : 1;
        uint64_t module_indicator_notification_6_support                                                : 1;
        uint64_t module_indicator_notification_7_support                                                : 1;
        uint64_t module_indicator_vendor_defined_1_support                                              : 1;
        uint64_t module_indicator_vendor_defined_2_support                                              : 1;
        uint64_t mechanical_event_injection_support                                                     : 1;
        uint64_t rsvdz                                                                                  : 18;
        uint64_t padding                                                                                : 7;
    };
};


union genz_mechanical_control {
    uint64_t val;
    struct {
        uint64_t mechanical_event_injection_enable : 1;
        uint64_t rsvdp                             : 53;
        uint64_t padding                           : 10;
    };
};


union genz_mechanical_event_detect {
    uint32_t val;
    struct {
        uint32_t runtime_module_insertion_detect               : 1;
        uint32_t runtime_module_removal_detect                 : 1;
        uint32_t attention_button_pressed_detect               : 1;
        uint32_t attention_indicator_on_continuously_detect    : 1;
        uint32_t module_power_up_detect                        : 1;
        uint32_t module_power_off_detect                       : 1;
        uint32_t mrl_open_detect                               : 1;
        uint32_t mrl_close_detect                              : 1;
        uint32_t module_indicator_activated_detect             : 1;
        uint32_t controller_cmd_completion_notification_detect : 1;
        uint32_t power_fault_detect                            : 1;
        uint32_t auxiliary_power_up_detect                     : 1;
        uint32_t auxiliary_power_off_detect                    : 1;
        uint32_t rsvdp                                         : 19;
    };
};


union genz_mechanical_event_injection {
    uint32_t val;
    struct {
        uint32_t inject_runtime_module_insertion               : 1;
        uint32_t inject_runtime_module_removal                 : 1;
        uint32_t inject_attention_button_pressed               : 1;
        uint32_t inject_attention_indicator_on_continuously    : 1;
        uint32_t inject_module_power_up                        : 1;
        uint32_t inject_module_power_off                       : 1;
        uint32_t inject_mrl_open                               : 1;
        uint32_t inject_mrl_close                              : 1;
        uint32_t inject_module_indicator_activated             : 1;
        uint32_t inject_controller_cmd_completion_notification : 1;
        uint32_t inject_power_fault                            : 1;
        uint32_t inject_auxiliary_power_up                     : 1;
        uint32_t inject_auxiliary_power_off                    : 1;
        uint32_t rsvdz                                         : 19;
    };
};


union genz_destination_table_cap_1 {
    uint32_t val;
    struct {
        uint32_t ei_support            : 1;
        uint32_t wildcard_ssdt_support : 1;
        uint32_t wildcard_msdt_support : 1;
        uint32_t rit_ssdt_support      : 1;
        uint32_t rsvdz                 : 28;
    };
};


union genz_destination_table_control {
    uint32_t val;
    struct {
        uint32_t peer_authorization_enable : 1;
        uint32_t rsvdp                     : 30;
        uint64_t padding                   : 1;
    };
};


union genz_c_access_cap_1 {
    uint8_t val;
    struct {
        uint8_t l_ac_validation_support   : 1;
        uint8_t p2p_ac_validation_support : 1;
        uint8_t rsvdz                     : 2;
    };
};


union genz_c_access_ctl {
    uint8_t val;
    struct {
        uint8_t c_access_r_key_validation_enable : 1;
        uint8_t l_ac_validation_enable           : 1;
        uint8_t p2p_ac_validation_enable         : 1;
        uint8_t rsvdp                            : 4;
        uint64_t padding                         : 1;
    };
};


union genz_req_p2p_cap_1 {
    uint8_t val;
    struct {
        uint8_t rsvdz : 8;
    };
};


union genz_req_p2p_cap_1_control {
    uint8_t val;
    struct {
        uint8_t rsvdp : 8;
    };
};


union genz_req_p2p_control {
    uint16_t val;
    struct {
        uint16_t rsvdp   : 10;
        uint64_t padding : 6;
    };
};


union genz_pa_cap_1 {
    uint32_t val;
    struct {
        uint32_t rsvdz   : 2;
        uint64_t padding : 30;
    };
};


union genz_pa_cap_1_control {
    uint32_t val;
    struct {
        uint32_t access_key_enable : 1;
        uint32_t rsvdp             : 31;
    };
};


union genz_c_event_cap_1 {
    uint16_t val;
    struct {
        uint16_t c_event_interrupt_1_support : 1;
        uint16_t c_event_interrupt_2_support : 1;
        uint16_t rsvdz                       : 11;
        uint64_t padding                     : 3;
    };
};


union genz_c_event_control {
    uint16_t val;
    struct {
        uint16_t interrupt_0_enable    : 1;
        uint16_t interrupt_1_enable    : 1;
        uint16_t interrupt_2_enable    : 1;
        uint16_t interrupt_0_completed : 1;
        uint16_t interrupt_1_completed : 1;
        uint16_t interrupt_2_completed : 1;
        uint16_t rsvdp                 : 10;
    };
};


union genz_lpd_cap_1 {
    uint32_t val;
    struct {
        uint32_t multi_subnet_support        : 1;
        uint32_t non_default_host_id_support : 1;
        uint32_t pco_support                 : 1;
        uint32_t device_number_support       : 1;
        uint32_t lpd_field_type_0_support    : 1;
        uint32_t lpd_field_type_3_support    : 1;
        uint32_t lpd_field_type_4_support    : 1;
        uint32_t rsvdz                       : 25;
    };
};


union genz_lpd_cap_1_control {
    uint32_t val;
    struct {
        uint32_t non_default_target_enable : 1;
        uint32_t lpd_reset                 : 1;
        uint32_t default_hsid_valid        : 1;
        uint32_t lpd_communications_enable : 1;
        uint32_t default_hcid_valid        : 1;
        uint32_t rsvdp                     : 27;
    };
};


union genz_f_ctl_sub_0 {
    uint16_t val;
    struct {
        uint16_t hwinit_write_enable        : 1;
        uint16_t request_traffic_class      : 4;
        uint16_t r_key_non_interrupt_enable : 1;
        uint16_t pco_enable                 : 1;
        uint16_t lpd_field_type_0_enable    : 1;
        uint16_t lpd_field_type_3_enable    : 1;
        uint16_t lpd_field_type_4_enable    : 1;
        uint16_t rsvdp                      : 5;
        uint64_t padding                    : 1;
    };
};


union genz_sod_cap_1 {
    uint32_t val;
    struct {
        uint32_t multi_subnet_support      : 1;
        uint32_t tc_sode_selection_support : 1;
        uint32_t rsvdz                     : 30;
    };
};


union genz_sod_cap_1_control {
    uint32_t val;
    struct {
        uint32_t sod_communications_enable : 1;
        uint32_t rsvdp                     : 31;
    };
};


union genz_congestion_cap_1 {
    uint16_t val;
    struct {
        uint16_t resource_congestion_management_support       : 1;
        uint16_t vendor_defined_congestion_management_support : 1;
        uint16_t rsvdz                                        : 14;
    };
};


union genz_congestion_cap_1_control {
    uint16_t val;
    struct {
        uint16_t rsvdp   : 12;
        uint64_t padding : 4;
    };
};


union genz_rkd_cap_1 {
    uint16_t val;
    struct {
        uint16_t rsvdz   : 13;
        uint64_t padding : 3;
    };
};


union genz_rkd_control_1 {
    uint16_t val;
    struct {
        uint16_t rkd_validation_enable : 1;
        uint16_t trusted_thread_enable : 1;
        uint16_t rsvdp                 : 14;
    };
};


union genz_pm_cap_1 {
    uint16_t val;
    struct {
        uint16_t max_perf_records : 5;
        uint16_t rsvdz            : 8;
        uint64_t padding          : 3;
    };
};


union genz_pm_control {
    uint16_t val;
    struct {
        uint16_t performance_log_record_enable : 1;
        uint16_t rsvdp                         : 14;
        uint64_t padding                       : 1;
    };
};


union genz_atp_cap_1 {
    uint32_t val;
    struct {
        uint32_t address_translation_services_support : 1;
        uint32_t page_services_support                : 1;
        uint32_t context_management_support           : 1;
        uint32_t privileged_mode_support              : 1;
        uint32_t execution_permission_support         : 1;
        uint32_t global_mapping_support               : 1;
        uint32_t global_invalidate_support            : 1;
        uint32_t rsvdz                                : 23;
        uint64_t padding                              : 2;
    };
};


union genz_atp_cap_1_control {
    uint32_t val;
    struct {
        uint32_t pasid_enable                        : 1;
        uint32_t address_translation_services_enable : 1;
        uint32_t page_services_enable                : 1;
        uint32_t reset_pri                           : 1;
        uint32_t context_management_override         : 1;
        uint32_t privileged_mode_enable              : 1;
        uint32_t execute_permission_enable           : 1;
        uint32_t global_mapping_enable               : 1;
        uint32_t global_invalidate_enable            : 1;
        uint32_t smallest_translation_unit_stu       : 5;
        uint32_t rsvdp                               : 16;
        uint64_t padding                             : 2;
    };
};


union genz_atp_status {
    uint32_t val;
    struct {
        uint32_t prg_response_notification_failure : 1;
        uint32_t unexpected_prg_index              : 1;
        uint32_t stopped                           : 1;
        uint32_t rsvdz                             : 29;
    };
};


union genz_re_table_cap_1 {
    uint16_t val;
    struct {
        uint16_t rsvdz : 16;
    };
};


union genz_re_table_cap_1_control {
    uint16_t val;
    struct {
        uint16_t rsvdp : 16;
    };
};


union genz_re_table_control {
    uint16_t val;
    struct {
        uint16_t re_table_enable : 1;
        uint16_t rsvdp           : 15;
    };
};


union genz_lph_cap_1 {
    uint32_t val;
    struct {
        uint32_t multi_subnet_support        : 1;
        uint32_t non_default_host_id_support : 1;
        uint32_t pco_support                 : 1;
        uint32_t lpd_field_type_3_support    : 1;
        uint32_t lpd_field_type_4_support    : 1;
        uint32_t rsvdz                       : 27;
    };
};


union genz_lph_cap_1_control {
    uint32_t val;
    struct {
        uint32_t non_default_target_enable : 1;
        uint32_t lph_reset                 : 1;
        uint32_t default_hsid_valid        : 1;
        uint32_t lph_communications_enable : 1;
        uint32_t default_hcid_valid        : 1;
        uint32_t lpd_field_type_3_enable   : 1;
        uint32_t lpd_field_type_4_enable   : 1;
        uint32_t rsvdp                     : 25;
    };
};


union genz_lph_ctl {
    uint16_t val;
    struct {
        uint16_t request_traffic_class      : 4;
        uint16_t r_key_non_interrupt_enable : 1;
        uint16_t pco_enable                 : 1;
        uint16_t rsvdp                      : 9;
        uint64_t padding                    : 1;
    };
};


union genz_pg_zmmu_cap_1 {
    uint32_t val;
    struct {
        uint32_t lpd_responder_zmmu_no_bypass_support      : 1;
        uint32_t lpd_responder_zmmu_bypass_support         : 1;
        uint32_t lpd_responder_zmmu_bypass_control_support : 1;
        uint32_t rsvdz                                     : 28;
        uint64_t padding                                   : 1;
    };
};


union genz_pg_zmmu_cap_1_control {
    uint32_t val;
    struct {
        uint32_t rsvdp : 32;
    };
};


union genz_pt_zmmu_cap_1 {
    uint32_t val;
    struct {
        uint32_t lpd_responder_zmmu_no_bypass_support      : 1;
        uint32_t lpd_responder_zmmu_bypass_support         : 1;
        uint32_t lpd_responder_zmmu_bypass_control_support : 1;
        uint32_t rsvdz                                     : 28;
        uint64_t padding                                   : 1;
    };
};


union genz_pt_zmmu_cap_1_control {
    uint32_t val;
    struct {
        uint32_t rsvdp : 32;
    };
};


union genz_interleave_cap_1 {
    uint32_t val;
    struct {
        uint32_t rsvdz   : 30;
        uint64_t padding : 2;
    };
};


union genz_interleave_cap_1_control {
    uint32_t val;
    struct {
        uint32_t rsvdp : 32;
    };
};


union genz_fw_table_cap_1 {
    uint16_t val;
    struct {
        uint16_t mutable_fw_support           : 1;
        uint16_t crc16_support                : 1;
        uint16_t fw_image_hash_digest_support : 1;
        uint16_t rsvdz                        : 13;
    };
};


union genz_fw_table_control {
    uint16_t val;
    struct {
        uint16_t fw_fault_injection_enable : 1;
        uint16_t rsvdp                     : 15;
    };
};


union genz_fw_detect {
    uint16_t val;
    struct {
        uint16_t fw_update_error_failure_immutable_image_detect : 1;
        uint16_t fw_update_disabled_detect                      : 1;
        uint16_t fw_internal_controller_issue_detected_detect   : 1;
        uint16_t fw_checksum_failure_detect                     : 1;
        uint16_t fw_hash_digest_error_detect                    : 1;
        uint16_t fw_encryption_error_detect                     : 1;
        uint16_t rsvdp                                          : 10;
    };
};


union genz_fw_fault_injection {
    uint16_t val;
    struct {
        uint16_t fw_update_error_failure_immutable_image_detect : 1;
        uint16_t fw_update_disabled_detect                      : 1;
        uint16_t fw_internal_controller_issue_detected_detect   : 1;
        uint16_t fw_checksum_failure_detect                     : 1;
        uint16_t fw_hash_digest_error_detect                    : 1;
        uint16_t fw_encryption_error_detect                     : 1;
        uint16_t rsvdz                                          : 10;
    };
};


union genz_swm_cap_1 {
    uint16_t val;
    struct {
        uint16_t swm_media_support : 1;
        uint16_t rsvdz             : 15;
    };
};


union genz_swm_control_1 {
    uint16_t val;
    struct {
        uint16_t swm_media_enable : 1;
        uint16_t swm_op_execute   : 1;
        uint16_t swm_op_abort     : 1;
        uint16_t swm_interrupt    : 1;
        uint16_t swm_read_release : 1;
        uint16_t swm_zero         : 1;
        uint16_t rsvdp            : 10;
    };
};


union genz_swm_status {
    uint16_t val;
    struct {
        uint16_t swm_op_completed     : 1;
        uint16_t swm_op_success       : 1;
        uint16_t swm_error            : 1;
        uint16_t swm_op_aborted       : 1;
        uint16_t swm_read             : 1;
        uint16_t swm_read_multi_block : 1;
        uint16_t swm_read_last_block  : 1;
        uint16_t swm_write_next_block : 1;
        uint16_t rsvdp                : 8;
    };
};


union genz_component_backup_cap_1 {
    uint64_t val;
    struct {
        uint64_t lps_support                            : 1;
        uint64_t tps_support                            : 1;
        uint64_t auto_op_check_lps_support              : 1;
        uint64_t lps_temp_support                       : 1;
        uint64_t backup_fault_injection_support         : 1;
        uint64_t point_to_point_topology_backup_support : 1;
        uint64_t switch_topology_backup_support         : 1;
        uint64_t rsvdz                                  : 51;
        uint64_t padding                                : 6;
    };
};


union genz_component_backup_cap_1_control {
    uint64_t val;
    struct {
        uint64_t backup_fault_injection_enable         : 1;
        uint64_t point_to_point_topology_backup_enable : 1;
        uint64_t switch_topology_backup_enable         : 1;
        uint64_t rsvdp                                 : 61;
    };
};


union genz_component_backup_status_1 {
    uint32_t val;
    struct {
        uint32_t arm_status                  : 1;
        uint32_t lps_present                 : 1;
        uint32_t lps_battery                 : 1;
        uint32_t lps_supercapacitor          : 1;
        uint32_t lps_hybrid_capacitor        : 1;
        uint32_t lps_failed                  : 1;
        uint32_t lps_wear_threshold_exceeded : 1;
        uint32_t lps_lower_thermal_exceeded  : 1;
        uint32_t lps_low_thermal_restored    : 1;
        uint32_t lps_upper_thermal_exceeded  : 1;
        uint32_t lps_upper_thermal_restored  : 1;
        uint32_t lps_assessment_status       : 1;
        uint32_t lps_assessment_type         : 1;
        uint32_t lps_assessment_in_progress  : 1;
        uint32_t rsvdz                       : 1;
        uint32_t tps_failed                  : 1;
        uint32_t lps_assessment_error        : 1;
        uint32_t insufficient_lps_power      : 1;
        uint32_t lps_charged                 : 1;
        uint64_t padding                     : 13;
    };
};


union genz_component_backup_control_1 {
    uint32_t val;
    struct {
        uint32_t initiate_lps_health_status                       : 1;
        uint32_t backup_fault_injection_enable                    : 1;
        uint32_t initiate_emergency_all_backup                    : 1;
        uint32_t emergency_backup_main_power_enable               : 1;
        uint32_t emergency_backup_media_controller_c_down_enable  : 1;
        uint32_t emergency_backup_all_interface_paths_lost_enable : 1;
        uint32_t rsvdp                                            : 1;
        uint32_t emergency_backup_management_initiated_enable     : 1;
        uint32_t emergency_backup_environmental_conditions_enable : 1;
        uint32_t emergency_backup_persistent_flush_ff_enable      : 1;
        uint32_t planned_backup_persistent_flush_ff_enable        : 1;
        uint64_t padding                                          : 21;
    };
};


union genz_component_backup_fault_injection_1 {
    uint64_t val;
    struct {
        uint64_t backup_success                                                          : 1;
        uint64_t emergency_backup_main_power_problem                                     : 1;
        uint64_t rsvdz                                                                   : 1;
        uint64_t emergency_backup_c_down                                                 : 1;
        uint64_t emergency_backup_path_lost                                              : 1;
        uint64_t emergency_backup_management_initiated                                   : 1;
        uint64_t planned_backup_initiated                                                : 1;
        uint64_t backup_error                                                            : 1;
        uint64_t backup_rejected_not_armed                                               : 1;
        uint64_t backup_abort_success                                                    : 1;
        uint64_t backup_abort_error                                                      : 1;
        uint64_t partial_backup_saved                                                    : 1;
        uint64_t restore_success                                                         : 1;
        uint64_t restore_error                                                           : 1;
        uint64_t restore_abort_success                                                   : 1;
        uint64_t restore_abort_error                                                     : 1;
        uint64_t restore_invalid_image                                                   : 1;
        uint64_t restore_volatile_invalidate_state                                       : 1;
        uint64_t abort_current_op_failed                                                 : 1;
        uint64_t backup_permanent_hw_failure                                             : 1;
        uint64_t invalid_pm_backup_table_entry_configuration                             : 1;
        uint64_t operation_failed_primary_media_not_operational                          : 1;
        uint64_t operation_failed_primary_media_not_accessible                           : 1;
        uint64_t operation_failed_could_not_allocate_pm_backup_table_entry               : 1; //FIXME: name too long.
        uint64_t operation_failed_lps_tps_issue_examine_other_status_bits_for_root_cause : 1; //FIXME: name too long.
        uint64_t operation_failed_primary_media_unsupported_or_invalid_hash_encryption   : 1; //FIXME: name too long.
        uint64_t erase_success                                                           : 1;
        uint64_t erase_error                                                             : 1;
        uint64_t erase_abort_success                                                     : 1;
        uint64_t erase_invalid_image                                                     : 1;
        uint64_t invalid_sm_backup_table_entry_configuration                             : 1;
        uint64_t operation_failed_secondary_media_not_operational                        : 1;
        uint64_t operation_failed_secondary_media_not_accessible                         : 1;
        uint64_t operation_failed_could_not_allocate_sm_backup_table_entry               : 1; //FIXME: name too long.
        uint64_t lps_present_lps_battery                                                 : 1;
        uint64_t lps_present_lps_supercapacitor                                          : 1;
        uint64_t lps_present_lps_hybrid_capacitor                                        : 1;
        uint64_t lps_lower_thermal_threshold_exceeded                                    : 1;
        uint64_t lps_lower_thermal_threshold_restored                                    : 1;
        uint64_t lps_upper_thermal_threshold_exceeded                                    : 1;
        uint64_t lps_upper_thermal_threshold_restored                                    : 1;
        uint64_t lps_failed_voltage_regulator_failed                                     : 1;
        uint64_t lps_failed_non_operational_cannot_detect                                : 1;
        uint64_t lps_wear_threshold_exceeded                                             : 1;
        uint64_t lps_assessment_error                                                    : 1;
        uint64_t insufficient_lps_power                                                  : 1;
        uint64_t lps_charged                                                             : 1;
        uint64_t padding                                                                 : 17;
    };
};


union genz_component_backup_fault_injection_2 {
    uint64_t val;
    struct {
        uint64_t rsvdz                       : 60;
        uint64_t inject_vendor_defined_event : 4;
    };
};


union genz_fw_ctl_sub_0 {
    uint16_t val;
    struct {
        uint16_t fw_table_entry_valid        : 1;
        uint16_t fw_update_enable            : 1;
        uint16_t fw_update                   : 1;
        uint16_t fw_image_validate           : 1;
        uint16_t fw_image_authenticate       : 1;
        uint16_t fw_immutable_halt           : 1;
        uint16_t fw_mutable_halt             : 1;
        uint16_t activate_immutable_firmware : 1;
        uint16_t activate_mutable_firmware   : 1;
        uint16_t rsvdp                       : 7;
    };
};


union genz_fw_status_sub_0 {
    uint16_t val;
    struct {
        uint16_t fw_image_crc_valid                   : 1;
        uint16_t fw_image_hash_digest_valid           : 1;
        uint16_t fw_update_disabled                   : 1;
        uint16_t internal_controller_issue_detected   : 1;
        uint16_t fw_update_in_progress                : 1;
        uint16_t immutable_firmware_image_active      : 1;
        uint16_t mutable_firmware_image_active        : 1;
        uint16_t fw_immutable_halted                  : 1;
        uint16_t fw_mutable_halted                    : 1;
        uint16_t fw_hash_digest_challenge_in_progress : 1;
        uint16_t fw_activation_in_progress            : 1;
        uint16_t fw_update_activation_completed       : 1;
        uint16_t rsvdz                                : 4;
    };
};


union genz_image_ctl_sub_0 {
    uint16_t val;
    struct {
        uint16_t image_table_entry_valid    : 1;
        uint16_t image_validate             : 1;
        uint16_t image_authenticate_decrypt : 1;
        uint16_t image_authenticate_hash    : 1;
        uint16_t delete_image               : 1;
        uint16_t rsvdp                      : 10;
        uint64_t padding                    : 1;
    };
};


union genz_image_status_sub_0 {
    uint16_t val;
    struct {
        uint16_t image_checksum_valid          : 1;
        uint16_t image_hash_digest_valid       : 1;
        uint16_t image_encryption_valid        : 1;
        uint16_t image_crc_in_progress         : 1;
        uint16_t image_hash_digest_in_progress : 1;
        uint16_t rsvdp                         : 11;
    };
};


union genz_oem_status {
    uint32_t val;
    struct {
        uint32_t emergency_backup_failure_tps  : 1;
        uint32_t last_emergency_backup_failure : 1;
        uint32_t rsvdp                         : 30;
    };
};


union genz_opcode_set_id_control_1 {
    uint16_t val;
    struct {
        uint16_t opcode_set_enable : 1;
        uint16_t rsvdp             : 15;
    };
};


union genz_peer_attr_sub_0 {
    uint16_t val;
    struct {
        uint16_t opcode_set_table_id                      : 3;
        uint16_t peer_explicit_opclass_next_header_enable : 1;
        uint16_t rsvdp                                    : 1;
        uint16_t peer_precision_time_enable               : 1;
        uint16_t peer_aead_enable                         : 1;
        uint16_t write_msg_embedded_read_enable           : 1;
        uint16_t meta_read_write_enable                   : 1;
        uint64_t padding                                  : 7;
    };
};


union genz_pm_backup_status_sub_0 {
    uint64_t val;
    struct {
        uint64_t backup_success                                                        : 1;
        uint64_t emergency_backup_initiated                                            : 1;
        uint64_t emergency_backup_main_power_problem                                   : 1;
        uint64_t rsvdz                                                                 : 1;
        uint64_t emergency_backup_c_down                                               : 1;
        uint64_t emergency_backup_path_lost                                            : 1;
        uint64_t emergency_backup_management_initiated                                 : 1;
        uint64_t planned_backup_initiated                                              : 1;
        uint64_t backup_error                                                          : 1;
        uint64_t backup_rejected_not_armed                                             : 1;
        uint64_t backup_abort_success                                                  : 1;
        uint64_t backup_abort_error                                                    : 1;
        uint64_t partial_backup_saved                                                  : 1;
        uint64_t backup_in_progress                                                    : 1;
        uint64_t restore_success                                                       : 1;
        uint64_t restore_error                                                         : 1;
        uint64_t restore_abort_success                                                 : 1;
        uint64_t restore_abort_error                                                   : 1;
        uint64_t restore_in_progress                                                   : 1;
        uint64_t restore_invalid_image                                                 : 1;
        uint64_t restore_volatile_invalid_state                                        : 1;
        uint64_t abort_current_op_failed                                               : 1;
        uint64_t backup_permanent_hw_failure                                           : 1;
        uint64_t invalid_pm_backup_table_entry_configuration                           : 1;
        uint64_t operation_failed_secondary_media_not_operational                      : 1;
        uint64_t operation_failed_secondary_media_not_accessible                       : 1;
        uint64_t operation_failed_primary_media_not_operational                        : 1;
        uint64_t operation_failed_could_not_allocate_pm_backup_table_entry             : 1; //FIXME: name too long.
        uint64_t operation_failed_lps_tps_issue                                        : 1;
        uint64_t operation_failed_primary_media_unsupported_or_invalid_hash_encryption : 1; //FIXME: name too long.
        uint64_t operation_failed_primary_media_length_exceeds_secondary_media         : 1; //FIXME: name too long.
        uint64_t padding                                                               : 33;
    };
};


union genz_pm_backup_control_sub_0 {
    uint32_t val;
    struct {
        uint32_t allocate_pm_backup_table_entry : 1;
        uint32_t backup_data_auth_enable        : 1;
        uint32_t rsvdp                          : 1;
        uint32_t arm_emergency_backup           : 1;
        uint32_t disable_emergency_backup       : 1;
        uint32_t initiate_emergency_backup      : 1;
        uint32_t initiate_planned_backup        : 1;
        uint32_t initiate_restore               : 1;
        uint32_t abort_current_op               : 1;
        uint64_t padding                        : 23;
    };
};


union genz_rc_cap_1 {
    uint16_t val;
    struct {
        uint16_t mss_support : 1;
        uint16_t hcs_support : 1;
        uint16_t rsvdz       : 12;
        uint64_t padding     : 2;
    };
};


union genz_sm_backup_status_sub_0 {
    uint64_t val;
    struct {
        uint64_t erase_success                                             : 1;
        uint64_t erase_error                                               : 1;
        uint64_t erase_abort_success                                       : 1;
        uint64_t erase_abort_error                                         : 1;
        uint64_t erase_in_progress                                         : 1;
        uint64_t erase_invalid_image                                       : 1;
        uint64_t invalid_sm_backup_table_entry_configuration               : 1;
        uint64_t backup_permanent_hw_failure                               : 1;
        uint64_t rsvdz                                                     : 1;
        uint64_t operation_failed_secondary_media_not_operational          : 1;
        uint64_t operation_failed_secondary_media_not_accessible           : 1;
        uint64_t operation_failed_could_not_allocate_sm_backup_table_entry : 1; //FIXME: name too long.
        uint64_t padding                                                   : 52;
    };
};


union genz_sm_backup_control_sub_0 {
    uint32_t val;
    struct {
        uint32_t allocate_sm_backup_table_entry : 1;
        uint32_t initiate_erase                 : 1;
        uint32_t abort_current_op               : 1;
        uint32_t rsvdp                          : 27;
        uint64_t padding                        : 2;
    };
};


union genz_tr_ctl_sub_0 {
    uint16_t val;
    struct {
        uint16_t tr_relay_enable : 1;
        uint16_t rsvdp           : 13;
        uint64_t padding         : 2;
    };
};

enum genz_c_status_c_state {
    C_STATUS_C_STATE_C_DOWN = 0x0,
    C_STATUS_C_STATE_C_CFG = 0x1,
    C_STATUS_C_STATE_C_UP = 0x2,
    C_STATUS_C_STATE_C_LP = 0x3,
    C_STATUS_C_STATE_C_DLP = 0x4
};

enum genz_c_status_component_thermal_status {
    C_STATUS_COMPONENT_THERMAL_STATUS_NOMINAL_THERMAL_CONDITIONS = 0x0,
    C_STATUS_COMPONENT_THERMAL_STATUS_CAUTION_THERMAL_LIMIT = 0x1,
    C_STATUS_COMPONENT_THERMAL_STATUS_EXCEEDED_UPPER_THERMAL_LIMIT = 0x2,
    C_STATUS_COMPONENT_THERMAL_STATUS_THERMAL_SHUTDOWN_TRIGGERED = 0x3
};

enum genz_c_status_hwinit_valid {
    C_STATUS_HWINIT_VALID_IN_PROGRESS = 0x0,
    C_STATUS_HWINIT_VALID_HWINIT_FIELDS_INITIALIZED_AND_MAY_BE_ACCESSED_BY_SOFTWARE = 0x1
};

enum genz_c_control_initiate_component_reset {
    C_CONTROL_INITIATE_COMPONENT_RESET_NO_IMPACT = 0x0,
    C_CONTROL_INITIATE_COMPONENT_RESET_FULL_COMPONENT_RESET = 0x1,
    C_CONTROL_INITIATE_COMPONENT_RESET_WARM_COMPONENT_RESET = 0x2,
    C_CONTROL_INITIATE_COMPONENT_RESET_WARM_NON_SWITCH_COMPONENT_RESET = 0x3,
    C_CONTROL_INITIATE_COMPONENT_RESET_CONTENT_COMPONENT_RESET = 0x4
};

enum genz_c_control_lpd_responder_zmmu_bypass_control {
    C_CONTROL_LPD_RESPONDER_ZMMU_BYPASS_CONTROL_DO_NOT_BYPASS_RESPONDER_ZMMU = 0x0,
    C_CONTROL_LPD_RESPONDER_ZMMU_BYPASS_CONTROL_BYPASS_RESPONDER_ZMMU = 0x1
};

enum genz_aec {
    AEC_AE_1B = 0x0,
    AEC_AD_1B = 0x1,
    AEC_UK_1B = 0x2
};

enum genz_component_cap_1_address_field_interpretation {
    COMPONENT_CAP_1_ADDRESS_FIELD_INTERPRETATION_ZERO_BASED = 0x0,
    COMPONENT_CAP_1_ADDRESS_FIELD_INTERPRETATION_NON_ZERO_BASED = 0x1
};

enum genz_component_cap_1_addressable_resource_classification {
    COMPONENT_CAP_1_ADDRESSABLE_RESOURCE_CLASSIFICATION_NO_ADDRESSABLE_DATA_SPACE_RESOURCES = 0x0,
    COMPONENT_CAP_1_ADDRESSABLE_RESOURCE_CLASSIFICATION_BYTE_ADDRESSABLE_DATA_SPACE_MEDIA = 0x1,
    COMPONENT_CAP_1_ADDRESSABLE_RESOURCE_CLASSIFICATION_BLOCK_ADDRESSABLE_DATA_SPACE_MEDIA = 0x2,
    COMPONENT_CAP_1_ADDRESSABLE_RESOURCE_CLASSIFICATION_COMPONENT_MEDIA_STRUCTURE_SPECIFIES_MEDIA = 0x3,
    COMPONENT_CAP_1_ADDRESSABLE_RESOURCE_CLASSIFICATION_NON_MEDIA_DATA_SPACE_RESOURCE = 0x4
};

enum genz_component_cap_1_cached_component_control_space_structure_support {
    COMPONENT_CAP_1_CACHED_COMPONENT_CONTROL_SPACE_STRUCTURE_SUPPORT_NON_CACHED = 0x0,
    COMPONENT_CAP_1_CACHED_COMPONENT_CONTROL_SPACE_STRUCTURE_SUPPORT_CACHED = 0x1
};

enum genz_component_cap_1_configuration_post_emergency_power_reduction {
    COMPONENT_CAP_1_CONFIGURATION_POST_EMERGENCY_POWER_REDUCTION_NO_SOFTWARE_IS_REQUIRED = 0x0,
    COMPONENT_CAP_1_CONFIGURATION_POST_EMERGENCY_POWER_REDUCTION_SOFTWARE_IS_REQUIRED = 0x1
};

enum genz_component_cap_1_c_state_power_control_support {
    COMPONENT_CAP_1_C_STATE_POWER_CONTROL_SUPPORT_NOTIFICATION_ONLY = 0x0,
    COMPONENT_CAP_1_C_STATE_POWER_CONTROL_SUPPORT_NOTIFICATION_AND_TRANSITION_REQUESTS = 0x1
};

enum genz_component_cap_1_power_scale_pwrs_is_used_to_calculate_the_various_component_maximum_non_auxiliary_power_consumption_values {
    COMPONENT_CAP_1_POWER_SCALE_PWRS_IS_USED_TO_CALCULATE_THE_VARIOUS_COMPONENT_MAXIMUM_NON_AUXILIARY_POWER_CONSUMPTION_VALUES_1_0 = 0x0,
    COMPONENT_CAP_1_POWER_SCALE_PWRS_IS_USED_TO_CALCULATE_THE_VARIOUS_COMPONENT_MAXIMUM_NON_AUXILIARY_POWER_CONSUMPTION_VALUES_0_1 = 0x1,
    COMPONENT_CAP_1_POWER_SCALE_PWRS_IS_USED_TO_CALCULATE_THE_VARIOUS_COMPONENT_MAXIMUM_NON_AUXILIARY_POWER_CONSUMPTION_VALUES_0_01 = 0x2,
    COMPONENT_CAP_1_POWER_SCALE_PWRS_IS_USED_TO_CALCULATE_THE_VARIOUS_COMPONENT_MAXIMUM_NON_AUXILIARY_POWER_CONSUMPTION_VALUES_0_001 = 0x3,
    COMPONENT_CAP_1_POWER_SCALE_PWRS_IS_USED_TO_CALCULATE_THE_VARIOUS_COMPONENT_MAXIMUM_NON_AUXILIARY_POWER_CONSUMPTION_VALUES_0_0001 = 0x4,
    COMPONENT_CAP_1_POWER_SCALE_PWRS_IS_USED_TO_CALCULATE_THE_VARIOUS_COMPONENT_MAXIMUM_NON_AUXILIARY_POWER_CONSUMPTION_VALUES_0_00001 = 0x5,
    COMPONENT_CAP_1_POWER_SCALE_PWRS_IS_USED_TO_CALCULATE_THE_VARIOUS_COMPONENT_MAXIMUM_NON_AUXILIARY_POWER_CONSUMPTION_VALUES_0_000001 = 0x6,
    COMPONENT_CAP_1_POWER_SCALE_PWRS_IS_USED_TO_CALCULATE_THE_VARIOUS_COMPONENT_MAXIMUM_NON_AUXILIARY_POWER_CONSUMPTION_VALUES_0_0000001 = 0x7
};

enum genz_component_cap_1_auxiliary_power_scale_apwrs_is_used_to_calculate_the_maximum_power_consumption_a_component_is_capable_of_consuming_when_operating_on_auxiliary_power {
    COMPONENT_CAP_1_AUXILIARY_POWER_SCALE_APWRS_IS_USED_TO_CALCULATE_THE_MAXIMUM_POWER_CONSUMPTION_A_COMPONENT_IS_CAPABLE_OF_CONSUMING_WHEN_OPERATING_ON_AUXILIARY_POWER_1_0 = 0x0,
    COMPONENT_CAP_1_AUXILIARY_POWER_SCALE_APWRS_IS_USED_TO_CALCULATE_THE_MAXIMUM_POWER_CONSUMPTION_A_COMPONENT_IS_CAPABLE_OF_CONSUMING_WHEN_OPERATING_ON_AUXILIARY_POWER_0_1 = 0x1,
    COMPONENT_CAP_1_AUXILIARY_POWER_SCALE_APWRS_IS_USED_TO_CALCULATE_THE_MAXIMUM_POWER_CONSUMPTION_A_COMPONENT_IS_CAPABLE_OF_CONSUMING_WHEN_OPERATING_ON_AUXILIARY_POWER_0_01 = 0x2,
    COMPONENT_CAP_1_AUXILIARY_POWER_SCALE_APWRS_IS_USED_TO_CALCULATE_THE_MAXIMUM_POWER_CONSUMPTION_A_COMPONENT_IS_CAPABLE_OF_CONSUMING_WHEN_OPERATING_ON_AUXILIARY_POWER_0_001 = 0x3,
    COMPONENT_CAP_1_AUXILIARY_POWER_SCALE_APWRS_IS_USED_TO_CALCULATE_THE_MAXIMUM_POWER_CONSUMPTION_A_COMPONENT_IS_CAPABLE_OF_CONSUMING_WHEN_OPERATING_ON_AUXILIARY_POWER_0_0001 = 0x4,
    COMPONENT_CAP_1_AUXILIARY_POWER_SCALE_APWRS_IS_USED_TO_CALCULATE_THE_MAXIMUM_POWER_CONSUMPTION_A_COMPONENT_IS_CAPABLE_OF_CONSUMING_WHEN_OPERATING_ON_AUXILIARY_POWER_0_00001 = 0x5,
    COMPONENT_CAP_1_AUXILIARY_POWER_SCALE_APWRS_IS_USED_TO_CALCULATE_THE_MAXIMUM_POWER_CONSUMPTION_A_COMPONENT_IS_CAPABLE_OF_CONSUMING_WHEN_OPERATING_ON_AUXILIARY_POWER_0_000001 = 0x6,
    COMPONENT_CAP_1_AUXILIARY_POWER_SCALE_APWRS_IS_USED_TO_CALCULATE_THE_MAXIMUM_POWER_CONSUMPTION_A_COMPONENT_IS_CAPABLE_OF_CONSUMING_WHEN_OPERATING_ON_AUXILIARY_POWER_0_0000001 = 0x7
};

enum genz_component_cap_1_core_latency_scale {
    COMPONENT_CAP_1_CORE_LATENCY_SCALE_US = 0x0,
    COMPONENT_CAP_1_CORE_LATENCY_SCALE_NS = 0x1,
    COMPONENT_CAP_1_CORE_LATENCY_SCALE_PS = 0x2
};

enum genz_component_cap_1_control_timer_unit {
    COMPONENT_CAP_1_CONTROL_TIMER_UNIT_US_1 = 0x0,
    COMPONENT_CAP_1_CONTROL_TIMER_UNIT_US_10 = 0x1,
    COMPONENT_CAP_1_CONTROL_TIMER_UNIT_US_100 = 0x2,
    COMPONENT_CAP_1_CONTROL_TIMER_UNIT_MS_1 = 0x3
};

enum genz_component_cap_1_timer_unit {
    COMPONENT_CAP_1_TIMER_UNIT_NS_1 = 0x0,
    COMPONENT_CAP_1_TIMER_UNIT_NS_10 = 0x1,
    COMPONENT_CAP_1_TIMER_UNIT_NS_100 = 0x2,
    COMPONENT_CAP_1_TIMER_UNIT_US_1 = 0x3,
    COMPONENT_CAP_1_TIMER_UNIT_US_10 = 0x4,
    COMPONENT_CAP_1_TIMER_UNIT_US_100 = 0x5,
    COMPONENT_CAP_1_TIMER_UNIT_MS_1 = 0x6,
    COMPONENT_CAP_1_TIMER_UNIT_MS_10 = 0x7,
    COMPONENT_CAP_1_TIMER_UNIT_MS_100 = 0x8,
    COMPONENT_CAP_1_TIMER_UNIT_S_1 = 0x9
};

enum genz_component_cap_1_max_cid {
    COMPONENT_CAP_1_MAX_CID_CID_0_SUPPORTED = 0x0,
    COMPONENT_CAP_1_MAX_CID_CID_0_AND_CID_1_SUPPORTED = 0x1,
    COMPONENT_CAP_1_MAX_CID_CID_0_CID_1_AND_CID_2_SUPPORTED = 0x2,
    COMPONENT_CAP_1_MAX_CID_CID_0_CID_1_CID_2_AND_CID_3_SUPPORTED = 0x3
};

enum genz_component_cap_1_control_no_snoop_control {
    COMPONENT_CAP_1_CONTROL_NO_SNOOP_CONTROL_0B = 0x0,
    COMPONENT_CAP_1_CONTROL_NO_SNOOP_CONTROL_0B_OR_1B = 0x1
};

enum genz_component_cap_1_control_built_in_self_test_bist_control {
    COMPONENT_CAP_1_CONTROL_BUILT_IN_SELF_TEST_BIST_CONTROL_HALT = 0x0,
    COMPONENT_CAP_1_CONTROL_BUILT_IN_SELF_TEST_BIST_CONTROL_INVOKE_BIST = 0x1
};

enum genz_component_cap_1_control_manager_type {
    COMPONENT_CAP_1_CONTROL_MANAGER_TYPE_PRIMARY_MANAGER = 0x0,
    COMPONENT_CAP_1_CONTROL_MANAGER_TYPE_FABRIC_MANAGER = 0x1
};

enum genz_component_cap_1_control_primary_manager_role {
    COMPONENT_CAP_1_CONTROL_PRIMARY_MANAGER_ROLE_NOT_CO_LOCATED = 0x0,
    COMPONENT_CAP_1_CONTROL_PRIMARY_MANAGER_ROLE_CO_LOCATED = 0x1
};

enum genz_component_cap_1_control_primary_fabric_manager_role {
    COMPONENT_CAP_1_CONTROL_PRIMARY_FABRIC_MANAGER_ROLE_NOT_CO_LOCATED = 0x0,
    COMPONENT_CAP_1_CONTROL_PRIMARY_FABRIC_MANAGER_ROLE_CO_LOCATED = 0x1
};

enum genz_component_cap_1_control_secondary_fabric_manager_role {
    COMPONENT_CAP_1_CONTROL_SECONDARY_FABRIC_MANAGER_ROLE_NOT_CO_LOCATED = 0x0,
    COMPONENT_CAP_1_CONTROL_SECONDARY_FABRIC_MANAGER_ROLE_CO_LOCATED = 0x1
};

enum genz_component_cap_1_control_power_manager_enable {
    COMPONENT_CAP_1_CONTROL_POWER_MANAGER_ENABLE_DISABLED = 0x0,
    COMPONENT_CAP_1_CONTROL_POWER_MANAGER_ENABLE_ENABLED_CID = 0x1,
    COMPONENT_CAP_1_CONTROL_POWER_MANAGER_ENABLE_ENABLED_CID_SID = 0x2
};

enum genz_component_cap_1_control_in_band_management_disable {
    COMPONENT_CAP_1_CONTROL_IN_BAND_MANAGEMENT_DISABLE_ENABLED_DEFAULT = 0x0,
    COMPONENT_CAP_1_CONTROL_IN_BAND_MANAGEMENT_DISABLE_DISABLED = 0x1
};

enum genz_component_cap_1_control_out_of_band_management_disable {
    COMPONENT_CAP_1_CONTROL_OUT_OF_BAND_MANAGEMENT_DISABLE_ENABLED_DEFAULT = 0x0,
    COMPONENT_CAP_1_CONTROL_OUT_OF_BAND_MANAGEMENT_DISABLE_DISABLED = 0x1
};

enum genz_component_cap_1_control_max_power_control {
    COMPONENT_CAP_1_CONTROL_MAX_POWER_CONTROL_LPWR = 0x0,
    COMPONENT_CAP_1_CONTROL_MAX_POWER_CONTROL_NPWR = 0x1,
    COMPONENT_CAP_1_CONTROL_MAX_POWER_CONTROL_HPWR = 0x2,
    COMPONENT_CAP_1_CONTROL_MAX_POWER_CONTROL_MAX_MECH_POWER_LVL_SEE_COMPONENT_MECHANICAL_STRUCTURE = 0x3
};

enum genz_component_cap_1_control_c_state_power_control_enable {
    COMPONENT_CAP_1_CONTROL_C_STATE_POWER_CONTROL_ENABLE_NOTIFICATION_ONLY = 0x0,
    COMPONENT_CAP_1_CONTROL_C_STATE_POWER_CONTROL_ENABLE_NOTIFICATION_AND_TRANSITION_REQUESTS = 0x1
};

enum genz_component_cap_1_control_lowest_automatic_c_state_level {
    COMPONENT_CAP_1_CONTROL_LOWEST_AUTOMATIC_C_STATE_LEVEL_C_UP = 0x0,
    COMPONENT_CAP_1_CONTROL_LOWEST_AUTOMATIC_C_STATE_LEVEL_C_LP = 0x1,
    COMPONENT_CAP_1_CONTROL_LOWEST_AUTOMATIC_C_STATE_LEVEL_C_DLP = 0x2
};

enum genz_component_cap_1_control_host_manager_mgr_uuid_enable {
    COMPONENT_CAP_1_CONTROL_HOST_MANAGER_MGR_UUID_ENABLE_ZERO = 0x0,
    COMPONENT_CAP_1_CONTROL_HOST_MANAGER_MGR_UUID_ENABLE_CORE = 0x1,
    COMPONENT_CAP_1_CONTROL_HOST_MANAGER_MGR_UUID_ENABLE_VENDOR_DEFINED = 0x2
};

enum genz_component_cap_2_r_key_support {
    COMPONENT_CAP_2_R_KEY_SUPPORT_UNSUPPORTED = 0x0,
    COMPONENT_CAP_2_R_KEY_SUPPORT_SUPPORTED_AS_A_REQUESTER = 0x1,
    COMPONENT_CAP_2_R_KEY_SUPPORT_SUPPORTED_AS_A_RESPONDER = 0x2,
    COMPONENT_CAP_2_R_KEY_SUPPORT_SUPPORTED_AS_A_REQUESTER_RESPONDER = 0x3
};

enum genz_component_cap_2_poison_granularity_support {
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_UNSUPPORTED = 0x0,
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_BYTES_16 = 0x1,
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_BYTES_32 = 0x2,
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_BYTES_64 = 0x3,
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_BYTES_128 = 0x4,
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_BYTES_256 = 0x5,
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_BYTES_512 = 0x6,
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_BYTES_1024 = 0x7,
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_BYTES_2048 = 0x8,
    COMPONENT_CAP_2_POISON_GRANULARITY_SUPPORT_BYTES_4096 = 0x9
};

enum genz_component_cap_2_performance_marker_support {
    COMPONENT_CAP_2_PERFORMANCE_MARKER_SUPPORT_UNSUPPORTED = 0x0,
    COMPONENT_CAP_2_PERFORMANCE_MARKER_SUPPORT_TYPE_0 = 0x1,
    COMPONENT_CAP_2_PERFORMANCE_MARKER_SUPPORT_TYPE_1 = 0x2
};

enum genz_component_cap_2_meta_read_write_support {
    COMPONENT_CAP_2_META_READ_WRITE_SUPPORT_UNSUPPORTED = 0x0,
    COMPONENT_CAP_2_META_READ_WRITE_SUPPORT_C_UUID_SEE_CORE_STRUCTURE = 0x1,
    COMPONENT_CAP_2_META_READ_WRITE_SUPPORT_VENDOR_DEFINED_SEE_COMPONENT_MEDIA_STRUCTURE = 0x2,
    COMPONENT_CAP_2_META_READ_WRITE_SUPPORT_SERVICE_UUID_SEE_SERVICE_UUID_STRUCTURE = 0x3
};

enum genz_component_cap_2_control_di_pi_block_size {
    COMPONENT_CAP_2_CONTROL_DI_PI_BLOCK_SIZE_BYTES_512 = 0x0,
    COMPONENT_CAP_2_CONTROL_DI_PI_BLOCK_SIZE_BYTES_4096 = 0x1
};

enum genz_component_cap_3_control_dequeue_size {
    COMPONENT_CAP_3_CONTROL_DEQUEUE_SIZE_BYTES_16 = 0x0,
    COMPONENT_CAP_3_CONTROL_DEQUEUE_SIZE_BYTES_32 = 0x1,
    COMPONENT_CAP_3_CONTROL_DEQUEUE_SIZE_BYTES_64 = 0x2
};

enum genz_opcode_set_cap_1_control_enabled_cache_line_size {
    OPCODE_SET_CAP_1_CONTROL_ENABLED_CACHE_LINE_SIZE_DISABLED = 0x0,
    OPCODE_SET_CAP_1_CONTROL_ENABLED_CACHE_LINE_SIZE_BYTES_32 = 0x1,
    OPCODE_SET_CAP_1_CONTROL_ENABLED_CACHE_LINE_SIZE_BYTES_64 = 0x2,
    OPCODE_SET_CAP_1_CONTROL_ENABLED_CACHE_LINE_SIZE_BYTES_128 = 0x3,
    OPCODE_SET_CAP_1_CONTROL_ENABLED_CACHE_LINE_SIZE_BYTES_256 = 0x4
};

enum genz_opcode_set_cap_1_control_interface_uniform_opclass_selected {
    OPCODE_SET_CAP_1_CONTROL_INTERFACE_UNIFORM_OPCLASS_SELECTED_NOT_CONFIGURED = 0x0,
    OPCODE_SET_CAP_1_CONTROL_INTERFACE_UNIFORM_OPCLASS_SELECTED_EXPLICIT_OPCLASSES = 0x1,
    OPCODE_SET_CAP_1_CONTROL_INTERFACE_UNIFORM_OPCLASS_SELECTED_P2P_64_OPCLASS = 0x2,
    OPCODE_SET_CAP_1_CONTROL_INTERFACE_UNIFORM_OPCLASS_SELECTED_P2P_VENDOR_DEFINED_OPCLASS = 0x3
};

enum genz_opcode_set_cap_1_atomic_data_endian_type {
    OPCODE_SET_CAP_1_ATOMIC_DATA_ENDIAN_TYPE_UNSUPPORTED = 0x0,
    OPCODE_SET_CAP_1_ATOMIC_DATA_ENDIAN_TYPE_LITTLE = 0x1,
    OPCODE_SET_CAP_1_ATOMIC_DATA_ENDIAN_TYPE_BIG = 0x2,
    OPCODE_SET_CAP_1_ATOMIC_DATA_ENDIAN_TYPE_LITTLE_AND_BIG = 0x3
};

enum genz_opcode_set_cap_1_interrupt_role_if_interrupts_are_supported {
    OPCODE_SET_CAP_1_INTERRUPT_ROLE_IF_INTERRUPTS_ARE_SUPPORTED_UNSUPPORTED = 0x0,
    OPCODE_SET_CAP_1_INTERRUPT_ROLE_IF_INTERRUPTS_ARE_SUPPORTED_REQUESTER = 0x1,
    OPCODE_SET_CAP_1_INTERRUPT_ROLE_IF_INTERRUPTS_ARE_SUPPORTED_RESPONDER = 0x2,
    OPCODE_SET_CAP_1_INTERRUPT_ROLE_IF_INTERRUPTS_ARE_SUPPORTED_REQUESTER_RESPONDER = 0x3
};

enum genz_opcode_set_cap_1_multi_opcode_set_support {
    OPCODE_SET_CAP_1_MULTI_OPCODE_SET_SUPPORT_ENABLE_SINGLE_OPCODE_SET = 0x0,
    OPCODE_SET_CAP_1_MULTI_OPCODE_SET_SUPPORT_ENABLE_MULTIPLE_OPCODE_SETS = 0x1
};

enum genz_opcode_set_cap_1_uniform_opclass_support {
    OPCODE_SET_CAP_1_UNIFORM_OPCLASS_SUPPORT_NON_UNIFORM_OPCLASS_ALLOWED = 0x0,
    OPCODE_SET_CAP_1_UNIFORM_OPCLASS_SUPPORT_UNIFORM_OPCLASS_REQUIRED = 0x1
};

enum genz_i_status_interface_state {
    I_STATUS_INTERFACE_STATE_I_DOWN_UNINITIALIZED_STATE = 0x0,
    I_STATUS_INTERFACE_STATE_I_CFG_INTERFACE_INITIALIZATION_IN_PROGRESS = 0x1,
    I_STATUS_INTERFACE_STATE_I_UP_OPERATIONAL_STATE_PACKET_EXCHANGE_ENABLED = 0x2,
    I_STATUS_INTERFACE_STATE_I_LP_LOW_POWER_STATE_PACKET_EXCHANGE_DISABLED = 0x3
};

enum genz_i_status_link_ctl_completion_status {
    I_STATUS_LINK_CTL_COMPLETION_STATUS_IN_PROGRESS_WAITING_FOR_LINK_ACK = 0x0,
    I_STATUS_LINK_CTL_COMPLETION_STATUS_LINK_ACK_LINK_CTL_RECEIVED = 0x1,
    I_STATUS_LINK_CTL_COMPLETION_STATUS_ERROR_DETECTED = -1
};

enum genz_i_status_peer_nonce_detected {
    I_STATUS_PEER_NONCE_DETECTED_NOT_RECEIVED = 0x0,
    I_STATUS_PEER_NONCE_DETECTED_RECEIVED = 0x1
};

enum genz_i_status_link_level_reliability_llr_status {
    I_STATUS_LINK_LEVEL_RELIABILITY_LLR_STATUS_FAILED_UNSUPPORTED_L_DOWN = 0x0,
    I_STATUS_LINK_LEVEL_RELIABILITY_LLR_STATUS_SUCCESS = 0x1
};

enum genz_i_control_auto_stop {
    I_CONTROL_AUTO_STOP_DO_NOT_AUTO_STOP = 0x0,
    I_CONTROL_AUTO_STOP_AUTO_STOP = 0x1
};

enum genz_i_control_initiate_l_lp_transition {
    I_CONTROL_INITIATE_L_LP_TRANSITION_NO_IMPACT = 0x0,
    I_CONTROL_INITIATE_L_LP_TRANSITION_INITIATE_ENTER_LINK_LP_LINK_CTL_WITH_REQUESTED_PHY_LP_1_4 = -1
};

enum genz_i_control_initiate_l_up_lp_transition {
    I_CONTROL_INITIATE_L_UP_LP_TRANSITION_NO_IMPACT = 0x0,
    I_CONTROL_INITIATE_L_UP_LP_TRANSITION_INITIATE_ENTER_LINK_UP_LP_LINK_CTL_WITH_REQUESTED_PHY_UP_LP_1_4 = -1
};

enum genz_i_control_ingress_dr_enable {
    I_CONTROL_INGRESS_DR_ENABLE_MAY_NOT_RECEIVE = 0x0,
    I_CONTROL_INGRESS_DR_ENABLE_MAY_RECEIVE = 0x1
};

enum genz_i_cap_1_implicit_flow_control_support {
    I_CAP_1_IMPLICIT_FLOW_CONTROL_SUPPORT_UNSUPPORTED = 0x0,
    I_CAP_1_IMPLICIT_FLOW_CONTROL_SUPPORT_SUPPORTED = 0x1
};

enum genz_i_cap_1_explicit_flow_control_support {
    I_CAP_1_EXPLICIT_FLOW_CONTROL_SUPPORT_UNSUPPORTED = 0x0,
    I_CAP_1_EXPLICIT_FLOW_CONTROL_SUPPORT_SUPPORTED = 0x1
};

enum genz_i_cap_1_packet_relay_access_key_field_provisioned {
    I_CAP_1_PACKET_RELAY_ACCESS_KEY_FIELD_PROVISIONED_NOT_PROVISIONED = 0x0,
    I_CAP_1_PACKET_RELAY_ACCESS_KEY_FIELD_PROVISIONED_PROVISIONED = 0x1
};

enum genz_i_cap_1_aggregated_interface_support {
    I_CAP_1_AGGREGATED_INTERFACE_SUPPORT_NON_AGGREGATED_INTERFACE = 0x0,
    I_CAP_1_AGGREGATED_INTERFACE_SUPPORT_NON_AGGREGATED_OR_AGGREGATED_INTERFACE = 0x1
};

enum genz_i_cap_1_aggregated_interface_role {
    I_CAP_1_AGGREGATED_INTERFACE_ROLE_ONLY_NAI = 0x0,
    I_CAP_1_AGGREGATED_INTERFACE_ROLE_SAI_OR_NAI = 0x1
};

enum genz_i_cap_1_p2p_standalone_acknowledgment_required {
    I_CAP_1_P2P_STANDALONE_ACKNOWLEDGMENT_REQUIRED_CONFIGURABLE = 0x0,
    I_CAP_1_P2P_STANDALONE_ACKNOWLEDGMENT_REQUIRED_HARDWIRED = 0x1
};

enum genz_i_cap_1_requires_interface_group_single_opclass {
    I_CAP_1_REQUIRES_INTERFACE_GROUP_SINGLE_OPCLASS_NOT_REQUIRED = 0x0,
    I_CAP_1_REQUIRES_INTERFACE_GROUP_SINGLE_OPCLASS_REQUIRED = 0x1
};

enum genz_i_cap_1_control_flow_control_type {
    I_CAP_1_CONTROL_FLOW_CONTROL_TYPE_EXPLICIT_FLOW_CONTROL = 0x0,
    I_CAP_1_CONTROL_FLOW_CONTROL_TYPE_IMPLICIT_FLOW_CONTROL = 0x1
};

enum genz_i_cap_1_control_opclass_select {
    I_CAP_1_CONTROL_OPCLASS_SELECT_NOT_CONFIGURED = 0x0,
    I_CAP_1_CONTROL_OPCLASS_SELECT_INTERFACE_SHALL_BE_USED_ONLY_TO_EXCHANGE_EXPLICIT_OPCLASS_PACKETS = 0x1,
    I_CAP_1_CONTROL_OPCLASS_SELECT_INTERFACE_SHALL_BE_USED_ONLY_TO_EXCHANGE_P2P_64_PACKETS = 0x2,
    I_CAP_1_CONTROL_OPCLASS_SELECT_INTERFACE_SHALL_BE_USED_ONLY_TO_EXCHANGE_P2P_VENDOR_DEFINED_PACKETS = 0x3,
    I_CAP_1_CONTROL_OPCLASS_SELECT_NO_COMPATIBLE_OPCLASS = 0x7
};

enum genz_i_cap_1_control_link_level_reliability_llr_crc_trigger {
    I_CAP_1_CONTROL_LINK_LEVEL_RELIABILITY_LLR_CRC_TRIGGER_PCRC_ERROR_OR_ECRC_ERROR = 0x0,
    I_CAP_1_CONTROL_LINK_LEVEL_RELIABILITY_LLR_CRC_TRIGGER_ONLY_PCRC_ERROR = 0x1
};

enum genz_i_cap_1_control_peer_cid_configured {
    I_CAP_1_CONTROL_PEER_CID_CONFIGURED_NOT_CONFIGURED = 0x0,
    I_CAP_1_CONTROL_PEER_CID_CONFIGURED_CONFIGURED = 0x1
};

enum genz_i_cap_1_control_peer_sid_configured {
    I_CAP_1_CONTROL_PEER_SID_CONFIGURED_NOT_CONFIGURED = 0x0,
    I_CAP_1_CONTROL_PEER_SID_CONFIGURED_CONFIGURED = 0x1
};

enum genz_i_cap_1_control_omit_p2p_standalone_acknowledgment {
    I_CAP_1_CONTROL_OMIT_P2P_STANDALONE_ACKNOWLEDGMENT_DO_NOT_OMIT = 0x0,
    I_CAP_1_CONTROL_OMIT_P2P_STANDALONE_ACKNOWLEDGMENT_OMIT = 0x1
};

enum genz_i_cap_1_control_aggregated_interface_control {
    I_CAP_1_CONTROL_AGGREGATED_INTERFACE_CONTROL_INDEPENDENT = 0x0,
    I_CAP_1_CONTROL_AGGREGATED_INTERFACE_CONTROL_NAI = 0x1,
    I_CAP_1_CONTROL_AGGREGATED_INTERFACE_CONTROL_SAI = 0x2
};

enum genz_i_cap_2_transient_error_history_size {
    I_CAP_2_TRANSIENT_ERROR_HISTORY_SIZE_256 = 0x0,
    I_CAP_2_TRANSIENT_ERROR_HISTORY_SIZE_512 = 0x1,
    I_CAP_2_TRANSIENT_ERROR_HISTORY_SIZE_1024 = 0x2
};

enum genz_peer_state_peer_component_c_state {
    PEER_STATE_PEER_COMPONENT_C_STATE_C_DOWN = 0x0,
    PEER_STATE_PEER_COMPONENT_C_STATE_C_CFG = 0x1,
    PEER_STATE_PEER_COMPONENT_C_STATE_C_UP = 0x2,
    PEER_STATE_PEER_COMPONENT_C_STATE_C_LP = 0x3,
    PEER_STATE_PEER_COMPONENT_C_STATE_C_DLP = 0x4
};

enum genz_peer_state_peer_component_manager_type {
    PEER_STATE_PEER_COMPONENT_MANAGER_TYPE_PRIMARY_MANAGER = 0x0,
    PEER_STATE_PEER_COMPONENT_MANAGER_TYPE_FABRIC_MANAGER = 0x1
};

enum genz_peer_state_peer_component_multiple_cid_configuration {
    PEER_STATE_PEER_COMPONENT_MULTIPLE_CID_CONFIGURATION_SINGLE_CID = 0x0,
    PEER_STATE_PEER_COMPONENT_MULTIPLE_CID_CONFIGURATION_MULTIPLE_CIDS = 0x1
};

enum genz_peer_state_peer_out_of_band_management_disabled {
    PEER_STATE_PEER_OUT_OF_BAND_MANAGEMENT_DISABLED_ENABLED_DEFAULT = 0x0,
    PEER_STATE_PEER_OUT_OF_BAND_MANAGEMENT_DISABLED_DISABLED = 0x1
};

enum genz_peer_state_peer_interface_flow_control_support {
    PEER_STATE_PEER_INTERFACE_FLOW_CONTROL_SUPPORT_IMPLICIT_FLOW_CONTROL_SUPPORT = 0x0,
    PEER_STATE_PEER_INTERFACE_FLOW_CONTROL_SUPPORT_EXPLICIT_FLOW_CONTROL_SUPPORT = 0x1,
    PEER_STATE_PEER_INTERFACE_FLOW_CONTROL_SUPPORT_IMPLICIT_FLOW_CONTROL_AND_EXPLICIT_FLOW_CONTROL_SUPPORT = 0x2
};

enum genz_peer_state_peer_in_band_management_disabled {
    PEER_STATE_PEER_IN_BAND_MANAGEMENT_DISABLED_ENABLED_DEFAULT = 0x0,
    PEER_STATE_PEER_IN_BAND_MANAGEMENT_DISABLED_DISABLED = 0x1
};

enum genz_peer_state_peer_uniform_opclass_selected {
    PEER_STATE_PEER_UNIFORM_OPCLASS_SELECTED_NOT_CONFIGURED = 0x0,
    PEER_STATE_PEER_UNIFORM_OPCLASS_SELECTED_EXPLICIT_OPCLASSES = 0x1,
    PEER_STATE_PEER_UNIFORM_OPCLASS_SELECTED_P2P_64_OPCLASS = 0x2,
    PEER_STATE_PEER_UNIFORM_OPCLASS_SELECTED_P2P_VENDOR_DEFINED_OPCLASS = 0x3
};

enum genz_ttc_unit {
    TTC_UNIT_US_1 = 0x0,
    TTC_UNIT_MS_1 = 0x1,
    TTC_UNIT_S_1 = 0x2
};

enum genz_c_lp_ctl_lp_state {
    C_LP_CTL_LP_STATE_L_UP_LP = 0x0,
    C_LP_CTL_LP_STATE_L_LP = 0x1
};

enum genz_c_lp_ctl_sub_state {
    C_LP_CTL_SUB_STATE_SUB_STATE_1 = 0x0,
    C_LP_CTL_SUB_STATE_SUB_STATE_2 = 0x1,
    C_LP_CTL_SUB_STATE_SUB_STATE_3 = 0x2,
    C_LP_CTL_SUB_STATE_SUB_STATE_4 = 0x3
};

enum genz_c_dlp_ctl_lp_state {
    C_DLP_CTL_LP_STATE_L_UP_LP = 0x0,
    C_DLP_CTL_LP_STATE_L_LP = 0x1
};

enum genz_c_dlp_ctl_sub_state {
    C_DLP_CTL_SUB_STATE_SUB_STATE_1 = 0x0,
    C_DLP_CTL_SUB_STATE_SUB_STATE_2 = 0x1,
    C_DLP_CTL_SUB_STATE_SUB_STATE_3 = 0x2,
    C_DLP_CTL_SUB_STATE_SUB_STATE_4 = 0x3
};

enum genz_phy_type {
    PHY_TYPE_PHY_CLAUSE_5_25G_FABRIC = 0x0,
    PHY_TYPE_PHY_CLAUSE_6_25G_LOCAL = 0x1,
    PHY_TYPE_PHY_CLAUSE_7_PCIE_THROUGH_16_GT_S_ELECTRICAL_LOGICAL_AND_LTSSM = 0x2
};

enum genz_phy_status_physical_layer_operational_status {
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_DOWN_UNINITIALIZED_STATE = 0x0,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP = 0x1,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_DOWN_RETRAIN = 0x2,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP_LOW_POWER_1 = 0x3,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP_LOW_POWER_2 = 0x4,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP_LOW_POWER_3 = 0x5,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP_LOW_POWER_4 = 0x6,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_LOW_POWER_1 = 0x7,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_LOW_POWER_2 = 0x8,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_LOW_POWER_3 = 0x9,
    PHY_STATUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_LOW_POWER_4 = 0xA
};

enum genz_phy_status_previous_physical_layer_operational_status {
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_DOWN_UNINITIALIZED_STATE = 0x0,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP = 0x1,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_DOWN_RETRAIN = 0x2,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP_LOW_POWER_1 = 0x3,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP_LOW_POWER_2 = 0x4,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP_LOW_POWER_3 = 0x5,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_UP_LOW_POWER_4 = 0x6,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_LOW_POWER_1 = 0x7,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_LOW_POWER_2 = 0x8,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_LOW_POWER_3 = 0x9,
    PHY_STATUS_PREVIOUS_PHYSICAL_LAYER_OPERATIONAL_STATUS_PHY_LOW_POWER_4 = 0xA
};

enum genz_phy_status_physical_layer_training_status {
    PHY_STATUS_PHYSICAL_LAYER_TRAINING_STATUS_TRAINING_HAS_NOT_OCCURRED = 0x0,
    PHY_STATUS_PHYSICAL_LAYER_TRAINING_STATUS_TRAINING_SUCCEEDED = 0x1,
    PHY_STATUS_PHYSICAL_LAYER_TRAINING_STATUS_TRAINING_HAS_FAILED = 0x2
};

enum genz_phy_status_physical_layer_retraining_status {
    PHY_STATUS_PHYSICAL_LAYER_RETRAINING_STATUS_RETRAINING_HAS_NOT_OCCURRED = 0x0,
    PHY_STATUS_PHYSICAL_LAYER_RETRAINING_STATUS_RETRAINING_SUCCEEDED = 0x1,
    PHY_STATUS_PHYSICAL_LAYER_RETRAINING_STATUS_RETRAINING_FAILED = 0x2
};

enum genz_phy_status_phy_tx_link_width_reduced {
    PHY_STATUS_PHY_TX_LINK_WIDTH_REDUCED_NOMINAL_TX_LINK_WIDTH = 0x0,
    PHY_STATUS_PHY_TX_LINK_WIDTH_REDUCED_REDUCED_TX_LINK_WIDTH = 0x1
};

enum genz_phy_status_phy_rx_link_width_reduced {
    PHY_STATUS_PHY_RX_LINK_WIDTH_REDUCED_NOMINAL_RX_LINK_WIDTH = 0x0,
    PHY_STATUS_PHY_RX_LINK_WIDTH_REDUCED_REDUCED_RX_LINK_WIDTH = 0x1
};

enum genz_phy_status_phy_tx_error_detected {
    PHY_STATUS_PHY_TX_ERROR_DETECTED_NO_TX_ERRORS_DETECTED = 0x0,
    PHY_STATUS_PHY_TX_ERROR_DETECTED_TX_ERROR_DETECTED = 0x1
};

enum genz_phy_status_phy_rx_error_detected {
    PHY_STATUS_PHY_RX_ERROR_DETECTED_NO_RX_ERRORS_DETECTED = 0x0,
    PHY_STATUS_PHY_RX_ERROR_DETECTED_RX_ERROR_DETECTED = 0x1
};

enum genz_phy_control_physical_layer_retraining_level {
    PHY_CONTROL_PHYSICAL_LAYER_RETRAINING_LEVEL_PHY_FULL_RETRAINING_LEVEL_1_DEFAULT = 0x0,
    PHY_CONTROL_PHYSICAL_LAYER_RETRAINING_LEVEL_PHY_RETRAINING_LEVEL_2 = 0x1,
    PHY_CONTROL_PHYSICAL_LAYER_RETRAINING_LEVEL_PHY_RETRAINING_LEVEL_3 = 0x2,
    PHY_CONTROL_PHYSICAL_LAYER_RETRAINING_LEVEL_PHY_RETRAINING_LEVEL_4 = 0x3
};

enum genz_phy_cap_1_default_phy {
    PHY_CAP_1_DEFAULT_PHY_NON_DEFAULT = 0x0,
    PHY_CAP_1_DEFAULT_PHY_DEFAULT = 0x1
};

enum genz_phy_cap_1_control_interface_aggregation_type {
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_NON_OPERATIONAL_AGGREGATED_INTERFACE_NAI = 0x0,
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_NON_AGGREGATED_INTERFACE_I_E_AN_INDEPENDENT_INTERFACE = 0x1,
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_SINGLE_AGGREGATED_INTERFACE_SAI_COMPOSED_OF_2_INTERFACES = 0x2,
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_SAI_COMPOSED_OF_4_INTERFACES = 0x3,
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_SAI_COMPOSED_OF_8_INTERFACES = 0x4,
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_SAI_COMPOSED_OF_16_INTERFACES = 0x5,
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_SAI_COMPOSED_OF_32_INTERFACES = 0x6,
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_SAI_COMPOSED_OF_64_INTERFACES = 0x7,
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_SAI_COMPOSED_OF_128_INTERFACES = 0x8,
    PHY_CAP_1_CONTROL_INTERFACE_AGGREGATION_TYPE_SAI_COMPOSED_OF_256_INTERFACES = 0x9
};

enum genz_phy_lane_status_phy_tx_link_width_reduced {
    PHY_LANE_STATUS_PHY_TX_LINK_WIDTH_REDUCED_NOMINAL_TX_LINK_WIDTH = 0x0,
    PHY_LANE_STATUS_PHY_TX_LINK_WIDTH_REDUCED_REDUCED_TX_LINK_WIDTH = 0x1
};

enum genz_phy_lane_status_phy_rx_link_width_reduced {
    PHY_LANE_STATUS_PHY_RX_LINK_WIDTH_REDUCED_NOMINAL_RX_LINK_WIDTH = 0x0,
    PHY_LANE_STATUS_PHY_RX_LINK_WIDTH_REDUCED_REDUCED_RX_LINK_WIDTH = 0x1
};

enum genz_phy_lane_status_asymmetric_lane_status {
    PHY_LANE_STATUS_ASYMMETRIC_LANE_STATUS_SYMMETRIC = 0x0,
    PHY_LANE_STATUS_ASYMMETRIC_LANE_STATUS_ASYMMETRIC = 0x1
};

enum genz_phy_lane_status_tx_reversal_status {
    PHY_LANE_STATUS_TX_REVERSAL_STATUS_TX_LANES_NOT_REVERSED = 0x0,
    PHY_LANE_STATUS_TX_REVERSAL_STATUS_TX_LANES_REVERSED = 0x1
};

enum genz_phy_lane_status_rx_reversal_status {
    PHY_LANE_STATUS_RX_REVERSAL_STATUS_RX_LANES_NOT_REVERSED = 0x0,
    PHY_LANE_STATUS_RX_REVERSAL_STATUS_RX_LANES_REVERSED = 0x1
};

enum genz_phy_lane_control_enable_lane_asymmetry {
    PHY_LANE_CONTROL_ENABLE_LANE_ASYMMETRY_SYMMETRIC_ENABLED = 0x0,
    PHY_LANE_CONTROL_ENABLE_LANE_ASYMMETRY_STATIC_ASYMMETRIC_ENABLED = 0x1,
    PHY_LANE_CONTROL_ENABLE_LANE_ASYMMETRY_DYNAMIC_ASYMMETRIC_ENABLED = 0x2
};

enum genz_phy_lane_control_enable_tx_reversal {
    PHY_LANE_CONTROL_ENABLE_TX_REVERSAL_TX_REVERSAL_DISABLED = 0x0,
    PHY_LANE_CONTROL_ENABLE_TX_REVERSAL_DYNAMIC_TX_REVERSAL_ENABLED = 0x1,
    PHY_LANE_CONTROL_ENABLE_TX_REVERSAL_STATIC_TX_REVERSAL_ENABLED = 0x2
};

enum genz_phy_lane_control_enable_rx_reversal {
    PHY_LANE_CONTROL_ENABLE_RX_REVERSAL_RX_REVERSAL_DISABLED = 0x0,
    PHY_LANE_CONTROL_ENABLE_RX_REVERSAL_DYNAMIC_RX_REVERSAL_ENABLED = 0x1,
    PHY_LANE_CONTROL_ENABLE_RX_REVERSAL_STATIC_RX_REVERSAL_ENABLED = 0x2
};

enum genz_phy_lane_cap_asymmetric_lane_support {
    PHY_LANE_CAP_ASYMMETRIC_LANE_SUPPORT_SYMMETRIC = 0x0,
    PHY_LANE_CAP_ASYMMETRIC_LANE_SUPPORT_STATIC_ASYMMETRIC = 0x1,
    PHY_LANE_CAP_ASYMMETRIC_LANE_SUPPORT_DYNAMIC_ASYMMETRIC = 0x2,
    PHY_LANE_CAP_ASYMMETRIC_LANE_SUPPORT_STATIC_AND_DYNAMIC_ASYMMETRIC = 0x3
};

enum genz_phy_lane_cap_reversal_support {
    PHY_LANE_CAP_REVERSAL_SUPPORT_REVERSAL_UNSUPPORTED = 0x0,
    PHY_LANE_CAP_REVERSAL_SUPPORT_STATIC_UNIFORM_REVERSAL_SUPPORTED = 0x1,
    PHY_LANE_CAP_REVERSAL_SUPPORT_DYNAMIC_AND_STATIC_UNIFORM_REVERSAL_SUPPORTED = 0x2,
    PHY_LANE_CAP_REVERSAL_SUPPORT_STATIC_NON_UNIFORM_REVERSAL_SUPPORTED = 0x3,
    PHY_LANE_CAP_REVERSAL_SUPPORT_DYNAMIC_AND_STATIC_NON_UNIFORM_REVERSAL_SUPPORTED = 0x4
};

enum genz_phy_remote_lane_cap_remote_asymmetric_lane_support {
    PHY_REMOTE_LANE_CAP_REMOTE_ASYMMETRIC_LANE_SUPPORT_SYMMETRIC = 0x0,
    PHY_REMOTE_LANE_CAP_REMOTE_ASYMMETRIC_LANE_SUPPORT_STATIC_ASYMMETRIC = 0x1,
    PHY_REMOTE_LANE_CAP_REMOTE_ASYMMETRIC_LANE_SUPPORT_DYNAMIC_ASYMMETRIC = 0x2,
    PHY_REMOTE_LANE_CAP_REMOTE_ASYMMETRIC_LANE_SUPPORT_STATIC_AND_DYNAMIC_ASYMMETRIC = 0x3
};

enum genz_phy_remote_lane_cap_remote_reversal_support {
    PHY_REMOTE_LANE_CAP_REMOTE_REVERSAL_SUPPORT_REVERSAL_UNSUPPORTED = 0x0,
    PHY_REMOTE_LANE_CAP_REMOTE_REVERSAL_SUPPORT_STATIC_UNIFORM_REVERSAL_SUPPORTED = 0x1,
    PHY_REMOTE_LANE_CAP_REMOTE_REVERSAL_SUPPORT_DYNAMIC_AND_STATIC_UNIFORM_REVERSAL_SUPPORTED = 0x2,
    PHY_REMOTE_LANE_CAP_REMOTE_REVERSAL_SUPPORT_STATIC_NON_UNIFORM_REVERSAL_SUPPORTED = 0x3,
    PHY_REMOTE_LANE_CAP_REMOTE_REVERSAL_SUPPORT_DYNAMIC_AND_DYNAMIC_NON_UNIFORM_REVERSAL_SUPPORTED = 0x4,
    PHY_REMOTE_LANE_CAP_REMOTE_REVERSAL_SUPPORT_STATIC_AND_DYNAMIC_ASYMMETRIC = -1
};

enum genz_i_stat_cap_1_provisioned_statistics_fields {
    I_STAT_CAP_1_PROVISIONED_STATISTICS_FIELDS_COMMON_INTERFACE_FIELDS = 0x0,
    I_STAT_CAP_1_PROVISIONED_STATISTICS_FIELDS_COMMON_AND_REQUESTER_AND_RESPONDER_INTERFACE_STATISTICS_FIELDS = 0x1,
    I_STAT_CAP_1_PROVISIONED_STATISTICS_FIELDS_COMMON_AND_PACKET_RELAY_INTERFACE_STATISTICS_FIELDS = 0x2,
    I_STAT_CAP_1_PROVISIONED_STATISTICS_FIELDS_COMMON_REQUESTER_AND_RESPONDER_INTERFACE_STATISTICS_FIELDS_FOLLOWED_BY_PACKET_RELAY_INTERFACE_STATISTICS_FIELDS = 0x3
};

enum genz_i_stat_cap_1_maximum_snapshot_time {
    I_STAT_CAP_1_MAXIMUM_SNAPSHOT_TIME_MS_1 = 0x0,
    I_STAT_CAP_1_MAXIMUM_SNAPSHOT_TIME_MS_10 = 0x1,
    I_STAT_CAP_1_MAXIMUM_SNAPSHOT_TIME_MS_100 = 0x2,
    I_STAT_CAP_1_MAXIMUM_SNAPSHOT_TIME_SECOND_1 = 0x3
};

enum genz_i_stat_status_interface_statistics_reset_status {
    I_STAT_STATUS_INTERFACE_STATISTICS_RESET_STATUS_NO_RESET_EVENT = 0x0,
    I_STAT_STATUS_INTERFACE_STATISTICS_RESET_STATUS_RESET_EVENT = 0x1
};

enum genz_i_stat_status_snapshot_status {
    I_STAT_STATUS_SNAPSHOT_STATUS_INCOMPLETE = 0x0,
    I_STAT_STATUS_SNAPSHOT_STATUS_COMPLETED = 0x1
};

enum genz_e_control_error_logging_level {
    E_CONTROL_ERROR_LOGGING_LEVEL_LOG_ONLY_CRITICAL_ERRORS = 0x0,
    E_CONTROL_ERROR_LOGGING_LEVEL_LOG_CRITICAL_AND_CAUTION_ERRORS = 0x1,
    E_CONTROL_ERROR_LOGGING_LEVEL_LOG_CRITICAL_CAUTION_AND_NON_CRITICAL_ERRORS = 0x2
};

enum genz_e_control_uep_error_target {
    E_CONTROL_UEP_ERROR_TARGET_TARGET_PRIMARY_MANAGER_AS_INDICATED_IN_THE_CORE_STRUCTURE = 0x0,
    E_CONTROL_UEP_ERROR_TARGET_TARGET_CORE_STRUCTURE_PRIMARY_OR_SECONDARY_FABRIC_MANAGER = 0x1,
    E_CONTROL_UEP_ERROR_TARGET_TARGET_MANAGER_ERROR_MGR_CID_VALID_ERROR_MGR_SID_INVALID = 0x2,
    E_CONTROL_UEP_ERROR_TARGET_TARGET_MANAGER_ERROR_MGR_CID_VALID_ERROR_MGR_SID_VALID = 0x3
};

enum genz_e_control_event_uep_target {
    E_CONTROL_EVENT_UEP_TARGET_TARGET_PRIMARY_MANAGER_AS_INDICATED_IN_THE_CORE_STRUCTURE = 0x0,
    E_CONTROL_EVENT_UEP_TARGET_TARGET_CORE_STRUCTURE_PRIMARY_OR_SECONDARY_FABRIC_MANAGER = 0x1,
    E_CONTROL_EVENT_UEP_TARGET_TARGET_MANAGER_EVENT_MGR_CID_VALID_EVENT_MGR_SID_INVALID = 0x2,
    E_CONTROL_EVENT_UEP_TARGET_TARGET_MANAGER_EVENT_MGR_CID_VALID_EVENT_MGR_SID_VALID = 0x3
};

enum genz_e_control_mech_uep_target {
    E_CONTROL_MECH_UEP_TARGET_TARGET_PRIMARY_MANAGER_AS_INDICATED_IN_THE_CORE_STRUCTURE = 0x0,
    E_CONTROL_MECH_UEP_TARGET_TARGET_CORE_STRUCTURE_PRIMARY_OR_SECONDARY_FABRIC_MANAGER = 0x1,
    E_CONTROL_MECH_UEP_TARGET_TARGET_MANAGER_MECH_MGR_CID_VALID_MECH_MGR_SID_INVALID = 0x2,
    E_CONTROL_MECH_UEP_TARGET_TARGET_MANAGER_MECH_MGR_CID_VALID_MECH_MGR_SID_VALID = 0x3
};

enum genz_e_control_media_uep_target {
    E_CONTROL_MEDIA_UEP_TARGET_TARGET_PRIMARY_MANAGER_AS_INDICATED_IN_THE_CORE_STRUCTURE = 0x0,
    E_CONTROL_MEDIA_UEP_TARGET_TARGET_CORE_STRUCTURE_PRIMARY_OR_SECONDARY_FABRIC_MANAGER = 0x1,
    E_CONTROL_MEDIA_UEP_TARGET_TARGET_MANAGER_MEDIA_MGR_CID_VALID_MEDIA_MGR_SID_INVALID = 0x2,
    E_CONTROL_MEDIA_UEP_TARGET_TARGET_MANAGER_MEDIA_MGR_CID_VALID_MEDIA_MGR_SID_VALID = 0x3
};

enum genz_error_signal_cap_1_vendor_defined_error_log_uuid {
    ERROR_SIGNAL_CAP_1_VENDOR_DEFINED_ERROR_LOG_UUID_UNSUPPORTED = 0x0,
    ERROR_SIGNAL_CAP_1_VENDOR_DEFINED_ERROR_LOG_UUID_CORE_STRUCTURE_C_UUID = 0x1,
    ERROR_SIGNAL_CAP_1_VENDOR_DEFINED_ERROR_LOG_UUID_VENDOR_DEFINED_STRUCTURE_WITH_UUID = 0x2
};

enum genz_e_control_2_pwr_uep_target {
    E_CONTROL_2_PWR_UEP_TARGET_TARGET_PRIMARY_MANAGER_AS_INDICATED_IN_THE_CORE_STRUCTURE = 0x0,
    E_CONTROL_2_PWR_UEP_TARGET_TARGET_CORE_STRUCTURE_PRIMARY_OR_SECONDARY_FABRIC_MANAGER = 0x1,
    E_CONTROL_2_PWR_UEP_TARGET_TARGET_MANAGER_PWR_MGR_CID_VALID_PWR_MGR_SID_INVALID = 0x2,
    E_CONTROL_2_PWR_UEP_TARGET_TARGET_MANAGER_PWR_MGR_CID_VALID_PWR_MGR_SID_VALID = 0x3
};

enum genz_component_media_control_primary_media_maintenance_disable {
    COMPONENT_MEDIA_CONTROL_PRIMARY_MEDIA_MAINTENANCE_DISABLE_ENABLED = 0x0,
    COMPONENT_MEDIA_CONTROL_PRIMARY_MEDIA_MAINTENANCE_DISABLE_DISABLED = 0x1
};

enum genz_component_media_control_secondary_media_maintenance_disable {
    COMPONENT_MEDIA_CONTROL_SECONDARY_MEDIA_MAINTENANCE_DISABLE_ENABLED = 0x0,
    COMPONENT_MEDIA_CONTROL_SECONDARY_MEDIA_MAINTENANCE_DISABLE_DISABLED = 0x1
};

enum genz_component_media_control_primary_se_initialization {
    COMPONENT_MEDIA_CONTROL_PRIMARY_SE_INITIALIZATION_RESERVED_SHALL_NOT_BE_USED = 0x0,
    COMPONENT_MEDIA_CONTROL_PRIMARY_SE_INITIALIZATION_SE_FAST_ZERO_MEDIA = 0x1,
    COMPONENT_MEDIA_CONTROL_PRIMARY_SE_INITIALIZATION_SE_FAST_ZERO_MEDIA_RANGE = 0x2,
    COMPONENT_MEDIA_CONTROL_PRIMARY_SE_INITIALIZATION_SE_ZERO_MEDIA = 0x3,
    COMPONENT_MEDIA_CONTROL_PRIMARY_SE_INITIALIZATION_SE_CRYPTOGRAPHIC_KEY = 0x4,
    COMPONENT_MEDIA_CONTROL_PRIMARY_SE_INITIALIZATION_SE_OVERWRITE_MEDIA_NO_INVERSION = 0x5,
    COMPONENT_MEDIA_CONTROL_PRIMARY_SE_INITIALIZATION_SE_OVERWRITE_MEDIA_ALTERNATING_INVERSION = 0x6,
    COMPONENT_MEDIA_CONTROL_PRIMARY_SE_INITIALIZATION_SE_VENDOR_DEFINED = 0x7,
    COMPONENT_MEDIA_CONTROL_PRIMARY_SE_INITIALIZATION_SE_VENDOR_DEFINED_RANGE = 0x8
};

enum genz_component_media_control_secondary_se_initialization {
    COMPONENT_MEDIA_CONTROL_SECONDARY_SE_INITIALIZATION_RESERVED_SHALL_NOT_BE_USED = 0x0,
    COMPONENT_MEDIA_CONTROL_SECONDARY_SE_INITIALIZATION_SE_FAST_ZERO_MEDIA = 0x1,
    COMPONENT_MEDIA_CONTROL_SECONDARY_SE_INITIALIZATION_SE_FAST_ZERO_MEDIA_RANGE = 0x2,
    COMPONENT_MEDIA_CONTROL_SECONDARY_SE_INITIALIZATION_SE_ZERO_MEDIA = 0x3,
    COMPONENT_MEDIA_CONTROL_SECONDARY_SE_INITIALIZATION_SE_CRYPTOGRAPHIC_KEY = 0x4,
    COMPONENT_MEDIA_CONTROL_SECONDARY_SE_INITIALIZATION_SE_OVERWRITE_MEDIA_NO_INVERSION = 0x5,
    COMPONENT_MEDIA_CONTROL_SECONDARY_SE_INITIALIZATION_SE_OVERWRITE_MEDIA_ALTERNATING_INVERSION = 0x6,
    COMPONENT_MEDIA_CONTROL_SECONDARY_SE_INITIALIZATION_SE_VENDOR_DEFINED = 0x7,
    COMPONENT_MEDIA_CONTROL_SECONDARY_SE_INITIALIZATION_SE_VENDOR_DEFINED_RANGE = 0x8
};

enum genz_primary_media_cap_1_63_0_primary_media_power_scale_mpwrs {
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_MEDIA_POWER_SCALE_MPWRS_1_0 = 0x0,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_MEDIA_POWER_SCALE_MPWRS_0_1 = 0x1,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_MEDIA_POWER_SCALE_MPWRS_0_01 = 0x2,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_MEDIA_POWER_SCALE_MPWRS_0_001 = 0x3
};

enum genz_primary_media_cap_1_63_0_primary_error_detection_range {
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_UNSUPPORTED_0 = 0x0,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_8 = 0x1,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_16 = 0x2,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_32 = 0x3,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_64 = 0x4,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_128 = 0x5,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_256 = 0x6,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_512 = 0x7,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_1024 = 0x8,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_2048 = 0x9,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_4096 = 0xA,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_ERROR_DETECTION_RANGE_8192 = 0xB
};

enum genz_primary_media_cap_1_63_0_primary_byte_block_addressing {
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_BYTE_BLOCK_ADDRESSING_BYTE = 0x0,
    PRIMARY_MEDIA_CAP_1_63_0_PRIMARY_BYTE_BLOCK_ADDRESSING_BLOCK = 0x1
};

enum genz_primary_media_cap_1_127_64_primary_row_remapping_size {
    PRIMARY_MEDIA_CAP_1_127_64_PRIMARY_ROW_REMAPPING_SIZE_UNSUPPORTED_CAPABILITY = 0x0,
    PRIMARY_MEDIA_CAP_1_127_64_PRIMARY_ROW_REMAPPING_SIZE_ROW_1 = 0x1,
    PRIMARY_MEDIA_CAP_1_127_64_PRIMARY_ROW_REMAPPING_SIZE_ROWS_2 = 0x2,
    PRIMARY_MEDIA_CAP_1_127_64_PRIMARY_ROW_REMAPPING_SIZE_ROWS_4 = 0x3,
    PRIMARY_MEDIA_CAP_1_127_64_PRIMARY_ROW_REMAPPING_SIZE_ROWS_8 = 0x4
};

enum genz_primary_media_cap_1_127_64_primary_media_volatility {
    PRIMARY_MEDIA_CAP_1_127_64_PRIMARY_MEDIA_VOLATILITY_VOLATILE_MEDIA = 0x0,
    PRIMARY_MEDIA_CAP_1_127_64_PRIMARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_REQUEST_PU_1B_TO_ENSURE_PERSISTENCY = 0x1,
    PRIMARY_MEDIA_CAP_1_127_64_PRIMARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_PERSISTENT_FLUSH_TO_ENSURE_PERSISTENCY = 0x2,
    PRIMARY_MEDIA_CAP_1_127_64_PRIMARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_REQUEST_PU_1B_OR_PERSISTENT_FLUSH_TO_ENSURE_PERSISTENCY = 0x3
};

enum genz_secondary_media_cap_1_63_0_secondary_media_power_scale_mpwrs {
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_MEDIA_POWER_SCALE_MPWRS_1_0 = 0x0,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_MEDIA_POWER_SCALE_MPWRS_0_1 = 0x1,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_MEDIA_POWER_SCALE_MPWRS_0_01 = 0x2,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_MEDIA_POWER_SCALE_MPWRS_0_001 = 0x3
};

enum genz_secondary_media_cap_1_63_0_secondary_error_detection_range {
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_UNSUPPORTED_0 = 0x0,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_8 = 0x1,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_16 = 0x2,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_32 = 0x3,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_64 = 0x4,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_128 = 0x5,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_256 = 0x6,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_512 = 0x7,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_1024 = 0x8,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_2048 = 0x9,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_4096 = 0xA,
    SECONDARY_MEDIA_CAP_1_63_0_SECONDARY_ERROR_DETECTION_RANGE_8192 = 0xB
};

enum genz_secondary_media_cap_1_127_64_secondary_media_addressability {
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_MEDIA_ADDRESSABILITY_NOT_ADDRESSABLE = 0x0,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_MEDIA_ADDRESSABILITY_BYTE = 0x1,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_MEDIA_ADDRESSABILITY_BLOCK = 0x2
};

enum genz_secondary_media_cap_1_127_64_secondary_row_remapping_size {
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_ROW_REMAPPING_SIZE_ROWS_UNSUPPORTED_0 = 0x0,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_ROW_REMAPPING_SIZE_ROW_1 = 0x1,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_ROW_REMAPPING_SIZE_ROWS_2 = 0x2,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_ROW_REMAPPING_SIZE_ROWS_4 = 0x3,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_ROW_REMAPPING_SIZE_ROWS_8 = 0x4
};

enum genz_secondary_media_cap_1_127_64_secondary_media_volatility {
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_MEDIA_VOLATILITY_VOLATILE_MEDIA = 0x0,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_REQUEST_PU_1B_TO_ENSURE_PERSISTENCY = 0x1,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_PERSISTENT_FLUSH_TO_ENSURE_PERSISTENCY = 0x2,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_REQUEST_PU_1B_OR_PERSISTENT_FLUSH_TO_ENSURE_PERSISTENCY = 0x3
};

enum genz_secondary_media_cap_1_127_64_secondary_media_location {
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_MEDIA_LOCATION_CO_LOCATED = 0x0,
    SECONDARY_MEDIA_CAP_1_127_64_SECONDARY_MEDIA_LOCATION_DISCRETE = 0x1
};

enum genz_primary_media_cap_1_control_primary_patrol_scrubbing_frequency {
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_PATROL_SCRUBBING_FREQUENCY_HOURS_48 = 0x0,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_PATROL_SCRUBBING_FREQUENCY_HOURS_36 = 0x1,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_PATROL_SCRUBBING_FREQUENCY_HOURS_24 = 0x2,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_PATROL_SCRUBBING_FREQUENCY_HOURS_12 = 0x3,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_PATROL_SCRUBBING_FREQUENCY_HOURS_8 = 0x4,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_PATROL_SCRUBBING_FREQUENCY_HOURS_4 = 0x5,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_PATROL_SCRUBBING_FREQUENCY_HOURS_2 = 0x6,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_PATROL_SCRUBBING_FREQUENCY_HOUR_1 = 0x7
};

enum genz_primary_media_cap_1_control_primary_error_and_event_notification {
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_ERROR_AND_EVENT_NOTIFICATION_RETURN_ERROR_REASONS_IN_RESPONSE_PACKETS = 0x0,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_ERROR_AND_EVENT_NOTIFICATION_DO_NOT_RETURN_ERROR_REASONS_IN_RESPONSE_PACKETS_INDEPENDENTLY_INFORM_MANAGEMENT_OF_ALL_ERRORS_AND_EVENTS = 0x1
};

enum genz_primary_media_cap_1_control_primary_management_event_notification {
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_DO_NOT_NOTIFY_MANAGEMENT = 0x0,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_NOTIFY_MANAGEMENT_OF_NEW_CRITICAL_EVENTS = 0x1,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_NOTIFY_MANAGEMENT_OF_NEW_CRITICAL_AND_CAUTION_EVENTS = 0x2,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_NOTIFY_MANAGEMENT_OF_NEW_CRITICAL_CAUTION_AND_NON_CRITICAL_EVENTS = 0x3
};

enum genz_primary_media_cap_1_control_primary_management_event_notification_method {
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_NO_SIGNAL_IS_GENERATED = 0x0,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPT_0 = 0x1,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPT_1 = 0x2,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPTS_0_AND_1 = 0x3,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_UNSOLICITED_EVENT_UE_PACKET = 0x4,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPT_0_AND_AN_UNSOLICITED_EVENT_UE_PACKET = 0x5,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPT_1_AND_AN_UNSOLICITED_EVENT_UE_PACKET = 0x6,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPTS_0_AND_1_AND_AN_UNSOLICITED_EVENT_UE_PACKET = 0x7
};

enum genz_primary_media_cap_1_control_primary_event_logging_level {
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_EVENT_LOGGING_LEVEL_DO_NOT_LOG_EVENTS = 0x0,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_EVENT_LOGGING_LEVEL_LOG_ONLY_CRITICAL_EVENTS = 0x1,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_EVENT_LOGGING_LEVEL_LOG_CRITICAL_AND_CAUTION_EVENTS = 0x2,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_EVENT_LOGGING_LEVEL_LOG_CRITICAL_CAUTION_AND_INFORM_EVENTS = 0x3
};

enum genz_primary_media_cap_1_control_initiate_primary_sanitize_and_erase {
    PRIMARY_MEDIA_CAP_1_CONTROL_INITIATE_PRIMARY_SANITIZE_AND_ERASE_RESERVED_SHALL_NOT_BE_USED = 0x0,
    PRIMARY_MEDIA_CAP_1_CONTROL_INITIATE_PRIMARY_SANITIZE_AND_ERASE_SE_FAST_ZERO_MEDIA = 0x1,
    PRIMARY_MEDIA_CAP_1_CONTROL_INITIATE_PRIMARY_SANITIZE_AND_ERASE_SE_FAST_ZERO_MEDIA_RANGE = 0x2,
    PRIMARY_MEDIA_CAP_1_CONTROL_INITIATE_PRIMARY_SANITIZE_AND_ERASE_SE_ZERO_MEDIA = 0x3,
    PRIMARY_MEDIA_CAP_1_CONTROL_INITIATE_PRIMARY_SANITIZE_AND_ERASE_SE_CRYPTOGRAPHIC_KEY = 0x4,
    PRIMARY_MEDIA_CAP_1_CONTROL_INITIATE_PRIMARY_SANITIZE_AND_ERASE_SE_OVERWRITE_MEDIA_NO_INVERSION = 0x5,
    PRIMARY_MEDIA_CAP_1_CONTROL_INITIATE_PRIMARY_SANITIZE_AND_ERASE_SE_OVERWRITE_MEDIA_ALTERNATING_INVERSION = 0x6,
    PRIMARY_MEDIA_CAP_1_CONTROL_INITIATE_PRIMARY_SANITIZE_AND_ERASE_SE_VENDOR_DEFINED = 0x7,
    PRIMARY_MEDIA_CAP_1_CONTROL_INITIATE_PRIMARY_SANITIZE_AND_ERASE_SE_VENDOR_DEFINED_RANGE = 0x8
};

enum genz_primary_media_cap_1_control_primary_se_overwrite_media_count {
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_SE_OVERWRITE_MEDIA_COUNT_1 = 0x0,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_SE_OVERWRITE_MEDIA_COUNT_8 = 0x1,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_SE_OVERWRITE_MEDIA_COUNT_16 = 0x2,
    PRIMARY_MEDIA_CAP_1_CONTROL_PRIMARY_SE_OVERWRITE_MEDIA_COUNT_32 = 0x3
};

enum genz_secondary_media_cap_1_control_secondary_patrol_scrubbing_frequency {
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_PATROL_SCRUBBING_FREQUENCY_HOURS_48 = 0x0,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_PATROL_SCRUBBING_FREQUENCY_HOURS_36 = 0x1,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_PATROL_SCRUBBING_FREQUENCY_HOURS_24 = 0x2,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_PATROL_SCRUBBING_FREQUENCY_HOURS_12 = 0x3,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_PATROL_SCRUBBING_FREQUENCY_HOURS_8 = 0x4,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_PATROL_SCRUBBING_FREQUENCY_HOURS_4 = 0x5,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_PATROL_SCRUBBING_FREQUENCY_HOURS_2 = 0x6,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_PATROL_SCRUBBING_FREQUENCY_HOUR_1 = 0x7
};

enum genz_secondary_media_cap_1_control_secondary_error_and_event_notification {
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_ERROR_AND_EVENT_NOTIFICATION_RETURN_ERROR_REASONS_IN_RESPONSE_PACKETS = 0x0,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_ERROR_AND_EVENT_NOTIFICATION_DO_NOT_RETURN_ERROR_REASONS_IN_RESPONSE_PACKETS_INDEPENDENTLY_INFORM_MANAGEMENT_OF_ALL_ERRORS_AND_EVENTS = 0x1
};

enum genz_secondary_media_cap_1_control_secondary_management_event_notification {
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_DO_NOT_NOTIFY_MANAGEMENT = 0x0,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_NOTIFY_MANAGEMENT_OF_NEW_CRITICAL_EVENTS = 0x1,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_NOTIFY_MANAGEMENT_OF_NEW_CRITICAL_AND_CAUTION_EVENTS = 0x2,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_NOTIFY_MANAGEMENT_OF_NEW_CRITICAL_CAUTION_AND_NON_CRITICAL_EVENTS = 0x3
};

enum genz_secondary_media_cap_1_control_secondary_management_event_notification_method {
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_NO_SIGNAL_IS_GENERATED = 0x0,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPT_0 = 0x1,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPT_1 = 0x2,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPTS_0_AND_1 = 0x3,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_UNSOLICITED_EVENT_UE_PACKET = 0x4,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPT_0_AND_AN_UNSOLICITED_EVENT_UE_PACKET = 0x5,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPT_1_AND_AN_UNSOLICITED_EVENT_UE_PACKET = 0x6,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_MANAGEMENT_EVENT_NOTIFICATION_METHOD_COMPONENT_LOCAL_INTERRUPTS_0_AND_1_AND_AN_UNSOLICITED_EVENT_UE_PACKET = 0x7
};

enum genz_secondary_media_cap_1_control_secondary_event_logging_level {
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_EVENT_LOGGING_LEVEL_DO_NOT_LOG_EVENTS = 0x0,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_EVENT_LOGGING_LEVEL_LOG_ONLY_CRITICAL_EVENTS = 0x1,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_EVENT_LOGGING_LEVEL_LOG_CRITICAL_AND_CAUTION_EVENTS = 0x2,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_EVENT_LOGGING_LEVEL_LOG_CRITICAL_CAUTION_AND_INFORM_EVENTS = 0x3
};

enum genz_secondary_media_cap_1_control_initiate_secondary_sanitize_and_erase {
    SECONDARY_MEDIA_CAP_1_CONTROL_INITIATE_SECONDARY_SANITIZE_AND_ERASE_RESERVED_SHALL_NOT_BE_USED = 0x0,
    SECONDARY_MEDIA_CAP_1_CONTROL_INITIATE_SECONDARY_SANITIZE_AND_ERASE_SE_FAST_ZERO_MEDIA = 0x1,
    SECONDARY_MEDIA_CAP_1_CONTROL_INITIATE_SECONDARY_SANITIZE_AND_ERASE_SE_FAST_ZERO_MEDIA_RANGE = 0x2,
    SECONDARY_MEDIA_CAP_1_CONTROL_INITIATE_SECONDARY_SANITIZE_AND_ERASE_SE_ZERO_MEDIA = 0x3,
    SECONDARY_MEDIA_CAP_1_CONTROL_INITIATE_SECONDARY_SANITIZE_AND_ERASE_SE_CRYPTOGRAPHIC_KEY = 0x4,
    SECONDARY_MEDIA_CAP_1_CONTROL_INITIATE_SECONDARY_SANITIZE_AND_ERASE_SE_OVERWRITE_MEDIA_NO_INVERSION = 0x5,
    SECONDARY_MEDIA_CAP_1_CONTROL_INITIATE_SECONDARY_SANITIZE_AND_ERASE_SE_OVERWRITE_MEDIA_ALTERNATING_INVERSION = 0x6,
    SECONDARY_MEDIA_CAP_1_CONTROL_INITIATE_SECONDARY_SANITIZE_AND_ERASE_SE_VENDOR_DEFINED = 0x7,
    SECONDARY_MEDIA_CAP_1_CONTROL_INITIATE_SECONDARY_SANITIZE_AND_ERASE_SE_VENDOR_DEFINED_RANGE = 0x8
};

enum genz_secondary_media_cap_1_control_secondary_se_overwrite_media_count {
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_SE_OVERWRITE_MEDIA_COUNT_1 = 0x0,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_SE_OVERWRITE_MEDIA_COUNT_8 = 0x1,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_SE_OVERWRITE_MEDIA_COUNT_16 = 0x2,
    SECONDARY_MEDIA_CAP_1_CONTROL_SECONDARY_SE_OVERWRITE_MEDIA_COUNT_32 = 0x3
};

enum genz_plog_size {
    PLOG_SIZE_ENTRIES_16 = 0x0,
    PLOG_SIZE_ENTRIES_64 = 0x1,
    PLOG_SIZE_ENTRIES_128 = 0x2,
    PLOG_SIZE_ENTRIES_256 = 0x3,
    PLOG_SIZE_ENTRIES_512 = 0x4,
    PLOG_SIZE_ENTRIES_1024 = 0x5,
    PLOG_SIZE_ENTRIES_2048 = 0x6,
    PLOG_SIZE_ENTRIES_4096 = 0x7
};

enum genz_slog_size {
    SLOG_SIZE_ENTRIES_16 = 0x0,
    SLOG_SIZE_ENTRIES_64 = 0x1,
    SLOG_SIZE_ENTRIES_128 = 0x2,
    SLOG_SIZE_ENTRIES_256 = 0x3,
    SLOG_SIZE_ENTRIES_512 = 0x4,
    SLOG_SIZE_ENTRIES_1024 = 0x5,
    SLOG_SIZE_ENTRIES_2048 = 0x6,
    SLOG_SIZE_ENTRIES_4096 = 0x7
};

enum genz_switch_cap_1_ulat_scale {
    SWITCH_CAP_1_ULAT_SCALE_NS = 0x0,
    SWITCH_CAP_1_ULAT_SCALE_PS = 0x1
};

enum genz_switch_cap_1_mlat_scale {
    SWITCH_CAP_1_MLAT_SCALE_NS = 0x0,
    SWITCH_CAP_1_MLAT_SCALE_PS = 0x1
};

enum genz_cstat_status_statistics_reset {
    CSTAT_STATUS_STATISTICS_RESET_INCOMPLETE_NOT_INITIATED = 0x0,
    CSTAT_STATUS_STATISTICS_RESET_RESET_COMPLETED = 0x1
};

enum genz_cstat_status_snapshot_status {
    CSTAT_STATUS_SNAPSHOT_STATUS_INCOMPLETE_UNSUPPORTED = 0x0,
    CSTAT_STATUS_SNAPSHOT_STATUS_COMPLETED = 0x1
};

enum genz_st_type {
    ST_TYPE_CORE_64_OPCLASS = 0x0,
    ST_TYPE_CONTROL_OPCLASS = 0x1,
    ST_TYPE_ATOMIC_1_OPCLASS = 0x2,
    ST_TYPE_LDM_1_OPCLASS = 0x3,
    ST_TYPE_ADVANCED_1_OPCLASS = 0x4,
    ST_TYPE_ADVANCED_2_OPCLASS = 0x5,
    ST_TYPE_RESERVED_OPCLASS = -1,
    ST_TYPE_CTXID_OPCLASS = 0x15,
    ST_TYPE_MULTICAST_OPCLASS = 0x16,
    ST_TYPE_SOD_OPCLASS = 0x17,
    ST_TYPE_VENDOR_DEFINED_1_OPCLASS = 0x18,
    ST_TYPE_VENDOR_DEFINED_2_OPCLASS = 0x19,
    ST_TYPE_VENDOR_DEFINED_3_OPCLASS = 0x1A,
    ST_TYPE_VENDOR_DEFINED_4_OPCLASS = 0x1B,
    ST_TYPE_VENDOR_DEFINED_5_OPCLASS = 0x1C,
    ST_TYPE_VENDOR_DEFINED_6_OPCLASS = 0x1D,
    ST_TYPE_VENDOR_DEFINED_7_OPCLASS = 0x1E,
    ST_TYPE_VENDOR_DEFINED_8_OPCLASS = 0x1F,
    ST_TYPE_P2P_VENDOR_DEFINED_OPCLASS = 0x21,
    ST_TYPE_P2P_64 = 0x22,
    ST_TYPE_P2P_64_RESPONSE_VENDOR_DEFINED = 0x23,
    ST_TYPE_P2P_64_REQUEST_VENDOR_DEFINED = 0x24,
    ST_TYPE_P2P_64_ATOMICS_AND_CTLS = 0x25,
    ST_TYPE_DR_OPCLASS = 0x26,
    ST_TYPE_VENDOR_DEFINED_STATISTICS_STRUCTURE = -1
};

enum genz_mcast_cap_1_provisioned_egress_mask_bits {
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_2 = 0x0,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_4 = 0x1,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_8 = 0x2,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_12 = 0x3,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_16 = 0x4,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_20 = 0x5,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_24 = 0x6,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_32 = 0x7,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_48 = 0x8,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_64 = 0x9,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_128 = 0xA,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_256 = 0xB,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_512 = 0xC,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_1024 = 0xD,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_2048 = 0xE,
    MCAST_CAP_1_PROVISIONED_EGRESS_MASK_BITS_4096 = 0xF
};

enum genz_mcast_cap_1_reliable_multicast_role_support {
    MCAST_CAP_1_RELIABLE_MULTICAST_ROLE_SUPPORT_REQUESTER = 0x0,
    MCAST_CAP_1_RELIABLE_MULTICAST_ROLE_SUPPORT_RESPONDER = 0x1,
    MCAST_CAP_1_RELIABLE_MULTICAST_ROLE_SUPPORT_REQUESTER_RESPONDER = 0x2
};

enum genz_mcast_cap_1_control_if_reliable_multicast_is_supported_then_this_bit_determines_if_each_entry_in_the_responder_tracking_table_consists_of_a_responder_cid_or_a_responder_cid_plus_sid {
    MCAST_CAP_1_CONTROL_IF_RELIABLE_MULTICAST_IS_SUPPORTED_THEN_THIS_BIT_DETERMINES_IF_EACH_ENTRY_IN_THE_RESPONDER_TRACKING_TABLE_CONSISTS_OF_A_RESPONDER_CID_OR_A_RESPONDER_CID_PLUS_SID_RESPONDER_CID = 0x0,
    MCAST_CAP_1_CONTROL_IF_RELIABLE_MULTICAST_IS_SUPPORTED_THEN_THIS_BIT_DETERMINES_IF_EACH_ENTRY_IN_THE_RESPONDER_TRACKING_TABLE_CONSISTS_OF_A_RESPONDER_CID_OR_A_RESPONDER_CID_PLUS_SID_RESPONDER_CID_PLUS_SID = 0x1
};

enum genz_image_cap_1_read_only_image_location {
    IMAGE_CAP_1_READ_ONLY_IMAGE_LOCATION_IMAGE_LOCATION_HAS_READ_WRITE_ACCESS = 0x0,
    IMAGE_CAP_1_READ_ONLY_IMAGE_LOCATION_IMAGE_LOCATION_IS_READ_ONLY_ACCESS = 0x1
};

enum genz_image_uep {
    IMAGE_UEP_PM_UEP_MASK = 0x0,
    IMAGE_UEP_PFM_UEP_MASK = 0x1,
    IMAGE_UEP_SFM_UEP_MASK = 0x2,
    IMAGE_UEP_ERROR_UEP_MASK = 0x3,
    IMAGE_UEP_MEDIA_UEP_MASK = 0x4
};

enum genz_pt_cap_1_component_precision_time_granularity_unit {
    PT_CAP_1_COMPONENT_PRECISION_TIME_GRANULARITY_UNIT_NS_DEFAULT = 0x0,
    PT_CAP_1_COMPONENT_PRECISION_TIME_GRANULARITY_UNIT_PS = 0x1
};

enum genz_pt_ctl_precision_time_requester_enable {
    PT_CTL_PRECISION_TIME_REQUESTER_ENABLE_COMPONENT_SHALL_NOT_TRANSMIT_PTREQ = 0x0,
    PT_CTL_PRECISION_TIME_REQUESTER_ENABLE_COMPONENT_MAY_TRANSMIT_PTREQ_PACKETS = 0x1
};

enum genz_pt_ctl_precision_time_responder_enable {
    PT_CTL_PRECISION_TIME_RESPONDER_ENABLE_COMPONENT_SHALL_NOT_TRANSMIT_PTRSP = 0x0,
    PT_CTL_PRECISION_TIME_RESPONDER_ENABLE_COMPONENT_MAY_TRANSMIT_PTRSP_PACKETS = 0x1
};

enum genz_pt_ctl_precision_time_gtc_enable {
    PT_CTL_PRECISION_TIME_GTC_ENABLE_NON_GTC_COMPONENT = 0x0,
    PT_CTL_PRECISION_TIME_GTC_ENABLE_GTC_COMPONENT = 0x1
};

enum genz_pt_ctl_ptd_granularity_unit {
    PT_CTL_PTD_GRANULARITY_UNIT_NS_DEFAULT = 0x0,
    PT_CTL_PTD_GRANULARITY_UNIT_PS = 0x1
};

enum genz_pt_ctl_gtc_cid_location {
    PT_CTL_GTC_CID_LOCATION_CO_LOCATED_USE_GTC_CID = 0x0,
    PT_CTL_GTC_CID_LOCATION_NOT_CO_LOCATED_USE_GTC_CID_GTC_SID = 0x1
};

enum genz_mechanical_cap_1_mechanical_insertion_removal_support {
    MECHANICAL_CAP_1_MECHANICAL_INSERTION_REMOVAL_SUPPORT_UNSUPPORTED = 0x0,
    MECHANICAL_CAP_1_MECHANICAL_INSERTION_REMOVAL_SUPPORT_MANAGED_INSERTION_AND_REMOVAL = 0x1,
    MECHANICAL_CAP_1_MECHANICAL_INSERTION_REMOVAL_SUPPORT_ASYNCHRONOUS_INSERTION_AND_REMOVAL = 0x2,
    MECHANICAL_CAP_1_MECHANICAL_INSERTION_REMOVAL_SUPPORT_MANAGED_AND_ASYNCHRONOUS_INSERTION_AND_REMOVAL = 0x3
};

enum genz_mechanical_cap_1_mech_power_scale {
    MECHANICAL_CAP_1_MECH_POWER_SCALE_1_0 = 0x0,
    MECHANICAL_CAP_1_MECH_POWER_SCALE_0_1 = 0x1,
    MECHANICAL_CAP_1_MECH_POWER_SCALE_0_01 = 0x2,
    MECHANICAL_CAP_1_MECH_POWER_SCALE_0_001 = 0x3,
    MECHANICAL_CAP_1_MECH_POWER_SCALE_0_0001 = 0x4,
    MECHANICAL_CAP_1_MECH_POWER_SCALE_0_00001 = 0x5,
    MECHANICAL_CAP_1_MECH_POWER_SCALE_0_000001 = 0x6,
    MECHANICAL_CAP_1_MECH_POWER_SCALE_0_0000001 = 0x7
};

enum genz_mechanical_cap_1_module_indicator_interpretation {
    MECHANICAL_CAP_1_MODULE_INDICATOR_INTERPRETATION_COMPONENTS_BASE_CLASS = 0x0,
    MECHANICAL_CAP_1_MODULE_INDICATOR_INTERPRETATION_COMPONENTS_C_UUID = 0x1,
    MECHANICAL_CAP_1_MODULE_INDICATOR_INTERPRETATION_VENDOR_DEFINED_STRUCTURE_SEE_MECH_VENDOR_DEF_PTR = 0x2
};

enum genz_mechanical_control_attention_indicator_control {
    MECHANICAL_CONTROL_ATTENTION_INDICATOR_CONTROL_ON = 0x1,
    MECHANICAL_CONTROL_ATTENTION_INDICATOR_CONTROL_BLINK = 0x2,
    MECHANICAL_CONTROL_ATTENTION_INDICATOR_CONTROL_OFF = 0x3
};

enum genz_mechanical_control_main_power_controller_disable {
    MECHANICAL_CONTROL_MAIN_POWER_CONTROLLER_DISABLE_ENABLE_MAIN_POWER_TO_THE_COMPONENTS_MECHANICAL_MODULE_DEFAULT = 0x0,
    MECHANICAL_CONTROL_MAIN_POWER_CONTROLLER_DISABLE_DISABLE_MAIN_POWER_TO_THE_COMPONENTS_MECHANICAL_MODULE = 0x1
};

enum genz_mechanical_control_power_indicator_control {
    MECHANICAL_CONTROL_POWER_INDICATOR_CONTROL_ON = 0x1,
    MECHANICAL_CONTROL_POWER_INDICATOR_CONTROL_BLINK = 0x2,
    MECHANICAL_CONTROL_POWER_INDICATOR_CONTROL_OFF = 0x3
};

enum genz_mechanical_control_activity_indicator_control {
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_MODULE_PRESENT = 0x0,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_LOCATE = 0x1,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_MODULE_FAILURE = 0x2,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_MODULE_INDICATOR_NOTIFICATION_1 = 0x3,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_MODULE_INDICATOR_NOTIFICATION_2 = 0x4,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_MODULE_INDICATOR_NOTIFICATION_3 = 0x5,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_MODULE_INDICATOR_NOTIFICATION_4 = 0x6,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_MODULE_INDICATOR_NOTIFICATION_5 = 0x7,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_MODULE_INDICATOR_NOTIFICATION_6 = 0x8,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_MODULE_INDICATOR_NOTIFICATION_7 = 0x9,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_VENDOR_DEFINED_NOTIFICATION_1 = 0xA,
    MECHANICAL_CONTROL_ACTIVITY_INDICATOR_CONTROL_VENDOR_DEFINED_NOTIFICATION_2 = 0xB
};

enum genz_mechanical_control_auxiliary_power_disable {
    MECHANICAL_CONTROL_AUXILIARY_POWER_DISABLE_ENABLE_AUXILIARY_POWER_TO_THE_COMPONENTS_MECHANICAL_MODULE_DEFAULT = 0x0,
    MECHANICAL_CONTROL_AUXILIARY_POWER_DISABLE_DISABLE_AUXILIARY_POWER_TO_THE_COMPONENTS_MECHANICAL_MODULE = 0x1
};

enum genz_destination_table_control_rit_ssdt_enable {
    DESTINATION_TABLE_CONTROL_RIT_SSDT_ENABLE_DISABLED_SHALL_USE_ONLY_RIT = 0x0,
    DESTINATION_TABLE_CONTROL_RIT_SSDT_ENABLE_ENABLED_SHALL_USE_SSDT_MSDT_AND_RIT = 0x1
};

enum genz_req_p2p_control_opclass_enable {
    REQ_P2P_CONTROL_OPCLASS_ENABLE_P2P_64 = 0x0,
    REQ_P2P_CONTROL_OPCLASS_ENABLE_P2P_VENDOR_DEFINED = 0x12
};

enum genz_req_p2p_control_primary_media_volatility {
    REQ_P2P_CONTROL_PRIMARY_MEDIA_VOLATILITY_VOLATILE_MEDIA = 0x0,
    REQ_P2P_CONTROL_PRIMARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_REQUEST_PU_1B_TO_ENSURE_PERSISTENCY = 0x1,
    REQ_P2P_CONTROL_PRIMARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_PERSISTENT_FLUSH_TO_ENSURE_PERSISTENCY = 0x2,
    REQ_P2P_CONTROL_PRIMARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_REQUEST_PU_1B_OR_PERSISTENT_FLUSH_TO_ENSURE_PERSISTENCY = 0x3
};

enum genz_req_p2p_control_secondary_media_volatility {
    REQ_P2P_CONTROL_SECONDARY_MEDIA_VOLATILITY_VOLATILE_MEDIA = 0x0,
    REQ_P2P_CONTROL_SECONDARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_REQUEST_PU_1B_TO_ENSURE_PERSISTENCY = 0x1,
    REQ_P2P_CONTROL_SECONDARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_PERSISTENT_FLUSH_TO_ENSURE_PERSISTENCY = 0x2,
    REQ_P2P_CONTROL_SECONDARY_MEDIA_VOLATILITY_PERSISTENT_MEDIA_REQUEST_PU_1B_OR_PERSISTENT_FLUSH_TO_ENSURE_PERSISTENCY = 0x3
};

enum genz_pa_cap_1_pa_index_field_size {
    PA_CAP_1_PA_INDEX_FIELD_SIZE_BITS_0 = 0x0,
    PA_CAP_1_PA_INDEX_FIELD_SIZE_BITS_8 = 0x1,
    PA_CAP_1_PA_INDEX_FIELD_SIZE_BITS_16 = 0x2
};

enum genz_pa_cap_1_wildcard_akey_support {
    PA_CAP_1_WILDCARD_AKEY_SUPPORT_AKEY = 0x0,
    PA_CAP_1_WILDCARD_AKEY_SUPPORT_WILDCARD = 0x1
};

enum genz_pa_cap_1_wildcard_peer_attr_support {
    PA_CAP_1_WILDCARD_PEER_ATTR_SUPPORT_PA_TABLE = 0x0,
    PA_CAP_1_WILDCARD_PEER_ATTR_SUPPORT_WILDCARD = 0x1
};

enum genz_pa_cap_1_wildcard_acreq_support {
    PA_CAP_1_WILDCARD_ACREQ_SUPPORT_ACREQ = 0x0,
    PA_CAP_1_WILDCARD_ACREQ_SUPPORT_W_ACREQ = 0x1
};

enum genz_pa_cap_1_wildcard_acrsp_support {
    PA_CAP_1_WILDCARD_ACRSP_SUPPORT_ACRSP = 0x0,
    PA_CAP_1_WILDCARD_ACRSP_SUPPORT_W_ACRSP = 0x1
};

enum genz_w_acreq {
    W_ACREQ_NO_ACCESS = 0x0,
    W_ACREQ_R_KEY_ENABLED = 0x1,
    W_ACREQ_FULL_ACCESS_TRUSTED_RESPONDER = 0x3
};

enum genz_w_acrsp {
    W_ACRSP_NO_ACCESS = 0x0,
    W_ACRSP_R_KEY_ENABLED = 0x1,
    W_ACRSP_FULL_ACCESS_TRUSTED_REQUESTER = 0x3
};

enum genz_event_signal_63_0 {
    EVENT_SIGNAL_63_0_NO_SIGNAL_ACTION_IS_TAKEN = 0x0,
    EVENT_SIGNAL_63_0_TRIGGER_COMPONENT_LOCAL_INTERRUPT_0 = 0x1,
    EVENT_SIGNAL_63_0_TRIGGER_COMPONENT_LOCAL_INTERRUPT_1 = 0x2,
    EVENT_SIGNAL_63_0_TRIGGER_COMPONENT_LOCAL_INTERRUPT_2 = 0x3
};

enum genz_event_signal_511_448 {
    EVENT_SIGNAL_511_448_NO_SIGNAL_ACTION_IS_TAKEN = 0x0,
    EVENT_SIGNAL_511_448_TRIGGER_COMPONENT_LOCAL_INTERRUPT_0 = 0x1,
    EVENT_SIGNAL_511_448_TRIGGER_COMPONENT_LOCAL_INTERRUPT_1 = 0x2,
    EVENT_SIGNAL_511_448_TRIGGER_COMPONENT_LOCAL_INTERRUPT_2 = 0x3
};

enum genz_f_ctl_sub_0_interrupt_r_key_enable {
    F_CTL_SUB_0_INTERRUPT_R_KEY_ENABLE_NO_R_KEY_PRESENT = 0x0,
    F_CTL_SUB_0_INTERRUPT_R_KEY_ENABLE_R_KEY_PRESENT = 0x1
};

enum genz_congestion_cap_1_control_congestion_management_control {
    CONGESTION_CAP_1_CONTROL_CONGESTION_MANAGEMENT_CONTROL_COMPONENT = 0x0,
    CONGESTION_CAP_1_CONTROL_CONGESTION_MANAGEMENT_CONTROL_RESOURCE = 0x1,
    CONGESTION_CAP_1_CONTROL_CONGESTION_MANAGEMENT_CONTROL_VENDOR_DEFINED = 0x2
};

enum genz_congestion_cap_1_control_strict_increment_mode_control {
    CONGESTION_CAP_1_CONTROL_STRICT_INCREMENT_MODE_CONTROL_VENDOR_DEFINED = 0x0,
    CONGESTION_CAP_1_CONTROL_STRICT_INCREMENT_MODE_CONTROL_STRICT_BY_1_ADJUSTMENT = 0x1
};

enum genz_resource_type {
    RESOURCE_TYPE_INTERFACE_ID = 0x0,
    RESOURCE_TYPE_INTERFACE_ID_AND_VC = 0x1,
    RESOURCE_TYPE_PROTOCOL_ENGINE_ID = 0x2,
    RESOURCE_TYPE_RESOURCE_GROUP_ID = 0x3,
    RESOURCE_TYPE_TRAFFIC_CLASS_TC = 0x4
};

enum genz_pm_cap_1_performance_marker_support {
    PM_CAP_1_PERFORMANCE_MARKER_SUPPORT_UNSUPPORTED = 0x0,
    PM_CAP_1_PERFORMANCE_MARKER_SUPPORT_GENERATES_PERFORMANCE_LOG_RECORD_TYPE_0 = 0x1,
    PM_CAP_1_PERFORMANCE_MARKER_SUPPORT_GENERATES_PERFORMANCE_LOG_RECORD_TYPES_1 = 0x2
};

enum genz_atp_cap_1_pasid_support {
    ATP_CAP_1_PASID_SUPPORT_PASID_RESERVED = 0x0,
    ATP_CAP_1_PASID_SUPPORT_PASID_VALUE = 0x1
};

enum genz_atp_cap_1_prg_rspn_pasid_required {
    ATP_CAP_1_PRG_RSPN_PASID_REQUIRED_PASID_IGNORED = 0x0,
    ATP_CAP_1_PRG_RSPN_PASID_REQUIRED_PASID_REQUIRED = 0x1
};

enum genz_atp_cap_1_control_address_translation_cache_enable {
    ATP_CAP_1_CONTROL_ADDRESS_TRANSLATION_CACHE_ENABLE_SHALL_NOT_CACHE = 0x0,
    ATP_CAP_1_CONTROL_ADDRESS_TRANSLATION_CACHE_ENABLE_MAY_CACHE = 0x1
};

enum genz_lph_ctl_interrupt_r_key_enable {
    LPH_CTL_INTERRUPT_R_KEY_ENABLE_NO_R_KEY_PRESENT = 0x0,
    LPH_CTL_INTERRUPT_R_KEY_ENABLE_R_KEY_PRESENT = 0x1
};

enum genz_pg_zmmu_cap_1_zmmu_type {
    PG_ZMMU_CAP_1_ZMMU_TYPE_REQUESTER_ZMMU = 0x0,
    PG_ZMMU_CAP_1_ZMMU_TYPE_RESPONDER_ZMMU = 0x1
};

enum genz_zmmu_supported_page_sizes {
    ZMMU_SUPPORTED_PAGE_SIZES_UNSUPPORTED_PAGE_SIZE = 0x0,
    ZMMU_SUPPORTED_PAGE_SIZES_SUPPORTED_PAGE_SIZE = 0x1
};

enum genz_pt_zmmu_cap_1_zmmu_type {
    PT_ZMMU_CAP_1_ZMMU_TYPE_REQUESTER_ZMMU = 0x0,
    PT_ZMMU_CAP_1_ZMMU_TYPE_RESPONDER_ZMMU = 0x1
};

enum genz_supported_page_sizes {
    SUPPORTED_PAGE_SIZES_UNSUPPORTED_PAGE_SIZE = 0x0,
    SUPPORTED_PAGE_SIZES_SUPPORTED_PAGE_SIZE = 0x1
};

enum genz_interleave_cap_1_requester_interleave_granule_size_support {
    INTERLEAVE_CAP_1_REQUESTER_INTERLEAVE_GRANULE_SIZE_SUPPORT_BYTE_4096 = 0x0,
    INTERLEAVE_CAP_1_REQUESTER_INTERLEAVE_GRANULE_SIZE_SUPPORT_BYTE_AND_256_BYTE_4096 = 0x1,
    INTERLEAVE_CAP_1_REQUESTER_INTERLEAVE_GRANULE_SIZE_SUPPORT_BYTE_256_BYTE_AND_64_BYTE_4096 = 0x2
};

enum genz_fw_uep {
    FW_UEP_PM_UEP_MASK = 0x0,
    FW_UEP_PFM_UEP_MASK = 0x1,
    FW_UEP_SFM_UEP_MASK = 0x2,
    FW_UEP_ERROR_UEP_MASK = 0x3
};

enum genz_swm_optype {
    SWM_OPTYPE_NULL_OPERATION_NO_ACTION_TO_TAKE = 0x0,
    SWM_OPTYPE_WRITE_SINGLE_BLOCK = 0x1,
    SWM_OPTYPE_WRITE_MULTI_BLOCK = 0x2,
    SWM_OPTYPE_WRITE_LAST_MULTI_BLOCK = 0x3,
    SWM_OPTYPE_VENDOR_DEFINED = -1
};

enum genz_swm_error {
    SWM_ERROR_NO_ERROR = 0x0,
    SWM_ERROR_UNSUPPORTED_OPERATION = 0x1,
    SWM_ERROR_MALFORMED_OPERATION = 0x2,
    SWM_ERROR_ACCESS_PERMISSION = 0x3,
    SWM_ERROR_OPERATION_TIMED_OUT = 0x4
};

enum genz_swm_cs {
    SWM_CS_NOT_CONFIGURED = 0x0,
    SWM_CS_SWM_CID = 0x1,
    SWM_CS_SWM_CID_SID = 0x2
};

enum genz_component_backup_cap_1_max_backup_retry_support {
    COMPONENT_BACKUP_CAP_1_MAX_BACKUP_RETRY_SUPPORT_BACKUP_RETRY_UNSUPPORTED = 0x0,
    COMPONENT_BACKUP_CAP_1_MAX_BACKUP_RETRY_SUPPORT_ONE_RETRY = 0x1,
    COMPONENT_BACKUP_CAP_1_MAX_BACKUP_RETRY_SUPPORT_TWO_RETRIES = 0x2,
    COMPONENT_BACKUP_CAP_1_MAX_BACKUP_RETRY_SUPPORT_THREE_RETRIES = 0x3
};

enum genz_component_backup_cap_1_max_restore_retry_support {
    COMPONENT_BACKUP_CAP_1_MAX_RESTORE_RETRY_SUPPORT_RESTORE_RETRY_UNSUPPORTED = 0x0,
    COMPONENT_BACKUP_CAP_1_MAX_RESTORE_RETRY_SUPPORT_ONE_RETRY = 0x1,
    COMPONENT_BACKUP_CAP_1_MAX_RESTORE_RETRY_SUPPORT_TWO_RETRIES = 0x2,
    COMPONENT_BACKUP_CAP_1_MAX_RESTORE_RETRY_SUPPORT_THREE_RETRIES = 0x3
};

enum genz_component_backup_cap_1_max_erase_retry_support {
    COMPONENT_BACKUP_CAP_1_MAX_ERASE_RETRY_SUPPORT_ERASE_RETRY_UNSUPPORTED = 0x0,
    COMPONENT_BACKUP_CAP_1_MAX_ERASE_RETRY_SUPPORT_ONE_RETRY = 0x1,
    COMPONENT_BACKUP_CAP_1_MAX_ERASE_RETRY_SUPPORT_TWO_RETRIES = 0x2,
    COMPONENT_BACKUP_CAP_1_MAX_ERASE_RETRY_SUPPORT_THREE_RETRIES = 0x3
};

enum genz_component_backup_control_1_wait_for_backup_power {
    COMPONENT_BACKUP_CONTROL_1_WAIT_FOR_BACKUP_POWER_WAIT = 0x0,
    COMPONENT_BACKUP_CONTROL_1_WAIT_FOR_BACKUP_POWER_DO_NOT_WAIT = 0x1
};

enum genz_component_backup_control_1_tps_state {
    COMPONENT_BACKUP_CONTROL_1_TPS_STATE_TPS_NOT_PRESENT_NOT_CHARGED = 0x0,
    COMPONENT_BACKUP_CONTROL_1_TPS_STATE_TPS_OPERATIONAL_CHARGED = 0x1
};

enum genz_component_backup_control_1_lps_tps_enable {
    COMPONENT_BACKUP_CONTROL_1_LPS_TPS_ENABLE_TPS = 0x0,
    COMPONENT_BACKUP_CONTROL_1_LPS_TPS_ENABLE_LPS = 0x1
};

enum genz_l_ac_sub_0 {
    L_AC_SUB_0_TRUSTED_RW_UNTRUSTED_RW = 0x0,
    L_AC_SUB_0_TRUSTED_RO_ACCESS = 0x1,
    L_AC_SUB_0_TRUSTED_RO_UNTRUSTED_RO = 0x2,
    L_AC_SUB_0_TRUSTED_RW_UNTRUSTED_RO = 0x3,
    L_AC_SUB_0_TRUSTED_RW_ACCESS = 0x4,
    L_AC_SUB_0_NO_ACCESS = 0x7
};

enum genz_p2p_ac_sub_0 {
    P2P_AC_SUB_0_TRUSTED_RW_UNTRUSTED_RW = 0x0,
    P2P_AC_SUB_0_TRUSTED_RO_ACCESS = 0x1,
    P2P_AC_SUB_0_TRUSTED_RO_UNTRUSTED_RO = 0x2,
    P2P_AC_SUB_0_TRUSTED_RW_UNTRUSTED_RO = 0x3,
    P2P_AC_SUB_0_TRUSTED_RW_ACCESS = 0x4,
    P2P_AC_SUB_0_NO_ACCESS = 0x7
};

enum genz_log_type {
    LOG_TYPE_FREE_ENTRY_FOR_EACH_LOG_ENTRY = 0x0,
    LOG_TYPE_COMPONENT = 0x1,
    LOG_TYPE_COMPONENT_FAULT_INJECTION = 0x2,
    LOG_TYPE_INTERFACE = 0x3,
    LOG_TYPE_INTERFACE_FAULT_INJECTION = 0x5,
    LOG_TYPE_COMPONENT_INTERNAL_ERROR = 0x6,
    LOG_TYPE_VENDOR_DEFINED = 0xF
};

enum genz_a {
    A_AVAILABLE = 0x0,
    A_UNAVAILABLE = 0x1
};

enum genz_image_ctl_sub_0_image_address_space_location {
    IMAGE_CTL_SUB_0_IMAGE_ADDRESS_SPACE_LOCATION_CONTROL_SPACE = 0x0,
    IMAGE_CTL_SUB_0_IMAGE_ADDRESS_SPACE_LOCATION_DATA_SPACE = 0x1
};

enum genz_root_cause {
    ROOT_CAUSE_NO_ADDITIONAL_INFORMATION = 0x0,
    ROOT_CAUSE_NON_TRANSIENT_LINK_PROTOCOL_ERROR = 0x1,
    ROOT_CAUSE_L_DOWN_TRANSITION_HARDWARE_FAILURE = 0x2,
    ROOT_CAUSE_L_DOWN_TRANSITION_BUFFER_OVERFLOW = 0x3,
    ROOT_CAUSE_L_DOWN_TRANSITION_ES_VENDOR_DEFINED = 0x4,
    ROOT_CAUSE_PACKET_FILTERING_CONTROL_OPCLASS_VIOLATION = 0x5,
    ROOT_CAUSE_PACKET_FILTERING_INVALID_CID_AND_OR_SID = 0x6,
    ROOT_CAUSE_PEER_NONCE_MISMATCH = 0x7,
    ROOT_CAUSE_INVALID_DIRECTED_CONTROL_SPACE_PACKET_RELAY_MANAGER = 0x8,
    ROOT_CAUSE_INTERFACE_AE_ES_VENDOR_DEFINED = 0x9,
    ROOT_CAUSE_INTERFACE_AE_INGRESS_DR_ENABLE_ZERO = 0xA,
    ROOT_CAUSE_SWITCH_PACKET_RELAY_FAILURE_UP_ERROR = 0xB,
    ROOT_CAUSE_SWITCH_PACKET_RELAY_FAILURE_INVALID_DR_INTERFACE = 0xC,
    ROOT_CAUSE_SWITCH_PACKET_RELAY_FAILURE_ES_VENDOR_DEFINED = 0xD
};

enum genz_v_sub_0 {
    V_SUB_0_INVALID_ROUTE_ENTRY_NOT_CONFIGURED = 0x0,
    V_SUB_0_VALID_ROUTE_ENTRY_CONFIGURED = 0x1
};

enum genz_v_sub_1 {
    V_SUB_1_INVALID_ROUTE_ENTRY_NOT_CONFIGURED = 0x0,
    V_SUB_1_VALID_ROUTE_ENTRY_CONFIGURED = 0x1
};

enum genz_peer_attr_sub_0_latency_domain {
    PEER_ATTR_SUB_0_LATENCY_DOMAIN_LOW_LATENCY_DOMAIN = 0x0,
    PEER_ATTR_SUB_0_LATENCY_DOMAIN_NON_LOW_LATENCY_DOMAIN = 0x1
};

enum genz_pm_backup_status_sub_0_arm_status {
    PM_BACKUP_STATUS_SUB_0_ARM_STATUS_DISARMED = 0x0,
    PM_BACKUP_STATUS_SUB_0_ARM_STATUS_ARMED = 0x1
};

enum genz_pm_backup_control_sub_0_discrete_valid {
    PM_BACKUP_CONTROL_SUB_0_DISCRETE_VALID_CO_LOCATED_PRIMARY_AND_SECONDARY_MEDIA = 0x0,
    PM_BACKUP_CONTROL_SUB_0_DISCRETE_VALID_P2P_IFACE_CONFIGURED_FOR_USE = 0x1,
    PM_BACKUP_CONTROL_SUB_0_DISCRETE_VALID_SM_CID_CONFIGURED_FOR_USE = 0x2,
    PM_BACKUP_CONTROL_SUB_0_DISCRETE_VALID_SM_CID_AND_SM_SID_CONFIGURED_FOR_USE = 0x3
};

enum genz_res {
    RES_NO_ADDITIONAL_ACCESS_CONTROL = 0x0,
    RES_RESTRICTED_ACCESS = 0x1
};

enum genz_v {
    V_INVALID_ALL_OTHER_PTE_BITS_SHALL_BE_IGNORED = 0x0,
    V_VALID = 0x1
};

enum genz_et {
    ET_POINTER_PAIR = 0x0,
    ET_PTE = 0x1
};

enum genz_pt_sub_0 {
    PT_SUB_0_INVALID_POINTER = 0x0,
    PT_SUB_0_POINTS_TO_NEXT_LEVEL_TABLE_USED_ONLY_IN_FIRST_AND_SECOND_LEVEL_TABLES = 0x1,
    PT_SUB_0_POINTS_TO_A_4096_ENTRY_TABLE_OF_PTES_DESCRIBING_4_KIB_PAGES_POINTER_18_11_SHALL_BE_0X0_USED_ONLY_IN_THIRD_LEVEL_TABLES = 0x2,
    PT_SUB_0_POINTS_TO_A_256_ENTRY_TABLE_OF_PTES_DESCRIBING_64_KIB_PAGES_POINTER_14_11_SHALL_BE_0X0_USED_ONLY_IN_THIRD_LEVEL_TABLES = 0x3,
    PT_SUB_0_POINTS_TO_A_16_ENTRY_TABLE_OF_PTES_DESCRIBING_1_MIB_PAGES_USED_ONLY_IN_THIRD_LEVEL_TABLES = 0x4
};

enum genz_pt_sub_1 {
    PT_SUB_1_INVALID_POINTER = 0x0,
    PT_SUB_1_POINTS_TO_NEXT_LEVEL_TABLE_USED_ONLY_IN_FIRST_AND_SECOND_LEVEL_TABLES = 0x1,
    PT_SUB_1_POINTS_TO_A_4096_ENTRY_TABLE_OF_PTES_DESCRIBING_4_KIB_PAGES_POINTER_18_11_SHALL_BE_0X0_USED_ONLY_IN_THIRD_LEVEL_TABLES = 0x2,
    PT_SUB_1_POINTS_TO_A_256_ENTRY_TABLE_OF_PTES_DESCRIBING_64_KIB_PAGES_POINTER_14_11_SHALL_BE_0X0_USED_ONLY_IN_THIRD_LEVEL_TABLES = 0x3,
    PT_SUB_1_POINTS_TO_A_16_ENTRY_TABLE_OF_PTES_DESCRIBING_1_MIB_PAGES_USED_ONLY_IN_THIRD_LEVEL_TABLES = 0x4
};

enum genz_scv_sub_0 {
    SCV_SUB_0_INVALID_CID_AND_INVALID_SID = 0x0,
    SCV_SUB_0_VALID_CID_AND_INVALID_SID = 0x1,
    SCV_SUB_0_VALID_CID_AND_VALID_SID = 0x2
};

enum genz_sm_backup_control_sub_0_discrete_valid {
    SM_BACKUP_CONTROL_SUB_0_DISCRETE_VALID_CO_LOCATED_PRIMARY_AND_SECONDARY_MEDIA = 0x0,
    SM_BACKUP_CONTROL_SUB_0_DISCRETE_VALID_P2P_IFACE_CONFIGURED_FOR_USE = 0x1,
    SM_BACKUP_CONTROL_SUB_0_DISCRETE_VALID_PM_CID_CONFIGURED_FOR_USE = 0x2,
    SM_BACKUP_CONTROL_SUB_0_DISCRETE_VALID_PM_CID_AND_PM_SID_CONFIGURED_FOR_USE = 0x3
};

enum genz_m {
    M_MULTI_MODULE = 0x0,
    M_INTRA_MODULE = 0x1
};

enum genz_hardware_types {
    GENZ_RESERVED_SHALL_NOT_BE_USED = 0,
    GENZ_MEMORY = 1,
    GENZ_SWITCH = 2,
    GENZ_PROCESSOR = 3,
    GENZ_ACCELERATOR = 4,
    GENZ_IO = 5,
    GENZ_BLOCK_STORAGE = 6,
    GENZ_TRANSPARENT_ROUTER = 7,
    GENZ_MULTICLASS_COMPONENT = 8,
    GENZ_BRIDGE = 9,
    GENZ_COMPLIANCE_TEST_BOARD = 10,
    GENZ_LOGICAL_PCIE_HIERARCHY = 11,
    GENZ_NUM_HARDWARE_TYPES
};

struct genz_component_rkd_structure_array{
    uint64_t rkd_authorization_63_0 : 64;
};

struct genz_component_lpd_structure_array{
    uint64_t f_ctl_sub_0             : 16;
    uint64_t bdf_table_index_sub_0   : 6;
    uint64_t r3                      : 2;
    uint64_t lpd_df_number_sub_0     : 8;
    uint64_t function_ptr_sub_0      : 32;
    uint64_t function_ro_r_key_sub_0 : 32;
    uint64_t function_rw_r_key_sub_0 : 32;
};

struct genz_component_event_structure_array{
    uint64_t event_signal_63_0 : 64;
};

struct genz_service_uuid_structure_array{
    uint64_t class_sub_0  : 16;
    uint64_t max_si_sub_0 : 16;
    uint64_t class_sub_1  : 16;
    uint64_t max_si_sub_1 : 16;
};

struct genz_vendor_defined_with_uuid_structure_array{
    uint64_t vendor_defined_data_sub_2 : 64;
};

struct genz_vendor_defined_structure_array{
    uint32_t vendor_defined_data_sub_0 : 32;
};

struct genz_interface_statistics_structure_array{
    uint64_t total_transmitted_packets_vc_sub_0 : 64;
    uint64_t total_transmitted_bytes_vc_sub_0   : 64;
    uint64_t total_received_packets_vc_sub_0    : 64;
    uint64_t total_received_bytes_vc_sub_0      : 64;
    uint64_t occupancy_vc_sub_0                 : 64;
};

struct genz_interface_phy_structure_array{
    uint64_t phy_specific_configuration_space_7_0 : 64;
};

struct genz_unreliable_multicast_table_array{
//    uint0_t u_pad_em_vc_v; //FIXME: 0 bits.
};

struct genz_type_1_interleave_table_array_array{
    uint64_t sid_sub_0 : 16;
    uint64_t cid_sub_0 : 12;
    uint64_t r3        : 4;
    uint64_t sid_sub_1 : 16;
    uint64_t cid_sub_1 : 12;
    uint64_t r4        : 4;
};

struct genz_type_1_interleave_table_array{
    uint64_t v                                                                            : 1;
    uint64_t m                                                                            : 1;
    uint64_t intlv_gran                                                                   : 2;
    uint64_t nb_responder_page                                                            : 6;
    uint64_t r0                                                                           : 2;
    uint64_t nb_intlv_lo_inc                                                              : 3;
    uint64_t r1                                                                           : 1;
    uint64_t max_way                                                                      : 16;
    uint64_t r2                                                                           : 32;
    struct genz_type_1_interleave_table_array_array type_1_interleave_table_array_array[];
};

struct genz_tr_table_array{
    uint64_t tr_zmmu_sub_0       : 32;
    uint64_t tr_rtr_sub_0        : 32;
    uint64_t tr_dt_sub_0         : 32;
    uint64_t tr_pa_sub_0         : 32;
    uint64_t tr_opcode_set_sub_0 : 32;
    uint64_t r0                  : 32;
    uint64_t tr_ctl_sub_0        : 16;
    uint64_t r1                  : 48;
    uint64_t tr_max_data_sub_0   : 64;
    uint64_t tr_rdlat_sub_0      : 16;
    uint64_t tr_wrlat_sub_0      : 16;
    uint64_t tr_wrplat_sub_0     : 16;
    uint64_t tr_rtrft_sub_0      : 16;
};

struct genz_service_uuid_table_array_array{
    uint64_t si_ds_base_sub_0   : 52;
    uint64_t r0                 : 12;
    uint64_t si_ds_length_sub_0 : 52;
    uint64_t r1                 : 12;
    uint64_t si_cs_base_sub_0   : 40;
    uint64_t r2                 : 4;
    uint64_t instance_id_sub_0  : 20;
    uint64_t si_cs_length_sub_0 : 40;
    uint64_t r3                 : 24;
};

struct genz_service_uuid_table_array{
    uuid_t service_uuid_0_63_0;
    uuid_t service_uuid_0_127_64;
    struct genz_service_uuid_table_array_array service_uuid_table_array_array[];
};

struct genz_ssdt_msdt_table_array_array{
    uint32_t mhc       : 6;
    uint32_t r0        : 2;
    uint64_t v_sub_0   : 1;
    uint32_t hc_sub_0  : 6;
    uint32_t vca_sub_0 : 5;
    uint32_t ei_sub_0  : 12;
};

struct genz_sm_backup_table_array{
    uint64_t sm_backup_status_sub_0  : 64;
    uint64_t sm_backup_control_sub_0 : 32;
    uint64_t sm_r_key_sub_0          : 32;
    uint64_t pm_image_address_sub_0  : 64;
    uint64_t sm_image_address_sub_0  : 64;
    uint64_t sm_image_length_sub_0   : 64;
    uint64_t p2p_iface_sub_0         : 4;
    uint64_t pm_cid_sub_0            : 12;
    uint64_t pm_sid_sub_0            : 16;
    uint64_t r1                      : 32;
};

struct genz_reliable_multicast_table_array{
//    uint0_t rsp_ptr_r_pad_em_mti_role_vc_v; //FIXME: 0 bits.
};

struct genz_reliable_multicast_responder_table_array{
    uint64_t scv_sub_0     : 2;
    uint32_t r0            : 2;
    uint32_t rsp_cid_sub_0 : 12;
    uint32_t rsp_sid_sub_0 : 16;
};

struct genz_rit_table_array{};

struct genz_re_table_array{
    uint64_t re_size : 16;
    uint64_t re_0    : 48;
};

struct genz_page_grid_restricted_page_grid_table_array{
    uint64_t r0                : 12;
    uint64_t pg_base_address_0 : 52;
    uint64_t page_size_0       : 7;
    uint64_t res               : 1;
    uint64_t page_count_0      : 24;
    uint64_t base_pte_index_0  : 32;
};

struct genz_pm_backup_table_array{
    uint64_t pm_backup_status_sub_0  : 64;
    uint64_t pm_backup_control_sub_0 : 32;
    uint64_t sm_r_key_sub_0          : 32;
    uint64_t pm_image_address_sub_0  : 64;
    uint64_t pm_image_length_sub_0   : 64;
    uint64_t sm_image_address_sub_0  : 64;
    uint64_t sm_image_length_sub_0   : 64;
    uint64_t p2p_iface_sub_0         : 4;
    uint64_t sm_cid_sub_0            : 12;
    uint64_t sm_sid_sub_0            : 16;
    uint64_t tc_sub_0                : 4;
    uint64_t r1                      : 28;
    uint64_t r2                      : 64;
};

struct genz_pa_table_array{
    uint16_t peer_attr_sub_0 : 16;
};

struct genz_oem_data_table_array{
    uint64_t oem_data_sub_0 : 64;
};

struct genz_media_log_table_array{
    uint64_t log_type  : 4;
    uint32_t r0        : 4;
    uint32_t log_event : 8;
    uint32_t ri        : 16;
    uint32_t ls_31_0   : 32;
    uint32_t ls_63_32  : 32;
    uint32_t ls_95_64  : 32;
};

struct genz_mvcat_table_array{
    uint32_t mvcm_sub_0 : 32;
};

struct genz_label_data_table_array{
    uint64_t label_data_sub_1 : 64;
};

struct genz_lprt_mprt_table_array_array{
    uint32_t mhc       : 6;
    uint32_t r0        : 2;
    uint64_t v_sub_0   : 1;
    uint32_t hc_sub_0  : 6;
    uint32_t vca_sub_0 : 5;
    uint32_t ei_sub_0  : 12;
};

struct genz_image_table_array{
    uuid_t image_uuid_sub_0;
    uint64_t image_ctl_sub_0     : 16;
    uint64_t image_status_sub_0  : 16;
    uint64_t r0                  : 32;
    uint64_t image_address_sub_0 : 64;
    uint64_t image_size_sub_0    : 64;
    uint64_t r1                  : 64;
};

struct genz_firmware_table_array{
    uuid_t fw_uuid_sub_0;
    uint64_t fw_ctl_sub_0                  : 16;
    uint64_t fw_status_sub_0               : 16;
    uint64_t fw_update_success_count_sub_0 : 16;
    uint64_t fw_update_failure_count_sub_0 : 16;
    uint64_t fw_immutable_address_sub_0    : 52;
    uint64_t r0                            : 12;
    uint64_t fw_immutable_length_sub_0     : 32;
    uint64_t fw_mutable_length_sub_0       : 32;
    uint64_t fw_mutable_address_sub_0      : 52;
    uint64_t r1                            : 12;
    uint64_t r2                            : 64;
};

struct genz_elog_table_array{
    uint64_t elog_sub_0 : 64;
};

struct genz_c_access_r_key_table_array{
    uint64_t c_access_ro_r_key_sub_0 : 32;
    uint64_t c_access_rw_r_key_sub_0 : 32;
};

struct genz_c_access_l_p2p_table_array{
    uint64_t l_ac_sub_0   : 3;
    uint64_t p2p_ac_sub_0 : 3;
    uint8_t r0            : 2;
};

struct genz_hardware_classes{
    const char * const raw_name;
    const char * const condensed_name;
    const enum genz_hardware_types value;
};

struct genz_core_structure{
    uint64_t type                                 : 12;
    uint64_t vers                                 : 4;
    uint64_t size                                 : 16;
    uint64_t r0                                   : 32;
    uint64_t c_status                             : 64;
    uint64_t c_control                            : 64;
    uint64_t base_c_class                         : 16;
    uint64_t max_interface                        : 12;
    uint64_t r_bist                               : 4;
    uint64_t rdlat                                : 16;
    uint64_t wrlat                                : 16;
    uint64_t max_rsp_supported_requests           : 20;
    uint64_t max_req_supported_requests           : 20;
    uint64_t c_op_clock                           : 24;
    uint64_t max_data                             : 64;
    uint64_t max_ctl                              : 52;
    uint64_t max_rnr                              : 3;
    uint64_t r1                                   : 9;
    uint64_t c_state_transition_latency           : 32;
    uint64_t c_idle_times                         : 16;
    uint64_t r2                                   : 16;
    uint64_t lpwr                                 : 10;
    uint64_t npwr                                 : 10;
    uint64_t hpwr                                 : 10;
    uint64_t epwr                                 : 10;
    uint64_t apwr                                 : 10;
    uint64_t r3                                   : 14;
    uint64_t control_structure_ptr_0              : 32;
    uint64_t control_structure_ptr_1              : 32;
    uint64_t control_structure_ptr_2              : 32;
    uint64_t control_structure_ptr_3              : 32;
    uint64_t control_structure_ptr_4              : 32;
    uint64_t control_structure_ptr_5              : 32;
    uint64_t control_structure_ptr_6              : 32;
    uint64_t control_structure_ptr_7              : 32;
    uint64_t control_structure_ptr_8              : 32;
    uint64_t core_lpd_bdf_table_ptr               : 32;
    uint64_t opcode_set_structure_ptr             : 32;
    uint64_t component_c_access_ptr               : 32;
    uint64_t component_destination_table_ptr      : 32;
    uint64_t interface_0_ptr                      : 32;
    uint64_t component_extension_ptr              : 32;
    uint64_t component_error_and_signal_event_ptr : 32;
    uint64_t llmuto                               : 16;
    uint64_t crpto                                : 16;
    uint64_t ccto                                 : 16;
    uint64_t failto                               : 16;
    uint64_t r4                                   : 48;
    uint64_t unrsp                                : 16;
    uint64_t uert                                 : 16;
    uint64_t nirt                                 : 16;
    uint64_t atsto                                : 16;
    uint64_t unreq                                : 16;
    uint64_t ll_request_deadline                  : 10;
    uint64_t nll_request_deadline                 : 10;
    uint64_t deadline_tick                        : 12;
    uint64_t fpst                                 : 16;
    uint64_t pco_fpst                             : 16;
    uint64_t ll_response_deadline                 : 10;
    uint64_t nll_response_deadline                : 10;
    uint64_t responder_deadline                   : 10;
    uint64_t r5                                   : 18;
    uint64_t sfmsid                               : 16;
    uint64_t pmcid                                : 12;
    uint64_t pwr_mgr_cid                          : 12;
    uint64_t pfmcid                               : 12;
    uint64_t pfmsid                               : 16;
    uint64_t sfmcid                               : 12;
    uint64_t sid_0                                : 16;
    uint64_t dr_request_deadline                  : 10;
    uint64_t r6                                   : 38;
    uint64_t cv                                   : 8;
    uint64_t cid_0                                : 12;
    uint64_t cid_1                                : 12;
    uint64_t cid_2                                : 12;
    uint64_t cid_3                                : 12;
    uint64_t r7                                   : 4;
    uint64_t buffer_tc                            : 4;
    uint64_t max_requests                         : 20;
    uint64_t r8                                   : 14;
    uint64_t pwr_mgr_sid                          : 16;
    uint64_t r9                                   : 14;
    uint64_t controlto                            : 16;
    uint64_t controldrto                          : 16;
    uint64_t nlmuto                               : 16;
    uint64_t nop_dest_cid                         : 12;
    uint64_t nop_dest_sid_1                       : 4; //NOTE: split bit
    uint64_t nop_dest_sid_2                       : 12; //NOTE: split bit
    uint64_t nop_src_cid                          : 12;
    uint64_t nop_src_sid                          : 16;
    uint64_t aec                                  : 4;
    uint64_t r10                                  : 20;
    uint64_t r11_1                                : 64; //NOTE: split bit
    uint64_t r11_2                                : 64; //NOTE: split bit
    uint64_t r12_1                                : 64; //NOTE: split bit
    uint64_t r12_2                                : 64; //NOTE: split bit
    uint64_t r13_1                                : 64; //NOTE: split bit
    uint64_t r13_2                                : 64; //NOTE: split bit
    uint64_t r14_1                                : 64; //NOTE: split bit
    uint64_t r14_2                                : 64; //NOTE: split bit
    uint64_t r15_1                                : 64; //NOTE: split bit
    uint64_t r15_2                                : 64; //NOTE: split bit
    uint64_t control_structure_ptr_9              : 32;
    uint64_t control_structure_ptr_10             : 32;
    uint64_t control_structure_ptr_11             : 32;
    uint64_t control_structure_ptr_12             : 32;
    uint64_t control_structure_ptr_13             : 48;
    uint64_t control_structure_ptr_14_1           : 16; //NOTE: split bit
    uint64_t control_structure_ptr_14_2           : 32; //NOTE: split bit
    uint64_t control_structure_ptr_15             : 32;
    uint64_t component_cap_1                      : 64;
    uint64_t component_cap_1_control              : 64;
    uint64_t component_cap_2                      : 64;
    uint64_t component_cap_2_control              : 64;
    uint64_t component_cap_3                      : 64;
    uint64_t component_cap_3_control              : 64;
    uint64_t component_cap_4                      : 64;
    uint64_t component_cap_4_control              : 64;
    uint64_t r16_1                                : 64; //NOTE: split bit
    uint64_t r16_2                                : 20; //NOTE: split bit
    uint64_t uwmsgsz                              : 11;
    uint64_t wmsgsz                               : 11;
    uint64_t cwmsgsz                              : 11;
    uint64_t ucwmsgsz                             : 11;
    uint64_t cohlat                               : 16;
    uint64_t oooto                                : 16;
    uint64_t reqnirto                             : 16;
    uint64_t reqabnirto                           : 16;
    uint64_t component_nonce                      : 64;
    uuid_t mgr_uuid;
    uint64_t serial_number                        : 64;
    uint64_t thermal_attributes                   : 16;
    uint64_t upper_thermal_limit                  : 10;
    uint64_t caution_thermal_limit                : 10;
    uint64_t lowest_thermal_limit                 : 11;
    uint64_t current_thermal                      : 11;
    uint64_t r17                                  : 6;
    uuid_t z_uuid;
    uuid_t c_uuid;
    uuid_t fru_uuid;
};

struct genz_opcode_set_structure{
    uint64_t type                       : 12;
    uint64_t vers                       : 4;
    uint64_t size                       : 16;
    uint64_t opcode_set_cap_1_control   : 32;
    uint64_t opcode_set_cap_1           : 64;
    uint64_t cache_line_sizes           : 4;
    uint64_t r0                         : 4;
    uint64_t write_poison_sizes         : 8;
    uint64_t arithmetic_atomic_sizes    : 8;
    uint64_t logical_fetch_atomic_sizes : 8;
    uint64_t floating_atomic_sizes      : 8;
    uint64_t swap_compare_atomic_sizes  : 8;
    uint64_t atomic_lat                 : 16;
    uint64_t opcode_set_uuid_ptr        : 32;
    uint64_t opcode_set_ptr             : 32;
    uint64_t supported_un               : 16;
    uint64_t supported_fl               : 8;
    uint64_t vocl_1                     : 5;
    uint64_t vocl_2                     : 5;
    uint64_t vocl_3                     : 5;
    uint64_t vocl_4                     : 5;
    uint64_t vocl_5                     : 5;
    uint64_t vocl_6                     : 5;
    uint64_t vocl_7                     : 5;
    uint64_t vocl_8                     : 5;
    uint64_t r1                         : 64;
};

struct genz_interface_structure{
    uint64_t type                              : 12;
    uint64_t vers                              : 4;
    uint64_t size                              : 16;
    uint64_t interface_id                      : 12;
    uint64_t hvs                               : 5;
    uint64_t r0                                : 7;
    uint64_t phy_power_enable                  : 8;
    uint64_t i_status                          : 32;
    uint64_t i_control                         : 32;
    uint64_t i_cap_1                           : 32;
    uint64_t i_cap_1_control                   : 32;
    uint64_t i_cap_2                           : 32;
    uint64_t i_cap_2_control                   : 32;
    uint64_t i_error_status                    : 16;
    uint64_t i_error_detect                    : 16;
    uint64_t i_error_fault_injection           : 16;
    uint64_t i_error_trigger                   : 16;
    uint64_t i_signal_target                   : 48;
    uint64_t teth                              : 4;
    uint64_t tete                              : 4;
    uint64_t fc_fwd_progress                   : 8;
    uint64_t ll_tx_packet_alignment            : 8;
    uint64_t ll_rx_packet_alignment            : 8;
    uint64_t max_implicit_fc_credits           : 16;
    uint64_t peer_interface_id                 : 12;
    uint64_t r1                                : 4;
    uint64_t peer_base_c_class                 : 16;
    uint64_t peer_cid                          : 12;
    uint64_t r2                                : 4;
    uint64_t peer_sid                          : 16;
    uint64_t peer_state                        : 32;
    uint64_t path_propagation_time             : 16;
    uint64_t tr_index                          : 4;
    uint64_t tr_cid                            : 12;
    uint64_t vc_pco_enabled                    : 32;
    uint64_t ee_tx_packet_alignment            : 8;
    uint64_t ee_rx_packet_alignment            : 8;
    uint64_t ee_tx_min_packet_start            : 8;
    uint64_t ee_rx_min_packet_start            : 8;
    uint64_t hve                               : 5;
    uint64_t r3                                : 9;
    uint64_t ttc_unit                          : 2;
    uint64_t peer_component_ttc                : 16;
    uint64_t peer_nonce                        : 64;
    uint64_t aggregation_support               : 8;
    uint64_t c_lp_ctl                          : 4;
    uint64_t c_dlp_ctl                         : 4;
    uint64_t max_phy_retrain_events            : 8;
    uint64_t tx_llrt_ack                       : 20;
    uint64_t rx_llrt_ack                       : 20;
    uint64_t te_history_threshold              : 12;
    uint64_t r4                                : 20;
    uint64_t link_ctl_control                  : 32;
    uint64_t r5                                : 64;
    uint64_t next_interface_ptr                : 32;
    uint64_t r6                                : 32;
    uint64_t next_ai_ptr                       : 32;
    uint64_t next_ig_ptr                       : 32;
    uint64_t i_phy_ptr                         : 32;
    uint64_t i_stats_ptr                       : 32;
    uint64_t mechanical_ptr                    : 32;
    uint64_t vd_ptr                            : 32;
    uint64_t vcat_ptr                          : 32;
    uint64_t lprt_ptr                          : 32;
    uint64_t mprt_ptr                          : 32;
    uint64_t r7                                : 32;
    uint64_t interface_ingress_access_key_mask : 64;
    uint64_t interface_egress_access_key_mask  : 64;
};

struct genz_interface_phy_structure{
    uint64_t type                                                             : 12;
    uint64_t vers                                                             : 4;
    uint64_t size                                                             : 16;
    uint64_t phy_type                                                         : 8;
    uint64_t txdly                                                            : 4;
    uint64_t r0                                                               : 20;
    uint64_t next_interface_phy_ptr                                           : 32;
    uint64_t vd_ptr                                                           : 32;
    uint64_t phy_status                                                       : 32;
    uint64_t phy_control                                                      : 32;
    uint64_t phy_cap_1                                                        : 32;
    uint64_t phy_cap_1_control                                                : 32;
    uint64_t phy_events                                                       : 32;
    uint64_t r1                                                               : 32;
    uint64_t r2                                                               : 64;
    uint64_t phy_lane_status                                                  : 32;
    uint64_t phy_lane_control                                                 : 32;
    uint64_t phy_lane_cap                                                     : 32;
    uint64_t phy_remote_lane_cap                                              : 32;
    uint64_t phy_lp_cap                                                       : 32;
    uint64_t phy_lp_timing_cap                                                : 32;
    uint64_t phy_up_lp_cap                                                    : 32;
    uint64_t phy_up_lp_timing_cap                                             : 32;
    uint64_t phy_extended_status                                              : 32;
    uint64_t phy_extended_control                                             : 32;
    uint64_t phy_extended_cap                                                 : 32;
    uint64_t phy_remote_extended_cap                                          : 32;
    struct genz_interface_phy_structure_array interface_phy_structure_array[];
};

struct genz_interface_statistics_structure{
    uint64_t type                                                                           : 12;
    uint64_t vers                                                                           : 4;
    uint64_t size                                                                           : 16;
    uint64_t i_stat_cap_1                                                                   : 16;
    uint64_t i_stat_control                                                                 : 8;
    uint64_t i_stat_status                                                                  : 8;
    uint64_t vendor_defined_ptr                                                             : 32;
    uint64_t i_snapshot_ptr                                                                 : 32;
    uint64_t i_snapshot_interval                                                            : 64;
    uint64_t pcrc_errors                                                                    : 32;
    uint64_t ecrc_errors                                                                    : 32;
    uint64_t tx_stomped_ecrc                                                                : 32;
    uint64_t rx_stomped_ecrc                                                                : 32;
    uint64_t non_crc_transient_errors                                                       : 32;
    uint64_t llr_recovery                                                                   : 32;
    uint64_t packet_deadline_discards                                                       : 32;
    uint64_t marked_ecn                                                                     : 32;
    uint64_t received_ecn                                                                   : 32;
    uint64_t link_nte                                                                       : 16;
    uint64_t akey_violations                                                                : 16;
    uint64_t r0                                                                             : 64;
    uint64_t r1                                                                             : 64;
    uint64_t total_transmitted_requests                                                     : 64;
    uint64_t total_transmitted_request_bytes                                                : 64;
    uint64_t total_received_requests                                                        : 64;
    uint64_t total_received_request_bytes                                                   : 64;
    uint64_t total_transmitted_responses                                                    : 64;
    uint64_t total_transmitted_response_bytes                                               : 64;
    uint64_t total_received_responses                                                       : 64;
    uint64_t total_received_response_bytes                                                  : 64;
    struct genz_interface_statistics_structure_array interface_statistics_structure_array[];
};

struct genz_component_error_and_signal_event_structure{
    uint64_t type                          : 12;
    uint64_t vers                          : 4;
    uint64_t size                          : 16;
    uint64_t e_control                     : 16;
    uint64_t e_status                      : 16;
    uint64_t error_mgr_cid                 : 12;
    uint64_t error_mgr_sid                 : 16;
    uint64_t r0                            : 4;
    uint64_t error_signal_cap_1            : 16;
    uint64_t error_signal_cap_1_control    : 16;
    uint64_t event_mgr_cid                 : 12;
    uint64_t event_mgr_sid                 : 16;
    uint64_t r1                            : 4;
    uint64_t elog_ptr                      : 32;
    uint64_t signal_interrupt_address_0    : 64;
    uint64_t signal_interrupt_address_1    : 64;
    uint64_t signal_interrupt_data_0       : 32;
    uint64_t signal_interrupt_data_1       : 32;
    uint64_t c_error_status                : 64;
    uint64_t c_error_detect                : 64;
    uint64_t r2                            : 64;
    uint64_t c_error_trigger               : 64;
    uint64_t c_error_fault_injection       : 64;
    uint64_t c_error_signal_target_63_0    : 64;
    uint64_t c_error_signal_target_127_64  : 64;
    uint64_t c_error_signal_target_191_128 : 64;
    uint64_t c_event_detect                : 64;
    uint64_t c_event_injection             : 64;
    uint64_t c_event_signal_target_63_0    : 64;
    uint64_t c_event_signal_target_127_64  : 64;
    uint64_t c_event_signal_target_191_128 : 64;
    uint64_t i_event_detect                : 64;
    uint64_t i_event_injection             : 64;
    uint64_t i_event_signal_target_63_0    : 64;
    uint64_t i_event_signal_target_127_64  : 64;
    uint64_t i_event_signal_target_191_128 : 64;
    uint64_t mv_sub_0                      : 1;
    uint64_t mgmt_vc_sub_0                 : 5;
    uint64_t mgmt_interface_id_sub_0       : 12;
    uint64_t mv_sub_1                      : 1;
    uint64_t mgmt_vc_sub_1                 : 5;
    uint64_t mgmt_interface_id_sub_1       : 12;
    uint64_t mv_sub_2                      : 1;
    uint64_t mgmt_vc_sub_2                 : 5;
    uint64_t mgmt_interface_id_sub_2       : 12;
    uint64_t r3                            : 10;
    uint64_t mv_sub_3                      : 1;
    uint64_t mgmt_vc_sub_3                 : 5;
    uint64_t mgmt_interface_id_sub_3       : 12;
    uint64_t mv_sub_4                      : 1;
    uint64_t mgmt_vc_sub_4                 : 5;
    uint64_t mgmt_interface_id_sub_4       : 12;
    uint64_t mv_sub_5                      : 1;
    uint64_t mgmt_vc_sub_5                 : 5;
    uint64_t mgmt_interface_id_sub_5       : 12;
    uint64_t r4                            : 10;
    uint64_t mv_sub_6                      : 1;
    uint64_t mgmt_vc_sub_6                 : 5;
    uint64_t mgmt_interface_id_sub_6       : 12;
    uint64_t mv_sub_7                      : 1;
    uint64_t mgmt_vc_sub_7                 : 5;
    uint64_t mgmt_interface_id_sub_7       : 12;
    uint64_t r5                            : 28;
    uint64_t pm_uep_mask                   : 8;
    uint64_t pfm_uep_mask                  : 8;
    uint64_t sfm_uep_mask                  : 8;
    uint64_t error_uep_mask                : 8;
    uint64_t event_uep_mask                : 8;
    uint64_t media_uep_mask                : 8;
    uint64_t pwr_mgr_uep_mask              : 8;
    uint64_t mech_mgr_uep_mask             : 8;
    uint64_t mech_mgr_cid                  : 12;
    uint64_t mech_mgr_sid                  : 16;
    uint64_t r6                            : 4;
    uint64_t media_mgr_cid                 : 12;
    uint64_t media_mgr_sid                 : 16;
    uint64_t r7                            : 4;
    uint64_t r8                            : 64;
    uint64_t e_control_2                   : 32;
    uint64_t r9                            : 32;
    uint64_t c_event_status                : 64;
    uint64_t i_event_status                : 64;
    uint64_t r10                           : 64;
};

struct genz_component_media_structure{
    uint64_t type                                : 12;
    uint64_t vers                                : 4;
    uint64_t size                                : 16;
    uint64_t vendor_defined_ptr                  : 32;
    uint64_t component_media_control             : 32;
    uint64_t next_media_structure_ptr            : 32;
    uint64_t primary_media_status                : 64;
    uint64_t secondary_media_status              : 64;
    uint64_t primary_media_cap_1_63_0            : 64;
    uint64_t primary_media_cap_1_127_64          : 64;
    uint64_t secondary_media_cap_1_63_0          : 64;
    uint64_t secondary_media_cap_1_127_64        : 64;
    uint64_t primary_media_cap_1_control         : 64;
    uint64_t secondary_media_cap_1_control       : 64;
    uint64_t primary_media_fault_injection       : 64;
    uint64_t secondary_media_fault_injection     : 64;
    uint64_t pri_mlen                            : 8;
    uint64_t plog_size                           : 4;
    uint64_t primary_media_base_address          : 52;
    uint64_t sec_mlen                            : 8;
    uint64_t slog_size                           : 4;
    uint64_t secondary_media_base_address        : 52;
    uint64_t interface_id_mask                   : 16;
    uint64_t c_media_id                          : 4;
    uint64_t r0                                  : 12;
    uint64_t backup_mgmt_ptr                     : 32;
    uint64_t primary_namespace_ptr               : 32;
    uint64_t primary_sit_ptr                     : 32;
    uint64_t secondary_namespace_ptr             : 32;
    uint64_t secondary_sit_ptr                   : 32;
    uint64_t primary_log_ptr                     : 32;
    uint64_t secondary_log_ptr                   : 32;
    uint64_t oem_data_ptr                        : 32;
    uint64_t se_vendor_defined_ptr               : 32;
    uint64_t primary_label_data_ptr              : 32;
    uint64_t secondary_label_data_ptr            : 32;
    uint64_t primary_correctable_error_count     : 24;
    uint64_t primary_uncorrectable_error_count   : 24;
    uint64_t power_status                        : 16;
    uint64_t secondary_correctable_error_count   : 24;
    uint64_t secondary_uncorrectable_error_count : 24;
    uint64_t pflat                               : 16;
    uint64_t pri_r_wear_percentage               : 7;
    uint64_t pri_w_wear_percentage               : 7;
    uint64_t pri_notify_percentage               : 7;
    uint64_t sec_r_wear_percentage               : 7;
    uint64_t sec_w_wear_percentage               : 7;
    uint64_t sec_notify_percentage               : 7;
    uint64_t se_percentage                       : 7;
    uint64_t r1                                  : 15;
    uint64_t min_pri_maintenance_time            : 16;
    uint64_t min_sec_maintenance_time            : 16;
    uint64_t max_pri_maintenance_time            : 16;
    uint64_t max_sec_maintenance_time            : 16;
    uint64_t inform_pri_maintenance_time         : 16;
    uint64_t inform_sec_maintenance_time         : 16;
    uint64_t se_overwrite_pattern                : 32;
    uint64_t max_factory_default_time            : 16;
    uint64_t factory_default_duration            : 16;
    uint64_t factory_default_success_count       : 16;
    uint64_t factory_default_failure_count       : 16;
    uint64_t primary_region_address              : 64;
    uint64_t primary_region_length               : 64;
    uint64_t secondary_region_address            : 64;
    uint64_t secondary_region_length             : 64;
    uuid_t primary_media_uuid;
    uuid_t secondary_media_uuid;
    uint64_t r2                                  : 64;
    uint64_t r3                                  : 64;
};

struct genz_component_switch_structure{
    uint64_t type                                : 12;
    uint64_t vers                                : 4;
    uint64_t size                                : 16;
    uint64_t switch_cap_1                        : 32;
    uint64_t switch_cap_1_control                : 32;
    uint64_t switch_status                       : 16;
    uint64_t switch_op_ctl                       : 16;
    uint64_t lprt_size                           : 12;
    uint64_t hc_size                             : 4;
    uint64_t mhc_size                            : 4;
    uint64_t max_routes                          : 12;
    uint64_t uvcatsz                             : 5;
    uint64_t mvcatsz                             : 5;
    uint64_t mcprt_msmcprt_pad_size              : 5;
    uint64_t r0                                  : 17;
    uint64_t lprt_mprt_row_size                  : 16;
    uint64_t mcprt_msmcprt_row_size              : 16;
    uint64_t default_multicast_egress_interface  : 12;
    uint64_t default_collective_egress_interface : 12;
    uint64_t r1                                  : 8;
    uint64_t max_ulat                            : 16;
    uint64_t max_mlat                            : 16;
    uint64_t mcprt_size                          : 12;
    uint64_t r2                                  : 20;
    uint64_t mprt_size                           : 16;
    uint64_t r3                                  : 16;
    uint64_t msmcprt_size                        : 28;
    uint64_t r4                                  : 4;
    uint64_t mvcat_ptr                           : 32;
    uint64_t route_control_ptr                   : 32;
    uint64_t mcprt_ptr                           : 32;
    uint64_t msmcprt_ptr                         : 32;
    uuid_t mce_uuid_63_0;
    uuid_t mce_uuid_127_64;
    uint64_t mv_sub_0                            : 1;
    uint64_t mgmt_vc_sub_0                       : 5;
    uint64_t mgmt_interface_id_sub_0             : 12;
    uint64_t mv_sub_1                            : 1;
    uint64_t mgmt_vc_sub_1                       : 5;
    uint64_t mgmt_interface_id_sub_1             : 12;
    uint64_t mv_sub_2                            : 1;
    uint64_t mgmt_vc_sub_2                       : 5;
    uint64_t mgmt_interface_id_sub_2             : 12;
    uint64_t r5                                  : 10;
    uint64_t mv_sub_3                            : 1;
    uint64_t mgmt_vc_sub_3                       : 5;
    uint64_t mgmt_interface_id_sub_3             : 12;
    uint64_t r6                                  : 46;
    uint64_t r7                                  : 64;
    uint64_t r8                                  : 64;
};

struct genz_component_statistics_structure{
    uint64_t type                     : 12;
    uint64_t vers                     : 4;
    uint64_t size                     : 16;
    uint64_t cstat_cap_1              : 8;
    uint64_t cstat_control            : 8;
    uint64_t cstat_status             : 8;
    uint64_t st_type                  : 8;
    uint64_t next_statistics_ptr      : 32;
    uint64_t c_snapshot_ptr           : 32;
    uint64_t ee_retry_exceeded        : 16;
    uint64_t r0                       : 48;
    uint64_t c_snapshot_interval      : 64;
    uint64_t opcode_vendor_defined_0  : 32;
    uint64_t opcode_vendor_defined_1  : 32;
    uint64_t opcode_vendor_defined_2  : 32;
    uint64_t opcode_vendor_defined_3  : 32;
    uint64_t opcode_vendor_defined_4  : 32;
    uint64_t opcode_vendor_defined_5  : 32;
    uint64_t opcode_vendor_defined_6  : 32;
    uint64_t opcode_vendor_defined_7  : 32;
    uint64_t opcode_vendor_defined_8  : 32;
    uint64_t opcode_vendor_defined_9  : 32;
    uint64_t opcode_vendor_defined_10 : 32;
    uint64_t opcode_vendor_defined_11 : 32;
    uint64_t opcode_vendor_defined_12 : 32;
    uint64_t opcode_vendor_defined_13 : 32;
    uint64_t opcode_vendor_defined_14 : 32;
    uint64_t opcode_vendor_defined_15 : 32;
    uint64_t opcode_vendor_defined_16 : 32;
    uint64_t opcode_vendor_defined_17 : 32;
    uint64_t opcode_vendor_defined_18 : 32;
    uint64_t opcode_vendor_defined_19 : 32;
    uint64_t opcode_vendor_defined_20 : 32;
    uint64_t opcode_vendor_defined_21 : 32;
    uint64_t opcode_vendor_defined_22 : 32;
    uint64_t opcode_vendor_defined_23 : 32;
    uint64_t opcode_vendor_defined_24 : 32;
    uint64_t opcode_vendor_defined_25 : 32;
    uint64_t opcode_vendor_defined_26 : 32;
    uint64_t opcode_vendor_defined_27 : 32;
    uint64_t opcode_vendor_defined_28 : 32;
    uint64_t opcode_vendor_defined_29 : 32;
    uint64_t opcode_vendor_defined_30 : 32;
    uint64_t opcode_vendor_defined_31 : 32;
};

struct genz_component_extension_structure{
    uint64_t type                         : 12;
    uint64_t vers                         : 4;
    uint64_t size                         : 16;
    uint64_t next_component_extension_ptr : 32;
    uint64_t control_structure_ptr_0      : 32;
    uint64_t control_structure_ptr_1      : 32;
    uint64_t control_structure_ptr_2      : 32;
    uint64_t control_structure_ptr_3      : 32;
    uint64_t control_structure_ptr_4      : 32;
    uint64_t control_structure_ptr_5      : 32;
    uint64_t control_structure_ptr_6      : 32;
    uint64_t control_structure_ptr_7      : 32;
    uint64_t control_structure_ptr_8      : 32;
    uint64_t control_structure_ptr_9      : 32;
    uint64_t control_structure_ptr_10     : 48;
    uint64_t r0                           : 16;
    uint64_t control_structure_ptr_11     : 48;
    uint64_t r1                           : 16;
};

struct genz_vendor_defined_structure{
    uint32_t type                                                               : 12;
    uint32_t vers                                                               : 4;
    uint32_t size                                                               : 16;
    struct genz_vendor_defined_structure_array vendor_defined_structure_array[];
};

struct genz_vendor_defined_with_uuid_structure{
    uint64_t type                                                                                   : 12;
    uint64_t vers                                                                                   : 4;
    uint64_t size                                                                                   : 16;
    uint64_t vendor_defined_data_0                                                                  : 32;
    uint64_t vendor_defined_data_1                                                                  : 64;
    uuid_t vd_uuid_63_0;
    uuid_t vd_uuid_127_64;
    struct genz_vendor_defined_with_uuid_structure_array vendor_defined_with_uuid_structure_array[];
};

struct genz_component_multicast_structure{
    uint64_t type                : 12;
    uint64_t vers                : 4;
    uint64_t size                : 16;
    uint64_t mcast_cap_1         : 16;
    uint64_t mcast_cap_1_control : 16;
    uint64_t cmt_size            : 12;
    uint64_t r0                  : 8;
    uint64_t rcmt_size           : 12;
    uint64_t minte_sub_0         : 16;
    uint64_t minte_sub_1         : 16;
    uint64_t minte_sub_2         : 16;
    uint64_t minte_sub_3         : 16;
    uint64_t minte_sub_4         : 16;
    uint64_t minte_sub_5         : 16;
    uint64_t minte_sub_6         : 16;
    uint64_t minte_sub_7         : 16;
    uint64_t cmt_ptr             : 32;
    uint64_t mscmt_ptr           : 32;
    uint64_t rcmt_ptr            : 32;
    uint64_t msrcmt_ptr          : 32;
    uint64_t mscmt_size          : 28;
    uint64_t r1                  : 4;
    uint64_t msrcmt_size         : 28;
    uint64_t u_pad_size          : 5;
    uint64_t r_pad_size          : 5;
    uint64_t max_rsp             : 4;
    uint64_t r2                  : 22;
    uint64_t mcgpt               : 16;
    uint64_t r3                  : 48;
    uuid_t mce_uuid_63_0;
    uuid_t mce_uuid_127_64;
};

struct genz_component_tr_structure{
    uint64_t type          : 12;
    uint64_t vers          : 4;
    uint64_t size          : 16;
    uint64_t tr_status     : 32;
    uint64_t tr_table_ptr  : 32;
    uint64_t tr_table_size : 16;
    uint64_t r0            : 16;
    uint64_t r1            : 64;
    uint64_t r2            : 64;
};

struct genz_component_image_structure{
    uint64_t type                     : 12;
    uint64_t vers                     : 4;
    uint64_t size                     : 16;
    uint64_t image_table_size         : 32;
    uint64_t image_cap_1              : 16;
    uint64_t image_cap_1_control      : 16;
    uint64_t image_table_control      : 16;
    uint64_t image_fault_injection    : 16;
    uint64_t image_table_ptr          : 48;
    uint64_t image_uep                : 3;
    uint64_t r0                       : 13;
    uint64_t next_image_structure_ptr : 32;
    uint64_t r1                       : 32;
    uint64_t image_detect             : 16;
    uint64_t image_signal_target      : 48;
    uint64_t r2                       : 64;
};

struct genz_component_precision_time_structure{
    uint64_t type                     : 12;
    uint64_t vers                     : 4;
    uint64_t size                     : 16;
    uint64_t pt_cap_1                 : 16;
    uint64_t pt_ctl                   : 16;
    uint64_t gtc_cid                  : 12;
    uint64_t r0                       : 4;
    uint64_t gtc_sid                  : 16;
    uint64_t pt_rsp_cid               : 12;
    uint64_t r1                       : 4;
    uint64_t pt_rsp_sid               : 16;
    uint64_t alt_pt_rsp_cid           : 12;
    uint64_t tc                       : 4;
    uint64_t alt_pt_rsp_sid           : 16;
    uint64_t component_pt_granularity : 10;
    uint64_t ptd_granularity          : 10;
    uint64_t ptd_interface            : 12;
    uint64_t alt_ptd_interface        : 12;
    uint64_t r2                       : 20;
    uint64_t next_pt_ptr              : 32;
};

struct genz_component_mechanical_structure{
    uint64_t type                           : 12;
    uint64_t vers                           : 4;
    uint64_t size                           : 16;
    uint64_t mechanical_event_status        : 32;
    uint64_t mechanical_cap_1               : 64;
    uint64_t mechanical_control             : 64;
    uint64_t mechanical_module_id           : 12;
    uint64_t enclosure_id                   : 20;
    uint64_t mech_vendor_def_ptr            : 32;
    uint64_t mechanical_event_detect        : 32;
    uint64_t mechanical_event_injection     : 32;
    uint64_t mechanical_signal_target_63_0  : 64;
    uint64_t mechanical_signal_target_95_64 : 32;
    uint64_t r0                             : 32;
    uint64_t r1                             : 64;
};

struct genz_component_destination_table_structure{
    uint64_t type                      : 12;
    uint64_t vers                      : 4;
    uint64_t size                      : 16;
    uint64_t destination_table_cap_1   : 32;
    uint64_t destination_table_control : 32;
    uint64_t ssdt_size                 : 12;
    uint64_t hc_size                   : 4;
    uint64_t mhc_size                  : 4;
    uint64_t max_routes                : 12;
    uint64_t req_vcatsz                : 5;
    uint64_t rsp_vcatsz                : 5;
    uint64_t rit_pad_size              : 5;
    uint64_t r0                        : 17;
    uint64_t ssdt_msdt_row_size        : 16;
    uint64_t msdt_size                 : 16;
    uint64_t rit_size                  : 12;
    uint64_t r1                        : 20;
    uint64_t route_control_ptr         : 32;
    uint64_t ssdt_ptr                  : 32;
    uint64_t msdt_ptr                  : 32;
    uint64_t req_vcat_ptr              : 32;
    uint64_t rit_ptr                   : 32;
    uint64_t rsp_vcat_ptr              : 32;
    uint64_t r2                        : 32;
    uint64_t r3                        : 64;
};

struct genz_service_uuid_structure{
    uint64_t type                                                           : 12;
    uint64_t vers                                                           : 4;
    uint64_t size                                                           : 16;
    uuid_t s_uuid_table_sz;
    uint64_t r0                                                             : 16;
    uint64_t s_uuid_ptr                                                     : 32;
    uint64_t r1                                                             : 32;
    struct genz_service_uuid_structure_array service_uuid_structure_array[];
};

struct genz_component_c_access_structure{
    uint64_t type                : 12;
    uint64_t vers                : 4;
    uint64_t size                : 16;
    uint64_t next_c_access_ptr   : 32;
    uint64_t c_page_size         : 4;
    uint64_t r0                  : 8;
    uint64_t base_address        : 40;
    uint64_t c_access_cap_1      : 4;
    uint64_t c_access_ctl        : 8;
    uint64_t c_access_table_size : 40;
    uint64_t r1                  : 24;
    uint64_t c_access_r_key_ptr  : 32;
    uint64_t c_access_l_p2p_ptr  : 32;
};

struct genz_requester_p2p_structure{
    uint64_t type                             : 12;
    uint64_t vers                             : 4;
    uint64_t size                             : 16;
    uint64_t req_p2p_cap_1                    : 8;
    uint64_t req_p2p_cap_1_control            : 8;
    uint64_t req_p2p_control                  : 16;
    uint64_t r0                               : 32;
    uint64_t data_len                         : 8;
    uint64_t ctl_len                          : 8;
    uint64_t max_if_id                        : 8;
    uint64_t r1                               : 8;
    uint64_t smdb                             : 7;
    uint64_t r2                               : 5;
    uint64_t data_reqla                       : 52;
    uint64_t r3                               : 12;
    uint64_t ctl_reqla                        : 52;
    uint64_t vi_63_0                          : 64;
    uint64_t vi_127_64                        : 64;
    uint64_t r4                               : 64;
    uint64_t next_requester_p2p_structure_ptr : 32;
    uint64_t vendor_defined_ptr               : 32;
};

struct genz_component_pa_structure{
    uint64_t type                : 12;
    uint64_t vers                : 4;
    uint64_t size                : 16;
    uint64_t pa_cap_1            : 32;
    uint64_t pa_cap_1_control    : 32;
    uint64_t ssap_size           : 12;
    uint64_t mcap_size           : 12;
    uint64_t r0                  : 3;
    uint64_t pad_size            : 5;
    uint64_t pa_size             : 16;
    uint64_t r1                  : 16;
    uint64_t msap_size           : 28;
    uint64_t r2                  : 4;
    uint64_t msmcap_size         : 28;
    uint64_t r3                  : 4;
    uint64_t pa_ptr              : 32;
    uint64_t ssap_ptr            : 32;
    uint64_t msap_ptr            : 32;
    uint64_t mcap_ptr            : 32;
    uint64_t msmcap_ptr          : 32;
    uint64_t r4                  : 64;
    uint64_t r5                  : 64;
    uint64_t r6                  : 32;
    uint64_t wildcard_peer_attr  : 16;
    uint64_t wildcard_access_key : 6;
    uint64_t w_acreq             : 2;
    uint64_t w_acrsp             : 2;
    uint64_t r7                  : 6;
    uint64_t r8                  : 64;
    uuid_t mse_uuid_63_0;
    uuid_t mse_uuid_127_64;
};

struct genz_component_event_structure{
    uint64_t type                                                                 : 12;
    uint64_t vers                                                                 : 4;
    uint64_t size                                                                 : 16;
    uint64_t c_event_cap_1                                                        : 16;
    uint64_t c_event_control                                                      : 16;
    uint64_t c_event_interrupt_address_0                                          : 64;
    uint64_t c_event_interrupt_address_1                                          : 64;
    uint64_t c_event_interrupt_address_2                                          : 64;
    uint64_t c_event_interrupt_data_0                                             : 32;
    uint64_t c_event_interrupt_data_1                                             : 32;
    uint64_t c_event_interrupt_data_2                                             : 32;
    uint64_t max_event_records                                                    : 16;
    uint64_t r0                                                                   : 16;
    uint64_t event_record_address_0                                               : 64;
    uint64_t event_record_address_1                                               : 64;
    uint64_t event_record_address_2                                               : 64;
    uint64_t last_event_record_0                                                  : 16;
    uint64_t last_event_record_1                                                  : 16;
    uint64_t last_event_record_2                                                  : 16;
    uint64_t r1                                                                   : 16;
    struct genz_component_event_structure_array component_event_structure_array[];
};

struct genz_component_lpd_structure{
    uint64_t type                                                             : 12;
    uint64_t vers                                                             : 4;
    uint64_t size                                                             : 16;
    uint64_t next_component_lpd_structure_ptr                                 : 32;
    uint64_t lpd_cap_1                                                        : 32;
    uint64_t lpd_cap_1_control                                                : 32;
    uint64_t default_hcid                                                     : 12;
    uint64_t default_hsid                                                     : 16;
    uint64_t r0                                                               : 20;
    uint64_t lpd_bus_number                                                   : 8;
    uint64_t function_table_size                                              : 8;
    uint64_t mmiol_gz_ds_base                                                 : 64;
    uint64_t mmiol_size                                                       : 32;
    uint64_t mmiol_pci_ms_base                                                : 32;
    uint64_t mmioh_gz_ds_base                                                 : 64;
    uint64_t mmioh_size                                                       : 64;
    uint64_t mmioh_pci_ms_base                                                : 64;
    uint64_t mmio_r_key                                                       : 32;
    uint64_t r1                                                               : 32;
    uint64_t r2                                                               : 64;
    struct genz_component_lpd_structure_array component_lpd_structure_array[];
};

struct genz_component_sod_structure{
    uint64_t type              : 12;
    uint64_t vers              : 4;
    uint64_t size              : 16;
    uint64_t sod_cap_1         : 32;
    uint64_t sod_cap_1_control : 32;
    uint64_t ssod_size         : 12;
    uint64_t sode              : 6;
    uint64_t r0                : 14;
    uint64_t msod_size         : 28;
    uint64_t r1                : 4;
    uint64_t ssod_ptr          : 32;
    uint64_t msod_ptr          : 32;
    uint64_t r2                : 32;
    uint64_t r3                : 64;
    uint64_t r4                : 64;
};

struct genz_congestion_management_structure{
    uint64_t type                       : 12;
    uint64_t vers                       : 4;
    uint64_t size                       : 16;
    uint64_t congestion_cap_1           : 16;
    uint64_t congestion_cap_1_control   : 16;
    uint64_t vendor_defined_ptr         : 32;
    uint64_t resource_array_ptr         : 32;
    uint64_t congestion_sampling_window : 32;
    uint64_t packet_generation_delay    : 16;
    uint64_t resource_array_size        : 16;
    uint64_t r0                         : 51;
    uint64_t c_min_index                : 5;
    uint64_t resource_type              : 8;
    uint64_t pidt_sub_0                 : 32;
    uint64_t pidt_sub_1                 : 32;
    uint64_t pidt_sub_2                 : 32;
    uint64_t pidt_sub_3                 : 32;
    uint64_t pidt_sub_4                 : 32;
    uint64_t pidt_sub_5                 : 32;
    uint64_t pidt_sub_6                 : 32;
    uint64_t pidt_sub_7                 : 32;
    uint64_t pidt_sub_8                 : 32;
    uint64_t pidt_sub_9                 : 32;
    uint64_t pidt_sub_10                : 32;
    uint64_t pidt_sub_11                : 32;
    uint64_t pidt_sub_12                : 32;
    uint64_t pidt_sub_13                : 32;
    uint64_t pidt_sub_14                : 32;
    uint64_t pidt_sub_15                : 32;
    uint64_t pidt_sub_16                : 32;
    uint64_t pidt_sub_17                : 32;
    uint64_t pidt_sub_18                : 32;
    uint64_t pidt_sub_19                : 32;
    uint64_t pidt_sub_20                : 32;
    uint64_t pidt_sub_21                : 32;
    uint64_t pidt_sub_22                : 32;
    uint64_t pidt_sub_23                : 32;
    uint64_t pidt_sub_24                : 32;
    uint64_t pidt_sub_25                : 32;
    uint64_t pidt_sub_26                : 32;
    uint64_t pidt_sub_27                : 32;
    uint64_t pidt_sub_28                : 32;
    uint64_t pidt_sub_29                : 32;
    uint64_t pidt_sub_30                : 32;
    uint64_t pidt_sub_31                : 32;
};

struct genz_component_rkd_structure{
    uint64_t type                                                             : 12;
    uint64_t vers                                                             : 4;
    uint64_t size                                                             : 16;
    uint64_t rkd_cap_1                                                        : 16;
    uint64_t rkd_control_1                                                    : 16;
    uint64_t r0                                                               : 64;
    struct genz_component_rkd_structure_array component_rkd_structure_array[];
};

struct genz_component_pm_structure{
    uint64_t type                : 12;
    uint64_t vers                : 4;
    uint64_t size                : 16;
    uint64_t pm_cap_1            : 16;
    uint64_t pm_control          : 16;
    uint64_t performance_log_ptr : 32;
    uint64_t r0                  : 32;
};

struct genz_component_atp_structure{
    uint64_t type                             : 12;
    uint64_t vers                             : 4;
    uint64_t size                             : 16;
    uint64_t atp_cap_1                        : 32;
    uint64_t atp_cap_1_control                : 32;
    uint64_t atp_status                       : 32;
    uint64_t stue                             : 5;
    uint64_t r0                               : 35;
    uint64_t failed_reqctxid                  : 24;
    uint64_t outstanding_prg_capacity         : 32;
    uint64_t outstanding_prg_allocation       : 32;
    uint64_t outstanding_prg_request_capacity : 52;
    uint64_t r1                               : 12;
    uint64_t r2                               : 64;
};

struct genz_component_re_table_structure{
    uint64_t type                        : 12;
    uint64_t vers                        : 4;
    uint64_t size                        : 16;
    uint64_t re_table_size               : 32;
    uint64_t re_table_cap_1              : 16;
    uint64_t re_table_cap_1_control      : 16;
    uint64_t re_table_control            : 16;
    uint64_t r0                          : 16;
    uint64_t re_table_ptr                : 48;
    uint64_t re_table_entry_size         : 16;
    uint64_t next_re_table_structure_ptr : 48;
    uint64_t re_table_id                 : 7;
    uint64_t r1                          : 9;
    uuid_t re_uuid_63_0;
    uuid_t re_uuid_127_64;
};

struct genz_component_lph_structure{
    uint64_t type                             : 12;
    uint64_t vers                             : 4;
    uint64_t size                             : 16;
    uint64_t next_component_lph_structure_ptr : 32;
    uint64_t lph_cap_1                        : 32;
    uint64_t lph_cap_1_control                : 32;
    uint64_t default_hcid                     : 12;
    uint64_t default_hsid                     : 16;
    uint64_t r0                               : 20;
    uint64_t lph_pio_rtrs                     : 8;
    uint64_t lph_dma_rtrs                     : 8;
    uint64_t mmiol_gz_ds_base                 : 64;
    uint64_t mmiol_size                       : 32;
    uint64_t mmiol_pci_ms_base                : 32;
    uint64_t mmioh_gz_ds_base                 : 64;
    uint64_t mmioh_size                       : 64;
    uint64_t mmioh_pci_ms_base                : 64;
    uint64_t mmio_r_key                       : 32;
    uint64_t r1                               : 32;
    uint64_t r2                               : 64;
    uint64_t lph_ctl                          : 16;
    uint64_t lph_ecam_size                    : 8;
    uint64_t lph_ecam_bn_offset               : 8;
    uint64_t lph_ecam_ptr                     : 32;
    uint64_t lph_ro_r_key                     : 32;
    uint64_t lph_rw_r_key                     : 32;
    uint64_t lph_rcrb_ptr                     : 32;
    uint64_t r3                               : 32;
    uint64_t r4                               : 64;
};

struct genz_component_page_grid_structure{
    uint64_t type                         : 12;
    uint64_t vers                         : 4;
    uint64_t size                         : 16;
    uint64_t pte_table_sz                 : 32;
    uint64_t pg_zmmu_cap_1                : 32;
    uint64_t pg_zmmu_cap_1_control        : 32;
    uint64_t pg_table_sz                  : 8;
    uint64_t pte_sz                       : 10;
    uint64_t r0                           : 46;
    uint64_t pg_base_ptr                  : 32;
    uint64_t pte_base_ptr                 : 32;
    uint64_t vendor_defined_ptr           : 32;
    uint64_t next_component_page_grid_ptr : 32;
    uint64_t restricted_pg_base_ptr       : 32;
    uint64_t restricted_pte_base_ptr      : 32;
    uint64_t pte_attr_63_0                : 64;
    uint64_t pte_attr_127_64              : 64;
    uint64_t r1                           : 64;
    uint64_t zmmu_supported_page_sizes    : 52;
    uint64_t r2                           : 12;
    uuid_t pg_pte_uuid_63_0;
    uuid_t pg_pte_uuid_127_64;
};

struct genz_component_page_table_structure{
    uint64_t type                          : 12;
    uint64_t vers                          : 4;
    uint64_t size                          : 16;
    uint64_t vendor_defined_ptr            : 32;
    uint64_t pt_zmmu_cap_1                 : 32;
    uint64_t pt_zmmu_cap_1_control         : 32;
    uint64_t pte_cache_ptr                 : 32;
    uint64_t pte_cache_length              : 32;
    uint64_t pt_address                    : 64;
    uint64_t pte_attr_63_0                 : 64;
    uint64_t pte_attr_127_64               : 64;
    uint64_t r0                            : 32;
    uint64_t next_component_page_table_ptr : 32;
    uint64_t supported_page_sizes          : 52;
    uint64_t pte_sz                        : 10;
    uint64_t r1                            : 2;
    uuid_t pt_pte_uuid_63_0;
    uuid_t pt_pte_uuid_127_64;
};

struct genz_component_interleave_structure{
    uint64_t type                          : 12;
    uint64_t vers                          : 4;
    uint64_t size                          : 16;
    uint64_t next_component_interleave_ptr : 32;
    uint64_t interleave_cap_1              : 32;
    uint64_t interleave_cap_1_control      : 32;
    uuid_t interleave_uuid_63_0;
    uuid_t interleave_uuid_127_64;
    uint64_t interleave_table_ptr          : 32;
    uint64_t max_it_entries                : 16;
    uint64_t it_entry_size                 : 11;
    uint64_t ilte_cids                     : 5;
};

struct genz_component_firmware_structure{
    uint64_t type               : 12;
    uint64_t vers               : 4;
    uint64_t size               : 16;
    uint64_t fw_table_sz        : 8;
    uint64_t fw_uep             : 3;
    uint64_t r0                 : 5;
    uint64_t max_fw_update_time : 16;
    uint64_t fw_table_ptr       : 32;
    uint64_t fw_table_cap_1     : 16;
    uint64_t fw_table_control   : 16;
    uint64_t fw_detect          : 16;
    uint64_t fw_signal_target   : 48;
    uint64_t fw_fault_injection : 16;
    uint64_t r1                 : 48;
};

struct genz_component_sw_management_structure{
    uint64_t type                  : 12;
    uint64_t vers                  : 4;
    uint64_t size                  : 16;
    uint64_t swm_cap_1             : 16;
    uint64_t swm_control_1         : 16;
    uint64_t swm_optype            : 8;
    uint64_t swm_error             : 8;
    uint64_t swm_max_size          : 16;
    uint64_t swm_max_read_size     : 16;
    uint64_t swm_max_write_size    : 16;
    uint64_t swm_read_offset       : 16;
    uint64_t swm_read_len          : 16;
    uint64_t swm_write_offset      : 16;
    uint64_t swm_write_len         : 16;
    uint64_t swm_ptr               : 32;
    uint64_t swm_time              : 16;
    uint64_t swm_status            : 16;
    uint64_t swm_interrupt_address : 64;
    uint64_t swm_interrupt_data    : 32;
    uint64_t swm_cid               : 12;
    uint64_t swm_sid               : 16;
    uint64_t swm_cs                : 2;
    uint64_t r0                    : 2;
    uint64_t r1                    : 64;
    uint64_t r2                    : 64;
};

struct genz_backup_mgmt_table{
    uint64_t component_backup_cap_1             : 64;
    uint64_t component_backup_cap_1_control     : 64;
    uint64_t component_backup_status_1          : 32;
    uint64_t component_backup_control_1         : 32;
    uint64_t component_backup_fault_injection_1 : 64;
    uint64_t component_backup_fault_injection_2 : 64;
    uint64_t min_lps_wear_threshold             : 7;
    uint64_t lps_wear_threshold                 : 7;
    uint64_t lps_low_thermal_threshold          : 11;
    uint64_t lps_upper_thermal_threshold        : 11;
    uint64_t lps_temp                           : 11;
    uint64_t auto_lps_assessment                : 8;
    uint64_t r0                                 : 9;
    uint64_t lps_operational_time               : 16;
    uint64_t power_cycle_count                  : 16;
    uint64_t lps_tps_backup_power               : 16;
    uint64_t max_lps_charge_power               : 16;
    uint64_t max_lps_charge_time                : 16;
    uint64_t post_backup_idle_power             : 16;
    uint64_t min_lps_tps_voltage                : 16;
    uint64_t max_lps_tps_voltage                : 16;
    uint64_t max_backup_time                    : 16;
    uint64_t max_erase_time                     : 16;
    uint64_t max_restore_time                   : 16;
    uint64_t max_arm_time                       : 16;
    uint64_t max_backup_nvm_init_time           : 16;
    uint64_t max_abort_time                     : 16;
    uint64_t backup_duration                    : 16;
    uint64_t restore_duration                   : 16;
    uint64_t erase_duration                     : 16;
    uint64_t arm_duration                       : 16;
    uint64_t backup_success_count               : 16;
    uint64_t backup_failure_count               : 16;
    uint64_t restore_success_count              : 16;
    uint64_t restore_failure_count              : 16;
    uint64_t erase_success_count                : 16;
    uint64_t erase_failure_count                : 16;
    uint64_t arm_success_count                  : 16;
    uint64_t arm_failure_count                  : 16;
    uint64_t r1                                 : 22;
    uint64_t da_range                           : 6;
    uint64_t da_sz                              : 4;
    uint64_t pm_backup_table_ptr                : 32;
    uint64_t sm_backup_table_ptr                : 32;
    uint64_t r2                                 : 64;
    uint64_t r3                                 : 64;
};

struct genz_component_error_elog_entry{
    uint64_t vers                 : 2;
    uint64_t error_code           : 7;
    uint64_t log_type             : 4;
    uint64_t r0                   : 19;
    uint64_t error_specific_3_0   : 32;
    uint64_t error_specific_11_4  : 64;
    uint64_t error_specific_19_12 : 64;
    uint64_t error_specific_27_20 : 64;
};

struct genz_core_lpd_bdf_table{
    uint64_t bdf_sub_0  : 16;
    uint64_t bdf_sub_1  : 16;
    uint64_t bdf_sub_2  : 16;
    uint64_t bdf_sub_3  : 16;
    uint64_t bdf_sub_4  : 16;
    uint64_t bdf_sub_5  : 16;
    uint64_t bdf_sub_6  : 16;
    uint64_t bdf_sub_7  : 16;
    uint64_t bdf_sub_8  : 16;
    uint64_t bdf_sub_9  : 16;
    uint64_t bdf_sub_10 : 16;
    uint64_t bdf_sub_11 : 16;
    uint64_t bdf_sub_12 : 16;
    uint64_t bdf_sub_13 : 16;
    uint64_t bdf_sub_14 : 16;
    uint64_t bdf_sub_15 : 16;
    uint64_t bdf_sub_16 : 16;
    uint64_t bdf_sub_17 : 16;
    uint64_t bdf_sub_18 : 16;
    uint64_t bdf_sub_19 : 16;
    uint64_t bdf_sub_20 : 16;
    uint64_t bdf_sub_21 : 16;
    uint64_t bdf_sub_22 : 16;
    uint64_t bdf_sub_23 : 16;
    uint64_t bdf_sub_24 : 16;
    uint64_t bdf_sub_25 : 16;
    uint64_t bdf_sub_26 : 16;
    uint64_t bdf_sub_27 : 16;
    uint64_t bdf_sub_28 : 16;
    uint64_t bdf_sub_29 : 16;
    uint64_t bdf_sub_30 : 16;
    uint64_t bdf_sub_31 : 16;
    uint64_t bdf_sub_32 : 16;
    uint64_t bdf_sub_33 : 16;
    uint64_t bdf_sub_34 : 16;
    uint64_t bdf_sub_35 : 16;
    uint64_t bdf_sub_36 : 16;
    uint64_t bdf_sub_37 : 16;
    uint64_t bdf_sub_38 : 16;
    uint64_t bdf_sub_39 : 16;
    uint64_t bdf_sub_40 : 16;
    uint64_t bdf_sub_41 : 16;
    uint64_t bdf_sub_42 : 16;
    uint64_t bdf_sub_43 : 16;
    uint64_t bdf_sub_44 : 16;
    uint64_t bdf_sub_45 : 16;
    uint64_t bdf_sub_46 : 16;
    uint64_t bdf_sub_47 : 16;
    uint64_t bdf_sub_48 : 16;
    uint64_t bdf_sub_49 : 16;
    uint64_t bdf_sub_50 : 16;
    uint64_t bdf_sub_51 : 16;
    uint64_t bdf_sub_52 : 16;
    uint64_t bdf_sub_53 : 16;
    uint64_t bdf_sub_54 : 16;
    uint64_t bdf_sub_55 : 16;
    uint64_t bdf_sub_56 : 16;
    uint64_t bdf_sub_57 : 16;
    uint64_t bdf_sub_58 : 16;
    uint64_t bdf_sub_59 : 16;
    uint64_t bdf_sub_60 : 16;
    uint64_t bdf_sub_61 : 16;
    uint64_t bdf_sub_62 : 16;
    uint64_t bdf_sub_63 : 16;
};

struct genz_elog_table{
    uint64_t elog_size                             : 16;
    uint64_t r0                                    : 16;
    uint64_t next_elog_ptr                         : 32;
    struct genz_elog_table_array log_table_array[];
};

struct genz_event_record{
    uint64_t a            : 1;
    uint32_t vers         : 2;
    uint32_t cv           : 1;
    uint32_t sv           : 1;
    uint32_t gc           : 1;
    uint32_t iv           : 1;
    uint32_t r0           : 1;
    uint32_t event        : 8;
    uint32_t r1           : 4;
    uint32_t interface_id : 12;
    uint32_t scid         : 12;
    uint32_t ssid         : 16;
    uint32_t r2           : 4;
    uint32_t rc_cid       : 12;
    uint32_t rc_sid       : 16;
    uint32_t r3           : 4;
    uint32_t es           : 32;
    uint32_t event_id     : 16;
    uint32_t r4           : 16;
};

struct genz_image_format_0xc86ed8c24bed49bda5143dd11950de9d_header_format{ //FIXME: name too long.
    uuid_t header_format_uuid_63_0;
    uuid_t header_format_uuid_127_64;
    uuid_t c_uuid_63_0;
    uuid_t c_uuid_127_64;
    uuid_t image_uuid_63_0;
    uuid_t image_uuid_127_64;
    uuid_t authentication_uuid_63_0;
    uuid_t authentication_uuid_127_64;
    uint64_t image_length             : 64;
    uint64_t image_version            : 16;
    uint64_t image_sub_version        : 16;
    uint64_t hd_sz                    : 16;
    uint64_t ek_sz                    : 16;
    uint64_t vdef_sz                  : 16;
    uint64_t name_sz                  : 16;
    uint64_t c_sz                     : 16;
    uint64_t checksum                 : 16;
    uint64_t hash_digest              : 64;
    uint64_t certificate              : 64;
    uint64_t name                     : 64;
    uint64_t encryption_key           : 64;
    uint64_t vendor_def               : 64;
};

struct genz_interface_error_elog_entry{
    uint64_t vers                 : 2;
    uint64_t error_code           : 7;
    uint64_t log_type             : 4;
    uint64_t root_cause           : 7;
    uint64_t interface_id         : 12;
    uint64_t error_specific_3_0   : 32;
    uint64_t error_specific_11_4  : 64;
    uint64_t error_specific_19_12 : 64;
    uint64_t error_specific_27_20 : 64;
};

struct genz_label_data_table{
    uint64_t label_data_size                                    : 24;
    uint64_t label_data_sub_0                                   : 40;
    struct genz_label_data_table_array label_data_table_array[];
};

struct genz_mcprt_msmcprt_table{};

struct genz_mcprt_msmcptr_row{};

struct genz_oem_data_table{
    uint64_t oem_data_size                                  : 16;
    uint64_t aggregate_uncorrectable_error_count            : 24;
    uint64_t aggregate_correctable_error_count              : 24;
    uint64_t oem_status                                     : 32;
    uint64_t backup_fail_count                              : 16;
    uint64_t r0                                             : 16;
    uuid_t oem_data_uuid_63_0;
    uuid_t oem_data_uuid_127_64;
    struct genz_oem_data_table_array oem_data_table_array[];
};

struct genz_opcode_set_table{
    uint64_t set_id                                : 3;
    uint64_t r0                                    : 13;
    uint64_t opcode_set_id_control_1               : 16;
    uint64_t next_opcode_set_ptr                   : 32;
    uint64_t r1                                    : 64;
    uint64_t supported_core_64_opcode_set          : 64;
    uint64_t enabled_core_64_opcode_set            : 64;
    uint64_t supported_control_opcode_set          : 64;
    uint64_t enabled_control_opcode_set            : 64;
    uint64_t supported_p2p_64_opcode_set           : 64;
    uint64_t enabled_p2p_64_opcode_set             : 64;
    uint64_t supported_atomic_1_opcode_set         : 64;
    uint64_t enabled_atomic_1_opcode_set           : 64;
    uint64_t supported_ldm_1_opcode_set            : 64;
    uint64_t enabled_ldm_1_opcode_set              : 64;
    uint64_t supported_advanced_1_opcode_set       : 64;
    uint64_t enabled_advanced_1_opcode_set         : 64;
    uint64_t supported_opclass_0x6_opcode_set      : 64;
    uint64_t enabled_opclass_0x6_opcode_set        : 64;
    uint64_t supported_opclass_0x7_opcode_set      : 64;
    uint64_t enabled_opclass_0x7_opcode_set        : 64;
    uint64_t supported_opclass_0x8_opcode_set      : 64;
    uint64_t enabled_opclass_0x8_opcode_set        : 64;
    uint64_t supported_opclass_0x9_opcode_set      : 64;
    uint64_t enabled_opclass_0x9_opcode_set        : 64;
    uint64_t supported_opclass_0xa_opcode_set      : 64;
    uint64_t enabled_opclass_0xa_opcode_set        : 64;
    uint64_t supported_opclass_0xb_opcode_set      : 64;
    uint64_t enabled_opclass_0xb_opcode_set        : 64;
    uint64_t supported_opclass_0xc_opcode_set      : 64;
    uint64_t enabled_opclass_0xc_opcode_set        : 64;
    uint64_t supported_opclass_0xd_opcode_set      : 64;
    uint64_t enabled_opclass_0xd_opcode_set        : 64;
    uint64_t supported_opclass_0xe_opcode_set      : 64;
    uint64_t enabled_opclass_0xe_opcode_set        : 64;
    uint64_t supported_opclass_0xf_opcode_set      : 64;
    uint64_t enabled_opclass_0xf_opcode_set        : 64;
    uint64_t supported_opclass_0x10_opcode_set     : 64;
    uint64_t enabled_opclass_0x10_opcode_set       : 64;
    uint64_t supported_opclass_0x11_opcode_set     : 64;
    uint64_t enabled_opclass_0x11_opcode_set       : 64;
    uint64_t supported_opclass_0x12_opcode_set     : 64;
    uint64_t enabled_opclass_0x12_opcode_set       : 64;
    uint64_t supported_opclass_0x13_opcode_set     : 64;
    uint64_t enabled_opclass_0x13_opcode_set       : 64;
    uint64_t supported_dr_opcode_set               : 64;
    uint64_t enabled_dr_opcode_set                 : 64;
    uint64_t supported_context_id_opcode_set       : 64;
    uint64_t enabled_context_id_opcode_set         : 64;
    uint64_t supported_multicast_opcode_set        : 64;
    uint64_t enabled_multicast_opcode_set          : 64;
    uint64_t supported_sod_opcode_set              : 64;
    uint64_t enabled_sod_opcode_set                : 64;
    uint64_t supported_multi_op_request_sub_op_set : 64;
    uint64_t enabled_multi_op_request_sub_op_set   : 64;
    uint64_t supported_read_multi_op_set           : 32;
    uint64_t enabled_read_multi_op_set             : 32;
    uint64_t r2                                    : 64;
};

struct genz_opcode_set_uuid_table{
    uint64_t supported_p2p_vendor_defined_set              : 64;
    uint64_t enabled_p2p_vendor_defined_set                : 64;
    uint64_t supported_vdo_opcode_set_1                    : 64;
    uint64_t enabled_vdo_opcode_set_1                      : 64;
    uint64_t supported_vdo_opcode_set_2                    : 64;
    uint64_t enabled_vdo_opcode_set_2                      : 64;
    uint64_t supported_vdo_opcode_set_3                    : 64;
    uint64_t enabled_vdo_opcode_set_3                      : 64;
    uint64_t supported_vdo_opcode_set_4                    : 64;
    uint64_t enabled_vdo_opcode_set_4                      : 64;
    uint64_t supported_vdo_opcode_set_5                    : 64;
    uint64_t enabled_vdo_opcode_set_5                      : 64;
    uint64_t supported_vdo_opcode_set_6                    : 64;
    uint64_t enabled_vdo_opcode_set_6                      : 64;
    uint64_t supported_vdo_opcode_set_7                    : 64;
    uint64_t enabled_vdo_opcode_set_7                      : 64;
    uint64_t supported_vdo_opcode_set_8                    : 64;
    uint64_t enabled_vdo_opcode_set_8                      : 64;
    uint64_t supported_p2p_64_subop_request_set_127_0_1    : 64; //NOTE: split bit
    uint64_t supported_p2p_64_subop_request_set_127_0_2    : 64; //NOTE: split bit
    uint64_t supported_p2p_64_subop_request_set_255_128_1  : 64; //NOTE: split bit
    uint64_t supported_p2p_64_subop_request_set_255_128_2  : 64; //NOTE: split bit
    uint64_t enabled_p2p_64_subop_request_set_127_0_1      : 64; //NOTE: split bit
    uint64_t enabled_p2p_64_subop_request_set_127_0_2      : 64; //NOTE: split bit
    uint64_t enabled_p2p_64_subop_request_set_255_128_1    : 64; //NOTE: split bit
    uint64_t enabled_p2p_64_subop_request_set_255_128_2    : 64; //NOTE: split bit
    uint64_t supported_p2p_64_subop_response_set_127_0_1   : 64; //NOTE: split bit
    uint64_t supported_p2p_64_subop_response_set_127_0_2   : 64; //NOTE: split bit
    uint64_t supported_p2p_64_subop_response_set_255_128_1 : 64; //NOTE: split bit
    uint64_t supported_p2p_64_subop_response_set_255_128_2 : 64; //NOTE: split bit
    uint64_t enabled_p2p_64_subop_response_set_127_0_1     : 64; //NOTE: split bit
    uint64_t enabled_p2p_64_subop_response_set_127_0_2     : 64; //NOTE: split bit
    uint64_t enabled_p2p_64_subop_response_set_255_128_1   : 64; //NOTE: split bit
    uint64_t enabled_p2p_64_subop_response_set_255_128_2   : 64; //NOTE: split bit
    uuid_t pm_uuid;
    uuid_t vdo_uuid_1;
    uuid_t vdo_uuid_2;
    uuid_t vdo_uuid_3;
    uuid_t vdo_uuid_4;
    uuid_t vdo_uuid_5;
    uuid_t vdo_uuid_6;
    uuid_t vdo_uuid_7;
    uuid_t vdo_uuid_8;
};

struct genz_pm_backup_table{
    uint64_t pm_backup_table_sz                               : 16;
    uint64_t vers                                             : 4;
    uint64_t r0                                               : 44;
    struct genz_pm_backup_table_array pm_backup_table_array[];
};

struct genz_pte_restricted_pte_table{};

struct genz_page_table_pointer_pair_table_entry{
    uint64_t v             : 1;
    uint64_t et            : 1;
    uint32_t r0            : 1;
    uint64_t pt_sub_0      : 5;
    uint32_t pointer_sub_0 : 24;
    uint32_t r1            : 3;
    uint64_t pt_sub_1      : 5;
    uint32_t pointer_sub_1 : 24;
};

struct genz_performance_log_record_0{
    uint32_t dcid                    : 12;
    uint32_t scid                    : 12;
    uint32_t ocl                     : 5;
    uint32_t opcode_2_0              : 3;
    uint32_t opcode_4_3              : 2;
    uint32_t length                  : 7;
    uint32_t rk                      : 1;
    uint32_t gc                      : 1;
    uint32_t nh                      : 1;
    uint32_t lp                      : 1;
    uint32_t ingress_vc              : 5;
    uint32_t ei                      : 1;
    uint32_t eo                      : 1;
    uint32_t tag                     : 12;
    uint32_t ingress_timestamp_31_0  : 32;
    uint32_t ingress_timestamp_63_32 : 32;
    uint32_t egress_delta_timestamp  : 32;
    uint32_t ingress_interface       : 12;
    uint32_t egress_interface        : 12;
    uint32_t vendor_defined_0        : 8;
};

struct genz_performance_log_record_1{
    uint32_t dcid                    : 12;
    uint32_t scid                    : 12;
    uint32_t ocl                     : 5;
    uint32_t opcode_2_0              : 3;
    uint32_t opcode_4_3              : 2;
    uint32_t length                  : 7;
    uint32_t rk                      : 1;
    uint32_t gc                      : 1;
    uint32_t nh                      : 1;
    uint32_t lp                      : 1;
    uint32_t ingress_vc              : 5;
    uint32_t ei                      : 1;
    uint32_t eo                      : 1;
    uint32_t tag                     : 12;
    uint32_t ingress_timestamp_31_0  : 32;
    uint32_t ingress_timestamp_63_32 : 32;
    uint32_t egress_delta_timestamp  : 32;
    uint32_t ingress_interface       : 12;
    uint32_t egress_interface        : 12;
    uint32_t vendor_defined_0        : 8;
    uint32_t ingress_packet_deadline : 10;
    uint32_t vendor_defined_1        : 22;
    uint32_t dsid                    : 16;
    uint32_t ssid                    : 16;
};

struct genz_reliable_multicast_table_entry_row{};

struct genz_requester_vcat_table{};

struct genz_resource_table{};

struct genz_responder_vcat_table{};

struct genz_route_control_table{
    uint32_t rc_cap_1                     : 16;
    uint32_t r0                           : 10;
    uint32_t dhc                          : 6;
    uint32_t requester_simultaneous_table : 16;
    uint32_t r1                           : 16;
    uint32_t requester_local_table_first  : 16;
    uint32_t r2                           : 16;
    uint32_t requester_threshold_enable   : 16;
    uint32_t r3                           : 16;
    uint32_t responder_simultaneous_table : 32;
    uint32_t responder_local_table_first  : 32;
    uint32_t responder_threshold_enable   : 32;
    uint32_t relay_simultaneous_table     : 32;
    uint32_t relay_local_table_first      : 32;
    uint32_t relay_threshold_enable       : 32;
    uint32_t r4                           : 32;
    uint32_t r5                           : 32;
};

struct genz_sm_backup_table{
    uint64_t sm_backup_table_sz                               : 16;
    uint64_t vers                                             : 4;
    uint64_t r0                                               : 44;
    struct genz_sm_backup_table_array sm_backup_table_array[];
};

struct genz_ssap_mcap_msap_and_msmcap_table{};

struct genz_ssod_msod_table{};

struct genz_unreliable_multicast_table_entry_row{};

struct genz_vcat_table{};

extern struct genz_control_ptr_info genz_struct_type_to_ptrs[];

extern size_t genz_control_ptr_info_nelems;

extern struct genz_hardware_classes genz_hardware_classes[];

extern size_t genz_hardware_classes_nelems;

extern struct genz_control_ptr_info genz_table_type_to_ptrs[];

extern size_t genz_struct_type_to_ptrs_nelems;

extern size_t genz_table_type_to_ptrs_nelems;

ssize_t genz_hardware_classes_size (struct genz_control_info *ci);

ssize_t genz_core_structure_size (struct genz_control_info *ci);

ssize_t genz_opcode_set_structure_size (struct genz_control_info *ci);

ssize_t genz_interface_structure_size (struct genz_control_info *ci);

ssize_t genz_interface_phy_structure_size (struct genz_control_info *ci);

ssize_t genz_interface_statistics_structure_size (struct genz_control_info *ci);

ssize_t genz_component_error_and_signal_event_structure_size (struct genz_control_info *ci);

ssize_t genz_component_media_structure_size (struct genz_control_info *ci);

ssize_t genz_component_switch_structure_size (struct genz_control_info *ci);

ssize_t genz_component_statistics_structure_size (struct genz_control_info *ci);

ssize_t genz_component_extension_structure_size (struct genz_control_info *ci);

ssize_t genz_vendor_defined_structure_size (struct genz_control_info *ci);

ssize_t genz_vendor_defined_with_uuid_structure_size (struct genz_control_info *ci);

ssize_t genz_component_multicast_structure_size (struct genz_control_info *ci);

ssize_t genz_component_tr_structure_size (struct genz_control_info *ci);

ssize_t genz_component_image_structure_size (struct genz_control_info *ci);

ssize_t genz_component_precision_time_structure_size (struct genz_control_info *ci);

ssize_t genz_component_mechanical_structure_size (struct genz_control_info *ci);

ssize_t genz_component_destination_table_structure_size (struct genz_control_info *ci);

ssize_t genz_service_uuid_structure_size (struct genz_control_info *ci);

ssize_t genz_component_c_access_structure_size (struct genz_control_info *ci);

ssize_t genz_requester_p2p_structure_size (struct genz_control_info *ci);

ssize_t genz_component_pa_structure_size (struct genz_control_info *ci);

ssize_t genz_component_event_structure_size (struct genz_control_info *ci);

ssize_t genz_component_lpd_structure_size (struct genz_control_info *ci);

ssize_t genz_component_sod_structure_size (struct genz_control_info *ci);

ssize_t genz_congestion_management_structure_size (struct genz_control_info *ci);

ssize_t genz_component_rkd_structure_size (struct genz_control_info *ci);

ssize_t genz_component_pm_structure_size (struct genz_control_info *ci);

ssize_t genz_component_atp_structure_size (struct genz_control_info *ci);

ssize_t genz_component_re_table_structure_size (struct genz_control_info *ci);

ssize_t genz_component_lph_structure_size (struct genz_control_info *ci);

ssize_t genz_component_page_grid_structure_size (struct genz_control_info *ci);

ssize_t genz_component_page_table_structure_size (struct genz_control_info *ci);

ssize_t genz_component_interleave_structure_size (struct genz_control_info *ci);

ssize_t genz_component_firmware_structure_size (struct genz_control_info *ci);

ssize_t genz_component_sw_management_structure_size (struct genz_control_info *ci);

ssize_t genz_backup_mgmt_table_size (struct genz_control_info *ci);

ssize_t genz_c_access_l_p2p_table_size (struct genz_control_info *ci);

ssize_t genz_c_access_r_key_table_size (struct genz_control_info *ci);

ssize_t genz_component_error_elog_entry_size (struct genz_control_info *ci);

ssize_t genz_core_lpd_bdf_table_size (struct genz_control_info *ci);

ssize_t genz_elog_table_size (struct genz_control_info *ci);

ssize_t genz_event_record_size (struct genz_control_info *ci);

ssize_t genz_firmware_table_size (struct genz_control_info *ci);

ssize_t genz_image_format_0xc86ed8c24bed49bda5143dd11950de9d_header_format_size (struct genz_control_info *ci);

ssize_t genz_image_table_size (struct genz_control_info *ci);

ssize_t genz_interface_error_elog_entry_size (struct genz_control_info *ci);

ssize_t genz_lprt_mprt_table_size (struct genz_control_info *ci);

ssize_t genz_label_data_table_size (struct genz_control_info *ci);

ssize_t genz_mcprt_msmcprt_table_size (struct genz_control_info *ci);

ssize_t genz_mcprt_msmcptr_row_size (struct genz_control_info *ci);

ssize_t genz_mvcat_table_size (struct genz_control_info *ci);

ssize_t genz_media_log_table_size (struct genz_control_info *ci);

ssize_t genz_oem_data_table_size (struct genz_control_info *ci);

ssize_t genz_opcode_set_table_size (struct genz_control_info *ci);

ssize_t genz_opcode_set_uuid_table_size (struct genz_control_info *ci);

ssize_t genz_pa_table_size (struct genz_control_info *ci);

ssize_t genz_pm_backup_table_size (struct genz_control_info *ci);

ssize_t genz_pte_restricted_pte_table_size (struct genz_control_info *ci);

ssize_t genz_page_grid_restricted_page_grid_table_size (struct genz_control_info *ci);

ssize_t genz_page_table_pointer_pair_table_entry_size (struct genz_control_info *ci);

ssize_t genz_performance_log_record_0_size (struct genz_control_info *ci);

ssize_t genz_performance_log_record_1_size (struct genz_control_info *ci);

ssize_t genz_re_table_size (struct genz_control_info *ci);

ssize_t genz_rit_table_size (struct genz_control_info *ci);

ssize_t genz_reliable_multicast_responder_table_size (struct genz_control_info *ci);

ssize_t genz_reliable_multicast_table_size (struct genz_control_info *ci);

ssize_t genz_reliable_multicast_table_entry_row_size (struct genz_control_info *ci);

ssize_t genz_requester_vcat_table_size (struct genz_control_info *ci);

ssize_t genz_resource_table_size (struct genz_control_info *ci);

ssize_t genz_responder_vcat_table_size (struct genz_control_info *ci);

ssize_t genz_route_control_table_size (struct genz_control_info *ci);

ssize_t genz_sm_backup_table_size (struct genz_control_info *ci);

ssize_t genz_ssap_mcap_msap_and_msmcap_table_size (struct genz_control_info *ci);

ssize_t genz_ssdt_msdt_table_size (struct genz_control_info *ci);

ssize_t genz_ssod_msod_table_size (struct genz_control_info *ci);

ssize_t genz_service_uuid_table_size (struct genz_control_info *ci);

ssize_t genz_tr_table_size (struct genz_control_info *ci);

ssize_t genz_type_1_interleave_table_size (struct genz_control_info *ci);

ssize_t genz_unreliable_multicast_table_size (struct genz_control_info *ci);

ssize_t genz_unreliable_multicast_table_entry_row_size (struct genz_control_info *ci);

ssize_t genz_vcat_table_size (struct genz_control_info *ci);


union genz_control_structure {
    struct genz_control_ptr_info control_ptr_info_ptr;
    struct genz_control_structure_ptr control_structure_ptr_ptr;
    struct genz_component_rkd_structure_array component_rkd_structure_array_ptr;
    struct genz_component_lpd_structure_array component_lpd_structure_array_ptr;
    struct genz_component_event_structure_array component_event_structure_array_ptr;
    struct genz_service_uuid_structure_array service_uuid_structure_array_ptr;
    struct genz_vendor_defined_with_uuid_structure_array vendor_defined_with_uuid_structure_array_ptr;
    struct genz_vendor_defined_structure_array vendor_defined_structure_array_ptr;
    struct genz_interface_statistics_structure_array interface_statistics_structure_array_ptr;
    struct genz_interface_phy_structure_array interface_phy_structure_array_ptr;
    struct genz_unreliable_multicast_table_array unreliable_multicast_table_array_ptr;
    struct genz_type_1_interleave_table_array_array type_1_interleave_table_array_array_ptr;
    struct genz_type_1_interleave_table_array type_1_interleave_table_array_ptr;
    struct genz_tr_table_array tr_table_array_ptr;
    struct genz_service_uuid_table_array_array service_uuid_table_array_array_ptr;
    struct genz_service_uuid_table_array service_uuid_table_array_ptr;
    struct genz_ssdt_msdt_table_array_array ssdt_msdt_table_array_array_ptr;
    struct genz_sm_backup_table_array sm_backup_table_array_ptr;
    struct genz_reliable_multicast_table_array reliable_multicast_table_array_ptr;
    struct genz_reliable_multicast_responder_table_array reliable_multicast_responder_table_array_ptr;
    struct genz_rit_table_array rit_table_array_ptr;
    struct genz_re_table_array re_table_array_ptr;
    struct genz_page_grid_restricted_page_grid_table_array page_grid_restricted_page_grid_table_array_ptr;
    struct genz_pm_backup_table_array pm_backup_table_array_ptr;
    struct genz_pa_table_array pa_table_array_ptr;
    struct genz_oem_data_table_array oem_data_table_array_ptr;
    struct genz_media_log_table_array media_log_table_array_ptr;
    struct genz_mvcat_table_array mvcat_table_array_ptr;
    struct genz_label_data_table_array label_data_table_array_ptr;
    struct genz_lprt_mprt_table_array_array lprt_mprt_table_array_array_ptr;
    struct genz_image_table_array image_table_array_ptr;
    struct genz_firmware_table_array firmware_table_array_ptr;
    struct genz_elog_table_array log_table_array_ptr;
    struct genz_c_access_r_key_table_array c_access_r_key_table_array_ptr;
    struct genz_c_access_l_p2p_table_array c_access_l_p2p_table_array_ptr;
    struct genz_hardware_classes hardware_classes_ptr;
    struct genz_core_structure core_structure_ptr;
    struct genz_opcode_set_structure opcode_set_structure_ptr;
    struct genz_interface_structure interface_structure_ptr;
    struct genz_interface_phy_structure interface_phy_structure_ptr;
    struct genz_interface_statistics_structure interface_statistics_structure_ptr;
    struct genz_component_error_and_signal_event_structure component_error_and_signal_event_structure_ptr;
    struct genz_component_media_structure component_media_structure_ptr;
    struct genz_component_switch_structure component_switch_structure_ptr;
    struct genz_component_statistics_structure component_statistics_structure_ptr;
    struct genz_component_extension_structure component_extension_structure_ptr;
    struct genz_vendor_defined_structure vendor_defined_structure_ptr;
    struct genz_vendor_defined_with_uuid_structure vendor_defined_with_uuid_structure_ptr;
    struct genz_component_multicast_structure component_multicast_structure_ptr;
    struct genz_component_tr_structure component_tr_structure_ptr;
    struct genz_component_image_structure component_image_structure_ptr;
    struct genz_component_precision_time_structure component_precision_time_structure_ptr;
    struct genz_component_mechanical_structure component_mechanical_structure_ptr;
    struct genz_component_destination_table_structure component_destination_table_structure_ptr;
    struct genz_service_uuid_structure service_uuid_structure_ptr;
    struct genz_component_c_access_structure component_c_access_structure_ptr;
    struct genz_requester_p2p_structure requester_p2p_structure_ptr;
    struct genz_component_pa_structure component_pa_structure_ptr;
    struct genz_component_event_structure component_event_structure_ptr;
    struct genz_component_lpd_structure component_lpd_structure_ptr;
    struct genz_component_sod_structure component_sod_structure_ptr;
    struct genz_congestion_management_structure congestion_management_structure_ptr;
    struct genz_component_rkd_structure component_rkd_structure_ptr;
    struct genz_component_pm_structure component_pm_structure_ptr;
    struct genz_component_atp_structure component_atp_structure_ptr;
    struct genz_component_re_table_structure component_re_table_structure_ptr;
    struct genz_component_lph_structure component_lph_structure_ptr;
    struct genz_component_page_grid_structure component_page_grid_structure_ptr;
    struct genz_component_page_table_structure component_page_table_structure_ptr;
    struct genz_component_interleave_structure component_interleave_structure_ptr;
    struct genz_component_firmware_structure component_firmware_structure_ptr;
    struct genz_component_sw_management_structure component_sw_management_structure_ptr;
    struct genz_backup_mgmt_table backup_mgmt_table_ptr;
    struct genz_component_error_elog_entry component_error_elog_entry_ptr;
    struct genz_core_lpd_bdf_table core_lpd_bdf_table_ptr;
    struct genz_elog_table log_table_ptr;
    struct genz_event_record vent_record_ptr;
    struct genz_image_format_0xc86ed8c24bed49bda5143dd11950de9d_header_format image_format_0xc86ed8c24bed49bda5143dd11950de9d_header_format_ptr;
    struct genz_interface_error_elog_entry interface_error_elog_entry_ptr;
    struct genz_label_data_table label_data_table_ptr;
    struct genz_mcprt_msmcprt_table mcprt_msmcprt_table_ptr;
    struct genz_mcprt_msmcptr_row mcprt_msmcptr_row_ptr;
    struct genz_oem_data_table oem_data_table_ptr;
    struct genz_opcode_set_table opcode_set_table_ptr;
    struct genz_opcode_set_uuid_table opcode_set_uuid_table_ptr;
    struct genz_pm_backup_table pm_backup_table_ptr;
    struct genz_pte_restricted_pte_table pte_restricted_pte_table_ptr;
    struct genz_page_table_pointer_pair_table_entry page_table_pointer_pair_table_entry_ptr;
    struct genz_performance_log_record_0 performance_log_record_0_ptr;
    struct genz_performance_log_record_1 performance_log_record_1_ptr;
    struct genz_reliable_multicast_table_entry_row reliable_multicast_table_entry_row_ptr;
    struct genz_requester_vcat_table requester_vcat_table_ptr;
    struct genz_resource_table resource_table_ptr;
    struct genz_responder_vcat_table responder_vcat_table_ptr;
    struct genz_route_control_table route_control_table_ptr;
    struct genz_sm_backup_table sm_backup_table_ptr;
    struct genz_ssap_mcap_msap_and_msmcap_table ssap_mcap_msap_and_msmcap_table_ptr;
    struct genz_ssod_msod_table ssod_msod_table_ptr;
    struct genz_unreliable_multicast_table_entry_row unreliable_multicast_table_entry_row_ptr;
    struct genz_vcat_table vcat_table_ptr;
};
#endif
