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

#ifndef _WILDCAT_CONTROL_H_
#define _WILDCAT_CONTROL_H_

struct wildcat_interface_structure {
    uint64_t type                              : 12;
    uint64_t vers                              : 4;
    uint64_t size                              : 16;
    uint64_t interface_id                      : 12;
    uint64_t hvs                               : 5;
    uint64_t r0                                : 7;
    uint64_t peer_daisy_intfc_id               : 8;
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

/* Function Prototypes */
uint64_t wildcat_slink_base(struct bridge *br);
int wildcat_control_read(struct genz_dev *zdev, loff_t offset, size_t size,
			 void *data, uint flags);
int wildcat_control_write(struct genz_dev *zdev, loff_t offset, size_t size,
			  void *data, uint flags);
int wildcat_control_structure_pointers(int vers, int struct_type,
			const struct genz_control_structure_ptr **csp,
			int *num_ptrs);

#endif /* _WILDCAT_CONTROL_H_ */
