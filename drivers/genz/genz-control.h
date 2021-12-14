/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
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

#include "genz.h"

int genz_create_gcid_file(struct kobject *kobj);
int genz_create_cclass_file(struct kobject *kobj);
int genz_create_uuid_files(struct genz_dev *zdev);
int genz_create_fru_uuid_file(struct kobject *kobj);
int genz_create_mgr_uuid_file(struct device *dev);
int genz_create_sid_file(struct genz_subnet *s);
int  genz_map_core(struct genz_dev *zdev, struct genz_core_structure **core);
int genz_find_control_structure(struct genz_dev *zdev, int type, int version);
int genz_request_control_structure(struct genz_dev *zdev, int index, int type,
	int version, genz_control_cookie *cookie);
void genz_release_control_structure(struct genz_dev *zdev,
	genz_control_cookie cookie);
int genz_map_control_structure(struct genz_dev *zdev,
	genz_control_cookie cookie, size_t *size, void **ctrl_struct);
int genz_request_control_table(struct genz_dev *zdev,
	genz_control_cookie cookie, int table_offset,
	int table_prt_size, genz_control_cookie *table_cookie);
void genz_release_control_table(struct genz_dev *zdev,
	genz_control_cookie cookie);
int genz_map_control_table(struct genz_dev *zdev,
	genz_control_cookie cookie, size_t *size,
	void **control_table);
int genz_bridge_create_control_files(struct genz_bridge_dev *zbdev);
int genz_bridge_remove_control_files(struct genz_bridge_dev *zbdev);
int genz_dr_create_control_files(struct genz_bridge_dev *zbdev,
				 struct genz_comp *f_comp,
				 struct genz_comp *dr_comp,
				 uint16_t dr_iface, uuid_t *mgr_uuid);
int genz_dr_remove_control_files(struct genz_bridge_dev *zbdev,
				 struct genz_comp *f_comp,
				 struct genz_comp *dr_comp,
				 uint16_t dr_iface);
int genz_comp_read_attrs(struct genz_bridge_dev *zbdev,
			 struct genz_rmr_info *rmri, struct genz_comp *comp);
int genz_fab_create_control_files(struct genz_bridge_dev *zbdev,
				  struct genz_comp *f_comp,
				  uint16_t dr_iface, uuid_t *mgr_uuid);
int genz_fab_remove_control_files(struct genz_bridge_dev *zbdev,
				  struct genz_comp *f_comp);
void genz_remove_uuid_files(struct genz_dev *zdev);
int genz_control_read_structure(struct genz_bridge_dev *zbdev,
		struct genz_rmr_info *rmri,
		void *buf, off_t cs_offset,
		off_t field_offset, size_t field_size);
int genz_control_write_structure(struct genz_bridge_dev *zbdev,
		struct genz_rmr_info *rmri,
		void *buf, off_t cs_offset,
		off_t field_offset, size_t field_size);
void *genz_control_structure_buffer_alloc(
		enum genz_control_structure_type stype, int flags);
int genz_control_read_cid0(struct genz_bridge_dev *zbdev,
			   struct genz_rmr_info *rmri, uint16_t *cid0);
int genz_control_read_sid(struct genz_bridge_dev *zbdev,
			  struct genz_rmr_info *rmri, uint16_t *sid);
int genz_control_read_cclass(struct genz_bridge_dev *zbdev,
			     struct genz_rmr_info *rmri, uint16_t *cclass);
int genz_control_read_serial(struct genz_bridge_dev *zbdev,
			     struct genz_rmr_info *rmri, uint64_t *serial);
int genz_control_read_c_uuid(struct genz_bridge_dev *zbdev,
			     struct genz_rmr_info *rmri, uuid_t *c_uuid);
int genz_control_read_fru_uuid(struct genz_bridge_dev *zbdev,
			       struct genz_rmr_info *rmri, uuid_t *fru_uuid);
int genz_control_read_mgr_uuid(struct genz_bridge_dev *zbdev,
			       struct genz_rmr_info *rmri, uuid_t *mgr_uuid);
int genz_control_read_c_control(struct genz_bridge_dev *zbdev,
				struct genz_rmr_info *rmri, uint64_t *c_control);
int genz_control_write_c_control(struct genz_bridge_dev *zbdev,
				 struct genz_rmr_info *rmri, uint64_t c_control);
struct genz_control_info *genz_first_struct_of_type(
			    struct genz_control_info *parent, uint type);
struct genz_control_info *genz_next_struct_of_type(
			    struct genz_control_info *prev, uint type);
