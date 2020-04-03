/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
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

#include "genz.h"

int genz_create_gcid_file(struct kobject *kobj);
int genz_create_cclass_file(struct kobject *kobj);
int genz_create_uuid_file(struct genz_dev *zdev);
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
void genz_remove_uuid_file(struct genz_dev *zdev);
int genz_control_read_structure(struct genz_dev *zdev,
		void *buf, off_t cs_offset,
		off_t field_offset, size_t field_size);
void *genz_control_structure_buffer_alloc(
		enum genz_control_structure_type stype, int flags);
int genz_control_read_cid0(struct genz_dev *zdev, uint16_t *cid0);
int genz_control_read_sid(struct genz_dev *zdev, uint16_t *sid);
int genz_control_read_cclass(struct genz_dev *zdev, uint16_t *cclass);
int genz_control_read_fru_uuid(struct genz_dev *zdev, uuid_t *fru_uuid);
