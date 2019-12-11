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

struct genz_fabric *genz_find_fabric(uint32_t fabric_num);
struct genz_fabric * genz_dev_to_fabric(struct device *dev);
void genz_free_fabric(struct device *dev);
struct genz_component *genz_lookup_component(struct genz_subnet *s,
		uint32_t cid);
struct genz_component *genz_add_component(struct genz_subnet *s, uint32_t cid);
struct genz_component *genz_alloc_component(void);
int genz_init_component(struct genz_component *zcomp, struct genz_subnet *s,
		uint32_t cid);
void genz_free_component(struct kref *kref);
struct genz_dev *genz_alloc_dev(struct genz_fabric *fabric);
int genz_init_dev(struct genz_dev *zdev, struct genz_fabric *fabric);
void genz_device_initialize(struct genz_dev *zdev);
int genz_device_add(struct genz_dev *zdev);
struct genz_subnet *genz_lookup_subnet(uint32_t sid, struct genz_fabric *f);
struct genz_subnet *genz_add_subnet(uint32_t sid, struct genz_fabric *f);
int genz_device_probe(struct device *dev);
int genz_device_remove(struct device *dev);
const struct genz_device_id *genz_match_device(struct genz_driver *zdrv,
					       struct genz_dev *zdev);
void print_components(struct genz_fabric *f);
