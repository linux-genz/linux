/*
 * Copyright (C) 2018-2019 Hewlett Packard Enterprise Development LP.
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

#ifndef _WILDCAT_UUID_H_
#define _WILDCAT_UUID_H_

void wildcat_generate_uuid(struct genz_bridge_dev *gzbr, uuid_t *uuid);
uint32_t wildcat_gcid_from_uuid(const uuid_t *uuid);
void wildcat_notify_remote_uuids(struct genz_mem_data *mdata);
int wildcat_common_UUID_IMPORT(struct genz_mem_data *mdata, uuid_t *uuid,
			       bool loopback, uint32_t uu_flags,
			       gfp_t alloc_flags);
int wildcat_common_UUID_FREE(struct genz_mem_data *mdata, uuid_t *uuid,
			     uint32_t *uu_flags, bool *local);
int wildcat_kernel_UUID_IMPORT(struct genz_mem_data *mdata, uuid_t *uuid,
			       uint32_t uu_flags, gfp_t alloc_flags);

static inline int wildcat_uuid_cmp(const uuid_t *u1, const uuid_t *u2)
{
	/* this must sort all UUIDs for a given GCID together, which it does
	 * because the GCID is in the first 28 bits.
	 */
	return memcmp(u1, u2, sizeof(uuid_t));
}

static inline bool wildcat_uuid_is_local(struct genz_bridge_dev *gzbr,
					 uuid_t *uuid)
{
	uint32_t gcid = genz_dev_gcid(&gzbr->zdev, 0);

	return wildcat_gcid_from_uuid(uuid) == gcid;
}

#endif /* _WILDCAT_UUID_H_ */
