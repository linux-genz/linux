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

/* Gen-Z Component Structure */
enum {
	GENZ_A_UNSPEC,
	GENZ_A_FABRIC_NUM,
	GENZ_A_GCID,
	GENZ_A_CCLASS,
	GENZ_A_FRU_UUID,
	GENZ_A_MGR_UUID,
	GENZ_A_RESOURCE_LIST,
	__GENZ_A_MAX,
};
#define GENZ_A_MAX (__GENZ_A_MAX - 1)

/* Resource List Structure */
enum {
	GENZ_A_UL_UNSPEC,
	GENZ_A_UL,
	__GENZ_A_UL_MAX,
};
#define GENZ_A_UL_MAX (__GENZ_A_UL_MAX - 1)

/* Resource Structure */
enum {
	GENZ_A_U_UNSPEC,
	GENZ_A_U_CLASS_UUID,
	GENZ_A_U_INSTANCE_UUID,
	GENZ_A_U_CLASS,
	GENZ_A_U_MRL,
	__GENZ_A_U_MAX,
};
#define GENZ_A_U_MAX (__GENZ_A_U_MAX - 1)

/* Memory Region List Structure */
enum {
	GENZ_A_MRL_UNSPEC,
	GENZ_A_MRL,
	__GENZ_A_MRL_MAX,
};
#define GENZ_A_MRL_MAX (__GENZ_A_MRL_MAX - 1)

/* Memory Region Structure */
enum {
	GENZ_A_MR_UNSPEC,
	GENZ_A_MR_START,
	GENZ_A_MR_LENGTH,
	GENZ_A_MR_TYPE,
	GENZ_A_MR_RO_RKEY,
	GENZ_A_MR_RW_RKEY,
	__GENZ_A_MR_MAX,
};
#define GENZ_A_MR_MAX (__GENZ_A_MR_MAX - 1)

#define GENZ_CONTROL_STR_LEN	12
#define GENZ_DATA_STR_LEN	9

/* Netlink Generic Commands */

/* Netlink Generic Commands */
enum {
	GENZ_C_ADD_OS_COMPONENT,
	GENZ_C_REMOVE_OS_COMPONENT,
	GENZ_C_SYMLINK_OS_COMPONENT,
	GENZ_C_FAB_MGR_CTL_WR_MSG,
	GENZ_C_ADD_FABRIC_COMPONENT,
	GENZ_C_REMOVE_FABRIC_COMPONENT,
	__GENZ_C_MAX,
};
#define GENZ_C_MAX (__GENZ_C_MAX - 1)

#define UUID_LEN	16	/* 16 uint8_t's */

#define NLINK_MSG_LEN 1024
#define GENZ_FAMILY_NAME "genz_cmd"

int genz_nl_init(void);
void genz_nl_exit(void);
void genz_free_zres(struct genz_dev *zdev, struct genz_zres *zres);
int genz_setup_zres(struct genz_zres *zres, struct genz_dev *zdev,
		int cdtype, int iores_flags, int str_len,
		char *fmt, struct list_head *cd_zres_list);
struct genz_zres *genz_alloc_and_add_zres(struct genz_dev *zdev);
