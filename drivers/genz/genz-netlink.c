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

#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/skbuff.h>
#include "genz-netlink.h"


/* Netlink Generic Attribute Policy */
const static struct nla_policy genz_genl_policy[GENZ_A_MAX + 1] = {
	[GENZ_A_FABRIC_NUM] = { .type = NLA_U32 },
	[GENZ_A_GCID] = { .type = NLA_U32 },
	[GENZ_A_CCLASS] = { .type = NLA_U16 },
	[GENZ_A_FRU_UUID] = { .len = UUID_LEN },
	[GENZ_A_RESOURCE_LIST] = { .type = NLA_NESTED },
};

const static struct nla_policy genz_genl_uuid_list_policy[GENZ_A_UL_MAX + 1] = {
	[GENZ_A_UL] = { .type = NLA_NESTED },
};

const static struct nla_policy genz_genl_resource_policy[GENZ_A_U_MAX + 1] = {
	[GENZ_A_U_UUID] = { .len = UUID_LEN },
	[GENZ_A_U_MRL] = { .type = NLA_NESTED },
};

const static struct nla_policy genz_genl_mr_list_policy[GENZ_A_MRL_MAX + 1] = {
	[GENZ_A_MRL] = { .type = NLA_NESTED },
};

const static struct nla_policy genz_genl_mem_region_policy[GENZ_A_MR_MAX + 1] = {
	[GENZ_A_MR_START] = { .type = NLA_U64 },
	[GENZ_A_MR_LENGTH] = { .type = NLA_U64 },
	[GENZ_A_MR_TYPE] = { .type = NLA_U8 },
	[GENZ_A_MR_RO_RKEY] = { .type = NLA_U32 },
	[GENZ_A_MR_RW_RKEY] = { .type = NLA_U32 },
};

static int parse_mr_list(const struct nlattr * mr_list)
{
	struct nlattr *nested_attr;
	struct nlattr *mr_attrs[GENZ_A_MR_MAX + 1];
	int ret = 0;
	int rem;
	uint64_t mem_start = -1U;
	uint64_t mem_len = -1U;
	/* Revisit: change type to bool or byte? */
	uint32_t mem_type = -1U;
	uint32_t ro_rkey = -1U;
	uint32_t rw_rkey = -1U;
	struct netlink_ext_ack extack;

	printk(KERN_INFO "\t\tMemory Region List:\n");
	/* Go through the nested list of memory region structures */
	nla_for_each_nested(nested_attr,  mr_list, rem) {
		/* Revisit: learn about netlink_ext_ack */
		/* Extract the nested Memory Region structure */
		ret = nla_parse_nested(mr_attrs, GENZ_A_MR_MAX,
			nested_attr, genz_genl_mem_region_policy, &extack);
		if (ret < 0) {
			printk(KERN_ERR "nla_parse_nested returned %d\n", ret);	
		}
		if (mr_attrs[GENZ_A_MR_START]) {
			mem_start = nla_get_u64(mr_attrs[GENZ_A_MR_START]);
		}
		if (mr_attrs[GENZ_A_MR_LENGTH]) {
			mem_len = nla_get_u64(mr_attrs[GENZ_A_MR_LENGTH]);
		}
		if (mr_attrs[GENZ_A_MR_TYPE]) {
			mem_type = nla_get_u8(mr_attrs[GENZ_A_MR_TYPE]);
		}
		if (mr_attrs[GENZ_A_MR_RO_RKEY]) {
			ro_rkey = nla_get_u32(mr_attrs[GENZ_A_MR_RO_RKEY]);
		}
		if (mr_attrs[GENZ_A_MR_RW_RKEY]) {
			rw_rkey = nla_get_u32(mr_attrs[GENZ_A_MR_RW_RKEY]);
		}
		printk(KERN_INFO "\t\t\tMR_START: 0x%llx\n\t\t\t\tMR_LENGTH: %lld\n\t\t\t\tMR_TYPE: %s\n\t\t\t\tRO_RKEY: 0x%x\n\t\t\t\tRW_KREY 0x%x\n", mem_start, mem_len, (mem_type == GENZ_DATA ? "DATA":"CONTROL"), ro_rkey, rw_rkey);
	}
	printk(KERN_INFO "\t\tend of Memory Region List\n");
	return ret;
}

static int parse_resource_list(const struct nlattr * resource_list)
{
	struct nlattr *nested_attr;
	struct nlattr *u_attrs[GENZ_A_U_MAX + 1];
	int ret = 0;
	int rem;
	struct netlink_ext_ack extack;

	printk(KERN_INFO "\tRESOURCE_LIST:\n");

	/* Go through the nested list of UUID structures */
	nla_for_each_nested(nested_attr, resource_list, rem) {

		/* Extract the nested UUID structure */
		ret = nla_parse_nested(u_attrs, GENZ_A_U_MAX,
			nested_attr, genz_genl_resource_policy, &extack);
		if (ret < 0) {
			printk(KERN_ERR "nla_parse_nested of UUID list returned %d\n", ret);	
		}
		if (u_attrs[GENZ_A_U_UUID]) {
			uint8_t * uuid;
			
			uuid = nla_data(u_attrs[GENZ_A_U_UUID]);
			printk(KERN_INFO "\t\tUUID: %pUL\n", uuid);
		}
		if (u_attrs[GENZ_A_U_MRL]) {
			ret = parse_mr_list(u_attrs[GENZ_A_U_MRL]);
			if (ret) {
				printk(KERN_ERR "\tparse of MRL failed\n");
			}
		}
	}
	printk(KERN_INFO "\tend of RESOURCE_LIST\n");
	return ret;
}

/* Netlink Generic Handler */
static int genz_add_component(struct sk_buff *skb, struct genl_info *info)
{
	/*
	 * message handling code goes here; return 0 on success,
	 * negative value on failure.
	 */
	if (info->attrs[GENZ_A_FABRIC_NUM]) {
		printk(KERN_INFO "Port: %u\n\tFABRIC_NUM: %d", info->snd_portid,
			nla_get_u32(info->attrs[GENZ_A_FABRIC_NUM]));
	}

	if (info->attrs[GENZ_A_GCID]) {
		printk(KERN_INFO "\tGCID: %d ",
			nla_get_u32(info->attrs[GENZ_A_GCID]));
	}

	if (info->attrs[GENZ_A_CCLASS]) {
		printk(KERN_INFO "\tC-Class = %d\n",
			(uint32_t) nla_get_u32(info->attrs[GENZ_A_CCLASS]));
	}
	if (info->attrs[GENZ_A_FRU_UUID]) {
		uint8_t * fru_uuid;
			
		fru_uuid = nla_data(info->attrs[GENZ_A_FRU_UUID]);
		printk(KERN_INFO "\tFRU_UUID: %pUL\n", fru_uuid);
	}
	if (info->attrs[GENZ_A_RESOURCE_LIST]) {
		parse_resource_list(info->attrs[GENZ_A_RESOURCE_LIST]);
	}
	return 0;
}

static int genz_remove_component(struct sk_buff *skb, struct genl_info *info)
{
	/*
	 * message handling code goes here; return 0 on success,
	 * negative value on failure.
	 */
	return 0;
}

static int genz_symlink_component(struct sk_buff *skb, struct genl_info *info)
{
	/*
	 * message handling code goes here; return 0 on success,
	 * negative value on failure.
	 */
	return 0;
}


/* Netlink Generic Operations */
static struct genl_ops genz_gnl_ops[] = {
	{
	.cmd = GENZ_C_ADD_COMPONENT,
	.doit = genz_add_component,
	},
	{
	.cmd = GENZ_C_REMOVE_COMPONENT,
	.doit = genz_remove_component,
	},
	{
	.cmd = GENZ_C_SYMLINK_COMPONENT,
	.doit = genz_symlink_component,
	},
};

/* Netlink Generic Family Definition */
static struct genl_family genz_gnl_family = {
	.hdrsize = 0,
	.name = GENZ_FAMILY_NAME,
	.version = 1,
	.maxattr = GENZ_A_MAX,
	.ops = genz_gnl_ops,
	.n_ops = ARRAY_SIZE(genz_gnl_ops)
};


int genz_nl_init(void)
{
	int ret;

	printk(KERN_INFO "Entering: %s\n",__FUNCTION__);
	ret = genl_register_family(&genz_gnl_family);
	if (ret != 0) {
		printk(KERN_INFO "genl_register_family returned %d\n", ret);
		return -1;
	}
	return 0;
}

void genz_nl_exit(void)
{
	printk(KERN_INFO "exiting nl module\n");
	genl_unregister_family(&genz_gnl_family);
}
