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
#include <linux/ioport.h> /* for resource type IORESOURCE_GENZ_CONTROL */
#include "genz.h"
#include "genz-netlink.h"
#include "genz-probe.h"
#include "genz-control.h"
#include "genz-sysfs.h"


/* Netlink Generic Attribute Policy */
const static struct nla_policy genz_genl_policy[GENZ_A_MAX + 1] = {
	[GENZ_A_FABRIC_NUM] = { .type = NLA_U32 },
	[GENZ_A_GCID] = { .type = NLA_U32 },
	[GENZ_A_CCLASS] = { .type = NLA_U16 },
	[GENZ_A_FRU_UUID] = { .len = UUID_LEN },
	[GENZ_A_MGR_UUID] = { .len = UUID_LEN },
	[GENZ_A_RESOURCE_LIST] = { .type = NLA_NESTED },
};

const static struct nla_policy genz_genl_uuid_list_policy[GENZ_A_UL_MAX + 1] = {
	[GENZ_A_UL] = { .type = NLA_NESTED },
};

const static struct nla_policy genz_genl_resource_policy[GENZ_A_U_MAX + 1] = {
	[GENZ_A_U_UUID] = { .len = UUID_LEN },
	[GENZ_A_U_CLASS] = { .type = NLA_U16 },
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

static struct genz_resource * alloc_and_add_zres(struct genz_dev *zdev)
{
	struct genz_resource *zr;

	zr = kzalloc(sizeof(*zr), GFP_KERNEL);
	if (!zr)
		return NULL;
	list_add_tail(&zr->zres_list, &zdev->zres_list);
	return(zr);
}

static int genz_free_zres(struct genz_dev *zdev, struct genz_resource *zres)
{
	/* free the name */
	kfree(zres->res.name);
	/* remove the zres from the zdev res_list */
	/* remove the zres from the appropriate component list */
	/* free the zres */
}

static int parse_mr_list(struct genz_dev *zdev, const struct nlattr * mr_list)
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
	struct genz_resource *zres;

	printk(KERN_INFO "\t\tMemory Region List:\n");
	/* Go through the nested list of memory region structures */
	nla_for_each_nested(nested_attr,  mr_list, rem) {
		/* Revisit: learn about netlink_ext_ack */
		/* Extract the nested Memory Region structure */
		ret = nla_parse_nested_deprecated(mr_attrs, GENZ_A_MR_MAX,
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
		zres = alloc_and_add_zres(zdev);
		if (zres != NULL) {
			zres->res.start = mem_start;
			zres->res.end = mem_start + mem_len -1;
			zres->res.desc = IORES_DESC_NONE;
			zres->ro_rkey = ro_rkey;
			zres->rw_rkey = rw_rkey;
			if (mem_type == GENZ_CONTROL) {
				zres->res.name = kzalloc(GENZ_CONTROL_STR_LEN,
							GFP_KERNEL);
				if (zres->res.name == NULL) {
					printk(KERN_ERR "Failed to kmalloc res->name\n");
				}
				snprintf(zres->res.name, GENZ_CONTROL_STR_LEN,
					"control%d",
					zdev->resource_count[GENZ_CONTROL]++);
	
				list_add_tail(&zres->component_list,
					&zdev->zcomp->control_zres_list);
			}
			else if (mem_type == GENZ_DATA) {
				zres->res.name = kzalloc(GENZ_DATA_STR_LEN,
							GFP_KERNEL);
				if (zres->res.name == NULL) {
					printk(KERN_ERR "Failed to kmalloc res->name\n");
				}
				snprintf(zres->res.name, GENZ_DATA_STR_LEN,
					"data%d",
					zdev->resource_count[GENZ_DATA]++);
				list_add_tail(&zres->component_list,
					&zdev->zcomp->data_zres_list);
			}
			ret = genz_create_attr(zdev, zres);
			if (ret) {
				printk(KERN_INFO "%s: genz_create_attr failed with %d\n", __FUNCTION__, ret);
			}
			/* Revisit: how to get the parent resource?
			ret = insert_resource(&zres->res, &zdev->parent_res);
			if (ret < 0) {
				printk(KERN_INFO "%s: insert_resource failed with %d\n", __FUNCTION__, ret);
			}
			*/
			/* Add this resource to the genz_dev's list */
			list_add_tail(&zres->zres_list, &zdev->zres_list);
		}	
		printk(KERN_INFO "\t\t\tMR_START: 0x%llx\n\t\t\t\tMR_LENGTH: %lld\n\t\t\t\tMR_TYPE: %s\n\t\t\t\tRO_RKEY: 0x%x\n\t\t\t\tRW_KREY 0x%x\n", mem_start, mem_len, (mem_type == GENZ_DATA ? "DATA":"CONTROL"), ro_rkey, rw_rkey);
	}
	printk(KERN_INFO "\t\tend of Memory Region List\n");
	return ret;
}

static int parse_resource_list(const struct nlattr * resource_list,
	struct genz_component *zcomp)
{
	struct nlattr *nested_attr;
	struct nlattr *u_attrs[GENZ_A_U_MAX + 1];
	int ret = 0;
	int rem;
	struct netlink_ext_ack extack;
	struct genz_fabric *fabric;
	struct genz_dev *zdev;

	fabric = genz_find_fabric(zcomp->subnet->fabric->number);
	if (!fabric)  {
		printk(KERN_ERR "genz_find_fabric failed\n");
		return -ENOMEM;
	}
	printk(KERN_INFO "\tRESOURCE_LIST:\n");
	/* Go through the nested list of UUID structures */
	nla_for_each_nested(nested_attr, resource_list, rem) {
		zdev = genz_alloc_dev(fabric);
		if (!zdev)  {
			/* Revisit: clean up fabric? */
			return -ENOMEM;
		}
		zdev->zcomp = zcomp;

		/* Extract the nested UUID structure */
		ret = nla_parse_nested_deprecated(u_attrs, GENZ_A_U_MAX,
			nested_attr, genz_genl_resource_policy, &extack);
		if (ret < 0) {
			printk(KERN_ERR "nla_parse_nested of UUID list returned %d\n", ret);	
		}
		if (u_attrs[GENZ_A_U_UUID]) {
			uint8_t * uuid;
			char *	uuid_name;
			int	u;

			uuid = nla_data(u_attrs[GENZ_A_U_UUID]);
			/* use the UUID as the device name */
			/* Revisit: when to free this name??? */
			uuid_name = kmalloc(UUID_STRING_LEN+1, GFP_KERNEL);
			if (!uuid_name) {
				printk(KERN_ERR "kmalloc of uuid_name failed\n");
				goto error;
			}
				
			snprintf(uuid_name, UUID_STRING_LEN + 1, "%pUb", uuid);
			/* convert to uuid_t */
			u = uuid_parse(uuid_name, &zdev->uuid);
			if (u) {
				printk(KERN_ERR "uuid_parse failed for resource uuid %pUb\n", (void *) uuid);
			}
			printk(KERN_INFO "\t\tUUID: %pUb\n", (void *) uuid);
			
		}
		if (u_attrs[GENZ_A_U_CLASS]) {
			int condensed_class;

			zdev->class = nla_get_u16(u_attrs[GENZ_A_U_CLASS]);
			printk(KERN_DEBUG "\t\tClass = %d\n",
				(uint32_t) zdev->class);
			if (zdev->class > HARDWARE_TYPES_MAX) {
				printk(KERN_ERR "%s: hardware CLASS invalid %d\n", __FUNCTION__, zdev->class);
				ret = -EINVAL;
				goto error;
			}
			/*
			 * The class is used as the device name along with 
			 * the count of that type of class. e.g. "memory0"
			 */
			condensed_class = hardware_classes[zdev->class].value;
			dev_set_name(&zdev->dev, "%s%d",
				hardware_classes[zdev->class].condensed_name,
				zdev->zcomp->resource_count[condensed_class]++);
		} else {
			printk(KERN_ERR "%s: missing required CLASS\n", __FUNCTION__);
			ret = -EINVAL;
			goto error;
		}
		ret = genz_device_add(zdev);
		if (ret) {
			printk(KERN_ERR "\tgenz_device_add failed with %d\n", ret);
		}
		ret = genz_create_uuid_file(zdev);
		if (ret) {
			printk(KERN_ERR "\tgenz_create_uuid_file failed with %d\n", ret);
		}
		if (u_attrs[GENZ_A_U_MRL]) {
			ret = parse_mr_list(zdev, u_attrs[GENZ_A_U_MRL]);
			if (ret) {
				printk(KERN_ERR "\tparse of MRL failed\n");
			}
		}
		if (ret) {
			printk(KERN_ERR "\tgenz_device_add failed with %d\n", ret);
			/* Revisit: more clean up here */
		}
	}
	printk(KERN_INFO "\tend of RESOURCE_LIST\n");
error:
	return ret;
}

/* Netlink Generic Handler */
static int genz_add_os_component(struct sk_buff *skb, struct genl_info *info)
{
	struct genz_component *zcomp = NULL;
	uint32_t fabric_num, gcid;
	int ret = 0;
	struct genz_fabric *f;
	struct genz_subnet *s;

	if (info->attrs[GENZ_A_FABRIC_NUM]) {
		fabric_num = nla_get_u32(info->attrs[GENZ_A_FABRIC_NUM]);
		printk(KERN_DEBUG "Port: %u\n\tFABRIC_NUM: %d",
			info->snd_portid, fabric_num);
	} else {
		printk(KERN_ERR "%s: missing required fabric number\n", __FUNCTION__);
		return -EINVAL;
	}
	f = genz_find_fabric(fabric_num);
	if (f == NULL) {
		printk(KERN_ERR "%s: failed to find fabric %d\n", __FUNCTION__, fabric_num);
		return -EINVAL;
	}

	if (info->attrs[GENZ_A_GCID]) {
		gcid = nla_get_u32(info->attrs[GENZ_A_GCID]);
		printk(KERN_DEBUG "\tGCID: %d ", gcid);
	} else {
		printk(KERN_ERR "%s: missing required GCID\n", __FUNCTION__);
		return -EINVAL;
	}
	/* Revisit: add a find_component() */
	s = genz_find_subnet(genz_get_sid(gcid), f);
	zcomp = genz_alloc_component();
	if (zcomp == NULL) {
		printk(KERN_ERR "%s: genz_alloc_component failed\n", __FUNCTION__);
		return -ENOMEM;
	}
	ret = genz_init_component(zcomp, s, genz_get_cid(gcid));
	if (ret) {
		printk(KERN_ERR "%s: genz_init_component failed with %d\n", __FUNCTION__, ret);
		return -ret;
	}
 
/*
	ret = genz_create_gcid_file(&(zcomp->kobj));
*/
	if (ret) {
		printk(KERN_ERR "%s: genz_create_gcid_file failed\n", __FUNCTION__);
		return -EINVAL;
	}

	if (info->attrs[GENZ_A_CCLASS]) {
		zcomp->cclass = nla_get_u16(info->attrs[GENZ_A_CCLASS]);
		printk(KERN_DEBUG "\tC-Class = %d\n",
			(uint32_t) zcomp->cclass);
	} else {
		printk(KERN_ERR "%s: missing required CCLASS\n", __FUNCTION__);
		ret = -EINVAL;
		goto err;
	}
/*
	ret = genz_create_cclass_file(&(zcomp->kobj));
*/

	if (info->attrs[GENZ_A_FRU_UUID]) {
		char uuid_str[UUID_STRING_LEN+1];
		int u;
	
		snprintf(uuid_str, UUID_STRING_LEN + 1, "%pUb", 
				 nla_data(info->attrs[GENZ_A_FRU_UUID]));
		u = uuid_parse(uuid_str, &zcomp->fru_uuid);
		if (u)
			printk(KERN_ERR "invalid fru uuid\n");
		else
			printk(KERN_DEBUG "\tFRU_UUID: %pUb\n", &zcomp->fru_uuid);
	} else {
		printk(KERN_ERR "%s: missing required FRU_UUID\n", __FUNCTION__);
		ret = -EINVAL;
		goto err;
	}
/*
	ret = genz_create_fru_uuid_file(&(zcomp->kobj));
*/

	if (info->attrs[GENZ_A_MGR_UUID]) {
		char uuid_str[UUID_STRING_LEN+1];
		int u;
	
		snprintf(uuid_str, UUID_STRING_LEN + 1, "%pUb", 
				 nla_data(info->attrs[GENZ_A_MGR_UUID]));
		u = uuid_parse(uuid_str, &f->mgr_uuid);
		if (u)
			printk(KERN_ERR "invalid mgr uuid\n");
		else
			printk(KERN_DEBUG "\tMGR_UUID: %pUb\n", &f->mgr_uuid);
	} else {
		printk(KERN_ERR "%s: missing required MGR_UUID\n", __FUNCTION__);
		ret = -EINVAL;
		goto err;
	}
	ret = genz_create_mgr_uuid_file(&f->dev);
	if (ret) {
		printk(KERN_ERR "%s: genz_create_mgr_uuid_file failed\n", __FUNCTION__);
		return -EINVAL;
	}
	if (info->attrs[GENZ_A_RESOURCE_LIST]) {
		ret = parse_resource_list(info->attrs[GENZ_A_RESOURCE_LIST],
			zcomp);
		if (ret < 0) 
			goto err;
	} else {
		printk(KERN_ERR "%s: Must supply at least one resource\n", __FUNCTION__);
		ret = -EINVAL;
		goto err;
	}

	return ret;
err:
	if (zcomp)
		kref_put(&zcomp->kref, genz_free_component);
	return ret;
}

static int genz_remove_os_component(struct sk_buff *skb, struct genl_info *info)
{
	/*
	 * message handling code goes here; return 0 on success,
	 * negative value on failure.
	 */
	return 0;
}

static int genz_symlink_os_component(struct sk_buff *skb, struct genl_info *info)
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
	.cmd = GENZ_C_ADD_OS_COMPONENT,
	.doit = genz_add_os_component,
	},
	{
	.cmd = GENZ_C_REMOVE_OS_COMPONENT,
	.doit = genz_remove_os_component,
	},
	{
	.cmd = GENZ_C_SYMLINK_OS_COMPONENT,
	.doit = genz_symlink_os_component,
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
