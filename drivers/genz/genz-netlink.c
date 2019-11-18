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
	[GENZ_A_U_CLASS_UUID] = { .len = UUID_LEN },
	[GENZ_A_U_INSTANCE_UUID] = { .len = UUID_LEN },
	/* Revisit: add serial number? */
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

static struct genz_resource *alloc_and_add_zres(struct genz_dev *zdev)
{
	struct genz_resource *zr;

	zr = kzalloc(sizeof(*zr), GFP_KERNEL);
	if (!zr)
		return NULL;
	list_add_tail(&zr->zres_list, &zdev->zres_list);
	return(zr);
}

void genz_free_zres(struct genz_dev *zdev, struct genz_resource *zres)
{
	genz_remove_attr(zdev, zres);
	list_del(&zres->zres_list);
	list_del(&zres->component_list);
	kfree(zres->res.name);
	kfree(zres);
}

static int setup_zres(struct genz_resource *zres,
		struct genz_dev *zdev,
		int cdtype, int iores_flags,
		int str_len,
		char *fmt,
		struct list_head *cd_zres_list)
{
	int ret = 0;
	char *name;

	zres->res.flags = iores_flags;
	name = kzalloc(str_len, GFP_KERNEL);
	if (name == NULL) {
		/* Revisit: clean up and exit */
		pr_debug("Failed to kmalloc res->name\n");
		ret = -ENOMEM;
		goto error;
	}
	snprintf(name, GENZ_CONTROL_STR_LEN, fmt,
		zdev->resource_count[cdtype]++);
	zres->res.name = name;

	list_add_tail(&zres->component_list, cd_zres_list);

error:
	return(ret);
}

static int parse_mr_list(struct genz_dev *zdev, const struct nlattr *mr_list)
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

	pr_debug("\t\tMemory Region List:\n");
	/* Go through the nested list of memory region structures */
	nla_for_each_nested(nested_attr,  mr_list, rem) {
		/* Revisit: learn about netlink_ext_ack */
		/* Extract the nested Memory Region structure */
		ret = nla_parse_nested_deprecated(mr_attrs, GENZ_A_MR_MAX,
			nested_attr, genz_genl_mem_region_policy, &extack);
		if (ret < 0) {
			pr_debug("nla_parse_nested returned %d\n", ret);
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
				ret = setup_zres(zres, zdev, GENZ_CONTROL,
					(zres->res.flags | IORESOURCE_GENZ_CONTROL),
					GENZ_CONTROL_STR_LEN,
					"control%d",
					&zdev->zcomp->control_zres_list);
				if (ret)
					goto error;

			}
			else if (mem_type == GENZ_DATA) {
				ret = setup_zres(zres, zdev, GENZ_DATA,
					(zres->res.flags & ~IORESOURCE_GENZ_CONTROL),
					GENZ_DATA_STR_LEN,
					"data%d",
					&zdev->zcomp->data_zres_list);
				if (ret)
					goto error;
			}
			ret = genz_create_attr(zdev, zres);
			if (ret) {
				pr_debug("genz_create_attr failed with %d\n", ret);
				goto error;
			}
			/* Revisit: how to get the parent resource?
			ret = insert_resource(&zres->res, &zdev->parent_res);
			if (ret < 0) {
				pr_debug("insert_resource failed with %d\n", ret);
			}
			*/
			/* Add this resource to the genz_dev's list */
			list_add_tail(&zres->zres_list, &zdev->zres_list);
		}	
		pr_debug("\t\t\tMR_START: 0x%llx\n\t\t\t\tMR_LENGTH: %lld\n\t\t\t\tMR_TYPE: %s\n\t\t\t\tRO_RKEY: 0x%x\n\t\t\t\tRW_KREY 0x%x\n", mem_start, mem_len, (mem_type == GENZ_DATA ? "DATA":"CONTROL"), ro_rkey, rw_rkey);
	}
	pr_debug("\t\tend of Memory Region List\n");
error:
	return ret;
}

static void bytes_to_uuid(uuid_t *uuid, uint8_t *ub)
{
	memcpy(&uuid->b, (void *) ub, UUID_SIZE);
	return;
}

static int parse_resource_list(const struct nlattr *resource_list,
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
		pr_debug("genz_find_fabric failed\n");
		return -ENOMEM;
	}
	pr_debug("\tRESOURCE_LIST:\n");
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
			pr_debug("nla_parse_nested of UUID list returned %d\n",
				 ret);
		}
		if (u_attrs[GENZ_A_U_CLASS_UUID]) {
			uint8_t *uuid;

			uuid = nla_data(u_attrs[GENZ_A_U_CLASS_UUID]);
			bytes_to_uuid(&zdev->class_uuid, uuid);
			pr_debug("\t\tCLASS_UUID: %pUb\n", (void *) uuid);
		}
		if (u_attrs[GENZ_A_U_INSTANCE_UUID]) {
			uint8_t *uuid;

			uuid = nla_data(u_attrs[GENZ_A_U_INSTANCE_UUID]);
			bytes_to_uuid(&zdev->instance_uuid, uuid);
			pr_debug("\t\tINSTANCE_UUID: %pUb\n", (void *) uuid);
		}
		if (u_attrs[GENZ_A_U_CLASS]) {
			int condensed_class;
			const char *condensed_name;

			zdev->class = nla_get_u16(u_attrs[GENZ_A_U_CLASS]);
			pr_debug("\t\tClass = %d\n",
				(uint32_t) zdev->class);
			if (zdev->class < genz_hardware_classes_nelems) {
				condensed_class =
				      genz_hardware_classes[zdev->class].value;
				condensed_name =
				      genz_hardware_classes[zdev->class].condensed_name;
			} else {
				condensed_class = GENZ_NUM_HARDWARE_TYPES;
				condensed_name = "unknown";
			}
			/*
			 * The condensed class is used as the device name along
			 * with the count of that class. e.g. "memory0"
			 */
			/* Revisit: locking or atomic_t */
			/* Revisit: include fab#:gcid_str in dev name */
			dev_set_name(&zdev->dev, "%s%d", condensed_name,
				zdev->zcomp->resource_count[condensed_class]++);
		} else {
			pr_debug("missing required CLASS\n");
			ret = -EINVAL;
			goto error;
		}
		ret = genz_device_add(zdev);
		if (ret) {
			pr_debug("\tgenz_device_add failed with %d\n", ret);
		}
		ret = genz_create_uuid_file(zdev);
		if (ret) {
			pr_debug("\tgenz_create_uuid_file failed with %d\n", ret);
		}
		if (u_attrs[GENZ_A_U_MRL]) {
			ret = parse_mr_list(zdev, u_attrs[GENZ_A_U_MRL]);
			if (ret) {
				pr_debug("\tparse of MRL failed\n");
			}
		}
	}
	pr_debug("\tend of RESOURCE_LIST\n");
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
	struct uuid_tracker *uu;
	uuid_t mgr_uuid;

	pr_debug("genz_add_os_component\n");
	if (info->attrs[GENZ_A_MGR_UUID]) {
		uint8_t * uuid_str;

		uuid_str = nla_data(info->attrs[GENZ_A_MGR_UUID]);
		bytes_to_uuid(&mgr_uuid, uuid_str);
		pr_debug("\tMGR_UUID: %pUb\n", &mgr_uuid);
	} else {
		pr_debug("missing required MGR_UUID\n");
		ret = -EINVAL;
		goto err;
	}
        uu = genz_fabric_uuid_tracker_alloc_and_insert(&mgr_uuid);
        if (!uu) {
                return -ENOMEM;
		goto err;
        }
        fabric_num = uu->fabric->fabric_num;
        f = uu->fabric->fabric;
	if (f == NULL) {
		pr_debug("fabric %d pointer from uu_tracker is NULL\n",
			fabric_num);
		ret = -EINVAL;
		goto err;
	}

	/*
	if (info->attrs[GENZ_A_FABRIC_NUM]) {
		fabric_num = nla_get_u32(info->attrs[GENZ_A_FABRIC_NUM]);
		pr_debug("Port: %u\n\tFABRIC_NUM: %d",
			info->snd_portid, fabric_num);
	} else {
		pr_debug("missing required fabric number\n");
		return -EINVAL;
	}
	if (fabric_num > MAX_FABRIC_NUM) {
		pr_debug("fabric number is invalid\n");
		return -EINVAL;
	}
	*/
	if (info->attrs[GENZ_A_GCID]) {
		gcid = nla_get_u32(info->attrs[GENZ_A_GCID]);
		pr_debug("\tGCID: %d ", gcid);
	} else {
		pr_debug("missing required GCID\n");
		return -EINVAL;
	}
	/* validate the GCID */
	if (gcid > MAX_GCID) {
		pr_debug("GCID is invalid.\n");
		return -EINVAL;
	}
	s = genz_find_subnet(genz_get_sid(gcid), f);
	if (s == NULL) {
		pr_debug("genz_find_subnet failed\n");
		return -ENOMEM;
	}
	zcomp = genz_find_component(s, genz_get_cid(gcid));
	if (zcomp == NULL) {
		pr_debug("genz_find_component failed\n");
		return -ENOMEM;
	}
/*
	ret = genz_create_gcid_file(&(zcomp->kobj));
*/
	if (ret) {
		pr_debug("genz_create_gcid_file failed\n");
		return -EINVAL;
	}

	if (info->attrs[GENZ_A_CCLASS]) {
		zcomp->cclass = nla_get_u16(info->attrs[GENZ_A_CCLASS]);
		pr_debug("\tC-Class = %d\n",
			(uint32_t) zcomp->cclass);
	} else {
		pr_debug("missing required CCLASS\n");
		ret = -EINVAL;
		goto err;
	}
	if (zcomp->cclass > GENZ_NUM_HARDWARE_TYPES) {
		pr_debug("CCLASS invalid\n");
		ret = -EINVAL;
		goto err;
	}
/*
	ret = genz_create_cclass_file(&(zcomp->kobj));
*/

	if (info->attrs[GENZ_A_FRU_UUID]) {
		uint8_t *uuid;

		uuid = nla_data(info->attrs[GENZ_A_FRU_UUID]);
		bytes_to_uuid(&zcomp->fru_uuid, uuid);
		pr_debug("\tFRU_UUID: %pUb\n", &zcomp->fru_uuid);
	} else {
		pr_debug("missing required FRU_UUID\n");
		ret = -EINVAL;
		goto err;
	}
/*
	ret = genz_create_fru_uuid_file(&(zcomp->kobj));
*/

	ret = genz_create_mgr_uuid_file(&f->dev);
	if (ret) {
		pr_debug("genz_create_mgr_uuid_file failed\n");
		return -EINVAL;
	}
	if (info->attrs[GENZ_A_RESOURCE_LIST]) {
		ret = parse_resource_list(info->attrs[GENZ_A_RESOURCE_LIST],
			zcomp);
		if (ret < 0) 
			goto err;
	} else {
		pr_debug("Must supply at least one resource\n");
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

	pr_debug("Entering\n");
	ret = genl_register_family(&genz_gnl_family);
	if (ret != 0) {
		pr_debug("genl_register_family returned %d\n", ret);
		return -1;
	}
	return 0;
}

void genz_nl_exit(void)
{
	pr_debug("genz_nl_exit\n");
	genl_unregister_family(&genz_gnl_family);
}
