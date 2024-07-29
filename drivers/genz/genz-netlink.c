// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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
const static struct nla_policy genz_genl_os_comp_policy[GENZ_A_MAX + 1] = {
	[GENZ_A_BRIDGE_GCID] = { .type = NLA_U32 },
	[GENZ_A_GCID] = { .type = NLA_U32 },
	[GENZ_A_CCLASS] = { .type = NLA_U16 },
	[GENZ_A_FRU_UUID] = { .len = UUID_LEN },
	[GENZ_A_MGR_UUID] = { .len = UUID_LEN },
	[GENZ_A_CUUID] = { .len = UUID_LEN },
	[GENZ_A_SERIAL] = { .type = NLA_U64 },
	[GENZ_A_RESOURCE_LIST] = { .type = NLA_NESTED },
};

const static struct nla_policy genz_genl_uuid_list_policy[GENZ_A_UL_MAX + 1] = {
	[GENZ_A_UL] = { .type = NLA_NESTED },
};

const static struct nla_policy genz_genl_resource_policy[GENZ_A_U_MAX + 1] = {
	[GENZ_A_U_CLASS_UUID] = { .len = UUID_LEN },
	[GENZ_A_U_INSTANCE_UUID] = { .len = UUID_LEN },
	[GENZ_A_U_REFERENCE_UUID] = { .len = UUID_LEN },
	[GENZ_A_U_FLAGS] = { .type = NLA_U64 },
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
	/* Revisit: add GENZ_A_MR_SHARED_COMPONENTS list */
};

const static struct nla_policy genz_genl_fabric_policy[GENZ_A_F_MAX + 1] = {
	[GENZ_A_F_FABRIC_UUID]   = { .len = UUID_LEN },
	[GENZ_A_F_MGR_UUID_LIST] = { .type = NLA_NESTED },
};

const static struct nla_policy genz_genl_fab_comp_policy[GENZ_A_FC_MAX + 1] = {
	[GENZ_A_FC_GCID]         = { .type = NLA_U32 },
	[GENZ_A_FC_BRIDGE_GCID]  = { .type = NLA_U32 },
	[GENZ_A_FC_TEMP_GCID]    = { .type = NLA_U32 },
	[GENZ_A_FC_DR_GCID]      = { .type = NLA_U32 },
	[GENZ_A_FC_DR_INTERFACE] = { .type = NLA_U16 },
	[GENZ_A_FC_MGR_UUID]     = { .len = UUID_LEN },
};

const static struct nla_policy genz_genl_uep_policy[GENZ_A_UEP_MAX + 1] = {
	[GENZ_A_UEP_FLAGS]       = { .type = NLA_U64 },
	[GENZ_A_UEP_MGR_UUID]    = { .len = UUID_LEN },
	[GENZ_A_UEP_BRIDGE_GCID] = { .type = NLA_U32 },
	[GENZ_A_UEP_TS_SEC]      = { .type = NLA_U64 },
	[GENZ_A_UEP_TS_NSEC]     = { .type = NLA_U64 },
	[GENZ_A_UEP_REC]         = { .len = sizeof(struct genz_uep_event_rec) },
};

static inline int check_netlink_perm(void)
{
	if (!capable(CAP_SYS_RAWIO)) {  /* Revisit: best CAP? */
		pr_debug("permission failure\n");
		return -EPERM;
	}

	return 0;
}

struct genz_zres *genz_alloc_and_add_zres(struct genz_dev *zdev)
{
	struct genz_zres *zres;

	pr_debug("zdev is %px\n", zdev);

	if (zdev == NULL) {
		pr_debug("passed a NULL zdev\n");
		return NULL;
	}
	zres = kzalloc(sizeof(struct genz_zres), GFP_KERNEL);
	pr_debug("kzalloc of zres %px\n", zres);
	if (zres == NULL)
		return NULL;
	list_add_tail(&(zres->zres_node), &(zdev->zres_list));
	return zres;
}

void genz_free_zres(struct genz_dev *zdev, struct genz_zres *zres)
{
	genz_remove_attr(zdev, zres);
	list_del(&zres->zres_node);
	kfree(zres->zres.res.name);
	kfree(zres);
}

int genz_setup_zres(struct genz_zres *zres,
		struct genz_dev *zdev,
		int cdtype, unsigned long iores_flags,
		int str_len,
		const char *fmt)
{
	int ret = 0;
	char *name;

	zres->zres.res.flags = iores_flags;
	name = kmalloc(str_len, GFP_KERNEL);
	if (name == NULL) {
		/* Revisit: clean up and exit */
		pr_debug("Failed to kmalloc res->name\n");
		ret = -ENOMEM;
		goto error;
	}
	snprintf(name, str_len, fmt,
		 genz_name(zdev),
		 zdev->resource_count[cdtype]++);  /* Revisit: atomic_t */
	zres->zres.res.name = name;
error:
	return ret;
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
	struct genz_zres *zres;
	unsigned long res_flags;
	int str_len;
	const char *fmt;

	/* Go through the nested list of memory region structures */
	nla_for_each_nested(nested_attr,  mr_list, rem) {
		/* Revisit: learn about netlink_ext_ack */
		/* Extract the nested Memory Region structure */
		ret = nla_parse_nested_deprecated(mr_attrs, GENZ_A_MR_MAX,
			nested_attr, genz_genl_mem_region_policy, &extack);
		if (ret < 0) {
			pr_debug("nla_parse_nested returned %d\n", ret);
		}
		/* mem_start is the Gen-Z fabric address needed for access */
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
		zres = genz_alloc_and_add_zres(zdev);
		if (!zres) {
			ret = -ENOMEM;
			goto error;
		}
		zres->zres.res.start = mem_start;
		zres->zres.res.end = mem_start + mem_len - 1;
		zres->zres.res.desc = IORES_DESC_NONE;
		zres->zres.ro_rkey = ro_rkey;
		zres->zres.rw_rkey = rw_rkey;
		if (!(mem_type == GENZ_CONTROL || mem_type == GENZ_DATA)) {
			pr_debug("invalid memory region mem_type %d\n",
				 mem_type);
			goto error;
		}
		if (mem_type == GENZ_CONTROL) {
			res_flags = zres->zres.res.flags |
				IORESOURCE_GENZ_CONTROL;
			str_len = strlen(genz_name(zdev)) + GENZ_CONTROL_STR_LEN;
			fmt = "%s control%d";
		} else {  /* GENZ_DATA */
			res_flags = zres->zres.res.flags &
				~IORESOURCE_GENZ_CONTROL;
			str_len = strlen(genz_name(zdev)) + GENZ_DATA_STR_LEN;
			fmt = "%s data%d";
		}
		ret = genz_setup_zres(zres, zdev, mem_type, res_flags,
				      str_len, fmt);
		if (ret) {
			pr_debug("genz_setup_zres failed with %d\n", ret);
			goto error;
		}

		pr_debug("MR_START: 0x%llx, MR_LENGTH: %lld, MR_TYPE: %s, RO_RKEY: 0x%x, RW_RKEY: 0x%x\n", mem_start, mem_len, (mem_type == GENZ_DATA ? "DATA":"CONTROL"), ro_rkey, rw_rkey);
	}
	return ret;
error:
	pr_debug("\t\tparse_mr_list failed with %d\n", ret);
	return ret;
}

static inline void bytes_to_uuid(uuid_t *uuid, uint8_t *ub)
{
	memcpy(&uuid->b, ub, UUID_SIZE);
}

static int add_resource_list(const struct nlattr *resource_list,
			     struct genz_os_comp *zcomp)
{
	struct nlattr *nested_attr;
	struct nlattr *u_attrs[GENZ_A_U_MAX + 1];
	int ret = 0;
	int rem;
	struct netlink_ext_ack extack;
	struct genz_fabric *fabric;
	struct uuid_tracker *uu;
	struct genz_dev *zdev;
	char gcstr[GCID_STRING_LEN+1];

	fabric = zcomp->subnet->subnet.fabric;
	if (!fabric)  {
		pr_debug("zcomp->subnet doesn't have a fabric yet\n");
		return -ENOENT;
	}
	pr_debug("\tRESOURCE_LIST:\n");
	/* Go through the nested list of UUID structures */
	nla_for_each_nested(nested_attr, resource_list, rem) {
		zdev = genz_alloc_dev(fabric);
		if (!zdev)  {
			/* Revisit: clean up fabric? */
			ret = -ENOMEM;
			goto err;
		}
		zdev->zcomp = zcomp;

		/* Extract the nested UUID structure */
		ret = nla_parse_nested_deprecated(u_attrs, GENZ_A_U_MAX,
			nested_attr, genz_genl_resource_policy, &extack);
		if (ret < 0) {
			pr_debug("nla_parse_nested of UUID list returned %d\n",
				 ret);
			goto err;
		}
		if (u_attrs[GENZ_A_U_CLASS_UUID]) {
			bytes_to_uuid(&zdev->class_uuid,
				      nla_data(u_attrs[GENZ_A_U_CLASS_UUID]));
			pr_debug("\t\tCLASS_UUID: %pUb\n", &zdev->class_uuid);
		}
		if (u_attrs[GENZ_A_U_INSTANCE_UUID]) {
			bytes_to_uuid(&zdev->instance_uuid,
				      nla_data(u_attrs[GENZ_A_U_INSTANCE_UUID]));
			pr_debug("\t\tINSTANCE_UUID: %pUb\n",
				 &zdev->instance_uuid);
		}
		if (u_attrs[GENZ_A_U_REFERENCE_UUID]) {
			bytes_to_uuid(&zdev->ref_uuid,
				      nla_data(u_attrs[GENZ_A_U_REFERENCE_UUID]));
			pr_debug("\t\tREFERENCE_UUID: %pUb\n", &zdev->ref_uuid);
		}
		if (u_attrs[GENZ_A_U_FLAGS]) {
			zdev->driver_flags = nla_get_u64(u_attrs[GENZ_A_U_FLAGS]);
			pr_debug("\t\tFLAGS: 0x%llx\n", zdev->driver_flags);
		}
		if (u_attrs[GENZ_A_U_CLASS]) {
			int condensed_class;
			const char *condensed_name;

			zdev->class = nla_get_u16(u_attrs[GENZ_A_U_CLASS]);
			pr_debug("\t\tClass = %d\n",
				(uint32_t) zdev->class);
			if (zdev->class > 0 &&
			    zdev->class < genz_hardware_classes_nelems) {
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
			dev_set_name(&zdev->dev, "genz%u:%s:%s%u",
				fabric->number,
				genz_gcid_str(genz_dev_gcid(zdev, 0),
					      gcstr, sizeof(gcstr)),
				condensed_name,
				atomic_inc_return(
				     &zcomp->res_count[condensed_class]) - 1);
		}
		uu = genz_zdev_uuid_tracker_alloc_and_insert(
			&zdev->instance_uuid, zdev);
		if (!uu) {
			return -ENOMEM;
			goto err;
		}
		genz_device_initialize(zdev);
		if (u_attrs[GENZ_A_U_MRL]) {
			ret = parse_mr_list(zdev, u_attrs[GENZ_A_U_MRL]);
			if (ret) {
				pr_debug("\tparse of MRL failed\n");
				goto err;
			}
		}
		/*
		 * The device add triggers the driver bind/probe. All of the
		 * resources must be in place for the driver probe. The
		 * sysfs files are created after the new device is added.
		 */
		ret = device_add(&zdev->dev);
		if (ret) {
			put_device(&zdev->dev);
			pr_debug("device_add failed with %d\n", ret);
			goto err;
		}
		ret = genz_create_uuid_files(zdev);
		if (ret) {
			pr_debug("\tgenz_create_uuid_files failed with %d\n", ret);
			goto err;
		}
		ret = genz_create_attrs(zdev);
		if (ret) {
			pr_debug("\tgenz_create_attrs failed with %d\n", ret);
			goto err;
		}
	}
	pr_debug("\tend of RESOURCE_LIST\n");
	return ret;
err:
	/* Revisit: cleanup  */
	return ret;
}

/* Netlink Generic Handlers */
static int genz_add_os_component(struct sk_buff *skb, struct genl_info *info)
{
	struct genz_os_comp *zcomp = NULL;
	uint32_t fabric_num, gcid;
	int ret = 0;
	struct genz_fabric *f;
	struct uuid_tracker *uu;
	uuid_t mgr_uuid;

	pr_debug("entered\n");
	ret = check_netlink_perm();
	if (ret < 0)
		goto err;
	if (info->attrs[GENZ_A_MGR_UUID]) {
		bytes_to_uuid(&mgr_uuid,
			      nla_data(info->attrs[GENZ_A_MGR_UUID]));
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
	print_components(f);
	if (f == NULL) {
		pr_debug("fabric %d pointer from uu_tracker is NULL\n",
			fabric_num);
		ret = -EINVAL;
		goto err;
	}
	if (info->attrs[GENZ_A_GCID]) {
		gcid = nla_get_u32(info->attrs[GENZ_A_GCID]);
		pr_debug("\tGCID: %d ", gcid);
	} else {
		pr_debug("missing required GCID\n");
		return -EINVAL;
	}
	/* validate the GCID */
	if (gcid > MAX_GCID) {
		pr_debug("GCID is out of range\n");
		return -EINVAL;
	}
	zcomp = genz_add_os_subnet_comp(f, genz_gcid_sid(gcid), genz_gcid_cid(gcid));
	if (IS_ERR(zcomp)) {
		pr_debug("genz_add_os_subnet_comp failed\n");
		return PTR_ERR(zcomp);
	}
	if (info->attrs[GENZ_A_CCLASS]) {
		zcomp->comp.cclass = nla_get_u16(info->attrs[GENZ_A_CCLASS]);
		pr_debug("\tC-Class = %d\n",
			(uint32_t) zcomp->comp.cclass);
	} else {
		pr_debug("missing required CCLASS\n");
		ret = -EINVAL;
		goto err;
	}
	if (zcomp->comp.cclass <= 0 ||
	    zcomp->comp.cclass >= genz_hardware_classes_nelems) {
		pr_debug("CCLASS invalid\n");
		ret = -EINVAL;
		goto err;
	}
	if (info->attrs[GENZ_A_SERIAL]) {
		zcomp->comp.serial = nla_get_u64(info->attrs[GENZ_A_SERIAL]);
		pr_debug("\tSerial = %016llx\n",
			(uint64_t) zcomp->comp.serial);
	} else {
		pr_debug("missing required SERIAL\n");
		ret = -EINVAL;
		goto err;
	}
	if (info->attrs[GENZ_A_CUUID]) {
		bytes_to_uuid(&zcomp->comp.c_uuid,
			      nla_data(info->attrs[GENZ_A_CUUID]));
		pr_debug("\tCUUID: %pUb\n", &zcomp->comp.c_uuid);
	} else {
		pr_debug("missing required CUUID\n");
		ret = -EINVAL;
		goto err;
	}
	if (info->attrs[GENZ_A_FRU_UUID]) {
		bytes_to_uuid(&zcomp->comp.fru_uuid,
			      nla_data(info->attrs[GENZ_A_FRU_UUID]));
		pr_debug("\tFRU_UUID: %pUb\n", &zcomp->comp.fru_uuid);
	} else {
		pr_debug("missing required FRU_UUID\n");
		ret = -EINVAL;
		goto err;
	}
	if (info->attrs[GENZ_A_RESOURCE_LIST]) {
		ret = add_resource_list(info->attrs[GENZ_A_RESOURCE_LIST],
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
		device_unregister(&zcomp->dev);
	return ret;
}

static int remove_resource_list(const struct nlattr *resource_list,
				struct genz_os_comp *zcomp)
{
	struct nlattr *nested_attr;
	struct nlattr *u_attrs[GENZ_A_U_MAX + 1];
	uuid_t instance_uuid;
	int ret = 0;
	int rem;
	struct netlink_ext_ack extack;
	struct genz_fabric *fabric;
	struct uuid_tracker *uu;
	struct genz_dev *zdev;

	/* Revisit: keep this fabric check? */
	fabric = zcomp->subnet->subnet.fabric;
	if (!fabric)  {
		pr_debug("zcomp->subnet doesn't have a fabric yet\n");
		return -ENOENT;
	}
	pr_debug("\tRESOURCE_LIST:\n");
	/* Go through the nested list of UUID structures */
	nla_for_each_nested(nested_attr, resource_list, rem) {
		/* Extract the nested UUID structure */
		ret = nla_parse_nested_deprecated(u_attrs, GENZ_A_U_MAX,
			nested_attr, genz_genl_resource_policy, &extack);
		if (ret < 0) {
			pr_debug("nla_parse_nested of UUID list returned %d\n",
				 ret);
			goto err;
		}
		if (u_attrs[GENZ_A_U_INSTANCE_UUID]) {
			bytes_to_uuid(&instance_uuid,
				      nla_data(u_attrs[GENZ_A_U_INSTANCE_UUID]));
			pr_debug("\t\tINSTANCE_UUID: %pUb\n", &instance_uuid);
		}
		uu = genz_uuid_search(&instance_uuid);
		if (!uu) {
			pr_debug("did not find matching INSTANCE_UUID\n");
			ret = -EINVAL;
			continue;
		}
		zdev = uu->zdev->zdev;
		/* The device del triggers the driver unbind/remove. */
		device_del(&zdev->dev);
	}
	pr_debug("\tend of RESOURCE_LIST\n");
	return ret;
err:
	/* Revisit: cleanup  */
	return ret;
}

static int genz_remove_os_component(struct sk_buff *skb, struct genl_info *info)
{
	struct genz_fabric *f;
	struct genz_os_subnet *s;
	struct genz_os_comp *zcomp = NULL;
	struct uuid_tracker *uu;
	uuid_t mgr_uuid;
	uint32_t gcid;
	int ret;

	pr_debug("entered\n");
	ret = check_netlink_perm();
	if (ret < 0)
		goto err;
	if (info->attrs[GENZ_A_MGR_UUID]) {
		bytes_to_uuid(&mgr_uuid,
			      nla_data(info->attrs[GENZ_A_MGR_UUID]));
		pr_debug("\tMGR_UUID: %pUb\n", &mgr_uuid);
	} else {
		pr_debug("missing required MGR_UUID\n");
		ret = -EINVAL;
		goto err;
	}
	uu = genz_uuid_search(&mgr_uuid);
	if (!uu) {
		pr_debug("did not find matching MGR_UUID\n");
		ret = -EINVAL;
		goto err;
	}
	f = uu->fabric->fabric;
	if (info->attrs[GENZ_A_GCID]) {
		gcid = nla_get_u32(info->attrs[GENZ_A_GCID]);
		pr_debug("\tGCID: %d ", gcid);
	} else {
		pr_debug("missing required GCID\n");
		ret = -EINVAL;
		goto mgr_uuid;
	}
	/* validate the GCID */
	if (gcid > MAX_GCID) {
		pr_debug("GCID is out of range\n");
		ret = -EINVAL;
		goto mgr_uuid;
	}
	s = genz_lookup_os_subnet(genz_gcid_sid(gcid), f);
	if (s == NULL) {
		pr_debug("genz_lookup_os_subnet failed\n");
		ret = -EINVAL;
		goto mgr_uuid;
	}
	zcomp = genz_lookup_os_comp(s, genz_gcid_cid(gcid));
	if (zcomp == NULL) {
		pr_debug("genz_lookup_os_comp failed\n");
		ret = -EINVAL;
		goto mgr_uuid;
	}
	if (info->attrs[GENZ_A_RESOURCE_LIST]) {
		ret = remove_resource_list(info->attrs[GENZ_A_RESOURCE_LIST],
					   zcomp);
		if (ret < 0)
			goto mgr_uuid;
	} else {
		pr_debug("Must supply at least one resource\n");
		ret = -EINVAL;
		goto mgr_uuid;
	}
#ifdef REVISIT
	/* this is wrong - need to lookup instance_uuid and remove that device */
	/* remove the component */
	device_unregister(&zcomp->dev);
#endif
mgr_uuid:
	/* genz_uuid_search takes a refcount. decrement it here */
	genz_uuid_remove(uu);
err:
	return ret;
}

static int genz_symlink_os_component(struct sk_buff *skb, struct genl_info *info)
{
	int ret;

	/* Revisit: implement this
	 * message handling code goes here; return 0 on success,
	 * negative value on failure.
	 */
	pr_debug("entered\n");
	ret = check_netlink_perm();
	if (ret < 0)
		goto err;

err:
	return ret;
}

struct genz_fab_comp_info {
	uint32_t              fabric_num, gcid, br_gcid, tmp_gcid, dr_gcid;
	uint16_t              dr_iface;
	struct genz_fabric    *f;
	union {
		struct genz_subnet    *zsub;
	};
	union {
		struct genz_comp      *zcomp;
		struct genz_os_comp   *ocomp;
	};
	struct uuid_tracker   *uu;
	uuid_t                mgr_uuid;
};

static int parse_fabric_component(struct genl_info *info,
				  struct genz_fab_comp_info *fci, bool dr,
				  bool add, uint *scenario)
{
	bool os = false;
	bool add_kobj;
	bool valid_dr_iface;
	uint32_t sid, cid, tcid;
	char gcstr[GCID_STRING_LEN+1];
	int ret = 0;

	*scenario = 0;  /* illegal scenario */
	if (info->attrs[GENZ_A_FC_MGR_UUID]) {
		bytes_to_uuid(&fci->mgr_uuid,
			      nla_data(info->attrs[GENZ_A_FC_MGR_UUID]));
		pr_debug("\tMGR_UUID: %pUb\n", &fci->mgr_uuid);
	} else {
		pr_debug("missing required MGR_UUID\n");
		ret = -EINVAL;
		goto err;
	}
	fci->uu = genz_fabric_uuid_tracker_alloc_and_insert(&fci->mgr_uuid);
	if (!fci->uu) {
		ret = -ENOMEM;
		goto err;
	}
	fci->fabric_num = fci->uu->fabric->fabric_num;
	fci->f = fci->uu->fabric->fabric;
	if (info->attrs[GENZ_A_FC_GCID]) {
		fci->gcid = nla_get_u32(info->attrs[GENZ_A_FC_GCID]);
		pr_debug("\tGCID: %s\n", genz_gcid_str(fci->gcid, gcstr, sizeof(gcstr)));
	} else {
		pr_debug("missing required GCID\n");
		ret = -EINVAL;
		goto err;
	}
	if (info->attrs[GENZ_A_FC_BRIDGE_GCID]) {
		fci->br_gcid = nla_get_u32(info->attrs[GENZ_A_FC_BRIDGE_GCID]);
		pr_debug("\tBRIDGE_GCID: %s\n", genz_gcid_str(fci->br_gcid, gcstr, sizeof(gcstr)));
	} else {
		pr_debug("missing required BRIDGE_GCID\n");
		ret = -EINVAL;
		goto err;
	}
	if (info->attrs[GENZ_A_FC_TEMP_GCID]) {
		fci->tmp_gcid = nla_get_u32(info->attrs[GENZ_A_FC_TEMP_GCID]);
		pr_debug("\tTEMP_GCID: %s\n", genz_gcid_str(fci->tmp_gcid, gcstr, sizeof(gcstr)));
	} else {
		pr_debug("missing required TEMP_GCID\n");
		ret = -EINVAL;
		goto err;
	}
	if (info->attrs[GENZ_A_FC_DR_GCID]) {
		fci->dr_gcid = nla_get_u32(info->attrs[GENZ_A_FC_DR_GCID]);
		pr_debug("\tDR_GCID: %s\n", genz_gcid_str(fci->dr_gcid, gcstr, sizeof(gcstr)));
	} else {
		pr_debug("missing required DR_GCID\n");
		ret = -EINVAL;
		goto err;
	}
	if (info->attrs[GENZ_A_FC_DR_INTERFACE]) {
		fci->dr_iface = nla_get_u16(info->attrs[GENZ_A_FC_DR_INTERFACE]);
		pr_debug("\tDR_INTERFACE: %d\n", fci->dr_iface);
		valid_dr_iface = (fci->dr_iface != GENZ_DR_IFACE_NONE);
	} else {
		pr_debug("missing required DR_INTERFACE\n");
		ret = -EINVAL;
		goto err;
	}
	if (genz_valid_gcid(fci->gcid)) {
		/* validate the GCID */
		if (fci->gcid > MAX_GCID) {
			pr_debug("GCID is out of range\n");
			ret = -EINVAL;
			goto err;
		}
	} else {
		pr_debug("GCID is invalid\n");
		ret = -EINVAL;
		goto err;
	}
	/* Determine the scenario - one of these 5:
	 * 1. A local bridge being moved from its temporary subsystem-assigned
	 *    fabric/GCID to its permanent home.
	 * 2. A new, directly-attached component.
	 * 3. An existing directed-relay component being moved to its
	 *    permanent GCID. If TEMP_GCID is valid, it means the initial
	 *    GCID "guess" was wrong and must be corrected.
	 * 4. A direct-attached component is to be accessed via directed relay
	 * 5. A switch-attached component is to be accessed via directed relay
	 *
	 * Scenario  GCID   BR_GCID  TEMP_GCID    DR_GCID  dr
	 * --------------------------------------------------------------
	 *    1      valid  GCID     temp subnet  invalid  false
	 *    2      valid  !GCID    invalid      invalid  false
	 *    3      valid  !GCID    (in)valid    valid    false
	 *    4      valid  valid    invalid      BR_GCID  true
	 *    5      valid  valid    invalid      !BR_GCID true
	 */
	if (!dr && genz_valid_gcid(fci->tmp_gcid) &&
	    !genz_valid_gcid(fci->dr_gcid)) {
		if (fci->gcid != fci->br_gcid) {
			pr_debug("scenario 1, gcid (%d) != br_gcid(%d)\n",
				 fci->gcid, fci->br_gcid);
			ret = -EINVAL;
			goto err;
		}
		*scenario = 1;
	} else if (!dr && !genz_valid_gcid(fci->tmp_gcid) &&
		   !genz_valid_gcid(fci->dr_gcid)) {
		if (fci->gcid == fci->br_gcid) {
			pr_debug("scenario 2, gcid (%d) == br_gcid(%d)\n",
				 fci->gcid, fci->br_gcid);
			ret = -EINVAL;
			goto err;
		}
		*scenario = 2;
	} else if (!dr && genz_valid_gcid(fci->dr_gcid)) {
		if (fci->gcid == fci->br_gcid) {
			pr_debug("scenario 3, gcid (%d) == br_gcid(%d)\n",
				 fci->gcid, fci->br_gcid);
			ret = -EINVAL;
			goto err;
		}
		*scenario = 3;
	} else if (dr && fci->br_gcid == fci->dr_gcid) {
		*scenario = 4;
	} else if (dr && fci->br_gcid != fci->dr_gcid) {
		*scenario = 5;
	} else {
		pr_debug("invalid scenario\n");
		ret = -EINVAL;
		goto err;
	}
	sid = genz_gcid_sid(fci->gcid);
	cid = genz_gcid_cid(fci->gcid);
	if (add) {
		fci->zsub = genz_add_subnet(sid, fci->f);
		if (fci->zsub == NULL) {
			pr_debug("genz_add_subnet failed\n");
			ret = -EINVAL;
			goto err;
		}
	} else { /* remove */
		fci->zsub = genz_lookup_subnet(sid, fci->f);
		if (fci->zsub == NULL) {
			pr_debug("genz_lookup_subnet failed to find 0x%x\n", sid);
			ret = -EINVAL;
			goto err;
		}
	}
	os = (*scenario == 1);
	if (os) {
		if (add) {
			fci->ocomp = genz_add_os_subnet_comp(fci->f, sid, cid);
			if (IS_ERR(fci->ocomp)) {
				pr_debug("genz_add_os_subnet_comp failed\n");
				ret = PTR_ERR(fci->ocomp);
				goto err;
			}
		} else { /* remove */
			fci->ocomp = genz_lookup_os_subnet_comp(fci->f,
								sid, cid);
			if (fci->ocomp == NULL) {
				ret = -EINVAL;
				goto err;
			}
		}
	} else { /* fabric */
		if (add) {
			add_kobj = (*scenario == 2) || (*scenario == 3);
			if (genz_valid_gcid(fci->tmp_gcid)) {
				tcid = genz_gcid_cid(fci->tmp_gcid);
				/* Revisit: tmp_gcid on diff subnet */
				fci->zcomp = genz_lookup_comp(fci->zsub, tcid,
							      /*lock*/true);
				if (fci->zcomp == NULL) {
					pr_debug("genz_lookup_comp failed to find 0x%x\n", tcid);
					ret = -EINVAL;
					goto err;
				}
			} else {
				fci->zcomp = genz_add_comp(fci->zsub, cid, add_kobj);
				if (fci->zcomp == NULL) {
					pr_debug("genz_add_comp failed\n");
					ret = -EINVAL;
					goto err;
				}
			}
		} else { /* remove */
			fci->zcomp = genz_lookup_comp(fci->zsub, cid,
						      /*lock*/true);
			if (fci->zcomp == NULL) {
				pr_debug("genz_lookup_comp failed to find 0x%x\n", cid);
				ret = -EINVAL;
				goto err;
			}
		}
	}

err:
	pr_debug("scenario=%u, ret=%d\n", *scenario, ret);
	return ret;
}

static int genz_add_fabric_component(struct sk_buff *skb, struct genl_info *info)
{
	struct genz_fab_comp_info fci;
	struct genz_bridge_dev *zbdev;
	struct genz_comp *existing;
	uint scenario;
	uint32_t cid;
	int ret;

	pr_debug("entered\n");
	ret = check_netlink_perm();
	if (ret < 0)
		goto err;

	ret = parse_fabric_component(info, &fci, /*dr*/false, /*add*/true,
				     &scenario);
	if (ret < 0)
		goto err;
	/*
	 * There are 3 scenarios handled here.  See parse_fabric_component()
	 * for details.
	 * 1. A local bridge being moved from its temporary subsystem-assigned
	 *    fabric/GCID to its permanent home.
	 * 2. A new, directly-attached component.
	 * 3. An existing directed-relay component being moved to its
	 *    permanent GCID.
	 */
	if (scenario == 1) {
		if (!genz_temp_fabric) {
			pr_debug("genz_temp_fabric is NULL\n");
			ret = -ENODEV;
			goto err;
		}
		zbdev = genz_lookup_zbdev(genz_temp_fabric, fci.tmp_gcid);
		if (zbdev == NULL) {
			pr_debug("scenario 1, tmp_gcid (%d) not found\n",
				 fci.tmp_gcid);
			ret = -EINVAL;
			goto err;
		}
		ret = genz_move_fabric_bridge(zbdev, fci.ocomp, fci.f, fci.zsub);
		if (ret < 0) {
			pr_debug("genz_move_fabric_bridge failed, ret=%d\n", ret);
			goto err;
		}
	} else if (scenario == 2) {
		zbdev = genz_lookup_zbdev(fci.f, fci.br_gcid);
		if (zbdev == NULL) {
			pr_debug("scenario 2, br_gcid (%d) not found\n",
				 fci.br_gcid);
			ret = -EINVAL;
			goto err_put;
		}
		ret = genz_fab_create_control_files(zbdev, fci.zcomp,
						    GENZ_DR_IFACE_NONE, &fci.mgr_uuid);
		if (ret < 0) {
			pr_debug("genz_fab_create_control_files failed, ret=%d\n", ret);
			goto err_put;
		}
	} else if (scenario == 3) {
		zbdev = genz_lookup_zbdev(fci.f, fci.br_gcid);
		if (zbdev == NULL) {
			pr_debug("scenario 3, br_gcid (%d) not found\n",
				 fci.br_gcid);
			ret = -EINVAL;
			goto err_put;
		}
		if (genz_valid_gcid(fci.tmp_gcid)) {
			/* Revisit: subnets */
			cid = genz_gcid_cid(fci.gcid);
			existing = genz_lookup_comp(fci.zsub, cid, /*lock*/true);
			if (existing) {
				pr_debug("scenario 3, cid %u already exists\n",
					 cid);
				genz_comp_put(existing);
				ret = -EEXIST;
				goto err_put;
			}
			fci.zcomp->cid = cid;
			ret = genz_init_comp_kobj(fci.zcomp, fci.zsub, cid);
			if (ret < 0) {
				pr_debug("genz_init_comp_kobj failed, ret=%d\n", ret);
				goto err_put;
			}
		}
		ret = genz_fab_create_control_files(zbdev, fci.zcomp,
						    fci.dr_iface, &fci.mgr_uuid);
		if (ret < 0) {
			pr_debug("genz_fab_create_control_files failed, ret=%d\n", ret);
			goto err_put;
		}
	} else {
		pr_debug("invalid combination of GCIDs\n");
		ret = -EINVAL;
		goto err;
	}
	return ret;
err_put:
	if (fci.zcomp)
		genz_comp_put(fci.zcomp);
err:
	return ret;
}

static int genz_remove_fabric_component(struct sk_buff *skb, struct genl_info *info)
{
	struct genz_fab_comp_info fci;
	struct genz_bridge_dev *zbdev;
	uint scenario;
	int ret;

	pr_debug("entered\n");
	ret = check_netlink_perm();
	if (ret < 0)
		goto err;

	ret = parse_fabric_component(info, &fci, /*dr*/false, /*add*/false,
				     &scenario);
	if (ret < 0)
		goto err;
	/*
	 * There are 3 scenarios possible here.  See parse_fabric_component()
	 * for details. Only 1 of them (scenario 2) is actually handled.
	 * 1. A local bridge being removed from its temporary subsystem-assigned
	 *    fabric/GCID. Should never happen.
	 * 2. Removing a fabric component.
	 * 3. An existing directed-relay component being removed. This
	 *    is handled by genz_remove_fabric_dr_component(), not here.
	 */
	if (scenario == 2) {
		zbdev = genz_lookup_zbdev(fci.f, fci.br_gcid);
		if (zbdev == NULL) {
			pr_debug("scenario 2, br_gcid (%d) not found\n",
				 fci.br_gcid);
			ret = -EINVAL;
			goto err;
		}
		ret = genz_fab_remove_control_files(zbdev, fci.zcomp);
		if (ret < 0) {
			pr_debug("genz_fab_remove_control_files failed, ret=%d\n", ret);
			goto err;
		}
		genz_remove_comp(fci.zcomp);
	} else {
		pr_debug("invalid combination of GCIDs\n");
		ret = -EINVAL;
		goto err;
	}
err:
	return ret;
}

static int genz_check_fabric_dr_gcids(struct genz_fab_comp_info *fci)
{
	int ret = 0;

	if (genz_valid_gcid(fci->tmp_gcid)) {
		pr_debug("tmp_gcid(%d) != INVALID\n", fci->tmp_gcid);
		ret = -EINVAL;
		goto err;
	}
	if (!genz_valid_gcid(fci->br_gcid) || !genz_valid_gcid(fci->dr_gcid)) {
		pr_debug("br_gcid (%d) or dr_gcid(%d) == INVALID\n",
			 fci->br_gcid, fci->dr_gcid);
		ret = -EINVAL;
		goto err;
	}
	if (fci->dr_iface == GENZ_DR_IFACE_NONE) {
		pr_debug("dr_iface is invalid\n");
		ret = -EINVAL;
		goto err;
	}
err:
	return ret;
}

static int genz_add_fabric_dr_component(struct sk_buff *skb, struct genl_info *info)
{
	struct genz_fab_comp_info fci;
	struct genz_bridge_dev *zbdev;
	struct genz_comp *dr_comp = NULL;
	uint scenario;
	int ret;

	pr_debug("entered\n");
	ret = check_netlink_perm();
	if (ret < 0)
		goto err;
	ret = parse_fabric_component(info, &fci, /*dr*/true, /*add*/true,
				     &scenario);
	if (ret < 0)
		goto err;
	ret = genz_check_fabric_dr_gcids(&fci);
	if (ret < 0)
		goto err;
	/* Two scenarios.  See parse_fabric_component() for details.
	 * 4. A direct-attached component is to be accessed via directed relay
	 * 5. A switch-attached component is to be accessed via directed relay
	 */
	if (scenario == 4) {
		zbdev = genz_lookup_zbdev(fci.f, fci.br_gcid);
		if (zbdev == NULL) {
			pr_debug("scenario 4, br_gcid (%d) not found\n",
				 fci.br_gcid);
			ret = -EINVAL;
			goto err;
		}
		dr_comp = &zbdev->zdev.zcomp->comp;
		ret = genz_dr_create_control_files(zbdev, fci.zcomp, dr_comp,
						   fci.dr_iface, &fci.mgr_uuid);
		if (ret < 0) {
			pr_debug("genz_dr_create_control_files failed, ret=%d\n", ret);
			goto err;
		}
	} else if (scenario == 5) {
		zbdev = genz_lookup_zbdev(fci.f, fci.br_gcid);
		if (zbdev == NULL) {
			pr_debug("scenario 5, br_gcid (%d) not found\n",
				 fci.br_gcid);
			ret = -EINVAL;
			goto err;
		}
		/* Revisit: refactor this - almost the same as scenario 4 */
		dr_comp = genz_lookup_gcid(fci.f, fci.dr_gcid);
		if (!dr_comp) {
			pr_debug("genz_lookup_gcid failed\n");
			goto err;
		}
		ret = genz_dr_create_control_files(zbdev, fci.zcomp, dr_comp,
						   fci.dr_iface, &fci.mgr_uuid);
		if (ret < 0) {
			pr_debug("genz_dr_create_control_files failed, ret=%d\n", ret);
			goto err_put;
		}
		genz_comp_put(dr_comp); /* put ref from genz_lookup_gcid */
	} else {
		pr_debug("invalid combination of GCIDs\n");
		ret = -EINVAL;
		goto err;
	}
	return ret;
err_put:
	if (dr_comp)
		kobject_put(&dr_comp->kobj);
err:
	return ret;
}

static int genz_remove_fabric_dr_component(struct sk_buff *skb, struct genl_info *info)
{
	struct genz_fab_comp_info fci;
	struct genz_bridge_dev *zbdev;
	struct genz_comp *dr_comp;
	uint scenario;
	int ret;

	pr_debug("entered\n");
	ret = check_netlink_perm();
	if (ret < 0)
		goto err;

	ret = parse_fabric_component(info, &fci, /*dr*/true, /*add*/false,
				     &scenario);
	if (ret < 0)
		goto err;
	ret = genz_check_fabric_dr_gcids(&fci);
	if (ret < 0)
		goto err;
	/* Two scenarios.  See parse_fabric_component() for details.
	 * 4. A direct-attached DR component is being removed
	 * 5. A switch-attached DR component is being removed
	 */
	if (scenario == 4) {
		zbdev = genz_lookup_zbdev(fci.f, fci.br_gcid);
		if (zbdev == NULL) {
			pr_debug("scenario 4, br_gcid (%d) not found\n",
				 fci.br_gcid);
			ret = -EINVAL;
			goto err;
		}
		dr_comp = &zbdev->zdev.zcomp->comp;
		ret = genz_dr_remove_control_files(zbdev, fci.zcomp, dr_comp,
						   fci.dr_iface);
		if (ret < 0) {
			pr_debug("genz_dr_remove_control_files failed, ret=%d\n", ret);
			goto err;
		}
		/* Revisit: genz_remove_comp()? */
	} else if (scenario == 5) {
		zbdev = genz_lookup_zbdev(fci.f, fci.br_gcid);
		if (zbdev == NULL) {
			pr_debug("scenario 5, br_gcid (%d) not found\n",
				 fci.br_gcid);
			ret = -EINVAL;
			goto err;
		}
		/* Revisit: refactor this - almost the same as scenario 4 */
		dr_comp = genz_lookup_gcid(fci.f, fci.dr_gcid);
		if (!dr_comp) {
			pr_debug("genz_lookup_gcid failed\n");
			goto err;
		}
		ret = genz_dr_remove_control_files(zbdev, fci.zcomp, dr_comp,
						   fci.dr_iface);
		if (ret < 0) {
			pr_debug("genz_dr_remove_control_files failed, ret=%d\n", ret);
			goto err;
		}
		genz_comp_put(dr_comp);
		/* Revisit: genz_remove_comp()? */
	} else {
		pr_debug("invalid combination of GCIDs\n");
		ret = -EINVAL;
		goto err;
	}
err:
	return ret;
}

static int genz_add_fabric(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;

	/* Revisit: implement this
	 * message handling code goes here; return 0 on success,
	 * negative value on failure.
	 */
	pr_debug("entered\n");
	ret = check_netlink_perm();
	if (ret < 0)
		goto err;

err:
	return ret;
}

static int genz_remove_fabric(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;

	/* Revisit: implement this
	 * message handling code goes here; return 0 on success,
	 * negative value on failure.
	 */
	pr_debug("entered\n");
	ret = check_netlink_perm();
	if (ret < 0)
		goto err;

err:
	return ret;
}

/* Netlink Generic Operations */
static struct genl_ops genz_gnl_ops[] = {
	{
	.cmd = GENZ_C_ADD_OS_COMPONENT,
	.doit = genz_add_os_component,
	.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
	{
	.cmd = GENZ_C_REMOVE_OS_COMPONENT,
	.doit = genz_remove_os_component,
	.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
	{
	.cmd = GENZ_C_SYMLINK_OS_COMPONENT,
	.doit = genz_symlink_os_component,
	.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
	{
	.cmd = GENZ_C_ADD_FABRIC_COMPONENT,
	.doit = genz_add_fabric_component,
	.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
	{
	.cmd = GENZ_C_REMOVE_FABRIC_COMPONENT,
	.doit = genz_remove_fabric_component,
	.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
	{
	.cmd = GENZ_C_ADD_FABRIC_DR_COMPONENT,
	.doit = genz_add_fabric_dr_component,
	.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
	{
	.cmd = GENZ_C_REMOVE_FABRIC_DR_COMPONENT,
	.doit = genz_remove_fabric_dr_component,
	.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
	{
	.cmd = GENZ_C_ADD_FABRIC,
	.doit = genz_add_fabric,
	.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
	{
	.cmd = GENZ_C_REMOVE_FABRIC,
	.doit = genz_remove_fabric,
	.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	},
};

static struct genl_multicast_group genz_mcgrps[] = {
	{ .name = "ueps" },
};

/* Netlink Generic Family Definition */
struct genl_family genz_gnl_family = {
	.hdrsize = 0,
	.name = GENZ_FAMILY_NAME,
	.version = 1,
	.maxattr = GENZ_A_MAX,
	.ops = genz_gnl_ops,
	.n_ops = ARRAY_SIZE(genz_gnl_ops),
	.resv_start_op = GENZ_C_MAX + 1,
	.mcgrps = genz_mcgrps,
	.n_mcgrps = ARRAY_SIZE(genz_mcgrps),
	.module = THIS_MODULE
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
