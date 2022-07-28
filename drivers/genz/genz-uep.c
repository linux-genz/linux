// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Copyright (C) 2021 IntelliProp Inc. All rights reserved. */

#include "genz.h"
#include "genz-control.h"
#include "genz-netlink.h"
#include "genz-probe.h"

static uint32_t uep_sgcid(struct genz_bridge_dev *zbdev,
			  struct genz_uep_event_rec *rec)
{
	uint32_t ssid;

	ssid = (rec->GC) ? rec->SSID : genz_gcid_sid(genz_br_gcid(zbdev));
	return genz_gcid(ssid, rec->SCID);
}

static uint16_t uep_event_id(struct genz_uep_event_rec *rec)
{
	return rec->EventID;
}

static int genz_notify_uep(struct genz_bridge_dev *zbdev,
			   struct genz_uep_info *uepi)
{
	struct sk_buff *skb;
	void *msg_header;
	uint32_t total_size, nla_genl_hdr_total_size;
	uint32_t br_gcid;
	uuid_t mgr_uuid;
	int ret;

	total_size = nla_total_size(sizeof(*uepi) + sizeof(mgr_uuid) +
				    sizeof(br_gcid));
	/* Add GENL_HDR to total_size */
	nla_genl_hdr_total_size = total_size + GENL_HDRLEN +
		genz_gnl_family.hdrsize + NLMSG_HDRLEN;
	skb = genlmsg_new(nla_genl_hdr_total_size, GFP_ATOMIC);
	if (!skb) {
		dev_dbg(zbdev->bridge_dev,
			"Failed to allocate UEP data SKB of size: %u\n",
			total_size);
		ret = -ENOMEM;
		goto err;
	}

	/* add the genetlink message header */
	msg_header = genlmsg_put(skb, 0, 0,
				 &genz_gnl_family, 0, GENZ_C_NOTIFY_UEP);
	if (!msg_header) {
		dev_dbg(zbdev->bridge_dev, "failed to copy command details\n");
		ret = -ENOMEM;
		goto free;
	}

	/* put all the message attributes */
	ret = nla_put_u64_64bit(skb, GENZ_A_UEP_FLAGS, uepi->flags, GENZ_ATTR_PAD);
	if (ret) {
		dev_dbg(zbdev->bridge_dev, "failed to copy UEP flags\n");
		goto free;
	}
	mgr_uuid = genz_br_mgr_uuid(zbdev);
	ret = nla_put(skb, GENZ_A_UEP_MGR_UUID, sizeof(mgr_uuid), &mgr_uuid);
	if (ret) {
		dev_dbg(zbdev->bridge_dev, "failed to copy UEP mgr_uuid\n");
		goto free;
	}
	br_gcid = genz_br_gcid(zbdev);
	ret = nla_put_u32(skb, GENZ_A_UEP_BRIDGE_GCID, br_gcid);
	if (ret) {
		dev_dbg(zbdev->bridge_dev, "failed to copy UEP br_gcid\n");
		goto free;
	}
	ret = nla_put_u64_64bit(skb, GENZ_A_UEP_TS_SEC, uepi->ts.tv_sec, GENZ_ATTR_PAD);
	if (ret) {
		dev_dbg(zbdev->bridge_dev, "failed to copy UEP ts sec\n");
		goto free;
	}
	ret = nla_put_u64_64bit(skb, GENZ_A_UEP_TS_NSEC, uepi->ts.tv_nsec, GENZ_ATTR_PAD);
	if (ret) {
		dev_dbg(zbdev->bridge_dev, "failed to copy UEP ts nsec\n");
		goto free;
	}
	ret = nla_put(skb, GENZ_A_UEP_REC, sizeof(uepi->rec), &uepi->rec);
	if (ret) {
		dev_dbg(zbdev->bridge_dev, "failed to copy UEP rec\n");
		goto free;
	}

	/* send genetlink multicast message to notify appplications */
	genlmsg_end(skb, msg_header);
	ret = genlmsg_multicast(&genz_gnl_family, skb, 0, 0, GFP_ATOMIC);

	/* If there are no listeners, genlmsg_multicast may return non-zero
	 * value (-ESRCH).
	 */
err:
	if (ret)
		dev_dbg(zbdev->bridge_dev,
			"error (%d) sending UEP event message to userspace\n", ret);
	return ret;

free:
	nlmsg_free(skb);
	goto err;
}

void genz_uep_pkt_to_rec(struct genz_uep_pkt *pkt, struct genz_uep_event_rec *rec)
{
	rec->A = 0;
	rec->Vers = GENZ_UEP_EVENT_REC_VERS;
	rec->CV = pkt->CV;
	rec->SV = pkt->SV;
	rec->GC = pkt->GC;
	rec->IV = pkt->IV;
	rec->R0 = 0;
	rec->Event = pkt->Event;
	rec->R1 = 0;
	rec->SCID = pkt->SCID;
	rec->R2 = 0;
	rec->R3 = 0;
	rec->R4 = 0;
	if (pkt->NH == 0 && pkt->GC == 0) {
		rec->IfaceID = pkt->u.u00.IfaceID;
		rec->SSID = 0;
		rec->RCCID = pkt->u.u00.RCCID;
		rec->RCSID = (pkt->u.u00.RCSIDh << 8) | pkt->u.u00.RCSIDl;
		rec->ES = pkt->u.u00.ES;
		rec->EventID = pkt->u.u00.EventID;
	} else if (pkt->NH == 0 && pkt->GC == 1) {
		rec->IfaceID = pkt->u.u01.IfaceID;
		rec->SSID = pkt->u.u01.SSID;
		rec->RCCID = pkt->u.u01.RCCID;
		rec->RCSID = (pkt->u.u01.RCSIDh << 8) | pkt->u.u01.RCSIDl;
		rec->ES = pkt->u.u01.ES;
		rec->EventID = pkt->u.u01.EventID;
	} else if (pkt->NH == 1 && pkt->GC == 0) {
		rec->IfaceID = pkt->u.u10.IfaceID;
		rec->SSID = 0;
		rec->RCCID = pkt->u.u10.RCCID;
		rec->RCSID = (pkt->u.u10.RCSIDh << 8) | pkt->u.u10.RCSIDl;
		rec->ES = pkt->u.u10.ES;
		rec->EventID = pkt->u.u10.EventID;
	} else { /* pkt->NH == 1 && pkt->GC == 1 */
		rec->IfaceID = pkt->u.u11.IfaceID;
		rec->SSID = pkt->u.u11.SSID;
		rec->RCCID = pkt->u.u11.RCCID;
		rec->RCSID = (pkt->u.u11.RCSIDh << 8) | pkt->u.u11.RCSIDl;
		rec->ES = pkt->u.u11.ES;
		rec->EventID = pkt->u.u11.EventID;
	}
}
EXPORT_SYMBOL_GPL(genz_uep_pkt_to_rec);

int genz_handle_uep(struct genz_bridge_dev *zbdev, struct genz_uep_info *uepi)
{
	struct genz_uep_event_rec *rec = &uepi->rec;
	char str[GCID_STRING_LEN+1];
	struct genz_rmr_info *rmri;
	struct genz_comp *comp;
	uint16_t event_id;
	uint32_t sgcid;
	union genz_c_control c_control;
	unsigned long flags;
	int ret;

	if (!zbdev) /* ignore UEPs that arrive before genz_register_bridge()
		       completes */
		return -EINVAL;

	if (uepi->version != GENZ_UEP_INFO_VERS) { /* only v1 supported */
		dev_dbg(zbdev->bridge_dev, "unsupported version %u\n",
			uepi->version);
		return -EINVAL;
	}

	dev_dbg(zbdev->bridge_dev, "version=%u, local=%u, ts_valid=%u\n",
		uepi->version, uepi->local, uepi->ts_valid);

	if (!uepi->ts_valid)
		genz_set_uep_timestamp(uepi);

	if (!uepi->local) {
		sgcid = uep_sgcid(zbdev, rec);
		event_id = uep_event_id(rec);
		dev_dbg(zbdev->bridge_dev, "sgcid=%s, event_id=%u\n",
			genz_gcid_str(sgcid, str, sizeof(str)), event_id);
		comp = genz_lookup_gcid(zbdev->fabric, sgcid);
		if (!comp) {
			pr_debug("genz_lookup_gcid failed\n");
			return -EINVAL;
		}
		spin_lock_irqsave(&comp->uep_lock, flags);
		/* check if UEP event id is a duplicate */
		if (event_id == comp->uep_id) {
			dev_dbg(zbdev->bridge_dev,
				"duplicate event id %hu for component %s\n",
				event_id,
				genz_gcid_str(sgcid, str, sizeof(str)));
			ret = 1; /* Revisit: enum or different value */
			goto unlock;
		}
		/* this event id is now the latest */
		comp->uep_id = event_id;
		rmri = &comp->ctl_rmr_info;
		/* do read-modify-write of c_control.halt_uert */
		ret = genz_control_read_c_control(zbdev, rmri, &c_control.val);
		if (ret < 0) {
			dev_dbg(zbdev->bridge_dev,
				"genz_control_read_c_control failed, ret=%d\n",
				ret);
			goto unlock;
		}
		c_control.halt_uert = 1;
		ret = genz_control_write_c_control(zbdev, rmri, c_control.val);
		if (ret < 0) {
			dev_dbg(zbdev->bridge_dev,
				"genz_control_write_c_control failed, ret=%d\n",
				ret);
			goto unlock;
		}
		spin_unlock_irqrestore(&comp->uep_lock, flags);
		genz_comp_put(comp);
	}

	/* clear unused uepi->flags (to avoid kernel mem leak) */
	uepi->rv = 0;
	/* send UEP to userspace via generic netlink */
	ret = genz_notify_uep(zbdev, uepi);
	return ret;

unlock:
	spin_unlock_irqrestore(&comp->uep_lock, flags);
	genz_comp_put(comp);
	return ret;
}
EXPORT_SYMBOL_GPL(genz_handle_uep);
