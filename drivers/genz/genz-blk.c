/*
 * file : genz-blk.c
 * desc : linux block device driver for Gen-Z
 *
 * Author:  Jim Hull <jim.hull@hpe.com>
 *          Betty Dall <betty.dall@hpe.com>
 *
 * Copyright:
 *     © Copyright 2016-2019 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/interrupt.h>
#include <linux/ratelimit.h>
#include <linux/dma-direction.h>
#include <linux/genz.h>
#include "wildcat/wildcat.h"  /* Revisit: remove wildcat dependency */

#define GENZ_BLK_DRV_NAME "genz-blk"
#define GENZ_BDEV_NAME    "gzb"

static struct genz_device_id genz_blk_id_table[] = {
	{ .uuid_str = "3cb8d3bd-51ba-4586-835f-3548789dd906" },
	{ },
};

MODULE_DEVICE_TABLE(genz, genz_blk_id_table);

struct genz_blk_bridge { /* one per bridge */
	struct list_head       bbr_node;
	struct genz_bridge_dev *zbdev;
	struct blk_mq_tag_set  *tag_set;
	struct blk_mq_tag_set  __tag_set;
	struct genz_blk_ctx    *bctx;
	struct genz_mem_data   mem_data;
	uuid_t                 uuid;
};

struct genz_blk_state {  /* one per genz_blk_probe */
	struct list_head       bdev_list;  /* list of genz_bdevs */
	struct mutex           lock;
	struct genz_dev        *zdev;
	struct genz_blk_bridge *bbr;
	wait_queue_head_t      block_io_queue;
	int                    block_io_ready;
};

struct genz_blk_ctx {  /* one per XDM */
	struct genz_blk_bridge *bbr;
	struct genz_xdm_info   xdmi;
	struct genz_rdm_info   rdmi;
	bool                   have_rdmi;
	/* Revisit: other stuff */
};

struct genz_bdev {  /* one per genz_resource == genz_bdev_probe */
	struct list_head       bdev_node;
	spinlock_t             lock;
	size_t                 size;  /* block device size (bytes) */
	uint32_t               gcid;  /* Revisit: move elsewhere? */
	uint                   bindex;
	uint                   bdev_start_minor;
	uint64_t               base_zaddr;
	struct genz_rmr_info   rmr_info;
	struct request_queue   *queue;
	struct gendisk         *gd;
	struct genz_blk_state  *bstate;
	struct genz_resource   *zres;
};

#define GENZ_BLK_MAX_SG  256  /* Revisit */

struct genz_blk_cmd {  /* one per request */
	struct scatterlist sg[GENZ_BLK_MAX_SG];
	int nents;
	unsigned short segments;
	blk_status_t error;
	struct genz_sgl_info sgli;
	/* Revisit: copied from null_blk - what do we actually need? */
	//struct list_head list;
	//struct llist_node ll_list;
	//struct __call_single_data csd;
	//struct bio *bio;
	//struct nullb_queue *nq;
	//struct hrtimer timer;
};
#define to_genz_blk_cmd(x) container_of(x, struct genz_blk_cmd, sgli)

static uint genz_blk_index = 0;
DEFINE_MUTEX(genz_blk_lock);  /* used only during initialization */

/* ============================================================
 *                    THE BDEV FILE OPS
 * ============================================================ */

static int genz_bdev_major = 0;
static uint genz_bdev_start_minor = 0;

#define GENZ_BLOCK_SIZE	512
#define GENZ_BDEV_MINORS 16

/*
 * We can tweak our hardware sector size, but the kernel block layer
 * talks to us in terms of 512-byte sectors, always.
 */
#define KERNEL_SECTOR_SHIFT	9
#define KERNEL_SECTOR_SIZE	(1<<KERNEL_SECTOR_SHIFT)

static int genz_bdev_open(struct block_device *bdev, fmode_t fm)
{
	return 0;
}

static void genz_bdev_release(struct gendisk *bgen, fmode_t fm)
{
	return;
}

static int genz_bdev_ioctl(struct block_device *bdev, fmode_t fm,
			   unsigned ioctl, unsigned long data)
{
	return 0;
}

#ifdef OLD_GZD
static irqreturn_t genz_bdev_irq_handler(int irq, void *data)
{
	int ret, handled = 0;
	uint req_id;
	struct genz_blk_card_data *card_data =
		(struct genz_blk_card_data *)data;
	int more, remaining, wakeup = 0;
	struct bdev_bio *bbio;
	uint free_reqs;
	struct pci_dev *pdev;

	pdev = card_data->core_info->pdev;
	dev_dbg(&pdev->dev, "%s: card_data=%p, hw=%p\n",
		__func__, card_data, (card_data) ? card_data->hw : 0);
	do {
		more = 0;
		ret = genz_blk_driver.block_io_response(card_data->hw,
							&req_id, &free_reqs);
		if (ret < 0) {
			pr_err("%s: block_io_response returned error: %d for req_id %u\n",
			       __func__, ret, req_id);
		}
		dev_dbg(&pdev->dev,
			"%s: block_io_response returned ret: %d, tag: %u, free_reqs: %u\n",
			__func__, ret, req_id, free_reqs);
		if (free_reqs > 0)
			wakeup = 1;
		if (ret == 0 || ret == -EINVAL || ret == -ENOSPC) {
			break;  /* no more responses */
		}
		more = handled = 1;
		/* Complete the block transfer. */
		bbio = bdev_tag_data[req_id].bbio;
		/* Mark completion of a chunk in our bbio */
		remaining = bdev_bio_chunk_done(&pdev->dev,
						&bdev_tag_data[req_id],
						min(bbio->remaining, CHUNK),
						ret);
		if (remaining == 0) {
			/* bio complete! */
			dev_dbg(&pdev->dev, "%s: bio complete\n", __func__);
			if (bbio->bio) {
				if (bbio->status == 0) /* no error */
					bio_endio(bbio->bio);
				else                   /* -EIO */
					bio_io_error(bbio->bio);
			}
			bdev_free_bbio(bbio);
		} else if (remaining == -1) {
			dev_err(&pdev->dev,
				"%s: bdev_bio_chunk_done returned -1\n",
				__func__);
			if (bbio->bio)
				bio_io_error(bbio->bio);
			bdev_free_bbio(bbio);
		} else {
			dev_dbg(&pdev->dev,
				"%s: bdev_bio_chunk_done returned remaining %d\n",
				__func__, remaining);
		}

		bdev_end_tag(req_id);
		dev_dbg(&pdev->dev, "%s: ending tag %d ret is %d\n",
			__func__, req_id, ret);
	} while (more);

	card_data->block_io_ready = free_reqs;
	if (wakeup) {
		dev_dbg(&pdev->dev, "bdev_irq_handler: wakeup, free_reqs=%u\n", free_reqs);
		wake_up_interruptible(&card_data->block_io_queue);
	}

	dev_dbg(&pdev->dev, "bdev_irq_handler: finished, handled=%d\n", handled);
	return (handled) ? IRQ_HANDLED : IRQ_NONE;
}

static int bdev_bio_chunk_done(struct device *dev,
			       struct tag_info *ti, int bytes_completed, int status)
{
	struct bdev_bio *bbio = ti->bbio;
	struct tag_dma_info *tag_dma = ti->tag_dma;

	/* Update the remaining bytes in the dma buffer. */
	if (tag_dma) {
		tag_dma->remaining -= bytes_completed;
		if (tag_dma->remaining <= 0) {
			if (tag_dma->unmap) {
				dev_dbg(dev, "unmap_page mem=%pad, len=%d, dma_dir=%d, remaining=%d\n",
					&tag_dma->mem, tag_dma->len, tag_dma->dma_dir, tag_dma->remaining);
				/* all the transfers for the dma buffer are done. */
				dma_sync_single_for_cpu(dev, tag_dma->mem,
							tag_dma->len, tag_dma->dma_dir);
				dma_unmap_page(dev, tag_dma->mem,
					       tag_dma->len, tag_dma->dma_dir);
			}
			bdev_free_tag_dma(tag_dma);
			ti->tag_dma = NULL;
		}
	}

	if (status < 0)  /* record error */
		bbio->status = status;
	if (bbio->remaining < bytes_completed)
		/* weird error */
		return -1;
	bbio->remaining -= bytes_completed;
	if (bbio->remaining == 0)
		return 0;
	else
		return bbio->remaining;
}
#endif

#define GENZ_BLK_WAIT_TIME (2 * HZ) /* 2 seconds */  /* Revisit */

static const struct block_device_operations genz_bdev_ops = {
	.owner   = THIS_MODULE,
	.open    = genz_bdev_open,
	.release = genz_bdev_release,
	.ioctl   = genz_bdev_ioctl,
};

static void genz_blk_sgl_cmpl(struct genz_dev *zdev,
			      struct genz_sgl_info *sgli)
{
	struct genz_blk_cmd *cmd = to_genz_blk_cmd(sgli);
	struct request *req = blk_mq_rq_from_pdu(cmd);

	dma_unmap_sg(sgli->xdmi->dma_dev, cmd->sg, cmd->nents,
		     rq_dma_dir(req));
	cmd->error = errno_to_blk_status(sgli->status);
	dev_dbg(&zdev->dev, "req=%px, status=%d, error=%d\n",
		req, sgli->status, cmd->error);
	blk_mq_end_request(req, cmd->error);
}

static blk_status_t genz_blk_queue_rq(struct blk_mq_hw_ctx *hctx,
				      const struct blk_mq_queue_data *mqd)
{
	struct request *const req = mqd->rq;
	struct request_queue *const q = req->q;
	struct genz_bdev *const zbd = q->queuedata;
	struct genz_rmr_info *rmri = &zbd->rmr_info;
	struct device *dev = disk_to_dev(zbd->gd);
	struct genz_blk_ctx *bctx = hctx->driver_data;
	struct genz_dev *zdev = zbd->bstate->zdev;
	const u32 tag = blk_mq_unique_tag(req);
	struct genz_blk_cmd *const cmd = blk_mq_rq_to_pdu(req);
	const u32 lba = blk_rq_pos(req);
	const u32 count = blk_rq_sectors(req);
	const int data_dir = rq_data_dir(req);
	unsigned short segments = blk_rq_nr_phys_segments(req);
	blk_status_t ret = BLK_STS_OK;
	int nr_mapped, err;

	might_sleep_if(hctx->flags & BLK_MQ_F_BLOCKING);

	/* setup cmd */
	cmd->segments = segments;
	cmd->sgli.rmri = rmri;
	cmd->sgli.xdmi = &bctx->xdmi;
	cmd->sgli.cmd = (data_dir == WRITE) ? GENZ_XDM_WRITE : GENZ_XDM_READ;
	cmd->sgli.tag = tag;
	cmd->sgli.offset = (loff_t)lba * KERNEL_SECTOR_SIZE;
	cmd->sgli.sg = cmd->sg;
	cmd->sgli.cmpl_fn = genz_blk_sgl_cmpl;
	dev_dbg_ratelimited(dev, "cmd=%s, tag=%u, lba=%u, count=%u, segments=%hu, offset=%llu\n",
			    (cmd->sgli.cmd == GENZ_XDM_WRITE) ? "WR" : "RD",
			    tag, lba, count, cmd->segments,
			    cmd->sgli.offset);
	/* map data */
	/* Revisit: add non-XDM version */
	cmd->nents = blk_rq_map_sg(q, req, cmd->sg);
	if (!cmd->nents) {
		ret = BLK_STS_RESOURCE;
		goto out;
	}
	if (cmd->segments > 0) {
		nr_mapped = dma_map_sg_attrs(bctx->xdmi.dma_dev,
					     cmd->sg, cmd->nents,
					     rq_dma_dir(req), DMA_ATTR_NO_WARN);
		if (!nr_mapped) {
			ret = BLK_STS_RESOURCE;
			goto out;
		}
		cmd->sgli.nr_sg = nr_mapped;
	}
	blk_mq_start_request(req);
	/* submit cmd */
	err = genz_sgl_request(zdev, &cmd->sgli);
	if (err < 0)
		ret = errno_to_blk_status(err);

out:
	if (ret != BLK_STS_OK) {
		/* Revisit: unmap data */
	}
	return ret;
}

/* Revisit: currently unused */
//static void genz_blk_complete_rq(struct request *req)
//{
//	struct genz_blk_cmd *cmd = blk_mq_rq_to_pdu(req);
//
//	blk_mq_end_request(req, cmd->error);
//}

static enum blk_eh_timer_return genz_blk_timeout_rq(struct request *rq,
						    bool reserved)
{
	struct genz_bdev *const zbd = rq->q->queuedata;

	/* Revisit: do more than print an error */
	dev_err_ratelimited(disk_to_dev(zbd->gd),
			    "request with tag %#x timed out\n",
			    blk_mq_unique_tag(rq));

	return BLK_EH_RESET_TIMER;
}

static int genz_blk_init_rq(struct blk_mq_tag_set *set, struct request *req,
			    uint hctx_idx, uint numa_node)
{
	struct genz_blk_cmd *const cmd = blk_mq_rq_to_pdu(req);

	pr_debug("hctx_idx=%u, cmd=%px\n", hctx_idx, cmd);
	//skreq->state = SKD_REQ_STATE_IDLE; /* Revisit: copied */
	//skreq->sg = (void *)(skreq + 1);
	sg_init_table(cmd->sg, GENZ_BLK_MAX_SG);

	return 0;
}

/* Revisit: currently empty */
//static void genz_blk_exit_rq(struct blk_mq_tag_set *set,
//			     struct request *rq, uint hctx_idx)
//{
//	struct genz_blk_cmd *const cmd = blk_mq_rq_to_pdu(rq);
//}

#define QFACTOR  16  /* Revisit: compute or make tunable */

static int genz_blk_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
			      uint index)
{
	struct genz_blk_bridge *bbr = (struct genz_blk_bridge *)data;
	struct genz_blk_ctx *bctx;
	struct genz_bridge_info *br_info = &bbr->zbdev->br_info;
	struct genz_rdm_info *rdmi = NULL;
	int ret;

	pr_debug("bbr=%px, index=%u\n", bbr, index);
	/* fill in genz_blk_ctx */
	bctx = &bbr->bctx[index];
	bctx->bbr = bbr;
	/* Revisit: add non-XDM mode */
	bctx->xdmi.cmdq_ent = bbr->tag_set->queue_depth * QFACTOR;
	bctx->xdmi.cmplq_ent = bctx->xdmi.cmdq_ent;
	bctx->xdmi.traffic_class = GENZ_TC_0;
	bctx->xdmi.priority = 0;
	bctx->xdmi.driver_data = hctx;
	if (!br_info->xdm_cmpl_intr && br_info->loopback &&
	    br_info->rdm && br_info->rdm_cmpl_intr) {
		/* use loopback to RDM as source of cmpl interrupts */
		rdmi = &bctx->rdmi;
		rdmi->cmplq_ent = bctx->xdmi.cmplq_ent;
		rdmi->driver_data = hctx;
		bctx->have_rdmi = true;
	}
	/* allocate XDM (and maybe RDM) queue */
	ret = genz_alloc_queues(bbr->zbdev, &bctx->xdmi, rdmi);
	if (ret < 0)
		goto free;
	hctx->driver_data = bctx;

	return 0;

free:
	kfree(bctx);
	return ret;
}

static void genz_blk_exit_hctx(struct blk_mq_hw_ctx *hctx, uint index)
{
	struct genz_blk_ctx *bctx = (struct genz_blk_ctx *)hctx->driver_data;
	struct genz_blk_bridge *bbr = bctx->bbr;
	struct genz_rdm_info *rdmi = (bctx->have_rdmi) ? &bctx->rdmi : NULL;

	pr_debug("bbr=%px, index=%u, rdmi=%px\n", bbr, index, rdmi);
	/* free XDM (and maybe RDM) queue */
	(void)genz_free_queues(&bctx->xdmi, rdmi);
}

static const struct blk_mq_ops genz_blk_mq_ops = {
	.queue_rq       = genz_blk_queue_rq,
//	.complete	= genz_blk_complete_rq, /* Revisit: needed? */
	.timeout	= genz_blk_timeout_rq,
	.init_request	= genz_blk_init_rq,
//	.exit_request	= genz_blk_exit_rq,  /* Revisit: currently empty */
	.init_hctx      = genz_blk_init_hctx,
	.exit_hctx      = genz_blk_exit_hctx,
};

static int genz_blk_bdev_start_size(struct genz_resource *zres,
				    size_t *start, size_t *size)
{
	size_t start_aligned, end_aligned, size_adjusted;
	int ret = 0;

	/* for DAX, make sure start/size are page-aligned */
	/* Revist: how can this work across systems with different PAGE_SIZE? */
	start_aligned = round_up(zres->res.start, PAGE_SIZE);
	end_aligned = round_down(zres->res.end + 1, PAGE_SIZE) - 1;
	size_adjusted = end_aligned - start_aligned + 1;
	if (size_adjusted == 0) {
		ret = -ENOSPC;
	} else {
		*start = start_aligned;
		*size = size_adjusted;
	}

	return ret;
}

static int genz_blk_register_gendisk(struct genz_bdev *zbd)
{
	struct gendisk *gd;
	int ret = 0;

	zbd->gd = gd = alloc_disk(GENZ_BDEV_MINORS);
	if (!gd) {
		ret = -ENOMEM;
		goto out;
	}
	gd->major = genz_bdev_major;
	gd->first_minor = zbd->bdev_start_minor;
	gd->fops = &genz_bdev_ops;
	gd->queue = zbd->queue;
	gd->private_data = zbd;
	scnprintf(gd->disk_name, 32, GENZ_BDEV_NAME "%u", zbd->bindex);
	pr_info("%s: first_minor=%d, base_zaddr=0x%llx\n",
		gd->disk_name, gd->first_minor, zbd->base_zaddr);
	set_capacity(gd, zbd->size/KERNEL_SECTOR_SIZE);
	pr_info("%s: set capacity to %zu 512 byte sectors\n",
		gd->disk_name, zbd->size/KERNEL_SECTOR_SIZE);
	/* Revisit: blk device appears under devices/virtual/block */
	add_disk(gd);

 out:
	return ret;
}

static int genz_blk_construct_bdev(struct genz_bdev *zbd,
				   struct genz_blk_bridge *bbr)
{
	int err = 0;

	zbd->queue = blk_mq_init_queue(bbr->tag_set);
	if (IS_ERR(zbd->queue)) {
		err = PTR_ERR(zbd->queue);
		return err;
	}
	zbd->queue->queuedata = zbd;
	blk_queue_logical_block_size(zbd->queue, GENZ_BLOCK_SIZE);
	blk_queue_max_segments(zbd->queue, GENZ_BLK_MAX_SG);
	blk_queue_max_hw_sectors(zbd->queue,
			 bbr->zbdev->br_info.xdm_max_xfer/KERNEL_SECTOR_SIZE);
	blk_queue_max_segment_size(zbd->queue,
				   bbr->zbdev->br_info.xdm_max_xfer);
	/* Gen-Z does not need bouncing. */
	blk_queue_bounce_limit(zbd->queue, BLK_BOUNCE_ANY);
	blk_queue_write_cache(zbd->queue, false, false);

	return genz_blk_register_gendisk(zbd);
}

static void genz_blk_destroy_bdev(struct genz_bdev *zbd)
{
	del_gendisk(zbd->gd);
	put_disk(zbd->gd);
	blk_cleanup_queue(zbd->queue);
}

static int genz_blk_init_tag_set(struct genz_blk_bridge *bbr)
{
	struct genz_blk_ctx *bctx;

	bbr->tag_set = &bbr->__tag_set; /* Revisit: need this? */
	bbr->tag_set->ops = &genz_blk_mq_ops;
	bbr->tag_set->nr_hw_queues = 2; /* Revisit */
	bbr->tag_set->queue_depth = 64; /* Revisit */
	bbr->tag_set->cmd_size = sizeof(struct genz_blk_cmd);
	bbr->tag_set->numa_node = NUMA_NO_NODE;
	bbr->tag_set->flags = BLK_MQ_F_SHOULD_MERGE |
		BLK_ALLOC_POLICY_TO_MQ_FLAG(BLK_TAG_ALLOC_FIFO);
	bbr->tag_set->driver_data = bbr; /* Revisit: need this? */
	/* allocate array of genz_blk_ctx */
	bctx = kzalloc(sizeof(*bctx) * bbr->tag_set->nr_hw_queues, GFP_KERNEL);
	if (!bctx) {
		return -ENOMEM;
	}
	bbr->bctx = bctx;
	return blk_mq_alloc_tag_set(bbr->tag_set);
}

LIST_HEAD(genz_blk_bbr_list);

static struct genz_blk_bridge *find_bbr(struct genz_bridge_dev *zbdev)
{
	struct genz_blk_bridge *bbr = NULL;
	struct uuid_tracker *uu;
	int err;

	mutex_lock(&genz_blk_lock);
	list_for_each_entry(bbr, &genz_blk_bbr_list, bbr_node) {
		if (bbr->zbdev == zbdev) {
			pr_debug("found bbr=%px\n", bbr);
			goto unlock;
		}
	}
	/* not found - allocate a new one */
	bbr = kzalloc(sizeof(*bbr), GFP_KERNEL);
	if (!bbr) {
		bbr = ERR_PTR(-ENOMEM);
		goto unlock;
	}
	bbr->zbdev = zbdev;
	err = genz_blk_init_tag_set(bbr);
	if (err < 0) {
		goto free;
	}
	genz_init_mem_data(&bbr->mem_data, zbdev);
	wildcat_generate_uuid(zbdev, &bbr->uuid);  /* Revisit: wildcat-specific */
	uu = genz_uuid_tracker_alloc_and_insert(&bbr->uuid, UUID_TYPE_LOCAL,
						0, &bbr->mem_data, GFP_KERNEL,
						&err);
	if (!uu) {
		goto free;
	}

	bbr->mem_data.local_uuid = uu;
	/* Revisit: we need a kref to keep track of when to free bbr */
	list_add_tail(&bbr->bbr_node, &genz_blk_bbr_list);
	mutex_unlock(&genz_blk_lock);

out:
	return bbr;

free:
	kzfree(bbr);
	if (err < 0)
		bbr = ERR_PTR(err);
unlock:
	mutex_unlock(&genz_blk_lock);
	goto out;
}

static int genz_bdev_probe(struct genz_blk_state *bstate,
			   struct genz_resource *zres)
{
	int err = 0;
	size_t bdev_size, bdev_start;
	struct genz_bdev *zbd;
	struct genz_blk_bridge *bbr;
	struct genz_mem_data *mdata;
	struct genz_dev *zdev = bstate->zdev;
	struct genz_bridge_dev *zbdev = zdev->zbdev;
	struct genz_bridge_info *br_info = &zbdev->br_info;
	uint32_t gcid = genz_dev_gcid(zdev, 0);
	uint64_t access;
	uint32_t rkey;

	dev_dbg(&zdev->dev, "allocating genz_bdev: bstate=%px, zres=%px\n",
		bstate, zres);
	zbd = kzalloc(sizeof(*zbd), GFP_KERNEL);
	if (!zbd) {
		err = -ENOMEM;
		goto fail;
	}

	mutex_lock(&genz_blk_lock);
	zbd->bindex = genz_blk_index++;
	zbd->bdev_start_minor = genz_bdev_start_minor;
	genz_bdev_start_minor += GENZ_BDEV_MINORS;
	mutex_unlock(&genz_blk_lock);

	spin_lock_init(&zbd->lock);
	zbd->bstate = bstate;
	zbd->zres = zres;
#ifdef OLD_GZD
	/* Register blockdevice irq handler */
	if (genz_blk_driver.request_irq != NULL) {
		genz_blk_driver.request_irq(card_data->hw,
					    BlockRWInt, bdev_irq_handler, 0,
					    GENZ_BLK_DRV_NAME, card_data);
	}
#endif
	err = genz_blk_bdev_start_size(zres, &bdev_start, &bdev_size);
	if (err < 0)
		goto fail;  /* Revisit: other cleanup */
	zbd->base_zaddr = bdev_start;
	zbd->size = bdev_size;
	zbd->gcid = gcid;
	bbr = bstate->bbr;
	mdata = &bbr->mem_data;
	/* Revisit: use zres to choose RO/RW access & rkey */
	access = GENZ_MR_WRITE_REMOTE|GENZ_MR_INDIVIDUAL;
	access |= (br_info->load_store) ? GENZ_MR_REQ_CPU : 0;
	rkey = zres->rw_rkey;
	err = genz_rmr_import(mdata, &zdev->instance_uuid, gcid,
			      zbd->base_zaddr, zbd->size, access,
			      rkey, &zbd->rmr_info);
	if (err < 0)
		goto fail;  /* Revisit: other cleanup */
	err = genz_blk_construct_bdev(zbd, bbr);
	if (err < 0)
		goto fail;  /* Revisit: other cleanup */

	mutex_lock(&bstate->lock);
	list_add_tail(&zbd->bdev_node, &bstate->bdev_list);
	mutex_unlock(&bstate->lock);

	return 0;

fail:
	return err;
}

static int genz_bdev_remove(struct genz_bdev *zbd)
{
	struct genz_blk_state  *bstate = zbd->bstate;
	struct genz_blk_bridge *bbr    = bstate->bbr;
	struct genz_mem_data   *mdata  = &bbr->mem_data;
	int err;

	dev_dbg(&bstate->zdev->dev, "entered\n");
	mutex_lock(&bstate->lock);
	list_del(&zbd->bdev_node);
	mutex_unlock(&bstate->lock);
	genz_blk_destroy_bdev(zbd);
	err = genz_rmr_free(mdata, &zbd->rmr_info);
	kfree(zbd);
	return err;
}

static int genz_blk_probe(struct genz_dev *zdev,
			  const struct genz_device_id *zdev_id)
{
	struct genz_blk_state  *bstate;
	struct genz_resource   *zres;
	struct genz_blk_bridge *bbr;
	struct genz_bridge_dev *zbdev = zdev->zbdev;
	int ret = 0;

	/* allocate & initialize state structure */
	dev_dbg(&zdev->dev, "allocating bstate\n");
	bstate = kzalloc(sizeof(*bstate), GFP_KERNEL);
	if (!bstate) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&bstate->bdev_list);
	mutex_init(&bstate->lock);
	bstate->zdev = zdev;
	init_waitqueue_head(&bstate->block_io_queue);
	genz_set_drvdata(zdev, bstate);

	bbr = find_bbr(zbdev);
	if (IS_ERR(bbr)) {
		ret = PTR_ERR(bbr);
		goto out;  /* Revisit: other cleanup */
	}
	bstate->bbr = bbr;
	dev_dbg(&zdev->dev, "instance_uuid=%pUb\n", &zdev->instance_uuid);
	/* Revisit: need non-wildcat-specific UUID_IMPORT */
	/* Revisit: should not need UUID_IS_FAM */
	ret = wildcat_kernel_UUID_IMPORT(&bbr->mem_data, &zdev->instance_uuid,
					 UUID_IS_FAM, GFP_KERNEL);
	if (ret < 0)
		goto out; /* Revisit: undo bstate */
	genz_for_each_resource(zres, zdev) {
		if (genz_is_data_resource(zres)) {
			ret = genz_bdev_probe(bstate, zres);
			/* Revisit: error handling */
		} else {
			/* Revisit: print control resource name */
			dev_warn(&zdev->dev, "unexpected control resource\n");
		}
	}

out:
	return ret;
}

static int genz_blk_remove(struct genz_dev *zdev)
{
	struct genz_blk_state  *bstate = genz_get_drvdata(zdev);
	struct genz_blk_bridge *bbr    = bstate->bbr;
	int ret = 0;
	uint32_t uu_flags = 0;
	bool local;
	struct genz_bdev *zbd, *next;

	dev_dbg(&zdev->dev, "entered\n");
	list_for_each_entry_safe(zbd, next, &bstate->bdev_list, bdev_node) {
		ret = genz_bdev_remove(zbd);
		/* Revisit: error handling */
	}

	/* Revisit: need non-wildcat-specific UUID_FREE */
	ret = wildcat_common_UUID_FREE(&bbr->mem_data,
				       &zdev->instance_uuid, &uu_flags, &local);
	kfree(bstate);
	return ret;
}

static struct genz_driver genz_blk_driver = {
	.name      = GENZ_BLK_DRV_NAME,
	.id_table  = genz_blk_id_table,
	.probe     = genz_blk_probe,
	.remove    = genz_blk_remove,
};

static int __init genz_blk_init(void)
{
	int ret;

	genz_bdev_major = register_blkdev(0, GENZ_BDEV_NAME);
	if (genz_bdev_major < 0) {
		ret = genz_bdev_major;
		pr_err("register_blkdev: unable to get major number %d\n",
		       ret);
		goto out;
	}
	ret = genz_register_driver(&genz_blk_driver);
	if (ret < 0) {
		pr_warning("%s:%s:genz_register_driver returned %d\n",
		       GENZ_BLK_DRV_NAME, __func__, ret);
		goto unregister_blkdev;
	}

out:
	return ret;

unregister_blkdev:
	unregister_blkdev(genz_bdev_major, GENZ_BDEV_NAME);
	goto out;
}

static void __exit genz_blk_exit(void)
{
	genz_unregister_driver(&genz_blk_driver);
	unregister_blkdev(genz_bdev_major, GENZ_BDEV_NAME);
}

module_init(genz_blk_init);
module_exit(genz_blk_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Block driver for Gen-Z");
