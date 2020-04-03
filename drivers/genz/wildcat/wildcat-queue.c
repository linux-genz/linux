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

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/genz.h>

#include "wildcat.h"

/* Forward declarations */
static int xdm_last_used_slice = SLICES-1;
static int rdm_last_used_slice = SLICES-1;

/*
 * Called from the wildcat_core driver probe function for each slice discovered.
 */
void wildcat_xqueue_init(struct slice *sl)
{
	spin_lock_init(&sl->xdm_slice_lock);
	bitmap_zero(sl->xdm_alloced_bitmap, XDM_QUEUES_PER_SLICE);
	sl->xdm_alloc_count = 0;

	return;
}

/*
 * Called from the wildcat_core driver probe function for each slice discovered.
 */
void wildcat_rqueue_init(struct slice *sl)
{
	spin_lock_init(&sl->rdm_slice_lock);
	bitmap_zero(sl->rdm_alloced_bitmap, RDM_QUEUES_PER_SLICE);
	sl->rdm_alloc_count = 0;

	return;
}

/*
 * These offsets into the XDM QCM are for fields that requre initialization
 * for ECC because they are "register files". Note that Active Command
 * Count in byte 0x28 is also a register file and need initialization for
 * ECC.
 */
int xqcm_hsr_offsets[] =
	{ 0x0, 0x08, 0x10, 0x18, 0x28, 0x40, 0x80, 0xc0, 0x100 };
#define XDM_A_MASK		0x0000000000008000
#define XDM_ACC_MASK		0x00000000000007ff

/*
 * These offsets into the RDM QCM are for fields that requre initialization
 * for ECC because they are "register files". Note that Active Command
 * Count in byte 0x28 is also a register file and needs initialization for
 * ECC.
 */
int rqcm_hsr_offsets[] =
	{ 0x0, 0x08, 0x40, 0x80, 0xc0 };
#define RDM_A_MASK		0x0000000000000001

static DECLARE_WAIT_QUEUE_HEAD(wqA);

/* Revisit: still useful? */
void wildcat_debug_xdm_qcm(const char *func, uint line, const void *cqcm)
{
#ifdef OLD_ZHPE
	void            *qcm = (void *)cqcm;
	uint            off;
	uint64_t        cmd_addr;
	uint64_t        cmpl_addr;
	uint64_t        cmd_paddr;
	uint64_t        cmpl_paddr;
	uint64_t        cmd_vaddr;
	uint64_t        cmpl_vaddr;

	if (!(zhpe_debug_flags & DEBUG_XQUEUE))
		return;

	cmd_addr = xdm_qcm_read(qcm, XDM_CMD_ADDR_OFFSET) & ~0x1FULL;
	cmpl_addr = xdm_qcm_read(qcm, XDM_CMPL_ADDR_OFFSET) & ~0x1FULL;
	if (xdm_qcm_read(qcm, XDM_PASID_OFFSET) & XDM_PASID_QVIRT_FLAG) {
		cmd_vaddr = cmd_addr;
		cmpl_vaddr = cmpl_addr;
		cmd_paddr = 0;
		cmpl_paddr = 0;
	} else {
		cmd_paddr = cmd_addr;
		cmpl_paddr = cmpl_addr;
		cmd_vaddr = (uintptr_t)phys_to_virt(cmd_addr);
		cmpl_vaddr = (uintptr_t)phys_to_virt(cmpl_addr);
	}

	printk(KERN_DEBUG
	       "%s,%u:xqcm %px cmd 0x%llx/0x%llx cmpl 0x%llx/0x%llx\n",
	       func, line, qcm, cmd_vaddr, cmd_paddr, cmpl_vaddr, cmpl_paddr);
	for (off = XDM_DUMP_08_START; off <= XDM_DUMP_08_END; off += 0x08)
		printk(KERN_DEBUG "xqcm[0x%03x] = 0x%llx\n",
		       off, xdm_qcm_read(qcm, off));
	for (off = XDM_DUMP_40_START; off <= XDM_DUMP_40_END; off += 0x40)
		printk(KERN_DEBUG "xqcm[0x%03x] = 0x%llx\n",
		       off, xdm_qcm_read(qcm, off));
#endif
}

void wildcat_debug_rdm_qcm(const char *func, uint line, const void *cqcm)
{
#ifdef OLD_ZHPE
	void            *qcm = (void *)cqcm;
	uint            off;
	uint64_t        cmpl_addr;
	uint64_t        cmpl_paddr;
	uint64_t        cmpl_vaddr;

	if (!(zhpe_debug_flags & DEBUG_XQUEUE))
		return;

	cmpl_addr = rdm_qcm_read(qcm, RDM_CMPL_ADDR_OFFSET) & ~0x1FULL;
	if (rdm_qcm_read(qcm, RDM_SIZE_OFFSET) & RDM_SIZE_QVIRT_FLAG) {
		cmpl_vaddr = cmpl_addr;
		cmpl_paddr = 0;
	} else {
		cmpl_paddr = cmpl_addr;
		cmpl_vaddr = (uintptr_t)phys_to_virt(cmpl_addr);
	}

	printk(KERN_DEBUG "%s,%u:rqcm %px cmpl 0x%llx/0x%llx\n",
	       func, line, qcm, cmpl_vaddr, cmpl_paddr);
	for (off = RDM_DUMP_08_START; off <= RDM_DUMP_08_END; off += 0x08)
		printk(KERN_DEBUG "rqcm[0x%03x] = 0x%llx\n",
		       off, rdm_qcm_read(qcm, off));
	for (off = RDM_DUMP_40_START; off <= RDM_DUMP_40_END; off += 0x40)
		printk(KERN_DEBUG "rqcm[0x%03x] = 0x%llx\n",
		       off, rdm_qcm_read(qcm, off));
#endif
}

static int xdm_get_A_bit(struct wildcat_xdm_qcm *qcm, uint16_t *acc)
{
	uint64_t a;

	a = xdm_qcm_read(qcm, XDM_A_OFFSET);
	*acc = (uint16_t)(a & XDM_ACC_MASK);
	return((a & XDM_A_MASK) ? 1 : 0);
}

static int rdm_get_A_bit(struct wildcat_rdm_qcm *qcm)
{
	uint64_t a;

	a = rdm_qcm_read(qcm, RDM_A_OFFSET);
	return((a & RDM_A_MASK) ? 1 : 0);
}

#define COMMANDS_TO_BUSYWAIT	5
#define COMMANDS_IN_20MS	280	/* Revisit Carbon: this is for Carbon. Check on HW */
#define USEC_WAIT_PER_COMMAND	72	/* Revisit Carbon: this is for Carbon. Check on HW */
#define BAIL_OUT		200	/* give up is wait loops this many */
#define MSLEEP_WAIT		2       /* 2ms wait for msleep loop */

#define BUSY_WAIT	1
#define USLEEP_RANGE	2
#define MSLEEP		3
static int xdm_wait(struct wildcat_xdm_qcm *qcm, int wait_type, int wait_time)
{
	int bail_out = 0;
	uint16_t acc;

	while(xdm_get_A_bit(qcm, &acc) == 1) {
		switch (wait_type) {
		case USLEEP_RANGE:
			usleep_range(wait_time/2, wait_time);
			break;
		case MSLEEP:
			msleep(wait_time);
			break;
		case BUSY_WAIT:
			break;
		}
		if (bail_out++ > BAIL_OUT) { /* prevent an infinite loop */
			pr_debug("xdm_wait: queue did not go idle. Active command count is %d\n",
				 acc);
			wildcat_debug_xdm_qcm(__func__, __LINE__, qcm);
			return -1;
		}
	}
	return 0;
}

static int xdm_wait_for_active_clear(struct wildcat_xdm_qcm *qcm)
{
	int a;
	uint16_t acc;
	int wait_time;

	/* Get active command count to calculate an estimated delay */
	a = xdm_get_A_bit(qcm, &acc);

	/* Queue is not active */
	if (!a)
		return 0;

	/* If only a small number of commands, busy wait on the A bit */
	if (acc < COMMANDS_TO_BUSYWAIT) {
		return xdm_wait(qcm, BUSY_WAIT, 0);
	}
	/* Use usleep_range if commands could be processed in 20ms */
	else if (acc < COMMANDS_IN_20MS) {
		if (acc == 0) acc = 1; /* prevent divide by 0 */
		wait_time = acc * USEC_WAIT_PER_COMMAND;
		return xdm_wait(qcm, USLEEP_RANGE, wait_time);
	}
	/* There are more than 20ms of commands, use msleep() */
	else {
		return xdm_wait(qcm, MSLEEP, MSLEEP_WAIT);
	}
}

static int clear_xdm_qcm(struct wildcat_xdm_qcm *qcm)
{
	int h;
	uint64_t junk;
	int hsr_count;

	/* Set the master stop bit */
	xdm_qcm_write_val(1, qcm, XDM_MASTER_STOP_OFFSET);

	/* Read back to ensure synchronization. */
	junk = xdm_qcm_read(qcm, XDM_MASTER_STOP_OFFSET);

	if (xdm_wait_for_active_clear(qcm)) {
		return -1;
	}

	/* Write each qcm HSR that contains data. */
	hsr_count = sizeof(xqcm_hsr_offsets)/sizeof(xqcm_hsr_offsets[0]);
	for (h = 0; h < hsr_count; h++)
		xdm_qcm_write_val(0, qcm, xqcm_hsr_offsets[h]);
	return 0;
}

int wildcat_clear_xdm_qcm(
	struct wildcat_xdm_qcm *qcm)
{
	int      q;
	uint64_t junk;

	pr_debug("qcm = 0x%px\n", qcm);

	/*
	 * The XDM HSR space has 32MB for 256 QCM. Each QCM has an App
	 * and a Kernel page for a total of 512 QCM. We write/read each
	 * kernel HSR page (not the App) to initialize the ECC and contents
	 * after a reset. Any errors are to be ignored.
	 */
	for (q = 0; q < XDM_QUEUES_PER_SLICE*2; q = q+2) {
		if (clear_xdm_qcm(&qcm[q]) != 0) {
			pr_debug("zhpe_clear_xdm_qcm: queue %d failed to clear\n", q);
			return -1;
		}
	}

	/* Read back one value to ensure synchronization. */
	junk = xdm_qcm_read(&qcm[0], XDM_MASTER_STOP_OFFSET);

	return 0;
}

static int clear_rdm_qcm(struct wildcat_rdm_qcm *qcm)
{
	int h;
	int bail_out = 0;
	uint64_t junk;
	int hsr_count;

	/* Set the master stop bit */
	rdm_qcm_write_val(1, qcm, RDM_MASTER_STOP_OFFSET);

	/* Read back to ensure synchronization. */
	junk = rdm_qcm_read(qcm, RDM_MASTER_STOP_OFFSET);

	/* Busy wait on the A bit */
	while (rdm_get_A_bit(qcm) == 1) {
		if (bail_out++ > 200) { /* prevent an infinite loop */
			pr_debug("clear_rdm_qcm: queue did not go idle.\n");
			return -1;
		}
	}

	/* Write each qcm HSR that contains data. */
	hsr_count = sizeof(rqcm_hsr_offsets)/sizeof(rqcm_hsr_offsets[0]);
	for (h = 0; h < hsr_count; h++)
		rdm_qcm_write_val(0, qcm, rqcm_hsr_offsets[h]);
	return 0;
}

int wildcat_clear_rdm_qcm(
	struct wildcat_rdm_qcm *qcm)
{
	int      q;
	uint64_t junk;

	pr_debug("qcm = 0x%px\n", qcm);

	/*
	 * The RDM HSR space has 32MB for 256 QCM. Each QCM has an App
	 * and a Kernel page for a total of 512 QCM. We write/read each
	 * kernel HSR page (not the App) to initialize the ECC and contents
	 * after a reset. Any errors are to be ignored.
	 */
	for (q = 0; q < RDM_QUEUES_PER_SLICE*2; q = q+2) {
		if (clear_rdm_qcm(&qcm[q]) != 0) {
			pr_debug("zhpe_clear_rdm_qcm: queue %d failed to clear\n", q);
			return -1;
		}
	}

	/* Read back one value to ensure synchronization. */
	junk = rdm_qcm_read(&qcm[0], RDM_MASTER_STOP_OFFSET);

	return 0;
}

static int distribute_irq(unsigned long *alloced_bitmap,
			  struct slice *sl, int *vector)
{
	int q;
	int min_vector, min;
	int v;
	int count;
	int clump_size = MAX_RDM_QUEUES_PER_SLICE / sl->irq_vectors_count;
	DECLARE_BITMAP(tmp_bitmap, RDM_QUEUES_PER_SLICE);

	/* Make a copy of the alloced_bitmap for shifting */
	bitmap_copy(tmp_bitmap, alloced_bitmap, RDM_QUEUES_PER_SLICE);
	/*
	 * Choose a free queue that distributes across the clumped irqs.
	 * The hardware may support up to 32 MSI interrupt vectors. The
	 * queues will be mapped to an interrupt in order. E.g. queues
	 * 0-7 map to vector 0, 8-15 vector 1, etc for 32 MSI vectors.
	 * Note that the actual number of MSI vectors that Linux allocated
	 * is stored in sl->irq_vectors_count - it may not be 32.
	 */
	/* Find which vector has the fewest queues assigned */
	min_vector = min = -1;
	for (v=0; v < sl->irq_vectors_count; v++) {
		/* count bits set in bitmap for the given range */
		count = bitmap_weight(tmp_bitmap, clump_size);
		if (min == -1) {
			min_vector = v;
			min = count;
		} else if (count < min) {
			/* Found a vector with fewer queues */
			min_vector = v;
			min = count;
		}
		/* Shift the bitmap to count the next clump */
		bitmap_shift_right(tmp_bitmap, tmp_bitmap, clump_size,
				   RDM_QUEUES_PER_SLICE);
	}
	/* Look for a free queue in that minimum range */
	q = find_first_zero_bit(alloced_bitmap+(min_vector*clump_size),
				clump_size)
		+ (min_vector*clump_size);
	*vector = min_vector;
	/* Return the chosen free queue */
	return q;
}

int wildcat_rdm_queue_to_vector(int queue, struct slice *sl)
{
	int vector;
	int clump_size = MAX_RDM_QUEUES_PER_SLICE / sl->irq_vectors_count;

	vector = queue / clump_size;

	return vector;
}

static int xdm_choose_slice_queue(
		struct bridge *br,
		uint8_t       slice_mask,
		int           *slice,
		int           *queue)
{
	int i;
	int q;
	int s = (xdm_last_used_slice + 1) % SLICES;
	struct slice *slices;
	struct slice *cur_slice;

	slices = br->slice;

	for (i = 0; i < SLICES; i++) {
		if (slice_mask & (1<<s)) {
			cur_slice = &slices[s];
			/* make sure this slice is valid */
			if (SLICE_VALID(cur_slice)) {
				spin_lock (&cur_slice->xdm_slice_lock);
				if (cur_slice->xdm_alloc_count < XDM_QUEUES_PER_SLICE) {
					/* Use this slice */
					cur_slice->xdm_alloc_count++;
					q = find_first_zero_bit(cur_slice->xdm_alloced_bitmap, XDM_QUEUES_PER_SLICE);
					set_bit(q, cur_slice->xdm_alloced_bitmap);
					spin_unlock (&cur_slice->xdm_slice_lock);
					xdm_last_used_slice = s;
					*slice = s;
					*queue = q;
					return 0;
				}
				spin_unlock (&cur_slice->xdm_slice_lock);
			}
		}
		s = (s + 1) % SLICES;
	}

	/* Didn't find any queues available. */
	return -ENOENT;
}

static int rdm_choose_slice_queue(
		struct bridge *br,
		uint8_t       slice_mask,
		int           *slice,
		int           *queue,
		int           *irq_vector)
{
	int i;
	int q;
	int s = (rdm_last_used_slice + 1) % SLICES;
	struct slice *slices;
	struct slice *cur_slice;
	int vector;

	slices = br->slice;

	for (i = 0; i < SLICES; i++) {
		if (slice_mask & (1<<s)) {
			cur_slice = &slices[s];

			pr_debug("considering slice %d\n", s);
			/* make sure this slice is valid */
			if (SLICE_VALID(cur_slice)) {
				spin_lock (&cur_slice->rdm_slice_lock);
				if (cur_slice->rdm_alloc_count < RDM_QUEUES_PER_SLICE) {
					/* Use this slice */
					cur_slice->rdm_alloc_count++;
					q = distribute_irq(cur_slice->rdm_alloced_bitmap, cur_slice, &vector);
					set_bit(q, cur_slice->rdm_alloced_bitmap);
					spin_unlock (&cur_slice->rdm_slice_lock);
					rdm_last_used_slice = s;
					*slice = s;
					*queue = q;
					*irq_vector = (s*VECTORS_PER_SLICE)+vector;
					pr_debug("assigning slice %d queue %d irq_vector %d\n",
						 *slice, *queue, *irq_vector);
					return 0;
				}
				spin_unlock (&cur_slice->rdm_slice_lock);
			}
		}
		s = (s + 1) % SLICES;
	}

	/* Didn't find any queues available. */
	return -ENOENT;
}

void wildcat_xdm_release_slice_queue(
	struct bridge *br,
	int           slice,
	int           queue)
{
	struct slice *slices;
	struct slice *cur_slice;

	slices = br->slice;
	cur_slice = &slices[slice];

	spin_lock (&cur_slice->xdm_slice_lock);
	cur_slice->xdm_alloc_count--;
	clear_bit(queue, cur_slice->xdm_alloced_bitmap);
	spin_unlock (&cur_slice->xdm_slice_lock);
}
EXPORT_SYMBOL(wildcat_xdm_release_slice_queue);

void wildcat_rdm_release_slice_queue(
	struct bridge *br,
	int           slice,
	int           queue)
{
	struct slice *slices;
	struct slice *cur_slice;

	slices = br->slice;
	cur_slice = &slices[slice];

	spin_lock (&cur_slice->rdm_slice_lock);
	cur_slice->rdm_alloc_count--;
	clear_bit(queue, cur_slice->rdm_alloced_bitmap);
	spin_unlock (&cur_slice->rdm_slice_lock);
}
EXPORT_SYMBOL(wildcat_rdm_release_slice_queue);

/* Allocate a queue from a slice according to the slice_mask. */
int wildcat_alloc_xqueue(
	struct bridge *br,
	uint8_t slice_mask,
	int     *slice,
	int     *queue)
{
	int ret;
	uint8_t sm;

	if (slice_mask == SLICE_DEMAND) {
		/* seting the DEMAND flag without any slices is an error. */
		return -1;
	}
	if (slice_mask == 0) {
		/* Caller did not specify any specific slices so use all. */
		sm = ALL_SLICES;
		return xdm_choose_slice_queue(br, sm, slice, queue);
	}
	else {
		/* Caller set a slice mask. Mask off DEMAND for now. */
		sm = slice_mask & ALL_SLICES;
		ret = xdm_choose_slice_queue(br, sm, slice, queue);
		if (slice_mask & SLICE_DEMAND) {
			/* Return if this is a demand */
			return ret;
		}
		if (ret == 0) {
			/* Found a queue in specified hint slices */
			return ret;
		}
		else {
			/* This is a hint so try again with un-tried slices. */
			sm = sm^ALL_SLICES;
			return xdm_choose_slice_queue(br, sm, slice, queue);
		}
	}
}
EXPORT_SYMBOL(wildcat_alloc_xqueue);

/* Allocate a queue from a slice according to the slice_mask. */
int wildcat_alloc_rqueue(
	struct bridge *br,
	uint8_t slice_mask,
	int     *slice,
	int     *queue,
	int     *irq_vector)
{
	int ret;
	uint8_t sm;

	if (slice_mask == SLICE_DEMAND) {
		/* seting the DEMAND flag without any slices is an error. */
		return -1;
	}
	if (slice_mask == 0) {
		/* Caller did not specify any specific slices so use all. */
		sm = ALL_SLICES;
		return rdm_choose_slice_queue(br, sm, slice, queue, irq_vector);
	}
	else {
		/* Caller set a slice mask. Mask off DEMAND for now. */
		sm = slice_mask & ALL_SLICES;
		ret = rdm_choose_slice_queue(br, sm, slice, queue, irq_vector);
		if (slice_mask & SLICE_DEMAND) {
			/* Return if this is a demand */
			return ret;
		}
		if (ret == 0) {
			/* Found a queue in specified hint slices */
			return ret;
		}
		else {
			/* This is a hint so try again with un-tried slices. */
			sm = sm^ALL_SLICES;
			return rdm_choose_slice_queue(br, sm, slice, queue, irq_vector);
		}
	}
}
EXPORT_SYMBOL(wildcat_alloc_rqueue);

int wildcat_xqueue_free(
	struct bridge *br,
	int slice,
	int queue)
{
	struct slice           *slices;
	struct slice           *sl;
	struct wildcat_xdm_qcm *hw_qcm_addr;

	slices = br->slice;

	if (slice < 0 || slice > SLICES)
		return -1;
	if (queue < 0 || queue > XDM_QUEUES_PER_SLICE)
		return -1;
	sl = &(slices[slice]);
	if (test_bit(queue, sl->xdm_alloced_bitmap) == 0) {
		pr_debug("Tried to free unallocated queue %d on slice %d\n",
			 queue, slice);
		return -1;
	}

	/*
	 * Set master stop and clear the hardware queue. May wait to drain
	 * the queue.
	 */
	hw_qcm_addr = &(sl->bar->xdm[(queue*2)]);
	if (clear_xdm_qcm(hw_qcm_addr) != 0) {
		pr_debug("xqueue_free: queue %d failed to clear\n", queue);
		return -1;
	}

	/* Return queue to the bridge's free pool */
	spin_lock (&slices[slice].xdm_slice_lock);
	slices[slice].xdm_alloc_count--;
	clear_bit(queue, slices[slice].xdm_alloced_bitmap);
	spin_unlock (&slices[slice].xdm_slice_lock);

	pr_debug("Freed queue %d on slice %d qcm=0x%px\n",
		 queue, slice, hw_qcm_addr);
	return 0;
}
EXPORT_SYMBOL(wildcat_xqueue_free);

int wildcat_rqueue_free(
	struct bridge *br,
	int slice,
	int queue)
{
	struct slice           *slices;
	struct slice           *sl;
	struct wildcat_rdm_qcm *hw_qcm_addr;

	slices = br->slice;

	if (slice < 0 || slice > SLICES)
		return -1;
	if (queue < 0 || queue > RDM_QUEUES_PER_SLICE)
		return -1;
	sl = &(slices[slice]);
	if (test_bit(queue, sl->rdm_alloced_bitmap) == 0) {
		pr_debug("Tried to free unallocated queue %d on slice %d\n",
			 queue, slice);
		return -1;
	}

	/*
	 * Set master stop and clear the hardware queue. May wait to drain
	 * the queue.
	 */
	hw_qcm_addr = &(sl->bar->rdm[(queue*2)]);
	if (clear_rdm_qcm(hw_qcm_addr) != 0) {
		pr_debug("rqueue_free: queue %d failed to clear\n", queue);
		return -1;
	}

	/* Return queue to the bridge's free pool */
	spin_lock (&slices[slice].rdm_slice_lock);
	slices[slice].rdm_alloc_count--;
	clear_bit(queue, slices[slice].rdm_alloced_bitmap);
	spin_unlock (&slices[slice].rdm_slice_lock);

	pr_debug("Freed queue %d on slice %d qcm=0x%px\n",
		 queue, slice, hw_qcm_addr);
	return 0;
}
EXPORT_SYMBOL(wildcat_rqueue_free);

int wildcat_dma_alloc_zpage(
	struct slice *sl,
	size_t q_size,
	union zpages **ret_zpage)
{
	int ret = 0;

	*ret_zpage = dma_zpages_alloc(sl, q_size);
	if (!*ret_zpage) {
		pr_debug("zpage_alloc failed\n");
		ret = -ENOMEM;
		return ret;
	}
	return ret;
}
EXPORT_SYMBOL(wildcat_dma_alloc_zpage);

#define CMDS_PER_PAGE ((uint32_t)(PAGE_SIZE / WILDCAT_HW_ENTRY_LEN))

void wildcat_xdm_qcm_setup(struct wildcat_xdm_qcm *hw_qcm_addr,
			   uint64_t cmdq_dma_addr, uint64_t cmplq_dma_addr,
			   uint cmdq_ent, uint cmplq_ent,
			   int traffic_class, int priority,
			   bool cur_valid, uint pasid)
{
	struct xdm_qcm_header     qcm = { 0 };
	uint64_t		  junk;
	int                       offset;

	/* Use a local qcm and then copy it to hardware */
	qcm.cmd_q_base_addr = cmdq_dma_addr;
	qcm.cmpl_q_base_addr = cmplq_dma_addr;
	/* Value written into the size field is queue size minus one. */
	qcm.cmd_q_size = cmdq_ent - 1; /* Revisit: change to -16 for command buffers */
	qcm.cmpl_q_size = cmplq_ent - 1;
	qcm.local_pasid = pasid;
	qcm.fabric_pasid = pasid;
	if (traffic_class > 15) {
		pr_debug("Invalid traffic_class: %d. Default to 0.\n",
			 traffic_class);
		qcm.traffic_class = 0;
	}
	else {
		/* Revisit: should we allow app control of traffic_class? */
		qcm.traffic_class = traffic_class;
	}
	if (priority > 1) {
		pr_debug("Invalid priority: %d. Default to 0.\n",
			 priority);
		qcm.priority = 0;
	}
	else {
		qcm.priority = priority;
	}
	/* Use virt addresses with IOMMU and PASID */
	qcm.virt_addr = (pasid != NO_PASID);
	qcm.q_virt_addr = 0;  /* Queues are physically addressed */
	qcm.toggle_valid = cur_valid;
	qcm.stop = 1;
	qcm.master_stop = 0;
	/* Write the first 4 64-byte words of the qcm to hardware */
	for (offset=0; offset < 0x20; offset+=0x8) {
		xdm_qcm_write(&qcm, hw_qcm_addr, offset);
	}
	/* Initialize the queue indicies. */
	xdm_qcm_write(&qcm, hw_qcm_addr, WILDCAT_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
	xdm_qcm_write(&qcm, hw_qcm_addr, WILDCAT_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
	xdm_qcm_write(&qcm, hw_qcm_addr,
		      WILDCAT_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET);

	/* Now set the stop bits to turn control over to application. */
	xdm_qcm_write(&qcm, hw_qcm_addr, XDM_STOP_OFFSET);
	xdm_qcm_write(&qcm, hw_qcm_addr, XDM_MASTER_STOP_OFFSET);

	/* Read back to ensure synchronization */
	junk = xdm_qcm_read(hw_qcm_addr, XDM_MASTER_STOP_OFFSET);

	wildcat_debug_xdm_qcm(__func__, __LINE__, hw_qcm_addr);
}
EXPORT_SYMBOL(wildcat_xdm_qcm_setup);

int wildcat_xdm_queue_sizes(uint32_t *cmdq_ent, uint32_t *cmplq_ent,
			    size_t *cmdq_size, size_t *cmplq_size,
			    size_t *qcm_size)
{
	int ret = 0;

	/* Validate the given queue lengths */
	if (*cmdq_ent < 2 || *cmdq_ent > MAX_SW_XDM_QLEN) {
		pr_debug("Invalid command queue entries %d\n", *cmdq_ent);
		ret = -EINVAL;
		goto done;
	}
	/*
	 * We force cmdq_ent to consume at least one kernel page and be
	 * rounded up to the next power of 2.
	 */
	*cmdq_ent = max(*cmdq_ent, CMDS_PER_PAGE);
	*cmdq_ent = roundup_pow_of_two(*cmdq_ent);

	if (*cmplq_ent < 2 || *cmplq_ent > MAX_SW_XDM_QLEN) {
		pr_debug("Invalid completion queue entries %d\n", *cmplq_ent);
		ret = -EINVAL;
		goto done;
	}
	/*
	 * The completion queue must be greater than or equal to the command
	 * queue and similarly rounded up.
	 */
	*cmplq_ent = max(*cmdq_ent, *cmplq_ent);
	*cmplq_ent = roundup_pow_of_two(*cmplq_ent);

	/* Compute sizes */
	*qcm_size = PAGE_SIZE;
	*cmdq_size = *cmdq_ent * WILDCAT_HW_ENTRY_LEN;
	*cmplq_size = *cmplq_ent * WILDCAT_HW_ENTRY_LEN;

 done:
	pr_debug("compute sizes: ret=%d cmdq_ent=%u cmdq_size=0x%lx "
		 "cmplq_ent=%u cmplq_size=0x%lx qcm_size=0x%lx\n",
		 ret, *cmdq_ent, *cmdq_size, *cmplq_ent, *cmplq_size,
		 *qcm_size);
	return ret;
}
EXPORT_SYMBOL(wildcat_xdm_queue_sizes);

int wildcat_kernel_XQALLOC(struct xdm_info *xdmi)
{
	struct genz_xdm_info *gzxi = xdmi->gzxi;
	int ret = 0;

	pr_debug("cmdq_ent=%u, cmplq_ent=%u\n",
		 gzxi->cmdq_ent, gzxi->cmplq_ent);
	ret = wildcat_xdm_queue_sizes(&gzxi->cmdq_ent, &gzxi->cmplq_ent,
				      &xdmi->cmdq_size, &xdmi->cmplq_size,
				      &xdmi->qcm_size);
	if (ret)
		goto done;
	ret = wildcat_alloc_xqueue(xdmi->br, xdmi->slice_mask,
				   &xdmi->slice, &xdmi->queue);
	if (ret)
		goto done;
	/* Get a pointer to the qcm chosen to initialize it's fields */
	xdmi->sl = &(xdmi->br->slice[xdmi->slice]);
	xdmi->hw_qcm_addr = &(xdmi->sl->bar->xdm[xdmi->queue*2]);
	ret = wildcat_dma_alloc_zpage(xdmi->sl, xdmi->cmdq_size, &xdmi->cmdq_zpage);
	if (ret != 0) {
		pr_debug("wildcat_dma_alloc_zpage failed for cmdq\n");
		goto release_queue;
	}
	ret = wildcat_dma_alloc_zpage(xdmi->sl, xdmi->cmplq_size,
				      &xdmi->cmplq_zpage);
	if (ret != 0) {
		pr_debug("wildcat_dma_alloc_zpage failed for cmplq\n");
		goto free_cmdq_zpage;
	}
	wildcat_xdm_qcm_setup(xdmi->hw_qcm_addr,
			      xdmi->cmdq_zpage->dma.dma_addr,
			      xdmi->cmplq_zpage->dma.dma_addr,
			      gzxi->cmdq_ent, gzxi->cmplq_ent,
			      gzxi->traffic_class, gzxi->priority,
			      xdmi->cur_valid, NO_PASID);
	xdmi->cmdq_head_shadow = 0;
	xdmi->cmdq_tail_shadow = 0;
	xdmi->cmplq_head = 0;
	xdmi->cmplq_tail_shadow = 0;
	ret = 0;
	pr_debug("slice=%d, queue=%d\n", xdmi->slice, xdmi->queue);
	goto done;

free_cmdq_zpage:
	wildcat_zpages_free(xdmi->cmdq_zpage);
release_queue:
	wildcat_xdm_release_slice_queue(xdmi->br, xdmi->slice, xdmi->queue);
done:
	return ret;
}

int wildcat_kernel_XQFREE(struct xdm_info *xdmi)
{
	int ret = 0;

	if (wildcat_xqueue_free(xdmi->br, xdmi->slice, xdmi->queue)) {
		/* _xqueue_free can fail if the queue doesn't drain */
		ret = -EBUSY;
		goto done;
	}

	wildcat_zpages_free(xdmi->cmdq_zpage);
	wildcat_zpages_free(xdmi->cmplq_zpage);

 done:
	return ret;
}

#define RSPCTXID_QUEUE_SHIFT		2
#define RSPCTXID_UPPER_SLICE_SHIFT	10
uint32_t wildcat_rspctxid_alloc(int slice, int queue)
{
	uint32_t rspctxid;

	/* bits 0-1 select the RDM instance in the bridge - use the slice. */
	/* bits 9:2 select the RDM queue number */
	/* bits 10:24 are the same for all 256 completion queues */
	/* Revisit FabricManager: 10:24 are 0 until we have a fabric manger interface */
	rspctxid = (queue<<RSPCTXID_QUEUE_SHIFT)|slice;
	return rspctxid;
}
EXPORT_SYMBOL(wildcat_rspctxid_alloc);

void wildcat_rdm_qcm_setup(struct wildcat_rdm_qcm *hw_qcm_addr,
			   uint64_t dma_addr, uint cmplq_ent,
			   bool cur_valid, uint pasid)
{
	struct rdm_qcm_header     qcm = { 0 };
	uint64_t		  junk;
	int                       offset;

	/* Use a local qcm and then copy it to hardware */
	qcm.cmpl_q_base_addr = dma_addr;
	/* The value written to the size field is queue size minus one */
	qcm.cmpl_q_size = cmplq_ent - 1;

	qcm.pasid = pasid;
	qcm.intr_enable = 1;
	qcm.q_virt_addr = 0;
	qcm.toggle_valid = cur_valid;
	qcm.stop = 1;
	qcm.master_stop = 0;
	/* Write the first 2 64-byte words of the qcm to hardware */
	for (offset=0; offset < 0x10; offset+=0x8) {
		rdm_qcm_write(&qcm, hw_qcm_addr, offset);
	}
	/* Initialize the queue indicies. */
	rdm_qcm_write(&qcm, hw_qcm_addr,
		      WILDCAT_RDM_QCM_RCV_QUEUE_TAIL_TOGGLE_OFFSET);
	rdm_qcm_write(&qcm, hw_qcm_addr, WILDCAT_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);

	/* Now set the stop bits to turn control over to application. */
	rdm_qcm_write(&qcm, hw_qcm_addr, RDM_STOP_OFFSET);
	rdm_qcm_write(&qcm, hw_qcm_addr, RDM_MASTER_STOP_OFFSET);

	/* Read back to ensure synchronization */
	junk = rdm_qcm_read(hw_qcm_addr, RDM_MASTER_STOP_OFFSET);

	wildcat_debug_rdm_qcm(__func__, __LINE__, hw_qcm_addr);
}
EXPORT_SYMBOL(wildcat_rdm_qcm_setup);

int wildcat_rdm_queue_sizes(uint32_t *cmplq_ent, size_t *cmplq_size,
			    size_t *qcm_size)
{
	int ret = 0;

	/* Validate the given queue length */
	if (*cmplq_ent < 2 || *cmplq_ent > MAX_SW_RDM_QLEN) {
		pr_debug("Invalid completion queue entries %d\n", *cmplq_ent);
		ret = -EINVAL;
		goto done;
	}
	/*
	 * We force cmplq_ent to consume at least one kernel page and be
	 * rounded up to the next power of 2.
	 */
	*cmplq_ent = max(*cmplq_ent, CMDS_PER_PAGE);
	*cmplq_ent = roundup_pow_of_two(*cmplq_ent);

	/* Compute sizes */
	*qcm_size = PAGE_SIZE;
	*cmplq_size = *cmplq_ent * WILDCAT_HW_ENTRY_LEN;

 done:
	pr_debug("compute sizes: ret=%d "
		 "cmplq_ent=%u cmplq_size=0x%lx qcm_size=0x%lx\n",
		 ret, *cmplq_ent, *cmplq_size, *qcm_size);
	return ret;
}
EXPORT_SYMBOL(wildcat_rdm_queue_sizes);

int wildcat_kernel_RQALLOC(struct rdm_info *rdmi)
{
	struct genz_rdm_info *gzri = rdmi->gzri;
	int ret = 0;

	pr_debug("cmplq_ent=%u, slice_mask 0x%x\n",
		 gzri->cmplq_ent, rdmi->slice_mask);
	ret = wildcat_rdm_queue_sizes(&gzri->cmplq_ent,
				      &rdmi->cmplq_size, &rdmi->qcm_size);
	if (ret)
		goto done;
	ret = wildcat_alloc_rqueue(rdmi->br, rdmi->slice_mask,
				   &rdmi->slice, &rdmi->queue, &rdmi->vector);
	if (ret)
		goto done;
	gzri->rspctxid = wildcat_rspctxid_alloc(rdmi->slice, rdmi->queue);
	/* Get a pointer to the qcm chosen to initialize it's fields */
	rdmi->sl = &(rdmi->br->slice[rdmi->slice]);
	rdmi->hw_qcm_addr = &(rdmi->sl->bar->rdm[rdmi->queue*2]);
	ret = wildcat_dma_alloc_zpage(rdmi->sl, rdmi->cmplq_size,
				      &rdmi->cmplq_zpage);
	if (ret != 0) {
		pr_debug("wildcat_dma_alloc_zpage failed for cmplq\n");
		goto release_queue;
	}
	wildcat_rdm_qcm_setup(rdmi->hw_qcm_addr,
			      rdmi->cmplq_zpage->dma.dma_addr,
			      gzri->cmplq_ent, rdmi->cur_valid, NO_PASID);
	rdmi->cmplq_tail_shadow = 0;
	rdmi->cmplq_head_shadow = 0;
	ret = 0;
	pr_debug("slice=%d, queue=%d, rspctxid=%u\n",
		 rdmi->slice, rdmi->queue, gzri->rspctxid);
	goto done;

release_queue:
	wildcat_rdm_release_slice_queue(rdmi->br, rdmi->slice, rdmi->queue);
done:
	return ret;
}

int wildcat_kernel_RQFREE(struct rdm_info *rdmi)
{
	int ret = 0;

	if (wildcat_rqueue_free(rdmi->br, rdmi->slice, rdmi->queue)) {
		/* _rqueue_free can fail if the queue doesn't drain */
		ret = -EBUSY;
		goto done;
	}

	wildcat_zpages_free(rdmi->cmplq_zpage);

done:
	return ret;
}

int wildcat_alloc_queues(struct genz_bridge_dev *gzbr,
			 struct genz_xdm_info *xdmi, struct genz_rdm_info *rdmi)
{
	int ret = 0;
	struct bridge *br = wildcat_gzbr_to_br(gzbr);
	struct xdm_info *wc_xdmi = NULL;
	struct rdm_info *wc_rdmi = NULL;

	/* Revisit: locking */
	if (!gzbr || !br) {
		ret = -EINVAL;
		goto done;
	}

	/* Allocate and set up the wildcat-specific XDM info */
	if (xdmi) {
		wc_xdmi = kzalloc(sizeof(*wc_xdmi), GFP_KERNEL);
		if (!wc_xdmi) {
			ret = -ENOMEM;
			goto done;
		}
		xdmi->br_driver_data = wc_xdmi;
		wc_xdmi->br = br;
		wc_xdmi->gzxi = xdmi;
		wc_xdmi->slice_mask = ALL_SLICES;
		wc_xdmi->cur_valid = 1;
		ret = wildcat_kernel_XQALLOC(wc_xdmi);
		if (ret)
			goto xdmi_free;
		xdmi->dma_dev = &wc_xdmi->sl->pdev->dev;
	}

	/* Allocate and set up the wildcat-specific RDM info */
	if (rdmi) {
		wc_rdmi = kzalloc(sizeof(*wc_rdmi), GFP_KERNEL);
		if (!wc_rdmi) {
			ret = -ENOMEM;
			goto xqfree;
		}
		rdmi->br_driver_data = wc_rdmi;
		wc_rdmi->br = br;
		wc_rdmi->gzri = rdmi;
		if (rdmi->br_driver_flags) {
			wc_rdmi->slice_mask = (uint8_t)rdmi->br_driver_flags;
		} else {
			/* any slice other than the XDM slice */
			wc_rdmi->slice_mask = (xdmi) ?
				(~(1u << wc_xdmi->slice) & ALL_SLICES) :
				ALL_SLICES;
		}
		wc_rdmi->cur_valid = 1;
		ret = wildcat_kernel_RQALLOC(wc_rdmi);
		if (ret)
			goto rdmi_free;
		rdmi->dma_dev = &wc_rdmi->sl->pdev->dev;
	}

	/* clear stop bits - queues are now ready */
	if (xdmi)
		xdm_qcm_write_val(0, wc_xdmi->hw_qcm_addr, XDM_STOP_OFFSET);
	if (rdmi)
		rdm_qcm_write_val(0, wc_rdmi->hw_qcm_addr, RDM_STOP_OFFSET);

	return 0;

rdmi_free:
	if (wc_rdmi)
		kfree(wc_rdmi);
xqfree:
	if (wc_xdmi)
		wildcat_kernel_XQFREE(wc_xdmi);
xdmi_free:
	if (wc_xdmi)
		kfree(wc_xdmi);
done:
	return ret;
}

int wildcat_free_queues(struct genz_xdm_info *gzxi, struct genz_rdm_info *gzri)
{
	int ret = 0;
	struct xdm_info *xdmi;
	struct rdm_info *rdmi;

	/* Revisit: locking */
	if (gzxi) {
		xdmi = (struct xdm_info *)gzxi->br_driver_data;
		ret = wildcat_kernel_XQFREE(xdmi);
	}

	if (gzri) {
		rdmi = (struct rdm_info *)gzri->br_driver_data;
		ret |= wildcat_kernel_RQFREE(rdmi);
	}

	return ret;
}

static int _xdm_get_sgli_cmpl(struct xdm_info *xdmi,
			      struct genz_sgl_info **sgli,
			      struct wildcat_cq_entry *entry)
{
	struct genz_xdm_info *gzxi = xdmi->gzxi;
	int ret = 0;
	uint head, next_head, cmdq_ent, cmpl_index;
	struct wildcat_cq_entry *cmpl_entry;
	union wildcat_hw_wq_entry *xdm_cmd;
	struct genz_sgl_info *cmpl_sgli;
	void *cmpl_addr, *cmd_addr;

	/* caller must hold xdm_info_lock */

	/* Return -EBUSY if no valid cmpl entry
	 * Return 0 if cmpl did not match (sgli is updated)
	 * Return 1 if cmpl did match
	 */

	cmdq_ent = gzxi->cmdq_ent;
	cmd_addr = xdmi->cmdq_zpage->dma.cpu_addr;
	cmpl_addr = xdmi->cmplq_zpage->dma.cpu_addr;
	head = xdmi->cmplq_head;
	cmpl_entry = &(((struct wildcat_cq_entry *)cmpl_addr)[head]);

	/* check valid bit */
	if (cmpl_entry->valid != xdmi->cur_valid) {
		return -EBUSY;
	}
	xdmi->active_cmds--;
	/* copy XDM completion entry to caller */
	*entry = *cmpl_entry;
	/* use cmpl index to find sgli and check if it is a match */
	cmpl_index = cmpl_entry->index;
	xdm_cmd = &(((union wildcat_hw_wq_entry *)cmd_addr)[cmpl_index]);
	cmpl_sgli = (struct genz_sgl_info *)xdm_cmd->dma.driver_data;
	if (cmpl_sgli == *sgli) {  /* match */
		ret = 1;
	} else {  /* not a match */
		*sgli = cmpl_sgli;
		ret = 0;
	}
	/* do mod-add to compute next head value */
	next_head = (head + 1) % gzxi->cmplq_ent;
	/* toggle cur_valid on wrap */
	if (next_head < head)
		xdmi->cur_valid = !xdmi->cur_valid;
	/* update cmplq_head - SW-only */
	/* must not reference cmpl_entry after this point */
	xdmi->cmplq_head = next_head;
	/* update cmdq_head_shadow if this completion moves it forward */
	/* must not reference xdm_cmd after this point */
	if (cmpl_index < cmdq_ent) {
		if (((xdmi->cmdq_tail_shadow - cmpl_index) % cmdq_ent) <
		    ((xdmi->cmdq_tail_shadow - xdmi->cmdq_head_shadow) %
		     cmdq_ent))
			xdmi->cmdq_head_shadow = cmpl_index;
	}

	return ret;
}

#define NS                    1000000000
#define WILDCAT_CMPL_TIMEOUT  ((u64)2 * NS)

static void wildcat_sgl_poll_cmpls(struct genz_dev *zdev,
				   struct genz_sgl_info *sgli)
{
	struct wildcat_cq_entry cq_entry;
	struct genz_xdm_info *gzxi = sgli->xdmi;
	struct xdm_info      *xdmi = (struct xdm_info *)gzxi->br_driver_data;
	struct genz_sgl_info *cmpl_sgli;
	uint                 cmpl_index;
	bool                 req_done;
	int ret, this_cpu;
	u64 start, now;
	ulong flags;

	/* Revisit: better to lock/unlock each loop interation? */
	spin_lock_irqsave(&gzxi->xdm_info_lock, flags);
	start = ktime_get_ns();
	this_cpu = smp_processor_id();
	/* Revisit: debug */
	dev_dbg_ratelimited(&zdev->dev,
			    "spin_lock, tag=%#x, nr_cmpls=%u, cpu=%d\n",
			    sgli->tag, atomic_read(&sgli->nr_cmpls), this_cpu);
	while (atomic_read(&sgli->nr_cmpls) > 0) {
		cmpl_sgli = sgli;
		ret = _xdm_get_sgli_cmpl(xdmi, &cmpl_sgli, &cq_entry);
		now = ktime_get_ns();
		if (ret >= 0) {  /* we have a completion */
			if (cq_entry.status != 0) {
				cmpl_index = cq_entry.index;
				dev_err(&zdev->dev,
					"XDM error: tag=%#x, cmpl_index=%u, status=0x%x\n",
					sgli->tag, cmpl_index, cq_entry.status);
				cmpl_sgli->status = -EIO;
			}
			/* Revisit: req_done unused */
			req_done = atomic_dec_and_test(&cmpl_sgli->nr_cmpls);
		}
		/* Revisit: busy-wait */
		if ((now - start) > WILDCAT_CMPL_TIMEOUT) {
			dev_err(&zdev->dev,
				"XDM cmpl timeout: tag=%#x\n", sgli->tag);
			sgli->status = -ETIMEDOUT;
			break;
		}
	}
	/* Revisit: debug */
	dev_dbg_ratelimited(&zdev->dev,
			    "spin_unlock, tag=%#x, status=%d, cpu=%d\n",
			    sgli->tag, sgli->status, this_cpu);
	spin_unlock_irqrestore(&gzxi->xdm_info_lock, flags);
}

int wildcat_sgl_request(struct genz_dev *zdev, struct genz_sgl_info *sgli)
{
	int i, ret = 0;
	struct scatterlist *sg;
	union wildcat_hw_wq_entry wc_cmd;
	char *cmd_name;
	uint dma_len;
	uint64_t zaddr;
	struct genz_xdm_info *gzxi = sgli->xdmi;
	struct xdm_info      *xdmi = (struct xdm_info *)gzxi->br_driver_data;

	/* Revisit: Just to get something to work, submit XDM command(s)
	 * and poll for completion.  Change to RDM interrupts for perf.
	 */

	zaddr = sgli->rmri->req_addr + sgli->offset;

	for_each_sg(sgli->sg, sg, sgli->nr_sg, i) {
		/* fill in cmd */
		dma_len = sg_dma_len(sg);
		wc_cmd.dma.len = dma_len;
		wc_cmd.dma.driver_data = sgli;
		if (sgli->cmd == GENZ_XDM_WRITE) {
			cmd_name = "PUT";
			wc_cmd.hdr.opcode = WILDCAT_HW_OPCODE_PUT;
			wc_cmd.dma.rd_addr = sg_dma_address(sg);
			wc_cmd.dma.wr_addr = zaddr;
		} else {  /* GENZ_XDM_READ */
			cmd_name = "GET";
			wc_cmd.hdr.opcode = WILDCAT_HW_OPCODE_GET;
			wc_cmd.dma.rd_addr = zaddr;
			wc_cmd.dma.wr_addr = sg_dma_address(sg);
		}
		/* submit cmd */
		ret = wildcat_xdm_queue_cmd(xdmi, &wc_cmd, false);
		/* Revisit: debug */
		dev_dbg_ratelimited(&zdev->dev,
			"%s: tag=%#x, rd_addr=0x%llx, wr_addr=0x%llx, len=%u, ret=%d\n",
			cmd_name, sgli->tag, wc_cmd.dma.rd_addr,
			wc_cmd.dma.wr_addr, dma_len, ret);
		if (ret < 0)  {  /* Revisit: handle EBUSY/EXFULL */
			/* cleanup submitted cmds */
			wildcat_sgl_poll_cmpls(zdev, sgli);
			goto out;
		}
		atomic_inc(&sgli->nr_cmpls);
		zaddr += dma_len;
	}

	/* Revisit: poll for completion */
	wildcat_sgl_poll_cmpls(zdev, sgli);
	sgli->cmpl_fn(zdev, sgli);
out:
	return ret;
}
