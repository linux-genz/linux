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
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/genz.h>
#include "wildcat.h"

int wildcat_get_irq_index(struct slice *sl, int queue)
{
	int vector;

	if (!SLICE_VALID(sl)) {
		pr_debug("%s: failed - slice is not valid\n", __func__);
		return -1;
	}
	if (queue < 0 || queue > RDM_QUEUES_PER_SLICE) {
		dev_dbg(&sl->pdev->dev,
			"failed - queue %d is out of range\n", queue);
		return -1;
	}
	if (test_bit(queue, sl->rdm_alloced_bitmap) == 0) {
		dev_dbg(&sl->pdev->dev,
			"failed - queue %d is not allocated\n", queue);
		return -1;
	}

	/*
	 * The irq_index is used to index into the counter arrays in
	 * the shared data pages. The irq_index is based on the maximum
	 * possible irq vectors per slice rather than the number actually
	 * allocated to the slice by Linux. This means that the counter
	 * arrays may be sparsely used but it makes the math easier and is
	 * not wasting that much space since the max for 4 slices is 128.
	 */
	vector = wildcat_rdm_queue_to_vector(queue, sl);
	return ((sl->id*VECTORS_PER_SLICE) + vector);
}

int wildcat_register_rdm_interrupt(struct slice *sl,
	int queue,
	irqreturn_t (*intr_handler)(int, void *),
	void *data)
{
	int irq_index;
	int vector;
	struct rdm_vector_list *new_entry;

	irq_index = wildcat_get_irq_index(sl, queue);
	if (irq_index < 0) {
		dev_dbg(&sl->pdev->dev,
			"get_irq_index failed with %d\n", irq_index);
		return -1;
	}

	/* Add an entry to the linked list */
	new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
	if (new_entry == NULL) {
		dev_dbg(&sl->pdev->dev, "kmalloc failed\n");
		return -ENOMEM;
	}
	new_entry->irq_index = irq_index;
	new_entry->handler = intr_handler;
	new_entry->data = data;
	new_entry->queue = queue;

	/* Get this queue's MSI interrupt vector (0 to VECTORS_PER_SLICE) */
	vector = wildcat_rdm_queue_to_vector(queue, sl);
	list_add(&new_entry->list, &sl->irq_vectors[vector]);

	dev_dbg(&sl->pdev->dev,
		"added handler and data for slice %d and queue %d to vector %d\n",
		sl->id, queue, vector);
	return 0;
}
EXPORT_SYMBOL(wildcat_register_rdm_interrupt);

void wildcat_unregister_rdm_interrupt(struct slice *sl, int queue)
{
	int vector;
	struct rdm_vector_list *tmp;
	struct list_head *pos, *q;

	vector = wildcat_rdm_queue_to_vector(queue, sl);
	list_for_each_safe(pos, q, &(sl->irq_vectors[vector])) {
		tmp = list_entry(pos, struct rdm_vector_list, list);
		if (tmp->queue == queue) {
			list_del(pos);
			kfree(tmp);
			break;
		}
	}
}
EXPORT_SYMBOL(wildcat_unregister_rdm_interrupt);

static int (*wildcat_rdm_trigger)(int, int *) = NULL;

int wildcat_register_rdm_trigger(int (*rdm_trigger)(int, int *))
{
	if (wildcat_rdm_trigger != NULL)
		return -EEXIST;

	wildcat_rdm_trigger = rdm_trigger;
	return 0;
}
EXPORT_SYMBOL(wildcat_register_rdm_trigger);

void wildcat_unregister_rdm_trigger(int (*rdm_trigger)(int, int *))
{
	if (wildcat_rdm_trigger == rdm_trigger)
		wildcat_rdm_trigger = NULL;
}
EXPORT_SYMBOL(wildcat_unregister_rdm_trigger);

static int wildcat_irq_to_vector(int irq, struct slice *sl)
{
	int base_vector = pci_irq_vector(sl->pdev, 0);
	int check;

	check = pci_irq_vector(sl->pdev, irq - base_vector);
	if (check != irq) {
		dev_dbg(&sl->pdev->dev,
			"check %d != irq %d\n", check, irq);
	}
	return (irq - base_vector);
}

static irqreturn_t wildcat_intr_handler(int irq, void *data_ptr)
{
	struct slice *sl = (struct slice *)data_ptr;
	struct list_head *pos;
	struct rdm_vector_list *entry;
	int ret = IRQ_HANDLED;
	int vector, irq_vector;
	int triggered = 0;

	/* Convert irq to the intr vector in the range 0-VECTORS_PER_SLICE */
	vector = wildcat_irq_to_vector(irq, sl);
	irq_vector = (sl->id*VECTORS_PER_SLICE) + vector;
	dev_dbg(&sl->pdev->dev,
		"received interrupt irq %d maps to irq_vector %d\n",
		irq, irq_vector);

	/* Call the registered trigger function */
	if (wildcat_rdm_trigger != NULL) {
		ret = wildcat_rdm_trigger(irq_vector, &triggered);
		if (ret != 0) {
			dev_dbg(&sl->pdev->dev,
				"wildcat_trigger failed for irq_vector %d\n",
				irq_vector);
		}
	}

	/* Call the secondary interrupt handler for each interested queue */
	list_for_each(pos, &(sl->irq_vectors[vector])) {
		entry = list_entry(pos, struct rdm_vector_list, list);
		if (entry->handler != NULL) {
			dev_dbg(&sl->pdev->dev,
				"calling secondary handler for slice=%d, irq_vector=%d, trigger=%d\n",
				sl->id, entry->irq_index, triggered);
			ret |= (*entry->handler)(entry->irq_index, entry->data);
		}
	}
	return ret;
}

int wildcat_intr_vectors_count(struct genz_bridge_dev *gzbr)
{
	struct bridge *br = wildcat_gzbr_to_br(gzbr);
	int sl, count = 0;

	if (gzbr == NULL || br == NULL) {
		pr_debug("invalid bridge, gzbr=%px, br=%px\n", gzbr, br);
		return -EINVAL;
	}

	for (sl = 0; sl < SLICES; sl++) {
		if (SLICE_VALID(&br->slice[sl]))
			count += br->slice[sl].irq_vectors_count;
	}
	return count;
}
EXPORT_SYMBOL(wildcat_intr_vectors_count);

int wildcat_register_interrupts(struct pci_dev *pdev, struct slice *sl)
{

	int ret = 0;
	int nvec = 0;
	int i;

	nvec = pci_alloc_irq_vectors(pdev, 1, VECTORS_PER_SLICE,
				     PCI_IRQ_MSI);
	if (nvec <= 0) {
		dev_dbg(&sl->pdev->dev, "Request for MSI vectors failed.\n");
		ret = -1;
		goto done;
	} else {
		dev_dbg(&sl->pdev->dev, "allocated %d irq vectors\n", nvec);
	}

	sl->irq_vectors_count = nvec;
	for (i = 0; i < nvec; i++) {
		ret = request_irq(pci_irq_vector(pdev, i), wildcat_intr_handler,
				  0, wildcat_driver_name, sl);
		if (ret) {
			dev_dbg(&sl->pdev->dev,
				"request_irq %d failed with %d\n", i, ret);
			goto free_vectors;
		} else {
			dev_dbg(&sl->pdev->dev, "request_irq[%d] = IRQ %d\n",
				i, pci_irq_vector(pdev, i));
		}
	}

	/* Initialize the array of lists for each interrupt vector */
	for (i=0; i < nvec; i++)
		INIT_LIST_HEAD(&sl->irq_vectors[i]);

	dev_dbg(&sl->pdev->dev,
		" INIT_LIST_HEAD irq_vectors list for %d lists\n", nvec);
	goto done;

free_vectors:
	while (--i >= 0)
		free_irq(pci_irq_vector(pdev, i), sl);
	pci_free_irq_vectors(pdev);

done:
	return ret;
}

void wildcat_free_interrupts(struct pci_dev *pdev)
{
	struct slice *sl = (struct slice *)pci_get_drvdata(pdev);
	int i;
	struct list_head *pos, *q;
	struct rdm_vector_list *tmp;

	for (i = 0; i < sl->irq_vectors_count; i++)
		free_irq(pci_irq_vector(pdev, i), sl);

	pci_free_irq_vectors(pdev);

	/* free space allocated for vector lists */
	for (i = 0; i < sl->irq_vectors_count; i++) {
		list_for_each_safe(pos, q, &sl->irq_vectors[i]) {
			tmp = list_entry(pos, struct rdm_vector_list, list);
			list_del(pos);
			kfree(tmp);
		}
	}
	return;
}
