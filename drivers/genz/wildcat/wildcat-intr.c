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
			"%s: failed - queue %d is out of range\n",
			__func__, queue);
		return -1;
	}
	if (test_bit(queue, sl->rdm_alloced_bitmap) == 0) {
		dev_dbg(&sl->pdev->dev,
			"%s: failed - queue %d is not allocated\n",
			__func__, queue);
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
	struct pci_dev *pdev = sl->pdev;
	struct list_head *pos;
	struct rdm_vector_list *entry;
	int ret = IRQ_HANDLED;
	int vector, irq_vector;
	int triggered = 0;

	/* Convert irq to the intr vector in the range 0-VECTORS_PER_SLICE */
	vector = wildcat_irq_to_vector(irq, sl);
	irq_vector = (sl->id*VECTORS_PER_SLICE) + vector;
	dev_dbg(&sl->pdev->dev,
		"%s: received interrupt irq %d maps to irq_vector %d\n",
		pci_name(pdev), irq, irq_vector);
#ifdef OLD_ZHPE
	/* Update the triggered count in the shared page */
	ret = wildcat_trigger(irq_vector, &triggered);
	if (ret != 0) {
		dev_dbg(&sl->pdev->dev,
			"wildcat_trigger failed for irq_vector %d\n",
			irq_vector);
	}
#endif
	/* Call the secondary interrupt handler for each interested queue */
	list_for_each(pos, &(sl->irq_vectors[vector])) {
		entry = list_entry(pos, struct rdm_vector_list, list);
		if (entry->handler != NULL) {
			dev_dbg(&sl->pdev->dev,
				"calling secondary handler for slice %d, irq_vector %d trigger = %d\n",
				sl->id, entry->irq_index, triggered);
			ret |= (*entry->handler)(entry->irq_index, entry->data);
		}
	}
	return ret;
}

int wildcat_register_interrupts(struct pci_dev *pdev, struct slice *sl)
{

	int ret = 0;
	int nvec = 0;
	int i;

	nvec = pci_alloc_irq_vectors(pdev, 1, VECTORS_PER_SLICE,
				     PCI_IRQ_MSI);
	if (nvec <= 0) {
		dev_dbg(&sl->pdev->dev, "%s: Request for MSI vectors failed.\n",
			pci_name(pdev));
		ret = -1;
		goto done;
	} else {
		dev_dbg(&sl->pdev->dev, "%s: allocated %d irq vectors\n",
			pci_name(pdev), nvec);
	}

	sl->irq_vectors_count = nvec;
	for (i = 0; i < nvec; i++) {
		ret = request_irq(pci_irq_vector(pdev, i), wildcat_intr_handler,
				  0, wildcat_driver_name, sl);
		if (ret) {
			dev_dbg(&sl->pdev->dev,
				"%s: request_irq %d failed with %d\n",
				pci_name(pdev), i, ret);
			goto free_vectors;
		} else {
			dev_dbg(&sl->pdev->dev,
				"%s: request_irq[%d] = IRQ %d\n",
				pci_name(pdev), i, pci_irq_vector(pdev, i));
                }
	}

	/* Initialize the array of lists for each interrupt vector */
	for (i=0; i < nvec; i++)
		INIT_LIST_HEAD(&sl->irq_vectors[i]);

	dev_dbg(&sl->pdev->dev,
		" INIT_LIST_HEAD irq_vectors list for %d lists\n", nvec);
#ifdef OLD_ZHPE
        /* Create the /dev/zhpe_poll_N files for nvec vectors */
        ret = zhpe_poll_device_create(sl, nvec);
        if (ret != 0) {
		debug(DEBUG_PCI, "zhpe_poll_device_create failed\n");
                goto free_vectors;
        }
#endif
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

#ifdef OLD_ZHPE
#define POLL_DEV_NAME	"zhpe_poll"
static dev_t zhpe_poll_dev;
static struct cdev *poll_cdev;
static struct class *poll_class;
static int zhpe_poll_dev_major;
static int zhpe_poll_open(struct inode *inode, struct file *file);

struct slice * zhpe_irq_index_to_slice(
	struct file_data *fdata,
	int irq_index)
{
	int slice_id;

	slice_id = irq_index / VECTORS_PER_SLICE;
	return (&fdata->md.bridge->slice[slice_id]);
}

static int zhpe_poll_open(struct inode *inode, struct file *file)
{
    struct file_data *fdata;
    pid_t  pid = task_pid_nr(current);
    struct bridge *br = &zhpe_bridge;
    struct slice *sl;
    int irq_index = iminor(inode);
    struct list_head *pos;
    struct rdm_vector_list *entry;
    int found_queue = 0;
    int vector;

    /* Find the fdata associated with this open's pid */
    fdata = pid_to_fdata(br, pid);
    if (fdata == NULL) {
        debug(DEBUG_PCI, "Failed to match poll open pid (%d) to fdata pid\n",
            pid);
        return -ENOENT;
    }

    /* check that this pid owns an rqueue in this irq_index */
    sl = zhpe_irq_index_to_slice(fdata, irq_index);
    vector = irq_index % VECTORS_PER_SLICE; /* per slice vector */
    debug(DEBUG_PCI, "slice = %d irq_index = %d vector = %d\n", sl->id, irq_index, vector);
    list_for_each(pos, &(sl->irq_vectors[vector])) {
        entry = list_entry(pos, struct rdm_vector_list, list);
        debug(DEBUG_PCI, "entry->irq_index = %d\n", entry->irq_index);
        if (entry->irq_index == irq_index) {
		found_queue = 1;
                break;
        }
    }
    if (!found_queue) {
        debug(DEBUG_INTR, "zhpe_poll_open: trying to open a file without owning a queue on that vector %d\n",  vector);
        return -ENXIO;
    }
    file->private_data = fdata;
    return 0;
}

static int zhpe_poll_close(struct inode *inode, struct file *file)
{
    return 0;
}

static unsigned int zhpe_poll_poll(struct file *file,
    struct poll_table_struct *wait)
{
    struct file_data *fdata = file->private_data;
    int irq_index = iminor(file_inode(file));
    int handled, triggered;
    struct zhpe_local_shared_data *local_shared_data;

    if (fdata == NULL) {
        debug(DEBUG_PCI, "zhpe_poll_poll: fdata is NULL\n");
        return 0;
    }

    poll_wait(file, &fdata->md.bridge->zhpe_poll_wq[irq_index], wait);

    /* Compare trigggered to handled */
    local_shared_data = (struct zhpe_local_shared_data *)
            fdata->local_shared_zpage->queue.pages[0];
    handled = READ_ONCE(local_shared_data->handled_counter[irq_index]);
    triggered = READ_ONCE(global_shared_data->triggered_counter[irq_index]);

    if (triggered != handled)
        return (POLLIN | POLLRDNORM);
    return 0;
}

static const struct file_operations zhpe_poll_fops = {
    .owner      = THIS_MODULE,
    .open       = zhpe_poll_open,
    .release    = zhpe_poll_close,
    .poll       = zhpe_poll_poll,
};

int zhpe_poll_device_create(struct slice *sl, int num_vectors)
{
    int d;
    int base_irq_vector;
    struct device * dev;
    int minor;

    base_irq_vector = sl->id * VECTORS_PER_SLICE;
    for (d = 0; d < num_vectors; d++) {
        minor = base_irq_vector + d;
        debug(DEBUG_PCI, "device create for /dev/zhpe_poll_%d class = %px major = %d, minor = %d\n", minor, poll_class, zhpe_poll_dev_major, minor);

        dev = device_create(poll_class, NULL,
                MKDEV(zhpe_poll_dev_major, minor),
                NULL, "zhpe_poll_%d", minor);
        if (IS_ERR(dev)) {
            debug(DEBUG_PCI, "device_create failed with %ld\n", PTR_ERR(dev));
            goto destroy_devices;
        }
    }

    return 0;

destroy_devices:
    for (;d > 0; d--) {
        minor = base_irq_vector + d;
        device_destroy(poll_class, MKDEV(zhpe_poll_dev_major, minor));
    }
    return -1;
}

static int __match_devt(struct device *dev, const void *data)
{
        const dev_t *devt = data;

        return dev->devt == *devt;
}

void zhpe_poll_device_destroy(struct slice *sl)
{
	int d;
	int base_irq_vector;
        int minor;
	struct device *dev;
	dev_t poll_devt;

        if (sl == NULL)
		return;
	debug(DEBUG_PCI, "zhpe_poll_device_destroy slice is %d\n", sl->id);
        base_irq_vector = sl->id * VECTORS_PER_SLICE;
	debug(DEBUG_PCI, "zhpe_poll_device_destroy base_irq_vector is %d\n", base_irq_vector);
	for (d = 0; d < sl->irq_vectors_count; d++) {
                minor = base_irq_vector + d;
	debug(DEBUG_PCI, "zhpe_poll_device_destroy poll_class %px zhpe_poll_dev_major %d minor %d\n", poll_class, zhpe_poll_dev_major, minor);
		poll_devt = MKDEV(zhpe_poll_dev_major, minor);
		dev = class_find_device(poll_class, NULL, &poll_devt, __match_devt);
		debug(DEBUG_PCI, "dev is %px\n", dev);
		debug(DEBUG_PCI, "dev->parent is %px\n", dev->parent);
		debug(DEBUG_PCI, "dev->bus is %px\n", dev->bus);
		if (dev->bus) {
			debug(DEBUG_PCI, "dev->bus->p is %px\n", dev->bus->p);
		}
		debug(DEBUG_PCI, "dev->p is %px\n", dev->p);
		debug(DEBUG_PCI, "MAJOR(dev->devt) is %d\n", MAJOR(dev->devt));
		debug(DEBUG_PCI, "dev->class is %px\n", dev->class);

                device_destroy(poll_class, MKDEV(zhpe_poll_dev_major, minor));
	}
	return;
}

void zhpe_poll_init_waitqueues(struct bridge *br)
{
    int i;

    /* Initialize wait queues for each poll device */
    for (i = 0; i < MAX_IRQ_VECTORS; i++) {
        init_waitqueue_head(&br->zhpe_poll_wq[i]);
    }
}

static char *poll_devnode(struct device *dev, umode_t *mode)
{
        if (!mode)
                return NULL;
        *mode = 0666;
        return NULL;
}

int zhpe_setup_poll_devs(void)
{
    int ret = -1;

    ret = alloc_chrdev_region(&zhpe_poll_dev, 0, MAX_IRQ_VECTORS,
            POLL_DEV_NAME);
    if (ret != 0) {
        debug(DEBUG_PCI, "alloc_chrdev_region failed with %d\n", ret);
        return ret;
    }

    zhpe_poll_dev_major = MAJOR(zhpe_poll_dev);
    debug(DEBUG_PCI, "zhpe_poll_dev_major is %d\n", zhpe_poll_dev_major);
    poll_class = class_create(THIS_MODULE, POLL_DEV_NAME);
    if (IS_ERR(poll_class)) {
        debug(DEBUG_PCI, "class_create failed\n");
        goto unreg_region;
    }
    poll_class->devnode = poll_devnode;
    debug(DEBUG_PCI, "poll_class is %px\n", poll_class);
    poll_cdev = cdev_alloc();
    if (poll_cdev == NULL) {
        debug(DEBUG_PCI, "cdev_alloc failed\n");
        goto destroy_class;
    }
    cdev_init(poll_cdev, &zhpe_poll_fops);

    ret = cdev_add(poll_cdev, zhpe_poll_dev, MAX_IRQ_VECTORS);
    if (ret < 0) {
        debug(DEBUG_PCI, "cdev_add failed with %d\n", ret);
        goto del_cdev;
    }

    ret = 0;
    goto done;

del_cdev:
    cdev_del(poll_cdev);

destroy_class:
    class_destroy(poll_class);

unreg_region:
    unregister_chrdev_region(zhpe_poll_dev, MAX_IRQ_VECTORS);

done:
    return ret;
}

void zhpe_cleanup_poll_devs(void)
{
        int minor;

	for (minor = 0; minor < MAX_IRQ_VECTORS; minor++) {
                device_destroy(poll_class, MKDEV(zhpe_poll_dev_major, minor));
	}
	cdev_del(poll_cdev);
	class_destroy(poll_class);
        unregister_chrdev_region(zhpe_poll_dev, MAX_IRQ_VECTORS);
}

int zhpe_trigger(int irq_index, int *triggered)
{
    if (irq_index < 0 || irq_index > MAX_IRQ_VECTORS) {
        debug(DEBUG_MSG, "zhpe_trigger passed an out of range irq_index %d\n",
                irq_index);
        return -1;
    }

    /* Use atomic fetch and add. */
    *triggered = __sync_add_and_fetch(
                    &global_shared_data->triggered_counter[irq_index], 1);

    return 0;
}
#endif
