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

#ifndef _WILDCAT_INTR_H_
#define _WILDCAT_INTR_H_

/* Function Prototypes */
int wildcat_register_interrupts(struct pci_dev *pdev, struct slice *sl);
void wildcat_free_interrupts(struct pci_dev *pdev);
int wildcat_get_irq_index(struct slice *sl, int queue);
irqreturn_t wildcat_rdm_interrupt_handler(int irq_index, void *data);
int wildcat_register_rdm_interrupt(struct slice *sl, int queue,
	irqreturn_t (*intr_handler)(int, void *), void *data);
void wildcat_unregister_rdm_interrupt(struct slice *sl, int queue);
#ifdef OLD_ZHPE
/* Revisit: fix these */
int zhpe_setup_poll_devs(void);
void zhpe_cleanup_poll_devs(void);
int zhpe_poll_device_create(struct slice *sl, int num_vectors);
void zhpe_poll_device_destroy(struct slice *sl);
wait_queue_head_t * zhpe_poll_get_wq(int irq_index);
int zhpe_trigger(int irq_index, int * triggered);
int zhpe_read_handled(struct file_data *fdata, struct slice *sl, int queue,
    int *handled);
void zhpe_poll_init_waitqueues(struct bridge *br);
#endif

#endif /* _WILDCAT_INTR_H_ */
