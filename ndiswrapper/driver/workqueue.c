/*
 *  Copyright (C) 2006 Giridhar Pemmasani
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#include "ntoskernel.h"

/* workqueue implementation for 2.4 kernels */

static int workq_thread(void *data)
{
	workqueue_struct_t *workq = data;
	work_struct_t *work;
	unsigned long flags;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
	strncpy(current->comm, workq->name, sizeof(current->comm));
	current->comm[sizeof(current->comm) - 1] = 0;
	daemonize();
	reparent_to_init();
	current->nice -= 5;
#else
	daemonize(workq->name);
	set_user_nice(current, -5);
#endif

#ifdef PF_NOFREEZE
	current->flags |= PF_NOFREEZE;
#else
	sigfillset(&current->blocked);
#endif

	workq->task = current;
	complete(workq->completion);
	workq->completion = NULL;
	WORKTRACE("%s (%d) started", workq->name, workq->pid);
	while (workq->pending >= 0) {
		if (wait_condition(workq->pending, 0, TASK_INTERRUPTIBLE) < 0) {
			/* TODO: deal with signal */
			WARNING("signal not blocked?");
			flush_signals(current);
			continue;
		}
		while (1) {
			struct list_head *entry;

			spin_lock_irqsave(&workq->lock, flags);
			if (list_empty(&workq->work_list)) {
				if (workq->pending > 0)
					workq->pending = 0;
				spin_unlock_irqrestore(&workq->lock, flags);
				break;
			}
			entry = workq->work_list.next;
			work = list_entry(entry, work_struct_t, list);
			if (xchg(&work->workq, NULL))
				list_del(entry);
			else
				work = NULL;
			spin_unlock_irqrestore(&workq->lock, flags);
			if (work)
				work->func(work->data);
		}
	}

	WORKTRACE("%s exiting", workq->name);
	workq->pid = 0;
	return 0;
}

wfastcall void wrap_queue_work(workqueue_struct_t *workq, work_struct_t *work)
{
	unsigned long flags;

	spin_lock_irqsave(&workq->lock, flags);
	if (!work->workq) {
		work->workq = workq;
		list_add_tail(&work->list, &workq->work_list);
		workq->pending++;
		wake_up_process(workq->task);
	}
	spin_unlock_irqrestore(&workq->lock, flags);
}

void wrap_cancel_work(work_struct_t *work)
{
	workqueue_struct_t *workq;
	unsigned long flags;

	if ((workq = xchg(&work->workq, NULL))) {
		spin_lock_irqsave(&workq->lock, flags);
		list_del(&work->list);
		spin_unlock_irqrestore(&workq->lock, flags);
	}
}

workqueue_struct_t *wrap_create_wq(const char *name)
{
	struct completion started;
	workqueue_struct_t *workq = kmalloc(sizeof(*workq), GFP_KERNEL);
	if (!workq) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	memset(workq, 0, sizeof(*workq));
	spin_lock_init(&workq->lock);
	strncpy(workq->name, name, sizeof(workq->name));
	workq->name[sizeof(workq->name) - 1] = 0;
	INIT_LIST_HEAD(&workq->work_list);
	init_completion(&started);
	workq->completion = &started;
	workq->pid = kernel_thread(workq_thread, workq, 0);
	if (workq->pid <= 0) {
		kfree(workq);
		WARNING("couldn't start thread %s", name);
		return NULL;
	}
	wait_for_completion(&started);
	return workq;
}

void wrap_flush_wq(workqueue_struct_t *workq)
{
	workq->pending = 1;
	wake_up_process(workq->task);
	while (workq->pending > 0)
		schedule();
}

void wrap_destroy_wq(workqueue_struct_t *workq)
{
	workq->pending = -1;
	wake_up_process(workq->task);
	while (workq->pid) {
		WORKTRACE("%d", workq->pid);
		schedule();
	}
	kfree(workq);
}
