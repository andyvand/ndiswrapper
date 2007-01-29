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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
#define SIG_LOCK(t) (&(t)->sigmask_lock)
#else
#define SIG_LOCK(t) (&(t)->sighand->siglock)
#endif

static int workq_thread(void *data)
{
	workqueue_struct_t *workq = data;
	work_struct_t *work;
	unsigned long flags;

	strncpy(current->comm, workq->name, sizeof(current->comm));
	current->comm[sizeof(current->comm) - 1] = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
	daemonize();
	reparent_to_init();
#else
	daemonize(workq->name);
#endif
#ifdef PF_NOFREEZE
	current->flags |= PF_NOFREEZE;
#else
	sigfillset(&current->blocked);
#endif
	set_user_nice(current, -5);
	while (1) {
		if (wait_event_interruptible(workq->waitq_head,
					     workq->pending)) {
			/* TODO: deal with signal */
			WARNING("signal not blocked?");
			flush_signals(current);
			continue;
		}
		spin_lock_irqsave(&workq->lock, flags);
		if (workq->pending-- < 0)
			break;
		if (list_empty(&workq->work_list))
			work = NULL;
		else {
			struct list_head *entry = workq->work_list.next;
			work = list_entry(entry, work_struct_t, list);
			BUG_ON(work->workq != workq);
			if (xchg(&work->workq, NULL))
				list_del(entry);
			else
				work = NULL;
		}
		spin_unlock_irqrestore(&workq->lock, flags);
		if (work)
			work->func(work->data);
	}
	/* set workq for each work to NULL so if work is cancelled
	 * later, it won't access workq */
	list_for_each_entry(work, &workq->work_list, list) {
		work->workq = NULL;
	}
	spin_unlock_irqrestore(&workq->lock, flags);
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
		wake_up_interruptible(&workq->waitq_head);
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
		/* don't decrement workq->pending here; otherwise, it
		 * may prematurely terminate the thread, as this work
		 * may already have been done (pending may have been
		 * decremented for it) */
		spin_unlock_irqrestore(&workq->lock, flags);
	}
}

workqueue_struct_t *wrap_create_wq(const char *name)
{
	workqueue_struct_t *workq = kmalloc(sizeof(*workq), GFP_KERNEL);
	if (!workq) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	memset(workq, 0, sizeof(*workq));
	init_waitqueue_head(&workq->waitq_head);
	spin_lock_init(&workq->lock);
	workq->name = name;
	INIT_LIST_HEAD(&workq->work_list);
	/* we don't need to wait for thread to start, so completion
	 * not used */
	workq->pid = kernel_thread(workq_thread, workq, 0);
	if (workq->pid <= 0) {
		kfree(workq);
		WARNING("couldn't start thread %s", name);
		return NULL;
	}
	return workq;
}

void wrap_destroy_wq(workqueue_struct_t *workq)
{
	while (workq->pid) {
		workq->pending = -1;
		wake_up_interruptible(&workq->waitq_head);
		schedule();
	}
	kfree(workq);
}
