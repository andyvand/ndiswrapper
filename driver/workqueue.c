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

spinlock_t workq_lock = SPIN_LOCK_UNLOCKED;

/* workqueue implementation for 2.4 kernels */

static int workqueue_thread(void *data)
{
	struct workqueue_struct *workq = data;
	struct work_struct *work;

	lock_kernel();
	strncpy(current->comm, workq->name, sizeof(current->comm));
	current->comm[sizeof(current->comm) - 1] = 0;
	daemonize();
	unlock_kernel();
	while (1) {
		if (wait_event_interruptible(workq->waitq_head,
					     workq->pending != 0)) {
			/* we don't want to terminate thread */
			flush_signals(current);
			continue;
		}
		spin_lock_bh(&workq->lock);
		if (workq->pending-- < 0)
			break;
		if (list_empty(&workq->work_list))
			work = NULL;
		else {
			struct list_head *entry;
			entry = workq->work_list.next;
			work = list_entry(entry, struct work_struct, list);
			list_del_init(entry);
			work->workq = NULL;
		}
		spin_unlock_bh(&workq->lock);
		if (work)
			work->func(work->data);
	}
	/* set workq for each work to NULL so if cancel_delayed_work
	 * is called later, it won't access workq */
	spin_lock_bh(&workq_lock);
	list_for_each_entry(work, &workq->work_list, list) {
		work->workq = NULL;
	}
	spin_unlock_bh(&workq_lock);
	spin_unlock_bh(&workq->lock);
	WORKTRACE("%s exiting", workq->name);
	workq->pid = 0;
	return 0;
}

wfastcall void queue_work(struct workqueue_struct *workq,
			  struct work_struct *work)
{
	spin_lock_bh(&workq->lock);
	if (!work->workq) {
		work->workq = workq;
		list_add_tail(&work->list, &workq->work_list);
		workq->pending++;
		wake_up_interruptible(&workq->waitq_head);
	}
	spin_unlock_bh(&workq->lock);
}

void cancel_delayed_work(struct work_struct *work)
{
	struct workqueue_struct *workq;
	spin_lock_bh(&workq_lock);
	workq = work->workq;
	if (workq) {
		spin_lock_bh(&workq->lock);
		list_del(&work->list);
		/* don't decrement workq->pending here; otherwise, it may
		 * prematurely terminate the thread, as wait_event
		 * above checks it without lock */
		spin_unlock_bh(&workq->lock);
	}
	spin_unlock_bh(&workq_lock);
}

struct workqueue_struct *create_singlethread_workqueue(const char *name)
{
	struct workqueue_struct *workq = kmalloc(sizeof(*workq), GFP_KERNEL);
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
	workq->pid = kernel_thread(workqueue_thread, workq, 0);
	if (workq->pid <= 0) {
		kfree(workq);
		WARNING("couldn't start thread %s", name);
		return NULL;
	}
	return workq;
}

void destroy_workqueue(struct workqueue_struct *workq)
{
	while (workq->pid) {
		workq->pending = -1;
		wake_up_interruptible(&workq->waitq_head);
		schedule();
	}
	kfree(workq);
}
