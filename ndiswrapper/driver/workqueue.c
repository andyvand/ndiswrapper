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

static int workqueue_thread(void *data)
{
	struct workqueue_struct *wq = data;
	struct work_struct *work;

	snprintf(current->comm, sizeof(current->comm), "%s", wq->name);
	set_user_nice(current, -5);
	daemonize();
	while (1) {
		wait_event(wq->wq_head, wq->pending != 0);
		spin_lock_bh(&wq->lock);
		if (wq->pending-- < 0) {
			spin_unlock_bh(&wq->lock);
			break;
		}
		if (list_empty(&wq->work_list))
			work = NULL;
		else {
			struct list_head *entry;
			entry = wq->work_list.next;
			work = list_entry(entry, struct work_struct, list);
			list_del_init(entry);
			work->wq = NULL;
		}
		spin_unlock_bh(&wq->lock);
		if (!work)
			continue;
		work->func(work->data);
	}
	WORKTRACE("%s exiting", wq->name);
	wq->pid = 0;
	return 0;
}

void queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	spin_lock_bh(&wq->lock);
	if (!work->wq) {
		work->wq = wq;
		list_add_tail(&work->list, &wq->work_list);
		wq->pending++;
		wake_up(&wq->wq_head);
	}
	spin_unlock_bh(&wq->lock);
}

void cancel_delayed_work(struct work_struct *work)
{
	struct workqueue_struct *wq = work->wq;
	if (wq) {
		spin_lock_bh(&wq->lock);
		list_del(&work->list);
		/* don't decrement wq->pending here, as wait_event
		 * above checks without lock */
		spin_unlock_bh(&wq->lock);
	}
}

struct workqueue_struct *create_singlethread_workqueue(const char *name)
{
	struct workqueue_struct *wq = kmalloc(sizeof(*wq), GFP_KERNEL);
	if (!wq) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	memset(wq, 0, sizeof(*wq));
	init_waitqueue_head(&wq->wq_head);
	spin_lock_init(&wq->lock);
	wq->name = name;
	INIT_LIST_HEAD(&wq->work_list);
	/* we don't need to wait for thread to start, so completion
	 * not used */
	wq->pid = kernel_thread(workqueue_thread, wq, 0);
	if (wq->pid <= 0) {
		kfree(wq);
		WARNING("couldn't start thread %s", name);
		return NULL;
	}
	return wq;
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	wq->pending = -1;
	wake_up(&wq->wq_head);
	while (wq->pid)
		schedule();
	kfree(wq);
}
