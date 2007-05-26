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

struct workq_thread_data {
	workqueue_struct_t *workq;
	int index;
};

static int workq_thread(void *data)
{
	struct workq_thread_data *thread_data = data;
	struct workqueue_thread *thread;
	workqueue_struct_t *workq;
	work_struct_t *work;

	workq = thread_data->workq;
	thread = &workq->threads[thread_data->index];
	WORKTRACE("%p, %d, %p", workq, thread_data->index, thread);
	strncpy(thread->name, current->comm, sizeof(thread->name));

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
	daemonize();
	reparent_to_init();
	current->nice -= 5;
	sigfillset(&current->blocked);
#else
	daemonize(thread->name);
	set_user_nice(current, -5);
#endif

	if (thread->task != current) {
		WARNING("invalid task: %p, %p", thread->task, current);
		thread->task = current;
	}
	thread->pid = current->pid;
	complete(xchg(&thread->completion, NULL));
	WORKTRACE("%s (%d) started", thread->name, thread->pid);
	while (1) {
		if (wait_condition(thread->pending, 0, TASK_INTERRUPTIBLE) < 0) {
			/* TODO: deal with signal */
			WARNING("signal not blocked?");
			flush_signals(current);
			continue;
		}
		while (1) {
			struct list_head *entry;
			unsigned long flags;

			spin_lock_irqsave(&thread->lock, flags);
			if (list_empty(&thread->work_list)) {
				struct completion *completion;
				if (thread->pending < 0) {
					spin_unlock_irqrestore(&thread->lock,
							       flags);
					goto out;
				}
				thread->pending = 0;
				completion = thread->completion;
				thread->completion = NULL;
				spin_unlock_irqrestore(&thread->lock, flags);
				if (completion)
					complete(completion);
				break;
			}
			entry = thread->work_list.next;
			work = list_entry(entry, work_struct_t, list);
			if (xchg(&work->thread, NULL))
				list_del(entry);
			else
				work = NULL;
			spin_unlock_irqrestore(&thread->lock, flags);
			DBG_BLOCK(4) {
				WORKTRACE("%p, %p", work, thread);
			}
			if (work)
				work->func(work->data);
		}
	}

out:
	WORKTRACE("%s exiting", thread->name);
	thread->pid = 0;
	return 0;
}

wfastcall int wrap_queue_work_on(workqueue_struct_t *workq, work_struct_t *work,
				 int cpu)
{
	struct workqueue_thread *thread = &workq->threads[cpu];
	unsigned long flags;
	int ret;

	assert(thread->pid > 0);
	DBG_BLOCK(4) {
		WORKTRACE("%p, %d", workq, cpu);
	}
	spin_lock_irqsave(&thread->lock, flags);
	if (work->thread)
		ret = 0;
	else {
		work->thread = thread;
		list_add_tail(&work->list, &thread->work_list);
		thread->pending = 1;
		wake_up_process(thread->task);
		ret = 1;
	}
	spin_unlock_irqrestore(&thread->lock, flags);
	return ret;
}

wfastcall int wrap_queue_work(workqueue_struct_t *workq, work_struct_t *work)
{
	if (NR_CPUS == 1 || workq->singlethread)
		return wrap_queue_work_on(workq, work, 0);
	else {
		typeof(workq->qon) qon;
		/* work is queued on threads in a round-robbin fashion */
		do {
			qon = workq->qon % workq->num_cpus;
			atomic_inc_var(workq->qon);
		} while (!workq->threads[qon].pid);
		return wrap_queue_work_on(workq, work, qon);
	}
}

void wrap_cancel_work(work_struct_t *work)
{
	struct workqueue_thread *thread;
	unsigned long flags;

	WORKTRACE("%p", work);
	if ((thread = xchg(&work->thread, NULL))) {
		WORKTRACE("%p", thread);
		spin_lock_irqsave(&thread->lock, flags);
		list_del(&work->list);
		spin_unlock_irqrestore(&thread->lock, flags);
	}
}

workqueue_struct_t *wrap_create_wq(const char *name, u8 singlethread, u8 freeze)
{
	struct completion started;
	workqueue_struct_t *workq;
	int i, n;

	if (singlethread)
		n = 1;
	else
		n = NR_CPUS;
	workq = kmalloc(sizeof(*workq) + n * sizeof(workq->threads[0]),
			GFP_KERNEL);
	if (!workq) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	memset(workq, 0, sizeof(*workq) + n * sizeof(workq->threads[0]));
	WORKTRACE("%p", workq);
	init_completion(&started);
	for_each_online_cpu(i) {
		struct workq_thread_data thread_data;
		spin_lock_init(&workq->threads[i].lock);
		INIT_LIST_HEAD(&workq->threads[i].work_list);
		INIT_COMPLETION(started);
		workq->threads[i].completion = &started;
		thread_data.workq = workq;
		thread_data.index = i;
		WORKTRACE("%p, %d, %p", workq, i, &workq->threads[i]);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
		workq->threads[i].pid =
			kernel_thread(workq_thread, &thread_data, CLONE_SIGHAND);
		if (workq->threads[i].pid < 0)
			workq->threads[i].task = (void *)-ENOMEM;
		else
			workq->threads[i].task =
				find_task_by_pid(workq->threads[i].pid);
#else
		workq->threads[i].task =
			kthread_create(workq_thread, &thread_data,
				       "%s/%d", name, i);
#endif
		if (IS_ERR(workq->threads[i].task)) {
			int j;
			for (j = 0; j < i; j++)
				wrap_destroy_wq_on(workq, j);
			kfree(workq);
			WARNING("couldn't start thread %s", name);
			return NULL;
		}
#ifdef PF_NOFREEZE
		if (!freeze)
			workq->threads[i].task->flags |= PF_NOFREEZE;
#endif
		kthread_bind(workq->threads[i].task, i);
		workq->num_cpus = max(workq->num_cpus, i);
		wake_up_process(workq->threads[i].task);
		wait_for_completion(&started);
		WORKTRACE("%s, %d: %p, %d", name, i,
			  workq, workq->threads[i].pid);
		if (singlethread)
			break;
	}
	workq->num_cpus++;
	return workq;
}

void wrap_flush_wq_on(workqueue_struct_t *workq, int cpu)
{
	struct workqueue_thread *thread = &workq->threads[cpu];
	struct completion done;

	WORKTRACE("%p: %d, %s", workq, cpu, thread->name);
	init_completion(&done);
	thread->completion = &done;
	thread->pending = 1;
	wake_up_process(thread->task);
	wait_for_completion(&done);
	return;
}

void wrap_flush_wq(workqueue_struct_t *workq)
{
	int i, n;

	WORKTRACE("%p", workq);
	if (workq->singlethread)
		n = 1;
	else
		n = NR_CPUS;
	for (i = 0; i < n; i++)
		wrap_flush_wq_on(workq, i);
}

void wrap_destroy_wq_on(workqueue_struct_t *workq, int cpu)
{
	struct workqueue_thread *thread = &workq->threads[cpu];

	WORKTRACE("%p: %d, %s", workq, cpu, thread->name);
	if (!thread->pid)
		return;
	thread->pending = -1;
	wake_up_process(thread->task);
	while (thread->pid) {
		WORKTRACE("%d", thread->pid);
		schedule();
	}
}

void wrap_destroy_wq(workqueue_struct_t *workq)
{
	int i, n;

	WORKTRACE("%p", workq);
	if (workq->singlethread)
		n = 1;
	else
		n = NR_CPUS;
	for (i = 0; i < n; i++)
		wrap_destroy_wq_on(workq, i);
	kfree(workq);
}
