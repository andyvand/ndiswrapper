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

#define _WRAPMEM_C_

#include "ntoskernel.h"

static struct nt_list slack_allocs;
static NT_SPIN_LOCK alloc_lock;

struct slack_alloc_info {
	struct nt_list list;
	size_t size;
};

struct alloc_info {
	enum alloc_type type;
	size_t size;
};

#ifdef ALLOC_INFO
static atomic_t allocs[ALLOC_TYPE_MAX];
#endif

int wrapmem_init(void)
{
	InitializeListHead(&slack_allocs);
	nt_spin_lock_init(&alloc_lock);
	return 0;
}

void wrapmem_exit(void)
{
	struct nt_list *ent;

	/* free all pointers on the slack list */
	nt_spin_lock(&alloc_lock);
	while ((ent = RemoveHeadList(&slack_allocs))) {
		struct slack_alloc_info *info;
		info = container_of(ent, struct slack_alloc_info, list);
		atomic_sub(info->size, &allocs[ALLOC_TYPE_SLACK]);
		kfree(info);
	}
	nt_spin_unlock(&alloc_lock);
	wrapmem_info();
	return;
}

void wrapmem_info(void)
{
#ifdef ALLOC_INFO
	enum alloc_type type;
	for (type = 0; type < ALLOC_TYPE_MAX; type++)
		printk(KERN_DEBUG "%s: total size of allocations in %d: %d\n",
		       DRIVER_NAME, type, atomic_read(&allocs[type]));
#endif
}

/* allocate memory with given flags and add it to list of allocated pointers;
 * if a driver doesn't free this memory for any reason (buggy driver or we
 * allocate space behind driver's back since we need more space than
 * corresponding Windows structure provides etc.), this gets freed
 * automatically when module is unloaded
 */
void *slack_kmalloc(size_t size)
{
	struct slack_alloc_info *info;
	unsigned int flags, n;
	void *ptr;

	TRACEENTER4("size = %lu", (unsigned long)size);

	if (current_irql() < DISPATCH_LEVEL)
		flags = GFP_KERNEL;
	else
		flags = GFP_ATOMIC;
	n = size + sizeof(*info);
	info = kmalloc(n, flags);
	if (!info)
		return NULL;
	info->size = size;
	ptr = info + 1;
	nt_spin_lock(&alloc_lock);
	InsertTailList(&slack_allocs, &info->list);
	nt_spin_unlock(&alloc_lock);
	atomic_add(size, &allocs[ALLOC_TYPE_SLACK]);
	DBGTRACE4("%p, %p", info, ptr);
	TRACEEXIT4(return ptr);
}

/* free pointer and remove from list of allocated pointers */
void slack_kfree(void *ptr)
{
	struct slack_alloc_info *info;

	TRACEENTER4("%p", ptr);
	info = ptr - sizeof(*info);
	nt_spin_lock(&alloc_lock);
	RemoveEntryList(&info->list);
	nt_spin_unlock(&alloc_lock);
	atomic_sub(info->size, &allocs[ALLOC_TYPE_SLACK]);
	kfree(info);
	TRACEEXIT4(return);
}

#ifdef ALLOC_INFO
void *wrap_kmalloc(size_t size, gfp_t flags)
{
	struct alloc_info *info;
	size_t n;
	n = size + sizeof(*info);
	info = kmalloc(n, flags);
	if (!info)
		return NULL;
	if (flags & GFP_ATOMIC)
		info->type = ALLOC_TYPE_ATOMIC;
	else
		info->type = ALLOC_TYPE_NON_ATOMIC;
	info->size = size;
	atomic_add(size, &allocs[info->type]);
	return (info + 1);
}

void wrap_kfree(const void *ptr)
{
	struct alloc_info *info;
	info = (void *)ptr - sizeof(*info);
	atomic_sub(info->size, &allocs[info->type]);
	kfree(info);
}

void *wrap_vmalloc(unsigned long size)
{
	struct alloc_info *info;
	size_t n;
	n = size + sizeof(*info);
	info = vmalloc(n);
	if (!info)
		return NULL;
	info->type = ALLOC_TYPE_VMALLOC;
	info->size = size;
	atomic_add(size, &allocs[info->type]);
	return (info + 1);
}

void wrap_vfree(void *ptr)
{
	struct alloc_info *info;
	info = ptr - sizeof(*info);
	atomic_sub(info->size, &allocs[info->type]);
	vfree(info);
}

int alloc_size(enum alloc_type type)
{
	if (type >= 0 && type < ALLOC_TYPE_MAX)
		return atomic_read(&allocs[type]);
	else
		return -EINVAL;
}

#endif

