/*
 *  Copyright (C) 2003-2004 Pontus Fuchs, Giridhar Pemmasani
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
#include "wrapper.h"

STDCALL void WRITE_REGISTER_ULONG(unsigned int reg, unsigned int val)
{
	writel(val, reg);
}

STDCALL void WRITE_REGISTER_USHORT(unsigned int reg, unsigned short val)
{
	writew(val, reg);
}

STDCALL void WRITE_REGISTER_UCHAR(unsigned int reg, unsigned char val)
{
	writeb(val, reg);
}

STDCALL void KeInitializeTimer(struct ktimer *ktimer)
{
	DBGTRACE("%s: %p\n", __FUNCTION__, ktimer);
	wrapper_init_timer(ktimer, NULL);
	ktimer->dispatch_header.signal_state = 0;
}

STDCALL void KeInitializeDpc(struct kdpc *kdpc, void *func, void *ctx)
{
	DBGTRACE("%s: %p, %p, %p\n", __FUNCTION__, kdpc, func, ctx);
	init_dpc(kdpc, func, ctx);
}

STDCALL int KeSetTimerEx(struct ktimer *ktimer, __s64 due_time,
			 __u32 period, struct kdpc *kdpc)
{
	unsigned long expires;
	unsigned long repeat;
	
	DBGTRACE("%s: %p, %ld, %u, %p\n",
		 __FUNCTION__, ktimer, (long)due_time, period, kdpc);
	
	if (ktimer == NULL)
		return 0;
	if (due_time < 0)
		expires = jiffies + HZ * (-due_time / 10000000);
	else
		expires = HZ * (due_time / 10000000);
	repeat = HZ * (period / 1000);
	if (kdpc)
		wrapper_set_timer_dpc(ktimer->wrapper_timer, kdpc);
	return wrapper_set_timer(ktimer->wrapper_timer, expires, repeat);
}

STDCALL int KeCancelTimer(struct ktimer *ktimer)
{
	char canceled;

	DBGTRACE("%s(entry): %p\n", __FUNCTION__, ktimer);
	wrapper_cancel_timer(ktimer->wrapper_timer, &canceled);
	return canceled;
}

STDCALL void KeInitializeSpinLock(KSPIN_LOCK *lock)
{
	spinlock_t *spin_lock;

	DBGTRACE("%s: lock = %p, *lock = %p\n", __FUNCTION__, lock, *lock);

	if (!lock)
		printk(KERN_ERR "%s: lock %p is not valid pointer?\n",
			   __FUNCTION__, lock);
	spin_lock = wrap_kmalloc(sizeof(spinlock_t), GFP_KERNEL);
	if (!spin_lock)
		printk(KERN_ERR "%s: couldn't allocate space for spinlock\n",
			   __FUNCTION__);
	else
	{
		DBGTRACE("%s: allocated spinlock %p\n", __FUNCTION__, spin_lock);
		spin_lock_init(spin_lock);
		*lock = (KSPIN_LOCK)spin_lock;
	}
}

STDCALL void KeAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *irql)
{
	DBGTRACE("%s: lock = %p, *lock = %p\n", __FUNCTION__, lock, (void *)*lock);
	if (lock && *lock)
		spin_lock((spinlock_t *)(*lock));
	else
		printk(KERN_ERR "%s: lock %p is not initialized?\n",
			   __FUNCTION__, lock);
}

STDCALL void KeReleaseSpinLock(KSPIN_LOCK *lock, KIRQL *oldirql)
{
	DBGTRACE("%s: lock = %p, *lock = %p\n", __FUNCTION__, lock, (void *)*lock);
	if (lock && *lock)
		spin_unlock((spinlock_t *)(*lock));
	else
		printk(KERN_ERR "%s: lock %p is not initialized?\n",
			   __FUNCTION__, lock);
}

_FASTCALL struct slist_entry *
ExInterlockedPushEntrySList(int dummy, 
			    struct slist_entry *entry,union slist_head *head,
			    KSPIN_LOCK *lock)
{
	struct slist_entry *oldhead;
	KIRQL irql;

	DBGTRACE("%s Entry: head = %p, entry = %p\n", __FUNCTION__, head, entry);

//	__asm__ __volatile__ ("" : "=c" (head), "=d" (entry));

	KeAcquireSpinLock(lock, &irql);
	oldhead = head->list.next;
	entry->next = head->list.next;
	head->list.next = entry;
	KeReleaseSpinLock(lock, &irql);
	DBGTRACE("%s exit head = %p, oldhead = %p\n", __FUNCTION__, head, oldhead);
	return(oldhead);
}

_FASTCALL struct slist_entry *
ExInterlockedPopEntrySList(int dummy, KSPIN_LOCK *lock,union slist_head *head)
{
	struct slist_entry *first;
	KIRQL irql;
	
	DBGTRACE("%s: head = %p\n", __FUNCTION__, head);
//	__asm__ __volatile__ ("" : "=c" (head));
	KeAcquireSpinLock(lock, &irql);
	first = NULL;
	if (head)
	{
		first = head->list.next;
		if (first)
		{
			head->list.next = first->next;
		}
	}
	KeReleaseSpinLock(lock, &irql);
	DBGTRACE("%s: Exit, returning %p\n", __FUNCTION__, first);
	return first;
}

STDCALL void *lookaside_def_alloc_func(POOL_TYPE pool_type,
									   unsigned long size, unsigned long tag)
{
	return kmalloc(size, GFP_ATOMIC);
}

STDCALL void lookaside_def_free_func(void *buffer)
{
	kfree(buffer);
}

STDCALL void
 ExInitializeNPagedLookasideList(struct npaged_lookaside_list *lookaside,
				 LOOKASIDE_ALLOC_FUNC *alloc_func,
				 LOOKASIDE_FREE_FUNC *free_func,
				 unsigned long flags, unsigned long size,
				 unsigned long tag, unsigned short depth)
{
	DBGTRACE("%s: Entry, lookaside: %p, size: %lu, flags: %lu,"
		 " head: %p, size of lookaside: %u\n",
		 __FUNCTION__, lookaside, size, flags,
		 lookaside->head.list.next, sizeof(struct npaged_lookaside_list));

	memset(lookaside, 0, sizeof(*lookaside));

	lookaside->size = size;
	lookaside->tag = tag;
	lookaside->depth = 4;
	lookaside->maxdepth = 256;

	if (alloc_func)
		lookaside->alloc_func = alloc_func;
	else
		lookaside->alloc_func = lookaside_def_alloc_func;
	if (free_func)
		lookaside->free_func = free_func;
	else
		lookaside->free_func = lookaside_def_free_func;

	KeInitializeSpinLock(&lookaside->obsolete);
	DBGTRACE("%s: Exit\n", __FUNCTION__);
	return ;
}
 
STDCALL void
ExDeleteNPagedLookasideList(struct npaged_lookaside_list *lookaside)
{
	struct slist_entry *entry, *p;
	
	DBGTRACE("%s: Entry, lookaside = %p\n", __FUNCTION__, lookaside);
	entry = lookaside->head.list.next;
	while (entry)
	{
		p = entry;
		entry = entry->next;
		lookaside->free_func(p);
	}
	DBGTRACE("%s: Exit\n", __FUNCTION__);
}


_FASTCALL void
ExInterlockedAddLargeStatistic(int dummy, u32 n, u64 *plint)
{
	DBGTRACE("%s: Stat %p = %llu, n = %u\n", __FUNCTION__, plint, *plint, n);
	*plint += n;
}

STDCALL void *MmMapIoSpace(__s64 phys_addr,
			   unsigned long size, int cache)
{
	void *virt;
	if (cache)
		virt = ioremap(phys_addr, size);
	else
		virt = ioremap_nocache(phys_addr, size);
	DBGTRACE("%s: %Lx, %lu, %d: %p\n",
		 __FUNCTION__, phys_addr, size, cache, virt);
	return virt;
}

STDCALL void MmUnmapIoSpace(void *addr, unsigned long size)
{
	DBGTRACE("%s: %p, %lu\n", __FUNCTION__, addr, size);
	iounmap(addr);
	return;
}

STDCALL int IoIsWdmVersionAvailable(unsigned char major, unsigned char minor)
{
	DBGTRACE("%s: %d, %d\n", __FUNCTION__, major, minor);
	if (major == 1 &&
	    (minor == 0x30 || // Windows 2003
	     minor == 0x20 || // Windows XP
	     minor == 0x10)) // Windows 2000
		return 1;
	return 0;
}

STDCALL unsigned int KeWaitForSingleObject(void **object, unsigned int reason, unsigned int waitmode, unsigned short alertable, void *timeout)
{
	UNIMPL();
	return 0;
}

STDCALL void *ExAllocatePoolWithTag(unsigned int type, unsigned int size, unsigned int tag)
{
	UNIMPL();
	return (void*)0x000afff8;
}

STDCALL void IoBuildSynchronousFsdRequest(void)
{
	UNIMPL();
}
STDCALL void IofCallDriver(void)
{
	UNIMPL();
}

NOREGPARM unsigned long DbgPrint(char *format, ...)
{
	int res = 0;

#ifdef DEBUG
	va_list args;
	static char buf[1024];

	va_start(args, format);
	res = vsnprintf(buf, sizeof(buf), format, args);
	printk("DbgPrint: ");
	printk(buf);
	va_end(args);
#endif
	return res;

}

void DbgBreakPoint(void)
{
	printk("Warning: Your Windows driver called DbgBreakPoint()! We should raise a blue screen now... ;o)\n");
}

void IofCompleteRequest(void){UNIMPL();}
void IoReleaseCancelSpinLock(void){UNIMPL();}
void KeInitializeEvent(void *event){UNIMPL();}
void IoDeleteDevice(void){UNIMPL();}
void IoCreateSymbolicLink(void){UNIMPL();}
void ExFreePool(void){UNIMPL();}
void MmMapLockedPages(void){UNIMPL();}
void IoCreateDevice(void){UNIMPL();}
void IoDeleteSymbolicLink(void){UNIMPL();}
void InterlockedExchange(void){UNIMPL();}
void KeSetEvent(void){UNIMPL();}
void KeClearEvent(void){UNIMPL();}
void MmMapLockedPagesSpecifyCache(void){UNIMPL();}
void MmProbeAndLockPages(void){UNIMPL();}
void MmUnlockPages(void){UNIMPL();}
void IoAllocateMdl(void){UNIMPL();}
void IoFreeMdl(void){UNIMPL();}
void ObfReferenceObject(void){UNIMPL();}
void ObReferenceObjectByHandle(void){UNIMPL();}
void _except_handler3(void){UNIMPL();}

struct wrap_func ntos_wrap_funcs[] =
{
	WRAP_FUNC_ENTRY(DbgBreakPoint),
	WRAP_FUNC_ENTRY(DbgPrint),
	WRAP_FUNC_ENTRY(ExAllocatePoolWithTag),
	WRAP_FUNC_ENTRY(ExDeleteNPagedLookasideList),
	WRAP_FUNC_ENTRY(ExFreePool),
	WRAP_FUNC_ENTRY(ExInitializeNPagedLookasideList),
	WRAP_FUNC_ENTRY(ExInterlockedAddLargeStatistic),
	WRAP_FUNC_ENTRY(ExInterlockedPopEntrySList),
	WRAP_FUNC_ENTRY(ExInterlockedPushEntrySList),
	WRAP_FUNC_ENTRY(InterlockedExchange),
	WRAP_FUNC_ENTRY(IoAllocateMdl),
	WRAP_FUNC_ENTRY(IoBuildSynchronousFsdRequest),
	WRAP_FUNC_ENTRY(IoCreateDevice),
	WRAP_FUNC_ENTRY(IoCreateSymbolicLink),
	WRAP_FUNC_ENTRY(IoDeleteDevice),
	WRAP_FUNC_ENTRY(IoDeleteSymbolicLink),
	WRAP_FUNC_ENTRY(IoFreeMdl),
	WRAP_FUNC_ENTRY(IoIsWdmVersionAvailable),
	WRAP_FUNC_ENTRY(IoReleaseCancelSpinLock),
	WRAP_FUNC_ENTRY(IofCallDriver),
	WRAP_FUNC_ENTRY(IofCompleteRequest),
	WRAP_FUNC_ENTRY(KeAcquireSpinLock),
	WRAP_FUNC_ENTRY(KeCancelTimer),
	WRAP_FUNC_ENTRY(KeClearEvent),
	WRAP_FUNC_ENTRY(KeInitializeDpc),
	WRAP_FUNC_ENTRY(KeInitializeEvent),
	WRAP_FUNC_ENTRY(KeInitializeSpinLock),
	WRAP_FUNC_ENTRY(KeInitializeTimer),
	WRAP_FUNC_ENTRY(KeReleaseSpinLock),
	WRAP_FUNC_ENTRY(KeSetEvent),
	WRAP_FUNC_ENTRY(KeSetTimerEx),
	WRAP_FUNC_ENTRY(KeWaitForSingleObject),
	WRAP_FUNC_ENTRY(MmMapIoSpace),
	WRAP_FUNC_ENTRY(MmMapLockedPages),
	WRAP_FUNC_ENTRY(MmMapLockedPagesSpecifyCache),
	WRAP_FUNC_ENTRY(MmProbeAndLockPages),
	WRAP_FUNC_ENTRY(MmUnlockPages),
	WRAP_FUNC_ENTRY(MmUnmapIoSpace),
	WRAP_FUNC_ENTRY(ObReferenceObjectByHandle),
	WRAP_FUNC_ENTRY(ObfReferenceObject),
	WRAP_FUNC_ENTRY(WRITE_REGISTER_UCHAR),
	WRAP_FUNC_ENTRY(WRITE_REGISTER_ULONG),
	WRAP_FUNC_ENTRY(WRITE_REGISTER_USHORT),
	WRAP_FUNC_ENTRY(_except_handler3),

	{NULL, NULL}
};
