#ifdef DBG_REALTEK
#include "ndis.h"

#include "ntoskernel.h"

int ndis_irql = 1;

STDCALL int KeGetCurrentIrql(void)
{
	static int irql = 1;
	if (irql != ndis_irql)
		DBGTRACE("%s returning %d\n", __FUNCTION__, ndis_irql);
	irql = ndis_irql;
	return ndis_irql;
}

STDCALL void KeInitializeSpinLock(PKSPIN_LOCK ndis_kspin_lock)
{
	printk(KERN_INFO "%s: lock = %p, *lock = %lu\n",
		 __FUNCTION__, ndis_kspin_lock, *ndis_kspin_lock);
	spinlock_t *lock = (spinlock_t *)(ndis_kspin_lock);
	*lock = SPIN_LOCK_UNLOCKED;
}

STDCALL void KeAcquireSpinLock(PKSPIN_LOCK ndis_kspin_lock, KIRQL *oldirql)
{
	printk(KERN_INFO "%s: lock = %p, *lock = %lu\n",
		 __FUNCTION__, ndis_kspin_lock, *ndis_kspin_lock);
	spin_lock_irq((spinlock_t *)(ndis_kspin_lock));
}

STDCALL void KeReleaseSpinLock(PKSPIN_LOCK ndis_kspin_lock, KIRQL *oldirql)
{
	printk(KERN_INFO "%s: lock = %p, *lock = %lu\n",
		 __FUNCTION__, ndis_kspin_lock, *ndis_kspin_lock);
	spin_unlock_irq((spinlock_t *)(ndis_kspin_lock));
}

STDCALL void KfAcquireSpinLock(PKSPIN_LOCK ndis_kspin_lock, KIRQL *oldirql)
{
	KeAcquireSpinLock(ndis_kspin_lock, oldirql);
}

_FASTCALL struct slist_entry *
ExInterlockedPushEntrySList(int dummy, 
			    struct slist_entry *entry,union slist_head *head,
			    PKSPIN_LOCK lock)
{

	struct slist_entry *oldhead;

	printk(KERN_INFO "%s Entry: head = %p, entry = %p\n",
			__FUNCTION__, head, entry);

//	__asm__ __volatile__ ("" : "=c" (head), "=d" (entry));

	oldhead = head->list.next;
	entry->next = head->list.next;
	head->list.next = entry;
	printk(KERN_INFO "%s exit head = %p, oldhead = %p\n",
			__FUNCTION__, head, oldhead);
	return(oldhead);

}

_FASTCALL
struct slist_entry *ExInterlockedPopEntrySList(int dummy, 
					       PKSPIN_LOCK ndis_kspin_lock,union slist_head *head)
{
	struct slist_entry *first;
//	KIRQL oldlvl;
	
	printk(KERN_INFO "%s: head = %p\n",
	       __FUNCTION__, head);
//	__asm__ __volatile__ ("" : "=c" (head));
//	KeAcquireSpinLock(ndis_kspin_lock, &oldlvl);
	first = NULL;
	if (head)
	{
		first = head->list.next;
		if (first)
		{
			head->list.next = first->next;
		}
	}
//	KeReleaseSpinLock(ndis_kspin_lock, &oldlvl);
	DBGTRACE("%s: Exit, returning %p\n", __FUNCTION__, first);
	return first;
}

kmem_cache_t *g_kmem_cache;
struct npaged_lookaside_list *g_lookaside;

STDCALL void *lookaside_def_alloc_func(POOL_TYPE pool_type, unsigned long size, unsigned long tag)
{
	char *mem;
//	struct slist_entry *entry;

	printk(KERN_INFO "%s called, size = %lu\n", __FUNCTION__, size);
//	entry = kmalloc(sizeof(struct slist_entry), GFP_ATOMIC);
	mem = kmem_cache_alloc(g_kmem_cache, GFP_ATOMIC);
	printk(KERN_INFO "%s allocates %p\n", __FUNCTION__, mem);
	if (!mem)
		printk(KERN_INFO "%s: alloc failed\n", __FUNCTION__);
	/*
	else
	{
		entry->next = g_lookaside->head.list.next;
		g_lookaside->head.list.next = entry;
	}
	*/
	return mem;
}

STDCALL void lookaside_def_free_func(void *buffer)
{
	printk(KERN_INFO "%s Entry\n", __FUNCTION__);
	kmem_cache_free(g_kmem_cache, buffer);
	printk(KERN_INFO "%s Exit\n", __FUNCTION__);
}

STDCALL void ExInitializeNPagedLookasideList(struct npaged_lookaside_list *lookaside, LOOKASIDE_ALLOC_FUNC *alloc_func, LOOKASIDE_FREE_FUNC *free_func, unsigned long flags, unsigned long size, unsigned long tag, unsigned short depth)
{
	
	int align;
	DBGTRACE("%s: Entry, lookaside: %p, size: %lu, flags: %lu,"
		 " head: %p, size of lookaside: %u\n",
		 __FUNCTION__, lookaside, size, flags,
		 lookaside->head.list.next, sizeof(struct npaged_lookaside_list));
	if (lookaside)
	{
		/*
		lookaside->totalallocs = 0;
		lookaside->allocmisses = 0;
		lookaside->totalfrees = 0;
		lookaside->freemisses = 0;
		*/
		lookaside->size = size;
		lookaside->tag = tag;
		if (alloc_func)
			lookaside->alloc_func = alloc_func;
		else
			lookaside->alloc_func = lookaside_def_alloc_func;
		if (free_func)
			lookaside->free_func = free_func;
		else
			lookaside->free_func = lookaside_def_free_func;
		
		/*
		lookaside->head.align = 0;
		lookaside->depth = 0;
		lookaside->maxdepth = 0;
		lookaside->obsolete = 0;
		*/
		KeInitializeSpinLock(&lookaside->obsolete);
		if (size > PAGE_SIZE)
			align = PAGE_SIZE;
		else
			align = 8;
		g_kmem_cache =
			kmem_cache_create("ndiswrapper", size, 0,
					  SLAB_HWCACHE_ALIGN, 0, 0);
		g_lookaside = lookaside;
	}
	DBGTRACE("%s: Exit\n", __FUNCTION__);
	return ;
}
 
STDCALL void ExDeleteNPagedLookasideList(struct npaged_lookaside_list *lookaside)
{
	DBGTRACE("%s: Entry, lookaside = %p\n", __FUNCTION__, lookaside);
	if (lookaside)
	{
//		struct slist_entry *entry, *p;
		if (g_kmem_cache)
		{
			if (kmem_cache_destroy(g_kmem_cache))
				printk(KERN_INFO "cache_destroy failed\n");
		} else
			printk(KERN_INFO "%s: kmem_cache is NULL\n",
			       __FUNCTION__);
		/*
		entry = lookaside->head.list.next; 
		while (entry)
		{
			p = entry;
			entry = entry->next;
			kfree(p);
		}
		*/
	}
	else
		printk(KERN_INFO "%s: lookaside is NULL\n", __FUNCTION__);
	g_kmem_cache = NULL;
}

#endif // DBG_REALTEK
	
