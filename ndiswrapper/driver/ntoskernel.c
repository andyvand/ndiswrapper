#include "ndis.h"
#include "ntoskernel.h"

NOREGPARM int my_sprintf(char *str, const char *format, int p1, int p2, int p3, int p4, int p5, int p6)
{
	int res;
	res = sprintf(str, format, p1, p2, p3, p4, p5, p6);
	return res;
}

NOREGPARM int my_vsprintf (char *str, const char *format, va_list ap)
{
	return vsprintf(str, format, ap);
}

NOREGPARM int my_snprintf(char *buf, size_t count, const char *format, ...)
{
	va_list args;
	int res;
	
	va_start(args, format);
	res = snprintf(buf, count, format, args);
	va_end(args);
	return res;
}

NOREGPARM int my_vsnprintf (char *str, size_t size,
							const char *format, va_list ap)
{
	return vsnprintf(str, size, format, ap);
}


NOREGPARM char *my_strncpy(char *dst, char *src, int n)
{
	return strncpy(dst, src, n);
}

NOREGPARM size_t my_strlen(const char *s)
{
       return strlen(s);
}

NOREGPARM int my_strncmp(const char *s1, const char *s2, size_t n)
{
	return strncmp(s1, s2, n);
}

NOREGPARM int my_strcmp(const char *s1, const char *s2)
{
	return strcmp(s1, s2);
}

NOREGPARM int my_tolower(int c)
{
	return tolower(c);
}

NOREGPARM void *my_memcpy(void * to, const void * from, size_t n)
{
	return memcpy(to, from, n);
}

NOREGPARM void *my_strcpy(void * to, const void * from)
{
	return strcpy(to, from);
}

NOREGPARM void *my_memset(void * s, char c,size_t count)
{
	return memset(s, c, count);
}

NOREGPARM void *my_memmove(void *to, void *from, size_t count)
{
	return memmove(to, from, count);
}
 
NOREGPARM void my_srand(unsigned int seed)
{
	net_srandom(seed);
}

NOREGPARM int my_atoi(const char *ptr)
{
	int i = simple_strtol(ptr, NULL, 10);
	return i;
}

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


STDCALL void WRITE_PORT_ULONG(unsigned int port, unsigned int value)
{
	outl(value, port);
}

STDCALL unsigned int READ_PORT_ULONG(unsigned int port)
{
	return inl(port);
}

STDCALL void WRITE_PORT_USHORT(unsigned int port, unsigned short value)
{
	outw(value, port);
}

STDCALL unsigned short READ_PORT_USHORT(unsigned int port)
{
	return inw(port);
}

STDCALL void WRITE_PORT_UCHAR(unsigned int port, unsigned char value)
{
	outb(value, port);
}

STDCALL unsigned short READ_PORT_UCHAR(unsigned int port)
{
	return inb(port);
}


STDCALL void WRITE_PORT_BUFFER_USHORT (unsigned int port, unsigned short *buf,
				       unsigned long count)
{
	unsigned long i;
	for (i = 0 ; i < count ; i++)
		outw(buf[i], port);
}

STDCALL void READ_PORT_BUFFER_USHORT (unsigned int port, unsigned short *buf,
				      unsigned long count)
{
	unsigned long i;
	for (i = 0 ; i < count; i++)
		buf[i] = inw(port);
}

int my_strcasecmp(char *s1, char *s2)
{
	int ret = 0;
	int len = min(strlen(s1), strlen(s2));

	while (!ret && len--)
		ret = toupper(*s1++) - toupper(*s2++);

	if (!ret)
		ret = strlen(s1) - strlen(s2);
	return ret;
}

STDCALL __s64 _alldiv(__s64 a, __s64 b)
{
	return (a / b);
}

STDCALL __u64 _aulldiv(__u64 a, __u64 b)
{
	return (a / b);
}

STDCALL __s64 _allmul(__s64 a, __s64 b)
{
	return (a * b);
}

STDCALL __u64 _aullmul(__u64 a, __u64 b)
{
	return (a * b);
}

STDCALL __s64 _allrem(__s64 a, __s64 b)
{
	return (a % b);
}

STDCALL __u64 _aullrem(__u64 a, __u64 b)
{
	return (a % b);
}

__attribute__ ((regparm(3))) __s64 _allshl(__s64 a, __u8 b)
{
	return (a << b);
}

__attribute__ ((regparm(3))) __u64 _aullshl(__u64 a, __u8 b)
{
	return (a << b);
}

__attribute__ ((regparm(3))) __s64 _allshr(__s64 a, __u8 b)
{
	return (a >> b);
}

__attribute__ ((regparm(3))) __u64 _aullshr(__u64 a, __u8 b)
{
	return (a >> b);
}


void ktimer_handler(unsigned long data)
{
	struct ktimer *ktimer = (struct ktimer*) data;
	STDCALL void (*func)(void *kdpc, void *ctx, void *arg1, void *arg2) =
		ktimer->kdpc->func;

	if (!ktimer->active)
		return;

	if (ktimer->repeat)
	{
		ktimer->expires = ktimer->timer.expires = jiffies + ktimer->repeat;
		add_timer(&ktimer->timer);
	}
	else
		ktimer->active = 0;

	if (ktimer->kdpc)
		func(ktimer->kdpc, ktimer->kdpc->ctx,
			 ktimer->kdpc->arg1, ktimer->kdpc->arg2);
	return;
}

STDCALL void KeInitializeTimer(struct ktimer *ktimer)
{
	DBGTRACE("%s: %p\n", __FUNCTION__, ktimer);
	init_timer(&ktimer->timer);
	ktimer->timer.data = (unsigned long)ktimer;
	ktimer->timer.function = ktimer_handler;
	ktimer->timer.expires = 0;
	ktimer->active = 0;
	ktimer->expires = 0;
	memset(&ktimer->kdpc, 0, sizeof(ktimer->kdpc));
	ktimer->repeat = 0;
}

STDCALL void KeInitializeDpc(struct kdpc *kdpc, void *func, void *ctx)
{
	DBGTRACE("%s: %p, %p, %p\n", __FUNCTION__, kdpc, func, ctx);
	kdpc->func = func;
	kdpc->ctx = ctx;
}

STDCALL int KeSetTimerEx(struct ktimer *ktimer, __s64 expires,
			 __u32 repeat, struct kdpc *kdpc)
{
	DBGTRACE("%s: %p, %ld, %u, %p\n",
		 __FUNCTION__, ktimer, (long)expires, repeat, kdpc);

	if (ktimer == NULL)
		return 0;
	if (expires < 0)
		ktimer->expires = jiffies + (-expires * HZ) / 10000;
	else
	{
		ktimer->expires = (expires * HZ) / 10000;
		if (repeat)
			printk(KERN_ERR "%s: absolute time with repeat? (%ld, %u)\n",
				   __FUNCTION__, (long)expires, repeat);
	}
	ktimer->repeat = (repeat * HZ) / 1000;
	ktimer->kdpc = kdpc;
	if (ktimer->active)
	{
		mod_timer(&ktimer->timer, ktimer->expires);
		return 1;
	}
	else
	{
		DBGTRACE("%s: adding timer at %ld, %ld\n",
				 __FUNCTION__, ktimer->timer.expires, ktimer->repeat);
		ktimer->timer.expires = ktimer->expires;
		add_timer(&ktimer->timer);
		ktimer->active = 1;
		return 0;
	}
}

STDCALL int KeCancelTimer(struct ktimer *ktimer)
{
	int active = ktimer->active;

	ktimer->active = 0;
	ktimer->repeat = 0;
	if (active)
	{
		DBGTRACE("%s: deleting timer at %ld, %ld\n",
				 __FUNCTION__, ktimer->timer.expires, ktimer->repeat);
		del_timer_sync(&ktimer->timer);
		return 1;
	}
	return 0;
}

STDCALL int rand(void)
{
	char buf[6];
	int i, r;

	get_random_bytes(buf, sizeof(buf));
	for (r = i = 0; i < sizeof(buf) ; i++)
		r += buf[i];
	return r;
}


STDCALL int KeGetCurrentIrql(void)
{
	return DISPATCH_LEVEL;
}

STDCALL void KeInitializeSpinLock(KSPIN_LOCK *lock)
{
	spinlock_t *spin_lock;

	DBGTRACE("%s: lock = %p, *lock = %p\n", __FUNCTION__, lock, *lock);

	if (!lock)
		printk(KERN_ERR "%s: lock %p is not valid pointer?\n",
			   __FUNCTION__, lock);
	spin_lock = kmalloc(sizeof(spinlock_t), GFP_KERNEL);
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

STDCALL void KfAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *oldirql)
{
	KeAcquireSpinLock(lock, oldirql);
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

STDCALL void *MmMapIoSpace(unsigned int phys_addr,
						   unsigned long size, int cache)
{
	void *virt;
	if (cache)
		virt = ioremap(phys_addr, size);
	else
		virt = ioremap_nocache(phys_addr, size);
	DBGTRACE("%s: %x, %lu, %d: %p\n",
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

/** Functions from CIPE **/
NOREGPARM void DbgPrint(char *str, int x, int y, int z)
{
	DBGTRACE(str, x, y, z);
}

/** Functions from HAL **/
STDCALL void KeStallExecutionProcessor(unsigned int usecs)
{
	//DBGTRACE("%s %d\n", __FUNCTION__ , usecs);
	udelay(usecs);
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
void DbgBreakPoint(void)
{
	UNIMPL();
}

void IofCompleteRequest(void){UNIMPL();}
void IoReleaseCancelSpinLock(void){UNIMPL();}
void KfReleaseSpinLock(void){UNIMPL();}
void KeInitializeEvent(void *event){UNIMPL();}
void IoDeleteDevice(void){UNIMPL();}
void IoCreateSymbolicLink(void){UNIMPL();}
void ExFreePool(void){UNIMPL();}
void MmMapLockedPages(void){UNIMPL();}
void IoCreateDevice(void){UNIMPL();}
void IoDeleteSymbolicLink(void){UNIMPL();}
void InterlockedExchange(void){UNIMPL();}
