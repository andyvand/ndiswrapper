/*
 *  Copyright (C) 2003 Pontus Fuchs
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
#include <linux/types.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <asm/io.h>
#include <linux/ctype.h>
#include <linux/random.h>

#include "ndis.h"
#include "ntoskernel.h"

/** Functions from CIPE **/
void DbgPrint(char *str, int x, int y, int z)
{
	DBGTRACE(str, x, y, z);
}

/** Functions from HAL **/
STDCALL void KeStallExecutionProcessor(unsigned int usecs)
{
	//DBGTRACE("%s %d\n", __FUNCTION__ , usecs);
	udelay(usecs);
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
	/*
	__asm__ __volatile__ ("cld ; rep ; outsw"
			      : "=S" (buf), "=c" (count) 
			      : "d" (port),"0" (buf),"1" (count));
	*/
	unsigned long i;
	for (i = 0 ; i < count ; i++)
		outw(buf[i], port);
}

STDCALL void READ_PORT_BUFFER_USHORT (unsigned int port, unsigned short *buf,
				      unsigned long count)
{
	/*
	__asm__ __volatile__ ("cld ; rep ; insw"
			      : "=D" (buf), "=c" (count) 
			      : "d" (port),"0" (buf),"1" (count));
	*/
	unsigned long i;
	for (i = 0 ; i < count; i++)
		buf[i] = inw(port);
}

/** Functions from ntoskrnl **/
int my_sprintf(char *str, const char *format, int p1, int p2, int p3, int p4, int p5, int p6)
{
	int res;
	res = sprintf(str, format, p1, p2, p3, p4, p5, p6);
	return res;
}

int my_vsprintf (char *str, const char *format, va_list ap)
{
	return vsprintf(str, format, ap);
}

char *my_strncpy(char *dst, char *src, int n)
{
	return strncpy(dst, src, n);
}

size_t my_strlen(const char *s)
{
       return strlen(s);
}

int my_strncmp(const char *s1, const char *s2, size_t n)
{
	return strncmp(s1, s2, n);
}

int my_tolower(int c)
{
	return tolower(c);
}

void *my_memcpy(void * to, const void * from, size_t n)
{
	return memcpy(to, from, n);
}

void *my_memset(void * s, char c,size_t count)
{
	return memset(s, c, count);
}

void *my_memmove(void *to, void *from, size_t count)
{
	return memmove(to, from, count);
}
 

STDCALL void WRITE_REGISTER_ULONG(unsigned int reg, unsigned int val)
{
	//DBGTRACE("%s: %08lx=%08lx\n", __FUNCTION__, reg, val);
	writel(val, reg);
}

STDCALL void WRITE_REGISTER_USHORT(unsigned int reg, unsigned short val)
{
	//DBGTRACE("%s: %08lx=%04x\n", __FUNCTION__, reg, val);
	writew(val, reg);
}

STDCALL void WRITE_REGISTER_UCHAR(unsigned int reg, unsigned char val)
{
	//DBGTRACE("%s: %08lx=%02x\n", __FUNCTION__, reg, val);
	writeb(val, reg);
}

STDCALL long RtlCompareString(const struct ustring *s1,
							  const struct ustring *s2, int case_insensitive)
{
	unsigned int len;
	long ret = 0;
	const char *p1, *p2;
	
	DBGTRACE("%s: entry\n", __FUNCTION__);
	len = min(s1->len, s2->len);
	p1 = s1->buf;
	p2 = s2->buf;
	
	if (case_insensitive)
		while (!ret && len--)
			ret = toupper(*p1++) - toupper(*p2++);
	else
		while (!ret && len--)
			ret = *p1++ - *p2++;
	if (!ret)
		ret = s1->len - s2->len;
	return ret;
}


STDCALL long RtlCompareUnicodeString(const struct ustring *s1,
				     const struct ustring *s2,
				     int case_insensitive)
{
	unsigned int len;
	long ret = 0;
	const __u16 *p1, *p2;
	
	DBGTRACE("%s: entry\n", __FUNCTION__);
	len = min(s1->len, s2->len);
	p1 = (__u16 *)s1->buf;
	p2 = (__u16 *)s2->buf;
	
	if (case_insensitive)
		while (!ret && len--)
			ret = toupper((__u8)*p1++) - toupper((__u8)*p2++);
	else
		while (!ret && len--)
			ret = *p1++ - *p2++;
	if (!ret)
		ret = s1->len - s2->len;
	return ret;
}

STDCALL int RtlEqualString(const struct ustring *s1,
			   const struct ustring *s2, int case_insensitive)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	if (s1->len != s2->len)
		return 0;
	return !RtlCompareString(s1, s2, case_insensitive);
}

STDCALL int RtlEqualUnicodeString(const struct ustring *s1,
				  const struct ustring *s2,
				  int case_insensitive)
{
	if (s1->len != s2->len)
		return 0;
	return !RtlCompareUnicodeString(s1, s2, case_insensitive);
}

STDCALL void RtlCopyUnicodeString(struct ustring *dst,
				  const struct ustring *src)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	if (src)
	{
		unsigned int len = min(src->len, dst->buflen);
		memcpy(dst->buf, src->buf, len);
		dst->len = len;
		/* append terminating '\0' if enough space */
		if (len < dst->buflen)
			dst->buf[len] = 0;
	}
	else dst->len = 0;
}

STDCALL int RtlAnsiStringToUnicodeString(struct ustring *dst, struct ustring *src, unsigned int dup)
{
	int i;
	__u16 *d;
	__u8 *s;

	DBGTRACE("%s: dup: %d src: %s\n", __FUNCTION__, dup, src->buf);
	if(dup)
	{
		char *buf = kmalloc((src->buflen+1) * sizeof(__u16), GFP_KERNEL);
		if(!buf)
			return NDIS_STATUS_FAILURE;
		dst->buf = buf;
		dst->buflen = (src->buflen+1) * sizeof(__u16);
	}
	else if (dst->buflen < (src->len+1) * sizeof(__u16))
		return NDIS_STATUS_FAILURE;

	dst->len = src->len * sizeof(__u16);
	d = (__u16 *)dst->buf;
	s = (__u8 *)src->buf;
	for(i = 0; i < src->len; i++)
	{
		d[i] = (__u16)s[i];
	}
	d[i] = 0;
	
	return NDIS_STATUS_SUCCESS;
}

STDCALL int RtlUnicodeStringToAnsiString(struct ustring *dst, struct ustring *src, unsigned int dup)
{
	int i;
	__u16 *s;
	__u8 *d;

	DBGTRACE("%s dup: %d src->len: %d src->buflen: %d, dst: %p\n", __FUNCTION__, dup, src->len, src->buflen, dst);
	if(dup)
	{
		char *buf = kmalloc((src->buflen+1) / sizeof(__u16), GFP_KERNEL);
		if(!buf)
			return NDIS_STATUS_FAILURE;
		dst->buf = buf;
		dst->buflen = (src->buflen+1) / sizeof(__u16);
	}
	else if (dst->buflen < (src->len+1) / sizeof(__u16))
		return NDIS_STATUS_FAILURE;

	dst->len = src->len / sizeof(__u16);
	s = (__u16 *)src->buf;
	d = (__u8 *)dst->buf;
	for(i = 0; i < dst->len; i++)
		d[i] = (__u8)s[i];
	d[i] = 0;

//	DBGTRACE(" buf: %s\n", dst->buf);
	return NDIS_STATUS_SUCCESS;
}

STDCALL int RtlIntegerToUnicodeString(unsigned long value, unsigned long base,
									  struct ustring *ustring)
{
	char string[sizeof(unsigned long) * 8 + 1];
	struct ustring ansi;
	int i;

	DBGTRACE("%s: entry\n", __FUNCTION__);
	if (base == 0)
		base = 10;
	if (!(base == 2 || base == 8 || base == 10 || base == 16))
		return NDIS_STATUS_INVALID_PARAMETER;
	for (i = 0; value && i < sizeof(string); i++)
	{
		int r;
		r = value % base;
		value /= base;
		if (r < 10)
			string[i] = r + '0';
		else
			string[i] = r + 'a' - 10;
	}

	if (i < sizeof(string))
		string[i] = 0;
	else
		return NDIS_STATUS_BUFFER_TOO_SHORT;

	ansi.buf = string;
	ansi.len = strlen(string);
	ansi.buflen = sizeof(string);
	return RtlAnsiStringToUnicodeString(ustring, &ansi, 0);
}

STDCALL void IoBuildSynchronousFsdRequest(void)
{
	UNIMPL();
}
STDCALL void IofCallDriver(void)
{
	UNIMPL();
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

void DbgBreakPoint(void)
{
	UNIMPL();
}

void NdisMRemoveMiniport(void) { UNIMPL(); }

#ifdef DBG_ATHEROS
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

void ktimer_handler(unsigned long data)
{
	struct ktimer *ktimer = (struct ktimer*) data;
	STDCALL void (*func)(void *kdpc, void *ctx, void *arg1, void *arg2) =
		ktimer->kdpc->func;

	if (!ktimer->active)
		return;
	func(ktimer->kdpc, ktimer->kdpc->ctx,
	     ktimer->kdpc->arg1, ktimer->kdpc->arg2);

	if (ktimer->repeat)
	{
		ktimer->expires = ktimer->timer.expires =
			jiffies + ktimer->repeat;
		add_timer(&ktimer->timer);
	}
	else
		ktimer->active = 0;
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

STDCALL int KeSetTimerEx(struct ktimer *ktimer, long expires,
			 long repeat, struct kdpc *kdpc)
{
	DBGTRACE("%s: %p, %ld, %ld, %p\n",
		 __FUNCTION__, ktimer, expires, repeat,
		kdpc);

	if (expires < 0)
		ktimer->expires = jiffies + (-expires * HZ) / 10000;
	else
	{
		ktimer->expires = (expires * HZ) / 10000;
		if (repeat)
			DBGTRACE("%s: absolute time with repeat? (%ld, %ld)\n",
				 __FUNCTION__, expires, repeat);
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
#else // DBG_ATHEROS
void MmMapIoSpace(void){UNIMPL();}
void MmUnmapIoSpace(void){UNIMPL();}
void KeInitializeTimer(void){UNIMPL();}
void KeInitializeDpc(void){UNIMPL();}
void KeSetTimerEx(void){UNIMPL();}
void KeCancelTimer(void){UNIMPL();}
void rand(void) { UNIMPL(); }
#endif // DBG_ATHEROS

void IoDeleteSymbolicLink(void){UNIMPL();}
void InterlockedExchange(void){UNIMPL();}
void MmMapLockedPages(void){UNIMPL();}
void IoCreateDevice(void){UNIMPL();}
void RtlFreeUnicodeString(void){UNIMPL();}
void IoDeleteDevice(void){UNIMPL();}
void IoCreateSymbolicLink(void){UNIMPL();}
void ExFreePool(void){UNIMPL();}
void RtlUnwind(void){UNIMPL();}
void IofCompleteRequest(void){UNIMPL();}
void IoReleaseCancelSpinLock(void){UNIMPL();}
void KfReleaseSpinLock(void){UNIMPL();}
void KeInitializeEvent(void *event){UNIMPL();}
void RtlCompareMemory(void){UNIMPL();}

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

__attribute__ ((regparm(3))) __u64 _allshl(__u64 a, __u8 b)
{
	return (a << b);
}

__attribute__ ((regparm(3))) __u64 _allshr(__u64 a, __u8 b)
{
	return (a >> b);
}

#ifndef DBG_REALTEK
void ExDeleteNPagedLookasideList(void){UNIMPL();}
void ExInitializeNPagedLookasideList(void){UNIMPL();}
void ExInterlockedPopEntrySList(void){UNIMPL();}
void ExInterlockedPushEntrySList(void){UNIMPL();}
void KeGetCurrentIrql(void){UNIMPL();}
STDCALL void KeInitializeSpinLock(void *spinlock)
{
	UNIMPL();
}
void KfAcquireSpinLock(void){UNIMPL();}

#endif // DBG_REALTEK

#ifdef DBG_TI
extern void NdisMCancelTimer(struct ndis_timer **, char *);
extern void NdisMInitializeTimer(struct ndis_timer **, void *, void *, void *);

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

STDCALL int NdisMRegisterDevice(struct ndis_handle *handle,
				struct ustring *dev_name,
				struct ustring *sym_name,
				void **funcs, void *dev_object,
				struct ndis_handle **dev_handle)
{
	DBGTRACE("%s: %p, %p\n", __FUNCTION__, *dev_handle, handle);
	*dev_handle = handle;
	return NDIS_STATUS_SUCCESS;
}

STDCALL int NdisMDeregisterDevice(struct ndis_handle *handle)
{
	return NDIS_STATUS_SUCCESS;
}

STDCALL void NdisCancelTimer(struct ndis_timer **timer, char *cancelled)
{
	NdisMCancelTimer(timer, cancelled);
}

STDCALL void NdisInitializeTimer(struct ndis_timer *timer,
								 void *func, void *ctx)
{
	DBGTRACE("%s(entry): %p, %p, %p, %p\n",
			 __FUNCTION__, timer_handle, *timer_handle, func, ctx);
//	NdisMInitializeTimer(timer_handle, NULL, func, ctx);
	DBGTRACE("%s(exit): %p, %p, %p, %p\n",
			 __FUNCTION__, timer_handle, *timer_handle, func, ctx);
}

#else // DBG_TI
void IoIsWdmVersionAvailable(void) { UNIMPL(); }
void NdisMRegisterDevice(void) { UNIMPL(); }
void NdisMDeregisterDevice(void) { UNIMPL(); }
void NdisCancelTimer(void) { UNIMPL(); }
void NdisInitializeTimer(void) { UNIMPL(); }
#endif // DBG_TI
