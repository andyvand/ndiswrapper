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

#include "ndis.h"
#include "casemap.h"


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
			      const struct ustring *s2, int CaseInsensitive)
{
	unsigned int len;
	long ret = 0;
	const char *p1, *p2;
	
	len = min(s1->len, s2->len);
	p1 = s1->buf;
	p2 = s2->buf;
	
	if (CaseInsensitive)
	{
		while (!ret && len--)
			ret = toupper(*p1++) - toupper(*p2++);
	}
	else
	{
		while (!ret && len--)
			ret = *p1++ - *p2++;
	}
	if (!ret)
		ret = s1->len - s2->len;
	return ret;
}

static inline __u16 toupperW(__u16 ch)
{
    extern const __u16 wine_casemap_upper[];
    return ch + wine_casemap_upper[wine_casemap_upper[ch >> 8] + (ch & 0xff)];
}


STDCALL long RtlCompareUnicodeString(const struct ustring *s1,
				     const struct ustring *s2,
				     int CaseInsensitive )
{
	unsigned int len;
	long ret = 0;
	const char *p1, *p2;
	
	len = min(s1->len, s2->len) / sizeof(__u16);
	p1 = s1->buf;
	p2 = s2->buf;
	
	if (CaseInsensitive)
	{
		while (!ret && len--)
			ret = toupperW(*p1++) - toupperW(*p2++);
	}
	else
	{
		while (!ret && len--)
			ret = *p1++ - *p2++;
	}
	if (!ret)
		ret = s1->len - s2->len;
	return ret;
}

STDCALL int RtlEqualString(const struct ustring *s1,
			   const struct ustring *s2, int CaseInsensitive )
{
	if (s1->len != s2->len)
		return 0;
	return !RtlCompareString(s1, s2, CaseInsensitive);
}

STDCALL int RtlEqualUnicodeString(const struct ustring *s1,
				  const struct ustring *s2,
				  int CaseInsensitive )
{
	if (s1->len != s2->len)
		return 0;
	return !RtlCompareUnicodeString(s1, s2, CaseInsensitive);
}

STDCALL void RtlCopyUnicodeString(struct ustring *dst,
				  const struct ustring *src)
{
	if (src)
	{
		unsigned int len = min(src->len, dst->buflen);
		memcpy(dst->buf, src->buf, len);
		dst->len = len;
		/* append terminating '\0' if enough space */
		if (len < dst->buflen)
			dst->buf[len / sizeof(__u16)] = 0;
	}
	else dst->len = 0;
}

STDCALL int RtlAnsiStringToUnicodeString(struct ustring *dst, struct ustring *src, unsigned int dup)
{
	int i, *d;

	DBGTRACE("%s: dup: %d src: %s\n", __FUNCTION__, dup, src->buf);
	if(dup)
	{
		char *buf = kmalloc((src->buflen+1) * 2, GFP_KERNEL);
		if(!buf)
			return NDIS_STATUS_FAILURE;
		dst->buf = buf;
		dst->buflen = (src->buflen+1) * 2;
	}

	d = (int*) dst->buf;
	for(i = 0; i < src->len; i++)
	{
		d[i] = src->buf[i];
	}
	d[i] = 0;
	
	dst->len = i*2;
	
	return NDIS_STATUS_SUCCESS;
}

STDCALL int RtlUnicodeStringToAnsiString(struct ustring *dst, struct ustring *src, unsigned int dup)
{
	int i, *s;

	DBGTRACE("%s dup: %d src->len: %d dst: %p", __FUNCTION__, dup, src->len, dst);
	if(dup)
	{
		char *buf = kmalloc(src->buflen, GFP_KERNEL);
		if(!buf)
			return NDIS_STATUS_FAILURE;
		dst->buf = buf;
		dst->len = 0;
		dst->buflen = src->buflen;
	}

	s = (int*) src->buf;
	for(i = 0; i < src->len; i++)
	{
		dst->buf[i] = s[i];
	}
	dst->len = i;
	dst->buf[i] = 0;
	DBGTRACE(" buf: %s\n", dst->buf);
	return NDIS_STATUS_SUCCESS;
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

#ifndef DBG_REALTEK
void _allmul(long p1, long p2, long p3, long p4){UNIMPL();}
void _aullrem(void){UNIMPL();}
void _aulldiv(void){UNIMPL();}
void _allshr(void){UNIMPL();}
void _allrem(void){UNIMPL();}
void _alldiv(void){UNIMPL();}
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
