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

#include "ndis.h"


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

void KfAcquireSpinLock(void){UNIMPL();}
void KfReleaseSpinLock(void){UNIMPL();}
void KeGetCurrentIrql(void){UNIMPL();}
void KeInitializeEvent(void *event){UNIMPL();}

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

STDCALL int RtlEqualUnicodeString(struct ustring *str1, struct ustring *str2, int nocase)
{
	DBGTRACE("%s\n", __FUNCTION__);
	if(str1->len != str2->len)
		return 0;
	
	if(memcmp(str1->buf, str2->buf, str1->len) == 0)
		return 1;

	if(nocase)
		printk(KERN_ERR "ndiswrapper: case insensitive compare not implemented yet\n");
	return 0;
}

STDCALL void RtlCopyUnicodeString(struct ustring *dest, struct ustring *source)
{
	int i, end;
	DBGTRACE("%s\n", __FUNCTION__);

	if (source == 0) {
		dest->len = 0;
		return;
	}

	if (source->len > dest->buflen) {
		end = dest->buflen;
	} else {
		end = source->len;
	}

	for (i = 0; i < end; i++) {
		dest->buf[i] = source->buf[i];
	}
	dest->len = end;
}

STDCALL void RtlAnsiStringToUnicodeString(char *dst, char *src, unsigned int dup)
{
	UNIMPL();
}

STDCALL void KeInitializeSpinLock(void *spinlock)
{
	UNIMPL();
}

STDCALL void *ExAllocatePoolWithTag(unsigned int type, unsigned int size, unsigned int tag)
{
	UNIMPL();
	return (void*)0x000afff8;
}



void IoDeleteSymbolicLink(void){UNIMPL();}
void InterlockedExchange(void){UNIMPL();}
void MmMapLockedPages(void){UNIMPL();}
void RtlUnicodeStringToAnsiString(void){UNIMPL();}
void IoCreateDevice(void){UNIMPL();}
void RtlFreeUnicodeString(void){UNIMPL();}
void IoDeleteDevice(void){UNIMPL();}
void IoCreateSymbolicLink(void){UNIMPL();}
void ExFreePool(void){UNIMPL();}
void RtlUnwind(void){UNIMPL();}
void IofCompleteRequest(void){UNIMPL();}
void IoReleaseCancelSpinLock(void){UNIMPL();}
void _allmul(long p1, long p2, long p3, long p4){UNIMPL();}

void _alldiv(void){UNIMPL();}
void RtlCompareMemory(void){UNIMPL();}
void _aullrem(void){UNIMPL();}
void _aulldiv(void){UNIMPL();}
void _allshr(void){UNIMPL();}
void _allrem(void){UNIMPL();}
void ExDeleteNPagedLookasideList(void){UNIMPL();}
void ExInitializeNPagedLookasideList(void){UNIMPL();}
void ExInterlockedPopEntrySList(void){UNIMPL();}
void ExInterlockedPushEntrySList(void){UNIMPL();}
