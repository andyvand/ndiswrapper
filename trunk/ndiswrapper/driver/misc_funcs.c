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
	printk(str, x, y, z);
}

/** Functions from HAL **/
STDCALL void KeStallExecutionProcessor(unsigned int usecs)
{
	//printk("%s %d\n", __FUNCTION__ , usecs);
	udelay(usecs);
}

void KfAcquireSpinLock(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void KfReleaseSpinLock(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}


/** Functions from ntoskrnl **/
int my_sprintf(char *str, const char *format, int p1, int p2, int p3, int p4, int p5, int p6)
{
	int res;
	res = sprintf(str, format, p1, p2, p3, p4, p5, p6);
	printk("%s: fmt: %s res:%s\n", __FUNCTION__, format, str);
	return res;
}
char * my_strncpy(char *dst, char *src, int n)
{
	printk("%s; ", __FUNCTION__ );
	int i;
	for(i = 0; i < n; i++)
	{
		if(src[i] == 0)
			break;
		printk("%c", src[i]);
	}
	printk("\n");
	
	return strncpy(dst, src, n);
}


STDCALL void WRITE_REGISTER_ULONG(unsigned int reg, unsigned int val)
{
	//printk("%s: %08lx=%08lx\n", __FUNCTION__, reg, val);
	writel(val, reg);
}

STDCALL void WRITE_REGISTER_USHORT(unsigned int reg, unsigned short val)
{
	//printk("%s: %08lx=%04x\n", __FUNCTION__, reg, val);
	writew(val, reg);
}

STDCALL void WRITE_REGISTER_UCHAR(unsigned int reg, unsigned char val)
{
	//printk("%s: %08lx=%02x\n", __FUNCTION__, reg, val);
	writew(val, reg);
}

STDCALL void KeInitializeEvent(void *event, unsigned int type, unsigned char state)
{
	printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );
}
STDCALL void IoBuildSynchronousFsdRequest(void)
{
	printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );
}
STDCALL void IofCallDriver(void)
{
	printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );
}
STDCALL unsigned int KeWaitForSingleObject(void **object, unsigned int reason, unsigned int waitmode, unsigned short alertable, void *timeout)
{
	printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );
	return 0;
}





STDCALL void RtlAnsiStringToUnicodeString(char *dst, char *src, unsigned int unknown)
{
	printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );
}

STDCALL void KeInitializeSpinLock(void *spinlock)
{
	printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );
}

STDCALL void *ExAllocatePoolWithTag(unsigned int type, unsigned int size, unsigned int tag)
{
	printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );
	return (void*)0x000afff8;
}
void IoDeleteSymbolicLink(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void InterlockedExchange(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void MmMapLockedPages(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void RtlUnicodeStringToAnsiString(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void IoCreateDevice(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void RtlFreeUnicodeString(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void IoDeleteDevice(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void IoCreateSymbolicLink(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void ExFreePool(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void RtlUnwind(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void IofCompleteRequest(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}
void IoReleaseCancelSpinLock(void){printk("%s --UNIMPLEMENTED--\n", __FUNCTION__ );}

