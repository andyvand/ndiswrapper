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

#include "ndis.h"
#include "ntoskernel.h"

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

STDCALL void KeStallExecutionProcessor(unsigned int usecs)
{
	//DBGTRACE("%s %d\n", __FUNCTION__ , usecs);
	udelay(usecs);
}

void KfReleaseSpinLock(void){UNIMPL();}

extern STDCALL void KeAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *irql);
STDCALL void KfAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *oldirql)
{
	KeAcquireSpinLock(lock, oldirql);
}

STDCALL int KeGetCurrentIrql(void)
{
	return DISPATCH_LEVEL;
}

struct wrap_func hal_wrap_funcs[] =
{
	WRAP_FUNC_ENTRY(WRITE_PORT_BUFFER_USHORT),
	WRAP_FUNC_ENTRY(WRITE_PORT_UCHAR),
	WRAP_FUNC_ENTRY(WRITE_PORT_ULONG),
	WRAP_FUNC_ENTRY(WRITE_PORT_USHORT),
	WRAP_FUNC_ENTRY(READ_PORT_BUFFER_USHORT),
	WRAP_FUNC_ENTRY(READ_PORT_UCHAR),
	WRAP_FUNC_ENTRY(READ_PORT_ULONG),
	WRAP_FUNC_ENTRY(READ_PORT_USHORT),
	WRAP_FUNC_ENTRY(KeStallExecutionProcessor),
	WRAP_FUNC_ENTRY(KfAcquireSpinLock),
	WRAP_FUNC_ENTRY(KeGetCurrentIrql),
	{NULL, NULL}
};

