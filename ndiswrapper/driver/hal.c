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


STDCALL KIRQL KfAcquireSpinLock(KSPIN_LOCK *lock)
{
	KIRQL irql;

	irql = KeGetCurrentIrql();
	DBGTRACE4("lock = %p, *lock = %p", lock, (void *)lock);
	if (lock && *lock)
	{
		if (irql == DISPATCH_LEVEL)
			spin_lock((spinlock_t *)(*lock));
		else // irql == PASSIVE_LEVEL
			spin_lock_bh((spinlock_t *)(*lock));
	}
	else
		ERROR("lock %p is not initialized!", lock);
	return irql;
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
	{NULL, NULL}
};

