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

STDCALL static void
WRITE_PORT_ULONG(unsigned int port, unsigned int value)
{
	outl(value, port);
}

STDCALL static unsigned int
READ_PORT_ULONG(unsigned int port)
{
	return inl(port);
}

STDCALL static void
WRITE_PORT_USHORT(unsigned int port, unsigned short value)
{
	outw(value, port);
}

STDCALL static unsigned short
READ_PORT_USHORT(unsigned int port)
{
	return inw(port);
}

STDCALL static void
WRITE_PORT_UCHAR(unsigned int port, unsigned char value)
{
	outb(value, port);
}

STDCALL static unsigned short
READ_PORT_UCHAR(unsigned int port)
{
	return inb(port);
}

STDCALL static void
WRITE_PORT_BUFFER_USHORT (unsigned int port, unsigned short *buf,
			  unsigned long count)
{
	unsigned long i;
	for (i = 0 ; i < count ; i++)
		outw(buf[i], port);
}

STDCALL static void
READ_PORT_BUFFER_USHORT (unsigned int port, unsigned short *buf,
			 unsigned long count)
{
	unsigned long i;
	for (i = 0 ; i < count; i++)
		buf[i] = inw(port);
}

STDCALL static void
KeStallExecutionProcessor(unsigned long usecs)
{
	//DBGTRACE("%s %d\n", __FUNCTION__ , usecs);
	udelay(usecs);
}


_FASTCALL static KIRQL
KfAcquireSpinLock(int dummy1, int dummy2, KSPIN_LOCK *lock)
{
	KIRQL irql;

	TRACEENTER4("lock = %p, *lock = %p", lock, (void *)lock);
	irql = KeGetCurrentIrql();

	if (!lock) {
		ERROR("%s", "invalid lock");
		return irql;
	}

	if (!*lock)
	{
		printk(KERN_WARNING "Buggy Windows driver trying to use "
		       "uninitialized lock. Trying to recover...");
		KeInitializeSpinLock(lock);
		if (*lock)
			printk(KERN_WARNING "ok\n");
		else
		{
			printk(KERN_WARNING "failed\n");
			BUG();
		}
	}

	wrap_spin_lock((struct wrap_spinlock *)*lock);
	return irql;
}

_FASTCALL static void
KfReleaseSpinLock(int dummy, KIRQL newirql, KSPIN_LOCK *lock)
{
	TRACEENTER4("lock = %p, *lock = %p", lock, (void *)*lock);

	if (!lock || !*lock)
	{
		ERROR("invalid spin lock %p", lock);
		return;
	}

	wrap_spin_unlock((struct wrap_spinlock *)*lock);
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
	WRAP_FUNC_ENTRY(KfReleaseSpinLock),
	{NULL, NULL}
};

