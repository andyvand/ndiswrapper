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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/delay.h>
#include <linux/usb.h>

#include "ntoskernel.h"

STDCALL static void WRAP_EXPORT(WRITE_PORT_ULONG)
	(unsigned int port, unsigned int value)
{
	outl(value, port);
}

STDCALL static unsigned int WRAP_EXPORT(READ_PORT_ULONG)
	(unsigned int port)
{
	return inl(port);
}

STDCALL static void WRAP_EXPORT(WRITE_PORT_USHORT)
	(unsigned int port, unsigned short value)
{
	outw(value, port);
}

STDCALL static unsigned short WRAP_EXPORT(READ_PORT_USHORT)
	(unsigned int port)
{
	return inw(port);
}

STDCALL static void WRAP_EXPORT(WRITE_PORT_UCHAR)
	(unsigned int port, unsigned char value)
{
	outb(value, port);
}

STDCALL static unsigned short WRAP_EXPORT(READ_PORT_UCHAR)
	(unsigned int port)
{
	return inb(port);
}

STDCALL static void WRAP_EXPORT(WRITE_PORT_BUFFER_USHORT)
	(unsigned int port, unsigned short *buf, unsigned long count)
{
	unsigned long i;
	for (i = 0 ; i < count ; i++)
		outw(buf[i], port);
}

STDCALL static void WRAP_EXPORT(READ_PORT_BUFFER_USHORT)
	(unsigned int port, unsigned short *buf, unsigned long count)
{
	unsigned long i;
	for (i = 0 ; i < count; i++)
		buf[i] = inw(port);
}

STDCALL static void WRAP_EXPORT(KeStallExecutionProcessor)
	(unsigned long usecs)
{
	//DBGTRACE("%s %d\n", __FUNCTION__ , usecs);
	udelay(usecs);
}

_FASTCALL KIRQL WRAP_EXPORT(KfRaiseIrql)
	(int dummy1, int dummy2, KIRQL newirql)
{
	KIRQL irql;

	TRACEENTER4("irql = %d", newirql);

	irql = KeGetCurrentIrql();
#if DEBUG_IRQL
	if (newirql < irql) {
		ERROR("invalid irql %d", irql);
		TRACEEXIT4(return PASSIVE_LEVEL);
	}
#endif

	if (irql < DISPATCH_LEVEL) {
		local_bh_disable();
		preempt_disable();
	}

	TRACEEXIT4(return irql);
}
	
_FASTCALL void WRAP_EXPORT(KfLowerIrql)
	(int dummy1, int dummy2, KIRQL oldirql)
{
	TRACEENTER4("irql = %d", oldirql);

	if (oldirql < DISPATCH_LEVEL) {
#if DEBUG_IRQL
		KIRQL irql;
		irql = KeGetCurrentIrql();
		if (irql != DISPATCH_LEVEL)
			WARNING("IRQL %d != DISPATCH_LEVEL", irql);
#endif
		preempt_enable();
		local_bh_enable();
	}

	TRACEEXIT4(return);
}

_FASTCALL KIRQL WRAP_EXPORT(KfAcquireSpinLock)
	(int dummy1, int dummy2, KSPIN_LOCK *lock)
{
	TRACEENTER4("lock = %p", lock);

	if (!lock) {
		ERROR("%s", "invalid lock");
		TRACEEXIT4(return PASSIVE_LEVEL);
	}

	if (!*lock) {
		printk(KERN_WARNING "Buggy Windows driver trying to use "
		       "uninitialized lock. Trying to recover...");
		KeInitializeSpinLock(lock);
		if (*lock)
			printk(KERN_WARNING "ok\n");
		else {
			printk(KERN_WARNING "failed\n");
			BUG();
		}
	} else if ((*lock)->magic != WRAPPER_SPIN_LOCK_MAGIC)
		ERROR("uninitialized spinlock %p", *lock);

	wrap_spin_lock(*lock);
	
	TRACEEXIT4(return (*lock)->irql);
}

_FASTCALL void WRAP_EXPORT(KefAcquireSpinLockAtDpcLevel)
	(int dummy1, int dummy2, KSPIN_LOCK *lock)
{
	TRACEENTER4("lock = %p", lock);

	if (KeGetCurrentIrql() != DISPATCH_LEVEL)
		ERROR("%s", "irql != DISPATCH_LEVEL");

	KfAcquireSpinLock(0, 0, lock);
}

_FASTCALL void WRAP_EXPORT(KefReleaseSpinLockFromDpcLevel)
	(int dummy1, int dummy2, KSPIN_LOCK *lock)
{
	struct wrap_spinlock *wrap_lock;
	TRACEENTER4("lock = %p", lock);
	if (KeGetCurrentIrql() != DISPATCH_LEVEL)
		ERROR("%s", "irql != DISPATCH_LEVEL");

	if (!lock || !*lock) {
		ERROR("invalid spin lock %p", lock);
		TRACEEXIT4(return);
	}
	
	wrap_lock = *lock;
	wrap_spin_unlock(wrap_lock);

	TRACEEXIT4(return);
}


_FASTCALL void WRAP_EXPORT(KfReleaseSpinLock)
	(int dummy, KIRQL oldirql, KSPIN_LOCK *lock)
{
	struct wrap_spinlock *wrap_lock;

	TRACEENTER4("lock = %p, irql = %d", lock, oldirql);

	if (!lock || !*lock) {
		ERROR("invalid spin lock %p", lock);
		TRACEEXIT4(return);
	}
	
	wrap_lock = *lock;
	if (oldirql != wrap_lock->irql)
		ERROR("invlid irql %d", oldirql);

	wrap_spin_unlock(wrap_lock);

	TRACEEXIT4(return);
}

#include "hal_exports.h"
