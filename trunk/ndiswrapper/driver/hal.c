/*
 *  Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
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

STDCALL void WRAP_EXPORT(WRITE_PORT_ULONG)
	(ULONG_PTR port, ULONG value)
{
	outl(value, port);
}

STDCALL ULONG WRAP_EXPORT(READ_PORT_ULONG)
	(ULONG_PTR port)
{
	return inl((unsigned long)port);
}

STDCALL void WRAP_EXPORT(WRITE_PORT_USHORT)
	(ULONG_PTR port, USHORT value)
{
	outw(value, (unsigned long)port);
}

STDCALL USHORT WRAP_EXPORT(READ_PORT_USHORT)
	(ULONG_PTR port)
{
	return inw((unsigned long)port);
}

STDCALL void WRAP_EXPORT(WRITE_PORT_UCHAR)
	(ULONG_PTR port, UCHAR value)
{
	outb(value, (unsigned long)port);
}

STDCALL UCHAR WRAP_EXPORT(READ_PORT_UCHAR)
	(ULONG_PTR port)
{
	return inb((unsigned long)port);
}

STDCALL void WRAP_EXPORT(WRITE_PORT_BUFFER_USHORT)
	(ULONG_PTR port, USHORT *buf, ULONG count)
{
	ULONG i;

	for (i = 0 ; i < count ; i++)
		outw(buf[i], (unsigned long)port);
}

STDCALL void WRAP_EXPORT(READ_PORT_BUFFER_USHORT)
	(ULONG_PTR port, USHORT *buf, ULONG count)
{
	ULONG i;

	for (i = 0 ; i < count; i++)
		buf[i] = inw((unsigned long)port);
}

STDCALL void WRAP_EXPORT(KeStallExecutionProcessor)
	(ULONG usecs)
{
	udelay(usecs);
}

_FASTCALL KIRQL WRAP_EXPORT(KfRaiseIrql)
	(FASTCALL_DECL_1(KIRQL newirql))
{
	KIRQL irql;

	TRACEENTER4("irql = %d", newirql);

	irql = KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL) {
		local_bh_disable();
		preempt_disable();
	}

	TRACEEXIT4(return irql);
}
	
_FASTCALL void WRAP_EXPORT(KfLowerIrql)
	(FASTCALL_DECL_1(KIRQL oldirql))
{
	TRACEENTER4("irql = %d", oldirql);

	if (oldirql < DISPATCH_LEVEL) {
#if DEBUG_IRQL
		KIRQL irql;
		irql = KeGetCurrentIrql();
		if (irql != DISPATCH_LEVEL) {
			WARNING("IRQL %d != DISPATCH_LEVEL", irql);
			return;
		}
#endif
		preempt_enable();
		local_bh_enable();
	}

	TRACEEXIT4(return);
}

_FASTCALL KIRQL WRAP_EXPORT(KfAcquireSpinLock)
	(FASTCALL_DECL_1(KSPIN_LOCK *lock))
{
	KIRQL oldirql;
	TRACEENTER4("lock = %p", lock);

	oldirql = raise_irql(DISPATCH_LEVEL);
	spin_lock(K_SPINLOCK(lock));

	TRACEEXIT4(return oldirql);
}

_FASTCALL void WRAP_EXPORT(KfReleaseSpinLock)
	(FASTCALL_DECL_2(KSPIN_LOCK *lock, KIRQL newirql))
{
	TRACEENTER4("lock = %p, irql = %d", lock, newirql);

	spin_unlock(K_SPINLOCK(lock));
	lower_irql(newirql);

	TRACEEXIT4(return);
}

_FASTCALL void WRAP_EXPORT(KefAcquireSpinLockAtDpcLevel)
	(FASTCALL_DECL_1(KSPIN_LOCK *lock))
{
	KIRQL irql;
	TRACEENTER4("lock = %p", lock);

#if DEBUG_IRQL
	irql = KeGetCurrentIrql();
	if (irql != DISPATCH_LEVEL)
		ERROR("irql %d != DISPATCH_LEVEL", irql);
#endif
	spin_lock(K_SPINLOCK(lock));
	TRACEEXIT4(return);
}

_FASTCALL void WRAP_EXPORT(KefReleaseSpinLockFromDpcLevel)
	(FASTCALL_DECL_1(KSPIN_LOCK *lock))
{
	TRACEENTER4("lock = %p", lock);

#ifdef DEBUG_IRQL
	if (KeGetCurrentIrql() != DISPATCH_LEVEL)
		ERROR("irql != DISPATCH_LEVEL");
#endif

	spin_unlock(K_SPINLOCK(lock));

	TRACEEXIT4(return);
}

#include "hal_exports.h"
