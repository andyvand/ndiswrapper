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

wstdcall void WIN_FUNC(WRITE_PORT_ULONG,2)
	(ULONG_PTR port, ULONG value)
{
	outl(value, port);
}

wstdcall ULONG WIN_FUNC(READ_PORT_ULONG,1)
	(ULONG_PTR port)
{
	return inl(port);
}

wstdcall void WIN_FUNC(WRITE_PORT_USHORT,2)
	(ULONG_PTR port, USHORT value)
{
	outw(value, port);
}

wstdcall USHORT WIN_FUNC(READ_PORT_USHORT,1)
	(ULONG_PTR port)
{
	return inw(port);
}

wstdcall void WIN_FUNC(WRITE_PORT_UCHAR,2)
	(ULONG_PTR port, UCHAR value)
{
	outb(value, port);
}

wstdcall UCHAR WIN_FUNC(READ_PORT_UCHAR,1)
	(ULONG_PTR port)
{
	return inb(port);
}

wstdcall void WIN_FUNC(WRITE_PORT_BUFFER_USHORT,3)
	(ULONG_PTR port, USHORT *buf, ULONG count)
{
	outsw(port, buf, count);
}

wstdcall void WIN_FUNC(READ_PORT_BUFFER_USHORT,3)
	(ULONG_PTR port, USHORT *buf, ULONG count)
{
	insw(port, buf, count);
}

wstdcall void WIN_FUNC(WRITE_PORT_BUFFER_ULONG,3)
	(ULONG_PTR port, ULONG *buf, ULONG count)
{
	outsl(port, buf, count);
}

wstdcall void WIN_FUNC(READ_PORT_BUFFER_ULONG,3)
	(ULONG_PTR port, ULONG *buf, ULONG count)
{
	insl(port, buf, count);
}

wstdcall USHORT WIN_FUNC(READ_REGISTER_USHORT,1)
	(void *reg)
{
	return readw(reg);
}

wstdcall void WIN_FUNC(WRITE_REGISTER_ULONG,2)
	(void *reg, UINT val)
{
	writel(val, reg);
}

wstdcall void WIN_FUNC(WRITE_REGISTER_USHORT,2)
	(void *reg, USHORT val)
{
	writew(val, reg);
}

wstdcall void WIN_FUNC(WRITE_REGISTER_UCHAR,2)
	(void *reg, UCHAR val)
{
	writeb(val, reg);
}

wstdcall void WIN_FUNC(KeStallExecutionProcessor,1)
	(ULONG usecs)
{
	udelay(usecs);
	do_softirq();
}

wstdcall KIRQL WIN_FUNC(KeGetCurrentIrql,0)
	(void)
{
	return current_irql();
}

wfastcall KIRQL WIN_FUNC(KfRaiseIrql,1)
	(KIRQL newirql)
{
	KIRQL irql;

	TRACEENTER5("irql = %d", newirql);
	irql = raise_irql(newirql);
	TRACEEXIT5(return irql);
}

wfastcall void WIN_FUNC(KfLowerIrql,1)
	(KIRQL oldirql)
{
	TRACEENTER5("irql = %d", oldirql);
	lower_irql(oldirql);
	TRACEEXIT5(return);
}

wfastcall KIRQL WIN_FUNC(KfAcquireSpinLock,1)
	(NT_SPIN_LOCK *lock)
{
	TRACEENTER5("lock = %p", lock);
	return nt_spin_lock_irql(lock, DISPATCH_LEVEL);
}

wfastcall void WIN_FUNC(KfReleaseSpinLock,2)
	(NT_SPIN_LOCK *lock, KIRQL oldirql)
{
	TRACEENTER5("lock = %p, irql = %d", lock, oldirql);
	nt_spin_unlock_irql(lock, oldirql);
}

wfastcall void WIN_FUNC(KefAcquireSpinLockAtDpcLevel,1)
	(NT_SPIN_LOCK *lock)
{
	TRACEENTER5("lock = %p", lock);
#ifdef DEBUG_IRQL
	if (current_irql() != DISPATCH_LEVEL)
		ERROR("irql != DISPATCH_LEVEL");
#endif
	nt_spin_lock(lock);
	TRACEEXIT5(return);
}

wfastcall void WIN_FUNC(KefReleaseSpinLockFromDpcLevel,1)
	(NT_SPIN_LOCK *lock)
{
	TRACEENTER5("lock = %p", lock);
#ifdef DEBUG_IRQL
	if (current_irql() != DISPATCH_LEVEL)
		ERROR("irql != DISPATCH_LEVEL");
#endif
	nt_spin_unlock(lock);
	TRACEEXIT5(return);
}

#include "hal_exports.h"
