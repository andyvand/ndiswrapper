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

wstdcall void WRAP_EXPORT(WRITE_PORT_ULONG)
	(ULONG_PTR port, ULONG value)
{
	outl(value, port);
}

wstdcall ULONG WRAP_EXPORT(READ_PORT_ULONG)
	(ULONG_PTR port)
{
	return inl(port);
}

wstdcall void WRAP_EXPORT(WRITE_PORT_USHORT)
	(ULONG_PTR port, USHORT value)
{
	outw(value, port);
}

wstdcall USHORT WRAP_EXPORT(READ_PORT_USHORT)
	(ULONG_PTR port)
{
	return inw(port);
}

wstdcall void WRAP_EXPORT(WRITE_PORT_UCHAR)
	(ULONG_PTR port, UCHAR value)
{
	outb(value, port);
}

wstdcall UCHAR WRAP_EXPORT(READ_PORT_UCHAR)
	(ULONG_PTR port)
{
	return inb(port);
}

wstdcall void WRAP_EXPORT(WRITE_PORT_BUFFER_USHORT)
	(ULONG_PTR port, USHORT *buf, ULONG count)
{
	outsw(port, buf, count);
}

wstdcall void WRAP_EXPORT(READ_PORT_BUFFER_USHORT)
	(ULONG_PTR port, USHORT *buf, ULONG count)
{
	insw(port, buf, count);
}

wstdcall void WRAP_EXPORT(WRITE_PORT_BUFFER_ULONG)
	(ULONG_PTR port, ULONG *buf, ULONG count)
{
	outsl(port, buf, count);
}

wstdcall void WRAP_EXPORT(READ_PORT_BUFFER_ULONG)
	(ULONG_PTR port, ULONG *buf, ULONG count)
{
	insl(port, buf, count);
}

wstdcall USHORT WRAP_EXPORT(READ_REGISTER_USHORT)
	(void *reg)
{
	return readw(reg);
}

wstdcall void WRAP_EXPORT(WRITE_REGISTER_ULONG)
	(void *reg, UINT val)
{
	writel(val, reg);
}

wstdcall void WRAP_EXPORT(WRITE_REGISTER_USHORT)
	(void *reg, USHORT val)
{
	writew(val, reg);
}

wstdcall void WRAP_EXPORT(WRITE_REGISTER_UCHAR)
	(void *reg, UCHAR val)
{
	writeb(val, reg);
}

wstdcall void WRAP_EXPORT(KeStallExecutionProcessor)
	(ULONG usecs)
{
	udelay(usecs);
}

wstdcall KIRQL WRAP_EXPORT(KeGetCurrentIrql)
	(void)
{
	return current_irql();
}

wfastcall KIRQL WRAP_EXPORT(KfRaiseIrql)
	(KIRQL newirql)
{
	KIRQL irql;

	TRACEENTER5("irql = %d", newirql);
	irql = raise_irql(newirql);
	TRACEEXIT5(return irql);
}

wfastcall void WRAP_EXPORT(KfLowerIrql)
	(KIRQL oldirql)
{
	TRACEENTER5("irql = %d", oldirql);
	lower_irql(oldirql);
	TRACEEXIT5(return);
}

wfastcall KIRQL WRAP_EXPORT(KfAcquireSpinLock)
	(NT_SPIN_LOCK *lock)
{
	TRACEENTER5("lock = %p", lock);
	return nt_spin_lock_irql(lock, DISPATCH_LEVEL);
}

wfastcall void WRAP_EXPORT(KfReleaseSpinLock)
	(NT_SPIN_LOCK *lock, KIRQL oldirql)
{
	TRACEENTER5("lock = %p, irql = %d", lock, oldirql);
	nt_spin_unlock_irql(lock, oldirql);
}

wfastcall void WRAP_EXPORT(KefAcquireSpinLockAtDpcLevel)
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

wfastcall void WRAP_EXPORT(KefReleaseSpinLockFromDpcLevel)
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
