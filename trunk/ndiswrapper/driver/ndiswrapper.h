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

#ifndef _NDISWRAPPER_H_
#define _NDISWRAPPER_H_

#define DRIVER_VERSION "1.26rc1"
#define UTILS_VERSION "1.9"

#define DRIVER_NAME "ndiswrapper"
#define DRIVER_CONFIG_DIR "/etc/ndiswrapper"

#define SSID_MAX_WPA_IE_LEN 40
#define NDIS_ESSID_MAX_SIZE 32
#define NDIS_ENCODING_TOKEN_MAX 32
#define MAX_ENCR_KEYS 4
#define TX_RING_SIZE 16
#define NDIS_MAX_RATES 8
#define NDIS_MAX_RATES_EX 16
#define WLAN_EID_GENERIC 221
#define MAX_WPA_IE_LEN 64
#define MAX_STR_LEN 512

#define WRAP_PCI_BUS 5
#define WRAP_PCMCIA_BUS 8
/* some USB devices, e.g., DWL-G120 have BusType as 0 */
#define WRAP_INTERNAL_BUS 0
/* documentation at msdn says 15 is PNP bus, but inf files from all
 * vendors say 15 is USB; which is correct? */
#define WRAP_USB_BUS 15

/* NDIS device must be 0, for compatability with old versions of
 * ndiswrapper where device type for NDIS drivers is 0 */
#define WRAP_NDIS_DEVICE 0
#define WRAP_USB_DEVICE 1
#define WRAP_BLUETOOTH_DEVICE1 2
#define WRAP_BLUETOOTH_DEVICE2 3

#define WRAP_DEVICE_BUS(dev, bus) ((dev) << 8 | (bus))
#define WRAP_BUS(dev_bus) ((dev_bus) & 0x000FF)
#define WRAP_DEVICE(dev_bus) ((dev_bus) >> 8)

#define MAX_DRIVER_NAME_LEN 32
#define MAX_VERSION_STRING_LEN 64
#define MAX_SETTING_NAME_LEN 128
#define MAX_SETTING_VALUE_LEN 256

#define MAX_DRIVER_PE_IMAGES 4
#define MAX_DRIVER_BIN_FILES 5
#define MAX_DEVICE_SETTINGS 512

#define MAX_ALLOCATED_URBS 15

#define DEV_ANY_ID -1

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTRSEP "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACSTR "%02x%02x%02x%02x%02x%02x"
#define MACINTADR(a) (int*)&((a)[0]), (int*)&((a)[1]), (int*)&((a)[2]), \
		(int*)&((a)[3]), (int*)&((a)[4]), (int*)&((a)[5])

#ifdef __KERNEL__
/* DEBUG macros */

#define MSG(level, fmt, ...)				\
	printk(level "ndiswrapper (%s:%d): " fmt "\n",	\
	       __FUNCTION__, __LINE__ , ## __VA_ARGS__)

#define WARNING(fmt, ...) MSG(KERN_WARNING, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...) MSG(KERN_ERR, fmt , ## __VA_ARGS__)
#define INFO(fmt, ...) MSG(KERN_INFO, fmt , ## __VA_ARGS__)

#define INFOEXIT(stmt) do { INFO("Exit"); stmt; } while(0)

#define TODO() ERROR("not fully implemented (yet)")

#define DBGTRACE(fmt, ...) do { } while (0)
#define DBGTRACE1(fmt, ...) do { } while (0)
#define DBGTRACE2(fmt, ...) do { } while (0)
#define DBGTRACE3(fmt, ...) do { }  while (0)
#define DBGTRACE4(fmt, ...) do { } while (0)
#define DBGTRACE5(fmt, ...) do { } while (0)
#define DBGTRACE6(fmt, ...) do { } while (0)

/* for a block of code */
#define DBG_BLOCK(level) while (0)

extern int debug;

#if defined DEBUG
#undef DBGTRACE
#define DBGTRACE(level, fmt, ...)				       \
do {								       \
	if (debug >= level)					       \
		printk(KERN_INFO "%s (%s:%d): " fmt "\n", DRIVER_NAME, \
		       __FUNCTION__, __LINE__ , ## __VA_ARGS__);       \
} while (0)
#undef DBG_BLOCK
#define DBG_BLOCK(level) if (debug >= level)
#endif

#if defined(DEBUG) && DEBUG >= 1
#undef DBGTRACE1
#define DBGTRACE1(fmt, ...) DBGTRACE(1, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 2
#undef DBGTRACE2
#define DBGTRACE2(fmt, ...) DBGTRACE(2, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 3
#undef DBGTRACE3
#define DBGTRACE3(fmt, ...) DBGTRACE(3, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 4
#undef DBGTRACE4
#define DBGTRACE4(fmt, ...) DBGTRACE(4, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 5
#undef DBGTRACE5
#define DBGTRACE5(fmt, ...) DBGTRACE(5, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 6
#undef DBGTRACE6
#define DBGTRACE6(fmt, ...) DBGTRACE(6, fmt , ## __VA_ARGS__)
#endif

#define TRACEENTER1(fmt, ...) DBGTRACE1("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER2(fmt, ...) DBGTRACE2("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER3(fmt, ...) DBGTRACE3("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER4(fmt, ...) DBGTRACE4("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER5(fmt, ...) DBGTRACE5("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER6(fmt, ...) DBGTRACE6("Enter " fmt , ## __VA_ARGS__)

#define TRACEEXIT1(stmt) do { DBGTRACE1("Exit"); stmt; } while(0)
#define TRACEEXIT2(stmt) do { DBGTRACE2("Exit"); stmt; } while(0)
#define TRACEEXIT3(stmt) do { DBGTRACE3("Exit"); stmt; } while(0)
#define TRACEEXIT4(stmt) do { DBGTRACE4("Exit"); stmt; } while(0)
#define TRACEEXIT5(stmt) do { DBGTRACE5("Exit"); stmt; } while(0)
#define TRACEEXIT6(stmt) do { DBGTRACE6("Exit"); stmt; } while(0)

#if defined(USB_DEBUG)
#define USBTRACE DBGTRACE1
#define USBENTER TRACEENTER1
#define USBEXIT TRACEEXIT1
#else
#define USBTRACE(fmt, ...)
#define USBENTER(fmt, ...)
#define USBEXIT(stmt) stmt
#endif

#if defined(EVENT_DEBUG)
#define EVENTTRACE DBGTRACE1
#define EVENTENTER TRACEENTER1
#define EVENTEXIT TRACEEXIT1
#else
#define EVENTTRACE(fmt, ...)
#define EVENTENTER(fmt, ...)
#define EVENTEXIT(stmt) stmt
#endif

#if defined(IO_DEBUG)
#define IOTRACE DBGTRACE1
#define IOENTER TRACEENTER1
#define IOEXIT TRACEEXIT1
#else
#define IOTRACE(fmt, ...)
#define IOENTER(fmt, ...)
#define IOEXIT(stmt) stmt
#endif

#if defined(WORK_DEBUG)
#define WORKTRACE DBGTRACE1
#define WORKENTER TRACEENTER1
#define WORKEXIT TRACEEXIT1
#else
#define WORKTRACE(fmt, ...)
#define WORKENTER(fmt, ...)
#define WORKEXIT(stmt) stmt
#endif

#if defined DEBUG
#define assert(expr)							\
do {									\
	if (!(expr))							\
		ERROR("assertion '%s' failed", #expr);			\
} while (0)
#else
#define assert(expr) do { } while (0)
#endif

#if defined(IO_DEBUG)
#define DUMP_IRP(irp)							\
do {									\
	struct io_stack_location *irp_sl;				\
	irp_sl = IoGetCurrentIrpStackLocation(irp);			\
	IOTRACE("irp: %p, stack size: %d, cl: %d, sl: %p, dev_obj: %p, " \
		"mj_fn: %d, minor_fn: %d, nt_urb: %p, event: %p",	\
		irp, irp->stack_count, (irp)->current_location,		\
		irp_sl, irp_sl->dev_obj, irp_sl->major_fn,		\
		irp_sl->minor_fn, URB_FROM_IRP(irp),			\
		(irp)->user_event);					\
} while (0)
#else
#define DUMP_IRP(irp) do { } while (0)
#endif
#endif // __KERNEL__

#endif // NDISWRAPPER_H
