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
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>

#include "ndis.h"
#include "iw_ndis.h"
#include "wrapper.h"

extern struct list_head ndis_drivers;
extern KSPIN_LOCK ntoskrnl_lock;

static struct list_head handle_ctx_list;

static struct work_struct ndis_work;
static struct list_head ndis_work_list;
static KSPIN_LOCK ndis_work_list_lock;

static void ndis_worker(void *data);
static void free_handle_ctx(struct ndis_handle *handle);

/* Some drivers allocate all NDIS_PACKETs they need at the beginning
 * and others allocate them quite often - every time a packet is
 * sent/received. We use cache pool for this to avoid memory
 * fragmentation, just like MDLs */
static kmem_cache_t *packet_cache;

/* ndis_init is called once when module is loaded */
int ndis_init(void)
{
	/* only one worker is used for all drivers */
	INIT_WORK(&ndis_work, &ndis_worker, NULL);
	INIT_LIST_HEAD(&ndis_work_list);
	INIT_LIST_HEAD(&handle_ctx_list);
	kspin_lock_init(&ndis_work_list_lock);
	packet_cache = kmem_cache_create("ndis_packet",
					 sizeof(struct ndis_packet), 0, 0,
					 NULL, NULL);
	if (!packet_cache) {
		ERROR("couldn't allocate packet cache");
		return -ENOMEM;
	}
	return 0;
}

/* ndis_exit is called once when module is removed */
void ndis_exit(void)
{
	if (kmem_cache_destroy(packet_cache))
		ERROR("Windows driver didn't free packet(s)");
	return;
}

/* ndis_exit_handle is called for each handle */
void ndis_exit_handle(struct ndis_handle *handle)
{
	/* TI driver doesn't call NdisMDeregisterInterrupt during halt! */
	if (handle->ndis_irq)
		NdisMDeregisterInterrupt(handle->ndis_irq);
	free_handle_ctx(handle);
	if (handle->pci_resources)
		vfree(handle->pci_resources);
}

/* remove all 'handle X ctx' pairs for the given handle */
static void free_handle_ctx(struct ndis_handle *handle)
{
	struct list_head *cur, *tmp;
	KIRQL irql;

	irql = kspin_lock(&ntoskrnl_lock, PASSIVE_LEVEL);
	list_for_each_safe(cur, tmp, &handle_ctx_list) {
		struct handle_ctx_entry *handle_ctx =
			list_entry(cur, struct handle_ctx_entry, list);
		if (handle_ctx->handle == handle) {
			list_del(&handle_ctx->list);
			kfree(handle_ctx);
		}
	}
	kspin_unlock(&ntoskrnl_lock, irql);
	return;
}

/* Called from the driver entry. */
STDCALL void WRAP_EXPORT(NdisInitializeWrapper)
	(struct ndis_handle **ndis_handle, void *SystemSpecific1,
	 void *SystemSpecific2, void *SystemSpecific3)
{
	TRACEENTER1("handle=%p, SS1=%p, SS2=%p", ndis_handle,
		    SystemSpecific1, SystemSpecific2);
	*ndis_handle = (struct ndis_handle *)SystemSpecific1;
	TRACEEXIT1(return);
}

STDCALL void WRAP_EXPORT(NdisTerminateWrapper)
	(struct ndis_handle *handle, void *SystemSpecific1)
{
	TRACEEXIT1(return);
}

/* Register a miniport with NDIS. Called from driver entry */
STDCALL NDIS_STATUS WRAP_EXPORT(NdisMRegisterMiniport)
	(struct ndis_driver *ndis_driver,
	 struct miniport_char *miniport_char, UINT char_len)
{
	int i, min_length;
	int *func;
	char *miniport_funcs[] = {
		"query",
		"reconfig",
		"reset",
		"send",
		"setinfo",
		"tx_data",
		"return_packet",
		"send_packets",
		"alloc_complete",
		"co_create_vc",
		"co_delete_vc",
		"co_activate_vc",
		"co_deactivate_vc",
		"co_send_packets",
		"co_request",
		"cancel_send_packets",
		"pnp_event_notify",
		"adapter_shutdown",
	};

	min_length = ((char *) &miniport_char->co_create_vc) -
		((char *) miniport_char);

	TRACEENTER1("driver: %p %p %d", ndis_driver, miniport_char, char_len);

	if (miniport_char->majorVersion < 4) {
		ERROR("Driver %s using ndis version %d which is too old.",
		      ndis_driver->name, miniport_char->majorVersion);
		TRACEEXIT1(return NDIS_STATUS_BAD_VERSION);
	}

	if (char_len < min_length) {
		ERROR("Characteristics length %d is too small for driver %s",
		      char_len, ndis_driver->name);
		TRACEEXIT1(return NDIS_STATUS_BAD_CHARACTERISTICS);
	}

	DBGTRACE1("Version %d.%d", miniport_char->majorVersion,
		  miniport_char->minorVersion);
	DBGTRACE1("Len: %08x:%u", char_len, (u32)sizeof(struct miniport_char));
	memcpy(&ndis_driver->miniport_char, miniport_char,
	       sizeof(struct miniport_char));

	i = 0;
	func = (int *)&ndis_driver->miniport_char.query;
	while (i < sizeof(miniport_funcs) / sizeof(miniport_funcs[0])) {
		DBGTRACE2("miniport function '%s' is at %lx",
			  miniport_funcs[i], (unsigned long)func[i]);
		i++;
	}

	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisAllocateMemory)
	(void **dest, UINT length, UINT flags,
	 NDIS_PHY_ADDRESS highest_address)
{
	TRACEENTER3("length = %u, flags = %08X", length, flags);
	if (length <= KMALLOC_THRESHOLD) {
		if (current_irql() < DISPATCH_LEVEL)
			*dest = kmalloc(length, GFP_KERNEL);
		else
			*dest = kmalloc(length, GFP_ATOMIC);
	} else if (flags & NDIS_MEMORY_CONTIGUOUS) {
		WARNING("Allocating %u bytes of physically "
		       "contiguous memory may fail", length);
		*dest = kmalloc(length, GFP_KERNEL);
	} else
		*dest = vmalloc(length);

	if (*dest)
		TRACEEXIT3(return NDIS_STATUS_SUCCESS);
	DBGTRACE3("Allocatemem failed size=%d", length);
	TRACEEXIT3(return NDIS_STATUS_FAILURE);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisAllocateMemoryWithTag)
	(void **dest, UINT length, ULONG tag)
{
	TRACEEXIT3(return NdisAllocateMemory(dest, length, 0, 0));
}

STDCALL void WRAP_EXPORT(NdisFreeMemory)
	(void *addr, UINT length, UINT flags)
{
	struct ndis_work_entry *ndis_work_entry;
	struct ndis_free_mem_work_item *free_mem;
	KIRQL irql;

	TRACEENTER3("addr = %p, flags = %08X", addr, flags);

	if (!addr)
		TRACEEXIT3(return);

	if (length <= KMALLOC_THRESHOLD)
		kfree(addr);
	else if (flags & NDIS_MEMORY_CONTIGUOUS)
		kfree(addr);
	else {
		if (!in_interrupt()) {
			vfree(addr);
			TRACEEXIT3(return);
		}
		/* Centrino 2200 driver calls this function when in
		 * ad-hoc mode in interrupt context when length >
		 * KMALLOC_THRESHOLD, which implies that vfree is
		 * called in interrupt context, which is not
		 * correct. So we use worker for it */
		ndis_work_entry = kmalloc(sizeof(*ndis_work_entry),
					  GFP_ATOMIC);
		BUG_ON(!ndis_work_entry);

		ndis_work_entry->type = NDIS_FREE_MEM_WORK_ITEM;
		free_mem = &ndis_work_entry->entry.free_mem_work_item;

		free_mem->addr = addr;
		free_mem->length = length;
		free_mem->flags = flags;

		irql = kspin_lock(&ndis_work_list_lock, DISPATCH_LEVEL);
		list_add_tail(&ndis_work_entry->list, &ndis_work_list);
		kspin_unlock(&ndis_work_list_lock, irql);

		schedule_work(&ndis_work);
	}

	TRACEEXIT3(return);
}

/*
 * This function should not be STDCALL because it's a variable args function.
 */
NOREGPARM void WRAP_EXPORT(NdisWriteErrorLogEntry)
	(struct ndis_handle *handle, unsigned int error, ULONG count,
	 unsigned int p1)
{
	ERROR("log: %08X, count: %d (%08x), return address: %p, entry: %p"
	      " offset: %lu", error, count, p1, __builtin_return_address(0),
	      handle->driver->entry,
	      (unsigned long)addr_offset(handle->driver));
	return;
}

STDCALL void WRAP_EXPORT(NdisOpenConfiguration)
	(NDIS_STATUS *status, struct ndis_handle **confhandle,
	 struct ndis_handle *handle)
{
	TRACEENTER2("confHandle: %p, handle->dev_name: %s",
			confhandle, handle->net_dev->name);
	*confhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisOpenProtocolConfiguration)
	(NDIS_STATUS *status, struct ndis_handle **confhandle,
	 struct unicode_string *section)
{
	TRACEENTER2("confHandle: %p", confhandle);
	*confhandle = (struct ndis_handle *)section;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisOpenConfigurationKeyByName)
	(NDIS_STATUS *status, struct ndis_handle *handle,
	 struct unicode_string *key, struct ndis_handle **subkeyhandle)
{
	TRACEENTER2("%s", "");
	*subkeyhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisOpenConfigurationKeyByIndex)
	(NDIS_STATUS *status, struct ndis_handle *handle, ULONG index,
	 struct unicode_string *key, struct ndis_handle **subkeyhandle)
{
	TRACEENTER2("%s", "");
	*subkeyhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisCloseConfiguration)
	(struct ndis_handle *handle)
{
	TRACEENTER2("handle: %p", handle);
	return;
}

STDCALL void WRAP_EXPORT(NdisOpenFile)
	(NDIS_STATUS *status, struct ndis_bin_file **filehandle,
	 UINT *filelength, struct unicode_string *filename,
	 NDIS_PHY_ADDRESS highest_address)
{
	struct ansi_string ansi;
	struct list_head *cur, *tmp;
	struct ndis_bin_file *file;

	TRACEENTER2("status = %p, filelength = %p, *filelength = %d, "
		    "high = %llx, filehandle = %p, *filehandle = %p",
		    status, filelength, *filelength,
		    highest_address, filehandle, *filehandle);

	ansi.buf = kmalloc(MAX_STR_LEN, GFP_KERNEL);
	if (!ansi.buf) {
		*status = NDIS_STATUS_RESOURCES;
		return;
	}
	ansi.buf[MAX_STR_LEN-1] = 0;
	ansi.buflen = MAX_STR_LEN;

	if (RtlUnicodeStringToAnsiString(&ansi, filename, 0)) {
		*status = NDIS_STATUS_RESOURCES;
		RtlFreeAnsiString(&ansi);
		TRACEEXIT2(return);
	}
	DBGTRACE2("Filename: %s", ansi.buf);

	/* Loop through all drivers and all files to find the requested file */
	list_for_each_safe(cur, tmp, &ndis_drivers) {
		struct ndis_driver *driver;
		int i;

		driver = list_entry(cur, struct ndis_driver, list);
		for (i = 0; i < driver->num_bin_files; i++) {
			int n;
			file = &driver->bin_files[i];
			DBGTRACE2("considering %s", file->name);
			n = min(strlen(file->name), strlen(ansi.buf));
			if (strnicmp(file->name, ansi.buf, n) == 0) {
				*filehandle = file;
				*filelength = file->size;
				*status = NDIS_STATUS_SUCCESS;
				RtlFreeAnsiString(&ansi);
				TRACEEXIT2(return);
			}
		}
	}
	*status = NDIS_STATUS_FILE_NOT_FOUND;
	RtlFreeAnsiString(&ansi);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisMapFile)
	(NDIS_STATUS *status, void **mappedbuffer,
	 struct ndis_bin_file *filehandle)
{
	TRACEENTER2("handle: %p", filehandle);

	if (!filehandle) {
		*status = NDIS_STATUS_ALREADY_MAPPED;
		TRACEEXIT2(return);
	}

	*status = NDIS_STATUS_SUCCESS;
	*mappedbuffer = filehandle->data;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisUnmapFile)
	(struct ndis_bin_file *filehandle)
{
	TRACEENTER2("handle: %p", filehandle);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisCloseFile)
	(struct ndis_bin_file *filehandle)
{
	TRACEENTER2("handle: %p", filehandle);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisGetSystemUpTime)
	(ULONG *systemuptime)
{
	TRACEENTER4("%s", "");
	*systemuptime = 10 * jiffies / HZ;
	TRACEEXIT4(return);
}

/* called as macro */
STDCALL ULONG WRAP_EXPORT(NDIS_BUFFER_TO_SPAN_PAGES)
	(ndis_buffer *buffer)
{
	ULONG_PTR start;
	ULONG n;

	TRACEENTER4("%s", "");

	if (buffer == NULL)
		return 0;

	if (MmGetMdlByteCount(buffer) == 0)
		return 1;

	start = (ULONG_PTR)(MmGetMdlVirtualAddress(buffer));
	n = SPAN_PAGES(start, MmGetMdlByteCount(buffer));
	DBGTRACE4("pages = %u", n);
	TRACEEXIT3(return n);
}

STDCALL void WRAP_EXPORT(NdisGetBufferPhysicalArraySize)
	(ndis_buffer *buffer, UINT *arraysize)
{
	TRACEENTER3("Buffer: %p", buffer);
	*arraysize = NDIS_BUFFER_TO_SPAN_PAGES(buffer);
	TRACEEXIT3(return);
}

static int ndis_encode_setting(struct device_setting *setting,
			       int device_setting_type)
{
	struct ansi_string ansi;
	struct ndis_config_param *param;

	TRACEENTER2("type = %d", device_setting_type);
	if (setting->config_param.type == device_setting_type)
		return NDIS_STATUS_SUCCESS;

	switch(device_setting_type) {
	case NDIS_CONFIG_PARAM_INT:
		setting->config_param.data.intval =
			simple_strtol(setting->value, NULL, 0);
		DBGTRACE1("value = %u",
			  (ULONG)setting->config_param.data.intval);
		break;
	case NDIS_CONFIG_PARAM_HEXINT:
		setting->config_param.data.intval =
			simple_strtol(setting->value, NULL, 16);
		DBGTRACE2("value = %u",
			  (ULONG)setting->config_param.data.intval);
		break;
	case NDIS_CONFIG_PARAM_STRING:
		ansi.buflen = ansi.len = strlen(setting->value);
		ansi.buf = setting->value;
		DBGTRACE2("setting value = %s", ansi.buf);
		param = &setting->config_param;
		if (param->data.ustring.buf)
			RtlFreeUnicodeString(&param->data.ustring);
		if (RtlAnsiStringToUnicodeString(&param->data.ustring,
						 &ansi, 1))
			TRACEEXIT1(return NDIS_STATUS_FAILURE);
		break;
	default:
		return NDIS_STATUS_FAILURE;
	}
	setting->config_param.type = device_setting_type;
	return NDIS_STATUS_SUCCESS;
}

static int ndis_decode_setting(struct device_setting *setting,
			       struct ndis_config_param *val)
{
	struct ansi_string ansi;

	if (setting->config_param.type == NDIS_CONFIG_PARAM_STRING &&
	    setting->config_param.data.ustring.buf)
		RtlFreeUnicodeString(&setting->config_param.data.ustring);

	switch(val->type) {
	case NDIS_CONFIG_PARAM_INT:
		snprintf(setting->value, sizeof(u32), "%u", val->data.intval);
		setting->value[sizeof(ULONG)] = 0;
		break;
	case NDIS_CONFIG_PARAM_HEXINT:
		snprintf(setting->value, sizeof(u32), "%x", val->data.intval);
		setting->value[sizeof(ULONG)] = 0;
		break;
	case NDIS_CONFIG_PARAM_STRING:
		ansi.buf = setting->value;
		ansi.buflen = MAX_STR_LEN;
		if (RtlUnicodeStringToAnsiString(&ansi, &val->data.ustring, 0)
		    || ansi.len >= MAX_STR_LEN) {
			TRACEEXIT1(return NDIS_STATUS_FAILURE);
		}
		memcpy(setting->value, ansi.buf, ansi.len);
		DBGTRACE2("value = %s", setting->value);
		setting->value[ansi.len] = 0;
		break;
	default:
		DBGTRACE2("unknown setting type: %d", val->type);
		return NDIS_STATUS_FAILURE;
	}
	setting->config_param.type = NDIS_CONFIG_PARAM_NONE;
	return NDIS_STATUS_SUCCESS;
}

STDCALL void WRAP_EXPORT(NdisReadConfiguration)
	(NDIS_STATUS *status, struct ndis_config_param **dest,
	 struct ndis_handle *handle, struct unicode_string *key,
	 enum ndis_config_param_type type)
{
	struct device_setting *setting;
	struct ansi_string ansi;
	char *keyname;
	int ret;

	TRACEENTER2("handle: %p", handle);
	ret = RtlUnicodeStringToAnsiString(&ansi, key, 1);
	DBGTRACE3("rtl func returns: %d", ret);
	if (ret) {
		*dest = NULL;
		*status = NDIS_STATUS_FAILURE;
		RtlFreeAnsiString(&ansi);
		TRACEEXIT2(return);
	}
	DBGTRACE3("handle: %p, string: %s", handle, ansi.buf);
	keyname = ansi.buf;
	DBGTRACE3("handle: %p, string: %s", handle, keyname);

	list_for_each_entry(setting, &handle->device->settings, list) {
		if (stricmp(keyname, setting->name) == 0) {
			DBGTRACE2("setting found %s=%s",
				 keyname, setting->value);

			*status = ndis_encode_setting(setting, type);
			if (*status == NDIS_STATUS_SUCCESS)
				*dest = &setting->config_param;
			else
				*dest = NULL;
			RtlFreeAnsiString(&ansi);
			DBGTRACE2("status = %d", *status);
			TRACEEXIT2(return);
		}
	}

	DBGTRACE2("setting %s not found (type:%d)", keyname, type);

	*dest = NULL;
	*status = NDIS_STATUS_FAILURE;
	RtlFreeAnsiString(&ansi);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisWriteConfiguration)
	(NDIS_STATUS *status, struct ndis_handle *handle,
	 struct unicode_string *key, struct ndis_config_param *param)
{
	struct ansi_string ansi;
	char *keyname;
	struct device_setting *setting;

	TRACEENTER2("%s", "");
	if (RtlUnicodeStringToAnsiString(&ansi, key, 1)) {
		*status = NDIS_STATUS_FAILURE;
		TRACEEXIT2(return);
	}
	keyname = ansi.buf;
	DBGTRACE2("key = %s", keyname);

	list_for_each_entry(setting, &handle->device->settings, list) {
		if (strcmp(keyname, setting->name) == 0) {
			*status = ndis_decode_setting(setting, param);
			DBGTRACE2("setting changed %s=%s",
				 keyname, setting->value);
			RtlFreeAnsiString(&ansi);
			TRACEEXIT2(return);
		}
	}

	if ((setting = kmalloc(sizeof(*setting), GFP_KERNEL)) == NULL) {
		*status = NDIS_STATUS_RESOURCES;
		RtlFreeAnsiString(&ansi);
		TRACEEXIT2(return);
	}
	memset(setting, 0, sizeof(*setting));
	memcpy(setting->name, keyname, ansi.len);
	setting->name[ansi.len] = 0;
	*status = ndis_decode_setting(setting, param);
	if (*status == NDIS_STATUS_SUCCESS)
		list_add(&setting->list, &handle->device->settings);
	else {
		kfree(setting->name);
		kfree(setting);
	}
	RtlFreeAnsiString(&ansi);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisInitializeString)
	(struct unicode_string *dest, UCHAR *src)
{
	struct ansi_string ansi;

	TRACEENTER2("%s", "");
	ansi.len = ansi.buflen = strlen(src);
	ansi.buf = src;
	if (RtlAnsiStringToUnicodeString(dest, &ansi, 1))
		DBGTRACE2("%s", "failed");
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisInitAnsiString)
	(struct ansi_string *dst, CHAR *src)
{
	RtlInitAnsiString(dst, src);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisInitString)
	(struct ansi_string *dst, CHAR *src)
{
	RtlInitString(dst, src);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisInitUnicodeString)
	(struct unicode_string *dest, const wchar_t *src)
{
	int i;

	TRACEENTER2("%s", "");
	if (dest == NULL)
		TRACEEXIT2(return);
	if (src == NULL) {
		dest->len = dest->buflen = 0;
		dest->buf = NULL;
		TRACEEXIT2(return);
	}

	for (i = 0 ; src[i] ; i++)
		;
	dest->len = dest->buflen = i * 2;
	dest->buf = (wchar_t *)src;
	TRACEEXIT2(return);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisAnsiStringToUnicodeString)
	(struct unicode_string *dst, struct ansi_string *src)
{
	int dup;

	TRACEENTER2("%s", "");
	if (dst == NULL || src == NULL)
		TRACEEXIT2(return NDIS_STATUS_FAILURE);
	if (dst->buf == NULL)
		dup = 1;
	else
		dup = 0;
	TRACEEXIT2(return RtlAnsiStringToUnicodeString(dst, src, 0));
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisUnicodeStringToAnsiString)
	(struct ansi_string *dst, struct unicode_string *src)
{
	int dup;

	TRACEENTER2("%s", "");
	if (dst == NULL || src == NULL)
		TRACEEXIT2(return NDIS_STATUS_FAILURE);
	if (dst->buf == NULL)
		dup = 1;
	else
		dup = 0;
	TRACEEXIT2(return RtlUnicodeStringToAnsiString(dst, src, dup));
}

/*
 * Called by driver from the init callback.
 * The adapter_ctx should be supplied to most other callbacks so we save
 * it in out handle. Some functions are called only with adapter_ctx, but
 * we also need handle in them, so we store handle X adapter_ctx map in
 * a global list.
 */
STDCALL void WRAP_EXPORT(NdisMSetAttributesEx)
	(struct ndis_handle *handle, void *adapter_ctx,
	 UINT hangcheck_interval, UINT attributes, ULONG adaptortype)
{
	struct handle_ctx_entry *handle_ctx;
	KIRQL irql;

	TRACEENTER2("%p, %p %d %08x, %d", handle, adapter_ctx,
		    hangcheck_interval, attributes, adaptortype);
	/* FIXME: is it possible to have duplicate ctx's? */
	handle_ctx = kmalloc(sizeof(*handle_ctx), GFP_KERNEL);
	if (handle_ctx) {
		handle_ctx->handle = handle;
		handle_ctx->ctx = adapter_ctx;
		/* ntoskrnl_lock is not meant for use here, but since this
		 * function is called during initialization only,
		 * no harm abusing it */
		irql = kspin_lock(&ntoskrnl_lock, PASSIVE_LEVEL);
		list_add(&handle_ctx->list, &handle_ctx_list);
		kspin_unlock(&ntoskrnl_lock, irql);
	}

	if (attributes & NDIS_ATTRIBUTE_BUS_MASTER)
		pci_set_master(handle->dev.pci);

	if (!(attributes & NDIS_ATTRIBUTE_DESERIALIZE)) {
		DBGTRACE2("serialized driver");
		set_bit(ATTR_SERIALIZED, &handle->attributes);
	}

	if (attributes & NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK)
		set_bit(ATTR_SURPRISE_REMOVE, &handle->attributes);

	if (!(attributes & NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND))
		set_bit(ATTR_HALT_ON_SUSPEND, &handle->attributes);

	if (handle->hangcheck_interval >= 0) {
		/* less than 3 seconds seem to be problematic */
		if (hangcheck_interval > 2)
			handle->hangcheck_interval = 2*hangcheck_interval * HZ;
		else
			handle->hangcheck_interval = 3 * HZ;
	}

	handle->adapter_ctx = adapter_ctx;
	TRACEEXIT2(return);
}

static struct ndis_handle *ctx_to_handle(void *ctx)
{
	struct handle_ctx_entry *handle_ctx;
	KIRQL irql;

	irql = kspin_lock(&ntoskrnl_lock, PASSIVE_LEVEL);
	list_for_each_entry(handle_ctx, &handle_ctx_list, list) {
		if (handle_ctx->ctx == ctx) {
			kspin_unlock(&ntoskrnl_lock, irql);
			return handle_ctx->handle;
		}
	}
	kspin_unlock(&ntoskrnl_lock, irql);

	return NULL;
}

STDCALL ULONG WRAP_EXPORT(NdisReadPciSlotInformation)
	(struct ndis_handle *handle, ULONG slot,
	 ULONG offset, char *buf, ULONG len)
{
	int i;
	for (i = 0; i < len; i++)
		pci_read_config_byte(handle->dev.pci, offset+i, &buf[i]);

	return len;
}

STDCALL ULONG WRAP_EXPORT(NdisWritePciSlotInformation)
	(struct ndis_handle *handle, ULONG slot,
	 ULONG offset, char *buf, ULONG len)
{
	int i;
	for (i = 0; i < len; i++)
		pci_write_config_byte(handle->dev.pci, offset+i, buf[i]);

	return len;
}

STDCALL void WRAP_EXPORT(NdisMQueryAdapterResources)
	(NDIS_STATUS *status, struct ndis_handle *handle,
	 struct ndis_resource_list *resource_list, UINT *size)
{
	int i;
	int len = 0;
	/* FIXME: do USB drivers call this? */
	struct pci_dev *pci_dev = handle->dev.pci;
	struct ndis_resource_entry *entry;
	TRACEENTER2("handle: %p. buf: %p, len: %d. IRQ:%d", handle,
		    resource_list, *size, pci_dev->irq);

	resource_list->version = 1;

	/* Put all memory and port resources */
	i = 0;
	while (pci_resource_start(pci_dev, i)) {
		entry = &resource_list->list[len++];
		if (pci_resource_flags(pci_dev, i) & IORESOURCE_MEM) {
			entry->type = 3;
			entry->flags = 0;

		} else if (pci_resource_flags(pci_dev, i) & IORESOURCE_IO) {
			entry->type = 1;
			entry->flags = 1;
		}

		entry->share = 0;
		entry->u.generic.start =
			(ULONG_PTR)pci_resource_start(pci_dev, i);
		entry->u.generic.length = pci_resource_len(pci_dev, i);

		i++;
	}

	/* Put IRQ resource */
	entry = &resource_list->list[len++];
	entry->type = 2;
	entry->share = 0;
	entry->flags = 0;
	entry->u.interrupt.level = pci_dev->irq;
	entry->u.interrupt.vector = pci_dev->irq;
	entry->u.interrupt.affinity = -1;

	resource_list->length = len;
	*size = (char *) (&resource_list->list[len]) - (char *)resource_list;
	*status = NDIS_STATUS_SUCCESS;


	DBGTRACE2("resource list v%d.%d len %d, size=%d",
		  resource_list->version, resource_list->revision,
		  resource_list->length, *size);

	for (i = 0; i < len; i++) {
		DBGTRACE2("resource: %d: %Lx %d, %d",
			  resource_list->list[i].type,
			  resource_list->list[i].u.generic.start,
			  resource_list->list[i].u.generic.length,
			  resource_list->list[i].flags);
	}
	TRACEEXIT2(return);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMPciAssignResources)
	(struct ndis_handle *handle, ULONG slot_number,
	 struct ndis_resource_list **resources)
{
	UINT size;
	NDIS_STATUS status;

	size = sizeof(struct ndis_resource_list) +
		sizeof(struct ndis_resource_entry) * 20;
	handle->pci_resources = vmalloc(size);
	if (!handle->resources) {
		ERROR("couldn't allocate memory");
		TRACEEXIT2(return NDIS_STATUS_SUCCESS);
	}
	NdisMQueryAdapterResources(&status, handle, handle->pci_resources,
				   &size);
	*resources = handle->pci_resources;
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMMapIoSpace)
	(void **virt, struct ndis_handle *handle,
	 NDIS_PHY_ADDRESS phy_addr, UINT len)
{
	TRACEENTER2("%016llx, %d", phy_addr, len);
	*virt = ioremap(phy_addr, len);
	if (*virt == NULL) {
		ERROR("%s", "ioremap failed");
		TRACEEXIT2(return NDIS_STATUS_FAILURE);
	}

	handle->mem_start = phy_addr;
	handle->mem_end = phy_addr + len -1;

	DBGTRACE2("ioremap successful %p", *virt);
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(NdisMUnmapIoSpace)
	(struct ndis_handle *handle, void *virtaddr, UINT len)
{
	TRACEENTER2("%p, %d", virtaddr, len);
	iounmap(virtaddr);
}

STDCALL void WRAP_EXPORT(NdisAllocateSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER4("lock %p", lock);

	KeInitializeSpinLock(&lock->klock);

	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisFreeSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER4("lock %p", lock);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisAcquireSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER5("lock %p", lock);
	lock->irql = kspin_lock(&lock->klock, DISPATCH_LEVEL);
	TRACEEXIT5(return);
}

STDCALL void WRAP_EXPORT(NdisReleaseSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER5("lock %p", lock);
	kspin_unlock(&lock->klock, lock->irql);
	TRACEEXIT5(return);
}

STDCALL void WRAP_EXPORT(NdisDprAcquireSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER5("lock %p", lock);
	/* this function should not change IRQL, as it is called from
	 * DISPATCH_LEVEL, so we use PASSIVE_LEVEL */
	lock->irql = kspin_lock(&lock->klock, PASSIVE_LEVEL);
	TRACEEXIT5(return);
}

STDCALL void WRAP_EXPORT(NdisDprReleaseSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER5("lock %p", lock);
	kspin_unlock(&lock->klock, lock->irql);
	TRACEEXIT5(return);
}

STDCALL void WRAP_EXPORT(NdisInitializeReadWriteLock)
	(struct ndis_rw_lock *rw_lock)
{
	memset(rw_lock, 0, sizeof(*rw_lock));
	KeInitializeSpinLock(&rw_lock->u.s.klock);
	return;
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMAllocateMapRegisters)
	(struct ndis_handle *handle, UINT dmachan,
	 NDIS_DMA_SIZE dmasize, ULONG basemap, ULONG size)
{
	TRACEENTER2("%d %d %d %d", dmachan, dmasize, basemap, size);

//	if (basemap > 64)
//		return NDIS_STATUS_RESOURCES;

	if (handle->map_count > 0) {
		DBGTRACE2("%s: map registers already allocated: %u",
			 handle->net_dev->name, handle->map_count);
		TRACEEXIT2(return NDIS_STATUS_RESOURCES);
	}

	handle->map_count = basemap;
	handle->map_dma_addr = kmalloc(basemap * sizeof(dma_addr_t),
				       GFP_KERNEL);
	if (!handle->map_dma_addr)
		TRACEEXIT2(return NDIS_STATUS_RESOURCES);
	memset(handle->map_dma_addr, 0, basemap * sizeof(dma_addr_t));

	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(NdisMFreeMapRegisters)
	(struct ndis_handle *handle)
{
	TRACEENTER2("handle: %p", handle);

	if (handle->map_dma_addr != NULL)
		kfree(handle->map_dma_addr);
	handle->map_count = 0;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisMAllocateSharedMemory)
	(struct ndis_handle *handle, ULONG size,
	 BOOLEAN cached, void **virt, NDIS_PHY_ADDRESS *phys)
{
	dma_addr_t p;
	void *v;

	TRACEENTER3("map count: %d, size: %u, cached: %d",
		    handle->map_count, size, cached);

//	if (handle->map_dma_addr == NULL)
//		ERROR("%s: DMA map address is not set!\n", __FUNCTION__);
	/* FIXME: do USB drivers call this? */
	v = PCI_DMA_ALLOC_COHERENT(handle->dev.pci, size, &p);
	if (!v) {
		ERROR("Failed to allocate DMA coherent memory. "
		      "Windows driver requested %d bytes of "
		      "%scached memory\n", size, cached ? "" : "un-");
	}

	*(char**)virt = v;
	*phys = p;

	DBGTRACE3("allocated shared memory: %p", v);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMAllocateSharedMemoryAsync)
	(struct ndis_handle *handle, ULONG size, BOOLEAN cached,
	 void *ctx)
{
	struct ndis_work_entry *ndis_work_entry;
	struct ndis_alloc_mem_work_item *alloc_mem;
	KIRQL irql;

	TRACEENTER3("%s", "");
	ndis_work_entry = kmalloc(sizeof(*ndis_work_entry), GFP_ATOMIC);
	if (!ndis_work_entry)
		return NDIS_STATUS_FAILURE;

	ndis_work_entry->type = NDIS_ALLOC_MEM_WORK_ITEM;
	ndis_work_entry->handle = handle;

	alloc_mem = &ndis_work_entry->entry.alloc_mem_work_item;
	alloc_mem->size = size;
	alloc_mem->cached = cached;
	alloc_mem->ctx = ctx;

	irql = kspin_lock(&ndis_work_list_lock, DISPATCH_LEVEL);
	list_add_tail(&ndis_work_entry->list, &ndis_work_list);
	kspin_unlock(&ndis_work_list_lock, irql);

	schedule_work(&ndis_work);
	TRACEEXIT3(return NDIS_STATUS_PENDING);
}

STDCALL void WRAP_EXPORT(NdisMFreeSharedMemory)
	(struct ndis_handle *handle, ULONG size, BOOLEAN cached,
	 void *virt, NDIS_PHY_ADDRESS addr)
{
	TRACEENTER3("%s", "");
	/* FIXME: do USB drivers call this? */
	PCI_DMA_FREE_COHERENT(handle->dev.pci, size, virt, addr);
	TRACEEXIT3(return);
}

/* Some drivers allocate NDIS_BUFFER (aka MDL) very often; instead of
 * allocating and freeing with kernel functions, we chain them into
 * ndis_buffer_pool. When an MDL is freed, it is added to the list of
 * free MDLs. When allocated, we first check if there is one in free
 * list and if so just return it; otherwise, we allocate a new one and
 * return that. This reduces memory fragmentation. Windows DDK says
 * that the driver itself shouldn't check what is returned in
 * pool_handle, presumably because buffer pools are not used in
 * XP. However, as long as driver follows rest of the semantics - that
 * it should indicate maximum number of MDLs used with num_descr and
 * pass the same pool_handle in other buffer functions, this should
 * work. Sadly, though, NdisFreeBuffer doesn't pass the pool_handle,
 * so we use 'process' field of MDL to store pool_handle. */
STDCALL void WRAP_EXPORT(NdisAllocateBufferPool)
	(NDIS_STATUS *status, struct ndis_buffer_pool **pool_handle,
	 UINT num_descr)
{
	struct ndis_buffer_pool *pool;

	TRACEENTER3("buffers: %d", num_descr);
	pool = kmalloc(sizeof(*pool), GFP_ATOMIC);
	if (!pool) {
		*status = NDIS_STATUS_RESOURCES;
		TRACEEXIT3(return);
	}
	kspin_lock_init(&pool->lock);
	pool->max_descr = num_descr;
	pool->num_allocated_descr = 0;
	pool->free_descr = NULL;
	*pool_handle = pool;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisAllocateBuffer)
	(NDIS_STATUS *status, ndis_buffer **buffer,
	 struct ndis_buffer_pool *pool, void *virt, UINT length)
{
	ndis_buffer *descr;
	KIRQL irql;

	TRACEENTER3("pool: %p, allocated: %d",
		    pool, pool->num_allocated_descr);
	if (!pool) {
		*status = NDIS_STATUS_FAILURE;
		TRACEEXIT4(return);
	}
	irql = kspin_lock(&pool->lock, DISPATCH_LEVEL);
	descr = NULL;
	if (pool->num_allocated_descr < pool->max_descr) {
		if (pool->free_descr) {
			descr = pool->free_descr;
			pool->free_descr = descr->next;
			memset(descr, 0, sizeof(*descr));
			MmInitializeMdl(descr, virt, length);
		} else
			descr = IoAllocateMdl(virt, length, FALSE, FALSE,
					      NULL);
	}

	if (descr) {
		/* NdisFreeBuffer doesn't pass pool, so we store pool
		 * in unused field 'process' */
		descr->process = pool;
		pool->num_allocated_descr++;
		*status = NDIS_STATUS_SUCCESS;
		DBGTRACE3("allocated buffer %p for %p", descr, virt);
	} else
		*status = NDIS_STATUS_FAILURE;

	*buffer = descr;
	kspin_unlock(&pool->lock, irql);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisFreeBuffer)
	(ndis_buffer *descr)
{
	struct ndis_buffer_pool *pool;
	KIRQL irql;

	TRACEENTER3("buffer: %p", descr);
	pool = descr->process;
	if (!pool) {
		ERROR("pool for descriptor %p is invalid", descr);
		TRACEEXIT3(return);
	}
	irql = kspin_lock(&pool->lock, DISPATCH_LEVEL);
	memset(descr, 0, sizeof(*descr));
	descr->next = pool->free_descr;
	pool->free_descr = descr;
	pool->num_allocated_descr--;
	kspin_unlock(&pool->lock, irql);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisFreeBufferPool)
	(struct ndis_buffer_pool *pool)
{
	ndis_buffer *cur, *prev;
	KIRQL irql;

	TRACEENTER3("pool: %p", pool);
	irql = kspin_lock(&pool->lock, DISPATCH_LEVEL);
	cur = pool->free_descr;
	while (cur) {
		prev = cur;
		cur = cur->next;
		prev->process = NULL;
		IoFreeMdl(prev);
	}
	kspin_unlock(&pool->lock, irql);
	kfree(pool);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisAdjustBufferLength)
	(ndis_buffer *buffer, UINT length)
{
	TRACEENTER4("%p", buffer);
	buffer->bytecount = length;
}

STDCALL void WRAP_EXPORT(NdisQueryBuffer)
	(ndis_buffer *buffer, void **virt, UINT *length)
{
	TRACEENTER3("buffer: %p", buffer);
	if (virt)
		*virt = MmGetMdlVirtualAddress(buffer);
	if (length)
		*length = MmGetMdlByteCount(buffer);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisQueryBufferSafe)
	(ndis_buffer *buffer, void **virt, UINT *length,
	 enum mm_page_priority priority)
{
	TRACEENTER3("%p, %p, %p", buffer, virt, length);
	if (virt)
		*virt = MmGetMdlVirtualAddress(buffer);
	if (length)
		*length = MmGetMdlByteCount(buffer);
}

STDCALL void *WRAP_EXPORT(NdisBufferVirtualAddress)
	(ndis_buffer *buffer)
{
	TRACEENTER3("%s", "");
	return MmGetMdlVirtualAddress(buffer);
}

STDCALL ULONG WRAP_EXPORT(NdisBufferLength)
	(ndis_buffer *buffer)
{
	TRACEENTER3("%p", buffer);
	return MmGetMdlByteCount(buffer);
}

STDCALL void WRAP_EXPORT(NdisAllocatePacketPool)
	(NDIS_STATUS *status, struct ndis_packet_pool **pool_handle,
	 UINT num_descr, UINT rsvlen)
{
	struct ndis_packet_pool *pool;

	TRACEENTER3("buffers: %d", num_descr);
	pool = kmalloc(sizeof(*pool), GFP_ATOMIC);
	if (!pool) {
		*status = NDIS_STATUS_RESOURCES;
		TRACEEXIT3(return);
	}
	kspin_lock_init(&pool->lock);
	pool->max_descr = num_descr;
	pool->num_allocated_descr = 0;
	pool->free_descr = NULL;
	*pool_handle = pool;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisAllocatePacketPoolEx)
	(NDIS_STATUS *status, struct ndis_packet_pool **pool_handle,
	 UINT num_descr, UINT overflowsize, UINT rsvlen)
{
	TRACEENTER3("%s", "");
	NdisAllocatePacketPool(status, pool_handle, num_descr, rsvlen);
	TRACEEXIT3(return);
}

STDCALL UINT WRAP_EXPORT(NdisPacketPoolUsage)
	(struct ndis_packet_pool *pool)
{
	UINT i;
	KIRQL irql;

	irql = kspin_lock(&pool->lock, DISPATCH_LEVEL);
	i = pool->num_allocated_descr;
	kspin_unlock(&pool->lock, irql);
	return i;
}

struct ndis_packet *allocate_ndis_packet(void)
{
	return kmem_cache_alloc(packet_cache, GFP_ATOMIC);
}

void free_ndis_packet(struct ndis_packet *packet)
{
	kmem_cache_free(packet_cache, packet);
}

STDCALL void WRAP_EXPORT(NdisAllocatePacket)
	(NDIS_STATUS *status, struct ndis_packet **packet,
	 struct ndis_packet_pool *pool)
{
	struct ndis_packet *descr;
	KIRQL irql;

	TRACEENTER3("pool: %p", pool);
	if (!pool) {
		*status = NDIS_STATUS_RESOURCES;
		TRACEEXIT3(return);
	}
	irql = kspin_lock(&pool->lock, DISPATCH_LEVEL);
	descr = NULL;
	if (pool->num_allocated_descr < pool->max_descr) {
		if (pool->free_descr) {
			descr = pool->free_descr;
			pool->free_descr = descr->next;
		} else
			descr = kmem_cache_alloc(packet_cache, GFP_ATOMIC);
	}

	if (descr) {
		pool->num_allocated_descr++;
		memset(descr, 0, sizeof(*descr));
		descr->private.oob_offset =
			offsetof(struct ndis_packet, oob_tx);
		descr->private.pool = pool;
		descr->private.packet_flags = 0xc0;
		*status = NDIS_STATUS_SUCCESS;
	} else
		*status = NDIS_STATUS_RESOURCES;
	*packet = descr;
	kspin_unlock(&pool->lock, irql);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisDprAllocatePacket)
	(NDIS_STATUS *status, struct ndis_packet **packet,
	 struct ndis_packet_pool *pool)
{
	NdisAllocatePacket(status, packet, pool);
}

STDCALL void WRAP_EXPORT(NdisFreePacket)
	(struct ndis_packet *descr)
{
	struct ndis_packet_pool *pool;
	KIRQL irql;

	TRACEENTER3("packet: %p", descr);
	pool = descr->private.pool;
	if (!pool) {
		ERROR("pool for descriptor %p is invalid", descr);
		TRACEEXIT3(return);
	}
	irql = kspin_lock(&pool->lock, DISPATCH_LEVEL);
	descr->next = pool->free_descr;
	pool->free_descr = descr;
	pool->num_allocated_descr--;
	kspin_unlock(&pool->lock, irql);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisFreePacketPool)
	(struct ndis_packet_pool *pool)
{
	struct ndis_packet *cur, *prev;
	KIRQL irql;

	TRACEENTER3("pool: %p", pool);
	irql = kspin_lock(&pool->lock, DISPATCH_LEVEL);
	cur = pool->free_descr;
	while (cur) {
		prev = cur;
		cur = cur->next;
		kmem_cache_free(packet_cache, prev);
	}
	kspin_unlock(&pool->lock, irql);
	kfree(pool);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisSend)
	(NDIS_STATUS *status, struct ndis_handle *handle,
	 struct ndis_packet *packet)
{
	KIRQL irql;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	if (miniport->send_packets) {
		struct ndis_packet *packets[1];

		packets[0] = packet;
		irql = raise_irql(DISPATCH_LEVEL);
		LIN2WIN3(miniport->send_packets, handle->adapter_ctx,
			 packets, 1);
		lower_irql(irql);
		if (test_bit(ATTR_SERIALIZED, &handle->attributes)) {
			*status = packet->status;
			switch (*status) {
			case NDIS_STATUS_SUCCESS:
				sendpacket_done(handle, packet);
				break;
			case NDIS_STATUS_PENDING:
				break;
			case NDIS_STATUS_RESOURCES:
				handle->send_ok = 0;
				break;
			case NDIS_STATUS_FAILURE:
			default:
				break;
			}
		} else {
			*status = NDIS_STATUS_PENDING;
		}
	} else {
		irql = raise_irql(DISPATCH_LEVEL);
		*status = LIN2WIN3(miniport->send, handle->adapter_ctx,
				   packet, 0);
		lower_irql(irql);
		switch (*status) {
		case NDIS_STATUS_SUCCESS:
			sendpacket_done(handle, packet);
			break;
		case NDIS_STATUS_PENDING:
			break;
		case NDIS_STATUS_RESOURCES:
			handle->send_ok = 0;
			break;
		case NDIS_STATUS_FAILURE:
			break;
		}
	}
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisMInitializeTimer)
	(struct ndis_miniport_timer *timer_handle, struct ndis_handle *handle,
	 void *func, void *ctx)
{
	TRACEENTER4("%s", "");
	wrapper_init_timer(&timer_handle->ktimer, handle);
	init_dpc(&timer_handle->kdpc, func, ctx);
	wrapper_set_timer_dpc(timer_handle->ktimer.wrapper_timer,
	                      &timer_handle->kdpc);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisInitializeTimer)
	(struct ndis_timer *timer_handle, void *func, void *ctx)
{
	TRACEENTER4("%p, %p, %p", timer_handle, func, ctx);
	wrapper_init_timer(&timer_handle->ktimer, NULL);
	init_dpc(&timer_handle->kdpc, func, ctx);
	wrapper_set_timer_dpc(timer_handle->ktimer.wrapper_timer,
	                      &timer_handle->kdpc);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisSetTimer)
	(struct ndis_timer *timer_handle, UINT ms)
{
	unsigned long expires = jiffies + (ms * HZ) / 1000;

	TRACEENTER4("%p, %u", timer_handle, ms);
	wrapper_set_timer(timer_handle->ktimer.wrapper_timer, expires, 0,
			  NULL);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisMSetPeriodicTimer)
	(struct ndis_miniport_timer *timer_handle, UINT ms)
{
	unsigned long expires = jiffies + (ms * HZ) / 1000;
	unsigned long repeat = ms * HZ / 1000;

	TRACEENTER4("%p, %u", timer_handle, ms);
	wrapper_set_timer(timer_handle->ktimer.wrapper_timer,
	                  expires, repeat, NULL);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisMCancelTimer)
	(struct ndis_miniport_timer *timer_handle, BOOLEAN *canceled)
{
	TRACEENTER4("%s", "");
	wrapper_cancel_timer(timer_handle->ktimer.wrapper_timer, canceled);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisCancelTimer)
	(struct ndis_timer *timer_handle, BOOLEAN *canceled)
{
	TRACEENTER4("%s", "");
	wrapper_cancel_timer(timer_handle->ktimer.wrapper_timer, canceled);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisReadNetworkAddress)
	(NDIS_STATUS *status, void **addr, UINT *len,
	 struct ndis_handle *handle)
{
	struct ndis_config_param *setting;
	struct unicode_string key;
	struct ansi_string ansi;
	int ret;

	TRACEENTER1("%s", "");
	ansi.buf = "mac_address";
	ansi.buflen = strlen(ansi.buf);
	ansi.len = ansi.buflen;

	*len = 0;
	*status = NDIS_STATUS_FAILURE;
	if (RtlAnsiStringToUnicodeString(&key, &ansi, 1) !=
	    NDIS_STATUS_SUCCESS)
		TRACEEXIT1(return);

	NdisReadConfiguration(status, &setting, handle, &key,
			      NDIS_CONFIG_PARAM_STRING);
	RtlFreeUnicodeString(&key);

	if (*status == NDIS_STATUS_SUCCESS) {
		int int_mac[ETH_ALEN];
		ret = RtlUnicodeStringToAnsiString(&ansi,
						   &setting->data.ustring, 1);
		if (ret != NDIS_STATUS_SUCCESS)
			TRACEEXIT1(return);

		ret = sscanf(ansi.buf, MACSTR, MACINTADR(int_mac));
		RtlFreeAnsiString(&ansi);
		if (ret == ETH_ALEN) {
			int i;
			for (i = 0; i < ETH_ALEN; i++)
				handle->mac[i] = int_mac[i];
			printk(KERN_INFO "%s: %s ethernet device " MACSTR "\n",
			       handle->net_dev->name, DRIVER_NAME,
			       MAC2STR(handle->mac));
			*len = ETH_ALEN;
			*addr = handle->mac;
			*status = NDIS_STATUS_SUCCESS;
		}
	}

	TRACEEXIT1(return);
}

STDCALL void WRAP_EXPORT(NdisMRegisterAdapterShutdownHandler)
	(struct ndis_handle *handle, void *ctx, void *func)
{
	TRACEENTER1("sp:%p", get_sp());
	handle->driver->miniport_char.adapter_shutdown = func;
	handle->shutdown_ctx = ctx;
}

STDCALL void WRAP_EXPORT(NdisMDeregisterAdapterShutdownHandler)
	(struct ndis_handle *handle)
{
	TRACEENTER1("sp:%p", get_sp());
	handle->driver->miniport_char.adapter_shutdown = NULL;
	handle->shutdown_ctx = NULL;
}

/* bottom half of the irq handler */
static void ndis_irq_bh(void *data)
{
	struct ndis_irq *ndis_irq = (struct ndis_irq *)data;
	struct ndis_handle *handle = ndis_irq->handle;
	struct miniport_char *miniport = &handle->driver->miniport_char;
	KIRQL irql;

	if (ndis_irq->enabled) {
		irql = raise_irql(DISPATCH_LEVEL);
		LIN2WIN1(miniport->handle_interrupt, handle->adapter_ctx);
		if (miniport->enable_interrupts)
			LIN2WIN1(miniport->enable_interrupts,
				 handle->adapter_ctx);
		lower_irql(irql);
	}
}

/* Top half of the irq handler */
static irqreturn_t ndis_irq_th(int irq, void *data, struct pt_regs *pt_regs)
{
	int recognized = 0;
	int handled = 0;
	struct ndis_irq *ndis_irq = (struct ndis_irq *)data;
	struct ndis_handle *handle;
	struct miniport_char *miniport;
	unsigned long flags;

	if (!ndis_irq || !ndis_irq->handle)
		return IRQ_NONE;
	handle = ndis_irq->handle;
	miniport = &handle->driver->miniport_char;
	/* this spinlock should be shared with NdisMSynchronizeWithInterrupt
	 */
	kspin_lock_irqsave(&ndis_irq->lock, flags);
	if (ndis_irq->req_isr)
		LIN2WIN3(miniport->isr, &recognized, &handled,
			 handle->adapter_ctx);
	else { //if (miniport->disable_interrupts)
		LIN2WIN1(miniport->disable_interrupts, handle->adapter_ctx);
		/* it is not shared interrupt, so handler must be called */
		recognized = handled = 1;
	}
	kspin_unlock_irqrestore(&ndis_irq->lock, flags);

	if (recognized && handled)
		schedule_work(&handle->irq_work);

	if (recognized)
		return IRQ_HANDLED;

	return IRQ_NONE;
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMRegisterInterrupt)
	(struct ndis_irq *ndis_irq, struct ndis_handle *handle,
	 UINT vector, UINT level, BOOLEAN req_isr,
	 BOOLEAN shared, enum kinterrupt_mode mode)
{
	TRACEENTER1("%p, vector:%d, level:%d, req_isr:%d, shared:%d, "
		    "mode:%d sp:%p", ndis_irq, vector, level, req_isr,
		    shared, mode, get_sp());

	ndis_irq->irq.irq = vector;
	ndis_irq->handle = handle;
	ndis_irq->req_isr = req_isr;
	if (shared && !req_isr)
		WARNING("%s", "shared but dynamic interrupt!");
	ndis_irq->shared = shared;
	kspin_lock_init(&ndis_irq->lock);

	INIT_WORK(&handle->irq_work, &ndis_irq_bh, ndis_irq);
	if (request_irq(vector, ndis_irq_th, shared? SA_SHIRQ : 0,
			"ndiswrapper", ndis_irq)) {
		printk(KERN_WARNING "%s: request for irq %d failed\n",
		       DRIVER_NAME, vector);
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	}
	ndis_irq->enabled = 1;
	printk(KERN_INFO "%s: using irq %d\n", DRIVER_NAME, vector);
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(NdisMDeregisterInterrupt)
	(struct ndis_irq *ndis_irq)
{
	struct ndis_handle *handle;

	TRACEENTER1("%p", ndis_irq);

	if (!ndis_irq)
		TRACEEXIT1(return);
	handle = ndis_irq->handle;
	if (!handle)
		TRACEEXIT1(return);

	ndis_irq->enabled = 0;
	/* flush irq_bh workqueue; calling it before enabled=0 will
	 * crash since some drivers (Centrino at least) don't expect
	 * irq hander to be called anymore */
	/* cancel_delayed_work is probably better, but 2.4 kernels
	 * don't have equivalent function
	 */
#if LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)
	flush_scheduled_work();
#else
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ/10);
#endif
	free_irq(ndis_irq->irq.irq, ndis_irq);
	ndis_irq->handle = NULL;
	handle->ndis_irq = NULL;
	TRACEEXIT1(return);
}

STDCALL BOOLEAN WRAP_EXPORT(NdisMSynchronizeWithInterrupt)
	(struct ndis_irq *ndis_irq, void *func, void *ctx)
{
	unsigned char ret;
	unsigned char (*sync_func)(void *ctx) STDCALL;
	unsigned long flags;

	TRACEENTER5("%p %p %p\n", ndis_irq, func, ctx);

	if (func == NULL || ctx == NULL)
		TRACEEXIT5(return 0);

	sync_func = func;
	kspin_lock_irqsave(&ndis_irq->lock, flags);
	ret = LIN2WIN1(sync_func, ctx);
	kspin_unlock_irqrestore(&ndis_irq->lock, flags);

	DBGTRACE5("sync_func returns %u", ret);
	TRACEEXIT5(return ret);
}

/* called via function pointer */
STDCALL void
NdisMIndicateStatus(struct ndis_handle *handle,
		    NDIS_STATUS status, void *buf, UINT len)
{
	TRACEENTER2("%08x", status);

	if (status == NDIS_STATUS_MEDIA_DISCONNECT) {
		handle->link_status = 0;
		handle->send_ok = 0;
		set_bit(LINK_STATUS_CHANGED, &handle->wrapper_work);
	}
	if (status == NDIS_STATUS_MEDIA_CONNECT) {
		handle->link_status = 1;
		handle->send_ok = 1;
		set_bit(LINK_STATUS_CHANGED, &handle->wrapper_work);
	}

	if (status == NDIS_STATUS_MEDIA_SPECIFIC_INDICATION && buf) {
		struct ndis_status_indication *status = buf;
		struct ndis_auth_req *auth_req;
		struct ndis_radio_status_indication *radio_status;

		switch (status->status_type) {
		case Ndis802_11StatusType_Authentication:
			buf = (char *)buf + sizeof(*status);
			len -= sizeof(*status);
			while (len > 0) {
				auth_req = (struct ndis_auth_req *)buf;
				DBGTRACE1(MACSTR, MAC2STR(auth_req->bssid));
				if (auth_req->flags & 0x01)
					DBGTRACE2("%s", "reqauth");
				if (auth_req->flags & 0x02)
					DBGTRACE2("%s", "keyupdate");
				if (auth_req->flags & 0x06)
					DBGTRACE2("%s", "pairwise_error");
				if (auth_req->flags & 0x0E)
					DBGTRACE2("%s", "group_error");
				len -= auth_req->length;
				buf = (char *)buf + auth_req->length;
			}
			break;
		case Ndis802_11StatusType_MediaStreamMode:
			break;
		case Ndis802_11StatusType_PMKID_CandidateList:
			break;
		case Ndis802_11StatusType_RadioState:
			radio_status = buf;
			if (radio_status->radio_state ==
			    Ndis802_11RadioStatusOn)
				INFO("radio is turned on");
			else if (radio_status->radio_state ==
				 Ndis802_11RadioStatusHardwareOff)
				INFO("radio is turned off by hardware");
			else if (radio_status->radio_state ==
				 Ndis802_11RadioStatusSoftwareOff)
				INFO("radio is turned off by software");
			break;
		}
	}

	TRACEEXIT1(return);
}

/* called via function pointer */
STDCALL void NdisMIndicateStatusComplete(struct ndis_handle *handle)
{
	TRACEENTER3("%s", "");
	schedule_work(&handle->wrapper_worker);
}

/* called via function pointer */
STDCALL void
NdisMIndicateReceivePacket(struct ndis_handle *handle,
			   struct ndis_packet **packets, UINT nr_packets)
{
	ndis_buffer *buffer;
	struct ndis_packet *packet;
	struct sk_buff *skb;
	int i;
	struct ndis_work_entry *ndis_work_entry;
	KIRQL irql;

	TRACEENTER3("%s", "");
	for (i = 0; i < nr_packets; i++) {
		packet = packets[i];
		if (!packet) {
			WARNING("%s", "Skipping empty packet on receive");
			continue;
		}

		buffer = packet->private.buffer_head;

		skb = dev_alloc_skb(MmGetMdlByteCount(buffer));
		if (skb) {
			skb->dev = handle->net_dev;
			eth_copy_and_sum(skb, MmGetMdlVirtualAddress(buffer),
					 MmGetMdlByteCount(buffer), 0);
			skb_put(skb, MmGetMdlByteCount(buffer));
			skb->protocol = eth_type_trans(skb, handle->net_dev);
			handle->stats.rx_bytes += MmGetMdlByteCount(buffer);
			handle->stats.rx_packets++;
			netif_rx(skb);
		} else
			handle->stats.rx_dropped++;

		/* serialized drivers check the status upon return
		 * from this function */
		if (test_bit(ATTR_SERIALIZED, &handle->attributes)) {
			packet->status = NDIS_STATUS_SUCCESS;
			continue;
		}

		/* if a deserialized driver sets
		 * NDIS_STATUS_RESOURCES, then it reclaims the packet
		 * upon return from this function: it doesn't matter
		 * what value we set in the status */
		if (packet->status == NDIS_STATUS_RESOURCES) {
			packet->status = NDIS_STATUS_SUCCESS;
			DBGTRACE3("low on resources");
			continue;
		}

		if (packet->status != NDIS_STATUS_SUCCESS)
			WARNING("invalid packet status %08X",
				packet->status);
		/* deserialized driver doesn't check the status upon
		 * return from this function; we need to call
		 * MiniportReturnPacket later for this packet. Calling
		 * MiniportReturnPacket from here is not correct - the
		 * driver doesn't expect it (at least Centrino driver
		 * crashes) */
		packet->status = NDIS_STATUS_PENDING;
		ndis_work_entry = kmalloc(sizeof(*ndis_work_entry),
					  GFP_ATOMIC);
		if (!ndis_work_entry) {
			ERROR("couldn't allocate memory");
			continue;
		}
		ndis_work_entry->type = NDIS_RETURN_PACKET_WORK_ITEM;
		ndis_work_entry->handle = handle;
		ndis_work_entry->entry.return_packet = packet;

		irql = kspin_lock(&ndis_work_list_lock, DISPATCH_LEVEL);
		list_add_tail(&ndis_work_entry->list, &ndis_work_list);
		kspin_unlock(&ndis_work_list_lock, irql);
	}
	schedule_work(&ndis_work);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisMCoIndicateReceivePacket)
	(struct ndis_handle *handle, struct ndis_packet **packets,
	 UINT nr_packets)
{
	TRACEENTER3("handle = %p", handle);
	NdisMIndicateReceivePacket(handle, packets, nr_packets);
	TRACEEXIT3(return);
}

/* called via function pointer */
STDCALL void
NdisMSendComplete(struct ndis_handle *handle,
		  struct ndis_packet *packet, NDIS_STATUS status)
{
	TRACEENTER3("%08x", status);
	sendpacket_done(handle, packet);
	/* In case a serialized driver has requested a pause by returning
	 * NDIS_STATUS_RESOURCES we need to give the send-code a kick again.
	 */
	handle->send_ok = 1;
	schedule_work(&handle->xmit_work);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisMCoSendComplete)
	(NDIS_STATUS status, struct ndis_handle *handle,
	 struct ndis_packet *packet)
{
	TRACEENTER3("%08x", status);
	NdisMSendComplete(handle, packet, status);
	TRACEEXIT3(return);
}

/* called via function pointer */
STDCALL void
NdisMSendResourcesAvailable(struct ndis_handle *handle)
{
	TRACEENTER3("%s", "");
	/* sending packets immediately seem to result in NDIS_STATUS_FAILURE,
	   so wait for a while before sending the packet again */
	mdelay(5);
	handle->send_ok = 1;
	schedule_work(&handle->xmit_work);
	TRACEEXIT3(return);
}

/* called via function pointer (by NdisMEthIndicateReceive macro) */
STDCALL void
EthRxIndicateHandler(void *adapter_ctx, void *rx_ctx, char *header1,
		     char *header, UINT header_size, void *look_ahead,
		     UINT look_ahead_size, UINT packet_size)
{
	struct sk_buff *skb = NULL;
	struct ndis_handle *handle = ctx_to_handle(rx_ctx);
	unsigned int skb_size = 0;
	KIRQL irql;

	TRACEENTER3("adapter_ctx = %p, rx_ctx = %p, buf = %p, size = %d, "
		    "buf = %p, size = %d, packet = %d",
		    adapter_ctx, rx_ctx, header, header_size, look_ahead,
		    look_ahead_size, packet_size);

	DBGTRACE3("handle = %p", handle);
	if (!handle)
		TRACEEXIT3(return);

	if (look_ahead_size < packet_size) {
		struct ndis_packet *packet;
		struct miniport_char *miniport;
		unsigned int res, bytes_txed;

		packet = kmalloc(sizeof(*packet), GFP_ATOMIC);
		if (!packet) {
			handle->stats.rx_dropped++;
			TRACEEXIT3(return);
		}
		memset(packet, 0, sizeof(*packet));
		packet->private.oob_offset =
			offsetof(struct ndis_packet, oob_tx);
		packet->private.pool = NULL;
		packet->private.packet_flags = 0xc0;

		miniport = &handle->driver->miniport_char;
		irql = raise_irql(DISPATCH_LEVEL);
		res = LIN2WIN6(miniport->tx_data, packet, &bytes_txed,
			       adapter_ctx, rx_ctx, look_ahead_size,
			       packet_size);
		lower_irql(irql);
		if (res == NDIS_STATUS_SUCCESS) {
			ndis_buffer *buffer;
			skb = dev_alloc_skb(header_size+look_ahead_size+
					    bytes_txed);
			if (skb) {
				memcpy(skb->data, header, header_size);
				memcpy(skb->data+header_size, look_ahead,
				       look_ahead_size);
				buffer = packet->private.buffer_head;
				memcpy(skb->data+header_size+look_ahead_size,
				       MmGetMdlVirtualAddress(buffer),
				       bytes_txed);
				skb_size = header_size+look_ahead_size+
					bytes_txed;
				kfree(packet);
			}
		} else if (res == NDIS_STATUS_PENDING) {
			/* driver will call td_complete */
			packet->look_ahead = kmalloc(look_ahead_size,
						     GFP_ATOMIC);
			if (!packet->look_ahead) {
				kfree(packet);
				handle->stats.rx_dropped++;
				TRACEEXIT3(return);
			}
			memcpy(&packet->header, header,
			       sizeof(packet->header));
			memcpy(packet->look_ahead, look_ahead,
			       look_ahead_size);
			packet->look_ahead_size = look_ahead_size;
		} else {
			kfree(packet);
			handle->stats.rx_dropped++;
			TRACEEXIT3(return);
		}
	} else {
		skb_size = header_size+packet_size;
		skb = dev_alloc_skb(skb_size);
		if (skb) {
			memcpy(skb->data, header, header_size);
			memcpy(skb->data+header_size, look_ahead, packet_size);
		}
	}

	if (skb && skb_size > 0) {
		skb->dev = handle->net_dev;
		skb_put(skb, skb_size);
		skb->protocol = eth_type_trans(skb, handle->net_dev);
		handle->stats.rx_bytes += skb_size;
		handle->stats.rx_packets++;
		netif_rx(skb);
	} else
		handle->stats.rx_dropped++;

	TRACEEXIT3(return);
}

/* called via function pointer */
STDCALL void
NdisMTransferDataComplete(struct ndis_handle *handle,
			  struct ndis_packet *packet,
			  NDIS_STATUS status, UINT bytes_txed)
{
	struct sk_buff *skb;
	unsigned int skb_size;

	TRACEENTER3("handle = %p, packet = %p, bytes_txed = %d",
		    handle, packet, bytes_txed);

	if (!packet) {
		WARNING("%s", "illegal packet");
		TRACEEXIT3(return);
	}

	skb_size = sizeof(packet->header) + packet->look_ahead_size +
		bytes_txed;

	skb = dev_alloc_skb(skb_size);
	if (!skb) {
		kfree(packet->look_ahead);
		kfree(packet);
		handle->stats.rx_dropped++;
		TRACEEXIT3(return);
	}

	skb->dev = handle->net_dev;
	memcpy(skb->data, packet->header, sizeof(packet->header));
	memcpy(skb->data + sizeof(packet->header), packet->look_ahead,
	       packet->look_ahead_size);
	memcpy(skb->data + sizeof(packet->header) + packet->look_ahead_size,
	       MmGetMdlVirtualAddress(packet->private.buffer_head),
	       bytes_txed);
	kfree(packet->look_ahead);
	kfree(packet);
	skb_put(skb, skb_size);
	skb->protocol = eth_type_trans(skb, handle->net_dev);
	handle->stats.rx_bytes += skb_size;
	handle->stats.rx_packets++;
	netif_rx(skb);
}

/* called via function pointer */
STDCALL void
EthRxComplete(struct ndis_handle *handle)
{
	DBGTRACE3("%s", "");
}

/* Called via function pointer if query returns NDIS_STATUS_PENDING */
STDCALL void
NdisMQueryInformationComplete(struct ndis_handle *handle, NDIS_STATUS status)
{
	TRACEENTER3("%08X", status);

	handle->ndis_comm_res = status;
	handle->ndis_comm_done = 1;
	wake_up(&handle->ndis_comm_wq);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisMCoRequestComplete)
	(NDIS_STATUS status, struct ndis_handle *handle,
	 struct ndis_request *ndis_request)
{
	TRACEENTER3("%08X", status);

	handle->ndis_comm_res = status;
	handle->ndis_comm_done = 1;
	wake_up(&handle->ndis_comm_wq);
	TRACEEXIT3(return);
}

/* Called via function pointer if setinfo returns NDIS_STATUS_PENDING */
STDCALL void
NdisMSetInformationComplete(struct ndis_handle *handle, NDIS_STATUS status)
{
	TRACEENTER3("status = %08X", status);

	handle->ndis_comm_res = status;
	handle->ndis_comm_done = 1;
	wake_up(&handle->ndis_comm_wq);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisMSleep)
	(ULONG us_to_sleep)
{
	TRACEENTER4("us: %u", us_to_sleep);
	if (us_to_sleep > 0) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout((us_to_sleep * HZ)/1000000);
		DBGTRACE4("%s", "woke up");
	}
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisGetCurrentSystemTime)
	(LARGE_INTEGER *time)
{
	*time = ticks_1601();
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMRegisterIoPortRange)
	(void **virt, struct ndis_handle *handle, UINT start, UINT len)
{
	TRACEENTER3("%08x %08x", start, len);
	*virt = (void *)(ULONG_PTR)start;
	return NDIS_STATUS_SUCCESS;
}

STDCALL void WRAP_EXPORT(NdisMDeregisterIoPortRange)
	(struct ndis_handle *handle, UINT start, UINT len, void* virt)
{
	TRACEENTER1("%08x %08x", start, len);
}

STDCALL LONG WRAP_EXPORT(NdisInterlockedDecrement)
	(LONG *val)
{
	LONG x;
	KIRQL irql;

	TRACEENTER4("%s", "");
	irql = kspin_lock(&ntoskrnl_lock, PASSIVE_LEVEL);
	(*val)--;
	x = *val;
	kspin_unlock(&ntoskrnl_lock, irql);
	TRACEEXIT4(return x);
}

STDCALL LONG WRAP_EXPORT(NdisInterlockedIncrement)
	(LONG *val)
{
	LONG x;
	KIRQL irql;

	TRACEENTER4("%s", "");
	irql = kspin_lock(&ntoskrnl_lock, PASSIVE_LEVEL);
	(*val)++;
	x = *val;
	kspin_unlock(&ntoskrnl_lock, irql);
	TRACEEXIT4(return x);
}

STDCALL struct list_entry * WRAP_EXPORT(NdisInterlockedInsertHeadList)
	(struct list_entry *head, struct list_entry *entry,
	 struct ndis_spinlock *lock)
{
	struct list_entry *flink;

	TRACEENTER4("lock: %p", lock);
	NdisAcquireSpinLock(lock);

	flink = head->fwd_link;
	entry->fwd_link = flink;
	entry->bwd_link = head;
	flink->bwd_link = entry;
	head->fwd_link = entry;

	NdisReleaseSpinLock(lock);
	TRACEEXIT4(return (flink == head) ? NULL : flink);
}

STDCALL struct list_entry * WRAP_EXPORT(NdisInterlockedInsertTailList)
	(struct list_entry *head, struct list_entry *entry,
	 struct ndis_spinlock *lock)
{
	struct list_entry *flink;

	TRACEENTER4("lock: %p", lock);
	NdisAcquireSpinLock(lock);

	flink = head->bwd_link;
	entry->fwd_link = head;
	entry->bwd_link = flink;
	flink->fwd_link = entry;
	head->bwd_link = entry;

	NdisReleaseSpinLock(lock);
	TRACEEXIT4(return (flink == head) ? NULL : flink);
}

STDCALL struct list_entry * WRAP_EXPORT(NdisInterlockedRemoveHeadList)
	(struct list_entry *head, struct ndis_spinlock *lock)
{
	struct list_entry *flink;

	TRACEENTER4("lock: %p", lock);
	NdisAcquireSpinLock(lock);

	flink = head->fwd_link;
	head->fwd_link = flink->fwd_link;
	head->fwd_link->bwd_link = head;

	NdisReleaseSpinLock(lock);
	TRACEEXIT4(return (flink == head) ? NULL : flink);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMInitializeScatterGatherDma)
	(struct ndis_handle *handle, UCHAR dma_size, ULONG max_phy_map)
{
	TRACEENTER2("dma_size=%d, maxtransfer=%u", dma_size, max_phy_map);
#ifdef CONFIG_X86_64
	if (dma_size != NDIS_DMA_64BITS)
		ERROR("DMA size is not 64-bits");
#endif
	handle->use_sg_dma = 1;
	return NDIS_STATUS_SUCCESS;
}

STDCALL ULONG WRAP_EXPORT(NdisMGetDmaAlignment)
	(struct ndis_handle *handle)
{
	TRACEENTER3("%s", "");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	return dma_get_cache_alignment();
#else
	return L1_CACHE_BYTES;
#endif
}

STDCALL void WRAP_EXPORT(NdisQueryBufferOffset)
	(ndis_buffer *buffer, UINT *offset, UINT *length)
{
	TRACEENTER3("%s", "");
	*offset = MmGetMdlByteOffset(buffer);
	*length = MmGetMdlByteCount(buffer);
}

STDCALL CHAR WRAP_EXPORT(NdisSystemProcessorCount)
	(void)
{
	return NR_CPUS;
}

STDCALL void WRAP_EXPORT(NdisInitializeEvent)
	(struct ndis_event *ndis_event)
{
	TRACEENTER3("%p", ndis_event);
	KeInitializeEvent(&ndis_event->kevent, NotificationEvent, 0);
}

STDCALL BOOLEAN WRAP_EXPORT(NdisWaitEvent)
	(struct ndis_event *ndis_event, UINT ms)
{
	LARGE_INTEGER ticks;
	NTSTATUS res;

	TRACEENTER3("%p %u", ndis_event, ms);
	ticks = ms * 10000;
	res = KeWaitForSingleObject(&ndis_event->kevent, 0, 0, 0, &ticks);
	if (res == STATUS_SUCCESS)
		TRACEEXIT3(return TRUE);
	else
		TRACEEXIT3(return FALSE);
}

STDCALL void WRAP_EXPORT(NdisSetEvent)
	(struct ndis_event *ndis_event)
{
	TRACEENTER3("%p", ndis_event);
	KeSetEvent(&ndis_event->kevent, 0, 0);
}

STDCALL void WRAP_EXPORT(NdisResetEvent)
	(struct ndis_event *ndis_event)
{
	TRACEENTER3("%p", ndis_event);
	KeResetEvent(&ndis_event->kevent);
}

/* called via function pointer */
STDCALL void
NdisMResetComplete(struct ndis_handle *handle, NDIS_STATUS status,
		   BOOLEAN address_reset)
{
	TRACEENTER2("status: %08X, reset status: %u", status,
		    address_reset);

	handle->ndis_comm_res = status;
	handle->reset_status = status;
	handle->ndis_comm_done = 1;
	wake_up(&handle->ndis_comm_wq);
	TRACEEXIT3(return);
}

/* one worker for all drivers/handles */
static void ndis_worker(void *data)
{
	struct ndis_work_entry *ndis_work_entry;
	struct ndis_sched_work_item *sched_work_item;
	struct ndis_alloc_mem_work_item *alloc_mem;
	struct ndis_free_mem_work_item *free_mem;
	struct ndis_io_work_item *io_work_item;
	struct ndis_packet *packet;
	struct ndis_handle *handle;
	struct miniport_char *miniport;
	void *virt;
	NDIS_PHY_ADDRESS phys;
	KIRQL irql;

	TRACEENTER3("%s", "");

	while (1) {
		irql = kspin_lock(&ndis_work_list_lock, DISPATCH_LEVEL);
		if (list_empty(&ndis_work_list))
			ndis_work_entry = NULL;
		else {
			ndis_work_entry =
				list_entry(ndis_work_list.next,
					   struct ndis_work_entry, list);
			list_del(&ndis_work_entry->list);
		}
		kspin_unlock(&ndis_work_list_lock, irql);

		if (!ndis_work_entry) {
			DBGTRACE3("%s", "No more work");
			break;
		}

		handle = ndis_work_entry->handle;
		switch (ndis_work_entry->type) {
		case NDIS_SCHED_WORK_ITEM:
			sched_work_item =
				ndis_work_entry->entry.sched_work_item;

			DBGTRACE3("Calling work at %p with parameter %p",
				  sched_work_item->func,
				  sched_work_item->ctx);
			LIN2WIN2(sched_work_item->func, sched_work_item,
				 sched_work_item->ctx);
			break;

		case NDIS_IO_WORK_ITEM:
			io_work_item =
				ndis_work_entry->entry.io_work_item;

			DBGTRACE3("Calling work at %p with parameter %p",
				  io_work_item->func, io_work_item->ctx);
			LIN2WIN2(io_work_item->func,
				io_work_item->device_object,
				io_work_item->ctx);
			break;

		case NDIS_ALLOC_MEM_WORK_ITEM:
			alloc_mem =
				&ndis_work_entry->entry.alloc_mem_work_item;
			DBGTRACE3("Allocating %scached memory of length %ld",
				  alloc_mem->cached ? "" : "un-",
				  alloc_mem->size);
			miniport = &handle->driver->miniport_char;
			NdisMAllocateSharedMemory(handle, alloc_mem->size,
						  alloc_mem->cached,
						  &virt, &phys);
			irql = raise_irql(DISPATCH_LEVEL);
			LIN2WIN5(miniport->alloc_complete, handle, virt,
				 &phys, alloc_mem->size, alloc_mem->ctx);
			lower_irql(irql);
			break;

		case NDIS_FREE_MEM_WORK_ITEM:
			free_mem = &ndis_work_entry->entry.free_mem_work_item;
			DBGTRACE3("Freeing memory of size %d, flags %d at %p",
				  free_mem->length, free_mem->flags,
				  free_mem->addr);
			if (free_mem->addr)
				vfree(free_mem->addr);
			break;

		case NDIS_RETURN_PACKET_WORK_ITEM:
			packet = ndis_work_entry->entry.return_packet;
			miniport = &handle->driver->miniport_char;
			irql = raise_irql(DISPATCH_LEVEL);
			LIN2WIN2(miniport->return_packet,
				 handle->adapter_ctx, packet);
			lower_irql(irql);
			break;

		default:
			ERROR("unknown ndis work item: %d",
			      ndis_work_entry->type);
			break;
		}
		kfree(ndis_work_entry);
	}
	TRACEEXIT3(return);
}

STDCALL struct ndis_io_work_item *WRAP_EXPORT(IoAllocateWorkItem)
	(void *device_object)
{
	struct ndis_io_work_item *io_work_item;

	io_work_item = kmalloc(sizeof(*io_work_item), GFP_ATOMIC);
	if (!io_work_item)
		return NULL;

	io_work_item->device_object = device_object;
	return io_work_item;
}

STDCALL void WRAP_EXPORT(IoFreeWorkItem)
	(struct ndis_io_work_item *io_work_item)
{
	kfree(io_work_item);
	return;
}

STDCALL void WRAP_EXPORT(IoQueueWorkItem)
	(struct ndis_io_work_item *io_work_item, void *func,
	 enum work_queue_type queue_type, void *ctx)
{
	struct ndis_work_entry *ndis_work_entry;
	KIRQL irql;

	TRACEENTER3("%s", "");
	if (io_work_item == NULL) {
		ERROR("%s", "io_work_item is NULL; item not queued");
		return;
	}

	ndis_work_entry = kmalloc(sizeof(*ndis_work_entry), GFP_ATOMIC);
	if (!ndis_work_entry)
		BUG();

	ndis_work_entry->type = NDIS_IO_WORK_ITEM;
	io_work_item->func = func;
	io_work_item->ctx = ctx;
	ndis_work_entry->entry.io_work_item = io_work_item;

	irql = kspin_lock(&ndis_work_list_lock, DISPATCH_LEVEL);
	list_add_tail(&ndis_work_entry->list, &ndis_work_list);
	kspin_unlock(&ndis_work_list_lock, irql);

	schedule_work(&ndis_work);
	TRACEEXIT3(return);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisScheduleWorkItem)
	(struct ndis_sched_work_item *ndis_sched_work_item)
{
	struct ndis_work_entry *ndis_work_entry;
	KIRQL irql;

	TRACEENTER3("%s", "");
	/* this function is called from irq_bh by realtek driver */
	ndis_work_entry = kmalloc(sizeof(*ndis_work_entry), GFP_ATOMIC);
	if (!ndis_work_entry)
		BUG();

	ndis_work_entry->type = NDIS_SCHED_WORK_ITEM;
	ndis_work_entry->entry.sched_work_item = ndis_sched_work_item;

	irql = kspin_lock(&ndis_work_list_lock, DISPATCH_LEVEL);
	list_add_tail(&ndis_work_entry->list, &ndis_work_list);
	kspin_unlock(&ndis_work_list_lock, irql);

	schedule_work(&ndis_work);
	TRACEEXIT3(return NDIS_STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(NdisUnchainBufferAtBack)
	(struct ndis_packet *packet, ndis_buffer **buffer)
{
	ndis_buffer *b, *btail;

	TRACEENTER3("%p", packet);
	if (packet == NULL || buffer == NULL)
		return;
	b = packet->private.buffer_head;
	if (!b) {
		/* no buffer in packet */
		*buffer = NULL;
		TRACEEXIT3(return);
	}
	btail = packet->private.buffer_tail;
	*buffer = btail;
	packet->private.valid_counts = FALSE;
	if (b == btail) {
		/* one buffer in packet */
		packet->private.buffer_head = NULL;
		packet->private.buffer_tail = NULL;
	} else {
		while (b->next != btail)
			b = b->next;
		packet->private.buffer_tail = b;
		b->next = NULL;
	}
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisUnchainBufferAtFront)
	(struct ndis_packet *packet, ndis_buffer **buffer)
{
	TRACEENTER3("%p", packet);
	if (buffer == NULL)
		return;
	if (packet == NULL) {
		/* no buffer in packet */
		*buffer = NULL;
		TRACEEXIT3(return);
	}

	packet->private.valid_counts = FALSE;
	*buffer = packet->private.buffer_head;
	if (packet->private.buffer_head == packet->private.buffer_tail) {
		/* one buffer in packet */
		packet->private.buffer_head = NULL;
		packet->private.buffer_tail = NULL;
	} else
		packet->private.buffer_head = (*buffer)->next;

	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisGetFirstBufferFromPacketSafe)
	(struct ndis_packet *packet, ndis_buffer **first_buffer,
	 void **first_buffer_va, UINT *first_buffer_length,
	 UINT *total_buffer_length, enum mm_page_priority priority)
{
	ndis_buffer *b = packet->private.buffer_head;

	TRACEENTER3("%p", b);
	*first_buffer = b;
	if (b) {
		*first_buffer_va = MmGetMdlVirtualAddress(b);
		*first_buffer_length = *total_buffer_length =
			MmGetMdlByteCount(b);
		for (b = b->next; b != NULL; b = b->next)
			*total_buffer_length += MmGetMdlByteCount(b);
	} else {
		*first_buffer_va = NULL;
		*first_buffer_length = 0;
		*total_buffer_length = 0;
	}
}

STDCALL void WRAP_EXPORT(NdisCopyFromPacketToPacketSafe)
	(struct ndis_packet *dst, UINT dst_offset, UINT num_to_copy,
	 struct ndis_packet *src, UINT src_offset, UINT *num_copied,
	 enum mm_page_priority priority)
{
	UINT dst_left, src_left, left, done;
	ndis_buffer *dst_buf;
	ndis_buffer *src_buf;

	TRACEENTER4("");
	if (!dst || !src) {
		*num_copied = 0;
		TRACEEXIT4(return);
	}

	dst_buf = dst->private.buffer_head;
	src_buf = src->private.buffer_head;

	if (!dst_buf || !src_buf) {
		*num_copied = 0;
		TRACEEXIT4(return);
	}
	dst_left = MmGetMdlByteCount(dst_buf) - dst_offset;
	src_left = MmGetMdlByteCount(src_buf) - src_offset;

	left = min(src_left, dst_left);
	left = min(left, num_to_copy);
	memcpy(MmGetMdlVirtualAddress(dst_buf) + dst_offset,
	       MmGetMdlVirtualAddress(src_buf) + src_offset, left);

	done = num_to_copy - left;
	while (done > 0) {
		if (left == dst_left) {
			dst_buf = dst_buf->next;
			if (!dst_buf)
				break;
			dst_left = MmGetMdlByteCount(dst_buf);
		} else
			dst_left -= left;
		if (left == src_left) {
			src_buf = src_buf->next;
			if (!src_buf)
				break;
			src_left = MmGetMdlByteCount(src_buf);
		} else
			src_left -= left;

		left = min(src_left, dst_left);
		left = min(left, done);
		memcpy(MmGetMdlVirtualAddress(dst_buf),
		       MmGetMdlVirtualAddress(src_buf), left);
		done -= left;
	}
	*num_copied = num_to_copy - done;
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisCopyFromPacketToPacket)
	(struct ndis_packet *dst, UINT dst_offset, UINT num_to_copy,
	 struct ndis_packet *src, UINT src_offset, UINT *num_copied)
{
	NdisCopyFromPacketToPacketSafe(dst, dst_offset, num_to_copy,
				       src, src_offset, num_copied,
				       NormalPagePriority);
	return;
}

STDCALL void WRAP_EXPORT(NdisMStartBufferPhysicalMapping)
	(struct ndis_handle *handle, ndis_buffer *buf,
	 ULONG phy_map_reg, BOOLEAN write_to_dev,
	 struct ndis_phy_addr_unit *phy_addr_array, UINT *array_size)
{
	TRACEENTER3("phy_map_reg: %u", phy_map_reg);

	if (!write_to_dev) {
		ERROR( "dma from device not supported (%d)", write_to_dev);
		*array_size = 0;
		return;
	}

	if (phy_map_reg > handle->map_count) {
		ERROR("map_register too big (%u > %u)",
		      phy_map_reg, handle->map_count);
		*array_size = 0;
		return;
	}

	if (handle->map_dma_addr[phy_map_reg] != 0) {
//		ERROR("map register already used (%lu)", phy_map_reg);
		*array_size = 1;
		return;
	}

	// map buffer
	/* FIXME: do USB drivers call this? */
	phy_addr_array[0].phy_addr =
		PCI_DMA_MAP_SINGLE(handle->dev.pci,
				   MmGetMdlVirtualAddress(buf),
				   MmGetMdlByteCount(buf), PCI_DMA_TODEVICE);
	phy_addr_array[0].length = MmGetMdlByteCount(buf);

	*array_size = 1;

	// save mapping index
	handle->map_dma_addr[phy_map_reg] = phy_addr_array[0].phy_addr;
}

STDCALL void WRAP_EXPORT(NdisMCompleteBufferPhysicalMapping)
	(struct ndis_handle *handle, ndis_buffer *buf,
	 ULONG phy_map_reg)
{
	TRACEENTER3("%p %u (%u)", handle, phy_map_reg, handle->map_count);

	if (phy_map_reg > handle->map_count) {
		ERROR("map_register too big (%u > %u)",
		      phy_map_reg, handle->map_count);
		return;
	}

	if (handle->map_dma_addr[phy_map_reg] == 0) {
//		ERROR("map register not used (%lu)", phy_map_reg);
		return;
	}

	// unmap buffer
	/* FIXME: do USB drivers call this? */
	PCI_DMA_UNMAP_SINGLE(handle->dev.pci,
			     handle->map_dma_addr[phy_map_reg],
			     MmGetMdlByteCount(buf), PCI_DMA_TODEVICE);

	// clear mapping index
	handle->map_dma_addr[phy_map_reg] = 0;
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMRegisterDevice)
	(struct ndis_handle *handle, struct unicode_string *dev_name,
	 struct unicode_string *sym_name, void **funcs,
	 struct device_object **dev_object, struct ndis_handle **dev_handle)
{
	TRACEENTER1("%p, %p", *dev_handle, handle);
	*dev_handle = handle;
	*dev_object = handle->device_obj;
	return NDIS_STATUS_SUCCESS;
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMDeregisterDevice)
	(struct ndis_handle *handle)
{
	return NDIS_STATUS_SUCCESS;
}

STDCALL void WRAP_EXPORT(NdisMGetDeviceProperty)
	(struct ndis_handle *handle, void **phy_dev, void **func_dev,
	 void **next_dev, void **alloc_res, void**trans_res)
{
	struct device_object *dev;
	int i;

	TRACEENTER2("phy_dev = %p, func_dev = %p, next_dev = %p, "
		"alloc_res = %p, trans_res = %p", phy_dev, func_dev,
		next_dev, alloc_res, trans_res);

	if (!handle->phys_device_obj) {
		/* some drivers don't allocate this pointer, nor is it
		 * NULL so use wrap_kmalloc so it gets freed
		 * automatically, if indeed we allocate it here */
		dev = wrap_kmalloc(sizeof(*dev), GFP_KERNEL);
		if (!dev) {
			ERROR("%s", "unable to allocate "
				"DEVICE_OBJECT structure!");
			TRACEEXIT2(return);
		}
	
		for (i = 0; i < (sizeof(*dev)/sizeof(void *)); i++)
			((int *)dev)[i] = 0x00000A00;

		dev->drv_obj = handle;
		dev->next_dev        = (void *)0x00000901;
		dev->current_irp     = (void *)0x00000801;
		/* flags: DO_BUFFERED_IO + DO_BUS_ENUMERATED_DEVICE */
		dev->flags           = 0x00001004;
		dev->characteristics = 01;
		dev->stack_size      = 1;

		/* assumes that the handle refers to an USB device */
		dev->device.usb = handle->dev.usb;

		dev->handle = handle;

		handle->phys_device_obj = dev;
	}

	if (phy_dev) {
		*phy_dev = handle->phys_device_obj;
		DBGTRACE2("*phy_dev = %p", *phy_dev);
	}

	if (func_dev) {
		*func_dev = handle->phys_device_obj;
		DBGTRACE2("*func_dev = %p", *func_dev);
	}

	if (next_dev) {
		/* physical and next device seem to be the same */
		*next_dev = handle->phys_device_obj;
		DBGTRACE2("*next_dev = %p", *next_dev);
	}

	if (alloc_res) {
		ERROR("%s", "request for alloc_res not yet supported!");
		*alloc_res = (void *)0x00000D00;
	}

	if (trans_res) {
		ERROR("%s", "request for trans_res not yet supported!");
		*trans_res = (void *)0x00000E00;
	}
}

STDCALL void WRAP_EXPORT(NdisMRegisterUnloadHandler)
	(struct ndis_driver *driver, void *unload)
{
	if (driver)
		driver->driver_unload = unload;
	return;
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMQueryAdapterInstanceName)
	(struct unicode_string *name, struct ndis_handle *handle)
{
	struct ansi_string ansi_string;

	if (handle->driver->bustype == NDIS_PCI_BUS)
		ansi_string.buf = "PCI Ethernet Adapter";
	else
		ansi_string.buf = "USB Ethernet Adapter";
	ansi_string.buflen = ansi_string.len = strlen(ansi_string.buf);
	if (RtlAnsiStringToUnicodeString(name, &ansi_string, 1))
		TRACEEXIT2(return NDIS_STATUS_RESOURCES);
	else
		TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL ULONG WRAP_EXPORT(NdisReadPcmciaAttributeMemory)
	(struct ndis_handle *handle, ULONG offset, void *buffer, ULONG length)
{
	UNIMPL();
	return 0;
}

STDCALL ULONG WRAP_EXPORT(NdisWritePcmciaAttributeMemory)
	(struct ndis_handle *handle, ULONG offset, void *buffer,
	 ULONG length)
{
	UNIMPL();
	return 0;
}

 /* Unimplemented...*/
STDCALL void WRAP_EXPORT(NdisMSetAttributes)(void){UNIMPL();}
STDCALL void WRAP_EXPORT(EthFilterDprIndicateReceiveComplete)
	(void){UNIMPL();}
STDCALL void WRAP_EXPORT(EthFilterDprIndicateReceive)(void){UNIMPL();}
STDCALL void WRAP_EXPORT(NdisMRemoveMiniport)(void) { UNIMPL(); }
//STDCALL void RndisMSendComplete(void) { UNIMPL(); }
//STDCALL void RndisMInitializeWrapper(void) { UNIMPL(); }
STDCALL void WRAP_EXPORT(RndisMIndicateReceive)(void) { UNIMPL(); }

STDCALL void WRAP_EXPORT(NdisMCoActivateVcComplete)(void){UNIMPL();}

STDCALL void WRAP_EXPORT(NdisMCoDeactivateVcComplete)(void)
{
	UNIMPL();
	return;
}

#include "ndis_exports.h"
