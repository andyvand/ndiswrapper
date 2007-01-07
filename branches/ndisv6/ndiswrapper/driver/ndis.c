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

#include "ndis.h"
#include "iw_ndis.h"
#include "wrapndis.h"
#include "pnp.h"
#include "loader.h"

#define MAX_ALLOCATED_NDIS_PACKETS 20
#define MAX_ALLOCATED_NDIS_BUFFERS 20

static workqueue_struct_t *ndis_wq;
static void ndis_worker(worker_param_t dummy);
static work_struct_t ndis_work;
static struct nt_list ndis_worker_list;
static NT_SPIN_LOCK ndis_work_list_lock;

extern struct semaphore loader_mutex;

/* ndis_init is called once when module is loaded */
int ndis_init(void)
{
	ndis_wq = create_singlethread_workqueue("ndis_wq");
	InitializeListHead(&ndis_worker_list);
	nt_spin_lock_init(&ndis_work_list_lock);
	initialize_work(&ndis_work, ndis_worker, NULL);

	return 0;
}

/* ndis_exit is called once when module is removed */
void ndis_exit(void)
{
	destroy_workqueue(ndis_wq);
	TRACEEXIT1(return);
}

/* ndis_exit_device is called for each handle */
void ndis_exit_device(struct wrap_ndis_device *wnd)
{
	struct wrap_device_setting *setting;
	DBGTRACE2("%p", wnd);
	if (down_interruptible(&loader_mutex))
		WARNING("couldn't obtain loader_mutex");
	nt_list_for_each_entry(setting, &wnd->wd->settings, list) {
		struct ndis_configuration_parameter *param;
		param = setting->encoded;
		if (param) {
			if (param->type == NdisParameterString)
				RtlFreeUnicodeString(&param->data.string);
			ExFreePool(param);
			setting->encoded = NULL;
		}
	}
	up(&loader_mutex);
}

wstdcall void WIN_FUNC(NdisInitializeWrapper,4)
	(void **driver_handle, struct driver_object *driver,
	 struct unicode_string *reg_path, void *unused)
{
	TRACEENTER1("handle: %p, driver: %p", driver_handle, driver);
	*driver_handle = driver;
	TRACEEXIT1(return);
}

wstdcall void WIN_FUNC(NdisTerminateWrapper,2)
	(struct device_object *dev_obj, void *system_specific)
{
	TRACEEXIT1(return);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMRegisterMiniportDriver,5)
	(struct driver_object *drv_obj, struct unicode_string *registry_path,
	 void *mp_driver_ctx, struct mp_driver_characteristics *mp_driver_chars,
	 void **driver_handle)
{
	struct wrap_driver *wrap_driver;
	struct wrap_ndis_driver *ndis_driver;

	TRACEENTER2("%p, %p",drv_obj,  mp_driver_ctx);
	if (mp_driver_chars->major_version != 0x6) {
		WARNING("invalid version: 0x%x", mp_driver_chars->major_version);
		return NDIS_STATUS_BAD_VERSION;
	}
	wrap_driver =
		IoGetDriverObjectExtension(drv_obj,
					   (void *)WRAP_DRIVER_CLIENT_ID);
	if (!wrap_driver) {
		ERROR("couldn't get wrap_driver");
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	}
	if (IoAllocateDriverObjectExtension(
		    drv_obj, (void *)NDIS_DRIVER_CLIENT_ID,
		    sizeof(*ndis_driver), (void **)&ndis_driver) !=
	    STATUS_SUCCESS)
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	wrap_driver->ndis_driver = ndis_driver;
	ndis_driver->wrap_driver = wrap_driver;
	ndis_driver->mp_driver_ctx = mp_driver_ctx;
	memcpy(&ndis_driver->mp_driver_chars, mp_driver_chars,
	       sizeof(ndis_driver->mp_driver_chars));
	*driver_handle = wrap_driver;
	if (mp_driver_chars->set_options) {
		NDIS_STATUS status;
		status = LIN2WIN2(mp_driver_chars->set_options, wrap_driver,
				  mp_driver_ctx);
		if (status != NDIS_STATUS_SUCCESS) {
			WARNING("failed: 0x%x", status);
			/* TODO: clean up */
			return NDIS_STATUS_FAILURE;
		}
	}
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisMDeregisterMiniportDriver,1)
	(void *driver_handle)
{
//	struct wrap_driver *wrap_driver = driver_handle;
	/* TODO */
}

wstdcall NDIS_STATUS WIN_FUNC(NdisSetOptionalHandlers,2)
	(void *handle, struct ndis_driver_optional_handlers *opt_handlers)
{
	struct wrap_driver *wrap_driver = handle;
	if (opt_handlers->header.type ==
	    NDIS_OBJECT_TYPE_MINIPORT_PNP_CHARACTERISTICS) {
		memcpy(&wrap_driver->ndis_driver->mp_pnp_chars, opt_handlers,
		       sizeof(wrap_driver->ndis_driver->mp_pnp_chars));
	} else
		WARNING("%d not supported", opt_handlers->header.type);
	return STATUS_SUCCESS;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisAllocateMemoryWithTag,3)
	(void **dest, UINT length, ULONG tag)
{
	void *res;
	res = ExAllocatePoolWithTag(NonPagedPool, length, tag);
	if (res) {
		*dest = res;
		TRACEEXIT4(return NDIS_STATUS_SUCCESS);
	} else
		TRACEEXIT4(return NDIS_STATUS_FAILURE);
}

wstdcall void *WIN_FUNC(NdisAllocateMemoryWithTagPriority,4)
	(struct ndis_miniport_block *nmb, UINT length, ULONG tag,
	 enum mm_page_priority priority)
{
	void *res;
	res = ExAllocatePoolWithTag(NonPagedPool, length, tag);
	TRACEEXIT4(return res);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisAllocateMemory,4)
	(void **dest, UINT length, UINT flags, NDIS_PHY_ADDRESS highest_address)
{
	return NdisAllocateMemoryWithTag(dest, length, 0);
}

/* length_tag is either length or tag, depending on if
 * NdisAllocateMemory or NdisAllocateMemoryTag is used to allocate
 * memory */
wstdcall void WIN_FUNC(NdisFreeMemory,3)
	(void *addr, UINT length_tag, UINT flags)
{
	ExFreePool(addr);
}

noregparm void WIN_FUNC(NdisWriteErrorLogEntry,12)
	(struct driver_object *drv_obj, ULONG error, ULONG count, ...)
{
	va_list args;
	int i;
	ULONG code;

	va_start(args, count);
	ERROR("log: %08X, count: %d, return_address: %p",
	      error, count, __builtin_return_address(0));
	for (i = 0; i < count; i++) {
		code = va_arg(args, ULONG);
		ERROR("code: 0x%x", code);
	}
	va_end(args);
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisOpenConfiguration,3)
	(NDIS_STATUS *status, struct ndis_miniport_block **conf_handle,
	 struct ndis_miniport_block *handle)
{
	TRACEENTER2("%p", conf_handle);
	*conf_handle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisOpenConfigurationEx,2)
	(struct ndis_configuration_object *object, void **handle)
{
	TRACEENTER2("%p", object);
	*handle = object->handle;
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisOpenProtocolConfiguration,3)
	(NDIS_STATUS *status, void **confhandle,
	 struct unicode_string *section)
{
	TRACEENTER2("%p", confhandle);
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisOpenConfigurationKeyByName,4)
	(NDIS_STATUS *status, void *handle,
	 struct unicode_string *key, void **subkeyhandle)
{
	struct ansi_string ansi;
	TRACEENTER2("");
	if (RtlUnicodeStringToAnsiString(&ansi, key, TRUE) == STATUS_SUCCESS) {
		DBGTRACE2("%s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	*subkeyhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisOpenConfigurationKeyByIndex,5)
	(NDIS_STATUS *status, void *handle, ULONG index,
	 struct unicode_string *key, void **subkeyhandle)
{
	TRACEENTER2("%u", index);
//	*subkeyhandle = handle;
	*status = NDIS_STATUS_FAILURE;
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisCloseConfiguration,1)
	(void *handle)
{
	/* instead of freeing all configuration parameters as we are
	 * supposed to do here, we free them when the device is
	 * removed */
	TRACEENTER2("%p", handle);
	return;
}

wstdcall void WIN_FUNC(NdisOpenFile,5)
	(NDIS_STATUS *status, struct wrap_bin_file **file,
	 UINT *filelength, struct unicode_string *filename,
	 NDIS_PHY_ADDRESS highest_address)
{
	struct ansi_string ansi;
	struct wrap_bin_file *bin_file;

	TRACEENTER2("%p, %d, %llx, %p", status, *filelength,
		    highest_address, *file);
	if (RtlUnicodeStringToAnsiString(&ansi, filename, TRUE) !=
	    STATUS_SUCCESS) {
		*status = NDIS_STATUS_RESOURCES;
		TRACEEXIT2(return);
	}
	DBGTRACE2("%s", ansi.buf);
	bin_file = get_bin_file(ansi.buf);
	if (bin_file) {
		*file = bin_file;
		*filelength = bin_file->size;
		*status = NDIS_STATUS_SUCCESS;
	} else
		*status = NDIS_STATUS_FILE_NOT_FOUND;

	RtlFreeAnsiString(&ansi);
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisMapFile,3)
	(NDIS_STATUS *status, void **mappedbuffer, struct wrap_bin_file *file)
{
	TRACEENTER2("%p", file);

	if (!file) {
		*status = NDIS_STATUS_ALREADY_MAPPED;
		TRACEEXIT2(return);
	}

	*status = NDIS_STATUS_SUCCESS;
	*mappedbuffer = file->data;
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisUnmapFile,1)
	(struct wrap_bin_file *file)
{
	TRACEENTER2("%p", file);
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisCloseFile,1)
	(struct wrap_bin_file *file)
{
	TRACEENTER2("%p", file);
	free_bin_file(file);
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisGetSystemUpTime,1)
	(ULONG *ms)
{
	TRACEENTER5("");
	*ms = 1000 * jiffies / HZ;
	TRACEEXIT5(return);
}

wstdcall void WIN_FUNC(NdisGetSystemUpTimeEx,1)
	(LARGE_INTEGER *ms)
{
	*ms = 1000 * jiffies / HZ;
}

wstdcall ULONG WIN_FUNC(NDIS_BUFFER_TO_SPAN_PAGES,1)
	(ndis_buffer *buffer)
{
	ULONG n, length;

	if (buffer == NULL)
		TRACEEXIT2(return 0);
	if (MmGetMdlByteCount(buffer) == 0)
		TRACEEXIT2(return 1);
	length = MmGetMdlByteCount(buffer);

#ifdef VT6655
	/* VIA VT6655 works with this bogus computation, but not with
	 * correct computation with SPAN_PAGES */
	do {
		ULONG_PTR start, end;
		unsigned long ptr;

		ptr = (unsigned long)MmGetMdlVirtualAddress(buffer);
		start = ptr & (PAGE_SIZE - 1);
		end = (ptr + length + PAGE_SIZE - 1) & PAGE_MASK;
		n = (end - start) / PAGE_SIZE;
	} while (0);
#else
	n = SPAN_PAGES(MmGetMdlVirtualAddress(buffer), length);
#endif
	DBGTRACE4("%p, %p, %d, %d", buffer->startva, buffer->mappedsystemva,
		  length, n);
	TRACEEXIT3(return n);
}

wstdcall void WIN_FUNC(NdisGetBufferPhysicalArraySize,2)
	(ndis_buffer *buffer, UINT *arraysize)
{
	TRACEENTER3("%p", buffer);
	*arraysize = NDIS_BUFFER_TO_SPAN_PAGES(buffer);
	TRACEEXIT3(return);
}

static struct ndis_configuration_parameter *
ndis_encode_setting(struct wrap_device_setting *setting,
		    enum ndis_parameter_type type)
{
	struct ansi_string ansi;
	struct ndis_configuration_parameter *param;

	param = setting->encoded;
	if (param) {
		if (param->type == type)
			TRACEEXIT2(return param);
		if (param->type == NdisParameterString)
			RtlFreeUnicodeString(&param->data.string);
		setting->encoded = NULL;
	} else
		param = ExAllocatePoolWithTag(NonPagedPool, sizeof(*param), 0);
	if (!param) {
		ERROR("couldn't allocate memory");
		return NULL;
	}
	switch(type) {
	case NdisParameterInteger:
		param->data.integer = simple_strtol(setting->value, NULL, 0);
		DBGTRACE2("%u", (ULONG)param->data.integer);
		break;
	case NdisParameterHexInteger:
		param->data.integer = simple_strtol(setting->value, NULL, 16);
		DBGTRACE2("%u", (ULONG)param->data.integer);
		break;
	case NdisParameterString:
		RtlInitAnsiString(&ansi, setting->value);
		DBGTRACE2("'%s'", ansi.buf);
		if (RtlAnsiStringToUnicodeString(&param->data.string,
						 &ansi, TRUE)) {
			ExFreePool(param);
			TRACEEXIT2(return NULL);
		}
		break;
	default:
		ERROR("unknown type: %d", type);
		ExFreePool(param);
		return NULL;
	}
	param->type = type;
	setting->encoded = param;
	TRACEEXIT2(return param);
}

static int ndis_decode_setting(struct wrap_device_setting *setting,
			       struct ndis_configuration_parameter *param)
{
	struct ansi_string ansi;
	struct ndis_configuration_parameter *prev;

	TRACEENTER2("%p, %p", setting, param);
	prev = setting->encoded;
	if (prev && prev->type == NdisParameterString) {
		RtlFreeUnicodeString(&prev->data.string);
		setting->encoded = NULL;
	}
	switch(param->type) {
	case NdisParameterInteger:
		snprintf(setting->value, sizeof(u32), "%u", param->data.integer);
		setting->value[sizeof(ULONG)] = 0;
		break;
	case NdisParameterHexInteger:
		snprintf(setting->value, sizeof(u32), "%x", param->data.integer);
		setting->value[sizeof(ULONG)] = 0;
		break;
	case NdisParameterString:
		ansi.buf = setting->value;
		ansi.max_length = MAX_SETTING_VALUE_LEN;
		if ((RtlUnicodeStringToAnsiString(&ansi, &param->data.string,
						  FALSE) != STATUS_SUCCESS)
		    || ansi.length >= MAX_SETTING_VALUE_LEN) {
			TRACEEXIT1(return -1);
		}
		if (ansi.length == ansi.max_length)
			ansi.length--;
		setting->value[ansi.length] = 0;
		break;
	default:
		DBGTRACE2("unknown setting type: %d", param->type);
		return -1;
	}
	DBGTRACE2("setting changed %s='%s', %d", setting->name, setting->value,
		  ansi.length);
	return 0;
}

wstdcall void WIN_FUNC(NdisReadConfiguration,5)
	(NDIS_STATUS *status, struct ndis_configuration_parameter **param,
	 struct wrap_ndis_device *wnd, struct unicode_string *key,
	 enum ndis_parameter_type type)
{
	struct wrap_device_setting *setting;
	struct ansi_string ansi;
	char *keyname;
	int ret;

	TRACEENTER2("nmb: %p", nmb);
	ret = RtlUnicodeStringToAnsiString(&ansi, key, TRUE);
	if (ret || ansi.buf == NULL) {
		*param = NULL;
		*status = NDIS_STATUS_FAILURE;
		RtlFreeAnsiString(&ansi);
		TRACEEXIT2(return);
	}
	DBGTRACE3("%d, %s", type, ansi.buf);
	keyname = ansi.buf;

	if (down_interruptible(&loader_mutex))
		WARNING("couldn't obtain loader_mutex");
	nt_list_for_each_entry(setting, &wnd->wd->settings, list) {
		if (strnicmp(keyname, setting->name, ansi.length) == 0) {
			DBGTRACE2("setting %s='%s'", keyname, setting->value);
			up(&loader_mutex);
			*param = ndis_encode_setting(setting, type);
			if (*param)
				*status = NDIS_STATUS_SUCCESS;
			else
				*status = NDIS_STATUS_FAILURE;
			RtlFreeAnsiString(&ansi);
			DBGTRACE2("%d", *status);
			TRACEEXIT2(return);
		}
	}
	up(&loader_mutex);
	DBGTRACE2("setting %s not found (type:%d)", keyname, type);
	*status = NDIS_STATUS_FAILURE;
	RtlFreeAnsiString(&ansi);
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisWriteConfiguration,4)
	(NDIS_STATUS *status, struct wrap_ndis_device *wnd,
	 struct unicode_string *key, struct ndis_configuration_parameter *param)
{
	struct ansi_string ansi;
	char *keyname;
	struct wrap_device_setting *setting;

	TRACEENTER2("wnd: %p", wnd);
	if (RtlUnicodeStringToAnsiString(&ansi, key, TRUE)) {
		*status = NDIS_STATUS_FAILURE;
		TRACEEXIT2(return);
	}
	keyname = ansi.buf;
	DBGTRACE2("%s", keyname);

	if (down_interruptible(&loader_mutex))
		WARNING("couldn't obtain loader_mutex");
	nt_list_for_each_entry(setting, &wnd->wd->settings, list) {
		if (strnicmp(keyname, setting->name, ansi.length) == 0) {
			up(&loader_mutex);
			if (ndis_decode_setting(setting, param))
				*status = NDIS_STATUS_FAILURE;
			else
				*status = NDIS_STATUS_SUCCESS;
			RtlFreeAnsiString(&ansi);
			TRACEEXIT2(return);
		}
	}
	up(&loader_mutex);
	setting = kmalloc(sizeof(*setting), GFP_KERNEL);
	if (setting) {
		memset(setting, 0, sizeof(*setting));
		if (ansi.length == ansi.max_length)
			ansi.length--;
		memcpy(setting->name, keyname, ansi.length);
		setting->name[ansi.length] = 0;
		if (ndis_decode_setting(setting, param))
			*status = NDIS_STATUS_FAILURE;
		else {
			*status = NDIS_STATUS_SUCCESS;
			if (down_interruptible(&loader_mutex))
				WARNING("couldn't obtain loader_mutex");
			InsertTailList(&wnd->wd->settings, &setting->list);
			up(&loader_mutex);
		}
	} else
		*status = NDIS_STATUS_RESOURCES;

	RtlFreeAnsiString(&ansi);
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisInitializeString,2)
	(struct unicode_string *dest, UCHAR *src)
{
	struct ansi_string ansi;

	TRACEENTER2("");
	if (src == NULL) {
		dest->length = dest->max_length = 0;
		dest->buf = NULL;
	} else {
		RtlInitAnsiString(&ansi, src);
		RtlAnsiStringToUnicodeString(dest, &ansi, TRUE);
	}
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisInitAnsiString,2)
	(struct ansi_string *dst, CHAR *src)
{
	RtlInitAnsiString(dst, src);
	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisInitUnicodeString,2)
	(struct unicode_string *dest, const wchar_t *src)
{
	RtlInitUnicodeString(dest, src);
	return;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisAnsiStringToUnicodeString,2)
	(struct unicode_string *dst, struct ansi_string *src)
{
	TRACEENTER2("");
	if (dst == NULL || src == NULL)
		TRACEEXIT2(return NDIS_STATUS_FAILURE);
	if (RtlAnsiStringToUnicodeString(dst, src, FALSE) == STATUS_SUCCESS)
		return NDIS_STATUS_SUCCESS;
	else
		return NDIS_STATUS_FAILURE;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisUnicodeStringToAnsiString,2)
	(struct ansi_string *dst, struct unicode_string *src)
{
	TRACEENTER2("");
	if (dst == NULL || src == NULL)
		TRACEEXIT2(return NDIS_STATUS_FAILURE);
	if (RtlUnicodeStringToAnsiString(dst, src, FALSE) == STATUS_SUCCESS)
		return NDIS_STATUS_SUCCESS;
	else
		return NDIS_STATUS_FAILURE;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMSetMiniportAttributes,2)
	(void *handle, union mp_adapter_attrs *mp_adapter_attrs)
{
	struct wrap_ndis_device *wnd = handle;
	struct ndis_object_header *header = handle;

	switch (header->type) {
	case NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES:
		memcpy(&wnd->registration_attrs, mp_adapter_attrs,
		       sizeof(wnd->registration_attrs));
		wnd->adapter_ctx = wnd->registration_attrs.ctx;
		break;
	case NDIS_OBJECT_TYPE_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES:
		memcpy(&wnd->add_device_attrs, mp_adapter_attrs,
		       sizeof(wnd->add_device_attrs));
		break;
	case NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES:
		memcpy(&wnd->general_attrs, mp_adapter_attrs,
		       sizeof(wnd->general_attrs));
		break;
	case NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES:
		memcpy(&wnd->native_802_11_attrs, mp_adapter_attrs,
		       sizeof(wnd->native_802_11_attrs));
		break;
	}
	return NDIS_STATUS_SUCCESS;
}

wstdcall void WIN_FUNC(NdisMSetAttributesEx,5)
	(struct wrap_ndis_device *wnd, void *adapter_ctx,
	 UINT hangcheck_interval, UINT attributes, ULONG adaptortype)
{
	TRACEENTER2("%p, %p %d %08x, %d", wnd, adapter_ctx,
		    hangcheck_interval, attributes, adaptortype);
	wnd->adapter_ctx = adapter_ctx;

	if (attributes & NDIS_ATTRIBUTE_BUS_MASTER)
		pci_set_master(wnd->wd->pci.pdev);

	wnd->attributes = attributes;

	if (hangcheck_interval > 0)
		wnd->hangcheck_interval = 2 * hangcheck_interval * HZ;
	else
		wnd->hangcheck_interval = 2 * HZ;

	TRACEEXIT2(return);
}

wstdcall ULONG WIN_FUNC(NdisReadPciSlotInformation,5)
	(struct wrap_ndis_device *wnd, ULONG slot, ULONG offset, char *buf,
	 ULONG len)
{
	struct wrap_device *wd = wnd->wd;
	ULONG i;
	for (i = 0; i < len; i++)
		if (pci_read_config_byte(wd->pci.pdev, offset + i, &buf[i]) !=
		    PCIBIOS_SUCCESSFUL)
			break;
	DBG_BLOCK(2) {
		if (i != len)
			WARNING("%u, %u", i, len);
	}
	return i;
}

wstdcall ULONG WIN_FUNC(NdisImmediateReadPciSlotInformation,5)
	(struct wrap_ndis_device *wnd, ULONG slot, ULONG offset, char *buf,
	 ULONG len)
{
	return NdisReadPciSlotInformation(wnd, slot, offset, buf, len);
}

wstdcall ULONG WIN_FUNC(NdisWritePciSlotInformation,5)
	(struct wrap_ndis_device *wnd, ULONG slot, ULONG offset, char *buf,
	 ULONG len)
{
	struct wrap_device *wd = wnd->wd;
	ULONG i;
	for (i = 0; i < len; i++)
		if (pci_write_config_byte(wd->pci.pdev, offset + i, buf[i]) !=
		    PCIBIOS_SUCCESSFUL)
			break;
	DBG_BLOCK(2) {
		if (i != len)
			WARNING("%u, %u", i, len);
	}
	return i;
}

wstdcall ULONG WIN_FUNC(NdisMGetBusData,5)
	(struct wrap_ndis_device *wnd, ULONG slot, ULONG offset, char *buf,
	 ULONG len)
{
	return NdisReadPciSlotInformation(wnd, slot, offset, buf, len);
}

wstdcall ULONG WIN_FUNC(NdisMSetBusData,5)
	(struct wrap_ndis_device *wnd, ULONG slot, ULONG offset, char *buf,
	 ULONG len)
{
	return NdisWritePciSlotInformation(wnd, slot, offset, buf, len);
}

wstdcall void WIN_FUNC(NdisReadPortUchar,3)
	(struct wrap_ndis_device *wnd, ULONG port, char *data)
{
	*data = inb(port);
}

wstdcall void WIN_FUNC(NdisImmediateReadPortUchar,3)
	(struct wrap_ndis_device *wnd, ULONG port, char *data)
{
	*data = inb(port);
}

wstdcall void WIN_FUNC(NdisWritePortUchar,3)
	(struct wrap_ndis_device *wnd, ULONG port, char data)
{
	outb(data, port);
}

wstdcall void WIN_FUNC(NdisImmediateWritePortUchar,3)
	(struct wrap_ndis_device *wnd, ULONG port, char data)
{
	outb(data, port);
}

wstdcall void WIN_FUNC(NdisAllocateSpinLock,1)
	(struct ndis_spinlock *lock)
{
	DBGTRACE4("lock %p, %lu", lock, lock->klock);
	KeInitializeSpinLock(&lock->klock);
	lock->irql = PASSIVE_LEVEL;
	TRACEEXIT4(return);
}

wstdcall void WIN_FUNC(NdisFreeSpinLock,1)
	(struct ndis_spinlock *lock)
{
	DBGTRACE4("lock %p, %lu", lock, lock->klock);
	TRACEEXIT4(return);
}

wstdcall void WIN_FUNC(NdisAcquireSpinLock,1)
	(struct ndis_spinlock *lock)
{
	DBGTRACE6("lock %p, %lu", lock, lock->klock);
	lock->irql = nt_spin_lock_irql(&lock->klock, DISPATCH_LEVEL);
	TRACEEXIT6(return);
}

wstdcall void WIN_FUNC(NdisReleaseSpinLock,1)
	(struct ndis_spinlock *lock)
{
	DBGTRACE6("lock %p, %lu", lock, lock->klock);
	nt_spin_unlock_irql(&lock->klock, lock->irql);
	TRACEEXIT6(return);
}

wstdcall void WIN_FUNC(NdisDprAcquireSpinLock,1)
	(struct ndis_spinlock *lock)
{
	TRACEENTER6("lock %p", lock);
	nt_spin_lock(&lock->klock);
	TRACEEXIT6(return);
}

wstdcall void WIN_FUNC(NdisDprReleaseSpinLock,1)
	(struct ndis_spinlock *lock)
{
	TRACEENTER6("lock %p", lock);
	nt_spin_unlock(&lock->klock);
	TRACEEXIT6(return);
}

/* TODO: implement these with read/write locks, instead of spinlocks */
wstdcall void WIN_FUNC(NdisInitializeReadWriteLock,1)
	(struct ndis_rw_lock *rw_lock)
{
	TRACEENTER3("%p", rw_lock);
	memset(rw_lock, 0, sizeof(*rw_lock));
	KeInitializeSpinLock(&rw_lock->u.s.klock);
	TRACEEXIT3(return);
}

wstdcall void WIN_FUNC(NdisAcquireReadWriteLock,3)
	(struct ndis_rw_lock *rw_lock, BOOLEAN write,
	 struct lock_state *lock_state)
{
	TRACEENTER3("%p", rw_lock);
	nt_spin_lock(&rw_lock->u.s.klock);
	TRACEEXIT3(return);
}

wstdcall void WIN_FUNC(NdisReleaseReadWriteLock,3)
	(struct ndis_rw_lock *rw_lock, struct lock_state *lock_state)
{
	TRACEENTER3("%p", rw_lock);
	nt_spin_unlock(&rw_lock->u.s.klock);
	TRACEEXIT3(return);
}

wstdcall struct net_buffer_pool *WIN_FUNC(NdisAllocateNetBufferPool,3)
	(struct wrap_ndis_device *wnd, struct net_buffer_pool_params *params)
{
	struct net_buffer_pool *pool;

	TRACEENTER2("%p, %u", wnd, params->data_size);
	pool = kmalloc(sizeof(*pool), gfp_irql());
	if (!pool) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	pool->data_length = params->data_size;
	pool->with_mdl = FALSE;
	pool->slist.next = NULL;
	pool->count = 0;
	DBGTRACE4("%p, %u", pool, pool->data_length);
	nt_spin_lock_init(&pool->lock);
	return pool;
}

wstdcall void WIN_FUNC(NdisFreeNetBufferPool,1)
	(struct net_buffer_pool *pool)
{
	TRACEENTER2("%p", pool);
	if (pool->count)
		WARNING("%d buffers not freed", pool->count);
	kfree(pool);
	TRACEEXIT4(return);
}

wstdcall struct net_buffer *WIN_FUNC(NdisAllocateNetBuffer,4)
	(struct net_buffer_pool *pool, struct mdl *mdl,
	 ULONG data_offset, SIZE_T data_length)
{
	struct net_buffer *buffer;
	KIRQL irql;

	/* TODO: use pool */
	TRACEENTER4("%p, %p, %u, %lu", pool, mdl, data_offset, data_length);
	irql = nt_spin_lock_irql(&pool->lock, DISPATCH_LEVEL);
	if (pool->count) {
		assert(pool->slist.next);
		buffer = container_of(pool->slist.next, struct net_buffer,
				      header.link.next);
		pool->slist.next = pool->slist.next->next;
		pool->count--;
	} else
		buffer = NULL;
	nt_spin_unlock_irql(&pool->lock, irql);
	if (!buffer) {
		buffer = kmalloc(sizeof(*buffer), gfp_irql());
		if (!buffer) {
			WARNING("couldn't allocate memory");
			return NULL;
		}
	}
	memset(buffer, 0, sizeof(*buffer));
	buffer->pool = pool;
	/* TODO: set current_mdl based on data offset */
	buffer->header.data.current_mdl = mdl;
	buffer->header.data.current_mdl_offset = data_offset;
	buffer->header.data.data_length.szlength = data_length;
	buffer->header.data.next = NULL;
	DBGTRACE4("%p", buffer);
	TRACEEXIT4(return buffer);
}

wstdcall void WIN_FUNC(NdisFreeNetBuffer,1)
	(struct net_buffer *buffer)
{
	struct net_buffer_pool *pool;
	KIRQL irql;

	TRACEENTER3("%p", buffer);
	pool = buffer->pool;
	irql = nt_spin_lock_irql(&pool->lock, DISPATCH_LEVEL);
	if (pool->count < MAX_ALLOCATED_NDIS_BUFFERS) {
		buffer->header.link.next = pool->slist.next;
		pool->slist.next = buffer->header.link.next;
		pool->count++;
	} else
		kfree(buffer);
	nt_spin_unlock_irql(&pool->lock, irql);
}

wstdcall struct net_buffer *WIN_FUNC(NdisAllocateNetBufferMdlAndData,1)
	(struct net_buffer_pool *pool)
{
	struct net_buffer *buffer;
	struct mdl *mdl;
	void *data;

	TRACEENTER4("%p", pool);
	data = kmalloc(pool->data_length, GFP_ATOMIC);
	if (!data) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	mdl = allocate_init_mdl(data, pool->data_length);
	if (!mdl) {
		kfree(data);
		return NULL;
	}
	buffer = NdisAllocateNetBuffer(pool, mdl, 0, pool->data_length);
	DBGTRACE4("%p, %p", mdl, buffer);
	return buffer;
}

wstdcall void *WIN_FUNC(NdisGetDataBuffer,5)
	(struct net_buffer *buffer, ULONG bytes_needed, void *storage,
	 UINT alignment, UINT align_offset)
{
	void *data;

	TRACEENTER3("%p, %u, %p, %u, %u", buffer, bytes_needed, storage,
		    alignment, align_offset);
	if (buffer->header.data.data_length.ulength < bytes_needed ||
	    storage == NULL)
		TRACEEXIT2(return NULL);
	/* data is always contiguous, and only one MDL maps it */
	data = MmGetSystemAddressForMdl(buffer->header.data.current_mdl);
	DBGTRACE3("%p", data);
	return data;
}

wstdcall struct net_buffer_list_pool *WIN_FUNC(NdisAllocateNetBufferListPool,2)
	(struct wrap_ndis_device *wnd,
	 struct net_buffer_list_pool_params *params)
{
	struct net_buffer_list_pool *pool;

	TRACEENTER2("%p, %u", wnd, params->ctx_size);
	pool = kmalloc(sizeof(*pool), gfp_irql());
	if (!pool) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	pool->ctx_length = params->ctx_size;
	if (params->fallocate_net_buffer) {
		struct net_buffer_pool_params buffer_params;
		pool->flags = NDIS_WRAPPER_POOL_FLAGS_ALLOC_BUFFER;
		buffer_params.data_size = params->data_size;
		pool->buffer_pool =
			NdisAllocateNetBufferPool(wnd, &buffer_params);
		if (!pool->buffer_pool) {
			kfree(pool);
			TRACEEXIT2(return NULL);
		}
	} else {
		pool->list_pool.data_length = params->data_size;
		pool->flags = 0;
	}

	pool->list_pool.count = 0;
	pool->list_pool.slist.next = NULL;
	nt_spin_lock_init(&pool->list_pool.lock);
	DBGTRACE4("%p", pool);
	return pool;
}

wstdcall void WIN_FUNC(NdisFreeNetBufferListPool,2)
	(struct net_buffer_list_pool *pool)
{
	TRACEENTER2("%p", pool);
	if (pool->flags & NDIS_WRAPPER_POOL_FLAGS_ALLOC_BUFFER)
		NdisFreeNetBufferPool(pool->buffer_pool);
	if (pool->list_pool.count)
		WARNING("%d buffers not freed", pool->list_pool.count);
	kfree(pool);
	return;
}

wstdcall void WIN_FUNC(NdisFreeNetBufferList,1)
	(struct net_buffer_list *buffer_list)
{
	struct net_buffer_list_pool *pool;
	struct net_buffer_list_context *ctx;
	KIRQL irql;
	struct net_buffer *buffer;

	TRACEENTER3("%p", buffer_list);
	buffer = buffer_list->header.data.first_buffer;
	while (buffer) {
		struct net_buffer *next;
		next = (struct net_buffer *)buffer->header.link.next;
		NdisFreeNetBuffer(buffer);
		buffer = next;
	}
	ctx = buffer_list->context;
	while (ctx) {
		struct net_buffer_list_context *next = ctx;
		kfree(ctx);
		ctx = next;
	}
	pool = buffer_list->pool;
	irql = nt_spin_lock_irql(&pool->list_pool.lock, DISPATCH_LEVEL);
	if (pool->list_pool.count < MAX_ALLOCATED_NDIS_BUFFERS) {
		buffer_list->header.link.next = pool->list_pool.slist.next;
		pool->list_pool.slist.next = buffer->header.link.next;
		pool->list_pool.count++;
	} else
		kfree(buffer_list);
	nt_spin_unlock_irql(&pool->list_pool.lock, irql);
}

wstdcall struct net_buffer_list *WIN_FUNC(NdisAllocateNetBufferList,3)
	(struct net_buffer_list_pool *pool, USHORT ctx_size,
	 USHORT backfill)
{
	struct net_buffer_list *buffer_list;
	KIRQL irql;

	irql = nt_spin_lock_irql(&pool->list_pool.lock, DISPATCH_LEVEL);
	if (pool->list_pool.count) {
		assert(pool->list_pool.slist.next);
		buffer_list = container_of(pool->list_pool.slist.next,
					   struct net_buffer_list,
					   header.link.next);
		pool->list_pool.slist.next = pool->list_pool.slist.next->next;
		pool->list_pool.count--;
	} else
		buffer_list = NULL;
	nt_spin_unlock_irql(&pool->list_pool.lock, irql);
	if (!buffer_list) {
		buffer_list = kmalloc(sizeof(*buffer_list), gfp_irql());
		if (!buffer_list) {
			WARNING("couldn't allocate memory");
			return NULL;
		}
	}
	memset(buffer_list, 0, sizeof(*buffer_list));
	buffer_list->pool = pool;
	if (ctx_size || pool->ctx_length) {
		int size = max_t(int, ctx_size + backfill, pool->ctx_length) +
			sizeof(*(buffer_list->context));
		buffer_list->context = kmalloc(size, GFP_ATOMIC);
		if (!buffer_list->context) {
			WARNING("couldn't allocate memory");
			NdisFreeNetBufferList(buffer_list);
			return NULL;
		}
		buffer_list->context->size = size;
		buffer_list->context->offset = size;
	}
	if (pool->flags & NDIS_WRAPPER_POOL_FLAGS_ALLOC_BUFFER) {
		buffer_list->header.data.first_buffer =
			NdisAllocateNetBufferMdlAndData(pool->buffer_pool);
		if (!buffer_list->header.data.first_buffer) {
			kfree(buffer_list);
			TRACEEXIT2(return NULL);
		}
	}
	buffer_list->header.data.next = NULL;
	return buffer_list;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisAllocateNetBufferListContext,4)
	(struct net_buffer_list *buffer_list, USHORT ctx_size, USHORT backfill,
	 ULONG pool_tag)
{
	struct net_buffer_list_context *ctx;

	TRACEENTER3("%p, %u, %u", buffer_list, ctx_size, backfill);

	/* TODO: how is this context list organized in buffer_list? 
	 * newer members are added to the end of list or front (as in
	 * the case of MDL)? */
	if (!buffer_list->context || buffer_list->context->offset < ctx_size) {
		ctx = kmalloc(sizeof(*ctx) + ctx_size + backfill, GFP_ATOMIC);
		if (!ctx) {
			WARNING("couldn't allocate memory");
			return NDIS_STATUS_RESOURCES;
		}
		DBGTRACE3("%p, %u, %u", ctx, ctx_size, backfill);
		ctx->size = ctx->offset = ctx_size + backfill;
		ctx->next = buffer_list->context;
		buffer_list->context = ctx;
	} else
		ctx = buffer_list->context;

	ctx->offset -= ctx_size;
	DBGTRACE3("%p, %u, %u", ctx, ctx->offset, ctx->size);
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisFreeNetBufferListContext,2)
	(struct net_buffer_list *buffer_list, USHORT ctx_size)
{
	struct net_buffer_list_context *next, *ctx = buffer_list->context;

	TRACEENTER3("%p, %p", buffer_list, ctx);
	if (!ctx) {
		WARNING("invalid context");
		return;
	}
	DBGTRACE3("%p, %u, %u, %u", ctx, ctx->offset, ctx->size, ctx_size);
	if (ctx->offset + ctx_size < ctx->size) {
		ctx->offset += ctx_size;
		return;
	}
	while (ctx && ctx->offset + ctx_size >= ctx->size) {
		ctx_size -= ctx->offset;
		next = ctx->next;
		kfree(ctx);
		ctx = next;
	}
	return;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisRetreatNetBufferDataStart,4)
	(struct net_buffer *buffer, ULONG offset, ULONG backfill,
	 struct mdl *(*alloc_handler)(void *, int) wstdcall)
{
	TRACEENTER2("%p, %d, %d, %p", buffer, offset, backfill, alloc_handler);
	/* TODO: most definitely this is wrong */
	if (buffer->header.data.data_offset < offset) {
		struct mdl *mdl;
		int length = max_t(int, offset + backfill, 80);
		void *buf = kmalloc(length, GFP_ATOMIC);
		if (!buf) {
			WARNING("couldn't allocate memory: %d", length);
			return NDIS_STATUS_RESOURCES;
		}
		if (alloc_handler)
			mdl = LIN2WIN2(alloc_handler, buf, length);
		else
			mdl = allocate_init_mdl(buf, length);
		if (!mdl) {
			kfree(buf);
			return NDIS_STATUS_RESOURCES;
		}
		mdl->next = buffer->header.data.mdl_chain;
		buffer->header.data.mdl_chain = mdl;
		buffer->header.data.data_offset = length - offset;
	} else {
		buffer->header.data.data_offset -= offset;
		DBGTRACE3("%p, %u", buffer, buffer->header.data.data_offset);
	}

	return NDIS_STATUS_SUCCESS;
}

wstdcall void WIN_FUNC(NdisAdvanceNetBufferDataStart,4)
	(struct net_buffer *buffer, ULONG offset, BOOLEAN need_free_mdl,
	 void (*free_handler)(struct mdl *) wstdcall)
{
	struct mdl *mdl;

	/* TODO: most definitely this is wrong */
	while (1) {
		mdl = buffer->header.data.mdl_chain;
		if (offset < MmGetMdlByteCount(mdl))
			break;
		buffer->header.data.mdl_chain = mdl->next;
		offset -= MmGetMdlByteCount(mdl);
		if (need_free_mdl) {
			if (free_handler)
				LIN2WIN1(free_handler, mdl);
			else
				free_mdl(mdl);
		}
	}
	buffer->header.data.data_offset = offset;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisRetreatNetBufferListDataStart,5)
	(struct net_buffer_list *buffer_list, ULONG offset, ULONG backfill,
	 void *alloc_handler, void *free_handler)
{
	struct net_buffer *buffer;
	NDIS_STATUS status;

	TRACEENTER3("%p, %u, %u, %p, %p", buffer_list, offset, backfill,
		    alloc_handler, free_handler);

	for ( ; buffer_list; buffer_list = buffer_list->header.data.next) {
		buffer = buffer_list->header.data.first_buffer;
		status = NdisRetreatNetBufferDataStart(buffer, offset, backfill,
						       alloc_handler);
		if (status != NDIS_STATUS_SUCCESS)
			TRACEEXIT2(return status);
	}
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisAdvanceNetBufferListDataStart,4)
	(struct net_buffer_list *buffer_list, ULONG offset,
	 BOOLEAN need_free_mdl, void *free_handler)
{
	struct net_buffer *buffer;

	TRACEENTER3("%p, %u, %d, %p", buffer_list, offset, need_free_mdl,
		    free_handler);
	for ( ; buffer_list; buffer_list = buffer_list->header.data.next) {
		buffer = buffer_list->header.data.first_buffer;
		NdisAdvanceNetBufferDataStart(buffer, offset, need_free_mdl,
					      free_handler);
	}
	TRACEEXIT2(return);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMInitializeScatterGatherDma,3)
	(struct wrap_ndis_device *wnd, BOOLEAN dma_size, ULONG max_phy_map)
{
	TRACEENTER2("dma_size=%d, maxtransfer=%u", dma_size, max_phy_map);
#ifdef CONFIG_X86_64
	if (dma_size != NDIS_DMA_64BITS)
		ERROR("DMA size is not 64-bits");
#endif
	wnd->use_sg_dma = TRUE;
	return NDIS_STATUS_SUCCESS;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMRegisterScatterGatherDma,3)
	(struct wrap_ndis_device *wnd, struct ndis_sg_dma_description *sg_descr,
	 struct ndis_sg_dma_handle **dma_handle)
{
	TRACEENTER2("%p", wnd);
#ifdef CONFIG_X86_64
	if (dma_size != NDIS_DMA_64BITS)
		ERROR("DMA size is not 64-bits");
#endif
	*dma_handle = kmalloc(sizeof(**dma_handle), GFP_ATOMIC);
	if (!*dma_handle) {
		WARNING("couldn't allocate memory");
		return NDIS_STATUS_RESOURCES;
	}
	wnd->use_sg_dma = TRUE;
	(*dma_handle)->sg_list_handler = sg_descr->sg_list_handler;
	(*dma_handle)->shared_mem_alloc_complete_handler =
		sg_descr->shared_mem_alloc_complete_handler;
	(*dma_handle)->max_physical_map = sg_descr->max_physical_map;
	(*dma_handle)->wnd = wnd;
	return NDIS_STATUS_SUCCESS;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMDeregisterScatterGatherDma,3)
	(struct ndis_sg_dma_handle *dma_handle)
{
	struct wrap_ndis_device *wnd = dma_handle->wnd;
	wnd->use_sg_dma = FALSE;
	kfree(dma_handle);
	return NDIS_STATUS_SUCCESS;
}

wstdcall ULONG WIN_FUNC(NdisMGetDmaAlignment,1)
	(struct wrap_ndis_device *wnd)
{
	TRACEENTER3("");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	return dma_get_cache_alignment();
#else
	return L1_CACHE_BYTES;
#endif
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMAllocateNetBufferSGList,6)
	(struct ndis_sg_dma_handle *dma_handle, struct net_buffer *buffer,
	 void *ctx, ULONG flags, struct ndis_sg_list *sg_list, ULONG size)
{
	int i, n, dir, alloc;
	struct net_buffer *b;
	struct ndis_sg_element *sg_elements;

	/* only one net buffer and one mdl should be in buffer */
	/* TODO: one buffer may have more than one mdl */
	for (n = 0, b = buffer; b; b = b->header.data.next)
		n++;
	if (sg_list == NULL ||
	    size < sizeof(*sg_list) + n * sizeof(*sg_elements)) {
		size = sizeof(*sg_list) + n * sizeof(*sg_elements);
		sg_list = kmalloc(size, GFP_ATOMIC);
		if (!sg_list) {
			WARNING("couldn't allocate memory");
			return NDIS_STATUS_RESOURCES;
		}
		alloc = 1;
	} else
		alloc = 0;

	if (flags & NDIS_SG_LIST_WRITE_TO_DEVICE)
		dir = PCI_DMA_TODEVICE;
	else
		dir = PCI_DMA_FROMDEVICE;

	sg_list->nent = n;
	sg_list->reserved = flags & NDIS_SG_LIST_WRITE_TO_DEVICE;
	if (alloc)
		sg_list->reserved |= NDIS_SG_LIST_WRAP_ALLOC;
	sg_elements = sg_list->elements;
	for (i = 0, b = buffer; i < n && b; i++, b = b->header.data.next) {
		struct mdl *mdl = b->header.data.current_mdl;
		sg_elements[i].length = MmGetMdlByteCount(mdl);
		sg_elements[i].address =
			PCI_DMA_MAP_SINGLE(dma_handle->wnd->wd->pci.pdev,
					   MmGetMdlVirtualAddress(mdl),
					   sg_elements[i].length, dir);
	}
	LIN2WIN4(dma_handle->sg_list_handler, dma_handle->wnd->pdo, NULL,
		 sg_list, ctx);
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisMFreeNetBufferSGList,6)
	(struct ndis_sg_dma_handle *dma_handle, struct ndis_sg_list *sg_list,
	 struct net_buffer *buffer)
{
	int i, dir;
	struct ndis_sg_element *sg_elements;

	TRACEENTER2("%p, %p, %p", dma_handle, sg_list, buffer);
	if (sg_list->reserved & NDIS_SG_LIST_WRITE_TO_DEVICE)
		dir = PCI_DMA_TODEVICE;
	else
		dir = PCI_DMA_FROMDEVICE;
	sg_elements = sg_list->elements;
	for (i = 0; i < sg_list->nent; i++) {
		PCI_DMA_UNMAP_SINGLE(dma_handle->wnd->wd->pci.pdev,
				     sg_elements[i].address,
				     sg_elements[i].length, dir);
	}
	if (sg_list->reserved & NDIS_SG_LIST_WRAP_ALLOC)
		kfree(sg_list);
	TRACEEXIT4(return);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisAllocateTimerObject,3)
	(struct wrap_ndis_device *wnd,
	 struct ndis_timer_characteristics *timer_chars, void **timer_object)
{
	struct ndis_timer *timer;
	timer = kmalloc(sizeof(*timer), gfp_irql());
	if (!timer) {
		WARNING("couldn't allocate memory");
		return NDIS_STATUS_RESOURCES;
	}
	memset(timer, 0, sizeof(*timer));
	KeInitializeDpc(&timer->kdpc, timer_chars->func, timer_chars->ctx);
	wrap_init_timer(&timer->nt_timer, NotificationTimer, &timer->kdpc, NULL);
	*timer_object = timer;
	TRACEEXIT3(return NDIS_STATUS_SUCCESS);
}

wstdcall BOOLEAN WIN_FUNC(NdisSetTimerObject,4)
	(struct ndis_timer *timer, LARGE_INTEGER duetime_ticks, ULONG period_ms,
	 void *ctx)
{
	unsigned long expires_hz, repeat_hz;

	expires_hz = SYSTEM_TIME_TO_HZ(duetime_ticks) + 1;
	if (period_ms)
		repeat_hz = MSEC_TO_HZ(period_ms);
	else
		repeat_hz = 0;
	TRACEENTER4("%p, %lu, %lu", timer, expires_hz, repeat_hz);
	if (ctx)
		timer->kdpc.ctx = ctx;
	return wrap_set_timer(&timer->nt_timer, expires_hz, repeat_hz, NULL);
}

wstdcall BOOLEAN WIN_FUNC(NdisCancelTimerObject,1)
	(struct ndis_timer *timer)
{
	return KeCancelTimer(&timer->nt_timer);
}

wstdcall void WIN_FUNC(NdisFreeTimerObject,1)
	(struct ndis_timer *timer)
{
	wrap_free_timer(&timer->nt_timer);
	kfree(timer);
}

wstdcall void WIN_FUNC(NdisMOidRequestComplete,3)
	(struct wrap_ndis_device *wnd, struct ndis_oid_request *oid_request,
	 NDIS_STATUS status)
{
	TRACEENTER2("wnd: %p, %08X", wnd, status);
	wnd->ndis_comm_status = status;
	wnd->ndis_comm_done = 1;
	wake_up(&wnd->ndis_comm_wq);
	TRACEEXIT2(return);
}

wstdcall struct mdl *WIN_FUNC(NdisAllocateMdl,3)
	(void *handle, void *virt, UINT length)
{
	struct mdl *mdl;

	TRACEENTER3("%p, %p, %u", handle, virt, length);
	mdl = allocate_init_mdl(virt, length);
	DBGTRACE3("%p", mdl);
	return mdl;
}

wstdcall void WIN_FUNC(NdisFreeMdl,1)
	(struct mdl *mdl)
{
	TRACEENTER3("%p", mdl);
	free_mdl(mdl);
}

wstdcall void wrap_miniport_timer(struct kdpc *kdpc, void *ctx, void *arg1,
				  void *arg2)
{
	struct ndis_miniport_timer *timer;
	struct wrap_ndis_device *wnd;

	timer = ctx;
	TRACEENTER5("timer: %p, func: %p, ctx: %p, wnd: %p",
		    timer, timer->func, timer->ctx, timer->wnd);
	wnd = timer->wnd;
	/* already called at DISPATCH_LEVEL */
	if (!deserialized_driver(wnd))
		serialize_lock(wnd);
	LIN2WIN4(timer->func, NULL, timer->ctx, NULL, NULL);
	if (!deserialized_driver(wnd))
		serialize_unlock(wnd);
	TRACEEXIT5(return);
}
WIN_FUNC_DECL(wrap_miniport_timer,4)

wstdcall void WIN_FUNC(NdisMInitializeTimer,4)
	(struct ndis_miniport_timer *timer, struct wrap_ndis_device *wnd,
	 DPC func, void *ctx)
{
	TRACEENTER4("timer: %p, func: %p, ctx: %p, wnd: %p",
		    timer, func, ctx, wnd);
	timer->func = func;
	timer->ctx = ctx;
	timer->wnd = wnd;
//	KeInitializeDpc(&timer->kdpc, func, ctx);
	KeInitializeDpc(&timer->kdpc, WIN_FUNC_PTR(wrap_miniport_timer,4),
			timer);
	wrap_init_timer(&timer->nt_timer, NotificationTimer, &timer->kdpc, wnd);
	TRACEEXIT4(return);
}

wstdcall void WIN_FUNC(NdisMSetPeriodicTimer,2)
	(struct ndis_miniport_timer *timer, UINT period_ms)
{
	unsigned long expires = MSEC_TO_HZ(period_ms) + 1;

	TRACEENTER4("%p, %u, %ld", timer, period_ms, expires);
	wrap_set_timer(&timer->nt_timer, expires, expires, NULL);
	TRACEEXIT4(return);
}

wstdcall void WIN_FUNC(NdisMCancelTimer,2)
	(struct ndis_miniport_timer *timer, BOOLEAN *canceled)
{
	TRACEENTER4("%p", timer);
	*canceled = KeCancelTimer(&timer->nt_timer);
	TRACEEXIT4(return);
}

wstdcall void WIN_FUNC(NdisInitializeTimer,3)
	(struct ndis_timer *timer, void *func, void *ctx)
{
	TRACEENTER4("%p, %p, %p", timer, func, ctx);
	KeInitializeDpc(&timer->kdpc, func, ctx);
	wrap_init_timer(&timer->nt_timer, NotificationTimer, &timer->kdpc, NULL);
	TRACEEXIT4(return);
}

/* NdisMSetTimer is a macro that calls NdisSetTimer with
 * ndis_miniport_timer typecast to ndis_timer */

wstdcall void WIN_FUNC(NdisSetTimer,2)
	(struct ndis_timer *timer, UINT duetime_ms)
{
	unsigned long expires = MSEC_TO_HZ(duetime_ms) + 1;

	TRACEENTER4("%p, %p, %u, %ld", timer, timer->nt_timer.wrap_timer,
		    duetime_ms, expires);
	wrap_set_timer(&timer->nt_timer, expires, 0, NULL);
	TRACEEXIT4(return);
}

wstdcall void WIN_FUNC(NdisCancelTimer,2)
	(struct ndis_timer *timer, BOOLEAN *canceled)
{
	TRACEENTER4("%p", timer);
	*canceled = KeCancelTimer(&timer->nt_timer);
	TRACEEXIT4(return);
}

wstdcall void WIN_FUNC(NdisReadNetworkAddress,4)
	(NDIS_STATUS *status, void **addr, UINT *len,
	 struct wrap_ndis_device *wnd)
{
	struct ndis_configuration_parameter *param;
	struct unicode_string key;
	struct ansi_string ansi;
	int ret;

	TRACEENTER1("");
	RtlInitAnsiString(&ansi, "mac_address");
	*len = 0;
	*status = NDIS_STATUS_FAILURE;
	if (RtlAnsiStringToUnicodeString(&key, &ansi, TRUE) != STATUS_SUCCESS)
		TRACEEXIT1(return);

	NdisReadConfiguration(status, &param, wnd, &key, NdisParameterString);
	RtlFreeUnicodeString(&key);

	if (*status == NDIS_STATUS_SUCCESS) {
		int int_mac[ETH_ALEN];
		ret = RtlUnicodeStringToAnsiString(&ansi, &param->data.string,
						   TRUE);
		if (ret != NDIS_STATUS_SUCCESS)
			TRACEEXIT1(return);

		ret = sscanf(ansi.buf, MACSTRSEP, MACINTADR(int_mac));
		if (ret != ETH_ALEN)
			ret = sscanf(ansi.buf, MACSTR, MACINTADR(int_mac));
		RtlFreeAnsiString(&ansi);
		if (ret == ETH_ALEN) {
			int i;
			for (i = 0; i < ETH_ALEN; i++)
				wnd->mac[i] = int_mac[i];
			printk(KERN_INFO "%s: %s ethernet device " MACSTRSEP
			       "\n", wnd->net_dev->name, DRIVER_NAME,
			       MAC2STR(wnd->mac));
			*len = ETH_ALEN;
			*addr = wnd->mac;
			*status = NDIS_STATUS_SUCCESS;
		}
	}

	TRACEEXIT1(return);
}

wstdcall void WIN_FUNC(NdisMRegisterAdapterShutdownHandler,3)
	(struct wrap_ndis_device *wnd, void *ctx, void *func)
{
	TRACEENTER1("%p", func);
	wnd->wd->driver->ndis_driver->miniport.shutdown = func;
	wnd->shutdown_ctx = ctx;
}

wstdcall void WIN_FUNC(NdisMDeregisterAdapterShutdownHandler,1)
	(struct wrap_ndis_device *wnd)
{
	wnd->wd->driver->ndis_driver->miniport.shutdown = NULL;
	wnd->shutdown_ctx = NULL;
}

static void ndis_irq_handler(unsigned long data)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;
	struct miniport_char *miniport;

	miniport = &wnd->wd->driver->ndis_driver->miniport;
	if_serialize_lock(wnd);
	LIN2WIN1(miniport->handle_interrupt, wnd->adapter_ctx);
	if (miniport->enable_interrupt)
		LIN2WIN1(miniport->enable_interrupt, wnd->adapter_ctx);
	if_serialize_unlock(wnd);
}

irqreturn_t mp_isr(int irq, void *data ISR_PT_REGS_PARAM_DECL)
{
	struct ndis_interrupt *interrupt = data;
	struct wrap_ndis_device *wnd = interrupt->wnd;
	struct miniport_char *miniport;
	BOOLEAN recognized, queue_handler;
	ULONG proc = 0;

	miniport = &wnd->wd->driver->ndis_driver->miniport;
	/* this spinlock should be shared with NdisMSynchronizeWithInterrupt
	 */
	nt_spin_lock(&interrupt->lock);
#if 0
	recognized = LIN2WIN2(miniport->isr, &queue_handler, &proc);
#else
	recognized = queue_handler = 0;
#endif
	nt_spin_unlock(&ndis_irq->lock);
	/* TODO: schedule worker on processors indicated */
	if (recognized) {
		if (queue_handler || proc)
			tasklet_schedule(&wnd->irq_tasklet);
		return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMRegisterInterruptEx,4)
	(struct wrap_ndis_device *wnd, void *isr_ctx,
	 struct mp_interrupt_characteristics *mp_interrupt_chars,
	 void **handle)
{
	struct ndis_interrupt *interrupt = &wnd->interrupt;

	TRACEENTER1("%p, %p", wnd, isr_ctx);
	interrupt->wnd = wnd;
	nt_spin_lock_init(&interrupt->lock);
	tasklet_init(&wnd->irq_tasklet, ndis_irq_handler, (unsigned long)wnd);
	if (request_irq(wnd->interrupt.vector, mp_isr, SA_SHIRQ,
			wnd->net_dev->name, interrupt)) {
		printk(KERN_WARNING "%s: request for IRQ %d failed\n",
		       DRIVER_NAME, wnd->interrupt.vector);
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	}
	printk(KERN_INFO "%s: using IRQ %d\n",
	       DRIVER_NAME, wnd->interrupt.vector);
	*handle = interrupt;
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisMDeregisterInterruptEx,1)
	(struct ndis_interrupt *interrupt)
{
	struct wrap_ndis_device *wnd;

	TRACEENTER1("%p", interrupt);

	if (!interrupt)
		TRACEEXIT1(return);
	wnd = interrupt->wnd;
	if (!wnd)
		TRACEEXIT1(return);

	free_irq(wnd->interrupt.vector, wnd);
	tasklet_kill(&wnd->irq_tasklet);
	TRACEEXIT1(return);
}

wstdcall BOOLEAN WIN_FUNC(NdisMSynchronizeWithInterruptEx,3)
	(struct ndis_interrupt *interrupt, ULONG msg_id, void *func, void *ctx)
{
	BOOLEAN ret;
	BOOLEAN (*sync_func)(void *ctx) wstdcall;
	unsigned long flags;

	TRACEENTER6("%p %p", func, ctx);
	sync_func = func;
	nt_spin_lock_irqsave(&interrupt->lock, flags);
	ret = LIN2WIN1(sync_func, ctx);
	nt_spin_unlock_irqrestore(&interrupt->lock, flags);
	DBGTRACE6("ret: %d", ret);
	TRACEEXIT6(return ret);
}

/* called via function pointer; but 64-bit RNDIS driver calls directly */
wstdcall void WIN_FUNC(NdisMIndicateStatusEx,4)
	(struct wrap_ndis_device *wnd, struct ndis_status_indication *status)
{
//	struct ndis_auth_req *auth_req;
//	struct ndis_radio_status_indication *radio_status;
	struct ndis_link_state *link_state;

	TRACEENTER2("status=0x%x", status->code);
	if (status->header.type !=  NDIS_OBJECT_TYPE_STATUS_INDICATION) {
		ERROR("invalid status: 0x%x", status->header.type);
		return;
	}

	switch (status->code) {
	case NDIS_STATUS_LINK_STATE:
		link_state = status->buf;
		if (link_state->media_connect_state ==
		    MediaConnectStateConnected) {
			netif_carrier_on(wnd->net_dev);
			set_bit(LINK_STATUS_CHANGED,
				&wnd->wrap_ndis_pending_work);
			schedule_wrap_work(&wnd->wrap_ndis_work);
		} else if (link_state->media_connect_state ==
			   MediaConnectStateConnected) {
			netif_carrier_on(wnd->net_dev);
			set_bit(LINK_STATUS_CHANGED,
				&wnd->wrap_ndis_pending_work);
			schedule_wrap_work(&wnd->wrap_ndis_work);
		}
		break;
	default:
		DBGTRACE2("unknown status: %08X", status->code);
		break;
	}

	TRACEEXIT2(return);
}

wstdcall void WIN_FUNC(NdisMIndicateReceiveNetBufferLists,5)
	(struct wrap_ndis_device *wnd, struct net_buffer_list *buffer_list,
	NDIS_PORT_NUMBER port, ULONG num_lists, ULONG rx_flags)
{

}

wstdcall void WIN_FUNC(NdisMSendNetBufferListsComplete,3)
	(struct wrap_ndis_device *wnd, struct net_buffer_list *buffer_list,
	 ULONG flags)
{
	struct net_buffer_list *blist, *next;

	blist = buffer_list;
	while (blist) {
		next = blist->header.data.next;
		free_tx_buffer_list(wnd, blist);
		blist = next;
	}
}

wstdcall void WIN_FUNC(NdisMSleep,1)
	(ULONG us)
{
	unsigned long delay;

	TRACEENTER4("%p: us: %u", current, us);
	delay = USEC_TO_HZ(us);
	sleep_hz(delay);
	DBGTRACE4("%p: done", current);
}

wstdcall void WIN_FUNC(NdisGetCurrentSystemTime,1)
	(LARGE_INTEGER *time)
{
	*time = ticks_1601();
	DBGTRACE5("%Lu, %lu", *time, jiffies);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMRegisterIoPortRange,4)
	(void **virt, struct wrap_ndis_device *wnd, UINT start, UINT len)
{
	TRACEENTER3("%08x %08x", start, len);
	*virt = (void *)(ULONG_PTR)start;
	return NDIS_STATUS_SUCCESS;
}

wstdcall void WIN_FUNC(NdisMDeregisterIoPortRange,4)
	(struct wrap_ndis_device *wnd, UINT start, UINT len, void* virt)
{
	TRACEENTER1("%08x %08x", start, len);
}

wstdcall LONG WIN_FUNC(NdisInterlockedDecrement,1)
	(LONG *val)
{
	return InterlockedDecrement(val);
}

wstdcall LONG WIN_FUNC(NdisInterlockedIncrement,1)
	(LONG *val)
{
	return InterlockedIncrement(val);
}

wstdcall struct nt_list *WIN_FUNC(NdisInterlockedInsertHeadList,3)
	(struct nt_list *head, struct nt_list *entry,
	 struct ndis_spinlock *lock)
{
	return ExInterlockedInsertHeadList(head, entry, &lock->klock);
}

wstdcall struct nt_list *WIN_FUNC(NdisInterlockedInsertTailList,3)
	(struct nt_list *head, struct nt_list *entry,
	 struct ndis_spinlock *lock)
{
	return ExInterlockedInsertTailList(head, entry, &lock->klock);
}

wstdcall struct nt_list *WIN_FUNC(NdisInterlockedRemoveHeadList,2)
	(struct nt_list *head, struct ndis_spinlock *lock)
{
	return ExInterlockedRemoveHeadList(head, &lock->klock);
}

wstdcall CHAR WIN_FUNC(NdisSystemProcessorCount,0)
	(void)
{
	return NR_CPUS;
}

wstdcall void WIN_FUNC(NdisInitializeEvent,1)
	(struct ndis_event *ndis_event)
{
	TRACEENTER3("%p", ndis_event);
	KeInitializeEvent(&ndis_event->nt_event, NotificationEvent, 0);
}

wstdcall BOOLEAN WIN_FUNC(NdisWaitEvent,2)
	(struct ndis_event *ndis_event, UINT ms)
{
	LARGE_INTEGER ticks;
	NTSTATUS res;

	TRACEENTER3("%p %u", ndis_event, ms);
	ticks = -((LARGE_INTEGER)ms * TICKSPERMSEC);
	res = KeWaitForSingleObject(&ndis_event->nt_event, 0, 0, TRUE,
				    ms == 0 ? NULL : &ticks);
	if (res == STATUS_SUCCESS)
		TRACEEXIT3(return TRUE);
	else
		TRACEEXIT3(return FALSE);
}

wstdcall void WIN_FUNC(NdisSetEvent,1)
	(struct ndis_event *ndis_event)
{
	TRACEENTER3("%p", ndis_event);
	KeSetEvent(&ndis_event->nt_event, 0, 0);
}

wstdcall void WIN_FUNC(NdisResetEvent,1)
	(struct ndis_event *ndis_event)
{
	TRACEENTER3("%p", ndis_event);
	KeResetEvent(&ndis_event->nt_event);
}

/* called via function pointer */
wstdcall void NdisMResetComplete(struct wrap_ndis_device *wnd,
				 NDIS_STATUS status, BOOLEAN address_reset)
{

	TRACEENTER3("status: %08X, %u", status, address_reset);
	wnd->ndis_comm_status = status;
	wnd->ndis_comm_done = 1 + address_reset;
	wake_up(&wnd->ndis_comm_wq);
	TRACEEXIT3(return);
}

static void ndis_worker(worker_param_t dummy)
{
	KIRQL irql;
	struct ndis_work_entry *ndis_work_entry;
	struct nt_list *ent;
	struct ndis_work_item *ndis_work_item;

	WORKENTER("");
	while (1) {
		irql = nt_spin_lock_irql(&ndis_work_list_lock, DISPATCH_LEVEL);
		ent = RemoveHeadList(&ndis_worker_list);
		nt_spin_unlock_irql(&ndis_work_list_lock, irql);
		if (!ent)
			break;
		ndis_work_entry = container_of(ent, struct ndis_work_entry,
					       list);
		ndis_work_item = ndis_work_entry->ndis_work_item;
		WORKTRACE("%p: %p, %p", ndis_work_item,
			  ndis_work_item->func, ndis_work_item->ctx);
		LIN2WIN2(ndis_work_item->func, ndis_work_item,
			 ndis_work_item->ctx);
		WORKTRACE("%p done", ndis_work_item);
		kfree(ndis_work_entry);
	}
	WORKEXIT(return);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisScheduleWorkItem,1)
	(struct ndis_work_item *ndis_work_item)
{
	struct ndis_work_entry *ndis_work_entry;
	KIRQL irql;

	TRACEENTER3("%p", ndis_work_item);
	ndis_work_entry = kmalloc(sizeof(*ndis_work_entry), gfp_irql());
	if (!ndis_work_entry)
		BUG();
	ndis_work_entry->ndis_work_item = ndis_work_item;
	irql = nt_spin_lock_irql(&ndis_work_list_lock, DISPATCH_LEVEL);
	InsertTailList(&ndis_worker_list, &ndis_work_entry->list);
	nt_spin_unlock_irql(&ndis_work_list_lock, irql);
	WORKTRACE("scheduling %p", ndis_work_item);
	schedule_ndis_work(&ndis_work);
	TRACEEXIT3(return NDIS_STATUS_SUCCESS);
}

wstdcall void *WIN_FUNC(NdisAllocateIoWorkItem,1)
	(void *object_handle)
{
	struct device_object *dev_obj;
	/* TODO: get device handle */
	dev_obj = object_handle;
	return IoAllocateWorkItem(dev_obj);
}

wstdcall void WIN_FUNC(NdisQueueIoWorkItem,3)
	(void *work_item_handle, void *routine, void *ctx)
{
	IoQueueWorkItem(work_item_handle, routine, DelayedWorkQueue, ctx);
}

wstdcall void WIN_FUNC(NdisFreeIoWorkItem,1)
	(void *work_item_handle)
{
	IoFreeWorkItem(work_item_handle);
}

#include "ndis_exports.h"

void init_nmb_functions(struct wrap_ndis_device *wnd)
{
	TODO();
#if 0
	nmb->rx_packet = WIN_FUNC_PTR(NdisMIndicateReceivePacket,3);
	nmb->send_complete = WIN_FUNC_PTR(NdisMSendComplete,3);
	nmb->send_resource_avail = WIN_FUNC_PTR(NdisMSendResourcesAvailable,1);
	nmb->status = WIN_FUNC_PTR(NdisMIndicateStatus,4);
	nmb->status_complete = WIN_FUNC_PTR(NdisMIndicateStatusComplete,1);
	nmb->query_complete = WIN_FUNC_PTR(NdisMQueryInformationComplete,2);
	nmb->set_complete = WIN_FUNC_PTR(NdisMSetInformationComplete,2);
	nmb->reset_complete = WIN_FUNC_PTR(NdisMResetComplete,3);
	nmb->eth_rx_indicate = WIN_FUNC_PTR(EthRxIndicateHandler,8);
	nmb->eth_rx_complete = WIN_FUNC_PTR(EthRxComplete,1);
	nmb->td_complete = WIN_FUNC_PTR(NdisMTransferDataComplete,4);
#endif
}
