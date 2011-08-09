/*
 *  Copyright (C) 2006-2007 Giridhar Pemmasani
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
#include "ndis_exports.h"

#define MAX_ALLOCATED_NDIS_PACKETS 20
#define MAX_ALLOCATED_NDIS_BUFFERS 20

workqueue_struct_t *ndis_wq;
static void ndis_worker(worker_param_t dummy);
static work_struct_t ndis_work;
static struct nt_list ndis_worker_list;
static spinlock_t ndis_work_list_lock;
static struct nt_thread *ndis_worker_thread;

wstdcall void WIN_FUNC(NdisInitializeWrapper,4)
	(void **driver_handle, struct driver_object *driver,
	 struct unicode_string *reg_path, void *unused)
{
	ENTER1("handle: %p, driver: %p", driver_handle, driver);
	*driver_handle = driver;
	EXIT1(return);
}

wstdcall void WIN_FUNC(NdisTerminateWrapper,2)
	(struct device_object *dev_obj, void *system_specific)
{
	EXIT1(return);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMRegisterMiniportDriver,5)
	(struct driver_object *drv_obj, struct unicode_string *registry_path,
	 void *mp_driver_ctx, struct mp_driver_characteristics *mp_driver,
	 void **driver_handle)
{
	struct wrap_driver *wrap_driver;
	struct ndis_driver *ndis_driver;

	ENTER2("%p, %p, 0x%x, 0x%x", drv_obj, mp_driver_ctx,
		    mp_driver->major_version, mp_driver->minor_version);
	if (mp_driver->major_version != 0x6) {
		WARNING("invalid version: 0x%x", mp_driver->major_version);
		return NDIS_STATUS_BAD_VERSION;
	}
	wrap_driver =
		IoGetDriverObjectExtension(drv_obj,
					   (void *)WRAP_DRIVER_CLIENT_ID);
	if (!wrap_driver) {
		ERROR("couldn't get wrap_driver");
		EXIT1(return NDIS_STATUS_RESOURCES);
	}
	if (IoAllocateDriverObjectExtension(
		    drv_obj, (void *)NDIS_DRIVER_CLIENT_ID,
		    sizeof(*ndis_driver), (void **)&ndis_driver) !=
	    STATUS_SUCCESS)
		EXIT1(return NDIS_STATUS_RESOURCES);
	TRACE2("%p, %p", wrap_driver, ndis_driver);
	memset(ndis_driver, 0, sizeof(*ndis_driver));
	wrap_driver->ndis_driver = ndis_driver;
	ndis_driver->wrap_driver = wrap_driver;
	ndis_driver->major_version = mp_driver->major_version;
	ndis_driver->minor_version = mp_driver->minor_version;
	ndis_driver->mp_driver_ctx = mp_driver_ctx;
	memcpy(&ndis_driver->mp_driver, mp_driver,
	       sizeof(ndis_driver->mp_driver));
	*driver_handle = wrap_driver;
	TRACE2("%p", mp_driver->set_options);
	if (mp_driver->set_options) {
		NDIS_STATUS status;
		status = LIN2WIN2(mp_driver->set_options, wrap_driver,
				  mp_driver_ctx);
		if (status != NDIS_STATUS_SUCCESS) {
			WARNING("failed: 0x%x", status);
			IoFreeDriverObjectExtension(
				drv_obj, (void *)NDIS_DRIVER_CLIENT_ID);
			return NDIS_STATUS_FAILURE;
		}
	}
	EXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisMDeregisterMiniportDriver,1)
	(struct wrap_driver *driver)
{
	ENTER1("%p", driver);
	/* TOODO */
}

wstdcall NDIS_STATUS WIN_FUNC(NdisSetOptionalHandlers,2)
	(void *handle, struct ndis_driver_optional_handlers *opt_handlers)
{
	struct wrap_driver *wrap_driver = handle;

	ENTER1("%p", handle);
	if (opt_handlers->header.type ==
	    NDIS_OBJECT_TYPE_MINIPORT_PNP_CHARACTERISTICS) {
		memcpy(&wrap_driver->ndis_driver->mp_pnp_chars, opt_handlers,
		       sizeof(wrap_driver->ndis_driver->mp_pnp_chars));
	} else
		WARNING("%d not supported", opt_handlers->header.type);
	return STATUS_SUCCESS;
}

wstdcall void WIN_FUNC(NdisMGetDeviceProperty,6)
	(struct ndis_mp_block *nmb, void **phy_dev, void **func_dev,
	 void **next_dev, void **alloc_res, void**trans_res)
{
	ENTER2("nmb: %p, phy_dev = %p, func_dev = %p, next_dev = %p, "
	       "alloc_res = %p, trans_res = %p", nmb, phy_dev, func_dev,
	       next_dev, alloc_res, trans_res);
	if (phy_dev)
		*phy_dev = nmb->wnd->pdo;
	if (func_dev)
		*func_dev = nmb->wnd->fdo;
	if (next_dev)
		*next_dev = nmb->wnd->next_device;
	if (alloc_res)
		*alloc_res = nmb->wnd->wd->resource_list;
	if (trans_res)
		*trans_res = nmb->wnd->wd->resource_list;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisAllocateMemoryWithTag,3)
	(void **dest, UINT length, ULONG tag)
{
	void *res;
	res = ExAllocatePoolWithTag(NonPagedPool, length, tag);
	if (res) {
		*dest = res;
		EXIT4(return NDIS_STATUS_SUCCESS);
	} else
		EXIT4(return NDIS_STATUS_FAILURE);
}

wstdcall void *WIN_FUNC(NdisAllocateMemoryWithTagPriority,4)
	(struct ndis_mp_block *nmb, UINT length, ULONG tag,
	 enum ex_pool_priority priority)
{
	void *res;
	ENTER4("%p, %u", nmb, length);
	res = ExAllocatePoolWithTag(NonPagedPool, length, tag);
	EXIT4(return res);
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
	DBG_BLOCK(2) {
		void *p = __builtin_return_address(0) - 30;
		dump_bytes(__func__, p, 30);
	}
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisOpenConfiguration,3)
	(NDIS_STATUS *status, void **conf_handle,
	 struct ndis_mp_block *nmb)
{
	ENTER2("%p", conf_handle);
	*conf_handle = nmb;
	*status = NDIS_STATUS_SUCCESS;
	EXIT2(return);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisOpenConfigurationEx,2)
	(struct ndis_configuration_object *object, void **handle)
{
	ENTER2("%p, %p", object, object->handle);
	/* TODO: the handle can be either wnd or wrap_driver */
	*handle = object->handle;
	EXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisOpenProtocolConfiguration,3)
	(NDIS_STATUS *status, void **confhandle,
	 struct unicode_string *section)
{
	ENTER2("%p", confhandle);
	*status = NDIS_STATUS_SUCCESS;
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisOpenConfigurationKeyByName,4)
	(NDIS_STATUS *status, void *handle,
	 struct unicode_string *key, void **subkeyhandle)
{
	struct ansi_string ansi;
	ENTER2("");
	if (RtlUnicodeStringToAnsiString(&ansi, key, TRUE) == STATUS_SUCCESS) {
		TRACE2("%s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	*subkeyhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisOpenConfigurationKeyByIndex,5)
	(NDIS_STATUS *status, void *handle, ULONG index,
	 struct unicode_string *key, void **subkeyhandle)
{
	ENTER2("%u", index);
//	*subkeyhandle = handle;
	*status = NDIS_STATUS_FAILURE;
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisCloseConfiguration,1)
	(void *handle)
{
	/* instead of freeing all configuration parameters as we are
	 * supposed to do here, we free them when the device is
	 * removed */
	ENTER2("%p", handle);
	return;
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
			EXIT2(return param);
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
		TRACE2("%u", (ULONG)param->data.integer);
		break;
	case NdisParameterHexInteger:
		param->data.integer = simple_strtol(setting->value, NULL, 16);
		TRACE2("%u", (ULONG)param->data.integer);
		break;
	case NdisParameterString:
		RtlInitAnsiString(&ansi, setting->value);
		TRACE2("'%s'", ansi.buf);
		if (RtlAnsiStringToUnicodeString(&param->data.string,
						 &ansi, TRUE)) {
			ExFreePool(param);
			EXIT2(return NULL);
		}
		break;
	default:
		ERROR("unknown type: %d", type);
		ExFreePool(param);
		return NULL;
	}
	param->type = type;
	setting->encoded = param;
	EXIT2(return param);
}

static int ndis_decode_setting(struct wrap_device_setting *setting,
			       struct ndis_configuration_parameter *param)
{
	struct ansi_string ansi;
	struct ndis_configuration_parameter *prev;

	ENTER2("%p, %p", setting, param);
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
			EXIT1(return -1);
		}
		if (ansi.length == ansi.max_length)
			ansi.length--;
		setting->value[ansi.length] = 0;
		break;
	default:
		TRACE2("unknown setting type: %d", param->type);
		return -1;
	}
	TRACE2("setting changed %s='%s', %d", setting->name, setting->value,
		  ansi.length);
	return 0;
}

static int read_setting(struct nt_list *setting_list, char *keyname, int length,
			struct ndis_configuration_parameter **param,
			enum ndis_parameter_type type)
{
	struct wrap_device_setting *setting;
	if (down_interruptible(&loader_mutex))
		WARNING("couldn't obtain loader_mutex");
	nt_list_for_each_entry(setting, setting_list, list) {
		if (strnicmp(keyname, setting->name, length) == 0) {
			TRACE2("setting %s='%s'", keyname, setting->value);
			up(&loader_mutex);
			*param = ndis_encode_setting(setting, type);
			if (*param)
				EXIT2(return 0);
			else
				EXIT2(return -1);
		}
	}
	up(&loader_mutex);
	EXIT2(return -1);
}

wstdcall void WIN_FUNC(NdisReadConfiguration,5)
	(NDIS_STATUS *status, struct ndis_configuration_parameter **param,
	 struct ndis_mp_block *nmb, struct unicode_string *key,
	 enum ndis_parameter_type type)
{
	struct ansi_string ansi;
	char *keyname;
	int ret;

	ENTER2("nmb: %p", nmb);
	ret = RtlUnicodeStringToAnsiString(&ansi, key, TRUE);
	if (ret || ansi.buf == NULL) {
		*param = NULL;
		*status = NDIS_STATUS_FAILURE;
		RtlFreeAnsiString(&ansi);
		EXIT2(return);
	}
	TRACE3("%d, %s", type, ansi.buf);
	keyname = ansi.buf;

	if (read_setting(&nmb->wnd->wd->settings, keyname,
			 ansi.length, param, type) == 0 ||
	    read_setting(&nmb->wnd->wd->driver->settings, keyname,
			 ansi.length, param, type) == 0)
		*status = NDIS_STATUS_SUCCESS;
	else {
		TRACE2("setting %s not found (type:%d)", keyname, type);
		*status = NDIS_STATUS_FAILURE;
	}
	RtlFreeAnsiString(&ansi);
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisWriteConfiguration,4)
	(NDIS_STATUS *status, struct ndis_mp_block *nmb,
	 struct unicode_string *key, struct ndis_configuration_parameter *param)
{
	struct ndis_device *wnd = nmb->wnd;
	struct ansi_string ansi;
	char *keyname;
	struct wrap_device_setting *setting;

	ENTER2("wnd: %p", wnd);
	if (RtlUnicodeStringToAnsiString(&ansi, key, TRUE)) {
		*status = NDIS_STATUS_FAILURE;
		EXIT2(return);
	}
	keyname = ansi.buf;
	TRACE2("%s", keyname);

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
			EXIT2(return);
		}
	}
	up(&loader_mutex);
	setting = kzalloc(sizeof(*setting), GFP_KERNEL);
	if (setting) {
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
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisOpenFile,5)
	(NDIS_STATUS *status, struct wrap_bin_file **file,
	 UINT *filelength, struct unicode_string *filename,
	 NDIS_PHY_ADDRESS highest_address)
{
	struct ansi_string ansi;
	struct wrap_bin_file *bin_file;

	ENTER2("%p, %d, %llx, %p", status, *filelength,
		    highest_address, *file);
	if (RtlUnicodeStringToAnsiString(&ansi, filename, TRUE) !=
	    STATUS_SUCCESS) {
		*status = NDIS_STATUS_RESOURCES;
		EXIT2(return);
	}
	TRACE2("%s", ansi.buf);
	bin_file = get_bin_file(ansi.buf);
	if (bin_file) {
		*file = bin_file;
		*filelength = bin_file->size;
		*status = NDIS_STATUS_SUCCESS;
	} else
		*status = NDIS_STATUS_FILE_NOT_FOUND;

	RtlFreeAnsiString(&ansi);
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisMapFile,3)
	(NDIS_STATUS *status, void **mappedbuffer, struct wrap_bin_file *file)
{
	ENTER2("%p", file);

	if (!file) {
		*status = NDIS_STATUS_ALREADY_MAPPED;
		EXIT2(return);
	}

	*status = NDIS_STATUS_SUCCESS;
	*mappedbuffer = file->data;
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisUnmapFile,1)
	(struct wrap_bin_file *file)
{
	ENTER2("%p", file);
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisCloseFile,1)
	(struct wrap_bin_file *file)
{
	ENTER2("%p", file);
	free_bin_file(file);
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisGetSystemUpTime,1)
	(ULONG *ms)
{
	ENTER5("");
	*ms = 1000 * jiffies / HZ;
	EXIT5(return);
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
		EXIT2(return 0);
	if (MmGetMdlByteCount(buffer) == 0)
		EXIT2(return 1);

	length = MmGetMdlByteCount(buffer);
	n = SPAN_PAGES(MmGetMdlVirtualAddress(buffer), length);
	TRACE4("%p, %p, %d, %d", buffer->startva, buffer->mappedsystemva,
		  length, n);
	EXIT3(return n);
}

wstdcall void WIN_FUNC(NdisGetBufferPhysicalArraySize,2)
	(ndis_buffer *buffer, UINT *arraysize)
{
	ENTER3("%p", buffer);
	*arraysize = NDIS_BUFFER_TO_SPAN_PAGES(buffer);
	EXIT3(return);
}

wstdcall void WIN_FUNC(NdisInitializeString,2)
	(struct unicode_string *dest, UCHAR *src)
{
	struct ansi_string ansi;

	ENTER2("");
	if (src == NULL) {
		dest->length = dest->max_length = 0;
		dest->buf = NULL;
	} else {
		RtlInitAnsiString(&ansi, src);
		RtlAnsiStringToUnicodeString(dest, &ansi, TRUE);
	}
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisInitAnsiString,2)
	(struct ansi_string *dst, CHAR *src)
{
	RtlInitAnsiString(dst, src);
	EXIT2(return);
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
	ENTER2("");
	if (dst == NULL || src == NULL)
		EXIT2(return NDIS_STATUS_FAILURE);
	if (RtlAnsiStringToUnicodeString(dst, src, FALSE) == STATUS_SUCCESS)
		return NDIS_STATUS_SUCCESS;
	else
		return NDIS_STATUS_FAILURE;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisUnicodeStringToAnsiString,2)
	(struct ansi_string *dst, struct unicode_string *src)
{
	ENTER2("");
	if (dst == NULL || src == NULL)
		EXIT2(return NDIS_STATUS_FAILURE);
	if (RtlUnicodeStringToAnsiString(dst, src, FALSE) == STATUS_SUCCESS)
		return NDIS_STATUS_SUCCESS;
	else
		return NDIS_STATUS_FAILURE;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMSetMiniportAttributes,2)
	(struct ndis_mp_block *nmb,
	 union mp_adapter_attrs *mp_adapter_attrs)
{
	struct ndis_device *wnd = nmb->wnd;
	struct ndis_object_header *header = &mp_adapter_attrs->reg_attrs.header;

	ENTER3("%p, %p", wnd, mp_adapter_attrs);
	TRACE3("0x%x", header->type);
	switch (header->type) {
	case NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES:
		nmb->adapter_ctx = mp_adapter_attrs->reg_attrs.ctx;
		wnd->attribute_flags =
			mp_adapter_attrs->reg_attrs.attribute_flags;
		wnd->hangcheck_interval =
			mp_adapter_attrs->reg_attrs.hangcheck_secs * HZ;
		wnd->interface_type =
			mp_adapter_attrs->reg_attrs.interface_type;
		TRACE2("%d", mp_adapter_attrs->reg_attrs.hangcheck_secs);
		break;
	case NDIS_OBJECT_TYPE_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES:
		wnd->add_dev_ctx = mp_adapter_attrs->add_dev_attrs.ctx;
		break;
	case NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES:
		memcpy(&wnd->general_attrs, mp_adapter_attrs,
		       sizeof(wnd->general_attrs));
		break;
	case NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES:
		TRACE2("%d, %zd", header->size,
			  sizeof(wnd->native_802_11_attrs));
		memcpy(&wnd->native_802_11_attrs, mp_adapter_attrs,
		       sizeof(wnd->native_802_11_attrs));
		break;
	default:
		WARNING("type 0x%x is not handled", header->type);
		break;
	}
	EXIT3(return NDIS_STATUS_SUCCESS);
}

wstdcall ULONG WIN_FUNC(NdisReadPciSlotInformation,5)
	(struct ndis_mp_block *nmb, ULONG slot, ULONG offset, char *buf,
	 ULONG len)
{
	struct wrap_device *wd = nmb->wnd->wd;
	ULONG i;
	ENTER3("%p, %p, %u, %u, %u", nmb, wd->pci.pdev, slot, offset, len);
	for (i = 0; i < len; i++) {
		if (pci_read_config_byte(wd->pci.pdev, offset + i, &buf[i]) !=
		    PCIBIOS_SUCCESSFUL)
			break;
	}
	DBG_BLOCK(2) {
		if (i != len)
			WARNING("%u, %u", i, len);
	}
	EXIT5(return i);
}

wstdcall ULONG WIN_FUNC(NdisImmediateReadPciSlotInformation,5)
	(struct ndis_mp_block *nmb, ULONG slot, ULONG offset, char *buf,
	 ULONG len)
{
	return NdisReadPciSlotInformation(nmb, slot, offset, buf, len);
}

wstdcall ULONG WIN_FUNC(NdisWritePciSlotInformation,5)
	(struct ndis_mp_block *nmb, ULONG slot, ULONG offset, char *buf,
	 ULONG len)
{
	struct wrap_device *wd = nmb->wnd->wd;
	ULONG i;
	ENTER3("%p, %p, %u, %u, %u", nmb, wd->pci.pdev, slot, offset, len);
	for (i = 0; i < len; i++) {
		if (pci_write_config_byte(wd->pci.pdev, offset + i, buf[i]) !=
		    PCIBIOS_SUCCESSFUL)
			break;
	}
	DBG_BLOCK(2) {
		if (i != len)
			WARNING("%u, %u", i, len);
	}
	EXIT5(return i);
}

wstdcall ULONG WIN_FUNC(NdisMGetBusData,5)
	(struct ndis_mp_block *nmb, ULONG where, ULONG offset, char *buf,
	 ULONG len)
{
	ENTER3("0x%x, %u, %u", where, offset, len);
	/* TODO: map ROM for PCI_WHICHSPACE_ROM */
	if (where == PCI_WHICHSPACE_CONFIG)
		return NdisReadPciSlotInformation(nmb, where, offset, buf, len);
	else if (where == PCI_WHICHSPACE_ROM && nmb->wnd->wd->pci.rom) {
		ULONG i;
		for (i = 0; i < len; i++)
			buf[i] = readb(nmb->wnd->wd->pci.rom + offset + i);
		EXIT3(return i);
	} else {
		ERROR("reading from 0x%x not supported", where);
		EXIT1(return 0);
	}
}

wstdcall ULONG WIN_FUNC(NdisMSetBusData,5)
	(struct ndis_mp_block *nmb, ULONG where, ULONG offset, char *buf,
	 ULONG len)
{
	ENTER3("0x%x, %u, %u", where, offset, len);
	/* TODO: map ROM for PCI_WHICHSPACE_ROM */
	if (where == PCI_WHICHSPACE_CONFIG)
		return NdisWritePciSlotInformation(nmb, where, offset, buf, len);
	else if (where == PCI_WHICHSPACE_ROM && nmb->wnd->wd->pci.rom) {
		ULONG i;
		for (i = 0; i < len; i++)
			writeb(buf[i], nmb->wnd->wd->pci.rom + offset + i);
		EXIT3(return i);
	} else {
		ERROR("writing to 0x%x not supported", where);
		EXIT1(return 0);
	}
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMAllocatePort,2)
	(struct ndis_mp_block *nmb,
	 struct ndis_port_characteristics *port_chars)
{
	ENTER1("%p, 0x%x, %d", nmb, port_chars->flags, port_chars->type);
	TODO();
	port_chars->port = 1;
	return NDIS_STATUS_SUCCESS;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMFreePort,2)
	(struct ndis_mp_block *nmb,
	 struct ndis_port_characteristics *port_chars)
{
	ENTER1("%p, 0x%x, %d, %d", nmb, port_chars->flags, port_chars->type,
	       port_chars->port);
	TODO();
	return NDIS_STATUS_SUCCESS;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMNetPnPEvent,2)
	(struct ndis_mp_block *nmb,
	 struct net_pnp_event_notification *pnp_event)
{
	ENTER1("%p, %d, %d", nmb, pnp_event->port, pnp_event->event.code);
	TODO();
	return NDIS_STATUS_SUCCESS;
}

wstdcall void WIN_FUNC(NdisReadPortUchar,3)
	(struct ndis_mp_block *nmb, ULONG port, char *data)
{
	*data = inb(port);
}

wstdcall void WIN_FUNC(NdisImmediateReadPortUchar,3)
	(struct ndis_mp_block *nmb, ULONG port, char *data)
{
	*data = inb(port);
}

wstdcall void WIN_FUNC(NdisWritePortUchar,3)
	(struct ndis_mp_block *nmb, ULONG port, char data)
{
	outb(data, port);
}

wstdcall void WIN_FUNC(NdisImmediateWritePortUchar,3)
	(struct ndis_mp_block *nmb, ULONG port, char data)
{
	outb(data, port);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMMapIoSpace,4)
	(void __iomem **virt, struct ndis_mp_block *nmb,
	 NDIS_PHY_ADDRESS phy_addr, UINT len)
{
	ENTER2("%Lx, %d", phy_addr, len);
	*virt = MmMapIoSpace(phy_addr, len, MmCached);
	if (*virt == NULL) {
		ERROR("ioremap failed");
		EXIT2(return NDIS_STATUS_FAILURE);
	}
	nmb->wnd->mem_start = phy_addr;
	nmb->wnd->mem_end = phy_addr + len;
	TRACE2("%p", *virt);
	EXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisMUnmapIoSpace,3)
	(struct ndis_mp_block *nmb, void __iomem *virt, UINT len)
{
	ENTER2("%p, %d", virt, len);
	MmUnmapIoSpace(virt, len);
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisAllocateSpinLock,1)
	(struct ndis_spinlock *lock)
{
	TRACE4("lock %p, %lu", lock, lock->klock);
	KeInitializeSpinLock(&lock->klock);
	lock->irql = PASSIVE_LEVEL;
	EXIT4(return);
}

wstdcall void WIN_FUNC(NdisFreeSpinLock,1)
	(struct ndis_spinlock *lock)
{
	TRACE4("lock %p, %lu", lock, lock->klock);
	EXIT4(return);
}

wstdcall void WIN_FUNC(NdisAcquireSpinLock,1)
	(struct ndis_spinlock *lock)
{
	TRACE6("lock %p, %lu", lock, lock->klock);
	lock->irql = nt_spin_lock_irql(&lock->klock, DISPATCH_LEVEL);
	EXIT6(return);
}

wstdcall void WIN_FUNC(NdisReleaseSpinLock,1)
	(struct ndis_spinlock *lock)
{
	TRACE6("lock %p, %lu", lock, lock->klock);
	nt_spin_unlock_irql(&lock->klock, lock->irql);
	EXIT6(return);
}

wstdcall void WIN_FUNC(NdisDprAcquireSpinLock,1)
	(struct ndis_spinlock *lock)
{
	ENTER6("lock %p", lock);
	nt_spin_lock(&lock->klock);
	EXIT6(return);
}

wstdcall void WIN_FUNC(NdisDprReleaseSpinLock,1)
	(struct ndis_spinlock *lock)
{
	ENTER6("lock %p", lock);
	nt_spin_unlock(&lock->klock);
	EXIT6(return);
}

/* TODO: implement these with read/write locks, instead of spinlocks */
wstdcall void WIN_FUNC(NdisInitializeReadWriteLock,1)
	(struct ndis_rw_lock *rw_lock)
{
	ENTER3("%p", rw_lock);
	memset(rw_lock, 0, sizeof(*rw_lock));
	KeInitializeSpinLock(&rw_lock->s.klock);
	EXIT3(return);
}

/* read/write locks are implemented in a rather simplisitic way - we
 * should probably use Linux's rw_lock implementation */

wstdcall void WIN_FUNC(NdisAcquireReadWriteLock,3)
	(struct ndis_rw_lock *rw_lock, BOOLEAN write,
	 struct lock_state *lock_state)
{
	if (write) {
		while (cmpxchg(&rw_lock->count, 0, -1) != 0) {
			do {
				cpu_relax();
			} while (rw_lock->count);
		}
		return;
	}
	while (1) {
		typeof(rw_lock->count) count;
		while ((count = rw_lock->count) < 0)
			cpu_relax();
		if (cmpxchg(&rw_lock->count, count, count + 1) == count)
			return;
	}
}

wstdcall void WIN_FUNC(NdisReleaseReadWriteLock,2)
	(struct ndis_rw_lock *rw_lock, struct lock_state *lock_state)
{
	if (rw_lock->count > 0)
		atomic_dec_var(rw_lock->count);
	else if (rw_lock->count == -1)
		rw_lock->count = 0;
	else
		WARNING("invalid state: %d", rw_lock->count);
}

wstdcall struct net_buffer_pool *WIN_FUNC(NdisAllocateNetBufferPool,3)
	(struct ndis_mp_block *nmb, struct net_buffer_pool_params *params)
{
	struct net_buffer_pool *pool;

	ENTER2("%p, %u", nmb, params->data_size);
	pool = kzalloc(sizeof(*pool), irql_gfp());
	if (!pool) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	pool->data_length = params->data_size;
	pool->with_mdl = FALSE;
	pool->slist.next = NULL;
	pool->count = 0;
	TRACE4("%p, %u", pool, pool->data_length);
	spin_lock_init(&pool->lock);
	return pool;
}

wstdcall void WIN_FUNC(NdisFreeNetBufferPool,1)
	(struct net_buffer_pool *pool)
{
	ENTER2("%p", pool);
	if (pool->count)
		WARNING("%d buffers not freed", pool->count);
	kfree(pool);
	EXIT4(return);
}

wstdcall struct net_buffer *WIN_FUNC(NdisAllocateNetBuffer,4)
	(struct net_buffer_pool *pool, struct mdl *mdl,
	 ULONG data_offset, SIZE_T data_length)
{
	struct net_buffer *buffer;

	/* TODO: use pool */
	ENTER3("%p, %d, %p, %u, %lu", pool, pool->count, mdl,
	       data_offset, data_length);
	spin_lock_bh(&pool->lock);
	if (pool->count) {
		buffer = (typeof(buffer))pool->slist.next;
		if (buffer) {
			pool->slist.next = buffer->header.link.next;
			TRACE3("%p, %p", buffer, pool->slist.next);
			pool->count--;
		}
	} else
		buffer = NULL;
	spin_unlock_bh(&pool->lock);
	if (!buffer) {
		buffer = kmalloc(sizeof(*buffer), irql_gfp());
		if (!buffer) {
			WARNING("couldn't allocate memory");
			return NULL;
		}
	}
	TRACE3("%p", buffer);
	memset(buffer, 0, sizeof(*buffer));
	buffer->pool = pool;
	/* TODO: set current_mdl based on data offset */
	buffer->header.data.current_mdl = buffer->header.data.mdl_chain = mdl;
	buffer->header.data.current_mdl_offset = data_offset;
	buffer->header.data.data_length.ulength = data_length;
	buffer->header.data.data_offset = data_offset;
	buffer->header.data.next = NULL;
	EXIT3(return buffer);
}

wstdcall void WIN_FUNC(NdisFreeNetBuffer,1)
	(struct net_buffer *buffer)
{
	struct net_buffer_pool *pool;
	struct mdl *mdl;

	ENTER3("%p", buffer);
	if (!buffer)
		EXIT1(return);
	pool = buffer->pool;
	TRACE3("%p, %d", pool, pool->count);
	spin_lock_bh(&pool->lock);
	while (buffer) {
		struct net_buffer *next;
		next = buffer->header.data.next;
		mdl = buffer->header.data.mdl_chain;
		while (mdl) {
			struct mdl *next_mdl;
			if (mdl->flags & MDL_FREE_EXTRA_PTES)
				kfree(MmGetMdlVirtualAddress(mdl));
			next_mdl = mdl->next;
			free_mdl(mdl);
			mdl = next_mdl;
		}
		if (pool->count < MAX_ALLOCATED_NDIS_BUFFERS) {
			buffer->header.link.next = pool->slist.next;
			pool->slist.next = (void *)buffer;
			pool->count++;
		} else
			kfree(buffer);
		buffer = next;
	}
	spin_unlock_bh(&pool->lock);
}

wstdcall struct net_buffer *WIN_FUNC(NdisAllocateNetBufferMdlAndData,1)
	(struct net_buffer_pool *pool)
{
	struct net_buffer *buffer;
	struct mdl *mdl;
	void *data;

	ENTER4("%p", pool);
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
	mdl->flags |= MDL_FREE_EXTRA_PTES;
	buffer = NdisAllocateNetBuffer(pool, mdl, 0, pool->data_length);
	TRACE4("%p, %p", mdl, buffer);
	return buffer;
}

wstdcall void *WIN_FUNC(NdisGetDataBuffer,5)
	(struct net_buffer *buffer, ULONG bytes_needed, void *storage,
	 UINT alignment, UINT align_offset)
{
	void *data;
	struct mdl *mdl;

	ENTER3("%p, %u, %p, %u, %u", buffer, bytes_needed, storage,
		    alignment, align_offset);
	if (buffer->header.data.data_length.ulength < bytes_needed ||
	    storage == NULL)
		EXIT2(return NULL);
	/* TODO: what if this buffer has next buffer? */
	mdl = buffer->header.data.current_mdl;
	/* usually data is always contiguous, and only one MDL maps it */
	if (mdl->next) {
		data = storage;
		while (mdl) {
			memcpy(storage, MmGetSystemAddressForMdl(mdl),
			       MmGetMdlByteCount(mdl));
			storage += MmGetMdlByteCount(mdl);
			mdl = mdl->next;
		}
	} else
		data = MmGetSystemAddressForMdl(mdl);
	TRACE3("%p", data);
	return data;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisRetreatNetBufferDataStart,4)
	(struct net_buffer *buffer, ULONG offset, ULONG backfill,
	 struct mdl *(*alloc_handler)(void *, int) wstdcall)
{
	struct mdl *mdl, *last;
	int length;
	void *buf;

	ENTER2("%p, %d, %d, %p", buffer, offset, backfill, alloc_handler);
	TRACE2("%ud, %ud", buffer->header.data.data_offset,
		  buffer->header.data.current_mdl_offset);
	/* TODO: most definitely this is wrong */
	assert(buffer->header.data.data_offset >=
	       buffer->header.data.current_mdl_offset);
	assert(buffer->header.data.data_offset >= offset);

	if (buffer->header.data.current_mdl_offset >= offset) {
		buffer->header.data.current_mdl_offset -= offset;
		buffer->header.data.data_offset -= offset;
		TRACE2("%p, %u", buffer->header.data.current_mdl,
			  buffer->header.data.data_offset);
		return NDIS_STATUS_SUCCESS;
	}

	offset -= buffer->header.data.current_mdl_offset;
	last = buffer->header.data.current_mdl;
	while (1) {
		mdl = buffer->header.data.mdl_chain;
		while (mdl->next && mdl->next != last)
			mdl = mdl->next;
		if (offset <= MmGetMdlByteCount(mdl)) {
			buffer->header.data.current_mdl = mdl;
			buffer->header.data.current_mdl_offset =
				MmGetMdlByteCount(mdl) - offset;
			buffer->header.data.data_offset -=
				MmGetMdlByteCount(mdl) - offset;
			TRACE2("%p, %u", mdl,
				  buffer->header.data.data_offset);
			return NDIS_STATUS_SUCCESS;
		}
		offset -= MmGetMdlByteCount(mdl);
		buffer->header.data.data_offset -= MmGetMdlByteCount(mdl);
		last = mdl;
		if (last == buffer->header.data.mdl_chain)
			break;
	}
	length = max_t(int, offset + backfill, 80);
	buf = kzalloc(length, GFP_ATOMIC);
	if (!buf) {
		WARNING("couldn't allocate memory: %d", length);
		return NDIS_STATUS_RESOURCES;
	}
	if (alloc_handler)
		mdl = (typeof(mdl))LIN2WIN2(alloc_handler, buf, length);
	else
		mdl = allocate_init_mdl(buf, length);

	if (!mdl) {
		kfree(buf);
		return NDIS_STATUS_RESOURCES;
	}
	mdl->next = buffer->header.data.mdl_chain;
	buffer->header.data.mdl_chain = mdl;
	buffer->header.data.current_mdl = mdl;
	buffer->header.data.current_mdl_offset = length - offset;
	buffer->header.data.data_offset = length - offset;

	TRACE2("%p, %u", mdl, buffer->header.data.data_offset);
	return NDIS_STATUS_SUCCESS;
}

wstdcall void WIN_FUNC(NdisAdvanceNetBufferDataStart,4)
	(struct net_buffer *buffer, ULONG offset, BOOLEAN need_free_mdl,
	 void (*free_handler)(struct mdl *) wstdcall)
{
	struct mdl *mdl, *next;

	ENTER2("%p, %u, %d, %p", buffer, offset, need_free_mdl,
		    free_handler);
	/* what if need-free_mdl is TRUE and there are MDLs ahead of
	 * current_mdl? */
	if (need_free_mdl) {
		mdl = buffer->header.data.mdl_chain;
		while (mdl != buffer->header.data.current_mdl) {
			next = mdl->next;
			free_mdl(mdl);
			mdl = next;
		}
	}
	mdl = buffer->header.data.current_mdl;
	if (offset > MmGetMdlByteCount(mdl) -
	    buffer->header.data.current_mdl_offset) {
		TRACE2("%p, %u, %u", mdl, MmGetMdlByteCount(mdl),
			  buffer->header.data.current_mdl_offset);
		offset += buffer->header.data.current_mdl_offset;
		while (mdl && offset < MmGetMdlByteCount(mdl)) {
			offset -= MmGetMdlByteCount(mdl);
			TRACE2("%p, %u, %u", mdl, offset,
				  MmGetMdlByteCount(mdl));
			next = mdl->next;
			if (need_free_mdl) {
				if (free_handler)
					LIN2WIN1(free_handler, mdl);
				else
					free_mdl(mdl);
			}
			mdl = next;
		}
	}
	buffer->header.data.current_mdl = mdl;
	if (mdl) {
		buffer->header.data.current_mdl_offset =
			buffer->header.data.data_offset =
			MmGetMdlByteCount(mdl) - offset;
	} else {
		buffer->header.data.current_mdl_offset =
			buffer->header.data.data_offset = 0;
	}
	TRACE2("%p, %u", mdl, buffer->header.data.data_offset);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisCopyFromNetBufferToNetBuffer,6)
	(struct net_buffer *dst_buffer, ULONG dst_offset, ULONG bytes_to_copy,
	 struct net_buffer *src_buffer, ULONG src_offset, ULONG *bytes_copied)
{
	struct mdl *src_mdl, *dst_mdl;

	src_mdl = src_buffer->header.data.current_mdl;
	src_offset += src_buffer->header.data.current_mdl_offset;
	while (src_mdl && src_offset > MmGetMdlByteCount(src_mdl)) {
		src_offset -= MmGetMdlByteCount(src_mdl);
		src_mdl = src_mdl->next;
	}

	dst_mdl = dst_buffer->header.data.current_mdl;
	dst_offset += dst_buffer->header.data.current_mdl_offset;
	while (dst_mdl && dst_offset > MmGetMdlByteCount(dst_mdl)) {
		dst_offset -= MmGetMdlByteCount(dst_mdl);
		dst_mdl = dst_mdl->next;
	}

	*bytes_copied = 0;
	while (bytes_to_copy > 0 && src_mdl && dst_mdl) {
		ULONG n = min(MmGetMdlByteCount(src_mdl) - src_offset,
			      MmGetMdlByteCount(dst_mdl) - dst_offset);
		n = min(n, bytes_to_copy);
		memcpy(MmGetSystemAddressForMdl(dst_mdl) + dst_offset,
		       MmGetSystemAddressForMdl(src_mdl) + src_offset, n);
		bytes_to_copy -= n;
		*bytes_copied += n;
		if (n == (MmGetMdlByteCount(src_mdl) - src_offset)) {
			src_offset = 0;
			src_mdl = src_mdl->next;
		} else {
			src_offset += n;
		}
		if (n == (MmGetMdlByteCount(dst_mdl) - dst_offset)) {
			dst_offset = 0;
			dst_mdl = dst_mdl->next;
		} else {
			dst_offset += n;
		}
	}
	return NDIS_STATUS_SUCCESS;
}


wstdcall struct net_buffer_list_pool *WIN_FUNC(NdisAllocateNetBufferListPool,2)
	(struct ndis_mp_block *nmb,
	 struct net_buffer_list_pool_params *params)
{
	struct net_buffer_list_pool *pool;

	ENTER2("%p, %u", nmb, params->ctx_size);
	pool = kzalloc(sizeof(*pool), irql_gfp());
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
			NdisAllocateNetBufferPool(nmb, &buffer_params);
		if (!pool->buffer_pool) {
			kfree(pool);
			EXIT2(return NULL);
		}
	} else {
		pool->list_pool.data_length = params->data_size;
		pool->flags = 0;
	}

	pool->list_pool.count = 0;
	pool->list_pool.slist.next = NULL;
	spin_lock_init(&pool->list_pool.lock);
	TRACE4("%p", pool);
	return pool;
}

wstdcall void WIN_FUNC(NdisFreeNetBufferListPool,2)
	(struct net_buffer_list_pool *pool)
{
	ENTER2("%p", pool);
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
	struct net_buffer *buffer;

	ENTER3("%p", buffer_list);
	pool = buffer_list->pool;
	TRACE3("%p", pool);
	spin_lock_bh(&pool->list_pool.lock);
	while (buffer_list) {
		struct net_buffer_list *next;
		next = (typeof(next))buffer_list->header.link.next;
		buffer = buffer_list->header.data.first_buffer;
		NdisFreeNetBuffer(buffer);
		ctx = buffer_list->context;
		TRACE3("%p", ctx);
		while (ctx) {
			struct net_buffer_list_context *new_ctx = ctx->next;
			kfree(ctx);
			ctx = new_ctx;
		}
		if (pool->list_pool.count < MAX_ALLOCATED_NDIS_BUFFERS) {
			buffer_list->header.link.next =
				pool->list_pool.slist.next;
			pool->list_pool.slist.next = (void *)buffer_list;
			pool->list_pool.count++;
		} else
			kfree(buffer_list);
		buffer_list = next;
	}
	spin_unlock_bh(&pool->list_pool.lock);
}

wstdcall struct net_buffer_list *WIN_FUNC(NdisAllocateNetBufferList,3)
	(struct net_buffer_list_pool *pool, USHORT ctx_size, USHORT backfill)
{
	struct net_buffer_list *buffer_list;

	ENTER3("%p, %u, %u", pool, ctx_size, backfill);
	spin_lock_bh(&pool->list_pool.lock);
	TRACE3("%d, %p", pool->list_pool.count, pool->list_pool.slist.next);
	if (pool->list_pool.count) {
		buffer_list = (typeof(buffer_list))pool->list_pool.slist.next;
		if (buffer_list) {
			pool->list_pool.slist.next =
				buffer_list->header.link.next;
			pool->list_pool.count--;
		}
		TRACE3("%d, %p", pool->list_pool.count, buffer_list);
	} else
		buffer_list = NULL;
	spin_unlock_bh(&pool->list_pool.lock);
	if (!buffer_list) {
		buffer_list = kmalloc(sizeof(*buffer_list), irql_gfp());
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
		buffer_list->context = kzalloc(size, GFP_ATOMIC);
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
			EXIT2(return NULL);
		}
	}
	buffer_list->header.data.next = NULL;
	TRACE3("%p", buffer_list);
	return buffer_list;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisAllocateNetBufferListContext,4)
	(struct net_buffer_list *buffer_list, USHORT ctx_size, USHORT backfill,
	 ULONG pool_tag)
{
	struct net_buffer_list_context *ctx;

	ENTER3("%p, %u, %u", buffer_list, ctx_size, backfill);

	/* TODO: how is this context list organized in buffer_list?
	 * newer members are added to the end of list or front (as in
	 * the case of MDL)? */
	if (!buffer_list->context || buffer_list->context->offset < ctx_size) {
		ctx = kzalloc(sizeof(*ctx) + ctx_size + backfill, GFP_ATOMIC);
		if (!ctx) {
			WARNING("couldn't allocate memory");
			return NDIS_STATUS_RESOURCES;
		}
		TRACE3("%p, %u, %u", ctx, ctx_size, backfill);
		ctx->size = ctx->offset = ctx_size + backfill;
		ctx->next = buffer_list->context;
		buffer_list->context = ctx;
	} else
		ctx = buffer_list->context;

	ctx->offset -= ctx_size;
	TRACE3("%p, %u, %u", ctx, ctx->offset, ctx->size);
	EXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisFreeNetBufferListContext,2)
	(struct net_buffer_list *buffer_list, USHORT ctx_size)
{
	struct net_buffer_list_context *next, *ctx = buffer_list->context;

	ENTER3("%p, %p", buffer_list, ctx);
	if (!ctx) {
		WARNING("invalid context");
		return;
	}
	TRACE3("%p, %u, %u, %u", ctx, ctx->offset, ctx->size, ctx_size);
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

wstdcall struct net_buffer_list *WIN_FUNC(NdisAllocateNetBufferAndNetBufferList,6)
	(struct net_buffer_list_pool *pool, USHORT ctx_size, USHORT backfill,
	 struct mdl *mdl_chain, ULONG data_offset, SIZE_T data_length)
{
	struct net_buffer_list *buffer_list;

	ENTER3("%p, %u, %u, %p, %u, %lu", pool, ctx_size, backfill,
		    mdl_chain, data_offset, data_length);
	buffer_list = NdisAllocateNetBufferList(pool, ctx_size, backfill);
	if (!buffer_list) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	buffer_list->header.data.first_buffer =
		NdisAllocateNetBuffer(pool->buffer_pool, mdl_chain, data_offset,
				      data_length);
	if (!buffer_list->header.data.first_buffer) {
		WARNING("couldn't allocate memory");
		NdisFreeNetBufferList(buffer_list);
		return NULL;
	}
	return buffer_list;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisRetreatNetBufferListDataStart,5)
	(struct net_buffer_list *buffer_list, ULONG offset, ULONG backfill,
	 void *alloc_handler, void *free_handler)
{
	struct net_buffer *buffer;
	NDIS_STATUS status;

	ENTER3("%p, %u, %u, %p, %p", buffer_list, offset, backfill,
		    alloc_handler, free_handler);

	for ( ; buffer_list; buffer_list = buffer_list->header.data.next) {
		buffer = buffer_list->header.data.first_buffer;
		status = NdisRetreatNetBufferDataStart(buffer, offset, backfill,
						       alloc_handler);
		if (status != NDIS_STATUS_SUCCESS)
			EXIT2(return status);
	}
	EXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisAdvanceNetBufferListDataStart,4)
	(struct net_buffer_list *buffer_list, ULONG offset,
	 BOOLEAN need_free_mdl, void *free_handler)
{
	struct net_buffer *buffer;

	ENTER3("%p, %u, %d, %p", buffer_list, offset, need_free_mdl,
		    free_handler);
	for ( ; buffer_list; buffer_list = buffer_list->header.data.next) {
		buffer = buffer_list->header.data.first_buffer;
		NdisAdvanceNetBufferDataStart(buffer, offset, need_free_mdl,
					      free_handler);
	}
	EXIT2(return);
}

wstdcall void WIN_FUNC(NdisMAllocateSharedMemory,5)
	(struct ndis_mp_block *nmb, ULONG size,
	 BOOLEAN cached, void **virt, NDIS_PHY_ADDRESS *phys)
{
	dma_addr_t dma_addr;

	ENTER3("size: %u, cached: %d", size, cached);
	*virt = PCI_DMA_ALLOC_COHERENT(nmb->wnd->wd->pci.pdev, size, &dma_addr);
	if (!*virt)
		WARNING("couldn't allocate %d bytes of %scached DMA memory",
			size, cached ? "" : "un-");
	*phys = dma_addr;
	EXIT3(return);
}

wstdcall void WIN_FUNC(NdisMFreeSharedMemory,5)
	(struct ndis_mp_block *nmb, ULONG size, BOOLEAN cached,
	 void *virt, NDIS_PHY_ADDRESS addr)
{
	ENTER3("%p, %p", nmb, virt);
	PCI_DMA_FREE_COHERENT(nmb->wnd->wd->pci.pdev, size, virt, addr);
	EXIT3(return);
}

wstdcall void alloc_shared_memory_async(void *arg1, void *arg2)
{
	struct ndis_device *wnd;
	struct alloc_shared_mem *alloc_shared_mem;
	struct ndis_sg_dma *sg_dma;
	void *virt;
	NDIS_PHY_ADDRESS phys;
	KIRQL irql;

	sg_dma = arg1;
	alloc_shared_mem = arg2;
	wnd = sg_dma->wnd;
	NdisMAllocateSharedMemory(wnd->nmb, alloc_shared_mem->size,
				  alloc_shared_mem->cached, &virt, &phys);
	irql = raise_irql(DISPATCH_LEVEL);
	LIN2WIN5(sg_dma->shmem_alloc_complete, wnd->nmb->adapter_ctx,
		 virt, &phys, alloc_shared_mem->size, alloc_shared_mem->ctx);
	lower_irql(irql);
	kfree(alloc_shared_mem);
}
WIN_FUNC_DECL(alloc_shared_memory_async,2)

/* NdisMAllocateSharedMemoryAsyncEx maps to
 * NdisMAllocateSharedMemoryAsync */
wstdcall NDIS_STATUS WIN_FUNC(NdisMAllocateSharedMemoryAsync,4)
	(struct ndis_sg_dma *sg_dma, ULONG size, BOOLEAN cached, void *ctx)
{
	struct alloc_shared_mem *alloc_shared_mem;

	ENTER3("sg_dma: %p", sg_dma);
	alloc_shared_mem = kzalloc(sizeof(*alloc_shared_mem), irql_gfp());
	if (!alloc_shared_mem) {
		WARNING("couldn't allocate memory");
		return NDIS_STATUS_FAILURE;
	}

	alloc_shared_mem->size = size;
	alloc_shared_mem->cached = cached;
	alloc_shared_mem->ctx = ctx;
	if (schedule_ntos_work_item(WIN_FUNC_PTR(alloc_shared_memory_async,2),
				    sg_dma, alloc_shared_mem))
		EXIT3(return NDIS_STATUS_FAILURE);
	EXIT3(return NDIS_STATUS_PENDING);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMInitializeScatterGatherDma,3)
	(struct ndis_mp_block *nmb, BOOLEAN dma_size, ULONG max_phy_map)
{
	ENTER2("dma_size=%d, maxtransfer=%u", dma_size, max_phy_map);
#ifdef CONFIG_X86_64
	if (dma_size != NDIS_DMA_64BITS)
		ERROR("DMA size is not 64-bits");
#endif
	nmb->wnd->sg_dma_size = max_phy_map;
	return NDIS_STATUS_SUCCESS;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMRegisterScatterGatherDma,3)
	(struct ndis_mp_block *nmb,
	 struct ndis_sg_dma_description *sg_descr,
	 struct ndis_sg_dma **sg_dma)
{
	ENTER2("%p", nmb);
	*sg_dma = kzalloc(sizeof(**sg_dma), GFP_ATOMIC);
	if (!*sg_dma) {
		WARNING("couldn't allocate memory");
		return NDIS_STATUS_RESOURCES;
	}
	nmb->wnd->sg_dma_size = sg_descr->max_physical_map;
	(*sg_dma)->sg_list_handler = sg_descr->sg_list_handler;
	(*sg_dma)->shmem_alloc_complete = sg_descr->shmem_alloc_complete;
	(*sg_dma)->max_physical_map = sg_descr->max_physical_map;
	(*sg_dma)->wnd = nmb->wnd;
	return NDIS_STATUS_SUCCESS;
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMDeregisterScatterGatherDma,3)
	(struct ndis_sg_dma *sg_dma)
{
	struct ndis_device *wnd = sg_dma->wnd;
	ENTER3("%p, %p", sg_dma, wnd);
	wnd->sg_dma_size = 0;
	kfree(sg_dma);
	return NDIS_STATUS_SUCCESS;
}

wstdcall ULONG WIN_FUNC(NdisMGetDmaAlignment,1)
	(struct ndis_mp_block *nmb)
{
	ENTER3("");
	return dma_get_cache_alignment();
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMAllocateNetBufferSGList,6)
	(struct ndis_device *wnd, struct net_buffer *buffer,
	 void *ctx, ULONG flags, struct ndis_sg_list *sg_list, ULONG size)
{
	int i, n, dir;
	struct net_buffer *b;
	struct ndis_sg_element *sg_elements;

	ENTER3("%p, %p, %u, %p, %u", buffer, ctx, flags, sg_list, size);
	/* only one net buffer and one mdl should be in buffer */
	/* TODO: one buffer may have more than one mdl */
	for (n = 0, b = buffer; b; b = b->header.data.next)
		n++;
	assert(n == 1);
	if (sg_list == NULL ||
	    size < sizeof(*sg_list) + n * sizeof(*sg_elements)) {
		size = sizeof(*sg_list) + n * sizeof(*sg_elements);
		sg_list = kzalloc(size, GFP_ATOMIC);
		if (!sg_list) {
			WARNING("couldn't allocate memory");
			return NDIS_STATUS_RESOURCES;
		}
		sg_list->reserved = WRAP_NDIS_SG_LIST;
	}

	if (flags & NDIS_SG_LIST_WRITE_TO_DEVICE)
		dir = PCI_DMA_TODEVICE;
	else
		dir = PCI_DMA_FROMDEVICE;

	assert(dir == PCI_DMA_TODEVICE);
	sg_list->nent = n;
	sg_list->reserved |= flags & NDIS_SG_LIST_WRITE_TO_DEVICE;
	sg_elements = sg_list->elements;
	for (i = 0, b = buffer; i < n && b; i++, b = b->header.data.next) {
		struct mdl *mdl = b->header.data.current_mdl;
		sg_elements[i].length = MmGetMdlByteCount(mdl);
		sg_elements[i].address =
			PCI_DMA_MAP_SINGLE(wnd->wd->pci.pdev,
					   MmGetMdlVirtualAddress(mdl),
					   sg_elements[i].length, dir);
	}
	TRACE3("%p", sg_list);
	LIN2WIN4(wnd->ndis_sg_dma.sg_list_handler, wnd->pdo, NULL,
		 sg_list, ctx);
	EXIT2(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisMFreeNetBufferSGList,6)
	(struct ndis_device *wnd, struct ndis_sg_list *sg_list,
	 struct net_buffer *buffer)
{
	int i, dir;
	struct ndis_sg_element *sg_elements;

	ENTER3("%p, %p, %p", wnd, sg_list, buffer);
	if (sg_list->reserved & NDIS_SG_LIST_WRITE_TO_DEVICE)
		dir = PCI_DMA_TODEVICE;
	else
		dir = PCI_DMA_FROMDEVICE;
	assert(dir == PCI_DMA_TODEVICE);
	sg_elements = sg_list->elements;
	for (i = 0; i < sg_list->nent; i++) {
		PCI_DMA_UNMAP_SINGLE(wnd->wd->pci.pdev, sg_elements[i].address,
				     sg_elements[i].length, dir);
	}
	if (sg_list->reserved & WRAP_NDIS_SG_LIST)
		kfree(sg_list);
	EXIT4(return);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisAllocateTimerObject,3)
	(struct ndis_mp_block *nmb,
	 struct ndis_timer_characteristics *timer_chars, void **timer_object)
{
	struct ndis_timer *timer;
	ENTER3("%p, %p, %p", nmb, timer_chars->func, timer_chars->ctx);
	timer = kzalloc(sizeof(*timer), irql_gfp());
	if (!timer) {
		WARNING("couldn't allocate memory");
		return NDIS_STATUS_RESOURCES;
	}
	KeInitializeDpc(&timer->kdpc, timer_chars->func, timer_chars->ctx);
	wrap_init_timer(&timer->nt_timer, NotificationTimer, NULL);
	*timer_object = timer;
	TRACE3("%p", timer);
	EXIT3(return NDIS_STATUS_SUCCESS);
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
	ENTER4("%p, %lu, %lu", timer, expires_hz, repeat_hz);
	if (ctx)
		timer->kdpc.ctx = ctx;
	return wrap_set_timer(&timer->nt_timer, expires_hz, repeat_hz,
			      &timer->kdpc);
}

wstdcall BOOLEAN WIN_FUNC(NdisCancelTimerObject,1)
	(struct ndis_timer *timer)
{
	return KeCancelTimer(&timer->nt_timer);
}

wstdcall void WIN_FUNC(NdisFreeTimerObject,1)
	(struct ndis_timer *timer)
{
	ENTER3("%p", timer);
	wrap_free_timer(&timer->nt_timer);
	kfree(timer);
}

wstdcall void WIN_FUNC(NdisMOidRequestComplete,3)
	(struct ndis_mp_block *nmb, struct ndis_oid_request *oid_request,
	 NDIS_STATUS status)
{
	struct ndis_device *wnd = nmb->wnd;
	ENTER2("wnd: %p, %08X", wnd, status);
	wnd->ndis_comm_status = status;
	wnd->ndis_comm_done = 1;
	wake_up(&wnd->ndis_comm_wq);
	EXIT2(return);
}

wstdcall struct mdl *WIN_FUNC(NdisAllocateMdl,3)
	(void *handle, void *virt, UINT length)
{
	struct mdl *mdl;

	ENTER4("%p, %p, %u", handle, virt, length);
	mdl = allocate_init_mdl(virt, length);
	MmBuildMdlForNonPagedPool(mdl);
//	mdl->flags |= MDL_SOURCE_IS_NONPAGED_POOL;
//	mdl->flags |= MDL_ALLOCATED_FIXED_SIZE;
	TRACE4("%p", mdl);
	return mdl;
}

wstdcall void WIN_FUNC(NdisFreeMdl,1)
	(struct mdl *mdl)
{
	ENTER4("%p", mdl);
	free_mdl(mdl);
}

wstdcall void mp_timer_dpc(struct kdpc *kdpc, void *ctx, void *arg1, void *arg2)
{
	struct ndis_mp_timer *timer;

	timer = ctx;
	ENTER3("timer: %p, func: %p, ctx: %p, nmb: %p",
	       timer, timer->func, timer->ctx, timer->nmb);
	/* already called at DISPATCH_LEVEL */
	LIN2WIN4(timer->func, NULL, timer->ctx, NULL, NULL);
	EXIT3(return);
}
WIN_FUNC_DECL(mp_timer_dpc,4)

wstdcall void WIN_FUNC(NdisMInitializeTimer,4)
	(struct ndis_mp_timer *timer, struct ndis_mp_block *nmb,
	 DPC func, void *ctx)
{
	ENTER3("timer: %p, func: %p, ctx: %p, nmb: %p",
	       timer, func, ctx, nmb);
	timer->func = func;
	timer->ctx = ctx;
	timer->nmb = nmb;
	KeInitializeDpc(&timer->kdpc, func, ctx);
//	KeInitializeDpc(&timer->kdpc, WIN_FUNC_PTR(mp_timer_dpc,4), timer);
	wrap_init_timer(&timer->nt_timer, NotificationTimer, nmb);
	EXIT3(return);
}

wstdcall void WIN_FUNC(NdisMSetPeriodicTimer,2)
	(struct ndis_mp_timer *timer, UINT period_ms)
{
	unsigned long expires = MSEC_TO_HZ(period_ms);

	ENTER3("%p, %u, %ld, %p", timer, period_ms, expires, &timer->kdpc);
	wrap_set_timer(&timer->nt_timer, expires, expires, &timer->kdpc);
	EXIT3(return);
}

wstdcall void WIN_FUNC(NdisMCancelTimer,2)
	(struct ndis_mp_timer *timer, BOOLEAN *canceled)
{
	ENTER4("%p", timer);
	*canceled = KeCancelTimer(&timer->nt_timer);
	EXIT4(return);
}

wstdcall void WIN_FUNC(NdisInitializeTimer,3)
	(struct ndis_timer *timer, void *func, void *ctx)
{
	ENTER4("%p, %p, %p", timer, func, ctx);
	KeInitializeDpc(&timer->kdpc, func, ctx);
	wrap_init_timer(&timer->nt_timer, NotificationTimer, NULL);
	EXIT4(return);
}

/* NdisMSetTimer is a macro that calls NdisSetTimer with
 * ndis_mp_timer typecast to ndis_timer */

wstdcall void WIN_FUNC(NdisSetTimer,2)
	(struct ndis_timer *timer, UINT duetime_ms)
{
	unsigned long expires = MSEC_TO_HZ(duetime_ms);

	ENTER4("%p, %p, %u, %ld", timer, timer->nt_timer.wrap_timer,
		    duetime_ms, expires);
	wrap_set_timer(&timer->nt_timer, expires, 0, &timer->kdpc);
	EXIT4(return);
}

wstdcall void WIN_FUNC(NdisCancelTimer,2)
	(struct ndis_timer *timer, BOOLEAN *canceled)
{
	ENTER4("%p", timer);
	*canceled = KeCancelTimer(&timer->nt_timer);
	EXIT4(return);
}

wstdcall void WIN_FUNC(NdisReadNetworkAddress,4)
	(NDIS_STATUS *status, void **addr, UINT *len,
	 struct ndis_mp_block *nmb)
{
	struct ndis_device *wnd = nmb->wnd;
	struct ndis_configuration_parameter *param;
	struct unicode_string key;
	struct ansi_string ansi;
	typeof(wnd->mac) mac;
	int i, ret;

	ENTER1("");
	RtlInitAnsiString(&ansi, "mac_address");
	*len = 0;
	*status = NDIS_STATUS_FAILURE;
	if (RtlAnsiStringToUnicodeString(&key, &ansi, TRUE) != STATUS_SUCCESS)
		EXIT1(return);

	NdisReadConfiguration(&ret, &param, nmb, &key, NdisParameterString);
	RtlFreeUnicodeString(&key);
	if (ret != NDIS_STATUS_SUCCESS)
		EXIT1(return);
	ret = RtlUnicodeStringToAnsiString(&ansi, &param->data.string, TRUE);
	if (ret != STATUS_SUCCESS)
		EXIT1(return);

	i = 0;
	if (ansi.length >= 2 * sizeof(mac)) {
		for (i = 0; i < sizeof(mac); i++) {
			char c[3];
			int x;
			c[0] = ansi.buf[i*2];
			c[1] = ansi.buf[i*2+1];
			c[2] = 0;
			ret = sscanf(c, "%x", &x);
			if (ret != 1)
				break;
			mac[i] = x;
		}
	}
	RtlFreeAnsiString(&ansi);
	if (i == sizeof(mac)) {
		memcpy(wnd->mac, mac, sizeof(wnd->mac));
		*len = sizeof(mac);
		*addr = wnd->mac;
		*status = NDIS_STATUS_SUCCESS;
	}
	EXIT1(return);
}

wstdcall void WIN_FUNC(NdisMRegisterAdapterShutdownHandler,3)
	(struct ndis_mp_block *nmb, void *ctx, void *func)
{
	ENTER1("%p", func);
//	nmb->wnd->wd->driver->ndis_driver->miniport.shutdown = func;
	nmb->wnd->shutdown_ctx = ctx;
}

wstdcall void WIN_FUNC(NdisMDeregisterAdapterShutdownHandler,1)
	(struct ndis_mp_block *nmb)
{
//	nmb->wnd->wd->driver->ndis_driver->miniport.shutdown = NULL;
	nmb->wnd->shutdown_ctx = NULL;
}

wstdcall void ndis_irq_handler(struct kdpc *kdpc, void *ctx,
			       void *arg1, void *arg2)
{
	mp_isr_dpc_handler isr_dpc_handler = arg1;

	ENTER4("%p, %p", arg1, arg2);
	LIN2WIN4(isr_dpc_handler, ctx, NULL, NULL, NULL);
	EXIT4(return);
}
WIN_FUNC_DECL(ndis_irq_handler,4)

wstdcall BOOLEAN ndis_isr(struct kinterrupt *interrupt, void *ctx)
{
	struct ndis_device *wnd = ctx;
	BOOLEAN recognized = TRUE, queue_handler = TRUE;
	ULONG proc = 0;

	ENTER6("%p", wnd);
	recognized = LIN2WIN3(wnd->interrupt_chars.isr, wnd->isr_ctx,
			      &queue_handler, &proc);
	/* TODO: schedule worker on processors indicated */
	if (queue_handler)
		queue_kdpc(&wnd->irq_kdpc);
	if (recognized)
		EXIT5(return TRUE);
	else
		return FALSE;
}
WIN_FUNC_DECL(ndis_isr,2)

wstdcall NDIS_STATUS WIN_FUNC(NdisMRegisterInterruptEx,4)
	(struct ndis_mp_block *nmb, void *isr_ctx,
	 struct mp_interrupt_characteristics *mp_interrupt_chars,
	 void **handle)
{
	struct ndis_device *wnd = nmb->wnd;
	ENTER1("%p, %p", wnd, isr_ctx);
	memcpy(&wnd->interrupt_chars, mp_interrupt_chars,
	       sizeof(wnd->interrupt_chars));
	mp_interrupt_chars->interrupt_type = NDIS_CONNECT_LINE_BASED;
	wnd->isr_ctx = isr_ctx;
	KeInitializeDpc(&wnd->irq_kdpc, WIN_FUNC_PTR(ndis_irq_handler,4),
			isr_ctx);
	wnd->irq_kdpc.arg1 = mp_interrupt_chars->isr_dpc_handler;
	wnd->irq_kdpc.arg2 = wnd;

	if (IoConnectInterrupt(&wnd->kinterrupt, WIN_FUNC_PTR(ndis_isr,2), wnd,
			       NULL, wnd->wd->pci.pdev->irq, DIRQL, DIRQL,
			       0, TRUE, 0, FALSE) != STATUS_SUCCESS) {
		printk(KERN_WARNING "%s: request for IRQ %d failed\n",
		       DRIVER_NAME, wnd->wd->pci.pdev->irq);
		return NDIS_STATUS_RESOURCES;
	}
	printk(KERN_INFO "%s: using IRQ %d\n",
	       DRIVER_NAME, wnd->wd->pci.pdev->irq);
	*handle = nmb;
	EXIT1(return NDIS_STATUS_SUCCESS);
}

wstdcall void WIN_FUNC(NdisMDeregisterInterruptEx,1)
	(struct ndis_mp_block *nmb)
{
	ENTER1("%p", nmb);

	IoDisconnectInterrupt(nmb->wnd->kinterrupt);
	nmb->wnd->kinterrupt = NULL;
	EXIT1(return);
}

wstdcall BOOLEAN WIN_FUNC(NdisMSynchronizeWithInterruptEx,3)
	(struct ndis_mp_block *nmb, ULONG msg_id, void *func, void *ctx)
{
	return KeSynchronizeExecution(nmb->wnd->kinterrupt, func, ctx);
}

wstdcall void WIN_FUNC(NdisMIndicateStatusEx,4)
	(struct ndis_mp_block *nmb, struct ndis_status_indication *status)
{
	struct ndis_device *wnd = nmb->wnd;
	struct ndis_link_state *link_state;
	struct ndis_dot11_association_start_parameters *assoc_start;
	struct ndis_dot11_association_completion_parameters *assoc_comp;
	struct ndis_dot11_connection_start_parameters *conn_start;
	struct ndis_dot11_connection_completion_parameters *conn_comp;
	struct ndis_dot11_phy_state_parameters *phy_state;
	struct ndis_dot11_link_quality_parameters *link_quality;
	struct ndis_dot11_link_quality_entry *link_quality_entry;

	ENTER2("status=0x%x", status->code);
	if (status->header.type !=  NDIS_OBJECT_TYPE_STATUS_INDICATION) {
		ERROR("invalid status: 0x%x", status->header.type);
		return;
	}

	switch (status->code) {
	case NDIS_STATUS_LINK_STATE:
		link_state = status->buf;
		TRACE2("%d", link_state->media_connect_state);
		if (link_state->media_connect_state ==
		    MediaConnectStateConnected) {
			set_media_state(wnd, NdisMediaStateConnected);
		} else if (link_state->media_connect_state ==
			   MediaConnectStateDisconnected) {
			set_media_state(wnd, NdisMediaStateDisconnected);
		}
		break;
	case NDIS_STATUS_DOT11_ASSOCIATION_START:
		assoc_start = status->buf;
		(void)assoc_start;
		TRACE2("0x%x, 0x%zx, " MACSTRSEP, assoc_start->header.size,
		       sizeof(*assoc_start), MAC2STR(assoc_start->mac));
		break;
	case NDIS_STATUS_DOT11_ASSOCIATION_COMPLETION:
		assoc_comp = status->buf;
		(void)assoc_comp;
		TRACE2("0x%x, 0x%zx, 0x%x", assoc_comp->header.size,
		       sizeof(*assoc_comp), status->buf_len);
		TRACE2("ap: " MACSTRSEP ", 0x%x, 0x%x, 0x%x",
		       MAC2STR(assoc_comp->mac), assoc_comp->status,
		       assoc_comp->auth_algo, assoc_comp->unicast_cipher);
		break;
	case NDIS_STATUS_DOT11_DISASSOCIATION:
		netif_carrier_off(wnd->net_dev);
		set_bit(LINK_STATUS_CHANGED, &wnd->ndis_pending_work);
		schedule_wrapndis_work(&wnd->ndis_work);
		break;
	case NDIS_STATUS_DOT11_CONNECTION_START:
		conn_start = status->buf;
		(void)conn_start;
		TRACE2("0x%x, 0x%zx, 0x%x", conn_start->header.size,
		       sizeof(*conn_start), conn_start->bss_type);
		break;
	case NDIS_STATUS_DOT11_CONNECTION_COMPLETION:
		conn_comp = status->buf;
		TRACE2("0x%x, 0x%zx, 0x%x", conn_comp->header.size,
		       sizeof(*conn_comp), conn_comp->status);
		if (conn_comp->status == DOT11_ASSOC_STATUS_SUCCESS) {
			netif_carrier_on(wnd->net_dev);
			set_bit(LINK_STATUS_CHANGED,
				&wnd->ndis_pending_work);
			schedule_wrapndis_work(&wnd->ndis_work);
		}
		break;
	case NDIS_STATUS_DOT11_SCAN_CONFIRM:
		TRACE2("status: %08X, %p, %p, %u, %u", status->code,
		       status->dst_handle, status->request_id,
		       *((ULONG *)status->buf), status->buf_len);
		break;
	case NDIS_STATUS_DOT11_PHY_STATE_CHANGED:
		phy_state = status->buf;
		(void)phy_state;
		TRACE2("%d, %d, %d", phy_state->phy_id, phy_state->hw_state,
		       phy_state->sw_state);
		set_bit(PHY_STATE_CHANGED, &wnd->ndis_pending_work);
		schedule_wrapndis_work(&wnd->ndis_work);
		break;
	case NDIS_STATUS_DOT11_LINK_QUALITY:
		link_quality = status->buf;
		link_quality_entry = (typeof(link_quality_entry))
			&((char *)status->buf)[link_quality->list_offset];
		TRACE2(MACSTRSEP ", %u", MAC2STR(link_quality_entry->peer_mac),
		       link_quality_entry->quality);
		break;
	default:
		TRACE2("unknown status: %08X, %p, %p, %p %u", status->code,
		       status->dst_handle, status->request_id, status->buf,
		       status->buf_len);
		break;
	}

	EXIT2(return);
}

wstdcall void return_net_buffer_lists(void *arg1, void *arg2)
{
	struct ndis_device *wnd;
	struct net_buffer_list *buffer_list;
	struct ndis_driver *ndis_driver;

	wnd = arg1;
	buffer_list = arg2;
	ENTER4("%p, %p", wnd, buffer_list);
	ndis_driver = wnd->wd->driver->ndis_driver;
	LIN2WIN3(ndis_driver->mp_driver.return_net_buffer_lists,
		 wnd->nmb->adapter_ctx, buffer_list, 0);
	EXIT4(return);
}
WIN_FUNC_DECL(return_net_buffer_lists,2)

wstdcall void WIN_FUNC(NdisMIndicateReceiveNetBufferLists,5)
	(struct ndis_mp_block *nmb, struct net_buffer_list *buffer_list,
	NDIS_PORT_NUMBER port, ULONG num_lists, ULONG rx_flags)
{
	struct ndis_device *wnd = nmb->wnd;
	struct net_buffer_list *blist;
	struct net_buffer *buffer;
	struct mdl *mdl;
	struct sk_buff *skb;
	UINT i, total_length = 0;

	ENTER3("%p, %d", wnd, num_lists);
	blist = buffer_list;
	for (i = 0, blist = buffer_list; i < num_lists;
	     i++, blist = blist->header.data.next) {
		for (buffer = blist->header.data.first_buffer; buffer;
		     buffer = buffer->header.data.next) {
			for (mdl = buffer->header.data.mdl_chain; mdl;
			     mdl = mdl->next) {
				total_length += MmGetMdlByteCount(mdl);
			}
		}
	}
	skb = dev_alloc_skb(total_length);
	if (skb) {
		for (i = 0, blist = buffer_list; i < num_lists;
		     i++, blist = blist->header.data.next) {
			for (buffer = blist->header.data.first_buffer; buffer;
			     buffer = buffer->header.data.next) {
				for (mdl = buffer->header.data.mdl_chain; mdl;
				     mdl = mdl->next) {
					memcpy_skb(skb,
						   MmGetSystemAddressForMdl(mdl),
						   MmGetMdlByteCount(mdl));
				}
			}
		}
		skb->dev = wnd->net_dev;
		skb->protocol = eth_type_trans(skb, wnd->net_dev);
		pre_atomic_add(wnd->stats.rx_bytes, total_length);
		atomic_inc_var(wnd->stats.rx_packets);
		if (in_interrupt())
			netif_rx(skb);
		else
			netif_rx_ni(skb);
	} else {
		WARNING("couldn't allocate skb; packet dropped");
		atomic_inc_var(wnd->stats.rx_dropped);
	}
	if (rx_flags & NDIS_RECEIVE_FLAGS_RESOURCES)
		EXIT2(return);
	schedule_ntos_work_item(WIN_FUNC_PTR(return_net_buffer_lists,2),
				wnd, buffer_list);
	EXIT3(return);
}

wstdcall void WIN_FUNC(NdisMSendNetBufferListsComplete,3)
	(struct ndis_mp_block *nmb, struct net_buffer_list *buffer_list,
	 ULONG flags)
{
	TRACE3("%p, %08X", buffer_list, buffer_list->status);
	free_tx_buffer_list(nmb->wnd, buffer_list);
}

wstdcall void WIN_FUNC(NdisMSleep,1)
	(ULONG us)
{
	unsigned long delay;

	ENTER4("%p: us: %u", current, us);
	delay = USEC_TO_HZ(us);
	sleep_hz(delay);
	TRACE4("%p: done", current);
}

wstdcall void WIN_FUNC(NdisGetCurrentSystemTime,1)
	(LARGE_INTEGER *time)
{
	*time = ticks_1601();
	TRACE5("%Lu, %lu", *time, jiffies);
}

wstdcall NDIS_STATUS WIN_FUNC(NdisMRegisterIoPortRange,4)
	(void **virt, struct ndis_mp_block *nmb, UINT start, UINT len)
{
	ENTER3("%08x %08x", start, len);
	*virt = (void *)(ULONG_PTR)start;
	return NDIS_STATUS_SUCCESS;
}

wstdcall void WIN_FUNC(NdisMDeregisterIoPortRange,4)
	(struct ndis_mp_block *nmb, UINT start, UINT len, void* virt)
{
	ENTER1("%08x %08x", start, len);
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
	return num_online_cpus();
}

wstdcall void WIN_FUNC(NdisInitializeEvent,1)
	(struct ndis_event *ndis_event)
{
	ENTER3("%p", ndis_event);
	KeInitializeEvent(&ndis_event->nt_event, NotificationEvent, 0);
}

wstdcall BOOLEAN WIN_FUNC(NdisWaitEvent,2)
	(struct ndis_event *ndis_event, UINT ms)
{
	LARGE_INTEGER ticks;
	NTSTATUS res;

	ENTER3("%p %u", ndis_event, ms);
	ticks = -((LARGE_INTEGER)ms * TICKSPERMSEC);
	res = KeWaitForSingleObject(&ndis_event->nt_event, 0, 0, TRUE,
				    ms == 0 ? NULL : &ticks);
	if (res == STATUS_SUCCESS)
		EXIT3(return TRUE);
	else
		EXIT3(return FALSE);
}

wstdcall void WIN_FUNC(NdisSetEvent,1)
	(struct ndis_event *ndis_event)
{
	ENTER3("%p", ndis_event);
	KeSetEvent(&ndis_event->nt_event, 0, 0);
}

wstdcall void WIN_FUNC(NdisResetEvent,1)
	(struct ndis_event *ndis_event)
{
	ENTER3("%p", ndis_event);
	KeResetEvent(&ndis_event->nt_event);
}

/* called via function pointer */
wstdcall void WIN_FUNC(NdisMResetComplete,3)
	(struct ndis_mp_block *nmb,
	 NDIS_STATUS status, BOOLEAN address_reset)
{
	ENTER3("status: %08X, %u", status, address_reset);
	nmb->wnd->ndis_comm_status = status;
	nmb->wnd->ndis_comm_done = 1 + address_reset;
	wake_up(&nmb->wnd->ndis_comm_wq);
	EXIT3(return);
}

wstdcall void WIN_FUNC(NdisMPauseComplete,1)
	(struct ndis_mp_block *nmb)
{
	ENTER3("%p", nmb);
	EXIT3(return);
}

static void ndis_worker(worker_param_t dummy)
{
	struct ndis_work_entry *ndis_work_entry;
	struct nt_list *ent;
	struct ndis_work_item *ndis_work_item;

	WORKENTER("");
	while (1) {
		spin_lock_bh(&ndis_work_list_lock);
		ent = RemoveHeadList(&ndis_worker_list);
		spin_unlock_bh(&ndis_work_list_lock);
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

	ENTER3("%p", ndis_work_item);
	ndis_work_entry = kzalloc(sizeof(*ndis_work_entry), irql_gfp());
	if (!ndis_work_entry)
		BUG();
	ndis_work_entry->ndis_work_item = ndis_work_item;
	spin_lock_bh(&ndis_work_list_lock);
	InsertTailList(&ndis_worker_list, &ndis_work_entry->list);
	spin_unlock_bh(&ndis_work_list_lock);
	WORKTRACE("scheduling %p", ndis_work_item);
	schedule_ndis_work(&ndis_work);
	EXIT3(return NDIS_STATUS_SUCCESS);
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

wstdcall UINT WIN_FUNC(NdisGetVersion,0)
	(void)
{
	return (6 << 16) | 0;
}

wstdcall void WIN_FUNC(NdisMRemoveMiniport,1)
	(void *handle)
{
	TODO();
}

/* ndis_init_device is called for each device */
int ndis_init_device(struct ndis_device *wnd)
{
	struct ndis_mp_block *nmb = wnd->nmb;

	nmb->reset_complete = WIN_FUNC_PTR(NdisMResetComplete,3);
	return 0;
}

/* ndis_exit_device is called for each handle */
void ndis_exit_device(struct ndis_device *wnd)
{
	struct wrap_device_setting *setting;
	TRACE2("%p", wnd);
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
/* ndis_init is called once when module is loaded */
int ndis_init(void)
{
	ndis_wq = create_singlethread_workqueue("ndis_wq");
	if (!ndis_wq) {
		WARNING("couldn't create worker thread");
		EXIT1(return -ENOMEM);
	}
	ndis_worker_thread = wrap_worker_init(ndis_wq);
	TRACE1("%p", ndis_worker_thread);
	InitializeListHead(&ndis_worker_list);
	spin_lock_init(&ndis_work_list_lock);
	initialize_work(&ndis_work, ndis_worker, NULL);

	return 0;
}

/* ndis_exit is called once when module is removed */
void ndis_exit(void)
{
	if (ndis_wq)
		destroy_workqueue(ndis_wq);
	if (ndis_worker_thread)
		ObDereferenceObject(ndis_worker_thread);
	EXIT1(return);
}
