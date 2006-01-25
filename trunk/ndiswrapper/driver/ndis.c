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
#define MAX_ALLOCATED_NDIS_BUFFERS 40

extern struct nt_list wrap_drivers;
extern NT_SPIN_LOCK ntoskernel_lock, loader_lock;

/* ndis_init is called once when module is loaded */
int ndis_init(void)
{
	return 0;
}

/* ndis_exit is called once when module is removed */
void ndis_exit(void)
{
	/* TODO: free all packets in all pools */
	TRACEEXIT1(return);
}

/* ndis_exit_device is called for each handle */
void ndis_exit_device(struct wrap_ndis_device *wnd)
{
	struct wrap_device_setting *setting;

	/* TI driver doesn't call NdisMDeregisterInterrupt during halt! */
	if (wnd->ndis_irq)
		NdisMDeregisterInterrupt(wnd->ndis_irq);
	nt_spin_lock(&loader_lock);
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
	nt_spin_unlock(&loader_lock);
}

/* Called from the driver entry. */
STDCALL void WRAP_EXPORT(NdisInitializeWrapper)
	(void **driver_handle, struct driver_object *driver,
	 struct unicode_string *reg_path, void *unused)
{
	TRACEENTER1("handle: %p, driver: %p", driver_handle, driver);
	*driver_handle = driver;
	TRACEEXIT1(return);
}

STDCALL void WRAP_EXPORT(NdisTerminateWrapper)
	(struct device_object *dev_obj, void *SystemSpecific1)
{
	TRACEEXIT1(return);
}

/* Register a miniport with NDIS. Called from driver entry */
STDCALL NDIS_STATUS WRAP_EXPORT(NdisMRegisterMiniport)
	(struct driver_object *drv_obj,
	 struct miniport_char *miniport_char, UINT char_len)
{
	int min_length;
	void **func;
	struct wrap_driver *wrap_driver;
	struct wrap_ndis_driver *ndis_driver;

	min_length = ((char *)&miniport_char->co_create_vc) -
		((char *)miniport_char);

	TRACEENTER1("%p %p %d", drv_obj, miniport_char, char_len);

	if (miniport_char->major_version < 4) {
		ERROR("Driver is using ndis version %d which is too old.",
		      miniport_char->major_version);
		TRACEEXIT1(return NDIS_STATUS_BAD_VERSION);
	}

	if (char_len < min_length) {
		ERROR("Characteristics length %d is too small", char_len);
		TRACEEXIT1(return NDIS_STATUS_BAD_CHARACTERISTICS);
	}

	DBGTRACE1("Version %d.%d", miniport_char->major_version,
		  miniport_char->minor_version);
	DBGTRACE1("Len: %08x:%u", char_len, (u32)sizeof(struct miniport_char));

	wrap_driver =
		IoGetDriverObjectExtension(drv_obj,
					   (void *)CE_WRAP_DRIVER_CLIENT_ID);
	if (!wrap_driver) {
		ERROR("couldn't get wrap_driver");
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	}
	if (IoAllocateDriverObjectExtension(drv_obj,
					    (void *)CE_NDIS_DRIVER_CLIENT_ID,
					    sizeof(*ndis_driver),
					    (void **)&ndis_driver) !=
	    STATUS_SUCCESS)
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	wrap_driver->ndis_driver = ndis_driver;
	TRACEENTER1("ndis_driver: %p", ndis_driver);
	memcpy(&ndis_driver->miniport, miniport_char,
	       char_len > sizeof(*miniport_char) ?
	       sizeof(*miniport_char) : char_len);

	DBG_BLOCK() {
		int i;
		char *miniport_funcs[] = {
			"query", "reconfig", "reset", "send", "setinfo",
			"tx_data", "return_packet", "send_packets",
			"alloc_complete", "co_create_vc", "co_delete_vc",
			"co_activate_vc", "co_deactivate_vc",
			"co_send_packets", "co_request",
			"cancel_send_packets", "pnp_event_notify",
			"shutdown",
		};
		func = (void **)&ndis_driver->miniport.query;
		for (i = 0; i < (sizeof(miniport_funcs) /
				 sizeof(miniport_funcs[0])); i++)
			DBGTRACE2("miniport function '%s' is at %p",
				  miniport_funcs[i], func[i]);
	}
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMRegisterDevice)
	(struct driver_object *drv_obj, struct unicode_string *dev_name,
	 struct unicode_string *link, void **funcs,
	 struct device_object **dev_obj, void **dev_obj_handle)
{
	NTSTATUS status;
	struct device_object *tmp;
	int i;

	TRACEENTER1("%p, %p, %p", drv_obj, dev_name, link);
	status = IoCreateDevice(drv_obj, 0, dev_name, FILE_DEVICE_NETWORK, 0,
				FALSE, &tmp);

	if (status != STATUS_SUCCESS)
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	if (link)
		status = IoCreateSymbolicLink(link, dev_name);
	if (status != STATUS_SUCCESS) {
		IoDeleteDevice(tmp);
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	}

	*dev_obj = tmp;
	*dev_obj_handle = *dev_obj;
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		if (funcs[i] && i != IRP_MJ_PNP && i != IRP_MJ_POWER) {
			drv_obj->major_func[i] = funcs[i];
			DBGTRACE1("mj_fn for 0x%x is at %p", i, funcs[i]);
		}
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMDeregisterDevice)
	(struct device_object *dev_obj)
{
	TRACEENTER2("%p", dev_obj);
	IoDeleteDevice(dev_obj);
	return NDIS_STATUS_SUCCESS;
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisAllocateMemoryWithTag)
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

STDCALL NDIS_STATUS WRAP_EXPORT(NdisAllocateMemory)
	(void **dest, UINT length, UINT flags,
	 NDIS_PHY_ADDRESS highest_address)
{
	DBGTRACE4("length = %u, flags = %08X", length, flags);
	return NdisAllocateMemoryWithTag(dest, length, 0);
}

/* length_tag is either length or tag, depending on if
 * NdisAllocateMemory or NdisAllocateMemoryTag is used to allocate
 * memory */
STDCALL void WRAP_EXPORT(NdisFreeMemory)
	(void *addr, UINT length_tag, UINT flags)
{
	ExFreePool(addr);
}

/*
 * This function should not be STDCALL because it's a variable args function.
 */
NOREGPARM void WRAP_EXPORT(NdisWriteErrorLogEntry)
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
		ERROR("code: %u", code);
	}
	va_end(args);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisOpenConfiguration)
	(NDIS_STATUS *status, struct ndis_miniport_block **conf_handle,
	 struct ndis_miniport_block *handle)
{
	TRACEENTER2("confHandle: %p", conf_handle);
	*conf_handle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisOpenProtocolConfiguration)
	(NDIS_STATUS *status, void **confhandle,
	 struct unicode_string *section)
{
	TRACEENTER2("confHandle: %p", confhandle);
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisOpenConfigurationKeyByName)
	(NDIS_STATUS *status, void *handle,
	 struct unicode_string *key, void **subkeyhandle)
{
	struct ansi_string ansi;
	TRACEENTER2("");
	if (RtlUnicodeStringToAnsiString(&ansi, key, TRUE) == STATUS_SUCCESS) {
		DBGTRACE2("key: %s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	} else
		DBGTRACE2("couldn't convert ustring %d, %d, %p",
			  key->length, key->max_length, key->buf);
	*subkeyhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisOpenConfigurationKeyByIndex)
	(NDIS_STATUS *status, void *handle, ULONG index,
	 struct unicode_string *key, void **subkeyhandle)
{
	TRACEENTER2("index: %u", index);
	*subkeyhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisCloseConfiguration)
	(void *handle)
{
	/* instead of freeing all configuration parameters as we are
	 * supposed to do here, we free them when the device is
	 * removed */
	TRACEENTER2("handle: %p", handle);
	return;
}

STDCALL void WRAP_EXPORT(NdisOpenFile)
	(NDIS_STATUS *status, struct wrap_bin_file **file,
	 UINT *filelength, struct unicode_string *filename,
	 NDIS_PHY_ADDRESS highest_address)
{
	struct ansi_string ansi;
	struct wrap_bin_file *bin_file;

	TRACEENTER2("status = %p, filelength = %p, *filelength = %d, "
		    "high = %llx, file = %p, *file = %p",
		    status, filelength, *filelength,
		    highest_address, file, *file);

	if (RtlUnicodeStringToAnsiString(&ansi, filename, TRUE) !=
	    STATUS_SUCCESS) {
		*status = NDIS_STATUS_RESOURCES;
		TRACEEXIT2(return);
	}
	DBGTRACE2("Filename: %s", ansi.buf);

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

STDCALL void WRAP_EXPORT(NdisMapFile)
	(NDIS_STATUS *status, void **mappedbuffer, struct wrap_bin_file *file)
{
	TRACEENTER2("handle: %p", file);

	if (!file) {
		*status = NDIS_STATUS_ALREADY_MAPPED;
		TRACEEXIT2(return);
	}

	*status = NDIS_STATUS_SUCCESS;
	*mappedbuffer = file->data;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisUnmapFile)
	(struct wrap_bin_file *file)
{
	TRACEENTER2("handle: %p", file);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisCloseFile)
	(struct wrap_bin_file *file)
{
	TRACEENTER2("handle: %p", file);
	free_bin_file(file);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisGetSystemUpTime)
	(ULONG *ms)
{
	TRACEENTER5("");
	*ms = 1000 * jiffies / HZ;
	TRACEEXIT5(return);
}

/* called as macro */
STDCALL ULONG WRAP_EXPORT(NDIS_BUFFER_TO_SPAN_PAGES)
	(ndis_buffer *buffer)
{
	ULONG_PTR start;
	ULONG n;

	TRACEENTER4("");

	if (buffer == NULL)
		return 0;

	if (MmGetMdlByteCount(buffer) == 0)
		return 1;

	start = (ULONG_PTR)(MmGetMdlVirtualAddress(buffer));
	n = SPAN_PAGES(start, MmGetMdlByteCount(buffer));
	DBGTRACE4("pages = %u", n);
	TRACEEXIT4(return n);
}

STDCALL void WRAP_EXPORT(NdisGetBufferPhysicalArraySize)
	(ndis_buffer *buffer, UINT *arraysize)
{
	TRACEENTER3("Buffer: %p", buffer);
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
			return param;
		if (param->type == NdisParameterString)
			RtlFreeUnicodeString(&param->data.string);
		ExFreePool(param);
		setting->encoded = NULL;
	}
	param = ExAllocatePoolWithTag(NonPagedPool, sizeof(*param), 0);
	if (!param) {
		ERROR("couldn't allocate memory");
		return NULL;
	}
	param->type = type;
	TRACEENTER2("type = %d", type);
	switch(type) {
	case NdisParameterInteger:
		param->data.integer = simple_strtol(setting->value, NULL, 0);
		DBGTRACE1("value = %u", (ULONG)param->data.integer);
		break;
	case NdisParameterHexInteger:
		param->data.integer = simple_strtol(setting->value, NULL, 16);
		DBGTRACE1("value = %u", (ULONG)param->data.integer);
		break;
	case NdisParameterString:
		ansi.length = strlen(setting->value);
		ansi.max_length = ansi.length + 1;
		ansi.buf = setting->value;
		DBGTRACE2("setting value = %s", ansi.buf);
		if (RtlAnsiStringToUnicodeString(&param->data.string,
						 &ansi, TRUE)) {
			ExFreePool(param);
			TRACEEXIT1(return NULL);
		}
		break;
	default:
		ERROR("unknown type: %d", type);
		ExFreePool(param);
		return NULL;
	}
	setting->encoded = param;
	return param;
}

static int ndis_decode_setting(struct wrap_device_setting *setting,
			       struct ndis_configuration_parameter *param)
{
	struct ansi_string ansi;

	switch(param->type) {
	case NdisParameterInteger:
		snprintf(setting->value, sizeof(u32), "%u",
			 param->data.integer);
		setting->value[sizeof(ULONG)] = 0;
		break;
	case NdisParameterHexInteger:
		snprintf(setting->value, sizeof(u32), "%x",
			 param->data.integer);
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
	DBGTRACE2("setting changed %s=%s", setting->name, setting->value);
	return 0;
}

STDCALL void WRAP_EXPORT(NdisReadConfiguration)
	(NDIS_STATUS *status, struct ndis_configuration_parameter **param,
	 struct ndis_miniport_block *nmb, struct unicode_string *key,
	 enum ndis_parameter_type type)
{
	struct wrap_device_setting *setting;
	struct ansi_string ansi;
	char *keyname;
	int ret;

	TRACEENTER2("nmb: %p", nmb);
	ret = RtlUnicodeStringToAnsiString(&ansi, key, TRUE);
	DBGTRACE3("rtl func returns: %d", ret);
	if (ret || ansi.buf == NULL) {
		*param = NULL;
		*status = NDIS_STATUS_FAILURE;
		RtlFreeAnsiString(&ansi);
		TRACEEXIT2(return);
	}
	DBGTRACE3("wd: %p, string: %s", nmb->wnd->wd, ansi.buf);
	keyname = ansi.buf;

	nt_spin_lock(&loader_lock);
	nt_list_for_each_entry(setting, &nmb->wnd->wd->settings, list) {
		if (stricmp(keyname, setting->name) == 0) {
			DBGTRACE2("setting found %s=%s",
				  keyname, setting->value);
			nt_spin_unlock(&loader_lock);
			*param = ndis_encode_setting(setting, type);
			if (*param)
				*status = NDIS_STATUS_SUCCESS;
			else
				*status = NDIS_STATUS_FAILURE;
			RtlFreeAnsiString(&ansi);
			DBGTRACE2("status = %d", *status);
			TRACEEXIT2(return);
		}
	}
	nt_spin_unlock(&loader_lock);
	DBGTRACE2("setting %s not found (type:%d)", keyname, type);
	*status = NDIS_STATUS_FAILURE;
	RtlFreeAnsiString(&ansi);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisWriteConfiguration)
	(NDIS_STATUS *status, struct ndis_miniport_block *nmb,
	 struct unicode_string *key,
	 struct ndis_configuration_parameter *param)
{
	struct ansi_string ansi;
	char *keyname;
	struct wrap_device_setting *setting;

	TRACEENTER2("nmb: %p", nmb);
	if (RtlUnicodeStringToAnsiString(&ansi, key, TRUE)) {
		*status = NDIS_STATUS_FAILURE;
		TRACEEXIT2(return);
	}
	keyname = ansi.buf;
	DBGTRACE2("key = %s", keyname);

	nt_spin_lock(&loader_lock);
	nt_list_for_each_entry(setting, &nmb->wnd->wd->settings, list) {
		if (strcmp(keyname, setting->name) == 0) {
			nt_spin_unlock(&loader_lock);
			if (ndis_decode_setting(setting, param))
				*status = NDIS_STATUS_FAILURE;
			else
				*status = NDIS_STATUS_SUCCESS;
			RtlFreeAnsiString(&ansi);
			TRACEEXIT2(return);
		}
	}
	nt_spin_unlock(&loader_lock);
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
			nt_spin_lock(&loader_lock);
			InsertTailList(&nmb->wnd->wd->settings,
				       &setting->list);
			nt_spin_unlock(&loader_lock);
		}
	} else
		*status = NDIS_STATUS_RESOURCES;
	RtlFreeAnsiString(&ansi);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisInitializeString)
	(struct unicode_string *dest, UCHAR *src)
{
	struct ansi_string ansi;

	TRACEENTER2("");
	ansi.length = strlen(src);
	ansi.max_length = ansi.length + 1;
	ansi.buf = src;
	if (RtlAnsiStringToUnicodeString(dest, &ansi, TRUE))
		DBGTRACE2("failed");
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
	TRACEEXIT2(return RtlInitUnicodeString(dest, src));
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisAnsiStringToUnicodeString)
	(struct unicode_string *dst, struct ansi_string *src)
{
	TRACEENTER2("");
	if (dst == NULL || src == NULL)
		TRACEEXIT2(return NDIS_STATUS_FAILURE);
	TRACEEXIT2(return RtlAnsiStringToUnicodeString(dst, src, FALSE));
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisUnicodeStringToAnsiString)
	(struct ansi_string *dst, struct unicode_string *src)
{
	TRACEENTER2("");
	if (dst == NULL || src == NULL)
		TRACEEXIT2(return NDIS_STATUS_FAILURE);
	TRACEEXIT2(return RtlUnicodeStringToAnsiString(dst, src, FALSE));
}

STDCALL void WRAP_EXPORT(NdisMSetAttributesEx)
	(struct ndis_miniport_block *nmb, void *adapter_ctx,
	 UINT hangcheck_interval, UINT attributes, ULONG adaptortype)
{
	struct wrap_ndis_device *wnd;

	TRACEENTER2("%p, %p %d %08x, %d", nmb, adapter_ctx,
		    hangcheck_interval, attributes, adaptortype);
	wnd = nmb->wnd;
	nmb->adapter_ctx = adapter_ctx;

	if (attributes & NDIS_ATTRIBUTE_BUS_MASTER)
		pci_set_master(wnd->wd->pci.pdev);

	if (!(attributes & NDIS_ATTRIBUTE_DESERIALIZE)) {
		DBGTRACE2("serialized driver");
		set_bit(ATTR_SERIALIZED, &wnd->attributes);
	}

	if (attributes & NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK)
		set_bit(ATTR_SURPRISE_REMOVE, &wnd->attributes);

	if (attributes & NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND)
		set_bit(ATTR_NO_HALT_ON_SUSPEND, &wnd->attributes);

	if (hangcheck_interval > 0)
		wnd->hangcheck_interval = 2 * hangcheck_interval * HZ;
	else
		wnd->hangcheck_interval = 2 * HZ;

	TRACEEXIT2(return);
}

STDCALL ULONG WRAP_EXPORT(NdisReadPciSlotInformation)
	(struct ndis_miniport_block *nmb, ULONG slot,
	 ULONG offset, char *buf, ULONG len)
{
	struct wrap_device *wd = nmb->wnd->wd;
	ULONG i;
	TRACEENTER3("%d", len);
	for (i = 0; i < len; i++)
		if (pci_read_config_byte(wd->pci.pdev, offset + i, &buf[i]) !=
		    PCIBIOS_SUCCESSFUL)
			break;
	TRACEEXIT3(return i);
}

STDCALL ULONG WRAP_EXPORT(NdisImmediateReadPciSlotInformation)
	(struct ndis_miniport_block *nmb, ULONG slot,
	 ULONG offset, char *buf, ULONG len)
{
	return NdisReadPciSlotInformation(nmb, slot, offset, buf, len);
}

STDCALL ULONG WRAP_EXPORT(NdisWritePciSlotInformation)
	(struct ndis_miniport_block *nmb, ULONG slot,
	 ULONG offset, char *buf, ULONG len)
{
	struct wrap_device *wd = nmb->wnd->wd;
	ULONG i;
	TRACEENTER3("%d", len);
	for (i = 0; i < len; i++)
		if (pci_write_config_byte(wd->pci.pdev, offset + i, buf[i]) !=
		    PCIBIOS_SUCCESSFUL)
			break;
	TRACEEXIT3(return i);
}

STDCALL void WRAP_EXPORT(NdisReadPortUchar)
	(struct ndis_miniport_block *nmb, ULONG port, char *data)
{
	*data = READ_PORT_UCHAR(port);
}

STDCALL void WRAP_EXPORT(NdisImmediateReadPortUchar)
	(struct ndis_miniport_block *nmb, ULONG port, char *data)
{
	*data = READ_PORT_UCHAR(port);
}

STDCALL void WRAP_EXPORT(NdisWritePortUchar)
	(struct ndis_miniport_block *nmb, ULONG port, char data)
{
	WRITE_PORT_UCHAR(port, data);
}

STDCALL void WRAP_EXPORT(NdisImmediateWritePortUchar)
	(struct ndis_miniport_block *nmb, ULONG port, char data)
{
	WRITE_PORT_UCHAR(port, data);
}

STDCALL void WRAP_EXPORT(NdisMQueryAdapterResources)
	(NDIS_STATUS *status, struct ndis_miniport_block *nmb,
	 NDIS_RESOURCE_LIST *resource_list, UINT *size)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	NDIS_RESOURCE_LIST *list;
	UINT resource_length;

	list = &wnd->wd->resource_list->list->partial_resource_list;
	resource_length = sizeof(struct cm_partial_resource_list) +
		sizeof(struct cm_partial_resource_descriptor) *
		(list->count - 1);
	DBGTRACE2("wnd: %p. buf: %p, len: %d (%d)", wnd,
		  resource_list, *size, resource_length);
	if (*size == 0) {
		*size = resource_length;
		*status = NDIS_STATUS_BUFFER_TOO_SHORT;
	} else {
		if (*size > resource_length)
			*size = resource_length;
		memcpy(resource_list, list, *size);
		*status = NDIS_STATUS_SUCCESS;
	}
	TRACEEXIT2(return);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMPciAssignResources)
	(struct ndis_miniport_block *nmb, ULONG slot_number,
	 NDIS_RESOURCE_LIST **resources)
{
	struct wrap_ndis_device *wnd = nmb->wnd;

	TRACEENTER2("%p", wnd);
	*resources = &wnd->wd->resource_list->list->partial_resource_list;
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMMapIoSpace)
	(void **virt, struct ndis_miniport_block *nmb,
	 NDIS_PHY_ADDRESS phy_addr, UINT len)
{
	struct wrap_ndis_device *wnd = nmb->wnd;

	TRACEENTER2("%016llx, %d", phy_addr, len);
	*virt = MmMapIoSpace(phy_addr, len, MmCached);
	if (*virt == NULL) {
		ERROR("ioremap failed");
		TRACEEXIT2(return NDIS_STATUS_FAILURE);
	}

	wnd->mem_start = phy_addr;
	wnd->mem_end = phy_addr + len;

	DBGTRACE2("ioremap successful %p", *virt);
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(NdisMUnmapIoSpace)
	(struct ndis_miniport_block *nmb, void *virt, UINT len)
{
	TRACEENTER2("%p, %d", virt, len);
	MmUnmapIoSpace(virt, len);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisAllocateSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER4("lock %p", lock);

	KeInitializeSpinLock(&lock->klock);
	lock->irql = PASSIVE_LEVEL;
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
	TRACEENTER6("lock %p", lock);
	nt_spin_lock(&lock->klock);
	TRACEEXIT6(return);
}

STDCALL void WRAP_EXPORT(NdisReleaseSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER6("lock %p", lock);
	nt_spin_unlock(&lock->klock);
	TRACEEXIT6(return);
}

STDCALL void WRAP_EXPORT(NdisDprAcquireSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER6("lock %p", lock);
	nt_spin_lock(&lock->klock);
	TRACEEXIT6(return);
}

STDCALL void WRAP_EXPORT(NdisDprReleaseSpinLock)
	(struct ndis_spinlock *lock)
{
	TRACEENTER6("lock %p", lock);
	nt_spin_unlock(&lock->klock);
	TRACEEXIT6(return);
}

STDCALL void WRAP_EXPORT(NdisInitializeReadWriteLock)
	(struct ndis_rw_lock *rw_lock)
{
	TRACEENTER3("%p", rw_lock);
	memset(rw_lock, 0, sizeof(*rw_lock));
	KeInitializeSpinLock(&rw_lock->u.s.klock);
	TRACEEXIT3(return);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMAllocateMapRegisters)
	(struct ndis_miniport_block *nmb, UINT dmachan,
	 NDIS_DMA_SIZE dmasize, ULONG basemap, ULONG size)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER2("%d %d %d %d", dmachan, dmasize, basemap, size);

//	if (basemap > 64)
//		return NDIS_STATUS_RESOURCES;

	if (wnd->map_count > 0) {
		DBGTRACE2("%s: map registers already allocated: %u",
			  wnd->net_dev->name, wnd->map_count);
		TRACEEXIT2(return NDIS_STATUS_RESOURCES);
	}

	wnd->map_count = basemap;
	wnd->map_dma_addr = kmalloc(basemap * sizeof(dma_addr_t),
				   GFP_KERNEL);
	if (!wnd->map_dma_addr)
		TRACEEXIT2(return NDIS_STATUS_RESOURCES);
	memset(wnd->map_dma_addr, 0, basemap * sizeof(dma_addr_t));

	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(NdisMFreeMapRegisters)
	(struct ndis_miniport_block *nmb)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER2("wnd: %p", wnd);

	if (wnd->map_dma_addr != NULL)
		kfree(wnd->map_dma_addr);
	wnd->map_count = 0;
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisMAllocateSharedMemory)
	(struct ndis_miniport_block *nmb, ULONG size,
	 BOOLEAN cached, void **virt, NDIS_PHY_ADDRESS *phys)
{
	dma_addr_t p;
	struct wrap_device *wd = nmb->wnd->wd;

	TRACEENTER3("map count: %d, size: %u, cached: %d",
		    nmb->wnd->map_count, size, cached);

//	if (wnd->map_dma_addr == NULL)
//		ERROR("%s: DMA map address is not set!\n", __FUNCTION__);
	/* FIXME: do USB drivers call this? */
	*virt = PCI_DMA_ALLOC_COHERENT(wd->pci.pdev, size, &p);
	if (!*virt) {
		ERROR("failed to allocate DMA coherent memory; "
		      "Windows driver requested %d bytes of "
		      "%scached memory", size, cached ? "" : "un-");
	}
	*phys = p;
	DBGTRACE3("allocated shared memory: %p", *virt);
}

STDCALL void alloc_shared_memory_async(void *arg1, void *arg2)
{
	struct wrap_ndis_device *wnd = arg1;
	struct alloc_shared_mem *alloc_shared_mem = arg2;
	struct miniport_char *miniport;
	void *virt;
	NDIS_PHY_ADDRESS phys;
	KIRQL irql;

	miniport = &wnd->wd->driver->ndis_driver->miniport;
	NdisMAllocateSharedMemory(wnd->nmb, alloc_shared_mem->size,
				  alloc_shared_mem->cached, &virt, &phys);
	irql = raise_irql(DISPATCH_LEVEL);
	LIN2WIN5(miniport->alloc_complete, wnd->nmb, virt,
		 &phys, alloc_shared_mem->size, alloc_shared_mem->ctx);
	lower_irql(irql);
	kfree(alloc_shared_mem);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMAllocateSharedMemoryAsync)
	(struct ndis_miniport_block *nmb, ULONG size, BOOLEAN cached,
	 void *ctx)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	struct alloc_shared_mem *alloc_shared_mem;

	TRACEENTER3("wnd: %p", wnd);
	alloc_shared_mem = kmalloc(sizeof(*alloc_shared_mem), GFP_ATOMIC);
	if (!alloc_shared_mem) {
		WARNING("couldn't allocate memory");
		return NDIS_STATUS_FAILURE;
	}

	alloc_shared_mem->size = size;
	alloc_shared_mem->cached = cached;
	alloc_shared_mem->ctx = ctx;
	if (schedule_wrap_work_item(alloc_shared_memory_async,
				    wnd, alloc_shared_mem, FALSE))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	TRACEEXIT3(return NDIS_STATUS_PENDING);
}

STDCALL void WRAP_EXPORT(NdisMFreeSharedMemory)
	(struct ndis_miniport_block *nmb, ULONG size, BOOLEAN cached,
	 void *virt, NDIS_PHY_ADDRESS addr)
{
	struct wrap_device *wd = nmb->wnd->wd;
	TRACEENTER3("");
	/* FIXME: do USB drivers call this? */
	PCI_DMA_FREE_COHERENT(wd->pci.pdev, size, virt, addr);
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

	TRACEENTER1("buffers: %d", num_descr);
	pool = kmalloc(sizeof(*pool), GFP_ATOMIC);
	if (!pool) {
		*status = NDIS_STATUS_RESOURCES;
		TRACEEXIT3(return);
	}
	nt_spin_lock_init(&pool->lock);
	pool->max_descr = num_descr;
	pool->num_allocated_descr = 0;
	pool->free_descr = NULL;
	*pool_handle = pool;
	*status = NDIS_STATUS_SUCCESS;
	DBGTRACE1("pool: %p, num_descr: %d", pool, num_descr);
	TRACEEXIT1(return);
}

STDCALL void WRAP_EXPORT(NdisAllocateBuffer)
	(NDIS_STATUS *status, ndis_buffer **buffer,
	 struct ndis_buffer_pool *pool, void *virt, UINT length)
{
	ndis_buffer *descr;

	TRACEENTER4("pool: %p, allocated: %d",
		    pool, pool->num_allocated_descr);
	if (!pool) {
		*status = NDIS_STATUS_FAILURE;
		TRACEEXIT4(return);
	}
	nt_spin_lock_bh(&pool->lock);
	if (pool->num_allocated_descr > pool->max_descr)
		DBGTRACE4("pool %p is full: %d(%d)", pool,
			  pool->num_allocated_descr, pool->max_descr);
	if (pool->free_descr) {
		typeof(descr->flags) flags;
		descr = pool->free_descr;
		pool->free_descr = descr->next;
		flags = descr->flags;
		memset(descr, 0, sizeof(*descr));
		MmInitializeMdl(descr, virt, length);
		MmBuildMdlForNonPagedPool(descr);
		if (flags & MDL_CACHE_ALLOCATED)
			descr->flags = MDL_CACHE_ALLOCATED;
	} else {
		nt_spin_unlock_bh(&pool->lock);
		DBGTRACE4("allocating mdl");
		descr = allocate_init_mdl(virt, length);
		DBGTRACE4("mdl: %p", descr);
		if (!descr) {
			WARNING("couldn't allocate buffer");
			*status = NDIS_STATUS_FAILURE;
			TRACEEXIT4(return);
		}
		DBGTRACE4("allocated buffer %p for %p, %d",
			  descr, virt, length);
		nt_spin_lock_bh(&pool->lock);
		pool->num_allocated_descr++;
	}
	/* NdisFreeBuffer doesn't pass pool, so we store pool
	 * in unused field 'process' */
	descr->process = pool;
	nt_spin_unlock_bh(&pool->lock);
	*buffer = descr;
	*status = NDIS_STATUS_SUCCESS;
	DBGTRACE4("buffer: %p", descr);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisFreeBuffer)
	(ndis_buffer *descr)
{
	struct ndis_buffer_pool *pool;

	TRACEENTER4("descr: %p", descr);
	pool = descr->process;
	if (!pool) {
		ERROR("pool for descriptor %p is invalid", descr);
		TRACEEXIT4(return);
	}
	nt_spin_lock_bh(&pool->lock);
	if (pool->num_allocated_descr > MAX_ALLOCATED_NDIS_BUFFERS) {
		/* NB NB NB: set mdl's 'process' field to NULL before
		 * calling free_mdl; otherwise free_mdl calls
		 * NdisFreeBuffer causing deadlock (for spinlock) */
		pool->num_allocated_descr--;
		descr->process = NULL;
		nt_spin_unlock_bh(&pool->lock);
		free_mdl(descr);
	} else {
		descr->next = pool->free_descr;
		pool->free_descr = descr;
		nt_spin_unlock_bh(&pool->lock);
	}
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisFreeBufferPool)
	(struct ndis_buffer_pool *pool)
{
	ndis_buffer *cur, *prev;

	DBGTRACE3("pool: %p", pool);
	if (!pool) {
		WARNING("invalid pool");
		TRACEEXIT3(return);
	}
	nt_spin_lock_bh(&pool->lock);
	cur = pool->free_descr;
	while (cur) {
		prev = cur;
		cur = cur->next;
		prev->process = NULL;
		free_mdl(prev);
	}
	nt_spin_unlock_bh(&pool->lock);
	kfree(pool);
	pool = NULL;
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisAdjustBufferLength)
	(ndis_buffer *buffer, UINT length)
{
	TRACEENTER4("%p", buffer);
	if (buffer)
		buffer->bytecount = length;
	else
		ERROR("invalid buffer");
}

STDCALL void WRAP_EXPORT(NdisQueryBuffer)
	(ndis_buffer *buffer, void **virt, UINT *length)
{
	TRACEENTER4("buffer: %p", buffer);
	if (virt)
		*virt = MmGetMdlVirtualAddress(buffer);
	if (length)
		*length = MmGetMdlByteCount(buffer);
	DBGTRACE4("%p, %u", *virt, *length);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisQueryBufferSafe)
	(ndis_buffer *buffer, void **virt, UINT *length,
	 enum mm_page_priority priority)
{
	TRACEENTER4("%p, %p, %p, %d", buffer, virt, length, priority);
	if (virt)
		*virt = MmGetMdlVirtualAddress(buffer);
	if (length)
		*length = MmGetMdlByteCount(buffer);
	DBGTRACE4("%p, %u", *virt, *length);
}

STDCALL void *WRAP_EXPORT(NdisBufferVirtualAddress)
	(ndis_buffer *buffer)
{
	TRACEENTER3("%p", buffer);
	return MmGetMdlVirtualAddress(buffer);
}

STDCALL ULONG WRAP_EXPORT(NdisBufferLength)
	(ndis_buffer *buffer)
{
	TRACEENTER3("%p", buffer);
	return MmGetMdlByteCount(buffer);
}

STDCALL void WRAP_EXPORT(NdisAllocatePacketPoolEx)
	(NDIS_STATUS *status, struct ndis_packet_pool **pool_handle,
	 UINT num_descr, UINT overflowsize, UINT proto_rsvd_length)
{
	struct ndis_packet_pool *pool;
	unsigned int alloc_flags;

	TRACEENTER3("buffers: %d, length: %d", num_descr, proto_rsvd_length);
	if (current_irql() < DISPATCH_LEVEL)
		alloc_flags = GFP_KERNEL;
	else
		alloc_flags = GFP_ATOMIC;
	pool = kmalloc(sizeof(*pool), alloc_flags);
	if (!pool) {
		*status = NDIS_STATUS_RESOURCES;
		TRACEEXIT3(return);
	}
	nt_spin_lock_init(&pool->lock);
	pool->max_descr = num_descr;
	pool->num_allocated_descr = 0;
	pool->num_used_descr = 0;
	pool->free_descr = NULL;
	pool->proto_rsvd_length = proto_rsvd_length;
	*pool_handle = pool;
	*status = NDIS_STATUS_SUCCESS;
	DBGTRACE3("pool: %p", pool);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisAllocatePacketPool)
	(NDIS_STATUS *status, struct ndis_packet_pool **pool_handle,
	 UINT num_descr, UINT proto_rsvd_length)
{
	TRACEENTER3("");
	NdisAllocatePacketPoolEx(status, pool_handle, num_descr, 0,
				 proto_rsvd_length);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisFreePacketPool)
	(struct ndis_packet_pool *pool)
{
	struct ndis_packet *packet, *next;

	TRACEENTER3("pool: %p", pool);
	if (!pool) {
		WARNING("invalid pool");
		TRACEEXIT3(return);
	}
	nt_spin_lock_bh(&pool->lock);
	packet = pool->free_descr;
	while (packet) {
		next = (NDIS_PACKET_OOB_DATA(packet))->next;
		kfree(packet);
		packet = next;
	}
	pool->num_allocated_descr = 0;
	pool->num_used_descr = 0;
	pool->free_descr = NULL;
	nt_spin_unlock_bh(&pool->lock);
	DBGTRACE3("pool: %p", pool);
	kfree(pool);
	TRACEEXIT3(return);
}

STDCALL UINT WRAP_EXPORT(NdisPacketPoolUsage)
	(struct ndis_packet_pool *pool)
{
	UINT i;

	TRACEENTER4("");
	nt_spin_lock_bh(&pool->lock);
	i = pool->num_used_descr;
	nt_spin_unlock_bh(&pool->lock);
	TRACEEXIT4(return i);
}

STDCALL void WRAP_EXPORT(NdisAllocatePacket)
	(NDIS_STATUS *status, struct ndis_packet **packet,
	 struct ndis_packet_pool *pool)
{
	struct ndis_packet *ndis_packet;
	unsigned int alloc_flags;
	int packet_length;

	TRACEENTER4("pool: %p", pool);
	if (!pool) {
		*status = NDIS_STATUS_RESOURCES;
		TRACEEXIT4(return);
	}
	/* packet has space for 1 byte in protocol_reserved field */
	packet_length = sizeof(*ndis_packet) - 1 + pool->proto_rsvd_length +
		sizeof(struct ndis_packet_oob_data);
	nt_spin_lock_bh(&pool->lock);
	if (pool->num_used_descr >= pool->max_descr)
		DBGTRACE4("pool %p is full: %d(%d)", pool,
			  pool->num_used_descr, pool->max_descr);
	ndis_packet = NULL;
	if (pool->free_descr) {
		struct ndis_packet_oob_data *oob_data;
		ndis_packet = pool->free_descr;
		oob_data = NDIS_PACKET_OOB_DATA(ndis_packet);
		pool->free_descr = oob_data->next;
	} else {
		nt_spin_unlock_bh(&pool->lock);
		if (current_irql() < DISPATCH_LEVEL)
			alloc_flags = GFP_KERNEL;
		else
			alloc_flags = GFP_ATOMIC;
		ndis_packet = kmalloc(packet_length, alloc_flags);
		if (!ndis_packet) {
			WARNING("couldn't allocate packet");
			*status = NDIS_STATUS_RESOURCES;
			return;
		}
		DBGTRACE3("allocated packet: %p", ndis_packet);
		nt_spin_lock_bh(&pool->lock);
		pool->num_allocated_descr++;
	}
	pool->num_used_descr++;
	memset(ndis_packet, 0, packet_length);
	ndis_packet->private.oob_offset = packet_length -
		sizeof(struct ndis_packet_oob_data);
	ndis_packet->private.packet_flags = fPACKET_ALLOCATED_BY_NDIS;
	ndis_packet->private.pool = pool;
	nt_spin_unlock_bh(&pool->lock);

	*status = NDIS_STATUS_SUCCESS;
	*packet = ndis_packet;
	DBGTRACE4("packet: %p, pool: %p", ndis_packet, pool);
	TRACEEXIT4(return);
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

	TRACEENTER3("packet: %p, pool: %p", descr, descr->private.pool);
	pool = descr->private.pool;
	if (!pool) {
		ERROR("pool for descriptor %p is invalid", descr);
		TRACEEXIT4(return);
	}
	nt_spin_lock_bh(&pool->lock);
	pool->num_used_descr--;
	if (pool->num_allocated_descr > MAX_ALLOCATED_NDIS_PACKETS) {
		pool->num_allocated_descr--;
		nt_spin_unlock_bh(&pool->lock);
		kfree(descr);
	} else {
		struct ndis_packet_oob_data *oob_data;
		oob_data = NDIS_PACKET_OOB_DATA(descr);
		descr->private.buffer_head = NULL;
		descr->private.valid_counts = FALSE;
		oob_data->next = pool->free_descr;
		pool->free_descr = descr;
		nt_spin_unlock_bh(&pool->lock);
	}
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisSend)
	(NDIS_STATUS *status, struct ndis_miniport_block *nmb,
	 struct ndis_packet *packet)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	struct miniport_char *miniport;
	KIRQL irql;

	miniport = &wnd->wd->driver->ndis_driver->miniport;
	if (miniport->send_packets) {
		struct ndis_packet *packets[1];

		packets[0] = packet;
		irql = raise_irql(DISPATCH_LEVEL);
		LIN2WIN3(miniport->send_packets, wnd->nmb->adapter_ctx,
			 packets, 1);
		lower_irql(irql);
		if (test_bit(ATTR_SERIALIZED, &wnd->attributes)) {
			struct ndis_packet_oob_data *oob_data;
			oob_data = NDIS_PACKET_OOB_DATA(packet);
			*status = oob_data->status;
			switch (*status) {
			case NDIS_STATUS_SUCCESS:
				sendpacket_done(wnd, packet);
				break;
			case NDIS_STATUS_PENDING:
				break;
			case NDIS_STATUS_RESOURCES:
				wnd->send_ok = 0;
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
		*status = LIN2WIN3(miniport->send, wnd->nmb->adapter_ctx,
				   packet, 0);
		lower_irql(irql);
		switch (*status) {
		case NDIS_STATUS_SUCCESS:
			sendpacket_done(wnd, packet);
			break;
		case NDIS_STATUS_PENDING:
			break;
		case NDIS_STATUS_RESOURCES:
			wnd->send_ok = 0;
			break;
		case NDIS_STATUS_FAILURE:
			break;
		}
	}
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisMInitializeTimer)
	(struct ndis_miniport_timer *timer, struct ndis_miniport_block *nmb,
	 void *func, void *ctx)
{
	TRACEENTER4("timer: %p, func: %p, ctx: %p, nmb: %p",
		    &timer->nt_timer, func, ctx, nmb);
	/* DDK implements with KeInitializeTimer */
	wrap_init_timer(&timer->nt_timer, NotificationTimer, nmb->wnd->wd);
	timer->func = func;
	timer->ctx = ctx;
	timer->nmb = nmb;
	KeInitializeDpc(&timer->kdpc, func, ctx);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisMSetPeriodicTimer)
	(struct ndis_miniport_timer *timer, UINT period_ms)
{
	unsigned long expires = MSEC_TO_HZ(period_ms) + 1;

	DBGTRACE4("%p, %u, %ld", timer, period_ms, expires);
	/* DDK implements with KeSetTimerEx */
	wrap_set_timer(&timer->nt_timer, expires, expires, &timer->kdpc);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisMCancelTimer)
	(struct ndis_miniport_timer *timer, BOOLEAN *canceled)
{
	TRACEENTER4("%p", timer);
	*canceled = KeCancelTimer(&timer->nt_timer);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisInitializeTimer)
	(struct ndis_timer *timer, void *func, void *ctx)
{
	TRACEENTER4("%p, %p, %p, %p", timer, func, ctx, &timer->nt_timer);
	KeInitializeTimer(&timer->nt_timer);
	KeInitializeDpc(&timer->kdpc, func, ctx);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisSetTimer)
	(struct ndis_timer *timer, UINT duetime_ms)
{
	unsigned long expires = MSEC_TO_HZ(duetime_ms) + 1;

	DBGTRACE4("%p, %u, %ld", timer, duetime_ms, expires);
	/* DDK implements with NdisMSetTimer, which in turn is
	 * implemented with KeSetTimer */
	wrap_set_timer(&timer->nt_timer, expires, 0, &timer->kdpc);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisCancelTimer)
	(struct ndis_timer *timer, BOOLEAN *canceled)
{
	TRACEENTER4("");
	*canceled = KeCancelTimer(&timer->nt_timer);
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisReadNetworkAddress)
	(NDIS_STATUS *status, void **addr, UINT *len,
	 struct ndis_miniport_block *nmb)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	struct ndis_configuration_parameter *param;
	struct unicode_string key;
	struct ansi_string ansi;
	int ret;

	TRACEENTER1("");
	ansi.buf = "mac_address";
	ansi.length = strlen(ansi.buf);
	ansi.max_length = ansi.length + 1;

	*len = 0;
	*status = NDIS_STATUS_FAILURE;
	if (RtlAnsiStringToUnicodeString(&key, &ansi, TRUE) != STATUS_SUCCESS)
		TRACEEXIT1(return);

	NdisReadConfiguration(status, &param, nmb, &key, NdisParameterString);
	RtlFreeUnicodeString(&key);

	if (*status == NDIS_STATUS_SUCCESS) {
		int int_mac[ETH_ALEN];
		ret = RtlUnicodeStringToAnsiString(&ansi, &param->data.string,
						   TRUE);
		if (ret != NDIS_STATUS_SUCCESS)
			TRACEEXIT1(return);

		ret = sscanf(ansi.buf, MACSTR, MACINTADR(int_mac));
		RtlFreeAnsiString(&ansi);
		if (ret == ETH_ALEN) {
			int i;
			for (i = 0; i < ETH_ALEN; i++)
				wnd->mac[i] = int_mac[i];
			printk(KERN_INFO "%s: %s ethernet device " MACSTR "\n",
			       wnd->net_dev->name, DRIVER_NAME,
			       MAC2STR(wnd->mac));
			*len = ETH_ALEN;
			*addr = wnd->mac;
			*status = NDIS_STATUS_SUCCESS;
		}
	}

	TRACEEXIT1(return);
}

STDCALL void WRAP_EXPORT(NdisMRegisterAdapterShutdownHandler)
	(struct ndis_miniport_block *nmb, void *ctx, void *func)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER1("sp:%p", get_sp());
	wnd->wd->driver->ndis_driver->miniport.shutdown = func;
	wnd->shutdown_ctx = ctx;
}

STDCALL void WRAP_EXPORT(NdisMDeregisterAdapterShutdownHandler)
	(struct ndis_miniport_block *nmb)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER1("sp:%p", get_sp());
	wnd->wd->driver->ndis_driver->miniport.shutdown = NULL;
	wnd->shutdown_ctx = NULL;
}

static void ndis_irq_handler(unsigned long data)
{
	struct ndis_irq *ndis_irq = (struct ndis_irq *)data;
	struct wrap_ndis_device *wnd;
	struct miniport_char *miniport;

	wnd = ndis_irq->wnd;
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	LIN2WIN1(miniport->handle_interrupt, wnd->nmb->adapter_ctx);
	if (miniport->enable_interrupts)
		LIN2WIN1(miniport->enable_interrupts,
			 wnd->nmb->adapter_ctx);
}

static irqreturn_t ndis_isr(int irq, void *data, struct pt_regs *pt_regs)
{
	int recognized, queue_handler;
	struct ndis_irq *ndis_irq = (struct ndis_irq *)data;
	struct wrap_ndis_device *wnd;
	struct miniport_char *miniport;

	wnd = ndis_irq->wnd;
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	/* this spinlock should be shared with NdisMSynchronizeWithInterrupt
	 */
	nt_spin_lock(&ndis_irq->lock);
	recognized = queue_handler = 0;
	if (ndis_irq->req_isr)
		LIN2WIN3(miniport->isr, &recognized, &queue_handler,
			 wnd->nmb->adapter_ctx);
	else { //if (miniport->disable_interrupts)
		LIN2WIN1(miniport->disable_interrupts, wnd->nmb->adapter_ctx);
		/* it is not shared interrupt, so handler must be called */
		recognized = queue_handler = 1;
	}
	nt_spin_unlock(&ndis_irq->lock);

	if (recognized) {
		if (queue_handler)
			tasklet_schedule(&wnd->irq_tasklet);
		return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMRegisterInterrupt)
	(struct ndis_irq *ndis_irq, struct ndis_miniport_block *nmb,
	 UINT vector, UINT level, BOOLEAN req_isr,
	 BOOLEAN shared, enum kinterrupt_mode mode)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER1("%p, vector:%d, level:%d, req_isr:%d, shared:%d, "
		    "mode:%d sp:%p", ndis_irq, vector, level, req_isr,
		    shared, mode, get_sp());

	ndis_irq->irq.irq = vector;
	ndis_irq->wnd = wnd;
	ndis_irq->req_isr = req_isr;
	if (shared && !req_isr)
		WARNING("shared but dynamic interrupt!");
	ndis_irq->shared = shared;
	nt_spin_lock_init(&ndis_irq->lock);
	wnd->ndis_irq = ndis_irq;

	tasklet_init(&wnd->irq_tasklet, ndis_irq_handler,
		     (unsigned long)ndis_irq);
	if (request_irq(vector, ndis_isr, req_isr ? SA_SHIRQ : 0,
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
	struct wrap_ndis_device *wnd;

	TRACEENTER1("%p", ndis_irq);

	if (!ndis_irq)
		TRACEEXIT1(return);
	wnd = ndis_irq->wnd;
	if (!wnd)
		TRACEEXIT1(return);

	free_irq(ndis_irq->irq.irq, ndis_irq);
	tasklet_kill(&wnd->irq_tasklet);
	ndis_irq->enabled = 0;
	ndis_irq->wnd = NULL;
	wnd->ndis_irq = NULL;
	TRACEEXIT1(return);
}

STDCALL BOOLEAN WRAP_EXPORT(NdisMSynchronizeWithInterrupt)
	(struct ndis_irq *ndis_irq, void *func, void *ctx)
{
	BOOLEAN ret;
	BOOLEAN (*sync_func)(void *ctx) STDCALL;

	TRACEENTER6("%p %p", func, ctx);
	sync_func = func;
	nt_spin_lock(&ndis_irq->lock);
	ret = LIN2WIN1(sync_func, ctx);
	nt_spin_unlock(&ndis_irq->lock);
	TRACEEXIT6(return ret);
}

/* called via function pointer */
STDCALL void WRAP_EXPORT(NdisMIndicateStatus)
	(struct ndis_miniport_block *nmb, NDIS_STATUS status,
	 void *buf, UINT len)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	struct ndis_status_indication *si;
	struct ndis_auth_req *auth_req;
	struct ndis_radio_status_indication *radio_status;

	TRACEENTER2("status=0x%x len=%d", status, len);
	switch (status) {
	case  NDIS_STATUS_MEDIA_DISCONNECT:
		if (wnd->link_status != 0) {
			wnd->link_status = 0;
			set_bit(LINK_STATUS_CHANGED, &wnd->wrap_ndis_work);
		}
		wnd->link_status = 0;
		wnd->send_ok = 0;
		break;
	case NDIS_STATUS_MEDIA_CONNECT:
		if (wnd->link_status != 1) {
			wnd->link_status = 1;
			set_bit(LINK_STATUS_CHANGED, &wnd->wrap_ndis_work);
		}
		wnd->link_status = 1;
		wnd->send_ok = 1;
		break;
	case NDIS_STATUS_MEDIA_SPECIFIC_INDICATION:
		if (!buf)
			break;
		si = buf;
		DBGTRACE2("status_type=%d", si->status_type);

		switch (si->status_type) {
		case Ndis802_11StatusType_Authentication:
			buf = (char *)buf + sizeof(*si);
			len -= sizeof(*si);
			while (len > 0) {
				auth_req = (struct ndis_auth_req *)buf;
				DBGTRACE1(MACSTR, MAC2STR(auth_req->bssid));
				if (auth_req->flags & 0x01)
					DBGTRACE2("reqauth");
				if (auth_req->flags & 0x02)
					DBGTRACE2("keyupdate");
				if (auth_req->flags & 0x06)
					DBGTRACE2("pairwise_error");
				if (auth_req->flags & 0x0E)
					DBGTRACE2("group_error");
				/* TODO: report to wpa_supplicant */
				len -= auth_req->length;
				buf = (char *)buf + auth_req->length;
			}
			break;
		case Ndis802_11StatusType_MediaStreamMode:
			break;
		case Ndis802_11StatusType_PMKID_CandidateList:
		{
			u8 *end;
			unsigned long i;
			struct ndis_pmkid_candidate_list *cand;

			cand = buf + sizeof(struct ndis_status_indication);
			if (len < sizeof(struct ndis_status_indication) +
			    sizeof(struct ndis_pmkid_candidate_list) ||
				cand->version != 1) {
				WARNING("Unrecognized PMKID_CANDIDATE_LIST"
					" ignored");
				TRACEEXIT1(return);
			}

			end = (u8 *)buf + len;
			DBGTRACE2("PMKID_CANDIDATE_LIST ver %ld "
				  "num_cand %ld",
				  cand->version, cand->num_candidates);
			for (i = 0; i < cand->num_candidates; i++) {
				struct ndis_pmkid_candidate *c =
					&cand->candidates[i];
				if ((u8 *)(c + 1) > end) {
					DBGTRACE2("Truncated "
						    "PMKID_CANDIDATE_LIST");
					break;
				}
				DBGTRACE2("%ld: " MACSTR " 0x%lx",
					  i, MAC2STR(c->bssid), c->flags);
#if WIRELESS_EXT > 17
				{
					struct iw_pmkid_cand pcand;
					union iwreq_data wrqu;
					memset(&pcand, 0, sizeof(pcand));
					if (c->flags & 0x01)
						pcand.flags |=
							IW_PMKID_CAND_PREAUTH;
					pcand.index = i;
					memcpy(pcand.bssid.sa_data, c->bssid,
					       ETH_ALEN);

					memset(&wrqu, 0, sizeof(wrqu));
					wrqu.data.length = sizeof(pcand);
					wireless_send_event(wnd->net_dev,
							    IWEVPMKIDCAND,
							    &wrqu,
							    (u8 *)&pcand);
				}
#endif
			}
			break;
		}
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
		default:
			/* is this RSSI indication? */
			DBGTRACE2("unknown indication: %x", si->status_type);
			break;
		}
		break;
	default:
		WARNING("unknown status: %08X", status);
		break;
	}

	TRACEEXIT1(return);
}

/* called via function pointer */
STDCALL void WRAP_EXPORT(NdisMIndicateStatusComplete)
	(struct ndis_miniport_block *nmb)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER2("%p", wnd);
	schedule_work(&wnd->wrap_ndis_worker);
	if (wnd->send_ok)
		schedule_work(&wnd->xmit_work);
}

STDCALL void return_packet(void *arg1, void *arg2)
{
	struct wrap_ndis_device *wnd;
	struct ndis_packet *packet;
	struct miniport_char *miniport;
	KIRQL irql;

	wnd = arg1;
	packet = arg2;
	TRACEENTER4("%p, %p", wnd, packet);
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	irql = raise_irql(DISPATCH_LEVEL);
	LIN2WIN2(miniport->return_packet, wnd->nmb->adapter_ctx, packet);
	lower_irql(irql);
	TRACEEXIT4(return);
}


/* called via function pointer */
STDCALL void
NdisMIndicateReceivePacket(struct ndis_miniport_block *nmb,
			   struct ndis_packet **packets, UINT nr_packets)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	ndis_buffer *buffer;
	struct ndis_packet *packet;
	struct sk_buff *skb;
	int i;
	struct ndis_packet_oob_data *oob_data;

	TRACEENTER3("");
	for (i = 0; i < nr_packets; i++) {
		packet = packets[i];
		if (!packet) {
			WARNING("empty packet ignored");
			continue;
		}
		/* TODO: we assume a packet has exactly one buffer,
		 * although at other places we don't */
		buffer = packet->private.buffer_head;
		skb = dev_alloc_skb(MmGetMdlByteCount(buffer));
		DBGTRACE3("length: %d", MmGetMdlByteCount(buffer));
		if (skb) {
			skb->dev = wnd->net_dev;
			eth_copy_and_sum(skb, MmGetMdlVirtualAddress(buffer),
					 MmGetMdlByteCount(buffer), 0);
			skb_put(skb, MmGetMdlByteCount(buffer));
			skb->protocol = eth_type_trans(skb, wnd->net_dev);
			wnd->stats.rx_bytes += MmGetMdlByteCount(buffer);
			wnd->stats.rx_packets++;
			netif_rx(skb);
		} else
			wnd->stats.rx_dropped++;

		oob_data = NDIS_PACKET_OOB_DATA(packet);
		/* serialized drivers check the status upon return
		 * from this function */
		if (test_bit(ATTR_SERIALIZED, &wnd->attributes)) {
			oob_data->status = NDIS_STATUS_SUCCESS;
			continue;
		}

		/* if a deserialized driver sets
		 * NDIS_STATUS_RESOURCES, then it reclaims the packet
		 * upon return from this function */
		if (oob_data->status == NDIS_STATUS_RESOURCES)
			continue;

		if (oob_data->status != NDIS_STATUS_SUCCESS)
			WARNING("invalid packet status %08X",
				oob_data->status);
		/* deserialized driver doesn't check the status upon
		 * return from this function; we need to call
		 * MiniportReturnPacket later for this packet. Calling
		 * MiniportReturnPacket from here is not correct - the
		 * driver doesn't expect it (at least Centrino driver
		 * crashes) */
		schedule_wrap_work_item(return_packet, wnd, packet, FALSE);
	}
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisMCoIndicateReceivePacket)
	(struct ndis_miniport_block *nmb, struct ndis_packet **packets,
	 UINT nr_packets)
{
	TRACEENTER3("nmb = %p", nmb);
	NdisMIndicateReceivePacket(nmb, packets, nr_packets);
	TRACEEXIT3(return);
}

/* called via function pointer */
STDCALL void
NdisMSendComplete(struct ndis_miniport_block *nmb, struct ndis_packet *packet,
		  NDIS_STATUS status)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER3("%p, %08x", packet, status);
	sendpacket_done(wnd, packet);
	/* In case a serialized driver has requested a pause by returning
	 * NDIS_STATUS_RESOURCES we need to give the send-code a kick again.
	 */
	if (wnd->send_ok == 0){ 
		wnd->send_ok = 1;
		schedule_work(&wnd->xmit_work);
	}
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisMCoSendComplete)
	(NDIS_STATUS status, struct ndis_miniport_block *nmb,
	 struct ndis_packet *packet)
{
	TRACEENTER3("%08x", status);
	NdisMSendComplete(nmb, packet, status);
	TRACEEXIT3(return);
}

/* called via function pointer */
STDCALL void
NdisMSendResourcesAvailable(struct ndis_miniport_block *nmb)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER3("");
	/* sending packets immediately seem to result in NDIS_STATUS_FAILURE,
	   so wait for a while before sending the packet again */
	mdelay(5);
	wnd->send_ok = 1;
	schedule_work(&wnd->xmit_work);
	TRACEEXIT3(return);
}

/* called via function pointer (by NdisMEthIndicateReceive macro); the
 * first argument is nmb->eth_db */
STDCALL void
EthRxIndicateHandler(struct ndis_miniport_block *nmb, void *rx_ctx,
		     char *header1, char *header, UINT header_size,
		     void *look_ahead, UINT look_ahead_size, UINT packet_size)
{
	struct sk_buff *skb = NULL;
	struct wrap_ndis_device *wnd;
	unsigned int skb_size = 0;
	KIRQL irql;

	TRACEENTER3("nmb = %p, rx_ctx = %p, buf = %p, size = %d, "
		    "buf = %p, size = %d, packet = %d",
		    nmb, rx_ctx, header, header_size, look_ahead,
		    look_ahead_size, packet_size);

	wnd = nmb->wnd;
	DBGTRACE3("wnd = %p", wnd);
	if (!wnd) {
		ERROR("nmb is NULL");
		TRACEEXIT3(return);
	}

	if (look_ahead_size < packet_size) {
		struct ndis_packet *packet;
		struct miniport_char *miniport;
		unsigned int bytes_txed;
		NDIS_STATUS res;

		NdisAllocatePacket(&res, &packet, wnd->wrapper_packet_pool);
		if (res != NDIS_STATUS_SUCCESS) {
			wnd->stats.rx_dropped++;
			TRACEEXIT3(return);
		}

		miniport = &wnd->wd->driver->ndis_driver->miniport;
		irql = raise_irql(DISPATCH_LEVEL);
		res = LIN2WIN6(miniport->tx_data, packet, &bytes_txed,
			       nmb, rx_ctx, look_ahead_size,
			       packet_size);
		lower_irql(irql);
		DBGTRACE3("%d, %d, %d", header_size, look_ahead_size,
			  bytes_txed);
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
				skb_size = header_size+look_ahead_size +
					bytes_txed;
				NdisFreePacket(packet);
			}
		} else if (res == NDIS_STATUS_PENDING) {
			struct ndis_packet_oob_data *oob_data;
			/* driver will call td_complete */
			oob_data = NDIS_PACKET_OOB_DATA(packet);
			oob_data->look_ahead = kmalloc(look_ahead_size,
						       GFP_ATOMIC);
			if (!oob_data->look_ahead) {
				NdisFreePacket(packet);
				wnd->stats.rx_dropped++;
				TRACEEXIT3(return);
			}
			memcpy(oob_data->header, header,
			       sizeof(oob_data->header));
			memcpy(oob_data->look_ahead, look_ahead,
			       look_ahead_size);
			oob_data->look_ahead_size = look_ahead_size;
		} else {
			NdisFreePacket(packet);
			wnd->stats.rx_dropped++;
			TRACEEXIT3(return);
		}
	} else {
		skb_size = header_size + packet_size;
		skb = dev_alloc_skb(skb_size);
		if (skb) {
			memcpy(skb->data, header, header_size);
			memcpy(skb->data+header_size, look_ahead, packet_size);
		}
	}

	if (skb && skb_size > 0) {
		skb->dev = wnd->net_dev;
		skb_put(skb, skb_size);
		skb->protocol = eth_type_trans(skb, wnd->net_dev);
		wnd->stats.rx_bytes += skb_size;
		wnd->stats.rx_packets++;
		netif_rx(skb);
	} else
		wnd->stats.rx_dropped++;

	TRACEEXIT3(return);
}

/* called via function pointer */
STDCALL void
NdisMTransferDataComplete(struct ndis_miniport_block *nmb,
			  struct ndis_packet *packet,
			  NDIS_STATUS status, UINT bytes_txed)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	struct sk_buff *skb;
	unsigned int skb_size;
	struct ndis_packet_oob_data *oob_data;

	TRACEENTER3("wnd = %p, packet = %p, bytes_txed = %d",
		    wnd, packet, bytes_txed);

	if (!packet) {
		WARNING("illegal packet");
		TRACEEXIT3(return);
	}

	oob_data = NDIS_PACKET_OOB_DATA(packet);
	skb_size = sizeof(oob_data->header) + oob_data->look_ahead_size +
		bytes_txed;

	skb = dev_alloc_skb(skb_size);
	if (!skb) {
		kfree(oob_data->look_ahead);
		NdisFreePacket(packet);
		wnd->stats.rx_dropped++;
		TRACEEXIT3(return);
	}

	skb->dev = wnd->net_dev;
	memcpy(skb->data, oob_data->header, sizeof(oob_data->header));
	memcpy(skb->data + sizeof(oob_data->header), oob_data->look_ahead,
	       oob_data->look_ahead_size);
	memcpy(skb->data + sizeof(oob_data->header) +
	       oob_data->look_ahead_size,
	       MmGetMdlVirtualAddress(packet->private.buffer_head),
	       bytes_txed);
	kfree(oob_data->look_ahead);
	NdisFreePacket(packet);
	skb_put(skb, skb_size);
	skb->protocol = eth_type_trans(skb, wnd->net_dev);
	wnd->stats.rx_bytes += skb_size;
	wnd->stats.rx_packets++;
	netif_rx(skb);
}

/* called via function pointer */
STDCALL void
EthRxComplete(struct ndis_miniport_block *nmb)
{
	DBGTRACE3("");
}

/* Called via function pointer if query returns NDIS_STATUS_PENDING */
STDCALL void
NdisMQueryInformationComplete(struct ndis_miniport_block *nmb,
			      NDIS_STATUS status)
{
	struct wrap_ndis_device *wnd = nmb->wnd;

	TRACEENTER2("nmb: %p, wnd: %p, %08X", nmb, wnd, status);
	wnd->ndis_comm_status = status;
	wnd->ndis_comm_done = 1;
	wake_up(&wnd->ndis_comm_wq);
	TRACEEXIT2(return);
}

STDCALL void WRAP_EXPORT(NdisMCoRequestComplete)
	(NDIS_STATUS status, struct ndis_miniport_block *nmb,
	 struct ndis_request *ndis_request)
{
	struct wrap_ndis_device *wnd = nmb->wnd;

	TRACEENTER3("%08X", status);
	wnd->ndis_comm_status = status;
	wnd->ndis_comm_done = 1;
	wake_up(&wnd->ndis_comm_wq);
	TRACEEXIT3(return);
}

/* Called via function pointer if setinfo returns NDIS_STATUS_PENDING */
STDCALL void
NdisMSetInformationComplete(struct ndis_miniport_block *nmb,
			    NDIS_STATUS status)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER2("status = %08X", status);

	wnd->ndis_comm_status = status;
	wnd->ndis_comm_done = 1;
	wake_up(&wnd->ndis_comm_wq);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisMSleep)
	(ULONG us)
{
	unsigned long delay;

	TRACEENTER4("%p: us: %u", get_current(), us);
	delay = USEC_TO_HZ(us) + 1;
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(delay);
	DBGTRACE4("%p: done", get_current());
	TRACEEXIT4(return);
}

STDCALL void WRAP_EXPORT(NdisGetCurrentSystemTime)
	(LARGE_INTEGER *time)
{
	*time = ticks_1601();
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMRegisterIoPortRange)
	(void **virt, struct ndis_miniport_block *nmb, UINT start, UINT len)
{
	TRACEENTER3("%08x %08x", start, len);
	*virt = (void *)(ULONG_PTR)start;
	return NDIS_STATUS_SUCCESS;
}

STDCALL void WRAP_EXPORT(NdisMDeregisterIoPortRange)
	(struct ndis_miniport_block *nmb, UINT start, UINT len, void* virt)
{
	TRACEENTER1("%08x %08x", start, len);
}

STDCALL LONG WRAP_EXPORT(NdisInterlockedDecrement)
	(LONG *val)
{
	return InterlockedDecrement(FASTCALL_ARGS_1(val));
}

STDCALL LONG WRAP_EXPORT(NdisInterlockedIncrement)
	(LONG *val)
{
	return InterlockedIncrement(FASTCALL_ARGS_1(val));
}

STDCALL struct nt_list *WRAP_EXPORT(NdisInterlockedInsertHeadList)
	(struct nt_list *head, struct nt_list *entry,
	 struct ndis_spinlock *lock)
{
	return ExInterlockedInsertHeadList(FASTCALL_ARGS_3(head, entry,
							   &lock->klock));
}

STDCALL struct nt_list *WRAP_EXPORT(NdisInterlockedInsertTailList)
	(struct nt_list *head, struct nt_list *entry,
	 struct ndis_spinlock *lock)
{
	return ExInterlockedInsertTailList(FASTCALL_ARGS_3(head, entry,
							   &lock->klock));
}

STDCALL struct nt_list *WRAP_EXPORT(NdisInterlockedRemoveHeadList)
	(struct nt_list *head, struct ndis_spinlock *lock)
{
	return ExInterlockedRemoveHeadList(FASTCALL_ARGS_2(head,
							   &lock->klock));
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMInitializeScatterGatherDma)
	(struct ndis_miniport_block *nmb, UCHAR dma_size, ULONG max_phy_map)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER2("dma_size=%d, maxtransfer=%u", dma_size, max_phy_map);
#ifdef CONFIG_X86_64
	if (dma_size != NDIS_DMA_64BITS)
		ERROR("DMA size is not 64-bits");
#endif
	wnd->use_sg_dma = TRUE;
	return NDIS_STATUS_SUCCESS;
}

STDCALL ULONG WRAP_EXPORT(NdisMGetDmaAlignment)
	(struct ndis_miniport_block *nmb)
{
	TRACEENTER3("");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	return dma_get_cache_alignment();
#else
	return L1_CACHE_BYTES;
#endif
}

STDCALL void WRAP_EXPORT(NdisQueryBufferOffset)
	(ndis_buffer *buffer, UINT *offset, UINT *length)
{
	TRACEENTER3("%p", buffer);
	*offset = MmGetMdlByteOffset(buffer);
	*length = MmGetMdlByteCount(buffer);
	DBGTRACE3("%d, %d", *offset, *length);
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
	KeInitializeEvent(&ndis_event->nt_event, NotificationEvent, 0);
}

STDCALL BOOLEAN WRAP_EXPORT(NdisWaitEvent)
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

STDCALL void WRAP_EXPORT(NdisSetEvent)
	(struct ndis_event *ndis_event)
{
	TRACEENTER3("%p", ndis_event);
	KeSetEvent(&ndis_event->nt_event, 0, 0);
}

STDCALL void WRAP_EXPORT(NdisResetEvent)
	(struct ndis_event *ndis_event)
{
	TRACEENTER3("%p", ndis_event);
	KeResetEvent(&ndis_event->nt_event);
}

/* called via function pointer */
STDCALL void
NdisMResetComplete(struct ndis_miniport_block *nmb, NDIS_STATUS status,
		   BOOLEAN address_reset)
{
	struct wrap_ndis_device *wnd = nmb->wnd;

	TRACEENTER3("status: %08X, reset status: %u", status,
		    address_reset);

	wnd->ndis_comm_status = status;
	wnd->ndis_comm_done = 1 + address_reset;
	wake_up(&wnd->ndis_comm_wq);
	TRACEEXIT3(return);
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisScheduleWorkItem)
	(struct ndis_sched_work_item *ndis_sched_work_item)
{
	TRACEENTER3("%p", ndis_sched_work_item);
	schedule_wrap_work_item(ndis_sched_work_item->func,
				ndis_sched_work_item,
				ndis_sched_work_item->ctx, TRUE);

	TRACEEXIT3(return NDIS_STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(NdisUnchainBufferAtBack)
	(struct ndis_packet *packet, ndis_buffer **buffer)
{
	ndis_buffer *b, *btail;

	TRACEENTER3("%p", packet);
	b = packet->private.buffer_head;
	if (!b) {
		/* no buffer in packet */
		*buffer = NULL;
		TRACEEXIT3(return);
	}
	btail = packet->private.buffer_tail;
	*buffer = btail;
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
	packet->private.valid_counts = FALSE;
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisUnchainBufferAtFront)
	(struct ndis_packet *packet, ndis_buffer **buffer)
{
	TRACEENTER3("%p", packet);
	if (packet->private.buffer_head == NULL) {
		/* no buffer in packet */
		*buffer = NULL;
		TRACEEXIT3(return);
	}

	*buffer = packet->private.buffer_head;
	if (packet->private.buffer_head == packet->private.buffer_tail) {
		/* one buffer in packet */
		packet->private.buffer_head = NULL;
		packet->private.buffer_tail = NULL;
	} else
		packet->private.buffer_head = (*buffer)->next;

	packet->private.valid_counts = FALSE;
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisGetFirstBufferFromPacketSafe)
	(struct ndis_packet *packet, ndis_buffer **first_buffer,
	 void **first_buffer_va, UINT *first_buffer_length,
	 UINT *total_buffer_length, enum mm_page_priority priority)
{
	ndis_buffer *b = packet->private.buffer_head;

	TRACEENTER3("%p(%p)", packet, b);
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
	DBGTRACE3("%p, %d, %d", *first_buffer_va, *first_buffer_length,
		  *total_buffer_length);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(NdisGetFirstBufferFromPacket)
	(struct ndis_packet *packet, ndis_buffer **first_buffer,
	 void **first_buffer_va, UINT *first_buffer_length,
	 UINT *total_buffer_length, enum mm_page_priority priority)
{
	NdisGetFirstBufferFromPacketSafe(packet, first_buffer,
					 first_buffer_va, first_buffer_length,
					 total_buffer_length,
					 NormalPagePriority);
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
	(struct ndis_miniport_block *nmb, ndis_buffer *buf,
	 ULONG phy_map_reg, BOOLEAN write_to_dev,
	 struct ndis_phy_addr_unit *phy_addr_array, UINT *array_size)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER3("phy_map_reg: %u", phy_map_reg);

	if (!write_to_dev) {
		ERROR( "dma from device not supported (%d)", write_to_dev);
		*array_size = 0;
		return;
	}

	if (phy_map_reg > wnd->map_count) {
		ERROR("map_register too big (%u > %u)",
		      phy_map_reg, wnd->map_count);
		*array_size = 0;
		return;
	}

	if (wnd->map_dma_addr[phy_map_reg] != 0) {
//		ERROR("map register already used (%lu)", phy_map_reg);
		*array_size = 1;
		return;
	}

	// map buffer
	phy_addr_array[0].phy_addr =
		PCI_DMA_MAP_SINGLE(wnd->wd->pci.pdev,
				   MmGetMdlVirtualAddress(buf),
				   MmGetMdlByteCount(buf), PCI_DMA_TODEVICE);
	phy_addr_array[0].length = MmGetMdlByteCount(buf);

	*array_size = 1;

	// save mapping index
	wnd->map_dma_addr[phy_map_reg] = phy_addr_array[0].phy_addr;
}

STDCALL void WRAP_EXPORT(NdisMCompleteBufferPhysicalMapping)
	(struct ndis_miniport_block *nmb, ndis_buffer *buf,
	 ULONG phy_map_reg)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	TRACEENTER3("%p %u (%u)", wnd, phy_map_reg, wnd->map_count);

	if (phy_map_reg > wnd->map_count) {
		ERROR("map_register too big (%u > %u)",
		      phy_map_reg, wnd->map_count);
		return;
	}

	if (wnd->map_dma_addr[phy_map_reg] == 0) {
//		ERROR("map register not used (%lu)", phy_map_reg);
		return;
	}

	// unmap buffer
	PCI_DMA_UNMAP_SINGLE(wnd->wd->pci.pdev,
			     wnd->map_dma_addr[phy_map_reg],
			     MmGetMdlByteCount(buf), PCI_DMA_TODEVICE);

	// clear mapping index
	wnd->map_dma_addr[phy_map_reg] = 0;
}

STDCALL void WRAP_EXPORT(NdisMGetDeviceProperty)
	(struct ndis_miniport_block *nmb, void **phy_dev, void **func_dev,
	 void **next_dev, void **alloc_res, void**trans_res)
{
	TRACEENTER2("nmb: %p, phy_dev = %p, func_dev = %p, next_dev = %p, "
		    "alloc_res = %p, trans_res = %p", phy_dev, func_dev,
		    nmb, next_dev, alloc_res, trans_res);
	if (phy_dev)
		*phy_dev = nmb->pdo;
	if (func_dev)
		*func_dev = nmb->fdo;
	if (next_dev)
		*next_dev = nmb->next_device;
}

STDCALL void WRAP_EXPORT(NdisMRegisterUnloadHandler)
	(struct driver_object *drv_obj, void *unload)
{
	if (drv_obj)
		drv_obj->unload = unload;
	return;
}

STDCALL NDIS_STATUS WRAP_EXPORT(NdisMQueryAdapterInstanceName)
	(struct unicode_string *name, struct ndis_miniport_block *nmb)
{
	struct wrap_ndis_device *wnd = nmb->wnd;
	struct ansi_string ansi_string;

	if (wrap_is_pci_bus(wnd->wd->dev_bus_type))
		ansi_string.buf = "PCI Ethernet Adapter";
	else
		ansi_string.buf = "USB Ethernet Adapter";
	ansi_string.length = strlen(ansi_string.buf);
	ansi_string.max_length = ansi_string.length + 1;
	if (RtlAnsiStringToUnicodeString(name, &ansi_string, TRUE))
		TRACEEXIT2(return NDIS_STATUS_RESOURCES);
	else
		TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL ULONG WRAP_EXPORT(NdisReadPcmciaAttributeMemory)
	(struct ndis_miniport_block *nmb, ULONG offset, void *buffer,
	 ULONG length)
{
	UNIMPL();
	return 0;
}

STDCALL ULONG WRAP_EXPORT(NdisWritePcmciaAttributeMemory)
	(struct ndis_miniport_block *nmb, ULONG offset, void *buffer,
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
STDCALL void WRAP_EXPORT(NdisMCoActivateVcComplete)(void){UNIMPL();}

STDCALL void WRAP_EXPORT(NdisMCoDeactivateVcComplete)(void)
{
	UNIMPL();
	return;
}

#include "ndis_exports.h"

void init_nmb_functions(struct ndis_miniport_block *nmb)
{
	nmb->rx_packet = WRAP_FUNC_PTR(NdisMIndicateReceivePacket);
	nmb->send_complete = WRAP_FUNC_PTR(NdisMSendComplete);
	nmb->send_resource_avail = WRAP_FUNC_PTR(NdisMSendResourcesAvailable);
	nmb->status = WRAP_FUNC_PTR(NdisMIndicateStatus);
	nmb->status_complete = WRAP_FUNC_PTR(NdisMIndicateStatusComplete);
	nmb->query_complete = WRAP_FUNC_PTR(NdisMQueryInformationComplete);
	nmb->set_complete = WRAP_FUNC_PTR(NdisMSetInformationComplete);
	nmb->reset_complete = WRAP_FUNC_PTR(NdisMResetComplete);
	nmb->eth_rx_indicate = WRAP_FUNC_PTR(EthRxIndicateHandler);
	nmb->eth_rx_complete = WRAP_FUNC_PTR(EthRxComplete);
	nmb->td_complete = WRAP_FUNC_PTR(NdisMTransferDataComplete);
}

