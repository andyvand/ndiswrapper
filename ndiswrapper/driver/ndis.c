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

extern int image_offset;
extern struct list_head ndis_driverlist;

struct list_head handle_ctx_list;
struct wrap_spinlock atomic_lock;
struct wrap_spinlock cancel_lock;

DECLARE_WAIT_QUEUE_HEAD(event_wq);

static struct work_struct ndis_work;
static struct list_head ndis_work_list;
static struct wrap_spinlock ndis_work_list_lock;

static void ndis_worker(void *data);

void init_ndis(void)
{
	INIT_WORK(&ndis_work, &ndis_worker, NULL);
	INIT_LIST_HEAD(&ndis_work_list);
	wrap_spin_lock_init(&ndis_work_list_lock);

	wrap_spin_lock_init(&atomic_lock);
	wrap_spin_lock_init(&cancel_lock);
	return;
}

/* Called from the driver entry. */
STDCALL static void
NdisInitializeWrapper(struct ndis_handle **ndis_handle, void *SystemSpecific1,
		      void *SystemSpecific2, void *SystemSpecific3)
{
	TRACEENTER1("handle=%08x, SS1=%08x, SS2=%08x", (int)ndis_handle,
		    (int)SystemSpecific1, (int)SystemSpecific2);
	*ndis_handle = (struct ndis_handle*) SystemSpecific1;
	TRACEEXIT1(return);
}

STDCALL static void
NdisTerminateWrapper(struct ndis_handle *handle, void *SystemSpecific1)
{
}

/* Register a miniport with NDIS. Called from driver entry */
STDCALL static int
NdisMRegisterMiniport(struct ndis_driver *ndis_driver,
		      struct miniport_char *miniport_char,
		      unsigned int char_len)
{
	int min_length = ((char*) &miniport_char->co_create_vc) -
		((char*) miniport_char);

	TRACEENTER1("driver: %p", ndis_driver);

	if(miniport_char->majorVersion < 4)
	{
		ERROR("Driver %s using ndis version %d which is too old.",
		      ndis_driver->name, miniport_char->majorVersion);
		TRACEEXIT1(return NDIS_STATUS_BAD_VERSION);
	}

	if(char_len < min_length)
	{
		ERROR("Characteristics length %d is too small for driver %s",
		      char_len, ndis_driver->name);
		TRACEEXIT1(return NDIS_STATUS_BAD_CHARACTERISTICS);
	}

	DBGTRACE1("Version %d.%d", miniport_char->majorVersion,
		 miniport_char->minorVersion);
	DBGTRACE1("Len: %08x:%08x", char_len, sizeof(struct miniport_char));
	memcpy(&ndis_driver->miniport_char, miniport_char,
	       sizeof(struct miniport_char));

	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

STDCALL static unsigned int
NdisAllocateMemory(void **dest, unsigned int length, unsigned int flags,
		   unsigned int highest_addr)
{
	TRACEENTER3("length = %u, flags = %08X", length, flags);
	if (length <= KMALLOC_THRESHOLD)
	{
		if (irqs_disabled() || in_atomic())
			*dest = (void *)kmalloc(length,
						GFP_ATOMIC | __GFP_NOWARN);
		else
			*dest = (void *)kmalloc(length,
						GFP_KERNEL | __GFP_NOWARN);
	}
	else if (flags & NDIS_MEMORY_CONTIGUOUS)
	{
		WARNING("Allocating %u bytes of physically "
		       "contiguous memory may fail", length);
		*dest = (void *)kmalloc(length, GFP_KERNEL | __GFP_NOWARN);
	}
	else
		*dest = vmalloc(length);

	if (*dest)
		TRACEEXIT3(return NDIS_STATUS_SUCCESS);
	DBGTRACE3("Allocatemem failed size=%d", length);
	TRACEEXIT3(return NDIS_STATUS_FAILURE);
}

STDCALL static unsigned int
NdisAllocateMemoryWithTag(void **dest, unsigned int length,
			  unsigned int tag)
{
	TRACEEXIT3(return NdisAllocateMemory(dest, length, 0, 0));
}

STDCALL static void
NdisFreeMemory(void *addr, unsigned int length, unsigned int flags)
{
	struct ndis_work_entry *ndis_work_entry;
	struct ndis_free_mem *free_mem;

	TRACEENTER3("length = %u, flags = %08X", length, flags);

	if (!addr)
		TRACEEXIT3(return);

	if (length <= KMALLOC_THRESHOLD)
		kfree(addr);
	else if (flags & NDIS_MEMORY_CONTIGUOUS)
		kfree(addr);
	else
	{
		if (!in_interrupt())
		{
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
		if (!ndis_work_entry)
		{
			BUG();
		}

		ndis_work_entry->type = _NDIS_FREE_MEM;
		free_mem = &ndis_work_entry->entry.free_mem;

		free_mem->addr = addr;
		free_mem->length = length;
		free_mem->flags = flags;

		wrap_spin_lock(&ndis_work_list_lock);
		list_add_tail(&ndis_work_entry->list, &ndis_work_list);
		wrap_spin_unlock(&ndis_work_list_lock);

		schedule_work(&ndis_work);
	}

	TRACEEXIT3(return);
}

/*
 * This function should not be STDCALL because it's a variable args function.
 */
NOREGPARM static void
NdisWriteErrorLogEntry(struct ndis_handle *handle, unsigned int error,
			    unsigned int length, unsigned int p1)
{
	ERROR("log: %08X, length: %d (%08x)\n", error, length, p1);
}

STDCALL static void
NdisOpenConfiguration(unsigned int *status, struct ndis_handle **confhandle,
		      struct ndis_handle *handle)
{
	TRACEENTER2("confHandle: %p, handle->dev_name: %s",
			confhandle, handle->net_dev->name);
	*confhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL static void
NdisOpenConfigurationKeyByName(unsigned int *status,
			       struct ndis_handle *handle, struct ustring *key,
			       struct ndis_handle **subkeyhandle)
{
	TRACEENTER2("%s", "");
	*subkeyhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL static void
NdisOpenConfigurationKeyByIndex(unsigned int *status,
				struct ndis_handle *handle,
				unsigned long index, struct ustring *key,
				struct ndis_handle **subkeyhandle)
{
	TRACEENTER2("%s", "");
	*subkeyhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT2(return);
}

STDCALL static void
NdisCloseConfiguration(void *confhandle)
{
	TRACEENTER2("confhandle: %08x", (int) confhandle);
}

STDCALL static void
NdisOpenFile(unsigned int *status, struct ndis_file **filehandle,
	     unsigned int *filelength, struct ustring *filename,
	     u64 highest_address)
{
	struct ustring ansi;
	struct list_head *curr, *tmp;
	struct ndis_file *file;

	TRACEENTER2("status = %p, filelength = %p, *filelength = %d, "
		    "high = %lu, filehandle = %p, *filehandle = %p",
		    status, filelength, *filelength,
		    (unsigned long)highest_address, filehandle, *filehandle);

	ansi.buf = kmalloc(MAX_STR_LEN, GFP_KERNEL);
	if (!ansi.buf)
	{
		*status = NDIS_STATUS_RESOURCES;
		return;
	}
	ansi.buf[MAX_STR_LEN-1] = 0;
	ansi.buflen = MAX_STR_LEN;


	if (RtlUnicodeStringToAnsiString(&ansi, filename, 0))
	{
		*status = NDIS_STATUS_RESOURCES;
		kfree(ansi.buf);
		TRACEEXIT2(return);
	}
	DBGTRACE2("Filename: %s, Highest Address: %08x",
			 ansi.buf, (int) highest_address);

	/* Loop through all drivers and all files to find the requested file */
	list_for_each_safe(curr, tmp, &ndis_driverlist)
	{
		struct list_head *curr2, *tmp2;

		struct ndis_driver *driver = (struct ndis_driver *) curr;
		list_for_each_safe(curr2, tmp2, &driver->files)
		{
			int n;
			file = (struct ndis_file*) curr2;
			DBGTRACE2("Considering %s", file->name);
			n = min(strlen(file->name), strlen(ansi.buf));
			if(strnicmp(file->name, ansi.buf, n) == 0)
			{
				*filehandle = file;
				*filelength = file->size;
				*status = NDIS_STATUS_SUCCESS;
				kfree(ansi.buf);
				TRACEEXIT2(return);
			}
		}
	}
	*status = NDIS_STATUS_FILE_NOT_FOUND;
	kfree(ansi.buf);
	TRACEEXIT2(return);
}

STDCALL static void
NdisMapFile(unsigned int *status, void **mappedbuffer,
	    struct ndis_file *filehandle)
{
	TRACEENTER2("Handle: %08x", (int) filehandle);

	if (!filehandle)
	{
		*status = NDIS_STATUS_ALREADY_MAPPED;
		TRACEEXIT2(return);
	}

	*status = NDIS_STATUS_SUCCESS;
	*mappedbuffer = filehandle->data;
	TRACEEXIT2(return);
}

STDCALL static void
NdisUnmapFile(struct ndis_file *filehandle)
{
	TRACEENTER2("Handle: %08x", (int) filehandle);
	TRACEEXIT2(return);
}

STDCALL static void
NdisCloseFile(struct ndis_file *filehandle)
{
	TRACEENTER2("Handle: %08x", (int) filehandle);
	TRACEEXIT2(return);
}

STDCALL static void
NdisGetSystemUpTime(unsigned int *systemuptime)
{
	TRACEENTER4("%s", "");
	*systemuptime = 10 * jiffies / HZ;
	TRACEEXIT4(return);
}

static inline int SPAN_PAGES(unsigned int ptr, unsigned int len)
{
	unsigned int p = ptr & (PAGE_SIZE - 1);
	TRACEEXIT3(return (p + len + (PAGE_SIZE - 1)) >> PAGE_SHIFT);
}

/* called as macro */
STDCALL unsigned long
NDIS_BUFFER_TO_SPAN_PAGES(struct ndis_buffer *buffer)
{
	unsigned int p;
	unsigned int i;

	TRACEENTER3("%s", "");

	if (buffer == NULL)
		return 0;

	if (buffer->len == 0)
		return 1;
	p = (unsigned int)buffer->data + buffer->offset;
	i = SPAN_PAGES(PAGE_ALIGN(p), buffer->len);
	DBGTRACE3("pages = %u", i);
	TRACEEXIT3(return i);
}

STDCALL static void
NdisGetBufferPhysicalArraySize(struct ndis_buffer *buffer,
			       unsigned int *arraysize)
{
	TRACEENTER3("Buffer: %08x", (int) buffer);
	*arraysize = NDIS_BUFFER_TO_SPAN_PAGES(buffer);
	TRACEEXIT3(return);
}

static int ndis_encode_setting(struct ndis_setting *setting,
			       int ndis_setting_type)
{
	struct ustring ansi;

	TRACEENTER2("type = %d", ndis_setting_type);
	if (setting->value.type == ndis_setting_type)
		return NDIS_STATUS_SUCCESS;

	if (setting->value.type == NDIS_SETTING_STRING)
		kfree(setting->value.data.ustring.buf);

	switch(ndis_setting_type)
	{
	case NDIS_SETTING_INT:
		setting->value.data.intval =
			simple_strtol(setting->val_str, NULL, 0);
		DBGTRACE("value = %lu", setting->value.data.intval);
		break;
	case NDIS_SETTING_HEXINT:
		setting->value.data.intval =
			simple_strtol(setting->val_str, NULL, 16);
		DBGTRACE2("value = %lu", setting->value.data.intval);
		break;
	case NDIS_SETTING_STRING:
		ansi.buflen = ansi.len = strlen(setting->val_str);
		ansi.buf = setting->val_str;
		if (RtlAnsiStringToUnicodeString(&setting->value.data.ustring,
						 &ansi, 1))
			TRACEEXIT1(return NDIS_STATUS_FAILURE);
		break;
	default:
		return NDIS_STATUS_FAILURE;
	}
	setting->value.type = ndis_setting_type;
	return NDIS_STATUS_SUCCESS;
}

static int ndis_decode_setting(struct ndis_setting *setting,
			       struct ndis_setting_val *val)
{
	struct ustring ansi;

	switch(val->type)
	{
	case NDIS_SETTING_INT:
		snprintf(setting->val_str, sizeof(long), "%lu",
			 (unsigned long)val->data.intval);
		setting->val_str[sizeof(long)] = 0;
		break;
	case NDIS_SETTING_HEXINT:
		snprintf(setting->val_str, sizeof(long), "%lx",
			 (unsigned long)val->data.intval);
		setting->val_str[sizeof(long)] = 0;
		break;
	case NDIS_SETTING_STRING:
		ansi.buf = setting->val_str;
		ansi.buflen = MAX_STR_LEN;
		if (RtlUnicodeStringToAnsiString(&ansi, &val->data.ustring, 0)
		    || ansi.len >= MAX_STR_LEN)
		{
			TRACEEXIT1(return NDIS_STATUS_FAILURE);
		}
		break;
	default:
		DBGTRACE2("unknown setting type: %d", val->type);
		return NDIS_STATUS_FAILURE;
	}
	setting->value.type = NDIS_SETTING_NONE;
	return NDIS_STATUS_SUCCESS;
}

STDCALL static void
NdisReadConfiguration(unsigned int *status, struct ndis_setting_val **dest,
		      struct ndis_handle *handle, struct ustring *key,
		      unsigned int type)
{
	struct ndis_setting *setting;
	struct ustring ansi;
	char *keyname;

	TRACEENTER2("%s", "");
	ansi.buf = kmalloc(MAX_STR_LEN, GFP_KERNEL);
	if (!ansi.buf)
	{
		*status = NDIS_STATUS_RESOURCES;
		return;
	}
	ansi.buf[MAX_STR_LEN-1] = 0;
	ansi.buflen = MAX_STR_LEN;
	if (RtlUnicodeStringToAnsiString(&ansi, key, 0))
	{
		*dest = NULL;
		*status = NDIS_STATUS_FAILURE;
		kfree(ansi.buf);
		TRACEEXIT2(return);
	}
	keyname = ansi.buf;

	list_for_each_entry(setting, &handle->device->settings, list)
	{
		if(stricmp(keyname, setting->name) == 0)
		{
			DBGTRACE2("setting found %s=%s",
				 keyname, setting->val_str);

			*status = ndis_encode_setting(setting, type);
			if (*status == NDIS_STATUS_SUCCESS)
				*dest = &setting->value;
			else
				*dest = NULL;
			kfree(ansi.buf);
			DBGTRACE2("status = %d", *status);
			TRACEEXIT2(return);
		}
	}

	DBGTRACE2("setting %s not found (type:%d)", keyname, type);

	*dest = NULL;
	*status = NDIS_STATUS_FAILURE;
	kfree(ansi.buf);
	TRACEEXIT2(return);
}

STDCALL static void
NdisWriteConfiguration(unsigned int *status, struct ndis_handle *handle,
		       struct ustring *key, struct ndis_setting_val *val)
{
	struct ustring ansi;
	struct ndis_setting *setting;
	char *keyname;

	TRACEENTER2("%s", "");
	ansi.buf = kmalloc(MAX_STR_LEN, GFP_KERNEL);
	if (!ansi.buf)
	{
		*status = NDIS_STATUS_RESOURCES;
		return;
	}
	ansi.buf[MAX_STR_LEN-1] = 0;
	ansi.buflen = MAX_STR_LEN;
	if (RtlUnicodeStringToAnsiString(&ansi, key, 0))
	{
		*status = NDIS_STATUS_FAILURE;
		kfree(ansi.buf);
		TRACEEXIT2(return);
	}
	keyname = ansi.buf;

	list_for_each_entry(setting, &handle->device->settings, list)
	{
		if(strcmp(keyname, setting->name) == 0)
		{
			if (setting->value.type == NDIS_SETTING_STRING)
				kfree(setting->value.data.ustring.buf);
			*status = ndis_decode_setting(setting, val);
			DBGTRACE2("setting changed %s=%s",
				 keyname, setting->val_str);
			kfree(ansi.buf);
			TRACEEXIT2(return);
		}
	}

	if ((setting = kmalloc(sizeof(*setting), GFP_KERNEL)) == NULL)
	{
		*status = NDIS_STATUS_RESOURCES;
		kfree(ansi.buf);
		TRACEEXIT2(return);
	}
	memset(setting, 0, sizeof(*setting));
	if ((setting->name = kmalloc(ansi.len+1, GFP_KERNEL)) == NULL)
	{
		kfree(setting);
		*status = NDIS_STATUS_RESOURCES;
		kfree(ansi.buf);
		TRACEEXIT2(return);
	}
	memcpy(setting->name, keyname, ansi.len);
	setting->name[ansi.len] = 0;
	*status = ndis_decode_setting(setting, val);
	if (*status == NDIS_STATUS_SUCCESS)
		list_add(&setting->list, &handle->device->settings);
	else
	{
		kfree(setting->name);
		kfree(setting);
	}
	kfree(ansi.buf);
	TRACEEXIT2(return);
}

STDCALL static void
NdisInitializeString(struct ustring *dest, char *src)
{
	struct ustring ansi;

	TRACEENTER2("%s", "");
	ansi.len = ansi.buflen = strlen(src);
	ansi.buf = src;
	if (RtlAnsiStringToUnicodeString(dest, &ansi, 1))
		DBGTRACE2("%s", "failed");
	TRACEEXIT2(return);
}

STDCALL static void
NdisInitAnsiString(struct ustring *dest, char *src)
{
	TRACEENTER2("%s", "");
	if (dest == NULL)
		TRACEEXIT2(return);
	if (src == NULL) {
		dest->len = dest->buflen = 0;
		dest->buf = NULL;
		TRACEEXIT2(return);
	}
	dest->len = dest->buflen = strlen(src);
	dest->buf = src;
	TRACEEXIT2(return);
}

STDCALL static void
NdisInitUnicodeString(struct ustring *dest, u16 *src)
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
	dest->buf = (u8 *)src;
	TRACEEXIT2(return);
}

STDCALL static unsigned int
NdisAnsiStringToUnicodeString(struct ustring *dst, struct ustring *src)
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

STDCALL static int
NdisUnicodeStringToAnsiString(struct ustring *dst, struct ustring *src)
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
STDCALL static void
NdisMSetAttributesEx(struct ndis_handle *handle, void* adapter_ctx,
		     unsigned int hangcheck_interval,
		     unsigned int attributes, unsigned int adaptortype)
{
	struct handle_ctx_entry *handle_ctx;

	TRACEENTER2("%08x, %08x %d %08x, %d", (int)handle, (int)adapter_ctx,
		    hangcheck_interval, attributes, adaptortype);
	/* FIXME: is it possible to have duplicate ctx's? */
	handle_ctx = kmalloc(sizeof(*handle_ctx), GFP_KERNEL);
	if (handle_ctx)
	{
		handle_ctx->handle = handle;
		handle_ctx->ctx = adapter_ctx;
		/* atomic_lock is not meant for use here, but since the
		 * functions that use it are fast, no harm abusing it */
		wrap_spin_lock(&atomic_lock);
		list_add(&handle_ctx->list, &handle_ctx_list);
		wrap_spin_unlock(&atomic_lock);
	}

	if (attributes & NDIS_ATTRIBUTE_BUS_MASTER)
	{
		pci_set_master(handle->dev.pci);
	}

	if (!(attributes & NDIS_ATTRIBUTE_DESERIALIZE))
		set_bit(ATTR_SERIALIZED, &handle->attributes);

	if (attributes & NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK)
		set_bit(ATTR_SURPRISE_REMOVE, &handle->attributes);

	if (!(attributes & NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND))
		set_bit(ATTR_HALT_ON_SUSPEND, &handle->attributes);

	/* less than 3 seconds seem to be problematic */
	if (hangcheck_interval >= 0)
	{
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

	wrap_spin_lock(&atomic_lock);
	list_for_each_entry(handle_ctx, &handle_ctx_list, list)
	{
		if (handle_ctx->ctx == ctx)
		{
			wrap_spin_unlock(&atomic_lock);
			return handle_ctx->handle;
		}
	}
	wrap_spin_unlock(&atomic_lock);

	return NULL;
}

/* remove all 'handle X ctx' pairs for the given handle */
void free_handle_ctx(struct ndis_handle *handle)
{
	struct list_head *curr, *tmp;

	wrap_spin_lock(&atomic_lock);
	list_for_each_safe(curr, tmp, &handle_ctx_list)
	{
		struct handle_ctx_entry *handle_ctx =
			(struct handle_ctx_entry *)curr;
		if (handle_ctx->handle == handle)
		{
			list_del(&handle_ctx->list);
			kfree(handle_ctx);
		}
	}
	wrap_spin_unlock(&atomic_lock);
	return;
}

STDCALL static unsigned int
NdisReadPciSlotInformation(struct ndis_handle *handle, unsigned int slot,
			   unsigned int offset, char *buf, unsigned int len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		pci_read_config_byte(handle->dev.pci, offset+i, &buf[i]);
	}
	return len;
}

STDCALL static unsigned int
NdisWritePciSlotInformation(struct ndis_handle *handle, unsigned int slot,
			    unsigned int offset, char *buf, unsigned int len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		pci_write_config_byte(handle->dev.pci, offset+i, buf[i]);
	}
	return len;
}

STDCALL static void
NdisMQueryAdapterResources(unsigned int *status, struct ndis_handle *handle,
			   struct ndis_resource_list *resource_list,
			   unsigned int *size)
{
	int i;
	int len = 0;
	/* FIXME: do USB drivers call this? */
	struct pci_dev *pci_dev = handle->dev.pci;
	struct ndis_resource_entry *entry;
	TRACEENTER2("handle: %08x. buf: %08x, len: %d. IRQ:%d", (int)handle,
		    (int)resource_list, *size, pci_dev->irq);

	resource_list->version = 1;
	resource_list->revision = 0;

	/* Put all memory and port resources */
	i = 0;
	while(pci_resource_start(pci_dev, i))
	{
		entry = &resource_list->list[len++];
		if(pci_resource_flags(pci_dev, i) & IORESOURCE_MEM)
		{
			entry->type = 3;
			entry->flags = 0;

		}

		else if(pci_resource_flags(pci_dev, i) & IORESOURCE_IO)
		{
			entry->type = 1;
			entry->flags = 1;
		}

		entry->share = 0;
		entry->param1 = pci_resource_start(pci_dev, i);
		entry->param2 = 0;
		entry->param3 = pci_resource_len(pci_dev, i);

		i++;
	}

	/* Put IRQ resource */
	entry = &resource_list->list[len++];
	entry->type = 2;
	entry->share = 0;
	entry->flags = 0;
	entry->param1 = pci_dev->irq; //Level
	entry->param2 = pci_dev->irq; //Vector
	entry->param3 = -1;  //affinity

	resource_list->length = len;
	*size = (char*) (&resource_list->list[len]) - (char*)resource_list;
	*status = NDIS_STATUS_SUCCESS;


	DBGTRACE2("resource list v%d.%d len %d, size=%d",
		  resource_list->version, resource_list->revision,
		  resource_list->length, *size);

	for(i = 0; i < len; i++)
	{
		DBGTRACE2("Resource: %d: %08x %08x %08x, %d",
			  resource_list->list[i].type,
			  resource_list->list[i].param1,
			  resource_list->list[i].param2,
			  resource_list->list[i].param3,
			  resource_list->list[i].flags);
	}
	TRACEEXIT2(return);
}

STDCALL static unsigned int
NdisMMapIoSpace(void **virt, struct ndis_handle *handle,
		unsigned int physlo, unsigned int physhi, unsigned int len)
{
	TRACEENTER2("%08x, %d", (int)physlo, len);
	*virt = ioremap(physlo, len);
	if(*virt == NULL) {
		ERROR("%s", "ioremap failed");
		TRACEEXIT2(return NDIS_STATUS_FAILURE);
	}

	handle->mem_start = physlo;
	handle->mem_end = physlo + len -1;
	DBGTRACE2("ioremap successful %08x", (int)*virt);
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

STDCALL static void
NdisMUnmapIoSpace(struct ndis_handle *handle, void *virtaddr, unsigned int len)
{
	TRACEENTER2("%08x, %d", (int)virtaddr, len);
	iounmap(virtaddr);
}

STDCALL static void
NdisAllocateSpinLock(struct ndis_spin_lock *lock)
{
	struct wrap_spinlock *wrap_spinlock;

	TRACEENTER4("lock %p", lock);

	wrap_spinlock = wrap_kmalloc(sizeof(wrap_spinlock), GFP_ATOMIC);
	if (!wrap_spinlock)
		ERROR("%s", "Couldn't allocate space for spinlock");
	else
	{
		DBGTRACE4("allocated spinlock %p", wrap_spinlock);
		wrap_spin_lock_init(wrap_spinlock);
		lock->wrap_spinlock = wrap_spinlock;
	}

	TRACEEXIT4(return);
}

STDCALL static void
NdisFreeSpinLock(struct ndis_spin_lock *lock)
{
	TRACEENTER4("lock %p", lock);
	if (!lock->wrap_spinlock)
	{
		ERROR("incorrect lock %p", lock);
		return;
	}
#ifdef CONFIG_DEBUG_SPINLOCK
	if (lock->wrap_spinlock->magic != NDIS_SPIN_LOCK_MAGIC)
		ERROR("uninitliazed lock %p (%u)",
		      lock->wrap_spinlock, lock->wrap_spinlock->magic);
	else
#endif
	{
		wrap_kfree(lock->wrap_spinlock);
		lock->wrap_spinlock = NULL;
	}
	TRACEEXIT4(return);
}

STDCALL static void
NdisAcquireSpinLock(struct ndis_spin_lock *lock)
{
	TRACEENTER5("lock %p", lock);
	if (!lock->wrap_spinlock)
	{
		WARNING("Windows driver trying to use uninitialized lock %p,"
		     " fixing it.", lock);
		NdisAllocateSpinLock(lock);
		if (!lock->wrap_spinlock)
			return;
	}
	wrap_spin_lock(lock->wrap_spinlock);
	TRACEEXIT5(return);
}

STDCALL static void
NdisReleaseSpinLock(struct ndis_spin_lock *lock)
{
	TRACEENTER5("lock %p", lock);
	if (!lock->wrap_spinlock)
	{
		ERROR("incorrect lock %p", lock);
		return;
	}
	wrap_spin_unlock(lock->wrap_spinlock);
	TRACEEXIT5(return);
}

STDCALL static void
NdisDprAcquireSpinLock(struct ndis_spin_lock *lock)
{
	TRACEENTER5("lock %p", lock);
	NdisAcquireSpinLock(lock);
	TRACEEXIT5(return);
}

STDCALL static void
NdisDprReleaseSpinLock(struct ndis_spin_lock *lock)
{
	TRACEENTER5("lock %p", lock);
	NdisReleaseSpinLock(lock);
	TRACEEXIT5(return);
}

STDCALL static  unsigned int
NdisMAllocateMapRegisters(struct ndis_handle *handle, unsigned int dmachan,
			  unsigned char dmasize, unsigned int basemap,
			  unsigned int size)
{
	TRACEENTER2("%d %d %d %d", dmachan, dmasize, basemap, size);

//	if (basemap > 64)
//		return NDIS_STATUS_RESOURCES;

	if (handle->map_count > 0)
	{
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

STDCALL static void
NdisMFreeMapRegisters(struct ndis_handle *handle)
{
	TRACEENTER2("handle: %08x", (int)handle);

	if (handle->map_dma_addr != NULL)
		kfree(handle->map_dma_addr);
	handle->map_count = 0;
	TRACEEXIT2(return);
}

STDCALL static void
NdisMAllocateSharedMemory(struct ndis_handle *handle, unsigned long size,
			  char cached, void **virt,
			  struct ndis_phy_address *phys)
{
	dma_addr_t p;
	void *v;

	TRACEENTER3("map count: %d, size: %lu, cached: %d",
		    handle->map_count, size, cached);

//	if (handle->map_dma_addr == NULL)
//		ERROR("%s: DMA map address is not set!\n", __FUNCTION__);
	/* FIXME: do USB drivers call this? */
	v = PCI_DMA_ALLOC_COHERENT(handle->dev.pci, size, &p);
	if (!v)
	{
		ERROR("Failed to allocate DMA coherent memory. "
		      "Windows driver requested %ld bytes of "
		      "%scached memory\n", size, cached ? "" : "un-");
	}

	*(char**)virt = v;
	phys->low = v == NULL ? 0 : (unsigned int)p;
	phys->high = 0;
	DBGTRACE3("allocated shared memory: %p", v);
}

STDCALL static int
NdisMAllocateSharedMemoryAsync(struct ndis_handle *handle,
			       unsigned long size, char cached, void *ctx)
{
	struct ndis_work_entry *ndis_work_entry;
	struct ndis_alloc_mem *alloc_mem;

	TRACEENTER3("%s", "");
	ndis_work_entry = kmalloc(sizeof(*ndis_work_entry), GFP_ATOMIC);
	if (!ndis_work_entry)
		return NDIS_STATUS_FAILURE;

	ndis_work_entry->type = _NDIS_ALLOC_MEM;

	alloc_mem = &ndis_work_entry->entry.alloc_mem;

	alloc_mem->handle = handle;
	alloc_mem->size = size;
	alloc_mem->cached = cached;
	alloc_mem->ctx = ctx;

	wrap_spin_lock(&ndis_work_list_lock);
	list_add_tail(&ndis_work_entry->list, &ndis_work_list);
	wrap_spin_unlock(&ndis_work_list_lock);

	schedule_work(&ndis_work);
	TRACEEXIT3(return NDIS_STATUS_PENDING);
}

STDCALL static void
NdisMFreeSharedMemory(struct ndis_handle *handle, unsigned int size,
		      char cached, void *virt,
		      unsigned int physlow, unsigned int physhigh)
{
	TRACEENTER3("%s", "");
	/* FIXME: do USB drivers call this? */
	PCI_DMA_FREE_COHERENT(handle->dev.pci, size, virt, physlow);
	TRACEEXIT3(return);
}

STDCALL static void
NdisAllocateBufferPool(unsigned int *status, unsigned int *poolhandle,
		       unsigned int size)
{
	TRACEENTER4("%s", "");
	*poolhandle = 0x0000fff8;
	*status = NDIS_STATUS_SUCCESS;
}

STDCALL static void
NdisFreeBufferPool(void *poolhandle)
{
	TRACEENTER4("%s", "");

	TRACEEXIT4(return);
}

STDCALL static void
NdisAllocateBuffer(unsigned int *status, void **buffer, void *poolhandle,
		   void *virt, unsigned int len)
{
	struct ndis_buffer *my_buffer = kmalloc(sizeof(struct ndis_buffer),
						GFP_ATOMIC);
	TRACEENTER4("%s", "");
	if(!my_buffer)
	{
		ERROR("%s", "Couldn't allocate memory");
		*status = NDIS_STATUS_FAILURE;
		TRACEEXIT4(return);
	}

	memset(my_buffer, 0, sizeof(struct ndis_buffer));

	my_buffer->data = virt;
	my_buffer->next = 0;
	my_buffer->len = len;

	*buffer = my_buffer;

	DBGTRACE4("allocated buffer: %p", buffer);
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT4(return);
}

STDCALL static void
NdisFreeBuffer(void *buffer)
{
	TRACEENTER4("%s", "");
	if(buffer)
	{
		memset(buffer, 0, sizeof(struct ndis_buffer));
		kfree(buffer);
	}
	TRACEEXIT4(return);
}

STDCALL static void
NdisAdjustBufferLength(struct ndis_buffer *buf, unsigned int len)
{
	TRACEENTER4("%s", "");
	buf->len = len;
}

STDCALL static void
NdisQueryBuffer(struct ndis_buffer *buf, void **adr, unsigned int *len)
{
	TRACEENTER3("%s", "");
	if(adr)
		*adr = buf->data;
	if(len)
		*len = buf->len;
}

STDCALL static void
NdisQueryBufferSafe(struct ndis_buffer *buf, void **adr,
		    unsigned int *len, unsigned int priority)
{
	TRACEENTER3("%08x, %08x, %08x", (int)buf, (int)adr, (int)len);
	if(adr)
		*adr = buf->data;
	if(len)
		*len = buf->len;
}

STDCALL static void *
NdisBufferVirtualAddress(struct ndis_buffer *buf)
{
	TRACEENTER3("%s", "");
	return buf->data;
}

STDCALL static unsigned long
NdisBufferLength(struct ndis_buffer *buf)
{
	TRACEENTER3("%s", "");
	return buf->len;
}

STDCALL static void
NdisAllocatePacketPool(unsigned int *status, unsigned int *poolhandle,
		       unsigned int size, unsigned int rsvlen)
{
	TRACEENTER3("size=%d", size);
	*poolhandle = 0xa000fff4;
	*status = NDIS_STATUS_SUCCESS;
}

STDCALL static void
NdisAllocatePacketPoolEx(unsigned int *status, unsigned int *poolhandle,
			 unsigned int size, unsigned int overflowsize,
			 unsigned int rsvlen)
{
	TRACEENTER3("%s", "");
	NdisAllocatePacketPool(status, poolhandle, size, rsvlen);
	TRACEEXIT3(return);
}

STDCALL static unsigned int
NdisPacketPoolUsage(void *poolhandle)
{
	UNIMPL();
	return 0;
}

STDCALL static void
NdisFreePacketPool(void *poolhandle)
{
	TRACEENTER3("handle: %08x", (int)poolhandle);
}

STDCALL static void
NdisAllocatePacket(unsigned int *status, struct ndis_packet **packet_out,
		   void *poolhandle)
{
	struct ndis_packet *packet;

	TRACEENTER3("%s", "");
	packet = kmalloc(sizeof(struct ndis_packet), GFP_ATOMIC);
	if(!packet)
	{
		ERROR("%s", "Couldn't allocate memory");
		*packet_out = NULL;
		*status = NDIS_STATUS_FAILURE;
		TRACEEXIT3(return);
	}
	memset(packet, 0, sizeof(struct ndis_packet));
	packet->oob_offset = (int)(&packet->timesent1) - (int)packet;
	packet->pool = (void*) 0xa000fff4;
	packet->packet_flags = 0xc0;

/* See comment in wrapper.c/send_one about this */
#if 0
	{
		int i = 0;
		/* Poision extra packet info */
		int *x = (int*) &packet->ext1;
		for(i = 0; i <= 12; i++)
		{
			x[i] = i;
		}
		packet->mediaspecific_size = 0x100;
		packet->mediaspecific = (void*) 0x0001f00;
	}
#endif


	*packet_out = packet;
	*status = NDIS_STATUS_SUCCESS;
	TRACEEXIT3(return);
}

STDCALL static void
NdisFreePacket(void *packet)
{
	TRACEENTER3("%s", "");
	if(packet)
	{
		memset(packet, 0, sizeof(struct ndis_packet));
		kfree(packet);
	}
	TRACEEXIT3(return);
}

STDCALL static void
NdisMInitializeTimer(struct ndis_miniport_timer *timer_handle,
		     struct ndis_handle *handle, void *func, void *ctx)
{
	TRACEENTER4("%s", "");
	wrapper_init_timer(&timer_handle->ktimer, handle);
	init_dpc(&timer_handle->kdpc, func, ctx);
	wrapper_set_timer_dpc(timer_handle->ktimer.wrapper_timer,
	                      &timer_handle->kdpc);
	TRACEEXIT4(return);
}

STDCALL static void
NdisInitializeTimer(struct ndis_timer *timer_handle, void *func, void *ctx)
{
	TRACEENTER4("%p, %p, %p", timer_handle, func, ctx);
	wrapper_init_timer(&timer_handle->ktimer, NULL);
	init_dpc(&timer_handle->kdpc, func, ctx);
	wrapper_set_timer_dpc(timer_handle->ktimer.wrapper_timer,
	                      &timer_handle->kdpc);
	TRACEEXIT4(return);
}

STDCALL static void
NdisSetTimer(struct ndis_timer *timer_handle, unsigned int ms)
{
	unsigned long expires = jiffies + (ms * HZ) / 1000;

	TRACEENTER4("%p, %u", timer_handle, ms);
	wrapper_set_timer(timer_handle->ktimer.wrapper_timer, expires, 0);
	TRACEEXIT4(return);
}

STDCALL static void
NdisMSetPeriodicTimer(struct ndis_miniport_timer *timer_handle,
		      unsigned int ms)
{
	unsigned long expires = jiffies + (ms * HZ) / 1000;
	unsigned long repeat = ms * HZ / 1000;

	TRACEENTER4("%p, %u", timer_handle, ms);
	wrapper_set_timer(timer_handle->ktimer.wrapper_timer, expires, repeat);
	TRACEEXIT4(return);
}

STDCALL static void
NdisMCancelTimer(struct ndis_miniport_timer *timer_handle, char *canceled)
{
	TRACEENTER4("%s", "");
	wrapper_cancel_timer(timer_handle->ktimer.wrapper_timer, canceled);
	TRACEEXIT4(return);
}

STDCALL static void
NdisCancelTimer(struct ndis_timer *timer_handle, char *canceled)
{
	TRACEENTER4("%s", "");
	wrapper_cancel_timer(timer_handle->ktimer.wrapper_timer, canceled);
	TRACEEXIT4(return);
}

/*
 * The driver asks ndis what mac it should use. If this
 * function returns failiure it will use it's default mac.
 */
STDCALL static void
NdisReadNetworkAddress(unsigned int *status, char *adr, unsigned int *len,
		       void *conf_handle)
{
	TRACEENTER1("%s", "");
	*len = 0;
	*status = NDIS_STATUS_FAILURE;
	TRACEEXIT1(return);
}

STDCALL static void
NdisMRegisterAdapterShutdownHandler(struct ndis_handle *handle,
				    void *ctx, void *func)
{
	TRACEENTER1("sp:%08x", getSp());
	handle->driver->miniport_char.adapter_shutdown = func;
	handle->shutdown_ctx = ctx;
}

STDCALL static void
NdisMDeregisterAdapterShutdownHandler(struct ndis_handle *handle)
{
	TRACEENTER1("sp:%08x", getSp());
	handle->driver->miniport_char.adapter_shutdown = NULL;
	handle->shutdown_ctx = NULL;
}

/* bottom half of the irq handler */
void ndis_irq_bh(void *data)
{
	struct ndis_irq *ndis_irq = (struct ndis_irq *) data;
	struct ndis_handle *handle = ndis_irq->handle;
	struct miniport_char *miniport = &handle->driver->miniport_char;

	if (ndis_irq->enabled)
	{
		miniport->handle_interrupt(handle->adapter_ctx);
		if (miniport->enable_interrupts)
			miniport->enable_interrupts(handle->adapter_ctx);
	}
}

/* Top half of the irq handler */
irqreturn_t ndis_irq_th(int irq, void *data, struct pt_regs *pt_regs)
{
	int recognized = 0;
	int handled = 0;
	struct ndis_irq *ndis_irq = (struct ndis_irq *) data;
	struct ndis_handle *handle;
	struct miniport_char *miniport;
	unsigned long flags;

	if (!ndis_irq || !ndis_irq->handle)
		return IRQ_NONE;
	handle = ndis_irq->handle;
	miniport = &handle->driver->miniport_char;
	/* this spinlock should be shared with NdisMSynchronizeWithInterrupt
	 */
	spin_lock_irqsave(ndis_irq->spinlock, flags);
	if (ndis_irq->req_isr)
		miniport->isr(&recognized, &handled, handle->adapter_ctx);
	else //if (miniport->disable_interrupts)
	{
		miniport->disable_interrupts(handle->adapter_ctx);
		/* it is not shared interrupt, so handler must be called */
		recognized = handled = 1;
	}
	spin_unlock_irqrestore(ndis_irq->spinlock, flags);

	if (recognized && handled)
		schedule_work(&handle->irq_bh);

	if (recognized)
		return IRQ_HANDLED;

	return IRQ_NONE;
}

STDCALL static unsigned int
NdisMRegisterInterrupt(struct ndis_irq *ndis_irq, struct ndis_handle *handle,
		       unsigned int vector, unsigned int level,
		       unsigned char req_isr, unsigned char shared,
		       unsigned int mode)
{
	TRACEENTER1("%08x, vector:%d, level:%d, req_isr:%d, shared:%d, "
		    "mode:%d sp:%08x",(int)ndis_irq, vector, level, req_isr,
		    shared, mode, (int)getSp());

	ndis_irq->spinlock = kmalloc(sizeof(spinlock_t), GFP_KERNEL);
	if (ndis_irq->spinlock == NULL)
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);

	ndis_irq->irq = vector;
	ndis_irq->handle = handle;
	ndis_irq->req_isr = req_isr;
	if (shared && !req_isr)
		WARNING("%s", "shared but dynamic interrupt!");
	ndis_irq->shared = shared;
	spin_lock_init(ndis_irq->spinlock);
	handle->ndis_irq = ndis_irq;

	INIT_WORK(&handle->irq_bh, &ndis_irq_bh, ndis_irq);
	if (request_irq(vector, ndis_irq_th, shared? SA_SHIRQ : 0,
			"ndiswrapper", ndis_irq))
	{
		printk(KERN_WARNING "%s: request for irq %d failed\n",
		       DRV_NAME, vector);
		TRACEEXIT1(return NDIS_STATUS_RESOURCES);
	}
	ndis_irq->enabled = 1;
	printk(KERN_INFO "%s: using irq %d\n", DRV_NAME, vector);
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

/* called in call_halt */
STDCALL void
NdisMDeregisterInterrupt(struct ndis_irq *ndis_irq)
{
	TRACEENTER1("%p", ndis_irq);

	if (ndis_irq)
	{
		struct ndis_handle *handle = ndis_irq->handle;
		ndis_irq->enabled = 0;
		/* flush irq_bh workqueue; calling it before enabled=0
		 * will crash since some drivers (Centrino at least) don't
		 * expect irq hander to be called anymore */
		/* cancel_delayed_work is probably better, but 2.4 kernels
		 * don't have equivalent function
		 */
		flush_scheduled_work();
		free_irq(ndis_irq->irq, ndis_irq);
		kfree(ndis_irq->spinlock);
		ndis_irq->spinlock = NULL;
		ndis_irq->handle = NULL;
		handle->ndis_irq = NULL;
	}
	TRACEEXIT1(return);
}

STDCALL static unsigned char
NdisMSynchronizeWithInterrupt(struct ndis_irq *ndis_irq, void *func, void *ctx)
{
	unsigned char ret;
	unsigned char (*sync_func)(void *ctx) STDCALL;
	unsigned long flags;

	TRACEENTER5("%08x %08x %08x %08x\n", (int) ndis_irq,
		    (int) ndis_irq, (int) func, (int) ctx);

	if (func == NULL || ctx == NULL)
		TRACEEXIT5(return 0);

	sync_func = func;
	spin_lock_irqsave(ndis_irq->spinlock, flags);
	ret = sync_func(ctx);
	spin_unlock_irqrestore(ndis_irq->spinlock, flags);

	DBGTRACE5("sync_func returns %u", ret);
	TRACEEXIT5(return ret);
}

/* called via fnuction pointer */
STDCALL void
NdisMIndicateStatus(struct ndis_handle *handle, unsigned int status, void *buf,
		    unsigned int len)
{
	TRACEENTER1("%08x", status);

	if (status == NDIS_STATUS_MEDIA_DISCONNECT)
	{
		handle->link_status = 0;
		set_bit(WRAPPER_LINK_STATUS, &handle->wrapper_work);
		schedule_work(&handle->wrapper_worker);
	}

	if (status == NDIS_STATUS_MEDIA_CONNECT)
	{
		handle->link_status = 1;
		set_bit(WRAPPER_LINK_STATUS, &handle->wrapper_work);
		schedule_work(&handle->wrapper_worker);
	}

	if (status == NDIS_STATUS_MEDIA_SPECIFIC_INDICATION && buf)
	{
		struct status_indication *status =
			(struct status_indication *)buf;
		DBGTRACE("%s", "media status");
		if (status->status_type == NDIS_STATUS_AUTHENTICATION)
		{
			struct auth_req *auth_req;
			buf = (char *)buf + sizeof(struct status_indication);
			len -= sizeof(struct status_indication);
			while (len > 0)
			{
				auth_req = (struct auth_req *)buf;
				DBGTRACE(MACSTR, MAC2STR(auth_req->bssid));
				if (auth_req->flags & 0x01)
					DBGTRACE("%s", "reqauth");
				if (auth_req->flags & 0x02)
					DBGTRACE("%s", "keyupdate");
				if (auth_req->flags & 0x06)
					DBGTRACE("%s", "pairwise_error");
				if (auth_req->flags & 0x0E)
					DBGTRACE("%s", "group_error");
				len -= auth_req->length;
				buf = (char *)buf + auth_req->length;
			}
		}
	}

	TRACEEXIT1(return);
}

/* called via function pointer */
STDCALL void
NdisMIndicateStatusComplete(struct ndis_handle *handle)
{
	TRACEENTER3("%s", "");
}

/* called via function pointer */
STDCALL void
NdisMIndicateReceivePacket(struct ndis_handle *handle,
			   struct ndis_packet **packets,
			   unsigned int nr_packets)
{
	struct ndis_buffer *buffer;
	struct ndis_packet *packet;
	struct sk_buff *skb;
	int i;

	TRACEENTER3("%s", "");
	for(i = 0; i < nr_packets; i++)
	{
		packet = packets[i];
		if(!packet)
		{
			WARNING("%s", "Skipping empty packet on receive");
			continue;
		}

		buffer = packet->buffer_head;

		skb = dev_alloc_skb(buffer->len);
		if(skb)
		{
			skb->dev = handle->net_dev;
			eth_copy_and_sum(skb, buffer->data, buffer->len, 0);
			skb_put(skb, buffer->len);
			skb->protocol = eth_type_trans(skb, handle->net_dev);
			handle->stats.rx_bytes += buffer->len;
			handle->stats.rx_packets++;
			netif_rx(skb);
		}
		else
			handle->stats.rx_dropped++;

		/* The driver normally sets status field to
		 * NDIS_STATUS_SUCCESS which means a normal packet
		 * delivery. We should then change status to
		 * NDIS_STATUS_PENDING meaning that we now own the
		 * package that we'll call the return_packet handler
		 * later when the packet is processed.
		 *
		 * Since we always make a copy of the packet here it
		 * would be tempting to call the return_packet from
		 * here but we cannot to this because some some
		 * drivers gets confused by this. The centrino driver
		 * for example calls this function with a spinlock
		 * held and when calling return_packet it tries to
		 * take the same lock again leading to an instant
		 * lockup on SMP.
		 *
		 * If status is NDIS_STATUS_RESOURCES it means that
		 * the driver is running out of packets and expects us
		 * to copy the packet and then set status to
		 * NDIS_STATUS_SUCCESS and not call the return_packet
		 * handler later.
		 */

		if(packet->status == NDIS_STATUS_RESOURCES)
		{
			/* Signal the driver that we did not take
			 * ownership of the packet. */
			packet->status = NDIS_STATUS_SUCCESS;
			DBGTRACE3("%s", "Low on resources");
		}
		else
		{
			if(packet->status != NDIS_STATUS_SUCCESS)
				WARNING("invalid packet status %08X",
					packet->status);
			/* Signal the driver that took ownership of
			 * the packet and will call return_packet later
			 */
			packet->status = NDIS_STATUS_PENDING;
			wrap_spin_lock(&handle->recycle_packets_lock);
			list_add(&packet->recycle_list,
				 &handle->recycle_packets);
			wrap_spin_unlock(&handle->recycle_packets_lock);
			schedule_work(&handle->recycle_packets_work);
		}
	}
	TRACEEXIT3(return);
}

STDCALL void
NdisMCoIndicateReceivePacket(struct ndis_handle *handle,
			   struct ndis_packet **packets,
			   unsigned int nr_packets)
{
	TRACEENTER3("handle = %p", handle);
	NdisMCoIndicateReceivePacket(handle, packets, nr_packets);
	TRACEEXIT3(return);
}

/* called via function pointer */
STDCALL void
NdisMSendComplete(struct ndis_handle *handle,
		  struct ndis_packet *packet, unsigned int status)
{
	TRACEENTER3("%08x", status);
	sendpacket_done(handle, packet);
	/* In case a serialized driver has requested a pause by returning
	 * NDIS_STATUS_RESOURCES we need to give the send-code a kick again.
	 */
	handle->send_status = 0;
	schedule_work(&handle->xmit_work);
	TRACEEXIT3(return);
}

STDCALL void
NdisMCoSendComplete(unsigned int status, struct ndis_handle *handle,
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
	handle->send_status = 0;
	schedule_work(&handle->xmit_work);
	TRACEEXIT3(return);
}

/* called via function pointer (by NdisMEthIndicateReiceve macro) */
STDCALL void
EthRxIndicateHandler(void *adapter_ctx, void *rx_ctx, char *header1,
		     char *header, u32 header_size, char *look_ahead,
		     u32 look_ahead_size, u32 packet_size)
{
	struct sk_buff *skb = NULL;
	struct ndis_handle *handle = ctx_to_handle(rx_ctx);
	unsigned int skb_size = 0;

	TRACEENTER3("adapter_ctx = %p, rx_ctx = %p, buf = %p, size = %d, "
		    "buf = %p, size = %d, packet = %d",
		    adapter_ctx, rx_ctx, header, header_size, look_ahead,
		    look_ahead_size, packet_size);

	DBGTRACE3("handle = %p", handle);
	if (!handle)
		TRACEEXIT3(return);

	if (look_ahead_size < packet_size)
	{
		struct ndis_packet *packet;
		struct miniport_char *miniport;
		unsigned int res, bytes_txed;

		NdisAllocatePacket(&res, &packet, NULL);
		if (res != NDIS_STATUS_SUCCESS)
		{
			handle->stats.rx_dropped++;
			TRACEEXIT3(return);
		}

		miniport = &handle->driver->miniport_char;
		res = miniport->tx_data(packet, &bytes_txed, adapter_ctx,
					rx_ctx, look_ahead_size, packet_size);
		if (res == NDIS_STATUS_SUCCESS)
		{
			skb = dev_alloc_skb(header_size+look_ahead_size+
					    bytes_txed);
			if (skb)
			{
				memcpy(skb->data, header, header_size);
				memcpy(skb->data+header_size, look_ahead,
				       look_ahead_size);
				memcpy(skb->data+header_size+look_ahead_size,
				       packet->buffer_head->data,
				       bytes_txed);
				skb_size = header_size+look_ahead_size+
					bytes_txed;
				NdisFreePacket(packet);
			}
		}
		else if (res == NDIS_STATUS_PENDING)
		{
			/* driver will call td_complete */
			packet->look_ahead = kmalloc(look_ahead_size,
						     GFP_ATOMIC);
			if (!packet->look_ahead)
			{
				NdisFreePacket(packet);
				handle->stats.rx_dropped++;
				TRACEEXIT3(return);
			}
			memcpy(&packet->header, header, 
			       sizeof(packet->header));
			memcpy(packet->look_ahead, look_ahead,
			       look_ahead_size);
			packet->look_ahead_size = look_ahead_size;
		}
		else
		{
			NdisFreePacket(packet);
			handle->stats.rx_dropped++;
			TRACEEXIT3(return);
		}
	}
	else
	{
		skb_size = header_size+packet_size;
		skb = dev_alloc_skb(skb_size);
		if (skb)
		{
			memcpy(skb->data, header, header_size);
			memcpy(skb->data+header_size, look_ahead, packet_size);
		}
	}

	if (skb && skb_size > 0)
	{
		skb->dev = handle->net_dev;
		skb_put(skb, skb_size);
		skb->protocol = eth_type_trans(skb, handle->net_dev);
		handle->stats.rx_bytes += skb_size;
		handle->stats.rx_packets++;
		netif_rx(skb);
	}
	else
		handle->stats.rx_dropped++;

	TRACEEXIT3(return);
}

/* called via function pointer */
STDCALL void
NdisMTransferDataComplete(struct ndis_handle *handle,
			  struct ndis_packet *packet,
			  unsigned int status, unsigned int bytes_txed)
{
	struct sk_buff *skb;
	unsigned int skb_size;

	TRACEENTER3("handle = %p, packet = %p, bytes_txed = %d",
		    handle, packet, bytes_txed);

	if (!packet)
	{
		WARNING("%s", "illegal packet");
		TRACEEXIT3(return);
	}

	if ((int)packet->look_ahead_size <= 0)
	{
		WARNING("illegal packet? (look_ahead_size = %d)",
			packet->look_ahead_size);
		TRACEEXIT3(return);
	}

	skb_size = sizeof(packet->header)+packet->look_ahead_size+bytes_txed;

	skb = dev_alloc_skb(skb_size);
	if (!skb)
	{
		kfree(packet->look_ahead);
		NdisFreePacket(packet);
		handle->stats.rx_dropped++;
		TRACEEXIT3(return);
	}

	skb->dev = handle->net_dev;
	memcpy(skb->data, packet->header, sizeof(packet->header));
	memcpy(skb->data+sizeof(packet->header), packet->look_ahead,
	       packet->look_ahead_size);
	memcpy(skb->data+sizeof(packet->header)+packet->look_ahead_size,
	       packet->buffer_head->data, bytes_txed);
	kfree(packet->look_ahead);
	NdisFreePacket(packet);
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
NdisMQueryInformationComplete(struct ndis_handle *handle, unsigned int status)
{
	TRACEENTER3("%08X", status);

	handle->ndis_comm_res = status;
	handle->ndis_comm_done = 1;
	wake_up(&handle->ndis_comm_wq);
	TRACEEXIT3(return);
}

STDCALL void
NdisMCoRequestComplete(unsigned int status, struct ndis_handle *handle,
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
NdisMSetInformationComplete(struct ndis_handle *handle,
					 unsigned int status)
{
	TRACEENTER3("status = %08X", status);

	handle->ndis_comm_res = status;
	handle->ndis_comm_done = 1;
	wake_up(&handle->ndis_comm_wq);
	TRACEEXIT3(return);
}

STDCALL static void
NdisMSleep(unsigned long us_to_sleep)
{
	TRACEENTER4("us: %lu", us_to_sleep);
	if (us_to_sleep > 0)
	{
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout((us_to_sleep * HZ)/1000000);
		DBGTRACE4("%s", "woke up");
	}
	TRACEEXIT4(return);
}

STDCALL static void
NdisGetCurrentSystemTime(u64 *time)
{
	struct timeval now;
	u64 t;

	do_gettimeofday(&now);
	t = (u64) now.tv_sec * TICKSPERSEC;
	t += now.tv_usec * 10 + TICKS_1601_TO_1970;
	*time = t;
}

STDCALL static unsigned int
NdisMRegisterIoPortRange(void **virt, struct ndis_handle *handle,
			 unsigned int start, unsigned int len)
{
	TRACEENTER3("%08x %08x", start, len);
	*virt = (void*) start;
	return NDIS_STATUS_SUCCESS;
}

STDCALL static void
NdisMDeregisterIoPortRange(struct ndis_handle *handle, unsigned int start,
			   unsigned int len, void* virt)
{
	TRACEENTER1("%08x %08x", start, len);
}

STDCALL static long
NdisInterlockedDecrement(long *val)
{
	long x;

	TRACEENTER4("%s", "");
	wrap_spin_lock(&atomic_lock);
	(*val)--;
	x = *val;
	wrap_spin_unlock(&atomic_lock);
	TRACEEXIT4(return x);
}

STDCALL static long
NdisInterlockedIncrement(long *val)
{
	long x;

	TRACEENTER4("%s", "");
	wrap_spin_lock(&atomic_lock);
	(*val)++;
	x = *val;
	wrap_spin_unlock(&atomic_lock);
	TRACEEXIT4(return x);
}

STDCALL static struct list_entry *
NdisInterlockedInsertHeadList(struct list_entry *head,
			      struct list_entry *entry,
			      struct ndis_spin_lock *lock)
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
	TRACEEXIT4(return (flink != head) ? flink : NULL);
}

STDCALL static struct list_entry *
NdisInterlockedInsertTailList(struct list_entry *head,
			      struct list_entry *entry,
			      struct ndis_spin_lock *lock)
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
	TRACEEXIT4(return (flink != head) ? flink : NULL);
}

STDCALL static struct list_entry *
NdisInterlockedRemoveHeadList(struct list_entry *head,
			      struct ndis_spin_lock *lock)
{
	struct list_entry *flink;

	TRACEENTER4("lock: %p", lock);
	NdisAcquireSpinLock(lock);

	flink = head->fwd_link;
	head->fwd_link = flink->fwd_link;
	head->fwd_link->bwd_link = head;

	NdisReleaseSpinLock(lock);
	TRACEEXIT4(return (flink != head) ? flink : NULL);
}

STDCALL static int
NdisMInitializeScatterGatherDma(struct ndis_handle *handle, int is64bit,
				unsigned long maxtransfer)
{
	TRACEENTER2("64bit=%d, maxtransfer=%ld", is64bit, maxtransfer);
	handle->use_scatter_gather = 1;
	return NDIS_STATUS_SUCCESS;
}

STDCALL static unsigned int
NdisMGetDmaAlignment(struct ndis_handle *handle)
{
	TRACEENTER3("%s", "");
	return dma_get_cache_alignment();
}

STDCALL static void
NdisQueryBufferOffset(struct ndis_buffer *buffer, unsigned int *offset,
		      unsigned int *length)
{
	TRACEENTER3("%s", "");
	*offset = 0;
	*length = buffer->len;
}

STDCALL static int
NdisSystemProcessorCount(void)
{
	return NR_CPUS;
}

STDCALL static void
NdisInitializeEvent(struct ndis_event *event)
{
	TRACEENTER3("%08x", (int)event);
	event->event.header.type = NOTIFICATION_EVENT;
	event->event.header.signal_state = 0;
}

STDCALL int
NdisWaitEvent(struct ndis_event *event, unsigned int timeout)
{
	int res;

	TRACEENTER3("%p %d", event, timeout);
	if (event->event.header.signal_state)
		TRACEEXIT3(return 1);
	if (!timeout) {
		wait_event_interruptible(event_wq,
			event->event.header.signal_state == 1);
		return 1;
	}

	res = wait_event_interruptible_timeout(event_wq,
		event->event.header.signal_state == 1, (timeout * HZ)/1000);
	DBGTRACE3("%p Woke up (%ld)", event,
		event->event.header.signal_state);

	if (event->event.header.signal_state == 1)
		TRACEEXIT3(return 1);

	TRACEEXIT3(return 0);
}

STDCALL void
NdisSetEvent(struct ndis_event *event)
{
	TRACEENTER3("%p", event);
	event->event.header.signal_state = 1;
	wake_up_interruptible(&event_wq);
}

STDCALL static void
NdisResetEvent(struct ndis_event *event)
{
	TRACEENTER3("%p", event);
	event->event.header.signal_state = 0;
}

/* called via function pointer */
STDCALL void
NdisMResetComplete(struct ndis_handle *handle, int status, int reset_status)
{
	TRACEENTER2("status: %08X, reset status: %u", status, reset_status);

	handle->ndis_comm_res = status;
	handle->reset_status = status;
	handle->ndis_comm_done = 1;
	wake_up(&handle->ndis_comm_wq);
	TRACEEXIT3(return);
}

static void ndis_worker(void *data)
{
	struct ndis_work_entry *ndis_work_entry;
	struct ndis_sched_work_item *sched_work_item;
	struct ndis_alloc_mem *alloc_mem;
	struct ndis_free_mem *free_mem;
	struct io_work_item *io_work_item;
	struct ndis_handle *handle;
	struct miniport_char *miniport;
	void *virt;
	struct ndis_phy_address phys;

	TRACEENTER3("%s", "");
	while (1)
	{
		wrap_spin_lock(&ndis_work_list_lock);
		if (list_empty(&ndis_work_list))
			ndis_work_entry = NULL;
		else
		{
			ndis_work_entry =
				(struct ndis_work_entry*)ndis_work_list.next;
			list_del(&ndis_work_entry->list);
		}
		wrap_spin_unlock(&ndis_work_list_lock);

		if (!ndis_work_entry)
		{
			DBGTRACE3("%s", "No more work");
			break;
		}

		switch (ndis_work_entry->type)
		{
		case _NDIS_SCHED_WORK:
			sched_work_item =
				ndis_work_entry->entry.sched_work_item;

			DBGTRACE3("Calling work at %08x (rva %08x) with "
				  "parameter %08x",
				  (int)sched_work_item->func,
				  (int)sched_work_item->func - image_offset,
				  (int)sched_work_item->ctx);
			sched_work_item->func(sched_work_item,
					      sched_work_item->ctx);
			break;

		case _IO_WORK_ITEM:
			io_work_item =
				ndis_work_entry->entry.io_work_item;

			DBGTRACE3("Calling work at %08x with "
				  "parameter %08x",
				  (int)io_work_item->func,
				  (int)io_work_item->ctx);
			io_work_item->func(io_work_item->device_object,
					   io_work_item->ctx);
			break;

		case _NDIS_ALLOC_MEM:
			alloc_mem = &ndis_work_entry->entry.alloc_mem;

			DBGTRACE3("Allocating %scached memory of length %ld",
				  alloc_mem->cached ? "" : "un-",
				  alloc_mem->size);
			handle = (struct ndis_handle *)alloc_mem->handle;
			miniport = &handle->driver->miniport_char;
			NdisMAllocateSharedMemory(handle, alloc_mem->size,
						  alloc_mem->cached,
						  &virt, &phys);
			miniport->alloc_complete(handle, virt, &phys,
						 alloc_mem->size,
						 alloc_mem->ctx);
			break;

		case _NDIS_FREE_MEM:
			free_mem = &ndis_work_entry->entry.free_mem;
			DBGTRACE3("Freeing memory of size %d, flags %d at %p",
				  free_mem->length, free_mem->flags,
				  free_mem->addr);
			if (free_mem->addr)
			{
				vfree(free_mem->addr);
			}
			break;
		default:
			ERROR("%s", "unknown ndis work item");
			break;
		}
		kfree(ndis_work_entry);
	}
	TRACEEXIT3(return);
}

STDCALL static struct io_work_item *
IoAllocateWorkItem(void *device_object)
{
	struct io_work_item *io_work_item;

	io_work_item = kmalloc(sizeof(*io_work_item), GFP_ATOMIC);
	if (!io_work_item)
		return NULL;

	io_work_item->device_object = device_object;
	return io_work_item;
}

STDCALL static void
IoFreeWorkItem(struct io_work_item *io_work_item)
{
	kfree(io_work_item);
	return;
}

STDCALL static void
IoQueueWorkItem(struct io_work_item *io_work_item, void *func, int queue_type,
		void *ctx)
{
	struct ndis_work_entry *ndis_work_entry;

	TRACEENTER3("%s", "");
	if (io_work_item == NULL)
	{
		ERROR("%s", "io_work_item is NULL; item not queued");
		return;
	}

	ndis_work_entry = kmalloc(sizeof(*ndis_work_entry), GFP_ATOMIC);
	if (!ndis_work_entry)
	{
		BUG();
	}

	ndis_work_entry->type = _IO_WORK_ITEM;
	io_work_item->func = func;
	io_work_item->ctx = ctx;
	ndis_work_entry->entry.io_work_item = io_work_item;

	wrap_spin_lock(&ndis_work_list_lock);
	list_add_tail(&ndis_work_entry->list, &ndis_work_list);
	wrap_spin_unlock(&ndis_work_list_lock);

	schedule_work(&ndis_work);
	TRACEEXIT3(return);
}

STDCALL static int
NdisScheduleWorkItem(struct ndis_sched_work_item *ndis_sched_work_item)
{
	struct ndis_work_entry *ndis_work_entry;

	TRACEENTER3("%s", "");
	/* this function is called from irq_bh by realtek driver */
	ndis_work_entry = kmalloc(sizeof(*ndis_work_entry), GFP_ATOMIC);
	if (!ndis_work_entry)
	{
		BUG();
	}
	ndis_work_entry->type = _NDIS_SCHED_WORK;
	ndis_work_entry->entry.sched_work_item = ndis_sched_work_item;

	wrap_spin_lock(&ndis_work_list_lock);
	list_add_tail(&ndis_work_entry->list, &ndis_work_list);
	wrap_spin_unlock(&ndis_work_list_lock);

	schedule_work(&ndis_work);
	TRACEEXIT3(return NDIS_STATUS_SUCCESS);
}

STDCALL static void
NdisUnchainBufferAtBack(struct ndis_packet *packet,
			struct ndis_buffer **buffer)
{
	struct ndis_buffer *b = packet->buffer_head;
	struct ndis_buffer *btail = packet->buffer_tail;

	TRACEENTER3("%p", b);
	if(!b) {
		/* No buffer in packet */
		*buffer = 0;
		TRACEEXIT3(return);
	}

	if(b == btail) {
		/* Only buffer in packet */
		packet->buffer_head = 0;
		packet->buffer_tail = 0;
	} else {
		while(b->next != btail) {
			b = b->next;
		}
		packet->buffer_tail = b;
	}
	b->next = 0;
	packet->valid_counts = 0;
	*buffer = btail;
	TRACEEXIT3(return);
}

STDCALL static void
NdisUnchainBufferAtFront(struct ndis_packet *packet,
			 struct ndis_buffer **buffer)
{
	struct ndis_buffer *b = packet->buffer_head;

	TRACEENTER3("%p", b);
	if(!b) {
		/* No buffer in packet */
		*buffer = 0;
		TRACEEXIT3(return);
	}

	if(b == packet->buffer_tail) {
		/* Only buffer in packet */
		packet->buffer_head = 0;
		packet->buffer_tail = 0;
	}
	else
	{
		packet->buffer_head = b->next;
	}

	b->next = 0;
	packet->valid_counts = 0;

	*buffer = b;
	TRACEEXIT3(return);
}

STDCALL static void
NdisGetFirstBufferFromPacketSafe(struct ndis_packet *packet,
				 struct ndis_buffer **buffer, void **virt,
				 unsigned int *len, unsigned int *totlen,
				 unsigned int priority)
{
	struct ndis_buffer *b = packet->buffer_head;

	TRACEENTER3("%p", b);

	*buffer = b;
	*virt = b->data;
	*len = b->len;
	*totlen = packet->len;
}

STDCALL static void
NdisMStartBufferPhysicalMapping(struct ndis_handle *handle,
				struct ndis_buffer *buf,
				unsigned long phy_map_reg,
				unsigned int write_to_dev,
				struct ndis_phy_addr_unit *phy_addr_array,
				unsigned int  *array_size)
{
	TRACEENTER3("phy_map_reg: %ld", phy_map_reg);
	if (!write_to_dev)
	{
		ERROR( "dma from device not supported (%d)", write_to_dev);
		*array_size = 0;
		return;
	}

	if (phy_map_reg > handle->map_count)
	{
		ERROR("map_register too big (%lu > %u)",
		      phy_map_reg, handle->map_count);
		*array_size = 0;
		return;
	}

	if (handle->map_dma_addr[phy_map_reg] != 0)
	{
		ERROR("map register already used (%lu)", phy_map_reg);
		*array_size = 0;
		return;
	}

	// map buffer
	/* FIXME: do USB drivers call this? */
	phy_addr_array[0].phy_addr.low =
		PCI_DMA_MAP_SINGLE(handle->dev.pci, buf->data, buf->len,
				   PCI_DMA_TODEVICE);
	phy_addr_array[0].phy_addr.high = 0;
	phy_addr_array[0].length= buf->len;

	*array_size = 1;

	// save mapping index
	handle->map_dma_addr[phy_map_reg] =
		(dma_addr_t)phy_addr_array[0].phy_addr.low;
}

STDCALL static void
NdisMCompleteBufferPhysicalMapping(struct ndis_handle *handle,
				   struct ndis_buffer *buf,
				   unsigned long phy_map_reg)
{
	TRACEENTER3("%p %lu (%u)", handle, phy_map_reg, handle->map_count);

	if (phy_map_reg > handle->map_count)
	{
		ERROR("map_register too big (%lu > %u)",
		      phy_map_reg, handle->map_count);
		return;
	}

	if (handle->map_dma_addr[phy_map_reg] == 0)
	{
		ERROR("map register not used (%lu)", phy_map_reg);
		return;
	}

	// unmap buffer
	/* FIXME: do USB drivers call this? */
	PCI_DMA_UNMAP_SINGLE(handle->dev.pci,
			     handle->map_dma_addr[phy_map_reg],
			     buf->len, PCI_DMA_TODEVICE);

	// clear mapping index
	handle->map_dma_addr[phy_map_reg] = 0;
}

STDCALL static int
NdisMRegisterDevice(struct ndis_handle *handle, struct ustring *dev_name,
		    struct ustring *sym_name, void **funcs,
		    struct device_object **dev_object,
		    struct ndis_handle **dev_handle)
{
	TRACEENTER1("%p, %p", *dev_handle, handle);
	*dev_handle = handle;
	*dev_object = handle->device_obj;
	return NDIS_STATUS_SUCCESS;
}

STDCALL static int
NdisMDeregisterDevice(struct ndis_handle *handle)
{
	return NDIS_STATUS_SUCCESS;
}

STDCALL static void
NdisMGetDeviceProperty(struct ndis_handle *handle, void **phy_dev,
		       void **func_dev, void **next_dev, void **alloc_res,
		       void**trans_res)
{
	struct device_object *dev;
	int i;

	TRACEENTER2("phy_dev = %p, func_dev = %p, next_dev = %p, "
		"alloc_res = %p, trans_res = %p", phy_dev, func_dev,
		next_dev, alloc_res, trans_res);

	if (!handle->phys_device_obj) {
		dev = kmalloc(
			sizeof(struct device_object), GFP_KERNEL);
		if (!dev) {
			ERROR("%s", "unable to allocate "
				"DEVICE_OBJECT structure!");
			BUG();
		}
	
		for (i = 0; i < (sizeof(*dev)/sizeof(void *)); i++)
			((int *)dev)[i] = 0x00000A00;

		dev->next_dev        = (void *)0x00000901;
		dev->current_irp     = (void *)0x00000801;
		/* flags: DO_BUFFERED_IO + DO_BUS_ENUMERATED_DEVICE */
		dev->flags           = 0x00001004;
		dev->characteristics = 01;
		/* dev_type: FILE_DEVICE_UNKNOWN */
		dev->dev_type        = 0x00000022;
		dev->stack_size      = 1;

		/* assumes that the handle refers to an USB device */
		dev->device.usb = handle->dev.usb;

		handle->phys_device_obj = dev;
		dev->handle = (void *)handle;
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

STDCALL static unsigned long
NdisReadPcmciaAttributeMemory(struct ndis_handle *handle,
			       unsigned int offset, void *buffer,
			       unsigned long length)
{
	UNIMPL();
	return 0;
}

STDCALL static unsigned long
NdisWritePcmciaAttributeMemory(struct ndis_handle *handle,
			       unsigned int offset, void *buffer,
			       unsigned long length)
{
	UNIMPL();
	return 0;
}

STDCALL void MmBuildMdlForNonPagedPool(struct mdl *mdl)
{
	UNIMPL();
	return;
}

 /* Unimplemented...*/
STDCALL static void NdisMSetAttributes(void){UNIMPL();}
STDCALL static void EthFilterDprIndicateReceiveComplete(void){UNIMPL();}
STDCALL static void EthFilterDprIndicateReceive(void){UNIMPL();}
STDCALL static void NdisMPciAssignResources(void){UNIMPL();}
STDCALL static void NdisMRemoveMiniport(void) { UNIMPL(); }
//STDCALL static void RndisMSendComplete(void) { UNIMPL(); }
//STDCALL static void RndisMInitializeWrapper(void) { UNIMPL(); }
STDCALL static void RndisMIndicateReceive(void) { UNIMPL(); }

STDCALL static void NdisMCoActivateVcComplete(void){UNIMPL();}
STDCALL static void NdisMRegisterUnloadHandler(struct ndis_handle *handle,
					       void *unload)
{
	UNIMPL();
	return;
}

STDCALL static void NdisMCoDeactivateVcComplete(void)
{
	UNIMPL();
	return;
}

struct wrap_func ndis_wrap_funcs[] =
{
	WRAP_FUNC_ENTRY(EthFilterDprIndicateReceive),
	WRAP_FUNC_ENTRY(EthFilterDprIndicateReceiveComplete),
	WRAP_FUNC_ENTRY(NDIS_BUFFER_TO_SPAN_PAGES),
	WRAP_FUNC_ENTRY(NdisAcquireSpinLock),
	WRAP_FUNC_ENTRY(NdisAdjustBufferLength),
	WRAP_FUNC_ENTRY(NdisAllocateBuffer),
	WRAP_FUNC_ENTRY(NdisAllocateBufferPool),
	WRAP_FUNC_ENTRY(NdisAllocateMemory),
	WRAP_FUNC_ENTRY(NdisAllocateMemoryWithTag),
	WRAP_FUNC_ENTRY(NdisAllocatePacket),
	WRAP_FUNC_ENTRY(NdisAllocatePacketPool),
	WRAP_FUNC_ENTRY(NdisAllocatePacketPoolEx),
	WRAP_FUNC_ENTRY(NdisAllocateSpinLock),
	WRAP_FUNC_ENTRY(NdisAnsiStringToUnicodeString),
	WRAP_FUNC_ENTRY(NdisBufferLength),
	WRAP_FUNC_ENTRY(NdisBufferVirtualAddress),
	WRAP_FUNC_ENTRY(NdisCancelTimer),
	WRAP_FUNC_ENTRY(NdisCloseConfiguration),
	WRAP_FUNC_ENTRY(NdisCloseFile),
	WRAP_FUNC_ENTRY(NdisDprAcquireSpinLock),
	WRAP_FUNC_ENTRY(NdisDprReleaseSpinLock),
	WRAP_FUNC_ENTRY(NdisFreeBuffer),
	WRAP_FUNC_ENTRY(NdisFreeBufferPool),
	WRAP_FUNC_ENTRY(NdisFreeMemory),
	WRAP_FUNC_ENTRY(NdisFreePacket),
	WRAP_FUNC_ENTRY(NdisFreePacketPool),
	WRAP_FUNC_ENTRY(NdisFreeSpinLock),
	WRAP_FUNC_ENTRY(NdisGetBufferPhysicalArraySize),
	WRAP_FUNC_ENTRY(NdisGetCurrentSystemTime),
	WRAP_FUNC_ENTRY(NdisGetFirstBufferFromPacketSafe),
	WRAP_FUNC_ENTRY(NdisGetSystemUpTime),
//	WRAP_FUNC_ENTRY(NdisMIndicateStatus),
//	WRAP_FUNC_ENTRY(NdisMIndicateStatusComplete),
	WRAP_FUNC_ENTRY(NdisInitAnsiString),
	WRAP_FUNC_ENTRY(NdisInitUnicodeString),
	WRAP_FUNC_ENTRY(NdisInitializeEvent),
	WRAP_FUNC_ENTRY(NdisInitializeString),
	WRAP_FUNC_ENTRY(NdisInitializeTimer),
	WRAP_FUNC_ENTRY(NdisInitializeWrapper),
	WRAP_FUNC_ENTRY(NdisInterlockedDecrement),
	WRAP_FUNC_ENTRY(NdisInterlockedIncrement),
	WRAP_FUNC_ENTRY(NdisInterlockedInsertHeadList),
	WRAP_FUNC_ENTRY(NdisInterlockedInsertTailList),
	WRAP_FUNC_ENTRY(NdisInterlockedRemoveHeadList),
	WRAP_FUNC_ENTRY(NdisMAllocateMapRegisters),
	WRAP_FUNC_ENTRY(NdisMAllocateSharedMemory),
	WRAP_FUNC_ENTRY(NdisMAllocateSharedMemoryAsync),
	WRAP_FUNC_ENTRY(NdisMCancelTimer),
	WRAP_FUNC_ENTRY(NdisMCompleteBufferPhysicalMapping),
	WRAP_FUNC_ENTRY(NdisMDeregisterAdapterShutdownHandler),
	WRAP_FUNC_ENTRY(NdisMDeregisterDevice),
	WRAP_FUNC_ENTRY(NdisMDeregisterInterrupt),
	WRAP_FUNC_ENTRY(NdisMDeregisterIoPortRange),
	WRAP_FUNC_ENTRY(NdisMFreeMapRegisters),
	WRAP_FUNC_ENTRY(NdisMFreeSharedMemory),
	WRAP_FUNC_ENTRY(NdisMGetDeviceProperty),
	WRAP_FUNC_ENTRY(NdisMGetDmaAlignment),
//	WRAP_FUNC_ENTRY(NdisMIndicateReceivePacket),
	WRAP_FUNC_ENTRY(NdisMInitializeScatterGatherDma),
	WRAP_FUNC_ENTRY(NdisMInitializeTimer),
	WRAP_FUNC_ENTRY(NdisMMapIoSpace),
	WRAP_FUNC_ENTRY(NdisMPciAssignResources),
	WRAP_FUNC_ENTRY(NdisMQueryAdapterResources),
//	WRAP_FUNC_ENTRY(NdisMQueryInformationComplete),
	WRAP_FUNC_ENTRY(NdisMRegisterAdapterShutdownHandler),
	WRAP_FUNC_ENTRY(NdisMRegisterDevice),
	WRAP_FUNC_ENTRY(NdisMRegisterInterrupt),
	WRAP_FUNC_ENTRY(NdisMRegisterIoPortRange),
	WRAP_FUNC_ENTRY(NdisMRegisterMiniport),
	WRAP_FUNC_ENTRY(NdisMRemoveMiniport),
//	WRAP_FUNC_ENTRY(NdisMResetComplete),
//	WRAP_FUNC_ENTRY(NdisMSendComplete),
//	WRAP_FUNC_ENTRY(NdisMSendResourcesAvailable),
	WRAP_FUNC_ENTRY(NdisMSetAttributes),
	WRAP_FUNC_ENTRY(NdisMSetAttributesEx),
//	WRAP_FUNC_ENTRY(NdisMSetInformationComplete),
	WRAP_FUNC_ENTRY(NdisMSetPeriodicTimer),
	WRAP_FUNC_ENTRY(NdisMSleep),
	WRAP_FUNC_ENTRY(NdisMStartBufferPhysicalMapping),
	WRAP_FUNC_ENTRY(NdisMSynchronizeWithInterrupt),
	WRAP_FUNC_ENTRY(NdisMUnmapIoSpace),
	WRAP_FUNC_ENTRY(NdisMapFile),
	WRAP_FUNC_ENTRY(NdisOpenConfiguration),
	WRAP_FUNC_ENTRY(NdisOpenConfigurationKeyByName),
	WRAP_FUNC_ENTRY(NdisOpenFile),
	WRAP_FUNC_ENTRY(NdisPacketPoolUsage),
	WRAP_FUNC_ENTRY(NdisQueryBuffer),
	WRAP_FUNC_ENTRY(NdisQueryBufferOffset),
	WRAP_FUNC_ENTRY(NdisQueryBufferSafe),
	WRAP_FUNC_ENTRY(NdisReadConfiguration),
	WRAP_FUNC_ENTRY(NdisReadNetworkAddress),
	WRAP_FUNC_ENTRY(NdisReadPciSlotInformation),
	WRAP_FUNC_ENTRY(NdisReadPcmciaAttributeMemory),
	WRAP_FUNC_ENTRY(NdisReleaseSpinLock),
	WRAP_FUNC_ENTRY(NdisResetEvent),
	WRAP_FUNC_ENTRY(NdisScheduleWorkItem),
	WRAP_FUNC_ENTRY(IoAllocateWorkItem),
	WRAP_FUNC_ENTRY(IoQueueWorkItem),
	WRAP_FUNC_ENTRY(IoFreeWorkItem),
	WRAP_FUNC_ENTRY(NdisSetEvent),
	WRAP_FUNC_ENTRY(NdisSetTimer),
	WRAP_FUNC_ENTRY(NdisSystemProcessorCount),
	WRAP_FUNC_ENTRY(NdisTerminateWrapper),
	WRAP_FUNC_ENTRY(NdisUnchainBufferAtBack),
	WRAP_FUNC_ENTRY(NdisUnchainBufferAtFront),
	WRAP_FUNC_ENTRY(NdisUnicodeStringToAnsiString),
	WRAP_FUNC_ENTRY(NdisUnmapFile),
	WRAP_FUNC_ENTRY(NdisWaitEvent),
	WRAP_FUNC_ENTRY(NdisWriteConfiguration),
	WRAP_FUNC_ENTRY(NdisWriteErrorLogEntry),
	WRAP_FUNC_ENTRY(NdisWritePciSlotInformation),
	WRAP_FUNC_ENTRY(NdisWritePcmciaAttributeMemory),
	WRAP_FUNC_ENTRY(MmBuildMdlForNonPagedPool),

	WRAP_FUNC_ENTRY(RndisMIndicateReceive),
	WRAP_FUNC_ENTRY(NdisMCoActivateVcComplete),
	WRAP_FUNC_ENTRY(NdisOpenConfigurationKeyByIndex),
	WRAP_FUNC_ENTRY(NdisMRegisterUnloadHandler),
	WRAP_FUNC_ENTRY(NdisMCoRequestComplete),
	WRAP_FUNC_ENTRY(NdisMCoSendComplete),
	WRAP_FUNC_ENTRY(NdisMCoIndicateReceivePacket),
	WRAP_FUNC_ENTRY(NdisMCoDeactivateVcComplete),
	{NULL, NULL}
};
