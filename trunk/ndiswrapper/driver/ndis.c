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

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0)
#undef __wait_event_interruptible_timeout
#undef wait_event_interruptible_timeout
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#endif

/*
 * 
 *
 * Called from the driver entry.
 */
STDCALL void NdisInitializeWrapper(struct ndis_handle **ndis_handle,
	                           void *SystemSpecific1,
				   void *SystemSpecific2,
				   void *SystemSpecific3)
{
	DBGTRACE("%s handle=%08x, SS1=%08x, SS2=%08x\n", __FUNCTION__, (int)ndis_handle, (int)SystemSpecific1, (int)SystemSpecific2);
	*ndis_handle = (struct ndis_handle*) SystemSpecific1;
}

STDCALL void NdisTerminateWrapper(struct ndis_handle *ndis_handle,
	                          void *SystemSpecific1)
{
	DBGTRACE("%s\n", __FUNCTION__ );
}

/*
 * Register a miniport with NDIS. 
 *
 * Called from driver entry
 */
STDCALL int NdisMRegisterMiniport(struct ndis_driver *ndis_driver,
	                          struct miniport_char *miniport_char,
	                          unsigned int char_len)
{
	int min_length = ((char*) &miniport_char->co_create_vc) - ((char*) miniport_char);

	DBGTRACE("%s driver: %p:\n", __FUNCTION__, ndis_driver);
	
	if(miniport_char->majorVersion < 4)
	{
		printk(KERN_WARNING "%s: Driver %s i using ndis version %d which is too old.\n", DRV_NAME, ndis_driver->name, miniport_char->majorVersion); 
		return NDIS_STATUS_BAD_VERSION;
	}

	if(char_len < min_length)
	{
		printk(KERN_WARNING "%s: Characteristics length to small %d for driver %s\n", DRV_NAME, char_len, ndis_driver->name); 
		return NDIS_STATUS_BAD_CHARACTERISTICS;
	}

	DBGTRACE("%s Version %d.%d\n", __FUNCTION__, miniport_char->majorVersion, miniport_char->minorVersion);
	DBGTRACE("%s Len: %08x:%08x\n", __FUNCTION__, char_len, sizeof(struct miniport_char));
	memcpy(&ndis_driver->miniport_char, miniport_char, sizeof(struct miniport_char));

	return NDIS_STATUS_SUCCESS;
}


/*
 * Allocate mem.
 *
 */
STDCALL unsigned int NdisAllocateMemory(void **dest,
	                                unsigned int length,
					unsigned int flags,
					unsigned int highest_addr)
{
	DBGTRACE("%s: length = %u, flags = %08X\n", __FUNCTION__,
		 length, flags);
	if (length <= KMALLOC_THRESHOLD)
	{
		if (in_irq() || in_atomic())
			*dest = (void *)kmalloc(length, GFP_ATOMIC);
		else
			*dest = (void *)kmalloc(length, GFP_KERNEL);
	}
	else if (flags & NDIS_MEMORY_CONTIGUOUS)
	{
		printk(KERN_ERR "%s: Allocating %u bytes of physically "
		       "contiguous memory may fail\n",
		       __FUNCTION__, length);
		*dest = (void *)kmalloc(length, GFP_KERNEL);
	}
	else
		*dest = vmalloc(length);

	if (*dest)
		return NDIS_STATUS_SUCCESS;
	DBGTRACE("%s: Allocatemem failed size=%d\n", __FUNCTION__, length);
	return NDIS_STATUS_FAILURE;
}

/*
 * Allocate mem.
 *
 * Debug version?
 */
STDCALL unsigned int NdisAllocateMemoryWithTag(void **dest,
	                                       unsigned int length,
					       unsigned int tag)
{
	return NdisAllocateMemory(dest, length, 0, 0);
}

/*
 * Free mem.
 */
STDCALL void NdisFreeMemory(void *adr, unsigned int length, unsigned int flags)
{
	DBGTRACE("%s: length = %u, flags = %08X\n", __FUNCTION__,
		 length, flags);
	if (length <= KMALLOC_THRESHOLD)
		kfree(adr);
	else if (flags & NDIS_MEMORY_CONTIGUOUS)
		kfree(adr);
	else
		vfree(adr);
	DBGTRACE("%s: exit\n", __FUNCTION__);
}


/*
 * Log an error.
 *
 * This function should not be STDCALL because it's a variable args function. 
 */
NOREGPARM void NdisWriteErrorLogEntry(struct ndis_handle *handle,
	                    unsigned int error,
			    unsigned int length,
			    unsigned int p1)
{
	printk(KERN_ERR "%s: error log: %08X, length: %d (%08x)\n",
	       DRV_NAME, error, length, p1);
}


STDCALL void NdisOpenConfiguration(unsigned int *status,
	                           struct ndis_handle **confhandle,
				   struct ndis_handle *handle)
{
	DBGTRACE("%s: confHandle: %p, handle->dev_name: %s\n",
			__FUNCTION__, confhandle, handle->net_dev->name);
	*confhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	return;
}

STDCALL void NdisOpenConfigurationKeyByName(unsigned int *status,
					    struct ndis_handle *handle,
					    struct ustring *key,
					    struct ndis_handle **subkeyhandle)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	*subkeyhandle = handle;
	*status = NDIS_STATUS_SUCCESS;
	return;
}

STDCALL void NdisCloseConfiguration(void *confhandle)
{
	DBGTRACE("%s: confhandle: %08x\n", __FUNCTION__, (int) confhandle);
}

STDCALL void NdisOpenFile(unsigned int *status,
			  struct ndis_file **filehandle,
			  unsigned int *filelength,
			  struct ustring *filename,
			  __u64 highest_address)
{
	char ansiname[512];
	struct ustring ansi;
	struct list_head *curr, *tmp;
	struct ndis_file *file;
	
	DBGTRACE("%s: entry, status = %p, filelength = %p, *filelength = %d, high = %lu, filehandle = %p, *filehandle = %p\n", __FUNCTION__, status, filelength, *filelength, (unsigned long)highest_address, filehandle, *filehandle);

	ansi.buf = ansiname;
	ansi.buflen = sizeof(ansiname);


	if (RtlUnicodeStringToAnsiString(&ansi, filename, 0))
	{
		*status = NDIS_STATUS_RESOURCES;
		return;
	}
	ansiname[sizeof(ansiname)-1] = 0;
	DBGTRACE("%s: Filename: %s, Highest Address: %08x\n",
			 __FUNCTION__, ansiname, (int) highest_address);
	
	/* Loop through all driver and then all files to find the requested file */
	
	list_for_each_safe(curr, tmp, &ndis_driverlist)
	{
		struct list_head *curr2, *tmp2;

		struct ndis_driver *driver = (struct ndis_driver *) curr;
		list_for_each_safe(curr2, tmp2, &driver->files)
		{
			int n;
			file = (struct ndis_file*) curr2;
			DBGTRACE("Considering %s.\n", file->name); 
			n = min(strlen(file->name), strlen(ansiname));
			if(strnicmp(file->name, ansiname, n) == 0)
			{
				*filehandle = file;
				*filelength = file->size;
				*status = NDIS_STATUS_SUCCESS;
				return;
			}
		}
	}
	*status = NDIS_STATUS_FILE_NOT_FOUND;
}
			   
STDCALL void NdisMapFile(unsigned int *status,
			 void **mappedbuffer,
			 struct ndis_file *filehandle)
{

	DBGTRACE("%s: Handle: %08x\n", __FUNCTION__, (int) filehandle);

	if (!filehandle)
	{
		*status = NDIS_STATUS_ALREADY_MAPPED;
		DBGTRACE("%s: (exit)\n", __FUNCTION__);
		return;
	}

	*status = NDIS_STATUS_SUCCESS;
	*mappedbuffer = filehandle->data;
	DBGTRACE("%s: (exit)\n", __FUNCTION__);
	return;
}

STDCALL void NdisUnmapFile(struct ndis_file *filehandle)
{
	DBGTRACE("%s: Handle: %08x\n", __FUNCTION__, (int) filehandle);
	return;
}

STDCALL void NdisCloseFile(struct ndis_file *filehandle)
{
	DBGTRACE("%s: Handle: %08x\n", __FUNCTION__, (int) filehandle);
	return;
}

STDCALL void NdisGetSystemUpTime(unsigned int *systemuptime)
{
//	DBGTRACE("%s:\n", __FUNCTION__);
	*systemuptime = 10 * jiffies / HZ;
}

static inline int SPAN_PAGES(unsigned int ptr, unsigned int len)
{
	unsigned int p = ptr & (PAGE_SIZE - 1);
	return (p + len + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
}

STDCALL unsigned long NDIS_BUFFER_TO_SPAN_PAGES(struct ndis_buffer *buffer)
{
	unsigned int p;
	unsigned int i;
	DBGTRACE("%s\n", __FUNCTION__ );

	if (buffer == NULL)
		return 0;

	if (buffer->len == 0)
		return 1;
	p = (unsigned int)buffer->data + buffer->offset;
	i = SPAN_PAGES(PAGE_ALIGN(p), buffer->len);
	DBGTRACE("%s: pages = %u\n", __FUNCTION__, i);
	return i;
}

STDCALL void NdisGetBufferPhysicalArraySize(struct ndis_buffer *buffer,
					    unsigned int *arraysize)
{
	DBGTRACE("%s: Buffer: %08x\n", __FUNCTION__, (int) buffer);
	*arraysize = NDIS_BUFFER_TO_SPAN_PAGES(buffer);
	DBGTRACE("%s: exit\n", __FUNCTION__);
}

static int ndis_encode_setting(struct ndis_setting *setting,
			       int ndis_setting_type)
{
	struct ustring ansi;

	if (setting->value.type == ndis_setting_type)
		return NDIS_STATUS_SUCCESS;

	if (setting->value.type == NDIS_SETTING_STRING)
		kfree(setting->value.data.ustring.buf);

	switch(ndis_setting_type)
	{
	case NDIS_SETTING_INT:
		setting->value.data.intval =
			simple_strtol(setting->val_str, NULL, 0);
		break;
	case NDIS_SETTING_HEXINT:
		setting->value.data.intval = 
			simple_strtol(setting->val_str, NULL, 16);
		break;
	case NDIS_SETTING_STRING:
		ansi.buflen = ansi.len = strlen(setting->val_str);
		ansi.buf = setting->val_str;
		if (RtlAnsiStringToUnicodeString(&setting->value.data.ustring,
						 &ansi, 1))
			return NDIS_STATUS_FAILURE;
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
	char val_str[512];

	switch(val->type)
	{
	case NDIS_SETTING_INT:
		snprintf(val_str, sizeof(val_str), "%lu",
			 (unsigned long)val->data.intval);
		break;
	case NDIS_SETTING_HEXINT:
		snprintf(val_str, sizeof(val_str), "%lx",
			 (unsigned long)val->data.intval);
		break;
	case NDIS_SETTING_STRING:
		ansi.buf = val_str;
		ansi.buflen = sizeof(val_str);
		if (RtlUnicodeStringToAnsiString(&ansi, &val->data.ustring, 0)
		    || ansi.len >= sizeof(val_str))
			return NDIS_STATUS_FAILURE;
		break;
	default:
		DBGTRACE("%s: unknown setting type: %d\n",
				__FUNCTION__, val->type);
		return NDIS_STATUS_FAILURE;
	}
	setting->val_str = kmalloc(strlen(val_str)+1, GFP_KERNEL);
	if (setting->val_str == NULL)
		return NDIS_STATUS_RESOURCES;
	val_str[sizeof(val_str)-1] = 0;
	strcpy(setting->val_str, val_str);
	setting->value.type = NDIS_SETTING_NONE;
	return NDIS_STATUS_SUCCESS;
}

STDCALL void NdisReadConfiguration(unsigned int *status,
                                   struct ndis_setting_val **dest,
				   struct ndis_handle *handle,
				   struct ustring *key,
				   unsigned int type)
{
	struct ndis_setting *setting;
	struct ustring ansi;
	char *keyname, string[512];

	ansi.buf = string;
	ansi.buflen = 512;
	if (RtlUnicodeStringToAnsiString(&ansi, key, 0))
	{
		*dest = NULL;
		*status = NDIS_STATUS_FAILURE;
		return;
	}
	string[sizeof(string)-1] = 0;
	keyname = ansi.buf;

	list_for_each_entry(setting, &handle->device->settings, list)
	{
		if(stricmp(keyname, setting->name) == 0)
		{
			DBGTRACE("%s:setting found %s=%s\n",
				 __FUNCTION__, keyname, setting->val_str);

			*status = ndis_encode_setting(setting, type);
			if (*status == NDIS_STATUS_SUCCESS)
				*dest = &setting->value;
			else
			{
				*dest = NULL;
				DBGTRACE("%s: status = %d\n",
					 __FUNCTION__, *status);
			}
			 return;
		}
	}
	
	DBGTRACE("%s: setting %s not found (type:%d)\n",
		 __FUNCTION__, keyname, type);

	*dest = NULL;
	*status = NDIS_STATUS_FAILURE;
	return;
}

STDCALL void NdisWriteConfiguration(unsigned int *status,
				    struct ndis_handle *handle,
				    struct ustring *key,
				    struct ndis_setting_val *val)
{
	struct ustring ansi;
	struct ndis_setting *setting;
	char *keyname, string[512];

	DBGTRACE("%s begins\n", __FUNCTION__);
	ansi.buf = string;
	ansi.buflen = 512;
	if (RtlUnicodeStringToAnsiString(&ansi, key, 0))
	{
		*status = NDIS_STATUS_FAILURE;
		return;
	}
	string[sizeof(string)-1] = 0;
	keyname = ansi.buf;

	list_for_each_entry(setting, &handle->device->settings, list)
	{
		if(strcmp(keyname, setting->name) == 0)
		{
			kfree(setting->val_str);
			if (setting->value.type == NDIS_SETTING_STRING)
				kfree(setting->value.data.ustring.buf);
			*status = ndis_decode_setting(setting, val);
			DBGTRACE("%s: setting changed %s=%s\n",
				 __FUNCTION__, keyname, setting->val_str);
			return;
		}
	}

	if ((setting = kmalloc(sizeof(*setting), GFP_KERNEL)) == NULL)
	{
		*status = NDIS_STATUS_RESOURCES;
		return;
	}
	memset(setting, 0, sizeof(*setting));
	if ((setting->name = kmalloc(ansi.len+1, GFP_KERNEL)) == NULL)
	{
		kfree(setting);
		*status = NDIS_STATUS_RESOURCES;
		return;
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
	return;
}

STDCALL void NdisInitializeString(struct ustring *dest, char *src)
{
	struct ustring ansi;

	DBGTRACE("%s begins\n", __FUNCTION__);
	ansi.len = ansi.buflen = strlen(src);
	ansi.buf = src;
	if (RtlAnsiStringToUnicodeString(dest, &ansi, 1))
		DBGTRACE("%s failed\n", __FUNCTION__);
	return;
}

STDCALL void NdisInitAnsiString(struct ustring *dest, char *src)
{

	DBGTRACE("%s begins\n", __FUNCTION__);
	if (dest == NULL)
		return;
	if (src == NULL) {
		dest->len = dest->buflen = 0;
		dest->buf = NULL;
		return;
	}
	dest->len = dest->buflen = strlen(src);
	dest->buf = src;
	return;
}

STDCALL void NdisInitUnicodeString(struct ustring *dest, __u16 *src)
{
	int i;

	DBGTRACE("%s begins\n", __FUNCTION__);
	if (dest == NULL)
		return;
	if (src == NULL) {
		dest->len = dest->buflen = 0;
		dest->buf = NULL;
		return;
	}
	
	for (i = 0 ; src[i] ; i++)
		;
	dest->len = dest->buflen = i * 2;
	dest->buf = (__u8 *)src;
	return;
}

STDCALL unsigned int NdisAnsiStringToUnicodeString(struct ustring *dst,
						   struct ustring *src)
{
	int dup;

	DBGTRACE("%s begins\n", __FUNCTION__);
	if (dst == NULL || src == NULL)
		return NDIS_STATUS_FAILURE;
	if (dst->buf == NULL)
		dup = 1;
	else
		dup = 0;
	return RtlAnsiStringToUnicodeString(dst, src, 0);
}

STDCALL int NdisUnicodeStringToAnsiString(struct ustring *dst,
					  struct ustring *src)
{
	int dup;
	DBGTRACE("%s begins\n", __FUNCTION__);
	if (dst == NULL || src == NULL)
		return NDIS_STATUS_FAILURE;
	if (dst->buf == NULL)
		dup = 1;
	else
		dup = 0;
	return RtlUnicodeStringToAnsiString(dst, src, dup);
}

/*
 * Called by driver from the init callback.
 *
 * The adapter_ctx should be supplied to most other callbacks so we save
 * it in out handle.
 *
 */ 
STDCALL void NdisMSetAttributesEx(struct ndis_handle *handle,
                                  void* adapter_ctx,
				  unsigned int hangcheck_interval,
				  unsigned int attributes,
				  unsigned int adaptortype)
{
	DBGTRACE("%s, %08x, %08x %d %08x, %d\n", __FUNCTION__, (int)handle, (int)adapter_ctx, hangcheck_interval, attributes, adaptortype);
	if(attributes & 8)
	{
		pci_set_master(handle->pci_dev);
	}

	if(!(attributes & 0x20))
	{
		handle->serialized = 1;
	}

	if(hangcheck_interval)
	{
		handle->hangcheck_interval = hangcheck_interval * HZ;
	}

	handle->adapter_ctx = adapter_ctx;
}

/*
 * Read information from the PCI config area
 *
 */  
STDCALL unsigned int NdisReadPciSlotInformation(struct ndis_handle *handle,
                                                unsigned int slot,
						unsigned int offset,
						char *buf,
						unsigned int len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		pci_read_config_byte(handle->pci_dev, offset+i, &buf[i]);
	}
	return len;
}


/*
 * Write information to the PCI config area
 *
 */  
STDCALL unsigned int NdisWritePciSlotInformation(struct ndis_handle *handle,
                                                 unsigned int slot,
						 unsigned int offset,
						 char *buf,
						 unsigned int len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		pci_write_config_byte(handle->pci_dev, offset+i, buf[i]);
	}
	return len;
}


/*
 * Read information about IRQ and other resources
 *
 */
STDCALL void NdisMQueryAdapterResources(unsigned int *status,
                                        struct ndis_handle *handle,
					struct ndis_resource_list *resource_list,
					unsigned int *size)
{
	int i;
	int len = 0;
	struct pci_dev *pci_dev = handle->pci_dev;
	struct ndis_resource_entry *entry;
	DBGTRACE("%s handle: %08x. buf: %08x, len: %d. IRQ:%d\n", __FUNCTION__, (int)handle, (int)resource_list, *size, pci_dev->irq);

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


#ifdef DEBUG
	{
		DBGTRACE("resource list v%d.%d len %d, size=%d\n", resource_list->version, resource_list->revision, resource_list->length, *size);

		for(i = 0; i < len; i++)
		{
			DBGTRACE("Resource: %d: %08x %08x %08x, %d\n", resource_list->list[i].type, resource_list->list[i].param1, resource_list->list[i].param2, resource_list->list[i].param3, resource_list->list[i].flags); 
		}	
	}
#endif
	return;
}


/*
 * Just like ioremap
 */
STDCALL unsigned int NdisMMapIoSpace(void **virt,
                                     struct ndis_handle *handle,
				     unsigned int physlo,
				     unsigned int physhi,
				     unsigned int len)
{
	DBGTRACE("%s: %08x, %d\n", __FUNCTION__, (int)physlo, len);
	*virt = ioremap(physlo, len);
	if(*virt == NULL) {
		printk(KERN_ERR "IORemap failed\n");
		return NDIS_STATUS_FAILURE;
	}
	
	handle->mem_start = physlo;
	handle->mem_end = physlo + len -1;
	DBGTRACE("ioremap successful %08x\n", (int)*virt);
	return NDIS_STATUS_SUCCESS;
}

/*
 * Just like iounmap
 */
STDCALL void NdisMUnmapIoSpace(struct ndis_handle *handle,
                               void *virtaddr,
			       unsigned int len)
{
	DBGTRACE("%s: %08x, %d\n", __FUNCTION__, (int)virtaddr, len);
	iounmap(virtaddr);
}


STDCALL void NdisAllocateSpinLock(struct ndis_spin_lock *lock)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	lock->linux_lock = kmalloc(sizeof(struct ndis_linux_spin_lock),
				   GFP_ATOMIC);
	if (lock->linux_lock)
	{
		memset(lock->linux_lock, 0, 
		       sizeof(struct ndis_linux_spin_lock));
		spin_lock_init(&lock->linux_lock->lock);
		lock->kirql = NDIS_SPIN_LOCK_MAGIC_CHAR;
	}
	
	else
	{
		printk(KERN_ERR "%s: couldn't allocate spinlock (%s)\n",
			   DRV_NAME, __FUNCTION__);
		lock->kirql = 0;
	}
}

STDCALL void NdisFreeSpinLock(struct ndis_spin_lock *lock)
{
	if(!lock)
	{
		DBGTRACE("%s: NULL\n", __FUNCTION__);
		return;       
	}
	if(lock->linux_lock)
		kfree(lock->linux_lock);
	lock->linux_lock = NULL;
	lock->kirql = 0;
}


STDCALL void NdisAcquireSpinLock(struct ndis_spin_lock *lock)
{
	if(lock->kirql != NDIS_SPIN_LOCK_MAGIC_CHAR ||
	   lock->linux_lock == NULL)
	{
		printk(KERN_INFO "%s: Buggy ndis driver trying to use unintilized spinlock. Trying to recover...", DRV_NAME);
		NdisAllocateSpinLock(lock);
		if (lock->kirql != NDIS_SPIN_LOCK_MAGIC_CHAR ||
			lock->linux_lock == NULL)
		{
			printk("failed.\n");
			BUG();
		}
		else
			printk("ok.\n");
	}
		
	spin_lock_bh(&lock->linux_lock->lock);
}

STDCALL void NdisReleaseSpinLock(struct ndis_spin_lock *lock)
{
	spin_unlock_bh(&lock->linux_lock->lock);
}


STDCALL void NdisDprAcquireSpinLock(struct ndis_spin_lock *lock)
{
	NdisAcquireSpinLock(lock);
}

STDCALL void NdisDprReleaseSpinLock(struct ndis_spin_lock *lock)
{
	NdisReleaseSpinLock(lock);
}



STDCALL unsigned int NdisMAllocateMapRegisters(struct ndis_handle *handle,
                                               unsigned int dmachan,
					       unsigned char dmasize,
					       unsigned int basemap,
					       unsigned int size)
{
	DBGTRACE("%s: %d %d %d %d\n", __FUNCTION__, dmachan, dmasize, basemap, size);

//	if (basemap > 64)
//		return NDIS_STATUS_RESOURCES;

	if (handle->map_count > 0)
	{
		DBGTRACE("%s (%s): map registers already allocated: %u\n",
			 handle->net_dev->name, __FUNCTION__,
			 handle->map_count);
		return NDIS_STATUS_RESOURCES;
	}
	
	handle->map_count = basemap;
	handle->map_dma_addr = kmalloc(basemap * sizeof(dma_addr_t), GFP_KERNEL);
	if (!handle->map_dma_addr)
		return NDIS_STATUS_RESOURCES;
	memset(handle->map_dma_addr, 0, basemap * sizeof(dma_addr_t));
	
	return NDIS_STATUS_SUCCESS;
}

STDCALL void NdisMFreeMapRegisters(struct ndis_handle *handle)
{
	DBGTRACE("%s: %08x\n", __FUNCTION__, (int)handle);
	
	if (handle->map_dma_addr != NULL)
		kfree(handle->map_dma_addr);
}


STDCALL void NdisMAllocateSharedMemory(struct ndis_handle *handle,
                                       unsigned int size,
				       char cached,
				       void **virt,
				       struct ndis_phy_address *phys)
{
	dma_addr_t p;

//	DBGTRACE("%s: entry\n", __FUNCTION__);
//	if (handle->map_dma_addr == NULL)
//		printk(KERN_ERR "%s: DMA map address is not set!\n",
//		       __FUNCTION__);
	void *v = PCI_DMA_ALLOC_COHERENT(handle->pci_dev, size, &p);
	if(!v)
	{
		printk(KERN_ERR "Failed to allocate DMA coherent memory. "
		       "Windows driver requested %d bytes of %scached memory\n",
		       size, cached ? "" : "un-");
	}

	*(char**)virt = v;
	phys->low = (unsigned int)p;
	phys->high = 0;
//	DBGTRACE("%s: allocated shared memory: %p\n", __FUNCTION__, v);
}

STDCALL void NdisMFreeSharedMemory(struct ndis_handle *handle,
                                   unsigned int size,
				   char cached,
				   void *virt,
				   unsigned int physlow,
				   unsigned int physhigh)
{
//	DBGTRACE("%s: entry\n", __FUNCTION__);
	PCI_DMA_FREE_COHERENT(handle->pci_dev, size, virt, physlow);
}


STDCALL void NdisAllocateBufferPool(unsigned int *status,
                                    unsigned int *poolhandle,
				    unsigned int size)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	*poolhandle = 0x0000fff8;
	*status = NDIS_STATUS_SUCCESS;
}



STDCALL void NdisFreeBufferPool(void *poolhandle)
{
	/* Make sure all packets are recycled */
	flush_scheduled_work();

	DBGTRACE("%s: %08x\n", __FUNCTION__, (int)poolhandle);
}


STDCALL void NdisAllocateBuffer(unsigned int *status,
                                void **buffer,
				void *poolhandle,
				void *virt,
				unsigned int len)
{
	struct ndis_buffer *my_buffer = kmalloc(sizeof(struct ndis_buffer), GFP_ATOMIC);
//	DBGTRACE("%s: entry\n", __FUNCTION__);
	if(!my_buffer)
	{
		printk(KERN_ERR "%s failed\n", __FUNCTION__);
		*status = NDIS_STATUS_FAILURE;
		return;
	}

	memset(my_buffer, 0, sizeof(struct ndis_buffer));

	my_buffer->data = virt;
	my_buffer->next = 0;
	my_buffer->len = len;

	*buffer = my_buffer;
	
//	DBGTRACE("%s: allocated buffer: %p\n", __FUNCTION__, buffer);
	*status = NDIS_STATUS_SUCCESS;

}

STDCALL void NdisFreeBuffer(void *buffer)
{
//	DBGTRACE("%s: entry\n", __FUNCTION__);
	if(buffer)
	{
		memset(buffer, 0, sizeof(struct ndis_buffer));
		kfree(buffer);
	}
}
STDCALL void NdisAdjustBufferLength(struct ndis_buffer *buf, unsigned int len)
{
//	DBGTRACE("%s: entry\n", __FUNCTION__);
	buf->len = len;
}
STDCALL void NdisQueryBuffer(struct ndis_buffer *buf, void **adr, unsigned int *len)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	if(adr)
		*adr = buf->data;
	if(len)
		*len = buf->len;
}

STDCALL void NdisQueryBufferSafe(struct ndis_buffer *buf, void **adr, unsigned int *len,
                                 unsigned int priority)
{
	DBGTRACE("%s %08x, %08x, %08x\n", __FUNCTION__, (int)buf, (int)adr, (int)len);
	if(adr)
		*adr = buf->data;
	if(len)
		*len = buf->len;
}                                

STDCALL void *NdisBufferVirtualAddress(struct ndis_buffer *buf)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	return buf->data; 
}

STDCALL unsigned long NdisBufferLength(struct ndis_buffer *buf)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	return buf->len;
}


STDCALL void NdisAllocatePacketPool(unsigned int *status,
                                    unsigned int *poolhandle,
				    unsigned int size,
				    unsigned int rsvlen)
{
	DBGTRACE("%s: size=%d\n", __FUNCTION__, size);
	*poolhandle = 0xa000fff4;
	*status = NDIS_STATUS_SUCCESS;
}

STDCALL void NdisAllocatePacketPoolEx(unsigned int *status,
                                      unsigned int *poolhandle,
				      unsigned int size,
				      unsigned int overflowsize,
				      unsigned int rsvlen)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	NdisAllocatePacketPool(status, poolhandle, size, rsvlen);
}

STDCALL unsigned int NdisPacketPoolUsage(void *poolhandle)
{
	printk("NdisWrapper %s: Untested function\n", __FUNCTION__);
	return 0;
}

STDCALL void NdisFreePacketPool(void *poolhandle)
{
	DBGTRACE("%s: %08x\n", __FUNCTION__, (int)poolhandle);
}

STDCALL void NdisAllocatePacket(unsigned int *status, struct ndis_packet **packet_out, void *poolhandle)
{
	struct ndis_packet *packet = (struct ndis_packet*) kmalloc(sizeof(struct ndis_packet), GFP_ATOMIC);
	DBGTRACE("%s: entry\n", __FUNCTION__);
	if(!packet)
	{
		printk(KERN_ERR "%s failed\n", __FUNCTION__);
		*packet_out = NULL;
		*status = NDIS_STATUS_FAILURE;
		return;
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
	DBGTRACE("%s: exit\n", __FUNCTION__);
}

STDCALL void NdisFreePacket(void *packet)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	if(packet)
	{
		memset(packet, 0, sizeof(struct ndis_packet));
		kfree(packet);
	}
	DBGTRACE("%s: exit\n", __FUNCTION__);
}

STDCALL void NdisMInitializeTimer(struct ndis_miniport_timer *timer_handle,
                                  struct ndis_handle *handle,
				  void *func,
				  void *ctx)
{
	wrapper_init_timer(&timer_handle->ktimer, handle);
	init_dpc(&timer_handle->kdpc, func, ctx);
	wrapper_set_timer_dpc(timer_handle->ktimer.wrapper_timer,
	                      &timer_handle->kdpc);
}

STDCALL void NdisInitializeTimer(struct ndis_timer *timer_handle,
								 void *func, void *ctx)
{
	DBGTRACE("%s(entry): %p, %p, %p\n",
			 __FUNCTION__, timer_handle, func, ctx);
	wrapper_init_timer(&timer_handle->ktimer, NULL);
	init_dpc(&timer_handle->kdpc, func, ctx);
	wrapper_set_timer_dpc(timer_handle->ktimer.wrapper_timer,
	                      &timer_handle->kdpc);
	DBGTRACE("%s(exit): %p, %p, %p\n",
			 __FUNCTION__, timer_handle, func, ctx);
}

/*
 * Start a one shot timer.
 */
STDCALL void NdisSetTimer(struct ndis_timer *timer_handle, unsigned int ms)
{
	unsigned long expires = jiffies + (ms * HZ) / 1000;

//	DBGTRACE("%s(entry): %p, %u\n",
//			 __FUNCTION__, timer_handle, ms);
	wrapper_set_timer(timer_handle->ktimer.wrapper_timer, expires, 0);
	return;
}

/*
 * Start a repeated timer.
 */
STDCALL void NdisMSetPeriodicTimer(struct ndis_miniport_timer *timer_handle,
                                   unsigned int ms)
{
	unsigned long expires = jiffies + (ms * HZ) / 1000;
	unsigned long repeat = ms * HZ / 1000;

	DBGTRACE("%s(entry): %p, %u\n",
			 __FUNCTION__, timer_handle, ms);
	wrapper_set_timer(timer_handle->ktimer.wrapper_timer, expires, repeat);
	return;
}

/*
 * Cancel a pending timer
 */
STDCALL void NdisMCancelTimer(struct ndis_miniport_timer *timer_handle,
							  char *canceled)
{
	DBGTRACE("%s\n", __FUNCTION__);
	wrapper_cancel_timer(timer_handle->ktimer.wrapper_timer, canceled);
	return;
}

STDCALL void NdisCancelTimer(struct ndis_timer *timer_handle, char *canceled)
{
	wrapper_cancel_timer(timer_handle->ktimer.wrapper_timer, canceled);
}

/*
 * The driver asks ndis what mac it should use. If this
 * function returns failiure it will use it's default mac.
 */
STDCALL void NdisReadNetworkAddress(unsigned int *status,
                                    char * adr,
				    unsigned int *len,
				    void *conf_handle)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	*len = 0;
	*status = NDIS_STATUS_FAILURE;
}


STDCALL void NdisMRegisterAdapterShutdownHandler(struct ndis_handle *handle,
                                                 void *ctx,
						 void *func)
{
	DBGTRACE("%s sp:%08x\n", __FUNCTION__ , getSp());
	handle->driver->miniport_char.adapter_shutdown = func;
	handle->shutdown_ctx = ctx;
}

STDCALL void NdisMDeregisterAdapterShutdownHandler(struct ndis_handle *handle)
{
	DBGTRACE("%s sp:%08x\n", __FUNCTION__ , getSp());
	handle->driver->miniport_char.adapter_shutdown = NULL;
	handle->shutdown_ctx = NULL;
}

/*
 *  bottom half of the irq handler
 *
 */
void ndis_irq_bh(void *data)
{
	struct ndis_irq *ndis_irq = (struct ndis_irq *) data;
	struct ndis_handle *handle = ndis_irq->handle;

	if (ndis_irq->enabled)
		handle->driver->miniport_char.handle_interrupt(handle->adapter_ctx);
}

/*
 *  Top half of the irq handler
 *
 */
irqreturn_t ndis_irq_th(int irq, void *data, struct pt_regs *pt_regs)
{
	int recognized = 0;
	int handle_interrupt = 0;

	struct ndis_irq *ndis_irq = (struct ndis_irq *) data;
	struct ndis_handle *handle = ndis_irq->handle; 

	/* We need a lock here in order to implement NdisMSynchronizeWithInterrupt,
	  however the ISR is really fast anyway so it should not hurt performance */
	spin_lock_irq(ndis_irq->spinlock);
	if (handle->ndis_irq->req_isr)
		handle->driver->miniport_char.isr(&recognized, &handle_interrupt, handle->adapter_ctx);
	else //if (handle->driver->miniport_char.disable_interrupts)
	{
		handle->driver->miniport_char.disable_interrupts(handle->adapter_ctx);
		/* it is not shared interrupt, so handler must be called */
		recognized = handle_interrupt = 1;
	}
	spin_unlock_irq(ndis_irq->spinlock);

	if(recognized && handle_interrupt)
		schedule_work(&handle->irq_bh);
	
	if(recognized)
		return IRQ_HANDLED;

	return IRQ_NONE;
}


/*
 * Register an irq
 *
 */
STDCALL unsigned int NdisMRegisterInterrupt(struct ndis_irq *ndis_irq,
                                            struct ndis_handle *handle,
					    unsigned int vector,
					    unsigned int level,
					    unsigned char req_isr,
					    unsigned char shared,
					    unsigned int mode)
{
	DBGTRACE("%s. %08x, vector:%d, level:%d, req_isr:%d, shared:%d, mode:%d sp:%08x\n", __FUNCTION__, (int)ndis_irq, vector, level, req_isr, shared, mode, (int)getSp());

	ndis_irq->spinlock = kmalloc(sizeof(spinlock_t), GFP_KERNEL);
	if (ndis_irq->spinlock == NULL)
		return NDIS_STATUS_RESOURCES;

	ndis_irq->irq = vector;
	ndis_irq->handle = handle;
	ndis_irq->req_isr = req_isr;
	if (shared && !req_isr)
		printk(KERN_ERR "%s: shared but dynamic interrupt!\n",
		       __FUNCTION__);
	ndis_irq->shared = shared;
	spin_lock_init(ndis_irq->spinlock);
	handle->ndis_irq = ndis_irq;

	INIT_WORK(&handle->irq_bh, &ndis_irq_bh, ndis_irq);
	if(request_irq(vector, ndis_irq_th, shared? SA_SHIRQ : 0,
				   "ndiswrapper", ndis_irq))
	{
		return NDIS_STATUS_RESOURCES;
	}
	ndis_irq->enabled = 1;
	return NDIS_STATUS_SUCCESS;
}

/*
 * Deregister an irq
 *
 */
STDCALL void NdisMDeregisterInterrupt(struct ndis_irq *ndis_irq)
{
//	DBGTRACE("%s: %08x %d %08x\n", __FUNCTION__, (int)ndis_irq, ndis_irq->irq, (int)ndis_irq->handle);

	if(ndis_irq)
	{
		ndis_irq->enabled = 0;
		free_irq(ndis_irq->irq, ndis_irq);
		kfree(ndis_irq->spinlock);
		ndis_irq->spinlock = 0;
	}
}


/*
 * Run func synchorinized with the isr.
 *
 */
STDCALL unsigned char NdisMSynchronizeWithInterrupt(struct ndis_irq *ndis_irq,
						    void *func, void *ctx)
{
	unsigned char ret;
	DBGTRACE("%s: %08x %08x %08x %08x\n", __FUNCTION__, (int) ndis_irq, (int) ndis_irq, (int) func, (int) ctx);
	unsigned char (*sync_func)(void *ctx) STDCALL;
	unsigned long flags;

	if (func == NULL || ctx == NULL)
		return 0;

	sync_func = func;
	spin_lock_irqsave(ndis_irq->spinlock, flags);
	ret = sync_func(ctx);
	spin_unlock_irqrestore(ndis_irq->spinlock, flags);

	DBGTRACE("%s: Past func (%u)\n", __FUNCTION__, ret);
	return ret;
}


/*
 * This function is not called in a format way.
 * It's called using a macro that referenced the opaque miniport-handler
 *
 */
STDCALL void NdisIndicateStatus(struct ndis_handle *handle, unsigned int status, void *buf, unsigned int len)
{
	DBGTRACE("%s %08x\n", __FUNCTION__, status);
	if(status == NDIS_STATUS_MEDIA_CONNECT)
		handle->link_status = 1;
	if(status == NDIS_STATUS_MEDIA_DISCONNECT)
		handle->link_status = 0;
}

/*
 *
 *
 * Called via function pointer.
 */
STDCALL void NdisIndicateStatusComplete(struct ndis_handle *handle)
{
	DBGTRACE("%s\n", __FUNCTION__);
}

/*
 *
 *
 * Called via function pointer.
 */
STDCALL void NdisMIndicateReceivePacket(struct ndis_handle *handle, struct ndis_packet **packets, unsigned int nr_packets)
{
	struct ndis_buffer *buffer;
	struct ndis_packet *packet;
	struct sk_buff *skb;
	int i;

	DBGTRACE("%s entry\n", __FUNCTION__);
	for(i = 0; i < nr_packets; i++)
	{
		packet = packets[i];
		if(!packet)
		{
			printk(KERN_WARNING "%s Skipping empty packet on receive\n", DRV_NAME); 
			continue;
		}
		
		buffer = packet->buffer_head;

		skb = dev_alloc_skb(buffer->len);
		if(skb)
		{
			skb->dev = handle->net_dev;
		
			eth_copy_and_sum(skb, buffer->data, buffer->len, 0);
			skb_put(skb, buffer->len);
			skb->protocol = eth_type_trans (skb, handle->net_dev);
			handle->stats.rx_bytes += buffer->len;
			handle->stats.rx_packets++;
			netif_rx(skb);
		}
		else
			handle->stats.rx_dropped++;

		/* The driver normally sets status field to NDIS_STATUS_SUCCESS which means
		 * a normal packet delivery. We should then change status to NDIS_STATUS_PENDING
		 * meaning that we now own the package that we'll call the return_packet
		 * handler later when the packet is processed.
		 *
		 * Since we always make a copy of the packet here it would be tempting to
		 * call the return_packet from here but we cannot to this because
		 * some some drivers gets confused by this. The centrino driver for example
		 * calls this function with a spinlock held and when calling return_packet
		 * it tries to take the same lock again leading to an instant lockup on SMP.
		 *
		 * If status is NDIS_STATUS_RESOURCES it means that the driver is running
		 * out of packets and expects us to copy the packet and then set status
		 * to NDIS_STATUS_SUCCESS and not call the return_packet handler later.
		 */

		if(packet->status == NDIS_STATUS_RESOURCES)
		{
			/* Signal the driver that we did not take ownership of the packet. */
			packet->status = NDIS_STATUS_SUCCESS;
			DBGTRACE("%s Low on resources!\n", __FUNCTION__);
		}
		else
		{
			if(packet->status != NDIS_STATUS_SUCCESS)
				printk(KERN_INFO "%s: %s packet->status is invalid\n", DRV_NAME, __FUNCTION__);

			 
			/* Signal the driver that took ownership of the packet and will
			 * call return_packet later
			 */
			packet->status = NDIS_STATUS_PENDING;
			spin_lock_bh(&handle->recycle_packets_lock);
			list_add(&packet->recycle_list, &handle->recycle_packets);
			spin_unlock_bh(&handle->recycle_packets_lock);
			schedule_work(&handle->packet_recycler);
		}
	}
}

/*
 *
 *
 * Called via function pointer.
 */
STDCALL void NdisMSendComplete(struct ndis_handle *handle, struct ndis_packet *packet, unsigned int status)
{

	DBGTRACE("%s %08x\n", __FUNCTION__, status);
	sendpacket_done(handle, packet);
	/* In case a serialized driver has requested a pause by returning NDIS_STATUS_RESOURCES we
	 * need to give the send-code a kick again.
	 */
	handle->send_status = 0;
	schedule_work(&handle->xmit_work);
}

STDCALL void NdisMSendResourcesAvailable(struct ndis_handle *handle)
{
	DBGTRACE("%s: Enter\n", __FUNCTION__);
	/* sending packets immediately seem to result in NDIS_STATUS_FAILURE,
	   so wait for a while before sending the packet again */
//	set_current_state(TASK_INTERRUPTIBLE);
//	schedule_timeout(HZ/2);
	mdelay(50);
	handle->send_status = 0;
	schedule_work(&handle->xmit_work);
}

/*
 *
 * Called via function pointer if query returns NDIS_STATUS_PENDING
 */
STDCALL void NdisMQueryInformationComplete(struct ndis_handle *handle, unsigned int status)
{
	DBGTRACE("%s: %08X\n", __FUNCTION__, status);

	handle->ndis_comm_res = status;
	handle->ndis_comm_done = 1;
	wake_up_interruptible(&handle->ndis_comm_wqhead);
}

/*
 *
 * Called via function pointer if setinfo returns NDIS_STATUS_PENDING
 */
STDCALL void NdisMSetInformationComplete(struct ndis_handle *handle, unsigned int status)
{
	DBGTRACE("%s: status = %08X\n", __FUNCTION__, status);

	handle->ndis_comm_res = status;
	handle->ndis_comm_done = 1;
	wake_up_interruptible(&handle->ndis_comm_wqhead);
}


/*
 * Sleeps for the given number of microseconds
 */
STDCALL void NdisMSleep(unsigned long us_to_sleep)
{
	DBGTRACE("%s called to sleep for %lu us\n", __FUNCTION__, us_to_sleep);
	if (us_to_sleep > 0)
	{
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout((us_to_sleep * HZ)/1000000);
		DBGTRACE("%s woke up\n", __FUNCTION__);
	} 
}

STDCALL void NdisGetCurrentSystemTime(u64 *time)
{
	struct timeval now;
	u64 t;
 
	do_gettimeofday(&now);
	t = (u64) now.tv_sec * TICKSPERSEC;
	t += now.tv_usec * 10 + TICKS_1601_TO_1970;
/*	DBGTRACE("%s: %llu\n", __FUNCTION__, t);*/
	*time = t;
}


STDCALL unsigned int NdisMRegisterIoPortRange(void **virt, struct ndis_handle *handle, unsigned int start, unsigned int len)
{
	DBGTRACE("%s %08x %08x\n", __FUNCTION__, start, len);
	*virt = (void*) start;
	return NDIS_STATUS_SUCCESS;
}

STDCALL void NdisMDeregisterIoPortRange(struct ndis_handle *handle, unsigned int start, unsigned int len, void* virt)
{
	DBGTRACE("%s %08x %08x\n", __FUNCTION__, start, len);
}

spinlock_t atomic_lock = SPIN_LOCK_UNLOCKED;

STDCALL long NdisInterlockedDecrement(long *val)
{
	long x;
//	DBGTRACE("%s: entry\n", __FUNCTION__);
	spin_lock(&atomic_lock);
	(*val)--;
	x = *val;
	spin_unlock(&atomic_lock);
	return x;
}

STDCALL long NdisInterlockedIncrement(long *val)
{
	long x;
//	DBGTRACE("%s: entry\n", __FUNCTION__);
	spin_lock(&atomic_lock);
	(*val)++;
	x = *val;
	spin_unlock(&atomic_lock);
	return x;
}

STDCALL struct list_entry *
NdisInterlockedInsertHeadList(struct list_entry *head,
			      struct list_entry *entry,
			      struct ndis_spin_lock *lock)
{
	struct list_entry *flink;

	NdisAcquireSpinLock(lock);

	flink = head->fwd_link;
	entry->fwd_link = flink;
	entry->bwd_link = head;
	flink->bwd_link = entry;
	head->fwd_link = entry;

	NdisReleaseSpinLock(lock);
	return (flink != head) ? flink : NULL;
}

STDCALL struct list_entry *
NdisInterlockedInsertTailList(struct list_entry *head,
			      struct list_entry *entry,
			      struct ndis_spin_lock *lock)
{
	struct list_entry *flink;

	NdisAcquireSpinLock(lock);

	flink = head->bwd_link;
	entry->fwd_link = head;
	entry->bwd_link = flink;
	flink->fwd_link = entry;
	head->bwd_link = entry;

	NdisReleaseSpinLock(lock);
	return (flink != head) ? flink : NULL;
}

STDCALL struct list_entry *
NdisInterlockedRemoveHeadList(struct list_entry *head,
			      struct ndis_spin_lock *lock)
{
	struct list_entry *flink;

	NdisAcquireSpinLock(lock);

	flink = head->fwd_link;
	head->fwd_link = flink->fwd_link;
	head->fwd_link->bwd_link = head;

	NdisReleaseSpinLock(lock);
	return (flink != head) ? flink : NULL;
}

/*
 * Arguments:
 * ndis_handle MiniportAdapterHandle: Handle input to MiniportInitialize
 * int Dma64BitAddress: Boolean if NIC can handle 64 bit addresses
 * unsigned long MaximumPhysicalMapping: Number of bytes the NIC can transfer on a single DMA operation
 */
STDCALL int NdisMInitializeScatterGatherDma(struct ndis_handle *handle,
                                            int is64bit,
                                            unsigned long maxtransfer)
{
	DBGTRACE("NdisMInitializeScatterGatherDma: 64bit=%d, maxtransfer=%ld\n", is64bit, maxtransfer);
	handle->use_scatter_gather = 1;
	return NDIS_STATUS_SUCCESS;
}

STDCALL unsigned int NdisMGetDmaAlignment(struct ndis_handle *handle)
{
	DBGTRACE("%s\n", __FUNCTION__);
	return PAGE_SIZE;
}


STDCALL void NdisQueryBufferOffset(struct ndis_buffer *buffer, unsigned int *offset, unsigned int *length)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	*offset = 0;
	*length = buffer->len;
}

STDCALL int NdisSystemProcessorCount(void)
{
	return NR_CPUS;
}


DECLARE_WAIT_QUEUE_HEAD(event_wq);

STDCALL void NdisInitializeEvent(struct ndis_event *event)
{
	DBGTRACE("%s %08x\n", __FUNCTION__, (int)event);
	event->state = 0;
}
                                                                                                                                                                                                                                    
STDCALL int NdisWaitEvent(struct ndis_event *event, int timeout)
{
	int res;

	DBGTRACE("%s %08x %08x\n", __FUNCTION__, (int)event, timeout);
	if(!timeout)
	{
		wait_event_interruptible(event_wq, event->state == 1);
		return 1;
	}
	do
	{
		res = wait_event_interruptible_timeout(event_wq, event->state == 1, (timeout * HZ)/1000);
	} while(res);
		
	DBGTRACE("%s %08x Woke up (%d)\n", __FUNCTION__, (int)event, event->state);
	return event->state;
}

STDCALL void NdisSetEvent(struct ndis_event *event)
{
	event->state = 1;
	wake_up_interruptible(&event_wq);
}

STDCALL void NdisResetEvent(struct ndis_event *event)
{
	//DBGTRACE("%s %08x\n", __FUNCTION__, (int)event);
	event->state = 0;
}

STDCALL void NdisMResetComplete(struct ndis_handle *handle, int status, int reset_status) 
{
	DBGTRACE("%s: %08X\n", __FUNCTION__, status);

	handle->ndis_comm_res = status;
	handle->ndis_comm_done = 1;
	handle->reset_status = reset_status;
	wake_up_interruptible(&handle->ndis_comm_wqhead);
}
		  
LIST_HEAD(worklist);
spinlock_t worklist_lock = SPIN_LOCK_UNLOCKED;

static void worker(void *context)
{
	unsigned long flags;
	struct ndis_workentry *workentry;
	struct ndis_work *ndis_work;
	DBGTRACE("%s\n", __FUNCTION__);
	while(1)
	{
		spin_lock_irqsave(&worklist_lock, flags);
		if(!list_empty(&worklist))
		{
			workentry = (struct ndis_workentry*) worklist.next;
			list_del(&workentry->list);
		}
		else
			workentry = 0;
		spin_unlock_irqrestore(&worklist_lock, flags);
		if(!workentry)
		{
			DBGTRACE("%s No more work\n", __FUNCTION__);
			break;
		}
		

		ndis_work = workentry->work;
		kfree(workentry);

		DBGTRACE("%s Calling work at %08x (rva %08x)with parameter %08x\n", __FUNCTION__, (int)ndis_work->func, (int)ndis_work->func - image_offset, (int)ndis_work->ctx);
		ndis_work->func(ndis_work, ndis_work->ctx);
	}
	
	
}

struct work_struct work;

void init_ndis_work(void)
{
	INIT_WORK(&work, &worker, NULL); 
}

STDCALL void NdisScheduleWorkItem(struct ndis_work *ndis_work)
{
	unsigned long flags;
	struct ndis_workentry *workentry;
	DBGTRACE("%s\n", __FUNCTION__);
	workentry = kmalloc(sizeof(*workentry), GFP_ATOMIC);
	if(!workentry)
	{
		BUG();
	}
	workentry->work = ndis_work;
	
	spin_lock_irqsave(&worklist_lock, flags);
	list_add_tail(&workentry->list, &worklist);
	spin_unlock_irqrestore(&worklist_lock, flags);
	
	schedule_work(&work);
}

STDCALL void NdisUnchainBufferAtBack(struct ndis_packet *packet, struct ndis_buffer **buffer)
{
	struct ndis_buffer *b = packet->buffer_head;
	struct ndis_buffer *btail = packet->buffer_tail;

	DBGTRACE("%s: %p\n", __FUNCTION__, b);
	if(!b) {
		/* No buffer in packet */
		*buffer = 0;
		return;
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
}

STDCALL void NdisUnchainBufferAtFront(struct ndis_packet *packet, struct ndis_buffer **buffer)
{
	struct ndis_buffer *b = packet->buffer_head;

	DBGTRACE("%s: %p\n", __FUNCTION__, b);
	if(!b) {
		/* No buffer in packet */
		*buffer = 0;
		return;
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
}


STDCALL void NdisGetFirstBufferFromPacketSafe(struct ndis_packet *packet,
                                              struct ndis_buffer **buffer,
                                              void **virt,
                                              unsigned int *len,
                                              unsigned int *totlen,
                                              unsigned int priority)
{
	struct ndis_buffer *b = packet->buffer_head;

	DBGTRACE("%s: %p\n", __FUNCTION__, b);

	*buffer = b;
	*virt = b->data;
	*len = b->len;
	*totlen = packet->len;
}
 
STDCALL void
NdisMStartBufferPhysicalMapping(struct ndis_handle *handle,
				struct ndis_buffer *buf,
				unsigned long phy_map_reg,
				unsigned int write_to_dev,
				struct ndis_phy_addr_unit *phy_addr_array,
				unsigned int  *array_size)
{
	DBGTRACE("%s: phy_map_reg: %ld\n", __FUNCTION__, phy_map_reg);
	if (!write_to_dev)
	{
		printk(KERN_ERR "%s (%s): dma from device not supported (%d)\n",
		       handle->net_dev->name, __FUNCTION__, write_to_dev);
		*array_size = 0;
		return;
	}

	if (phy_map_reg > handle->map_count)
	{
		printk(KERN_ERR "%s (%s): map_register too big (%lu > %u)\n",
		       handle->net_dev->name, __FUNCTION__,
		       phy_map_reg, handle->map_count);
		*array_size = 0;
		return;
	}
	
	if (handle->map_dma_addr[phy_map_reg] != 0)
	{
		printk(KERN_ERR "%s (%s): map register already used (%lu)\n",
		       handle->net_dev->name, __FUNCTION__, phy_map_reg);
		*array_size = 0;
		return;
	}

	// map buffer
	phy_addr_array[0].phy_addr.low =
		PCI_DMA_MAP_SINGLE(handle->pci_dev, buf->data, buf->len,
				   PCI_DMA_TODEVICE);
	phy_addr_array[0].phy_addr.high = 0;
	phy_addr_array[0].length= buf->len;
	
	*array_size = 1;
	
	// save mapping index
	handle->map_dma_addr[phy_map_reg] =
		(dma_addr_t)phy_addr_array[0].phy_addr.low;
}

STDCALL void
NdisMCompleteBufferPhysicalMapping(struct ndis_handle *handle,
				   struct ndis_buffer *buf,
				   unsigned long phy_map_reg)
{
	DBGTRACE("%s (%s): %p %lu (%u)\n",
		 handle->net_dev->name, __FUNCTION__,
		 handle, phy_map_reg, handle->map_count);

	if (phy_map_reg > handle->map_count)
	{
		printk(KERN_ERR "%s (%s): map_register too big (%lu > %u)\n",
		       handle->net_dev->name, __FUNCTION__,
		       phy_map_reg, handle->map_count);
		return;
	}

	if (handle->map_dma_addr[phy_map_reg] == 0)
	{
		printk(KERN_ERR "%s (%s): map register not used (%lu)\n",
		       handle->net_dev->name, __FUNCTION__, phy_map_reg);
		return;
	}
	
	// unmap buffer
	PCI_DMA_UNMAP_SINGLE(handle->pci_dev,
			     handle->map_dma_addr[phy_map_reg],
			     buf->len, PCI_DMA_TODEVICE);

	// clear mapping index
	handle->map_dma_addr[phy_map_reg] = 0;
}

STDCALL int NdisMRegisterDevice(struct ndis_handle *handle,
				struct ustring *dev_name,
				struct ustring *sym_name,
				void **funcs, void *dev_object,
				struct ndis_handle **dev_handle)
{
	DBGTRACE("%s: %p, %p\n", __FUNCTION__, *dev_handle, handle);
	*dev_handle = handle;
	return NDIS_STATUS_SUCCESS;
}

STDCALL int NdisMDeregisterDevice(struct ndis_handle *handle)
{
	return NDIS_STATUS_SUCCESS;
}

STDCALL void NdisMGetDeviceProperty(struct ndis_handle handle,
				    void **phy_dev, void **func_dev,
				    void **next_dev,
				    void **alloc_res, void**trans_res)
{
	DBGTRACE("%s: entry\n", __FUNCTION__);
	return;
}

STDCALL unsigned long
NdisReadPcmciaAttributeMemory(struct ndis_handle *handle,
			       unsigned int offset, void *buffer,
			       unsigned long length)
{
	UNIMPL();
	return 0;
}

STDCALL unsigned long
NdisWritePcmciaAttributeMemory(struct ndis_handle *handle,
			       unsigned int offset, void *buffer,
			       unsigned long length)
{
	UNIMPL();
	return 0;
}

 /* Unimplemented...*/
STDCALL void NdisMSetAttributes(void){UNIMPL();}
STDCALL void EthFilterDprIndicateReceiveComplete(void){UNIMPL();}
STDCALL void EthFilterDprIndicateReceive(void){UNIMPL();}
STDCALL void NdisMPciAssignResources(void){UNIMPL();}
STDCALL void NdisMRemoveMiniport(void) { UNIMPL(); }

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
	WRAP_FUNC_ENTRY(NdisIndicateStatus),
	WRAP_FUNC_ENTRY(NdisIndicateStatusComplete),
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
	WRAP_FUNC_ENTRY(NdisMIndicateReceivePacket),
	WRAP_FUNC_ENTRY(NdisMInitializeScatterGatherDma),
	WRAP_FUNC_ENTRY(NdisMInitializeTimer),
	WRAP_FUNC_ENTRY(NdisMMapIoSpace),
	WRAP_FUNC_ENTRY(NdisMPciAssignResources),
	WRAP_FUNC_ENTRY(NdisMQueryAdapterResources),
	WRAP_FUNC_ENTRY(NdisMQueryInformationComplete),
	WRAP_FUNC_ENTRY(NdisMRegisterAdapterShutdownHandler),
	WRAP_FUNC_ENTRY(NdisMRegisterDevice),
	WRAP_FUNC_ENTRY(NdisMRegisterInterrupt),
	WRAP_FUNC_ENTRY(NdisMRegisterIoPortRange),
	WRAP_FUNC_ENTRY(NdisMRegisterMiniport),
	WRAP_FUNC_ENTRY(NdisMRemoveMiniport),
	WRAP_FUNC_ENTRY(NdisMResetComplete),
	WRAP_FUNC_ENTRY(NdisMSendComplete),
	WRAP_FUNC_ENTRY(NdisMSendResourcesAvailable),
	WRAP_FUNC_ENTRY(NdisMSetAttributes),
	WRAP_FUNC_ENTRY(NdisMSetAttributesEx),
	WRAP_FUNC_ENTRY(NdisMSetInformationComplete),
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

	{NULL, NULL}
};
