/*
 *  Copyright (C) 2003 Pontus Fuchs
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

#include "ndis.h"

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

extern int image_offset;


int getSp(void)
{
	volatile int i;
	asm("movl %esp,(%esp,1)");
	return i;
}

void inline my_dumpstack(void)
{
	int *sp = (int*) getSp();
	int i;
	for(i = 0; i < 20; i++)
	{
		printk("%08x\n", sp[i]);
	}
}



int unicodeToStr(char *dst, struct ustring *src, int dstlen)
{
	char *buf = src->buf;
	int i = 0;
	while((i/2 < src->len) && (buf[0] || buf[1])) {
		if(i >= dstlen)
		{
			printk(KERN_ERR "%s failed. Buffer to small\n", __FUNCTION__);
			return -1;	
		}
		dst[i++] = buf[0];
		buf +=2;
	}
	dst[i] = 0;
	return 0;
}


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
	DBGTRACE("%s driver: %08x\n", __FUNCTION__, (int)ndis_driver);

	if(miniport_char->majorVersion < 4)
	{
		return NDIS_STATUS_BAD_VERSION;
	}

	if(char_len < sizeof(struct miniport_char))
	{
		return NDIS_STATUS_BAD_CHAR;
	}

	DBGTRACE("%s Version %d.%d\n", __FUNCTION__, miniport_char->majorVersion, miniport_char->minorVersion);
	DBGTRACE("%s Len: %08x:%08x\n", __FUNCTION__, char_len, sizeof(struct miniport_char));
	memcpy(&ndis_driver->miniport_char, miniport_char, sizeof(struct miniport_char));

	return NDIS_STATUS_SUCCESS;
}


#define VMALLOC_THRESHOLD 65536
/*
 * Allocate mem.
 *
 */
STDCALL unsigned int NdisAllocateMemory(void **dest,
	                                unsigned int length,
					unsigned int flags,
					unsigned int highest_addr)
{
	if(length < VMALLOC_THRESHOLD)
		*dest = (void*) kmalloc(length, GFP_ATOMIC);
	else
		*dest = vmalloc(length);

	if(*dest)
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
	if(length < VMALLOC_THRESHOLD)
		kfree(adr);
	else
		vfree(adr);
}


/*
 * Log an error.
 *
 * This function should not be STDCALL because it's a variable args function. 
 */
void NdisWriteErrorLogEntry(struct ndis_handle *handle,
	                    unsigned int error,
			    unsigned int length,
			    unsigned int p1)
{
	printk(KERN_ERR "%s: error log: %08X, length: %d (%08x)\n",
	       DRV_NAME, error, length, p1);
}


STDCALL void NdisOpenConfiguration(unsigned int *status,
	                           void **confhandle,
				   struct ndis_handle *handle)
{
	DBGTRACE("%s: Handle: %08x\n", __FUNCTION__, (int) handle);
	*confhandle = (void*) handle;
	*status = NDIS_STATUS_SUCCESS;
}

STDCALL void NdisCloseConfiguration(void *confhandle)
{
	DBGTRACE("%s: confhandle: %08x\n", __FUNCTION__, (int) confhandle);
}

STDCALL void NdisOpenFile(unsigned int *status,
			  void **filehandle,
			  unsigned int *filelength,
			  char *filename,
			  unsigned long highest_address)
{
	DBGTRACE("%s: Filename: %s @ %p Highest Address: %08x\n", __FUNCTION__, filename, filename, (int) highest_address);
	*status = NDIS_STATUS_FILE_NOT_FOUND;
}
			   
STDCALL void NdisCloseFile(void *filehandle)
{
	DBGTRACE("%s: Handle: %08x\n", __FUNCTION__, (int) filehandle);
}

STDCALL void NdisMapFile(unsigned int *status,
			 void **mappedbuffer,
			 void *filehandle)
{
	DBGTRACE("%s: Handle: %08x\n", __FUNCTION__, (int) filehandle);
	*status = NDIS_STATUS_ALREADY_MAPPED;
}

STDCALL void NdisUnmapFile(void *filehandle)
{
	DBGTRACE("%s: Handle: %08x\n", __FUNCTION__, (int) filehandle);
}

STDCALL void NdisGetSystemUpTime(unsigned int *systemuptime)
{
	DBGTRACE("%s:\n", __FUNCTION__);
	*systemuptime = 10 * jiffies / HZ;
}

STDCALL void NdisGetBufferPhysicalArraySize(void **buffer,
					    unsigned int *arraysize)
{
	int i = 0;
	unsigned long *mdl = *buffer;
	DBGTRACE("%s: Buffer: %08x\n", __FUNCTION__, (int) buffer);
	while (mdl) {
		i++;
		mdl = (void*) *mdl;
	}
	*arraysize = i;
}

struct internal_parameters
{
	char *name;
	struct ndis_setting_val val;
};

struct internal_parameters internal_parameters[] = { 
	{
		.name = "NdisVersion",
		.val = {.type = 0, .data = {.intval = 0x00050000}}
	},

	{
		.name = "Environment",
		.val = {.type = 0, .data = {.intval = 1}}
	},

	{
		.name = "BusType",
		.val = {.type = 0, .data = {.intval = 5}}
	},

	{
		.name = "media_type",
		.val = {.type = 2, .data = {.ustring = {20, 22, "A\0u\0t\0o\0s\0e\0l\0e\0c\0t\0\0"}}}
	},
	{
		.name = 0,
		.val = {.type = 0, .data = {.intval = 0}}
	}
};


STDCALL void NdisReadConfiguration(unsigned int *status,
                                   struct ndis_setting_val **dest,
				   struct ndis_handle *handle, struct ustring *key,
				   unsigned int type)
{
	struct ndis_setting *setting;

	char keyname[1024];
	int i;
	unicodeToStr(keyname, key, sizeof(keyname));

	/* Search built in keys */
	for(i = 0; internal_parameters[i].name; i++)
	{
		if(strcmp(keyname, internal_parameters[i].name) == 0)
		{
			DBGTRACE("%s: Builtin found value for %s\n", __FUNCTION__, keyname);
			
			*dest = &internal_parameters[i].val;
			*status = NDIS_STATUS_SUCCESS;
			return;
		}
	}

	/* Search parameters from inf-file */
	list_for_each_entry(setting, &handle->driver->settings, list)
	{
		if(strcmp(keyname, setting->name) == 0)
		{
			DBGTRACE("%s: From inf found value for %s: %d\n", __FUNCTION__, keyname, setting->val.data.intval);

			*dest =& setting->val;
			*status = NDIS_STATUS_SUCCESS;
			return;
		}
	}

	
	DBGTRACE(KERN_INFO "%s: Key not found type:%d key:%s\n", __FUNCTION__, type, keyname);

	*dest = (struct ndis_setting_val*)0;
	*status = NDIS_STATUS_FAILURE;
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
		handle->serialized_driver = 1;
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
 * - This needs to be more general, and I'm not sure it's correct..
 * - IOPort resources are not handled.
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


STDCALL void NdisAllocateSpinLock(spinlock_t **lock)
{
	*lock = kmalloc(sizeof(spinlock_t), GFP_KERNEL);
	if(*lock)
		spin_lock_init(*lock);
}

STDCALL void NdisFreeSpinLock(spinlock_t **lock)
{
	if(!lock)
	{
		DBGTRACE("%s: NULL\n", __FUNCTION__);
		return;       
	}
	if(*lock)
		kfree(*lock);
	*lock = NULL;
}

STDCALL void NdisAcquireSpinLock(spinlock_t **lock)
{
	spin_lock(*lock);	
}

STDCALL void NdisReleaseSpinLock(spinlock_t **lock)
{
	spin_unlock(*lock);	
}


STDCALL void NdisDprAcquireSpinLock(spinlock_t **lock)
{
	spin_lock(*lock);	
}

STDCALL void NdisDprReleaseSpinLock(spinlock_t **lock)
{
	spin_unlock(*lock);	
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
	handle->map_dma_addr = kmalloc(basemap * sizeof(dma_addr_t),
				       GFP_ATOMIC);
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

	void *v = pci_alloc_consistent(handle->pci_dev, size, &p);  
	if(!v)
	{
		printk(KERN_ERR "failed to allocate shared mem\n");
	}

	*(char**)virt = v;
	phys->low = (unsigned int)p;
	phys->high = 0;
}

STDCALL void NdisMFreeSharedMemory(struct ndis_handle *handle,
                                   unsigned int size,
				   char cached,
				   void *virt,
				   unsigned int physlow,
				   unsigned int physhigh)
{
	pci_free_consistent(handle->pci_dev, size, virt, physlow);
}


STDCALL void NdisAllocateBufferPool(unsigned int *status,
                                    unsigned int *poolhandle,
				    unsigned int size)
{
	*poolhandle = 0x0000fff8;
	*status = NDIS_STATUS_SUCCESS;
}



STDCALL void NdisFreeBufferPool(void *poolhandle)
{
	DBGTRACE("%s: %08x\n", __FUNCTION__, (int)poolhandle);
}


STDCALL void NdisAllocateBuffer(unsigned int *status,
                                void **buffer,
				void *poolhandle,
				void *virt,
				unsigned int len)
{
	struct ndis_buffer *my_buffer = kmalloc(sizeof(struct ndis_buffer), GFP_ATOMIC);
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
	
	*status = NDIS_STATUS_SUCCESS;

}

STDCALL void NdisFreeBuffer(void *buffer)
{
	if(buffer)
	{
		memset(buffer, 0, sizeof(struct ndis_buffer));
		kfree(buffer);
	}
}
STDCALL void NdisAdjustBufferLength(struct ndis_buffer *buf, unsigned int len)
{
	buf->len = len;
}
STDCALL void NdisQueryBuffer(struct ndis_buffer *buf, void **adr, unsigned int *len)
{
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
	return buf->data; 
}

STDCALL unsigned long NdisBufferLength(struct ndis_buffer *buf)
{
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
	NdisAllocatePacketPool(status, poolhandle, size, rsvlen);
}



STDCALL void NdisFreePacketPool(void *poolhandle)
{
	DBGTRACE("%s: %08x\n", __FUNCTION__, (int)poolhandle);
}

STDCALL void NdisAllocatePacket(unsigned int *status, struct ndis_packet **packet_out, void *poolhandle)
{
	struct ndis_packet *packet = (struct ndis_packet*) kmalloc(sizeof(struct ndis_packet), GFP_ATOMIC);
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
	
#ifdef DEBUG
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
}

STDCALL void NdisFreePacket(void *packet)
{
	if(packet)
	{
		memset(packet, 0, sizeof(struct ndis_packet));
		kfree(packet);
	}
}

/*
 * Timer function.
 */
void ndis_timer_handler(unsigned long data)
{
	struct ndis_timer *timer = (struct ndis_timer*) data;
	STDCALL void (*func)(void *res1, void *data, void *res3, void *res4) = timer->func;

	if (!timer->active)
		return;
	if (timer->repeat)
	{
		timer->timer.expires = jiffies + timer->repeat;
		add_timer(&timer->timer);
	}
	else
		timer->active = 0;
	func(0, timer->ctx, 0, 0);
}


STDCALL void NdisMInitializeTimer(struct ndis_timer **timer_handle,
                                  struct ndis_handle *handle,
				  void *func,
				  void *ctx)
{
	struct ndis_timer *timer;
	DBGTRACE("%s: %08x %08x, %08x, %08x\n", __FUNCTION__ , (int)timer_handle, (int)handle, (int)func, (int)ctx);
	timer = kmalloc(sizeof(struct ndis_timer), GFP_KERNEL);
	if(!timer)
	{
		timer_handle = NULL;
		return;
	}

	init_timer(&timer->timer);
	timer->timer.data = (unsigned long) timer;
	timer->timer.function = &ndis_timer_handler;
	timer->func = func;
	timer->ctx = ctx;
	timer->active = 0;
	*timer_handle = timer;
	DBGTRACE("Allocated timer at %08x\n", (int)timer);
}


/*
 * Start a one shot timer.
 */
STDCALL void NdisSetTimer(struct ndis_timer **timer_handle, unsigned int ms)
{
	struct ndis_timer *ndis_timer = *timer_handle;
	unsigned long expires = jiffies + (ms * HZ) / 1000;

	ndis_timer->repeat = 0;
	if(ndis_timer->active)
		mod_timer(&ndis_timer->timer, expires);
	else
	{
		ndis_timer->timer.expires = expires;
		add_timer(&ndis_timer->timer);
	}
	ndis_timer->active = 1;
}

/*
 * Start a repeated timer.
 */
STDCALL void NdisMSetPeriodicTimer(struct ndis_timer **timer_handle,
                                   unsigned int ms)
{

	struct ndis_timer *ndis_timer = *timer_handle;
	unsigned long expires = jiffies + (ms * HZ) / 1000;

	ndis_timer->repeat = (ms * HZ) / 1000;
	if(ndis_timer->active)
		mod_timer(&ndis_timer->timer, expires);
	else
	{
		ndis_timer->timer.expires = expires;
		add_timer(&ndis_timer->timer);
	}
	ndis_timer->active = 1;
}

/*
 * Cancel a pending timer
 */
STDCALL void NdisMCancelTimer(struct ndis_timer **timer_handle, char *canceled)
{
	DBGTRACE("%s\n", __FUNCTION__);
	(*timer_handle)->repeat = 0;
	*canceled = del_timer_sync(&(*timer_handle)->timer);
	(*timer_handle)->active = 0;
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
	*len = 0;
	*status = NDIS_STATUS_FAILURE;
}


STDCALL void NdisMRegisterAdapterShutdownHandler(struct ndis_handle *handle,
                                                 void *ctx,
						 void *func)
{
	DBGTRACE("%s sp:%08x\n", __FUNCTION__ , getSp());
}

STDCALL void NdisMDeregisterAdapterShutdownHandler(struct ndis_handle *handle)
{
	DBGTRACE("%s sp:%08x\n", __FUNCTION__ , getSp());
}


/*
 *  bottom half of the irq handler
 *
 */
void ndis_irq_bh(void *data)
{
	struct ndis_handle *handle = (struct ndis_handle *) data;
	if (handle->ndis_irq_enabled)
		handle->driver->miniport_char.handle_interrupt(handle->adapter_ctx);
}

/*
 *  Top half of the irq handler
 *
 */
irqreturn_t ndis_irq_th(int irq, void *data, struct pt_regs *pt_regs)
{
	int handeled = 0;
	int more_work = 0;

	struct ndis_irq *irqhandle = (struct ndis_irq *) data;
	struct ndis_handle *handle = irqhandle->handle; 
	unsigned long flags;

	spin_lock_irqsave(&irqhandle->spinlock, flags);
	handle->driver->miniport_char.isr(&handeled, &more_work, handle->adapter_ctx);
	spin_unlock_irqrestore(&irqhandle->spinlock, flags);

	if(more_work)
		schedule_work(&handle->irq_bh);
	
	if(handeled)
		return IRQ_HANDLED;

	return IRQ_NONE;
}


/*
 * Register an irq
 *
 */
STDCALL unsigned int NdisMRegisterInterrupt(struct ndis_irq **ndis_irq_ptr,
                                            struct ndis_handle *handle,
					    unsigned int vector,
					    unsigned int level,
					    char req_isr,
					    char shared,
					    unsigned int mode)
{
	struct ndis_irq *ndis_irq; 
	DBGTRACE("%s. %08x, vector:%d, level:%d, req_isr:%d, shared:%d, mode:%d sp:%08x\n", __FUNCTION__, (int)ndis_irq_ptr, vector, level, req_isr, shared, mode, (int)getSp());

	*ndis_irq_ptr = (struct ndis_irq*) kmalloc(sizeof(struct ndis_irq), GFP_KERNEL);
	
	if(!*ndis_irq_ptr)
		return NDIS_STATUS_FAILURE;

	ndis_irq = *ndis_irq_ptr;
	handle->irq = vector;

	spin_lock_init(&ndis_irq->spinlock);
	ndis_irq->irq = vector;
	ndis_irq->handle = handle;
	spin_lock(&ndis_irq->spinlock);
	spin_unlock(&ndis_irq->spinlock);

	if(request_irq(vector, ndis_irq_th, SA_SHIRQ, "ndiswrapper", ndis_irq))
	{
		kfree(ndis_irq);
		return NDIS_STATUS_FAILURE;
	}
	handle->ndis_irq_enabled = 1;
	INIT_WORK(&handle->irq_bh, &ndis_irq_bh, handle);
	return NDIS_STATUS_SUCCESS;
}

/*
 * Deregister an irq
 *
 */
STDCALL void NdisMDeregisterInterrupt(struct ndis_irq **ndis_irq_ptr)
{
	struct ndis_irq *ndis_irq = *ndis_irq_ptr;
	struct ndis_handle *handle = ndis_irq->handle;

	DBGTRACE("%s: %08x %d %08x\n", __FUNCTION__, (int)ndis_irq, ndis_irq->irq, (int)ndis_irq->handle);

	if(ndis_irq)
	{
		handle->ndis_irq_enabled = 0;
		free_irq(ndis_irq->irq, ndis_irq);
		kfree(ndis_irq);
	}
}


/*
 * Run func synchorinized with the isr.
 *
 */
typedef unsigned int (*sync_func_t)(void *ctx);
STDCALL char NdisMSynchronizeWithInterrupt(struct ndis_irq **ndis_irq_ptr,
                                           STDCALL sync_func_t func,
					   void *ctx)
{
	unsigned int ret;
	unsigned long flags;
	struct ndis_irq *ndis_irq = *ndis_irq_ptr;
	DBGTRACE("%s: %08x %08x %08x %08x\n", __FUNCTION__, (int) ndis_irq, (int) ndis_irq_ptr, (int) func, (int) ctx);

	spin_lock_irqsave(&ndis_irq->spinlock, flags);
	ret = func(ctx);
	spin_unlock_irqrestore(&ndis_irq->spinlock, flags);

	DBGTRACE("%s: Past func\n", __FUNCTION__);
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

	for(i = 0; i < nr_packets; i++)
	{
		packet = packets[i];
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
		handle->driver->miniport_char.return_packet(handle->adapter_ctx,  packet);
	}
}

/*
 *
 *
 * Called via function pointer.
 */
STDCALL void NdisMSendComplete(struct ndis_handle *handle, struct ndis_packet *packet, unsigned int status)
{
	handle->stats.tx_bytes += packet->len;
	handle->stats.tx_packets++;
	ndis_sendpacket_done(handle, packet);
}

STDCALL unsigned long NDIS_BUFFER_TO_SPAN_PAGES(void *buffer)
{
	DBGTRACE("%s\n", __FUNCTION__ );
	return 1;
}

/*
 * Sleeps for the given number of microseconds
 */
STDCALL void NdisMSleep(unsigned long us_to_sleep)
{
	DBGTRACE("%s called to sleep for %lu us\n", __FUNCTION__, us_to_sleep);
	if (us_to_sleep > 0)
	{
		schedule_timeout((us_to_sleep * HZ)/1000000);
		DBGTRACE("%s woke up\n", __FUNCTION__);
	} 
}

STDCALL void NdisGetCurrentSystemTime(u64 *time)
{
#define TICKSPERSEC             10000000
#define SECSPERDAY              86400
 
/* 1601 to 1970 is 369 years plus 89 leap days */
#define SECS_1601_TO_1970       ((369 * 365 + 89) * (u64)SECSPERDAY)
#define TICKS_1601_TO_1970      (SECS_1601_TO_1970 * TICKSPERSEC)

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
	unsigned long flags;
	long x;
	spin_lock_irqsave(&atomic_lock, flags);
	*val--;
	x = *val;
	spin_unlock_irqrestore(&atomic_lock, flags);
	return x;
}

STDCALL long NdisInterlockedIncrement(long *val)
{
	unsigned long flags;
	long x;
	spin_lock_irqsave(&atomic_lock, flags);
	*val++;
	x = *val;
	spin_unlock_irqrestore(&atomic_lock, flags);
	return x;
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
		wait_event(event_wq, event->state == 1);
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
	wake_up(&event_wq);
}

STDCALL void NdisResetEvent(struct ndis_event *event)
{
	//DBGTRACE("%s %08x\n", __FUNCTION__, (int)event);
	event->state = 0;
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
	if (!write_to_dev)
	{
		DBGTRACE("%s (%s): dma from device not supported (%d)\n",
			 handle->net_dev->name, __FUNCTION__, write_to_dev);
		*array_size = 0;
		return;
	}

	if (phy_map_reg > handle->map_count)
	{
		DBGTRACE("%s (%s): map_register too big (%lu > %u)\n",
			 handle->net_dev->name, __FUNCTION__,
			 phy_map_reg, handle->map_count);
		*array_size = 0;
		return;
	}
	
	if (handle->map_dma_addr[phy_map_reg] != 0)
	{
		DBGTRACE("%s (%s): map register already used (%lu)\n",
			 handle->net_dev->name, __FUNCTION__, phy_map_reg);
		*array_size = 0;
		return;
	}

	// map buffer
	phy_addr_array[0].phy_addr.low =
		pci_map_single(handle->pci_dev, buf->data, buf->len,
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
	DBGTRACE("%s (%s): %x %lu (%u)\n",
		 handle->net_dev->name, __FUNCTION__,
		 handle, phy_map_reg, handle->map_count);

	if (phy_map_reg > handle->map_count)
	{
		DBGTRACE("%s (%s): map_register too big (%lu > %u)\n",
			 handle->net_dev->name, __FUNCTION__,
			 phy_map_reg, handle->map_count);
		return;
	}

	if (handle->map_dma_addr[phy_map_reg] == 0)
	{
		DBGTRACE("%s (%s): map register not used (%lu)\n",
			 handle->net_dev->name, __FUNCTION__, phy_map_reg);
		return;
	}
	
	// unmap buffer
	pci_unmap_single(handle->pci_dev, handle->map_dma_addr[phy_map_reg],
			 buf->len, PCI_DMA_TODEVICE);

	// clear mapping index
	handle->map_dma_addr[phy_map_reg] = 0;
}

 /* Unimplemented...*/
STDCALL void NdisInitAnsiString(void *src, void *dst) {UNIMPL();}
STDCALL void NdisOpenConfigurationKeyByName(unsigned int *status, void *handle, void *key, void *subkeyhandle){UNIMPL();}
STDCALL void NdisWriteConfiguration(unsigned int *status, void *handle, void *keyword, void *val){UNIMPL();}
STDCALL unsigned int NdisAnsiStringToUnicodeString(void *dst, void *src){UNIMPL();return 0;}
STDCALL void NdisMGetDeviceProperty(void *handle, void **p1, void **p2, void **p3, void**p4, void**p5){UNIMPL();}
STDCALL unsigned long NdisWritePcmciaAttributeMemory(void *handle, unsigned int offset, void *buffer, unsigned int length){UNIMPL();return 0;}
STDCALL unsigned long NdisReadPcmciaAttributeMemory(void *handle, unsigned int offset, void *buffer, unsigned int length){UNIMPL();return 0;}
STDCALL void NdisUnicodeStringToAnsiString(void){UNIMPL();}

STDCALL void NdisInitializeString(void){UNIMPL();}
STDCALL void NdisMSetAttributes(void){UNIMPL();}
STDCALL void EthFilterDprIndicateReceiveComplete(void){UNIMPL();}
STDCALL void EthFilterDprIndicateReceive(void){UNIMPL();}
STDCALL void NdisMPciAssignResources(void){UNIMPL();}

