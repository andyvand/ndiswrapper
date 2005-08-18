/*
 *  Copyright (C) 2004 Jan Kiszka
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
#include "usb.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,5)
#define CUR_ALT_SETTING(intf) (intf)->cur_altsetting
#else
#define CUR_ALT_SETTING(intf) (intf)->altsetting[(intf)->act_altsetting]
#endif

static struct nt_list urb_tx_complete_list;
extern KSPIN_LOCK urb_tx_complete_list_lock;
void usb_tx_complete_tasklet(unsigned long dummy);
void usb_cancel_worker(void *dummy);
void urb_tx_complete_worker(void *dummy);
static struct work_struct urb_tx_complete_work;
STDCALL void usb_cancel_transfer(struct device_object *dev_obj,
				 struct irp *irp);

/* keep track of allocated urbs so they can be canceled/freed */
struct wrap_urb {
	struct nt_list list;
	struct irp *irp;
	struct urb *urb;
};
static struct nt_list wrap_urb_list;
static KSPIN_LOCK wrap_urb_list_lock;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static void *usb_buffer_alloc(struct usb_device *dev, size_t size,
			      unsigned mem_flags, dma_addr_t *dma)
{
	return NULL;
}
static void usb_buffer_free(struct usb_device *dev, size_t size,
			    void *addr, dma_addr_t dma)
{
	return;
}
#define URB_NO_TRANSFER_DMA_MAP 0
#define URB_NO_SETUP_DMA_MAP 0
#endif

#ifdef DUMPURBS
#define DUMP_URB(urb) do {						\
		int i;							\
		char dbg[40], *t;					\
		if ((urb)->pipe & USB_DIR_IN)				\
			USBTRACE("URB coming back");			\
		else							\
			USBTRACE("URB going down");			\
		printk(KERN_DEBUG "length: %x",				\
		       urb->transfer_buffer_length);			\
		t = dbg;						\
		for (i = 0; i < urb->transfer_buffer_length &&		\
			     t < &dbg[sizeof(dbg) - 2]; i++)		\
			t += sprintf(t, "%02X ",			\
				     *(((UCHAR *)urb->transfer_buffer)+i)); \
		dbg[sizeof(dbg)-1] = 0;					\
		printk(KERN_DEBUG "%s\n", dbg);				\
	} while (0)
#else
#define DUMP_URB(urb)
#endif /* DUMPURBS */

static struct urb *wrap_alloc_urb(unsigned int mem_flags, struct irp *irp,
				  struct usb_device *dev, int tx_buf_len)
{
	struct urb *urb;

	struct wrap_urb *wrap_urb;
	KIRQL irql;

	wrap_urb = kmalloc(sizeof(*wrap_urb), mem_flags);
	if (!wrap_urb) {
		ERROR("couldn't allocate memory");
		return NULL;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	urb = usb_alloc_urb(0);
#else
	urb = usb_alloc_urb(0, mem_flags);
#endif
	if (!urb) {
		WARNING("couldn't allocate urb");
		kfree(wrap_urb);
		return NULL;
	}
	wrap_urb->urb = urb;
	wrap_urb->irp = irp;
	irql = kspin_lock_irql(&wrap_urb_list_lock, DISPATCH_LEVEL);
	InsertTailList(&wrap_urb_list, &wrap_urb->list);
	kspin_unlock_irql(&wrap_urb_list_lock, irql);
	irp->urb = urb;
	irp->cancel_routine = usb_cancel_transfer;
	if (tx_buf_len) {
		urb->transfer_buffer =
			usb_buffer_alloc(dev, tx_buf_len, mem_flags,
					 &urb->transfer_dma);
		if (!urb->transfer_buffer) {
			WARNING("couldn't allocate dma buf");
			usb_free_urb(urb);
			return NULL;
		}
		urb->transfer_buffer_length = tx_buf_len;
		urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	} else
		urb->transfer_buffer = NULL;
	urb->context = wrap_urb;
	return urb;
}

static void wrap_free_urb(struct urb *urb)
{
	struct irp *irp;

	struct wrap_urb *wrap_urb;
	KIRQL irql;

	wrap_urb = urb->context;
	irql = kspin_lock_irql(&wrap_urb_list_lock, DISPATCH_LEVEL);
	RemoveEntryList(&wrap_urb->list);
	kspin_unlock_irql(&wrap_urb_list_lock, irql);

	irp = wrap_urb->irp;
	irp->cancel_routine = NULL;
	if (urb->transfer_buffer)
		usb_buffer_free(urb->dev, urb->transfer_buffer_length, 
				urb->transfer_buffer, urb->transfer_dma);
	if (urb->setup_packet)
		usb_buffer_free(urb->dev, sizeof(struct usb_ctrlrequest),
				urb->setup_packet, urb->setup_dma);
	usb_free_urb(urb);
	kfree(wrap_urb);
	irp->urb = NULL;
	return;
}

void usb_cancel_pending_urbs(void)
{
	while (1) {
		struct nt_list *cur;
		struct wrap_urb *wrap_urb;
		KIRQL irql;
		
		irql = kspin_lock_irql(&wrap_urb_list_lock, DISPATCH_LEVEL);
		cur = GetHeadList(&wrap_urb_list);
		kspin_unlock_irql(&wrap_urb_list_lock, irql);
		if (!cur)
			break;
		wrap_urb = container_of(cur, struct wrap_urb, list);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
		usb_kill_urb(wrap_urb->urb);
#else
		usb_unlink_urb(wrap_urb->urb);
#endif
		USBTRACE("urb %p killed", wrap_urb->urb);
	}
	return;
}

static inline int wrap_submit_urb(struct urb *urb, unsigned int mem_flags)
{
	int ret;

	USBTRACE("wrap_urb: %p, urb: %p", urb->context, urb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	ret = usb_submit_urb(urb);
#else
	ret = usb_submit_urb(urb, mem_flags);
#endif
	if (ret)
		wrap_free_urb(urb);
	return ret;
}

/* for a given Linux urb status code, return corresponding NT urb status */
int wrap_urb_status(int urb_status)
{
	switch (urb_status) {
	case 0:
		return USBD_STATUS_SUCCESS;
	case -EPROTO:
		return USBD_STATUS_BTSTUFF;
	case -EILSEQ:
		return USBD_STATUS_CRC;
	case -EPIPE:
		return USBD_STATUS_INVALID_PIPE_HANDLE;
	case -ECOMM:
		return USBD_STATUS_DATA_OVERRUN;
	case -ENOSR:
		return USBD_STATUS_DATA_UNDERRUN;
	case -EOVERFLOW:
		return USBD_STATUS_BABBLE_DETECTED;
	case -EREMOTEIO:
		return USBD_STATUS_ERROR_SHORT_TRANSFER;;
	case -ENODEV:
	case -ESHUTDOWN:
		return USBD_STATUS_DEVICE_GONE;
	default:
		return USBD_STATUS_REQUEST_FAILED;
	}
}

int usb_init(void)
{
	kspin_lock_init(&urb_tx_complete_list_lock);
	InitializeListHead(&urb_tx_complete_list);
	INIT_WORK(&urb_tx_complete_work, urb_tx_complete_worker, NULL);
	InitializeListHead(&wrap_urb_list);
	kspin_lock_init(&wrap_urb_list_lock);
	return 0;
}

void usb_exit(void)
{
	/* TODO: free all urbs? */
	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
void usb_transfer_complete(struct urb *urb, struct pt_regs *regs)
#else
void usb_transfer_complete(struct urb *urb)
#endif
{
	struct wrap_urb *wrap_urb;
	struct irp *irp;
	KIRQL irql;

	wrap_urb = urb->context;
	irql = kspin_lock_irql(&urb_tx_complete_list_lock, DISPATCH_LEVEL);
	irp = wrap_urb->irp;
	irp->cancel_routine = NULL;
	InsertTailList(&urb_tx_complete_list, &irp->urb_list);
	kspin_unlock_irql(&urb_tx_complete_list_lock, irql);
	schedule_work(&urb_tx_complete_work);
	USBTRACEEXIT(return);
}

/* this is called holding irp_cancel_lock */
STDCALL void usb_cancel_transfer(struct device_object *dev_obj,
				 struct irp *irp)
{
	struct urb *urb;

	USBTRACEENTER("irp = %p", irp);
	urb = irp->urb;
	USBTRACE("canceling urb %p", urb);

	/* while this function can run at DISPATCH_LEVEL,
	 * usb_unlink/kill_urb will only work successfully in
	 * schedulable context */
	kspin_unlock_irql(&urb_tx_complete_list_lock, irp->cancel_irql);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
	usb_kill_urb(urb);
#else
	usb_unlink_urb(urb);
#endif
}

void urb_tx_complete_worker(void *dummy)
{
	struct irp *irp;
	struct urb *urb;
	KIRQL irql;
	struct bulk_or_intr_transfer *bulk_int_tx;
	union nt_urb *nt_urb;

	while (1) {
		struct nt_list *entry;

		irql = kspin_lock_irql(&urb_tx_complete_list_lock,
				       DISPATCH_LEVEL);
		entry = RemoveHeadList(&urb_tx_complete_list);
		if (entry == NULL)
			irp = NULL;
		else
			irp = container_of(entry, struct irp, urb_list);
		kspin_unlock_irql(&urb_tx_complete_list_lock, irql);

		if (!irp)
			break;
		DUMP_IRP(irp);
		urb = irp->urb;
		if (!urb) {
			ERROR("urb for %p already freed?", irp);
			continue;
		}
		nt_urb = URB_FROM_IRP(irp);
		if (!nt_urb) {
			ERROR("nt_urb for %p already freed?", irp);
			continue;
		}
		USBTRACE("urb: %p, nt_urb: %p", urb, nt_urb);

		switch (urb->status) {
		case -ENOENT:
		case -ECONNRESET:
			irp->io_status.status = STATUS_CANCELLED;
			irp->io_status.status_info = 0;
			break;
		case 0:
			if (urb->status) {
				irp->io_status.status = STATUS_FAILURE;
				irp->io_status.status_info = 0;
			} else {
				irp->io_status.status = STATUS_SUCCESS;
				irp->io_status.status_info =
					urb->actual_length;
			}

			bulk_int_tx = &nt_urb->bulk_int_transfer;
			bulk_int_tx->transferBufLen = urb->actual_length;
			if (urb->transfer_buffer &&
			    USBD_DIRECTION_IN(bulk_int_tx->transferFlags))
				memcpy(bulk_int_tx->transferBuf,
				       urb->transfer_buffer,
				       urb->actual_length);
			DUMP_URB(urb);
			break;
		default:
			irp->io_status.status = STATUS_FAILURE;
			irp->io_status.status_info = 0;
		}
		NT_URB_STATUS(nt_urb) = wrap_urb_status(urb->status);
		wrap_free_urb(urb);
		USBTRACE("irp: %p, status: %d", irp, irp->io_status.status);
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
}

unsigned long usb_bulk_or_intr_trans(struct usb_device *dev,
				     union nt_urb *nt_urb, struct irp *irp)
{
	union pipe_handle pipe_handle;
	struct urb *urb;
	unsigned int pipe;
	int ret;
	UCHAR endpoint;
	struct bulk_or_intr_transfer *bulk_int_tx;

	bulk_int_tx = &nt_urb->bulk_int_transfer;
	ASSERT(!bulk_int_tx->transferBufMdl);
	ASSERT(!bulk_int_tx->urbLink);
	USBTRACE("flags = %X, length = %u, buffer = %p",
		  bulk_int_tx->transferFlags,
		  bulk_int_tx->transferBufLen,
		  bulk_int_tx->transferBuf);

	DUMP_IRP(irp);
	/* TODO: we should better check what GFP_ is required */
	urb = wrap_alloc_urb(GFP_ATOMIC, irp, dev,
			     bulk_int_tx->transferBufLen);
	if (!urb)
		return -ENOMEM;

	pipe_handle = bulk_int_tx->pipeHandle;
	endpoint = pipe_handle.encoded.endpointAddr;
	if (bulk_int_tx->transferBufLen > 0 &&
	    USBD_DIRECTION_OUT(bulk_int_tx->transferFlags))
		memcpy(urb->transfer_buffer, bulk_int_tx->transferBuf,
		       bulk_int_tx->transferBufLen);

	/* TODO: at least for interrupt urbs, we should avoid
	 * allocating/freeing dma every time */
	switch(pipe_handle.encoded.pipeType) {
	case USB_ENDPOINT_XFER_BULK:
		if (USBD_DIRECTION_IN(bulk_int_tx->transferFlags))
			pipe = usb_rcvbulkpipe(dev, endpoint);
		else
			pipe = usb_sndbulkpipe(dev, endpoint);

		usb_fill_bulk_urb(urb, dev, pipe, urb->transfer_buffer,
				  bulk_int_tx->transferBufLen,
				  usb_transfer_complete, urb->context);
		break;
	case USB_ENDPOINT_XFER_INT:
		if (USBD_DIRECTION_IN(bulk_int_tx->transferFlags))
			pipe = usb_rcvintpipe(dev, endpoint);
		else
			pipe = usb_sndintpipe(dev, endpoint);

		usb_fill_int_urb(urb, dev, pipe, urb->transfer_buffer,
				 bulk_int_tx->transferBufLen,
				 usb_transfer_complete, urb->context,
				 pipe_handle.encoded.interval);
		break;
	default:
		ERROR("unknown pipe type: %d", pipe_handle.encoded.pipeType);
		return -EINVAL;
	}

	DUMP_URB(urb);

	USBTRACE("submitting urb %p on pipe %p", urb, pipe_handle.handle);
	/* FIXME: we should better check what GFP_ is required */
	ret = wrap_submit_urb(urb, GFP_ATOMIC);
	return ret;
}

unsigned long usb_vendor_or_class_intf(struct usb_device *dev,
				       union nt_urb *nt_urb, struct irp *irp)
{
	struct urb *urb;
	struct usb_ctrlrequest *dr;
	char req_type;
	unsigned int pipe;
	int ret;
	struct vendor_or_class_request *vc_req;

	vc_req = &nt_urb->vendor_class_request;
	ASSERT(!vc_req->transferBufMdl);
	ASSERT(!vc_req->urbLink);
	USBTRACE("reservedBits = %x, request = %x, "
		 "value = %d, index = %d, transferFlags = %x, "
		 "transferBuf = %p, transferBufLen = %d",
		 vc_req->reservedBits,
		 vc_req->request, vc_req->value,
		 vc_req->index,
		 vc_req->transferFlags,
		 vc_req->transferBuf,
		 vc_req->transferBufLen);

	DUMP_IRP(irp);
	/* FIXME: we should better check what GFP_ is required */
	urb = wrap_alloc_urb(GFP_ATOMIC, irp, dev,
			     vc_req->transferBufLen);
	if (!urb) {
		ERROR("couldn't allocate urb");
		return -ENOMEM;
	}
	if (vc_req->transferBufLen > 0 &&
	    USBD_DIRECTION_OUT(vc_req->transferBufLen))
		memcpy(urb->transfer_buffer, vc_req->transferBuf,
		       vc_req->transferBufLen);

	req_type = USB_TYPE_VENDOR | USB_RECIP_DEVICE |
		vc_req->reservedBits;

	if (USBD_DIRECTION_IN(vc_req->transferFlags)) {
		pipe = usb_rcvctrlpipe(dev, 0);
		req_type |= USB_DIR_IN;
	} else {
		pipe = usb_sndctrlpipe(dev, 0);
		req_type |= USB_DIR_OUT;
	}

	dr = usb_buffer_alloc(dev, sizeof(*dr), GFP_ATOMIC, &urb->setup_dma);
	if (!dr) {
		ERROR("couldn't allocate dma buffer");
		wrap_free_urb(urb);
		return -ENOMEM;
	}
	urb->transfer_flags |= URB_NO_SETUP_DMA_MAP;

	dr->bRequestType = req_type;
	dr->bRequest = vc_req->request;
	dr->wValue = vc_req->value;
	dr->wIndex = vc_req->index;
	dr->wLength = vc_req->transferBufLen;

	usb_fill_control_urb(urb, dev, pipe, (unsigned char *)dr,
			     urb->transfer_buffer, vc_req->transferBufLen,
			     usb_transfer_complete, urb->context);

	if (USBD_DIRECTION_IN(vc_req->transferFlags) &&
	    (!(vc_req->transferFlags &
	       USBD_SHORT_TRANSFER_OK)))
		urb->transfer_flags |= URB_SHORT_NOT_OK;

	DUMP_URB(urb);

	USBTRACE("submitting urb %p on control pipe", urb);
	/* FIXME: we should better check what GFP_ is required */
	ret = wrap_submit_urb(urb, GFP_ATOMIC);
	return ret;
}

unsigned long usb_reset_pipe(struct usb_device *dev,
			     union pipe_handle pipe_handle)
{
	int pipe;
	UCHAR endpoint;

	USBTRACE("pipe = %p", pipe_handle.handle);
	endpoint = pipe_handle.encoded.endpointAddr;
	switch (pipe_handle.encoded.pipeType) {
	case USB_ENDPOINT_XFER_CONTROL:
		if (pipe_handle.encoded.endpointAddr & USB_ENDPOINT_DIR_MASK)
			pipe = usb_rcvctrlpipe(dev, endpoint);
		else
			pipe = usb_sndctrlpipe(dev, endpoint);
		break;

	case USB_ENDPOINT_XFER_BULK:
		if (pipe_handle.encoded.endpointAddr & USB_ENDPOINT_DIR_MASK)
			pipe = usb_rcvbulkpipe(dev, endpoint);
		else
			pipe = usb_sndbulkpipe(dev, endpoint);
		break;

	case USB_ENDPOINT_XFER_INT:
		if (pipe_handle.encoded.endpointAddr & USB_ENDPOINT_DIR_MASK)
			pipe = usb_rcvbulkpipe(dev, endpoint);
		else
			pipe = usb_sndbulkpipe(dev, endpoint);
		break;
	default:
		WARNING("unknown pipe type: %d", pipe_handle.encoded.pipeType);
		return -EINVAL;
	}

	return usb_clear_halt(dev, pipe);
}

unsigned long usb_select_configuration(struct usb_device *dev,
				       union nt_urb *nt_urb, struct irp *irp)
{
	struct usb_interface *intf;
	struct usbd_pipe_information *pipe_info;
	int i, ret;
	struct usb_endpoint_descriptor *desc;
	struct select_configuration *sel_conf;

	sel_conf = &nt_urb->select_conf;
	ASSERT(sel_conf->config->bNumInterfaces == 1);
	USBTRACE("intf.intfNum = %d, intf.altSet = %d",
		 sel_conf->intf.intfNum,
		 sel_conf->intf.altSet);

	ret = usb_set_interface(dev, sel_conf->intf.intfNum,
				sel_conf->intf.altSet);
	if (ret < 0) {
		ERROR("usb_set_interface() = %d", ret);
		USBTRACEEXIT(return ret);
	}

	intf = usb_ifnum_to_if(dev, sel_conf->intf.intfNum);
	if (!intf) {
		ERROR("usb_ifnum_to_if() = %d", ret);
		USBTRACEEXIT(return ret);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	for (i = 0; i < CUR_ALT_SETTING(intf)->desc.bNumEndpoints; i++) {
		desc = &(CUR_ALT_SETTING(intf)->endpoint + i)->desc;
#else
	for (i = 0; i < CUR_ALT_SETTING(intf).bNumEndpoints; i++) {
		desc = &((CUR_ALT_SETTING(intf)).endpoint[i]);
#endif
		pipe_info = &sel_conf->intf.pipes[i];

		pipe_info->maxPacketSize = desc->wMaxPacketSize;
		pipe_info->endpointAddr = desc->bEndpointAddress;
		pipe_info->interval = desc->bInterval;
		pipe_info->pipeType = desc->bmAttributes;

		pipe_info->pipeHandle.encoded.endpointAddr =
			desc->bEndpointAddress;
		pipe_info->pipeHandle.encoded.pipeType =
			desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
		pipe_info->pipeHandle.encoded.interval =
			(dev->speed == USB_SPEED_HIGH) ?
			desc->bInterval + 3 : desc->bInterval;
		pipe_info->pipeHandle.encoded.fill = 0;

		USBTRACE("%i: Addr %X, Type %d, PkSz %d, "
			  "Intv %d, Handle %p", i, desc->bEndpointAddress,
			  desc->bmAttributes, desc->wMaxPacketSize,
			  desc->bInterval, pipe_info->pipeHandle.handle);
	}
	USBTRACEEXIT(return 0);
}

unsigned long usb_submit_nt_urb(struct usb_device *dev, union nt_urb *nt_urb,
				struct irp *irp)
{
	struct control_descriptor_request *ctrl_req;
	int ret;
	char *buf;

	USBTRACEENTER("nt_urb = %p, irp = %p, length = %d, function = %x",
		    nt_urb, irp, nt_urb->header.length,
		    nt_urb->header.function);

	DUMP_IRP(irp);
	nt_urb->header.status = USBD_STATUS_SUCCESS;

	switch (nt_urb->header.function) {
	case URB_FUNCTION_SELECT_CONFIGURATION:
		usb_select_configuration(dev, nt_urb, irp);
		USBTRACEEXIT(return STATUS_SUCCESS);

	case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
		ret = usb_bulk_or_intr_trans(dev, nt_urb, irp);
		if (ret < 0)
			break;
		USBTRACEEXIT(return STATUS_PENDING);

	case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
		ctrl_req = &nt_urb->control_request;
		ASSERT(!ctrl_req->transferBufMdl);
		ASSERT(!ctrl_req->urbLink);
		USBTRACE("desctype = %d, descindex = %d, "
			  "transferBuf = %p, transferBufLen = %d",
			  ctrl_req->desctype,
			  ctrl_req->index,
			  ctrl_req->transferBuf,
			  ctrl_req->transferBufLen);

		buf = kmalloc(ctrl_req->transferBufLen, GFP_NOIO);
		if (!buf) {
			ERROR("couldn't allocate memory");
			break;
		}
		ret = usb_get_descriptor(dev, ctrl_req->desctype,
					 ctrl_req->index, buf,
					 ctrl_req->transferBufLen);
		if (ret < 0) {
			ERROR("usb_get_descriptor() = %d", ret);
			break;
		}
		memcpy(ctrl_req->transferBuf, buf, ret);
		kfree(buf);
		ctrl_req->transferBufLen = ret;
		USBTRACEEXIT(return STATUS_SUCCESS);

	case URB_FUNCTION_VENDOR_DEVICE:
	case URB_FUNCTION_VENDOR_INTERFACE:
	case URB_FUNCTION_CLASS_INTERFACE:
		USBTRACE("func: %d", nt_urb->header.function);
		ret = usb_vendor_or_class_intf(dev, nt_urb, irp);
		if (ret < 0)
			break;
		USBTRACEEXIT(return STATUS_PENDING);

	case URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL:
		ret = usb_reset_pipe(dev, nt_urb->pipe_req.pipeHandle);
		if (ret < 0) {
			ERROR("usb_reset_pipe() = %d", ret);
			break;
		}
		USBTRACEEXIT(return STATUS_SUCCESS);

	default:
		ERROR("function %X NOT IMPLEMENTED!\n",
		      nt_urb->header.function);
	}
	nt_urb->header.status = USBD_STATUS_INVALID_URB_FUNCTION;
	USBTRACEEXIT(return STATUS_FAILURE);
}

unsigned long usb_reset_port(struct usb_device *dev)
{
	int ret;

	USBTRACEENTER("%s", "");

	ret = usb_reset_device(dev);
	if (ret < 0) {
		ERROR("usb_reset_device() = %d", ret);
		USBTRACEEXIT(return STATUS_FAILURE);
	}

	USBTRACEEXIT(return STATUS_SUCCESS);
}

STDCALL union nt_urb *WRAP_EXPORT(USBD_CreateConfigurationRequest)
	(struct usb_config_descriptor *config, unsigned short *nt_urb_size)
{
	union nt_urb *nt_urb;
	struct usb_interface_descriptor *intf_desc = NULL;
	struct usbd_interface_information *intf_info;
	char *pos = (char *)config;
	int cfg_size = config->wTotalLength;

	USBTRACEENTER("config = %p, urb_size = %p", config, nt_urb_size);
	ASSERT(config->bNumInterfaces < 2);

	while (((char *)pos - (char *)config) < cfg_size) {
		intf_desc = (struct usb_interface_descriptor *)pos;
		pos = pos + intf_desc->bLength;

		if (intf_desc->bDescriptorType == USB_DT_INTERFACE) {
			USBTRACE("selected interface = %p", intf_desc);
			break;
		}
	}
	if (((char *)pos - (char *)config) >= cfg_size)
		USBTRACEEXIT(return NULL);

	*nt_urb_size = sizeof(*nt_urb) +
		sizeof(struct usbd_pipe_information) *
		(intf_desc->bNumEndpoints - 1);
	/* FIXME: we should better check what GFP_ is required */
	nt_urb = kmalloc(*nt_urb_size, GFP_ATOMIC);

	if (nt_urb) {
		nt_urb->select_conf.header.length = *nt_urb_size;
		nt_urb->select_conf.header.function =
			URB_FUNCTION_SELECT_CONFIGURATION;
		nt_urb->select_conf.config = config;

		intf_info = &nt_urb->select_conf.intf;
		intf_info->length = sizeof(struct usbd_interface_information)+
			sizeof(struct usbd_pipe_information) *
			(intf_desc->bNumEndpoints - 1);
		intf_info->intfNum = intf_desc->bInterfaceNumber;
		intf_info->altSet = intf_desc->bAlternateSetting;
		intf_info->class = intf_desc->bInterfaceClass;
		intf_info->subClass = intf_desc->bInterfaceSubClass;
		intf_info->proto = intf_desc->bInterfaceProtocol;
		intf_info->pipeNum = intf_desc->bNumEndpoints;
	}

	USBTRACEEXIT(return nt_urb);
}

STDCALL union nt_urb *WRAP_EXPORT(USBD_CreateConfigurationRequestEx)
	(struct usb_config_descriptor *config,
	 struct usbd_interface_list_entry *intfList)
{
	union nt_urb *nt_urb;
	int nt_urb_size;
	struct usb_interface_descriptor *intf_desc;
	struct usbd_interface_information *intf_info;

	/*
	 * Note: This function is more or less a hack - due to a lack
	 * of understanding of the underlying USB details. It only
	 * sets up an URB with one interface inside. This is what the
	 * WUSB54G driver requests or what the WUSB54G device
	 * provides. However, this function warns if the assumption is
	 * incorrect.
	 */

	USBTRACEENTER("config = %p, intfList = %p", config, intfList);
	ASSERT(config->bNumInterfaces < 2);

	intf_desc = intfList->intfDesc;
	nt_urb_size = sizeof(union nt_urb) +
		sizeof(struct usbd_pipe_information) *
		(intf_desc->bNumEndpoints - 1);
	/* FIXME: we should better check what GFP_ is required */
	nt_urb = kmalloc(nt_urb_size, GFP_ATOMIC);

	if (nt_urb) {
		nt_urb->select_conf.header.length = nt_urb_size;
		nt_urb->select_conf.header.function =
			URB_FUNCTION_SELECT_CONFIGURATION;
		nt_urb->select_conf.config = config;

		intf_info = &nt_urb->select_conf.intf;
		intfList->intf = intf_info;
		intf_info->length = sizeof(struct usbd_interface_information)+
			sizeof(struct usbd_pipe_information) *
			(intf_desc->bNumEndpoints - 1);
		intf_info->intfNum = intf_desc->bInterfaceNumber;
		intf_info->altSet = intf_desc->bAlternateSetting;
		intf_info->class = intf_desc->bInterfaceClass;
		intf_info->subClass = intf_desc->bInterfaceSubClass;
		intf_info->proto = intf_desc->bInterfaceProtocol;
		intf_info->pipeNum = intf_desc->bNumEndpoints;

		ASSERT(!(intfList+1)->intfDesc);
	}

	USBTRACEEXIT(return nt_urb);
}
WRAP_EXPORT_MAP("_USBD_CreateConfigurationRequestEx@8",	USBD_CreateConfigurationRequestEx);

STDCALL struct usb_interface_descriptor *
	WRAP_EXPORT(USBD_ParseConfigurationDescriptorEx)
	(struct usb_config_descriptor *config,
	 void *startPos, LONG intfNum, LONG altSet,
	 LONG intfClass, LONG intfSubClass, LONG intfProto)
{
	int size = config->wTotalLength;
	char *pos = startPos;
	struct usb_interface_descriptor *intf;

	USBTRACEENTER("config = %p, startPos = %p, intfNum = %d, altSet = %d,"
		    " intfClass = %d, intfSubClass = %d, intfProto = %d",
		    config, startPos, intfNum, altSet, intfClass, intfSubClass,
		    intfProto);

	while ((char *)pos - (char *)config < size) {
		intf = (struct usb_interface_descriptor *)pos;
		pos = pos + intf->bLength;

		if (intf->bDescriptorType != USB_DT_INTERFACE)
			continue;
		if ((intfNum != -1) && (intf->bInterfaceNumber != intfNum))
			continue;
		if ((altSet != -1) && (intf->bAlternateSetting != altSet))
			continue;
		if ((intfClass != -1) && (intf->bInterfaceClass != intfClass))
			continue;
		if ((intfSubClass != -1) &&
		    (intf->bInterfaceSubClass != intfSubClass))
			continue;
		if ((intfProto != -1) &&
		    (intf->bInterfaceProtocol != intfProto))
			continue;

		USBTRACE("selected interface = %p", intf);
		USBTRACEEXIT(return intf);
	}

	USBTRACEEXIT(return NULL);
}
WRAP_EXPORT_MAP("_USBD_ParseConfigurationDescriptorEx@28", USBD_ParseConfigurationDescriptorEx);

STDCALL struct usb_interface_descriptor *
	WRAP_EXPORT(USBD_ParseConfigurationDescriptor)
	(struct usb_config_descriptor *config,
	 unsigned char intfNum, unsigned char altSet)
{
	return USBD_ParseConfigurationDescriptorEx(config, config, intfNum,
						   altSet, -1, -1, -1);
}

#include "usb_exports.h"
