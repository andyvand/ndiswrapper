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

#if 1
#undef USBTRACE
#undef USBTRACEENTER
#undef USBTRACEEXIT
#define USBTRACE(fmt, ...) INFO(fmt, ## __VA_ARGS__)
#define USBTRACEENTER(fmt, ...) INFO(fmt, ## __VA_ARGS__)
#define USBTRACEEXIT(stmt) do { INFO("Exit"); stmt; } while (0)
#define DUMPURBS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,5)
#define CUR_ALT_SETTING(intf) (intf)->cur_altsetting
#else
#define CUR_ALT_SETTING(intf) (intf)->altsetting[(intf)->act_altsetting]
#endif

STDCALL void usb_cancel_transfer(struct device_object *dev_obj,
				 struct irp *irp);
static KSPIN_LOCK usb_tx_complete_list_lock;
static struct nt_list usb_tx_complete_list;
static void usb_tx_complete_worker(void *data);
static struct work_struct usb_tx_complete_work;

static KSPIN_LOCK usb_tx_submit_list_lock;
static struct nt_list usb_tx_submit_list;
static void usb_tx_submit_worker(void *data);
struct work_struct usb_tx_submit_work;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static inline void *usb_buffer_alloc(struct usb_device *dev, size_t size,
				     unsigned mem_flags, dma_addr_t *dma)
{
	void *buf;
	/* TODO: provide dma buffer */
	buf = kmalloc(size, mem_flags);
	if (buf)
		memset(buf, 0, size);
	return buf;
}
static inline void usb_buffer_free(struct usb_device *dev, size_t size,
				   void *addr, dma_addr_t dma)
{
	kfree(addr);
}
#define URB_NO_TRANSFER_DMA_MAP 0
#define URB_NO_SETUP_DMA_MAP 0
#endif

#define DUMP_BUFFER(buf, len)						\
	do {								\
		int __i;						\
		char msg[100], *t;					\
		if (!buf)						\
			break;						\
		t = msg;						\
		for (__i = 0; __i < len && t < &msg[sizeof(msg) -4]; __i++) { \
			t += sprintf(t, "%02X ",			\
				     (((UCHAR *)buf)[__i])); \
		}							\
		printk(KERN_INFO "%s\n", msg);				\
	} while (0)

#ifdef DUMPURBS
int urb_num;

#define DUMP_URB(urb) do {						\
		USBTRACE("urb: %p, buf: %p, len: %d, pipe: %u",		\
			 urb, urb->transfer_buffer,			\
			 urb->transfer_buffer_length, urb->pipe);	\
	} while (0)
#endif /* DUMPURBS */

int usb_init(void)
{
	kspin_lock_init(&usb_tx_complete_list_lock);
	INIT_WORK(&usb_tx_complete_work, usb_tx_complete_worker, NULL);
	InitializeListHead(&usb_tx_complete_list);

	kspin_lock_init(&usb_tx_submit_list_lock);
	INIT_WORK(&usb_tx_submit_work, usb_tx_submit_worker, NULL);
	InitializeListHead(&usb_tx_submit_list);
	return 0;
}

void usb_exit(void)
{
	/* TODO: free all urbs? */
	return;
}

static struct urb *wrap_alloc_urb(unsigned int mem_flags, struct irp *irp,
				  struct usb_device *dev,
				  int transfer_buffer_length)
{
	struct urb *urb;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	urb = usb_alloc_urb(0);
#else
	urb = usb_alloc_urb(0, mem_flags);
#endif
	if (!urb) {
		WARNING("couldn't allocate urb");
		return NULL;
	}
	irp->urb = urb;
	irp->cancel_routine = usb_cancel_transfer;
	if (transfer_buffer_length) {
		urb->transfer_buffer =
			usb_buffer_alloc(dev, transfer_buffer_length,
					 mem_flags, &urb->transfer_dma);
		if (!urb->transfer_buffer) {
			WARNING("couldn't allocate dma buf");
			usb_free_urb(urb);
			return NULL;
		}
		urb->transfer_buffer_length = transfer_buffer_length;
		urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	} else
		urb->transfer_buffer = NULL;
	urb->context = irp;
	return urb;
}

static void wrap_free_urb(struct urb *urb)
{
	struct irp *irp;

	irp = urb->context;
	irp->cancel_routine = NULL;
	if (urb->transfer_buffer)
		usb_buffer_free(urb->dev, urb->transfer_buffer_length, 
				urb->transfer_buffer, urb->transfer_dma);
	if (urb->setup_packet)
		kfree(urb->setup_packet);
//		usb_buffer_free(urb->dev, sizeof(struct usb_ctrlrequest),
//				urb->setup_packet, urb->setup_dma);
	usb_free_urb(urb);
	irp->urb = NULL;
	return;
}

static inline void wrap_submit_urb(struct urb *urb, unsigned int mem_flags)
{
	KIRQL irql;
	struct irp *irp;

	USBTRACE("irp: %p, urb: %p", urb->context, urb);

	irp = urb->context;
	IoAcquireCancelSpinLock(&irql);
	InsertTailList(&usb_tx_submit_list, &irp->tx_submit_list);
	IoReleaseCancelSpinLock(irql);

	return;
}

static void usb_tx_submit_worker(void *data)
{
	int ret;
	KIRQL irql;
	struct irp *irp;
	struct urb *urb;
	struct nt_list *ent;

	while (1) {
		IoAcquireCancelSpinLock(&irql);
		ent = RemoveHeadList(&usb_tx_submit_list);
		if (ent) {
			irp = container_of(ent, struct irp, tx_submit_list);
			InitializeListHead(&irp->tx_submit_list);
		} else
			irp = NULL;
		IoReleaseCancelSpinLock(irql);
		if (!irp)
			break;
		urb = irp->urb;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
		ret = usb_submit_urb(urb);
#else
		ret = usb_submit_urb(urb, GFP_ATOMIC);
#endif
		USBTRACE("ret: %d", ret);
		if (ret)
			wrap_free_urb(urb);
	}
	return;
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
	case -ENOMEM:
		return USBD_STATUS_NO_MEMORY;
	default:
		return USBD_STATUS_NOT_SUPPORTED;
	}
}

int nt_urb_irp_status(int nt_urb_status)
{
	switch (nt_urb_status) {
	case USBD_STATUS_SUCCESS:
		return STATUS_SUCCESS;
	case USBD_STATUS_DEVICE_GONE:
		return STATUS_DEVICE_REMOVED;
	case USBD_STATUS_PENDING:
		return STATUS_PENDING;
	case USBD_STATUS_NOT_SUPPORTED:
		return STATUS_NOT_IMPLEMENTED;
	case USBD_STATUS_NO_MEMORY:
		return STATUS_NO_MEMORY;
	default:
		return STATUS_FAILURE;
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
void usb_transfer_complete(struct urb *urb, struct pt_regs *regs)
#else
void usb_transfer_complete(struct urb *urb)
#endif
{
	struct irp *irp;
	KIRQL irql;

	irp = urb->context;
	IoAcquireCancelSpinLock(&irp->cancel_irql);
	irp->cancel_routine = NULL;
	IoReleaseCancelSpinLock(irp->cancel_irql);
	USBTRACE("urb: %p, irp: %p", urb, irp);

	irql = kspin_lock_irql(&usb_tx_complete_list_lock, DISPATCH_LEVEL);
	InsertTailList(&usb_tx_complete_list, &irp->list);
	kspin_unlock_irql(&usb_tx_complete_list_lock, irql);
	schedule_work(&usb_tx_complete_work);
	return;
}
STDCALL void usb_cancel_transfer(struct device_object *dev_obj,
				 struct irp *irp)
{
	struct urb *urb;

	USBTRACEENTER("irp = %p", irp);
	urb = irp->urb;
	USBTRACE("canceling urb %p", urb);

	/* NB: this function is called holding irp_cancel_lock */
	RemoveEntryList(&usb_tx_submit_list);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
	if (irp->cancel_irql < DISPATCH_LEVEL) {
		IoReleaseCancelSpinLock(irp->cancel_irql);
		usb_kill_urb(urb);
	} else
#endif
	{
		urb->transfer_flags |= URB_ASYNC_UNLINK;
		if (usb_unlink_urb(urb) != -EINPROGRESS)
			WARNING("usb_unlink_urb returns %d", urb->status);
		IoReleaseCancelSpinLock(irp->cancel_irql);
	}
}

static void usb_tx_complete_worker(void *data)
{
	struct usbd_bulk_or_intr_transfer *bulk_int_tx;
	struct usbd_vendor_or_class_request *vc_req;
	union nt_urb *nt_urb;
	struct irp *irp;
	struct urb *urb;
	KIRQL irql;

	while (1) {
		struct nt_list *ent;

		irql = kspin_lock_irql(&usb_tx_complete_list_lock,
				       DISPATCH_LEVEL);
		ent = RemoveHeadList(&usb_tx_complete_list);
		kspin_unlock_irql(&usb_tx_complete_list_lock, irql);
		if (!ent)
			break;
		irp = container_of(ent, struct irp, list);
		urb = irp->urb;
		DUMP_URB(urb);
		DUMP_IRP(irp);
		nt_urb = URB_FROM_IRP(irp);
		USBTRACE("urb: %p, nt_urb: %p, status: %d",
			 urb, nt_urb, -(urb->status));

		switch (urb->status) {
		case 0:
			/* succesfully transferred */
			NT_URB_STATUS(nt_urb) = wrap_urb_status(urb->status);
			irp->io_status.status = STATUS_SUCCESS;
			irp->io_status.status_info = urb->actual_length;

			switch (nt_urb->header.function) {
			case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
				bulk_int_tx = &nt_urb->bulk_int_transfer;
				bulk_int_tx->transfer_buffer_length =
					urb->actual_length;
				if (urb->transfer_buffer &&
				    USBD_DIRECTION_IN(bulk_int_tx->transfer_flags))
					memcpy(bulk_int_tx->transfer_buffer,
					       urb->transfer_buffer,
					       urb->actual_length);
				DUMP_BUFFER(urb->transfer_buffer,
					    urb->actual_length);
				break;

			case URB_FUNCTION_VENDOR_DEVICE:
			case URB_FUNCTION_VENDOR_INTERFACE:
			case URB_FUNCTION_CLASS_INTERFACE:
				vc_req = &nt_urb->vendor_class_request;
				vc_req->transfer_buffer_length =
					urb->actual_length;
				if (urb->transfer_buffer &&
				    USBD_DIRECTION_IN(vc_req->transfer_flags))
					memcpy(vc_req->transfer_buffer,
					       urb->transfer_buffer,
					       urb->actual_length);
				DUMP_BUFFER(urb->transfer_buffer,
					    urb->actual_length);
				DUMP_BUFFER(urb->setup_packet, 4);
				break;
			default:
				WARNING("nt_urb type: %d unknown",
					nt_urb->header.function);
				break;
			}
			USBTRACE("irp: %p, status: %d (%08X)",
				 irp, urb->status, irp->io_status.status);
			break;
		case -ENOENT:
		case -ECONNRESET:
			/* irp canceled */
			NT_URB_STATUS(nt_urb) = USBD_STATUS_CANCELLED;
			irp->io_status.status = STATUS_CANCELLED;
			irp->io_status.status_info = 0;
			USBTRACE("irp %p canceled", irp);
			break;
		default:
			NT_URB_STATUS(nt_urb) = wrap_urb_status(urb->status);
			irp->io_status.status =
				nt_urb_irp_status(NT_URB_STATUS(nt_urb));
			irp->io_status.status_info = 0;
			WARNING("irp: %p, status: %08X",
				irp, irp->io_status.status);
			break;
		}
		wrap_free_urb(urb);
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
}

USBD_STATUS usb_bulk_or_intr_trans(struct usb_device *dev,
				   union nt_urb *nt_urb, struct irp *irp)
{
	union pipe_handle *pipe_handle;
	struct urb *urb;
	unsigned int pipe;
	int ret;
	UCHAR endpoint;
	struct usbd_bulk_or_intr_transfer *bulk_int_tx;

	bulk_int_tx = &nt_urb->bulk_int_transfer;
	ASSERT(!bulk_int_tx->transfer_buffer_mdl);
	ASSERT(!bulk_int_tx->urb_link);
	USBTRACE("flags = %X, length = %u, buffer = %p",
		  bulk_int_tx->transfer_flags,
		  bulk_int_tx->transfer_buffer_length,
		  bulk_int_tx->transfer_buffer);

	DUMP_IRP(irp);
	urb = wrap_alloc_urb(GFP_ATOMIC, irp, dev,
			     bulk_int_tx->transfer_buffer_length);
	if (!urb)
		return -ENOMEM;

	pipe_handle = &bulk_int_tx->pipe_handle;
	endpoint = pipe_handle->encoded.endpoint;
	if (bulk_int_tx->transfer_buffer_length > 0 &&
	    USBD_DIRECTION_OUT(bulk_int_tx->transfer_flags))
		memcpy(urb->transfer_buffer, bulk_int_tx->transfer_buffer,
		       bulk_int_tx->transfer_buffer_length);

	/* TODO: at least for interrupt urbs, we should avoid
	 * allocating/freeing dma every time */

	ret = NT_URB_STATUS(nt_urb) = USBD_STATUS_PENDING;
	irp->pending_returned = TRUE;
	IoMarkIrpPending(irp);
	irp->io_status.status = STATUS_PENDING;

	switch(pipe_handle->encoded.type) {
	case USB_ENDPOINT_XFER_BULK:
		if (USBD_DIRECTION_IN(bulk_int_tx->transfer_flags))
			pipe = usb_rcvbulkpipe(dev, endpoint);
		else
			pipe = usb_sndbulkpipe(dev, endpoint);

		usb_fill_bulk_urb(urb, dev, pipe, urb->transfer_buffer,
				  bulk_int_tx->transfer_buffer_length,
				  usb_transfer_complete, urb->context);
		USBTRACE("submitting urb %p on pipe %p",
			urb, pipe_handle->handle);
		DUMP_URB(urb);

		wrap_submit_urb(urb, GFP_ATOMIC);
		USBTRACE("ret: %d", ret);
		break;
	case USB_ENDPOINT_XFER_INT:
		if (USBD_DIRECTION_IN(bulk_int_tx->transfer_flags))
			pipe = usb_rcvintpipe(dev, endpoint);
		else
			pipe = usb_sndintpipe(dev, endpoint);

		usb_fill_int_urb(urb, dev, pipe, urb->transfer_buffer,
				 bulk_int_tx->transfer_buffer_length,
				 usb_transfer_complete, urb->context,
				 pipe_handle->encoded.interval);
		USBTRACE("submitting urb %p on pipe %p",
				urb, pipe_handle->handle);
		DUMP_URB(urb);
		wrap_submit_urb(urb, GFP_ATOMIC);
		USBTRACE("ret: %d", ret);
		break;
	default:
		ERROR("unknown pipe type: %d", pipe_handle->encoded.type);
		ret = -EINVAL;
		NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
	}

	USBTRACEEXIT(return ret);
}

USBD_STATUS usb_vendor_or_class_req(struct usb_device *dev,
				    union nt_urb *nt_urb, struct irp *irp)
{
	struct urb *urb;
	struct usb_ctrlrequest *dr;
	char req_type;
	unsigned int pipe;
	int ret;
	struct usbd_vendor_or_class_request *vc_req;
	u16 buf_len;

	vc_req = &nt_urb->vendor_class_request;
	ASSERT(!vc_req->transfer_buffer_mdl);
	ASSERT(!vc_req->urb_link);
	USBTRACE("bits = %x, req = %x, val = %08x, index = %08x, flags = %x,"
		 "tx_buf = %p, tx_buf_len = %d", vc_req->reserved_bits,
		 vc_req->request, vc_req->value, vc_req->index,
		 vc_req->transfer_flags, vc_req->transfer_buffer,
		 vc_req->transfer_buffer_length);

	switch (nt_urb->header.function) {
	case URB_FUNCTION_VENDOR_DEVICE:
		req_type = USB_TYPE_VENDOR | USB_RECIP_DEVICE;
		break;
	case URB_FUNCTION_VENDOR_INTERFACE:
		req_type = USB_TYPE_VENDOR | USB_RECIP_INTERFACE;
		break;
	case URB_FUNCTION_VENDOR_ENDPOINT:
		req_type = USB_TYPE_VENDOR | USB_RECIP_ENDPOINT;
		break;
	case URB_FUNCTION_VENDOR_OTHER:
		req_type = USB_TYPE_VENDOR | USB_RECIP_OTHER;
		break;
	case URB_FUNCTION_CLASS_DEVICE:
		req_type = USB_TYPE_CLASS | USB_RECIP_DEVICE;
		break;
	case URB_FUNCTION_CLASS_INTERFACE:
		req_type = USB_TYPE_CLASS | USB_RECIP_INTERFACE;
		break;
	case URB_FUNCTION_CLASS_ENDPOINT:
		req_type = USB_TYPE_CLASS | USB_RECIP_ENDPOINT;
		break;
	case URB_FUNCTION_CLASS_OTHER:
		req_type = USB_TYPE_CLASS | USB_RECIP_OTHER;
		break;
	default:
		ERROR("unknown request type: %x", nt_urb->header.function);
		req_type = 0;
	}

	req_type |= vc_req->reserved_bits;

	USBTRACE("short tx: %d",
		 vc_req->transfer_flags & USBD_SHORT_TRANSFER_OK);

	urb = wrap_alloc_urb(GFP_ATOMIC, irp, dev,
			     vc_req->transfer_buffer_length);
	if (!urb) {
		ERROR("couldn't allocate urb");
		return -ENOMEM;
	}
	if (USBD_DIRECTION_IN(vc_req->transfer_flags)) {
		pipe = usb_rcvctrlpipe(dev, 0);
		req_type |= USB_DIR_IN;
		USBTRACE("pipe: %u, dir in", pipe);
	} else {
		pipe = usb_sndctrlpipe(dev, 0);
		req_type |= USB_DIR_OUT;
		memcpy(urb->transfer_buffer, vc_req->transfer_buffer,
		       vc_req->transfer_buffer_length);
		USBTRACE("pipe: %u, dir out", pipe);
	}

	USBTRACE("req type: %08x", req_type);
	if (!(vc_req->transfer_flags & USBD_SHORT_TRANSFER_OK)) {
		USBTRACE("short not ok");
		urb->transfer_flags |= URB_SHORT_NOT_OK;
	}

//	dr = usb_buffer_alloc(dev, sizeof(*dr), GFP_ATOMIC, &urb->setup_dma);
	dr = kmalloc(sizeof(*dr), GFP_ATOMIC);
	if (!dr) {
		ERROR("couldn't allocate dma buffer");
		wrap_free_urb(urb);
		ret = NT_URB_STATUS(nt_urb) = USBD_STATUS_NO_MEMORY;
		irp->io_status.status = nt_urb_irp_status(ret);
		irp->io_status.status_info = 0;
		return ret;
	}
	memset(dr, 0, sizeof(*dr));
//	urb->transfer_flags |= URB_NO_SETUP_DMA_MAP;

	dr->bRequestType = req_type;
	dr->bRequest = vc_req->request;
	dr->wValue = cpu_to_le16p(&vc_req->value);
	dr->wIndex = cpu_to_le16p(&vc_req->index);
	buf_len = vc_req->transfer_buffer_length;
	dr->wLength = cpu_to_le16p(&buf_len);

	usb_fill_control_urb(urb, dev, pipe, (unsigned char *)dr,
			     urb->transfer_buffer,
			     vc_req->transfer_buffer_length,
			     usb_transfer_complete, urb->context);

	ret = NT_URB_STATUS(nt_urb) = USBD_STATUS_PENDING;
	irp->pending_returned = TRUE;
	IoMarkIrpPending(irp);
	irp->io_status.status = STATUS_PENDING;
	DUMP_URB(urb);
	wrap_submit_urb(urb, GFP_ATOMIC);
	USBTRACE("ret: %d", ret);
	USBTRACEEXIT(return ret);
}

unsigned long usb_reset_pipe(struct usb_device *dev, struct irp *irp)
{
	unsigned int pipe;
	UCHAR endpoint;
	int ret;
	union nt_urb *nt_urb;
	union pipe_handle* pipe_handle;

	USBTRACE("irp = %p", irp);
	nt_urb = URB_FROM_IRP(irp);
	pipe_handle = &nt_urb->pipe_req.pipe_handle;
	endpoint = pipe_handle->encoded.endpoint;
	if (pipe_handle->encoded.endpoint & USB_ENDPOINT_DIR_MASK)
		pipe = usb_rcvctrlpipe(dev, endpoint);
	else
		pipe = usb_sndctrlpipe(dev, endpoint);
	ret = usb_clear_halt(dev, pipe);
	NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
	return ret;
}

unsigned long usb_select_configuration(struct wrapper_dev *wd,
				       union nt_urb *nt_urb, struct irp *irp)
{
	struct usbd_pipe_information *pipe_info;
	int i, ret;
	struct usb_endpoint_descriptor *desc;
	struct usbd_select_configuration *sel_conf;
	struct usb_device *dev;
	struct usbd_interface_information *intf;
	struct usb_config_descriptor *config;
	struct usb_interface *usb_intf;

	dev = wd->dev.usb;
	sel_conf = &nt_urb->select_conf;
	intf = &sel_conf->intf;
	config = sel_conf->config;
	if (sel_conf->config == NULL) {
		/* TODO: driver is stopping the device, process it */
		return 0;
	}
	ASSERT(sel_conf->config->bNumInterfaces == 1);
	USBTRACE("intf.ifnum = %d, intf.alt_setting = %d",
		 intf->ifnum, intf->alt_setting);

	USBTRACE("new intf: num: %d, alt_setting: %d, length: %d, type: %d,"
		 "total: %d, numif: %d, attr: %08x, conf value: %d",
		 intf->ifnum, intf->alt_setting, config->bLength,
		 config->bDescriptorType, config->wTotalLength,
		 config->bNumInterfaces, config->bmAttributes,
		 config->bConfigurationValue);

	ret = usb_control_msg(dev, usb_sndctrlpipe(dev, 0),
			      USB_REQ_SET_CONFIGURATION, 0,
			      config->bConfigurationValue, 0,
			      NULL, 0, USB_CTRL_SET_TIMEOUT);
	if (ret < 0) {
		ERROR("ret: %d", ret);
		USBTRACEEXIT(return ret);
	}
#if 1
	ret = usb_set_interface(dev, intf->ifnum, intf->alt_setting);
	if (ret < 0) {
		ERROR("usb_set_interface failed with %d", ret);
		USBTRACEEXIT(return ret);
	}
	usb_intf = usb_ifnum_to_if(dev, sel_conf->intf.ifnum);
	if (!usb_intf) {
		ERROR("usb_ifnum_to_if failed with %d", ret);
		USBTRACEEXIT(return ret);
	}
	wd->dev.usb = interface_to_usbdev(usb_intf);
	usb_set_intfdata(usb_intf, wd);
#else
	usb_intf = wd->intf;
#endif

	USBTRACE("intf: %p, handle: %p", intf, sel_conf->handle);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	for (i = 0; i < CUR_ALT_SETTING(usb_intf)->desc.bNumEndpoints; i++) {
		desc = &(CUR_ALT_SETTING(usb_intf)->endpoint + i)->desc;
#else
	for (i = 0; i < CUR_ALT_SETTING(usb_intf).bNumEndpoints; i++) {
		desc = &((CUR_ALT_SETTING(usb_intf)).endpoint[i]);
#endif
		pipe_info = &sel_conf->intf.pipes[i];

		pipe_info->max_pkt_size = desc->wMaxPacketSize;
		pipe_info->endpoint = desc->bEndpointAddress;
		pipe_info->interval = desc->bInterval;
		pipe_info->type = desc->bmAttributes;

		pipe_info->handle.encoded.endpoint =
			desc->bEndpointAddress;
		pipe_info->handle.encoded.type =
			desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
		pipe_info->handle.encoded.interval =
			/* TODO: for high speed, interval is between 1
			 * and 16; why are we adding 3 for high speed
			 * devices? */
//			desc->bInterval;
			(dev->speed == USB_SPEED_HIGH) ?
			desc->bInterval + 3 : desc->bInterval;
		pipe_info->handle.encoded.fill = 0;
//		pipe_info->handle.handle = &pipe_info->handle;

		USBTRACE("%d: addr %X, type %d, pkt_sz %d, intv %d, handle %p",
			 i, desc->bEndpointAddress, desc->bmAttributes,
			 desc->wMaxPacketSize, desc->bInterval,
			 pipe_info->handle.handle);
	}
	USBTRACEEXIT(return 0);
}

NTSTATUS usb_submit_nt_urb(struct wrapper_dev *wd, struct irp *irp)
{
	struct usbd_control_descriptor_request *ctrl_req;
	int ret;
	char *buf;
	union nt_urb *nt_urb;
	struct usb_device *dev;

	dev = wd->dev.usb;
	nt_urb = URB_FROM_IRP(irp);
	USBTRACEENTER("nt_urb = %p, irp = %p, length = %d, function = %x",
		      nt_urb, irp, nt_urb->header.length,
		      nt_urb->header.function);

	DUMP_IRP(irp);
	ret = 0;
	switch (nt_urb->header.function) {
	case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
		ret = usb_bulk_or_intr_trans(dev, nt_urb, irp);
		/* status for NT_URB and IRP are already set */
		break;

	case URB_FUNCTION_VENDOR_DEVICE:
	case URB_FUNCTION_VENDOR_INTERFACE:
	case URB_FUNCTION_VENDOR_ENDPOINT:
	case URB_FUNCTION_VENDOR_OTHER:
	case URB_FUNCTION_CLASS_DEVICE:
	case URB_FUNCTION_CLASS_INTERFACE:
	case URB_FUNCTION_CLASS_ENDPOINT:
	case URB_FUNCTION_CLASS_OTHER:
		USBTRACE("func: %d", nt_urb->header.function);
		ret = usb_vendor_or_class_req(dev, nt_urb, irp);
		/* status for NT_URB and IRP are already set */
		break;

	case URB_FUNCTION_SELECT_CONFIGURATION:
		ret = usb_select_configuration(wd, nt_urb, irp);
		if (ret < 0)
			NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
		else
			NT_URB_STATUS(nt_urb) = USBD_STATUS_SUCCESS;
		break;

	case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
		ctrl_req = &nt_urb->control_request;
		ASSERT(!ctrl_req->transfer_buffer_mdl);
		ASSERT(!ctrl_req->urb_link);
		USBTRACE("desctype = %d, descindex = %d, transfer_buffer = %p,"
			 "transfer_buffer_length = %d", ctrl_req->desc_type,
			 ctrl_req->index, ctrl_req->transfer_buffer,
			 ctrl_req->transfer_buffer_length);

		buf = kmalloc(ctrl_req->transfer_buffer_length, GFP_ATOMIC);
		if (!buf) {
			ERROR("couldn't allocate memory");
			break;
		}
		/* TODO: find out if usb_get_string or usb_string need
		 * to be used from langid */
		if (ctrl_req->desc_type == USB_DT_STRING) {
			USBTRACE("langid: %d", ctrl_req->language_id);
			ret = usb_get_string(dev, ctrl_req->language_id,
					     ctrl_req->index, buf,
					     ctrl_req->transfer_buffer_length);
		} else
			ret = usb_get_descriptor(dev, ctrl_req->desc_type,
						 ctrl_req->index, buf,
						 ctrl_req->transfer_buffer_length);
		if (ret < 0) {
			WARNING("usb_get_descriptor failed with %d", ret);
			NT_URB_STATUS(nt_urb) = USBD_STATUS_REQUEST_FAILED;
			ctrl_req->transfer_buffer_length = 0;
		} else {
			USBTRACE("ret: %08x", ret);
			DUMP_BUFFER(buf, ret);
			memcpy(ctrl_req->transfer_buffer, buf, ret);
			ctrl_req->transfer_buffer_length = ret;
			irp->io_status.status_info = ret;
			NT_URB_STATUS(nt_urb) = USBD_STATUS_SUCCESS;
		}
		kfree(buf);
		break;

	case URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL:
		ret = usb_reset_pipe(dev, irp);
		break;
	default:
		ERROR("function %X NOT IMPLEMENTED!\n",
		      nt_urb->header.function);
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NOT_SUPPORTED;
		break;
	}
	ret = NT_URB_STATUS(nt_urb);
	if (ret == USBD_STATUS_PENDING)
		return STATUS_PENDING;
	ret = irp->io_status.status = nt_urb_irp_status(ret);
	USBTRACE("ret: %08X", ret);
	USBTRACEEXIT(return ret);
}

NTSTATUS usb_reset_port(struct usb_device *dev, struct irp *irp)
{
	int ret;
	union nt_urb *nt_urb;

	USBTRACEENTER("%s", "");

	nt_urb = URB_FROM_IRP(irp);
	ret = usb_reset_device(dev);
	if (ret < 0)
		ERROR("usb_reset_device() = %d", ret);
	NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
	ret = nt_urb_irp_status(NT_URB_STATUS(nt_urb));
	irp->io_status.status = ret;
	USBTRACEEXIT(return ret);
}

NTSTATUS usb_submit_irp(struct device_object *pdo, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrapper_dev *wd;
	int ret;
	union nt_urb *nt_urb;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wd = pdo->reserved;

	switch (irp_sl->params.ioctl.code) {
	case IOCTL_INTERNAL_USB_SUBMIT_URB:
		ret = usb_submit_nt_urb(wd, irp);
		break;

	case IOCTL_INTERNAL_USB_RESET_PORT:
		ret = usb_reset_port(wd->dev.usb, irp);
		break;
	default:
 		ERROR("ioctl %08X NOT IMPLEMENTED!",
		      irp_sl->params.ioctl.code);
 		ret = STATUS_INVALID_DEVICE_REQUEST;
		irp->io_status.status = ret;
		irp->io_status.status_info = 0;
		nt_urb = URB_FROM_IRP(irp);
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NOT_SUPPORTED;
	}

	USBTRACE("ret: %d", ret);
	return ret;

}

STDCALL union nt_urb *WRAP_EXPORT(USBD_CreateConfigurationRequestEx)
	(struct usb_config_descriptor *config,
	 struct usbd_interface_list_entry *intf_list)
{
	union nt_urb *nt_urb;
	int nt_urb_size, i;
	struct usb_interface_descriptor *intf_desc;
	struct usbd_interface_information *intf_info;

	/* from WDM, it seems this function is called after
	 * select_configuration, so much of the needed information is
	 * already stored in config */
	USBTRACEENTER("config = %p, intf_list = %p", config, intf_list);
	ASSERT(config->bNumInterfaces < 2);

	intf_desc = intf_list->intf_desc;
	nt_urb_size = sizeof(*nt_urb) +
		sizeof(struct usbd_pipe_information) *
		(intf_desc->bNumEndpoints - 1);
	nt_urb = ExAllocatePoolWithTag(NonPagedPool, nt_urb_size,
				       POOL_TAG('U', 'S', 'B', 0));
	if (!nt_urb) {
		WARNING("couldn't allocate memory");
		return NULL;
	}

	nt_urb->select_conf.header.length = nt_urb_size;
	nt_urb->select_conf.header.function =
		URB_FUNCTION_SELECT_CONFIGURATION;
	nt_urb->select_conf.config = config;

	intf_info = &nt_urb->select_conf.intf;
	intf_list->intf = intf_info;
	intf_info->length = sizeof(struct usbd_interface_information)+
		sizeof(struct usbd_pipe_information) *
		(intf_desc->bNumEndpoints - 1);
	intf_info->ifnum = intf_desc->bInterfaceNumber;
	intf_info->alt_setting = intf_desc->bAlternateSetting;
	intf_info->class = intf_desc->bInterfaceClass;
	intf_info->sub_class = intf_desc->bInterfaceSubClass;
	intf_info->proto = intf_desc->bInterfaceProtocol;
	intf_info->pipe_num = intf_desc->bNumEndpoints;
	for (i = 0; i < intf_info->pipe_num - 1; i++) {
		struct usbd_pipe_information *pipe;
		pipe = &intf_info->pipes[i];
		USBTRACE("pipe handle: %p, type: %d",
			 pipe->handle.handle, pipe->type);
		pipe->max_pkt_size = USBD_DEFAULT_MAXIMUM_TRANSFER_SIZE;
	}

	ASSERT(!(intf_list+1)->intf_desc);

	USBTRACEEXIT(return nt_urb);
}
WRAP_EXPORT_MAP("_USBD_CreateConfigurationRequestEx@8",	USBD_CreateConfigurationRequestEx);

STDCALL struct usb_interface_descriptor *
	WRAP_EXPORT(USBD_ParseConfigurationDescriptorEx)
	(struct usb_config_descriptor *config, void *start, LONG ifnum,
	 LONG alt_setting, LONG class, LONG subclass, LONG proto)
{
	char *pos;
	struct usb_interface_descriptor *intf;

	USBTRACEENTER("config = %p, start = %p, ifnum = %d, alt_setting = %d,"
		      " class = %d, subclass = %d, proto = %d", config, start,
		      ifnum, alt_setting, class, subclass, proto);

	pos = start;
	while (((char *)pos - (char *)config) < config->wTotalLength) {
		intf = (struct usb_interface_descriptor *)pos;

		if ((intf->bDescriptorType == USB_DT_INTERFACE) &&
		    ((ifnum == -1) || (intf->bInterfaceNumber == ifnum)) &&
		    ((alt_setting == -1) ||
		     (intf->bAlternateSetting == alt_setting)) &&
		    ((class == -1) || (intf->bInterfaceClass == class)) &&
		    ((subclass == -1) ||
		     (intf->bInterfaceSubClass == subclass)) &&
		    ((proto == -1) || (intf->bInterfaceProtocol == proto))) {
			USBTRACE("selected interface = %p", intf);
			USBTRACEEXIT(return intf);
		}
		pos = pos + intf->bLength;
	}

	USBTRACEEXIT(return NULL);
}
WRAP_EXPORT_MAP("_USBD_ParseConfigurationDescriptorEx@28", USBD_ParseConfigurationDescriptorEx);

STDCALL union nt_urb *WRAP_EXPORT(USBD_CreateConfigurationRequest)
	(struct usb_config_descriptor *config, unsigned short *nt_urb_size)
{
	union nt_urb *nt_urb;
	struct usb_interface_descriptor *intf_desc = NULL;
	struct usbd_interface_list_entry intf_list;

	USBTRACEENTER("config = %p, urb_size = %p", config, nt_urb_size);
	ASSERT(config->bNumInterfaces < 2);

	intf_desc = USBD_ParseConfigurationDescriptorEx(config, config, -1, -1,
							-1, -1, -1);
	*nt_urb_size = sizeof(*nt_urb) +
		sizeof(struct usbd_pipe_information) *
		(intf_desc->bNumEndpoints - 1);
	intf_list.intf_desc = intf_desc;
	nt_urb = USBD_CreateConfigurationRequestEx(config, &intf_list);
	USBTRACEEXIT(return nt_urb);
}

STDCALL struct usb_interface_descriptor *
	WRAP_EXPORT(USBD_ParseConfigurationDescriptor)
	(struct usb_config_descriptor *config,
	 unsigned char ifnum, unsigned char alt_setting)
{
	return USBD_ParseConfigurationDescriptorEx(config, config, ifnum,
						   alt_setting, -1, -1, -1);
}

#include "usb_exports.h"
