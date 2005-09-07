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
static struct nt_list usb_tx_complete_list;
static void usb_tx_complete_worker(void *data);
static struct work_struct usb_tx_complete_work;

static struct nt_list usb_tx_submit_list;
static void usb_tx_submit_worker(void *data);
struct work_struct usb_tx_submit_work;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static inline void *usb_buffer_alloc(struct usb_device *dev, size_t size,
				     unsigned mem_flags, dma_addr_t *dma)
{
	void *buf;
	/* TODO: provide dma buffer? */
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

#ifdef DUMPURBS
int urb_num;

#define DUMP_URB(urb) do {						\
		USBTRACE("urb: %p, buf: %p, len: %d, pipe: %u",		\
			 urb, urb->transfer_buffer,			\
			 urb->transfer_buffer_length, urb->pipe);	\
	} while (0)

#define DUMP_BUFFER(buf, len)						\
	do {								\
		int __i;						\
		char __msg[100], *__t;					\
		if (!buf)						\
			break;						\
		__t = __msg;						\
		for (__i = 0; __i < len &&				\
			     __t < &__msg[sizeof(__msg) - 4]; __i++) {	\
			__t += sprintf(__t, "%02X ",			\
				       (((UCHAR *)buf)[__i]));		\
		}							\
		USBTRACE("%s", __msg);					\
	} while (0)

#else
#define DUMP_URB(urb)
#define DUMP_BUFFER(buf, len)
#endif /* DUMPURBS */

int usb_init(void)
{
	INIT_WORK(&usb_tx_complete_work, usb_tx_complete_worker, NULL);
	InitializeListHead(&usb_tx_complete_list);

	INIT_WORK(&usb_tx_submit_work, usb_tx_submit_worker, NULL);
	InitializeListHead(&usb_tx_submit_list);
	return 0;
}

void usb_exit(void)
{
	return;
}

int usb_init_device(struct wrapper_dev *wd)
{
	wd->dev.usb.pipes = NULL;
	return 0;
}

void usb_exit_device(struct wrapper_dev *wd)
{
	if (wd->dev.usb.pipes)
		kfree(wd->dev.usb.pipes);
	wd->dev.usb.pipes = NULL;
	return;
}

static struct urb *wrap_alloc_urb(unsigned int mem_flags, struct irp *irp,
				  struct usb_device *udev, int buf_len)
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
	urb->context = irp;
	return urb;
}

static void wrap_free_urb(struct urb *urb)
{
	struct irp *irp;

	irp = urb->context;
	irp->cancel_routine = NULL;
	irp->urb = NULL;
	usb_free_urb(urb);
	return;
}

static inline void wrap_submit_urb(struct urb *urb)
{
	KIRQL irql;
	struct irp *irp;
	union nt_urb *nt_urb;

	USBTRACE("irp: %p, urb: %p", urb->context, urb);

	irp = urb->context;
	IoAcquireCancelSpinLock(&irql);
	InsertTailList(&usb_tx_submit_list, &irp->tx_submit_list);
	nt_urb = URB_FROM_IRP(irp);
	NT_URB_STATUS(nt_urb) = USBD_STATUS_PENDING;
	irp->pending_returned = TRUE;
	IoMarkIrpPending(irp);
	irp->io_status.status = STATUS_PENDING;
	IoReleaseCancelSpinLock(irql);
	/* don't schedule work here - pdoDispatchDeviceControl will do
	 * it */
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
		IoReleaseCancelSpinLock(irql);
		if (!ent)
			break;
		irp = container_of(ent, struct irp, tx_submit_list);
		urb = irp->urb;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
		ret = usb_submit_urb(urb);
#else
		ret = usb_submit_urb(urb, GFP_KERNEL);
#endif
		USBTRACE("ret: %d", ret);
		if (ret) {
			if (!usb_clear_halt(urb->dev, urb->pipe))
				ret = usb_submit_urb(urb, GFP_KERNEL);
			if (ret) {
				WARNING("couldn't submit urb: %p", urb);
				wrap_free_urb(urb);
			}
		}
	}
	return;
}

/* for a given Linux urb status code, return corresponding NT urb status */
USBD_STATUS wrap_urb_status(int urb_status)
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

NTSTATUS nt_urb_irp_status(USBD_STATUS nt_urb_status)
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

	irp = urb->context;
	IoAcquireCancelSpinLock(&irp->cancel_irql);
	irp->cancel_routine = NULL;
	InsertTailList(&usb_tx_complete_list, &irp->list);
	IoReleaseCancelSpinLock(irp->cancel_irql);
	USBTRACE("urb: %p, irp: %p", urb, irp);

	schedule_work(&usb_tx_complete_work);
	return;
}
STDCALL void usb_cancel_transfer(struct device_object *dev_obj,
				 struct irp *irp)
{
	struct urb *urb;

	/* NB: this function is called holding irp_cancel_lock */
	USBTRACEENTER("irp = %p", irp);
	urb = irp->urb;
	USBTRACE("canceling urb %p", urb);

	/* TODO: there is a potential problem here: what if the urb
	 * has not been submitted to Linux USB layer yet and is still
	 * in tx_submit queue? We should keep a flag to indicate
	 * status of urb */
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
	struct nt_list *ent;

	while (1) {
		IoAcquireCancelSpinLock(&irql);
		ent = RemoveHeadList(&usb_tx_complete_list);
		IoReleaseCancelSpinLock(irql);
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
				DUMP_BUFFER(urb->transfer_buffer,
					    urb->actual_length);
				break;
			case URB_FUNCTION_VENDOR_DEVICE:
			case URB_FUNCTION_VENDOR_INTERFACE:
			case URB_FUNCTION_VENDOR_ENDPOINT:
			case URB_FUNCTION_VENDOR_OTHER:
			case URB_FUNCTION_CLASS_DEVICE:
			case URB_FUNCTION_CLASS_INTERFACE:
			case URB_FUNCTION_CLASS_ENDPOINT:
			case URB_FUNCTION_CLASS_OTHER:
				vc_req = &nt_urb->vendor_class_request;
				vc_req->transfer_buffer_length =
					urb->actual_length;
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
			WARNING("irp: %p, urb: %p, status: %08X",
				irp, urb, irp->io_status.status);
			break;
		}
		wrap_free_urb(urb);
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
}

static void wrap_bulk_or_intr_trans(struct usb_device *udev,
				    union nt_urb *nt_urb, struct irp *irp)
{
	struct urb *urb;
	unsigned int pipe;
	struct usbd_bulk_or_intr_transfer *bulk_int_tx;
	usbd_pipe_handle pipe_handle;

	bulk_int_tx = &nt_urb->bulk_int_transfer;
	ASSERT(!bulk_int_tx->transfer_buffer_mdl);
	ASSERT(!bulk_int_tx->urb_link);
	USBTRACE("flags = %X, buf = %p, len = %d",
		 bulk_int_tx->transfer_flags, bulk_int_tx->transfer_buffer,
		 bulk_int_tx->transfer_buffer_length);

	DUMP_IRP(irp);
	urb = wrap_alloc_urb(GFP_KERNEL, irp, udev,
			     bulk_int_tx->transfer_buffer_length);
	if (!urb) {
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NO_MEMORY;
		return;
	}

	pipe_handle = bulk_int_tx->pipe_handle;
	urb->transfer_buffer = bulk_int_tx->transfer_buffer;
	urb->transfer_buffer_length = bulk_int_tx->transfer_buffer_length;

	if (USBD_DIRECTION_IN(bulk_int_tx->transfer_flags))
		pipe = usb_rcvbulkpipe(udev, pipe_handle->bEndpointAddress);
	else
		pipe = usb_sndbulkpipe(udev, pipe_handle->bEndpointAddress);

#if 1
	if (USBD_DIRECTION_IN(bulk_int_tx->transfer_flags) &&
	    (!(bulk_int_tx->transfer_flags & USBD_SHORT_TRANSFER_OK)))
		urb->transfer_flags |= URB_SHORT_NOT_OK;
#endif

	switch(pipe_handle->pipe_type) {
	case USB_ENDPOINT_XFER_BULK:
		usb_fill_bulk_urb(urb, udev, pipe, urb->transfer_buffer,
				  bulk_int_tx->transfer_buffer_length,
				  usb_transfer_complete, urb->context);
		USBTRACE("submitting urb %p on pipe %u",
			urb, pipe_handle->bEndpointAddress);
		DUMP_URB(urb);
		wrap_submit_urb(urb);
		break;
	case USB_ENDPOINT_XFER_INT:
		usb_fill_int_urb(urb, udev, pipe, urb->transfer_buffer,
				 bulk_int_tx->transfer_buffer_length,
				 usb_transfer_complete, urb->context,
				 pipe_handle->bInterval);
		USBTRACE("submitting urb %p on pipe %u",
				urb, pipe_handle->bEndpointAddress);
		DUMP_URB(urb);
		wrap_submit_urb(urb);
		break;
	default:
		ERROR("unknown pipe type: %d", pipe_handle->pipe_type);
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NOT_SUPPORTED;
	}

	USBTRACEEXIT(return);
}

static void wrap_vendor_or_class_req(struct usb_device *udev,
				     union nt_urb *nt_urb, struct irp *irp)
{
	struct urb *urb;
	struct usb_ctrlrequest *dr;
	char req_type;
	unsigned int pipe;
	struct usbd_vendor_or_class_request *vc_req;

	vc_req = &nt_urb->vendor_class_request;
	ASSERT(!vc_req->transfer_buffer_mdl);
	ASSERT(!vc_req->urb_link);
	USBTRACE("bits = %x, req = %x, val = %08x, index = %08x, flags = %x,"
		 "buf = %p, len = %d, link = %p", vc_req->reserved_bits,
		 vc_req->request, vc_req->value, vc_req->index,
		 vc_req->transfer_flags, vc_req->transfer_buffer,
		 vc_req->transfer_buffer_length, vc_req->link);

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

	if (USBD_DIRECTION_IN(vc_req->transfer_flags)) {
		pipe = usb_rcvctrlpipe(udev, 0);
		req_type |= USB_DIR_IN;
		USBTRACE("pipe: %u, dir in", pipe);
	} else {
		pipe = usb_sndctrlpipe(udev, 0);
		req_type |= USB_DIR_OUT;
		USBTRACE("pipe: %u, dir out", pipe);
	}

	USBTRACE("req type: %08x", req_type);

	if (vc_req->link)
		WARNING("link is not procesed");

#if 0
	ret = usb_control_msg(udev, pipe, vc_req->request, req_type,
			      vc_req->value, vc_req->index,
			      vc_req->transfer_buffer,
			      vc_req->transfer_buffer_length,
			      2 * HZ);
	if (ret < 0)
		irp->io_status.status_info = 0;
	else
		irp->io_status.status_info = ret;
	ret = NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
	irp->io_status.status = nt_urb_irp_status(ret);
	DUMP_URB(urb);
#else
	urb = wrap_alloc_urb(GFP_KERNEL, irp, udev,
			     vc_req->transfer_buffer_length);
	if (!urb) {
		ERROR("couldn't allocate urb");
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NO_MEMORY;
		return;
	}
	urb->transfer_buffer = vc_req->transfer_buffer;
	urb->transfer_buffer_length = vc_req->transfer_buffer_length;

	if (USBD_DIRECTION_IN(vc_req->transfer_flags) &&
	    (!(vc_req->transfer_flags & USBD_SHORT_TRANSFER_OK))) {
		USBTRACE("short not ok");
		urb->transfer_flags |= URB_SHORT_NOT_OK;
	}

	dr = kmalloc(sizeof(*dr), GFP_KERNEL);
	if (!dr) {
		ERROR("couldn't allocate dma buffer");
		wrap_free_urb(urb);
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NO_MEMORY;
		return;
	}
	memset(dr, 0, sizeof(*dr));

	dr->bRequestType = req_type;
	dr->bRequest = vc_req->request;
	dr->wValue = cpu_to_le16p(&vc_req->value);
	dr->wIndex = cpu_to_le16p(&vc_req->index);
	dr->wLength = cpu_to_le16p((u16 *)&vc_req->transfer_buffer_length);

	usb_fill_control_urb(urb, udev, pipe, (unsigned char *)dr,
			     urb->transfer_buffer,
			     vc_req->transfer_buffer_length,
			     usb_transfer_complete, urb->context);

	DUMP_URB(urb);
	wrap_submit_urb(urb);
#endif
	USBTRACEEXIT(return);
}

static void wrap_reset_pipe(struct usb_device *udev, struct irp *irp)
{
	unsigned int pipe;
	usbd_pipe_handle pipe_handle;
	int ret;
	union nt_urb *nt_urb;

	USBTRACE("irp = %p", irp);
	nt_urb = URB_FROM_IRP(irp);
	pipe_handle = nt_urb->pipe_req.pipe_handle;
	if ((pipe_handle->bEndpointAddress & USB_ENDPOINT_DIR_MASK) ==
	    USB_DIR_IN)
		pipe = usb_rcvctrlpipe(udev, pipe_handle->bEndpointAddress);
	else
		pipe = usb_sndctrlpipe(udev, pipe_handle->bEndpointAddress);
	ret = usb_clear_halt(udev, pipe);
	NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
	return;
}

static void wrap_select_configuration(struct wrapper_dev *wd,
				      union nt_urb *nt_urb, struct irp *irp)
{
	struct usbd_pipe_information *pipe;
	int i, n, ret, pipe_num;
	struct usb_endpoint_descriptor *ep;
	struct usbd_select_configuration *sel_conf;
	struct usb_device *udev;
	struct usbd_interface_information *intf;
	struct usb_config_descriptor *config;
	struct usb_interface *usb_intf;

	udev = wd->dev.usb.udev;
	sel_conf = &nt_urb->select_conf;
	config = sel_conf->config;
	if (config == NULL) {
		/* TODO: set to unconfigured state (configuration 0):
		 * is this correctt? */
		ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
				      USB_REQ_SET_CONFIGURATION, 0,
				      0, 0, NULL, 0, USB_CTRL_SET_TIMEOUT);
		NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
		return;
	}

	USBTRACE("conf: %d, type: %d, length: %d, numif: %d, attr: %08x",
		 config->bConfigurationValue, config->bDescriptorType,
		 config->wTotalLength, config->bNumInterfaces,
		 config->bmAttributes);

	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      USB_REQ_SET_CONFIGURATION, 0,
			      config->bConfigurationValue, 0,
			      NULL, 0, USB_CTRL_SET_TIMEOUT);
	if (ret < 0) {
		ERROR("ret: %d", ret);
		NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
		USBTRACEEXIT(return);
	}

	/* first find out total number of endpoints for all interfaces */
	pipe_num = 0;
	intf = &sel_conf->intf; 
	for (n = 0; n < config->bNumInterfaces && intf->bLength > 0; n++) {
		pipe_num += intf->bNumEndpoints;
		intf = (((void *)intf) + intf->bLength);
	}

	USBTRACE("pipes: %d", pipe_num);
	if (wd->dev.usb.pipes)
		kfree(wd->dev.usb.pipes);
	wd->dev.usb.pipes = kmalloc(pipe_num * sizeof(*pipe), GFP_ATOMIC);
	if (!wd->dev.usb.pipes) {
		ERROR("couldn't allocate memory");
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NO_MEMORY;
		USBTRACEEXIT(return);
	}

	pipe_num = 0;
	intf = &sel_conf->intf;
	for (n = 0; n < config->bNumInterfaces && intf->bLength > 0; n++) {
		USBTRACE("intf: %d, alt setting: %d",
			 intf->bInterfaceNumber, intf->bAlternateSetting);
		ret = usb_set_interface(udev, intf->bInterfaceNumber,
					intf->bAlternateSetting);
		if (ret < 0) {
			ERROR("usb_set_interface failed with %d", ret);
			NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
			USBTRACEEXIT(return);
		}
		usb_intf =
			usb_ifnum_to_if(udev, sel_conf->intf.bInterfaceNumber);
		if (!usb_intf) {
			ERROR("usb_ifnum_to_if failed with %d", ret);
			NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
			USBTRACEEXIT(return);
		}

		USBTRACE("intf: %p, num ep: %d", intf, intf->bNumEndpoints);
		for (i = 0; i < intf->bNumEndpoints; i++, pipe_num++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
			ep = &(CUR_ALT_SETTING(usb_intf)->endpoint[i]).desc;
#else
			ep = &((CUR_ALT_SETTING(usb_intf)).endpoint[i]);
#endif
			pipe = &intf->pipes[i];

			if (pipe->flags & USBD_PF_CHANGE_MAX_PACKET)
				WARNING("pkt_sz: %d: %d", pipe->wMaxPacketSize,
					ep->wMaxPacketSize);

			pipe->wMaxPacketSize = ep->wMaxPacketSize;
			USBTRACE("driver wants max_tx_size to %d",
				 pipe->max_tx_size);
			pipe->bEndpointAddress = ep->bEndpointAddress;
			pipe->bInterval = ep->bInterval;
			pipe->pipe_type =
				ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;

			pipe->pipe_handle = &wd->dev.usb.pipes[pipe_num];
			memcpy(pipe->pipe_handle, pipe, sizeof(*pipe));

			USBTRACE("%d: addr %X, type %d, pkt_sz %d, intv %d,"
				 "handle %p", i, ep->bEndpointAddress,
				 ep->bmAttributes, ep->wMaxPacketSize,
				 ep->bInterval, pipe->pipe_handle);
		}
		intf = (((void *)intf) + intf->bLength);
	}
	NT_URB_STATUS(nt_urb) = USBD_STATUS_SUCCESS;
	USBTRACEEXIT(return);
}

static void wrap_get_descriptor(struct wrapper_dev *wd, union nt_urb *nt_urb,
				struct irp *irp)
{
	struct usbd_control_descriptor_request *ctrl_req;
	int ret;
	struct usb_device *udev;

	udev = wd->dev.usb.udev;
	ctrl_req = &nt_urb->control_request;
	ASSERT(!ctrl_req->transfer_buffer_mdl);
	ASSERT(!ctrl_req->urb_link);
	USBTRACE("desctype = %d, descindex = %d, transfer_buffer = %p,"
		 "transfer_buffer_length = %d", ctrl_req->desc_type,
		 ctrl_req->index, ctrl_req->transfer_buffer,
		 ctrl_req->transfer_buffer_length);

	if (ctrl_req->desc_type == USB_DT_STRING) {
		USBTRACE("langid: %d", ctrl_req->language_id);
		ret = usb_get_string(udev, ctrl_req->language_id,
				     ctrl_req->index,
				     ctrl_req->transfer_buffer,
				     ctrl_req->transfer_buffer_length);
	} else
		ret = usb_get_descriptor(udev, ctrl_req->desc_type,
					 ctrl_req->index,
					 ctrl_req->transfer_buffer,
					 ctrl_req->transfer_buffer_length);
	if (ret < 0) {
		WARNING("usb_get_descriptor failed with %d", ret);
		NT_URB_STATUS(nt_urb) = USBD_STATUS_REQUEST_FAILED;
		ctrl_req->transfer_buffer_length = 0;
	} else {
		USBTRACE("ret: %08x", ret);
		DUMP_BUFFER(ctrl_req->transfer_buffer, ret);
		ctrl_req->transfer_buffer_length = ret;
		irp->io_status.status_info = ret;
		NT_URB_STATUS(nt_urb) = USBD_STATUS_SUCCESS;
	}
	USBTRACEEXIT(return);
}

NTSTATUS wrap_process_nt_urb(struct wrapper_dev *wd, struct irp *irp)
{
	union nt_urb *nt_urb;
	struct usb_device *udev;

	udev = wd->dev.usb.udev;
	nt_urb = URB_FROM_IRP(irp);
	USBTRACEENTER("nt_urb = %p, irp = %p, length = %d, function = %x",
		      nt_urb, irp, nt_urb->header.length,
		      nt_urb->header.function);

	DUMP_IRP(irp);
	switch (nt_urb->header.function) {
	case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
		wrap_bulk_or_intr_trans(udev, nt_urb, irp);
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
		wrap_vendor_or_class_req(udev, nt_urb, irp);
		/* status for NT_URB and IRP are already set */
		break;

	case URB_FUNCTION_SELECT_CONFIGURATION:
		wrap_select_configuration(wd, nt_urb, irp);
		break;

	case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
		wrap_get_descriptor(wd, nt_urb, irp);
		break;

	case URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL:
		wrap_reset_pipe(udev, irp);
		break;
	default:
		ERROR("function %X NOT IMPLEMENTED", nt_urb->header.function);
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NOT_SUPPORTED;
		break;
	}
	USBTRACE("status: %08X", NT_URB_STATUS(nt_urb));
	if (NT_URB_STATUS(nt_urb) == USBD_STATUS_PENDING)
		return STATUS_PENDING;
	irp->io_status.status = nt_urb_irp_status(NT_URB_STATUS(nt_urb));
	if (NT_URB_STATUS(nt_urb) != USBD_STATUS_SUCCESS)
		irp->io_status.status_info = 0;
	USBTRACEEXIT(return irp->io_status.status);
}

NTSTATUS wrap_reset_port(struct wrapper_dev *wd, struct irp *irp)
{
	int ret;
	union nt_urb *nt_urb;

	USBTRACEENTER("%p, %p", wd, wd->dev.usb.udev);

	nt_urb = URB_FROM_IRP(irp);
	ret = usb_reset_device(wd->dev.usb.udev);
	if (ret < 0)
		WARNING("reset failed: %d", ret);
	NT_URB_STATUS(nt_urb) = wrap_urb_status(ret);
	irp->io_status.status = nt_urb_irp_status(NT_URB_STATUS(nt_urb));
	USBTRACEEXIT(return irp->io_status.status);
}

NTSTATUS usb_submit_irp(struct device_object *pdo, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrapper_dev *wd;
	NTSTATUS ret;
	union nt_urb *nt_urb;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wd = pdo->reserved;

	switch (irp_sl->params.ioctl.code) {
	case IOCTL_INTERNAL_USB_SUBMIT_URB:
		ret = wrap_process_nt_urb(wd, irp);
		break;

	case IOCTL_INTERNAL_USB_RESET_PORT:
		ret = wrap_reset_port(wd, irp);
		break;
	default:
 		ERROR("ioctl %08X NOT IMPLEMENTED", irp_sl->params.ioctl.code);
 		ret = STATUS_INVALID_DEVICE_REQUEST;
		irp->io_status.status = ret;
		irp->io_status.status_info = 0;
		nt_urb = URB_FROM_IRP(irp);
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NOT_SUPPORTED;
	}

	USBTRACE("ret: %08X", ret);
	return ret;
}

STDCALL union nt_urb *WRAP_EXPORT(USBD_CreateConfigurationRequestEx)
	(struct usb_config_descriptor *config,
	 struct usbd_interface_list_entry *intf_list)
{
	int size, i, n, pipe_num;
	struct usbd_interface_information *intf;
	struct usbd_pipe_information *pipe;
	struct usb_interface_descriptor *intf_desc;
	struct usbd_select_configuration *select_conf;

	USBTRACEENTER("config = %p, intf_list = %p", config, intf_list);

	/* calculate size required; select_conf already has space for
	 * one intf structure */
	size = sizeof(*select_conf) - sizeof(*intf);
	for (n = 0; n < config->bNumInterfaces; n++) {
		pipe_num = intf_list[n].intf_desc->bNumEndpoints;
		/* intf already has space for one pipe */
		size += sizeof(*intf) + (pipe_num - 1) * sizeof(*pipe);
	}
	/* don't use kmalloc - driver frees it with ExFreePool */
	select_conf = ExAllocatePoolWithTag(NonPagedPool, size,
					    POOL_TAG('U', 'S', 'B', 0));
	if (!select_conf) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	memset(select_conf, 0, size);
	intf = &select_conf->intf;
	/* handle points to beginning of interface information */
	select_conf->handle = intf;
	for (n = 0; n < config->bNumInterfaces && intf_list[n].intf_desc;
	     n++) {
		/* initialize 'intf' fields in intf_list so they point
		 * to appropriate entry; these may be read/written by
		 * driver after this function returns */
		intf_list[n].intf = intf;
		intf_desc = intf_list[n].intf_desc;

		pipe_num = intf_desc->bNumEndpoints;
		intf->bLength = sizeof(*intf) + (pipe_num - 1) * sizeof(*pipe);

		intf->bInterfaceNumber = intf_desc->bInterfaceNumber;
		intf->bAlternateSetting = intf_desc->bAlternateSetting;
		intf->bInterfaceClass = intf_desc->bInterfaceClass;
		intf->bInterfaceSubClass = intf_desc->bInterfaceSubClass;
		intf->bInterfaceProtocol = intf_desc->bInterfaceProtocol;
		intf->bNumEndpoints = intf_desc->bNumEndpoints;

		pipe = &intf->pipes[0];
		for (i = 0; i < intf->bNumEndpoints; i++) {
			memset(&pipe[i], 0, sizeof(*pipe));
			pipe[i].max_tx_size =
				USBD_DEFAULT_MAXIMUM_TRANSFER_SIZE;
		}
		intf = (((void *)intf) + intf->bLength);
	}
	select_conf->header.function = URB_FUNCTION_SELECT_CONFIGURATION;
	select_conf->header.length = sizeof(*select_conf);
	select_conf->config = config;
	USBTRACEEXIT(return (union nt_urb *)select_conf);
}
WRAP_EXPORT_MAP("_USBD_CreateConfigurationRequestEx@8",	USBD_CreateConfigurationRequestEx);

STDCALL struct usb_interface_descriptor *
WRAP_EXPORT(USBD_ParseConfigurationDescriptorEx)
	(struct usb_config_descriptor *config, void *start, LONG ifnum,
	 LONG alt_setting, LONG class, LONG subclass, LONG proto)
{
	void *pos;
	struct usb_interface_descriptor *intf;

	USBTRACEENTER("config = %p, start = %p, ifnum = %d, alt_setting = %d,"
		      " class = %d, subclass = %d, proto = %d", config, start,
		      ifnum, alt_setting, class, subclass, proto);

	pos = start;
	while ((pos - (void *)config) < config->wTotalLength) {
		intf = pos;

		if ((intf->bDescriptorType == USB_DT_INTERFACE) &&
		    ((ifnum == -1) ||
		     (intf->bInterfaceNumber == ifnum)) &&
		    ((alt_setting == -1) ||
		     (intf->bAlternateSetting == alt_setting)) &&
		    ((class == -1) ||
		     (intf->bInterfaceClass == class)) &&
		    ((subclass == -1) ||
		     (intf->bInterfaceSubClass == subclass)) &&
		    ((proto == -1) ||
		     (intf->bInterfaceProtocol == proto))) {
			USBTRACE("selected interface = %p", intf);
			USBTRACEEXIT(return intf);
		}
		pos += intf->bLength;
	}

	USBTRACEEXIT(return NULL);
}
WRAP_EXPORT_MAP("_USBD_ParseConfigurationDescriptorEx@28", USBD_ParseConfigurationDescriptorEx);

STDCALL union nt_urb *WRAP_EXPORT(USBD_CreateConfigurationRequest)
	(struct usb_config_descriptor *config, USHORT *size)
{
	union nt_urb *nt_urb;
	struct usbd_interface_list_entry intf_list[2];
	struct usb_interface_descriptor *intf_desc;

	USBTRACEENTER("config = %p, urb_size = %p", config, size);

	intf_desc = USBD_ParseConfigurationDescriptorEx(config, config, -1, -1,
							-1, -1, -1);
	intf_list[0].intf_desc = intf_desc;
	intf_list[0].intf = NULL;
	intf_list[1].intf_desc = NULL;
	intf_list[0].intf = NULL;
	nt_urb = USBD_CreateConfigurationRequestEx(config, intf_list);
	if (!nt_urb)
		return NULL;

	*size = sizeof(*nt_urb) + sizeof(struct usbd_interface_information) +
		(intf_desc->bNumEndpoints - 1) *
		sizeof(struct usbd_pipe_information);

	USBTRACEEXIT(return nt_urb);
}

STDCALL struct usb_interface_descriptor *
WRAP_EXPORT(USBD_ParseConfigurationDescriptor)
	(struct usb_config_descriptor *config, UCHAR ifnum, UCHAR alt_setting)
{
	return USBD_ParseConfigurationDescriptorEx(config, config, ifnum,
						   alt_setting, -1, -1, -1);
}

#include "usb_exports.h"
