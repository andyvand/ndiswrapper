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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#define WRAP_ALLOC_URB(a, b)  usb_alloc_urb(a)
#define WRAP_SUBMIT_URB(a, b) usb_submit_urb(a)

#else

#define WRAP_ALLOC_URB(a, b)  usb_alloc_urb(a, b)
#define WRAP_SUBMIT_URB(a, b) usb_submit_urb(a, b)

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,5)
#define CUR_ALT_SETTING(intf) (intf)->cur_altsetting
#else
#define CUR_ALT_SETTING(intf) (intf)->altsetting[(intf)->act_altsetting]
#endif

static struct list_head completed_irps;
static KIRQL completed_irps_lock;
void usb_transfer_complete_tasklet(unsigned long dummy);
DECLARE_TASKLET(completed_irps_tasklet, usb_transfer_complete_tasklet, 0);

static struct list_head canceled_irps;
void usb_cancel_worker(void *dummy);
static struct work_struct cancel_usb_irp_work;
extern KSPIN_LOCK irp_cancel_lock;

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

static inline int wrap_submit_urb(struct urb *urb, int flags)
{
	int ret;
	struct irp *irp = urb->context;

	ret = WRAP_SUBMIT_URB(urb, flags);
	if (ret) {
		ERROR("usb_submit_urb() = %d", ret);
		usb_free_urb(urb);
		if (IRP_DRIVER_CONTEXT(irp)[2])
			kfree(IRP_DRIVER_CONTEXT(irp)[2]);
	}
	return ret;
}

int usb_init(void)
{
	kspin_lock_init(&completed_irps_lock);
	INIT_LIST_HEAD(&canceled_irps);
	INIT_LIST_HEAD(&completed_irps);
	INIT_WORK(&cancel_usb_irp_work, usb_cancel_worker, NULL);
	return 0;
}

void usb_exit(void)
{
	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
void usb_transfer_complete(struct urb *urb, struct pt_regs *regs)
#else
void usb_transfer_complete(struct urb *urb)
#endif
{
	struct irp *irp = urb->context;
	int cancel;

	USBTRACEENTER("urb = %p", urb);

	/* canceled via usb_unlink_urb? */
	if ((urb->status == -ENOENT) || (urb->status == -ECONNRESET))
		USBTRACEEXIT(return);

	/* canceled but not yet unlinked? */
	kspin_lock(&irp_cancel_lock);
	irp->cancel_routine = NULL;
	cancel = irp->cancel;
	kspin_unlock(&irp_cancel_lock);

	if (cancel)
		USBTRACEEXIT(return);

	kspin_lock(&completed_irps_lock);
	list_add_tail(&irp->completed_list, &completed_irps);
	kspin_unlock(&completed_irps_lock);

	tasklet_schedule(&completed_irps_tasklet);
	USBTRACEEXIT(return);
}

void usb_transfer_complete_tasklet(unsigned long dummy)
{
	struct irp *irp;
	struct urb *urb;
	struct io_stack_location *stack;
	union nt_urb *nt_urb;
	unsigned long flags;

	while (1) {
		kspin_lock_irqsave(&completed_irps_lock, flags);

		if (list_empty(&completed_irps)) {
			kspin_unlock_irqrestore(&completed_irps_lock, flags);
			USBTRACEEXIT(return);
		}
		irp = list_entry(completed_irps.next, struct irp,
				 completed_list);
		list_del(&irp->completed_list);

		kspin_unlock_irqrestore(&completed_irps_lock, flags);

		urb = IRP_DRIVER_CONTEXT(irp)[3];
		stack = IRP_CUR_STACK_LOC(irp) - 1;
		nt_urb = stack->params.generic.arg1;

		USBTRACE("irp = %p, urb = %p, status = %d", irp, urb,
			  urb->status);

		if (urb->setup_packet)
			kfree(urb->setup_packet);

		irp->pending_returned = 1;

		if (urb->status)
			irp->io_status.status = STATUS_FAILURE;
		else
			irp->io_status.status = STATUS_SUCCESS;
		irp->io_status.status_info = urb->actual_length;

		/* also applies to ctrlDescReq or venClsReq */
		nt_urb->bulkIntrTrans.transferBufLen = urb->actual_length;

		DUMP_URB(urb);

		if (IRP_DRIVER_CONTEXT(irp)[2]) {
			if (urb->pipe & USB_DIR_IN) {
				/* also applies to ctrlDescReq or venClsReq */
				memcpy(nt_urb->bulkIntrTrans.transferBuf,
				       IRP_DRIVER_CONTEXT(irp)[2],
				       nt_urb->bulkIntrTrans.transferBufLen);
			}
			kfree(IRP_DRIVER_CONTEXT(irp)[2]);
		}

		IofCompleteRequest(FASTCALL_ARGS_2(irp, 0));

		USBTRACE("freeing urb %p", urb);
		usb_free_urb(urb);
	}
}

/* this is called holding irp_cancel_lock */
STDCALL void usb_cancel_transfer(struct device_object *dev_obj,
				 struct irp *irp)
{
	struct urb *urb;

	USBTRACEENTER("irp = %p", irp);
	urb = IRP_DRIVER_CONTEXT(irp)[3];
	USBTRACE("adding urb %p to cancel", urb);

	/* while this function can run at DISPATCH_LEVEL,
	 * usb_unlink/kill_urb will only work successfully in
	 * schedulable context */
	list_add_tail(&irp->cancel_list, &canceled_irps);

	schedule_work(&cancel_usb_irp_work);
}

void usb_cancel_worker(void *dummy)
{
	struct irp *irp;
	struct urb *urb;

	USBTRACEENTER("%s", "");

	while (1) {
		kspin_lock(&irp_cancel_lock);

		if (list_empty(&canceled_irps)) {
			kspin_unlock(&irp_cancel_lock);
			USBTRACEEXIT(return);
		}
		irp = list_entry(canceled_irps.next, struct irp, cancel_list);
		list_del(&irp->cancel_list);

		kspin_unlock(&irp_cancel_lock);

		urb = IRP_DRIVER_CONTEXT(irp)[3];

		USBTRACE("freeing urb = %p", urb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
		usb_kill_urb(urb);
#else
		if (usb_unlink_urb(urb) < 0)
			USBTRACEEXIT(return);
#endif
		if (urb->setup_packet)
			kfree(urb->setup_packet);

		usb_free_urb(urb);
		if (IRP_DRIVER_CONTEXT(irp)[2])
			kfree(IRP_DRIVER_CONTEXT(irp)[2]);

		irp->io_status.status = STATUS_CANCELLED;
		irp->io_status.status_info = 0;
		IofCompleteRequest(FASTCALL_ARGS_2(irp, 0));
	}
}

unsigned long usb_bulk_or_intr_trans(struct usb_device *dev,
				     union nt_urb *nt_urb, struct irp *irp)
{
	union pipe_handle pipe_handle;
	struct urb *urb;
	unsigned int pipe;
	int i, ret;
	UCHAR endpoint;

	ASSERT(!nt_urb->bulkIntrTrans.transferBufMdl);
	ASSERT(!nt_urb->bulkIntrTrans.urbLink);
	USBTRACE("flags = %lX, length = %lu, buffer = %p",
		  nt_urb->bulkIntrTrans.transferFlags,
		  nt_urb->bulkIntrTrans.transferBufLen,
		  nt_urb->bulkIntrTrans.transferBuf);

	/* FIXME: we should better check what GFP_ is required */
	urb = WRAP_ALLOC_URB(0, GFP_ATOMIC);
	if (!urb)
		return -ENOMEM;

	/* store the linux-urb in the nt-irp and set the cancel routine */
	IRP_DRIVER_CONTEXT(irp)[3] = urb;
	irp->cancel_routine = usb_cancel_transfer;

	pipe_handle = nt_urb->bulkIntrTrans.pipeHandle;

	endpoint = pipe_handle.encoded.endpointAddr;
	switch(pipe_handle.encoded.pipeType) {
	case USB_ENDPOINT_XFER_CONTROL:
		if (nt_urb->bulkIntrTrans.transferFlags &
		    USBD_TRANSFER_DIRECTION_IN)
			pipe = usb_rcvctrlpipe(dev, endpoint);
		else
			pipe = usb_sndctrlpipe(dev, endpoint);

		usb_fill_control_urb(urb, dev, pipe, urb->setup_packet,
				     nt_urb->bulkIntrTrans.transferBuf,
				     nt_urb->bulkIntrTrans.transferBufLen,
				     usb_transfer_complete, irp);
		break;
	case USB_ENDPOINT_XFER_ISOC:
		if (nt_urb->bulkIntrTrans.transferFlags &
		    USBD_TRANSFER_DIRECTION_IN)
			pipe = usb_rcvisocpipe(dev, endpoint);
		else
			pipe = usb_sndisocpipe(dev, endpoint);
		urb->dev = dev;
		urb->context = irp;
		urb->pipe = pipe;
		urb->interval = 1;
		urb->transfer_flags = nt_urb->isochTrans.transferFlags;
		urb->transfer_buffer = nt_urb->isochTrans.transferBuf;
		urb->complete = usb_transfer_complete;
		urb->number_of_packets = nt_urb->isochTrans.numPackets;
		urb->transfer_buffer_length =
			nt_urb->isochTrans.transferBufLen;
		for (i = 0; i < urb->transfer_buffer_length; i++) {
			urb->iso_frame_desc[i].offset = i;
			urb->iso_frame_desc[i].length = 1;
		}
		break;

	case USB_ENDPOINT_XFER_BULK:
		if (nt_urb->bulkIntrTrans.transferFlags &
		    USBD_TRANSFER_DIRECTION_IN)
			pipe = usb_rcvbulkpipe(dev, endpoint);
		else
			pipe = usb_sndbulkpipe(dev, endpoint);

		usb_fill_bulk_urb(urb, dev, pipe,
				  nt_urb->bulkIntrTrans.transferBuf,
				  nt_urb->bulkIntrTrans.transferBufLen,
				  usb_transfer_complete, irp);
		break;
	case USB_ENDPOINT_XFER_INT:
		if (nt_urb->bulkIntrTrans.transferFlags &
		    USBD_TRANSFER_DIRECTION_IN)
			pipe = usb_rcvintpipe(dev, endpoint);
		else
			pipe = usb_sndintpipe(dev, endpoint);

		usb_fill_int_urb(urb, dev, pipe,
				 nt_urb->bulkIntrTrans.transferBuf,
				 nt_urb->bulkIntrTrans.transferBufLen,
				 usb_transfer_complete, irp,
				 pipe_handle.encoded.interval);
		break;
	default:
		ERROR("unknown pipe type: %d", pipe_handle.encoded.pipeType);
		return -EINVAL;
	}

	if ((nt_urb->venClsReq.transferFlags &
	     (USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK)) ==
	    USBD_TRANSFER_DIRECTION_IN)
		urb->transfer_flags |= URB_SHORT_NOT_OK;

	DUMP_URB(urb);

	/* non-DMA-capable buffers have to be mirrored */
	IRP_DRIVER_CONTEXT(irp)[2] = NULL;
	if (!virt_addr_valid(nt_urb->bulkIntrTrans.transferBuf)) {
		IRP_DRIVER_CONTEXT(irp)[2] =
			kmalloc(nt_urb->bulkIntrTrans.transferBufLen,
				GFP_ATOMIC);
		if (!IRP_DRIVER_CONTEXT(irp)[2]) {
			ERROR("%s", "kmalloc failed!");
			usb_free_urb(urb);
			return -ENOMEM;
		}

		if (!(pipe & USB_DIR_IN))
			memcpy(IRP_DRIVER_CONTEXT(irp)[2],
			       nt_urb->bulkIntrTrans.transferBuf,
			       nt_urb->bulkIntrTrans.transferBufLen);
		urb->transfer_buffer = IRP_DRIVER_CONTEXT(irp)[2];
		USBTRACE("mirroring non-DMA buffer");
	}

	/* mark setup_packet as unused for cleanup procedure */
	urb->setup_packet = NULL;

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

	ASSERT(!nt_urb->venClsReq.transferBufMdl);
	ASSERT(!nt_urb->venClsReq.urbLink);
	USBTRACE("reservedBits = %x, request = %x, "
		  "value = %d, index = %d, transferFlags = %lx, "
		  "transferBuf = %p, transferBufLen = %ld",
		  nt_urb->venClsReq.reservedBits,
		  nt_urb->venClsReq.request, nt_urb->venClsReq.value,
		  nt_urb->venClsReq.index, nt_urb->venClsReq.transferFlags,
		  nt_urb->venClsReq.transferBuf,
		  nt_urb->venClsReq.transferBufLen);

	/* FIXME: we should better check what GFP_ is required */
	urb = WRAP_ALLOC_URB(0, GFP_ATOMIC);
	if (!urb) {
		ERROR("%s", "usb_alloc_urb failed!");
		return -ENOMEM;
	}

	req_type = USB_TYPE_VENDOR | USB_RECIP_DEVICE |
		nt_urb->venClsReq.reservedBits;

	if (nt_urb->venClsReq.transferFlags & USBD_TRANSFER_DIRECTION_IN) {
		pipe = usb_rcvctrlpipe(dev, 0);
		req_type |= USB_DIR_IN;
	} else {
		pipe = usb_sndctrlpipe(dev, 0);
		req_type |= USB_DIR_OUT;
	}

	dr = kmalloc(sizeof(struct usb_ctrlrequest), GFP_ATOMIC);
	if (!dr) {
		ERROR("%s", "kmalloc failed!");
		usb_free_urb(urb);
		return -ENOMEM;
	}

	dr->bRequestType = req_type;
	dr->bRequest = nt_urb->venClsReq.request;
	dr->wValue = nt_urb->venClsReq.value;
	dr->wIndex = nt_urb->venClsReq.index;
	dr->wLength = nt_urb->venClsReq.transferBufLen;

	usb_fill_control_urb(urb, dev, pipe, (unsigned char *)dr,
			     nt_urb->venClsReq.transferBuf,
			     nt_urb->venClsReq.transferBufLen,
			     usb_transfer_complete, irp);

	if ((nt_urb->venClsReq.transferFlags &
	     (USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK)) ==
	    USBD_TRANSFER_DIRECTION_IN)
		urb->transfer_flags |= URB_SHORT_NOT_OK;

	DUMP_URB(urb);

	/* non-DMA-capable buffers have to be mirrored */
	IRP_DRIVER_CONTEXT(irp)[2] = NULL;
	if ((nt_urb->venClsReq.transferBufLen > 0) &&
	    !virt_addr_valid(nt_urb->venClsReq.transferBuf)) {
		IRP_DRIVER_CONTEXT(irp)[2] =
			kmalloc(nt_urb->venClsReq.transferBufLen, GFP_KERNEL);
		if (!IRP_DRIVER_CONTEXT(irp)[2]) {
			ERROR("%s", "kmalloc failed!");
			kfree(dr);
			usb_free_urb(urb);
			return -ENOMEM;
		}

		if (!(pipe & USB_DIR_IN))
			memcpy(IRP_DRIVER_CONTEXT(irp)[2],
			       nt_urb->venClsReq.transferBuf,
			       nt_urb->venClsReq.transferBufLen);
		urb->transfer_buffer = IRP_DRIVER_CONTEXT(irp)[2];
		USBTRACE("mirroring non-DMA buffer");
	}

	/* store the linux-urb in the nt-irp and set the cancel routine */
	IRP_DRIVER_CONTEXT(irp)[3] = urb;
	irp->cancel_routine = usb_cancel_transfer;

	USBTRACE("submitting urb %p on control pipe", urb);
	/* FIXME: we should better check what GFP_ is required */
	ret = wrap_submit_urb(urb, GFP_ATOMIC);
	if (ret)
		kfree(dr);
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

	case USB_ENDPOINT_XFER_ISOC:
		if (pipe_handle.encoded.endpointAddr & USB_ENDPOINT_DIR_MASK)
			pipe = usb_rcvisocpipe(dev, endpoint);
		else
			pipe = usb_sndisocpipe(dev, endpoint);
		break;

	case USB_ENDPOINT_XFER_BULK:
		if (pipe_handle.encoded.endpointAddr & USB_ENDPOINT_DIR_MASK)
			pipe = usb_rcvbulkpipe(dev, endpoint);
		else
			pipe = usb_sndbulkpipe(dev, endpoint);
		break;

	default: /* USB_ENDPOINT_XFER_INT */
		if (pipe_handle.encoded.endpointAddr & USB_ENDPOINT_DIR_MASK)
			pipe = usb_rcvbulkpipe(dev, endpoint);
		else
			pipe = usb_sndbulkpipe(dev, endpoint);
		break;
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

	ASSERT(nt_urb->selConf.config->bNumInterfaces == 1);
	USBTRACE("intf.intfNum = %d, intf.altSet = %d",
		  nt_urb->selConf.intf.intfNum, nt_urb->selConf.intf.altSet);

	ret = usb_set_interface(dev, nt_urb->selConf.intf.intfNum,
				nt_urb->selConf.intf.altSet);
	if (ret < 0) {
		ERROR("usb_set_interface() = %d", ret);
		USBTRACEEXIT(return ret);
	}

	intf = usb_ifnum_to_if(dev, nt_urb->selConf.intf.intfNum);
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
		pipe_info = &nt_urb->selConf.intf.pipes[i];

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
	int ret;

	USBTRACEENTER("nt_urb = %p, irp = %p, length = %d, function = %x",
		    nt_urb, irp, nt_urb->header.length,
		    nt_urb->header.function);

	nt_urb->header.status = USB_STATUS_SUCCESS;

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
		ASSERT(!nt_urb->ctrlDescReq.transferBufMdl);
		ASSERT(!nt_urb->ctrlDescReq.urbLink);
		USBTRACE("desctype = %d, descindex = %d, "
			  "transferBuf = %p, transferBufLen = %ld",
			  nt_urb->ctrlDescReq.desctype,
			  nt_urb->ctrlDescReq.index,
			  nt_urb->ctrlDescReq.transferBuf,
			  nt_urb->ctrlDescReq.transferBufLen);

		ret = usb_get_descriptor(dev, nt_urb->ctrlDescReq.desctype,
					 nt_urb->ctrlDescReq.index,
					 nt_urb->ctrlDescReq.transferBuf,
					 nt_urb->ctrlDescReq.transferBufLen);
		if (ret < 0) {
			ERROR("usb_get_descriptor() = %d", ret);
			break;
		}
		nt_urb->ctrlDescReq.transferBufLen = ret;
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
		ret = usb_reset_pipe(dev, nt_urb->pipeReq.pipeHandle);
		if (ret < 0) {
			ERROR("usb_reset_pipe() = %d", ret);
			break;
		}
		USBTRACEEXIT(return STATUS_SUCCESS);

	default:
		ERROR("function %X NOT IMPLEMENTED!\n",
		      nt_urb->header.function);
	}
	nt_urb->header.status = USB_STATUS_ERROR;
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
	(struct usb_config_descriptor *config, unsigned short *urb_size)
{
	union nt_urb *urb;
	struct usb_interface_descriptor *intf_desc;
	struct usbd_interface_information *intf_info;
	char *pos = (char *)config;
	int cfg_size = config->wTotalLength;
	int found = 0;

	USBTRACEENTER("config = %p, urb_size = %p", config, urb_size);
	ASSERT(config->bNumInterfaces < 2);

	while ((char *)pos - (char *)config < cfg_size) {
		intf_desc = (struct usb_interface_descriptor *)pos;
		pos = pos + intf_desc->bLength;

		if (intf_desc->bDescriptorType != USB_DT_INTERFACE)
			continue;

		USBTRACE("selected interface = %p", intf_desc);
		found = 1;
		break;
	}
	if (!found)
		USBTRACEEXIT(return NULL);

	*urb_size = sizeof(union nt_urb) +
		sizeof(struct usbd_pipe_information) *
		(intf_desc->bNumEndpoints - 1);
	/* FIXME: we should better check what GFP_ is required */
	urb = kmalloc(*urb_size, GFP_ATOMIC);

	if (urb) {
		urb->selConf.header.length = *urb_size;
		urb->selConf.header.function =
			URB_FUNCTION_SELECT_CONFIGURATION;
		urb->selConf.config = config;

		intf_info = &urb->selConf.intf;
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

	USBTRACEEXIT(return urb);
}

STDCALL union nt_urb * WRAP_EXPORT(USBD_CreateConfigurationRequestEx)
	(struct usb_config_descriptor *config,
	 struct usbd_interface_list_entry *intfList)
{
	union nt_urb *urb;
	int urb_size;
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
	urb_size = sizeof(union nt_urb) +
		sizeof(struct usbd_pipe_information) *
		(intf_desc->bNumEndpoints - 1);
	/* FIXME: we should better check what GFP_ is required */
	urb = kmalloc(urb_size, GFP_ATOMIC);

	if (urb) {
		urb->selConf.header.length = urb_size;
		urb->selConf.header.function =
			URB_FUNCTION_SELECT_CONFIGURATION;
		urb->selConf.config = config;

		intf_info = &urb->selConf.intf;
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

	USBTRACEEXIT(return urb);
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
