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

void usb_transfer_complete(struct urb *urb, struct pt_regs *regs)
{
	struct irp *irp = urb->context;
	struct io_stack_location *stack = irp->current_stack_location-1;
	union nt_urb *nt_urb = stack->params.generic.arg1;


	TRACEENTER3("urb = %p, status = %d", urb, urb->status);
	irp->pending_returned = 1;
	if (urb->status)
		irp->io_status.status = STATUS_FAILURE;
	else
		irp->io_status.status = STATUS_SUCCESS;
	if (irp->user_status)
		irp->user_status->status = irp->io_status.status;
	nt_urb->bulkIntrTrans.transferBufLen = urb->actual_length;

#if defined DEBUG
/* && DEBUG >= 3*/
	if ((urb->pipe & USB_DIR_IN)) {
		int i;

		printk("Receiving ");
		for (i = 0; i < urb->actual_length; i++)
			printk("%02X ", *(((unsigned char *)urb->transfer_buffer)+i));
		printk("\n");
	}
#endif

	if (stack->completion_handler) {
		if (((urb->status == 0) &&
		     (stack->control & CALL_ON_SUCCESS)) ||
		    ((urb->status != 0) &&
		     (stack->control & CALL_ON_ERROR))) {
			DBGTRACE3("calling %p", stack->completion_handler);
			if (stack->completion_handler(stack->dev_obj, irp,
			                              stack->handler_arg) ==
			    STATUS_MORE_PROCESSING_REQUIRED)
				TRACEEXIT3(return);
		}
	}

	if (irp->user_event) {
		DBGTRACE3("setting event %p", irp->user_event);
		NdisSetEvent((struct ndis_event *)irp->user_event);
	}

	/* To-Do: what about IRP_DEALLOCATE_BUFFER...? */
	DBGTRACE("freeing irp %p", irp);
	kfree(irp);

	usb_free_urb(urb);

	TRACEEXIT3(return);
}

void STDCALL usb_cancel_transfer(struct device_object *dev_obj,
                                 struct irp *irp)
{
	TRACEENTER3("irp = %p", irp);

	usb_unlink_urb(irp->driver_context[3]);
	usb_free_urb(irp->driver_context[3]);
	if (irp->driver_context[2])
		kfree(irp->driver_context[2]);

	TRACEEXIT3(return);
}

unsigned long usb_bulk_or_intr_trans(struct usb_device *dev,
                                     union nt_urb *nt_urb, struct irp *irp)
{
	union pipe_handle pipe_handle;
	struct urb *urb;
	unsigned int pipe;


	ASSERT(!nt_urb->bulkIntrTrans.transferBufMdl);
	ASSERT(!nt_urb->bulkIntrTrans.urbLink);
	DBGTRACE3("flags = %lX, length = %lu, buffer = %p",
		nt_urb->bulkIntrTrans.transferFlags,
		nt_urb->bulkIntrTrans.transferBufLen,
		nt_urb->bulkIntrTrans.transferBuf);

	/* XXX we should better check what GFP_ is required XXX */
	urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!urb)
		return -ENOMEM;

	/* store the linux-urb in the nt-irp and set the cancel routine */
	irp->driver_context[3] = urb;
	irp->cancel_routine = usb_cancel_transfer;

	pipe_handle = nt_urb->bulkIntrTrans.pipeHandle;
	if (pipe_handle.encoded.pipeType == USB_ENDPOINT_XFER_BULK) {
		if (nt_urb->bulkIntrTrans.transferFlags &
		    USBD_TRANSFER_DIRECTION_IN)
			pipe = usb_rcvbulkpipe(dev,
				pipe_handle.encoded.endpointAddr);
		else
			pipe = usb_sndbulkpipe(dev,
				pipe_handle.encoded.endpointAddr);

		usb_fill_bulk_urb(urb, dev, pipe,
			nt_urb->bulkIntrTrans.transferBuf,
			nt_urb->bulkIntrTrans.transferBufLen,
			usb_transfer_complete, irp);
	} else { /* USB_ENDPOINT_XFER_INT */
		pipe = usb_rcvintpipe(dev, pipe_handle.encoded.endpointAddr);

		usb_fill_int_urb(urb, dev, pipe,
			nt_urb->bulkIntrTrans.transferBuf,
			nt_urb->bulkIntrTrans.transferBufLen,
			usb_transfer_complete, irp,
			pipe_handle.encoded.interval);
	}
	if ((nt_urb->bulkIntrTrans.transferFlags &
	     (USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK)) ==
	     USBD_TRANSFER_DIRECTION_IN)
		urb->transfer_flags |= URB_SHORT_NOT_OK;

#if defined DEBUG
/* && DEBUG >= 3*/
	if (!(urb->pipe & USB_DIR_IN)) {
		int i;

		printk("Sending ");
		for (i = 0; i < urb->transfer_buffer_length; i++)
			printk("%02X ", *(((unsigned char *)urb->transfer_buffer)+i));
		printk("\n");
	}
#endif

	/* non-DMA-capable buffers have to be mirrored */
	irp->driver_context[2] = NULL;
	if (!virt_addr_valid(nt_urb->bulkIntrTrans.transferBuf)) {
		irp->driver_context[2] = kmalloc(
			nt_urb->bulkIntrTrans.transferBufLen, GFP_ATOMIC);
		memcpy(irp->driver_context[2],
			nt_urb->bulkIntrTrans.transferBuf,
			nt_urb->bulkIntrTrans.transferBufLen);
		urb->transfer_buffer = irp->driver_context[2];
		DBGTRACE3("mirroring non-DMA buffer");
	}

	DBGTRACE3("submitting urb %p on pipe %p", urb, pipe_handle.handle);
	/* XXX we should better check what GFP_ is required XXX */
	return usb_submit_urb(urb, GFP_ATOMIC);
}

unsigned long usb_reset_pipe(struct usb_device *dev,
                             union pipe_handle pipe_handle)
{
	int pipe;


	DBGTRACE3("pipe = %p", pipe_handle.handle);
	switch (pipe_handle.encoded.pipeType) {
		case USB_ENDPOINT_XFER_CONTROL:
			if (pipe_handle.encoded.endpointAddr &
			    USB_ENDPOINT_DIR_MASK)
				pipe = usb_rcvctrlpipe(dev,
					pipe_handle.encoded.endpointAddr);
			else
				pipe = usb_sndctrlpipe(dev,
					pipe_handle.encoded.endpointAddr);
			break;

		case USB_ENDPOINT_XFER_ISOC:
			if (pipe_handle.encoded.endpointAddr &
			    USB_ENDPOINT_DIR_MASK)
				pipe = usb_rcvisocpipe(dev,
					pipe_handle.encoded.endpointAddr);
			else
				pipe = usb_sndisocpipe(dev,
					pipe_handle.encoded.endpointAddr);
			break;

		case USB_ENDPOINT_XFER_BULK:
			if (pipe_handle.encoded.endpointAddr &
			    USB_ENDPOINT_DIR_MASK)
				pipe = usb_rcvbulkpipe(dev,
					pipe_handle.encoded.endpointAddr);
			else
				pipe = usb_sndbulkpipe(dev,
					pipe_handle.encoded.endpointAddr);
			break;

		default: /* USB_ENDPOINT_XFER_INT */
			pipe = usb_rcvintpipe(dev,
				pipe_handle.encoded.endpointAddr);
			break;
	}

	return usb_clear_halt(dev, pipe);
}

unsigned long usb_submit_nt_urb(struct usb_device *dev, union nt_urb *nt_urb,
                                struct irp *irp)
{
	struct usb_interface *intf;
	struct usb_host_endpoint *endp;
	struct usbd_pipe_information *pipe_info;
	int i, ret;


	TRACEENTER3("nt_urb = %p, irp = %p, length = %d, function = %x",
		nt_urb, irp, nt_urb->header.length, nt_urb->header.function);

	nt_urb->header.status = USB_STATUS_SUCCESS;

	switch (nt_urb->header.function) {
		case FUNC_SELECT_CONFIGURATION:
			ASSERT(nt_urb->selConf.config->bNumInterfaces == 1);
			DBGTRACE2("intf.intfNum = %d, intf.altSet = %d",
				nt_urb->selConf.intf.intfNum,
				nt_urb->selConf.intf.altSet);

			ret = usb_set_interface(dev,
				nt_urb->selConf.intf.intfNum,
				nt_urb->selConf.intf.altSet);
			if (ret < 0) {
				ERROR("usb_set_interface() = %d", ret);
				break;
			}

			intf = usb_ifnum_to_if(dev,
				nt_urb->selConf.intf.intfNum);
			if (!intf) {
				ERROR("usb_ifnum_to_if() = %d", ret);
				break;
			}
			for (i = 0;
			     i < intf->cur_altsetting->desc.bNumEndpoints;
			     i++) {
				endp = intf->cur_altsetting->endpoint + i;
				pipe_info = &nt_urb->selConf.intf.pipes[i];

				pipe_info->maxPacketSize =
					endp->desc.wMaxPacketSize;
				pipe_info->endpointAddr =
					endp->desc.bEndpointAddress;
				pipe_info->interval = endp->desc.bInterval;
				pipe_info->pipeType = endp->desc.bmAttributes;

				pipe_info->pipeHandle.encoded.endpointAddr =
					endp->desc.bEndpointAddress;
				pipe_info->pipeHandle.encoded.pipeType =
					endp->desc.bmAttributes;
				pipe_info->pipeHandle.encoded.interval =
					endp->desc.bInterval;
				pipe_info->pipeHandle.encoded.fill = 0;

				DBGTRACE3("%i: Addr %X, Type %d, PkSz %d, "
					"Intv %d, Handle %p", i,
					endp->desc.bEndpointAddress,
					endp->desc.bmAttributes,
					endp->desc.wMaxPacketSize,
					endp->desc.bInterval,
					pipe_info->pipeHandle.handle);
			}
			TRACEEXIT3(return STATUS_SUCCESS);

		case FUNC_BULK_OR_INTERRUPT_TRANSFER:
			ret = usb_bulk_or_intr_trans(dev, nt_urb, irp);
			if (ret < 0) {
				ERROR("usb_bulk_or_intr_trans() = %d", ret);
				break;
			}
			TRACEEXIT3(return STATUS_PENDING);

		case FUNC_GET_DESCRIPTOR_FROM_DEVICE:
			ASSERT(!nt_urb->ctrlDescReq.transferBufMdl);
			ASSERT(!nt_urb->ctrlDescReq.urbLink);

			ret = usb_get_descriptor(dev,
				nt_urb->ctrlDescReq.desctype,
				nt_urb->ctrlDescReq.descindex,
				nt_urb->ctrlDescReq.transferBuf,
				nt_urb->ctrlDescReq.transferBufLen);
			if (ret < 0) {
				ERROR("usb_get_descriptor() = %d", ret);
				break;
			}
			nt_urb->ctrlDescReq.transferBufLen = ret;
			TRACEEXIT3(return STATUS_SUCCESS);

		case FUNC_RESET_PIPE:
			ret = usb_reset_pipe(dev, nt_urb->pipeReq.pipeHandle);
			if (ret < 0) {
				ERROR("usb_reset_pipe() = %d", ret);
				break;
			}
			TRACEEXIT3(return STATUS_SUCCESS);

		default:
			ERROR("function %X NOT IMPLEMENTED!\n",
				nt_urb->header.function);
	}

	nt_urb->header.status = USB_STATUS_ERROR;
	TRACEEXIT3(return STATUS_FAILURE);
}

STDCALL union nt_urb *
USBD_CreateConfigurationRequestEx(struct usb_config_descriptor *config,
                                  struct usbd_interface_list_entry *intfList)
{
	union nt_urb *urb;

	int urb_size;
	struct usb_interface_descriptor *intf_desc;
	struct usbd_interface_information *intf_info;


	/*
	 * Note: This function is more or less a hack - due to a lack of
	 *       understanding of the underlying USB details. It only sets up
	 *       an URB with one interface inside. This is what the WUSB54G
	 *       driver requests or what the WUSB54G device provides. However,
	 *       this function warns if the assumption is incorrect.
	 */

	TRACEENTER2("config = %p, intfList = %p", config, intfList);
	ASSERT(config->bNumInterfaces < 2);

	intf_desc = intfList->intfDesc;
	urb_size = sizeof(union nt_urb) +
		sizeof(struct usbd_pipe_information) *
		(intf_desc->bNumEndpoints - 1);
	/* XXX we should better check what GFP_ is required XXX */
	urb = kmalloc(urb_size, GFP_ATOMIC);

	if (urb) {
		urb->selConf.header.length   = urb_size;
		urb->selConf.header.function = FUNC_SELECT_CONFIGURATION;
		urb->selConf.config          = config;

		intf_info = &urb->selConf.intf;
		intfList->intf = intf_info;
		intf_info->length = sizeof(struct usbd_interface_information)+
			sizeof(struct usbd_pipe_information) *
			(intf_desc->bNumEndpoints - 1);
		intf_info->intfNum  = intf_desc->bInterfaceNumber;
		intf_info->altSet   = intf_desc->bAlternateSetting;
		intf_info->class    = intf_desc->bInterfaceClass;
		intf_info->subClass = intf_desc->bInterfaceSubClass;
		intf_info->proto    = intf_desc->bInterfaceProtocol;
		intf_info->pipeNum  = intf_desc->bNumEndpoints;

		ASSERT(!(intfList+1)->intfDesc);
	}

	TRACEEXIT2(return urb);
}

STDCALL struct usb_interface_descriptor *
USBD_ParseConfigurationDescriptorEx(struct usb_config_descriptor *config,
                                    void *startPos, long intfNum, long altSet,
                                    long intfClass, long intfSubClass,
                                    long intfProto)
{
	int size = config->wTotalLength;
	char *pos = startPos;
	struct usb_interface_descriptor *intf;


	TRACEENTER2("config = %p, startPos = %p, intfNum = %ld, altSet = %ld,"
		" intfClass = %ld, intfSubClass = %ld, intfProto = %ld",
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

		DBGTRACE2("selected interface = %p", intf);
		TRACEEXIT2(return intf);
	}

	TRACEEXIT2(return NULL);
}

struct wrap_func usb_wrap_funcs[] =
{
	WRAP_FUNC_ENTRY(USBD_CreateConfigurationRequestEx),
	WRAP_FUNC_ENTRY(USBD_ParseConfigurationDescriptorEx),
	{NULL, NULL}
};
