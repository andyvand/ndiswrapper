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

#ifndef USB_H
#define USB_H

#define IOCTL_INTERNAL_USB_SUBMIT_URB	0x00220003
#define IOCTL_INTERNAL_USB_RESET_PORT	0x00220007

#define USB_STATUS_SUCCESS		0x00000000
#define USB_STATUS_ERROR		0x80000000

#define FUNC_SELECT_CONFIGURATION	0x0000
#define FUNC_BULK_OR_INTERRUPT_TRANSFER	0x0009
#define FUNC_GET_DESCRIPTOR_FROM_DEVICE	0x000B
#define FUNC_VENDOR_DEVICE		0x0017
#define FUNC_VENDOR_INTERFACE		0x0018
#define FUNC_CLASS_INTERFACE		0x001B
#define FUNC_RESET_PIPE			0x001E

#define USBD_TRANSFER_DIRECTION_IN	0x00000001
#define USBD_SHORT_TRANSFER_OK		0x00000002

union pipe_handle {
	void *handle;
	struct packed {
		unsigned char endpointAddr;
		unsigned char pipeType;
		unsigned char interval;
		unsigned char fill;
	} encoded;
};

struct packed usbd_pipe_information {
	unsigned short maxPacketSize;
	unsigned char endpointAddr;
	unsigned char interval;
	enum {ptControl, ptIsochronous, ptBulk, ptIntr} pipeType;
	union pipe_handle pipeHandle;
	unsigned long maxTransferSize;
	unsigned long fill;
};

struct packed usbd_interface_information {
	unsigned short length;
	unsigned char intfNum;
	unsigned char altSet;
	unsigned char class;
	unsigned char subClass;
	unsigned char proto;
	unsigned char fill;
	void *intfHandle;
	unsigned long pipeNum;
	struct usbd_pipe_information pipes[1];
};

struct packed usbd_interface_list_entry {
	struct usb_interface_descriptor *intfDesc;
	struct usbd_interface_information *intf;
};

struct packed nt_urb_header {
	unsigned short length;
	unsigned short function;
	long status;
	void *fill1;
	unsigned long fill2;
};

struct packed select_configuration {
	struct nt_urb_header header;
	struct usb_config_descriptor *config;
	void *configHandle;
	struct usbd_interface_information intf;
};

struct packed bulk_or_intr_transfer {
	struct nt_urb_header header;
	union pipe_handle pipeHandle;
	unsigned long transferFlags;
	unsigned long transferBufLen;
	void *transferBuf;
	void *transferBufMdl;
	union nt_urb *urbLink;
	void *fill3[8];
};

struct packed control_descriptor_request {
	struct nt_urb_header header;
	void *fill1;
	unsigned long fill2;
	unsigned long transferBufLen;
	void *transferBuf;
	void *transferBufMdl;
	union nt_urb *urbLink;
	void *fill3[8];
	unsigned short fill4;
	unsigned char descindex;
	unsigned char desctype;
	unsigned short langid;
};

struct packed pipe_request {
	struct nt_urb_header header;
	union pipe_handle pipeHandle;
};

struct packed vendor_or_class_request {
	struct nt_urb_header header;
	void *fill1;
	unsigned long transferFlags;
	unsigned long transferBufLen;
	void *transferBuf;
	void *transferBufMdl;
	union nt_urb *urbLink;
	void *fill2[8];
	unsigned char reservedBits;
	unsigned char request;
	unsigned short value;
	unsigned short index;
	unsigned short fill3;
};

union nt_urb {
	struct nt_urb_header header;
	struct select_configuration selConf;
	struct bulk_or_intr_transfer bulkIntrTrans;
	struct control_descriptor_request ctrlDescReq;
	struct vendor_or_class_request venClsReq;
	struct pipe_request pipeReq;
};

unsigned long usb_submit_nt_urb(struct usb_device *dev, union nt_urb *nt_urb,
                                struct irp *irp);
unsigned long usb_reset_port(struct usb_device *dev);

#endif /* USB_H */
