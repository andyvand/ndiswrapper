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

#include "ntoskernel.h"

#define IOCTL_INTERNAL_USB_SUBMIT_URB	0x00220003
#define IOCTL_INTERNAL_USB_RESET_PORT	0x00220007

#define USB_STATUS_SUCCESS		0x00000000
#define USB_STATUS_ERROR		0x80000000

#define URB_FUNCTION_SELECT_CONFIGURATION            0x0000
#define URB_FUNCTION_SELECT_INTERFACE                0x0001
#define URB_FUNCTION_ABORT_PIPE                      0x0002
#define URB_FUNCTION_TAKE_FRAME_LENGTH_CONTROL       0x0003
#define URB_FUNCTION_RELEASE_FRAME_LENGTH_CONTROL    0x0004
#define URB_FUNCTION_GET_FRAME_LENGTH                0x0005
#define URB_FUNCTION_SET_FRAME_LENGTH                0x0006
#define URB_FUNCTION_GET_CURRENT_FRAME_NUMBER        0x0007
#define URB_FUNCTION_CONTROL_TRANSFER                0x0008
#define URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER      0x0009
#define URB_FUNCTION_ISOCH_TRANSFER                  0x000A
#define URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE      0x000B
#define URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE        0x000C
#define URB_FUNCTION_SET_FEATURE_TO_DEVICE           0x000D
#define URB_FUNCTION_SET_FEATURE_TO_INTERFACE        0x000E
#define URB_FUNCTION_SET_FEATURE_TO_ENDPOINT         0x000F
#define URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE         0x0010
#define URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE      0x0011
#define URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT       0x0012
#define URB_FUNCTION_GET_STATUS_FROM_DEVICE          0x0013
#define URB_FUNCTION_GET_STATUS_FROM_INTERFACE       0x0014
#define URB_FUNCTION_GET_STATUS_FROM_ENDPOINT        0x0015
#define URB_FUNCTION_RESERVED_0X0016                 0x0016
#define URB_FUNCTION_VENDOR_DEVICE                   0x0017
#define URB_FUNCTION_VENDOR_INTERFACE                0x0018
#define URB_FUNCTION_VENDOR_ENDPOINT                 0x0019
#define URB_FUNCTION_CLASS_DEVICE                    0x001A
#define URB_FUNCTION_CLASS_INTERFACE                 0x001B
#define URB_FUNCTION_CLASS_ENDPOINT                  0x001C
#define URB_FUNCTION_RESERVE_0X001D                  0x001D
#define URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL 0x001E
#define URB_FUNCTION_CLASS_OTHER                     0x001F
#define URB_FUNCTION_VENDOR_OTHER                    0x0020
#define URB_FUNCTION_GET_STATUS_FROM_OTHER           0x0021
#define URB_FUNCTION_CLEAR_FEATURE_TO_OTHER          0x0022
#define URB_FUNCTION_SET_FEATURE_TO_OTHER            0x0023
#define URB_FUNCTION_GET_DESCRIPTOR_FROM_ENDPOINT    0x0024
#define URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT      0x0025
#define URB_FUNCTION_GET_CONFIGURATION               0x0026
#define URB_FUNCTION_GET_INTERFACE                   0x0027
#define URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE   0x0028
#define URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE     0x0029
#define URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR       0x002A
#define URB_FUNCTION_RESERVE_0X002B                  0x002B
#define URB_FUNCTION_RESERVE_0X002C                  0x002C
#define URB_FUNCTION_RESERVE_0X002D                  0x002D
#define URB_FUNCTION_RESERVE_0X002E                  0x002E
#define URB_FUNCTION_RESERVE_0X002F                  0x002F
// USB 2.0 calls start at 0x0030         
#define URB_FUNCTION_SYNC_RESET_PIPE                 0x0030
#define URB_FUNCTION_SYNC_CLEAR_STALL                0x0031

#define USBD_TRANSFER_DIRECTION_IN	0x00000001
#define USBD_SHORT_TRANSFER_OK		0x00000002

typedef LONG USBD_STATUS;

union pipe_handle {
	void *handle;
	struct {
		unsigned char endpointAddr;
		unsigned char pipeType;
		unsigned char interval;
		unsigned char fill;
	} encoded;
};

struct urb_hcd_area {
	void *reserved8[8];
};

struct usbd_pipe_information {
	USHORT maxPacketSize;
	UCHAR endpointAddr;
	UCHAR interval;
	enum {ptControl, ptIsochronous, ptBulk, ptIntr} pipeType;
	union pipe_handle pipeHandle;
	ULONG maxTransferSize;
	ULONG pipeFlags;
};

struct usbd_interface_information {
	USHORT length;
	UCHAR intfNum;
	UCHAR altSet;
	UCHAR class;
	UCHAR subClass;
	UCHAR proto;
	UCHAR fill;
	void *intfHandle;
	ULONG pipeNum;
	struct usbd_pipe_information pipes[1];
};

struct usbd_interface_list_entry {
	struct usb_interface_descriptor *intfDesc;
	struct usbd_interface_information *intf;
};

struct nt_urb_header {
	USHORT length;
	USHORT function;
	USBD_STATUS status;
	void *usbdDevHandle;
	ULONG usbdFlags;
};

struct select_configuration {
	struct nt_urb_header header;
	struct usb_config_descriptor *config;
	void *configHandle;
	struct usbd_interface_information intf;
};

struct bulk_or_intr_transfer {
	struct nt_urb_header header;
	union pipe_handle pipeHandle;
	ULONG transferFlags;
	ULONG transferBufLen;
	void *transferBuf;
	struct mdl *transferBufMdl;
	union nt_urb *urbLink;
	struct urb_hcd_area hca;
};

struct control_descriptor_request {
	struct nt_urb_header header;
	void *reserved;
	ULONG reserved0;
	ULONG transferBufLen;
	void *transferBuf;
	struct MDL *transferBufMdl;
	union nt_urb *urbLink;
	struct urb_hcd_area hca;
	USHORT reserved1;
	UCHAR index;
	UCHAR desctype;
	USHORT langid;
	USHORT reserved2;
};

struct pipe_request {
	struct nt_urb_header header;
	union pipe_handle pipeHandle;
};

struct vendor_or_class_request {
	struct nt_urb_header header;
	void *reserved;
	ULONG transferFlags;
	ULONG transferBufLen;
	void *transferBuf;
	struct mdl *transferBufMdl;
	union nt_urb *urbLink;
	struct urb_hcd_area hca;
	UCHAR reservedBits;
	UCHAR request;
	UCHAR value;
	UCHAR index;
	USHORT reserved1;
};

struct usbd_iso_packet_desc {
	ULONG offset;
	ULONG length;
	USBD_STATUS status;
};

struct isochronous_transfer {
	struct nt_urb_header header;
	union pipe_handle pipeHandle;
	ULONG transferFlags;
	ULONG transferBufLen;
	void *transferBuf;
	struct mdl *transferMDL;
	union nt_urb *urbLink;
	struct urb_hcd_area hca;
	ULONG startFrame;
	ULONG numPackets;
	ULONG errorCount;
	struct usbd_iso_packet_desc isoPacket[1];
};

union nt_urb {
	struct nt_urb_header header;
	struct select_configuration selConf;
	struct bulk_or_intr_transfer bulkIntrTrans;
	struct control_descriptor_request ctrlDescReq;
	struct vendor_or_class_request venClsReq;
	struct isochronous_transfer isochTrans;
	struct pipe_request pipeReq;
};

unsigned long usb_submit_nt_urb(struct usb_device *dev, union nt_urb *nt_urb,
                                struct irp *irp);
unsigned long usb_reset_port(struct usb_device *dev);

#endif /* USB_H */
