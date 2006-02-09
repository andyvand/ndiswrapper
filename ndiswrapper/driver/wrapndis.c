/*
 *  Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
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
#include "iw_ndis.h"
#include "pnp.h"
#include "loader.h"
#include "wrapndis.h"

extern NT_SPIN_LOCK loader_lock;
extern struct wrap_device *wrap_devices;
extern struct nt_list wrap_drivers;

extern char *if_name;
extern int hangcheck_interval;
extern int disable_stats;
extern const struct iw_handler_def ndis_handler_def;

static int set_packet_filter(struct wrap_ndis_device *wnd,
			     ULONG packet_filter);
static void stats_timer_add(struct wrap_ndis_device *wnd);
static void stats_timer_del(struct wrap_ndis_device *wnd);
static NDIS_STATUS ndis_start_device(struct wrap_ndis_device *wnd);
static NDIS_STATUS ndis_remove_device(struct wrap_ndis_device *wnd);

static inline int ndis_wait_pending_completion(struct wrap_ndis_device *wnd)
{
	/* wait for NdisMXXComplete to be called*/
	/* As per spec, we should wait until miniport calls back
	 * completion routine, but some drivers (e.g., ZyDas) don't
	 * call back, so timeout is used; TODO: find out why drivers
	 * don't call completion function */
#if 0
	/* setting PM state takes a long time, upto 2 seconds, for USB
	 * devices */
	if ((wait_event_interruptible_timeout(wnd->ndis_comm_wq,
					      (wnd->ndis_comm_done > 0),
					      3 * HZ) <= 0))
#else
	if ((wait_event_interruptible(wnd->ndis_comm_wq,
				      (wnd->ndis_comm_done > 0))))
#endif
		return -1;
	else
		return 0;
}

/* MiniportReset */
NDIS_STATUS miniport_reset(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS res = 0;
	struct miniport_char *miniport;
	UINT cur_lookahead;
	UINT max_lookahead;
	BOOLEAN reset_address;
	KIRQL irql;

	TRACEENTER2("wnd: %p", wnd);

	if (!test_bit(HW_AVAILABLE, &wnd->hw_status))
		TRACEEXIT1(return NDIS_STATUS_FAILURE);

	if (down_interruptible(&wnd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	cur_lookahead = wnd->nmb->cur_lookahead;
	max_lookahead = wnd->nmb->max_lookahead;
	irql = raise_irql(DISPATCH_LEVEL);
	wnd->ndis_comm_done = 0;
	res = LIN2WIN2(miniport->reset, &reset_address,
		       wnd->nmb->adapter_ctx);
	lower_irql(irql);

	DBGTRACE2("res = %08X, reset_status = %08X", res, reset_address);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMResetComplete */
		if (ndis_wait_pending_completion(wnd))
			res = NDIS_STATUS_FAILURE;
		else {
			res = wnd->ndis_comm_status;
			reset_address = wnd->ndis_comm_done - 1;
		}
		DBGTRACE2("res = %08X, reset_status = %08X",
			  res, reset_address);
	}
	DBGTRACE2("reset: res = %08X, reset status = %08X",
		  res, reset_address);
	up(&wnd->ndis_comm_mutex);
	if (res == NDIS_STATUS_SUCCESS && reset_address) {
		wnd->nmb->cur_lookahead = cur_lookahead;
		wnd->nmb->max_lookahead = max_lookahead;
		set_packet_filter(wnd, wnd->packet_filter);
//		set_multicast_list(wnd->net_dev);
	}

	TRACEEXIT3(return res);
}

/* MiniportQueryInformation */
NDIS_STATUS miniport_query_info_needed(struct wrap_ndis_device *wnd,
				       ndis_oid oid, void *buf,
				       ULONG bufsize, ULONG *needed)
{
	NDIS_STATUS res = 0;
	ULONG written;
	struct miniport_char *miniport;
	KIRQL irql;

	DBGTRACE2("oid: %08X", oid);

	if (!test_bit(HW_AVAILABLE, &wnd->hw_status))
		TRACEEXIT1(return NDIS_STATUS_FAILURE);

	if (down_interruptible(&wnd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	DBGTRACE2("query %p, oid: %08X", miniport->query, oid);
	irql = raise_irql(DISPATCH_LEVEL);
	wnd->ndis_comm_done = 0;
	res = LIN2WIN6(miniport->query, wnd->nmb->adapter_ctx, oid, buf,
		       bufsize, &written, needed);
	lower_irql(irql);

	DBGTRACE2("res: %08X, oid: %08X", res, oid);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMQueryInformationComplete */
		if (ndis_wait_pending_completion(wnd))
			res = NDIS_STATUS_FAILURE;
		else
			res = wnd->ndis_comm_status;
		DBGTRACE2("res: %08X", res);
	}
	up(&wnd->ndis_comm_mutex);
	if (res && needed)
		DBGTRACE2("res: %08X, bufsize: %d, written: %d, needed: %d",
			  res, bufsize, written, *needed);
	TRACEEXIT3(return res);
}

NDIS_STATUS miniport_query_info(struct wrap_ndis_device *wnd, ndis_oid oid,
				void *buf, ULONG bufsize)
{
	NDIS_STATUS res;
	ULONG needed;

	res = miniport_query_info_needed(wnd, oid, buf, bufsize, &needed);
	return res;
}

/* MiniportSetInformation */
NDIS_STATUS miniport_set_info(struct wrap_ndis_device *wnd, ndis_oid oid,
			      void *buf, ULONG bufsize)
{
	NDIS_STATUS res = 0;
	ULONG written, needed;
	struct miniport_char *miniport;
	KIRQL irql;

	DBGTRACE2("oid: %08X", oid);

	if (!test_bit(HW_AVAILABLE, &wnd->hw_status))
		TRACEEXIT1(return NDIS_STATUS_FAILURE);

	if (down_interruptible(&wnd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	DBGTRACE2("query %p, oid: %08X", miniport->query, oid);
	irql = raise_irql(DISPATCH_LEVEL);
	wnd->ndis_comm_done = 0;
	res = LIN2WIN6(miniport->setinfo, wnd->nmb->adapter_ctx, oid,
		       buf, bufsize, &written, &needed);
	lower_irql(irql);

	DBGTRACE2("res: %08X, oid: %08X", res, oid);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMQueryInformationComplete */
		if (ndis_wait_pending_completion(wnd))
			res = NDIS_STATUS_FAILURE;
		else
			res = wnd->ndis_comm_status;
		DBGTRACE2("res: %08X", res);
	}
	up(&wnd->ndis_comm_mutex);

	if (res && needed)
		DBGTRACE2("res: %08X, bufsize: %d, written: %d, needed: %d",
			  res, bufsize, written, needed);
	TRACEEXIT3(return res);
}

NDIS_STATUS miniport_query_int(struct wrap_ndis_device *wnd, ndis_oid oid,
			       ULONG *data)
{
	return miniport_query_info(wnd, oid, data, sizeof(ULONG));
}

NDIS_STATUS miniport_set_int(struct wrap_ndis_device *wnd, ndis_oid oid,
			     ULONG data)
{
	return miniport_set_info(wnd, oid, &data, sizeof(data));
}

static NDIS_STATUS miniport_init(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS error_status, status;
	UINT medium_index;
	UINT medium_array[] = {NdisMedium802_3};
	struct miniport_char *miniport;

	TRACEENTER1("irql: %d", current_irql());
	if (test_bit(HW_INITIALIZED, &wnd->hw_status)) {
		ERROR("device %p already initialized!", wnd);
		return NDIS_STATUS_FAILURE;
	}

	if (!wnd->wd->driver->ndis_driver ||
	    !wnd->wd->driver->ndis_driver->miniport.init) {
		ERROR("assuming WDM (non-NDIS) driver");
		TRACEEXIT1(return NDIS_STATUS_SUCCESS);
	}
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	status = LIN2WIN6(miniport->init, &error_status,
			  &medium_index, medium_array,
			  sizeof(medium_array) / sizeof(medium_array[0]),
			  wnd->nmb, wnd->nmb);
	DBGTRACE1("init returns: %08X, irql: %d", status, current_irql());
	if (status != NDIS_STATUS_SUCCESS) {
		WARNING("couldn't initialize device: %08X", status);
		TRACEEXIT1(return NDIS_STATUS_FAILURE);
	}

	/* Wait a little to let card power up otherwise ifup might
	 * fail after boot; USB devices seem to need long delays */
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ);

#if 0
	status = miniport_set_pm_state(wnd, NdisDeviceStateD0);
	if (status)
		DBGTRACE1("setting power state to device %s returns %08X",
			  wnd->net_dev->name, status);
#endif
	set_bit(HW_INITIALIZED, &wnd->hw_status);
	set_bit(HW_AVAILABLE, &wnd->hw_status);
	hangcheck_add(wnd);
	stats_timer_add(wnd);
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

static void miniport_halt(struct wrap_ndis_device *wnd)
{
	struct miniport_char *miniport;

	TRACEENTER1("%p", wnd);
	clear_bit(HW_AVAILABLE, &wnd->hw_status);
	hangcheck_del(wnd);
	stats_timer_del(wnd);
	if (!test_bit(HW_INITIALIZED, &wnd->hw_status)) {
		WARNING("device %p is not initialized - not halting", wnd);
		TRACEEXIT1(return);
	}
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	DBGTRACE1("driver halt is at %p", miniport->miniport_halt);
	LIN2WIN1(miniport->miniport_halt, wnd->nmb->adapter_ctx);
	clear_bit(HW_INITIALIZED, &wnd->hw_status);

	TRACEEXIT1(return);
}

static NDIS_STATUS miniport_pnp_event(struct wrap_ndis_device *wnd,
				      enum ndis_device_pnp_event event)
{
	struct miniport_char *miniport;
	ULONG pnp_info;

	miniport = &wnd->wd->driver->ndis_driver->miniport;
	switch (event) {
	case NdisDevicePnPEventSurpriseRemoved:
		DBGTRACE1("%d, %p",
			  test_bit(ATTR_SURPRISE_REMOVE, &wnd->attributes),
			  miniport->pnp_event_notify);
		if (test_bit(ATTR_SURPRISE_REMOVE, &wnd->attributes) &&
		    miniport->pnp_event_notify) {
			DBGTRACE1("calling surprise_removed");
			LIN2WIN4(miniport->pnp_event_notify,
				 wnd->nmb->adapter_ctx,
				 NdisDevicePnPEventSurpriseRemoved, NULL, 0);
		} else
			DBGTRACE1("Windows driver %s doesn't support "
				  "MiniportPnpEventNotify for safe unplugging",
				  wnd->wd->driver->name);
		return NDIS_STATUS_SUCCESS;
	case NdisDevicePnPEventPowerProfileChanged:
		if (!miniport->pnp_event_notify) {
			DBGTRACE1("Windows driver %s doesn't support "
				  "MiniportPnpEventNotify",
				  wnd->wd->driver->name);
			return NDIS_STATUS_FAILURE;
		}
		pnp_info = NdisPowerProfileAcOnLine;
		DBGTRACE2("calling pnp_event_notify");
		LIN2WIN4(miniport->pnp_event_notify, wnd->nmb->adapter_ctx,
			 NdisDevicePnPEventPowerProfileChanged,
			 &pnp_info, (ULONG)sizeof(pnp_info));
		return NDIS_STATUS_SUCCESS;
	default:
		WARNING("event %d not yet implemented", event);
		return NDIS_STATUS_SUCCESS;
	}
}

/*
 * query functions may not be called from this function as they might
 * sleep which is not allowed from the context this function is
 * running in.
 */
static struct net_device_stats *ndis_get_stats(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return &wnd->stats;
}

static int ndis_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	int rc = -ENODEV;
	return rc;
}

/*
 * This function is called fom BH context
 */
static void ndis_set_multicast_list(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	set_bit(SET_MULTICAST_LIST, &wnd->wrap_ndis_work);
	schedule_ndis_work(&wnd->wrap_ndis_worker);
}

static int ndis_set_mac_addr(struct net_device *dev, void *p)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	struct sockaddr *addr = p;
	struct ndis_configuration_parameter param;
	struct unicode_string key;
	struct ansi_string ansi;
	NDIS_STATUS res;
	unsigned char mac_string[3 * ETH_ALEN];
	mac_address mac;

	/* string <-> ansi <-> unicode conversion is driving me nuts */

	memcpy(mac, addr->sa_data, sizeof(mac));
	memset(mac_string, 0, sizeof(mac_string));
	res = snprintf(mac_string, sizeof(mac_string), MACSTR,
		       MAC2STR(mac));
	DBGTRACE2("res = %d, mac_tring = %s", res, mac_string);
	if (res != (sizeof(mac_string) - 1))
		TRACEEXIT1(return -EINVAL);

	ansi.buf = "mac_address";
	ansi.length = strlen(ansi.buf);
	ansi.max_length = ansi.length + 1;
	if (RtlAnsiStringToUnicodeString(&key, &ansi, TRUE))
		TRACEEXIT1(return -EINVAL);

	ansi.buf = mac_string;
	ansi.length = strlen(mac_string);
	ansi.max_length = ansi.length + 1;
	if (RtlAnsiStringToUnicodeString(&param.data.string, &ansi,
					 TRUE) != NDIS_STATUS_SUCCESS) {
		RtlFreeUnicodeString(&key);
		TRACEEXIT1(return -EINVAL);
	}
	param.type = NdisParameterString;
	NdisWriteConfiguration(&res, wnd->nmb, &key, &param);
	if (res != NDIS_STATUS_SUCCESS) {
		RtlFreeUnicodeString(&key);
		RtlFreeUnicodeString(&param.data.string);
		TRACEEXIT1(return -EINVAL);
	}
	if (pnp_stop_device(wnd->wd) == STATUS_SUCCESS &&
	    pnp_start_device(wnd->wd) == STATUS_SUCCESS)
		memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	RtlFreeUnicodeString(&key);
	RtlFreeUnicodeString(&param.data.string);
	TRACEEXIT1(return 0);
}

static void show_supported_oids(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS res;
	int i, n, needed;
	ndis_oid *oids;

#ifndef DEBUG
	return;
#endif
	res = miniport_query_info_needed(wnd, OID_GEN_SUPPORTED_LIST, NULL, 0,
					 &needed);
	if (!(res == NDIS_STATUS_BUFFER_TOO_SHORT ||
	      res == NDIS_STATUS_INVALID_LENGTH))
		TRACEEXIT1(return);
	oids = kmalloc(needed, GFP_KERNEL);
	if (!oids) {
		DBGTRACE1("couldn't allocate memory");
		TRACEEXIT1(return);
	}
	res = miniport_query_info(wnd, OID_GEN_SUPPORTED_LIST, oids, needed);
	if (res) {
		DBGTRACE1("failed: %08X", res);
		kfree(oids);
		TRACEEXIT1(return);
	}
	for (i = 0, n = needed / sizeof(*oids); i < n; i++)
		DBGTRACE1("oid: %08X", oids[i]);
	kfree(oids);
	TRACEEXIT1(return);
}

static struct ndis_packet *
allocate_send_packet(struct wrap_ndis_device *wnd, ndis_buffer *buffer)
{
	struct ndis_packet *packet;
	struct ndis_packet_oob_data *oob_data;
	NDIS_STATUS status;

	NdisAllocatePacket(&status, &packet, wnd->wrapper_packet_pool);
	if (status != NDIS_STATUS_SUCCESS)
		return NULL;

	packet->private.buffer_head = buffer;
	packet->private.buffer_tail = buffer;

	oob_data = NDIS_PACKET_OOB_DATA(packet);
	if (wnd->use_sg_dma) {
		oob_data->ndis_sg_element.address =
			PCI_DMA_MAP_SINGLE(wnd->wd->pci.pdev,
					   MmGetMdlVirtualAddress(buffer),
					   MmGetMdlByteCount(buffer),
					   PCI_DMA_TODEVICE);

		oob_data->ndis_sg_element.length = MmGetMdlByteCount(buffer);
		oob_data->ndis_sg_list.nent = 1;
		oob_data->ndis_sg_list.elements = &oob_data->ndis_sg_element;
		oob_data->extension.info[ScatterGatherListPacketInfo] =
			&oob_data->ndis_sg_list;
	}
	return packet;
}

static void free_send_packet(struct wrap_ndis_device *wnd,
			     struct ndis_packet *packet)
{
	ndis_buffer *buffer;
	struct ndis_packet_oob_data *oob_data;

	TRACEENTER3("packet: %p", packet);
	buffer = packet->private.buffer_head;
	oob_data = NDIS_PACKET_OOB_DATA(packet);
	if (wnd->use_sg_dma)
		PCI_DMA_UNMAP_SINGLE(wnd->wd->pci.pdev,
				     oob_data->ndis_sg_element.address,
				     oob_data->ndis_sg_element.length,
				     PCI_DMA_TODEVICE);

	DBGTRACE3("freeing buffer %p", buffer);
	NdisFreeBuffer(buffer);
	dev_kfree_skb_any(oob_data->skb);

	DBGTRACE3("freeing packet %p", packet);
	NdisFreePacket(packet);
	TRACEEXIT3(return);
}

/*
 * MiniportSend and MiniportSendPackets
 * this function is called with lock held in DISPATCH_LEVEL, so no need
 * to raise irql to DISPATCH_LEVEL during MiniportSend(Packets)
*/
static int send_packets(struct wrap_ndis_device *wnd, unsigned int start,
			unsigned int pending)
{
	NDIS_STATUS res;
	struct miniport_char *miniport;
	unsigned int sent, n;
	struct ndis_packet *packet;

	TRACEENTER3("start: %d, pending: %d", start, pending);
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	if (pending > wnd->max_send_packets)
		n = wnd->max_send_packets;
	else
		n = pending;

	if (miniport->send_packets) {
		int i;
		/* copy packets from xmit ring to linear xmit array */
		for (i = 0; i < n; i++) {
			int j = (start + i) % XMIT_RING_SIZE;
			wnd->xmit_array[i] = wnd->xmit_ring[j];
		}
		LIN2WIN3(miniport->send_packets, wnd->nmb->adapter_ctx,
			 wnd->xmit_array, n);
		DBGTRACE3("sent");
		if (test_bit(ATTR_SERIALIZED, &wnd->attributes)) {
			for (sent = 0; sent < n && wnd->send_ok; sent++) {
				struct ndis_packet_oob_data *oob_data;
				packet = wnd->xmit_array[sent];
				oob_data = NDIS_PACKET_OOB_DATA(packet);
				switch(oob_data->status) {
				case NDIS_STATUS_SUCCESS:
					sendpacket_done(wnd, packet);
					break;
				case NDIS_STATUS_PENDING:
					break;
				case NDIS_STATUS_RESOURCES:
					wnd->send_ok = 0;
					break;
				case NDIS_STATUS_FAILURE:
				default:
					free_send_packet(wnd, packet);
					break;
				}
			}
		} else {
			sent = n;
		}
	} else {
		packet = wnd->xmit_ring[start];
		res = LIN2WIN3(miniport->send, wnd->nmb->adapter_ctx,
			       packet, 0);
		sent = 1;
		switch (res) {
		case NDIS_STATUS_SUCCESS:
			sendpacket_done(wnd, packet);
			break;
		case NDIS_STATUS_PENDING:
			break;
		case NDIS_STATUS_RESOURCES:
			wnd->send_ok = 0;
			sent = 0;
			break;
		case NDIS_STATUS_FAILURE:
			free_send_packet(wnd, packet);
			break;
		}
	}
	TRACEEXIT3(return sent);
}

static void xmit_worker(void *param)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)param;
	int n;
	KIRQL irql;

	TRACEENTER3("send_ok %d", wnd->send_ok);

	/* some drivers e.g., new RT2500 driver, crash if any packets
	 * are sent when the card is not associated */
	while (wnd->send_ok) {
		irql = nt_spin_lock_irql(&wnd->xmit_lock, DISPATCH_LEVEL);
		if (wnd->xmit_ring_pending == 0) {
			nt_spin_unlock_irql(&wnd->xmit_lock, irql);
			break;
		}
		n = send_packets(wnd, wnd->xmit_ring_start,
				 wnd->xmit_ring_pending);
		wnd->xmit_ring_start =
			(wnd->xmit_ring_start + n) % XMIT_RING_SIZE;
		wnd->xmit_ring_pending -= n;
		if (netif_queue_stopped(wnd->net_dev) && n > 0)
			netif_wake_queue(wnd->net_dev);
		nt_spin_unlock_irql(&wnd->xmit_lock, irql);
	}

	TRACEEXIT3(return);
}

/*
 * Free and unmap packet created in xmit
 */
void sendpacket_done(struct wrap_ndis_device *wnd,
		     struct ndis_packet *packet)
{

	TRACEENTER3("%p", packet);
	nt_spin_lock(&wnd->send_packet_done_lock);
	wnd->stats.tx_bytes += packet->private.len;
	wnd->stats.tx_packets++;
	nt_spin_unlock(&wnd->send_packet_done_lock);
	free_send_packet(wnd, packet);
	TRACEEXIT3(return);
}

/*
 * This function is called in BH disabled context and ndis drivers
 * must have their send-functions called from sleepeable context so we
 * just queue the packets up here and schedule a workqueue to run
 * later.
 */
static int start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	ndis_buffer *buffer;
	struct ndis_packet *packet;
	struct ndis_packet_oob_data *oob_data;
	unsigned int xmit_ring_next_slot;
	NDIS_STATUS res;

	NdisAllocateBuffer(&res, &buffer, wnd->wrapper_buffer_pool,
			   skb->data, skb->len);
	if (res != NDIS_STATUS_SUCCESS)
		return 1;
	packet = allocate_send_packet(wnd, buffer);
	if (!packet) {
		NdisFreeBuffer(buffer);
		return 1;
	}
	oob_data = NDIS_PACKET_OOB_DATA(packet);
	oob_data->skb = skb;
	nt_spin_lock(&wnd->xmit_lock);
	xmit_ring_next_slot = (wnd->xmit_ring_start +
			       wnd->xmit_ring_pending) % XMIT_RING_SIZE;
	wnd->xmit_ring[xmit_ring_next_slot] = packet;
	wnd->xmit_ring_pending++;
	if (wnd->xmit_ring_pending == XMIT_RING_SIZE)
		netif_stop_queue(wnd->net_dev);
	nt_spin_unlock(&wnd->xmit_lock);

	schedule_ndis_work(&wnd->xmit_work);

	return 0;
}

static int set_packet_filter(struct wrap_ndis_device *wnd, ULONG packet_filter)
{
	NDIS_STATUS res;
	ULONG filter = packet_filter;

	TRACEENTER3("%x", packet_filter);
	res = miniport_set_info(wnd, OID_GEN_CURRENT_PACKET_FILTER,
				&filter, sizeof(filter));
	if (res) {
		DBGTRACE1("couldn't set packet filter: %08X", res);
		TRACEEXIT3(return res);
	}
	wnd->packet_filter = packet_filter;
	TRACEEXIT3(return 0);
}

static int get_packet_filter(struct wrap_ndis_device *wnd,
			     ULONG *packet_filter)
{
	NDIS_STATUS res;

	TRACEENTER3("%p", wnd);
	res = miniport_query_info(wnd, OID_GEN_CURRENT_PACKET_FILTER,
				  packet_filter, sizeof(*packet_filter));
	if (res) {
		DBGTRACE1("couldn't get packet filter: %08X", res);
		TRACEEXIT3(return res);
	}
	TRACEEXIT3(return 0);
}

static int ndis_open(struct net_device *dev)
{
	ULONG packet_filter;
	struct wrap_ndis_device *wnd = netdev_priv(dev);

	TRACEENTER1("%p", wnd);
	packet_filter = NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST;
	/* add any dev specific filters */
	if (dev->flags & IFF_PROMISC)
		packet_filter |= NDIS_PACKET_TYPE_PROMISCUOUS |
			NDIS_PACKET_TYPE_ALL_LOCAL;
	if (set_packet_filter(wnd, packet_filter) &&
	    packet_filter & NDIS_PACKET_TYPE_PROMISCUOUS) {
		DBGTRACE1("couldn't add packet filter %x", packet_filter);
		packet_filter &= ~NDIS_PACKET_TYPE_PROMISCUOUS;
		if (set_packet_filter(wnd, packet_filter))
			DBGTRACE1("couldn't add packet filter %x",
				  packet_filter);
	}
	/* NDIS_PACKET_TYPE_PROMISCUOUS will not work with 802.11 */
	netif_device_attach(dev);
	netif_start_queue(dev);
	return 0;
}

static int ndis_close(struct net_device *dev)
{
	if (netif_running(dev)) {
		netif_tx_disable(dev);
		netif_device_detach(dev);
	}
	return 0;
}

static void update_wireless_stats(struct wrap_ndis_device *wnd)
{
	struct iw_statistics *iw_stats = &wnd->wireless_stats;
	struct ndis_wireless_stats ndis_stats;
	NDIS_STATUS res;
	ndis_rssi rssi;
	unsigned long frag;

	TRACEENTER2("%p", wnd);
	if (wnd->stats_enabled == FALSE || wnd->link_status == 0) {
		memset(iw_stats, 0, sizeof(*iw_stats));
		TRACEEXIT2(return);
	}
	res = miniport_query_info(wnd, OID_802_11_RSSI, &rssi, sizeof(rssi));
	if (res == NDIS_STATUS_SUCCESS)
		iw_stats->qual.level = rssi;

	memset(&ndis_stats, 0, sizeof(ndis_stats));
	res = miniport_query_info(wnd, OID_802_11_STATISTICS,
				  &ndis_stats, sizeof(ndis_stats));
	if (res != NDIS_STATUS_SUCCESS)
		TRACEEXIT2(return);
	iw_stats->discard.retries = (unsigned long)ndis_stats.retry +
		(unsigned long)ndis_stats.multi_retry;
	iw_stats->discard.misc = (unsigned long)ndis_stats.fcs_err +
		(unsigned long)ndis_stats.rtss_fail +
		(unsigned long)ndis_stats.ack_fail +
		(unsigned long)ndis_stats.frame_dup;

	frag = 6 * (unsigned long)ndis_stats.tx_frag;
	if (frag)
		iw_stats->qual.qual =
			100 - 100 * (((unsigned long)ndis_stats.retry +
				      2*(unsigned long)ndis_stats.multi_retry +
				      3*(unsigned long)ndis_stats.failed) /
				     frag);
	else
		iw_stats->qual.qual = 100;
	TRACEEXIT2(return);
}

static void set_multicast_list(struct wrap_ndis_device *wnd)
{
	struct net_device *net_dev;
	ULONG packet_filter;
	NDIS_STATUS res = 0;

	net_dev = wnd->net_dev;
	if (!(net_dev->mc_count > 0 ||
	      net_dev->flags & IFF_ALLMULTI))
		TRACEEXIT3(return);

	res = get_packet_filter(wnd, &packet_filter);
	if (res) {
//		WARNING("couldn't get packet filter: %08X", res);
		TRACEEXIT3(return);
	}

	packet_filter |= NDIS_PACKET_TYPE_MULTICAST;
	packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
	DBGTRACE2("packet filter: %08x", packet_filter);
	res = set_packet_filter(wnd, packet_filter);
	if (res)
		DBGTRACE1("couldn't set packet filter (%08X)", res);

	TRACEEXIT2(return);
}

static void link_status_handler(struct wrap_ndis_device *wnd)
{
	struct ndis_assoc_info *ndis_assoc_info;
#if WIRELESS_EXT < 18
	unsigned char *wpa_assoc_info, *ies;
	unsigned char *p;
	int i;
#endif
	unsigned char *assoc_info;
	union iwreq_data wrqu;
	NDIS_STATUS res;
	const int assoc_size = sizeof(*ndis_assoc_info) + IW_CUSTOM_MAX;

	TRACEENTER2("link status: %d", wnd->link_status);
	if (wnd->link_status == 0) {
#if 0
		unsigned int i;
		struct encr_info *encr_info = &wnd->encr_info;

		if (wnd->encr_mode == Ndis802_11Encryption1Enabled ||
		    wnd->infrastructure_mode == Ndis802_11IBSS) {
			for (i = 0; i < MAX_ENCR_KEYS; i++) {
				if (encr_info->keys[i].length == 0)
					continue;
				add_wep_key(wnd, encr_info->keys[i].key,
					    encr_info->keys[i].length, i);
			}

			set_bit(SET_ESSID, &wnd->wrap_ndis_work);
			schedule_ndis_work(&wnd->wrap_ndis_worker);
			TRACEEXIT2(return);
		}
		/* TODO: not clear if NDIS says keys should
		 * be cleared here */
		for (i = 0; i < MAX_ENCR_KEYS; i++)
			wnd->encr_info.keys[i].length = 0;
#endif

		memset(&wrqu, 0, sizeof(wrqu));
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
		wireless_send_event(wnd->net_dev, SIOCGIWAP, &wrqu, NULL);
		TRACEEXIT2(return);
	}

	if (!(test_bit(Ndis802_11Encryption2Enabled, &wnd->capa.encr) ||
	      test_bit(Ndis802_11Encryption3Enabled, &wnd->capa.encr)))
		TRACEEXIT2(return);

	assoc_info = kmalloc(assoc_size, GFP_KERNEL);
	if (!assoc_info) {
		ERROR("couldn't allocate memory");
		TRACEEXIT2(return);
	}
	memset(assoc_info, 0, assoc_size);

	ndis_assoc_info = (struct ndis_assoc_info *)assoc_info;
#if 0
	ndis_assoc_info->length = sizeof(*ndis_assoc_info);
	ndis_assoc_info->offset_req_ies = sizeof(*ndis_assoc_info);
	ndis_assoc_info->req_ie_length = IW_CUSTOM_MAX / 2;
	ndis_assoc_info->offset_resp_ies = sizeof(*ndis_assoc_info) +
		ndis_assoc_info->req_ie_length;
	ndis_assoc_info->resp_ie_length = IW_CUSTOM_MAX / 2;
#endif
	res = miniport_query_info(wnd, OID_802_11_ASSOCIATION_INFORMATION,
				  assoc_info, assoc_size);
	if (res) {
		DBGTRACE2("query assoc_info failed (%08X)", res);
		kfree(assoc_info);
		TRACEEXIT2(return);
	}

	/*
	 * TODO: backwards compatibility would require that IWEVCUSTOM
	 * is sent even if WIRELESS_EXT > 17. This version does not do
	 * this in order to allow wpa_supplicant to be tested with
	 * WE-18.
	 */
#if WIRELESS_EXT > 17
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.length = ndis_assoc_info->req_ie_length;
	wireless_send_event(wnd->net_dev, IWEVASSOCREQIE, &wrqu,
			    ((char *) ndis_assoc_info) +
			    ndis_assoc_info->offset_req_ies);
	wrqu.data.length = ndis_assoc_info->resp_ie_length;
	wireless_send_event(wnd->net_dev, IWEVASSOCRESPIE, &wrqu,
			    ((char *) ndis_assoc_info) +
			    ndis_assoc_info->offset_resp_ies);
#else
	/* we need 28 extra bytes for the format strings */
	if ((ndis_assoc_info->req_ie_length +
	     ndis_assoc_info->resp_ie_length + 28) > IW_CUSTOM_MAX) {
		WARNING("information element is too long! (%u,%u),"
			"association information dropped",
			ndis_assoc_info->req_ie_length,
			ndis_assoc_info->resp_ie_length);
		kfree(assoc_info);
		TRACEEXIT2(return);
	}

	wpa_assoc_info = kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
	if (!wpa_assoc_info) {
		ERROR("couldn't allocate memory");
		kfree(assoc_info);
		TRACEEXIT2(return);
	}
	p = wpa_assoc_info;
	p += sprintf(p, "ASSOCINFO(ReqIEs=");
	ies = ((char *)ndis_assoc_info) +
		ndis_assoc_info->offset_req_ies;
	for (i = 0; i < ndis_assoc_info->req_ie_length; i++)
		p += sprintf(p, "%02x", ies[i]);

	p += sprintf(p, " RespIEs=");
	ies = ((char *)ndis_assoc_info) +
		ndis_assoc_info->offset_resp_ies;
	for (i = 0; i < ndis_assoc_info->resp_ie_length; i++)
		p += sprintf(p, "%02x", ies[i]);

	p += sprintf(p, ")");

	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.length = p - wpa_assoc_info;
	DBGTRACE2("adding %d bytes", wrqu.data.length);
	wireless_send_event(wnd->net_dev, IWEVCUSTOM, &wrqu, wpa_assoc_info);

	kfree(wpa_assoc_info);
#endif
	kfree(assoc_info);

	get_ap_address(wnd, (char *)&wrqu.ap_addr.sa_data);
	wrqu.ap_addr.sa_family = ARPHRD_ETHER;
	wireless_send_event(wnd->net_dev, SIOCGIWAP, &wrqu, NULL);
	DBGTRACE2("associate to " MACSTR, MAC2STR(wrqu.ap_addr.sa_data));
	TRACEEXIT2(return);
}

static void stats_proc(unsigned long data)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;

	set_bit(COLLECT_STATS, &wnd->wrap_ndis_work);
	schedule_ndis_work(&wnd->wrap_ndis_worker);
	wnd->stats_timer.expires += 10 * HZ;
	add_timer(&wnd->stats_timer);
}

static void stats_timer_add(struct wrap_ndis_device *wnd)
{
	init_timer(&wnd->stats_timer);
	wnd->stats_timer.data = (unsigned long)wnd;
	wnd->stats_timer.function = &stats_proc;
	wnd->stats_timer.expires = jiffies + 10 * HZ;
	add_timer(&wnd->stats_timer);
}

static void stats_timer_del(struct wrap_ndis_device *wnd)
{
	del_timer_sync(&wnd->stats_timer);
}

static void hangcheck_proc(unsigned long data)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;

	TRACEENTER3("");
	set_bit(HANGCHECK, &wnd->wrap_ndis_work);
	schedule_ndis_work(&wnd->wrap_ndis_worker);

	wnd->hangcheck_timer.expires += wnd->hangcheck_interval;
	add_timer(&wnd->hangcheck_timer);

	TRACEEXIT3(return);
}

void hangcheck_add(struct wrap_ndis_device *wnd)
{
	if (!wnd->wd->driver->ndis_driver->miniport.hangcheck ||
	    hangcheck_interval < 0)
		return;
	if (hangcheck_interval > 0)
		wnd->hangcheck_interval = hangcheck_interval * HZ;
	init_timer(&wnd->hangcheck_timer);
	wnd->hangcheck_timer.data = (unsigned long)wnd;
	wnd->hangcheck_timer.function = &hangcheck_proc;
	wnd->hangcheck_timer.expires = jiffies + wnd->hangcheck_interval;
	add_timer(&wnd->hangcheck_timer);
	return;
}

void hangcheck_del(struct wrap_ndis_device *wnd)
{
	del_timer_sync(&wnd->hangcheck_timer);
}

#ifdef HAVE_ETHTOOL
static u32 ndis_get_link(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return wnd->link_status;
}

static struct ethtool_ops ndis_ethtool_ops = {
	.get_link		= ndis_get_link,
};
#endif

/* worker procedure to take care of setting/checking various states */
static void wrap_ndis_worker_proc(void *param)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)param;

	DBGTRACE2("%lu", wnd->wrap_ndis_work);

	if (test_bit(SHUTDOWN, &wnd->wrap_ndis_work) ||
	    !test_bit(HW_INITIALIZED, &wnd->hw_status))
		TRACEEXIT3(return);

	if (test_and_clear_bit(SET_INFRA_MODE, &wnd->wrap_ndis_work))
		set_infra_mode(wnd, wnd->infrastructure_mode);

	if (test_and_clear_bit(SET_ESSID, &wnd->wrap_ndis_work))
		set_essid(wnd, wnd->essid.essid, wnd->essid.length);

	if (test_and_clear_bit(SET_MULTICAST_LIST, &wnd->wrap_ndis_work))
		set_multicast_list(wnd);

	if (test_and_clear_bit(COLLECT_STATS, &wnd->wrap_ndis_work))
		update_wireless_stats(wnd);

	if (test_and_clear_bit(LINK_STATUS_CHANGED, &wnd->wrap_ndis_work))
		link_status_handler(wnd);

	if (test_and_clear_bit(HANGCHECK, &wnd->wrap_ndis_work)) {
		NDIS_STATUS res;
		struct miniport_char *miniport;
		KIRQL irql;

		miniport = &wnd->wd->driver->ndis_driver->miniport;
		irql = raise_irql(DISPATCH_LEVEL);
		res = LIN2WIN1(miniport->hangcheck, wnd->nmb->adapter_ctx);
		lower_irql(irql);
		if (res) {
			WARNING("%s is being reset", wnd->net_dev->name);
			res = miniport_reset(wnd);
			DBGTRACE3("reset returns %08X", res);
		}
	}
	TRACEEXIT3(return);
}

struct iw_statistics *get_wireless_stats(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return &wnd->wireless_stats;
}

NDIS_STATUS ndis_reinit(struct wrap_ndis_device *wnd)
{
	pnp_stop_device(wnd->wd);
	return pnp_start_device(wnd->wd);
}

/* check capabilites - mainly for WPA */
void check_capa(struct wrap_ndis_device *wnd)
{
	int i, mode;
	NDIS_STATUS res;
	struct ndis_assoc_info ndis_assoc_info;
	struct ndis_add_key ndis_key;
	struct ndis_capability *c;
	char *buf;
	const int buf_len = 512;

	TRACEENTER1("%p", wnd);
	/* check if WEP is supported */
	if (set_encr_mode(wnd, Ndis802_11Encryption1Enabled) == 0 &&
	    get_encr_mode(wnd) == Ndis802_11Encryption1KeyAbsent)
		set_bit(Ndis802_11Encryption1Enabled, &wnd->capa.encr);

	/* check if WPA is supported */
	if (set_auth_mode(wnd, Ndis802_11AuthModeWPA) == 0 &&
	    get_auth_mode(wnd) == Ndis802_11AuthModeWPA)
		set_bit(Ndis802_11AuthModeWPA, &wnd->capa.auth);
	else
		TRACEEXIT1(return);

	if (set_auth_mode(wnd, Ndis802_11AuthModeWPAPSK) == 0 &&
	    get_auth_mode(wnd) == Ndis802_11AuthModeWPAPSK)
		set_bit(Ndis802_11AuthModeWPAPSK, &wnd->capa.auth);

	/* check for highest encryption */
	mode = 0;
	if (set_encr_mode(wnd, Ndis802_11Encryption3Enabled) == 0 &&
	    (i = get_encr_mode(wnd)) > 0 &&
	    (i == Ndis802_11Encryption3KeyAbsent ||
	     i == Ndis802_11Encryption3Enabled))
		mode = Ndis802_11Encryption3Enabled;
	else if (set_encr_mode(wnd, Ndis802_11Encryption2Enabled) == 0 &&
		 (i = get_encr_mode(wnd)) > 0 &&
		 (i == Ndis802_11Encryption2KeyAbsent ||
		  i == Ndis802_11Encryption2Enabled))
		mode = Ndis802_11Encryption2Enabled;
	else if (set_encr_mode(wnd, Ndis802_11Encryption1Enabled) == 0 &&
		 (i = get_encr_mode(wnd)) > 0 &&
		 (i == Ndis802_11Encryption1KeyAbsent ||
		  i == Ndis802_11Encryption1Enabled))
		mode = Ndis802_11Encryption1Enabled;

	DBGTRACE1("mode: %d", mode);
	if (mode == 0)
		TRACEEXIT1(return);
	set_bit(Ndis802_11Encryption1Enabled, &wnd->capa.encr);
	if (mode == Ndis802_11Encryption1Enabled)
		TRACEEXIT1(return);

	ndis_key.length = 32;
	ndis_key.index = 0xC0000001;
	ndis_key.struct_size = sizeof(ndis_key);
	res = miniport_set_info(wnd, OID_802_11_ADD_KEY, &ndis_key,
				ndis_key.struct_size);
	DBGTRACE2("add key returns %08X, size = %lu",
		  res, (unsigned long)sizeof(ndis_key));
	if (res && res != NDIS_STATUS_INVALID_DATA)
		TRACEEXIT1(return);
	res = miniport_query_info(wnd, OID_802_11_ASSOCIATION_INFORMATION,
				  &ndis_assoc_info, sizeof(ndis_assoc_info));
	DBGTRACE1("assoc info returns %08X", res);
	if (res == NDIS_STATUS_NOT_SUPPORTED)
		TRACEEXIT1(return);

	set_bit(Ndis802_11Encryption2Enabled, &wnd->capa.encr);
	if (mode == Ndis802_11Encryption3Enabled)
		set_bit(Ndis802_11Encryption3Enabled, &wnd->capa.encr);
	/* not all drivers support OID_802_11_CAPABILITY, so we don't
	 * know for sure if driver support WPA or WPAPSK; assume
	 * WPA */
	set_bit(Ndis802_11AuthModeWPA, &wnd->capa.auth);

	/* check for wpa2 */
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		ERROR("couldn't allocate memory");
		TRACEEXIT1(return);
	}
	memset(buf, 0, buf_len);
	c = (struct ndis_capability *)buf;
	res = miniport_query_info(wnd, OID_802_11_CAPABILITY, buf, buf_len);
	if (!(res == NDIS_STATUS_SUCCESS && c->version == 2)) {
		DBGTRACE1("res: %X", res);
		kfree(buf);
		TRACEEXIT1(return);
	}
	wnd->num_pmkids = c->num_PMKIDs;

	for (i = 0; i < c->num_auth_encr_pair; i++) {
		struct ndis_auth_encr_pair *ae;

		ae = &c->auth_encr_pair[i];
		if ((char *)(ae + 1) > buf + buf_len)
			break;
		switch (ae->auth_mode) {
		case Ndis802_11AuthModeOpen:
		case Ndis802_11AuthModeShared:
		case Ndis802_11AuthModeWPA:
		case Ndis802_11AuthModeWPAPSK:
		case Ndis802_11AuthModeWPANone:
		case Ndis802_11AuthModeWPA2:
		case Ndis802_11AuthModeWPA2PSK:
			set_bit(ae->auth_mode, &wnd->capa.auth);
			break;
		default:
			WARNING("unknown auth_mode: %d", ae->auth_mode);
			break;
		}
		switch (ae->encr_mode) {
		case Ndis802_11EncryptionDisabled:
		case Ndis802_11Encryption1Enabled:
		case Ndis802_11Encryption2Enabled:
		case Ndis802_11Encryption3Enabled:
			set_bit(ae->encr_mode, &wnd->capa.encr);
			break;
		default:
			WARNING("unknown encr_mode: %d", ae->encr_mode);
			break;
		}
	}
	kfree(buf);
	TRACEEXIT1(return);
}

static NDIS_STATUS miniport_set_power_state(struct wrap_ndis_device *wnd,
					    enum ndis_power_state state)
{
	NDIS_STATUS status;
	struct miniport_char *miniport;

	TRACEENTER2("state: %d", state);
	if (state == NdisDeviceStateD0) {
		status = STATUS_SUCCESS;
		if (test_and_clear_bit(HW_HALTED, &wnd->hw_status)) {
			DBGTRACE2("starting device");
			/* TODO: should we use pnp_start_device instead? */
			if (miniport_init(wnd) != NDIS_STATUS_SUCCESS) {
				WARNING("couldn't re-initialize device %s",
					wnd->net_dev->name);
				TRACEEXIT2(return NDIS_STATUS_FAILURE);
			}
		}
		if (test_and_clear_bit(HW_SUSPENDED, &wnd->hw_status)) {
			status = miniport_set_int(wnd, OID_PNP_SET_POWER,
						  NdisDeviceStateD0);
			DBGTRACE2("set_power returns %08X", status);
			miniport = &wnd->wd->driver->ndis_driver->miniport;
			if (status == NDIS_STATUS_SUCCESS)
				miniport_pnp_event(wnd,
				   NdisDevicePnPEventPowerProfileChanged);
		}
		TRACEEXIT1(return status);
	} else {
		status = miniport_set_int(wnd, OID_PNP_SET_POWER, state);
		if (status == NDIS_STATUS_SUCCESS)
			set_bit(HW_SUSPENDED, &wnd->hw_status);
		else
			WARNING("setting power state to %d failed: %08X",
				state, status);
		if (status != NDIS_STATUS_SUCCESS) {
			WARNING("device may not support power management");
			DBGTRACE2("no pm: halting the device");
			/* TODO: should we use pnp_stop_device instead? */
			miniport_halt(wnd);
			set_bit(HW_HALTED, &wnd->hw_status);
			status = STATUS_SUCCESS;
		}
		TRACEEXIT1(return status);
	}
}

static NTSTATUS _NdisDispatchDeviceControl(struct device_object *fdo,
					  struct irp *irp)
{
	struct wrap_ndis_device *wnd;

	DBGTRACE3("fdo: %p", fdo);
	/* for now, we don't have anything intresting here, so pass it
	 * down to bus driver */
	wnd = fdo->reserved;
	return LIN2WIN2(winIopPassIrpDown, wnd->nmb->pdo, irp);
}

STDCALL NTSTATUS winNdisDispatchDeviceControl(struct device_object *fdo,
					      struct irp *irp)
{
	unsigned long ret;
	WIN2LIN2(_NdisDispatchDeviceControl, fdo, irp, ret);
	return ret;
}

NTSTATUS _NdisDispatchPower(struct device_object *fdo, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrap_ndis_device *wnd;
	enum ndis_power_state state;
	NTSTATUS status;
	NDIS_STATUS ndis_status;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wnd = fdo->reserved;
	IOTRACE("fdo: %p, fn: %d:%d, wnd: %p", fdo, irp_sl->major_fn,
		irp_sl->minor_fn, wnd);
	if (irp_sl->params.power.state.device_state == PowerDeviceD0)
		state = NdisDeviceStateD0;
	else
		state = NdisDeviceStateD3;
	switch (irp_sl->minor_fn) {
	case IRP_MN_SET_POWER:
		if (state == NdisDeviceStateD0) {
			IoCopyCurrentIrpStackLocationToNext(irp);
			IoSetCompletionRoutine(irp, winIrpStopCompletion, wnd,
					       TRUE, FALSE, FALSE);
			status = IoCallDriver(wnd->nmb->pdo, irp);
			if (status != STATUS_SUCCESS)
				break;
			ndis_status = miniport_set_power_state(wnd, state);
			if (ndis_status != NDIS_STATUS_SUCCESS)
				WARNING("setting power to %d failed: %08X",
					state, ndis_status);
			hangcheck_add(wnd);
			stats_timer_add(wnd);
			set_scan(wnd);
			set_bit(SET_ESSID, &wnd->wrap_ndis_work);
			if (netif_running(wnd->net_dev)) {
				netif_device_attach(wnd->net_dev);
				netif_wake_queue(wnd->net_dev);
			}
			netif_poll_enable(wnd->net_dev);
			DBGTRACE2("%s: device resumed", wnd->net_dev->name);
			TRACEEXIT2(return STATUS_SUCCESS);
		} else {
			if (test_bit(HW_SUSPENDED, &wnd->hw_status) ||
			    test_bit(HW_HALTED, &wnd->hw_status))
				return STATUS_FAILURE;
			DBGTRACE2("irql: %d", current_irql());
			netif_poll_disable(wnd->net_dev);
			if (netif_running(wnd->net_dev)) {
				netif_tx_disable(wnd->net_dev);
				netif_device_detach(wnd->net_dev);
			}
			hangcheck_del(wnd);
			stats_timer_del(wnd);
			ndis_status = miniport_set_power_state(wnd, state);
			/* TODO: we need to send the IRP back with
			 * error so that pdo can restart device */
			if (ndis_status != NDIS_STATUS_SUCCESS)
				WARNING("setting power to %d failed: %08X",
					state, ndis_status);
			return LIN2WIN2(winIopPassIrpDown, wnd->nmb->pdo, irp);
		}
		status = STATUS_SUCCESS;
		break;
	case IRP_MN_QUERY_POWER:
		ndis_status = miniport_query_int(wnd, OID_PNP_QUERY_POWER,
						 &state);
		DBGTRACE2("query_power to state %d returns %08X",
			  state, ndis_status);
		if (ndis_status == NDIS_STATUS_SUCCESS)
			status = STATUS_SUCCESS;
		else
			status = STATUS_FAILURE;
		break;
	case IRP_MN_WAIT_WAKE:
	case IRP_MN_POWER_SEQUENCE:
		/* TODO: implement WAIT_WAKE */
		status = STATUS_NOT_SUPPORTED;
		break;
	default:
		return LIN2WIN2(winIopPassIrpDown, wnd->nmb->pdo, irp);
	}
	irp->io_status.status_info = 0;
	irp->io_status.status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

STDCALL NTSTATUS winNdisDispatchPower(struct device_object *fdo,
				      struct irp *irp)
{
	unsigned long ret;
	WIN2LIN2(_NdisDispatchPower, fdo, irp, ret);
	return ret;
}

NTSTATUS _NdisDispatchPnp(struct device_object *fdo, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrap_ndis_device *wnd;
	struct device_object *pdo;
	NTSTATUS status;

	IOENTER("fdo: %p, irp: %p", fdo, irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wnd = fdo->reserved;
	pdo = wnd->nmb->pdo;
	IOTRACE("fn %d:%d, wnd: %p, fdo: %p, pdo: %p",
		irp_sl->major_fn, irp_sl->minor_fn, wnd, fdo, pdo);
	switch (irp_sl->minor_fn) {
	case IRP_MN_START_DEVICE:
		IoCopyCurrentIrpStackLocationToNext(irp);
		IoSetCompletionRoutine(irp, winIrpStopCompletion, wnd, TRUE,
				       FALSE, FALSE);
		status = IoCallDriver(pdo, irp);
		if (status != STATUS_SUCCESS)
			break;
		if (ndis_start_device(wnd) == NDIS_STATUS_SUCCESS)
			status = STATUS_SUCCESS;
		else
			status = STATUS_FAILURE;
		break;
	case IRP_MN_QUERY_STOP_DEVICE:
		return LIN2WIN2(winIopPassIrpDown, pdo, irp);
	case IRP_MN_STOP_DEVICE:
		miniport_halt(wnd);
		return LIN2WIN2(winIopPassIrpDown, pdo, irp);
	case IRP_MN_REMOVE_DEVICE:
		DBGTRACE1("%s", wnd->net_dev->name);
		if (ndis_remove_device(wnd) != NDIS_STATUS_SUCCESS) {
			status = STATUS_FAILURE;
			break;
		}
		return LIN2WIN2(winIopPassIrpDown, pdo, irp);
	default:
		return LIN2WIN2(winIopPassIrpDown, pdo, irp);
	}
	irp->io_status.status = status;
	IOTRACE("res: %08X", status);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

STDCALL NTSTATUS winNdisDispatchPnp(struct device_object *fdo,
				      struct irp *irp)
{
	unsigned long ret;
	WIN2LIN2(_NdisDispatchPnp, fdo, irp, ret);
	return ret;
}

static NDIS_STATUS ndis_start_device(struct wrap_ndis_device *wnd)
{
	struct wrap_device *wd;
	struct net_device *net_dev;
	NDIS_STATUS ndis_status;
	mac_address mac;
	char buf[256];

	if (miniport_init(wnd) != NDIS_STATUS_SUCCESS)
		return NDIS_STATUS_FAILURE;
	/* NB: xmit_array is used to recognize if device is being
	 * started for the first time or being re-started */
	if (wnd->xmit_array)
		TRACEEXIT2(return NDIS_STATUS_SUCCESS);
	wd = wnd->wd;
	net_dev = wnd->net_dev;
	show_supported_oids(wnd);
	strncpy(net_dev->name, if_name, IFNAMSIZ-1);
	net_dev->name[IFNAMSIZ-1] = '\0';

	DBGTRACE1("%s: querying for mac", DRIVER_NAME);
	ndis_status = miniport_query_info(wnd, OID_802_3_CURRENT_ADDRESS,
					  mac, sizeof(mac));
	if (ndis_status) {
		ERROR("couldn't get mac address: %08X", ndis_status);
		goto err_start;
	}
	DBGTRACE1("mac:" MACSTR, MAC2STR(mac));
	memcpy(&net_dev->dev_addr, mac, ETH_ALEN);

	net_dev->open = ndis_open;
	net_dev->hard_start_xmit = start_xmit;
	net_dev->stop = ndis_close;
	net_dev->get_stats = ndis_get_stats;
	net_dev->do_ioctl = ndis_ioctl;
#if WIRELESS_EXT < 19
	net_dev->get_wireless_stats = get_wireless_stats;
#endif
	net_dev->wireless_handlers =
		(struct iw_handler_def *)&ndis_handler_def;
	net_dev->set_multicast_list = ndis_set_multicast_list;
	net_dev->set_mac_address = ndis_set_mac_addr;
#ifdef HAVE_ETHTOOL
	net_dev->ethtool_ops = &ndis_ethtool_ops;
#endif
	if (wnd->ndis_irq)
		net_dev->irq = wnd->ndis_irq->irq.irq;
	net_dev->mem_start = wnd->mem_start;
	net_dev->mem_end = wnd->mem_end;
	if (register_netdev(net_dev)) {
		ERROR("cannot register net device %s", net_dev->name);
		goto err_start;
	}

	memset(buf, 0, sizeof(buf));
	ndis_status = miniport_query_info(wnd, OID_GEN_VENDOR_DESCRIPTION,
					  buf, sizeof(buf));
	if (ndis_status == NDIS_STATUS_SUCCESS)
		printk(KERN_INFO "%s: vendor: '%s'\n", net_dev->name, buf);

	printk(KERN_INFO "%s: %s ethernet device " MACSTR " using driver %s,"
	       " %s\n", net_dev->name, DRIVER_NAME, MAC2STR(net_dev->dev_addr),
	       wnd->wd->driver->name, wnd->wd->conf_file_name);

	check_capa(wnd);
	DBGTRACE1("capbilities = %ld", wnd->capa.encr);
	printk(KERN_INFO "%s: encryption modes supported: %s%s%s%s%s%s%s\n",
	       net_dev->name,
	       test_bit(Ndis802_11Encryption1Enabled, &wnd->capa.encr) ?
	       "WEP" : "none",

	       test_bit(Ndis802_11Encryption2Enabled, &wnd->capa.encr) ?
	       "; TKIP with WPA" : "",
	       test_bit(Ndis802_11AuthModeWPA2, &wnd->capa.auth) ?
	       ", WPA2" : "",
	       test_bit(Ndis802_11AuthModeWPA2PSK, &wnd->capa.auth) ?
	       ", WPA2PSK" : "",

	       test_bit(Ndis802_11Encryption3Enabled, &wnd->capa.encr) ?
	       "; AES/CCMP with WPA" : "",
	       test_bit(Ndis802_11AuthModeWPA2, &wnd->capa.auth) ?
	       ", WPA2" : "",
	       test_bit(Ndis802_11AuthModeWPA2PSK, &wnd->capa.auth) ?
	       ", WPA2PSK" : "");

	if (test_bit(ATTR_SERIALIZED, &wnd->attributes)) {
		ndis_status =
			miniport_query_int(wnd, OID_GEN_MAXIMUM_SEND_PACKETS,
					   &wnd->max_send_packets);
		if (ndis_status == NDIS_STATUS_NOT_SUPPORTED)
			wnd->max_send_packets = 1;
		if (wnd->max_send_packets > XMIT_RING_SIZE)
			wnd->max_send_packets = XMIT_RING_SIZE;
	} else {
		/* deserialized drivers don't have a limit, but we
		 * keep max at XMIT_RING_SIZE to allocate xmit_array
		 * below */
		wnd->max_send_packets = XMIT_RING_SIZE;
	}

	DBGTRACE1("maximum send packets: %d", wnd->max_send_packets);
	wnd->xmit_array =
		kmalloc(sizeof(struct ndis_packet *) * wnd->max_send_packets,
			GFP_KERNEL);
	if (!wnd->xmit_array) {
		ERROR("couldn't allocate memory for tx_packets");
		goto err_start;

	}
	/* we need at least one extra packet for
	 * EthRxIndicateHandler */
	NdisAllocatePacketPoolEx(&ndis_status, &wnd->wrapper_packet_pool,
				 wnd->max_send_packets + 1, 0,
				 PROTOCOL_RESERVED_SIZE_IN_PACKET);
	if (ndis_status != NDIS_STATUS_SUCCESS) {
		ERROR("couldn't allocate packet pool");
		goto packet_pool_err;
	}
	NdisAllocateBufferPool(&ndis_status, &wnd->wrapper_buffer_pool,
			       wnd->max_send_packets + 4);
	if (ndis_status != NDIS_STATUS_SUCCESS) {
		ERROR("couldn't allocate buffer pool");
		goto buffer_pool_err;
	}
	DBGTRACE1("pool: %p", wnd->wrapper_buffer_pool);
	miniport_set_int(wnd, OID_802_11_NETWORK_TYPE_IN_USE,
			 Ndis802_11Automode);
//	miniport_set_int(wnd, OID_802_11_POWER_MODE, NDIS_POWER_OFF);
	/* check_capa changes auth_mode and encr_mode, so set them again */
	set_infra_mode(wnd, Ndis802_11Infrastructure);
	set_auth_mode(wnd, Ndis802_11AuthModeOpen);
	set_encr_mode(wnd, Ndis802_11EncryptionDisabled);
	set_scan(wnd);
	set_privacy_filter(wnd, Ndis802_11PrivFilterAcceptAll);
	set_essid(wnd, "", 0);

	wrap_procfs_add_ndis_device(wnd);
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);

buffer_pool_err:
	wnd->wrapper_buffer_pool = NULL;
	if (wnd->wrapper_packet_pool) {
		NdisFreePacketPool(wnd->wrapper_packet_pool);
		wnd->wrapper_packet_pool = NULL;
	}
packet_pool_err:
	kfree(wnd->xmit_array);
	wnd->xmit_array = NULL;
err_start:
	ndis_remove_device(wnd);
	TRACEEXIT1(return NDIS_STATUS_FAILURE);
}

static NDIS_STATUS ndis_remove_device(struct wrap_ndis_device *wnd)
{
	KIRQL irql;

	set_bit(SHUTDOWN, &wnd->wrap_ndis_work);
	miniport_pnp_event(wnd, NdisDevicePnPEventSurpriseRemoved);
	ndis_close(wnd->net_dev);
	netif_carrier_off(wnd->net_dev);
	wrap_procfs_remove_ndis_device(wnd);
	/* throw away pending packets */
	irql = nt_spin_lock_irql(&wnd->xmit_lock, DISPATCH_LEVEL);
	while (wnd->xmit_ring_pending) {
		struct ndis_packet *packet;

		packet = wnd->xmit_ring[wnd->xmit_ring_start];
		free_send_packet(wnd, packet);
		wnd->xmit_ring_start =
			(wnd->xmit_ring_start + 1) % XMIT_RING_SIZE;
		wnd->xmit_ring_pending--;
	}
	nt_spin_unlock_irql(&wnd->xmit_lock, irql);
	miniport_halt(wnd);
	ndis_exit_device(wnd);
	/* flush_scheduled_work here causes crash with 2.4 kernels */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	flush_scheduled_work();
#endif
	if (wnd->wrapper_packet_pool) {
		NdisFreePacketPool(wnd->wrapper_packet_pool);
		wnd->wrapper_packet_pool = NULL;
	}
	if (wnd->wrapper_buffer_pool) {
		NdisFreeBufferPool(wnd->wrapper_buffer_pool);
		wnd->wrapper_buffer_pool = NULL;
	}
	IoDetachDevice(wnd->nmb->next_device);
	IoDeleteDevice(wnd->nmb->fdo);
	if (wnd->xmit_array)
		kfree(wnd->xmit_array);
	printk(KERN_INFO "%s: device %s removed\n", DRIVER_NAME,
	       wnd->net_dev->name);
	unregister_netdev(wnd->net_dev);
	free_netdev(wnd->net_dev);
	TRACEEXIT2(return NDIS_STATUS_SUCCESS);
}

static STDCALL NTSTATUS NdisAddDevice(struct driver_object *drv_obj,
				      struct device_object *pdo)
{
	struct device_object *fdo;
	struct ndis_miniport_block *nmb;
	NTSTATUS status;
	struct wrap_ndis_device *wnd;
	struct net_device *net_dev;
	struct wrap_device *wd;
	int i;

	TRACEENTER2("%p, %p", drv_obj, pdo);
	if (strlen(if_name) > (IFNAMSIZ-1)) {
		ERROR("interface name '%s' is too long", if_name);
		return STATUS_INVALID_PARAMETER;
	}
	net_dev = alloc_etherdev(sizeof(*wnd) + sizeof(*nmb));
	if (!net_dev) {
		ERROR("couldn't allocate device");
		return STATUS_RESOURCES;
	}
	wd = pdo->reserved;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	SET_MODULE_OWNER(net_dev);
	if (wrap_is_pci_bus(wd->dev_bus_type))
		SET_NETDEV_DEV(net_dev, &wd->pci.pdev->dev);
	if (wrap_is_usb_bus(wd->dev_bus_type))
		SET_NETDEV_DEV(net_dev, &wd->usb.intf->dev);
#endif
	status = IoCreateDevice(drv_obj, 0, NULL, FILE_DEVICE_UNKNOWN, 0,
				FALSE, &fdo);
	if (status != STATUS_SUCCESS) {
		free_netdev(net_dev);
		TRACEEXIT2(return status);
	}
	wnd = netdev_priv(net_dev);
	DBGTRACE1("wnd: %p", wnd);

	nmb = ((void *)wnd) + sizeof(*wnd);
	wnd->nmb = nmb;
	nmb->wnd = wnd;
	wnd->nmb->pdo = pdo;
	wd->wnd = wnd;
	wnd->wd = wd;
	nmb->filterdbs.eth_db = nmb;
	nmb->filterdbs.tr_db = nmb;
	nmb->filterdbs.fddi_db = nmb;
	nmb->filterdbs.arc_db = nmb;

	KeInitializeSpinLock(&nmb->lock);
	init_nmb_functions(nmb);
	wnd->net_dev = net_dev;
	wnd->ndis_irq = NULL;
	nt_spin_lock_init(&wnd->xmit_lock);
	init_MUTEX(&wnd->ndis_comm_mutex);
	init_waitqueue_head(&wnd->ndis_comm_wq);
	wnd->ndis_comm_done = 0;
	/* don't send packets until the card is associated */
	wnd->send_ok = 0;
	INIT_WORK(&wnd->xmit_work, xmit_worker, wnd);
	wnd->xmit_ring_start = 0;
	wnd->xmit_ring_pending = 0;
	nt_spin_lock_init(&wnd->send_packet_done_lock);
	wnd->encr_mode = Ndis802_11EncryptionDisabled;
	wnd->auth_mode = Ndis802_11AuthModeOpen;
	wnd->capa.encr = 0;
	wnd->capa.auth = 0;
	wnd->attributes = 0;
	wnd->dma_map_count = 0;
	wnd->dma_map_addr = NULL;
	wnd->nick[0] = 0;
	init_timer(&wnd->hangcheck_timer);
	wnd->scan_timestamp = 0;
	init_timer(&wnd->stats_timer);
	wnd->wrap_ndis_work = 0;
	memset(&wnd->essid, 0, sizeof(wnd->essid));
	memset(&wnd->encr_info, 0, sizeof(wnd->encr_info));
	wnd->infrastructure_mode = Ndis802_11Infrastructure;
	INIT_WORK(&wnd->wrap_ndis_worker, wrap_ndis_worker_proc, wnd);
	wnd->hw_status = 0;
	set_bit(HW_AVAILABLE, &wnd->hw_status);
	if (wd->driver->ndis_driver)
		wd->driver->ndis_driver->miniport.shutdown = NULL;
	/* ZyDas driver doesn't call completion function when
	 * querying for stats or rssi, so disable stats */
	if (stricmp(wd->driver->name, "zd1211u") == 0)
		wnd->stats_enabled = FALSE;
	else
		wnd->stats_enabled = TRUE;

	fdo->reserved = wnd;
	nmb = wnd->nmb;
	nmb->fdo = fdo;
	nmb->next_device = IoAttachDeviceToDeviceStack(fdo, pdo);
	DBGTRACE1("nmb: %p, pdo: %p, fdo: %p, attached: %p, next: %p",
		  nmb, pdo, fdo, fdo->attached, nmb->next_device);

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv_obj->major_func[i] = winIopPassIrpDown;
	drv_obj->major_func[IRP_MJ_PNP] = winNdisDispatchPnp;
	drv_obj->major_func[IRP_MJ_POWER] = winNdisDispatchPower;
	drv_obj->major_func[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
		winNdisDispatchDeviceControl;
	drv_obj->major_func[IRP_MJ_DEVICE_CONTROL] =
		winNdisDispatchDeviceControl;
	TRACEEXIT2(return STATUS_SUCCESS);
}

int init_ndis_driver(struct driver_object *drv_obj)
{
	drv_obj->drv_ext->add_device = NdisAddDevice;
	return 0;
}
