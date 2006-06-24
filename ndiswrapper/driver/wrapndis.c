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

extern char *if_name;
extern int hangcheck_interval;
extern struct iw_handler_def ndis_handler_def;

static int set_packet_filter(struct wrap_ndis_device *wnd,
			     ULONG packet_filter);
static void add_stats_timer(struct wrap_ndis_device *wnd);
static void del_stats_timer(struct wrap_ndis_device *wnd);
static NDIS_STATUS ndis_start_device(struct wrap_ndis_device *wnd);
static int ndis_remove_device(struct wrap_ndis_device *wnd);
static void set_multicast_list(struct wrap_ndis_device *wnd);

static inline int ndis_wait_comm_completion(struct wrap_ndis_device *wnd)
{
	if ((wait_event_interruptible(wnd->ndis_comm_wq,
				      (wnd->ndis_comm_done > 0))))
		return -1;
	else
		return 0;
}

/* MiniportReset */
NDIS_STATUS miniport_reset(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS res;
	struct miniport_char *miniport;
	UINT cur_lookahead, max_lookahead;
	BOOLEAN reset_address;
	KIRQL irql;

	TRACEENTER2("wnd: %p", wnd);

	if (down_interruptible(&wnd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	down_interruptible(&wnd->tx_ring_mutex);
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	cur_lookahead = wnd->nmb->cur_lookahead;
	max_lookahead = wnd->nmb->max_lookahead;
	if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE)
		irql = raise_irql(DISPATCH_LEVEL);
	else
		irql = nt_spin_lock_irql(&wnd->nmb->lock, DISPATCH_LEVEL);
	wnd->ndis_comm_done = 0;
	res = LIN2WIN2(miniport->reset, &reset_address, wnd->nmb->adapter_ctx);
	if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE)
		lower_irql(irql);
	else
		nt_spin_unlock_irql(&wnd->nmb->lock, irql);

	DBGTRACE2("%08X, %08X", res, reset_address);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMResetComplete */
		if (ndis_wait_comm_completion(wnd))
			res = NDIS_STATUS_FAILURE;
		else {
			res = wnd->ndis_comm_status;
			reset_address = wnd->ndis_comm_done - 1;
		}
		DBGTRACE2("%08X, %08X", res, reset_address);
	}
	up(&wnd->ndis_comm_mutex);
	if (res == NDIS_STATUS_SUCCESS && reset_address) {
		wnd->nmb->cur_lookahead = cur_lookahead;
		wnd->nmb->max_lookahead = max_lookahead;
		set_packet_filter(wnd, wnd->packet_filter);
		set_multicast_list(wnd);
	}
	up(&wnd->tx_ring_mutex);
	TRACEEXIT3(return res);
}

/* MiniportQueryInformation */
NDIS_STATUS miniport_query_info_needed(struct wrap_ndis_device *wnd,
				       ndis_oid oid, void *buf,
				       ULONG bufsize, ULONG *needed)
{
	NDIS_STATUS res;
	ULONG written;
	struct miniport_char *miniport;
	KIRQL irql;

	DBGTRACE2("oid: %08X", oid);

	if (down_interruptible(&wnd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	DBGTRACE2("%p, %08X", miniport->query, oid);
	irql = raise_irql(DISPATCH_LEVEL);
	wnd->ndis_comm_done = 0;
	if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE)
		irql = raise_irql(DISPATCH_LEVEL);
	else
		irql = nt_spin_lock_irql(&wnd->nmb->lock, DISPATCH_LEVEL);
	res = LIN2WIN6(miniport->query, wnd->nmb->adapter_ctx, oid, buf,
		       bufsize, &written, needed);
	if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE)
		lower_irql(irql);
	else
		nt_spin_unlock_irql(&wnd->nmb->lock, irql);

	DBGTRACE2("%08X, %08X", res, oid);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMQueryInformationComplete */
		if (ndis_wait_comm_completion(wnd))
			res = NDIS_STATUS_FAILURE;
		else
			res = wnd->ndis_comm_status;
		DBGTRACE2("%08X, %08X", res, oid);
	}
	up(&wnd->ndis_comm_mutex);
	DBG_BLOCK(2) {
		if (res || needed)
			DBGTRACE2("%08X, %d, %d, %d", res, bufsize, written,
				  *needed);
	}
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
	NDIS_STATUS res;
	ULONG written, needed;
	struct miniport_char *miniport;
	KIRQL irql;

	DBGTRACE2("oid: %08X", oid);

	if (down_interruptible(&wnd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	DBGTRACE2("%p, %08X", miniport->query, oid);
	irql = raise_irql(DISPATCH_LEVEL);
	wnd->ndis_comm_done = 0;
	if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE)
		irql = raise_irql(DISPATCH_LEVEL);
	else
		irql = nt_spin_lock_irql(&wnd->nmb->lock, DISPATCH_LEVEL);
	res = LIN2WIN6(miniport->setinfo, wnd->nmb->adapter_ctx, oid,
		       buf, bufsize, &written, &needed);
	if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE)
		lower_irql(irql);
	else
		nt_spin_unlock_irql(&wnd->nmb->lock, irql);

	DBGTRACE2("%08X, %08X", res, oid);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMQueryInformationComplete */
		if (ndis_wait_comm_completion(wnd))
			res = NDIS_STATUS_FAILURE;
		else
			res = wnd->ndis_comm_status;
		DBGTRACE2("%08X, %08X", res, oid);
	}
	up(&wnd->ndis_comm_mutex);
	DBG_BLOCK(2) {
		if (res && needed)
			DBGTRACE2("%08X, %d, %d, %d", res, bufsize, written,
				  needed);
	}
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

/* MiniportPnPEventNotify */
static NDIS_STATUS miniport_pnp_event(struct wrap_ndis_device *wnd,
				      enum ndis_device_pnp_event event)
{
	struct miniport_char *miniport;
	enum ndis_power_profile power_profile;

	TRACEENTER1("%p, %d", wnd, event);
	/* RNDIS driver doesn't like to be notified if device is
	 * already halted */
	if (!test_bit(HW_INITIALIZED, &wnd->hw_status))
		TRACEEXIT1(return NDIS_STATUS_SUCCESS);
	miniport = &wnd->wd->driver->ndis_driver->miniport;
	switch (event) {
	case NdisDevicePnPEventSurpriseRemoved:
		DBGTRACE1("%u, %p",
			  (wnd->attributes & NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK),
			  miniport->pnp_event_notify);
		if ((wnd->attributes & NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK) &&
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
		power_profile = NdisPowerProfileAcOnLine;
		LIN2WIN4(miniport->pnp_event_notify, wnd->nmb->adapter_ctx,
			 NdisDevicePnPEventPowerProfileChanged,
			 &power_profile, (ULONG)sizeof(power_profile));
		return NDIS_STATUS_SUCCESS;
	default:
		WARNING("event %d not yet implemented", event);
		return NDIS_STATUS_SUCCESS;
	}
}

/* MiniportInitialize */
static NDIS_STATUS miniport_init(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS error_status, status;
	UINT medium_index;
	UINT medium_array[] = {NdisMedium802_3};
	struct miniport_char *miniport;
	struct ndis_pnp_capabilities pnp_capa;

	TRACEENTER1("irql: %d", current_irql());
	if (test_bit(HW_INITIALIZED, &wnd->hw_status)) {
		WARNING("device %p already initialized!", wnd);
		return NDIS_STATUS_FAILURE;
	}

	if (!wnd->wd->driver->ndis_driver ||
	    !wnd->wd->driver->ndis_driver->miniport.init) {
		WARNING("assuming WDM (non-NDIS) driver");
		TRACEEXIT1(return NDIS_STATUS_NOT_RECOGNIZED);
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
	 * fail after boot */
	sleep_hz(HZ / 2);
	set_bit(HW_INITIALIZED, &wnd->hw_status);
	hangcheck_add(wnd);
	up(&wnd->ndis_comm_mutex);
	up(&wnd->tx_ring_mutex);
	/* the description about NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND is
	 * misleading/confusing; we just ignore it */
	status = miniport_query_info(wnd, OID_PNP_CAPABILITIES,
				     &pnp_capa, sizeof(pnp_capa));
	if (status == NDIS_STATUS_SUCCESS)
		wnd->pm_capa = TRUE;
	else
		wnd->pm_capa = FALSE;
	DBGTRACE1("%d", pnp_capa.wakeup_capa.min_magic_packet_wakeup);
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

/* MiniportHalt */
static void miniport_halt(struct wrap_ndis_device *wnd)
{
	struct miniport_char *miniport;

	TRACEENTER1("%p", wnd);
	/* semaphores may already be locked, e.g., during suspend or
	 * if device is suspended, but resume failed */
	down_trylock(&wnd->ndis_comm_mutex);
	down_trylock(&wnd->tx_ring_mutex);
	if (test_bit(HW_INITIALIZED, &wnd->hw_status)) {
		hangcheck_del(wnd);
		del_stats_timer(wnd);
		miniport = &wnd->wd->driver->ndis_driver->miniport;
		DBGTRACE1("halt: %p", miniport->miniport_halt);
		LIN2WIN1(miniport->miniport_halt, wnd->nmb->adapter_ctx);
		clear_bit(HW_INITIALIZED, &wnd->hw_status);
	} else
		WARNING("device %p is not initialized - not halting", wnd);
	TRACEEXIT1(return);
}

static NDIS_STATUS miniport_set_power_state(struct wrap_ndis_device *wnd,
					    enum ndis_power_state state)
{
	NDIS_STATUS status;

	DBGTRACE1("%d", state);
	if (state == NdisDeviceStateD0) {
		status = NDIS_STATUS_SUCCESS;
		if (test_and_clear_bit(HW_HALTED, &wnd->hw_status)) {
			status = miniport_init(wnd);
			if (status == NDIS_STATUS_SUCCESS) {
				set_packet_filter(wnd, wnd->packet_filter);
				set_multicast_list(wnd);
			}
		} else if (test_and_clear_bit(HW_SUSPENDED, &wnd->hw_status)) {
			up(&wnd->ndis_comm_mutex);
			status = miniport_set_int(wnd, OID_PNP_SET_POWER,
						  state);
			if (status == NDIS_STATUS_SUCCESS)
				up(&wnd->tx_ring_mutex);
			else {
				down_interruptible(&wnd->ndis_comm_mutex);
				WARNING("%s: setting power to state %d failed? "
					"%08X", wnd->net_dev->name, state,
					status);
			}
			if (wnd->ndis_wolopts &&
			    wrap_is_pci_bus(wnd->wd->dev_bus_type))
				pci_enable_wake(wnd->wd->pci.pdev, PCI_D0, 0);
		} else
			return NDIS_STATUS_FAILURE;

		if (status == NDIS_STATUS_SUCCESS) {
			hangcheck_add(wnd);
			add_stats_timer(wnd);
			set_scan(wnd);
			if (netif_running(wnd->net_dev)) {
				netif_device_attach(wnd->net_dev);
				netif_wake_queue(wnd->net_dev);
			}
			netif_poll_enable(wnd->net_dev);
		} else {
			WARNING("%s: couldn't set power to state %d; device not"
				" resumed", wnd->net_dev->name, state);
		}
		TRACEEXIT1(return status);
	} else {
		netif_poll_disable(wnd->net_dev);
		if (netif_running(wnd->net_dev)) {
			netif_tx_disable(wnd->net_dev);
			netif_device_detach(wnd->net_dev);
		}
		if (down_interruptible(&wnd->tx_ring_mutex))
			WARNING("couldn't lock tx_ring_mutex");
		hangcheck_del(wnd);
		del_stats_timer(wnd);
		status = NDIS_STATUS_NOT_SUPPORTED;
		if (wnd->pm_capa == TRUE) {
			enum ndis_power_state pm_state = state;
			if (wnd->ndis_wolopts) {
				status = miniport_set_int(wnd,
							  OID_PNP_ENABLE_WAKE_UP,
							  wnd->ndis_wolopts);
				if (status == NDIS_STATUS_SUCCESS) {
					if (wrap_is_pci_bus(wnd->wd->dev_bus_type))
						pci_enable_wake(wnd->wd->pci.pdev,
								PCI_D0, 1);
				} else
					WARNING("%s: couldn't enable WOL: %08x",
						wnd->net_dev->name, status);
			}
			status = miniport_set_int(wnd, OID_PNP_SET_POWER,
						  pm_state);
			if (status == NDIS_STATUS_SUCCESS) {
				set_bit(HW_SUSPENDED, &wnd->hw_status);
				if (down_interruptible(&wnd->ndis_comm_mutex))
					WARNING("couldn't lock ndis_comm_mutex");
			} else
				WARNING("suspend failed: %08X", status);
		}
		if (status != NDIS_STATUS_SUCCESS) {
			WARNING("%s does not support power management; "
				"halting the device", wnd->net_dev->name);
			/* TODO: should we use pnp_stop_device instead? */
			miniport_halt(wnd);
			set_bit(HW_HALTED, &wnd->hw_status);
			status = STATUS_SUCCESS;
		}
		TRACEEXIT1(return status);
	}
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
	if (res != (sizeof(mac_string) - 1))
		TRACEEXIT1(return -EINVAL);

	RtlInitAnsiString(&ansi, "mac_address");
	if (RtlAnsiStringToUnicodeString(&key, &ansi, TRUE))
		TRACEEXIT1(return -EINVAL);

	RtlInitAnsiString(&ansi, mac_string);
	if (RtlAnsiStringToUnicodeString(&param.data.string, &ansi, TRUE)) {
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

static struct ndis_packet *alloc_tx_packet(struct wrap_ndis_device *wnd,
					   struct sk_buff *skb)
{
	struct ndis_packet *packet;
	ndis_buffer *buffer;
	struct ndis_packet_oob_data *oob_data;
	NDIS_STATUS status;

	NdisAllocatePacket(&status, &packet, wnd->tx_packet_pool);
	if (status != NDIS_STATUS_SUCCESS)
		return NULL;
	NdisAllocateBuffer(&status, &buffer, wnd->tx_buffer_pool,
			   skb->data, skb->len);
	if (status != NDIS_STATUS_SUCCESS) {
		NdisFreePacket(packet);
		return NULL;
	}
	packet->private.buffer_head = buffer;
	packet->private.buffer_tail = buffer;

	oob_data = NDIS_PACKET_OOB_DATA(packet);
	oob_data->skb = skb;
	if (wnd->use_sg_dma) {
		oob_data->ndis_sg_element.address =
			PCI_DMA_MAP_SINGLE(wnd->wd->pci.pdev, skb->data,
					   skb->len, PCI_DMA_TODEVICE);
		oob_data->ndis_sg_element.length = skb->len;
		oob_data->ndis_sg_list.nent = 1;
		oob_data->ndis_sg_list.elements = &oob_data->ndis_sg_element;
		oob_data->extension.info[ScatterGatherListPacketInfo] =
			&oob_data->ndis_sg_list;
	}
#if 0
	if (wnd->tx_csum_info.value)
		oob_data->extension.info[TcpIpChecksumPacketInfo] =
			&wnd->tx_csum_info;
#endif
	DBG_BLOCK(4) {
		dump_bytes(__FUNCTION__, skb->data, skb->len);
	}
	DBGTRACE4("packet: %p, buffer: %p, skb: %p", packet, buffer, skb);
	return packet;
}

void free_tx_packet(struct wrap_ndis_device *wnd, struct ndis_packet *packet,
		    NDIS_STATUS status)
{
	ndis_buffer *buffer;
	struct ndis_packet_oob_data *oob_data;
	KIRQL irql;

	TRACEENTER3("%p, %08X", packet, status);
	irql = nt_spin_lock_irql(&wnd->tx_stats_lock, DISPATCH_LEVEL);
	if (status == NDIS_STATUS_SUCCESS) {
		wnd->stats.tx_bytes += packet->private.len;
		wnd->stats.tx_packets++;
	} else {
		DBGTRACE1("packet dropped: %08X", status);
		wnd->stats.tx_dropped++;
	}
	nt_spin_unlock_irql(&wnd->tx_stats_lock, irql);
	oob_data = NDIS_PACKET_OOB_DATA(packet);
	if (wnd->use_sg_dma)
		PCI_DMA_UNMAP_SINGLE(wnd->wd->pci.pdev,
				     oob_data->ndis_sg_element.address,
				     oob_data->ndis_sg_element.length,
				     PCI_DMA_TODEVICE);
	buffer = packet->private.buffer_head;
	DBGTRACE3("freeing buffer %p", buffer);
	NdisFreeBuffer(buffer);
	if (oob_data->skb)
		dev_kfree_skb_any(oob_data->skb);
	DBGTRACE3("freeing packet %p", packet);
	NdisFreePacket(packet);
	TRACEEXIT3(return);
}

/* MiniportSend and MiniportSendPackets */
/* this function is called holding tx_ring_mutex, so safe to read
 * tx_ring_start (tx_ring_end is not updated in tx_worker or here, so
 * safe to read tx_ring_end, too) without lock */
static int miniport_tx_packets(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS res;
	struct miniport_char *miniport;
	int n, sent, start, end;
	struct ndis_packet *packet;
	KIRQL irql;

	miniport = &wnd->wd->driver->ndis_driver->miniport;
	start = wnd->tx_ring_start;
	end = wnd->tx_ring_end;
	/* end == start when ring is full: (TX_RING_SIZE - 1) number
	 * of packets are pending */
	n = end - start;
	if (n < 0)
		n += TX_RING_SIZE;
	else if (n == 0) {
		assert(wnd->is_tx_ring_full == 1);
		n = TX_RING_SIZE - 1;
	}
	if (unlikely(n > wnd->max_tx_packets))
		n = wnd->max_tx_packets;
	DBGTRACE3("%d, %d, %d", n, start, end);
	if (miniport->send_packets) {
		int i;
		/* copy packets from tx ring to linear tx array */
		for (i = 0; i < n; i++) {
			int j = (start + i) % TX_RING_SIZE;
			wnd->tx_array[i] = wnd->tx_ring[j];
		}
		if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE) {
			LIN2WIN3(miniport->send_packets, wnd->nmb->adapter_ctx,
				 wnd->tx_array, n);
			sent = n;
		} else {
			struct ndis_packet_oob_data *oob_data;
			irql = nt_spin_lock_irql(&wnd->nmb->lock, DISPATCH_LEVEL);
			LIN2WIN3(miniport->send_packets, wnd->nmb->adapter_ctx,
				 wnd->tx_array, n);
			nt_spin_unlock_irql(&wnd->nmb->lock, irql);
			for (sent = 0; sent < n && wnd->tx_ok; sent++) {
				packet = wnd->tx_array[sent];
				oob_data = NDIS_PACKET_OOB_DATA(packet);
				switch (xchg(&oob_data->status,
					     NDIS_STATUS_NOT_RECOGNIZED)) {
				case NDIS_STATUS_SUCCESS:
					free_tx_packet(wnd, packet,
						       NDIS_STATUS_SUCCESS);
					break;
				case NDIS_STATUS_PENDING:
					break;
				case NDIS_STATUS_RESOURCES:
					atomic_dec(&wnd->tx_ok);
					/* resubmit this packet and
					 * the rest when resources
					 * become available */
					sent--;
					break;
				case NDIS_STATUS_FAILURE:
					free_tx_packet(wnd, packet,
						       NDIS_STATUS_FAILURE);
					break;
				default:
					ERROR("packet %p: invalid status",
					      packet);
					free_tx_packet(wnd, packet,
						       oob_data->status);
					break;
				}
			}
		}
		DBGTRACE3("sent: %d(%d)", sent, n);
	} else {
		irql = PASSIVE_LEVEL;
		for (sent = 0; sent < n && wnd->tx_ok; sent++) {
			struct ndis_packet_oob_data *oob_data;
			packet = wnd->tx_ring[(start + sent) % TX_RING_SIZE];
			oob_data = NDIS_PACKET_OOB_DATA(packet);
			oob_data->status = NDIS_STATUS_NOT_RECOGNIZED;
			if (!(wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE))
				irql = nt_spin_lock_irql(&wnd->nmb->lock,
							 DISPATCH_LEVEL);
			res = LIN2WIN3(miniport->send, wnd->nmb->adapter_ctx,
				       packet, packet->private.flags);
			if (!(wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE))
				nt_spin_unlock_irql(&wnd->nmb->lock, irql);
			switch (res) {
			case NDIS_STATUS_SUCCESS:
				free_tx_packet(wnd, packet, res);
				break;
			case NDIS_STATUS_PENDING:
				break;
			case NDIS_STATUS_RESOURCES:
				atomic_dec(&wnd->tx_ok);
				/* resend this packet when resources
				 * become available */
				sent--;
				break;
			case NDIS_STATUS_FAILURE:
				free_tx_packet(wnd, packet, res);
				break;
			default:
				ERROR("packet %p: invalid status: %08X",
				      packet, res);
				break;
			}
		}
	}
	TRACEEXIT3(return sent);
}

static void tx_worker(void *param)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)param;
	int n;

	TRACEENTER3("tx_ok %d", wnd->tx_ok);
	while (wnd->tx_ok) {
		if (down_interruptible(&wnd->tx_ring_mutex))
			break;
		/* end == start if either ring is empty or full; in
		 * the latter case is_tx_ring_full is set */
		if (wnd->tx_ring_end == wnd->tx_ring_start &&
		    !wnd->is_tx_ring_full) {
			up(&wnd->tx_ring_mutex);
			break;
		}
		n = miniport_tx_packets(wnd);
		if (n > 0) {
			wnd->tx_ring_start =
				(wnd->tx_ring_start + n) % TX_RING_SIZE;
			wnd->is_tx_ring_full = 0;
			if (netif_queue_stopped(wnd->net_dev))
				netif_wake_queue(wnd->net_dev);
		}
		up(&wnd->tx_ring_mutex);
		DBGTRACE3("%d, %d, %d", n, wnd->tx_ring_start,
			  wnd->tx_ring_end);
	}
	TRACEEXIT3(return);
}

static int tx_skbuff(struct sk_buff *skb, struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	struct ndis_packet *packet;

	packet = alloc_tx_packet(wnd, skb);
	if (!packet) {
		WARNING("couldn't allocate packet");
		return NETDEV_TX_BUSY;
	}
	/* no need for lock here - already called holding
	 * net_dev->xmit_lock and tx_ring_end is not updated
	 * elsewhere */
	wnd->tx_ring[wnd->tx_ring_end++] = packet;
	if (wnd->tx_ring_end == TX_RING_SIZE)
		wnd->tx_ring_end = 0;
	if (wnd->tx_ring_end == wnd->tx_ring_start) {
		wnd->is_tx_ring_full = 1;
		netif_stop_queue(wnd->net_dev);
	}
	DBGTRACE3("%d, %d", wnd->tx_ring_start, wnd->tx_ring_end);
	schedule_wrap_work(&wnd->tx_work);
	return NETDEV_TX_OK;
}

static int set_packet_filter(struct wrap_ndis_device *wnd, ULONG packet_filter)
{
	NDIS_STATUS res;

	while (1) {
		res = miniport_set_int(wnd, OID_GEN_CURRENT_PACKET_FILTER,
				       packet_filter);
		if (res == NDIS_STATUS_SUCCESS)
			break;
		DBGTRACE2("couldn't set filter 0x%08x", packet_filter);
		/* NDIS_PACKET_TYPE_PROMISCUOUS may not work with 802.11 */
		if (packet_filter & NDIS_PACKET_TYPE_PROMISCUOUS) {
			packet_filter &= ~NDIS_PACKET_TYPE_PROMISCUOUS;
			continue;
		}
		if (packet_filter & NDIS_PACKET_TYPE_ALL_LOCAL) {
			packet_filter &= ~NDIS_PACKET_TYPE_ALL_LOCAL;
			continue;
		}
		if (packet_filter & NDIS_PACKET_TYPE_ALL_FUNCTIONAL) {
			packet_filter &= ~NDIS_PACKET_TYPE_ALL_FUNCTIONAL;
			continue;
		}
		if (packet_filter & NDIS_PACKET_TYPE_MULTICAST) {
			packet_filter &= ~NDIS_PACKET_TYPE_MULTICAST;
			packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
			continue;
		}
		if (packet_filter & NDIS_PACKET_TYPE_ALL_MULTICAST) {
			packet_filter &= ~NDIS_PACKET_TYPE_ALL_MULTICAST;
			continue;
		}
		break;
	}

	wnd->packet_filter = packet_filter;
	res = miniport_query_int(wnd, OID_GEN_CURRENT_PACKET_FILTER,
				 &packet_filter);
	if (packet_filter != wnd->packet_filter) {
		WARNING("filter not set: 0x%08x, 0x%08x",
			packet_filter, wnd->packet_filter);
		wnd->packet_filter = packet_filter;
	}
	if (wnd->packet_filter)
		TRACEEXIT3(return 0);
	else
		TRACEEXIT3(return -1);
}

static int ndis_open(struct net_device *dev)
{
	ULONG packet_filter;
	struct wrap_ndis_device *wnd = netdev_priv(dev);

	TRACEENTER1("%p", wnd);
	packet_filter = NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST |
		NDIS_PACKET_TYPE_ALL_FUNCTIONAL;
	if (set_packet_filter(wnd, packet_filter)) {
		WARNING("couldn't set packet filter");
		return -ENODEV;
	}
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

#ifdef CONFIG_NET_POLL_CONTROLLER
static void ndis_poll_controller(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);

	disable_irq(dev->irq);
	if (wnd->ndis_irq->req_isr)
		ndis_isr_shared(dev->irq, wnd, NULL);
	else
		ndis_isr_dynamic(dev->irq, wnd, NULL);
	enable_irq(dev->irq);
}
#endif

/* this function is called fom BH context */
static struct net_device_stats *ndis_get_stats(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return &wnd->stats;
}

/* this function is called fom BH context */
static void ndis_set_multicast_list(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	set_bit(SET_MULTICAST_LIST, &wnd->wrap_ndis_pending_work);
	schedule_wrap_work(&wnd->wrap_ndis_work);
}

/* this function is called fom BH context */
struct iw_statistics *get_wireless_stats(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return &wnd->wireless_stats;
}

#if defined(HAVE_ETHTOOL)
static void ndis_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	strncpy(info->driver, DRIVER_NAME, sizeof(info->driver) - 1);
	strncpy(info->version, DRIVER_VERSION, sizeof(info->version) - 1);
	strncpy(info->fw_version, wnd->wd->driver->version,
		sizeof(info->fw_version) - 1);
	if (wrap_is_pci_bus(wnd->wd->dev_bus_type))
		strncpy(info->bus_info, pci_name(wnd->wd->pci.pdev),
			sizeof(info->bus_info) - 1);
#ifdef CONFIG_USB
	else
		usb_make_path(wnd->wd->usb.udev, info->bus_info,
			      sizeof(info->bus_info) - 1);
#endif
	return;
}

static u32 ndis_get_link(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return wnd->link_status;
}

static void ndis_get_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	if (wnd->ndis_wolopts & NDIS_PNP_WAKE_UP_MAGIC_PACKET)
		wol->wolopts |= WAKE_MAGIC;
	/* no other options supported */
	return;
}

static int ndis_set_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	struct ndis_pnp_capabilities pnp_capa;
	NDIS_STATUS status;

	if (!(wol->wolopts & WAKE_MAGIC))
		return -EINVAL;
	if (!wnd->pm_capa)
		return -EOPNOTSUPP;
	status = miniport_query_info(wnd, OID_PNP_CAPABILITIES,
				     &pnp_capa, sizeof(pnp_capa));
	if (status != NDIS_STATUS_SUCCESS)
		return -EOPNOTSUPP;
	/* we always suspend to D3 */
	DBGTRACE1("%d, %d", pnp_capa.wakeup_capa.min_magic_packet_wakeup,
		  pnp_capa.wakeup_capa.min_pattern_wakeup);
	if (pnp_capa.wakeup_capa.min_magic_packet_wakeup != NdisDeviceStateD3)
		return -EOPNOTSUPP;
	/* no other options supported */
	wnd->ndis_wolopts = NDIS_PNP_WAKE_UP_MAGIC_PACKET;
	return 0;
}

static struct ethtool_ops ndis_ethtool_ops = {
	.get_drvinfo		= ndis_get_drvinfo,
	.get_link		= ndis_get_link,
	.get_wol		= ndis_get_wol,
	.set_wol		= ndis_set_wol,
};
#endif

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
	NDIS_STATUS res;

	net_dev = wnd->net_dev;
	packet_filter = wnd->packet_filter;

	DBGTRACE2("0x%08x", packet_filter);
	if (net_dev->flags & IFF_PROMISC) {
		packet_filter |= NDIS_PACKET_TYPE_PROMISCUOUS |
			NDIS_PACKET_TYPE_ALL_LOCAL;
	} else if (net_dev->flags & IFF_ALLMULTI ||
		   net_dev->mc_count > wnd->multicast_size) {
		packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
		DBGTRACE2("0x%08x", packet_filter);
	} else if (net_dev->mc_count > 0) {
		int i, size;
		char *buf;
		struct dev_mc_list *mclist;
		size = min(wnd->multicast_size, net_dev->mc_count);
		DBGTRACE2("%d, %d", wnd->multicast_size, net_dev->mc_count);
		buf = kmalloc(size * ETH_ALEN, GFP_KERNEL);
		if (!buf) {
			WARNING("couldn't allocate memory");
			TRACEEXIT2(return);
		}
		mclist = net_dev->mc_list;
		for (i = 0; i < size && mclist; mclist = mclist->next) {
			if (mclist->dmi_addrlen != ETH_ALEN)
				continue;
			memcpy(buf + i * ETH_ALEN, mclist->dmi_addr, ETH_ALEN);
			DBGTRACE2(MACSTR, MAC2STR(mclist->dmi_addr));
			i++;
		}
		res = miniport_set_info(wnd, OID_802_3_MULTICAST_LIST,
					buf, i * ETH_ALEN);
		if (res == NDIS_STATUS_SUCCESS && i > 0)
			packet_filter |= NDIS_PACKET_TYPE_MULTICAST;
		else
			packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
		kfree(buf);
	}
	DBGTRACE2("0x%08x", packet_filter);
	res = set_packet_filter(wnd, packet_filter);
	if (res)
		DBGTRACE1("couldn't set packet filter (%08X)", res);
	TRACEEXIT2(return);
}

static void link_status_handler(struct wrap_ndis_device *wnd)
{
	struct ndis_assoc_info *ndis_assoc_info;
	union iwreq_data wrqu;
	NDIS_STATUS res;
	const int assoc_size = sizeof(*ndis_assoc_info) + IW_CUSTOM_MAX + 32;
#if WIRELESS_EXT <= 17
	unsigned char *wpa_assoc_info, *ies;
	unsigned char *p;
	int i;
#endif

	TRACEENTER2("link: %d", wnd->link_status);
	if (wnd->physical_medium != NdisPhysicalMediumWirelessLan)
		TRACEEXIT2(return);
	if (wnd->link_status == 0) {
		wnd->tx_ok = 0;
		memset(&wrqu, 0, sizeof(wrqu));
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
		wireless_send_event(wnd->net_dev, SIOCGIWAP, &wrqu, NULL);
		TRACEEXIT2(return);
	}

	wnd->tx_ok = 1;
	ndis_assoc_info = kmalloc(assoc_size, GFP_KERNEL);
	if (!ndis_assoc_info) {
		ERROR("couldn't allocate memory");
		TRACEEXIT2(return);
	}
	memset(ndis_assoc_info, 0, assoc_size);

	res = miniport_query_info(wnd, OID_802_11_ASSOCIATION_INFORMATION,
				  ndis_assoc_info, assoc_size);
	if (res) {
		DBGTRACE2("query assoc_info failed (%08X)", res);
		kfree(ndis_assoc_info);
		TRACEEXIT2(return);
	}

#if WIRELESS_EXT > 17
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.length = ndis_assoc_info->req_ie_length;
	wireless_send_event(wnd->net_dev, IWEVASSOCREQIE, &wrqu,
			    ((char *)ndis_assoc_info) +
			    ndis_assoc_info->offset_req_ies);
	wrqu.data.length = ndis_assoc_info->resp_ie_length;
	wireless_send_event(wnd->net_dev, IWEVASSOCRESPIE, &wrqu,
			    ((char *)ndis_assoc_info) +
			    ndis_assoc_info->offset_resp_ies);
#else
	/* we need 28 extra bytes for the format strings */
	if ((ndis_assoc_info->req_ie_length +
	     ndis_assoc_info->resp_ie_length + 28) > IW_CUSTOM_MAX) {
		WARNING("information element is too long! (%u,%u),"
			"association information dropped",
			ndis_assoc_info->req_ie_length,
			ndis_assoc_info->resp_ie_length);
		kfree(ndis_assoc_info);
		TRACEEXIT2(return);
	}

	wpa_assoc_info = kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
	if (!wpa_assoc_info) {
		ERROR("couldn't allocate memory");
		kfree(ndis_assoc_info);
		TRACEEXIT2(return);
	}
	p = wpa_assoc_info;
	p += sprintf(p, "ASSOCINFO(ReqIEs=");
	ies = ((char *)ndis_assoc_info) + ndis_assoc_info->offset_req_ies;
	for (i = 0; i < ndis_assoc_info->req_ie_length; i++)
		p += sprintf(p, "%02x", ies[i]);

	p += sprintf(p, " RespIEs=");
	ies = ((char *)ndis_assoc_info) + ndis_assoc_info->offset_resp_ies;
	for (i = 0; i < ndis_assoc_info->resp_ie_length; i++)
		p += sprintf(p, "%02x", ies[i]);

	p += sprintf(p, ")");

	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.length = p - wpa_assoc_info;
	wireless_send_event(wnd->net_dev, IWEVCUSTOM, &wrqu, wpa_assoc_info);

	kfree(wpa_assoc_info);
#endif
	kfree(ndis_assoc_info);

	get_ap_address(wnd, (char *)&wrqu.ap_addr.sa_data);
	wrqu.ap_addr.sa_family = ARPHRD_ETHER;
	wireless_send_event(wnd->net_dev, SIOCGIWAP, &wrqu, NULL);
	DBGTRACE2(MACSTR, MAC2STR(wrqu.ap_addr.sa_data));
	TRACEEXIT2(return);
}

static void stats_timer_proc(unsigned long data)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;

	set_bit(COLLECT_STATS, &wnd->wrap_ndis_pending_work);
	schedule_wrap_work(&wnd->wrap_ndis_work);
	wnd->stats_timer.expires += 10 * HZ;
	add_timer(&wnd->stats_timer);
}

static void add_stats_timer(struct wrap_ndis_device *wnd)
{
	init_timer(&wnd->stats_timer);
	if (wnd->physical_medium != NdisPhysicalMediumWirelessLan)
		return;
	wnd->stats_timer.data = (unsigned long)wnd;
	wnd->stats_timer.function = &stats_timer_proc;
	wnd->stats_timer.expires = jiffies + 10 * HZ;
	add_timer(&wnd->stats_timer);
}

static void del_stats_timer(struct wrap_ndis_device *wnd)
{
	del_timer_sync(&wnd->stats_timer);
}

static void hangcheck_proc(unsigned long data)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;

	TRACEENTER3("");
	set_bit(HANGCHECK, &wnd->wrap_ndis_pending_work);
	schedule_wrap_work(&wnd->wrap_ndis_work);

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

/* worker procedure to take care of setting/checking various states */
static void wrap_ndis_worker(void *param)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)param;

	DBGTRACE2("%lu", wnd->wrap_ndis_pending_work);

	if (test_bit(SHUTDOWN, &wnd->wrap_ndis_pending_work))
		TRACEEXIT3(return);

	if (test_and_clear_bit(SET_MULTICAST_LIST, &wnd->wrap_ndis_pending_work))
		set_multicast_list(wnd);

	if (test_and_clear_bit(COLLECT_STATS, &wnd->wrap_ndis_pending_work))
		update_wireless_stats(wnd);

	if (test_and_clear_bit(LINK_STATUS_CHANGED,
			       &wnd->wrap_ndis_pending_work))
		link_status_handler(wnd);

	if (test_and_clear_bit(HANGCHECK, &wnd->wrap_ndis_pending_work)) {
		NDIS_STATUS res;
		struct miniport_char *miniport;
		KIRQL irql;

		miniport = &wnd->wd->driver->ndis_driver->miniport;
		if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE)
			irql = raise_irql(DISPATCH_LEVEL);
		else
			irql = nt_spin_lock_irql(&wnd->nmb->lock,
						 DISPATCH_LEVEL);
		res = LIN2WIN1(miniport->hangcheck, wnd->nmb->adapter_ctx);
		if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE)
			lower_irql(irql);
		else
			nt_spin_unlock_irql(&wnd->nmb->lock, irql);
		if (res) {
			WARNING("%s is being reset", wnd->net_dev->name);
			res = miniport_reset(wnd);
			DBGTRACE3("%08X", res);
		}
	}
	TRACEEXIT3(return);
}

NDIS_STATUS ndis_reinit(struct wrap_ndis_device *wnd)
{
	pnp_stop_device(wnd->wd);
	return pnp_start_device(wnd->wd);
}

void get_encryption_capa(struct wrap_ndis_device *wnd)
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
	DBGTRACE2("%08X, %lu", res, (unsigned long)sizeof(ndis_key));
	if (res && res != NDIS_STATUS_INVALID_DATA)
		TRACEEXIT1(return);
	res = miniport_query_info(wnd, OID_802_11_ASSOCIATION_INFORMATION,
				  &ndis_assoc_info, sizeof(ndis_assoc_info));
	DBGTRACE1("%08X", res);
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

/* called as Windows function, so call WIN2LIN2 before accessing
 * arguments */
wstdcall NTSTATUS NdisDispatchDeviceControl(struct device_object *fdo,
					    struct irp *irp)
{
	struct wrap_ndis_device *wnd;

	WIN2LIN2(fdo, irp);

	DBGTRACE3("fdo: %p", fdo);
	/* for now, we don't have anything intresting here, so pass it
	 * down to bus driver */
	wnd = fdo->reserved;
	return LIN2WIN2(IoPassIrpDown, wnd->nmb->pdo, irp);
}

/* called as Windows function, so call WIN2LIN2 before accessing
 * arguments */
wstdcall NTSTATUS NdisDispatchPower(struct device_object *fdo, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrap_ndis_device *wnd;
	enum ndis_power_state state;
	NTSTATUS status;
	NDIS_STATUS ndis_status;

	WIN2LIN2(fdo, irp);

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wnd = fdo->reserved;
	IOTRACE("fdo: %p, fn: %d:%d, wnd: %p", fdo, irp_sl->major_fn,
		irp_sl->minor_fn, wnd);
	if ((irp_sl->params.power.type == SystemPowerState &&
	     irp_sl->params.power.state.system_state > PowerSystemWorking) ||
	    (irp_sl->params.power.type == DevicePowerState &&
	     irp_sl->params.power.state.device_state > PowerDeviceD0))
		state = NdisDeviceStateD3;
	else
		state = NdisDeviceStateD0;
	switch (irp_sl->minor_fn) {
	case IRP_MN_SET_POWER:
		if (state == NdisDeviceStateD0) {
			status = LIN2WIN2(IoSyncForwardIrp, wnd->nmb->pdo, irp);
			if (status != STATUS_SUCCESS)
				break;
			ndis_status = miniport_set_power_state(wnd, state);
			if (ndis_status != NDIS_STATUS_SUCCESS)
				WARNING("couldn't set power to %d: %08X",
					state, ndis_status);
			DBGTRACE2("%s: device resumed", wnd->net_dev->name);
			irp->io_status.status = status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		} else {
			ndis_status = miniport_set_power_state(wnd, state);
			/* TODO: handle error case */
			if (ndis_status != NDIS_STATUS_SUCCESS)
				WARNING("setting power to %d failed: %08X",
					state, ndis_status);
			status = LIN2WIN2(IoAsyncForwardIrp, wnd->nmb->pdo, irp);
		}
		break;
	case IRP_MN_QUERY_POWER:
		if (wnd->pm_capa) {
			ndis_status = miniport_query_info(wnd,
							  OID_PNP_QUERY_POWER,
							  &state, sizeof(state));
			DBGTRACE2("%d, %08X", state, ndis_status);
			/* this OID must always succeed */
			if (ndis_status != NDIS_STATUS_SUCCESS)
				DBGTRACE1("query power returns %08X",
					  ndis_status);
			irp->io_status.status = STATUS_SUCCESS;
		} else
			irp->io_status.status = STATUS_SUCCESS;
		status = LIN2WIN2(IoPassIrpDown, wnd->nmb->pdo, irp);
		break;
	case IRP_MN_WAIT_WAKE:
	case IRP_MN_POWER_SEQUENCE:
		/* TODO: implement WAIT_WAKE */
		status = LIN2WIN2(IoPassIrpDown, wnd->nmb->pdo, irp);
		break;
	default:
		status = LIN2WIN2(IoPassIrpDown, wnd->nmb->pdo, irp);
		break;
	}
	IOEXIT(return status);
}

/* called as Windows function, so call WIN2LIN2 before accessing
 * arguments */
wstdcall NTSTATUS NdisDispatchPnp(struct device_object *fdo, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrap_ndis_device *wnd;
	struct device_object *pdo;
	NTSTATUS status;

	WIN2LIN2(fdo, irp);

	IOTRACE("fdo: %p, irp: %p", fdo, irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wnd = fdo->reserved;
	pdo = wnd->nmb->pdo;
	switch (irp_sl->minor_fn) {
	case IRP_MN_START_DEVICE:
		status = LIN2WIN2(IoSyncForwardIrp, pdo, irp);
		if (status != STATUS_SUCCESS)
			break;
		if (ndis_start_device(wnd) == NDIS_STATUS_SUCCESS)
			status = STATUS_SUCCESS;
		else
			status = STATUS_FAILURE;
		irp->io_status.status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		break;
	case IRP_MN_QUERY_STOP_DEVICE:
		/* TODO: implement in NDIS */
		status = LIN2WIN2(IoPassIrpDown, wnd->nmb->pdo, irp);
		break;
	case IRP_MN_STOP_DEVICE:
		miniport_halt(wnd);
		irp->io_status.status = STATUS_SUCCESS;
		status = LIN2WIN2(IoAsyncForwardIrp, pdo, irp);
		break;
	case IRP_MN_REMOVE_DEVICE:
		DBGTRACE1("%s", wnd->net_dev->name);
		if (wnd->wd->surprise_removed == TRUE)
			miniport_pnp_event(wnd,
					   NdisDevicePnPEventSurpriseRemoved);
		if (ndis_remove_device(wnd)) {
			status = STATUS_FAILURE;
			break;
		}
		/* wnd is already freed */
		status = LIN2WIN2(IoAsyncForwardIrp, pdo, irp);
		IoDetachDevice(fdo);
		IoDeleteDevice(fdo);
		break;
	default:
		status = LIN2WIN2(IoAsyncForwardIrp, pdo, irp);
		break;
	}
	IOTRACE("status: %08X", status);
	IOEXIT(return status);
}

static int set_task_offload(struct wrap_ndis_device *wnd, void *buf,
			    const int buf_size)
{
#if 0
	struct ndis_task_offload_header *task_offload_header;
	struct ndis_task_offload *task_offload;
	struct ndis_task_tcp_ip_checksum *task_tcp_ip_csum = NULL;
	struct ndis_task_tcp_ip_checksum csum;
	NDIS_STATUS status;

	memset(buf, 0, buf_size);
	task_offload_header = buf;
	task_offload_header->version = NDIS_TASK_OFFLOAD_VERSION;
	task_offload_header->size = sizeof(*task_offload_header);
	task_offload_header->encapsulation_format.encapsulation =
		IEEE_802_3_Encapsulation;
	status = miniport_query_info(wnd, OID_TCP_TASK_OFFLOAD, buf, buf_size);
	DBGTRACE1("%08X", status);
	if (status != NDIS_STATUS_SUCCESS)
		TRACEEXIT1(return -1);
	if (task_offload_header->offset_first_task == 0)
		TRACEEXIT1(return -1);
	task_offload = ((void *)task_offload_header +
			task_offload_header->offset_first_task);
	while (1) {
		DBGTRACE1("%d, %d", task_offload->version, task_offload->task);
		switch(task_offload->task) {
		case TcpIpChecksumNdisTask:
			task_tcp_ip_csum = (void *)task_offload->task_buf;
			break;
		default:
			DBGTRACE1("%d", task_offload->task);
			break;
		}
		if (task_offload->offset_next_task == 0)
			break;
		task_offload = (void *)task_offload +
			task_offload->offset_next_task;
	}
	if (!task_tcp_ip_csum)
		TRACEEXIT1(return -1);
	memcpy(&csum, task_tcp_ip_csum, sizeof(csum));

	task_offload_header->encapsulation_format.flags.fixed_header_size = 1;
	task_offload_header->encapsulation_format.header_size =
		sizeof(struct ethhdr);
	task_offload_header->offset_first_task = sizeof(*task_offload_header);
	task_offload = ((void *)task_offload_header +
			task_offload_header->offset_first_task);
	memcpy(task_offload->task_buf, &csum, sizeof(csum));
	task_offload->offset_next_task = 0;
	task_offload->size = sizeof(*task_offload);
	task_offload->task = TcpIpChecksumNdisTask;
	task_offload->task_buf_length = sizeof(csum);
	status = miniport_set_info(wnd, OID_TCP_TASK_OFFLOAD,
				   task_offload_header,
				   sizeof(*task_offload_header) +
				   sizeof(*task_offload) + sizeof(csum));
	DBGTRACE1("%08X", status);
	if (status != NDIS_STATUS_SUCCESS)
		TRACEEXIT2(return -1);
	DBGTRACE1("%08x, %08x", csum.v4_tx.value, csum.v4_rx.value);
	if (csum.v4_tx.ip_csum) {
		wnd->tx_csum_info.tx.v4 = 1;
		if (csum.v4_tx.tcp_csum && csum.v4_tx.udp_csum) {
			wnd->net_dev->features |= NETIF_F_HW_CSUM;
			wnd->tx_csum_info.tx.tcp = 1;
			wnd->tx_csum_info.tx.ip = 1;
			wnd->tx_csum_info.tx.udp = 1;
			DBGTRACE1("hw_csum");
		} else {
			wnd->net_dev->features |= NETIF_F_IP_CSUM;
			wnd->tx_csum_info.tx.ip = 1;
			DBGTRACE1("ip_csum");
		}
	}
	wnd->rx_csum = csum.v4_rx;
#endif
	TRACEEXIT1(return 0);
}

static void get_supported_oids(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS res;
	int i, n, needed;
	ndis_oid *oids;

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
	for (i = 0, n = needed / sizeof(*oids); i < n; i++) {
		DBGTRACE1("oid: %08X", oids[i]);
		/* if a wireless device didn't say so for
		 * OID_GEN_PHYSICAL_MEDIUM (they should, but in case) */
		if (wnd->physical_medium != NdisPhysicalMediumWirelessLan &&
		    oids[i] == OID_802_11_SSID)
			wnd->physical_medium = NdisPhysicalMediumWirelessLan;
	}
	kfree(oids);
	TRACEEXIT1(return);
}

static NDIS_STATUS ndis_start_device(struct wrap_ndis_device *wnd)
{
	struct wrap_device *wd;
	struct net_device *net_dev;
	NDIS_STATUS ndis_status;
	char *buf;
	const int buf_size = 256;
	mac_address mac;

	ndis_status = miniport_init(wnd);
	if (ndis_status == NDIS_STATUS_NOT_RECOGNIZED)
		TRACEEXIT1(return NDIS_STATUS_SUCCESS);
	if (ndis_status != NDIS_STATUS_SUCCESS)
		TRACEEXIT1(return ndis_status);
	/* NB: tx_array is used to recognize if device is being
	 * started for the first time or being re-started */
	if (wnd->tx_array)
		TRACEEXIT2(return NDIS_STATUS_SUCCESS);
	wd = wnd->wd;
	net_dev = wnd->net_dev;

	ndis_status = miniport_query_int(wnd, OID_GEN_PHYSICAL_MEDIUM,
					 &wnd->physical_medium);
	if (ndis_status != NDIS_STATUS_SUCCESS)
		wnd->physical_medium = NdisPhysicalMediumUnspecified;

	get_supported_oids(wnd);
	strncpy(net_dev->name, if_name, IFNAMSIZ - 1);
	net_dev->name[IFNAMSIZ - 1] = '\0';

	ndis_status = miniport_query_info(wnd, OID_802_3_CURRENT_ADDRESS,
					  mac, sizeof(mac));
	if (ndis_status) {
		ERROR("couldn't get mac address: %08X", ndis_status);
		return ndis_status;
	}
	DBGTRACE1("mac:" MACSTR, MAC2STR(mac));
	memcpy(&net_dev->dev_addr, mac, ETH_ALEN);

	net_dev->open = ndis_open;
	net_dev->hard_start_xmit = tx_skbuff;
	net_dev->stop = ndis_close;
	net_dev->get_stats = ndis_get_stats;
	net_dev->do_ioctl = NULL;
	if (wnd->physical_medium == NdisPhysicalMediumWirelessLan) {
#if WIRELESS_EXT < 19
		net_dev->get_wireless_stats = get_wireless_stats;
#endif
		net_dev->wireless_handlers = &ndis_handler_def;
	} else
		wnd->tx_ok = 1;
	net_dev->set_multicast_list = ndis_set_multicast_list;
	net_dev->set_mac_address = ndis_set_mac_addr;
#if defined(HAVE_ETHTOOL)
	net_dev->ethtool_ops = &ndis_ethtool_ops;
#endif
	if (wnd->ndis_irq)
		net_dev->irq = wnd->ndis_irq->irq.irq;
	net_dev->mem_start = wnd->mem_start;
	net_dev->mem_end = wnd->mem_end;
	ndis_status = miniport_query_int(wnd, OID_802_3_MAXIMUM_LIST_SIZE,
					 &wnd->multicast_size);
	if (ndis_status != NDIS_STATUS_SUCCESS || wnd->multicast_size < 0)
		wnd->multicast_size = 0;
	if (wnd->multicast_size > 0)
		net_dev->flags |= IFF_MULTICAST;
	else
		net_dev->flags &= ~IFF_MULTICAST;
#ifdef CONFIG_NET_POLL_CONTROLLER
	net_dev->poll_controller = ndis_poll_controller;
#endif

	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf) {
		WARNING("couldn't allocate memory");
		goto err_start;
	}

	set_task_offload(wnd, buf, buf_size);
	if (register_netdev(net_dev)) {
		ERROR("cannot register net device %s", net_dev->name);
		goto err_register;
	}

	memset(buf, 0, buf_size);
	ndis_status = miniport_query_info(wnd, OID_GEN_VENDOR_DESCRIPTION,
					  buf, buf_size);
	if (ndis_status == NDIS_STATUS_SUCCESS)
		printk(KERN_INFO "%s: vendor: '%s'\n", net_dev->name, buf);

	printk(KERN_INFO "%s: %s ethernet device " MACSTR " using %sdriver %s,"
	       " %s\n", net_dev->name, DRIVER_NAME, MAC2STR(net_dev->dev_addr),
	       wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE ? "" : "serialized ",
	       wnd->wd->driver->name, wnd->wd->conf_file_name);

	if (wnd->attributes & NDIS_ATTRIBUTE_DESERIALIZE) {
		/* deserialized drivers don't have a limit, but we
		 * keep max at TX_RING_SIZE to allocate tx_array
		 * below */
		wnd->max_tx_packets = TX_RING_SIZE;
	} else {
		ndis_status =
			miniport_query_int(wnd, OID_GEN_MAXIMUM_SEND_PACKETS,
					   &wnd->max_tx_packets);
		if (ndis_status == NDIS_STATUS_NOT_SUPPORTED)
			wnd->max_tx_packets = 1;
		if (wnd->max_tx_packets > TX_RING_SIZE)
			wnd->max_tx_packets = TX_RING_SIZE;
	}
	DBGTRACE1("maximum send packets: %d", wnd->max_tx_packets);
	wnd->tx_array =
		kmalloc(sizeof(struct ndis_packet *) * wnd->max_tx_packets,
			GFP_KERNEL);
	if (!wnd->tx_array) {
		ERROR("couldn't allocate memory for tx_packets");
		goto err_start;

	}
	/* we need at least one extra packet for
	 * EthRxIndicateHandler */
	NdisAllocatePacketPoolEx(&ndis_status, &wnd->tx_packet_pool,
				 wnd->max_tx_packets + 1, 0,
				 PROTOCOL_RESERVED_SIZE_IN_PACKET);
	if (ndis_status != NDIS_STATUS_SUCCESS) {
		ERROR("couldn't allocate packet pool");
		goto packet_pool_err;
	}
	NdisAllocateBufferPool(&ndis_status, &wnd->tx_buffer_pool,
			       wnd->max_tx_packets + 4);
	if (ndis_status != NDIS_STATUS_SUCCESS) {
		ERROR("couldn't allocate buffer pool");
		goto buffer_pool_err;
	}
	DBGTRACE1("pool: %p", wnd->tx_buffer_pool);
	if (wnd->physical_medium == NdisPhysicalMediumWirelessLan) {
		miniport_set_int(wnd, OID_802_11_POWER_MODE, NDIS_POWER_OFF);
		miniport_set_int(wnd, OID_802_11_NETWORK_TYPE_IN_USE,
				 Ndis802_11Automode);
		get_encryption_capa(wnd);
		DBGTRACE1("capbilities = %ld", wnd->capa.encr);
		printk(KERN_INFO "%s: encryption modes supported: "
		       "%s%s%s%s%s%s%s\n", net_dev->name,
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

		set_infra_mode(wnd, Ndis802_11Infrastructure);
		set_scan(wnd);
		set_priv_filter(wnd, Ndis802_11PrivFilterAcceptAll);
		set_auth_mode(wnd, Ndis802_11AuthModeOpen);
		set_encr_mode(wnd, Ndis802_11EncryptionDisabled);
		set_essid(wnd, "", 0);
	}
	kfree(buf);
	wrap_procfs_add_ndis_device(wnd);
	add_stats_timer(wnd);
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);

buffer_pool_err:
	wnd->tx_buffer_pool = NULL;
	if (wnd->tx_packet_pool) {
		NdisFreePacketPool(wnd->tx_packet_pool);
		wnd->tx_packet_pool = NULL;
	}
packet_pool_err:
	kfree(wnd->tx_array);
	wnd->tx_array = NULL;
err_register:
	kfree(buf);
err_start:
	ndis_remove_device(wnd);
	TRACEEXIT1(return NDIS_STATUS_FAILURE);
}

static int ndis_remove_device(struct wrap_ndis_device *wnd)
{
	int tx_pending;

	set_bit(SHUTDOWN, &wnd->wrap_ndis_pending_work);
	wnd->tx_ok = 0;
	ndis_close(wnd->net_dev);
	netif_carrier_off(wnd->net_dev);
	cancel_delayed_work(&wnd->wrap_ndis_work);
	/* In 2.4 kernels, this function is called in atomic context,
	 * so we can't (don't need to?) wait on mutex. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	/* if device is suspended, but resume failed, tx_ring_mutex is
	 * already locked */
	down_trylock(&wnd->tx_ring_mutex);
#endif
	tx_pending = wnd->tx_ring_end - wnd->tx_ring_start;
	if (tx_pending < 0)
		tx_pending += TX_RING_SIZE;
	else if (tx_pending == 0 && wnd->is_tx_ring_full)
		tx_pending = TX_RING_SIZE - 1;
	wnd->is_tx_ring_full = 0;
	/* throw away pending packets */
	while (tx_pending > 0) {
		struct ndis_packet *packet;

		packet = wnd->tx_ring[wnd->tx_ring_start];
		free_tx_packet(wnd, packet, NDIS_STATUS_CLOSING);
		wnd->tx_ring_start = (wnd->tx_ring_start + 1) % TX_RING_SIZE;
		tx_pending--;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	up(&wnd->tx_ring_mutex);
#endif
	wrap_procfs_remove_ndis_device(wnd);
	miniport_halt(wnd);
	ndis_exit_device(wnd);

	if (wnd->tx_packet_pool) {
		NdisFreePacketPool(wnd->tx_packet_pool);
		wnd->tx_packet_pool = NULL;
	}
	if (wnd->tx_buffer_pool) {
		NdisFreeBufferPool(wnd->tx_buffer_pool);
		wnd->tx_buffer_pool = NULL;
	}
	if (wnd->tx_array)
		kfree(wnd->tx_array);
	printk(KERN_INFO "%s: device %s removed\n", DRIVER_NAME,
	       wnd->net_dev->name);
	unregister_netdev(wnd->net_dev);
	free_netdev(wnd->net_dev);
	TRACEEXIT2(return 0);
}

static wstdcall NTSTATUS NdisAddDevice(struct driver_object *drv_obj,
				      struct device_object *pdo)
{
	struct device_object *fdo;
	struct ndis_miniport_block *nmb;
	NTSTATUS status;
	struct wrap_ndis_device *wnd;
	struct net_device *net_dev;
	struct wrap_device *wd;
	unsigned long i;

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
#if defined(DEBUG) && DEBUG >= 6
	/* poison nmb so if a driver accesses uninitialized pointers, we
	 * know what it is */
	for (i = 0; i < sizeof(*nmb) / sizeof(unsigned long); i++)
		((unsigned long *)nmb)[i] = i + 0x8a3fc1;
#endif

	nmb->wnd = wnd;
	nmb->pdo = pdo;
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
	init_MUTEX_LOCKED(&wnd->tx_ring_mutex);
	init_MUTEX_LOCKED(&wnd->ndis_comm_mutex);
	init_waitqueue_head(&wnd->ndis_comm_wq);
	wnd->ndis_comm_done = 0;
	wnd->tx_ok = 0;
	INIT_WORK(&wnd->tx_work, tx_worker, wnd);
	wnd->tx_ring_start = 0;
	wnd->tx_ring_end = 0;
	wnd->is_tx_ring_full = 0;
	nt_spin_lock_init(&wnd->tx_stats_lock);
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
	wnd->wrap_ndis_pending_work = 0;
	memset(&wnd->essid, 0, sizeof(wnd->essid));
	memset(&wnd->encr_info, 0, sizeof(wnd->encr_info));
	wnd->infrastructure_mode = Ndis802_11Infrastructure;
	INIT_WORK(&wnd->wrap_ndis_work, wrap_ndis_worker, wnd);
	wnd->hw_status = 0;
	if (wd->driver->ndis_driver)
		wd->driver->ndis_driver->miniport.shutdown = NULL;
	wnd->stats_enabled = TRUE;
	wnd->rx_csum.value = 0;

	fdo->reserved = wnd;
	nmb->fdo = fdo;
	nmb->next_device = IoAttachDeviceToDeviceStack(fdo, pdo);
	DBGTRACE1("nmb: %p, pdo: %p, fdo: %p, attached: %p, next: %p",
		  nmb, pdo, fdo, fdo->attached, nmb->next_device);

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv_obj->major_func[i] = IoPassIrpDown;
	drv_obj->major_func[IRP_MJ_PNP] = NdisDispatchPnp;
	drv_obj->major_func[IRP_MJ_POWER] = NdisDispatchPower;
	drv_obj->major_func[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
		NdisDispatchDeviceControl;
	drv_obj->major_func[IRP_MJ_DEVICE_CONTROL] = NdisDispatchDeviceControl;
	TRACEEXIT2(return STATUS_SUCCESS);
}

int init_ndis_driver(struct driver_object *drv_obj)
{
	drv_obj->drv_ext->add_device = NdisAddDevice;
	return 0;
}
