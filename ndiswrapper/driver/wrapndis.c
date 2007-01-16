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
#include <linux/inetdevice.h>

extern char *if_name;
extern int hangcheck_interval;
extern struct iw_handler_def ndis_handler_def;
extern NT_SPIN_LOCK timer_lock;

static int set_packet_filter(struct wrap_ndis_device *wnd,
			     ULONG packet_filter);
static void add_stats_timer(struct wrap_ndis_device *wnd);
static void del_stats_timer(struct wrap_ndis_device *wnd);
static NDIS_STATUS ndis_start_device(struct wrap_ndis_device *wnd);
static int ndis_remove_device(struct wrap_ndis_device *wnd);
static void set_multicast_list(struct wrap_ndis_device *wnd);
static int ndis_net_dev_open(struct net_device *net_dev);
static int ndis_net_dev_close(struct net_device *net_dev);

static inline int ndis_wait_comm_completion(struct wrap_ndis_device *wnd)
{
	if ((wait_event_interruptible(wnd->ndis_comm_wq,
				      (wnd->ndis_comm_done > 0))))
		return -1;
	else
		return 0;
}

NDIS_STATUS miniport_oid_request(struct wrap_ndis_device *wnd,
				 struct ndis_oid_request *oid_request)
{
	NDIS_STATUS res;
	struct mp_driver_characteristics *mp_chars;

	DBGTRACE2("oid: %08X", oid_request->data.query_info.oid);

	if (down_interruptible(&wnd->ndis_comm_mutex))
		TRACEEXIT3(return NDIS_STATUS_FAILURE);
	mp_chars = &wnd->wd->driver->ndis_driver->mp_driver_chars;
	DBGTRACE2("%08X", oid_request->data.query_info.oid);
	wnd->ndis_comm_done = 0;

	oid_request->header.type = NDIS_OBJECT_TYPE_OID_REQUEST;
	oid_request->header.revision = NDIS_OID_REQUEST_REVISION_1;
	oid_request->header.size = sizeof(*oid_request);

	res = LIN2WIN2(mp_chars->oid_request, wnd->adapter_ctx, oid_request);

	DBGTRACE2("%08X, %08X", res, oid_request->data.query_info.oid);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for NdisMQueryInformationComplete */
		if (ndis_wait_comm_completion(wnd))
			res = NDIS_STATUS_FAILURE;
		else
			res = wnd->ndis_comm_status;
		DBGTRACE2("%08X, %08X", oid_request->data.query_info.oid, res);
	}
	up(&wnd->ndis_comm_mutex);
	DBG_BLOCK(2) {
		if (res)
			DBGTRACE2("%08X", res);
	}
	TRACEEXIT3(return res);
}

static void prepare_mp_oid_request(struct ndis_oid_request *oid_request)
{
	memset(oid_request, 0, sizeof(*oid_request));
	oid_request->port = 0;
	oid_request->timeout_sec = 0;
}

NDIS_STATUS mp_oid_request_query(struct wrap_ndis_device *wnd, ndis_oid oid,
				 void *buf, int buf_len)
{
	struct ndis_oid_request oid_request;

	TRACEENTER2("%08X", oid);
	prepare_mp_oid_request(&oid_request);
	oid_request.type = NdisRequestQueryInformation;
	oid_request.data.query_info.oid = oid;
	oid_request.data.query_info.buf = buf;
	oid_request.data.query_info.buf_length = buf_len;
	return miniport_oid_request(wnd, &oid_request);
}

NDIS_STATUS miniport_query_info(struct wrap_ndis_device *wnd, ndis_oid oid,
				void *buf, ULONG buf_len)
{
	return mp_oid_request_query(wnd, oid, buf, buf_len);
}

NDIS_STATUS miniport_query_info_needed(struct wrap_ndis_device *wnd,
				       ndis_oid oid, void *buf, ULONG buf_len,
				       ULONG *needed)
{
	return mp_oid_request_query(wnd, oid, buf, buf_len);
}

NDIS_STATUS miniport_query_int(struct wrap_ndis_device *wnd, ndis_oid oid,
			       ULONG *value)
{
	return mp_oid_request_query(wnd, oid, (void *)value, sizeof(ULONG));
}

NDIS_STATUS mp_oid_request_set(struct wrap_ndis_device *wnd, ndis_oid oid,
			       void *buf, ULONG buf_len)
{
	struct ndis_oid_request oid_request;

	TRACEENTER2("%08X", oid);
	prepare_mp_oid_request(&oid_request);
	oid_request.type = NdisRequestSetInformation;
	oid_request.data.query_info.oid = oid;
	oid_request.data.query_info.buf = buf;
	oid_request.data.query_info.buf_length = buf_len;
	return miniport_oid_request(wnd, &oid_request);
}

NDIS_STATUS miniport_set_info(struct wrap_ndis_device *wnd, ndis_oid oid,
			      void *buf, ULONG buf_len)
{
	return mp_oid_request_set(wnd, oid, buf, buf_len);
}

NDIS_STATUS miniport_set_int(struct wrap_ndis_device *wnd, ndis_oid oid,
			     ULONG value)
{
	return mp_oid_request_set(wnd, oid, (void *)&value, sizeof(ULONG));
}

NDIS_STATUS miniport_reset(struct wrap_ndis_device *wnd)
{
	TODO();
	return NDIS_STATUS_SUCCESS;
}

/* MiniportInitialize */
static NDIS_STATUS miniport_init(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS status;
	struct wrap_ndis_driver *ndis_driver;
	struct mp_init_params init_params;

	TRACEENTER1("irql: %d", current_irql());
	if (test_bit(HW_INITIALIZED, &wnd->hw_status)) {
		WARNING("device %p already initialized!", wnd);
		return NDIS_STATUS_FAILURE;
	}

	if (!wnd->wd->driver->ndis_driver) {
		WARNING("assuming WDM (non-NDIS) driver");
		TRACEEXIT1(return NDIS_STATUS_NOT_RECOGNIZED);
	}
	ndis_driver = wnd->wd->driver->ndis_driver;
	memset(&init_params, 0, sizeof(init_params));
	init_params.header.type = NDIS_OBJECT_TYPE_MINIPORT_INIT_PARAMETERS;
	init_params.header.revision = NDIS_MINIPORT_INIT_PARAMETERS_REVISION_1;
	init_params.header.size = sizeof(init_params);
	init_params.allocated_resources =
		&wnd->wd->resource_list->list[0].partial_resource_list;
	init_params.mp_add_dev_ctx = wnd->add_dev_ctx;
	init_params.if_index = 0;
	init_params.net_luid.info.if_type = IF_TYPE_IEEE80211;
	init_params.port_auth_states.header.type = NDIS_OBJECT_TYPE_DEFAULT;
	init_params.port_auth_states.header.revision =
		NDIS_PORT_AUTHENTICATION_PARAMETERS_REVISION_1;
	init_params.port_auth_states.header.size =
		sizeof(init_params.port_auth_states);
	init_params.port_auth_states.tx_control_state =
		NdisPortControlStateUnknown;
	init_params.port_auth_states.rx_control_state =
		NdisPortControlStateUnknown;

	status = LIN2WIN3(ndis_driver->mp_driver_chars.initialize,
			  wnd, wnd, &init_params);
	DBGTRACE1("init returns: %08X, irql: %d", status, current_irql());
	if (status != NDIS_STATUS_SUCCESS) {
		WARNING("couldn't initialize device: %08X", status);
		TRACEEXIT1(return NDIS_STATUS_FAILURE);
	}

	/* Wait a little to let card power up otherwise ifup might
	 * fail after boot */
	sleep_hz(HZ / 2);
	set_bit(HW_INITIALIZED, &wnd->hw_status);
	status = miniport_pnp_event(wnd, NdisDevicePnPEventPowerProfileChanged,
				    NdisPowerProfileAcOnLine);
	if (status != NDIS_STATUS_SUCCESS)
		DBGTRACE1("couldn't set power profile: %08X", status);
	/* although some NDIS drivers support suspend, Linux kernel
	 * has issues with suspending USB devices */
	if (wrap_is_usb_bus(wnd->wd->dev_bus))
		wnd->attribute_flags &= ~NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND;
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);
}

/* MiniportHalt */
static void miniport_halt(struct wrap_ndis_device *wnd)
{
	struct mp_driver_characteristics *mp_driver;
	enum ndis_halt_action halt_action;

	TRACEENTER1("%p", wnd);

	if (!test_and_clear_bit(HW_INITIALIZED, &wnd->hw_status)) {
		WARNING("device %p is not initialized - not halting", wnd);
		return;
	}
	mp_driver = &wnd->wd->driver->ndis_driver->mp_driver_chars;
	if (wnd->wd->surprise_removed)
		halt_action = NdisHaltDeviceSurpriseRemoved;
	else
		halt_action = NdisHaltDeviceDisabled;

	hangcheck_del(wnd);
	del_stats_timer(wnd);
	down_interruptible(&wnd->ndis_comm_mutex);
	LIN2WIN2(mp_driver->halt, wnd->adapter_ctx, halt_action);
	up(&wnd->ndis_comm_mutex);
	/* cancel any timers left by bugyy windows driver; also free
	 * the memory for timers */
	while (1) {
		KIRQL irql;
		struct nt_list *ent;
		struct wrap_timer *wrap_timer;

		irql = nt_spin_lock_irql(&timer_lock, DISPATCH_LEVEL);
		ent = RemoveHeadList(&wnd->timer_list);
		nt_spin_unlock_irql(&timer_lock, irql);
		if (!ent)
			break;
		wrap_timer = container_of(ent, struct wrap_timer, list);
		wrap_timer->repeat = 0;
		/* ktimer that this wrap_timer is associated to can't
		 * be touched, as it may have been freed by the driver
		 * already */
		if (del_timer_sync(&wrap_timer->timer))
			WARNING("Buggy Windows driver left timer %p running",
				&wrap_timer->timer);
		memset(wrap_timer, 0, sizeof(*wrap_timer));
		slack_kfree(wrap_timer);
	}
	TRACEEXIT1(return);
}

static struct net_buffer_list *
alloc_tx_buffer_list(struct wrap_ndis_device *wnd, struct sk_buff *skb)
{
	struct net_buffer_list *buffer_list;
	struct net_buffer *buffer;
	struct mdl *mdl;

	buffer_list = NdisAllocateNetBufferList(wnd->tx_buffer_list_pool, 0, 0);
	mdl = allocate_init_mdl(skb->data, skb->len);
	if (unlikely(!mdl)) {
		WARNING("couldn't allocate mdl");
		NdisFreeNetBufferList(buffer_list);
		return NULL;
	}
	buffer = NdisAllocateNetBuffer(wnd->tx_buffer_pool, mdl, 0, skb->len);
	if (unlikely(!buffer)) {
		WARNING("couldn't allocate buffer");
		free_mdl(mdl);
		NdisFreeNetBufferList(buffer_list);
		return NULL;
	}
	buffer->ndis_reserved[0] = skb;
	return buffer_list;
}

void free_tx_buffer_list(struct wrap_ndis_device *wnd,
			 struct net_buffer_list *buffer_list)
{
	struct net_buffer_list *blist, *next;

	blist = buffer_list;
	while (blist) {
		struct net_buffer *buffer, *next_buffer;

		next = blist->header.data.next;
		buffer = buffer_list->header.data.first_buffer;
		while (buffer) {
			struct mdl *mdl, *next_mdl;
			struct sk_buff *skb;
			next_buffer = buffer->header.data.next;
			mdl = buffer->header.data.mdl_chain;
			while (mdl) {
				next_mdl = mdl->next;
				free_mdl(mdl);
				mdl = next_mdl;
			}
			skb = buffer->ndis_reserved[0];
			dev_kfree_skb_any(skb);
			NdisFreeNetBuffer(buffer);
			buffer = next_buffer;
		}
		NdisFreeNetBufferList(blist);
		blist = next;
	}
}

static void tx_worker(worker_param_t param)
{
	struct wrap_ndis_device *wnd;

	wnd = worker_param_data(param, struct wrap_ndis_device, tx_work);
	TRACEENTER3("tx_ok %d", wnd->tx_ok);
	while (wnd->tx_ok) {
		struct net_buffer_list *last;
		struct mp_driver_characteristics *mp_driver;

		last = xchg(&wnd->last_tx_buffer_list, NULL);
		mp_driver = &wnd->wd->driver->ndis_driver->mp_driver_chars;
		if (last)
			LIN2WIN4(mp_driver->tx_net_buffer_lists,
				 wnd->adapter_ctx, last, 0, 0);
	}
	TRACEEXIT3(return);
}

static int tx_skbuff(struct sk_buff *skb, struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	struct net_buffer_list *buffer_list;

	buffer_list = alloc_tx_buffer_list(wnd, skb);
	if (!buffer_list) {
		WARNING("couldn't allocate packet");
		return NETDEV_TX_BUSY;
	}
	/* TODO: do we need lock here? */
	if (wnd->last_tx_buffer_list) {
		buffer_list->ndis_reserved[0] =
			wnd->last_tx_buffer_list->ndis_reserved[0];
		wnd->last_tx_buffer_list->header.data.next = buffer_list;
	}
	wnd->last_tx_buffer_list = buffer_list;
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

static int ndis_net_dev_open(struct net_device *net_dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(net_dev);

	TRACEENTER1("%p", wnd);
	if (set_packet_filter(wnd, wnd->packet_filter)) {
		WARNING("couldn't set packet filter");
		return -ENODEV;
	}
	netif_wake_queue(net_dev);
	netif_poll_enable(net_dev);
	return 0;
}

static int ndis_net_dev_close(struct net_device *net_dev)
{
	netif_poll_disable(net_dev);
	netif_tx_disable(net_dev);
	return 0;
}

static int ndis_change_mtu(struct net_device *net_dev, int mtu)
{
	struct wrap_ndis_device *wnd = netdev_priv(net_dev);
	int max;

	if (mtu < ETH_ZLEN)
		return -EINVAL;
	if (miniport_query_int(wnd, OID_GEN_MAXIMUM_TOTAL_SIZE, &max) !=
	    NDIS_STATUS_SUCCESS)
		return -EOPNOTSUPP;
	DBGTRACE2("%d", max);
	max -= ETH_HLEN;
	if (max <= ETH_ZLEN)
		return -EINVAL;
	if (mtu + ETH_HLEN > max)
		return -EINVAL;
	net_dev->mtu = mtu;
	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void ndis_poll_controller(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);

	disable_irq(dev->irq);
	mp_isr(dev->irq, wnd ISR_PT_REGS_ARG);
	enable_irq(dev->irq);
}
#endif

/* called from BH context */
static struct net_device_stats *ndis_get_stats(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	return &wnd->stats;
}

/* called from BH context */
static void ndis_set_multicast_list(struct net_device *dev)
{
	struct wrap_ndis_device *wnd = netdev_priv(dev);
	set_bit(SET_MULTICAST_LIST, &wnd->wrap_ndis_pending_work);
	schedule_wrap_work(&wnd->wrap_ndis_work);
}

/* called from BH context */
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
	if (wrap_is_pci_bus(wnd->wd->dev_bus))
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
	return netif_carrier_ok(wnd->net_dev);
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
	if (!(wnd->attribute_flags & NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND))
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
	.get_drvinfo	= ndis_get_drvinfo,
	.get_link	= ndis_get_link,
	.get_wol	= ndis_get_wol,
	.set_wol	= ndis_set_wol,
};
#endif

static int notifier_event(struct notifier_block *notifier, unsigned long event,
			  void *ptr)
{
	struct net_device *net_dev = (struct net_device *)ptr;
	struct wrap_ndis_device *wnd;

	if (net_dev->open != ndis_net_dev_open)
		return NOTIFY_DONE;

	wnd = netdev_priv(net_dev);
	/* called with rtnl lock held, so no need to lock */
	switch (event) {
	case NETDEV_CHANGENAME:
		wrap_procfs_remove_ndis_device(wnd);
		printk(KERN_INFO "%s: changing interface name from '%s' to "
		       "'%s'\n", DRIVER_NAME, wnd->netdev_name, net_dev->name);
		memcpy(wnd->netdev_name, net_dev->name,
		       sizeof(wnd->netdev_name));
		wrap_procfs_add_ndis_device(wnd);
		break;
	default:
		DBGTRACE2("%lx", event);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block netdev_notifier = {
	.notifier_call = notifier_event,
};

static void update_wireless_stats(struct wrap_ndis_device *wnd)
{
	struct iw_statistics *iw_stats = &wnd->wireless_stats;
	struct ndis_wireless_stats ndis_stats;
	NDIS_STATUS res;
	ndis_rssi rssi;
	int qual;

	TRACEENTER2("%p", wnd);
	if (wnd->stats_enabled == FALSE || !netif_carrier_ok(wnd->net_dev)) {
		memset(iw_stats, 0, sizeof(*iw_stats));
		TRACEEXIT2(return);
	}
	res = miniport_query_info(wnd, OID_802_11_RSSI, &rssi, sizeof(rssi));
	if (res == NDIS_STATUS_SUCCESS)
		iw_stats->qual.level = rssi;

	qual = 100 * (rssi - WL_NOISE) / (WL_SIGMAX - WL_NOISE);
	if (qual < 0)
		qual = 0;
	else if (qual > 100)
		qual = 100;

	iw_stats->qual.noise = WL_NOISE;
	iw_stats->qual.qual  = qual;

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
			DBGTRACE2(MACSTRSEP, MAC2STR(mclist->dmi_addr));
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
	int i;
#if WIRELESS_EXT <= 17
	unsigned char *wpa_assoc_info, *ies;
	unsigned char *p;
#endif

	TRACEENTER2("link: %d", netif_carrier_ok(wnd->net_dev));
	if (wnd->physical_medium != NdisPhysicalMediumWirelessLan)
		TRACEEXIT2(return);
#ifndef CONFIG_NET_RADIO
	TRACEEXIT2(return);
#endif
	if (!netif_carrier_ok(wnd->net_dev)) {
		memset(&wrqu, 0, sizeof(wrqu));
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
		wireless_send_event(wnd->net_dev, SIOCGIWAP, &wrqu, NULL);
		/* In IBSS (ad-hoc) mode, it may be desirable to have
		 * one node configured for association, but drivers
		 * disassociate if last node disassociates; to
		 * configure again, set essid */
		if (wnd->infrastructure_mode == Ndis802_11IBSS &&
		    wnd->essid.length > 0) {
			set_essid(wnd, wnd->essid.essid, wnd->essid.length);
			for (i = 0; i < MAX_ENCR_KEYS; i++) {
				if (wnd->encr_info.keys[i].length <= 0)
					continue;
				add_wep_key(wnd, wnd->encr_info.keys[i].key,
					    wnd->encr_info.keys[i].length, i);
			}
		}
		TRACEEXIT2(return);
	}

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
	DBGTRACE2(MACSTRSEP, MAC2STR(wrqu.ap_addr.sa_data));
	TRACEEXIT2(return);
}

static void stats_timer_proc(unsigned long data)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;

	TRACEENTER2("");
	if (wnd->stats_interval <= 0)
		TRACEEXIT2(return);
	set_bit(COLLECT_STATS, &wnd->wrap_ndis_pending_work);
	schedule_wrap_work(&wnd->wrap_ndis_work);
	mod_timer(&wnd->stats_timer, jiffies + wnd->stats_interval);
}

static void add_stats_timer(struct wrap_ndis_device *wnd)
{
	if (wnd->physical_medium != NdisPhysicalMediumWirelessLan)
		return;
	if (wnd->stats_interval < 0)
		wnd->stats_interval *= -1;
	wnd->stats_timer.data = (unsigned long)wnd;
	wnd->stats_timer.function = stats_timer_proc;
	mod_timer(&wnd->stats_timer, jiffies + wnd->stats_interval);
}

static void del_stats_timer(struct wrap_ndis_device *wnd)
{
	TRACEENTER2("");
	wnd->stats_interval *= -1;
	del_timer_sync(&wnd->stats_timer);
	TRACEEXIT2(return);
}

static void hangcheck_proc(unsigned long data)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;

	TRACEENTER2("");
	TRACEEXIT3(return);
	if (wnd->hangcheck_interval <= 0)
		TRACEEXIT2(return);
	TODO();
	TRACEEXIT3(return);
}

void hangcheck_add(struct wrap_ndis_device *wnd)
{
	TODO();
	TRACEEXIT2(return);
	wnd->hangcheck_timer.data = (unsigned long)wnd;
	wnd->hangcheck_timer.function = hangcheck_proc;
	mod_timer(&wnd->hangcheck_timer, jiffies + wnd->hangcheck_interval);
}

void hangcheck_del(struct wrap_ndis_device *wnd)
{
	TRACEENTER2("");
	if (wnd->hangcheck_interval > 0)
		wnd->hangcheck_interval *= -1;
	del_timer_sync(&wnd->hangcheck_timer);
	TRACEEXIT2(return);
}

/* worker procedure to take care of setting/checking various states */
static void wrap_ndis_worker(worker_param_t param)
{
	struct wrap_ndis_device *wnd;

	wnd = worker_param_data(param, struct wrap_ndis_device, wrap_ndis_work);

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

	if (test_and_clear_bit(MINIPORT_RESET, &wnd->wrap_ndis_pending_work))
		miniport_reset(wnd);
	TRACEEXIT3(return);
}

NDIS_STATUS miniport_set_power_state(struct wrap_ndis_device *wnd,
				     enum ndis_power_state state)
{
	NDIS_STATUS status;

	DBGTRACE1("%d", state);
	if (state == NdisDeviceStateD0) {
		status = NDIS_STATUS_SUCCESS;
		up(&wnd->ndis_comm_mutex);
		if (test_and_clear_bit(HW_HALTED, &wnd->hw_status)) {
			status = miniport_init(wnd);
			if (status == NDIS_STATUS_SUCCESS) {
				set_packet_filter(wnd, wnd->packet_filter);
				set_multicast_list(wnd);
			}
		} else if (test_and_clear_bit(HW_SUSPENDED, &wnd->hw_status)) {
			status = miniport_set_int(wnd, OID_PNP_SET_POWER,
						  state);
			if (status != NDIS_STATUS_SUCCESS)
				WARNING("%s: setting power to state %d failed? "
					"%08X", wnd->net_dev->name, state,
					status);
			miniport_pnp_event(wnd,
					   NdisDevicePnPEventPowerProfileChanged,
					   NdisPowerProfileAcOnLine);
			if (wnd->ndis_wolopts &&
			    wrap_is_pci_bus(wnd->wd->dev_bus))
				pci_enable_wake(wnd->wd->pci.pdev, PCI_D0, 0);
		} else
			return NDIS_STATUS_FAILURE;

		if (status == NDIS_STATUS_SUCCESS) {
			netif_device_attach(wnd->net_dev);
			hangcheck_add(wnd);
			add_stats_timer(wnd);
			set_scan(wnd);
		} else {
			WARNING("%s: couldn't set power to state %d; device not"
				" resumed", wnd->net_dev->name, state);
		}
		TRACEEXIT1(return status);
	} else {
		netif_device_detach(wnd->net_dev);
		hangcheck_del(wnd);
		del_stats_timer(wnd);
		status = NDIS_STATUS_NOT_SUPPORTED;
		if (wnd->attribute_flags & NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND) {
			enum ndis_power_state pm_state = state;
			if (wnd->ndis_wolopts) {
				status = miniport_set_int(wnd,
							  OID_PNP_ENABLE_WAKE_UP,
							  wnd->ndis_wolopts);
				if (status == NDIS_STATUS_SUCCESS) {
					if (wrap_is_pci_bus(wnd->wd->dev_bus))
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
			} else
				WARNING("suspend failed: %08X", status);
		}
		if (status != NDIS_STATUS_SUCCESS) {
			WARNING("%s does not support power management; "
				"halting the device", wnd->net_dev->name);
			miniport_halt(wnd);
			set_bit(HW_HALTED, &wnd->hw_status);
			status = STATUS_SUCCESS;
		}
		if (down_interruptible(&wnd->ndis_comm_mutex))
			WARNING("couldn't lock ndis_comm_mutex");
		TRACEEXIT1(return status);
	}
}

NDIS_STATUS miniport_pnp_event(struct wrap_ndis_device *wnd,
			       enum ndis_device_pnp_event event, ULONG profile)
{
	struct wrap_ndis_driver *ndis_driver;
	struct net_device_pnp_event net_event;

	TRACEENTER1("%p, %d", wnd, event);
	ndis_driver = wnd->wd->driver->ndis_driver;
	if (!ndis_driver->mp_driver_chars.pnp_event_notify) {
		DBGTRACE1("Windows driver %s doesn't support "
			  "MiniportPnpEventNotify", wnd->wd->driver->name);
		return NDIS_STATUS_FAILURE;
	}
	/* RNDIS driver doesn't like to be notified if device is
	 * already halted */
	if (!test_bit(HW_INITIALIZED, &wnd->hw_status))
		TRACEEXIT1(return NDIS_STATUS_SUCCESS);
	memset(&net_event, 0, sizeof(net_event));
	net_event.header.type = NDIS_OBJECT_TYPE_DEFAULT;
	net_event.header.revision = NET_DEVICE_PNP_EVENT_REVISION_1;
	net_event.header.size = sizeof(net_event);
	net_event.port = 0;
	net_event.event = event;
	
	switch (event) {
	case NdisDevicePnPEventSurpriseRemoved:
		net_event.buf = NULL;
		net_event.buf_length = 0;
		if (wnd->wd->surprise_removed != TRUE)
			TRACEEXIT1(return NDIS_STATUS_SUCCESS);
		if (wnd->attribute_flags & NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK)
			LIN2WIN2(ndis_driver->mp_driver_chars.pnp_event_notify,
				 wnd->adapter_ctx, &net_event);
		else
			DBGTRACE1("Windows driver %s doesn't support "
				  "MiniportPnpEventNotify for safe unplugging",
				  wnd->wd->driver->name);
		return NDIS_STATUS_SUCCESS;
	case NdisDevicePnPEventPowerProfileChanged:
		/* TODO: get ac/battery status from kernel */
		net_event.buf = &profile;
		net_event.buf_length = sizeof(profile);
		LIN2WIN2(ndis_driver->mp_driver_chars.pnp_event_notify,
			 wnd->adapter_ctx, &net_event);
		return NDIS_STATUS_SUCCESS;
	default:
		WARNING("event %d not yet implemented", event);
		return NDIS_STATUS_SUCCESS;
	}
}

NDIS_STATUS ndis_reinit(struct wrap_ndis_device *wnd)
{
	NDIS_STATUS status;

	wnd->attribute_flags &= ~NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND;
	status = miniport_set_power_state(wnd, NdisDeviceStateD3);
	if (status != NDIS_STATUS_SUCCESS) {
		ERROR("halting device %s failed: %08X", wnd->net_dev->name,
		      status);
		return status;
	}
	status = miniport_set_power_state(wnd, NdisDeviceStateD0);
	if (status != NDIS_STATUS_SUCCESS)
		ERROR("starting device %s failed: %08X", wnd->net_dev->name,
		      status);
	return status;
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

wstdcall NTSTATUS NdisDispatchDeviceControl(struct device_object *fdo,
					    struct irp *irp)
{
	struct wrap_ndis_device *wnd;

	DBGTRACE3("fdo: %p", fdo);
	/* for now, we don't have anything intresting here, so pass it
	 * down to bus driver */
	wnd = fdo->reserved;
	return IoPassIrpDown(wnd->pdo, irp);
}
WIN_FUNC_DECL(NdisDispatchDeviceControl,2)

wstdcall NTSTATUS NdisDispatchPower(struct device_object *fdo, struct irp *irp)
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
			status = IoSyncForwardIrp(wnd->pdo, irp);
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
			status = IoAsyncForwardIrp(wnd->pdo, irp);
		}
		break;
	case IRP_MN_QUERY_POWER:
		if (wnd->attribute_flags & NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND) {
			ndis_status =
				miniport_query_info(wnd, OID_PNP_QUERY_POWER,
						    &state, sizeof(state));
			DBGTRACE2("%d, %08X", state, ndis_status);
			/* this OID must always succeed */
			if (ndis_status != NDIS_STATUS_SUCCESS)
				DBGTRACE1("query power returns %08X",
					  ndis_status);
			irp->io_status.status = STATUS_SUCCESS;
		} else
			irp->io_status.status = STATUS_SUCCESS;
		status = IoPassIrpDown(wnd->pdo, irp);
		break;
	case IRP_MN_WAIT_WAKE:
	case IRP_MN_POWER_SEQUENCE:
		/* TODO: implement WAIT_WAKE */
		status = IoPassIrpDown(wnd->pdo, irp);
		break;
	default:
		status = IoPassIrpDown(wnd->pdo, irp);
		break;
	}
	IOEXIT(return status);
}
WIN_FUNC_DECL(NdisDispatchPower,2)

wstdcall NTSTATUS NdisDispatchPnp(struct device_object *fdo, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrap_ndis_device *wnd;
	struct device_object *pdo;
	NTSTATUS status;

	IOTRACE("fdo: %p, irp: %p", fdo, irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wnd = fdo->reserved;
	pdo = wnd->pdo;
	switch (irp_sl->minor_fn) {
	case IRP_MN_START_DEVICE:
		status = IoSyncForwardIrp(pdo, irp);
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
		status = IoPassIrpDown(wnd->pdo, irp);
		break;
	case IRP_MN_STOP_DEVICE:
		miniport_halt(wnd);
		irp->io_status.status = STATUS_SUCCESS;
		status = IoAsyncForwardIrp(pdo, irp);
		break;
	case IRP_MN_REMOVE_DEVICE:
		DBGTRACE1("%s", wnd->net_dev->name);
		miniport_pnp_event(wnd, NdisDevicePnPEventSurpriseRemoved, 0);
		if (ndis_remove_device(wnd)) {
			status = STATUS_FAILURE;
			break;
		}
		/* wnd is already freed */
		status = IoAsyncForwardIrp(pdo, irp);
		IoDetachDevice(fdo);
		IoDeleteDevice(fdo);
		break;
	default:
		status = IoAsyncForwardIrp(pdo, irp);
		break;
	}
	IOTRACE("status: %08X", status);
	IOEXIT(return status);
}
WIN_FUNC_DECL(NdisDispatchPnp,2)

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
	struct mp_pnp_characteristics *mp_pnp_chars;
	struct transport_header_offset transport_header_offset;
	int n;
	struct net_buffer_pool_params nb_pool_params;
	struct net_buffer_list_pool_params nbl_pool_params;

	mp_pnp_chars = &wnd->wd->driver->ndis_driver->mp_pnp_chars;
	if (mp_pnp_chars->add_device)
		LIN2WIN2(mp_pnp_chars->add_device,
			 wnd->wd->driver->ndis_driver->mp_driver_ctx, NULL);

	ndis_status = miniport_init(wnd);
	if (ndis_status == NDIS_STATUS_NOT_RECOGNIZED)
		TRACEEXIT1(return NDIS_STATUS_SUCCESS);
	if (ndis_status != NDIS_STATUS_SUCCESS)
		TRACEEXIT1(return ndis_status);
	wd = wnd->wd;
	net_dev = wnd->net_dev;

	ndis_status = miniport_query_info(wnd, OID_802_3_CURRENT_ADDRESS,
					  mac, sizeof(mac));
	if (ndis_status) {
		ERROR("couldn't get mac address: %08X", ndis_status);
		goto err_start;
	}
	DBGTRACE1("mac:" MACSTRSEP, MAC2STR(mac));
	ndis_status = miniport_query_int(wnd, OID_GEN_PHYSICAL_MEDIUM,
					 &wnd->physical_medium);
	if (ndis_status != NDIS_STATUS_SUCCESS)
		wnd->physical_medium = NdisPhysicalMediumUnspecified;

	get_supported_oids(wnd);
	strncpy(net_dev->name, if_name, IFNAMSIZ - 1);
	net_dev->name[IFNAMSIZ - 1] = '\0';
	memcpy(&net_dev->dev_addr, mac, ETH_ALEN);

	wnd->packet_filter = NDIS_PACKET_TYPE_DIRECTED |
		NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_MULTICAST;
	net_dev->open = ndis_net_dev_open;
	net_dev->hard_start_xmit = tx_skbuff;
	net_dev->stop = ndis_net_dev_close;
	net_dev->get_stats = ndis_get_stats;
	net_dev->change_mtu = ndis_change_mtu;
	net_dev->do_ioctl = NULL;
	if (wnd->physical_medium == NdisPhysicalMediumWirelessLan) {
#if WIRELESS_EXT < 19
		net_dev->get_wireless_stats = get_wireless_stats;
#endif
		net_dev->wireless_handlers = &ndis_handler_def;
	}
	net_dev->set_multicast_list = ndis_set_multicast_list;
//	net_dev->set_mac_address = ndis_set_mac_address;
#if defined(HAVE_ETHTOOL)
	net_dev->ethtool_ops = &ndis_ethtool_ops;
#endif
	net_dev->irq = wnd->wd->pci.pdev->irq;
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

	if (register_netdev(net_dev)) {
		ERROR("cannot register net device %s", net_dev->name);
		goto err_register;
	}
	register_netdevice_notifier(&netdev_notifier);
	memcpy(wnd->netdev_name, net_dev->name, sizeof(wnd->netdev_name));
	wnd->tx_ok = 1;
	memset(buf, 0, buf_size);
	ndis_status = miniport_query_info(wnd, OID_GEN_VENDOR_DESCRIPTION,
					  buf, buf_size);
	if (ndis_status != NDIS_STATUS_SUCCESS) {
		WARNING("couldn't get vendor information: 0x%x", ndis_status);
		buf[0] = 0;
	}
	wnd->drv_ndis_version = n = 0;
	miniport_query_int(wnd, OID_GEN_DRIVER_VERSION,
			   &wnd->drv_ndis_version);
	miniport_query_int(wnd, OID_GEN_VENDOR_DRIVER_VERSION, &n);

	printk(KERN_INFO "%s: ethernet device " MACSTRSEP " using %sNDIS "
	       "driver: %s, version: 0x%x, NDIS version: 0x%x, vendor: '%s', "
	       "%s\n", net_dev->name, MAC2STR(net_dev->dev_addr),
	       deserialized_driver(wnd) ? "" : "serialized ",
	       wnd->wd->driver->name, n, wnd->drv_ndis_version, buf,
	       wnd->wd->conf_file_name);

	if (deserialized_driver(wnd)) {
		/* deserialized drivers don't have a limit, but we
		 * keep max at TX_RING_SIZE */
		wnd->max_tx_packets = TX_RING_SIZE;
	} else {
		ndis_status =
			miniport_query_int(wnd, OID_GEN_MAXIMUM_SEND_PACKETS,
					   &wnd->max_tx_packets);
		if (ndis_status != NDIS_STATUS_SUCCESS)
			wnd->max_tx_packets = 1;
		if (wnd->max_tx_packets > TX_RING_SIZE)
			wnd->max_tx_packets = TX_RING_SIZE;
	}
	DBGTRACE2("maximum send packets: %d", wnd->max_tx_packets);
	/* we need at least one extra packet for
	 * EthRxIndicateHandler */

	memset(&nbl_pool_params, 0, sizeof(nbl_pool_params));
	nbl_pool_params.header.type = NDIS_OBJECT_TYPE_DEFAULT;
	nbl_pool_params.header.revision =
		NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	nbl_pool_params.header.size = sizeof(nbl_pool_params);
	nbl_pool_params.fallocate_net_buffer = FALSE;
	nbl_pool_params.ctx_size = 0;
	nbl_pool_params.tag = 0;
	nbl_pool_params.data_size = 0;

	wnd->tx_buffer_list_pool =
		NdisAllocateNetBufferListPool(wnd, &nbl_pool_params);
	if (ndis_status != NDIS_STATUS_SUCCESS) {
		ERROR("couldn't allocate buffer pool");
		goto buffer_pool_err;
	}

	memset(&nb_pool_params, 0, sizeof(nb_pool_params));
	nb_pool_params.header.type = NDIS_OBJECT_TYPE_DEFAULT;
	nb_pool_params.header.revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
	nb_pool_params.header.size = sizeof(nb_pool_params);
	nb_pool_params.tag = 0;
	nb_pool_params.data_size = 0;

	wnd->tx_buffer_pool = NdisAllocateNetBufferPool(wnd, &nb_pool_params);
	DBGTRACE1("pool: %p", wnd->tx_buffer_pool);

	if (miniport_query_int(wnd, OID_GEN_MAXIMUM_TOTAL_SIZE, &n) ==
	    NDIS_STATUS_SUCCESS && n > ETH_HLEN)
		ndis_change_mtu(wnd->net_dev, n - ETH_HLEN);

	if (miniport_query_int(wnd, OID_GEN_MAC_OPTIONS, &n) ==
	    NDIS_STATUS_SUCCESS && n > 0)
		DBGTRACE2("mac options supported: 0x%x", n);

	transport_header_offset.protocol_type = NDIS_PROTOCOL_ID_TCP_IP;
	transport_header_offset.header_offset = sizeof(ETH_HLEN);
	ndis_status = miniport_set_info(wnd, OID_GEN_TRANSPORT_HEADER_OFFSET,
					&transport_header_offset,
					sizeof(transport_header_offset));
	TRACEENTER2("%08X", ndis_status);

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
	hangcheck_add(wnd);
	add_stats_timer(wnd);
	TRACEEXIT1(return NDIS_STATUS_SUCCESS);

buffer_pool_err:
	wnd->tx_buffer_pool = NULL;
err_register:
	kfree(buf);
err_start:
	ndis_remove_device(wnd);
	TRACEEXIT1(return NDIS_STATUS_FAILURE);
}

static int ndis_remove_device(struct wrap_ndis_device *wnd)
{
	/* prevent setting essid during disassociation */
	memset(&wnd->essid, 0, sizeof(wnd->essid));
	if (wnd->physical_medium == NdisPhysicalMediumWirelessLan) {
		up(&wnd->ndis_comm_mutex);
		miniport_set_info(wnd, OID_802_11_DISASSOCIATE, NULL, 0);
		down_interruptible(&wnd->ndis_comm_mutex);
	}
	set_bit(SHUTDOWN, &wnd->wrap_ndis_pending_work);
	unregister_netdevice_notifier(&netdev_notifier);
	wnd->tx_ok = 0;
	unregister_netdev(wnd->net_dev);
	netif_carrier_off(wnd->net_dev);
	wrap_procfs_remove_ndis_device(wnd);
	miniport_halt(wnd);
	ndis_exit_device(wnd);

	if (wnd->last_tx_buffer_list) {
		struct net_buffer_list *buffer_list;
		buffer_list = wnd->last_tx_buffer_list->ndis_reserved[0];
		free_tx_buffer_list(wnd, buffer_list);
	}
	if (wnd->tx_buffer_list_pool) {
		NdisFreeNetBufferListPool(wnd->tx_buffer_list_pool);
		wnd->tx_buffer_list_pool = NULL;
	}
	if (wnd->tx_buffer_pool) {
		NdisFreeNetBufferPool(wnd->tx_buffer_pool);
		wnd->tx_buffer_pool = NULL;
	}
	printk(KERN_INFO "%s: device %s removed\n", DRIVER_NAME,
	       wnd->net_dev->name);
	free_netdev(wnd->net_dev);
	TRACEEXIT2(return 0);
}

static wstdcall NTSTATUS NdisAddDevice(struct driver_object *drv_obj,
				       struct device_object *pdo)
{
	struct device_object *fdo;
	NTSTATUS status;
	struct wrap_ndis_device *wnd;
	struct net_device *net_dev;
	struct wrap_device *wd;
	unsigned long i;

	TRACEENTER2("%p, %p", drv_obj, pdo);
	if (strlen(if_name) >= IFNAMSIZ) {
		ERROR("interface name '%s' is too long", if_name);
		return STATUS_INVALID_PARAMETER;
	}
	net_dev = alloc_etherdev(sizeof(*wnd));
	if (!net_dev) {
		ERROR("couldn't allocate device");
		return STATUS_RESOURCES;
	}
	wnd = netdev_priv(net_dev);
	DBGTRACE1("wnd: %p", wnd);
	status = IoCreateDevice(drv_obj, 0, NULL,
				FILE_DEVICE_UNKNOWN, 0, FALSE, &fdo);
	if (status != STATUS_SUCCESS) {
		free_netdev(net_dev);
		TRACEEXIT2(return status);
	}
	fdo->reserved = wnd;
	wd = pdo->reserved;
	wd->wnd = wnd;
	wnd->wd = wd;
	wnd->pdo = pdo;
	wnd->fdo = fdo;
	wnd->net_dev = net_dev;
	init_MUTEX(&wnd->ndis_comm_mutex);
	init_waitqueue_head(&wnd->ndis_comm_wq);
	wnd->ndis_comm_done = 0;
	initialize_work(&wnd->tx_work, tx_worker, wnd);
	wnd->encr_mode = Ndis802_11EncryptionDisabled;
	wnd->auth_mode = Ndis802_11AuthModeOpen;
	wnd->capa.encr = 0;
	wnd->capa.auth = 0;
	wnd->attribute_flags = 0;
	wnd->dma_map_count = 0;
	wnd->dma_map_addr = NULL;
	wnd->nick[0] = 0;
	init_timer(&wnd->hangcheck_timer);
	wnd->scan_timestamp = 0;
	init_timer(&wnd->stats_timer);
	wnd->stats_interval = 10 * HZ;
	wnd->wrap_ndis_pending_work = 0;
	memset(&wnd->essid, 0, sizeof(wnd->essid));
	memset(&wnd->encr_info, 0, sizeof(wnd->encr_info));
	wnd->infrastructure_mode = Ndis802_11Infrastructure;
	initialize_work(&wnd->wrap_ndis_work, wrap_ndis_worker, wnd);
	wnd->hw_status = 0;

	wnd->next_device = IoAttachDeviceToDeviceStack(fdo, pdo);
	wnd->stats_enabled = TRUE;
	InitializeListHead(&wnd->timer_list);

	/* dispatch routines are called as Windows functions */
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv_obj->major_func[i] =
			WIN_FUNC_PTR(IoPassIrpDown,2);
	drv_obj->major_func[IRP_MJ_PNP] =
		WIN_FUNC_PTR(NdisDispatchPnp,2);
	drv_obj->major_func[IRP_MJ_POWER] =
		WIN_FUNC_PTR(NdisDispatchPower,2);
	drv_obj->major_func[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
		WIN_FUNC_PTR(NdisDispatchDeviceControl,2);
//	drv_obj->major_func[IRP_MJ_DEVICE_CONTROL] =
//		WIN_FUNC_PTR(NdisDispatchDeviceControl,2);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	SET_MODULE_OWNER(net_dev);
	if (wrap_is_pci_bus(wd->dev_bus))
		SET_NETDEV_DEV(net_dev, &wd->pci.pdev->dev);
	if (wrap_is_usb_bus(wd->dev_bus))
		SET_NETDEV_DEV(net_dev, &wd->usb.intf->dev);
#endif
	TRACEEXIT2(return STATUS_SUCCESS);
	if (wd->driver->ndis_driver) {
		struct wrap_ndis_driver *ndis_driver = wd->driver->ndis_driver;
		DBGTRACE2("%p, %p", ndis_driver, ndis_driver->mp_pnp_chars.add_device);
		if (ndis_driver->mp_pnp_chars.add_device) {
			status = LIN2WIN2(ndis_driver->mp_pnp_chars.add_device,
					  wnd, ndis_driver->mp_driver_ctx);
			if (status != NDIS_STATUS_SUCCESS) {
				WARNING("failed: 0x%x", status);
				free_netdev(net_dev);
				return status;
			}
		}
	}

}

int init_ndis_driver(struct driver_object *drv_obj)
{
	TRACEENTER1("%p", drv_obj);
	drv_obj->drv_ext->add_device = NdisAddDevice;
	return 0;
}
