/*
 *  Copyright (C) 2006-2007 Giridhar Pemmasani
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
#include "wrapper.h"

/* Functions callable from the NDIS driver */
wstdcall NTSTATUS NdisDispatchDeviceControl(struct device_object *fdo,
					    struct irp *irp);
wstdcall NTSTATUS NdisDispatchPnp(struct device_object *fdo, struct irp *irp);
wstdcall NTSTATUS NdisDispatchPower(struct device_object *fdo, struct irp *irp);

workqueue_struct_t *wrapndis_wq;

static struct nt_thread *wrapndis_worker_thread;
static int set_packet_filter(struct ndis_device *wnd,
			     ULONG packet_filter);
static void add_stats_timer(struct ndis_device *wnd);
static void del_stats_timer(struct ndis_device *wnd);
static NDIS_STATUS ndis_start_device(struct ndis_device *wnd);
static int ndis_remove_device(struct ndis_device *wnd);
static void set_multicast_list(struct ndis_device *wnd);
static int ndis_net_dev_open(struct net_device *net_dev);
static int ndis_net_dev_close(struct net_device *net_dev);

static NDIS_STATUS mp_oid_request(struct ndis_device *wnd,
				  struct ndis_oid_request *oid_req)
{
	NDIS_STATUS res;
	struct mp_driver_characteristics *mp_driver;

	TRACE2("oid: %08X", oid_req->data.query.oid);

	if (down_interruptible(&wnd->ndis_comm_mutex))
		EXIT3(return NDIS_STATUS_FAILURE);
	mp_driver = &wnd->wd->driver->ndis_driver->mp_driver;
	TRACE2("%08X", oid_req->data.query.oid);
	wnd->ndis_comm_done = 0;
	init_ndis_object_header(oid_req, NDIS_OBJECT_TYPE_OID_REQUEST,
				NDIS_OID_REQUEST_REVISION_1);
	oid_req->id = NULL;
	oid_req->handle = oid_req;
	res = LIN2WIN2(mp_driver->oid_request, wnd->nmb->adapter_ctx, oid_req);
	TRACE2("%08X, %08X", res, oid_req->data.query.oid);
	if (res == NDIS_STATUS_PENDING) {
		/* wait for completion */
		if (wait_condition((wnd->ndis_comm_done > 0), 0,
				   TASK_INTERRUPTIBLE) < 0)
			res = NDIS_STATUS_FAILURE;
		else
			res = wnd->ndis_comm_status;
		TRACE2("%08X, %08X", oid_req->data.query.oid, res);
	}
	up(&wnd->ndis_comm_mutex);
	DBG_BLOCK(2) {
		if (res)
			TRACE2("%08X", res);
	}
	EXIT3(return res);
}

static void prepare_mp_oid_request(struct ndis_oid_request *oid_req)
{
	memset(oid_req, 0, sizeof(*oid_req));
	oid_req->port = 0;
	oid_req->timeout_sec = 0;
}

NDIS_STATUS mp_query_info(struct ndis_device *wnd, ndis_oid oid, void *buf,
			  ULONG buf_len, UINT *needed, UINT *written)
{
	struct ndis_oid_request oid_req;
	NDIS_STATUS status;

	ENTER2("%08X", oid);
	prepare_mp_oid_request(&oid_req);
	oid_req.type = NdisRequestQueryInformation;
	oid_req.data.query.oid = oid;
	oid_req.data.query.buf = buf;
	oid_req.data.query.buf_length = buf_len;
	status = mp_oid_request(wnd, &oid_req);
	TRACE2("%d/%d/%d", buf_len, oid_req.data.query.bytes_written,
	       oid_req.data.query.bytes_needed);
	if (needed)
		*needed = oid_req.data.query.bytes_needed;
	if (written)
		*written = oid_req.data.query.bytes_written;
	return status;
}

NDIS_STATUS mp_set_info(struct ndis_device *wnd, ndis_oid oid,
			void *buf, ULONG buf_len, UINT *needed, UINT *written)
{
	struct ndis_oid_request oid_req;
	NDIS_STATUS res;

	ENTER2("%08X", oid);
	prepare_mp_oid_request(&oid_req);
	oid_req.type = NdisRequestSetInformation;
	oid_req.data.set.oid = oid;
	oid_req.data.set.buf = buf;
	oid_req.data.set.buf_length = buf_len;
	res = mp_oid_request(wnd, &oid_req);
	TRACE2("%d/%d/%d", buf_len, oid_req.data.set.bytes_written,
	       oid_req.data.set.bytes_needed);
	if (needed)
		*needed = oid_req.data.set.bytes_needed;
	if (written)
		*written = oid_req.data.set.bytes_written;
	return res;
}

NDIS_STATUS mp_request_method(struct ndis_device *wnd, ndis_oid oid,
			      void *buf, ULONG buf_len, UINT *needed,
			      UINT *written)
{
	struct ndis_oid_request oid_req;
	NDIS_STATUS status;

	ENTER2("%08X", oid);
	prepare_mp_oid_request(&oid_req);
	oid_req.type = NdisRequestMethod;
	oid_req.data.method.oid = oid;
	oid_req.data.method.buf = buf;
	oid_req.data.method.in_buf_length = buf_len;
	oid_req.data.method.out_buf_length = buf_len;
	status = mp_oid_request(wnd, &oid_req);
	TRACE2("%d/%d/%d/%d", buf_len, oid_req.data.method.bytes_written,
	       oid_req.data.method.bytes_read, oid_req.data.method.bytes_needed);
	if (needed)
		*needed = oid_req.data.method.bytes_needed;
	if (written)
		*written = oid_req.data.method.bytes_written;
	return status;
}

NDIS_STATUS mp_reset(struct ndis_device *wnd)
{
	struct mp_driver_characteristics *mp_driver;
	NDIS_STATUS res;
	BOOLEAN address_reset;

	mp_driver = &wnd->wd->driver->ndis_driver->mp_driver;
	res = LIN2WIN2(mp_driver->reset, wnd->nmb->adapter_ctx, &address_reset);
	TRACE2("%08X, %d", res, address_reset);
	return res;
}

/* MiniportInitialize */
static NDIS_STATUS mp_init(struct ndis_device *wnd)
{
	NDIS_STATUS status;
	struct ndis_driver *ndis_driver;
	struct mp_init_params init_params;

	ENTER1("irql: %d", current_irql());
	if (test_bit(HW_INITIALIZED, &wnd->hw_status)) {
		WARNING("device %p already initialized!", wnd);
		return NDIS_STATUS_FAILURE;
	}

	if (!wnd->wd->driver->ndis_driver) {
		WARNING("assuming WDM (non-NDIS) driver");
		EXIT1(return NDIS_STATUS_NOT_RECOGNIZED);
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
		NdisPortControlStateUncontrolled;
	init_params.port_auth_states.rx_control_state =
		NdisPortControlStateUncontrolled;
	init_params.port_auth_states.tx_auth_state = NdisPortUnauthorized;
	init_params.port_auth_states.rx_auth_state = NdisPortUnauthorized;

	status = LIN2WIN3(ndis_driver->mp_driver.initialize,
			  wnd->nmb, ndis_driver->mp_driver_ctx,
			  &init_params);
	TRACE1("init returns: %08X, irql: %d", status, current_irql());
	if (status != NDIS_STATUS_SUCCESS) {
		WARNING("couldn't initialize device: %08X", status);
		EXIT1(return NDIS_STATUS_FAILURE);
	}

	sleep_hz(HZ / 5);
	set_bit(HW_INITIALIZED, &wnd->hw_status);

	/* although some NDIS drivers support suspend, Linux kernel
	 * has issues with suspending USB devices */
	if (wrap_is_usb_bus(wnd->wd->dev_bus))
		wnd->attribute_flags &= ~NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND;
	EXIT1(return NDIS_STATUS_SUCCESS);
}

/* MiniportHalt */
static void mp_halt(struct ndis_device *wnd)
{
	struct mp_driver_characteristics *mp_driver;
	enum ndis_halt_action halt_action;

	ENTER1("%p", wnd);

	if (!test_and_clear_bit(HW_INITIALIZED, &wnd->hw_status)) {
		WARNING("device %p is not initialized - not halting", wnd);
		return;
	}
	mp_driver = &wnd->wd->driver->ndis_driver->mp_driver;
	if (test_bit(HW_PRESENT, &wnd->wd->hw_status))
		halt_action = NdisHaltDeviceDisabled;
	else
		halt_action = NdisHaltDeviceSurpriseRemoved;

	hangcheck_del(wnd);
	del_stats_timer(wnd);
	if (down_interruptible(&wnd->ndis_comm_mutex))
		WARNING("couldn't obtain ndis_comm_mutex");
	LIN2WIN2(mp_driver->mphalt, wnd->nmb->adapter_ctx, halt_action);
	up(&wnd->ndis_comm_mutex);
	/* cancel any timers left by bugyy windows driver; also free
	 * the memory for timers */
	while (1) {
		struct nt_slist *slist;
		struct wrap_timer *wrap_timer;

		slist = atomic_remove_list_head(wnd->wrap_timer_slist.next,
						oldhead->next);
		TIMERTRACE("%p", slist);
		if (!slist)
			break;
		wrap_timer = container_of(slist, struct wrap_timer, slist);
		wrap_timer->repeat = 0;
		/* ktimer that this wrap_timer is associated to can't
		 * be touched, as it may have been freed by the driver
		 * already */
		if (del_timer_sync(&wrap_timer->timer))
			WARNING("Buggy Windows driver left timer %p "
				"running", wrap_timer->nt_timer);
		memset(wrap_timer, 0, sizeof(*wrap_timer));
		kfree(wrap_timer);
	}
	EXIT1(return);
}

static struct net_buffer_list *
alloc_tx_buffer_list(struct ndis_device *wnd, struct sk_buff *skb)
{
	struct net_buffer_list *buffer_list;
	struct net_buffer *buffer;
	struct mdl *mdl;

	buffer_list = NdisAllocateNetBufferList(wnd->tx_buffer_list_pool, 0, 0);
	if (!buffer_list)
		return NULL;
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
	buffer_list->header.data.first_buffer = buffer;
	TRACE3("%p, %p, %p", buffer_list, buffer, skb);
	return buffer_list;
}

void free_tx_buffer_list(struct ndis_device *wnd,
			 struct net_buffer_list *buffer_list)
{
	struct net_buffer_list *blist;
	unsigned long n = 0;

	TRACE3("%p", buffer_list);
	for (blist = buffer_list; blist; blist = blist->header.data.next) {
		struct net_buffer *buffer;

		for (buffer = buffer_list->header.data.first_buffer; buffer;
		     buffer = buffer->header.data.next) {
			struct sk_buff *skb;
			skb = buffer->ndis_reserved[0];
			n += skb->len;
			dev_kfree_skb_any(skb);
		}
	}
	if (buffer_list->status == NDIS_STATUS_SUCCESS) {
		pre_atomic_add(wnd->net_stats.tx_bytes, n);
		atomic_inc_var(wnd->net_stats.tx_packets);
	} else {
		TRACE1("packet dropped: %08X", buffer_list->status);
		atomic_inc_var(wnd->net_stats.tx_dropped);
	}
	NdisFreeNetBufferList(buffer_list);
}

static void tx_worker(worker_param_t param)
{
	struct ndis_device *wnd;
	struct mp_driver_characteristics *mp_driver;

	wnd = worker_param_data(param, struct ndis_device, tx_work);
	ENTER3("tx_ok %d", wnd->tx_ok);
	mp_driver = &wnd->wd->driver->ndis_driver->mp_driver;
	while (wnd->tx_ok) {
		struct net_buffer_list *tx_buffer_list;

		spin_lock_bh(&wnd->tx_ring_lock);
		tx_buffer_list = wnd->tx_buffer_list;
		wnd->tx_buffer_list = NULL;
		spin_unlock_bh(&wnd->tx_ring_lock);
		TRACE3("%p", tx_buffer_list);
		if (!tx_buffer_list)
			break;
		LIN2WIN4(mp_driver->tx_net_buffer_lists, wnd->nmb->adapter_ctx,
			 tx_buffer_list, 0, 0);
	}
	EXIT3(return);
}

static int tx_skbuff(struct sk_buff *skb, struct net_device *dev)
{
	struct ndis_device *wnd = netdev_priv(dev);
	struct net_buffer_list *tx_buffer_list;

	tx_buffer_list = alloc_tx_buffer_list(wnd, skb);
	if (!tx_buffer_list) {
		WARNING("couldn't allocate packet");
		netif_tx_lock(dev);
		netif_stop_queue(dev);
		netif_tx_unlock(dev);
		return NETDEV_TX_BUSY;
	}
	TRACE3("%p, %p", tx_buffer_list, skb);
	spin_lock(&wnd->tx_ring_lock);
	if (wnd->tx_buffer_list) {
		struct net_buffer_list *last;
		last = wnd->tx_buffer_list->ndis_reserved[0];
		last->header.data.next = tx_buffer_list;
	} else
		wnd->tx_buffer_list = tx_buffer_list;
	wnd->tx_buffer_list->ndis_reserved[0] = tx_buffer_list;
	spin_unlock(&wnd->tx_ring_lock);
	schedule_wrapndis_work(&wnd->tx_work);
	return NETDEV_TX_OK;
}

static int set_packet_filter(struct ndis_device *wnd, ULONG packet_filter)
{
	NDIS_STATUS res;

	while (1) {
		res = mp_set_int(wnd, OID_GEN_CURRENT_PACKET_FILTER,
				 packet_filter);
		if (res == NDIS_STATUS_SUCCESS)
			break;
		TRACE2("couldn't set filter 0x%08x", packet_filter);
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
	res = mp_query_int(wnd, OID_GEN_CURRENT_PACKET_FILTER, &packet_filter);
	if (packet_filter != wnd->packet_filter) {
		WARNING("filter not set: 0x%08x, 0x%08x",
			packet_filter, wnd->packet_filter);
		wnd->packet_filter = packet_filter;
	}
	if (wnd->packet_filter)
		EXIT3(return 0);
	else
		EXIT3(return -1);
}

void set_media_state(struct ndis_device *wnd, enum ndis_media_state state)
{
	ENTER2("state: 0x%x", state);
	if (state == NdisMediaStateConnected) {
		netif_carrier_on(wnd->net_dev);
		wnd->tx_ok = 1;
		if (netif_queue_stopped(wnd->net_dev))
			netif_wake_queue(wnd->net_dev);
		if (wnd->physical_medium == NdisPhysicalMediumWirelessLan) {
			set_bit(LINK_STATUS_CHANGED, &wnd->ndis_pending_work);
			schedule_wrapndis_work(&wnd->ndis_work);
		}
	} else if (state == NdisMediaStateDisconnected) {
		netif_carrier_off(wnd->net_dev);
		netif_stop_queue(wnd->net_dev);
		wnd->tx_ok = 0;
		if (wnd->physical_medium == NdisPhysicalMediumWirelessLan) {
			memset(&wnd->essid, 0, sizeof(wnd->essid));
			set_bit(LINK_STATUS_CHANGED, &wnd->ndis_pending_work);
			schedule_wrapndis_work(&wnd->ndis_work);
		}
	} else {
		WARNING("invalid media state: 0x%x", state);
	}
}

static int ndis_net_dev_open(struct net_device *net_dev)
{
	struct ndis_device *wnd = netdev_priv(net_dev);
	int status;

	ENTER1("%p", wnd);
	if (set_packet_filter(wnd, wnd->packet_filter)) {
		WARNING("couldn't set packet filter");
		return -ENODEV;
	}
	if (mp_query_int(wnd, OID_GEN_MEDIA_CONNECT_STATUS, &status) ==
	    NDIS_STATUS_SUCCESS)
		set_media_state(wnd, status);
	netif_start_queue(net_dev);
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
	struct ndis_device *wnd = netdev_priv(net_dev);
	int max;

	if (mtu < ETH_ZLEN)
		return -EINVAL;
	if (mp_query_int(wnd, OID_GEN_MAXIMUM_TOTAL_SIZE, &max) !=
	    NDIS_STATUS_SUCCESS)
		return -EOPNOTSUPP;
	TRACE2("%d", max);
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
	struct ndis_device *wnd = netdev_priv(dev);

	disable_irq(dev->irq);
	ndis_isr(wnd->kinterrupt, wnd);
	enable_irq(dev->irq);
}
#endif

/* called from BH context */
static struct net_device_stats *ndis_get_stats(struct net_device *dev)
{
	struct ndis_device *wnd = netdev_priv(dev);
	return &wnd->stats;
}

/* called from BH context */
static void ndis_set_multicast_list(struct net_device *dev)
{
	struct ndis_device *wnd = netdev_priv(dev);
	set_bit(SET_MULTICAST_LIST, &wnd->ndis_pending_work);
	schedule_wrapndis_work(&wnd->ndis_work);
}

/* called from BH context */
struct iw_statistics *get_iw_stats(struct net_device *dev)
{
	struct ndis_device *wnd = netdev_priv(dev);
	return &wnd->wireless_stats;
}

static void ndis_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	struct ndis_device *wnd = netdev_priv(dev);
	strncpy(info->driver, DRIVER_NAME, sizeof(info->driver) - 2);
	strcat(info->driver, "+");
	strncat(info->driver, wnd->wd->driver->name,
		sizeof(info->driver) - strlen(DRIVER_NAME) - 1);
	strncpy(info->version, DRIVER_VERSION, sizeof(info->version) - 2);
	strcat(info->version, "+");
	strncat(info->version, wnd->wd->driver->version,
		sizeof(info->version) - strlen(DRIVER_VERSION) - 1);
	if (wrap_is_pci_bus(wnd->wd->dev_bus))
		strncpy(info->bus_info, pci_name(wnd->wd->pci.pdev),
			sizeof(info->bus_info) - 1);
#ifdef ENABLE_USB
	else
		usb_make_path(wnd->wd->usb.udev, info->bus_info,
			      sizeof(info->bus_info) - 1);
#endif
	return;
}

static u32 ndis_get_link(struct net_device *dev)
{
	struct ndis_device *wnd = netdev_priv(dev);
	return netif_carrier_ok(wnd->net_dev);
}

static struct ethtool_ops ndis_ethtool_ops = {
	.get_drvinfo	= ndis_get_drvinfo,
	.get_link	= ndis_get_link,
};

static int notifier_event(struct notifier_block *notifier, unsigned long event,
			  void *ptr)
{
	struct net_device *net_dev = (struct net_device *)ptr;
	struct ndis_device *wnd;

	if (net_dev->ethtool_ops != &ndis_ethtool_ops)
		return NOTIFY_DONE;

	wnd = netdev_priv(net_dev);
	/* called with rtnl lock held, so no need to lock */
	if (event == NETDEV_CHANGENAME) {
		wrap_procfs_remove_ndis_device(wnd);
		printk(KERN_INFO "%s: changing interface name from '%s' to "
		       "'%s'\n", DRIVER_NAME, wnd->netdev_name, net_dev->name);
		memcpy(wnd->netdev_name, net_dev->name,
		       sizeof(wnd->netdev_name));
		wrap_procfs_add_ndis_device(wnd);
		return NOTIFY_OK;
	}
	TRACE2("%s: %lx", wnd->netdev_name, event);
	return NOTIFY_DONE;
}

static struct notifier_block netdev_notifier = {
	.notifier_call = notifier_event,
};

static void update_wireless_stats(struct ndis_device *wnd)
{
	struct iw_statistics *iw_stats = &wnd->wireless_stats;
	NDIS_STATUS res;
	struct ndis_dot11_statistics *ndis_stats;
	struct ndis_dot11_phy_frame_statistics *phy_stats;
	struct ndis_dot11_mac_frame_statistics *mac_stats;
	int n;

	ENTER2("%p", wnd);
	if (wnd->stats_enabled == FALSE || !netif_carrier_ok(wnd->net_dev)) {
		memset(iw_stats, 0, sizeof(*iw_stats));
//		EXIT2(return);
	}
	n = sizeof(*ndis_stats) +
		sizeof(*phy_stats) * (wnd->phy_types->num_entries - 1);
	ndis_stats = kzalloc(n, GFP_KERNEL);
	if (!ndis_stats) {
		WARNING("couldn't allocate memory");
		return;
	}
	init_ndis_object_header(ndis_stats, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_STATISTICS_REVISION_1);
	res = mp_query(wnd, OID_DOT11_STATISTICS, ndis_stats, n);
	TRACE2("%08X", res);
	if (res != NDIS_STATUS_SUCCESS)
		return;
	mac_stats = &ndis_stats->mac_ucast_stats;
	(void)mac_stats;
	TRACE2("%Lu, %Lu, %Lu, %Lu", mac_stats->tx_frames,
		  mac_stats->rx_frames, mac_stats->tx_failure_frames,
		  mac_stats->rx_failure_frames);

	phy_stats = &ndis_stats->phy_stats[wnd->phy_id];
	TRACE2("%Lu, %Lu, %Lu, %Lu, %Lu, %Lu : "
		  "%Lu, %Lu, %Lu, %Lu : "
		  "%Lu, %Lu, %Lu, %Lu : "
		  "%Lu, %Lu, %Lu, %Lu",
		  phy_stats->tx_frames, phy_stats->multicast_tx_frames,
		  phy_stats->failed, phy_stats->retry,
		  phy_stats->multiple_retry, phy_stats->max_tx_lifetime_exceeded,

		  phy_stats->tx_fragments, phy_stats->rts_success,
		  phy_stats->rts_failure, phy_stats->ack_failure,

		  phy_stats->rx_frames, phy_stats->multicast_rx_frames,
		  phy_stats->promisc_rx_frames,
		  phy_stats->max_rx_lifetime_exceeded,

		  phy_stats->dup_frames, phy_stats->rx_fragments,
		  phy_stats->promisc_rx_fragments, phy_stats->fcs_errors);

	memset(iw_stats, 0, sizeof(*iw_stats));
	EXIT2(return);
}

static void set_multicast_list(struct ndis_device *wnd)
{
	struct net_device *net_dev;
	ULONG packet_filter;
	NDIS_STATUS res;

	net_dev = wnd->net_dev;
	packet_filter = wnd->packet_filter;

	TRACE2("0x%08x", packet_filter);
	if (net_dev->flags & IFF_PROMISC) {
		packet_filter |= NDIS_PACKET_TYPE_PROMISCUOUS |
			NDIS_PACKET_TYPE_ALL_LOCAL;
	} else if (net_dev->flags & IFF_ALLMULTI ||
		   netdev_mc_count(net_dev) > wnd->multicast_size) {
		packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
		TRACE2("0x%08x", packet_filter);
	} else if (netdev_mc_count(net_dev) > 0) {
		int i, size;
		char *buf;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
		struct netdev_hw_addr *ha;
#else
		struct dev_mc_list *mclist;
#endif
		size = min(wnd->multicast_size, netdev_mc_count(net_dev));
		TRACE2("%d, %d", wnd->multicast_size, netdev_mc_count(net_dev));
		buf = kmalloc(size * ETH_ALEN, GFP_KERNEL);
		if (!buf) {
			WARNING("couldn't allocate memory");
			EXIT2(return);
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
		i = 0;
		netdev_for_each_mc_addr(ha, net_dev) {
			if (i >= size)
				break;
			memcpy(buf + i * ETH_ALEN, ha->addr, ETH_ALEN);
			TRACE2(MACSTRSEP, MAC2STR(ha->addr));
			i++;
		}
#else
		mclist = net_dev->mc_list;
		for (i = 0; i < size && mclist; mclist = mclist->next) {
			if (mclist->dmi_addrlen != ETH_ALEN)
				continue;
			memcpy(buf + i * ETH_ALEN, mclist->dmi_addr, ETH_ALEN);
			TRACE2(MACSTRSEP, MAC2STR(mclist->dmi_addr));
			i++;
		}
#endif
		res = mp_set(wnd, OID_802_3_MULTICAST_LIST, buf, i * ETH_ALEN);
		if (res == NDIS_STATUS_SUCCESS && i > 0)
			packet_filter |= NDIS_PACKET_TYPE_MULTICAST;
		else
			packet_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
		kfree(buf);
	}
	TRACE2("0x%08x", packet_filter);
	res = set_packet_filter(wnd, packet_filter);
	if (res)
		TRACE1("couldn't set packet filter (%08X)", res);
	EXIT2(return);
}

static void link_status_handler(struct ndis_device *wnd)
{
	ENTER2("link: %d", netif_carrier_ok(wnd->net_dev));
	if (wnd->physical_medium == NdisPhysicalMediumNative802_11)
		EXIT2(return);
	EXIT2(return);
}

static void stats_timer_proc(unsigned long data)
{
	struct ndis_device *wnd = (struct ndis_device *)data;

	ENTER2("");
	if (wnd->stats_interval <= 0)
		EXIT2(return);
	set_bit(COLLECT_STATS, &wnd->ndis_pending_work);
	schedule_wrapndis_work(&wnd->ndis_work);
	mod_timer(&wnd->stats_timer, jiffies + wnd->stats_interval);
}

static void add_stats_timer(struct ndis_device *wnd)
{
	if (wnd->physical_medium != NdisPhysicalMediumWirelessLan)
		return;
	if (wnd->stats_interval < 0)
		wnd->stats_interval *= -1;
	wnd->stats_timer.data = (unsigned long)wnd;
	wnd->stats_timer.function = stats_timer_proc;
	mod_timer(&wnd->stats_timer, jiffies + wnd->stats_interval);
}

static void del_stats_timer(struct ndis_device *wnd)
{
	ENTER2("");
	wnd->stats_interval *= -1;
	del_timer_sync(&wnd->stats_timer);
	EXIT2(return);
}

static void hangcheck_proc(unsigned long data)
{
	struct ndis_device *wnd = (struct ndis_device *)data;
	struct ndis_driver *ndis_driver;
	BOOLEAN res;

	ENTER2("");
	if (wnd->hangcheck_interval <= 0)
		EXIT2(return);

	ndis_driver = wnd->wd->driver->ndis_driver;
	res = LIN2WIN1(ndis_driver->mp_driver.check_for_hang,
		       wnd->nmb->adapter_ctx);
	if (res) {
		set_bit(MINIPORT_RESET, &wnd->ndis_pending_work);
		schedule_wrapndis_work(&wnd->ndis_work);
	}
	mod_timer(&wnd->hangcheck_timer, jiffies + wnd->hangcheck_interval);
	EXIT3(return);
}

void hangcheck_add(struct ndis_device *wnd)
{
	ENTER2("%d, %d", wnd->hangcheck_interval, hangcheck_interval);
	if (hangcheck_interval < 0)
		EXIT2(return);
	if (hangcheck_interval > 0)
		wnd->hangcheck_interval = hangcheck_interval * HZ;
	if (wnd->hangcheck_interval < 0)
		wnd->hangcheck_interval *= -1;

	EXIT2(return);
	wnd->hangcheck_timer.data = (unsigned long)wnd;
	wnd->hangcheck_timer.function = hangcheck_proc;
	mod_timer(&wnd->hangcheck_timer, jiffies + wnd->hangcheck_interval);
}

void hangcheck_del(struct ndis_device *wnd)
{
	ENTER2("");
	if (wnd->hangcheck_interval > 0)
		wnd->hangcheck_interval *= -1;
	del_timer_sync(&wnd->hangcheck_timer);
	EXIT2(return);
}

/* worker procedure to take care of setting/checking various states */
static void ndis_worker(worker_param_t param)
{
	struct ndis_device *wnd;

	wnd = worker_param_data(param, struct ndis_device, ndis_work);

	TRACE2("%lu", wnd->ndis_pending_work);

	if (test_bit(SHUTDOWN, &wnd->ndis_pending_work))
		EXIT3(return);

	if (test_and_clear_bit(SET_MULTICAST_LIST, &wnd->ndis_pending_work))
		set_multicast_list(wnd);

	if (test_and_clear_bit(COLLECT_STATS, &wnd->ndis_pending_work))
		update_wireless_stats(wnd);

	if (test_and_clear_bit(LINK_STATUS_CHANGED, &wnd->ndis_pending_work))
		link_status_handler(wnd);

	if (test_and_clear_bit(PHY_STATE_CHANGED,
			       &wnd->ndis_pending_work)) {
		NDIS_STATUS res;
		BOOLEAN b = TRUE;
		res = mp_set_info(wnd, OID_DOT11_HARDWARE_PHY_STATE, &b,
				  sizeof(b), NULL, NULL);
		(void)res;
		TRACE1("%08X", res);
	}
	if (test_and_clear_bit(MINIPORT_RESET, &wnd->ndis_pending_work))
		mp_reset(wnd);
	EXIT3(return);
}

static NDIS_STATUS mp_set_power_state(struct ndis_device *wnd,
				      enum ndis_power_state state)
{
	NDIS_STATUS status;

	TRACE1("%d", state);
	if (state == NdisDeviceStateD0) {
		status = NDIS_STATUS_SUCCESS;
		up(&wnd->ndis_comm_mutex);
		if (test_and_clear_bit(HW_HALTED, &wnd->hw_status)) {
			status = mp_init(wnd);
			if (status == NDIS_STATUS_SUCCESS) {
				set_packet_filter(wnd, wnd->packet_filter);
				set_multicast_list(wnd);
			}
		} else if (test_and_clear_bit(HW_SUSPENDED, &wnd->hw_status)) {
			status = mp_set_int(wnd, OID_PNP_SET_POWER, state);
			if (status != NDIS_STATUS_SUCCESS)
				WARNING("%s: setting power to state %d failed? "
					"%08X", wnd->net_dev->name, state,
					status);
			mp_pnp_event(wnd, NdisDevicePnPEventPowerProfileChanged,
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
		EXIT1(return status);
	} else {
		netif_device_detach(wnd->net_dev);
		hangcheck_del(wnd);
		del_stats_timer(wnd);
		status = NDIS_STATUS_NOT_SUPPORTED;
		if (wnd->attribute_flags & NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND) {
			enum ndis_power_state pm_state = state;
			if (wnd->ndis_wolopts) {
				status = mp_set_int(wnd, OID_PNP_ENABLE_WAKE_UP,
						    wnd->ndis_wolopts);
				if (status == NDIS_STATUS_SUCCESS) {
					if (wrap_is_pci_bus(wnd->wd->dev_bus))
						pci_enable_wake(wnd->wd->pci.pdev,
								PCI_D0, 1);
				} else
					WARNING("%s: couldn't enable WOL: %08x",
						wnd->net_dev->name, status);
			}
			status = mp_set_int(wnd, OID_PNP_SET_POWER, pm_state);
			if (status == NDIS_STATUS_SUCCESS)
				set_bit(HW_SUSPENDED, &wnd->hw_status);
			else
				WARNING("suspend failed: %08X", status);
		}
		if (status != NDIS_STATUS_SUCCESS) {
			WARNING("%s does not support power management; "
				"halting the device", wnd->net_dev->name);
			mp_halt(wnd);
			set_bit(HW_HALTED, &wnd->hw_status);
			status = STATUS_SUCCESS;
		}
		if (down_interruptible(&wnd->ndis_comm_mutex))
			WARNING("couldn't lock ndis_comm_mutex");
		EXIT1(return status);
	}
}

NDIS_STATUS mp_pnp_event(struct ndis_device *wnd,
			 enum ndis_device_pnp_event event, ULONG profile)
{
	struct ndis_driver *ndis_driver;
	struct net_device_pnp_event net_event;

	ENTER1("%p, %d", wnd, event);
	ndis_driver = wnd->wd->driver->ndis_driver;
	if (!ndis_driver->mp_driver.pnp_event_notify) {
		TRACE1("Windows driver %s doesn't support "
			  "MiniportPnpEventNotify", wnd->wd->driver->name);
		return NDIS_STATUS_FAILURE;
	}
	/* RNDIS driver doesn't like to be notified if device is
	 * already halted */
	if (!test_bit(HW_INITIALIZED, &wnd->hw_status))
		EXIT1(return NDIS_STATUS_SUCCESS);
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
		if (!test_bit(HW_PRESENT, &wnd->wd->hw_status))
			EXIT1(return NDIS_STATUS_SUCCESS);
		if (wnd->attribute_flags & NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK)
			LIN2WIN2(ndis_driver->mp_driver.pnp_event_notify,
				 wnd->nmb->adapter_ctx, &net_event);
		else
			TRACE1("Windows driver %s doesn't support "
				  "MiniportPnpEventNotify for safe unplugging",
				  wnd->wd->driver->name);
		return NDIS_STATUS_SUCCESS;
	case NdisDevicePnPEventPowerProfileChanged:
		/* TODO: get ac/battery status from kernel */
		net_event.buf = &profile;
		net_event.buf_length = sizeof(profile);
		LIN2WIN2(ndis_driver->mp_driver.pnp_event_notify,
			 wnd->nmb->adapter_ctx, &net_event);
		return NDIS_STATUS_SUCCESS;
	default:
		WARNING("event %d not yet implemented", event);
		return NDIS_STATUS_SUCCESS;
	}
}

NDIS_STATUS ndis_reinit(struct ndis_device *wnd)
{
	NDIS_STATUS status;

	wnd->attribute_flags &= ~NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND;
	status = mp_set_power_state(wnd, NdisDeviceStateD3);
	if (status != NDIS_STATUS_SUCCESS) {
		ERROR("halting device %s failed: %08X", wnd->net_dev->name,
		      status);
		return status;
	}
	status = mp_set_power_state(wnd, NdisDeviceStateD0);
	if (status != NDIS_STATUS_SUCCESS)
		ERROR("starting device %s failed: %08X", wnd->net_dev->name,
		      status);
	return status;
}

static void get_dot11_encryption_capa(struct ndis_device *wnd,
				      void *buf, int buf_len)
{
	struct ndis_dot11_auth_cipher_pair_list *auth_cipher_pairs;
	NDIS_STATUS res;
	int i;

	ENTER1("");
	res = mp_query(wnd, OID_DOT11_SUPPORTED_UNICAST_ALGORITHM_PAIR,
		       buf, buf_len);
	if (res) {
		WARNING("authentication/cipher query failed: %08x", res);
		return;
	}
	auth_cipher_pairs = buf;
	init_ndis_object_header(auth_cipher_pairs, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_AUTH_CIPHER_PAIR_LIST_REVISION_1);
	if (res) {
		WARNING("authentication/cipher query failed: %08X", res);
		return;
	}
	for (i = 0; i < auth_cipher_pairs->num_entries; i++) {
		struct ndis_dot11_auth_cipher_pair *pair =
			&auth_cipher_pairs->pairs[i];
		TRACE2("%d, %d", pair->auth_algo_id, pair->cipher_algo_id);
		if (pair->auth_algo_id >= DOT11_AUTH_ALGO_80211_OPEN &&
		    pair->auth_algo_id <= DOT11_AUTH_ALGO_RSNA_PSK)
			set_bit(pair->auth_algo_id, &wnd->capa.auth);
		if (pair->cipher_algo_id >= DOT11_CIPHER_ALGO_WEP40 &&
		    pair->cipher_algo_id <= DOT11_CIPHER_ALGO_WEP104)
			set_bit(pair->cipher_algo_id, &wnd->capa.encr);
	}
	EXIT1(return);
}

static void init_dot11_station(struct ndis_device *wnd, void *buf,
			       int buf_len)
{
	struct ndis_dot11_reset_request *reset_req;
	struct ndis_dot11_current_operation_mode *op_mode;
	struct ndis_dot11_op_mode_capability *op_mode_capa;
	struct ndis_dot11_country_or_region_string_list *country_region_list;
	NDIS_STATUS res;

	reset_req = (typeof(reset_req))buf;
	reset_req->type = ndis_dot11_reset_type_phy_and_mac;
	reset_req->set_default_mib = TRUE;
	res = mp_set(wnd, OID_DOT11_RESET_REQUEST,
		     reset_req, sizeof(*reset_req));
	TRACE2("%08X", res);

	get_dot11_encryption_capa(wnd, buf, buf_len);
	TRACE1("capbilities = %ld", wnd->capa.encr);
	printk(KERN_INFO "%s: encryption modes supported: "
	       "%s%s%s%s%s%s%s%s%s%s%s%s\n", wnd->net_dev->name,
	       test_bit(DOT11_CIPHER_ALGO_WEP40, &wnd->capa.encr) ?
	       "WEP40" : "",

	       test_bit(DOT11_CIPHER_ALGO_WEP104, &wnd->capa.encr) ?
	       "WEP104" : "",

	       test_bit(DOT11_CIPHER_ALGO_TKIP, &wnd->capa.encr) ?
	       "; TKIP with" : "",
	       test_bit(DOT11_AUTH_ALGO_WPA, &wnd->capa.auth) ?
	       ", WPA" : "",
	       test_bit(DOT11_AUTH_ALGO_WPA_PSK, &wnd->capa.auth) ?
	       ", WPAPSK" : "",
	       test_bit(DOT11_AUTH_ALGO_RSNA, &wnd->capa.auth) ?
	       ", WPA2" : "",
	       test_bit(DOT11_AUTH_ALGO_RSNA_PSK, &wnd->capa.auth) ?
	       ", WPA2PSK" : "",

	       test_bit(DOT11_CIPHER_ALGO_CCMP, &wnd->capa.encr) ?
	       "; AES/CCMP with" : "",
	       test_bit(DOT11_AUTH_ALGO_WPA, &wnd->capa.auth) ?
	       ", WPA" : "",
	       test_bit(DOT11_AUTH_ALGO_WPA_PSK, &wnd->capa.auth) ?
	       ", WPAPSK" : "",
	       test_bit(DOT11_AUTH_ALGO_RSNA, &wnd->capa.auth) ?
	       ", WPA2" : "",
	       test_bit(DOT11_AUTH_ALGO_RSNA_PSK, &wnd->capa.auth) ?
	       ", WPA2PSK" : "");

	op_mode_capa = buf;
	op_mode_capa->major_version = 2;
	op_mode_capa->minor_version = 0;
	res = mp_query(wnd, OID_DOT11_OPERATION_MODE_CAPABILITY,
		       op_mode_capa, sizeof(*op_mode_capa));
	TRACE2("%d, %d, %d, %d, 0x%x", op_mode_capa->major_version,
	       op_mode_capa->minor_version, op_mode_capa->num_tx_buffers,
	       op_mode_capa->num_rx_buffers, op_mode_capa->mode);
	op_mode = buf;
	op_mode->reserved = 0;
	op_mode->mode = DOT11_OPERATION_MODE_EXTENSIBLE_STATION;
	res = mp_set(wnd, OID_DOT11_CURRENT_OPERATION_MODE,
		     op_mode, sizeof(*op_mode));
	if (res)
		WARNING("setting operation mode failed: %08x", res);
	wnd->phy_types = buf;
	res = mp_query(wnd, OID_DOT11_SUPPORTED_PHY_TYPES, buf, buf_len);
	if (res || wnd->phy_types->num_entries == 0)
		WARNING("query failed: %08X", res);
	else {
		int i, len;
		len = sizeof(*wnd->phy_types) +
			(wnd->phy_types->num_entries - 1) *
			sizeof(wnd->phy_types->phy_types);
		for (i = 0; i < wnd->phy_types->num_entries; i++)
			TRACE2("%d: 0x%x", i, wnd->phy_types->phy_types[i]);
		wnd->phy_types = kmalloc(len, GFP_KERNEL);
		if (!wnd->phy_types)
			WARNING("couldn't allocate memory");
		else
			memcpy(wnd->phy_types, buf, len);
	}
	res = mp_query_int(wnd, OID_DOT11_CURRENT_REG_DOMAIN, buf);
	if (!res)
		TRACE1("regulatory domain: 0x%x", *((ULONG *)buf));

	country_region_list = (typeof(country_region_list))buf;
#if 0
	init_ndis_object_header(country_region_list, NDIS_OBJECT_TYPE_DEFAULT,
				DOT11_COUNTRY_OR_REGION_STRING_LIST_REVISION_1);
	res = mp_query(wnd, OID_DOT11_SUPPORTED_COUNTRY_OR_REGION_STRING,
		       buf, buf_len);
	TRACE2("%08X", res);
	if (!res) {
		int i;
		for (i = 0; i < country_region_list->num_entries; i++) {
			TRACE1("%c%c", country_region_list->entries[i][0],
				  country_region_list->entries[i][1]);
		}
	}
	*((ULONG *)buf) = 0;
	res = mp_query(wnd, OID_DOT11_MULTI_DOMAIN_CAPABILITY_IMPLEMENTED,
		       buf, sizeof(BOOLEAN));
	TRACE2("%08X, %u", res, *((BOOLEAN *)buf));

	res = mp_query(wnd, OID_DOT11_DESIRED_COUNTRY_OR_REGION_STRING,
		       buf, buf_len);
	TRACE2("%08X, %c%c", res, ((char *)buf)[0], ((char *)buf)[1]);
#endif

	res = mp_set_int(wnd, OID_DOT11_POWER_MGMT_REQUEST,
			 DOT11_POWER_SAVING_NO_POWER_SAVING);
	TRACE1("%08X", res);
#if 0
	mp_query_int(wnd, OID_PNP_QUERY_POWER, &status);
	TRACE1("%d", status);
	status = mp_set_int(wnd, OID_PNP_SET_POWER, NdisDeviceStateD0);
	TRACE1("%08X", status);
	status = mp_pnp_event(wnd, NdisDevicePnPEventPowerProfileChanged,
			      NdisPowerProfileAcOnLine);
	if (status != NDIS_STATUS_SUCCESS)
		TRACE1("couldn't set power profile: %08X", status);

	res = mp_set_int(wnd, OID_DOT11_AUTO_CONFIG_ENABLED,
			 DOT11_PHY_AUTO_CONFIG_ENABLED_FLAG |
			 DOT11_MAC_AUTO_CONFIG_ENABLED_FLAG);
	TRACE2("%08X", res);
#endif

	do {
		BOOLEAN b;
		b = TRUE;
		res = mp_set(wnd, OID_DOT11_NIC_POWER_STATE, &b, sizeof(b));
		TRACE1("%08X", res);
		res = mp_query(wnd, OID_DOT11_HARDWARE_PHY_STATE, &b, sizeof(b));
		TRACE1("%d", b);
	} while (0);

	res = mp_query(wnd, OID_DOT11_CURRENT_PHY_ID,
		       &wnd->phy_id, sizeof(wnd->phy_id));
	TRACE2("%08X, %u", res, wnd->phy_id);

//	set_infra_mode(wnd, ndis_dot11_bss_type_infrastructure);
//	set_auth_algo(wnd, DOT11_AUTH_ALGO_80211_OPEN);
//	set_cipher_algo(wnd, DOT11_CIPHER_ALGO_NONE);
	EXIT1(return);
}

wstdcall NTSTATUS NdisDispatchDeviceControl(struct device_object *fdo,
					    struct irp *irp)
{
	struct ndis_device *wnd;

	TRACE3("fdo: %p", fdo);
	/* for now, we don't have anything intresting here, so pass it
	 * down to bus driver */
	wnd = fdo->reserved;
	return IoPassIrpDown(wnd->pdo, irp);
}
WIN_FUNC_DECL(NdisDispatchDeviceControl,2)

wstdcall NTSTATUS NdisDispatchPower(struct device_object *fdo, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct ndis_device *wnd;
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
			ndis_status = mp_set_power_state(wnd, state);
			if (ndis_status != NDIS_STATUS_SUCCESS)
				WARNING("couldn't set power to %d: %08X",
					state, ndis_status);
			TRACE2("%s: device resumed", wnd->net_dev->name);
			irp->io_status.status = status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		} else {
			ndis_status = mp_set_power_state(wnd, state);
			/* TODO: handle error case */
			if (ndis_status != NDIS_STATUS_SUCCESS)
				WARNING("setting power to %d failed: %08X",
					state, ndis_status);
			status = IoAsyncForwardIrp(wnd->pdo, irp);
		}
		break;
	case IRP_MN_QUERY_POWER:
		if (wnd->attribute_flags & NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND) {
			ndis_status = mp_query(wnd, OID_PNP_QUERY_POWER,
					       &state, sizeof(state));
			TRACE2("%d, %08X", state, ndis_status);
			/* this OID must always succeed */
			if (ndis_status != NDIS_STATUS_SUCCESS)
				TRACE1("query power returns %08X",
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
	struct ndis_device *wnd;
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
		mp_halt(wnd);
		irp->io_status.status = STATUS_SUCCESS;
		status = IoAsyncForwardIrp(pdo, irp);
		break;
	case IRP_MN_REMOVE_DEVICE:
		TRACE1("%s", wnd->net_dev->name);
		mp_pnp_event(wnd, NdisDevicePnPEventSurpriseRemoved, 0);
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

static void get_supported_oids(struct ndis_device *wnd)
{
	NDIS_STATUS res;
	int i, n, needed;
	ndis_oid *oids;

	res = mp_query_info(wnd, OID_GEN_SUPPORTED_LIST, NULL, 0,
			    &needed, NULL);
	if (!(res == NDIS_STATUS_BUFFER_TOO_SHORT ||
	      res == NDIS_STATUS_INVALID_LENGTH))
		EXIT1(return);
	oids = kmalloc(needed, GFP_KERNEL);
	if (!oids) {
		TRACE1("couldn't allocate memory");
		EXIT1(return);
	}
	res = mp_query(wnd, OID_GEN_SUPPORTED_LIST, oids, needed);
	if (res) {
		TRACE1("failed: %08X", res);
		kfree(oids);
		EXIT1(return);
	}
	for (i = 0, n = needed / sizeof(*oids); i < n; i++) {
		TRACE1("oid: %08X", oids[i]);
		/* if a wireless device didn't say so for
		 * OID_GEN_PHYSICAL_MEDIUM (they should, but in case) */
		if (wnd->physical_medium != NdisPhysicalMediumWirelessLan &&
		    wnd->physical_medium != NdisPhysicalMediumNative802_11 &&
		    oids[i] == OID_802_11_SSID)
			wnd->physical_medium = NdisPhysicalMediumWirelessLan;
	}
	kfree(oids);
	EXIT1(return);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
static const struct net_device_ops ndis_netdev_ops = {
	.ndo_open = ndis_net_dev_open,
	.ndo_stop = ndis_net_dev_close,
	.ndo_start_xmit = tx_skbuff,
	.ndo_change_mtu = ndis_change_mtu,
	.ndo_set_multicast_list = ndis_set_multicast_list,
//	.ndo_set_mac_address = ndis_set_mac_address,
	.ndo_get_stats = ndis_get_stats,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = ndis_poll_controller,
#endif
};
#endif

static NDIS_STATUS ndis_start_device(struct ndis_device *wnd)
{
	struct wrap_device *wd;
	struct net_device *net_dev;
	NDIS_STATUS res;
	char *buf;
	const int buf_len = 256;
	mac_address mac;
	struct mp_pnp_characteristics *mp_pnp_chars;
	int n;
	struct net_buffer_pool_params nb_pool_params;
	struct net_buffer_list_pool_params nbl_pool_params;
	struct ndis_dot11_extsta_attributes *extsta_attrs;

	mp_pnp_chars = &wnd->wd->driver->ndis_driver->mp_pnp_chars;
	if (mp_pnp_chars->add_device)
		LIN2WIN2(mp_pnp_chars->add_device,
			 wnd->wd->driver->ndis_driver->mp_driver_ctx, NULL);

	res = mp_init(wnd);
	if (res == NDIS_STATUS_NOT_RECOGNIZED)
		EXIT1(return NDIS_STATUS_SUCCESS);
	if (res != NDIS_STATUS_SUCCESS)
		EXIT1(return res);
	wd = wnd->wd;
	net_dev = wnd->net_dev;

	res = mp_query(wnd, OID_802_3_CURRENT_ADDRESS, mac, sizeof(mac));
	if (res) {
		ERROR("couldn't get mac address: %08X", res);
		goto err_start;
	}
	TRACE1("mac:" MACSTRSEP, MAC2STR(mac));
	res = mp_query_int(wnd, OID_GEN_PHYSICAL_MEDIUM, &wnd->physical_medium);
	TRACE1("%d", wnd->physical_medium);
	if (res != NDIS_STATUS_SUCCESS)
		wnd->physical_medium = NdisPhysicalMediumUnspecified;

	get_supported_oids(wnd);

	extsta_attrs = wnd->native_802_11_attrs.extsta_attrs;
	(void)extsta_attrs;
	TRACE2("0x%x, %u, %u, %u, %u : %u, %u, %u, %u, %u : %u, %u, %u, "
		  "%u, %u : %u, 0x%x, %d, %u, %u : %u, %u, %u",
		  wnd->native_802_11_attrs.op_mode_capability,
		  wnd->native_802_11_attrs.num_tx_bufs,
		  wnd->native_802_11_attrs.num_rx_bufs,
		  wnd->native_802_11_attrs.multi_domain_capability_implemented,
		  wnd->native_802_11_attrs.num_supported_phys,

		  extsta_attrs->scan_ssid_size,
		  extsta_attrs->desired_bssid_size,
		  extsta_attrs->desired_ssid_size,
		  extsta_attrs->excluded_mac_size,
		  extsta_attrs->privacy_exemption_size,

		  extsta_attrs->key_mapping_size,
		  extsta_attrs->default_key_size,
		  extsta_attrs->wep_key_max_length,
		  extsta_attrs->pmkid_cache_size,
		  extsta_attrs->max_num_per_sta_default_key_tables,

		  extsta_attrs->strictly_ordered_service_class,
		  extsta_attrs->qos_protocol_flags,
		  extsta_attrs->safe_mode,
		  extsta_attrs->num_country_region_strings,
		  extsta_attrs->num_infra_ucast_algo_pairs,

		  extsta_attrs->num_infra_mcast_algo_pairs,
		  extsta_attrs->num_adhoc_ucast_algo_pairs,
		  extsta_attrs->num_adhoc_mcast_algo_pairs);

//	wnd->physical_medium = NdisPhysicalMediumWirelessLan;

	strncpy(net_dev->name, if_name, IFNAMSIZ - 1);
	net_dev->name[IFNAMSIZ - 1] = '\0';
	memcpy(&net_dev->dev_addr, mac, ETH_ALEN);

	wnd->packet_filter = NDIS_PACKET_TYPE_DIRECTED |
		NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_MULTICAST;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	net_dev->netdev_ops = &ndis_netdev_ops;
#else
	net_dev->open = ndis_net_dev_open;
	net_dev->hard_start_xmit = tx_skbuff;
	net_dev->stop = ndis_net_dev_close;
	net_dev->get_stats = ndis_get_stats;
	net_dev->change_mtu = ndis_change_mtu;
	net_dev->set_multicast_list = ndis_set_multicast_list;
//	net_dev->set_mac_address = ndis_set_mac_address;
#ifdef CONFIG_NET_POLL_CONTROLLER
	net_dev->poll_controller = ndis_poll_controller;
#endif
#endif
	if (wnd->physical_medium == NdisPhysicalMediumWirelessLan ||
	    wnd->physical_medium == NdisPhysicalMediumNative802_11) {
		net_dev->wireless_handlers = &ndis_handler_def;
	}
	net_dev->ethtool_ops = &ndis_ethtool_ops;
	net_dev->irq = wd->pci.pdev->irq;
	net_dev->mem_start = wnd->mem_start;
	net_dev->mem_end = wnd->mem_end;
	res = mp_query_int(wnd, OID_802_3_MAXIMUM_LIST_SIZE,
			   &wnd->multicast_size);
	if (res != NDIS_STATUS_SUCCESS || wnd->multicast_size < 0)
		wnd->multicast_size = 0;
	if (wnd->multicast_size > 0)
		net_dev->flags |= IFF_MULTICAST;
	else
		net_dev->flags &= ~IFF_MULTICAST;
#ifdef NETIF_F_LLTX
	net_dev->features |= NETIF_F_LLTX;
#endif

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		WARNING("couldn't allocate memory");
		goto err_start;
	}

	if (register_netdev(net_dev)) {
		ERROR("cannot register net device %s", net_dev->name);
		goto err_register;
	}
	memcpy(wnd->netdev_name, net_dev->name, sizeof(wnd->netdev_name));
	wnd->tx_ok = 1;
	memset(buf, 0, buf_len);
	res = mp_query(wnd, OID_GEN_VENDOR_DESCRIPTION, buf, buf_len);
	if (res != NDIS_STATUS_SUCCESS) {
		WARNING("couldn't get vendor information: 0x%x", res);
		buf[0] = 0;
	}
	wnd->drv_ndis_version = n = 0;
	mp_query_int(wnd, OID_GEN_DRIVER_VERSION, &wnd->drv_ndis_version);
	mp_query_int(wnd, OID_GEN_VENDOR_DRIVER_VERSION, &n);

	printk(KERN_INFO "%s: ethernet device " MACSTRSEP " using NDIS "
	       "driver: %s, version: 0x%x, NDIS version: 0x%x, vendor: '%s', "
	       "%s\n", net_dev->name, MAC2STR(net_dev->dev_addr),
	       wd->driver->name, n, wnd->drv_ndis_version, buf,
	       wd->conf_file_name);

	/* deserialized drivers don't have a limit, but we
	 * keep max at TX_RING_SIZE */
	wnd->max_tx_packets = TX_RING_SIZE;
	TRACE2("maximum send packets: %d", wnd->max_tx_packets);
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
		NdisAllocateNetBufferListPool(wnd->nmb, &nbl_pool_params);
	if (res != NDIS_STATUS_SUCCESS) {
		ERROR("couldn't allocate buffer pool");
		goto buffer_pool_err;
	}
	TRACE3("%p", wnd->tx_buffer_list_pool);
	memset(&nb_pool_params, 0, sizeof(nb_pool_params));
	nb_pool_params.header.type = NDIS_OBJECT_TYPE_DEFAULT;
	nb_pool_params.header.revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
	nb_pool_params.header.size = sizeof(nb_pool_params);
	nb_pool_params.tag = 0;
	nb_pool_params.data_size = 0;

	wnd->tx_buffer_pool = NdisAllocateNetBufferPool(wnd->nmb,
							&nb_pool_params);
	TRACE1("pool: %p", wnd->tx_buffer_pool);

	if (mp_query_int(wnd, OID_GEN_MAXIMUM_TOTAL_SIZE, &n) ==
	    NDIS_STATUS_SUCCESS && n > ETH_HLEN)
		ndis_change_mtu(wnd->net_dev, n - ETH_HLEN);

	if (mp_query_int(wnd, OID_GEN_MAC_OPTIONS, &n) ==
	    NDIS_STATUS_SUCCESS && n > 0)
		TRACE2("mac options supported: 0x%x", n);

#if 0
	struct transport_header_offset transport_header_offset;
	transport_header_offset.protocol_type = NDIS_PROTOCOL_ID_TCP_IP;
	transport_header_offset.header_offset = sizeof(ETH_HLEN);
	res = mp_set_info(wnd, OID_GEN_TRANSPORT_HEADER_OFFSET,
			  &transport_header_offset,
			  sizeof(transport_header_offset));
	ENTER2("%08X", res);
#endif

	if (wnd->physical_medium == NdisPhysicalMediumWirelessLan ||
	    wnd->physical_medium == NdisPhysicalMediumNative802_11)
		init_dot11_station(wnd, buf, buf_len);

	kfree(buf);
	wrap_procfs_add_ndis_device(wnd);
	hangcheck_add(wnd);
	add_stats_timer(wnd);
	EXIT1(return NDIS_STATUS_SUCCESS);

buffer_pool_err:
	wnd->tx_buffer_pool = NULL;
err_register:
	kfree(buf);
err_start:
	ndis_remove_device(wnd);
	EXIT1(return NDIS_STATUS_FAILURE);
}

static int ndis_remove_device(struct ndis_device *wnd)
{
	/* prevent setting essid during disassociation */
	memset(&wnd->essid, 0, sizeof(wnd->essid));
	if (wnd->physical_medium == NdisPhysicalMediumWirelessLan ||
	    wnd->physical_medium == NdisPhysicalMediumNative802_11) {
		up(&wnd->ndis_comm_mutex);
		mp_set(wnd, OID_802_11_DISASSOCIATE, NULL, 0);
		if (wnd->phy_types)
			kfree(wnd->phy_types);
		if (down_interruptible(&wnd->ndis_comm_mutex))
			WARNING("couldn't obtain ndis_comm_mutex");
	}
	set_bit(SHUTDOWN, &wnd->ndis_pending_work);
	wnd->tx_ok = 0;
	if (wnd->max_tx_packets)
		unregister_netdev(wnd->net_dev);
	netif_carrier_off(wnd->net_dev);
	wrap_procfs_remove_ndis_device(wnd);
	mp_halt(wnd);
	ndis_exit_device(wnd);

	if (wnd->tx_buffer_list)
		free_tx_buffer_list(wnd, wnd->tx_buffer_list);

	if (wnd->tx_buffer_list_pool) {
		NdisFreeNetBufferListPool(wnd->tx_buffer_list_pool);
		wnd->tx_buffer_list_pool = NULL;
	}
	if (wnd->tx_buffer_pool) {
		NdisFreeNetBufferPool(wnd->tx_buffer_pool);
		wnd->tx_buffer_pool = NULL;
	}
	if (wnd->phy_types)
		kfree(wnd->phy_types);
	printk(KERN_INFO "%s: device %s removed\n", DRIVER_NAME,
	       wnd->net_dev->name);
	free_netdev(wnd->net_dev);
	EXIT2(return 0);
}

static wstdcall NTSTATUS NdisAddDevice(struct driver_object *drv_obj,
				       struct device_object *pdo)
{
	struct device_object *fdo;
	NTSTATUS status;
	struct ndis_device *wnd;
	struct ndis_mp_block *nmb;
	struct net_device *net_dev;
	struct wrap_device *wd;
	unsigned long i;

	ENTER2("%p, %p", drv_obj, pdo);
	if (strlen(if_name) >= IFNAMSIZ) {
		ERROR("interface name '%s' is too long", if_name);
		return STATUS_INVALID_PARAMETER;
	}
	net_dev = alloc_etherdev(sizeof(*wnd) + sizeof(*nmb));
	if (!net_dev) {
		ERROR("couldn't allocate device");
		return STATUS_RESOURCES;
	}
	wnd = netdev_priv(net_dev);
	nmb = (struct ndis_mp_block *)(wnd + 1);
	TRACE1("wnd: %p", wnd);
	status = IoCreateDevice(drv_obj, 0, NULL,
				FILE_DEVICE_UNKNOWN, 0, FALSE, &fdo);
	if (status != STATUS_SUCCESS) {
		kfree(wnd->nmb);
		free_netdev(net_dev);
		EXIT2(return status);
	}
	fdo->reserved = wnd;
	wd = pdo->reserved;
	wd->wnd = wnd;
	wnd->wd = wd;
	nmb->wnd = wnd;
	wnd->nmb = nmb;
	wnd->pdo = pdo;
	wnd->fdo = fdo;
	wnd->net_dev = net_dev;
	sema_init(&wnd->ndis_comm_mutex, 1);
	init_waitqueue_head(&wnd->ndis_comm_wq);
	wnd->ndis_comm_done = 0;
	initialize_work(&wnd->tx_work, tx_worker, wnd);
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
	wnd->ndis_pending_work = 0;
	memset(&wnd->essid, 0, sizeof(wnd->essid));
	memset(&wnd->cipher_info, 0, sizeof(wnd->cipher_info));
	wnd->cipher_info.algo = DOT11_CIPHER_ALGO_NONE;
	wnd->auth_algo = DOT11_AUTH_ALGO_80211_OPEN;
	initialize_work(&wnd->ndis_work, ndis_worker, wnd);
	wnd->hw_status = 0;

	wnd->next_device = IoAttachDeviceToDeviceStack(fdo, pdo);
	wnd->stats_enabled = TRUE;
	wnd->wrap_timer_slist.next = NULL;

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

	if (wrap_is_pci_bus(wd->dev_bus))
		SET_NETDEV_DEV(net_dev, &wd->pci.pdev->dev);
	if (wrap_is_usb_bus(wd->dev_bus))
		SET_NETDEV_DEV(net_dev, &wd->usb.intf->dev);

	if (ndis_init_device(wnd)) {
		kfree(wnd->nmb);
		free_netdev(net_dev);
	}
	if (wd->driver->ndis_driver) {
		struct ndis_driver *ndis_driver = wd->driver->ndis_driver;
		TRACE2("%p, %p", ndis_driver,
		       ndis_driver->mp_pnp_chars.add_device);
		if (ndis_driver->mp_pnp_chars.add_device) {
			status = LIN2WIN2(ndis_driver->mp_pnp_chars.add_device,
					  wnd, ndis_driver->mp_driver_ctx);
			if (status != NDIS_STATUS_SUCCESS) {
				WARNING("failed: 0x%x", status);
				kfree(wnd->nmb);
				free_netdev(net_dev);
				return status;
			}
		}
	}
	EXIT2(return NDIS_STATUS_SUCCESS);
}

int init_ndis_driver(struct driver_object *drv_obj)
{
	ENTER1("%p", drv_obj);
	drv_obj->drv_ext->add_device = NdisAddDevice;
	return 0;
}

int wrapndis_init(void)
{
	wrapndis_wq = create_singlethread_workqueue("wrapndis_wq");
	if (!wrapndis_wq)
		EXIT1(return -ENOMEM);
	wrapndis_worker_thread = wrap_worker_init(wrapndis_wq);
	TRACE1("%p", wrapndis_worker_thread);
	register_netdevice_notifier(&netdev_notifier);
	return 0;
}

void wrapndis_exit(void)
{
	unregister_netdevice_notifier(&netdev_notifier);
	if (wrapndis_wq)
		destroy_workqueue(wrapndis_wq);
	TRACE1("%p", wrapndis_worker_thread);
	if (wrapndis_worker_thread)
		ObDereferenceObject(wrapndis_worker_thread);
}
