/*
 * WPA Supplicant - driver interaction with generic Linux Wireless Extensions
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <net/if_arp.h>

#include "wireless_copy.h"
#include "common.h"
#include "driver.h"
#include "l2_packet.h"
#include "eloop.h"
#include "wpa_ndiswrapper.h"
#include "priv_netlink.h"
#include "driver_wext.h"

static int get_socket()
{
	static const int families[] = {
		AF_INET, AF_IPX, AF_AX25, AF_APPLETALK
	};
	unsigned int  i;
	int       sock;
	
	for(i = 0; i < sizeof(families)/sizeof(int); ++i)
	{
		sock = socket(families[i], SOCK_DGRAM, 0);
		if(sock >= 0)
			return sock;
	}
	
	return -1;
}


static inline int
iw_set_ext(int skfd, const char *ifname, int request, struct iwreq *pwrq)
{
  strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
  return(ioctl(skfd, request, pwrq));
}

static inline int
iw_get_ext(int skfd, const char *ifname, int request, struct iwreq *pwrq)
{
	strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
	return ioctl(skfd, request, pwrq);
}

int wpa_ndiswrapper_set_wpa(const char *ifname, int enabled)
{
	struct iwreq priv_req;
	int s;
	int ret;

	printf("%s: called with %s, %d\n", __FUNCTION__, ifname, enabled);
	s = get_socket();
	printf("%s: socket is %d\n", __FUNCTION__, s);
//	if (!enabled && wpa_ndiswrapper_wext_set_wpa_ie(ifname, NULL, 0) < 0)
//		ret = -1;

	priv_req.u.data.flags = enabled;
	if (iw_set_ext(s, ifname, WPA_SET_WPA, &priv_req) < 0)
		ret = -1;
	else
		ret = 0;
	close(s);
	return ret;
}

int wpa_ndiswrapper_set_key(const char *ifname, wpa_alg alg, u8 *addr,
			   int key_idx, int set_tx, u8 *seq, size_t seq_len,
			   u8 *key, size_t key_len)
{
	struct wpa_key wpa_key;
	int s, ret;
	struct iwreq priv_req;

	wpa_key.alg = alg;
	wpa_key.addr = addr;
	wpa_key.key_index = key_idx;
	wpa_key.set_tx = set_tx;
	wpa_key.seq = seq;
	wpa_key.seq_len = seq_len;
	wpa_key.key = key;
	wpa_key.key_len = key_len;

	priv_req.u.data.pointer = (void *)&wpa_key;
	s = get_socket();

	if (iw_set_ext(s, ifname, WPA_SET_KEY, &priv_req) < 0)
		ret = -1;
	else
		ret = 0;
	close(s);
	return ret;
}

int wpa_ndiswrapper_set_countermeasures(const char *ifname, int enabled)
{
	return 0;
}

int wpa_ndiswrapper_set_drop_unencrypted(const char *ifname, int enabled)
{
	return 0;
}

int wpa_ndiswrapper_deauthenticate(const char *ifname, u8 *addr,
				   int reason_code)
{
	return 0;
}

int wpa_ndiswrapper_disassociate(const char *ifname, u8 *addr,
				 int reason_code)
{
	int s = get_socket();
	int ret;
	struct iwreq priv_req;

	memcpy(&priv_req.u.ap_addr, addr, ETH_ALEN);
	if (iw_set_ext(s, ifname, WPA_DISASSOCIATE, &priv_req) < 0)
		ret = -1;
	else
		ret = 0;

	close(s);
	return ret;
}

int wpa_ndiswrapper_associate(const char *ifname, const char *bssid,
			      const char *ssid, size_t ssid_len, int freq,
			      const char *wpa_ie, size_t wpa_ie_len,
			      wpa_cipher pairwise_suite,
			      wpa_cipher group_suite,
			      wpa_key_mgmt key_mgmt_suite)
{
	int s = get_socket();
	int ret;
	struct iwreq priv_req;

	priv_req.u.essid.length = ssid_len;
	priv_req.u.essid.pointer = (void *)ssid;
	memcpy(&priv_req.u.ap_addr, bssid, ETH_ALEN);
	priv_req.u.freq.e = 1;
	priv_req.u.freq.m = freq;
	if (iw_set_ext(s, ifname, WPA_ASSOCIATE, &priv_req) < 0)
		ret = -1;
	else
		ret = 0;

	close(s);
	return ret;
}

void wpa_ndiswrapper_cleanup(const char *ifname)
{
	return;
}

struct wpa_driver_ops wpa_driver_ndiswrapper_ops = {
	.set_wpa = wpa_ndiswrapper_set_wpa,
	.set_key = wpa_ndiswrapper_set_key,
	.set_countermeasures = wpa_ndiswrapper_set_countermeasures,
	.set_drop_unencrypted = wpa_ndiswrapper_set_drop_unencrypted,
	.deauthenticate = wpa_ndiswrapper_deauthenticate,
	.disassociate = wpa_ndiswrapper_disassociate,
	.associate = wpa_ndiswrapper_associate,
	.cleanup = wpa_ndiswrapper_cleanup,

	.get_bssid = wpa_driver_wext_get_bssid,
	.get_ssid = wpa_driver_wext_get_ssid,
	.events_init = wpa_driver_wext_events_init,
	.events_deinit = wpa_driver_wext_events_deinit,
	.scan = wpa_driver_wext_scan,
	.get_scan_results = wpa_driver_wext_get_scan_results,
};
