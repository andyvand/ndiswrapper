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

int wpa_ndiswrapper_wext_get_bssid(const char *ifname, char *bssid)
{
	struct iwreq iwr;
	int s, ret = 0;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(s, SIOCGIWAP, &iwr) < 0) {
		perror("ioctl[SIOCGIWAP]");
		ret = -1;
	}
	memcpy(bssid, iwr.u.ap_addr.sa_data, ETH_ALEN);

	close(s);
	return ret;
}


int wpa_ndiswrapper_wext_set_bssid(const char *ifname, const char *bssid)
{
	struct iwreq iwr;
	int s, ret = 0;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.ap_addr.sa_family = ARPHRD_ETHER;
	memcpy(iwr.u.ap_addr.sa_data, bssid, ETH_ALEN);

	if (ioctl(s, SIOCSIWAP, &iwr) < 0) {
		perror("ioctl[SIOCSIWAP]");
		ret = -1;
	}

	close(s);
	return ret;
}


int wpa_ndiswrapper_wext_get_ssid(const char *ifname, char *ssid)
{
	struct iwreq iwr;
	int s, ret = 0;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.essid.pointer = (caddr_t) ssid;
	iwr.u.essid.length = 32;

	if (ioctl(s, SIOCGIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCGIWESSID]");
		ret = -1;
	} else
		ret = iwr.u.essid.length;

	close(s);
	return ret;
}


int wpa_ndiswrapper_wext_set_ssid(const char *ifname, const char *ssid,
				  size_t ssid_len)
{
	struct iwreq iwr;
	int s, ret = 0;
	char buf[33];

	if (ssid_len > 32)
		return -1;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.essid.flags = 1;
	memset(buf, 0, sizeof(buf));
	memcpy(buf, ssid, ssid_len);
	iwr.u.essid.pointer = (caddr_t) buf;
	iwr.u.essid.length = ssid_len;

	if (ioctl(s, SIOCSIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCSIWESSID]");
		ret = -1;
	}

	close(s);
	return ret;
}


int wpa_ndiswrapper_wext_set_freq(const char *ifname, int freq)
{
	struct iwreq iwr;
	int s, ret = 0;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.freq.m = freq * 100000;
	iwr.u.freq.e = 1;

	if (ioctl(s, SIOCSIWFREQ, &iwr) < 0) {
		perror("ioctl[SIOCSIWFREQ]");
		ret = -1;
	}

	close(s);
	return ret;
}


static void wpa_ndiswrapper_wext_event_wireless_custom(void *ctx, char *custom)
{
	union wpa_event_data data;

	wpa_printf(MSG_DEBUG, "Custom wireless event: '%s'", custom);

	memset(&data, 0, sizeof(data));
	/* Host AP driver */
	if (strncmp(custom, "MLME-MICHAELMICFAILURE.indication", 33) == 0) {
		data.michael_mic_failure.unicast =
			strstr(custom, " unicast ") != NULL;
		/* TODO: parse parameters(?) */
		wpa_supplicant_event(ctx, EVENT_MICHAEL_MIC_FAILURE, &data);
	} else if (strncmp(custom, "ASSOCINFO(ReqIEs=", 17) == 0) {
		char *spos;
		int bytes;

		spos = custom + 17;

		bytes = strspn(spos, "0123456789abcdefABCDEF");
		if (!bytes || (bytes & 1))
			return;
		bytes /= 2;

		data.assoc_info.req_ies = malloc(bytes);
		if (data.assoc_info.req_ies == NULL)
			return;

		data.assoc_info.req_ies_len = bytes;
		hexstr2bin(spos, data.assoc_info.req_ies, bytes);

		spos += bytes * 2;

		data.assoc_info.resp_ies = NULL;
		data.assoc_info.resp_ies_len = 0;

		if (strncmp(spos, " RespIEs=", 9) == 0) {
			spos += 9;

			bytes = strspn(spos, "0123456789abcdefABCDEF");
			if (!bytes || (bytes & 1))
				goto done;
			bytes /= 2;

			data.assoc_info.resp_ies = malloc(bytes);
			if (data.assoc_info.resp_ies == NULL)
				goto done;

			data.assoc_info.resp_ies_len = bytes;
			hexstr2bin(spos, data.assoc_info.resp_ies, bytes);
		}

		wpa_supplicant_event(ctx, EVENT_ASSOCINFO, &data);

	done:
		free(data.assoc_info.resp_ies);
		free(data.assoc_info.req_ies);
	}
}


static void wpa_ndiswrapper_wext_event_wireless(void *ctx, char *data, int len)
{
	struct iw_event *iwe;
	char *pos, *end, *custom, *buf;

	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		iwe = (struct iw_event *) pos;
		wpa_printf(MSG_DEBUG, "Wireless event: cmd=0x%x len=%d",
			   iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;
		switch (iwe->cmd) {
		case SIOCGIWAP:
			wpa_printf(MSG_DEBUG, "Wireless event: new AP: "
				   MACSTR,
				   MAC2STR((u8 *) iwe->u.ap_addr.sa_data));
			if (memcmp(iwe->u.ap_addr.sa_data,
				   "\x00\x00\x00\x00\x00\x00", ETH_ALEN) == 0
			    ||
			    memcmp(iwe->u.ap_addr.sa_data,
				   "\x44\x44\x44\x44\x44\x44", ETH_ALEN) == 0)
				wpa_supplicant_event(ctx, EVENT_DISASSOC,
						     NULL);
			else
				wpa_supplicant_event(ctx, EVENT_ASSOC, NULL);
			break;
		case IWEVCUSTOM:
			custom = pos + IW_EV_POINT_LEN;
			if (custom + iwe->u.data.length > end)
				return;
			buf = malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;
			memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';
			wpa_ndiswrapper_wext_event_wireless_custom(ctx, buf);
			free(buf);
			break;
		case SIOCGIWSCAN:
			eloop_cancel_timeout(wpa_ndiswrapper_wext_scan_timeout,
					     NULL, ctx);
			wpa_supplicant_event(ctx, EVENT_SCAN_RESULTS, NULL);
			break;
		}

		pos += iwe->len;
	}
}


static void wpa_ndiswrapper_wext_event_rtm_newlink(void *ctx,
						   struct nlmsghdr *h, int len)
{
	struct ifinfomsg *ifi;
	int attrlen, nlmsg_len, rta_len;
	struct rtattr * attr;

	if (len < sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);

	/* TODO: use ifi->ifi_index to recognize the interface (?) */

	nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - nlmsg_len;
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			wpa_ndiswrapper_wext_event_wireless(
				ctx,((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}


static void wpa_ndiswrapper_wext_event_receive(int sock, void *eloop_ctx,
					       void *sock_ctx)
{
	char buf[8192];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;

	fromlen = sizeof(from);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *) &from, &fromlen);
	if (left < 0) {
		if (errno != EINTR && errno != EAGAIN)
			perror("recvfrom(netlink)");
		return;
	}

	h = (struct nlmsghdr *) buf;
	while (left >= sizeof(*h)) {
		int len, plen;

		len = h->nlmsg_len;
		plen = len - sizeof(*h);
		if (len > left || plen < 0) {
			wpa_printf(MSG_DEBUG, "Malformed netlink message: "
				   "len=%d left=%d plen=%d",
				   len, left, plen);
			break;
		}

		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
			wpa_ndiswrapper_wext_event_rtm_newlink(eloop_ctx, h, plen);
			break;
		}

		len = NLMSG_ALIGN(len);
		left -= len;
		h = (struct nlmsghdr *) ((char *) h + len);
	}

	if (left > 0) {
		wpa_printf(MSG_DEBUG, "%d extra bytes in the end of netlink "
			   "message", left);
	}
}


struct wpa_ndiswrapper_wext_events_data {
	int sock;
};


void * wpa_ndiswrapper_wext_events_init(void *ctx)
{
	int s;
	struct sockaddr_nl local;
	struct wpa_ndiswrapper_wext_events_data *data;

	data = malloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	memset(data, 0, sizeof(*data));

	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		perror("socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)");
		free(data);
		return NULL;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("bind(netlink)");
		close(s);
		free(data);
		return NULL;
	}

	eloop_register_read_sock(s, wpa_ndiswrapper_wext_event_receive, ctx, NULL);
	data->sock = s;

	return data;
}


int wpa_ndiswrapper_wext_events_deinit(void *ctx, void *priv)
{
	struct wpa_ndiswrapper_wext_events_data *data = priv;
	close(data->sock);
	free(data);
	return 0;
}


int wpa_ndiswrapper_hostap_set_countermeasures(const char *ifname, int enabled)
{
	return 0;
}

int wpa_ndiswrapper_hostap_set_drop_unencrypted(const char *ifname, int enabled)
{
	return 0;
}

void wpa_ndiswrapper_wext_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	wpa_printf(MSG_DEBUG, "Scan timeout - try to get results");
	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
}


int wpa_ndiswrapper_wext_scan(const char *ifname, void *ctx, u8 *ssid,
			      size_t ssid_len)
{
	struct iwreq iwr;
	int s, ret = 0;

	if (ssid)
		return -1;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(s, SIOCSIWSCAN, &iwr) < 0) {
		perror("ioctl[SIOCSIWSCAN]");
		ret = -1;
	}

	close(s);

	/* Not all drivers generate "scan completed" wireless event, so try to
	 * read results after a timeout. */
	eloop_register_timeout(3, 0, wpa_ndiswrapper_wext_scan_timeout, NULL, ctx);

	return ret;
}


int wpa_ndiswrapper_wext_get_scan_results(const char *ifname,
					  struct wpa_scan_result *results,
					  size_t max_size)
{
	struct iwreq iwr;
	int s, ap_num = 0, first;
	u8 res_buf[IW_SCAN_MAX_DATA];
	struct iw_event *iwe;
	char *pos, *end, *custom;
	size_t len, clen;

	memset(results, 0, max_size * sizeof(struct wpa_scan_result));
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.data.pointer = res_buf;
	iwr.u.data.length = IW_SCAN_MAX_DATA;

	if (ioctl(s, SIOCGIWSCAN, &iwr) < 0) {
		perror("ioctl[SIOCGIWSCAN]");
		close(s);
		return -1;
	}

	len = iwr.u.data.length;
	ap_num = 0;
	first = 1;

	pos = res_buf;
	end = res_buf + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		int ssid_len;

		iwe = (struct iw_event *) pos;
		if (iwe->len <= IW_EV_LCP_LEN)
			break;
		switch (iwe->cmd) {
		case SIOCGIWAP:
			if (!first)
				ap_num++;
			first = 0;
			if (ap_num < max_size) {
				memcpy(results[ap_num].bssid,
				       iwe->u.ap_addr.sa_data, ETH_ALEN);
			}
			break;
		case SIOCGIWESSID:
			ssid_len = iwe->u.essid.length;
			custom = pos + IW_EV_POINT_LEN;
			if (custom + ssid_len > end)
				break;
			if (iwe->u.essid.flags &&
			    ssid_len > 0 &&
			    ssid_len <= IW_ESSID_MAX_SIZE) {
				if (ap_num < max_size) {
					memcpy(results[ap_num].ssid, custom,
					       ssid_len);
					results[ap_num].ssid_len = ssid_len;
				}
			}
			break;
		case SIOCGIWFREQ:
			if (ap_num < max_size) {
				int div = 1000000, i;
				if (iwe->u.freq.e > 6) {
					wpa_printf(
						MSG_DEBUG, "Invalid freq "
						"in scan results (BSSID="
						MACSTR ": m=%d e=%d\n",
						MAC2STR(results[ap_num].bssid),
						iwe->u.freq.m, iwe->u.freq.e);
					break;
				}
				for (i = 0; i < iwe->u.freq.e; i++)
					div /= 10;
				results[ap_num].freq = iwe->u.freq.m / div;
			}
			break;
		case IWEVCUSTOM:
			custom = pos + IW_EV_POINT_LEN;
			clen = iwe->u.data.length;
			if (custom + clen > end)
				break;
			if (clen > 7 && strncmp(custom, "wpa_ie=", 7) == 0 &&
			    ap_num < max_size) {
				char *spos;
				int bytes;
				spos = custom + 7;
				bytes = custom + clen - spos;
				if (bytes & 1)
					break;
				bytes /= 2;
				if (bytes > SSID_MAX_WPA_IE_LEN) {
					wpa_printf(MSG_INFO, "Too long WPA IE "
						   "(%d)", bytes);
					break;
				}
				hexstr2bin(spos, results[ap_num].wpa_ie,
					   bytes);
				results[ap_num].wpa_ie_len = bytes;
			} else if (clen > 7 &&
				   strncmp(custom, "rsn_ie=", 7) == 0 &&
				   ap_num < max_size) {
				char *spos;
				int bytes;
				spos = custom + 7;
				bytes = custom + clen - spos;
				if (bytes & 1)
					break;
				bytes /= 2;
				if (bytes > SSID_MAX_WPA_IE_LEN) {
					wpa_printf(MSG_INFO, "Too long RSN IE "
						   "(%d)", bytes);
					break;
				}
				hexstr2bin(spos, results[ap_num].rsn_ie,
					   bytes);
				results[ap_num].rsn_ie_len = bytes;
			}
			break;
		}

		pos += iwe->len;
	}

	wpa_printf(MSG_DEBUG, "Received %d bytes of scan results (%d BSSes)",
		   len, first ? 0 : ap_num + 1);

	close(s);
	return first ? 0 : ap_num + 1;
}

int wp_driver_wext_set_key(const char *ifname, wpa_alg alg, u8 *addr,
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

int wpa_ndiswrapper_wext_deauthenticate(const char *ifname, u8 *addr,
					int reason_code)
{
	return 0;
}

int wpa_ndiswrapper_wext_disassociate(const char *ifname, u8 *addr,
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

int wpa_ndiswrapper_wext_associate(const char *ifname, const char *bssid,
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

int wpa_ndiswrapper_wext_set_wpa(const char *ifname, int enabled)
{
	struct iwreq priv_req;
	int s;
	int ret;

	printf("%s: called with %s, %d\n", __FUNCTION__, ifname, enabled);
	s = get_socket();
	printf("%s: socket is %d\n", __FUNCTION__, s);
	priv_req.u.data.flags = enabled;
	if (iw_set_ext(s, ifname, WPA_SET_WPA, &priv_req) < 0)
		ret = -1;
	else
		ret = 0;
	close(s);
	return ret;
}

int wpa_ndiswrapper_wext_set_key(const char *ifname, wpa_alg alg, u8 *addr,
				 int key_idx, int set_tx, u8 *seq,
				 size_t seq_len, u8 *key, size_t key_len)
{
	struct wpa_key wpa_key;
	struct iwreq priv_req;
	int s = get_socket();
	int ret;

	wpa_key.alg = alg;
	wpa_key.addr = addr;
	wpa_key.key_index = key_idx;
	wpa_key.set_tx = set_tx;
	wpa_key.seq = seq;
	wpa_key.seq_len = seq_len;
	wpa_key.key = key;
	wpa_key.key_len = key_len;
	
	priv_req.u.data.pointer = (void *)&wpa_key;
	if (iw_set_ext(s, ifname, WPA_SET_KEY, &priv_req) < 0)
		ret = -1;
	else
		ret = 0;

	close(s);
	return ret;
}

void wpa_ndiswrapper_wext_cleanup(const char *ifname)
{
	return;
}

struct wpa_driver_ops wpa_ndiswrapper_ops = {
    .get_bssid = wpa_ndiswrapper_wext_get_bssid,
    .get_ssid = wpa_ndiswrapper_wext_get_ssid,
    .set_wpa = wpa_ndiswrapper_wext_set_wpa,
    .set_key = wpa_ndiswrapper_wext_set_key,
    .events_init = wpa_ndiswrapper_wext_events_init,
    .events_deinit = wpa_ndiswrapper_wext_events_deinit,
    .set_countermeasures = wpa_ndiswrapper_hostap_set_countermeasures,
    .set_drop_unencrypted = wpa_ndiswrapper_hostap_set_drop_unencrypted,
    .scan = wpa_ndiswrapper_wext_scan,
    .get_scan_results = wpa_ndiswrapper_wext_get_scan_results,
    .deauthenticate = wpa_ndiswrapper_wext_deauthenticate,
    .disassociate = wpa_ndiswrapper_wext_disassociate,
    .associate = wpa_ndiswrapper_wext_associate,
    .cleanup = wpa_ndiswrapper_wext_cleanup,
};
