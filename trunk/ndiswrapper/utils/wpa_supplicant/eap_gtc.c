/*
 * WPA Supplicant / EAP-GTC (RFC 2284)
 * Copyright (c) 2004, Jouni Malinen <jkmaline@cc.hut.fi>
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
#include <netinet/in.h>
#include <string.h>

#include "common.h"
#include "eapol_sm.h"
#include "eap.h"
#include "wpa_supplicant.h"
#include "config.h"


static void * eap_gtc_init(struct eap_sm *sm)
{
	return (void *) 1;
}


static void eap_gtc_deinit(struct eap_sm *sm, void *priv)
{
}


static u8 * eap_gtc_process(struct eap_sm *sm, void *priv,
			    u8 *reqData, size_t reqDataLen,
			    size_t *respDataLen)
{
	struct wpa_ssid *config = sm->eapol->config;
	struct eap_hdr *req, *resp;
	u8 *pos;

	if (config == NULL || config->password == NULL) {
		wpa_printf(MSG_INFO, "EAP-GTC: Password not configured");
		eap_sm_request_password(sm, config);
		sm->ignore = TRUE;
		return NULL;
	}

	req = (struct eap_hdr *) reqData;
	pos = (u8 *) (req + 1);
	if (reqDataLen < sizeof(*req) + 1 || *pos != EAP_TYPE_GTC) {
		wpa_printf(MSG_INFO, "EAP-GTC: Invalid frame");
		sm->ignore = TRUE;
		return NULL;
	}
	pos++;
	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-GTC: Request message",
			  pos, reqDataLen - sizeof(*req) - 1);
	sm->ignore = FALSE;

	sm->methodState = METHOD_DONE;
	sm->decision = DECISION_UNCOND_SUCC;
	sm->allowNotifications = TRUE;

	*respDataLen = sizeof(struct eap_hdr) + 1 + config->password_len;
	resp = malloc(*respDataLen);
	if (resp == NULL)
		return NULL;
	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = req->identifier;
	resp->length = htons(*respDataLen);
	pos = (u8 *) (resp + 1);
	*pos++ = EAP_TYPE_GTC;
	memcpy(pos, config->password, config->password_len);
	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-GTC: Response",
			  config->password, config->password_len);

	/* EAP-GTC does not generate keying data, so eapKeyData is never filled
	 * here */

	return (u8 *) resp;
}


const struct eap_method eap_method_gtc =
{
	.method = EAP_TYPE_GTC,
	.init = eap_gtc_init,
	.deinit = eap_gtc_deinit,
	.process = eap_gtc_process,
};
