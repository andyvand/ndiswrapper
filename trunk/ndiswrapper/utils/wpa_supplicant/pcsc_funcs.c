/*
 * WPA Supplicant / PC/SC smartcard interface for USIM, GSM SIM
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
#include <string.h>
#include <winscard.h>

#include "common.h"
#include "wpa_supplicant.h"
#include "pcsc_funcs.h"


/* See ETSI GSM 11.11 and ETSI TS 102 221 for details.
 * SIM commands:
 * Command APDU: CLA INS P1 P2 P3 Data
 *   CLA (class of instruction): A0 for GSM, 00 for USIM
 *   INS (instruction)
 *   P1 P2 P3 (parameters, P3 = length of Data)
 * Response APDU: Data SW1 SW2
 *   SW1 SW2 (Status words)
 * Commands (INS P1 P2 P3):
 *   SELECT: A4 00 00 02 <file_id, 2 bytes>
 *   GET RESPONSE: C0 00 00 <len>
 *   RUN GSM ALG: 88 00 00 00 <RAND len = 10>
 *   READ BINARY: B0 <offset high> <offset low> <len>
 *   VERIFY CHV: 20 00 <CHV number> 08
 *   CHANGE CHV: 24 00 <CHV number> 10
 *   DISABLE CHV: 26 00 01 08
 *   ENABLE CHV: 28 00 01 08
 *   UNBLOCK CHV: 2C 00 <00=CHV1, 02=CHV2> 10
 *   SLEEP: FA 00 00 00
 */

/* GSM SIM commands */
#define SIM_CMD_SELECT			0xa0, 0xa4, 0x00, 0x00, 0x02
#define SIM_CMD_RUN_GSM_ALG		0xa0, 0x88, 0x00, 0x00, 0x10
#define SIM_CMD_GET_RESPONSE		0xa0, 0xc0, 0x00, 0x00
#define SIM_CMD_READ_BIN		0xa0, 0xb0, 0x00, 0x00
#define SIM_CMD_VERIFY_CHV1		0xa0, 0x20, 0x00, 0x01, 0x08

/* USIM commands */
#define USIM_CMD_SELECT			0x00, 0xa4, 0x00, 0x04, 0x02


typedef enum { SCARD_GSM_SIM, SCARD_USIM } sim_types;

struct scard_data {
	long ctx;
	long card;
	unsigned long protocol;
	SCARD_IO_REQUEST recv_pci;
	sim_types sim_type;
};


static int _scard_select_file(struct scard_data *scard, unsigned short file_id,
			      unsigned char *buf, size_t *buf_len,
			      sim_types sim_type);


struct scard_data * scard_init(scard_sim_type sim_type)
{
	long ret, len;
	struct scard_data *scard;
	char *readers = NULL;
	char buf[100];
	size_t blen;

	wpa_printf(MSG_DEBUG, "SCARD: initializing smart card interface");
	scard = malloc(sizeof(*scard));
	if (scard == NULL)
		return NULL;
	memset(scard, 0, sizeof(*scard));

	ret = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
				    &scard->ctx);
	if (ret != SCARD_S_SUCCESS) {
		wpa_printf(MSG_DEBUG, "SCARD: Could not establish smart card "
			   "context (err=%ld)", ret);
		goto failed;
	}

	ret = SCardListReaders(scard->ctx, NULL, NULL, &len);
	if (ret != SCARD_S_SUCCESS) {
		wpa_printf(MSG_DEBUG, "SCARD: SCardListReaders failed "
			   "(err=%ld)", ret);
		goto failed;
	}

	readers = malloc(len);
	if (readers == NULL) {
		printf("malloc failed\n");
		goto failed;
	}

	ret = SCardListReaders(scard->ctx, NULL, readers, &len);
	if (ret != SCARD_S_SUCCESS) {
		wpa_printf(MSG_DEBUG, "SCARD: SCardListReaders failed(2) "
			   "(err=%ld)", ret);
		goto failed;
	}
	if (len < 3) {
		wpa_printf(MSG_WARNING, "SCARD: No smart card readers "
			   "available.");
		goto failed;
	}
	/* readers is a list of available reader. Last entry is terminated with
	 * double NUL.
	 * TODO: add support for selecting the reader; now just use the first
	 * one.. */
	wpa_printf(MSG_DEBUG, "SCARD: Selected reader='%s'", readers);

	ret = SCardConnect(scard->ctx, readers, SCARD_SHARE_SHARED,
			   SCARD_PROTOCOL_T0, &scard->card, &scard->protocol);
	if (ret != SCARD_S_SUCCESS) {
		if (ret == SCARD_E_NO_SMARTCARD)
			wpa_printf(MSG_INFO, "No smart card inserted.");
		else
			wpa_printf(MSG_WARNING, "SCardConnect err=%lx", ret);
		goto failed;
	}

	free(readers);
	readers = NULL;

	wpa_printf(MSG_DEBUG, "SCARD: card=%ld active_protocol=%lu",
		   scard->card, scard->protocol);

	wpa_printf(MSG_DEBUG, "SCARD: verifying USIM support");
	blen = sizeof(buf);

	scard->sim_type = SCARD_GSM_SIM;
	if ((sim_type == SCARD_USIM_ONLY || sim_type == SCARD_TRY_BOTH) &&
	    _scard_select_file(scard, SCARD_FILE_MF, buf, &blen, SCARD_USIM)) {
		wpa_printf(MSG_DEBUG, "SCARD: USIM is not supported");
		if (sim_type == SCARD_USIM_ONLY)
			goto failed;
		wpa_printf(MSG_DEBUG, "SCARD: Trying to use GSM SIM");
		scard->sim_type = SCARD_GSM_SIM;
	} else {
		wpa_printf(MSG_DEBUG, "SCARD: USIM is supported");
		scard->sim_type = SCARD_USIM;
	}

	/* TODO: add support for USIM */
	if (scard->sim_type == SCARD_USIM) {
		wpa_printf(MSG_DEBUG, "SCARD: USIM support not yet complete - "
			   "reverting to GSM SIM");
		scard->sim_type = SCARD_GSM_SIM;
		/* Some cards require re-initialization when changing
		 * application class. */
		ret = SCardReconnect(scard->card, SCARD_SHARE_SHARED,
			   SCARD_PROTOCOL_T0, 1, &scard->protocol);
		if (ret != SCARD_S_SUCCESS) {
			wpa_printf(MSG_WARNING, "SCardReconnect err=%lx", ret);
			goto failed;
		}
	}

	blen = sizeof(buf);
	if (scard_select_file(scard, SCARD_FILE_MF, buf, &blen)) {
		wpa_printf(MSG_DEBUG, "SCARD: Failed to read MF");
		goto failed;
	}

	return scard;

failed:
	free(readers);
	scard_deinit(scard);
	return NULL;
}


void scard_deinit(struct scard_data *scard)
{
	long ret;

	if (scard == NULL)
		return;

	wpa_printf(MSG_DEBUG, "SCARD: deinitializing smart card interface");
	if (scard->card) {
		ret = SCardDisconnect(scard->card, SCARD_UNPOWER_CARD);
		if (ret != SCARD_S_SUCCESS) {
			wpa_printf(MSG_DEBUG, "SCARD: Failed to disconnect "
				   "smart card (err=%ld)", ret);
		}
	}

	if (scard->ctx) {
		ret = SCardReleaseContext(scard->ctx);
		if (ret != SCARD_S_SUCCESS) {
			wpa_printf(MSG_DEBUG, "Failed to release smart card "
				   "context (err=%ld)", ret);
		}
	}
	free(scard);
}


static long scard_transmit(struct scard_data *scard,
			   unsigned char *send, size_t send_len,
			   unsigned char *recv, size_t *recv_len)
{
	long ret;
	unsigned long rlen;

	wpa_hexdump(MSG_DEBUG, "SCARD: scard_transmit: send", send, send_len);
	rlen = *recv_len;
	ret = SCardTransmit(scard->card,
			    scard->protocol == SCARD_PROTOCOL_T1 ?
			    SCARD_PCI_T1 : SCARD_PCI_T0,
			    send, (unsigned long) send_len,
			    &scard->recv_pci, recv, &rlen);
	*recv_len = rlen;
	if (ret == SCARD_S_SUCCESS) {
		wpa_hexdump(MSG_DEBUG, "SCARD: scard_transmit: recv",
			    recv, rlen);
	} else {
		wpa_printf(MSG_WARNING, "SCARD: SCardTransmit failed "
			   "(err=0x%lx)", ret);
	}
	return ret;
}


static int _scard_select_file(struct scard_data *scard, unsigned short file_id,
			      unsigned char *buf, size_t *buf_len,
			      sim_types sim_type)
{
	long ret;
	unsigned char resp[3];
	unsigned char cmd[7] = { SIM_CMD_SELECT };
	unsigned char get_resp[5] = { SIM_CMD_GET_RESPONSE };
	size_t len, rlen;

	if (sim_type == SCARD_USIM) {
		unsigned char ucmd[7] = { USIM_CMD_SELECT };
		memcpy(cmd, ucmd, sizeof(cmd));
	}

	wpa_printf(MSG_DEBUG, "SCARD: select file %04x", file_id);
	cmd[5] = file_id >> 8;
	cmd[6] = file_id & 0xff;
	len = sizeof(resp);
	ret = scard_transmit(scard, cmd, sizeof(cmd), resp, &len);
	if (ret != SCARD_S_SUCCESS) {
		wpa_printf(MSG_WARNING, "SCARD: SCardTransmit failed "
			   "(err=0x%lx)", ret);
		return -1;
	}

	if (len != 2) {
		wpa_printf(MSG_WARNING, "SCARD: unexpected resp len "
			   "%d (expected 2)", (int) len);
		return -1;
	}

	if (resp[0] == 0x98 && resp[1] == 0x04) {
		/* Security status not satisfied (PIN_WLAN) */
		wpa_printf(MSG_WARNING, "SCARD: Security status not satisfied "
			   "(PIN_WLAN)");
		return -1;
	}

	if (resp[0] == 0x6e) {
		wpa_printf(MSG_DEBUG, "SCARD: used CLA not supported");
		return -1;
	}

	if (resp[0] != 0x6c && resp[0] != 0x9f && resp[0] != 0x61) {
		wpa_printf(MSG_WARNING, "SCARD: unexpected response 0x%02x "
			   "(expected 0x61, 0x6c, or 0x9f)", resp[0]);
		return -1;
	}
	/* Normal ending of command; resp[1] bytes available */
	get_resp[4] = resp[1];
	wpa_printf(MSG_DEBUG, "SCARD: trying to get response (%d bytes)",
		   resp[1]);

	rlen = *buf_len;
	ret = scard_transmit(scard, get_resp, sizeof(get_resp), buf, &rlen);
	if (ret == SCARD_S_SUCCESS) {
		wpa_hexdump(MSG_DEBUG, "SCARD: scard_io: recv", buf, rlen);
		*buf_len = resp[1] < rlen ? resp[1] : rlen;
		return 0;
	}

	wpa_printf(MSG_WARNING, "SCARD: SCardTransmit err=0x%lx\n", ret);
	return -1;
}


int scard_select_file(struct scard_data *scard, unsigned short file_id,
		      unsigned char *buf, size_t *buf_len)
{
	return _scard_select_file(scard, file_id, buf, buf_len,
				  scard->sim_type);
}


static int scard_read_file(struct scard_data *scard,
			   unsigned char *data, size_t len)
{
	char cmd[5] = { SIM_CMD_READ_BIN, len };
	size_t blen = len + 3;
	unsigned char *buf;
	long ret;

	buf = malloc(blen);
	if (buf == NULL)
		return -1;

	ret = scard_transmit(scard, cmd, sizeof(cmd), buf, &blen);
	if (ret != SCARD_S_SUCCESS) {
		free(buf);
		return -2;
	}
	if (blen != len + 2) {
		wpa_printf(MSG_DEBUG, "SCARD: file read returned unexpected "
			   "length %d (expected %d)", blen, len + 2);
		free(buf);
		return -3;
	}

	if (buf[len] != 0x90 || buf[len + 1] != 0x00) {
		wpa_printf(MSG_DEBUG, "SCARD: file read returned unexpected "
			   "status %02x %02x (expected 90 00)",
			   buf[len], buf[len + 1]);
		free(buf);
		return -4;
	}

	memcpy(data, buf, len);
	free(buf);

	return 0;
}


int scard_verify_pin(struct scard_data *scard, char *pin)
{
	long ret;
	unsigned char resp[3];
	char cmd[5 + 8] = { SIM_CMD_VERIFY_CHV1 };
	size_t len;

	wpa_printf(MSG_DEBUG, "SCARD: verifying PIN");

	if (pin == NULL || strlen(pin) > 8)
		return -1;

	memcpy(cmd + 5, pin, strlen(pin));
	memset(cmd + 5 + strlen(pin), 0xff, 8 - strlen(pin));

	ret = scard_transmit(scard, cmd, sizeof(cmd), resp, &len);
	if (ret != SCARD_S_SUCCESS)
		return -2;

	if (len != 2 || resp[0] != 0x90 || resp[1] != 0x00) {
		wpa_printf(MSG_WARNING, "SCARD: PIN verification failed");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "SCARD: PIN verified successfully");
	return 0;
}


int scard_get_imsi(struct scard_data *scard, char *imsi, size_t *len)
{
	char buf[100];
	size_t blen, imsilen;
	char *pos;
	int i;

	wpa_printf(MSG_DEBUG, "SCARD: reading IMSI from (GSM) EF-IMSI");
	blen = sizeof(buf);
	if (scard_select_file(scard, SCARD_FILE_GSM_EF_IMSI, buf, &blen))
		return -1;
	if (blen < 4) {
		wpa_printf(MSG_WARNING, "SCARD: too short (GSM) EF-IMSI "
			   "header (len=%d)", blen);
		return -2;
	}

	blen = (buf[2] << 8) | buf[3];
	if (blen < 2 || blen > sizeof(buf)) {
		wpa_printf(MSG_DEBUG, "SCARD: invalid IMSI file length=%d",
			   blen);
		return -3;
	}

	imsilen = (blen - 2) * 2 + 1;
	wpa_printf(MSG_DEBUG, "SCARD: IMSI file length=%d imsilen=%d",
		   blen, imsilen);
	if (blen < 2 || imsilen > *len) {
		*len = imsilen;
		return -4;
	}

	if (scard_read_file(scard, buf, blen))
		return -5;

	*len = imsilen;
	pos = imsi;
	*pos++ = '0' + (buf[1] >> 4 & 0x0f);
	for (i = 2; i < blen; i++) {
		*pos++ = '0' + (buf[i] & 0x0f);
		*pos++ = '0' + (buf[i] >> 4 & 0x0f);
	}

	return 0;
}


int scard_gsm_auth(struct scard_data *scard, unsigned char *rand,
		   unsigned char *sres, unsigned char *kc)
{
	unsigned char cmd[5 + 16] = { SIM_CMD_RUN_GSM_ALG };
	unsigned char get_resp[5] = { SIM_CMD_GET_RESPONSE, 0x0c };
	unsigned char resp[3], buf[12 + 3];
	size_t len;
	long ret;

	if (scard == NULL)
		return -1;

	wpa_hexdump(MSG_DEBUG, "SCARD: GSM auth - RAND", rand, 16);
	memcpy(cmd + 5, rand, 16);
	ret = scard_transmit(scard, cmd, sizeof(cmd), resp, &len);
	if (ret != SCARD_S_SUCCESS)
		return -2;

	if (len != 2 || resp[0] != 0x9f || resp[1] != 0x0c) {
		wpa_printf(MSG_WARNING, "SCARD: unexpected response for GSM "
			   "auth request (len=%d resp=%02x %02x)",
			   len, resp[0], resp[1]);
		return -3;
	}

	len = sizeof(buf);
	ret = scard_transmit(scard, get_resp, sizeof(get_resp), buf, &len);
	if (ret != SCARD_S_SUCCESS)
		return -4;
	if (len != 12 + 2) {
		wpa_printf(MSG_WARNING, "SCARD: unexpected data length for "
			   "GSM auth (len=%d, expected 14)", len);
		return -5;
	}

	memcpy(sres, buf, 4);
	wpa_hexdump(MSG_DEBUG, "SCARD: GSM auth - SRES", sres, 4);
	memcpy(kc, buf + 4, 8);
	wpa_hexdump(MSG_DEBUG, "SCARD: GSM auth - Kc", kc, 8);

	return 0;
}
