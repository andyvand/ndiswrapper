#ifndef WPA_SUPPLICANT_I_H
#define WPA_SUPPLICANT_I_H

#define PMKID_LEN 16
struct rsn_pmksa_cache {
	struct rsn_pmksa_cache *next;
	u8 pmkid[PMKID_LEN];
	u8 pmk[PMK_LEN];
	time_t expiration;
	int akmp; /* WPA_KEY_MGMT_* */
	u8 aa[ETH_ALEN];
};

struct rsn_pmksa_candidate {
	struct rsn_pmksa_candidate *next;
	u8 bssid[ETH_ALEN];
};


struct wpa_ptk {
	u8 mic_key[16]; /* EAPOL-Key MIC Key (MK) */
	u8 encr_key[16]; /* EAPOL-Key Encryption Key (EK) */
	u8 tk1[16]; /* Temporal Key 1 (TK1) */
	union {
		u8 tk2[16]; /* Temporal Key 2 (TK2) */
		struct {
			u8 tx_mic_key[8];
			u8 rx_mic_key[8];
		} auth;
	} u;
} __attribute__ ((packed));


struct wpa_supplicant {
	struct l2_packet_data *l2;
	unsigned char own_addr[ETH_ALEN];
	char ifname[20];
	int dot1x_s; /* socket for connection to Xsupplicant */
	int ext_pmk_received; /* 1 = PMK was received from Xsupplicant */

	u8 pmk[PMK_LEN];
	u8 counter[WPA_NONCE_LEN];
	u8 snonce[WPA_NONCE_LEN];
	u8 anonce[WPA_NONCE_LEN]; /* ANonce from the last 1/4 msg */
	struct wpa_ptk ptk, tptk;
	int ptk_set, tptk_set;
	char *confname;
	struct wpa_config *conf;
	u8 request_counter[WPA_REPLAY_COUNTER_LEN];
	int countermeasures;
	time_t last_michael_mic_error;
	u8 rx_replay_counter[WPA_REPLAY_COUNTER_LEN];
	int rx_replay_counter_set;
	u8 bssid[ETH_ALEN];
	int reassociate; /* reassociation requested */
	struct wpa_ssid *current_ssid;
	int current_supports_preauth;
	u8 *ap_wpa_ie;
	size_t ap_wpa_ie_len;
	u8 *assoc_wpa_ie;
	size_t assoc_wpa_ie_len;

	/* Selected configuration (based on Beacon/ProbeResp WPA IE) */
	int proto;
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;

	void *events_priv; /* private data used by wpa_driver_events */

	struct wpa_ssid *prev_scan_ssid; /* previously scanned SSID;
					  * NULL = not yet initialized (start
					  * with broadcast SSID)
					  * BROADCAST_SSID_SCAN = broadcast
					  * SSID was used in the previous scan
					  */
#define BROADCAST_SSID_SCAN ((struct wpa_ssid *) 1)

	struct wpa_driver_ops *driver;
	struct eapol_sm *eapol;

	int ctrl_sock; /* UNIX domain socket for control interface or -1 if
			* not used */
	struct wpa_ctrl_dst *ctrl_dst;

	enum {
		WPA_DISCONNECTED, WPA_SCANNING, WPA_ASSOCIATING,
		WPA_ASSOCIATED, WPA_4WAY_HANDSHAKE, WPA_GROUP_HANDSHAKE,
		WPA_COMPLETED
	} wpa_state;

	struct rsn_pmksa_cache *pmksa; /* PMKSA cache */
	int pmksa_count; /* number of entries in PMKSA cache */
	struct rsn_pmksa_cache *cur_pmksa; /* current PMKSA entry */
	struct rsn_pmksa_candidate *pmksa_candidates;

	struct l2_packet_data *l2_preauth;
	u8 preauth_bssid[ETH_ALEN]; /* current RSN pre-auth peer or
				     * 00:00:00:00:00:00 if no pre-auth is
				     * in progress */
	struct eapol_sm *preauth_eapol;

	int eapol_received; /* number of EAPOL packets received after the
			     * previous association event */

	u8 *imsi;
	size_t imsi_len;
	struct scard_data *scard;
};


/* wpa_supplicant.c */
void wpa_supplicant_scan(void *eloop_ctx, void *timeout_ctx);

void wpa_supplicant_req_scan(struct wpa_supplicant *wpa_s, int sec, int usec);

void wpa_supplicant_cancel_scan(struct wpa_supplicant *wpa_s);

void wpa_supplicant_disassociate(struct wpa_supplicant *wpa_s,
				 int reason_code);

void wpa_supplicant_req_auth_timeout(struct wpa_supplicant *wpa_s,
				     int sec, int usec);

void wpa_supplicant_cancel_auth_timeout(struct wpa_supplicant *wpa_s);


/* wpa.c */
void wpa_supplicant_key_request(struct wpa_supplicant *wpa_s,
				int error, int pairwise);

struct wpa_ie_data {
	int proto;
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int capabilities;
};

int wpa_parse_wpa_ie(struct wpa_supplicant *wpa_s, u8 *wpa_ie,
		     size_t wpa_ie_len, struct wpa_ie_data *data);

int wpa_gen_wpa_ie(struct wpa_supplicant *wpa_s, u8 *wpa_ie);

void wpa_supplicant_rx_eapol(void *ctx, unsigned char *src_addr,
			     unsigned char *buf, size_t len);

int wpa_supplicant_init_counter(struct wpa_supplicant *wpa_s);

void pmksa_cache_free(struct wpa_supplicant *wpa_s);
struct rsn_pmksa_cache * pmksa_cache_get(struct wpa_supplicant *wpa_s,
					 u8 *aa, u8 *pmkid);
int pmksa_cache_list(struct wpa_supplicant *wpa_s, char *buf, size_t len);
void pmksa_candidate_free(struct wpa_supplicant *wpa_s);

int wpa_get_mib(struct wpa_supplicant *wpa_s, char *buf, size_t buflen);

struct wpa_scan_result;
#ifdef IEEE8021X_EAPOL
int rsn_preauth_init(struct wpa_supplicant *wpa_s, u8 *dst);
void rsn_preauth_deinit(struct wpa_supplicant *wpa_s);
void rsn_preauth_scan_results(struct wpa_supplicant *wpa_s,
			      struct wpa_scan_result *results, int count);
#else /* IEEE8021X_EAPOL */
static inline int rsn_preauth_init(struct wpa_supplicant *wpa_s, u8 *dst)
{
	return -1;
}

static inline void rsn_preauth_deinit(struct wpa_supplicant *wpa_s)
{
}
static inline void rsn_preauth_scan_results(struct wpa_supplicant *wpa_s,
					    struct wpa_scan_result *results,
					    int count)
{
}
#endif /* IEEE8021X_EAPOL */

#endif /* WPA_SUPPLICANT_I_H */
