#ifndef EAPOL_SM_H
#define EAPOL_SM_H

typedef enum { FALSE = 0, TRUE = 1 } Boolean;

#ifdef IEEE8021X_EAPOL

/* IEEE 802.1aa/D6.1 - Supplicant */

struct eapol_sm {
	/* Timers */
	unsigned int authWhile;
	unsigned int heldWhile;
	unsigned int startWhen;
	unsigned int idleWhile; /* for EAP state machine */

	/* Global variables */
	Boolean eapFail;
	Boolean eapolEap;
	Boolean eapSuccess;
	Boolean initialize;
	Boolean keyDone;
	Boolean keyRun;
	Boolean portEnabled;
	enum {
		Unauthorized, Authorized
	} portStatus;  /* dot1xSuppControlledPortStatus */
	Boolean portValid;
	Boolean suppAbort;
	Boolean suppFail;
	Boolean suppStart;
	Boolean suppSuccess;
	Boolean suppTimeout;

	/* Supplicant PAE state machine */
	enum {
		SUPP_PAE_UNKNOWN = 0,
		SUPP_PAE_DISCONNECTED = 1,
		SUPP_PAE_LOGOFF = 2,
		SUPP_PAE_CONNECTING = 3,
		SUPP_PAE_AUTHENTICATING = 4,
		SUPP_PAE_AUTHENTICATED = 5,
		/* unused(6) */
		SUPP_PAE_HELD = 7,
		SUPP_PAE_RESTART = 8
	} SUPP_PAE_state; /* dot1xSuppPaeState */
	/* Variables */
	Boolean userLogoff;
	Boolean logoffSent;
	unsigned int startCount;
	Boolean eapRestart;
	/* Constants */
	unsigned int heldPeriod; /* dot1xSuppHeldPeriod */
	unsigned int startPeriod; /* dot1xSuppStartPeriod */
	unsigned int maxStart; /* dot1xSuppMaxStart */

	/* Key Receive state machine */
	enum {
		KEY_RX_UNKNOWN = 0,
		KEY_RX_NO_KEY_RECEIVE, KEY_RX_KEY_RECEIVE
	} KEY_RX_state;
	/* Variables */
	Boolean rxKey;

	/* Supplicant Backend state machine */
	enum {
		SUPP_BE_UNKNOWN = 0,
		SUPP_BE_INITIALIZE = 1,
		SUPP_BE_IDLE = 2,
		SUPP_BE_REQUEST = 3,
		SUPP_BE_RECEIVE = 4,
		SUPP_BE_RESPONSE = 5,
		SUPP_BE_FAIL = 6,
		SUPP_BE_TIMEOUT = 7, 
		SUPP_BE_SUCCESS = 8
	} SUPP_BE_state; /* dot1xSuppBackendPaeState */
	/* Variables */
	Boolean eapNoResp;
	Boolean eapReq;
	Boolean eapResp;
	/* Constants */
	unsigned int authPeriod; /* dot1xSuppAuthPeriod */

	/* Statistics */
	unsigned int dot1xSuppEapolFramesRx;
	unsigned int dot1xSuppEapolFramesTx;
	unsigned int dot1xSuppEapolStartFramesTx;
	unsigned int dot1xSuppEapolLogoffFramesTx;
	unsigned int dot1xSuppEapolRespFramesTx;
	unsigned int dot1xSuppEapolReqIdFramesRx;
	unsigned int dot1xSuppEapolReqFramesRx;
	unsigned int dot1xSuppInvalidEapolFramesRx;
	unsigned int dot1xSuppEapLengthErrorFramesRx;
	unsigned int dot1xSuppLastEapolFrameVersion;
	unsigned char dot1xSuppLastEapolFrameSource[6];

	/* Miscellaneous variables (not defined in IEEE 802.1aa/D6.1) */
	Boolean changed;
	struct eap_sm *eap;
	struct wpa_ssid *config;
	void *ctx; /* pointer to arbitrary upper level context */
	int preauth; /* This EAPOL state machine is used for IEEE 802.11i/RSN
		      * pre-authentication */
	Boolean initial_req;
	u8 *last_rx_key;
	size_t last_rx_key_len;
	u8 *eapReqData; /* for EAP */
	size_t eapReqDataLen; /* for EAP */
	Boolean altAccept; /* for EAP */
	Boolean altReject; /* for EAP */
	Boolean replay_counter_valid;
	u8 last_replay_counter[16];
	int accept_802_1x_keys;

	void (*cb)(struct eapol_sm *eapol, int success, void *ctx);
	void *cb_ctx;
	enum { EAPOL_CB_IN_PROGRESS = 0, EAPOL_CB_SUCCESS, EAPOL_CB_FAILURE }
		cb_status;
	void *msg_ctx, *scard_ctx;
	Boolean cached_pmk;
};


struct eapol_sm *eapol_sm_init(void *ctx, int preauth);
void eapol_sm_deinit(struct eapol_sm *sm);
void eapol_sm_step(struct eapol_sm *sm);
int eapol_sm_get_status(struct eapol_sm *sm, char *buf, size_t buflen);
int eapol_sm_get_mib(struct eapol_sm *sm, char *buf, size_t buflen);
void eapol_sm_configure(struct eapol_sm *sm, int heldPeriod, int authPeriod,
			int startPeriod, int maxStart);
void eapol_sm_rx_eapol(struct eapol_sm *sm, u8 *src, u8 *buf, size_t len);
static void inline eapol_sm_notify_tx_eapol_key(struct eapol_sm *sm)
{
	if (sm)
		sm->dot1xSuppEapolFramesTx++;
}
void eapol_sm_notify_portEnabled(struct eapol_sm *sm, Boolean enabled);
void eapol_sm_notify_portValid(struct eapol_sm *sm, Boolean valid);
void eapol_sm_notify_eap_success(struct eapol_sm *sm, Boolean success);
void eapol_sm_notify_eap_fail(struct eapol_sm *sm, Boolean fail);
void eapol_sm_notify_config(struct eapol_sm *sm, struct wpa_ssid *config,
			    int accept_802_1x_keys);
int eapol_sm_get_key(struct eapol_sm *sm, u8 *key, size_t len);
void eapol_sm_notify_logoff(struct eapol_sm *sm, Boolean logoff);
void eapol_sm_notify_cached(struct eapol_sm *sm);
void eapol_sm_notify_pmkid_attempt(struct eapol_sm *sm);
void eapol_sm_register_cb(struct eapol_sm *sm,
			  void (*cb)(struct eapol_sm *eapol, int success,
				     void *ctx), void *ctx);
void eapol_sm_register_msg_ctx(struct eapol_sm *sm, void *ctx);
void eapol_sm_register_scard_ctx(struct eapol_sm *sm, void *ctx);
#else /* IEEE8021X_EAPOL */
static inline struct eapol_sm *eapol_sm_init(void *ctx, int preauth)
{
	return (struct eapol_sm *) 1;
}
static inline void eapol_sm_deinit(struct eapol_sm *sm)
{
}
static inline void eapol_sm_step(struct eapol_sm *sm)
{
}
static inline int eapol_sm_get_status(struct eapol_sm *sm, char *buf,
				      size_t buflen)
{
	return 0;
}
static inline int eapol_sm_get_mib(struct eapol_sm *sm, char *buf,
				   size_t buflen)
{
	return 0;
}
static inline void eapol_sm_configure(struct eapol_sm *sm, int heldPeriod,
				      int authPeriod, int startPeriod,
				      int maxStart)
{
}
static inline void eapol_sm_rx_eapol(struct eapol_sm *sm, u8 *src, u8 *buf,
				     size_t len)
{
}
static inline void eapol_sm_notify_tx_eapol_key(struct eapol_sm *sm)
{
}
static inline void eapol_sm_notify_portEnabled(struct eapol_sm *sm,
					       Boolean enabled)
{
}
static inline void eapol_sm_notify_portValid(struct eapol_sm *sm,
					     Boolean valid)
{
}
static inline void eapol_sm_notify_eap_success(struct eapol_sm *sm,
					       Boolean success)
{
}
static inline void eapol_sm_notify_eap_fail(struct eapol_sm *sm, Boolean fail)
{
}
static inline void eapol_sm_notify_config(struct eapol_sm *sm,
					  struct wpa_ssid *config,
					  int accept_802_1x_keys)
{
}
static inline int eapol_sm_get_key(struct eapol_sm *sm, u8 *key, size_t len)
{
	return -1;
}
static inline void eapol_sm_notify_logoff(struct eapol_sm *sm, Boolean logoff)
{
}
static inline void eapol_sm_notify_cached(struct eapol_sm *sm)
{
}
#define eapol_sm_notify_pmkid_attempt(sm) do { } while (0)
static inline void eapol_sm_register_cb(struct eapol_sm *sm,
					void (*cb)(struct eapol_sm *eapol,
						   int success, void *ctx),
					void *ctx)
{
}
#define eapol_sm_register_msg_ctx(sm, ctx) do { } while (0)
#define eapol_sm_register_scard_ctx(sm, ctx) do { } while (0)
#endif /* IEEE8021X_EAPOL */

#endif /* EAPOL_SM_H */
