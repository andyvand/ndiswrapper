#include <linux/wireless.h>
#include <asm/types.h>
#include <linux/types.h>

#include "driver.h"
#include "wpa_supplicant.h"

struct wpa_key
{
	wpa_alg alg;
	u8 *addr;
	int key_index;
	int set_tx;
	u8 *seq;
	size_t seq_len;
	u8 *key;
	size_t key_len;
};

#define PRIV_RESET SIOCIWFIRSTPRIV+0
#define WPA_SET_WPA SIOCIWFIRSTPRIV+1
#define WPA_SET_KEY SIOCIWFIRSTPRIV+2
#define WPA_ASSOCIATE SIOCIWFIRSTPRIV+3
#define WPA_DISASSOCIATE SIOCIWFIRSTPRIV+4
#define WPA_SET_PRIV_FILTER SIOCIWFIRSTPRIV+5
#define WPA_SET_GENERIC_ELEMENT SIOCIWFIRSTPRIV+6
