#define DOT11_BSSID_LIST_REVISION_1 		1
struct ndis_dot11_bssid_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	mac_address bssids[1];
};

enum ndis_dot11_phy_type {
	ndis_dot11_phy_type_unknown = 0,
	ndis_dot11_phy_type_any = ndis_dot11_phy_type_unknown,
	ndis_dot11_phy_type_fhss = 1,
	ndis_dot11_phy_type_dsss = 2,
	ndis_dot11_phy_type_irbaseband = 3,
	ndis_dot11_phy_type_ofdm = 4,
	ndis_dot11_phy_type_hrdsss = 5,
	ndis_dot11_phy_type_erp = 6,
	ndis_dot11_phy_type_ihv_start = 0x80000000,
	ndis_dot11_phy_type_ihv_end = 0xffffffff
};

#define DOT11_SSID_MAX_LENGTH			32
struct ndis_dot11_ssid {
	ULONG length;
	UCHAR ssid[DOT11_SSID_MAX_LENGTH];
};

enum ndis_dot11_bss_type {
	ndis_dot11_bss_type_infrastructure = 1,
	ndis_dot11_bss_type_independent = 2,
	ndis_dot11_bss_type_any = 3
};
	
#define DOT11_RATE_SET_MAX_LENGTH		126

struct ndis_dot11_rate_set {
	ULONG length;
	UCHAR rates[DOT11_RATE_SET_MAX_LENGTH];
};

#define DOT11_MAX_PDU_SIZE			2346
#define DOT11_MIN_PDU_SIZE			(256)
#define DOT11_MAX_NUM_DEFAULT_KEY		4

#define NDIS_MANDATORY_OID			(0x01)
#define NDIS_OPTIONAL_OID			(0x02)
#define NDIS_OPERATIONAL_OID			(0x01)
#define NDIS_STATISTICS_OID			(0x02)

#define NDIS_DEFINE_OID(seq, oid, m)				\
	((0x0E000000) | ((oid) << 16) | ((m) << 8) | (seq))

#define OID_DOT11_NDIS_START			0x0D010300

#define DOT11_HW_WEP_SUPPORTED_TX		0x00000001
#define DOT11_HW_WEP_SUPPORTED_RX		0x00000002
#define DOT11_HW_FRAGMENTATION_SUPPORTED	0x00000004
#define DOT11_HW_DEFRAGMENTATION_SUPPORTED	0x00000008
#define DOT11_HW_MSDU_AUTH_SUPPORTED_TX		0x00000010
#define DOT11_HW_MSDU_AUTH_SUPPORTED_RX		0x00000020
#define DOT11_CONF_ALGO_WEP_RC4			0x00000001
#define DOT11_CONF_ALGO_TKIP			0x00000002 
#define DOT11_AUTH_ALGO_MICHAEL			0x00000001

struct ndis_dot11_offload_capability {
	ULONG eserved;
	ULONG flags;
	ULONG supported_wep;
	ULONG num_replay_windows;
	ULONG max_wep_key_map_length;
	ULONG supported_auth_algos;
	ULONG max_auth_key_map_length;
};

#define OID_DOT11_CURRENT_OFFLOAD_CAPABILITY	(OID_DOT11_NDIS_START + 1)
struct ndis_dot11_current_offload_capability {
	ULONG eserved;
	ULONG flags;
};

#define OID_DOT11_WEP_OFFLOAD			(OID_DOT11_NDIS_START + 2)
enum ndis_dot11_offload_type {
	ndis_dot11_offload_type_wep = 1,
	ndis_dot11_offload_type_auth = 2
};

struct ndis_dot11_iv48_counter {
	ULONG iv32_counter;
	USHORT iv16_counter;
};

struct ndis_dot11_wep_offload {
	ULONG reserved;
	void *ctx;
	void *offload;
	enum ndis_dot11_offload_type type;
	ULONG algo;
	BOOLEAN row_outbound;
	BOOLEAN use_default;
	ULONG flags;
	mac_address mac;
	ULONG num_rws_on_peer;
	ULONG num_rws_on_me;
	struct ndis_dot11_iv48_counter iv48_counters[16];
	USHORT rw_bitmaps[16];
	USHORT key_length;
	UCHAR key[1];
};

#define OID_DOT11_WEP_UPLOAD			(OID_DOT11_NDIS_START + 3)
struct ndis_dot11_wep_upload {
	ULONG reserved;
	enum ndis_dot11_offload_type type;
	void *offload;
	ULONG num_rws_used;
	struct ndis_dot11_iv48_counter iv48_counters[16];
	USHORT rw_bitmaps[16];
};

#define OID_DOT11_DEFAULT_WEP_OFFLOAD		(OID_DOT11_NDIS_START + 4)
enum ndis_dot11_key_direction {
	ndis_dot11_key_direction_both = 1,
	ndis_dot11_key_direction_inbound = 2,
	ndis_dot11_key_direction_outbound = 3
};

struct ndis_dot11_default_wep_offload {
	ULONG reserved;
	void *ctx;
	void *offload;
	ULONG index;
	enum ndis_dot11_offload_type type;
	ULONG algo;
	ULONG flags;
	enum ndis_dot11_key_direction key_direction;
	mac_address mac;
	ULONG num_rws_on_me;
	struct ndis_dot11_iv48_counter iv48_counters[16];
	USHORT rw_bitmaps[16];
	USHORT key_length;
	UCHAR key[1];
};

#define OID_DOT11_DEFAULT_WEP_UPLOAD		(OID_DOT11_NDIS_START + 5)
struct ndis_dot11_default_wep_upload {
        ULONG reserved;
        enum ndis_dot11_offload_type type;
        void *offload;
        ULONG num_rws_used;
        struct ndis_dot11_iv48_counter iv48_counters[16];
        USHORT rw_bitmaps[16];
};

#define OID_DOT11_MPDU_MAX_LENGTH		(OID_DOT11_NDIS_START + 6)

#define OID_DOT11_OPERATION_MODE_CAPABILITY	(OID_DOT11_NDIS_START + 7)
#define DOT11_OPERATION_MODE_UNKNOWN		0x00000000
#define DOT11_OPERATION_MODE_STATION		0x00000001
#define DOT11_OPERATION_MODE_AP			0x00000002
#define DOT11_OPERATION_MODE_EXTENSIBLE_STATION	0x00000004
#define DOT11_OPERATION_MODE_NETWORK_MONITOR	0x80000000
struct ndis_dot11_op_mode_capability {
	ULONG reserved;
	ULONG major_version;
	ULONG minor_version;
	ULONG num_tx_buffers;
	ULONG num_rx_buffers;
	ULONG mode;
};

#define OID_DOT11_CURRENT_OPERATION_MODE	(OID_DOT11_NDIS_START + 8)
struct ndis_dot11_current_operation_mode {
	ULONG reserved;
	ULONG mode;
};

#define OID_DOT11_CURRENT_PACKET_FILTER		(OID_DOT11_NDIS_START + 9)
#define DOT11_PACKET_TYPE_DIRECTED_CTRL		0x00000001
#define DOT11_PACKET_TYPE_DIRECTED_MGMT		0x00000002
#define DOT11_PACKET_TYPE_DIRECTED_DATA		0x00000004
#define DOT11_PACKET_TYPE_MULTICAST_CTRL	0x00000008
#define DOT11_PACKET_TYPE_MULTICAST_MGMT	0x00000010
#define DOT11_PACKET_TYPE_MULTICAST_DATA	0x00000020
#define DOT11_PACKET_TYPE_BROADCAST_CTRL	0x00000040
#define DOT11_PACKET_TYPE_BROADCAST_MGMT	0x00000080
#define DOT11_PACKET_TYPE_BROADCAST_DATA	0x00000100
#define DOT11_PACKET_TYPE_PROMISCUOUS_CTRL	0x00000200
#define DOT11_PACKET_TYPE_PROMISCUOUS_MGMT	0x00000400
#define DOT11_PACKET_TYPE_PROMISCUOUS_DATA	0x00000800
#define DOT11_PACKET_TYPE_ALL_MULTICAST_CTRL	0x00001000
#define DOT11_PACKET_TYPE_ALL_MULTICAST_MGMT	0x00002000
#define DOT11_PACKET_TYPE_ALL_MULTICAST_DATA	0x00004000

#define OID_DOT11_ATIM_WINDOW			(OID_DOT11_NDIS_START + 10)

#define OID_DOT11_SCAN_REQUEST			(OID_DOT11_NDIS_START + 11)

enum ndis_dot11_scan_type {
	ndis_dot11_scan_type_active = 1,
	ndis_dot11_scan_type_passive = 2,
	ndis_dot11_scan_type_auto = 3,
	ndis_dot11_scan_type_forced = 0x80000000
};

struct ndis_dot11_scan_request {
	enum ndis_dot11_bss_type bss_type;
	mac_address bssid;
	struct ndis_dot11_ssid ssid;
	enum ndis_dot11_scan_type scan_type;
	BOOLEAN restricted_scan;
	BOOLEAN use_request_ie;
	ULONG req_ids_offset;
	ULONG num_req_ides;;
	ULONG phy_types_offset;
	ULONG num_phy_types;
	ULONG ies_offset;
	ULONG ies_length;
	UCHAR buffer[1];
};

enum ndis_ch_desc_type {
	ndis_ch_desc_type_logical = 1,
	ndis_ch_desc_type_center_frequency = 2,
	ndis_ch_desc_type_phy_specific
};

struct ndis_dot11_phy_type_info {
	enum ndis_dot11_phy_type phy_type;
	BOOLEAN use_params;
	ULONG probe_delay;
	ULONG min_channel_time;
	ULONG max_channel_time;
	enum ndis_ch_desc_type ch_desc_type;
	ULONG channel_list_size;
	UCHAR channel_list_buffer[1];
};

#define NDIS_DOT11_BSSID_ANY			0xFFFFFFFFFFFF

struct ndis_dot11_info_element {
	UCHAR id;
	UCHAR length;
};

#define DOT11_IE_SSID_MAX_LENGTH					\
	(DOT11_SSID_MAX_LENGTH + sizeof(struct ndis_dot11_info_element))

#define DOT11_INFO_ELEMENT_ID_SSID		0
#define DOT11_INFO_ELEMENT_ID_SUPPORTED_RATES	1
#define DOT11_INFO_ELEMENT_ID_FH_PARAM_SET	2
#define DOT11_INFO_ELEMENT_ID_DS_PARAM_SET	3
#define DOT11_INFO_ELEMENT_ID_CF_PARAM_SET	4
#define DOT11_INFO_ELEMENT_ID_TIM		5
#define DOT11_INFO_ELEMENT_ID_IBSS_PARAM_SET	6
#define DOT11_INFO_ELEMENT_ID_COUNTRY_INFO	7
#define DOT11_INFO_ELEMENT_ID_FH_PARAM		8
#define DOT11_INFO_ELEMENT_ID_FH_PATTERN_TABLE	9
#define DOT11_INFO_ELEMENT_ID_REQUESTED		10
#define DOT11_INFO_ELEMENT_ID_CHALLENGE		16
#define DOT11_INFO_ELEMENT_ID_ERP		42
#define DOT11_INFO_ELEMENT_ID_RSN		48
#define DOT11_INFO_ELEMENT_ID_EXTD_SUPPORTED_RATES	50
#define DOT11_INFO_ELEMENT_ID_VENDOR_SPECIFIC	221


struct ndis_dot11_scan_request_v2 {
	enum ndis_dot11_bss_type bss_type;
	mac_address bssid;
	enum ndis_dot11_scan_type scan_type;
	BOOLEAN restricted_scan;
	ULONG ssids_offset;
	ULONG num_ssids;
	BOOLEAN use_request_ie;
	ULONG request_ids_offset;
	ULONG num_request_ids;
	ULONG phy_types_offset;
	ULONG num_phy_types;
	ULONG ies_offset;
	ULONG ies_length;
	UCHAR buffer[1];
};

#define OID_DOT11_CURRENT_PHY_TYPE		(OID_DOT11_NDIS_START + 12)
#define DOT11_PHY_TYPE_LIST_REVISION_1		1
struct ndis_dot11_phy_type_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	enum ndis_dot11_phy_type phy_types[1];
};

#define OID_DOT11_JOIN_REQUEST			(OID_DOT11_NDIS_START + 13)

#define DOT11_CAPABILITY_INFO_ESS		0x0001
#define DOT11_CAPABILITY_INFO_IBSS		0x0002
#define DOT11_CAPABILITY_INFO_CF_POLLABLE	0x0004
#define DOT11_CAPABILITY_INFO_CF_POLL_REQ	0x0008
#define DOT11_CAPABILITY_INFO_PRIVACY		0x0010
#define DOT11_CAPABILITY_SHORT_PREAMBLE		0x0020
#define DOT11_CAPABILITY_PBCC			0x0040
#define DOT11_CAPABILITY_CHANNEL_AGILITY	0x0080
#define DOT11_CAPABILITY_SHORT_SLOT_TIME	0x0400
#define DOT11_CAPABILITY_DSSSOFDM		0x2000

struct ndis_dot11_bss_desc {
	ULONG reserved;
	mac_address bssid;
	enum ndis_dot11_bss_type bss_type;
	USHORT beacon_period;
	ULONGLONG time_stamp;
	USHORT capa_info;
	ULONG buffer_length;
	UCHAR buffer[1];
};

struct ndis_dot11_join_request {
	ULONG failure_timeout;
	struct ndis_dot11_rate_set rate_set;
	ULONG ch_center_freq;
	struct ndis_dot11_bss_desc bss_desc;
};

#define OID_DOT11_START_REQUEST		(OID_DOT11_NDIS_START + 14)
struct ndis_dot11_start_request {
	ULONG failure_timeout;
	struct ndis_dot11_rate_set rate_set;
	ULONG ch_center_freq;
	struct ndis_dot11_bss_desc bss_desc;
};

#define OID_DOT11_UPDATE_IE		(OID_DOT11_NDIS_START + 15)
enum ndis_dot11_update_ie_op {
	ndis_dot11_update_ie_op_create_replace = 1,
	ndis_dot11_update_ie_op_delete = 2,
};

struct ndis_dot11_update_ie {
	enum ndis_dot11_update_ie_op update_ie_op;
	ULONG buffer_length;
	UCHAR buffer[1];
};

#define OID_DOT11_RESET_REQUEST		(OID_DOT11_NDIS_START + 16)
enum ndis_dot11_reset_type {
	ndis_dot11_reset_type_phy = 1,
	ndis_dot11_reset_type_mac = 2,
	ndis_dot11_reset_type_phy_and_mac = 3
};

struct ndis_dot11_reset_request {
	enum ndis_dot11_reset_type type;
	mac_address mac;
	BOOLEAN set_default_mib;
};

#define OID_DOT11_NIC_POWER_STATE		(OID_DOT11_NDIS_START + 17)

#define OID_DOT11_POWER_MGMT_MODE		(OID_DOT11_NDIS_START + 25)
enum ndis_dot11_power_mode {
	ndis_dot11_power_mode_unknown = 0,
	ndis_dot11_power_mode_active = 1,
	ndis_dot11_power_mode_powersave = 2
};
#define DOT11_POWER_SAVE_LEVEL_MAX_PSP      1
#define DOT11_POWER_SAVE_LEVEL_FAST_PSP     2
struct ndis_dot11_power_mgmt_mode {
	enum ndis_dot11_power_mode power_mode;
	ULONG power_save_level;
	USHORT listen_interval;
	USHORT aid;
	BOOLEAN receive_dtims;
};

#define OID_DOT11_OPERATIONAL_RATE_SET		(OID_DOT11_NDIS_START + 26)
#define OID_DOT11_BEACON_PERIOD			(OID_DOT11_NDIS_START + 27)
#define OID_DOT11_DTIM_PERIOD			(OID_DOT11_NDIS_START + 28)
#define OID_DOT11_WEP_ICV_ERROR_COUNT		(OID_DOT11_NDIS_START + 29)
#define OID_DOT11_MAC_ADDRESS			(OID_DOT11_NDIS_START + 30)
#define OID_DOT11_RTS_THRESHOLD			(OID_DOT11_NDIS_START + 31)
#define OID_DOT11_SHORT_RETRY_LIMIT		(OID_DOT11_NDIS_START + 32)
#define OID_DOT11_LONG_RETRY_LIMIT		(OID_DOT11_NDIS_START + 33)
#define OID_DOT11_FRAGMENTATION_THRESHOLD	(OID_DOT11_NDIS_START + 34)
#define OID_DOT11_MAX_TRANSMIT_MSDU_LIFETIME	(OID_DOT11_NDIS_START + 35)
#define OID_DOT11_MAX_RECEIVE_LIFETIME		(OID_DOT11_NDIS_START + 36)
#define OID_DOT11_COUNTERS_ENTRY		(OID_DOT11_NDIS_START + 37)
struct ndis_dot11_counters_entry {
	ULONG tx_fragments;
	ULONG multicast_tx_frames;
	ULONG failed;
	ULONG retry;
	ULONG multiple_rx;
	ULONG frame_dups;
	ULONG rts_success;
	ULONG rts_failure;
	ULONG ack_failure;
	ULONG rx_frams;
	ULONG multicast_rx_frames;
	ULONG fcs_error;
	ULONG tx_frames;
};

#define OID_DOT11_SUPPORTED_PHY_TYPES		(OID_DOT11_NDIS_START + 38)
struct ndis_dot11_supported_phy_types {
	ULONG num_entries;
	ULONG num_total_entries;
	enum ndis_dot11_phy_type phy_types[1];
};

#define OID_DOT11_CURRENT_REG_DOMAIN		(OID_DOT11_NDIS_START + 39)
#define DOT11_REG_DOMAIN_OTHER			0x00000000
#define DOT11_REG_DOMAIN_FCC			0x00000010
#define DOT11_REG_DOMAIN_DOC			0x00000020
#define DOT11_REG_DOMAIN_ETSI			0x00000030
#define DOT11_REG_DOMAIN_SPAIN			0x00000031
#define DOT11_REG_DOMAIN_FRANCE			0x00000032
#define DOT11_REG_DOMAIN_MKK			0x00000040

#define OID_DOT11_TEMP_TYPE			(OID_DOT11_NDIS_START + 40)
enum ndis_dot11_temp_type {
	ndis_dot11_temp_type_unknown = 0,
	ndis_dot11_temp_type_1 = 1,
	ndis_dot11_temp_type_2 = 2
};

#define OID_DOT11_CURRENT_TX_ANTENNA		(OID_DOT11_NDIS_START + 41)
#define OID_DOT11_DIVERSITY_SUPPORT		(OID_DOT11_NDIS_START + 42)
enum ndis_dot11_diversity_support {
	dot11_diversity_support_unknown = 0,
	dot11_diversity_support_fixedlist = 1,
	dot11_diversity_support_notsupported = 2,
	dot11_diversity_support_dynamic = 3
};

#define OID_DOT11_CURRENT_RX_ANTENNA		(OID_DOT11_NDIS_START + 43)

#define OID_DOT11_MAX_TX_POWER_LEVELS 8

#define OID_DOT11_SUPPORTED_POWER_LEVELS	(OID_DOT11_NDIS_START + 44)
struct ndis_dot11_supported_power_levels {
	ULONG num_levels;
	ULONG levels[OID_DOT11_MAX_TX_POWER_LEVELS];
};

#define OID_DOT11_CURRENT_TX_POWER_LEVEL	(OID_DOT11_NDIS_START + 45)
#define OID_DOT11_HOP_TIME			(OID_DOT11_NDIS_START + 46)
#define OID_DOT11_CURRENT_CHANNEL_NUMBER	(OID_DOT11_NDIS_START + 47)
#define OID_DOT11_MAX_DWELL_TIME		(OID_DOT11_NDIS_START + 48)
#define OID_DOT11_CURRENT_DWELL_TIME		(OID_DOT11_NDIS_START + 49)
#define OID_DOT11_CURRENT_SET			(OID_DOT11_NDIS_START + 50)
#define OID_DOT11_CURRENT_PATTERN		(OID_DOT11_NDIS_START + 51)
#define OID_DOT11_CURRENT_INDEX			(OID_DOT11_NDIS_START + 52)
#define OID_DOT11_CURRENT_CHANNEL		(OID_DOT11_NDIS_START + 53)
#define OID_DOT11_CCA_MODE_SUPPORTED		(OID_DOT11_NDIS_START + 54)
#define DOT11_CCA_MODE_ED_ONLY			0x00000001
#define DOT11_CCA_MODE_CS_ONLY			0x00000002
#define DOT11_CCA_MODE_ED_and_CS		0x00000004
#define DOT11_CCA_MODE_CS_WITH_TIMER		0x00000008
#define DOT11_CCA_MODE_HRCS_AND_ED		0x00000010
#define OID_DOT11_CURRENT_CCA_MODE		(OID_DOT11_NDIS_START + 55)
#define OID_DOT11_ED_THRESHOLD			(OID_DOT11_NDIS_START + 56)
#define OID_DOT11_CCA_WATCHDOG_TIMER_MAX	(OID_DOT11_NDIS_START + 57)
#define OID_DOT11_CCA_WATCHDOG_TIMER_MIN	(OID_DOT11_NDIS_START + 59)
#define OID_DOT11_CCA_WATCHDOG_COUNT_MIN	(OID_DOT11_NDIS_START + 60)

#define OID_DOT11_REG_DOMAINS_SUPPORT_VALUE	(OID_DOT11_NDIS_START + 61)
struct ndis_dot11_reg_domain_value {
	ULONG uRegDomainsSupportIndex;
	ULONG uRegDomainsSupportValue;
};
struct ndis_dot11_reg_domains_support_value {
	ULONG num_entries;
	ULONG num_total_entries;
	struct ndis_dot11_reg_domain_value value[1];
};

#define OID_DOT11_SUPPORTED_TX_ANTENNA		(OID_DOT11_NDIS_START + 62)
struct ndis_dot11_supported_antenna {
	ULONG list_index;
	BOOLEAN supported_antenna;
};
struct ndis_dot11_supported_antenna_list {
	ULONG num_entries;
	ULONG num_total_entries;
	struct ndis_dot11_supported_antenna antenna[1];
};

#define OID_DOT11_SUPPORTED_RX_ANTENNA		(OID_DOT11_NDIS_START + 63)
#define OID_DOT11_DIVERSITY_SELECTION_RX	(OID_DOT11_NDIS_START + 64)
struct ndis_dot11_diversity_selection_rx {
	ULONG list_index;
	BOOLEAN rx;
};
struct ndis_dot11_diversity_selection_rx_list {
	ULONG num_entries;
	ULONG num_total_entries;
	struct ndis_dot11_diversity_selection_rx rx[1];
};

#define OID_DOT11_SUPPORTED_DATA_RATES_VALUE	(OID_DOT11_NDIS_START + 65)
#define MAX_NUM_SUPPORTED_RATES			8
#define MAX_NUM_SUPPORTED_RATES_V2		255
struct ndis_dot11_supported_data_rates_value {
	UCHAR tx_rates[MAX_NUM_SUPPORTED_RATES];
	UCHAR rx_rates[MAX_NUM_SUPPORTED_RATES];
};

struct ndis_dot11_supported_data_rates_value_v2 {
	UCHAR tx_rates[MAX_NUM_SUPPORTED_RATES_V2];
	UCHAR rx_rates[MAX_NUM_SUPPORTED_RATES_V2];
};

#define OID_DOT11_CURRENT_FREQUENCY		(OID_DOT11_NDIS_START + 66)
#define OID_DOT11_TI_THRESHOLD			(OID_DOT11_NDIS_START + 67)
#define OID_DOT11_FREQUENCY_BANDS_SUPPORTED	(OID_DOT11_NDIS_START + 68)
#define DOT11_FREQUENCY_BANDS_LOWER		0x00000001
#define DOT11_FREQUENCY_BANDS_MIDDLE		0x00000002
#define DOT11_FREQUENCY_BANDS_UPPER		0x00000004

#define OID_DOT11_MULTI_DOMAIN_CAPABILITY_IMPLEMENTED	\
	(OID_DOT11_NDIS_START + 74)

#define OID_DOT11_MULTI_DOMAIN_CAPABILITY_ENABLED	\
	(OID_DOT11_NDIS_START + 75)

#define OID_DOT11_COUNTRY_STRING		(OID_DOT11_NDIS_START + 76)

#define OID_DOT11_WPA_TSC			(OID_DOT11_NDIS_START + 89)
struct ndis_dot11_wpa_tsc {
	ULONG uReserved;
	enum ndis_dot11_offload_type offload_type;
	void *offload;
	struct ndis_dot11_iv48_counter iv48_counter;
};

#define OID_DOT11_RSSI_RANGE			(OID_DOT11_NDIS_START + 90)
struct ndis_dot11_rssi_range {
	enum ndis_dot11_phy_type phy_type;
	ULONG min;
	ULONG max;
};

#define OID_DOT11_RF_USAGE			(OID_DOT11_NDIS_START + 91)

#define OID_DOT11_AP_JOIN_REQUEST		(OID_DOT11_NDIS_START + 93)
struct ndis_dot11_ap_join_request {
	ULONG failure_timeout;
	struct ndis_dot11_rate_set rate_set;
	ULONG ch_center_freq;
	struct ndis_dot11_bss_desc bss_desc;
};

struct ndis_dot11_recv_sensitivity {
	UCHAR data_rate;
	LONG min_rssi;
	LONG max_rssi;
};

#define OID_DOT11_RECV_SENSITIVITY_LIST		(OID_DOT11_NDIS_START + 101)

struct ndis_dot11_recv_sensitivity_list {
	union {
		enum ndis_dot11_phy_type phy_type;
		ULONG phy_id;
	};
	ULONG num_entries;
	ULONG num_total_entries;
	struct ndis_dot11_recv_sensitivity entries[1];
};

struct ndis_dot11_byte_array {
	struct ndis_object_header header;
	ULONG num_bytes;
	ULONG num_total_bytes;
	UCHAR buffer[1];
};

#define OID_DOT11_AUTO_CONFIG_ENABLED					\
	NDIS_DEFINE_OID(120, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_PHY_AUTO_CONFIG_ENABLED_FLAG	0x00000001U
#define DOT11_MAC_AUTO_CONFIG_ENABLED_FLAG	0x00000002U

#define OID_DOT11_ENUM_BSS_LIST						\
	NDIS_DEFINE_OID(121, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

union ndis_dot11_bss_entry_phy_specific_info {
	ULONG ch_center_freq;
	struct {
		ULONG hop_pattern;
		ULONG hop_set;
		ULONG dwell_time;
	} fhss;
};

struct ndis_dot11_bss_entry {
	ULONG phy_id;
	union ndis_dot11_bss_entry_phy_specific_info phy_specific_info;
	mac_address bss_id;
	enum ndis_dot11_bss_type bss_type;
	LONG rssi;
	ULONG link_quality;
	BOOLEAN in_reg_domain;
	USHORT beacon_period;
	ULONGLONG time_stamp;
	ULONGLONG host_timestamp;
	USHORT capability_info;
	ULONG buffer_length;
	UCHAR buffer[1];
};

#define OID_DOT11_FLUSH_BSS_LIST					\
	NDIS_DEFINE_OID(122, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_POWER_MGMT_REQUEST					\
	NDIS_DEFINE_OID(123, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_POWER_SAVING_NO_POWER_SAVING	0
#define DOT11_POWER_SAVING_FAST_PSP		8
#define DOT11_POWER_SAVING_MAX_PSP		16
#define DOT11_POWER_SAVING_MAXIMUM_LEVEL	24

#define OID_DOT11_DESIRED_SSID_LIST					\
	NDIS_DEFINE_OID(124, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_SSID_LIST_REVISION_1		1
struct ndis_dot11_ssid_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	struct ndis_dot11_ssid ssids[1];
};

#define OID_DOT11_EXCLUDED_MAC_ADDRESS_LIST				\
	NDIS_DEFINE_OID(125, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_MAC_ADDRESS_LIST_REVISION_1	1
struct ndis_dot11_mac_address_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	mac_address mac[1];
};

#define OID_DOT11_DESIRED_BSSID_LIST					\
	NDIS_DEFINE_OID(126, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_DESIRED_BSS_TYPE					\
	NDIS_DEFINE_OID(127, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_PMKID_LIST						\
	NDIS_DEFINE_OID(128, NDIS_OPERATIONAL_OID, NDIS_OPTIONAL_OID)

typedef UCHAR ndis_dot11_pmkid_value_t[16];
struct ndis_dot11_pmkid_entry {
	mac_address bssid;
	ndis_dot11_pmkid_value_t pmkid;
	ULONG flags;
};

#define DOT11_PMKID_LIST_REVISION_1		1
struct ndis_dot11_pmkid_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	struct ndis_dot11_pmkid_entry pmkids[1];
};

#define OID_DOT11_CONNECT_REQUEST					\
	NDIS_DEFINE_OID(129, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_EXCLUDE_UNENCRYPTED					\
	NDIS_DEFINE_OID(130, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)
    // BOOLEAN

#define OID_DOT11_STATISTICS						\
	NDIS_DEFINE_OID(131, NDIS_STATISTICS_OID, NDIS_MANDATORY_OID)

#define DOT11_STATISTICS_UNKNOWN		(ULONGLONG)(-1LL)

struct ndis_dot11_phy_frame_statistics {
	// tx counters (msdu/mmpdu)
	ULONGLONG tx_frames;
	ULONGLONG multicast_tx_frames;
	ULONGLONG failed;
	ULONGLONG retry;
	ULONGLONG multiple_retry;
	ULONGLONG max_tx_lifetime_exceeded;

	// tx counters (mpdu)
	ULONGLONG tx_fragments;
	ULONGLONG rts_success;
	ULONGLONG rts_failure;
	ULONGLONG ack_failure;

	// rx counters (msdu/mmpdu)
	ULONGLONG rx_frames;
	ULONGLONG multicast_rx_frames;
	ULONGLONG promisc_rx_frames;
	ULONGLONG max_rx_lifetime_exceeded;

	// rx counters (mpdu)
	ULONGLONG dup_frames;
	ULONGLONG rx_fragments;
	ULONGLONG promisc_rx_fragments;
	ULONGLONG fcs_errors;
};

struct ndis_dot11_mac_frame_statistics {
	ULONGLONG tx_frames;
	ULONGLONG rx_frames;
	ULONGLONG tx_failure_frames;
	ULONGLONG rx_failure_frames;

	ULONGLONG wep_excluded;
	ULONGLONG tkip_local_mic_failres;
	ULONGLONG tkip_replays;
	ULONGLONG tkip_icv_errors;
	ULONGLONG ccmp_replays;
	ULONGLONG ccmp_decrypt_errors;
	ULONGLONG wep_undecryptables;
	ULONGLONG wep_icv_errors;
	ULONGLONG decrypt_success;
	ULONGLONG decrypt_failure;
};

#define DOT11_STATISTICS_REVISION_1		1
struct ndis_dot11_statistics {
	struct ndis_object_header header;
	ULONGLONG four_way_handshake_failures;
	ULONGLONG tkip_counter_measures_invoked;
	ULONGLONG reserved;

	struct ndis_dot11_mac_frame_statistics mac_ucast_stats;
	struct ndis_dot11_mac_frame_statistics mac_mcast_stats;
	struct ndis_dot11_phy_frame_statistics phy_stats[1];
};

#define OID_DOT11_PRIVACY_EXEMPTION_LIST				\
	NDIS_DEFINE_OID(132, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_EXEMPT_NO_EXEMPTION		0
#define DOT11_EXEMPT_ALWAYS			1
#define DOT11_EXEMPT_ON_KEY_MAPPING_KEY_UNAVAILABLE 2
#define DOT11_EXEMPT_UNICAST			1
#define DOT11_EXEMPT_MULTICAST			2
#define DOT11_EXEMPT_BOTH			3
#define DOT11_PRIVACY_EXEMPTION_LIST_REVISION_1	1

struct ndis_dot11_privacy_exemption {
	USHORT ether_type;
        USHORT exemption_action_type;
        USHORT exemption_packet_type;
};

struct ndis_dot11_privacy_exemption_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
        struct ndis_dot11_privacy_exemption priv_exception_entries[1];
};

#define OID_DOT11_ENABLED_AUTHENTICATION_ALGORITHM			\
	NDIS_DEFINE_OID(133, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

enum ndis_dot11_auth_algorithm {
	DOT11_AUTH_ALGO_80211_OPEN = 1,
	DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
	DOT11_AUTH_ALGO_WPA = 3,
	DOT11_AUTH_ALGO_WPA_PSK = 4,
	DOT11_AUTH_ALGO_WPA_NONE = 5,
	DOT11_AUTH_ALGO_RSNA = 6,
	DOT11_AUTH_ALGO_RSNA_PSK = 7,
	DOT11_AUTH_ALGO_IHV_START = 0x80000000,
	DOT11_AUTH_ALGO_IHV_END = 0xffffffff
};

enum ndis_dot11_cipher_algorithm {
	DOT11_CIPHER_ALGO_NONE = 0x00,
	DOT11_CIPHER_ALGO_WEP40 = 0x01,
	DOT11_CIPHER_ALGO_TKIP = 0x02,
	DOT11_CIPHER_ALGO_CCMP = 0x04,
	DOT11_CIPHER_ALGO_WEP104 = 0x05,
	DOT11_CIPHER_ALGO_WPA_USE_GROUP = 0x100,
	DOT11_CIPHER_ALGO_RSN_USE_GROUP = 0x100,
	DOT11_CIPHER_ALGO_WEP = 0x101,
	DOT11_CIPHER_ALGO_IHV_START = 0x80000000,
	DOT11_CIPHER_ALGO_IHV_END = 0xffffffff
};

#define DOT11_AUTH_ALGORITHM_LIST_REVISION_1		1
struct ndis_dot11_auth_algorithm_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	enum ndis_dot11_auth_algorithm algo_ids[1];
};

#define OID_DOT11_SUPPORTED_UNICAST_ALGORITHM_PAIR			\
	NDIS_DEFINE_OID(134, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

struct ndis_dot11_auth_cipher_pair {
	enum ndis_dot11_auth_algorithm auth_algo_id;
	enum ndis_dot11_cipher_algorithm cipher_algo_id;
};

#define DOT11_AUTH_CIPHER_PAIR_LIST_REVISION_1		1
struct ndis_dot11_auth_cipher_pair_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	struct ndis_dot11_auth_cipher_pair pairs[1];
};

#define OID_DOT11_ENABLED_UNICAST_CIPHER_ALGORITHM			\
	NDIS_DEFINE_OID(135, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_CIPHER_ALGORITHM_LIST_REVISION_1		1
struct ndis_dot11_cipher_algorithm_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	enum ndis_dot11_cipher_algorithm algo_ids[1];
};

#define OID_DOT11_SUPPORTED_MULTICAST_ALGORITHM_PAIR			\
	NDIS_DEFINE_OID(136, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_ENABLED_MULTICAST_CIPHER_ALGORITHM			\
	NDIS_DEFINE_OID(137, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_CIPHER_DEFAULT_KEY_ID					\
	NDIS_DEFINE_OID(138, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_CIPHER_DEFAULT_KEY					\
	NDIS_DEFINE_OID(139, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_CIPHER_DEFAULT_KEY_VALUE_REVISION_1	1
struct ndis_dot11_cipher_default_key_value {
	struct ndis_object_header header;
	ULONG key_index;
	enum ndis_dot11_cipher_algorithm algo_id;
	mac_address mac;
	BOOLEAN delete;
	BOOLEAN is_static;
	USHORT key_length;
	UCHAR key[1];
};

struct ndis_dot11_key_algo_tkip_mic {
	UCHAR iv48_counter[6];
	ULONG tkip_key_length;
	ULONG mic_key_length;
	UCHAR tkip_mic_keys[1];
};

struct ndis_dot11_key_algo_ccmp {
	UCHAR iv48_counter[6];
	ULONG ccmp_key_length;
	UCHAR ccmp_key[1];
};

#define OID_DOT11_CIPHER_KEY_MAPPING_KEY				\
	NDIS_DEFINE_OID(140, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

enum ndis_dot11_direction {
	DOT11_DIR_INBOUND = 1,
	DOT11_DIR_OUTBOUND,
	DOT11_DIR_BOTH
};
#define DOT11_CIPHER_KEY_MAPPING_KEY_VALUE_BYTE_ARRAY_REVISION_1 1
struct ndis_dot11_cipher_key_mapping_key_value {
	mac_address peer_mac;
	enum ndis_dot11_cipher_algorithm algo_id;
	enum ndis_dot11_direction direction;
	BOOLEAN delete;
	BOOLEAN is_static;
	USHORT key_length;
        UCHAR key[1];
};

#define OID_DOT11_ENUM_ASSOCIATION_INFO					\
	NDIS_DEFINE_OID(141, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

enum ndis_dot11_association_state {
	ndis_dot11_assoc_state_zero = 0,
	ndis_dot11_assoc_state_unauth_unassoc = 1,
	ndis_dot11_assoc_state_auth_unassoc = 2,
	ndis_dot11_assoc_state_auth_assoc = 3
};

struct ndis_dot11_association_info_ex {
	mac_address peer_mac;
	mac_address bssid;
	USHORT capability_info;
	USHORT listen_interval;
	UCHAR peer_supported_rates[MAX_NUM_SUPPORTED_RATES_V2];
	USHORT assoc_id;
	enum ndis_dot11_association_state assoc_state;
	enum ndis_dot11_power_mode power_mode;
	LARGE_INTEGER assoc_uptime;
	ULONGLONG num_tx_packet_success;
	ULONGLONG num_tx_packet_failure;
	ULONGLONG num_rx_packet_success;
	ULONGLONG num_rx_packet_failure;
};

#define DOT11_ASSOCIATION_INFO_LIST_REVISION_1	1
struct ndis_dot11_association_info_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	struct ndis_dot11_association_info_ex assoc_info[1];
};

#define OID_DOT11_DISCONNECT_REQUEST					\
	NDIS_DEFINE_OID(142, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_UNICAST_USE_GROUP_ENABLED				\
	NDIS_DEFINE_OID(143, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_HARDWARE_PHY_STATE					\
	NDIS_DEFINE_OID(144, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_DESIRED_PHY_LIST					\
	NDIS_DEFINE_OID(145, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_PHY_ID_LIST_REVISION_1		1
struct ndis_dot11_phy_id_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	ULONG phy_ids[1];
};

#define DOT11_PHY_ID_ANY        (0xffffffffU)

#define OID_DOT11_CURRENT_PHY_ID\
	NDIS_DEFINE_OID(146, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_MEDIA_STREAMING_ENABLED				\
	NDIS_DEFINE_OID(147, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_UNREACHABLE_DETECTION_THRESHOLD			\
	NDIS_DEFINE_OID(148, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_ACTIVE_PHY_LIST					\
	NDIS_DEFINE_OID(149, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_EXTSTA_CAPABILITY					\
	NDIS_DEFINE_OID(150, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_EXTSTA_CAPABILITY_REVISION_1	1
struct ndis_dot11_extsta_capability {
	struct ndis_object_header header;
	ULONG scan_ssid_list_size;
	ULONG desired_bssid_list_size;
	ULONG desired_ssid_list_size;
	ULONG excluded_mac_address_list_size;
	ULONG privacy_exemption_list_size;
	ULONG key_mapping_table_size;
	ULONG default_key_table_size;
	ULONG wep_key_value_max_length;
	ULONG pmkid_cache_size;
	ULONG max_per_sta_default_key_tables;
};

#define OID_DOT11_DATA_RATE_MAPPING_TABLE				\
	NDIS_DEFINE_OID(151, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

struct ndis_dot11_data_rate_mapping_entry {
	UCHAR data_rate_index;
	UCHAR data_rate_flag;
	USHORT data_rate_value;
};

#define DOT11_DATA_RATE_MAPPING_TABLE_REVISION_1	1
struct ndis_dot11_data_rate_mapping_table {
	struct ndis_object_header header;
	ULONG data_rate_mapping_length;
	struct ndis_dot11_data_rate_mapping_entry entries[DOT11_RATE_SET_MAX_LENGTH];
};

#define DOT11_DATA_RATE_NON_STANDARD		0x01U
#define DOT11_DATA_RATE_INDEX_MASK		0x7fU

#define OID_DOT11_SUPPORTED_COUNTRY_OR_REGION_STRING			\
	NDIS_DEFINE_OID(152, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

typedef UCHAR ndis_dot11_country_region_string_t[3];

#define DOT11_COUNTRY_OR_REGION_STRING_LIST_REVISION_1	1
struct ndis_dot11_country_or_region_string_list {
	struct ndis_object_header header;
	ULONG num_entries;
	ULONG num_total_entries;
	ndis_dot11_country_region_string_t entries[1];
};

#define OID_DOT11_DESIRED_COUNTRY_OR_REGION_STRING			\
	NDIS_DEFINE_OID(153, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_PORT_STATE_NOTIFICATION				\
	NDIS_DEFINE_OID(154, NDIS_OPERATIONAL_OID, NDIS_OPTIONAL_OID)

#define DOT11_PORT_STATE_NOTIFICATION_REVISION_1	1
struct ndis_dot11_port_state_notification {
	struct ndis_object_header header;
	mac_address peer_mac;
	BOOLEAN open;
};

#define OID_DOT11_IBSS_PARAMS						\
	NDIS_DEFINE_OID(155, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_IBSS_PARAMS_REVISION_1		1
struct DOT11_IBSS_PARAMS {
	struct ndis_object_header header;
	BOOLEAN join_only;
	ULONG ies_offset;
	ULONG ies_length;
};

#define OID_DOT11_QOS_PARAMS						\
	NDIS_DEFINE_OID(156, NDIS_OPERATIONAL_OID, NDIS_OPTIONAL_OID)

#define DOT11_QOS_PARAMS_REVISION_1		1
#define DOT11_QOS_PROTOCOL_FLAG_WMM		(0x01U)
#define DOT11_QOS_PROTOCOL_FLAG_11E		(0x02U)
struct ndis_dot11_qos_params {
	struct ndis_object_header header;
	UCHAR enabled_qos_protocol_flags;
};

#define OID_DOT11_SAFE_MODE_ENABLED					\
	NDIS_DEFINE_OID(157, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define OID_DOT11_HIDDEN_NETWORK_ENABLED				\
	NDIS_DEFINE_OID(158, NDIS_OPERATIONAL_OID, NDIS_MANDATORY_OID)

#define DOT11_MAX_NUM_OF_FRAGMENTS		16
#define DOT11_PRIORITY_CONTENTION		0
#define DOT11_PRIORITY_CONTENTION_FREE		1
#define DOT11_SERVICE_CLASS_REORDERABLE_MULTICAST	0
#define DOT11_SERVICE_CLASS_STRICTLY_ORDERED	1
#define DOT11_FLAGS_80211B_SHORT_PREAMBLE	0x00000001
#define DOT11_FLAGS_80211B_PBCC			0x00000002
#define DOT11_FLAGS_80211B_CHANNEL_AGILITY	0x00000004
#define DOT11_FLAGS_PS_ON			0x00000008
#define DOT11_FLAGS_80211G_DSSS_OFDM		0x00000010
#define DOT11_FLAGS_80211G_USE_PROTECTION	0x00000020
#define DOT11_FLAGS_80211G_NON_ERP_PRESENT	0x00000040
#define DOT11_FLAGS_80211G_BARKER_PREAMBLE_MODE	0x00000080
#define DOT11_WME_PACKET			0x00000100

struct ndis_dot11_fragment_descriptor {
	ULONG offset;
	ULONG length;
};

struct ndis_dot11_per_msdu_counters {
	ULONG tx_fragments;
	ULONG retry;
	ULONG rts_success;
	ULONG rts_failure;
	ULONG ack_failure;
};

struct ndis_dot11_hrdsss_phy_attributes {
	BOOLEAN short_preamble_option;
	BOOLEAN pbcc_option;
	BOOLEAN channel_agility;
	ULONG hrcca_mode;
};

struct ndis_dot11_ofdm_phy_attributes {
	ULONG freq_bands;
};

struct ndis_dot11_erp_phy_attributes {
	struct ndis_dot11_hrdsss_phy_attributes hrdsss_attr;
	BOOLEAN erppbcc_option;
	BOOLEAN dssofdm_option;
	BOOLEAN short_slot_time_option;
};

#define DOT11_RATE_SET_MAX_LENGTH		126
#define DOT11_PHY_ATTRIBUTES_REVISION_1		1
struct ndis_dot11_phy_attributes {
	struct ndis_object_header header;
	enum ndis_dot11_phy_type phy_type;
	BOOLEAN hw_phy_state;
	BOOLEAN sw_phy_state;
	BOOLEAN cf_pollable;
	ULONG mpdu_max_length;
	enum ndis_dot11_temp_type temp_type;
	enum ndis_dot11_diversity_support diversity_support;
	union {
		struct ndis_dot11_hrdsss_phy_attributes hrdsss_attrs;
		struct ndis_dot11_ofdm_phy_attributes ofdm_attrs;
		struct ndis_dot11_erp_phy_attributes erp_attrs;
		ULONG supported_power_levels;
		ULONG tx_power_levels[8];
		ULONG num_data_rate_mapping_entries;
		struct ndis_dot11_data_rate_mapping_entry rate_maps[DOT11_RATE_SET_MAX_LENGTH];
		struct ndis_dot11_supported_data_rates_value_v2 data_rates;
	};
};

#define DOT11_STATUS_SUCCESS			0x00000001
#define DOT11_STATUS_RETRY_LIMIT_EXCEEDED	0x00000002
#define DOT11_STATUS_UNSUPPORTED_PRIORITY	0x00000004
#define DOT11_STATUS_UNSUPPORTED_SERVICE_CLASS	0x00000008
#define DOT11_STATUS_UNAVAILABLE_PRIORITY	0x00000010
#define DOT11_STATUS_UNAVAILABLE_SERVICE_CLASS	0x00000020
#define DOT11_STATUS_XMIT_MSDU_TIMER_EXPIRED	0x00000040
#define DOT11_STATUS_UNAVAILABLE_BSS		0x00000080
#define DOT11_STATUS_EXCESSIVE_DATA_LENGTH	0x00000100
#define DOT11_STATUS_ENCRYPTION_FAILED		0x00000200
#define DOT11_STATUS_WEP_KEY_UNAVAILABLE	0x00000400
#define DOT11_STATUS_ICV_VERIFIED		0x00000800
#define DOT11_STATUS_PACKET_REASSEMBLED		0x00001000
#define DOT11_STATUS_PACKET_NOT_REASSEMBLED	0x00002000
#define DOT11_STATUS_GENERATE_AUTH_FAILED	0x00004000
#define DOT11_STATUS_AUTH_NOT_VERIFIED		0x00008000
#define DOT11_STATUS_AUTH_VERIFIED		0x00010000
#define DOT11_STATUS_AUTH_FAILED		0x00020000
#define DOT11_STATUS_PS_LIFETIME_EXPIRED	0x00040000

struct ndis_dot11_status_indication {
	ULONG type;
	NDIS_STATUS status;
};

#define DOT11_STATUS_RESET_CONFIRM		4

#define DOT11_MPDU_MAX_LENGTH_INDICATION_REVISION_1	1
struct ndis_dot11_mpdu_max_length_indication {
	struct ndis_object_header header;
	ULONG phy_id;
	ULONG mpdu_max_length;
};

#define DOT11_ASSOCIATION_START_PARAMETERS_REVISION_1	1
struct ndis_dot11_association_start_parameters {
	struct ndis_object_header header;
	mac_address mac;
	struct ndis_dot11_ssid ssid;
	ULONG ihv_data_offset, ihv_data_size;
};

#define DOT11_ENCAP_RFC_1042			1
#define DOT11_ENCAP_802_1H			2
struct ndis_dot11_encap_entry {
	USHORT ether_type;
	USHORT encap_type;
};

enum ndis_dot11_ds_info {
	DOT11_DS_CHANGED,
	DOT11_DS_UNCHANGED,
	DOT11_DS_UNKNOWN
};

typedef ULONG ndis_dot11_assoc_status_t;

#define DOT11_ASSOC_STATUS_SUCCESS			0
#define DOT11_ASSOC_STATUS_FAILURE			0x00000001U
#define DOT11_ASSOC_STATUS_UNREACHABLE			0x00000002U
#define DOT11_ASSOC_STATUS_RADIO_OFF			0x00000003U
#define DOT11_ASSOC_STATUS_PHY_DISABLED			0x00000004U
#define DOT11_ASSOC_STATUS_CANCELLED			0x00000005U
#define DOT11_ASSOC_STATUS_CANDIDATE_LIST_EXHAUSTED	0x00000006U
#define DOT11_ASSOC_STATUS_DISASSOCIATED_BY_OS		0x00000007U
#define DOT11_ASSOC_STATUS_DISASSOCIATED_BY_OS		0x00000007U
#define DOT11_ASSOC_STATUS_DISASSOCIATED_BY_RESET	0x00000009U
#define DOT11_ASSOC_STATUS_SYSTEM_ERROR			0x0000000aU
#define DOT11_ASSOC_STATUS_ROAMING_BETTER_AP_FOUND	0x0000000bU
#define DOT11_ASSOC_STATUS_ROAMING_ASSOCIATION_LOST	0x0000000cU
#define DOT11_ASSOC_STATUS_ROAMING_ADHOC		0x0000000dU
#define DOT11_ASSOC_STATUS_PEER_DEAUTHENTICATED		0x00010000U
#define DOT11_ASSOC_STATUS_PEER_DEAUTHENTICATED_START	DOT11_ASSOC_STATUS_PEER_DEAUTHENTICATED
#define DOT11_ASSOC_STATUS_PEER_DEAUTHENTICATED_END	0x0001ffffU
#define DOT11_ASSOC_STATUS_PEER_DISASSOCIATED		0x00020000U
#define DOT11_ASSOC_STATUS_PEER_DISASSOCIATED_START	DOT11_ASSOC_STATUS_PEER_DISASSOCIATED
#define DOT11_ASSOC_STATUS_PEER_DISASSOCIATED_END	0x0002ffffU

#define DOT11_ASSOC_STATUS_ASSOCIATION_RESPONSE		0x00030000U
#define DOT11_ASSOC_STATUS_ASSOCIATION_RESPONSE_START	DOT11_ASSOC_STATUS_ASSOCIATION_RESPONSE
#define DOT11_ASSOC_STATUS_ASSOCIATION_RESPONSE_END	0x0003ffffU
#define DOT11_ASSOC_STATUS_REASON_CODE_MASK		0xffffU
#define DOT11_ASSOC_STATUS_IHV_START			0x80000000U
#define DOT11_ASSOC_STATUS_IHV_END			0xffffffffU

#define DOT11_ASSOCIATION_COMPLETION_PARAMETERS_REVISION_1	1
struct ndis_dot11_association_completion_parameters {
	struct ndis_object_header header;
	mac_address mac;
	ndis_dot11_assoc_status_t status;
	BOOLEAN reassoc_req;
	BOOLEAN reassoc_resp;
	ULONG assoc_req_offset, assoc_req_size;
	ULONG assoc_resp_offset, assoc_resp_size;
	ULONG beacon_offset, beacon_size;
	ULONG ihv_data_offset, ihv_data_size;
	enum ndis_dot11_auth_algorithm auth_algo;
	enum ndis_dot11_cipher_algorithm unicast_cipher;
	enum ndis_dot11_cipher_algorithm multicast_cipher;
	ULONG active_phy_list_offset, active_phy_list_size;
	BOOLEAN four_address_supported;
	BOOLEAN port_authorized;
	UCHAR active_qos_protocol;
	enum ndis_dot11_ds_info ds_info;
	ULONG encap_table_offset, encap_table_size;
};

#define DOT11_CONNECTION_START_PARAMETERS_REVISION_1  1
struct ndis_dot11_connection_start_parameters {
	struct ndis_object_header header;
	enum ndis_dot11_bss_type bss_type;
	mac_address adhoc_bssid;
	struct ndis_dot11_ssid adhoc_ssid;
};

#define DOT11_CONNECTION_STATUS_SUCCESS		DOT11_ASSOC_STATUS_SUCCESS
#define DOT11_CONNECTION_STATUS_FAILURE		DOT11_ASSOC_STATUS_FAILURE
#define DOT11_CONNECTION_STATUS_CANDIDATE_LIST_EXHAUSTED DOT11_ASSOC_STATUS_CANDIDATE_LIST_EXHAUSTED
#define DOT11_CONNECTION_STATUS_PHY_POWER_DOWN	DOT11_ASSOC_STATUS_RADIO_OFF
#define DOT11_CONNECTION_STATUS_CANCELLED	DOT11_ASSOC_STATUS_CANCELLED
#define DOT11_CONNECTION_STATUS_IHV_START	DOT11_ASSOC_STATUS_IHV_START
#define DOT11_CONNECTION_STATUS_IHV_END		DOT11_ASSOC_STATUS_IHV_END

#define DOT11_CONNECTION_COMPLETION_PARAMETERS_REVISION_1	1
struct ndis_dot11_connection_completion_parameters {
	struct ndis_object_header header;
	ndis_dot11_assoc_status_t status;
};

#define DOT11_ROAMING_REASON_BETTER_AP_FOUND	DOT11_ASSOC_STATUS_ROAMING_BETTER_AP_FOUND
#define DOT11_ROAMING_REASON_ASSOCIATION_LOST	DOT11_ASSOC_STATUS_ROAMING_ASSOCIATION_LOST
#define DOT11_ROAMING_REASON_ADHOC		DOT11_ASSOC_STATUS_ROAMING_ADHOC
#define DOT11_ROAMING_REASON_IHV_START		DOT11_ASSOC_STATUS_IHV_START
#define DOT11_ROAMING_REASON_IHV_END		DOT11_ASSOC_STATUS_IHV_END

#define DOT11_ROAMING_START_PARAMETERS_REVISION_1	1
struct ndis_dot11_roaming_start_parameters {
	struct ndis_object_header header;
	mac_address adhoc_bssid;
	struct ndis_dot11_ssid adhoc_ssid;
	ndis_dot11_assoc_status_t roaming_reason;
};

#define DOT11_ROAMING_COMPLETION_PARAMETERS_REVISION_1	1
struct ndis_dot11_roaming_completion_parameters {
	struct ndis_object_header header;
	ndis_dot11_assoc_status_t status;
};

#define DOT11_DISASSOC_REASON_OS		DOT11_ASSOC_STATUS_DISASSOCIATED_BY_OS
#define DOT11_DISASSOC_REASON_PEER_UNREACHABLE	DOT11_ASSOC_STATUS_UNREACHABLE
#define DOT11_DISASSOC_REASON_RADIO_OFF		DOT11_ASSOC_STATUS_RADIO_OFF
#define DOT11_DISASSOC_REASON_PHY_DISABLED	DOT11_ASSOC_STATUS_PHY_DISABLED
#define DOT11_DISASSOC_REASON_IHV_START		DOT11_ASSOC_STATUS_IHV_START
#define DOT11_DISASSOC_REASON_IHV_END		DOT11_ASSOC_STATUS_IHV_END

#define DOT11_DISASSOCIATION_PARAMETERS_REVISION_1	1
struct ndis_dot11_disassociation_parameters {
	struct ndis_object_header header;
	mac_address mac;
	ndis_dot11_assoc_status_t reason;
	ULONG ihv_data_offset, ihv_data_size;
};

#define DOT11_TKIPMIC_FAILURE_PARAMETERS_REVISION_1	1
struct ndis_dot11_tkipmic_failure_parameters {
	struct ndis_object_header header;
	BOOLEAN default_key_failure;
	ULONG key_index;
	mac_address peer_mac;
};

#define DOT11_PMKID_CANDIDATE_LIST_PARAMETERS_REVISION_1	1
struct ndis_dot11_pmkid_candidate_list_parameters {
	struct ndis_object_header header;
	ULONG candidate_list_size;
	ULONG candidate_list_offset;
};

#define DOT11_PMKID_CANDIDATE_PREAUTH_ENABLED		0x00000001U
struct ndis_dot11_bssid_candidate {
	mac_address bssid;
	ULONG flags;
};

#define DOT11_PHY_STATE_PARAMETERS_REVISION_1		1
struct ndis_dot11_phy_state_parameters {
	struct ndis_object_header header;
	ULONG phy_id;
	BOOLEAN hw_state;
	BOOLEAN sw_state;
};

struct ndis_dot11_link_quality_entry {
	mac_address peer_mac;
	UCHAR quality;
};

#define DOT11_LINK_QUALITY_PARAMETERS_REVISION_1	1
struct ndis_dot11_link_quality_parameters {
	struct ndis_object_header header;
	ULONG list_size;
	ULONG list_offset;
};

#define DOT11_EXTSTA_SEND_CONTEXT_REVISION_1		1
struct ndis_dot11_extsta_send_context {
	struct ndis_object_header header;
	USHORT exemption_action_type;
	ULONG phy_id;
	ULONG delayed_sleep_value;
	void *media_specific_info;
	ULONG send_flags;
};

#define DOT11_RECV_FLAG_RAW_PACKET		0x00000001U
#define DOT11_RECV_FLAG_RAW_PACKET_FCS_FAILURE	0x00000002U
#define DOT11_RECV_FLAG_RAW_PACKET_TIMESTAMP	0x00000004U

#define DOT11_EXTSTA_RECV_CONTEXT_REVISION_1	1
struct ndis_dot11_extsta_recv_context {
	struct ndis_object_header header;
	ULONG rx_flags;
	ULONG phy_id;
	ULONG ch_center_frequency;
	USHORT num_mpdus_received;
	LONG rssi;
	UCHAR data_rate;
	ULONG size_media_specific_info;
	void *media_specific_info;
	ULONGLONG timestamp;
};

#define DOT11_EXTSTA_ATTRIBUTES_REVISION_1	1
struct ndis_dot11_extsta_attributes {
	struct ndis_object_header header;
	ULONG scan_ssid_size;
	ULONG desired_bssid_size;
	ULONG desired_ssid_size;
	ULONG excluded_mac_size;
	ULONG privacy_exemption_size;
	ULONG key_mapping_size;
	ULONG default_key_size;
	ULONG wep_key_max_length;
	ULONG pmkid_cache_size;
	ULONG max_num_per_sta_default_key_tables;
	BOOLEAN strictly_ordered_service_class;
	UCHAR qos_protocol_flags;
	BOOLEAN safe_mode;
	ULONG num_country_region_strings;
	ndis_dot11_country_region_string_t *country_region_strings;
	ULONG num_infra_ucast_algo_pairs;
	struct ndis_dot11_auth_cipher_pair *infra_ucast_algo_pairs;
	ULONG num_infra_mcast_algo_pairs;
	struct ndis_dot11_auth_cipher_pair *infra_mcast_algo_pairs;
	ULONG num_adhoc_ucast_algo_pairs;
	struct ndis_dot11_auth_cipher_pair *adhoc_ucast_algo_pairs;
	ULONG num_adhoc_mcast_algo_pairs;
	struct ndis_dot11_auth_cipher_pair *adhoc_mcast_algo_pairs;
};

#define OID_DOT11_PRIVATE_OIDS_START	(OID_DOT11_NDIS_START + 1024)
#define OID_DOT11_CURRENT_ADDRESS	(OID_DOT11_PRIVATE_OIDS_START + 2)
#define OID_DOT11_PERMANENT_ADDRESS	(OID_DOT11_PRIVATE_OIDS_START + 3)
#define OID_DOT11_MULTICAST_LIST	(OID_DOT11_PRIVATE_OIDS_START + 4)
#define OID_DOT11_MAXIMUM_LIST_SIZE	(OID_DOT11_PRIVATE_OIDS_START + 5)

