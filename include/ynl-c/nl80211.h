/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/nl80211.yaml */
/* YNL-GEN user header */

#ifndef _LINUX_NL80211_GEN_H
#define _LINUX_NL80211_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/nl80211.h>

struct ynl_sock;

extern const struct ynl_family ynl_nl80211_family;

/* Enums */
const char *nl80211_op_str(int op);
const char *nl80211_commands_str(enum nl80211_commands value);
const char *nl80211_feature_flags_str(enum nl80211_feature_flags value);
const char *nl80211_channel_type_str(enum nl80211_channel_type value);
const char *
nl80211_protocol_features_str(enum nl80211_protocol_features value);

/* Common nested types */
struct nl80211_supported_iftypes {
	struct {
		__u32 adhoc:1;
		__u32 station:1;
		__u32 ap:1;
		__u32 ap_vlan:1;
		__u32 wds:1;
		__u32 monitor:1;
		__u32 mesh_point:1;
		__u32 p2p_client:1;
		__u32 p2p_go:1;
		__u32 p2p_device:1;
		__u32 ocb:1;
		__u32 nan:1;
	} _present;
};

struct nl80211_wowlan_triggers_attrs {
	struct {
		__u32 any:1;
		__u32 disconnect:1;
		__u32 magic_pkt:1;
		__u32 pkt_pattern:1;
		__u32 gtk_rekey_supported:1;
		__u32 gtk_rekey_failure:1;
		__u32 eap_ident_request:1;
		__u32 _4way_handshake:1;
		__u32 rfkill_release:1;
		__u32 wakeup_pkt_80211:1;
		__u32 wakeup_pkt_80211_len:1;
		__u32 wakeup_pkt_8023:1;
		__u32 wakeup_pkt_8023_len:1;
		__u32 tcp_connection:1;
		__u32 wakeup_tcp_match:1;
		__u32 wakeup_tcp_connlost:1;
		__u32 wakeup_tcp_nomoretokens:1;
		__u32 net_detect:1;
		__u32 net_detect_results:1;
		__u32 unprotected_deauth_disassoc:1;
	} _present;
};

struct nl80211_txq_stats_attrs {
	struct {
		__u32 backlog_bytes:1;
		__u32 backlog_packets:1;
		__u32 flows:1;
		__u32 drops:1;
		__u32 ecn_marks:1;
		__u32 overlimit:1;
		__u32 overmemory:1;
		__u32 collisions:1;
		__u32 tx_bytes:1;
		__u32 tx_packets:1;
		__u32 max_flows:1;
	} _present;

	__u32 backlog_bytes;
	__u32 backlog_packets;
	__u32 flows;
	__u32 drops;
	__u32 ecn_marks;
	__u32 overlimit;
	__u32 overmemory;
	__u32 collisions;
	__u32 tx_bytes;
	__u32 tx_packets;
	__u32 max_flows;
};

struct nl80211_frame_type_attrs {
	struct {
		__u32 frame_type:1;
	} _present;

	__u16 frame_type;
};

struct nl80211_iface_limit_attributes {
	struct {
		__u32 max:1;
		__u32 types:1;
	} _present;

	__u32 idx;
	__u32 max;
	struct nl80211_supported_iftypes types;
};

struct nl80211_sar_specs {
	struct {
		__u32 power:1;
		__u32 range_index:1;
		__u32 start_freq:1;
		__u32 end_freq:1;
	} _present;

	__u32 idx;
	__s32 power;
	__u32 range_index;
	__u32 start_freq;
	__u32 end_freq;
};

struct nl80211_bitrate_attrs {
	struct {
		__u32 rate:1;
		__u32 _2ghz_shortpreamble:1;
	} _present;

	__u32 idx;
	__u32 rate;
};

struct nl80211_iftype_data_attrs {
	struct {
		__u32 iftypes_len;
		__u32 he_cap_mac_len;
		__u32 he_cap_phy_len;
		__u32 he_cap_mcs_set_len;
		__u32 he_cap_ppe_len;
		__u32 he_6ghz_capa_len;
		__u32 vendor_elems_len;
		__u32 eht_cap_mac_len;
		__u32 eht_cap_phy_len;
		__u32 eht_cap_mcs_set_len;
		__u32 eht_cap_ppe_len;
	} _present;

	__u32 idx;
	void *iftypes;
	void *he_cap_mac;
	void *he_cap_phy;
	void *he_cap_mcs_set;
	void *he_cap_ppe;
	void *he_6ghz_capa;
	void *vendor_elems;
	void *eht_cap_mac;
	void *eht_cap_phy;
	void *eht_cap_mcs_set;
	void *eht_cap_ppe;
};

struct nl80211_wmm_attrs {
	struct {
		__u32 cw_min:1;
		__u32 cw_max:1;
		__u32 aifsn:1;
		__u32 txop:1;
	} _present;

	__u32 idx;
	__u16 cw_min;
	__u16 cw_max;
	__u8 aifsn;
	__u16 txop;
};

struct nl80211_iftype_attrs {
	struct {
		__u32 unspecified:1;
		__u32 adhoc:1;
		__u32 station:1;
		__u32 ap:1;
		__u32 ap_vlan:1;
		__u32 wds:1;
		__u32 monitor:1;
		__u32 mesh_point:1;
		__u32 p2p_client:1;
		__u32 p2p_go:1;
		__u32 p2p_device:1;
		__u32 ocb:1;
		__u32 nan:1;
	} _present;

	struct nl80211_frame_type_attrs unspecified;
	struct nl80211_frame_type_attrs adhoc;
	struct nl80211_frame_type_attrs station;
	struct nl80211_frame_type_attrs ap;
	struct nl80211_frame_type_attrs ap_vlan;
	struct nl80211_frame_type_attrs wds;
	struct nl80211_frame_type_attrs monitor;
	struct nl80211_frame_type_attrs mesh_point;
	struct nl80211_frame_type_attrs p2p_client;
	struct nl80211_frame_type_attrs p2p_go;
	struct nl80211_frame_type_attrs p2p_device;
	struct nl80211_frame_type_attrs ocb;
	struct nl80211_frame_type_attrs nan;
};

struct nl80211_if_combination_attributes {
	struct {
		__u32 maxnum:1;
		__u32 sta_ap_bi_match:1;
		__u32 num_channels:1;
		__u32 radar_detect_widths:1;
		__u32 radar_detect_regions:1;
		__u32 bi_min_gcd:1;
	} _present;

	__u32 idx;
	unsigned int n_limits;
	struct nl80211_iface_limit_attributes *limits;
	__u32 maxnum;
	__u32 num_channels;
	__u32 radar_detect_widths;
	__u32 radar_detect_regions;
	__u32 bi_min_gcd;
};

struct nl80211_sar_attributes {
	struct {
		__u32 type:1;
	} _present;

	__u32 type;
	unsigned int n_specs;
	struct nl80211_sar_specs *specs;
};

struct nl80211_frequency_attrs {
	struct {
		__u32 freq:1;
		__u32 disabled:1;
		__u32 no_ir:1;
		__u32 no_ibss:1;
		__u32 radar:1;
		__u32 max_tx_power:1;
		__u32 dfs_state:1;
		__u32 dfs_time_len;
		__u32 no_ht40_minus_len;
		__u32 no_ht40_plus_len;
		__u32 no_80mhz_len;
		__u32 no_160mhz_len;
		__u32 dfs_cac_time_len;
		__u32 indoor_only_len;
		__u32 ir_concurrent_len;
		__u32 no_20mhz_len;
		__u32 no_10mhz_len;
		__u32 no_he_len;
		__u32 offset:1;
		__u32 _1mhz_len;
		__u32 _2mhz_len;
		__u32 _4mhz_len;
		__u32 _8mhz_len;
		__u32 _16mhz_len;
		__u32 no_320mhz_len;
		__u32 no_eht_len;
		__u32 psd_len;
		__u32 dfs_concurrent_len;
		__u32 no_6ghz_vlp_client_len;
		__u32 no_6ghz_afc_client_len;
		__u32 can_monitor_len;
		__u32 allow_6ghz_vlp_ap_len;
	} _present;

	__u32 idx;
	__u32 freq;
	__u32 max_tx_power;
	__u32 dfs_state;
	void *dfs_time;
	void *no_ht40_minus;
	void *no_ht40_plus;
	void *no_80mhz;
	void *no_160mhz;
	void *dfs_cac_time;
	void *indoor_only;
	void *ir_concurrent;
	void *no_20mhz;
	void *no_10mhz;
	unsigned int n_wmm;
	struct nl80211_wmm_attrs *wmm;
	void *no_he;
	__u32 offset;
	void *_1mhz;
	void *_2mhz;
	void *_4mhz;
	void *_8mhz;
	void *_16mhz;
	void *no_320mhz;
	void *no_eht;
	void *psd;
	void *dfs_concurrent;
	void *no_6ghz_vlp_client;
	void *no_6ghz_afc_client;
	void *can_monitor;
	void *allow_6ghz_vlp_ap;
};

struct nl80211_band_attrs {
	struct {
		__u32 ht_mcs_set_len;
		__u32 ht_capa:1;
		__u32 ht_ampdu_factor:1;
		__u32 ht_ampdu_density:1;
		__u32 vht_mcs_set_len;
		__u32 vht_capa:1;
		__u32 edmg_channels_len;
		__u32 edmg_bw_config_len;
		__u32 s1g_mcs_nss_set_len;
		__u32 s1g_capa_len;
	} _present;

	unsigned int n_freqs;
	struct nl80211_frequency_attrs *freqs;
	unsigned int n_rates;
	struct nl80211_bitrate_attrs *rates;
	void *ht_mcs_set;
	__u16 ht_capa;
	__u8 ht_ampdu_factor;
	__u8 ht_ampdu_density;
	void *vht_mcs_set;
	__u32 vht_capa;
	unsigned int n_iftype_data;
	struct nl80211_iftype_data_attrs *iftype_data;
	void *edmg_channels;
	void *edmg_bw_config;
	void *s1g_mcs_nss_set;
	void *s1g_capa;
};

struct nl80211_wiphy_bands {
	struct {
		__u32 _2ghz:1;
		__u32 _5ghz:1;
		__u32 _60ghz:1;
		__u32 _6ghz:1;
		__u32 s1ghz:1;
		__u32 lc:1;
	} _present;

	struct nl80211_band_attrs _2ghz;
	struct nl80211_band_attrs _5ghz;
	struct nl80211_band_attrs _60ghz;
	struct nl80211_band_attrs _6ghz;
	struct nl80211_band_attrs s1ghz;
	struct nl80211_band_attrs lc;
};

/* ============== NL80211_CMD_GET_WIPHY ============== */
/* NL80211_CMD_GET_WIPHY - do */
struct nl80211_get_wiphy_req {
	struct {
		__u32 wiphy:1;
		__u32 wdev:1;
		__u32 ifindex:1;
	} _present;

	__u32 wiphy;
	__u64 wdev;
	__u32 ifindex;
};

static inline struct nl80211_get_wiphy_req *nl80211_get_wiphy_req_alloc(void)
{
	return calloc(1, sizeof(struct nl80211_get_wiphy_req));
}
void nl80211_get_wiphy_req_free(struct nl80211_get_wiphy_req *req);

static inline void
nl80211_get_wiphy_req_set_wiphy(struct nl80211_get_wiphy_req *req, __u32 wiphy)
{
	req->_present.wiphy = 1;
	req->wiphy = wiphy;
}
static inline void
nl80211_get_wiphy_req_set_wdev(struct nl80211_get_wiphy_req *req, __u64 wdev)
{
	req->_present.wdev = 1;
	req->wdev = wdev;
}
static inline void
nl80211_get_wiphy_req_set_ifindex(struct nl80211_get_wiphy_req *req,
				  __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}

struct nl80211_get_wiphy_rsp {
	struct {
		__u32 bands:1;
		__u32 cipher_suites_len;
		__u32 control_port_ethertype:1;
		__u32 ext_capa_len;
		__u32 ext_capa_mask_len;
		__u32 ext_features_len;
		__u32 feature_flags:1;
		__u32 generation:1;
		__u32 ht_capability_mask_len;
		__u32 mac_len;
		__u32 max_csa_counters:1;
		__u32 max_match_sets:1;
		__u32 max_num_akm_suites_len;
		__u32 max_num_pmkids:1;
		__u32 max_num_scan_ssids:1;
		__u32 max_num_sched_scan_plans:1;
		__u32 max_num_sched_scan_ssids:1;
		__u32 max_remain_on_channel_duration:1;
		__u32 max_scan_ie_len:1;
		__u32 max_scan_plan_interval:1;
		__u32 max_scan_plan_iterations:1;
		__u32 max_sched_scan_ie_len:1;
		__u32 offchannel_tx_ok:1;
		__u32 rx_frame_types:1;
		__u32 sar_spec:1;
		__u32 sched_scan_max_reqs:1;
		__u32 software_iftypes:1;
		__u32 support_ap_uapsd:1;
		__u32 supported_iftypes:1;
		__u32 tdls_external_setup:1;
		__u32 tdls_support:1;
		__u32 tx_frame_types:1;
		__u32 txq_limit:1;
		__u32 txq_memory_limit:1;
		__u32 txq_quantum:1;
		__u32 txq_stats:1;
		__u32 vht_capability_mask_len;
		__u32 wiphy:1;
		__u32 wiphy_antenna_avail_rx:1;
		__u32 wiphy_antenna_avail_tx:1;
		__u32 wiphy_antenna_rx:1;
		__u32 wiphy_antenna_tx:1;
		__u32 wiphy_bands:1;
		__u32 wiphy_coverage_class:1;
		__u32 wiphy_frag_threshold:1;
		__u32 wiphy_name_len;
		__u32 wiphy_retry_long:1;
		__u32 wiphy_retry_short:1;
		__u32 wiphy_rts_threshold:1;
		__u32 wowlan_triggers_supported:1;
	} _present;

	__u32 bands;
	void *cipher_suites;
	void *ext_capa;
	void *ext_capa_mask;
	void *ext_features;
	__u32 feature_flags;
	__u32 generation;
	void *ht_capability_mask;
	unsigned int n_interface_combinations;
	struct nl80211_if_combination_attributes *interface_combinations;
	void *mac;
	__u8 max_csa_counters;
	__u8 max_match_sets;
	void *max_num_akm_suites;
	__u8 max_num_pmkids;
	__u8 max_num_scan_ssids;
	__u32 max_num_sched_scan_plans;
	__u8 max_num_sched_scan_ssids;
	__u32 max_remain_on_channel_duration;
	__u16 max_scan_ie_len;
	__u32 max_scan_plan_interval;
	__u32 max_scan_plan_iterations;
	__u16 max_sched_scan_ie_len;
	struct nl80211_iftype_attrs rx_frame_types;
	struct nl80211_sar_attributes sar_spec;
	__u32 sched_scan_max_reqs;
	struct nl80211_supported_iftypes software_iftypes;
	unsigned int n_supported_commands;
	__u32 *supported_commands;
	struct nl80211_supported_iftypes supported_iftypes;
	struct nl80211_iftype_attrs tx_frame_types;
	__u32 txq_limit;
	__u32 txq_memory_limit;
	__u32 txq_quantum;
	struct nl80211_txq_stats_attrs txq_stats;
	void *vht_capability_mask;
	__u32 wiphy;
	__u32 wiphy_antenna_avail_rx;
	__u32 wiphy_antenna_avail_tx;
	__u32 wiphy_antenna_rx;
	__u32 wiphy_antenna_tx;
	struct nl80211_wiphy_bands wiphy_bands;
	__u8 wiphy_coverage_class;
	__u32 wiphy_frag_threshold;
	char *wiphy_name;
	__u8 wiphy_retry_long;
	__u8 wiphy_retry_short;
	__u32 wiphy_rts_threshold;
	struct nl80211_wowlan_triggers_attrs wowlan_triggers_supported;
};

void nl80211_get_wiphy_rsp_free(struct nl80211_get_wiphy_rsp *rsp);

/*
 * Get information about a wiphy or dump a list of all wiphys. Requests to dump get-wiphy
should unconditionally include the split-wiphy-dump flag in the request.

 */
struct nl80211_get_wiphy_rsp *
nl80211_get_wiphy(struct ynl_sock *ys, struct nl80211_get_wiphy_req *req);

/* NL80211_CMD_GET_WIPHY - dump */
struct nl80211_get_wiphy_req_dump {
	struct {
		__u32 wiphy:1;
		__u32 wdev:1;
		__u32 ifindex:1;
		__u32 split_wiphy_dump:1;
	} _present;

	__u32 wiphy;
	__u64 wdev;
	__u32 ifindex;
};

static inline struct nl80211_get_wiphy_req_dump *
nl80211_get_wiphy_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct nl80211_get_wiphy_req_dump));
}
void nl80211_get_wiphy_req_dump_free(struct nl80211_get_wiphy_req_dump *req);

static inline void
nl80211_get_wiphy_req_dump_set_wiphy(struct nl80211_get_wiphy_req_dump *req,
				     __u32 wiphy)
{
	req->_present.wiphy = 1;
	req->wiphy = wiphy;
}
static inline void
nl80211_get_wiphy_req_dump_set_wdev(struct nl80211_get_wiphy_req_dump *req,
				    __u64 wdev)
{
	req->_present.wdev = 1;
	req->wdev = wdev;
}
static inline void
nl80211_get_wiphy_req_dump_set_ifindex(struct nl80211_get_wiphy_req_dump *req,
				       __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
nl80211_get_wiphy_req_dump_set_split_wiphy_dump(struct nl80211_get_wiphy_req_dump *req)
{
	req->_present.split_wiphy_dump = 1;
}

struct nl80211_get_wiphy_rsp_dump {
	struct {
		__u32 bands:1;
		__u32 cipher_suites_len;
		__u32 control_port_ethertype:1;
		__u32 ext_capa_len;
		__u32 ext_capa_mask_len;
		__u32 ext_features_len;
		__u32 feature_flags:1;
		__u32 generation:1;
		__u32 ht_capability_mask_len;
		__u32 mac_len;
		__u32 max_csa_counters:1;
		__u32 max_match_sets:1;
		__u32 max_num_akm_suites_len;
		__u32 max_num_pmkids:1;
		__u32 max_num_scan_ssids:1;
		__u32 max_num_sched_scan_plans:1;
		__u32 max_num_sched_scan_ssids:1;
		__u32 max_remain_on_channel_duration:1;
		__u32 max_scan_ie_len:1;
		__u32 max_scan_plan_interval:1;
		__u32 max_scan_plan_iterations:1;
		__u32 max_sched_scan_ie_len:1;
		__u32 offchannel_tx_ok:1;
		__u32 rx_frame_types:1;
		__u32 sar_spec:1;
		__u32 sched_scan_max_reqs:1;
		__u32 software_iftypes:1;
		__u32 support_ap_uapsd:1;
		__u32 supported_iftypes:1;
		__u32 tdls_external_setup:1;
		__u32 tdls_support:1;
		__u32 tx_frame_types:1;
		__u32 txq_limit:1;
		__u32 txq_memory_limit:1;
		__u32 txq_quantum:1;
		__u32 txq_stats:1;
		__u32 vht_capability_mask_len;
		__u32 wiphy:1;
		__u32 wiphy_antenna_avail_rx:1;
		__u32 wiphy_antenna_avail_tx:1;
		__u32 wiphy_antenna_rx:1;
		__u32 wiphy_antenna_tx:1;
		__u32 wiphy_bands:1;
		__u32 wiphy_coverage_class:1;
		__u32 wiphy_frag_threshold:1;
		__u32 wiphy_name_len;
		__u32 wiphy_retry_long:1;
		__u32 wiphy_retry_short:1;
		__u32 wiphy_rts_threshold:1;
		__u32 wowlan_triggers_supported:1;
	} _present;

	__u32 bands;
	void *cipher_suites;
	void *ext_capa;
	void *ext_capa_mask;
	void *ext_features;
	__u32 feature_flags;
	__u32 generation;
	void *ht_capability_mask;
	unsigned int n_interface_combinations;
	struct nl80211_if_combination_attributes *interface_combinations;
	void *mac;
	__u8 max_csa_counters;
	__u8 max_match_sets;
	void *max_num_akm_suites;
	__u8 max_num_pmkids;
	__u8 max_num_scan_ssids;
	__u32 max_num_sched_scan_plans;
	__u8 max_num_sched_scan_ssids;
	__u32 max_remain_on_channel_duration;
	__u16 max_scan_ie_len;
	__u32 max_scan_plan_interval;
	__u32 max_scan_plan_iterations;
	__u16 max_sched_scan_ie_len;
	struct nl80211_iftype_attrs rx_frame_types;
	struct nl80211_sar_attributes sar_spec;
	__u32 sched_scan_max_reqs;
	struct nl80211_supported_iftypes software_iftypes;
	unsigned int n_supported_commands;
	__u32 *supported_commands;
	struct nl80211_supported_iftypes supported_iftypes;
	struct nl80211_iftype_attrs tx_frame_types;
	__u32 txq_limit;
	__u32 txq_memory_limit;
	__u32 txq_quantum;
	struct nl80211_txq_stats_attrs txq_stats;
	void *vht_capability_mask;
	__u32 wiphy;
	__u32 wiphy_antenna_avail_rx;
	__u32 wiphy_antenna_avail_tx;
	__u32 wiphy_antenna_rx;
	__u32 wiphy_antenna_tx;
	struct nl80211_wiphy_bands wiphy_bands;
	__u8 wiphy_coverage_class;
	__u32 wiphy_frag_threshold;
	char *wiphy_name;
	__u8 wiphy_retry_long;
	__u8 wiphy_retry_short;
	__u32 wiphy_rts_threshold;
	struct nl80211_wowlan_triggers_attrs wowlan_triggers_supported;
};

struct nl80211_get_wiphy_rsp_list {
	struct nl80211_get_wiphy_rsp_list *next;
	struct nl80211_get_wiphy_rsp_dump obj __attribute__((aligned(8)));
};

void nl80211_get_wiphy_rsp_list_free(struct nl80211_get_wiphy_rsp_list *rsp);

struct nl80211_get_wiphy_rsp_list *
nl80211_get_wiphy_dump(struct ynl_sock *ys,
		       struct nl80211_get_wiphy_req_dump *req);

/* ============== NL80211_CMD_GET_INTERFACE ============== */
/* NL80211_CMD_GET_INTERFACE - do */
struct nl80211_get_interface_req {
	struct {
		__u32 ifname_len;
	} _present;

	char *ifname;
};

static inline struct nl80211_get_interface_req *
nl80211_get_interface_req_alloc(void)
{
	return calloc(1, sizeof(struct nl80211_get_interface_req));
}
void nl80211_get_interface_req_free(struct nl80211_get_interface_req *req);

static inline void
nl80211_get_interface_req_set_ifname(struct nl80211_get_interface_req *req,
				     const char *ifname)
{
	free(req->ifname);
	req->_present.ifname_len = strlen(ifname);
	req->ifname = malloc(req->_present.ifname_len + 1);
	memcpy(req->ifname, ifname, req->_present.ifname_len);
	req->ifname[req->_present.ifname_len] = 0;
}

struct nl80211_get_interface_rsp {
	struct {
		__u32 ifname_len;
		__u32 iftype:1;
		__u32 ifindex:1;
		__u32 wiphy:1;
		__u32 wdev:1;
		__u32 mac_len;
		__u32 generation:1;
		__u32 txq_stats:1;
		__u32 _4addr:1;
	} _present;

	char *ifname;
	__u32 iftype;
	__u32 ifindex;
	__u32 wiphy;
	__u64 wdev;
	void *mac;
	__u32 generation;
	struct nl80211_txq_stats_attrs txq_stats;
	__u8 _4addr;
};

void nl80211_get_interface_rsp_free(struct nl80211_get_interface_rsp *rsp);

/*
 * Get information about an interface or dump a list of all interfaces
 */
struct nl80211_get_interface_rsp *
nl80211_get_interface(struct ynl_sock *ys,
		      struct nl80211_get_interface_req *req);

/* NL80211_CMD_GET_INTERFACE - dump */
struct nl80211_get_interface_req_dump {
	struct {
		__u32 ifname_len;
	} _present;

	char *ifname;
};

static inline struct nl80211_get_interface_req_dump *
nl80211_get_interface_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct nl80211_get_interface_req_dump));
}
void
nl80211_get_interface_req_dump_free(struct nl80211_get_interface_req_dump *req);

static inline void
nl80211_get_interface_req_dump_set_ifname(struct nl80211_get_interface_req_dump *req,
					  const char *ifname)
{
	free(req->ifname);
	req->_present.ifname_len = strlen(ifname);
	req->ifname = malloc(req->_present.ifname_len + 1);
	memcpy(req->ifname, ifname, req->_present.ifname_len);
	req->ifname[req->_present.ifname_len] = 0;
}

struct nl80211_get_interface_rsp_dump {
	struct {
		__u32 ifname_len;
		__u32 iftype:1;
		__u32 ifindex:1;
		__u32 wiphy:1;
		__u32 wdev:1;
		__u32 mac_len;
		__u32 generation:1;
		__u32 txq_stats:1;
		__u32 _4addr:1;
	} _present;

	char *ifname;
	__u32 iftype;
	__u32 ifindex;
	__u32 wiphy;
	__u64 wdev;
	void *mac;
	__u32 generation;
	struct nl80211_txq_stats_attrs txq_stats;
	__u8 _4addr;
};

struct nl80211_get_interface_rsp_list {
	struct nl80211_get_interface_rsp_list *next;
	struct nl80211_get_interface_rsp_dump obj __attribute__((aligned(8)));
};

void
nl80211_get_interface_rsp_list_free(struct nl80211_get_interface_rsp_list *rsp);

struct nl80211_get_interface_rsp_list *
nl80211_get_interface_dump(struct ynl_sock *ys,
			   struct nl80211_get_interface_req_dump *req);

/* ============== NL80211_CMD_GET_PROTOCOL_FEATURES ============== */
/* NL80211_CMD_GET_PROTOCOL_FEATURES - do */
struct nl80211_get_protocol_features_req {
	struct {
		__u32 protocol_features:1;
	} _present;

	__u32 protocol_features;
};

static inline struct nl80211_get_protocol_features_req *
nl80211_get_protocol_features_req_alloc(void)
{
	return calloc(1, sizeof(struct nl80211_get_protocol_features_req));
}
void
nl80211_get_protocol_features_req_free(struct nl80211_get_protocol_features_req *req);

static inline void
nl80211_get_protocol_features_req_set_protocol_features(struct nl80211_get_protocol_features_req *req,
							__u32 protocol_features)
{
	req->_present.protocol_features = 1;
	req->protocol_features = protocol_features;
}

struct nl80211_get_protocol_features_rsp {
	struct {
		__u32 protocol_features:1;
	} _present;

	__u32 protocol_features;
};

void
nl80211_get_protocol_features_rsp_free(struct nl80211_get_protocol_features_rsp *rsp);

/*
 * Get information about supported protocol features
 */
struct nl80211_get_protocol_features_rsp *
nl80211_get_protocol_features(struct ynl_sock *ys,
			      struct nl80211_get_protocol_features_req *req);

#endif /* _LINUX_NL80211_GEN_H */
