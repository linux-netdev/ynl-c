// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/nl80211.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "nl80211-user.h"
#include "ynl.h"
#include <linux/nl80211.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const nl80211_op_strmap[] = {
	[3] = "get-wiphy",
	[7] = "get-interface",
	[NL80211_CMD_GET_PROTOCOL_FEATURES] = "get-protocol-features",
};

const char *nl80211_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(nl80211_op_strmap))
		return NULL;
	return nl80211_op_strmap[op];
}

static const char * const nl80211_commands_strmap[] = {
	[0] = "unspec",
	[1] = "get-wiphy",
	[2] = "set-wiphy",
	[3] = "new-wiphy",
	[4] = "del-wiphy",
	[5] = "get-interface",
	[6] = "set-interface",
	[7] = "new-interface",
	[8] = "del-interface",
	[9] = "get-key",
	[10] = "set-key",
	[11] = "new-key",
	[12] = "del-key",
	[13] = "get-beacon",
	[14] = "set-beacon",
	[15] = "new-beacon",
	[16] = "del-beacon",
	[17] = "get-station",
	[18] = "set-station",
	[19] = "new-station",
	[20] = "del-station",
	[21] = "get-mpath",
	[22] = "set-mpath",
	[23] = "new-mpath",
	[24] = "del-mpath",
	[25] = "set-bss",
	[26] = "set-reg",
	[27] = "req-set-reg",
	[28] = "get-mesh-config",
	[29] = "set-mesh-config",
	[30] = "set-mgmt-extra-ie",
	[31] = "get-reg",
	[32] = "get-scan",
	[33] = "trigger-scan",
	[34] = "new-scan-results",
	[35] = "scan-aborted",
	[36] = "reg-change",
	[37] = "authenticate",
	[38] = "associate",
	[39] = "deauthenticate",
	[40] = "disassociate",
	[41] = "michael-mic-failure",
	[42] = "reg-beacon-hint",
	[43] = "join-ibss",
	[44] = "leave-ibss",
	[45] = "testmode",
	[46] = "connect",
	[47] = "roam",
	[48] = "disconnect",
	[49] = "set-wiphy-netns",
	[50] = "get-survey",
	[51] = "new-survey-results",
	[52] = "set-pmksa",
	[53] = "del-pmksa",
	[54] = "flush-pmksa",
	[55] = "remain-on-channel",
	[56] = "cancel-remain-on-channel",
	[57] = "set-tx-bitrate-mask",
	[58] = "register-action",
	[59] = "action",
	[60] = "action-tx-status",
	[61] = "set-power-save",
	[62] = "get-power-save",
	[63] = "set-cqm",
	[64] = "notify-cqm",
	[65] = "set-channel",
	[66] = "set-wds-peer",
	[67] = "frame-wait-cancel",
	[68] = "join-mesh",
	[69] = "leave-mesh",
	[70] = "unprot-deauthenticate",
	[71] = "unprot-disassociate",
	[72] = "new-peer-candidate",
	[73] = "get-wowlan",
	[74] = "set-wowlan",
	[75] = "start-sched-scan",
	[76] = "stop-sched-scan",
	[77] = "sched-scan-results",
	[78] = "sched-scan-stopped",
	[79] = "set-rekey-offload",
	[80] = "pmksa-candidate",
	[81] = "tdls-oper",
	[82] = "tdls-mgmt",
	[83] = "unexpected-frame",
	[84] = "probe-client",
	[85] = "register-beacons",
	[86] = "unexpected-4-addr-frame",
	[87] = "set-noack-map",
	[88] = "ch-switch-notify",
	[89] = "start-p2p-device",
	[90] = "stop-p2p-device",
	[91] = "conn-failed",
	[92] = "set-mcast-rate",
	[93] = "set-mac-acl",
	[94] = "radar-detect",
	[95] = "get-protocol-features",
	[96] = "update-ft-ies",
	[97] = "ft-event",
	[98] = "crit-protocol-start",
	[99] = "crit-protocol-stop",
	[100] = "get-coalesce",
	[101] = "set-coalesce",
	[102] = "channel-switch",
	[103] = "vendor",
	[104] = "set-qos-map",
	[105] = "add-tx-ts",
	[106] = "del-tx-ts",
	[107] = "get-mpp",
	[108] = "join-ocb",
	[109] = "leave-ocb",
	[110] = "ch-switch-started-notify",
	[111] = "tdls-channel-switch",
	[112] = "tdls-cancel-channel-switch",
	[113] = "wiphy-reg-change",
	[114] = "abort-scan",
	[115] = "start-nan",
	[116] = "stop-nan",
	[117] = "add-nan-function",
	[118] = "del-nan-function",
	[119] = "change-nan-config",
	[120] = "nan-match",
	[121] = "set-multicast-to-unicast",
	[122] = "update-connect-params",
	[123] = "set-pmk",
	[124] = "del-pmk",
	[125] = "port-authorized",
	[126] = "reload-regdb",
	[127] = "external-auth",
	[128] = "sta-opmode-changed",
	[129] = "control-port-frame",
	[130] = "get-ftm-responder-stats",
	[131] = "peer-measurement-start",
	[132] = "peer-measurement-result",
	[133] = "peer-measurement-complete",
	[134] = "notify-radar",
	[135] = "update-owe-info",
	[136] = "probe-mesh-link",
	[137] = "set-tid-config",
	[138] = "unprot-beacon",
	[139] = "control-port-frame-tx-status",
	[140] = "set-sar-specs",
	[141] = "obss-color-collision",
	[142] = "color-change-request",
	[143] = "color-change-started",
	[144] = "color-change-aborted",
	[145] = "color-change-completed",
	[146] = "set-fils-aad",
	[147] = "assoc-comeback",
	[148] = "add-link",
	[149] = "remove-link",
	[150] = "add-link-sta",
	[151] = "modify-link-sta",
	[152] = "remove-link-sta",
	[153] = "set-hw-timestamp",
	[154] = "links-removed",
	[155] = "set-tid-to-link-mapping",
};

const char *nl80211_commands_str(enum nl80211_commands value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(nl80211_commands_strmap))
		return NULL;
	return nl80211_commands_strmap[value];
}

static const char * const nl80211_feature_flags_strmap[] = {
	[0] = "sk-tx-status",
	[1] = "ht-ibss",
	[2] = "inactivity-timer",
	[3] = "cell-base-reg-hints",
	[4] = "p2p-device-needs-channel",
	[5] = "sae",
	[6] = "low-priority-scan",
	[7] = "scan-flush",
	[8] = "ap-scan",
	[9] = "vif-txpower",
	[10] = "need-obss-scan",
	[11] = "p2p-go-ctwin",
	[12] = "p2p-go-oppps",
	[13] = "reserved",
	[14] = "advertise-chan-limits",
	[15] = "full-ap-client-state",
	[16] = "userspace-mpm",
	[17] = "active-monitor",
	[18] = "ap-mode-chan-width-change",
	[19] = "ds-param-set-ie-in-probes",
	[20] = "wfa-tpc-ie-in-probes",
	[21] = "quiet",
	[22] = "tx-power-insertion",
	[23] = "ackto-estimation",
	[24] = "static-smps",
	[25] = "dynamic-smps",
	[26] = "supports-wmm-admission",
	[27] = "mac-on-create",
	[28] = "tdls-channel-switch",
	[29] = "scan-random-mac-addr",
	[30] = "sched-scan-random-mac-addr",
	[31] = "no-random-mac-addr",
};

const char *nl80211_feature_flags_str(enum nl80211_feature_flags value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(nl80211_feature_flags_strmap))
		return NULL;
	return nl80211_feature_flags_strmap[value];
}

static const char * const nl80211_channel_type_strmap[] = {
	[0] = "no-ht",
	[1] = "ht20",
	[2] = "ht40minus",
	[3] = "ht40plus",
};

const char *nl80211_channel_type_str(enum nl80211_channel_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(nl80211_channel_type_strmap))
		return NULL;
	return nl80211_channel_type_strmap[value];
}

static const char * const nl80211_protocol_features_strmap[] = {
	[0] = "split-wiphy-dump",
};

const char *nl80211_protocol_features_str(enum nl80211_protocol_features value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(nl80211_protocol_features_strmap))
		return NULL;
	return nl80211_protocol_features_strmap[value];
}

/* Policies */
const struct ynl_policy_attr nl80211_supported_iftypes_policy[NL80211_IFTYPE_MAX + 1] = {
	[NL80211_IFTYPE_ADHOC] = { .name = "adhoc", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_STATION] = { .name = "station", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_AP] = { .name = "ap", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_AP_VLAN] = { .name = "ap-vlan", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_WDS] = { .name = "wds", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_MONITOR] = { .name = "monitor", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_MESH_POINT] = { .name = "mesh-point", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_P2P_CLIENT] = { .name = "p2p-client", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_P2P_GO] = { .name = "p2p-go", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_P2P_DEVICE] = { .name = "p2p-device", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_OCB] = { .name = "ocb", .type = YNL_PT_FLAG, },
	[NL80211_IFTYPE_NAN] = { .name = "nan", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest nl80211_supported_iftypes_nest = {
	.max_attr = NL80211_IFTYPE_MAX,
	.table = nl80211_supported_iftypes_policy,
};

const struct ynl_policy_attr nl80211_wowlan_triggers_attrs_policy[MAX_NL80211_WOWLAN_TRIG + 1] = {
	[NL80211_WOWLAN_TRIG_ANY] = { .name = "any", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_DISCONNECT] = { .name = "disconnect", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_MAGIC_PKT] = { .name = "magic-pkt", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_PKT_PATTERN] = { .name = "pkt-pattern", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED] = { .name = "gtk-rekey-supported", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE] = { .name = "gtk-rekey-failure", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST] = { .name = "eap-ident-request", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE] = { .name = "4way-handshake", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_RFKILL_RELEASE] = { .name = "rfkill-release", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211] = { .name = "wakeup-pkt-80211", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211_LEN] = { .name = "wakeup-pkt-80211-len", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023] = { .name = "wakeup-pkt-8023", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023_LEN] = { .name = "wakeup-pkt-8023-len", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_TCP_CONNECTION] = { .name = "tcp-connection", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH] = { .name = "wakeup-tcp-match", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST] = { .name = "wakeup-tcp-connlost", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS] = { .name = "wakeup-tcp-nomoretokens", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_NET_DETECT] = { .name = "net-detect", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS] = { .name = "net-detect-results", .type = YNL_PT_FLAG, },
	[NL80211_WOWLAN_TRIG_UNPROTECTED_DEAUTH_DISASSOC] = { .name = "unprotected-deauth-disassoc", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest nl80211_wowlan_triggers_attrs_nest = {
	.max_attr = MAX_NL80211_WOWLAN_TRIG,
	.table = nl80211_wowlan_triggers_attrs_policy,
};

const struct ynl_policy_attr nl80211_txq_stats_attrs_policy[NL80211_TXQ_STATS_MAX + 1] = {
	[NL80211_TXQ_STATS_BACKLOG_BYTES] = { .name = "backlog-bytes", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_BACKLOG_PACKETS] = { .name = "backlog-packets", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_FLOWS] = { .name = "flows", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_DROPS] = { .name = "drops", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_ECN_MARKS] = { .name = "ecn-marks", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_OVERLIMIT] = { .name = "overlimit", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_OVERMEMORY] = { .name = "overmemory", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_COLLISIONS] = { .name = "collisions", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_TX_BYTES] = { .name = "tx-bytes", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_TX_PACKETS] = { .name = "tx-packets", .type = YNL_PT_U32, },
	[NL80211_TXQ_STATS_MAX_FLOWS] = { .name = "max-flows", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest nl80211_txq_stats_attrs_nest = {
	.max_attr = NL80211_TXQ_STATS_MAX,
	.table = nl80211_txq_stats_attrs_policy,
};

const struct ynl_policy_attr nl80211_frame_type_attrs_policy[NUM_NL80211_ATTR + 1] = {
	[NL80211_ATTR_FRAME_TYPE] = { .name = "frame-type", .type = YNL_PT_U16, },
};

const struct ynl_policy_nest nl80211_frame_type_attrs_nest = {
	.max_attr = NUM_NL80211_ATTR,
	.table = nl80211_frame_type_attrs_policy,
};

const struct ynl_policy_attr nl80211_iface_limit_attributes_policy[MAX_NL80211_IFACE_LIMIT + 1] = {
	[NL80211_IFACE_LIMIT_MAX] = { .name = "max", .type = YNL_PT_U32, },
	[NL80211_IFACE_LIMIT_TYPES] = { .name = "types", .type = YNL_PT_NEST, .nest = &nl80211_supported_iftypes_nest, },
};

const struct ynl_policy_nest nl80211_iface_limit_attributes_nest = {
	.max_attr = MAX_NL80211_IFACE_LIMIT,
	.table = nl80211_iface_limit_attributes_policy,
};

const struct ynl_policy_attr nl80211_sar_specs_policy[NL80211_SAR_ATTR_SPECS_MAX + 1] = {
	[NL80211_SAR_ATTR_SPECS_POWER] = { .name = "power", .type = YNL_PT_U32, },
	[NL80211_SAR_ATTR_SPECS_RANGE_INDEX] = { .name = "range-index", .type = YNL_PT_U32, },
	[NL80211_SAR_ATTR_SPECS_START_FREQ] = { .name = "start-freq", .type = YNL_PT_U32, },
	[NL80211_SAR_ATTR_SPECS_END_FREQ] = { .name = "end-freq", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest nl80211_sar_specs_nest = {
	.max_attr = NL80211_SAR_ATTR_SPECS_MAX,
	.table = nl80211_sar_specs_policy,
};

const struct ynl_policy_attr nl80211_bitrate_attrs_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
	[NL80211_BITRATE_ATTR_RATE] = { .name = "rate", .type = YNL_PT_U32, },
	[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = { .name = "2ghz-shortpreamble", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest nl80211_bitrate_attrs_nest = {
	.max_attr = NL80211_BITRATE_ATTR_MAX,
	.table = nl80211_bitrate_attrs_policy,
};

const struct ynl_policy_attr nl80211_iftype_data_attrs_policy[NL80211_BAND_IFTYPE_ATTR_MAX + 1] = {
	[NL80211_BAND_IFTYPE_ATTR_IFTYPES] = { .name = "iftypes", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC] = { .name = "he-cap-mac", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY] = { .name = "he-cap-phy", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET] = { .name = "he-cap-mcs-set", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE] = { .name = "he-cap-ppe", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA] = { .name = "he-6ghz-capa", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS] = { .name = "vendor-elems", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC] = { .name = "eht-cap-mac", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY] = { .name = "eht-cap-phy", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET] = { .name = "eht-cap-mcs-set", .type = YNL_PT_BINARY,},
	[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE] = { .name = "eht-cap-ppe", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest nl80211_iftype_data_attrs_nest = {
	.max_attr = NL80211_BAND_IFTYPE_ATTR_MAX,
	.table = nl80211_iftype_data_attrs_policy,
};

const struct ynl_policy_attr nl80211_wmm_attrs_policy[NL80211_WMMR_MAX + 1] = {
	[NL80211_WMMR_CW_MIN] = { .name = "cw-min", .type = YNL_PT_U16, },
	[NL80211_WMMR_CW_MAX] = { .name = "cw-max", .type = YNL_PT_U16, },
	[NL80211_WMMR_AIFSN] = { .name = "aifsn", .type = YNL_PT_U8, },
	[NL80211_WMMR_TXOP] = { .name = "txop", .type = YNL_PT_U16, },
};

const struct ynl_policy_nest nl80211_wmm_attrs_nest = {
	.max_attr = NL80211_WMMR_MAX,
	.table = nl80211_wmm_attrs_policy,
};

const struct ynl_policy_attr nl80211_iftype_attrs_policy[NL80211_IFTYPE_MAX + 1] = {
	[NL80211_IFTYPE_UNSPECIFIED] = { .name = "unspecified", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_ADHOC] = { .name = "adhoc", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_STATION] = { .name = "station", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_AP] = { .name = "ap", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_AP_VLAN] = { .name = "ap-vlan", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_WDS] = { .name = "wds", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_MONITOR] = { .name = "monitor", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_MESH_POINT] = { .name = "mesh-point", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_P2P_CLIENT] = { .name = "p2p-client", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_P2P_GO] = { .name = "p2p-go", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_P2P_DEVICE] = { .name = "p2p-device", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_OCB] = { .name = "ocb", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
	[NL80211_IFTYPE_NAN] = { .name = "nan", .type = YNL_PT_NEST, .nest = &nl80211_frame_type_attrs_nest, },
};

const struct ynl_policy_nest nl80211_iftype_attrs_nest = {
	.max_attr = NL80211_IFTYPE_MAX,
	.table = nl80211_iftype_attrs_policy,
};

const struct ynl_policy_attr nl80211_if_combination_attributes_policy[MAX_NL80211_IFACE_COMB + 1] = {
	[NL80211_IFACE_COMB_LIMITS] = { .name = "limits", .type = YNL_PT_NEST, .nest = &nl80211_iface_limit_attributes_nest, },
	[NL80211_IFACE_COMB_MAXNUM] = { .name = "maxnum", .type = YNL_PT_U32, },
	[NL80211_IFACE_COMB_STA_AP_BI_MATCH] = { .name = "sta-ap-bi-match", .type = YNL_PT_FLAG, },
	[NL80211_IFACE_COMB_NUM_CHANNELS] = { .name = "num-channels", .type = YNL_PT_U32, },
	[NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS] = { .name = "radar-detect-widths", .type = YNL_PT_U32, },
	[NL80211_IFACE_COMB_RADAR_DETECT_REGIONS] = { .name = "radar-detect-regions", .type = YNL_PT_U32, },
	[NL80211_IFACE_COMB_BI_MIN_GCD] = { .name = "bi-min-gcd", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest nl80211_if_combination_attributes_nest = {
	.max_attr = MAX_NL80211_IFACE_COMB,
	.table = nl80211_if_combination_attributes_policy,
};

const struct ynl_policy_attr nl80211_sar_attributes_policy[NL80211_SAR_ATTR_MAX + 1] = {
	[NL80211_SAR_ATTR_TYPE] = { .name = "type", .type = YNL_PT_U32, },
	[NL80211_SAR_ATTR_SPECS] = { .name = "specs", .type = YNL_PT_NEST, .nest = &nl80211_sar_specs_nest, },
};

const struct ynl_policy_nest nl80211_sar_attributes_nest = {
	.max_attr = NL80211_SAR_ATTR_MAX,
	.table = nl80211_sar_attributes_policy,
};

const struct ynl_policy_attr nl80211_frequency_attrs_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
	[NL80211_FREQUENCY_ATTR_FREQ] = { .name = "freq", .type = YNL_PT_U32, },
	[NL80211_FREQUENCY_ATTR_DISABLED] = { .name = "disabled", .type = YNL_PT_FLAG, },
	[NL80211_FREQUENCY_ATTR_NO_IR] = { .name = "no-ir", .type = YNL_PT_FLAG, },
	[__NL80211_FREQUENCY_ATTR_NO_IBSS] = { .name = "no-ibss", .type = YNL_PT_FLAG, },
	[NL80211_FREQUENCY_ATTR_RADAR] = { .name = "radar", .type = YNL_PT_FLAG, },
	[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .name = "max-tx-power", .type = YNL_PT_U32, },
	[NL80211_FREQUENCY_ATTR_DFS_STATE] = { .name = "dfs-state", .type = YNL_PT_U32, },
	[NL80211_FREQUENCY_ATTR_DFS_TIME] = { .name = "dfs-time", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS] = { .name = "no-ht40-minus", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS] = { .name = "no-ht40-plus", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_80MHZ] = { .name = "no-80mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_160MHZ] = { .name = "no-160mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME] = { .name = "dfs-cac-time", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_INDOOR_ONLY] = { .name = "indoor-only", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_IR_CONCURRENT] = { .name = "ir-concurrent", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_20MHZ] = { .name = "no-20mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_10MHZ] = { .name = "no-10mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_WMM] = { .name = "wmm", .type = YNL_PT_NEST, .nest = &nl80211_wmm_attrs_nest, },
	[NL80211_FREQUENCY_ATTR_NO_HE] = { .name = "no-he", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_OFFSET] = { .name = "offset", .type = YNL_PT_U32, },
	[NL80211_FREQUENCY_ATTR_1MHZ] = { .name = "1mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_2MHZ] = { .name = "2mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_4MHZ] = { .name = "4mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_8MHZ] = { .name = "8mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_16MHZ] = { .name = "16mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_320MHZ] = { .name = "no-320mhz", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_EHT] = { .name = "no-eht", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_PSD] = { .name = "psd", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_DFS_CONCURRENT] = { .name = "dfs-concurrent", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT] = { .name = "no-6ghz-vlp-client", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT] = { .name = "no-6ghz-afc-client", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_CAN_MONITOR] = { .name = "can-monitor", .type = YNL_PT_BINARY,},
	[NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP] = { .name = "allow-6ghz-vlp-ap", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest nl80211_frequency_attrs_nest = {
	.max_attr = NL80211_FREQUENCY_ATTR_MAX,
	.table = nl80211_frequency_attrs_policy,
};

const struct ynl_policy_attr nl80211_band_attrs_policy[NL80211_BAND_ATTR_MAX + 1] = {
	[NL80211_BAND_ATTR_FREQS] = { .name = "freqs", .type = YNL_PT_NEST, .nest = &nl80211_frequency_attrs_nest, },
	[NL80211_BAND_ATTR_RATES] = { .name = "rates", .type = YNL_PT_NEST, .nest = &nl80211_bitrate_attrs_nest, },
	[NL80211_BAND_ATTR_HT_MCS_SET] = { .name = "ht-mcs-set", .type = YNL_PT_BINARY,},
	[NL80211_BAND_ATTR_HT_CAPA] = { .name = "ht-capa", .type = YNL_PT_U16, },
	[NL80211_BAND_ATTR_HT_AMPDU_FACTOR] = { .name = "ht-ampdu-factor", .type = YNL_PT_U8, },
	[NL80211_BAND_ATTR_HT_AMPDU_DENSITY] = { .name = "ht-ampdu-density", .type = YNL_PT_U8, },
	[NL80211_BAND_ATTR_VHT_MCS_SET] = { .name = "vht-mcs-set", .type = YNL_PT_BINARY,},
	[NL80211_BAND_ATTR_VHT_CAPA] = { .name = "vht-capa", .type = YNL_PT_U32, },
	[NL80211_BAND_ATTR_IFTYPE_DATA] = { .name = "iftype-data", .type = YNL_PT_NEST, .nest = &nl80211_iftype_data_attrs_nest, },
	[NL80211_BAND_ATTR_EDMG_CHANNELS] = { .name = "edmg-channels", .type = YNL_PT_BINARY,},
	[NL80211_BAND_ATTR_EDMG_BW_CONFIG] = { .name = "edmg-bw-config", .type = YNL_PT_BINARY,},
	[NL80211_BAND_ATTR_S1G_MCS_NSS_SET] = { .name = "s1g-mcs-nss-set", .type = YNL_PT_BINARY,},
	[NL80211_BAND_ATTR_S1G_CAPA] = { .name = "s1g-capa", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest nl80211_band_attrs_nest = {
	.max_attr = NL80211_BAND_ATTR_MAX,
	.table = nl80211_band_attrs_policy,
};

const struct ynl_policy_attr nl80211_wiphy_bands_policy[NUM_NL80211_BANDS + 1] = {
	[NL80211_BAND_2GHZ] = { .name = "2ghz", .type = YNL_PT_NEST, .nest = &nl80211_band_attrs_nest, },
	[NL80211_BAND_5GHZ] = { .name = "5ghz", .type = YNL_PT_NEST, .nest = &nl80211_band_attrs_nest, },
	[NL80211_BAND_60GHZ] = { .name = "60ghz", .type = YNL_PT_NEST, .nest = &nl80211_band_attrs_nest, },
	[NL80211_BAND_6GHZ] = { .name = "6ghz", .type = YNL_PT_NEST, .nest = &nl80211_band_attrs_nest, },
	[NL80211_BAND_S1GHZ] = { .name = "s1ghz", .type = YNL_PT_NEST, .nest = &nl80211_band_attrs_nest, },
	[NL80211_BAND_LC] = { .name = "lc", .type = YNL_PT_NEST, .nest = &nl80211_band_attrs_nest, },
};

const struct ynl_policy_nest nl80211_wiphy_bands_nest = {
	.max_attr = NUM_NL80211_BANDS,
	.table = nl80211_wiphy_bands_policy,
};

const struct ynl_policy_attr nl80211_nl80211_attrs_policy[NUM_NL80211_ATTR + 1] = {
	[NL80211_ATTR_WIPHY] = { .name = "wiphy", .type = YNL_PT_U32, },
	[NL80211_ATTR_WIPHY_NAME] = { .name = "wiphy-name", .type = YNL_PT_NUL_STR, },
	[NL80211_ATTR_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[NL80211_ATTR_IFNAME] = { .name = "ifname", .type = YNL_PT_NUL_STR, },
	[NL80211_ATTR_IFTYPE] = { .name = "iftype", .type = YNL_PT_U32, },
	[NL80211_ATTR_MAC] = { .name = "mac", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_KEY_DATA] = { .name = "key-data", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_KEY_IDX] = { .name = "key-idx", .type = YNL_PT_U8, },
	[NL80211_ATTR_KEY_CIPHER] = { .name = "key-cipher", .type = YNL_PT_U32, },
	[NL80211_ATTR_KEY_SEQ] = { .name = "key-seq", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_KEY_DEFAULT] = { .name = "key-default", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_BEACON_INTERVAL] = { .name = "beacon-interval", .type = YNL_PT_U32, },
	[NL80211_ATTR_DTIM_PERIOD] = { .name = "dtim-period", .type = YNL_PT_U32, },
	[NL80211_ATTR_BEACON_HEAD] = { .name = "beacon-head", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_BEACON_TAIL] = { .name = "beacon-tail", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_STA_AID] = { .name = "sta-aid", .type = YNL_PT_U16, },
	[NL80211_ATTR_STA_FLAGS] = { .name = "sta-flags", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_STA_LISTEN_INTERVAL] = { .name = "sta-listen-interval", .type = YNL_PT_U16, },
	[NL80211_ATTR_STA_SUPPORTED_RATES] = { .name = "sta-supported-rates", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_STA_VLAN] = { .name = "sta-vlan", .type = YNL_PT_U32, },
	[NL80211_ATTR_STA_INFO] = { .name = "sta-info", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_WIPHY_BANDS] = { .name = "wiphy-bands", .type = YNL_PT_NEST, .nest = &nl80211_wiphy_bands_nest, },
	[NL80211_ATTR_MNTR_FLAGS] = { .name = "mntr-flags", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MESH_ID] = { .name = "mesh-id", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_STA_PLINK_ACTION] = { .name = "sta-plink-action", .type = YNL_PT_U8, },
	[NL80211_ATTR_MPATH_NEXT_HOP] = { .name = "mpath-next-hop", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MPATH_INFO] = { .name = "mpath-info", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_BSS_CTS_PROT] = { .name = "bss-cts-prot", .type = YNL_PT_U8, },
	[NL80211_ATTR_BSS_SHORT_PREAMBLE] = { .name = "bss-short-preamble", .type = YNL_PT_U8, },
	[NL80211_ATTR_BSS_SHORT_SLOT_TIME] = { .name = "bss-short-slot-time", .type = YNL_PT_U8, },
	[NL80211_ATTR_HT_CAPABILITY] = { .name = "ht-capability", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SUPPORTED_IFTYPES] = { .name = "supported-iftypes", .type = YNL_PT_NEST, .nest = &nl80211_supported_iftypes_nest, },
	[NL80211_ATTR_REG_ALPHA2] = { .name = "reg-alpha2", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_REG_RULES] = { .name = "reg-rules", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MESH_CONFIG] = { .name = "mesh-config", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_BSS_BASIC_RATES] = { .name = "bss-basic-rates", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_WIPHY_TXQ_PARAMS] = { .name = "wiphy-txq-params", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_WIPHY_FREQ] = { .name = "wiphy-freq", .type = YNL_PT_U32, },
	[NL80211_ATTR_WIPHY_CHANNEL_TYPE] = { .name = "wiphy-channel-type", .type = YNL_PT_U32, },
	[NL80211_ATTR_KEY_DEFAULT_MGMT] = { .name = "key-default-mgmt", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_MGMT_SUBTYPE] = { .name = "mgmt-subtype", .type = YNL_PT_U8, },
	[NL80211_ATTR_IE] = { .name = "ie", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MAX_NUM_SCAN_SSIDS] = { .name = "max-num-scan-ssids", .type = YNL_PT_U8, },
	[NL80211_ATTR_SCAN_FREQUENCIES] = { .name = "scan-frequencies", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SCAN_SSIDS] = { .name = "scan-ssids", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_GENERATION] = { .name = "generation", .type = YNL_PT_U32, },
	[NL80211_ATTR_BSS] = { .name = "bss", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_REG_INITIATOR] = { .name = "reg-initiator", .type = YNL_PT_U8, },
	[NL80211_ATTR_REG_TYPE] = { .name = "reg-type", .type = YNL_PT_U8, },
	[NL80211_ATTR_SUPPORTED_COMMANDS] = { .name = "supported-commands", .type = YNL_PT_U32, },
	[NL80211_ATTR_FRAME] = { .name = "frame", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SSID] = { .name = "ssid", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_AUTH_TYPE] = { .name = "auth-type", .type = YNL_PT_U32, },
	[NL80211_ATTR_REASON_CODE] = { .name = "reason-code", .type = YNL_PT_U16, },
	[NL80211_ATTR_KEY_TYPE] = { .name = "key-type", .type = YNL_PT_U32, },
	[NL80211_ATTR_MAX_SCAN_IE_LEN] = { .name = "max-scan-ie-len", .type = YNL_PT_U16, },
	[NL80211_ATTR_CIPHER_SUITES] = { .name = "cipher-suites", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FREQ_BEFORE] = { .name = "freq-before", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FREQ_AFTER] = { .name = "freq-after", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FREQ_FIXED] = { .name = "freq-fixed", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_WIPHY_RETRY_SHORT] = { .name = "wiphy-retry-short", .type = YNL_PT_U8, },
	[NL80211_ATTR_WIPHY_RETRY_LONG] = { .name = "wiphy-retry-long", .type = YNL_PT_U8, },
	[NL80211_ATTR_WIPHY_FRAG_THRESHOLD] = { .name = "wiphy-frag-threshold", .type = YNL_PT_U32, },
	[NL80211_ATTR_WIPHY_RTS_THRESHOLD] = { .name = "wiphy-rts-threshold", .type = YNL_PT_U32, },
	[NL80211_ATTR_TIMED_OUT] = { .name = "timed-out", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_USE_MFP] = { .name = "use-mfp", .type = YNL_PT_U32, },
	[NL80211_ATTR_STA_FLAGS2] = { .name = "sta-flags2", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_CONTROL_PORT] = { .name = "control-port", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_TESTDATA] = { .name = "testdata", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_PRIVACY] = { .name = "privacy", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_DISCONNECTED_BY_AP] = { .name = "disconnected-by-ap", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_STATUS_CODE] = { .name = "status-code", .type = YNL_PT_U16, },
	[NL80211_ATTR_CIPHER_SUITES_PAIRWISE] = { .name = "cipher-suites-pairwise", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_CIPHER_SUITE_GROUP] = { .name = "cipher-suite-group", .type = YNL_PT_U32, },
	[NL80211_ATTR_WPA_VERSIONS] = { .name = "wpa-versions", .type = YNL_PT_U32, },
	[NL80211_ATTR_AKM_SUITES] = { .name = "akm-suites", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_REQ_IE] = { .name = "req-ie", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_RESP_IE] = { .name = "resp-ie", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_PREV_BSSID] = { .name = "prev-bssid", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_KEY] = { .name = "key", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_KEYS] = { .name = "keys", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_PID] = { .name = "pid", .type = YNL_PT_U32, },
	[NL80211_ATTR_4ADDR] = { .name = "4addr", .type = YNL_PT_U8, },
	[NL80211_ATTR_SURVEY_INFO] = { .name = "survey-info", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_PMKID] = { .name = "pmkid", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MAX_NUM_PMKIDS] = { .name = "max-num-pmkids", .type = YNL_PT_U8, },
	[NL80211_ATTR_DURATION] = { .name = "duration", .type = YNL_PT_U32, },
	[NL80211_ATTR_COOKIE] = { .name = "cookie", .type = YNL_PT_U64, },
	[NL80211_ATTR_WIPHY_COVERAGE_CLASS] = { .name = "wiphy-coverage-class", .type = YNL_PT_U8, },
	[NL80211_ATTR_TX_RATES] = { .name = "tx-rates", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FRAME_MATCH] = { .name = "frame-match", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_ACK] = { .name = "ack", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_PS_STATE] = { .name = "ps-state", .type = YNL_PT_U32, },
	[NL80211_ATTR_CQM] = { .name = "cqm", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_LOCAL_STATE_CHANGE] = { .name = "local-state-change", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_AP_ISOLATE] = { .name = "ap-isolate", .type = YNL_PT_U8, },
	[NL80211_ATTR_WIPHY_TX_POWER_SETTING] = { .name = "wiphy-tx-power-setting", .type = YNL_PT_U32, },
	[NL80211_ATTR_WIPHY_TX_POWER_LEVEL] = { .name = "wiphy-tx-power-level", .type = YNL_PT_U32, },
	[NL80211_ATTR_TX_FRAME_TYPES] = { .name = "tx-frame-types", .type = YNL_PT_NEST, .nest = &nl80211_iftype_attrs_nest, },
	[NL80211_ATTR_RX_FRAME_TYPES] = { .name = "rx-frame-types", .type = YNL_PT_NEST, .nest = &nl80211_iftype_attrs_nest, },
	[NL80211_ATTR_FRAME_TYPE] = { .name = "frame-type", .type = YNL_PT_U16, },
	[NL80211_ATTR_CONTROL_PORT_ETHERTYPE] = { .name = "control-port-ethertype", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT] = { .name = "control-port-no-encrypt", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_SUPPORT_IBSS_RSN] = { .name = "support-ibss-rsn", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_WIPHY_ANTENNA_TX] = { .name = "wiphy-antenna-tx", .type = YNL_PT_U32, },
	[NL80211_ATTR_WIPHY_ANTENNA_RX] = { .name = "wiphy-antenna-rx", .type = YNL_PT_U32, },
	[NL80211_ATTR_MCAST_RATE] = { .name = "mcast-rate", .type = YNL_PT_U32, },
	[NL80211_ATTR_OFFCHANNEL_TX_OK] = { .name = "offchannel-tx-ok", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_BSS_HT_OPMODE] = { .name = "bss-ht-opmode", .type = YNL_PT_U16, },
	[NL80211_ATTR_KEY_DEFAULT_TYPES] = { .name = "key-default-types", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION] = { .name = "max-remain-on-channel-duration", .type = YNL_PT_U32, },
	[NL80211_ATTR_MESH_SETUP] = { .name = "mesh-setup", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX] = { .name = "wiphy-antenna-avail-tx", .type = YNL_PT_U32, },
	[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX] = { .name = "wiphy-antenna-avail-rx", .type = YNL_PT_U32, },
	[NL80211_ATTR_SUPPORT_MESH_AUTH] = { .name = "support-mesh-auth", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_STA_PLINK_STATE] = { .name = "sta-plink-state", .type = YNL_PT_U8, },
	[NL80211_ATTR_WOWLAN_TRIGGERS] = { .name = "wowlan-triggers", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED] = { .name = "wowlan-triggers-supported", .type = YNL_PT_NEST, .nest = &nl80211_wowlan_triggers_attrs_nest, },
	[NL80211_ATTR_SCHED_SCAN_INTERVAL] = { .name = "sched-scan-interval", .type = YNL_PT_U32, },
	[NL80211_ATTR_INTERFACE_COMBINATIONS] = { .name = "interface-combinations", .type = YNL_PT_NEST, .nest = &nl80211_if_combination_attributes_nest, },
	[NL80211_ATTR_SOFTWARE_IFTYPES] = { .name = "software-iftypes", .type = YNL_PT_NEST, .nest = &nl80211_supported_iftypes_nest, },
	[NL80211_ATTR_REKEY_DATA] = { .name = "rekey-data", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS] = { .name = "max-num-sched-scan-ssids", .type = YNL_PT_U8, },
	[NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN] = { .name = "max-sched-scan-ie-len", .type = YNL_PT_U16, },
	[NL80211_ATTR_SCAN_SUPP_RATES] = { .name = "scan-supp-rates", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_HIDDEN_SSID] = { .name = "hidden-ssid", .type = YNL_PT_U32, },
	[NL80211_ATTR_IE_PROBE_RESP] = { .name = "ie-probe-resp", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_IE_ASSOC_RESP] = { .name = "ie-assoc-resp", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_STA_WME] = { .name = "sta-wme", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SUPPORT_AP_UAPSD] = { .name = "support-ap-uapsd", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_ROAM_SUPPORT] = { .name = "roam-support", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_SCHED_SCAN_MATCH] = { .name = "sched-scan-match", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MAX_MATCH_SETS] = { .name = "max-match-sets", .type = YNL_PT_U8, },
	[NL80211_ATTR_PMKSA_CANDIDATE] = { .name = "pmksa-candidate", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_TX_NO_CCK_RATE] = { .name = "tx-no-cck-rate", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_TDLS_ACTION] = { .name = "tdls-action", .type = YNL_PT_U8, },
	[NL80211_ATTR_TDLS_DIALOG_TOKEN] = { .name = "tdls-dialog-token", .type = YNL_PT_U8, },
	[NL80211_ATTR_TDLS_OPERATION] = { .name = "tdls-operation", .type = YNL_PT_U8, },
	[NL80211_ATTR_TDLS_SUPPORT] = { .name = "tdls-support", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_TDLS_EXTERNAL_SETUP] = { .name = "tdls-external-setup", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_DEVICE_AP_SME] = { .name = "device-ap-sme", .type = YNL_PT_U32, },
	[NL80211_ATTR_DONT_WAIT_FOR_ACK] = { .name = "dont-wait-for-ack", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_FEATURE_FLAGS] = { .name = "feature-flags", .type = YNL_PT_U32, },
	[NL80211_ATTR_PROBE_RESP_OFFLOAD] = { .name = "probe-resp-offload", .type = YNL_PT_U32, },
	[NL80211_ATTR_PROBE_RESP] = { .name = "probe-resp", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_DFS_REGION] = { .name = "dfs-region", .type = YNL_PT_U8, },
	[NL80211_ATTR_DISABLE_HT] = { .name = "disable-ht", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_HT_CAPABILITY_MASK] = { .name = "ht-capability-mask", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_NOACK_MAP] = { .name = "noack-map", .type = YNL_PT_U16, },
	[NL80211_ATTR_INACTIVITY_TIMEOUT] = { .name = "inactivity-timeout", .type = YNL_PT_U16, },
	[NL80211_ATTR_RX_SIGNAL_DBM] = { .name = "rx-signal-dbm", .type = YNL_PT_U32, },
	[NL80211_ATTR_BG_SCAN_PERIOD] = { .name = "bg-scan-period", .type = YNL_PT_U16, },
	[NL80211_ATTR_WDEV] = { .name = "wdev", .type = YNL_PT_U64, },
	[NL80211_ATTR_USER_REG_HINT_TYPE] = { .name = "user-reg-hint-type", .type = YNL_PT_U32, },
	[NL80211_ATTR_CONN_FAILED_REASON] = { .name = "conn-failed-reason", .type = YNL_PT_U32, },
	[NL80211_ATTR_AUTH_DATA] = { .name = "auth-data", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_VHT_CAPABILITY] = { .name = "vht-capability", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SCAN_FLAGS] = { .name = "scan-flags", .type = YNL_PT_U32, },
	[NL80211_ATTR_CHANNEL_WIDTH] = { .name = "channel-width", .type = YNL_PT_U32, },
	[NL80211_ATTR_CENTER_FREQ1] = { .name = "center-freq1", .type = YNL_PT_U32, },
	[NL80211_ATTR_CENTER_FREQ2] = { .name = "center-freq2", .type = YNL_PT_U32, },
	[NL80211_ATTR_P2P_CTWINDOW] = { .name = "p2p-ctwindow", .type = YNL_PT_U8, },
	[NL80211_ATTR_P2P_OPPPS] = { .name = "p2p-oppps", .type = YNL_PT_U8, },
	[NL80211_ATTR_LOCAL_MESH_POWER_MODE] = { .name = "local-mesh-power-mode", .type = YNL_PT_U32, },
	[NL80211_ATTR_ACL_POLICY] = { .name = "acl-policy", .type = YNL_PT_U32, },
	[NL80211_ATTR_MAC_ADDRS] = { .name = "mac-addrs", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MAC_ACL_MAX] = { .name = "mac-acl-max", .type = YNL_PT_U32, },
	[NL80211_ATTR_RADAR_EVENT] = { .name = "radar-event", .type = YNL_PT_U32, },
	[NL80211_ATTR_EXT_CAPA] = { .name = "ext-capa", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_EXT_CAPA_MASK] = { .name = "ext-capa-mask", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_STA_CAPABILITY] = { .name = "sta-capability", .type = YNL_PT_U16, },
	[NL80211_ATTR_STA_EXT_CAPABILITY] = { .name = "sta-ext-capability", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_PROTOCOL_FEATURES] = { .name = "protocol-features", .type = YNL_PT_U32, },
	[NL80211_ATTR_SPLIT_WIPHY_DUMP] = { .name = "split-wiphy-dump", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_DISABLE_VHT] = { .name = "disable-vht", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_VHT_CAPABILITY_MASK] = { .name = "vht-capability-mask", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MDID] = { .name = "mdid", .type = YNL_PT_U16, },
	[NL80211_ATTR_IE_RIC] = { .name = "ie-ric", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_CRIT_PROT_ID] = { .name = "crit-prot-id", .type = YNL_PT_U16, },
	[NL80211_ATTR_MAX_CRIT_PROT_DURATION] = { .name = "max-crit-prot-duration", .type = YNL_PT_U16, },
	[NL80211_ATTR_PEER_AID] = { .name = "peer-aid", .type = YNL_PT_U16, },
	[NL80211_ATTR_COALESCE_RULE] = { .name = "coalesce-rule", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_CH_SWITCH_COUNT] = { .name = "ch-switch-count", .type = YNL_PT_U32, },
	[NL80211_ATTR_CH_SWITCH_BLOCK_TX] = { .name = "ch-switch-block-tx", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_CSA_IES] = { .name = "csa-ies", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_CNTDWN_OFFS_BEACON] = { .name = "cntdwn-offs-beacon", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_CNTDWN_OFFS_PRESP] = { .name = "cntdwn-offs-presp", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_RXMGMT_FLAGS] = { .name = "rxmgmt-flags", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_STA_SUPPORTED_CHANNELS] = { .name = "sta-supported-channels", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES] = { .name = "sta-supported-oper-classes", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_HANDLE_DFS] = { .name = "handle-dfs", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_SUPPORT_5_MHZ] = { .name = "support-5-mhz", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_SUPPORT_10_MHZ] = { .name = "support-10-mhz", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_OPMODE_NOTIF] = { .name = "opmode-notif", .type = YNL_PT_U8, },
	[NL80211_ATTR_VENDOR_ID] = { .name = "vendor-id", .type = YNL_PT_U32, },
	[NL80211_ATTR_VENDOR_SUBCMD] = { .name = "vendor-subcmd", .type = YNL_PT_U32, },
	[NL80211_ATTR_VENDOR_DATA] = { .name = "vendor-data", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_VENDOR_EVENTS] = { .name = "vendor-events", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_QOS_MAP] = { .name = "qos-map", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MAC_HINT] = { .name = "mac-hint", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_WIPHY_FREQ_HINT] = { .name = "wiphy-freq-hint", .type = YNL_PT_U32, },
	[NL80211_ATTR_MAX_AP_ASSOC_STA] = { .name = "max-ap-assoc-sta", .type = YNL_PT_U32, },
	[NL80211_ATTR_TDLS_PEER_CAPABILITY] = { .name = "tdls-peer-capability", .type = YNL_PT_U32, },
	[NL80211_ATTR_SOCKET_OWNER] = { .name = "socket-owner", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_CSA_C_OFFSETS_TX] = { .name = "csa-c-offsets-tx", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MAX_CSA_COUNTERS] = { .name = "max-csa-counters", .type = YNL_PT_U8, },
	[NL80211_ATTR_TDLS_INITIATOR] = { .name = "tdls-initiator", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_USE_RRM] = { .name = "use-rrm", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_WIPHY_DYN_ACK] = { .name = "wiphy-dyn-ack", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_TSID] = { .name = "tsid", .type = YNL_PT_U8, },
	[NL80211_ATTR_USER_PRIO] = { .name = "user-prio", .type = YNL_PT_U8, },
	[NL80211_ATTR_ADMITTED_TIME] = { .name = "admitted-time", .type = YNL_PT_U16, },
	[NL80211_ATTR_SMPS_MODE] = { .name = "smps-mode", .type = YNL_PT_U8, },
	[NL80211_ATTR_OPER_CLASS] = { .name = "oper-class", .type = YNL_PT_U8, },
	[NL80211_ATTR_MAC_MASK] = { .name = "mac-mask", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_WIPHY_SELF_MANAGED_REG] = { .name = "wiphy-self-managed-reg", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_EXT_FEATURES] = { .name = "ext-features", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SURVEY_RADIO_STATS] = { .name = "survey-radio-stats", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_NETNS_FD] = { .name = "netns-fd", .type = YNL_PT_U32, },
	[NL80211_ATTR_SCHED_SCAN_DELAY] = { .name = "sched-scan-delay", .type = YNL_PT_U32, },
	[NL80211_ATTR_REG_INDOOR] = { .name = "reg-indoor", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS] = { .name = "max-num-sched-scan-plans", .type = YNL_PT_U32, },
	[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL] = { .name = "max-scan-plan-interval", .type = YNL_PT_U32, },
	[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS] = { .name = "max-scan-plan-iterations", .type = YNL_PT_U32, },
	[NL80211_ATTR_SCHED_SCAN_PLANS] = { .name = "sched-scan-plans", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_PBSS] = { .name = "pbss", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_BSS_SELECT] = { .name = "bss-select", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_STA_SUPPORT_P2P_PS] = { .name = "sta-support-p2p-ps", .type = YNL_PT_U8, },
	[NL80211_ATTR_PAD] = { .name = "pad", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_IFTYPE_EXT_CAPA] = { .name = "iftype-ext-capa", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MU_MIMO_GROUP_DATA] = { .name = "mu-mimo-group-data", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR] = { .name = "mu-mimo-follow-mac-addr", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SCAN_START_TIME_TSF] = { .name = "scan-start-time-tsf", .type = YNL_PT_U64, },
	[NL80211_ATTR_SCAN_START_TIME_TSF_BSSID] = { .name = "scan-start-time-tsf-bssid", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MEASUREMENT_DURATION] = { .name = "measurement-duration", .type = YNL_PT_U16, },
	[NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY] = { .name = "measurement-duration-mandatory", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_MESH_PEER_AID] = { .name = "mesh-peer-aid", .type = YNL_PT_U16, },
	[NL80211_ATTR_NAN_MASTER_PREF] = { .name = "nan-master-pref", .type = YNL_PT_U8, },
	[NL80211_ATTR_BANDS] = { .name = "bands", .type = YNL_PT_U32, },
	[NL80211_ATTR_NAN_FUNC] = { .name = "nan-func", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_NAN_MATCH] = { .name = "nan-match", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FILS_KEK] = { .name = "fils-kek", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FILS_NONCES] = { .name = "fils-nonces", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED] = { .name = "multicast-to-unicast-enabled", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_BSSID] = { .name = "bssid", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI] = { .name = "sched-scan-relative-rssi", .type = YNL_PT_U8, },
	[NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST] = { .name = "sched-scan-rssi-adjust", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_TIMEOUT_REASON] = { .name = "timeout-reason", .type = YNL_PT_U32, },
	[NL80211_ATTR_FILS_ERP_USERNAME] = { .name = "fils-erp-username", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FILS_ERP_REALM] = { .name = "fils-erp-realm", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM] = { .name = "fils-erp-next-seq-num", .type = YNL_PT_U16, },
	[NL80211_ATTR_FILS_ERP_RRK] = { .name = "fils-erp-rrk", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FILS_CACHE_ID] = { .name = "fils-cache-id", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_PMK] = { .name = "pmk", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SCHED_SCAN_MULTI] = { .name = "sched-scan-multi", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_SCHED_SCAN_MAX_REQS] = { .name = "sched-scan-max-reqs", .type = YNL_PT_U32, },
	[NL80211_ATTR_WANT_1X_4WAY_HS] = { .name = "want-1x-4way-hs", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_PMKR0_NAME] = { .name = "pmkr0-name", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_PORT_AUTHORIZED] = { .name = "port-authorized", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_EXTERNAL_AUTH_ACTION] = { .name = "external-auth-action", .type = YNL_PT_U32, },
	[NL80211_ATTR_EXTERNAL_AUTH_SUPPORT] = { .name = "external-auth-support", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_NSS] = { .name = "nss", .type = YNL_PT_U8, },
	[NL80211_ATTR_ACK_SIGNAL] = { .name = "ack-signal", .type = YNL_PT_U32, },
	[NL80211_ATTR_CONTROL_PORT_OVER_NL80211] = { .name = "control-port-over-nl80211", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_TXQ_STATS] = { .name = "txq-stats", .type = YNL_PT_NEST, .nest = &nl80211_txq_stats_attrs_nest, },
	[NL80211_ATTR_TXQ_LIMIT] = { .name = "txq-limit", .type = YNL_PT_U32, },
	[NL80211_ATTR_TXQ_MEMORY_LIMIT] = { .name = "txq-memory-limit", .type = YNL_PT_U32, },
	[NL80211_ATTR_TXQ_QUANTUM] = { .name = "txq-quantum", .type = YNL_PT_U32, },
	[NL80211_ATTR_HE_CAPABILITY] = { .name = "he-capability", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FTM_RESPONDER] = { .name = "ftm-responder", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FTM_RESPONDER_STATS] = { .name = "ftm-responder-stats", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_TIMEOUT] = { .name = "timeout", .type = YNL_PT_U32, },
	[NL80211_ATTR_PEER_MEASUREMENTS] = { .name = "peer-measurements", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_AIRTIME_WEIGHT] = { .name = "airtime-weight", .type = YNL_PT_U16, },
	[NL80211_ATTR_STA_TX_POWER_SETTING] = { .name = "sta-tx-power-setting", .type = YNL_PT_U8, },
	[NL80211_ATTR_STA_TX_POWER] = { .name = "sta-tx-power", .type = YNL_PT_U16, },
	[NL80211_ATTR_SAE_PASSWORD] = { .name = "sae-password", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_TWT_RESPONDER] = { .name = "twt-responder", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_HE_OBSS_PD] = { .name = "he-obss-pd", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_WIPHY_EDMG_CHANNELS] = { .name = "wiphy-edmg-channels", .type = YNL_PT_U8, },
	[NL80211_ATTR_WIPHY_EDMG_BW_CONFIG] = { .name = "wiphy-edmg-bw-config", .type = YNL_PT_U8, },
	[NL80211_ATTR_VLAN_ID] = { .name = "vlan-id", .type = YNL_PT_U16, },
	[NL80211_ATTR_HE_BSS_COLOR] = { .name = "he-bss-color", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_IFTYPE_AKM_SUITES] = { .name = "iftype-akm-suites", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_TID_CONFIG] = { .name = "tid-config", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_CONTROL_PORT_NO_PREAUTH] = { .name = "control-port-no-preauth", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_PMK_LIFETIME] = { .name = "pmk-lifetime", .type = YNL_PT_U32, },
	[NL80211_ATTR_PMK_REAUTH_THRESHOLD] = { .name = "pmk-reauth-threshold", .type = YNL_PT_U8, },
	[NL80211_ATTR_RECEIVE_MULTICAST] = { .name = "receive-multicast", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_WIPHY_FREQ_OFFSET] = { .name = "wiphy-freq-offset", .type = YNL_PT_U32, },
	[NL80211_ATTR_CENTER_FREQ1_OFFSET] = { .name = "center-freq1-offset", .type = YNL_PT_U32, },
	[NL80211_ATTR_SCAN_FREQ_KHZ] = { .name = "scan-freq-khz", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_HE_6GHZ_CAPABILITY] = { .name = "he-6ghz-capability", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_FILS_DISCOVERY] = { .name = "fils-discovery", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_UNSOL_BCAST_PROBE_RESP] = { .name = "unsol-bcast-probe-resp", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_S1G_CAPABILITY] = { .name = "s1g-capability", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_S1G_CAPABILITY_MASK] = { .name = "s1g-capability-mask", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SAE_PWE] = { .name = "sae-pwe", .type = YNL_PT_U8, },
	[NL80211_ATTR_RECONNECT_REQUESTED] = { .name = "reconnect-requested", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_SAR_SPEC] = { .name = "sar-spec", .type = YNL_PT_NEST, .nest = &nl80211_sar_attributes_nest, },
	[NL80211_ATTR_DISABLE_HE] = { .name = "disable-he", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_OBSS_COLOR_BITMAP] = { .name = "obss-color-bitmap", .type = YNL_PT_U64, },
	[NL80211_ATTR_COLOR_CHANGE_COUNT] = { .name = "color-change-count", .type = YNL_PT_U8, },
	[NL80211_ATTR_COLOR_CHANGE_COLOR] = { .name = "color-change-color", .type = YNL_PT_U8, },
	[NL80211_ATTR_COLOR_CHANGE_ELEMS] = { .name = "color-change-elems", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MBSSID_CONFIG] = { .name = "mbssid-config", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MBSSID_ELEMS] = { .name = "mbssid-elems", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_RADAR_BACKGROUND] = { .name = "radar-background", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_AP_SETTINGS_FLAGS] = { .name = "ap-settings-flags", .type = YNL_PT_U32, },
	[NL80211_ATTR_EHT_CAPABILITY] = { .name = "eht-capability", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_DISABLE_EHT] = { .name = "disable-eht", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_MLO_LINKS] = { .name = "mlo-links", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MLO_LINK_ID] = { .name = "mlo-link-id", .type = YNL_PT_U8, },
	[NL80211_ATTR_MLD_ADDR] = { .name = "mld-addr", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MLO_SUPPORT] = { .name = "mlo-support", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_MAX_NUM_AKM_SUITES] = { .name = "max-num-akm-suites", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_EML_CAPABILITY] = { .name = "eml-capability", .type = YNL_PT_U16, },
	[NL80211_ATTR_MLD_CAPA_AND_OPS] = { .name = "mld-capa-and-ops", .type = YNL_PT_U16, },
	[NL80211_ATTR_TX_HW_TIMESTAMP] = { .name = "tx-hw-timestamp", .type = YNL_PT_U64, },
	[NL80211_ATTR_RX_HW_TIMESTAMP] = { .name = "rx-hw-timestamp", .type = YNL_PT_U64, },
	[NL80211_ATTR_TD_BITMAP] = { .name = "td-bitmap", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_PUNCT_BITMAP] = { .name = "punct-bitmap", .type = YNL_PT_U32, },
	[NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS] = { .name = "max-hw-timestamp-peers", .type = YNL_PT_U16, },
	[NL80211_ATTR_HW_TIMESTAMP_ENABLED] = { .name = "hw-timestamp-enabled", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_EMA_RNR_ELEMS] = { .name = "ema-rnr-elems", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_MLO_LINK_DISABLED] = { .name = "mlo-link-disabled", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_BSS_DUMP_INCLUDE_USE_DATA] = { .name = "bss-dump-include-use-data", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_MLO_TTLM_DLINK] = { .name = "mlo-ttlm-dlink", .type = YNL_PT_U16, },
	[NL80211_ATTR_MLO_TTLM_ULINK] = { .name = "mlo-ttlm-ulink", .type = YNL_PT_U16, },
	[NL80211_ATTR_ASSOC_SPP_AMSDU] = { .name = "assoc-spp-amsdu", .type = YNL_PT_FLAG, },
	[NL80211_ATTR_WIPHY_RADIOS] = { .name = "wiphy-radios", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS] = { .name = "wiphy-interface-combinations", .type = YNL_PT_BINARY,},
	[NL80211_ATTR_VIF_RADIO_MASK] = { .name = "vif-radio-mask", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest nl80211_nl80211_attrs_nest = {
	.max_attr = NUM_NL80211_ATTR,
	.table = nl80211_nl80211_attrs_policy,
};

/* Common nested types */
void nl80211_supported_iftypes_free(struct nl80211_supported_iftypes *obj)
{
}

int nl80211_supported_iftypes_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested)
{
	struct nl80211_supported_iftypes *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_IFTYPE_ADHOC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.adhoc = 1;
		} else if (type == NL80211_IFTYPE_STATION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.station = 1;
		} else if (type == NL80211_IFTYPE_AP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ap = 1;
		} else if (type == NL80211_IFTYPE_AP_VLAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ap_vlan = 1;
		} else if (type == NL80211_IFTYPE_WDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wds = 1;
		} else if (type == NL80211_IFTYPE_MONITOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.monitor = 1;
		} else if (type == NL80211_IFTYPE_MESH_POINT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mesh_point = 1;
		} else if (type == NL80211_IFTYPE_P2P_CLIENT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.p2p_client = 1;
		} else if (type == NL80211_IFTYPE_P2P_GO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.p2p_go = 1;
		} else if (type == NL80211_IFTYPE_P2P_DEVICE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.p2p_device = 1;
		} else if (type == NL80211_IFTYPE_OCB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ocb = 1;
		} else if (type == NL80211_IFTYPE_NAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nan = 1;
		}
	}

	return 0;
}

void
nl80211_wowlan_triggers_attrs_free(struct nl80211_wowlan_triggers_attrs *obj)
{
}

int nl80211_wowlan_triggers_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	struct nl80211_wowlan_triggers_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_WOWLAN_TRIG_ANY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.any = 1;
		} else if (type == NL80211_WOWLAN_TRIG_DISCONNECT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.disconnect = 1;
		} else if (type == NL80211_WOWLAN_TRIG_MAGIC_PKT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.magic_pkt = 1;
		} else if (type == NL80211_WOWLAN_TRIG_PKT_PATTERN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pkt_pattern = 1;
		} else if (type == NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gtk_rekey_supported = 1;
		} else if (type == NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gtk_rekey_failure = 1;
		} else if (type == NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.eap_ident_request = 1;
		} else if (type == NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._4way_handshake = 1;
		} else if (type == NL80211_WOWLAN_TRIG_RFKILL_RELEASE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rfkill_release = 1;
		} else if (type == NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wakeup_pkt_80211 = 1;
		} else if (type == NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wakeup_pkt_80211_len = 1;
		} else if (type == NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wakeup_pkt_8023 = 1;
		} else if (type == NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wakeup_pkt_8023_len = 1;
		} else if (type == NL80211_WOWLAN_TRIG_TCP_CONNECTION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tcp_connection = 1;
		} else if (type == NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wakeup_tcp_match = 1;
		} else if (type == NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wakeup_tcp_connlost = 1;
		} else if (type == NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wakeup_tcp_nomoretokens = 1;
		} else if (type == NL80211_WOWLAN_TRIG_NET_DETECT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.net_detect = 1;
		} else if (type == NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.net_detect_results = 1;
		} else if (type == NL80211_WOWLAN_TRIG_UNPROTECTED_DEAUTH_DISASSOC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.unprotected_deauth_disassoc = 1;
		}
	}

	return 0;
}

void nl80211_txq_stats_attrs_free(struct nl80211_txq_stats_attrs *obj)
{
}

int nl80211_txq_stats_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	struct nl80211_txq_stats_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_TXQ_STATS_BACKLOG_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.backlog_bytes = 1;
			dst->backlog_bytes = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_BACKLOG_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.backlog_packets = 1;
			dst->backlog_packets = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_FLOWS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flows = 1;
			dst->flows = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_DROPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.drops = 1;
			dst->drops = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_ECN_MARKS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn_marks = 1;
			dst->ecn_marks = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_OVERLIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.overlimit = 1;
			dst->overlimit = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_OVERMEMORY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.overmemory = 1;
			dst->overmemory = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_COLLISIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.collisions = 1;
			dst->collisions = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_TX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tx_bytes = 1;
			dst->tx_bytes = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_TX_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tx_packets = 1;
			dst->tx_packets = ynl_attr_get_u32(attr);
		} else if (type == NL80211_TXQ_STATS_MAX_FLOWS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_flows = 1;
			dst->max_flows = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void nl80211_frame_type_attrs_free(struct nl80211_frame_type_attrs *obj)
{
}

int nl80211_frame_type_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	struct nl80211_frame_type_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_ATTR_FRAME_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.frame_type = 1;
			dst->frame_type = ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

void
nl80211_iface_limit_attributes_free(struct nl80211_iface_limit_attributes *obj)
{
	nl80211_supported_iftypes_free(&obj->types);
}

int nl80211_iface_limit_attributes_parse(struct ynl_parse_arg *yarg,
					 const struct nlattr *nested,
					 __u32 idx)
{
	struct nl80211_iface_limit_attributes *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_IFACE_LIMIT_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max = 1;
			dst->max = ynl_attr_get_u32(attr);
		} else if (type == NL80211_IFACE_LIMIT_TYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.types = 1;

			parg.rsp_policy = &nl80211_supported_iftypes_nest;
			parg.data = &dst->types;
			if (nl80211_supported_iftypes_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void nl80211_sar_specs_free(struct nl80211_sar_specs *obj)
{
}

int nl80211_sar_specs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested, __u32 idx)
{
	struct nl80211_sar_specs *dst = yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_SAR_ATTR_SPECS_POWER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.power = 1;
			dst->power = ynl_attr_get_s32(attr);
		} else if (type == NL80211_SAR_ATTR_SPECS_RANGE_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.range_index = 1;
			dst->range_index = ynl_attr_get_u32(attr);
		} else if (type == NL80211_SAR_ATTR_SPECS_START_FREQ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.start_freq = 1;
			dst->start_freq = ynl_attr_get_u32(attr);
		} else if (type == NL80211_SAR_ATTR_SPECS_END_FREQ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.end_freq = 1;
			dst->end_freq = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void nl80211_bitrate_attrs_free(struct nl80211_bitrate_attrs *obj)
{
}

int nl80211_bitrate_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested, __u32 idx)
{
	struct nl80211_bitrate_attrs *dst = yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_BITRATE_ATTR_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rate = 1;
			dst->rate = ynl_attr_get_u32(attr);
		} else if (type == NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._2ghz_shortpreamble = 1;
		}
	}

	return 0;
}

void nl80211_iftype_data_attrs_free(struct nl80211_iftype_data_attrs *obj)
{
	free(obj->iftypes);
	free(obj->he_cap_mac);
	free(obj->he_cap_phy);
	free(obj->he_cap_mcs_set);
	free(obj->he_cap_ppe);
	free(obj->he_6ghz_capa);
	free(obj->vendor_elems);
	free(obj->eht_cap_mac);
	free(obj->eht_cap_phy);
	free(obj->eht_cap_mcs_set);
	free(obj->eht_cap_ppe);
}

int nl80211_iftype_data_attrs_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested, __u32 idx)
{
	struct nl80211_iftype_data_attrs *dst = yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_BAND_IFTYPE_ATTR_IFTYPES) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.iftypes = len;
			dst->iftypes = malloc(len);
			memcpy(dst->iftypes, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.he_cap_mac = len;
			dst->he_cap_mac = malloc(len);
			memcpy(dst->he_cap_mac, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.he_cap_phy = len;
			dst->he_cap_phy = malloc(len);
			memcpy(dst->he_cap_phy, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.he_cap_mcs_set = len;
			dst->he_cap_mcs_set = malloc(len);
			memcpy(dst->he_cap_mcs_set, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.he_cap_ppe = len;
			dst->he_cap_ppe = malloc(len);
			memcpy(dst->he_cap_ppe, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.he_6ghz_capa = len;
			dst->he_6ghz_capa = malloc(len);
			memcpy(dst->he_6ghz_capa, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.vendor_elems = len;
			dst->vendor_elems = malloc(len);
			memcpy(dst->vendor_elems, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.eht_cap_mac = len;
			dst->eht_cap_mac = malloc(len);
			memcpy(dst->eht_cap_mac, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.eht_cap_phy = len;
			dst->eht_cap_phy = malloc(len);
			memcpy(dst->eht_cap_phy, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.eht_cap_mcs_set = len;
			dst->eht_cap_mcs_set = malloc(len);
			memcpy(dst->eht_cap_mcs_set, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.eht_cap_ppe = len;
			dst->eht_cap_ppe = malloc(len);
			memcpy(dst->eht_cap_ppe, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void nl80211_wmm_attrs_free(struct nl80211_wmm_attrs *obj)
{
}

int nl80211_wmm_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested, __u32 idx)
{
	struct nl80211_wmm_attrs *dst = yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_WMMR_CW_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cw_min = 1;
			dst->cw_min = ynl_attr_get_u16(attr);
		} else if (type == NL80211_WMMR_CW_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cw_max = 1;
			dst->cw_max = ynl_attr_get_u16(attr);
		} else if (type == NL80211_WMMR_AIFSN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.aifsn = 1;
			dst->aifsn = ynl_attr_get_u8(attr);
		} else if (type == NL80211_WMMR_TXOP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txop = 1;
			dst->txop = ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

void nl80211_iftype_attrs_free(struct nl80211_iftype_attrs *obj)
{
	nl80211_frame_type_attrs_free(&obj->unspecified);
	nl80211_frame_type_attrs_free(&obj->adhoc);
	nl80211_frame_type_attrs_free(&obj->station);
	nl80211_frame_type_attrs_free(&obj->ap);
	nl80211_frame_type_attrs_free(&obj->ap_vlan);
	nl80211_frame_type_attrs_free(&obj->wds);
	nl80211_frame_type_attrs_free(&obj->monitor);
	nl80211_frame_type_attrs_free(&obj->mesh_point);
	nl80211_frame_type_attrs_free(&obj->p2p_client);
	nl80211_frame_type_attrs_free(&obj->p2p_go);
	nl80211_frame_type_attrs_free(&obj->p2p_device);
	nl80211_frame_type_attrs_free(&obj->ocb);
	nl80211_frame_type_attrs_free(&obj->nan);
}

int nl80211_iftype_attrs_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested)
{
	struct nl80211_iftype_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_IFTYPE_UNSPECIFIED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.unspecified = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->unspecified;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_ADHOC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.adhoc = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->adhoc;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_STATION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.station = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->station;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_AP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ap = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->ap;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_AP_VLAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ap_vlan = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->ap_vlan;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_WDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wds = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->wds;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_MONITOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.monitor = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->monitor;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_MESH_POINT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mesh_point = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->mesh_point;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_P2P_CLIENT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.p2p_client = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->p2p_client;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_P2P_GO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.p2p_go = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->p2p_go;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_P2P_DEVICE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.p2p_device = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->p2p_device;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_OCB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ocb = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->ocb;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_IFTYPE_NAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nan = 1;

			parg.rsp_policy = &nl80211_frame_type_attrs_nest;
			parg.data = &dst->nan;
			if (nl80211_frame_type_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void
nl80211_if_combination_attributes_free(struct nl80211_if_combination_attributes *obj)
{
	free(obj->limits);
}

int nl80211_if_combination_attributes_parse(struct ynl_parse_arg *yarg,
					    const struct nlattr *nested,
					    __u32 idx)
{
	struct nl80211_if_combination_attributes *dst = yarg->data;
	const struct nlattr *attr_limits;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_limits = 0;
	int i;

	parg.ys = yarg->ys;

	dst->idx = idx;
	if (dst->limits)
		return ynl_error_parse(yarg, "attribute already present (if-combination-attributes.limits)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_IFACE_COMB_LIMITS) {
			const struct nlattr *attr2;

			attr_limits = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.limits++;
			}
		} else if (type == NL80211_IFACE_COMB_MAXNUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.maxnum = 1;
			dst->maxnum = ynl_attr_get_u32(attr);
		} else if (type == NL80211_IFACE_COMB_STA_AP_BI_MATCH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sta_ap_bi_match = 1;
		} else if (type == NL80211_IFACE_COMB_NUM_CHANNELS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.num_channels = 1;
			dst->num_channels = ynl_attr_get_u32(attr);
		} else if (type == NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.radar_detect_widths = 1;
			dst->radar_detect_widths = ynl_attr_get_u32(attr);
		} else if (type == NL80211_IFACE_COMB_RADAR_DETECT_REGIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.radar_detect_regions = 1;
			dst->radar_detect_regions = ynl_attr_get_u32(attr);
		} else if (type == NL80211_IFACE_COMB_BI_MIN_GCD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bi_min_gcd = 1;
			dst->bi_min_gcd = ynl_attr_get_u32(attr);
		}
	}

	if (n_limits) {
		dst->limits = calloc(n_limits, sizeof(*dst->limits));
		dst->_count.limits = n_limits;
		i = 0;
		parg.rsp_policy = &nl80211_iface_limit_attributes_nest;
		ynl_attr_for_each_nested(attr, attr_limits) {
			parg.data = &dst->limits[i];
			if (nl80211_iface_limit_attributes_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void nl80211_sar_attributes_free(struct nl80211_sar_attributes *obj)
{
	free(obj->specs);
}

int nl80211_sar_attributes_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	struct nl80211_sar_attributes *dst = yarg->data;
	const struct nlattr *attr_specs;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_specs = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->specs)
		return ynl_error_parse(yarg, "attribute already present (sar-attributes.specs)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_SAR_ATTR_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.type = 1;
			dst->type = ynl_attr_get_u32(attr);
		} else if (type == NL80211_SAR_ATTR_SPECS) {
			const struct nlattr *attr2;

			attr_specs = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.specs++;
			}
		}
	}

	if (n_specs) {
		dst->specs = calloc(n_specs, sizeof(*dst->specs));
		dst->_count.specs = n_specs;
		i = 0;
		parg.rsp_policy = &nl80211_sar_specs_nest;
		ynl_attr_for_each_nested(attr, attr_specs) {
			parg.data = &dst->specs[i];
			if (nl80211_sar_specs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void nl80211_frequency_attrs_free(struct nl80211_frequency_attrs *obj)
{
	free(obj->dfs_time);
	free(obj->no_ht40_minus);
	free(obj->no_ht40_plus);
	free(obj->no_80mhz);
	free(obj->no_160mhz);
	free(obj->dfs_cac_time);
	free(obj->indoor_only);
	free(obj->ir_concurrent);
	free(obj->no_20mhz);
	free(obj->no_10mhz);
	free(obj->wmm);
	free(obj->no_he);
	free(obj->_1mhz);
	free(obj->_2mhz);
	free(obj->_4mhz);
	free(obj->_8mhz);
	free(obj->_16mhz);
	free(obj->no_320mhz);
	free(obj->no_eht);
	free(obj->psd);
	free(obj->dfs_concurrent);
	free(obj->no_6ghz_vlp_client);
	free(obj->no_6ghz_afc_client);
	free(obj->can_monitor);
	free(obj->allow_6ghz_vlp_ap);
}

int nl80211_frequency_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested, __u32 idx)
{
	struct nl80211_frequency_attrs *dst = yarg->data;
	const struct nlattr *attr_wmm;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_wmm = 0;
	int i;

	parg.ys = yarg->ys;

	dst->idx = idx;
	if (dst->wmm)
		return ynl_error_parse(yarg, "attribute already present (frequency-attrs.wmm)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_FREQUENCY_ATTR_FREQ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.freq = 1;
			dst->freq = ynl_attr_get_u32(attr);
		} else if (type == NL80211_FREQUENCY_ATTR_DISABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.disabled = 1;
		} else if (type == NL80211_FREQUENCY_ATTR_NO_IR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.no_ir = 1;
		} else if (type == __NL80211_FREQUENCY_ATTR_NO_IBSS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.no_ibss = 1;
		} else if (type == NL80211_FREQUENCY_ATTR_RADAR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.radar = 1;
		} else if (type == NL80211_FREQUENCY_ATTR_MAX_TX_POWER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_tx_power = 1;
			dst->max_tx_power = ynl_attr_get_u32(attr);
		} else if (type == NL80211_FREQUENCY_ATTR_DFS_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dfs_state = 1;
			dst->dfs_state = ynl_attr_get_u32(attr);
		} else if (type == NL80211_FREQUENCY_ATTR_DFS_TIME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dfs_time = len;
			dst->dfs_time = malloc(len);
			memcpy(dst->dfs_time, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_HT40_MINUS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_ht40_minus = len;
			dst->no_ht40_minus = malloc(len);
			memcpy(dst->no_ht40_minus, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_HT40_PLUS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_ht40_plus = len;
			dst->no_ht40_plus = malloc(len);
			memcpy(dst->no_ht40_plus, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_80MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_80mhz = len;
			dst->no_80mhz = malloc(len);
			memcpy(dst->no_80mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_160MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_160mhz = len;
			dst->no_160mhz = malloc(len);
			memcpy(dst->no_160mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_DFS_CAC_TIME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dfs_cac_time = len;
			dst->dfs_cac_time = malloc(len);
			memcpy(dst->dfs_cac_time, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_INDOOR_ONLY) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.indoor_only = len;
			dst->indoor_only = malloc(len);
			memcpy(dst->indoor_only, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_IR_CONCURRENT) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ir_concurrent = len;
			dst->ir_concurrent = malloc(len);
			memcpy(dst->ir_concurrent, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_20MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_20mhz = len;
			dst->no_20mhz = malloc(len);
			memcpy(dst->no_20mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_10MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_10mhz = len;
			dst->no_10mhz = malloc(len);
			memcpy(dst->no_10mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_WMM) {
			const struct nlattr *attr2;

			attr_wmm = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.wmm++;
			}
		} else if (type == NL80211_FREQUENCY_ATTR_NO_HE) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_he = len;
			dst->no_he = malloc(len);
			memcpy(dst->no_he, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_OFFSET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.offset = 1;
			dst->offset = ynl_attr_get_u32(attr);
		} else if (type == NL80211_FREQUENCY_ATTR_1MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len._1mhz = len;
			dst->_1mhz = malloc(len);
			memcpy(dst->_1mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_2MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len._2mhz = len;
			dst->_2mhz = malloc(len);
			memcpy(dst->_2mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_4MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len._4mhz = len;
			dst->_4mhz = malloc(len);
			memcpy(dst->_4mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_8MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len._8mhz = len;
			dst->_8mhz = malloc(len);
			memcpy(dst->_8mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_16MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len._16mhz = len;
			dst->_16mhz = malloc(len);
			memcpy(dst->_16mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_320MHZ) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_320mhz = len;
			dst->no_320mhz = malloc(len);
			memcpy(dst->no_320mhz, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_EHT) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_eht = len;
			dst->no_eht = malloc(len);
			memcpy(dst->no_eht, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_PSD) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.psd = len;
			dst->psd = malloc(len);
			memcpy(dst->psd, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_DFS_CONCURRENT) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dfs_concurrent = len;
			dst->dfs_concurrent = malloc(len);
			memcpy(dst->dfs_concurrent, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_6ghz_vlp_client = len;
			dst->no_6ghz_vlp_client = malloc(len);
			memcpy(dst->no_6ghz_vlp_client, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.no_6ghz_afc_client = len;
			dst->no_6ghz_afc_client = malloc(len);
			memcpy(dst->no_6ghz_afc_client, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_CAN_MONITOR) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.can_monitor = len;
			dst->can_monitor = malloc(len);
			memcpy(dst->can_monitor, ynl_attr_data(attr), len);
		} else if (type == NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.allow_6ghz_vlp_ap = len;
			dst->allow_6ghz_vlp_ap = malloc(len);
			memcpy(dst->allow_6ghz_vlp_ap, ynl_attr_data(attr), len);
		}
	}

	if (n_wmm) {
		dst->wmm = calloc(n_wmm, sizeof(*dst->wmm));
		dst->_count.wmm = n_wmm;
		i = 0;
		parg.rsp_policy = &nl80211_wmm_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_wmm) {
			parg.data = &dst->wmm[i];
			if (nl80211_wmm_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void nl80211_band_attrs_free(struct nl80211_band_attrs *obj)
{
	free(obj->freqs);
	free(obj->rates);
	free(obj->ht_mcs_set);
	free(obj->vht_mcs_set);
	free(obj->iftype_data);
	free(obj->edmg_channels);
	free(obj->edmg_bw_config);
	free(obj->s1g_mcs_nss_set);
	free(obj->s1g_capa);
}

int nl80211_band_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	struct nl80211_band_attrs *dst = yarg->data;
	const struct nlattr *attr_iftype_data;
	const struct nlattr *attr_freqs;
	const struct nlattr *attr_rates;
	unsigned int n_iftype_data = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_freqs = 0;
	unsigned int n_rates = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->freqs)
		return ynl_error_parse(yarg, "attribute already present (band-attrs.freqs)");
	if (dst->iftype_data)
		return ynl_error_parse(yarg, "attribute already present (band-attrs.iftype-data)");
	if (dst->rates)
		return ynl_error_parse(yarg, "attribute already present (band-attrs.rates)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_BAND_ATTR_FREQS) {
			const struct nlattr *attr2;

			attr_freqs = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.freqs++;
			}
		} else if (type == NL80211_BAND_ATTR_RATES) {
			const struct nlattr *attr2;

			attr_rates = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.rates++;
			}
		} else if (type == NL80211_BAND_ATTR_HT_MCS_SET) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ht_mcs_set = len;
			dst->ht_mcs_set = malloc(len);
			memcpy(dst->ht_mcs_set, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_ATTR_HT_CAPA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ht_capa = 1;
			dst->ht_capa = ynl_attr_get_u16(attr);
		} else if (type == NL80211_BAND_ATTR_HT_AMPDU_FACTOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ht_ampdu_factor = 1;
			dst->ht_ampdu_factor = ynl_attr_get_u8(attr);
		} else if (type == NL80211_BAND_ATTR_HT_AMPDU_DENSITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ht_ampdu_density = 1;
			dst->ht_ampdu_density = ynl_attr_get_u8(attr);
		} else if (type == NL80211_BAND_ATTR_VHT_MCS_SET) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.vht_mcs_set = len;
			dst->vht_mcs_set = malloc(len);
			memcpy(dst->vht_mcs_set, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_ATTR_VHT_CAPA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vht_capa = 1;
			dst->vht_capa = ynl_attr_get_u32(attr);
		} else if (type == NL80211_BAND_ATTR_IFTYPE_DATA) {
			const struct nlattr *attr2;

			attr_iftype_data = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.iftype_data++;
			}
		} else if (type == NL80211_BAND_ATTR_EDMG_CHANNELS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.edmg_channels = len;
			dst->edmg_channels = malloc(len);
			memcpy(dst->edmg_channels, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_ATTR_EDMG_BW_CONFIG) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.edmg_bw_config = len;
			dst->edmg_bw_config = malloc(len);
			memcpy(dst->edmg_bw_config, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_ATTR_S1G_MCS_NSS_SET) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.s1g_mcs_nss_set = len;
			dst->s1g_mcs_nss_set = malloc(len);
			memcpy(dst->s1g_mcs_nss_set, ynl_attr_data(attr), len);
		} else if (type == NL80211_BAND_ATTR_S1G_CAPA) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.s1g_capa = len;
			dst->s1g_capa = malloc(len);
			memcpy(dst->s1g_capa, ynl_attr_data(attr), len);
		}
	}

	if (n_freqs) {
		dst->freqs = calloc(n_freqs, sizeof(*dst->freqs));
		dst->_count.freqs = n_freqs;
		i = 0;
		parg.rsp_policy = &nl80211_frequency_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_freqs) {
			parg.data = &dst->freqs[i];
			if (nl80211_frequency_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}
	if (n_iftype_data) {
		dst->iftype_data = calloc(n_iftype_data, sizeof(*dst->iftype_data));
		dst->_count.iftype_data = n_iftype_data;
		i = 0;
		parg.rsp_policy = &nl80211_iftype_data_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_iftype_data) {
			parg.data = &dst->iftype_data[i];
			if (nl80211_iftype_data_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}
	if (n_rates) {
		dst->rates = calloc(n_rates, sizeof(*dst->rates));
		dst->_count.rates = n_rates;
		i = 0;
		parg.rsp_policy = &nl80211_bitrate_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_rates) {
			parg.data = &dst->rates[i];
			if (nl80211_bitrate_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void nl80211_wiphy_bands_free(struct nl80211_wiphy_bands *obj)
{
	nl80211_band_attrs_free(&obj->_2ghz);
	nl80211_band_attrs_free(&obj->_5ghz);
	nl80211_band_attrs_free(&obj->_60ghz);
	nl80211_band_attrs_free(&obj->_6ghz);
	nl80211_band_attrs_free(&obj->s1ghz);
	nl80211_band_attrs_free(&obj->lc);
}

int nl80211_wiphy_bands_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct nl80211_wiphy_bands *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_BAND_2GHZ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._2ghz = 1;

			parg.rsp_policy = &nl80211_band_attrs_nest;
			parg.data = &dst->_2ghz;
			if (nl80211_band_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_BAND_5GHZ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._5ghz = 1;

			parg.rsp_policy = &nl80211_band_attrs_nest;
			parg.data = &dst->_5ghz;
			if (nl80211_band_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_BAND_60GHZ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._60ghz = 1;

			parg.rsp_policy = &nl80211_band_attrs_nest;
			parg.data = &dst->_60ghz;
			if (nl80211_band_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_BAND_6GHZ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._6ghz = 1;

			parg.rsp_policy = &nl80211_band_attrs_nest;
			parg.data = &dst->_6ghz;
			if (nl80211_band_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_BAND_S1GHZ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.s1ghz = 1;

			parg.rsp_policy = &nl80211_band_attrs_nest;
			parg.data = &dst->s1ghz;
			if (nl80211_band_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_BAND_LC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.lc = 1;

			parg.rsp_policy = &nl80211_band_attrs_nest;
			parg.data = &dst->lc;
			if (nl80211_band_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

/* ============== NL80211_CMD_GET_WIPHY ============== */
/* NL80211_CMD_GET_WIPHY - do */
void nl80211_get_wiphy_req_free(struct nl80211_get_wiphy_req *req)
{
	free(req);
}

void nl80211_get_wiphy_rsp_free(struct nl80211_get_wiphy_rsp *rsp)
{
	free(rsp->cipher_suites);
	free(rsp->ext_capa);
	free(rsp->ext_capa_mask);
	free(rsp->ext_features);
	free(rsp->ht_capability_mask);
	free(rsp->interface_combinations);
	free(rsp->mac);
	free(rsp->max_num_akm_suites);
	nl80211_iftype_attrs_free(&rsp->rx_frame_types);
	nl80211_sar_attributes_free(&rsp->sar_spec);
	nl80211_supported_iftypes_free(&rsp->software_iftypes);
	free(rsp->supported_commands);
	nl80211_supported_iftypes_free(&rsp->supported_iftypes);
	nl80211_iftype_attrs_free(&rsp->tx_frame_types);
	nl80211_txq_stats_attrs_free(&rsp->txq_stats);
	free(rsp->vht_capability_mask);
	nl80211_wiphy_bands_free(&rsp->wiphy_bands);
	free(rsp->wiphy_name);
	nl80211_wowlan_triggers_attrs_free(&rsp->wowlan_triggers_supported);
	free(rsp);
}

int nl80211_get_wiphy_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr_interface_combinations;
	const struct nlattr *attr_supported_commands;
	unsigned int n_interface_combinations = 0;
	unsigned int n_supported_commands = 0;
	struct nl80211_get_wiphy_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = yarg->data;
	parg.ys = yarg->ys;

	if (dst->interface_combinations)
		return ynl_error_parse(yarg, "attribute already present (nl80211-attrs.interface-combinations)");
	if (dst->supported_commands)
		return ynl_error_parse(yarg, "attribute already present (nl80211-attrs.supported-commands)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_ATTR_BANDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bands = 1;
			dst->bands = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_CIPHER_SUITES) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.cipher_suites = len / sizeof(__u32);
			len = dst->_count.cipher_suites * sizeof(__u32);
			dst->cipher_suites = malloc(len);
			memcpy(dst->cipher_suites, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_CONTROL_PORT_ETHERTYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.control_port_ethertype = 1;
		} else if (type == NL80211_ATTR_EXT_CAPA) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ext_capa = len;
			dst->ext_capa = malloc(len);
			memcpy(dst->ext_capa, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_EXT_CAPA_MASK) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ext_capa_mask = len;
			dst->ext_capa_mask = malloc(len);
			memcpy(dst->ext_capa_mask, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_EXT_FEATURES) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ext_features = len;
			dst->ext_features = malloc(len);
			memcpy(dst->ext_features, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_FEATURE_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.feature_flags = 1;
			dst->feature_flags = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_GENERATION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.generation = 1;
			dst->generation = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_HT_CAPABILITY_MASK) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ht_capability_mask = len;
			dst->ht_capability_mask = malloc(len);
			memcpy(dst->ht_capability_mask, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_INTERFACE_COMBINATIONS) {
			const struct nlattr *attr2;

			attr_interface_combinations = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.interface_combinations++;
			}
		} else if (type == NL80211_ATTR_MAC) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.mac = len;
			dst->mac = malloc(len);
			memcpy(dst->mac, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_MAX_CSA_COUNTERS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_csa_counters = 1;
			dst->max_csa_counters = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_MATCH_SETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_match_sets = 1;
			dst->max_match_sets = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_NUM_AKM_SUITES) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.max_num_akm_suites = len;
			dst->max_num_akm_suites = malloc(len);
			memcpy(dst->max_num_akm_suites, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_MAX_NUM_PMKIDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_num_pmkids = 1;
			dst->max_num_pmkids = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_NUM_SCAN_SSIDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_num_scan_ssids = 1;
			dst->max_num_scan_ssids = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_num_sched_scan_plans = 1;
			dst->max_num_sched_scan_plans = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_num_sched_scan_ssids = 1;
			dst->max_num_sched_scan_ssids = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_remain_on_channel_duration = 1;
			dst->max_remain_on_channel_duration = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_MAX_SCAN_IE_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_scan_ie_len = 1;
			dst->max_scan_ie_len = ynl_attr_get_u16(attr);
		} else if (type == NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_scan_plan_interval = 1;
			dst->max_scan_plan_interval = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_scan_plan_iterations = 1;
			dst->max_scan_plan_iterations = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_sched_scan_ie_len = 1;
			dst->max_sched_scan_ie_len = ynl_attr_get_u16(attr);
		} else if (type == NL80211_ATTR_OFFCHANNEL_TX_OK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.offchannel_tx_ok = 1;
		} else if (type == NL80211_ATTR_RX_FRAME_TYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rx_frame_types = 1;

			parg.rsp_policy = &nl80211_iftype_attrs_nest;
			parg.data = &dst->rx_frame_types;
			if (nl80211_iftype_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_SAR_SPEC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sar_spec = 1;

			parg.rsp_policy = &nl80211_sar_attributes_nest;
			parg.data = &dst->sar_spec;
			if (nl80211_sar_attributes_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_SCHED_SCAN_MAX_REQS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sched_scan_max_reqs = 1;
			dst->sched_scan_max_reqs = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_SOFTWARE_IFTYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.software_iftypes = 1;

			parg.rsp_policy = &nl80211_supported_iftypes_nest;
			parg.data = &dst->software_iftypes;
			if (nl80211_supported_iftypes_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_SUPPORT_AP_UAPSD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_ap_uapsd = 1;
		} else if (type == NL80211_ATTR_SUPPORTED_COMMANDS) {
			const struct nlattr *attr2;

			attr_supported_commands = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.supported_commands++;
			}
		} else if (type == NL80211_ATTR_SUPPORTED_IFTYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.supported_iftypes = 1;

			parg.rsp_policy = &nl80211_supported_iftypes_nest;
			parg.data = &dst->supported_iftypes;
			if (nl80211_supported_iftypes_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_TDLS_EXTERNAL_SETUP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tdls_external_setup = 1;
		} else if (type == NL80211_ATTR_TDLS_SUPPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tdls_support = 1;
		} else if (type == NL80211_ATTR_TX_FRAME_TYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tx_frame_types = 1;

			parg.rsp_policy = &nl80211_iftype_attrs_nest;
			parg.data = &dst->tx_frame_types;
			if (nl80211_iftype_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_TXQ_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_limit = 1;
			dst->txq_limit = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_TXQ_MEMORY_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_memory_limit = 1;
			dst->txq_memory_limit = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_TXQ_QUANTUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_quantum = 1;
			dst->txq_quantum = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_TXQ_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_stats = 1;

			parg.rsp_policy = &nl80211_txq_stats_attrs_nest;
			parg.data = &dst->txq_stats;
			if (nl80211_txq_stats_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_VHT_CAPABILITY_MASK) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.vht_capability_mask = len;
			dst->vht_capability_mask = malloc(len);
			memcpy(dst->vht_capability_mask, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_WIPHY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy = 1;
			dst->wiphy = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_antenna_avail_rx = 1;
			dst->wiphy_antenna_avail_rx = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_antenna_avail_tx = 1;
			dst->wiphy_antenna_avail_tx = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_ANTENNA_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_antenna_rx = 1;
			dst->wiphy_antenna_rx = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_ANTENNA_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_antenna_tx = 1;
			dst->wiphy_antenna_tx = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_BANDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_bands = 1;

			parg.rsp_policy = &nl80211_wiphy_bands_nest;
			parg.data = &dst->wiphy_bands;
			if (nl80211_wiphy_bands_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_WIPHY_COVERAGE_CLASS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_coverage_class = 1;
			dst->wiphy_coverage_class = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_WIPHY_FRAG_THRESHOLD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_frag_threshold = 1;
			dst->wiphy_frag_threshold = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_NAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.wiphy_name = len;
			dst->wiphy_name = malloc(len + 1);
			memcpy(dst->wiphy_name, ynl_attr_get_str(attr), len);
			dst->wiphy_name[len] = 0;
		} else if (type == NL80211_ATTR_WIPHY_RETRY_LONG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_retry_long = 1;
			dst->wiphy_retry_long = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_WIPHY_RETRY_SHORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_retry_short = 1;
			dst->wiphy_retry_short = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_WIPHY_RTS_THRESHOLD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_rts_threshold = 1;
			dst->wiphy_rts_threshold = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wowlan_triggers_supported = 1;

			parg.rsp_policy = &nl80211_wowlan_triggers_attrs_nest;
			parg.data = &dst->wowlan_triggers_supported;
			if (nl80211_wowlan_triggers_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	if (n_interface_combinations) {
		dst->interface_combinations = calloc(n_interface_combinations, sizeof(*dst->interface_combinations));
		dst->_count.interface_combinations = n_interface_combinations;
		i = 0;
		parg.rsp_policy = &nl80211_if_combination_attributes_nest;
		ynl_attr_for_each_nested(attr, attr_interface_combinations) {
			parg.data = &dst->interface_combinations[i];
			if (nl80211_if_combination_attributes_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}
	if (n_supported_commands) {
		dst->supported_commands = calloc(n_supported_commands, sizeof(*dst->supported_commands));
		dst->_count.supported_commands = n_supported_commands;
		i = 0;
		ynl_attr_for_each_nested(attr, attr_supported_commands) {
			dst->supported_commands[i] = ynl_attr_get_u32(attr);
			i++;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct nl80211_get_wiphy_rsp *
nl80211_get_wiphy(struct ynl_sock *ys, struct nl80211_get_wiphy_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nl80211_get_wiphy_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NL80211_CMD_GET_WIPHY, 1);
	ys->req_policy = &nl80211_nl80211_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;

	if (req->_present.wiphy)
		ynl_attr_put_u32(nlh, NL80211_ATTR_WIPHY, req->wiphy);
	if (req->_present.wdev)
		ynl_attr_put_u64(nlh, NL80211_ATTR_WDEV, req->wdev);
	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, req->ifindex);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = nl80211_get_wiphy_rsp_parse;
	yrs.rsp_cmd = 3;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	nl80211_get_wiphy_rsp_free(rsp);
	return NULL;
}

/* NL80211_CMD_GET_WIPHY - dump */
int nl80211_get_wiphy_rsp_dump_parse(const struct nlmsghdr *nlh,
				     struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr_interface_combinations;
	const struct nlattr *attr_supported_commands;
	unsigned int n_interface_combinations = 0;
	struct nl80211_get_wiphy_rsp_dump *dst;
	unsigned int n_supported_commands = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = yarg->data;
	parg.ys = yarg->ys;

	if (dst->interface_combinations)
		return ynl_error_parse(yarg, "attribute already present (nl80211-attrs.interface-combinations)");
	if (dst->supported_commands)
		return ynl_error_parse(yarg, "attribute already present (nl80211-attrs.supported-commands)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_ATTR_BANDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bands = 1;
			dst->bands = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_CIPHER_SUITES) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.cipher_suites = len / sizeof(__u32);
			len = dst->_count.cipher_suites * sizeof(__u32);
			dst->cipher_suites = malloc(len);
			memcpy(dst->cipher_suites, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_CONTROL_PORT_ETHERTYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.control_port_ethertype = 1;
		} else if (type == NL80211_ATTR_EXT_CAPA) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ext_capa = len;
			dst->ext_capa = malloc(len);
			memcpy(dst->ext_capa, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_EXT_CAPA_MASK) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ext_capa_mask = len;
			dst->ext_capa_mask = malloc(len);
			memcpy(dst->ext_capa_mask, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_EXT_FEATURES) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ext_features = len;
			dst->ext_features = malloc(len);
			memcpy(dst->ext_features, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_FEATURE_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.feature_flags = 1;
			dst->feature_flags = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_GENERATION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.generation = 1;
			dst->generation = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_HT_CAPABILITY_MASK) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ht_capability_mask = len;
			dst->ht_capability_mask = malloc(len);
			memcpy(dst->ht_capability_mask, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_INTERFACE_COMBINATIONS) {
			const struct nlattr *attr2;

			attr_interface_combinations = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.interface_combinations++;
			}
		} else if (type == NL80211_ATTR_MAC) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.mac = len;
			dst->mac = malloc(len);
			memcpy(dst->mac, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_MAX_CSA_COUNTERS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_csa_counters = 1;
			dst->max_csa_counters = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_MATCH_SETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_match_sets = 1;
			dst->max_match_sets = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_NUM_AKM_SUITES) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.max_num_akm_suites = len;
			dst->max_num_akm_suites = malloc(len);
			memcpy(dst->max_num_akm_suites, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_MAX_NUM_PMKIDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_num_pmkids = 1;
			dst->max_num_pmkids = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_NUM_SCAN_SSIDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_num_scan_ssids = 1;
			dst->max_num_scan_ssids = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_num_sched_scan_plans = 1;
			dst->max_num_sched_scan_plans = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_num_sched_scan_ssids = 1;
			dst->max_num_sched_scan_ssids = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_remain_on_channel_duration = 1;
			dst->max_remain_on_channel_duration = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_MAX_SCAN_IE_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_scan_ie_len = 1;
			dst->max_scan_ie_len = ynl_attr_get_u16(attr);
		} else if (type == NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_scan_plan_interval = 1;
			dst->max_scan_plan_interval = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_scan_plan_iterations = 1;
			dst->max_scan_plan_iterations = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_sched_scan_ie_len = 1;
			dst->max_sched_scan_ie_len = ynl_attr_get_u16(attr);
		} else if (type == NL80211_ATTR_OFFCHANNEL_TX_OK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.offchannel_tx_ok = 1;
		} else if (type == NL80211_ATTR_RX_FRAME_TYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rx_frame_types = 1;

			parg.rsp_policy = &nl80211_iftype_attrs_nest;
			parg.data = &dst->rx_frame_types;
			if (nl80211_iftype_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_SAR_SPEC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sar_spec = 1;

			parg.rsp_policy = &nl80211_sar_attributes_nest;
			parg.data = &dst->sar_spec;
			if (nl80211_sar_attributes_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_SCHED_SCAN_MAX_REQS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sched_scan_max_reqs = 1;
			dst->sched_scan_max_reqs = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_SOFTWARE_IFTYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.software_iftypes = 1;

			parg.rsp_policy = &nl80211_supported_iftypes_nest;
			parg.data = &dst->software_iftypes;
			if (nl80211_supported_iftypes_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_SUPPORT_AP_UAPSD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_ap_uapsd = 1;
		} else if (type == NL80211_ATTR_SUPPORTED_COMMANDS) {
			const struct nlattr *attr2;

			attr_supported_commands = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.supported_commands++;
			}
		} else if (type == NL80211_ATTR_SUPPORTED_IFTYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.supported_iftypes = 1;

			parg.rsp_policy = &nl80211_supported_iftypes_nest;
			parg.data = &dst->supported_iftypes;
			if (nl80211_supported_iftypes_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_TDLS_EXTERNAL_SETUP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tdls_external_setup = 1;
		} else if (type == NL80211_ATTR_TDLS_SUPPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tdls_support = 1;
		} else if (type == NL80211_ATTR_TX_FRAME_TYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tx_frame_types = 1;

			parg.rsp_policy = &nl80211_iftype_attrs_nest;
			parg.data = &dst->tx_frame_types;
			if (nl80211_iftype_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_TXQ_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_limit = 1;
			dst->txq_limit = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_TXQ_MEMORY_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_memory_limit = 1;
			dst->txq_memory_limit = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_TXQ_QUANTUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_quantum = 1;
			dst->txq_quantum = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_TXQ_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_stats = 1;

			parg.rsp_policy = &nl80211_txq_stats_attrs_nest;
			parg.data = &dst->txq_stats;
			if (nl80211_txq_stats_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_VHT_CAPABILITY_MASK) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.vht_capability_mask = len;
			dst->vht_capability_mask = malloc(len);
			memcpy(dst->vht_capability_mask, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_WIPHY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy = 1;
			dst->wiphy = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_antenna_avail_rx = 1;
			dst->wiphy_antenna_avail_rx = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_antenna_avail_tx = 1;
			dst->wiphy_antenna_avail_tx = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_ANTENNA_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_antenna_rx = 1;
			dst->wiphy_antenna_rx = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_ANTENNA_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_antenna_tx = 1;
			dst->wiphy_antenna_tx = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_BANDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_bands = 1;

			parg.rsp_policy = &nl80211_wiphy_bands_nest;
			parg.data = &dst->wiphy_bands;
			if (nl80211_wiphy_bands_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_WIPHY_COVERAGE_CLASS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_coverage_class = 1;
			dst->wiphy_coverage_class = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_WIPHY_FRAG_THRESHOLD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_frag_threshold = 1;
			dst->wiphy_frag_threshold = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY_NAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.wiphy_name = len;
			dst->wiphy_name = malloc(len + 1);
			memcpy(dst->wiphy_name, ynl_attr_get_str(attr), len);
			dst->wiphy_name[len] = 0;
		} else if (type == NL80211_ATTR_WIPHY_RETRY_LONG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_retry_long = 1;
			dst->wiphy_retry_long = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_WIPHY_RETRY_SHORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_retry_short = 1;
			dst->wiphy_retry_short = ynl_attr_get_u8(attr);
		} else if (type == NL80211_ATTR_WIPHY_RTS_THRESHOLD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy_rts_threshold = 1;
			dst->wiphy_rts_threshold = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wowlan_triggers_supported = 1;

			parg.rsp_policy = &nl80211_wowlan_triggers_attrs_nest;
			parg.data = &dst->wowlan_triggers_supported;
			if (nl80211_wowlan_triggers_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	if (n_interface_combinations) {
		dst->interface_combinations = calloc(n_interface_combinations, sizeof(*dst->interface_combinations));
		dst->_count.interface_combinations = n_interface_combinations;
		i = 0;
		parg.rsp_policy = &nl80211_if_combination_attributes_nest;
		ynl_attr_for_each_nested(attr, attr_interface_combinations) {
			parg.data = &dst->interface_combinations[i];
			if (nl80211_if_combination_attributes_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}
	if (n_supported_commands) {
		dst->supported_commands = calloc(n_supported_commands, sizeof(*dst->supported_commands));
		dst->_count.supported_commands = n_supported_commands;
		i = 0;
		ynl_attr_for_each_nested(attr, attr_supported_commands) {
			dst->supported_commands[i] = ynl_attr_get_u32(attr);
			i++;
		}
	}

	return YNL_PARSE_CB_OK;
}

void nl80211_get_wiphy_req_dump_free(struct nl80211_get_wiphy_req_dump *req)
{
	free(req);
}

void nl80211_get_wiphy_rsp_list_free(struct nl80211_get_wiphy_rsp_list *rsp)
{
	struct nl80211_get_wiphy_rsp_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.cipher_suites);
		free(rsp->obj.ext_capa);
		free(rsp->obj.ext_capa_mask);
		free(rsp->obj.ext_features);
		free(rsp->obj.ht_capability_mask);
		free(rsp->obj.interface_combinations);
		free(rsp->obj.mac);
		free(rsp->obj.max_num_akm_suites);
		nl80211_iftype_attrs_free(&rsp->obj.rx_frame_types);
		nl80211_sar_attributes_free(&rsp->obj.sar_spec);
		nl80211_supported_iftypes_free(&rsp->obj.software_iftypes);
		free(rsp->obj.supported_commands);
		nl80211_supported_iftypes_free(&rsp->obj.supported_iftypes);
		nl80211_iftype_attrs_free(&rsp->obj.tx_frame_types);
		nl80211_txq_stats_attrs_free(&rsp->obj.txq_stats);
		free(rsp->obj.vht_capability_mask);
		nl80211_wiphy_bands_free(&rsp->obj.wiphy_bands);
		free(rsp->obj.wiphy_name);
		nl80211_wowlan_triggers_attrs_free(&rsp->obj.wowlan_triggers_supported);
		free(rsp);
	}
}

struct nl80211_get_wiphy_rsp_list *
nl80211_get_wiphy_dump(struct ynl_sock *ys,
		       struct nl80211_get_wiphy_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct nl80211_get_wiphy_rsp_list);
	yds.cb = nl80211_get_wiphy_rsp_dump_parse;
	yds.rsp_cmd = 3;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, NL80211_CMD_GET_WIPHY, 1);
	ys->req_policy = &nl80211_nl80211_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.wiphy)
		ynl_attr_put_u32(nlh, NL80211_ATTR_WIPHY, req->wiphy);
	if (req->_present.wdev)
		ynl_attr_put_u64(nlh, NL80211_ATTR_WDEV, req->wdev);
	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, req->ifindex);
	if (req->_present.split_wiphy_dump)
		ynl_attr_put(nlh, NL80211_ATTR_SPLIT_WIPHY_DUMP, NULL, 0);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	nl80211_get_wiphy_rsp_list_free(yds.first);
	return NULL;
}

/* ============== NL80211_CMD_GET_INTERFACE ============== */
/* NL80211_CMD_GET_INTERFACE - do */
void nl80211_get_interface_req_free(struct nl80211_get_interface_req *req)
{
	free(req->ifname);
	free(req);
}

void nl80211_get_interface_rsp_free(struct nl80211_get_interface_rsp *rsp)
{
	free(rsp->ifname);
	free(rsp->mac);
	nl80211_txq_stats_attrs_free(&rsp->txq_stats);
	free(rsp);
}

int nl80211_get_interface_rsp_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	struct nl80211_get_interface_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_ATTR_IFNAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.ifname = len;
			dst->ifname = malloc(len + 1);
			memcpy(dst->ifname, ynl_attr_get_str(attr), len);
			dst->ifname[len] = 0;
		} else if (type == NL80211_ATTR_IFTYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.iftype = 1;
			dst->iftype = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy = 1;
			dst->wiphy = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WDEV) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wdev = 1;
			dst->wdev = ynl_attr_get_u64(attr);
		} else if (type == NL80211_ATTR_MAC) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.mac = len;
			dst->mac = malloc(len);
			memcpy(dst->mac, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_GENERATION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.generation = 1;
			dst->generation = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_TXQ_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_stats = 1;

			parg.rsp_policy = &nl80211_txq_stats_attrs_nest;
			parg.data = &dst->txq_stats;
			if (nl80211_txq_stats_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_4ADDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._4addr = 1;
			dst->_4addr = ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct nl80211_get_interface_rsp *
nl80211_get_interface(struct ynl_sock *ys,
		      struct nl80211_get_interface_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nl80211_get_interface_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NL80211_CMD_GET_INTERFACE, 1);
	ys->req_policy = &nl80211_nl80211_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;

	if (req->_len.ifname)
		ynl_attr_put_str(nlh, NL80211_ATTR_IFNAME, req->ifname);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = nl80211_get_interface_rsp_parse;
	yrs.rsp_cmd = 7;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	nl80211_get_interface_rsp_free(rsp);
	return NULL;
}

/* NL80211_CMD_GET_INTERFACE - dump */
int nl80211_get_interface_rsp_dump_parse(const struct nlmsghdr *nlh,
					 struct ynl_parse_arg *yarg)
{
	struct nl80211_get_interface_rsp_dump *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_ATTR_IFNAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.ifname = len;
			dst->ifname = malloc(len + 1);
			memcpy(dst->ifname, ynl_attr_get_str(attr), len);
			dst->ifname[len] = 0;
		} else if (type == NL80211_ATTR_IFTYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.iftype = 1;
			dst->iftype = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WIPHY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wiphy = 1;
			dst->wiphy = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_WDEV) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wdev = 1;
			dst->wdev = ynl_attr_get_u64(attr);
		} else if (type == NL80211_ATTR_MAC) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.mac = len;
			dst->mac = malloc(len);
			memcpy(dst->mac, ynl_attr_data(attr), len);
		} else if (type == NL80211_ATTR_GENERATION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.generation = 1;
			dst->generation = ynl_attr_get_u32(attr);
		} else if (type == NL80211_ATTR_TXQ_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txq_stats = 1;

			parg.rsp_policy = &nl80211_txq_stats_attrs_nest;
			parg.data = &dst->txq_stats;
			if (nl80211_txq_stats_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NL80211_ATTR_4ADDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._4addr = 1;
			dst->_4addr = ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

void
nl80211_get_interface_req_dump_free(struct nl80211_get_interface_req_dump *req)
{
	free(req->ifname);
	free(req);
}

void
nl80211_get_interface_rsp_list_free(struct nl80211_get_interface_rsp_list *rsp)
{
	struct nl80211_get_interface_rsp_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.ifname);
		free(rsp->obj.mac);
		nl80211_txq_stats_attrs_free(&rsp->obj.txq_stats);
		free(rsp);
	}
}

struct nl80211_get_interface_rsp_list *
nl80211_get_interface_dump(struct ynl_sock *ys,
			   struct nl80211_get_interface_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct nl80211_get_interface_rsp_list);
	yds.cb = nl80211_get_interface_rsp_dump_parse;
	yds.rsp_cmd = 7;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, NL80211_CMD_GET_INTERFACE, 1);
	ys->req_policy = &nl80211_nl80211_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.ifname)
		ynl_attr_put_str(nlh, NL80211_ATTR_IFNAME, req->ifname);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	nl80211_get_interface_rsp_list_free(yds.first);
	return NULL;
}

/* ============== NL80211_CMD_GET_PROTOCOL_FEATURES ============== */
/* NL80211_CMD_GET_PROTOCOL_FEATURES - do */
void
nl80211_get_protocol_features_req_free(struct nl80211_get_protocol_features_req *req)
{
	free(req);
}

void
nl80211_get_protocol_features_rsp_free(struct nl80211_get_protocol_features_rsp *rsp)
{
	free(rsp);
}

int nl80211_get_protocol_features_rsp_parse(const struct nlmsghdr *nlh,
					    struct ynl_parse_arg *yarg)
{
	struct nl80211_get_protocol_features_rsp *dst;
	const struct nlattr *attr;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL80211_ATTR_PROTOCOL_FEATURES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.protocol_features = 1;
			dst->protocol_features = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct nl80211_get_protocol_features_rsp *
nl80211_get_protocol_features(struct ynl_sock *ys,
			      struct nl80211_get_protocol_features_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nl80211_get_protocol_features_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NL80211_CMD_GET_PROTOCOL_FEATURES, 1);
	ys->req_policy = &nl80211_nl80211_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;

	if (req->_present.protocol_features)
		ynl_attr_put_u32(nlh, NL80211_ATTR_PROTOCOL_FEATURES, req->protocol_features);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = nl80211_get_protocol_features_rsp_parse;
	yrs.rsp_cmd = NL80211_CMD_GET_PROTOCOL_FEATURES;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	nl80211_get_protocol_features_rsp_free(rsp);
	return NULL;
}

const struct ynl_family ynl_nl80211_family =  {
	.name		= "nl80211",
	.hdr_len	= sizeof(struct genlmsghdr),
};
