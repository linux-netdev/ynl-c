// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-link.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "rt-link-user.h"
#include "ynl.h"
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>
#include <linux/dpll.h>
#include <linux/rtnetlink.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const rt_link_op_strmap[] = {
	// skip "newlink-ntf", duplicate reply value
	[16] = "getlink",
	[92] = "getstats",
};

const char *rt_link_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(rt_link_op_strmap))
		return NULL;
	return rt_link_op_strmap[op];
}

static const char * const rt_link_ifinfo_flags_strmap[] = {
	[0] = "up",
	[1] = "broadcast",
	[2] = "debug",
	[3] = "loopback",
	[4] = "point-to-point",
	[5] = "no-trailers",
	[6] = "running",
	[7] = "no-arp",
	[8] = "promisc",
	[9] = "all-multi",
	[10] = "master",
	[11] = "slave",
	[12] = "multicast",
	[13] = "portsel",
	[14] = "auto-media",
	[15] = "dynamic",
	[16] = "lower-up",
	[17] = "dormant",
	[18] = "echo",
};

const char *rt_link_ifinfo_flags_str(enum net_device_flags value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_ifinfo_flags_strmap))
		return NULL;
	return rt_link_ifinfo_flags_strmap[value];
}

static const char * const rt_link_vlan_protocols_strmap[] = {
	[33024] = "8021q",
	[34984] = "8021ad",
};

const char *rt_link_vlan_protocols_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_vlan_protocols_strmap))
		return NULL;
	return rt_link_vlan_protocols_strmap[value];
}

static const char * const rt_link_ipv4_devconf_strmap[] = {
	[0] = "forwarding",
	[1] = "mc-forwarding",
	[2] = "proxy-arp",
	[3] = "accept-redirects",
	[4] = "secure-redirects",
	[5] = "send-redirects",
	[6] = "shared-media",
	[7] = "rp-filter",
	[8] = "accept-source-route",
	[9] = "bootp-relay",
	[10] = "log-martians",
	[11] = "tag",
	[12] = "arpfilter",
	[13] = "medium-id",
	[14] = "noxfrm",
	[15] = "nopolicy",
	[16] = "force-igmp-version",
	[17] = "arp-announce",
	[18] = "arp-ignore",
	[19] = "promote-secondaries",
	[20] = "arp-accept",
	[21] = "arp-notify",
	[22] = "accept-local",
	[23] = "src-vmark",
	[24] = "proxy-arp-pvlan",
	[25] = "route-localnet",
	[26] = "igmpv2-unsolicited-report-interval",
	[27] = "igmpv3-unsolicited-report-interval",
	[28] = "ignore-routes-with-linkdown",
	[29] = "drop-unicast-in-l2-multicast",
	[30] = "drop-gratuitous-arp",
	[31] = "bc-forwarding",
	[32] = "arp-evict-nocarrier",
};

const char *rt_link_ipv4_devconf_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_ipv4_devconf_strmap))
		return NULL;
	return rt_link_ipv4_devconf_strmap[value];
}

static const char * const rt_link_ipv6_devconf_strmap[] = {
	[0] = "forwarding",
	[1] = "hoplimit",
	[2] = "mtu6",
	[3] = "accept-ra",
	[4] = "accept-redirects",
	[5] = "autoconf",
	[6] = "dad-transmits",
	[7] = "rtr-solicits",
	[8] = "rtr-solicit-interval",
	[9] = "rtr-solicit-delay",
	[10] = "use-tempaddr",
	[11] = "temp-valid-lft",
	[12] = "temp-prefered-lft",
	[13] = "regen-max-retry",
	[14] = "max-desync-factor",
	[15] = "max-addresses",
	[16] = "force-mld-version",
	[17] = "accept-ra-defrtr",
	[18] = "accept-ra-pinfo",
	[19] = "accept-ra-rtr-pref",
	[20] = "rtr-probe-interval",
	[21] = "accept-ra-rt-info-max-plen",
	[22] = "proxy-ndp",
	[23] = "optimistic-dad",
	[24] = "accept-source-route",
	[25] = "mc-forwarding",
	[26] = "disable-ipv6",
	[27] = "accept-dad",
	[28] = "force-tllao",
	[29] = "ndisc-notify",
	[30] = "mldv1-unsolicited-report-interval",
	[31] = "mldv2-unsolicited-report-interval",
	[32] = "suppress-frag-ndisc",
	[33] = "accept-ra-from-local",
	[34] = "use-optimistic",
	[35] = "accept-ra-mtu",
	[36] = "stable-secret",
	[37] = "use-oif-addrs-only",
	[38] = "accept-ra-min-hop-limit",
	[39] = "ignore-routes-with-linkdown",
	[40] = "drop-unicast-in-l2-multicast",
	[41] = "drop-unsolicited-na",
	[42] = "keep-addr-on-down",
	[43] = "rtr-solicit-max-interval",
	[44] = "seg6-enabled",
	[45] = "seg6-require-hmac",
	[46] = "enhanced-dad",
	[47] = "addr-gen-mode",
	[48] = "disable-policy",
	[49] = "accept-ra-rt-info-min-plen",
	[50] = "ndisc-tclass",
	[51] = "rpl-seg-enabled",
	[52] = "ra-defrtr-metric",
	[53] = "ioam6-enabled",
	[54] = "ioam6-id",
	[55] = "ioam6-id-wide",
	[56] = "ndisc-evict-nocarrier",
	[57] = "accept-untracked-na",
};

const char *rt_link_ipv6_devconf_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_ipv6_devconf_strmap))
		return NULL;
	return rt_link_ipv6_devconf_strmap[value];
}

static const char * const rt_link_ifla_icmp6_stats_strmap[] = {
	[0] = "num",
	[1] = "inmsgs",
	[2] = "inerrors",
	[3] = "outmsgs",
	[4] = "outerrors",
	[5] = "csumerrors",
	[6] = "ratelimithost",
};

const char *rt_link_ifla_icmp6_stats_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_ifla_icmp6_stats_strmap))
		return NULL;
	return rt_link_ifla_icmp6_stats_strmap[value];
}

static const char * const rt_link_ifla_inet6_stats_strmap[] = {
	[0] = "num",
	[1] = "inpkts",
	[2] = "inoctets",
	[3] = "indelivers",
	[4] = "outforwdatagrams",
	[5] = "outpkts",
	[6] = "outoctets",
	[7] = "inhdrerrors",
	[8] = "intoobigerrors",
	[9] = "innoroutes",
	[10] = "inaddrerrors",
	[11] = "inunknownprotos",
	[12] = "intruncatedpkts",
	[13] = "indiscards",
	[14] = "outdiscards",
	[15] = "outnoroutes",
	[16] = "reasmtimeout",
	[17] = "reasmreqds",
	[18] = "reasmoks",
	[19] = "reasmfails",
	[20] = "fragoks",
	[21] = "fragfails",
	[22] = "fragcreates",
	[23] = "inmcastpkts",
	[24] = "outmcastpkts",
	[25] = "inbcastpkts",
	[26] = "outbcastpkts",
	[27] = "inmcastoctets",
	[28] = "outmcastoctets",
	[29] = "inbcastoctets",
	[30] = "outbcastoctets",
	[31] = "csumerrors",
	[32] = "noectpkts",
	[33] = "ect1-pkts",
	[34] = "ect0-pkts",
	[35] = "cepkts",
	[36] = "reasm-overlaps",
};

const char *rt_link_ifla_inet6_stats_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_ifla_inet6_stats_strmap))
		return NULL;
	return rt_link_ifla_inet6_stats_strmap[value];
}

static const char * const rt_link_vlan_flags_strmap[] = {
	[0] = "reorder-hdr",
	[1] = "gvrp",
	[2] = "loose-binding",
	[3] = "mvrp",
	[4] = "bridge-binding",
};

const char *rt_link_vlan_flags_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_vlan_flags_strmap))
		return NULL;
	return rt_link_vlan_flags_strmap[value];
}

static const char * const rt_link_ifla_vf_link_state_enum_strmap[] = {
	[0] = "auto",
	[1] = "enable",
	[2] = "disable",
};

const char *rt_link_ifla_vf_link_state_enum_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_ifla_vf_link_state_enum_strmap))
		return NULL;
	return rt_link_ifla_vf_link_state_enum_strmap[value];
}

static const char * const rt_link_rtext_filter_strmap[] = {
	[0] = "vf",
	[1] = "brvlan",
	[2] = "brvlan-compressed",
	[3] = "skip-stats",
	[4] = "mrp",
	[5] = "cfm-config",
	[6] = "cfm-status",
	[7] = "mst",
};

const char *rt_link_rtext_filter_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_rtext_filter_strmap))
		return NULL;
	return rt_link_rtext_filter_strmap[value];
}

static const char * const rt_link_netkit_policy_strmap[] = {
	[0] = "forward",
	[2] = "blackhole",
};

const char *rt_link_netkit_policy_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_netkit_policy_strmap))
		return NULL;
	return rt_link_netkit_policy_strmap[value];
}

static const char * const rt_link_netkit_mode_strmap[] = {
	[0] = "l2",
	[1] = "l3",
};

const char *rt_link_netkit_mode_str(enum netkit_mode value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_netkit_mode_strmap))
		return NULL;
	return rt_link_netkit_mode_strmap[value];
}

static const char * const rt_link_netkit_scrub_strmap[] = {
	[0] = "none",
	[1] = "default",
};

const char *rt_link_netkit_scrub_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_netkit_scrub_strmap))
		return NULL;
	return rt_link_netkit_scrub_strmap[value];
}

static const char * const rt_link_ovpn_mode_strmap[] = {
	[0] = "p2p",
	[1] = "mp",
};

const char *rt_link_ovpn_mode_str(enum ovpn_mode value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_link_ovpn_mode_strmap))
		return NULL;
	return rt_link_ovpn_mode_strmap[value];
}

/* Policies */
const struct ynl_policy_attr rt_link_vf_ports_attrs_policy[IFLA_MAX + 1] = {
};

const struct ynl_policy_nest rt_link_vf_ports_attrs_nest = {
	.max_attr = IFLA_MAX,
	.table = rt_link_vf_ports_attrs_policy,
};

const struct ynl_policy_attr rt_link_port_self_attrs_policy[IFLA_MAX + 1] = {
};

const struct ynl_policy_nest rt_link_port_self_attrs_nest = {
	.max_attr = IFLA_MAX,
	.table = rt_link_port_self_attrs_policy,
};

const struct ynl_policy_attr rt_link_xdp_attrs_policy[IFLA_XDP_MAX + 1] = {
	[IFLA_XDP_FD] = { .name = "fd", .type = YNL_PT_U32, },
	[IFLA_XDP_ATTACHED] = { .name = "attached", .type = YNL_PT_U8, },
	[IFLA_XDP_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[IFLA_XDP_PROG_ID] = { .name = "prog-id", .type = YNL_PT_U32, },
	[IFLA_XDP_DRV_PROG_ID] = { .name = "drv-prog-id", .type = YNL_PT_U32, },
	[IFLA_XDP_SKB_PROG_ID] = { .name = "skb-prog-id", .type = YNL_PT_U32, },
	[IFLA_XDP_HW_PROG_ID] = { .name = "hw-prog-id", .type = YNL_PT_U32, },
	[IFLA_XDP_EXPECTED_FD] = { .name = "expected-fd", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_xdp_attrs_nest = {
	.max_attr = IFLA_XDP_MAX,
	.table = rt_link_xdp_attrs_policy,
};

const struct ynl_policy_attr rt_link_prop_list_link_attrs_policy[IFLA_MAX + 1] = {
	[IFLA_ALT_IFNAME] = { .name = "alt-ifname", .type = YNL_PT_NUL_STR, },
};

const struct ynl_policy_nest rt_link_prop_list_link_attrs_nest = {
	.max_attr = IFLA_MAX,
	.table = rt_link_prop_list_link_attrs_policy,
};

const struct ynl_policy_attr rt_link_link_dpll_pin_attrs_policy[DPLL_A_MAX + 1] = {
	[DPLL_A_ID] = { .name = "id", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_link_dpll_pin_attrs_nest = {
	.max_attr = DPLL_A_MAX,
	.table = rt_link_link_dpll_pin_attrs_policy,
};

const struct ynl_policy_attr rt_link_ifla_attrs_policy[IFLA_INET_MAX + 1] = {
	[IFLA_INET_CONF] = { .name = "conf", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest rt_link_ifla_attrs_nest = {
	.max_attr = IFLA_INET_MAX,
	.table = rt_link_ifla_attrs_policy,
};

const struct ynl_policy_attr rt_link_ifla6_attrs_policy[IFLA_INET6_MAX + 1] = {
	[IFLA_INET6_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[IFLA_INET6_CONF] = { .name = "conf", .type = YNL_PT_BINARY,},
	[IFLA_INET6_STATS] = { .name = "stats", .type = YNL_PT_BINARY,},
	[IFLA_INET6_MCAST] = { .name = "mcast", .type = YNL_PT_BINARY,},
	[IFLA_INET6_CACHEINFO] = { .name = "cacheinfo", .type = YNL_PT_BINARY,},
	[IFLA_INET6_ICMP6STATS] = { .name = "icmp6stats", .type = YNL_PT_BINARY,},
	[IFLA_INET6_TOKEN] = { .name = "token", .type = YNL_PT_BINARY,},
	[IFLA_INET6_ADDR_GEN_MODE] = { .name = "addr-gen-mode", .type = YNL_PT_U8, },
	[IFLA_INET6_RA_MTU] = { .name = "ra-mtu", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_ifla6_attrs_nest = {
	.max_attr = IFLA_INET6_MAX,
	.table = rt_link_ifla6_attrs_policy,
};

const struct ynl_policy_attr rt_link_mctp_attrs_policy[IFLA_MCTP_MAX + 1] = {
	[IFLA_MCTP_NET] = { .name = "net", .type = YNL_PT_U32, },
	[IFLA_MCTP_PHYS_BINDING] = { .name = "phys-binding", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest rt_link_mctp_attrs_nest = {
	.max_attr = IFLA_MCTP_MAX,
	.table = rt_link_mctp_attrs_policy,
};

const struct ynl_policy_attr rt_link_hw_s_info_one_policy[IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX + 1] = {
	[IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST] = { .name = "request", .type = YNL_PT_U8, },
	[IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED] = { .name = "used", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest rt_link_hw_s_info_one_nest = {
	.max_attr = IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX,
	.table = rt_link_hw_s_info_one_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_bridge_attrs_policy[IFLA_BR_MAX + 1] = {
	[IFLA_BR_FORWARD_DELAY] = { .name = "forward-delay", .type = YNL_PT_U32, },
	[IFLA_BR_HELLO_TIME] = { .name = "hello-time", .type = YNL_PT_U32, },
	[IFLA_BR_MAX_AGE] = { .name = "max-age", .type = YNL_PT_U32, },
	[IFLA_BR_AGEING_TIME] = { .name = "ageing-time", .type = YNL_PT_U32, },
	[IFLA_BR_STP_STATE] = { .name = "stp-state", .type = YNL_PT_U32, },
	[IFLA_BR_PRIORITY] = { .name = "priority", .type = YNL_PT_U16, },
	[IFLA_BR_VLAN_FILTERING] = { .name = "vlan-filtering", .type = YNL_PT_U8, },
	[IFLA_BR_VLAN_PROTOCOL] = { .name = "vlan-protocol", .type = YNL_PT_U16, },
	[IFLA_BR_GROUP_FWD_MASK] = { .name = "group-fwd-mask", .type = YNL_PT_U16, },
	[IFLA_BR_ROOT_ID] = { .name = "root-id", .type = YNL_PT_BINARY,},
	[IFLA_BR_BRIDGE_ID] = { .name = "bridge-id", .type = YNL_PT_BINARY,},
	[IFLA_BR_ROOT_PORT] = { .name = "root-port", .type = YNL_PT_U16, },
	[IFLA_BR_ROOT_PATH_COST] = { .name = "root-path-cost", .type = YNL_PT_U32, },
	[IFLA_BR_TOPOLOGY_CHANGE] = { .name = "topology-change", .type = YNL_PT_U8, },
	[IFLA_BR_TOPOLOGY_CHANGE_DETECTED] = { .name = "topology-change-detected", .type = YNL_PT_U8, },
	[IFLA_BR_HELLO_TIMER] = { .name = "hello-timer", .type = YNL_PT_U64, },
	[IFLA_BR_TCN_TIMER] = { .name = "tcn-timer", .type = YNL_PT_U64, },
	[IFLA_BR_TOPOLOGY_CHANGE_TIMER] = { .name = "topology-change-timer", .type = YNL_PT_U64, },
	[IFLA_BR_GC_TIMER] = { .name = "gc-timer", .type = YNL_PT_U64, },
	[IFLA_BR_GROUP_ADDR] = { .name = "group-addr", .type = YNL_PT_BINARY,},
	[IFLA_BR_FDB_FLUSH] = { .name = "fdb-flush", .type = YNL_PT_BINARY,},
	[IFLA_BR_MCAST_ROUTER] = { .name = "mcast-router", .type = YNL_PT_U8, },
	[IFLA_BR_MCAST_SNOOPING] = { .name = "mcast-snooping", .type = YNL_PT_U8, },
	[IFLA_BR_MCAST_QUERY_USE_IFADDR] = { .name = "mcast-query-use-ifaddr", .type = YNL_PT_U8, },
	[IFLA_BR_MCAST_QUERIER] = { .name = "mcast-querier", .type = YNL_PT_U8, },
	[IFLA_BR_MCAST_HASH_ELASTICITY] = { .name = "mcast-hash-elasticity", .type = YNL_PT_U32, },
	[IFLA_BR_MCAST_HASH_MAX] = { .name = "mcast-hash-max", .type = YNL_PT_U32, },
	[IFLA_BR_MCAST_LAST_MEMBER_CNT] = { .name = "mcast-last-member-cnt", .type = YNL_PT_U32, },
	[IFLA_BR_MCAST_STARTUP_QUERY_CNT] = { .name = "mcast-startup-query-cnt", .type = YNL_PT_U32, },
	[IFLA_BR_MCAST_LAST_MEMBER_INTVL] = { .name = "mcast-last-member-intvl", .type = YNL_PT_U64, },
	[IFLA_BR_MCAST_MEMBERSHIP_INTVL] = { .name = "mcast-membership-intvl", .type = YNL_PT_U64, },
	[IFLA_BR_MCAST_QUERIER_INTVL] = { .name = "mcast-querier-intvl", .type = YNL_PT_U64, },
	[IFLA_BR_MCAST_QUERY_INTVL] = { .name = "mcast-query-intvl", .type = YNL_PT_U64, },
	[IFLA_BR_MCAST_QUERY_RESPONSE_INTVL] = { .name = "mcast-query-response-intvl", .type = YNL_PT_U64, },
	[IFLA_BR_MCAST_STARTUP_QUERY_INTVL] = { .name = "mcast-startup-query-intvl", .type = YNL_PT_U64, },
	[IFLA_BR_NF_CALL_IPTABLES] = { .name = "nf-call-iptables", .type = YNL_PT_U8, },
	[IFLA_BR_NF_CALL_IP6TABLES] = { .name = "nf-call-ip6tables", .type = YNL_PT_U8, },
	[IFLA_BR_NF_CALL_ARPTABLES] = { .name = "nf-call-arptables", .type = YNL_PT_U8, },
	[IFLA_BR_VLAN_DEFAULT_PVID] = { .name = "vlan-default-pvid", .type = YNL_PT_U16, },
	[IFLA_BR_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[IFLA_BR_VLAN_STATS_ENABLED] = { .name = "vlan-stats-enabled", .type = YNL_PT_U8, },
	[IFLA_BR_MCAST_STATS_ENABLED] = { .name = "mcast-stats-enabled", .type = YNL_PT_U8, },
	[IFLA_BR_MCAST_IGMP_VERSION] = { .name = "mcast-igmp-version", .type = YNL_PT_U8, },
	[IFLA_BR_MCAST_MLD_VERSION] = { .name = "mcast-mld-version", .type = YNL_PT_U8, },
	[IFLA_BR_VLAN_STATS_PER_PORT] = { .name = "vlan-stats-per-port", .type = YNL_PT_U8, },
	[IFLA_BR_MULTI_BOOLOPT] = { .name = "multi-boolopt", .type = YNL_PT_BINARY,},
	[IFLA_BR_MCAST_QUERIER_STATE] = { .name = "mcast-querier-state", .type = YNL_PT_BINARY,},
	[IFLA_BR_FDB_N_LEARNED] = { .name = "fdb-n-learned", .type = YNL_PT_U32, },
	[IFLA_BR_FDB_MAX_LEARNED] = { .name = "fdb-max-learned", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_linkinfo_bridge_attrs_nest = {
	.max_attr = IFLA_BR_MAX,
	.table = rt_link_linkinfo_bridge_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_gre_attrs_policy[IFLA_GRE_MAX + 1] = {
	[IFLA_GRE_LINK] = { .name = "link", .type = YNL_PT_U32, },
	[IFLA_GRE_IFLAGS] = { .name = "iflags", .type = YNL_PT_U16, },
	[IFLA_GRE_OFLAGS] = { .name = "oflags", .type = YNL_PT_U16, },
	[IFLA_GRE_IKEY] = { .name = "ikey", .type = YNL_PT_U32, },
	[IFLA_GRE_OKEY] = { .name = "okey", .type = YNL_PT_U32, },
	[IFLA_GRE_LOCAL] = { .name = "local", .type = YNL_PT_BINARY,},
	[IFLA_GRE_REMOTE] = { .name = "remote", .type = YNL_PT_BINARY,},
	[IFLA_GRE_TTL] = { .name = "ttl", .type = YNL_PT_U8, },
	[IFLA_GRE_TOS] = { .name = "tos", .type = YNL_PT_U8, },
	[IFLA_GRE_PMTUDISC] = { .name = "pmtudisc", .type = YNL_PT_U8, },
	[IFLA_GRE_ENCAP_LIMIT] = { .name = "encap-limit", .type = YNL_PT_U8, },
	[IFLA_GRE_FLOWINFO] = { .name = "flowinfo", .type = YNL_PT_U32, },
	[IFLA_GRE_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[IFLA_GRE_ENCAP_TYPE] = { .name = "encap-type", .type = YNL_PT_U16, },
	[IFLA_GRE_ENCAP_FLAGS] = { .name = "encap-flags", .type = YNL_PT_U16, },
	[IFLA_GRE_ENCAP_SPORT] = { .name = "encap-sport", .type = YNL_PT_U16, },
	[IFLA_GRE_ENCAP_DPORT] = { .name = "encap-dport", .type = YNL_PT_U16, },
	[IFLA_GRE_COLLECT_METADATA] = { .name = "collect-metadata", .type = YNL_PT_FLAG, },
	[IFLA_GRE_IGNORE_DF] = { .name = "ignore-df", .type = YNL_PT_U8, },
	[IFLA_GRE_FWMARK] = { .name = "fwmark", .type = YNL_PT_U32, },
	[IFLA_GRE_ERSPAN_INDEX] = { .name = "erspan-index", .type = YNL_PT_U32, },
	[IFLA_GRE_ERSPAN_VER] = { .name = "erspan-ver", .type = YNL_PT_U8, },
	[IFLA_GRE_ERSPAN_DIR] = { .name = "erspan-dir", .type = YNL_PT_U8, },
	[IFLA_GRE_ERSPAN_HWID] = { .name = "erspan-hwid", .type = YNL_PT_U16, },
};

const struct ynl_policy_nest rt_link_linkinfo_gre_attrs_nest = {
	.max_attr = IFLA_GRE_MAX,
	.table = rt_link_linkinfo_gre_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_gre6_attrs_policy[IFLA_GRE_MAX + 1] = {
	[IFLA_GRE_LINK] = { .name = "link", .type = YNL_PT_U32, },
	[IFLA_GRE_IFLAGS] = { .name = "iflags", .type = YNL_PT_U16, },
	[IFLA_GRE_OFLAGS] = { .name = "oflags", .type = YNL_PT_U16, },
	[IFLA_GRE_IKEY] = { .name = "ikey", .type = YNL_PT_U32, },
	[IFLA_GRE_OKEY] = { .name = "okey", .type = YNL_PT_U32, },
	[IFLA_GRE_LOCAL] = { .name = "local", .type = YNL_PT_BINARY,},
	[IFLA_GRE_REMOTE] = { .name = "remote", .type = YNL_PT_BINARY,},
	[IFLA_GRE_TTL] = { .name = "ttl", .type = YNL_PT_U8, },
	[IFLA_GRE_ENCAP_LIMIT] = { .name = "encap-limit", .type = YNL_PT_U8, },
	[IFLA_GRE_FLOWINFO] = { .name = "flowinfo", .type = YNL_PT_U32, },
	[IFLA_GRE_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[IFLA_GRE_ENCAP_TYPE] = { .name = "encap-type", .type = YNL_PT_U16, },
	[IFLA_GRE_ENCAP_FLAGS] = { .name = "encap-flags", .type = YNL_PT_U16, },
	[IFLA_GRE_ENCAP_SPORT] = { .name = "encap-sport", .type = YNL_PT_U16, },
	[IFLA_GRE_ENCAP_DPORT] = { .name = "encap-dport", .type = YNL_PT_U16, },
	[IFLA_GRE_COLLECT_METADATA] = { .name = "collect-metadata", .type = YNL_PT_FLAG, },
	[IFLA_GRE_FWMARK] = { .name = "fwmark", .type = YNL_PT_U32, },
	[IFLA_GRE_ERSPAN_INDEX] = { .name = "erspan-index", .type = YNL_PT_U32, },
	[IFLA_GRE_ERSPAN_VER] = { .name = "erspan-ver", .type = YNL_PT_U8, },
	[IFLA_GRE_ERSPAN_DIR] = { .name = "erspan-dir", .type = YNL_PT_U8, },
	[IFLA_GRE_ERSPAN_HWID] = { .name = "erspan-hwid", .type = YNL_PT_U16, },
};

const struct ynl_policy_nest rt_link_linkinfo_gre6_attrs_nest = {
	.max_attr = IFLA_GRE_MAX,
	.table = rt_link_linkinfo_gre6_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_geneve_attrs_policy[IFLA_GENEVE_MAX + 1] = {
	[IFLA_GENEVE_ID] = { .name = "id", .type = YNL_PT_U32, },
	[IFLA_GENEVE_REMOTE] = { .name = "remote", .type = YNL_PT_U32, },
	[IFLA_GENEVE_TTL] = { .name = "ttl", .type = YNL_PT_U8, },
	[IFLA_GENEVE_TOS] = { .name = "tos", .type = YNL_PT_U8, },
	[IFLA_GENEVE_PORT] = { .name = "port", .type = YNL_PT_U16, },
	[IFLA_GENEVE_COLLECT_METADATA] = { .name = "collect-metadata", .type = YNL_PT_FLAG, },
	[IFLA_GENEVE_REMOTE6] = { .name = "remote6", .type = YNL_PT_BINARY,},
	[IFLA_GENEVE_UDP_CSUM] = { .name = "udp-csum", .type = YNL_PT_U8, },
	[IFLA_GENEVE_UDP_ZERO_CSUM6_TX] = { .name = "udp-zero-csum6-tx", .type = YNL_PT_U8, },
	[IFLA_GENEVE_UDP_ZERO_CSUM6_RX] = { .name = "udp-zero-csum6-rx", .type = YNL_PT_U8, },
	[IFLA_GENEVE_LABEL] = { .name = "label", .type = YNL_PT_U32, },
	[IFLA_GENEVE_TTL_INHERIT] = { .name = "ttl-inherit", .type = YNL_PT_U8, },
	[IFLA_GENEVE_DF] = { .name = "df", .type = YNL_PT_U8, },
	[IFLA_GENEVE_INNER_PROTO_INHERIT] = { .name = "inner-proto-inherit", .type = YNL_PT_FLAG, },
	[IFLA_GENEVE_PORT_RANGE] = { .name = "port-range", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest rt_link_linkinfo_geneve_attrs_nest = {
	.max_attr = IFLA_GENEVE_MAX,
	.table = rt_link_linkinfo_geneve_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_hsr_attrs_policy[IFLA_HSR_MAX + 1] = {
	[IFLA_HSR_SLAVE1] = { .name = "slave1", .type = YNL_PT_U32, },
	[IFLA_HSR_SLAVE2] = { .name = "slave2", .type = YNL_PT_U32, },
	[IFLA_HSR_MULTICAST_SPEC] = { .name = "multicast-spec", .type = YNL_PT_U8, },
	[IFLA_HSR_SUPERVISION_ADDR] = { .name = "supervision-addr", .type = YNL_PT_BINARY,},
	[IFLA_HSR_SEQ_NR] = { .name = "seq-nr", .type = YNL_PT_U16, },
	[IFLA_HSR_VERSION] = { .name = "version", .type = YNL_PT_U8, },
	[IFLA_HSR_PROTOCOL] = { .name = "protocol", .type = YNL_PT_U8, },
	[IFLA_HSR_INTERLINK] = { .name = "interlink", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_linkinfo_hsr_attrs_nest = {
	.max_attr = IFLA_HSR_MAX,
	.table = rt_link_linkinfo_hsr_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_iptun_attrs_policy[IFLA_IPTUN_MAX + 1] = {
	[IFLA_IPTUN_LINK] = { .name = "link", .type = YNL_PT_U32, },
	[IFLA_IPTUN_LOCAL] = { .name = "local", .type = YNL_PT_BINARY,},
	[IFLA_IPTUN_REMOTE] = { .name = "remote", .type = YNL_PT_BINARY,},
	[IFLA_IPTUN_TTL] = { .name = "ttl", .type = YNL_PT_U8, },
	[IFLA_IPTUN_TOS] = { .name = "tos", .type = YNL_PT_U8, },
	[IFLA_IPTUN_ENCAP_LIMIT] = { .name = "encap-limit", .type = YNL_PT_U8, },
	[IFLA_IPTUN_FLOWINFO] = { .name = "flowinfo", .type = YNL_PT_U32, },
	[IFLA_IPTUN_FLAGS] = { .name = "flags", .type = YNL_PT_U16, },
	[IFLA_IPTUN_PROTO] = { .name = "proto", .type = YNL_PT_U8, },
	[IFLA_IPTUN_PMTUDISC] = { .name = "pmtudisc", .type = YNL_PT_U8, },
	[IFLA_IPTUN_6RD_PREFIX] = { .name = "6rd-prefix", .type = YNL_PT_BINARY,},
	[IFLA_IPTUN_6RD_RELAY_PREFIX] = { .name = "6rd-relay-prefix", .type = YNL_PT_U32, },
	[IFLA_IPTUN_6RD_PREFIXLEN] = { .name = "6rd-prefixlen", .type = YNL_PT_U16, },
	[IFLA_IPTUN_6RD_RELAY_PREFIXLEN] = { .name = "6rd-relay-prefixlen", .type = YNL_PT_U16, },
	[IFLA_IPTUN_ENCAP_TYPE] = { .name = "encap-type", .type = YNL_PT_U16, },
	[IFLA_IPTUN_ENCAP_FLAGS] = { .name = "encap-flags", .type = YNL_PT_U16, },
	[IFLA_IPTUN_ENCAP_SPORT] = { .name = "encap-sport", .type = YNL_PT_U16, },
	[IFLA_IPTUN_ENCAP_DPORT] = { .name = "encap-dport", .type = YNL_PT_U16, },
	[IFLA_IPTUN_COLLECT_METADATA] = { .name = "collect-metadata", .type = YNL_PT_FLAG, },
	[IFLA_IPTUN_FWMARK] = { .name = "fwmark", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_linkinfo_iptun_attrs_nest = {
	.max_attr = IFLA_IPTUN_MAX,
	.table = rt_link_linkinfo_iptun_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_ip6tnl_attrs_policy[IFLA_IPTUN_MAX + 1] = {
	[IFLA_IPTUN_LINK] = { .name = "link", .type = YNL_PT_U32, },
	[IFLA_IPTUN_LOCAL] = { .name = "local", .type = YNL_PT_BINARY,},
	[IFLA_IPTUN_REMOTE] = { .name = "remote", .type = YNL_PT_BINARY,},
	[IFLA_IPTUN_TTL] = { .name = "ttl", .type = YNL_PT_U8, },
	[IFLA_IPTUN_ENCAP_LIMIT] = { .name = "encap-limit", .type = YNL_PT_U8, },
	[IFLA_IPTUN_FLOWINFO] = { .name = "flowinfo", .type = YNL_PT_U32, },
	[IFLA_IPTUN_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[IFLA_IPTUN_PROTO] = { .name = "proto", .type = YNL_PT_U8, },
	[IFLA_IPTUN_ENCAP_TYPE] = { .name = "encap-type", .type = YNL_PT_U16, },
	[IFLA_IPTUN_ENCAP_FLAGS] = { .name = "encap-flags", .type = YNL_PT_U16, },
	[IFLA_IPTUN_ENCAP_SPORT] = { .name = "encap-sport", .type = YNL_PT_U16, },
	[IFLA_IPTUN_ENCAP_DPORT] = { .name = "encap-dport", .type = YNL_PT_U16, },
	[IFLA_IPTUN_COLLECT_METADATA] = { .name = "collect-metadata", .type = YNL_PT_FLAG, },
	[IFLA_IPTUN_FWMARK] = { .name = "fwmark", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_linkinfo_ip6tnl_attrs_nest = {
	.max_attr = IFLA_IPTUN_MAX,
	.table = rt_link_linkinfo_ip6tnl_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_tun_attrs_policy[IFLA_TUN_MAX + 1] = {
	[IFLA_TUN_OWNER] = { .name = "owner", .type = YNL_PT_U32, },
	[IFLA_TUN_GROUP] = { .name = "group", .type = YNL_PT_U32, },
	[IFLA_TUN_TYPE] = { .name = "type", .type = YNL_PT_U8, },
	[IFLA_TUN_PI] = { .name = "pi", .type = YNL_PT_U8, },
	[IFLA_TUN_VNET_HDR] = { .name = "vnet-hdr", .type = YNL_PT_U8, },
	[IFLA_TUN_PERSIST] = { .name = "persist", .type = YNL_PT_U8, },
	[IFLA_TUN_MULTI_QUEUE] = { .name = "multi-queue", .type = YNL_PT_U8, },
	[IFLA_TUN_NUM_QUEUES] = { .name = "num-queues", .type = YNL_PT_U32, },
	[IFLA_TUN_NUM_DISABLED_QUEUES] = { .name = "num-disabled-queues", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_linkinfo_tun_attrs_nest = {
	.max_attr = IFLA_TUN_MAX,
	.table = rt_link_linkinfo_tun_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_vrf_attrs_policy[IFLA_VRF_MAX + 1] = {
	[IFLA_VRF_TABLE] = { .name = "table", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_linkinfo_vrf_attrs_nest = {
	.max_attr = IFLA_VRF_MAX,
	.table = rt_link_linkinfo_vrf_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_vti_attrs_policy[IFLA_VTI_MAX + 1] = {
	[IFLA_VTI_LINK] = { .name = "link", .type = YNL_PT_U32, },
	[IFLA_VTI_IKEY] = { .name = "ikey", .type = YNL_PT_U32, },
	[IFLA_VTI_OKEY] = { .name = "okey", .type = YNL_PT_U32, },
	[IFLA_VTI_LOCAL] = { .name = "local", .type = YNL_PT_BINARY,},
	[IFLA_VTI_REMOTE] = { .name = "remote", .type = YNL_PT_BINARY,},
	[IFLA_VTI_FWMARK] = { .name = "fwmark", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_linkinfo_vti_attrs_nest = {
	.max_attr = IFLA_VTI_MAX,
	.table = rt_link_linkinfo_vti_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_vti6_attrs_policy[IFLA_VTI_MAX + 1] = {
	[IFLA_VTI_LINK] = { .name = "link", .type = YNL_PT_U32, },
	[IFLA_VTI_IKEY] = { .name = "ikey", .type = YNL_PT_U32, },
	[IFLA_VTI_OKEY] = { .name = "okey", .type = YNL_PT_U32, },
	[IFLA_VTI_LOCAL] = { .name = "local", .type = YNL_PT_BINARY,},
	[IFLA_VTI_REMOTE] = { .name = "remote", .type = YNL_PT_BINARY,},
	[IFLA_VTI_FWMARK] = { .name = "fwmark", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_linkinfo_vti6_attrs_nest = {
	.max_attr = IFLA_VTI_MAX,
	.table = rt_link_linkinfo_vti6_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_netkit_attrs_policy[IFLA_NETKIT_MAX + 1] = {
	[IFLA_NETKIT_PEER_INFO] = { .name = "peer-info", .type = YNL_PT_BINARY,},
	[IFLA_NETKIT_PRIMARY] = { .name = "primary", .type = YNL_PT_U8, },
	[IFLA_NETKIT_POLICY] = { .name = "policy", .type = YNL_PT_U32, },
	[IFLA_NETKIT_PEER_POLICY] = { .name = "peer-policy", .type = YNL_PT_U32, },
	[IFLA_NETKIT_MODE] = { .name = "mode", .type = YNL_PT_U32, },
	[IFLA_NETKIT_SCRUB] = { .name = "scrub", .type = YNL_PT_U32, },
	[IFLA_NETKIT_PEER_SCRUB] = { .name = "peer-scrub", .type = YNL_PT_U32, },
	[IFLA_NETKIT_HEADROOM] = { .name = "headroom", .type = YNL_PT_U16, },
	[IFLA_NETKIT_TAILROOM] = { .name = "tailroom", .type = YNL_PT_U16, },
};

const struct ynl_policy_nest rt_link_linkinfo_netkit_attrs_nest = {
	.max_attr = IFLA_NETKIT_MAX,
	.table = rt_link_linkinfo_netkit_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_ovpn_attrs_policy[IFLA_OVPN_MAX + 1] = {
	[IFLA_OVPN_MODE] = { .name = "mode", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest rt_link_linkinfo_ovpn_attrs_nest = {
	.max_attr = IFLA_OVPN_MAX,
	.table = rt_link_linkinfo_ovpn_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_brport_attrs_policy[IFLA_BRPORT_MAX + 1] = {
	[IFLA_BRPORT_STATE] = { .name = "state", .type = YNL_PT_U8, },
	[IFLA_BRPORT_PRIORITY] = { .name = "priority", .type = YNL_PT_U16, },
	[IFLA_BRPORT_COST] = { .name = "cost", .type = YNL_PT_U32, },
	[IFLA_BRPORT_MODE] = { .name = "mode", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_GUARD] = { .name = "guard", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_PROTECT] = { .name = "protect", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_FAST_LEAVE] = { .name = "fast-leave", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_LEARNING] = { .name = "learning", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_UNICAST_FLOOD] = { .name = "unicast-flood", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_PROXYARP] = { .name = "proxyarp", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_LEARNING_SYNC] = { .name = "learning-sync", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_PROXYARP_WIFI] = { .name = "proxyarp-wifi", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_ROOT_ID] = { .name = "root-id", .type = YNL_PT_BINARY,},
	[IFLA_BRPORT_BRIDGE_ID] = { .name = "bridge-id", .type = YNL_PT_BINARY,},
	[IFLA_BRPORT_DESIGNATED_PORT] = { .name = "designated-port", .type = YNL_PT_U16, },
	[IFLA_BRPORT_DESIGNATED_COST] = { .name = "designated-cost", .type = YNL_PT_U16, },
	[IFLA_BRPORT_ID] = { .name = "id", .type = YNL_PT_U16, },
	[IFLA_BRPORT_NO] = { .name = "no", .type = YNL_PT_U16, },
	[IFLA_BRPORT_TOPOLOGY_CHANGE_ACK] = { .name = "topology-change-ack", .type = YNL_PT_U8, },
	[IFLA_BRPORT_CONFIG_PENDING] = { .name = "config-pending", .type = YNL_PT_U8, },
	[IFLA_BRPORT_MESSAGE_AGE_TIMER] = { .name = "message-age-timer", .type = YNL_PT_U64, },
	[IFLA_BRPORT_FORWARD_DELAY_TIMER] = { .name = "forward-delay-timer", .type = YNL_PT_U64, },
	[IFLA_BRPORT_HOLD_TIMER] = { .name = "hold-timer", .type = YNL_PT_U64, },
	[IFLA_BRPORT_FLUSH] = { .name = "flush", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_MULTICAST_ROUTER] = { .name = "multicast-router", .type = YNL_PT_U8, },
	[IFLA_BRPORT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[IFLA_BRPORT_MCAST_FLOOD] = { .name = "mcast-flood", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_MCAST_TO_UCAST] = { .name = "mcast-to-ucast", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_VLAN_TUNNEL] = { .name = "vlan-tunnel", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_BCAST_FLOOD] = { .name = "bcast-flood", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_GROUP_FWD_MASK] = { .name = "group-fwd-mask", .type = YNL_PT_U16, },
	[IFLA_BRPORT_NEIGH_SUPPRESS] = { .name = "neigh-suppress", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_ISOLATED] = { .name = "isolated", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_BACKUP_PORT] = { .name = "backup-port", .type = YNL_PT_U32, },
	[IFLA_BRPORT_MRP_RING_OPEN] = { .name = "mrp-ring-open", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_MRP_IN_OPEN] = { .name = "mrp-in-open", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT] = { .name = "mcast-eht-hosts-limit", .type = YNL_PT_U32, },
	[IFLA_BRPORT_MCAST_EHT_HOSTS_CNT] = { .name = "mcast-eht-hosts-cnt", .type = YNL_PT_U32, },
	[IFLA_BRPORT_LOCKED] = { .name = "locked", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_MAB] = { .name = "mab", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_MCAST_N_GROUPS] = { .name = "mcast-n-groups", .type = YNL_PT_U32, },
	[IFLA_BRPORT_MCAST_MAX_GROUPS] = { .name = "mcast-max-groups", .type = YNL_PT_U32, },
	[IFLA_BRPORT_NEIGH_VLAN_SUPPRESS] = { .name = "neigh-vlan-suppress", .type = YNL_PT_FLAG, },
	[IFLA_BRPORT_BACKUP_NHID] = { .name = "backup-nhid", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_linkinfo_brport_attrs_nest = {
	.max_attr = IFLA_BRPORT_MAX,
	.table = rt_link_linkinfo_brport_attrs_policy,
};

const struct ynl_policy_attr rt_link_bond_slave_attrs_policy[IFLA_BOND_SLAVE_MAX + 1] = {
	[IFLA_BOND_SLAVE_STATE] = { .name = "state", .type = YNL_PT_U8, },
	[IFLA_BOND_SLAVE_MII_STATUS] = { .name = "mii-status", .type = YNL_PT_U8, },
	[IFLA_BOND_SLAVE_LINK_FAILURE_COUNT] = { .name = "link-failure-count", .type = YNL_PT_U32, },
	[IFLA_BOND_SLAVE_PERM_HWADDR] = { .name = "perm-hwaddr", .type = YNL_PT_BINARY,},
	[IFLA_BOND_SLAVE_QUEUE_ID] = { .name = "queue-id", .type = YNL_PT_U16, },
	[IFLA_BOND_SLAVE_AD_AGGREGATOR_ID] = { .name = "ad-aggregator-id", .type = YNL_PT_U16, },
	[IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE] = { .name = "ad-actor-oper-port-state", .type = YNL_PT_U8, },
	[IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE] = { .name = "ad-partner-oper-port-state", .type = YNL_PT_U16, },
	[IFLA_BOND_SLAVE_PRIO] = { .name = "prio", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_link_bond_slave_attrs_nest = {
	.max_attr = IFLA_BOND_SLAVE_MAX,
	.table = rt_link_bond_slave_attrs_policy,
};

const struct ynl_policy_attr rt_link_vf_stats_attrs_policy[IFLA_VF_STATS_MAX + 1] = {
	[IFLA_VF_STATS_RX_PACKETS] = { .name = "rx-packets", .type = YNL_PT_U64, },
	[IFLA_VF_STATS_TX_PACKETS] = { .name = "tx-packets", .type = YNL_PT_U64, },
	[IFLA_VF_STATS_RX_BYTES] = { .name = "rx-bytes", .type = YNL_PT_U64, },
	[IFLA_VF_STATS_TX_BYTES] = { .name = "tx-bytes", .type = YNL_PT_U64, },
	[IFLA_VF_STATS_BROADCAST] = { .name = "broadcast", .type = YNL_PT_U64, },
	[IFLA_VF_STATS_MULTICAST] = { .name = "multicast", .type = YNL_PT_U64, },
	[IFLA_VF_STATS_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[IFLA_VF_STATS_RX_DROPPED] = { .name = "rx-dropped", .type = YNL_PT_U64, },
	[IFLA_VF_STATS_TX_DROPPED] = { .name = "tx-dropped", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest rt_link_vf_stats_attrs_nest = {
	.max_attr = IFLA_VF_STATS_MAX,
	.table = rt_link_vf_stats_attrs_policy,
};

const struct ynl_policy_attr rt_link_vf_vlan_attrs_policy[IFLA_VF_VLAN_INFO_MAX + 1] = {
	[IFLA_VF_VLAN_INFO] = { .name = "info", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest rt_link_vf_vlan_attrs_nest = {
	.max_attr = IFLA_VF_VLAN_INFO_MAX,
	.table = rt_link_vf_vlan_attrs_policy,
};

const struct ynl_policy_attr rt_link_bond_ad_info_attrs_policy[IFLA_BOND_AD_INFO_MAX + 1] = {
	[IFLA_BOND_AD_INFO_AGGREGATOR] = { .name = "aggregator", .type = YNL_PT_U16, },
	[IFLA_BOND_AD_INFO_NUM_PORTS] = { .name = "num-ports", .type = YNL_PT_U16, },
	[IFLA_BOND_AD_INFO_ACTOR_KEY] = { .name = "actor-key", .type = YNL_PT_U16, },
	[IFLA_BOND_AD_INFO_PARTNER_KEY] = { .name = "partner-key", .type = YNL_PT_U16, },
	[IFLA_BOND_AD_INFO_PARTNER_MAC] = { .name = "partner-mac", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest rt_link_bond_ad_info_attrs_nest = {
	.max_attr = IFLA_BOND_AD_INFO_MAX,
	.table = rt_link_bond_ad_info_attrs_policy,
};

const struct ynl_policy_attr rt_link_ifla_vlan_qos_policy[IFLA_VLAN_QOS_MAX + 1] = {
	[IFLA_VLAN_QOS_MAPPING] = { .name = "mapping", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest rt_link_ifla_vlan_qos_nest = {
	.max_attr = IFLA_VLAN_QOS_MAX,
	.table = rt_link_ifla_vlan_qos_policy,
};

const struct ynl_policy_attr rt_link_af_spec_attrs_policy[AF_MAX + 1] = {
	[AF_INET] = { .name = "inet", .type = YNL_PT_NEST, .nest = &rt_link_ifla_attrs_nest, },
	[AF_INET6] = { .name = "inet6", .type = YNL_PT_NEST, .nest = &rt_link_ifla6_attrs_nest, },
	[AF_MCTP] = { .name = "mctp", .type = YNL_PT_NEST, .nest = &rt_link_mctp_attrs_nest, },
};

const struct ynl_policy_nest rt_link_af_spec_attrs_nest = {
	.max_attr = AF_MAX,
	.table = rt_link_af_spec_attrs_policy,
};

const struct ynl_policy_attr rt_link_link_offload_xstats_policy[IFLA_OFFLOAD_XSTATS_MAX + 1] = {
	[IFLA_OFFLOAD_XSTATS_CPU_HIT] = { .name = "cpu-hit", .type = YNL_PT_BINARY,},
	[IFLA_OFFLOAD_XSTATS_HW_S_INFO] = { .name = "hw-s-info", .type = YNL_PT_NEST, .nest = &rt_link_hw_s_info_one_nest, },
	[IFLA_OFFLOAD_XSTATS_L3_STATS] = { .name = "l3-stats", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest rt_link_link_offload_xstats_nest = {
	.max_attr = IFLA_OFFLOAD_XSTATS_MAX,
	.table = rt_link_link_offload_xstats_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_member_data_msg_policy[] = {
	[0] = { .type = YNL_PT_SUBMSG, .name = "bridge", .nest = &rt_link_linkinfo_brport_attrs_nest, },
	[1] = { .type = YNL_PT_SUBMSG, .name = "bond", .nest = &rt_link_bond_slave_attrs_nest, },
};

const struct ynl_policy_nest rt_link_linkinfo_member_data_msg_nest = {
	.max_attr = 1,
	.table = rt_link_linkinfo_member_data_msg_policy,
};

const struct ynl_policy_attr rt_link_vfinfo_attrs_policy[IFLA_VF_MAX + 1] = {
	[IFLA_VF_MAC] = { .name = "mac", .type = YNL_PT_BINARY,},
	[IFLA_VF_VLAN] = { .name = "vlan", .type = YNL_PT_BINARY,},
	[IFLA_VF_TX_RATE] = { .name = "tx-rate", .type = YNL_PT_BINARY,},
	[IFLA_VF_SPOOFCHK] = { .name = "spoofchk", .type = YNL_PT_BINARY,},
	[IFLA_VF_LINK_STATE] = { .name = "link-state", .type = YNL_PT_BINARY,},
	[IFLA_VF_RATE] = { .name = "rate", .type = YNL_PT_BINARY,},
	[IFLA_VF_RSS_QUERY_EN] = { .name = "rss-query-en", .type = YNL_PT_BINARY,},
	[IFLA_VF_STATS] = { .name = "stats", .type = YNL_PT_NEST, .nest = &rt_link_vf_stats_attrs_nest, },
	[IFLA_VF_TRUST] = { .name = "trust", .type = YNL_PT_BINARY,},
	[IFLA_VF_IB_NODE_GUID] = { .name = "ib-node-guid", .type = YNL_PT_BINARY,},
	[IFLA_VF_IB_PORT_GUID] = { .name = "ib-port-guid", .type = YNL_PT_BINARY,},
	[IFLA_VF_VLAN_LIST] = { .name = "vlan-list", .type = YNL_PT_NEST, .nest = &rt_link_vf_vlan_attrs_nest, },
	[IFLA_VF_BROADCAST] = { .name = "broadcast", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest rt_link_vfinfo_attrs_nest = {
	.max_attr = IFLA_VF_MAX,
	.table = rt_link_vfinfo_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_bond_attrs_policy[IFLA_BOND_MAX + 1] = {
	[IFLA_BOND_MODE] = { .name = "mode", .type = YNL_PT_U8, },
	[IFLA_BOND_ACTIVE_SLAVE] = { .name = "active-slave", .type = YNL_PT_U32, },
	[IFLA_BOND_MIIMON] = { .name = "miimon", .type = YNL_PT_U32, },
	[IFLA_BOND_UPDELAY] = { .name = "updelay", .type = YNL_PT_U32, },
	[IFLA_BOND_DOWNDELAY] = { .name = "downdelay", .type = YNL_PT_U32, },
	[IFLA_BOND_USE_CARRIER] = { .name = "use-carrier", .type = YNL_PT_U8, },
	[IFLA_BOND_ARP_INTERVAL] = { .name = "arp-interval", .type = YNL_PT_U32, },
	[IFLA_BOND_ARP_IP_TARGET] = { .name = "arp-ip-target", .type = YNL_PT_U32, },
	[IFLA_BOND_ARP_VALIDATE] = { .name = "arp-validate", .type = YNL_PT_U32, },
	[IFLA_BOND_ARP_ALL_TARGETS] = { .name = "arp-all-targets", .type = YNL_PT_U32, },
	[IFLA_BOND_PRIMARY] = { .name = "primary", .type = YNL_PT_U32, },
	[IFLA_BOND_PRIMARY_RESELECT] = { .name = "primary-reselect", .type = YNL_PT_U8, },
	[IFLA_BOND_FAIL_OVER_MAC] = { .name = "fail-over-mac", .type = YNL_PT_U8, },
	[IFLA_BOND_XMIT_HASH_POLICY] = { .name = "xmit-hash-policy", .type = YNL_PT_U8, },
	[IFLA_BOND_RESEND_IGMP] = { .name = "resend-igmp", .type = YNL_PT_U32, },
	[IFLA_BOND_NUM_PEER_NOTIF] = { .name = "num-peer-notif", .type = YNL_PT_U8, },
	[IFLA_BOND_ALL_SLAVES_ACTIVE] = { .name = "all-slaves-active", .type = YNL_PT_U8, },
	[IFLA_BOND_MIN_LINKS] = { .name = "min-links", .type = YNL_PT_U32, },
	[IFLA_BOND_LP_INTERVAL] = { .name = "lp-interval", .type = YNL_PT_U32, },
	[IFLA_BOND_PACKETS_PER_SLAVE] = { .name = "packets-per-slave", .type = YNL_PT_U32, },
	[IFLA_BOND_AD_LACP_RATE] = { .name = "ad-lacp-rate", .type = YNL_PT_U8, },
	[IFLA_BOND_AD_SELECT] = { .name = "ad-select", .type = YNL_PT_U8, },
	[IFLA_BOND_AD_INFO] = { .name = "ad-info", .type = YNL_PT_NEST, .nest = &rt_link_bond_ad_info_attrs_nest, },
	[IFLA_BOND_AD_ACTOR_SYS_PRIO] = { .name = "ad-actor-sys-prio", .type = YNL_PT_U16, },
	[IFLA_BOND_AD_USER_PORT_KEY] = { .name = "ad-user-port-key", .type = YNL_PT_U16, },
	[IFLA_BOND_AD_ACTOR_SYSTEM] = { .name = "ad-actor-system", .type = YNL_PT_BINARY,},
	[IFLA_BOND_TLB_DYNAMIC_LB] = { .name = "tlb-dynamic-lb", .type = YNL_PT_U8, },
	[IFLA_BOND_PEER_NOTIF_DELAY] = { .name = "peer-notif-delay", .type = YNL_PT_U32, },
	[IFLA_BOND_AD_LACP_ACTIVE] = { .name = "ad-lacp-active", .type = YNL_PT_U8, },
	[IFLA_BOND_MISSED_MAX] = { .name = "missed-max", .type = YNL_PT_U8, },
	[IFLA_BOND_NS_IP6_TARGET] = { .name = "ns-ip6-target", .type = YNL_PT_BINARY, .len = 16, },
	[IFLA_BOND_COUPLED_CONTROL] = { .name = "coupled-control", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest rt_link_linkinfo_bond_attrs_nest = {
	.max_attr = IFLA_BOND_MAX,
	.table = rt_link_linkinfo_bond_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_vlan_attrs_policy[IFLA_VLAN_MAX + 1] = {
	[IFLA_VLAN_ID] = { .name = "id", .type = YNL_PT_U16, },
	[IFLA_VLAN_FLAGS] = { .name = "flags", .type = YNL_PT_BINARY,},
	[IFLA_VLAN_EGRESS_QOS] = { .name = "egress-qos", .type = YNL_PT_NEST, .nest = &rt_link_ifla_vlan_qos_nest, },
	[IFLA_VLAN_INGRESS_QOS] = { .name = "ingress-qos", .type = YNL_PT_NEST, .nest = &rt_link_ifla_vlan_qos_nest, },
	[IFLA_VLAN_PROTOCOL] = { .name = "protocol", .type = YNL_PT_U16, },
};

const struct ynl_policy_nest rt_link_linkinfo_vlan_attrs_nest = {
	.max_attr = IFLA_VLAN_MAX,
	.table = rt_link_linkinfo_vlan_attrs_policy,
};

const struct ynl_policy_attr rt_link_vfinfo_list_attrs_policy[IFLA_VF_MAX + 1] = {
	[IFLA_VF_INFO] = { .name = "info", .type = YNL_PT_NEST, .nest = &rt_link_vfinfo_attrs_nest, },
};

const struct ynl_policy_nest rt_link_vfinfo_list_attrs_nest = {
	.max_attr = IFLA_VF_MAX,
	.table = rt_link_vfinfo_list_attrs_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_data_msg_policy[] = {
	[0] = { .type = YNL_PT_SUBMSG, .name = "bond", .nest = &rt_link_linkinfo_bond_attrs_nest, },
	[1] = { .type = YNL_PT_SUBMSG, .name = "bridge", .nest = &rt_link_linkinfo_bridge_attrs_nest, },
	[2] = { .type = YNL_PT_SUBMSG, .name = "erspan", .nest = &rt_link_linkinfo_gre_attrs_nest, },
	[3] = { .type = YNL_PT_SUBMSG, .name = "gre", .nest = &rt_link_linkinfo_gre_attrs_nest, },
	[4] = { .type = YNL_PT_SUBMSG, .name = "gretap", .nest = &rt_link_linkinfo_gre_attrs_nest, },
	[5] = { .type = YNL_PT_SUBMSG, .name = "ip6gre", .nest = &rt_link_linkinfo_gre6_attrs_nest, },
	[6] = { .type = YNL_PT_SUBMSG, .name = "geneve", .nest = &rt_link_linkinfo_geneve_attrs_nest, },
	[7] = { .type = YNL_PT_SUBMSG, .name = "hsr", .nest = &rt_link_linkinfo_hsr_attrs_nest, },
	[8] = { .type = YNL_PT_SUBMSG, .name = "ipip", .nest = &rt_link_linkinfo_iptun_attrs_nest, },
	[9] = { .type = YNL_PT_SUBMSG, .name = "ip6tnl", .nest = &rt_link_linkinfo_ip6tnl_attrs_nest, },
	[10] = { .type = YNL_PT_SUBMSG, .name = "sit", .nest = &rt_link_linkinfo_iptun_attrs_nest, },
	[11] = { .type = YNL_PT_SUBMSG, .name = "tun", .nest = &rt_link_linkinfo_tun_attrs_nest, },
	[12] = { .type = YNL_PT_SUBMSG, .name = "vlan", .nest = &rt_link_linkinfo_vlan_attrs_nest, },
	[13] = { .type = YNL_PT_SUBMSG, .name = "vrf", .nest = &rt_link_linkinfo_vrf_attrs_nest, },
	[14] = { .type = YNL_PT_SUBMSG, .name = "vti", .nest = &rt_link_linkinfo_vti_attrs_nest, },
	[15] = { .type = YNL_PT_SUBMSG, .name = "vti6", .nest = &rt_link_linkinfo_vti6_attrs_nest, },
	[16] = { .type = YNL_PT_SUBMSG, .name = "netkit", .nest = &rt_link_linkinfo_netkit_attrs_nest, },
	[17] = { .type = YNL_PT_SUBMSG, .name = "ovpn", .nest = &rt_link_linkinfo_ovpn_attrs_nest, },
};

const struct ynl_policy_nest rt_link_linkinfo_data_msg_nest = {
	.max_attr = 17,
	.table = rt_link_linkinfo_data_msg_policy,
};

const struct ynl_policy_attr rt_link_linkinfo_attrs_policy[IFLA_INFO_MAX + 1] = {
	[IFLA_INFO_KIND] = { .name = "kind", .type = YNL_PT_NUL_STR, .is_selector = 1, },
	[IFLA_INFO_DATA] = { .name = "data", .type = YNL_PT_NEST, .nest = &rt_link_linkinfo_data_msg_nest, .is_submsg = 1, .selector_type = 1 },
	[IFLA_INFO_XSTATS] = { .name = "xstats", .type = YNL_PT_BINARY,},
	[IFLA_INFO_SLAVE_KIND] = { .name = "slave-kind", .type = YNL_PT_NUL_STR, .is_selector = 1, },
	[IFLA_INFO_SLAVE_DATA] = { .name = "slave-data", .type = YNL_PT_NEST, .nest = &rt_link_linkinfo_member_data_msg_nest, .is_submsg = 1, .selector_type = 4 },
};

const struct ynl_policy_nest rt_link_linkinfo_attrs_nest = {
	.max_attr = IFLA_INFO_MAX,
	.table = rt_link_linkinfo_attrs_policy,
};

const struct ynl_policy_attr rt_link_link_attrs_policy[IFLA_MAX + 1] = {
	[IFLA_ADDRESS] = { .name = "address", .type = YNL_PT_BINARY,},
	[IFLA_BROADCAST] = { .name = "broadcast", .type = YNL_PT_BINARY,},
	[IFLA_IFNAME] = { .name = "ifname", .type = YNL_PT_NUL_STR, },
	[IFLA_MTU] = { .name = "mtu", .type = YNL_PT_U32, },
	[IFLA_LINK] = { .name = "link", .type = YNL_PT_U32, },
	[IFLA_QDISC] = { .name = "qdisc", .type = YNL_PT_NUL_STR, },
	[IFLA_STATS] = { .name = "stats", .type = YNL_PT_BINARY,},
	[IFLA_COST] = { .name = "cost", .type = YNL_PT_NUL_STR, },
	[IFLA_PRIORITY] = { .name = "priority", .type = YNL_PT_NUL_STR, },
	[IFLA_MASTER] = { .name = "master", .type = YNL_PT_U32, },
	[IFLA_WIRELESS] = { .name = "wireless", .type = YNL_PT_NUL_STR, },
	[IFLA_PROTINFO] = { .name = "protinfo", .type = YNL_PT_NUL_STR, },
	[IFLA_TXQLEN] = { .name = "txqlen", .type = YNL_PT_U32, },
	[IFLA_MAP] = { .name = "map", .type = YNL_PT_BINARY,},
	[IFLA_WEIGHT] = { .name = "weight", .type = YNL_PT_U32, },
	[IFLA_OPERSTATE] = { .name = "operstate", .type = YNL_PT_U8, },
	[IFLA_LINKMODE] = { .name = "linkmode", .type = YNL_PT_U8, },
	[IFLA_LINKINFO] = { .name = "linkinfo", .type = YNL_PT_NEST, .nest = &rt_link_linkinfo_attrs_nest, },
	[IFLA_NET_NS_PID] = { .name = "net-ns-pid", .type = YNL_PT_U32, },
	[IFLA_IFALIAS] = { .name = "ifalias", .type = YNL_PT_NUL_STR, },
	[IFLA_NUM_VF] = { .name = "num-vf", .type = YNL_PT_U32, },
	[IFLA_VFINFO_LIST] = { .name = "vfinfo-list", .type = YNL_PT_NEST, .nest = &rt_link_vfinfo_list_attrs_nest, },
	[IFLA_STATS64] = { .name = "stats64", .type = YNL_PT_BINARY,},
	[IFLA_VF_PORTS] = { .name = "vf-ports", .type = YNL_PT_NEST, .nest = &rt_link_vf_ports_attrs_nest, },
	[IFLA_PORT_SELF] = { .name = "port-self", .type = YNL_PT_NEST, .nest = &rt_link_port_self_attrs_nest, },
	[IFLA_AF_SPEC] = { .name = "af-spec", .type = YNL_PT_NEST, .nest = &rt_link_af_spec_attrs_nest, },
	[IFLA_GROUP] = { .name = "group", .type = YNL_PT_U32, },
	[IFLA_NET_NS_FD] = { .name = "net-ns-fd", .type = YNL_PT_U32, },
	[IFLA_EXT_MASK] = { .name = "ext-mask", .type = YNL_PT_U32, },
	[IFLA_PROMISCUITY] = { .name = "promiscuity", .type = YNL_PT_U32, },
	[IFLA_NUM_TX_QUEUES] = { .name = "num-tx-queues", .type = YNL_PT_U32, },
	[IFLA_NUM_RX_QUEUES] = { .name = "num-rx-queues", .type = YNL_PT_U32, },
	[IFLA_CARRIER] = { .name = "carrier", .type = YNL_PT_U8, },
	[IFLA_PHYS_PORT_ID] = { .name = "phys-port-id", .type = YNL_PT_BINARY,},
	[IFLA_CARRIER_CHANGES] = { .name = "carrier-changes", .type = YNL_PT_U32, },
	[IFLA_PHYS_SWITCH_ID] = { .name = "phys-switch-id", .type = YNL_PT_BINARY,},
	[IFLA_LINK_NETNSID] = { .name = "link-netnsid", .type = YNL_PT_U32, },
	[IFLA_PHYS_PORT_NAME] = { .name = "phys-port-name", .type = YNL_PT_NUL_STR, },
	[IFLA_PROTO_DOWN] = { .name = "proto-down", .type = YNL_PT_U8, },
	[IFLA_GSO_MAX_SEGS] = { .name = "gso-max-segs", .type = YNL_PT_U32, },
	[IFLA_GSO_MAX_SIZE] = { .name = "gso-max-size", .type = YNL_PT_U32, },
	[IFLA_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[IFLA_XDP] = { .name = "xdp", .type = YNL_PT_NEST, .nest = &rt_link_xdp_attrs_nest, },
	[IFLA_EVENT] = { .name = "event", .type = YNL_PT_U32, },
	[IFLA_NEW_NETNSID] = { .name = "new-netnsid", .type = YNL_PT_U32, },
	[IFLA_TARGET_NETNSID] = { .name = "target-netnsid", .type = YNL_PT_U32, },
	[IFLA_CARRIER_UP_COUNT] = { .name = "carrier-up-count", .type = YNL_PT_U32, },
	[IFLA_CARRIER_DOWN_COUNT] = { .name = "carrier-down-count", .type = YNL_PT_U32, },
	[IFLA_NEW_IFINDEX] = { .name = "new-ifindex", .type = YNL_PT_U32, },
	[IFLA_MIN_MTU] = { .name = "min-mtu", .type = YNL_PT_U32, },
	[IFLA_MAX_MTU] = { .name = "max-mtu", .type = YNL_PT_U32, },
	[IFLA_PROP_LIST] = { .name = "prop-list", .type = YNL_PT_NEST, .nest = &rt_link_prop_list_link_attrs_nest, },
	[IFLA_ALT_IFNAME] = { .name = "alt-ifname", .type = YNL_PT_NUL_STR, },
	[IFLA_PERM_ADDRESS] = { .name = "perm-address", .type = YNL_PT_BINARY,},
	[IFLA_PROTO_DOWN_REASON] = { .name = "proto-down-reason", .type = YNL_PT_NUL_STR, },
	[IFLA_PARENT_DEV_NAME] = { .name = "parent-dev-name", .type = YNL_PT_NUL_STR, },
	[IFLA_PARENT_DEV_BUS_NAME] = { .name = "parent-dev-bus-name", .type = YNL_PT_NUL_STR, },
	[IFLA_GRO_MAX_SIZE] = { .name = "gro-max-size", .type = YNL_PT_U32, },
	[IFLA_TSO_MAX_SIZE] = { .name = "tso-max-size", .type = YNL_PT_U32, },
	[IFLA_TSO_MAX_SEGS] = { .name = "tso-max-segs", .type = YNL_PT_U32, },
	[IFLA_ALLMULTI] = { .name = "allmulti", .type = YNL_PT_U32, },
	[IFLA_DEVLINK_PORT] = { .name = "devlink-port", .type = YNL_PT_BINARY,},
	[IFLA_GSO_IPV4_MAX_SIZE] = { .name = "gso-ipv4-max-size", .type = YNL_PT_U32, },
	[IFLA_GRO_IPV4_MAX_SIZE] = { .name = "gro-ipv4-max-size", .type = YNL_PT_U32, },
	[IFLA_DPLL_PIN] = { .name = "dpll-pin", .type = YNL_PT_NEST, .nest = &rt_link_link_dpll_pin_attrs_nest, },
	[IFLA_MAX_PACING_OFFLOAD_HORIZON] = { .name = "max-pacing-offload-horizon", .type = YNL_PT_UINT, },
	[IFLA_NETNS_IMMUTABLE] = { .name = "netns-immutable", .type = YNL_PT_U8, },
	[IFLA_HEADROOM] = { .name = "headroom", .type = YNL_PT_U16, },
	[IFLA_TAILROOM] = { .name = "tailroom", .type = YNL_PT_U16, },
};

const struct ynl_policy_nest rt_link_link_attrs_nest = {
	.max_attr = IFLA_MAX,
	.table = rt_link_link_attrs_policy,
};

const struct ynl_policy_attr rt_link_stats_attrs_policy[IFLA_STATS_MAX + 1] = {
	[IFLA_STATS_LINK_64] = { .name = "link-64", .type = YNL_PT_BINARY,},
	[IFLA_STATS_LINK_XSTATS] = { .name = "link-xstats", .type = YNL_PT_BINARY,},
	[IFLA_STATS_LINK_XSTATS_SLAVE] = { .name = "link-xstats-slave", .type = YNL_PT_BINARY,},
	[IFLA_STATS_LINK_OFFLOAD_XSTATS] = { .name = "link-offload-xstats", .type = YNL_PT_NEST, .nest = &rt_link_link_offload_xstats_nest, },
	[IFLA_STATS_AF_SPEC] = { .name = "af-spec", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest rt_link_stats_attrs_nest = {
	.max_attr = IFLA_STATS_MAX,
	.table = rt_link_stats_attrs_policy,
};

/* Common nested types */
void rt_link_vf_ports_attrs_free(struct rt_link_vf_ports_attrs *obj)
{
}

int rt_link_vf_ports_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       struct rt_link_vf_ports_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vf_ports_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	return 0;
}

void rt_link_port_self_attrs_free(struct rt_link_port_self_attrs *obj)
{
}

int rt_link_port_self_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				struct rt_link_port_self_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_port_self_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	return 0;
}

void rt_link_xdp_attrs_free(struct rt_link_xdp_attrs *obj)
{
}

int rt_link_xdp_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct rt_link_xdp_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.fd)
		ynl_attr_put_s32(nlh, IFLA_XDP_FD, obj->fd);
	if (obj->_present.attached)
		ynl_attr_put_u8(nlh, IFLA_XDP_ATTACHED, obj->attached);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, IFLA_XDP_FLAGS, obj->flags);
	if (obj->_present.prog_id)
		ynl_attr_put_u32(nlh, IFLA_XDP_PROG_ID, obj->prog_id);
	if (obj->_present.drv_prog_id)
		ynl_attr_put_u32(nlh, IFLA_XDP_DRV_PROG_ID, obj->drv_prog_id);
	if (obj->_present.skb_prog_id)
		ynl_attr_put_u32(nlh, IFLA_XDP_SKB_PROG_ID, obj->skb_prog_id);
	if (obj->_present.hw_prog_id)
		ynl_attr_put_u32(nlh, IFLA_XDP_HW_PROG_ID, obj->hw_prog_id);
	if (obj->_present.expected_fd)
		ynl_attr_put_s32(nlh, IFLA_XDP_EXPECTED_FD, obj->expected_fd);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_xdp_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct rt_link_xdp_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_XDP_FD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fd = 1;
			dst->fd = ynl_attr_get_s32(attr);
		} else if (type == IFLA_XDP_ATTACHED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.attached = 1;
			dst->attached = ynl_attr_get_u8(attr);
		} else if (type == IFLA_XDP_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_PROG_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.prog_id = 1;
			dst->prog_id = ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_DRV_PROG_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.drv_prog_id = 1;
			dst->drv_prog_id = ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_SKB_PROG_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.skb_prog_id = 1;
			dst->skb_prog_id = ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_HW_PROG_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hw_prog_id = 1;
			dst->hw_prog_id = ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_EXPECTED_FD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.expected_fd = 1;
			dst->expected_fd = ynl_attr_get_s32(attr);
		}
	}

	return 0;
}

void
rt_link_prop_list_link_attrs_free(struct rt_link_prop_list_link_attrs *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.alt_ifname; i++)
		free(obj->alt_ifname[i]);
	free(obj->alt_ifname);
}

int rt_link_prop_list_link_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     struct rt_link_prop_list_link_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (i = 0; i < obj->_count.alt_ifname; i++)
		ynl_attr_put_str(nlh, IFLA_ALT_IFNAME, obj->alt_ifname[i]->str);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_prop_list_link_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	struct rt_link_prop_list_link_attrs *dst = yarg->data;
	unsigned int n_alt_ifname = 0;
	const struct nlattr *attr;
	int i;

	if (dst->alt_ifname)
		return ynl_error_parse(yarg, "attribute already present (prop-list-link-attrs.alt-ifname)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_ALT_IFNAME) {
			n_alt_ifname++;
		}
	}

	if (n_alt_ifname) {
		dst->alt_ifname = calloc(n_alt_ifname, sizeof(*dst->alt_ifname));
		dst->_count.alt_ifname = n_alt_ifname;
		i = 0;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == IFLA_ALT_IFNAME) {
				unsigned int len;

				len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
				dst->alt_ifname[i] = malloc(sizeof(struct ynl_string) + len + 1);
				dst->alt_ifname[i]->len = len;
				memcpy(dst->alt_ifname[i]->str, ynl_attr_get_str(attr), len);
				dst->alt_ifname[i]->str[len] = 0;
				i++;
			}
		}
	}

	return 0;
}

void rt_link_link_dpll_pin_attrs_free(struct rt_link_link_dpll_pin_attrs *obj)
{
}

void rt_link_ifla_attrs_free(struct rt_link_ifla_attrs *obj)
{
	free(obj->conf);
}

int rt_link_ifla_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct rt_link_ifla_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_count.conf) {
		i = obj->_count.conf * sizeof(__u32);
		ynl_attr_put(nlh, IFLA_INET_CONF, obj->conf, i);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_ifla_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	struct rt_link_ifla_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_INET_CONF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.conf = len / sizeof(__u32);
			len = dst->_count.conf * sizeof(__u32);
			dst->conf = malloc(len);
			memcpy(dst->conf, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void rt_link_ifla6_attrs_free(struct rt_link_ifla6_attrs *obj)
{
	free(obj->conf);
	free(obj->stats);
	free(obj->mcast);
	free(obj->cacheinfo);
	free(obj->icmp6stats);
	free(obj->token);
}

int rt_link_ifla6_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct rt_link_ifla6_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, IFLA_INET6_FLAGS, obj->flags);
	if (obj->_count.conf) {
		i = obj->_count.conf * sizeof(__u32);
		ynl_attr_put(nlh, IFLA_INET6_CONF, obj->conf, i);
	}
	if (obj->_count.stats) {
		i = obj->_count.stats * sizeof(__u64);
		ynl_attr_put(nlh, IFLA_INET6_STATS, obj->stats, i);
	}
	if (obj->_len.mcast)
		ynl_attr_put(nlh, IFLA_INET6_MCAST, obj->mcast, obj->_len.mcast);
	if (obj->_len.cacheinfo)
		ynl_attr_put(nlh, IFLA_INET6_CACHEINFO, obj->cacheinfo, obj->_len.cacheinfo);
	if (obj->_count.icmp6stats) {
		i = obj->_count.icmp6stats * sizeof(__u64);
		ynl_attr_put(nlh, IFLA_INET6_ICMP6STATS, obj->icmp6stats, i);
	}
	if (obj->_len.token)
		ynl_attr_put(nlh, IFLA_INET6_TOKEN, obj->token, obj->_len.token);
	if (obj->_present.addr_gen_mode)
		ynl_attr_put_u8(nlh, IFLA_INET6_ADDR_GEN_MODE, obj->addr_gen_mode);
	if (obj->_present.ra_mtu)
		ynl_attr_put_u32(nlh, IFLA_INET6_RA_MTU, obj->ra_mtu);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_ifla6_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct rt_link_ifla6_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_INET6_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == IFLA_INET6_CONF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.conf = len / sizeof(__u32);
			len = dst->_count.conf * sizeof(__u32);
			dst->conf = malloc(len);
			memcpy(dst->conf, ynl_attr_data(attr), len);
		} else if (type == IFLA_INET6_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.stats = len / sizeof(__u64);
			len = dst->_count.stats * sizeof(__u64);
			dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == IFLA_INET6_MCAST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.mcast = len;
			dst->mcast = malloc(len);
			memcpy(dst->mcast, ynl_attr_data(attr), len);
		} else if (type == IFLA_INET6_CACHEINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.cacheinfo = len;
			if (len < sizeof(struct ifla_cacheinfo))
				dst->cacheinfo = calloc(1, sizeof(struct ifla_cacheinfo));
			else
				dst->cacheinfo = malloc(len);
			memcpy(dst->cacheinfo, ynl_attr_data(attr), len);
		} else if (type == IFLA_INET6_ICMP6STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.icmp6stats = len / sizeof(__u64);
			len = dst->_count.icmp6stats * sizeof(__u64);
			dst->icmp6stats = malloc(len);
			memcpy(dst->icmp6stats, ynl_attr_data(attr), len);
		} else if (type == IFLA_INET6_TOKEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.token = len;
			dst->token = malloc(len);
			memcpy(dst->token, ynl_attr_data(attr), len);
		} else if (type == IFLA_INET6_ADDR_GEN_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.addr_gen_mode = 1;
			dst->addr_gen_mode = ynl_attr_get_u8(attr);
		} else if (type == IFLA_INET6_RA_MTU) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ra_mtu = 1;
			dst->ra_mtu = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void rt_link_mctp_attrs_free(struct rt_link_mctp_attrs *obj)
{
}

int rt_link_mctp_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct rt_link_mctp_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.net)
		ynl_attr_put_u32(nlh, IFLA_MCTP_NET, obj->net);
	if (obj->_present.phys_binding)
		ynl_attr_put_u8(nlh, IFLA_MCTP_PHYS_BINDING, obj->phys_binding);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_mctp_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	struct rt_link_mctp_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_MCTP_NET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.net = 1;
			dst->net = ynl_attr_get_u32(attr);
		} else if (type == IFLA_MCTP_PHYS_BINDING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.phys_binding = 1;
			dst->phys_binding = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void rt_link_hw_s_info_one_free(struct rt_link_hw_s_info_one *obj)
{
}

int rt_link_hw_s_info_one_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested, __u32 idx)
{
	struct rt_link_hw_s_info_one *dst = yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.request = 1;
			dst->request = ynl_attr_get_u8(attr);
		} else if (type == IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.used = 1;
			dst->used = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void
rt_link_linkinfo_bridge_attrs_free(struct rt_link_linkinfo_bridge_attrs *obj)
{
	free(obj->root_id);
	free(obj->bridge_id);
	free(obj->group_addr);
	free(obj->fdb_flush);
	free(obj->multi_boolopt);
	free(obj->mcast_querier_state);
}

int rt_link_linkinfo_bridge_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      struct rt_link_linkinfo_bridge_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.forward_delay)
		ynl_attr_put_u32(nlh, IFLA_BR_FORWARD_DELAY, obj->forward_delay);
	if (obj->_present.hello_time)
		ynl_attr_put_u32(nlh, IFLA_BR_HELLO_TIME, obj->hello_time);
	if (obj->_present.max_age)
		ynl_attr_put_u32(nlh, IFLA_BR_MAX_AGE, obj->max_age);
	if (obj->_present.ageing_time)
		ynl_attr_put_u32(nlh, IFLA_BR_AGEING_TIME, obj->ageing_time);
	if (obj->_present.stp_state)
		ynl_attr_put_u32(nlh, IFLA_BR_STP_STATE, obj->stp_state);
	if (obj->_present.priority)
		ynl_attr_put_u16(nlh, IFLA_BR_PRIORITY, obj->priority);
	if (obj->_present.vlan_filtering)
		ynl_attr_put_u8(nlh, IFLA_BR_VLAN_FILTERING, obj->vlan_filtering);
	if (obj->_present.vlan_protocol)
		ynl_attr_put_u16(nlh, IFLA_BR_VLAN_PROTOCOL, obj->vlan_protocol);
	if (obj->_present.group_fwd_mask)
		ynl_attr_put_u16(nlh, IFLA_BR_GROUP_FWD_MASK, obj->group_fwd_mask);
	if (obj->_len.root_id)
		ynl_attr_put(nlh, IFLA_BR_ROOT_ID, obj->root_id, obj->_len.root_id);
	if (obj->_len.bridge_id)
		ynl_attr_put(nlh, IFLA_BR_BRIDGE_ID, obj->bridge_id, obj->_len.bridge_id);
	if (obj->_present.root_port)
		ynl_attr_put_u16(nlh, IFLA_BR_ROOT_PORT, obj->root_port);
	if (obj->_present.root_path_cost)
		ynl_attr_put_u32(nlh, IFLA_BR_ROOT_PATH_COST, obj->root_path_cost);
	if (obj->_present.topology_change)
		ynl_attr_put_u8(nlh, IFLA_BR_TOPOLOGY_CHANGE, obj->topology_change);
	if (obj->_present.topology_change_detected)
		ynl_attr_put_u8(nlh, IFLA_BR_TOPOLOGY_CHANGE_DETECTED, obj->topology_change_detected);
	if (obj->_present.hello_timer)
		ynl_attr_put_u64(nlh, IFLA_BR_HELLO_TIMER, obj->hello_timer);
	if (obj->_present.tcn_timer)
		ynl_attr_put_u64(nlh, IFLA_BR_TCN_TIMER, obj->tcn_timer);
	if (obj->_present.topology_change_timer)
		ynl_attr_put_u64(nlh, IFLA_BR_TOPOLOGY_CHANGE_TIMER, obj->topology_change_timer);
	if (obj->_present.gc_timer)
		ynl_attr_put_u64(nlh, IFLA_BR_GC_TIMER, obj->gc_timer);
	if (obj->_len.group_addr)
		ynl_attr_put(nlh, IFLA_BR_GROUP_ADDR, obj->group_addr, obj->_len.group_addr);
	if (obj->_len.fdb_flush)
		ynl_attr_put(nlh, IFLA_BR_FDB_FLUSH, obj->fdb_flush, obj->_len.fdb_flush);
	if (obj->_present.mcast_router)
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_ROUTER, obj->mcast_router);
	if (obj->_present.mcast_snooping)
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_SNOOPING, obj->mcast_snooping);
	if (obj->_present.mcast_query_use_ifaddr)
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_QUERY_USE_IFADDR, obj->mcast_query_use_ifaddr);
	if (obj->_present.mcast_querier)
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_QUERIER, obj->mcast_querier);
	if (obj->_present.mcast_hash_elasticity)
		ynl_attr_put_u32(nlh, IFLA_BR_MCAST_HASH_ELASTICITY, obj->mcast_hash_elasticity);
	if (obj->_present.mcast_hash_max)
		ynl_attr_put_u32(nlh, IFLA_BR_MCAST_HASH_MAX, obj->mcast_hash_max);
	if (obj->_present.mcast_last_member_cnt)
		ynl_attr_put_u32(nlh, IFLA_BR_MCAST_LAST_MEMBER_CNT, obj->mcast_last_member_cnt);
	if (obj->_present.mcast_startup_query_cnt)
		ynl_attr_put_u32(nlh, IFLA_BR_MCAST_STARTUP_QUERY_CNT, obj->mcast_startup_query_cnt);
	if (obj->_present.mcast_last_member_intvl)
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_LAST_MEMBER_INTVL, obj->mcast_last_member_intvl);
	if (obj->_present.mcast_membership_intvl)
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_MEMBERSHIP_INTVL, obj->mcast_membership_intvl);
	if (obj->_present.mcast_querier_intvl)
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_QUERIER_INTVL, obj->mcast_querier_intvl);
	if (obj->_present.mcast_query_intvl)
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_QUERY_INTVL, obj->mcast_query_intvl);
	if (obj->_present.mcast_query_response_intvl)
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_QUERY_RESPONSE_INTVL, obj->mcast_query_response_intvl);
	if (obj->_present.mcast_startup_query_intvl)
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_STARTUP_QUERY_INTVL, obj->mcast_startup_query_intvl);
	if (obj->_present.nf_call_iptables)
		ynl_attr_put_u8(nlh, IFLA_BR_NF_CALL_IPTABLES, obj->nf_call_iptables);
	if (obj->_present.nf_call_ip6tables)
		ynl_attr_put_u8(nlh, IFLA_BR_NF_CALL_IP6TABLES, obj->nf_call_ip6tables);
	if (obj->_present.nf_call_arptables)
		ynl_attr_put_u8(nlh, IFLA_BR_NF_CALL_ARPTABLES, obj->nf_call_arptables);
	if (obj->_present.vlan_default_pvid)
		ynl_attr_put_u16(nlh, IFLA_BR_VLAN_DEFAULT_PVID, obj->vlan_default_pvid);
	if (obj->_present.vlan_stats_enabled)
		ynl_attr_put_u8(nlh, IFLA_BR_VLAN_STATS_ENABLED, obj->vlan_stats_enabled);
	if (obj->_present.mcast_stats_enabled)
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_STATS_ENABLED, obj->mcast_stats_enabled);
	if (obj->_present.mcast_igmp_version)
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_IGMP_VERSION, obj->mcast_igmp_version);
	if (obj->_present.mcast_mld_version)
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_MLD_VERSION, obj->mcast_mld_version);
	if (obj->_present.vlan_stats_per_port)
		ynl_attr_put_u8(nlh, IFLA_BR_VLAN_STATS_PER_PORT, obj->vlan_stats_per_port);
	if (obj->_len.multi_boolopt)
		ynl_attr_put(nlh, IFLA_BR_MULTI_BOOLOPT, obj->multi_boolopt, obj->_len.multi_boolopt);
	if (obj->_len.mcast_querier_state)
		ynl_attr_put(nlh, IFLA_BR_MCAST_QUERIER_STATE, obj->mcast_querier_state, obj->_len.mcast_querier_state);
	if (obj->_present.fdb_n_learned)
		ynl_attr_put_u32(nlh, IFLA_BR_FDB_N_LEARNED, obj->fdb_n_learned);
	if (obj->_present.fdb_max_learned)
		ynl_attr_put_u32(nlh, IFLA_BR_FDB_MAX_LEARNED, obj->fdb_max_learned);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_bridge_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	struct rt_link_linkinfo_bridge_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BR_FORWARD_DELAY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.forward_delay = 1;
			dst->forward_delay = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_HELLO_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hello_time = 1;
			dst->hello_time = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MAX_AGE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_age = 1;
			dst->max_age = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_AGEING_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ageing_time = 1;
			dst->ageing_time = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_STP_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stp_state = 1;
			dst->stp_state = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.priority = 1;
			dst->priority = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_VLAN_FILTERING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vlan_filtering = 1;
			dst->vlan_filtering = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_VLAN_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vlan_protocol = 1;
			dst->vlan_protocol = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_GROUP_FWD_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.group_fwd_mask = 1;
			dst->group_fwd_mask = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_ROOT_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.root_id = len;
			if (len < sizeof(struct ifla_bridge_id))
				dst->root_id = calloc(1, sizeof(struct ifla_bridge_id));
			else
				dst->root_id = malloc(len);
			memcpy(dst->root_id, ynl_attr_data(attr), len);
		} else if (type == IFLA_BR_BRIDGE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.bridge_id = len;
			if (len < sizeof(struct ifla_bridge_id))
				dst->bridge_id = calloc(1, sizeof(struct ifla_bridge_id));
			else
				dst->bridge_id = malloc(len);
			memcpy(dst->bridge_id, ynl_attr_data(attr), len);
		} else if (type == IFLA_BR_ROOT_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.root_port = 1;
			dst->root_port = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_ROOT_PATH_COST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.root_path_cost = 1;
			dst->root_path_cost = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_TOPOLOGY_CHANGE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.topology_change = 1;
			dst->topology_change = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_TOPOLOGY_CHANGE_DETECTED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.topology_change_detected = 1;
			dst->topology_change_detected = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_HELLO_TIMER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hello_timer = 1;
			dst->hello_timer = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_TCN_TIMER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tcn_timer = 1;
			dst->tcn_timer = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_TOPOLOGY_CHANGE_TIMER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.topology_change_timer = 1;
			dst->topology_change_timer = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_GC_TIMER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gc_timer = 1;
			dst->gc_timer = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_GROUP_ADDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.group_addr = len;
			dst->group_addr = malloc(len);
			memcpy(dst->group_addr, ynl_attr_data(attr), len);
		} else if (type == IFLA_BR_FDB_FLUSH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.fdb_flush = len;
			dst->fdb_flush = malloc(len);
			memcpy(dst->fdb_flush, ynl_attr_data(attr), len);
		} else if (type == IFLA_BR_MCAST_ROUTER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_router = 1;
			dst->mcast_router = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_SNOOPING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_snooping = 1;
			dst->mcast_snooping = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_QUERY_USE_IFADDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_query_use_ifaddr = 1;
			dst->mcast_query_use_ifaddr = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_QUERIER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_querier = 1;
			dst->mcast_querier = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_HASH_ELASTICITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_hash_elasticity = 1;
			dst->mcast_hash_elasticity = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MCAST_HASH_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_hash_max = 1;
			dst->mcast_hash_max = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MCAST_LAST_MEMBER_CNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_last_member_cnt = 1;
			dst->mcast_last_member_cnt = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MCAST_STARTUP_QUERY_CNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_startup_query_cnt = 1;
			dst->mcast_startup_query_cnt = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MCAST_LAST_MEMBER_INTVL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_last_member_intvl = 1;
			dst->mcast_last_member_intvl = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_MEMBERSHIP_INTVL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_membership_intvl = 1;
			dst->mcast_membership_intvl = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_QUERIER_INTVL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_querier_intvl = 1;
			dst->mcast_querier_intvl = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_QUERY_INTVL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_query_intvl = 1;
			dst->mcast_query_intvl = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_QUERY_RESPONSE_INTVL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_query_response_intvl = 1;
			dst->mcast_query_response_intvl = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_STARTUP_QUERY_INTVL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_startup_query_intvl = 1;
			dst->mcast_startup_query_intvl = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_NF_CALL_IPTABLES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nf_call_iptables = 1;
			dst->nf_call_iptables = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_NF_CALL_IP6TABLES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nf_call_ip6tables = 1;
			dst->nf_call_ip6tables = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_NF_CALL_ARPTABLES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nf_call_arptables = 1;
			dst->nf_call_arptables = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_VLAN_DEFAULT_PVID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vlan_default_pvid = 1;
			dst->vlan_default_pvid = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_VLAN_STATS_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vlan_stats_enabled = 1;
			dst->vlan_stats_enabled = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_STATS_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_stats_enabled = 1;
			dst->mcast_stats_enabled = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_IGMP_VERSION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_igmp_version = 1;
			dst->mcast_igmp_version = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_MLD_VERSION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_mld_version = 1;
			dst->mcast_mld_version = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_VLAN_STATS_PER_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vlan_stats_per_port = 1;
			dst->vlan_stats_per_port = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MULTI_BOOLOPT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.multi_boolopt = len;
			if (len < sizeof(struct br_boolopt_multi))
				dst->multi_boolopt = calloc(1, sizeof(struct br_boolopt_multi));
			else
				dst->multi_boolopt = malloc(len);
			memcpy(dst->multi_boolopt, ynl_attr_data(attr), len);
		} else if (type == IFLA_BR_MCAST_QUERIER_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.mcast_querier_state = len;
			dst->mcast_querier_state = malloc(len);
			memcpy(dst->mcast_querier_state, ynl_attr_data(attr), len);
		} else if (type == IFLA_BR_FDB_N_LEARNED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fdb_n_learned = 1;
			dst->fdb_n_learned = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_FDB_MAX_LEARNED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fdb_max_learned = 1;
			dst->fdb_max_learned = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void rt_link_linkinfo_gre_attrs_free(struct rt_link_linkinfo_gre_attrs *obj)
{
	free(obj->local);
	free(obj->remote);
}

int rt_link_linkinfo_gre_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct rt_link_linkinfo_gre_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.link)
		ynl_attr_put_u32(nlh, IFLA_GRE_LINK, obj->link);
	if (obj->_present.iflags)
		ynl_attr_put_u16(nlh, IFLA_GRE_IFLAGS, obj->iflags);
	if (obj->_present.oflags)
		ynl_attr_put_u16(nlh, IFLA_GRE_OFLAGS, obj->oflags);
	if (obj->_present.ikey)
		ynl_attr_put_u32(nlh, IFLA_GRE_IKEY, obj->ikey);
	if (obj->_present.okey)
		ynl_attr_put_u32(nlh, IFLA_GRE_OKEY, obj->okey);
	if (obj->_len.local)
		ynl_attr_put(nlh, IFLA_GRE_LOCAL, obj->local, obj->_len.local);
	if (obj->_len.remote)
		ynl_attr_put(nlh, IFLA_GRE_REMOTE, obj->remote, obj->_len.remote);
	if (obj->_present.ttl)
		ynl_attr_put_u8(nlh, IFLA_GRE_TTL, obj->ttl);
	if (obj->_present.tos)
		ynl_attr_put_u8(nlh, IFLA_GRE_TOS, obj->tos);
	if (obj->_present.pmtudisc)
		ynl_attr_put_u8(nlh, IFLA_GRE_PMTUDISC, obj->pmtudisc);
	if (obj->_present.encap_limit)
		ynl_attr_put_u8(nlh, IFLA_GRE_ENCAP_LIMIT, obj->encap_limit);
	if (obj->_present.flowinfo)
		ynl_attr_put_u32(nlh, IFLA_GRE_FLOWINFO, obj->flowinfo);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, IFLA_GRE_FLAGS, obj->flags);
	if (obj->_present.encap_type)
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_TYPE, obj->encap_type);
	if (obj->_present.encap_flags)
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_FLAGS, obj->encap_flags);
	if (obj->_present.encap_sport)
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_SPORT, obj->encap_sport);
	if (obj->_present.encap_dport)
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_DPORT, obj->encap_dport);
	if (obj->_present.collect_metadata)
		ynl_attr_put(nlh, IFLA_GRE_COLLECT_METADATA, NULL, 0);
	if (obj->_present.ignore_df)
		ynl_attr_put_u8(nlh, IFLA_GRE_IGNORE_DF, obj->ignore_df);
	if (obj->_present.fwmark)
		ynl_attr_put_u32(nlh, IFLA_GRE_FWMARK, obj->fwmark);
	if (obj->_present.erspan_index)
		ynl_attr_put_u32(nlh, IFLA_GRE_ERSPAN_INDEX, obj->erspan_index);
	if (obj->_present.erspan_ver)
		ynl_attr_put_u8(nlh, IFLA_GRE_ERSPAN_VER, obj->erspan_ver);
	if (obj->_present.erspan_dir)
		ynl_attr_put_u8(nlh, IFLA_GRE_ERSPAN_DIR, obj->erspan_dir);
	if (obj->_present.erspan_hwid)
		ynl_attr_put_u16(nlh, IFLA_GRE_ERSPAN_HWID, obj->erspan_hwid);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_gre_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct rt_link_linkinfo_gre_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_GRE_LINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link = 1;
			dst->link = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_IFLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.iflags = 1;
			dst->iflags = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_OFLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.oflags = 1;
			dst->oflags = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_IKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ikey = 1;
			dst->ikey = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_OKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.okey = 1;
			dst->okey = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_LOCAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.local = len;
			dst->local = malloc(len);
			memcpy(dst->local, ynl_attr_data(attr), len);
		} else if (type == IFLA_GRE_REMOTE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.remote = len;
			dst->remote = malloc(len);
			memcpy(dst->remote, ynl_attr_data(attr), len);
		} else if (type == IFLA_GRE_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ttl = 1;
			dst->ttl = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_TOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tos = 1;
			dst->tos = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_PMTUDISC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pmtudisc = 1;
			dst->pmtudisc = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ENCAP_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_limit = 1;
			dst->encap_limit = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_FLOWINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flowinfo = 1;
			dst->flowinfo = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_type = 1;
			dst->encap_type = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_flags = 1;
			dst->encap_flags = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_SPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_sport = 1;
			dst->encap_sport = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_DPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_dport = 1;
			dst->encap_dport = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.collect_metadata = 1;
		} else if (type == IFLA_GRE_IGNORE_DF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ignore_df = 1;
			dst->ignore_df = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_FWMARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmark = 1;
			dst->fwmark = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ERSPAN_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.erspan_index = 1;
			dst->erspan_index = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ERSPAN_VER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.erspan_ver = 1;
			dst->erspan_ver = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ERSPAN_DIR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.erspan_dir = 1;
			dst->erspan_dir = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ERSPAN_HWID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.erspan_hwid = 1;
			dst->erspan_hwid = ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

void rt_link_linkinfo_gre6_attrs_free(struct rt_link_linkinfo_gre6_attrs *obj)
{
	free(obj->local);
	free(obj->remote);
}

int rt_link_linkinfo_gre6_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    struct rt_link_linkinfo_gre6_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.link)
		ynl_attr_put_u32(nlh, IFLA_GRE_LINK, obj->link);
	if (obj->_present.iflags)
		ynl_attr_put_u16(nlh, IFLA_GRE_IFLAGS, obj->iflags);
	if (obj->_present.oflags)
		ynl_attr_put_u16(nlh, IFLA_GRE_OFLAGS, obj->oflags);
	if (obj->_present.ikey)
		ynl_attr_put_u32(nlh, IFLA_GRE_IKEY, obj->ikey);
	if (obj->_present.okey)
		ynl_attr_put_u32(nlh, IFLA_GRE_OKEY, obj->okey);
	if (obj->_len.local)
		ynl_attr_put(nlh, IFLA_GRE_LOCAL, obj->local, obj->_len.local);
	if (obj->_len.remote)
		ynl_attr_put(nlh, IFLA_GRE_REMOTE, obj->remote, obj->_len.remote);
	if (obj->_present.ttl)
		ynl_attr_put_u8(nlh, IFLA_GRE_TTL, obj->ttl);
	if (obj->_present.encap_limit)
		ynl_attr_put_u8(nlh, IFLA_GRE_ENCAP_LIMIT, obj->encap_limit);
	if (obj->_present.flowinfo)
		ynl_attr_put_u32(nlh, IFLA_GRE_FLOWINFO, obj->flowinfo);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, IFLA_GRE_FLAGS, obj->flags);
	if (obj->_present.encap_type)
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_TYPE, obj->encap_type);
	if (obj->_present.encap_flags)
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_FLAGS, obj->encap_flags);
	if (obj->_present.encap_sport)
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_SPORT, obj->encap_sport);
	if (obj->_present.encap_dport)
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_DPORT, obj->encap_dport);
	if (obj->_present.collect_metadata)
		ynl_attr_put(nlh, IFLA_GRE_COLLECT_METADATA, NULL, 0);
	if (obj->_present.fwmark)
		ynl_attr_put_u32(nlh, IFLA_GRE_FWMARK, obj->fwmark);
	if (obj->_present.erspan_index)
		ynl_attr_put_u32(nlh, IFLA_GRE_ERSPAN_INDEX, obj->erspan_index);
	if (obj->_present.erspan_ver)
		ynl_attr_put_u8(nlh, IFLA_GRE_ERSPAN_VER, obj->erspan_ver);
	if (obj->_present.erspan_dir)
		ynl_attr_put_u8(nlh, IFLA_GRE_ERSPAN_DIR, obj->erspan_dir);
	if (obj->_present.erspan_hwid)
		ynl_attr_put_u16(nlh, IFLA_GRE_ERSPAN_HWID, obj->erspan_hwid);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_gre6_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	struct rt_link_linkinfo_gre6_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_GRE_LINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link = 1;
			dst->link = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_IFLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.iflags = 1;
			dst->iflags = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_OFLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.oflags = 1;
			dst->oflags = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_IKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ikey = 1;
			dst->ikey = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_OKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.okey = 1;
			dst->okey = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_LOCAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.local = len;
			dst->local = malloc(len);
			memcpy(dst->local, ynl_attr_data(attr), len);
		} else if (type == IFLA_GRE_REMOTE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.remote = len;
			dst->remote = malloc(len);
			memcpy(dst->remote, ynl_attr_data(attr), len);
		} else if (type == IFLA_GRE_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ttl = 1;
			dst->ttl = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ENCAP_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_limit = 1;
			dst->encap_limit = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_FLOWINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flowinfo = 1;
			dst->flowinfo = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_type = 1;
			dst->encap_type = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_flags = 1;
			dst->encap_flags = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_SPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_sport = 1;
			dst->encap_sport = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_DPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_dport = 1;
			dst->encap_dport = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.collect_metadata = 1;
		} else if (type == IFLA_GRE_FWMARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmark = 1;
			dst->fwmark = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ERSPAN_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.erspan_index = 1;
			dst->erspan_index = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ERSPAN_VER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.erspan_ver = 1;
			dst->erspan_ver = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ERSPAN_DIR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.erspan_dir = 1;
			dst->erspan_dir = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ERSPAN_HWID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.erspan_hwid = 1;
			dst->erspan_hwid = ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

void
rt_link_linkinfo_geneve_attrs_free(struct rt_link_linkinfo_geneve_attrs *obj)
{
	free(obj->remote6);
	free(obj->port_range);
}

int rt_link_linkinfo_geneve_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      struct rt_link_linkinfo_geneve_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.id)
		ynl_attr_put_u32(nlh, IFLA_GENEVE_ID, obj->id);
	if (obj->_present.remote)
		ynl_attr_put_u32(nlh, IFLA_GENEVE_REMOTE, obj->remote);
	if (obj->_present.ttl)
		ynl_attr_put_u8(nlh, IFLA_GENEVE_TTL, obj->ttl);
	if (obj->_present.tos)
		ynl_attr_put_u8(nlh, IFLA_GENEVE_TOS, obj->tos);
	if (obj->_present.port)
		ynl_attr_put_u16(nlh, IFLA_GENEVE_PORT, obj->port);
	if (obj->_present.collect_metadata)
		ynl_attr_put(nlh, IFLA_GENEVE_COLLECT_METADATA, NULL, 0);
	if (obj->_len.remote6)
		ynl_attr_put(nlh, IFLA_GENEVE_REMOTE6, obj->remote6, obj->_len.remote6);
	if (obj->_present.udp_csum)
		ynl_attr_put_u8(nlh, IFLA_GENEVE_UDP_CSUM, obj->udp_csum);
	if (obj->_present.udp_zero_csum6_tx)
		ynl_attr_put_u8(nlh, IFLA_GENEVE_UDP_ZERO_CSUM6_TX, obj->udp_zero_csum6_tx);
	if (obj->_present.udp_zero_csum6_rx)
		ynl_attr_put_u8(nlh, IFLA_GENEVE_UDP_ZERO_CSUM6_RX, obj->udp_zero_csum6_rx);
	if (obj->_present.label)
		ynl_attr_put_u32(nlh, IFLA_GENEVE_LABEL, obj->label);
	if (obj->_present.ttl_inherit)
		ynl_attr_put_u8(nlh, IFLA_GENEVE_TTL_INHERIT, obj->ttl_inherit);
	if (obj->_present.df)
		ynl_attr_put_u8(nlh, IFLA_GENEVE_DF, obj->df);
	if (obj->_present.inner_proto_inherit)
		ynl_attr_put(nlh, IFLA_GENEVE_INNER_PROTO_INHERIT, NULL, 0);
	if (obj->_len.port_range)
		ynl_attr_put(nlh, IFLA_GENEVE_PORT_RANGE, obj->port_range, obj->_len.port_range);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_geneve_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	struct rt_link_linkinfo_geneve_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_GENEVE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GENEVE_REMOTE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.remote = 1;
			dst->remote = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GENEVE_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ttl = 1;
			dst->ttl = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_TOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tos = 1;
			dst->tos = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port = 1;
			dst->port = ynl_attr_get_u16(attr);
		} else if (type == IFLA_GENEVE_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.collect_metadata = 1;
		} else if (type == IFLA_GENEVE_REMOTE6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.remote6 = len;
			dst->remote6 = malloc(len);
			memcpy(dst->remote6, ynl_attr_data(attr), len);
		} else if (type == IFLA_GENEVE_UDP_CSUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.udp_csum = 1;
			dst->udp_csum = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_UDP_ZERO_CSUM6_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.udp_zero_csum6_tx = 1;
			dst->udp_zero_csum6_tx = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_UDP_ZERO_CSUM6_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.udp_zero_csum6_rx = 1;
			dst->udp_zero_csum6_rx = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_LABEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.label = 1;
			dst->label = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GENEVE_TTL_INHERIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ttl_inherit = 1;
			dst->ttl_inherit = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_DF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.df = 1;
			dst->df = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_INNER_PROTO_INHERIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.inner_proto_inherit = 1;
		} else if (type == IFLA_GENEVE_PORT_RANGE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.port_range = len;
			if (len < sizeof(struct ifla_geneve_port_range))
				dst->port_range = calloc(1, sizeof(struct ifla_geneve_port_range));
			else
				dst->port_range = malloc(len);
			memcpy(dst->port_range, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void rt_link_linkinfo_hsr_attrs_free(struct rt_link_linkinfo_hsr_attrs *obj)
{
	free(obj->supervision_addr);
}

int rt_link_linkinfo_hsr_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct rt_link_linkinfo_hsr_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.slave1)
		ynl_attr_put_u32(nlh, IFLA_HSR_SLAVE1, obj->slave1);
	if (obj->_present.slave2)
		ynl_attr_put_u32(nlh, IFLA_HSR_SLAVE2, obj->slave2);
	if (obj->_present.multicast_spec)
		ynl_attr_put_u8(nlh, IFLA_HSR_MULTICAST_SPEC, obj->multicast_spec);
	if (obj->_len.supervision_addr)
		ynl_attr_put(nlh, IFLA_HSR_SUPERVISION_ADDR, obj->supervision_addr, obj->_len.supervision_addr);
	if (obj->_present.seq_nr)
		ynl_attr_put_u16(nlh, IFLA_HSR_SEQ_NR, obj->seq_nr);
	if (obj->_present.version)
		ynl_attr_put_u8(nlh, IFLA_HSR_VERSION, obj->version);
	if (obj->_present.protocol)
		ynl_attr_put_u8(nlh, IFLA_HSR_PROTOCOL, obj->protocol);
	if (obj->_present.interlink)
		ynl_attr_put_u32(nlh, IFLA_HSR_INTERLINK, obj->interlink);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_hsr_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct rt_link_linkinfo_hsr_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_HSR_SLAVE1) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.slave1 = 1;
			dst->slave1 = ynl_attr_get_u32(attr);
		} else if (type == IFLA_HSR_SLAVE2) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.slave2 = 1;
			dst->slave2 = ynl_attr_get_u32(attr);
		} else if (type == IFLA_HSR_MULTICAST_SPEC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.multicast_spec = 1;
			dst->multicast_spec = ynl_attr_get_u8(attr);
		} else if (type == IFLA_HSR_SUPERVISION_ADDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.supervision_addr = len;
			dst->supervision_addr = malloc(len);
			memcpy(dst->supervision_addr, ynl_attr_data(attr), len);
		} else if (type == IFLA_HSR_SEQ_NR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.seq_nr = 1;
			dst->seq_nr = ynl_attr_get_u16(attr);
		} else if (type == IFLA_HSR_VERSION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.version = 1;
			dst->version = ynl_attr_get_u8(attr);
		} else if (type == IFLA_HSR_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.protocol = 1;
			dst->protocol = ynl_attr_get_u8(attr);
		} else if (type == IFLA_HSR_INTERLINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.interlink = 1;
			dst->interlink = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void
rt_link_linkinfo_iptun_attrs_free(struct rt_link_linkinfo_iptun_attrs *obj)
{
	free(obj->local);
	free(obj->remote);
	free(obj->_6rd_prefix);
}

int rt_link_linkinfo_iptun_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     struct rt_link_linkinfo_iptun_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.link)
		ynl_attr_put_u32(nlh, IFLA_IPTUN_LINK, obj->link);
	if (obj->_len.local)
		ynl_attr_put(nlh, IFLA_IPTUN_LOCAL, obj->local, obj->_len.local);
	if (obj->_len.remote)
		ynl_attr_put(nlh, IFLA_IPTUN_REMOTE, obj->remote, obj->_len.remote);
	if (obj->_present.ttl)
		ynl_attr_put_u8(nlh, IFLA_IPTUN_TTL, obj->ttl);
	if (obj->_present.tos)
		ynl_attr_put_u8(nlh, IFLA_IPTUN_TOS, obj->tos);
	if (obj->_present.encap_limit)
		ynl_attr_put_u8(nlh, IFLA_IPTUN_ENCAP_LIMIT, obj->encap_limit);
	if (obj->_present.flowinfo)
		ynl_attr_put_u32(nlh, IFLA_IPTUN_FLOWINFO, obj->flowinfo);
	if (obj->_present.flags)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_FLAGS, obj->flags);
	if (obj->_present.proto)
		ynl_attr_put_u8(nlh, IFLA_IPTUN_PROTO, obj->proto);
	if (obj->_present.pmtudisc)
		ynl_attr_put_u8(nlh, IFLA_IPTUN_PMTUDISC, obj->pmtudisc);
	if (obj->_len._6rd_prefix)
		ynl_attr_put(nlh, IFLA_IPTUN_6RD_PREFIX, obj->_6rd_prefix, obj->_len._6rd_prefix);
	if (obj->_present._6rd_relay_prefix)
		ynl_attr_put_u32(nlh, IFLA_IPTUN_6RD_RELAY_PREFIX, obj->_6rd_relay_prefix);
	if (obj->_present._6rd_prefixlen)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_6RD_PREFIXLEN, obj->_6rd_prefixlen);
	if (obj->_present._6rd_relay_prefixlen)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_6RD_RELAY_PREFIXLEN, obj->_6rd_relay_prefixlen);
	if (obj->_present.encap_type)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_TYPE, obj->encap_type);
	if (obj->_present.encap_flags)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_FLAGS, obj->encap_flags);
	if (obj->_present.encap_sport)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_SPORT, obj->encap_sport);
	if (obj->_present.encap_dport)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_DPORT, obj->encap_dport);
	if (obj->_present.collect_metadata)
		ynl_attr_put(nlh, IFLA_IPTUN_COLLECT_METADATA, NULL, 0);
	if (obj->_present.fwmark)
		ynl_attr_put_u32(nlh, IFLA_IPTUN_FWMARK, obj->fwmark);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_iptun_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	struct rt_link_linkinfo_iptun_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_IPTUN_LINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link = 1;
			dst->link = ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_LOCAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.local = len;
			dst->local = malloc(len);
			memcpy(dst->local, ynl_attr_data(attr), len);
		} else if (type == IFLA_IPTUN_REMOTE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.remote = len;
			dst->remote = malloc(len);
			memcpy(dst->remote, ynl_attr_data(attr), len);
		} else if (type == IFLA_IPTUN_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ttl = 1;
			dst->ttl = ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_TOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tos = 1;
			dst->tos = ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_ENCAP_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_limit = 1;
			dst->encap_limit = ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_FLOWINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flowinfo = 1;
			dst->flowinfo = ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_PROTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proto = 1;
			dst->proto = ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_PMTUDISC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pmtudisc = 1;
			dst->pmtudisc = ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_6RD_PREFIX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len._6rd_prefix = len;
			dst->_6rd_prefix = malloc(len);
			memcpy(dst->_6rd_prefix, ynl_attr_data(attr), len);
		} else if (type == IFLA_IPTUN_6RD_RELAY_PREFIX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._6rd_relay_prefix = 1;
			dst->_6rd_relay_prefix = ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_6RD_PREFIXLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._6rd_prefixlen = 1;
			dst->_6rd_prefixlen = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_6RD_RELAY_PREFIXLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present._6rd_relay_prefixlen = 1;
			dst->_6rd_relay_prefixlen = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_type = 1;
			dst->encap_type = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_flags = 1;
			dst->encap_flags = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_SPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_sport = 1;
			dst->encap_sport = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_DPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_dport = 1;
			dst->encap_dport = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.collect_metadata = 1;
		} else if (type == IFLA_IPTUN_FWMARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmark = 1;
			dst->fwmark = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void
rt_link_linkinfo_ip6tnl_attrs_free(struct rt_link_linkinfo_ip6tnl_attrs *obj)
{
	free(obj->local);
	free(obj->remote);
}

int rt_link_linkinfo_ip6tnl_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      struct rt_link_linkinfo_ip6tnl_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.link)
		ynl_attr_put_u32(nlh, IFLA_IPTUN_LINK, obj->link);
	if (obj->_len.local)
		ynl_attr_put(nlh, IFLA_IPTUN_LOCAL, obj->local, obj->_len.local);
	if (obj->_len.remote)
		ynl_attr_put(nlh, IFLA_IPTUN_REMOTE, obj->remote, obj->_len.remote);
	if (obj->_present.ttl)
		ynl_attr_put_u8(nlh, IFLA_IPTUN_TTL, obj->ttl);
	if (obj->_present.encap_limit)
		ynl_attr_put_u8(nlh, IFLA_IPTUN_ENCAP_LIMIT, obj->encap_limit);
	if (obj->_present.flowinfo)
		ynl_attr_put_u32(nlh, IFLA_IPTUN_FLOWINFO, obj->flowinfo);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, IFLA_IPTUN_FLAGS, obj->flags);
	if (obj->_present.proto)
		ynl_attr_put_u8(nlh, IFLA_IPTUN_PROTO, obj->proto);
	if (obj->_present.encap_type)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_TYPE, obj->encap_type);
	if (obj->_present.encap_flags)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_FLAGS, obj->encap_flags);
	if (obj->_present.encap_sport)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_SPORT, obj->encap_sport);
	if (obj->_present.encap_dport)
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_DPORT, obj->encap_dport);
	if (obj->_present.collect_metadata)
		ynl_attr_put(nlh, IFLA_IPTUN_COLLECT_METADATA, NULL, 0);
	if (obj->_present.fwmark)
		ynl_attr_put_u32(nlh, IFLA_IPTUN_FWMARK, obj->fwmark);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_ip6tnl_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	struct rt_link_linkinfo_ip6tnl_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_IPTUN_LINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link = 1;
			dst->link = ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_LOCAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.local = len;
			dst->local = malloc(len);
			memcpy(dst->local, ynl_attr_data(attr), len);
		} else if (type == IFLA_IPTUN_REMOTE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.remote = len;
			dst->remote = malloc(len);
			memcpy(dst->remote, ynl_attr_data(attr), len);
		} else if (type == IFLA_IPTUN_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ttl = 1;
			dst->ttl = ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_ENCAP_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_limit = 1;
			dst->encap_limit = ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_FLOWINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flowinfo = 1;
			dst->flowinfo = ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_PROTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proto = 1;
			dst->proto = ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_type = 1;
			dst->encap_type = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_flags = 1;
			dst->encap_flags = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_SPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_sport = 1;
			dst->encap_sport = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_DPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_dport = 1;
			dst->encap_dport = ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.collect_metadata = 1;
		} else if (type == IFLA_IPTUN_FWMARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmark = 1;
			dst->fwmark = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void rt_link_linkinfo_tun_attrs_free(struct rt_link_linkinfo_tun_attrs *obj)
{
}

int rt_link_linkinfo_tun_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct rt_link_linkinfo_tun_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.owner)
		ynl_attr_put_u32(nlh, IFLA_TUN_OWNER, obj->owner);
	if (obj->_present.group)
		ynl_attr_put_u32(nlh, IFLA_TUN_GROUP, obj->group);
	if (obj->_present.type)
		ynl_attr_put_u8(nlh, IFLA_TUN_TYPE, obj->type);
	if (obj->_present.pi)
		ynl_attr_put_u8(nlh, IFLA_TUN_PI, obj->pi);
	if (obj->_present.vnet_hdr)
		ynl_attr_put_u8(nlh, IFLA_TUN_VNET_HDR, obj->vnet_hdr);
	if (obj->_present.persist)
		ynl_attr_put_u8(nlh, IFLA_TUN_PERSIST, obj->persist);
	if (obj->_present.multi_queue)
		ynl_attr_put_u8(nlh, IFLA_TUN_MULTI_QUEUE, obj->multi_queue);
	if (obj->_present.num_queues)
		ynl_attr_put_u32(nlh, IFLA_TUN_NUM_QUEUES, obj->num_queues);
	if (obj->_present.num_disabled_queues)
		ynl_attr_put_u32(nlh, IFLA_TUN_NUM_DISABLED_QUEUES, obj->num_disabled_queues);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_tun_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct rt_link_linkinfo_tun_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_TUN_OWNER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.owner = 1;
			dst->owner = ynl_attr_get_u32(attr);
		} else if (type == IFLA_TUN_GROUP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.group = 1;
			dst->group = ynl_attr_get_u32(attr);
		} else if (type == IFLA_TUN_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.type = 1;
			dst->type = ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_PI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pi = 1;
			dst->pi = ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_VNET_HDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vnet_hdr = 1;
			dst->vnet_hdr = ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_PERSIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.persist = 1;
			dst->persist = ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_MULTI_QUEUE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.multi_queue = 1;
			dst->multi_queue = ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_NUM_QUEUES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.num_queues = 1;
			dst->num_queues = ynl_attr_get_u32(attr);
		} else if (type == IFLA_TUN_NUM_DISABLED_QUEUES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.num_disabled_queues = 1;
			dst->num_disabled_queues = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void rt_link_linkinfo_vrf_attrs_free(struct rt_link_linkinfo_vrf_attrs *obj)
{
}

int rt_link_linkinfo_vrf_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct rt_link_linkinfo_vrf_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.table)
		ynl_attr_put_u32(nlh, IFLA_VRF_TABLE, obj->table);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_vrf_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct rt_link_linkinfo_vrf_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VRF_TABLE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.table = 1;
			dst->table = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void rt_link_linkinfo_vti_attrs_free(struct rt_link_linkinfo_vti_attrs *obj)
{
	free(obj->local);
	free(obj->remote);
}

int rt_link_linkinfo_vti_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct rt_link_linkinfo_vti_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.link)
		ynl_attr_put_u32(nlh, IFLA_VTI_LINK, obj->link);
	if (obj->_present.ikey)
		ynl_attr_put_u32(nlh, IFLA_VTI_IKEY, obj->ikey);
	if (obj->_present.okey)
		ynl_attr_put_u32(nlh, IFLA_VTI_OKEY, obj->okey);
	if (obj->_len.local)
		ynl_attr_put(nlh, IFLA_VTI_LOCAL, obj->local, obj->_len.local);
	if (obj->_len.remote)
		ynl_attr_put(nlh, IFLA_VTI_REMOTE, obj->remote, obj->_len.remote);
	if (obj->_present.fwmark)
		ynl_attr_put_u32(nlh, IFLA_VTI_FWMARK, obj->fwmark);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_vti_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct rt_link_linkinfo_vti_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VTI_LINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link = 1;
			dst->link = ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_IKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ikey = 1;
			dst->ikey = ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_OKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.okey = 1;
			dst->okey = ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_LOCAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.local = len;
			dst->local = malloc(len);
			memcpy(dst->local, ynl_attr_data(attr), len);
		} else if (type == IFLA_VTI_REMOTE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.remote = len;
			dst->remote = malloc(len);
			memcpy(dst->remote, ynl_attr_data(attr), len);
		} else if (type == IFLA_VTI_FWMARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmark = 1;
			dst->fwmark = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void rt_link_linkinfo_vti6_attrs_free(struct rt_link_linkinfo_vti6_attrs *obj)
{
	free(obj->local);
	free(obj->remote);
}

int rt_link_linkinfo_vti6_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    struct rt_link_linkinfo_vti6_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.link)
		ynl_attr_put_u32(nlh, IFLA_VTI_LINK, obj->link);
	if (obj->_present.ikey)
		ynl_attr_put_u32(nlh, IFLA_VTI_IKEY, obj->ikey);
	if (obj->_present.okey)
		ynl_attr_put_u32(nlh, IFLA_VTI_OKEY, obj->okey);
	if (obj->_len.local)
		ynl_attr_put(nlh, IFLA_VTI_LOCAL, obj->local, obj->_len.local);
	if (obj->_len.remote)
		ynl_attr_put(nlh, IFLA_VTI_REMOTE, obj->remote, obj->_len.remote);
	if (obj->_present.fwmark)
		ynl_attr_put_u32(nlh, IFLA_VTI_FWMARK, obj->fwmark);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_vti6_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	struct rt_link_linkinfo_vti6_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VTI_LINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link = 1;
			dst->link = ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_IKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ikey = 1;
			dst->ikey = ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_OKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.okey = 1;
			dst->okey = ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_LOCAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.local = len;
			dst->local = malloc(len);
			memcpy(dst->local, ynl_attr_data(attr), len);
		} else if (type == IFLA_VTI_REMOTE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.remote = len;
			dst->remote = malloc(len);
			memcpy(dst->remote, ynl_attr_data(attr), len);
		} else if (type == IFLA_VTI_FWMARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmark = 1;
			dst->fwmark = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void
rt_link_linkinfo_netkit_attrs_free(struct rt_link_linkinfo_netkit_attrs *obj)
{
	free(obj->peer_info);
}

int rt_link_linkinfo_netkit_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      struct rt_link_linkinfo_netkit_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.peer_info)
		ynl_attr_put(nlh, IFLA_NETKIT_PEER_INFO, obj->peer_info, obj->_len.peer_info);
	if (obj->_present.primary)
		ynl_attr_put_u8(nlh, IFLA_NETKIT_PRIMARY, obj->primary);
	if (obj->_present.policy)
		ynl_attr_put_u32(nlh, IFLA_NETKIT_POLICY, obj->policy);
	if (obj->_present.peer_policy)
		ynl_attr_put_u32(nlh, IFLA_NETKIT_PEER_POLICY, obj->peer_policy);
	if (obj->_present.mode)
		ynl_attr_put_u32(nlh, IFLA_NETKIT_MODE, obj->mode);
	if (obj->_present.scrub)
		ynl_attr_put_u32(nlh, IFLA_NETKIT_SCRUB, obj->scrub);
	if (obj->_present.peer_scrub)
		ynl_attr_put_u32(nlh, IFLA_NETKIT_PEER_SCRUB, obj->peer_scrub);
	if (obj->_present.headroom)
		ynl_attr_put_u16(nlh, IFLA_NETKIT_HEADROOM, obj->headroom);
	if (obj->_present.tailroom)
		ynl_attr_put_u16(nlh, IFLA_NETKIT_TAILROOM, obj->tailroom);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_netkit_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	struct rt_link_linkinfo_netkit_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_NETKIT_PEER_INFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.peer_info = len;
			dst->peer_info = malloc(len);
			memcpy(dst->peer_info, ynl_attr_data(attr), len);
		} else if (type == IFLA_NETKIT_PRIMARY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.primary = 1;
			dst->primary = ynl_attr_get_u8(attr);
		} else if (type == IFLA_NETKIT_POLICY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.policy = 1;
			dst->policy = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_PEER_POLICY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.peer_policy = 1;
			dst->peer_policy = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mode = 1;
			dst->mode = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_SCRUB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.scrub = 1;
			dst->scrub = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_PEER_SCRUB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.peer_scrub = 1;
			dst->peer_scrub = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_HEADROOM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.headroom = 1;
			dst->headroom = ynl_attr_get_u16(attr);
		} else if (type == IFLA_NETKIT_TAILROOM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tailroom = 1;
			dst->tailroom = ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

void rt_link_linkinfo_ovpn_attrs_free(struct rt_link_linkinfo_ovpn_attrs *obj)
{
}

int rt_link_linkinfo_ovpn_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    struct rt_link_linkinfo_ovpn_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.mode)
		ynl_attr_put_u8(nlh, IFLA_OVPN_MODE, obj->mode);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_ovpn_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	struct rt_link_linkinfo_ovpn_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_OVPN_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mode = 1;
			dst->mode = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void
rt_link_linkinfo_brport_attrs_free(struct rt_link_linkinfo_brport_attrs *obj)
{
	free(obj->root_id);
	free(obj->bridge_id);
}

int rt_link_linkinfo_brport_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      struct rt_link_linkinfo_brport_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.state)
		ynl_attr_put_u8(nlh, IFLA_BRPORT_STATE, obj->state);
	if (obj->_present.priority)
		ynl_attr_put_u16(nlh, IFLA_BRPORT_PRIORITY, obj->priority);
	if (obj->_present.cost)
		ynl_attr_put_u32(nlh, IFLA_BRPORT_COST, obj->cost);
	if (obj->_present.mode)
		ynl_attr_put(nlh, IFLA_BRPORT_MODE, NULL, 0);
	if (obj->_present.guard)
		ynl_attr_put(nlh, IFLA_BRPORT_GUARD, NULL, 0);
	if (obj->_present.protect)
		ynl_attr_put(nlh, IFLA_BRPORT_PROTECT, NULL, 0);
	if (obj->_present.fast_leave)
		ynl_attr_put(nlh, IFLA_BRPORT_FAST_LEAVE, NULL, 0);
	if (obj->_present.learning)
		ynl_attr_put(nlh, IFLA_BRPORT_LEARNING, NULL, 0);
	if (obj->_present.unicast_flood)
		ynl_attr_put(nlh, IFLA_BRPORT_UNICAST_FLOOD, NULL, 0);
	if (obj->_present.proxyarp)
		ynl_attr_put(nlh, IFLA_BRPORT_PROXYARP, NULL, 0);
	if (obj->_present.learning_sync)
		ynl_attr_put(nlh, IFLA_BRPORT_LEARNING_SYNC, NULL, 0);
	if (obj->_present.proxyarp_wifi)
		ynl_attr_put(nlh, IFLA_BRPORT_PROXYARP_WIFI, NULL, 0);
	if (obj->_len.root_id)
		ynl_attr_put(nlh, IFLA_BRPORT_ROOT_ID, obj->root_id, obj->_len.root_id);
	if (obj->_len.bridge_id)
		ynl_attr_put(nlh, IFLA_BRPORT_BRIDGE_ID, obj->bridge_id, obj->_len.bridge_id);
	if (obj->_present.designated_port)
		ynl_attr_put_u16(nlh, IFLA_BRPORT_DESIGNATED_PORT, obj->designated_port);
	if (obj->_present.designated_cost)
		ynl_attr_put_u16(nlh, IFLA_BRPORT_DESIGNATED_COST, obj->designated_cost);
	if (obj->_present.id)
		ynl_attr_put_u16(nlh, IFLA_BRPORT_ID, obj->id);
	if (obj->_present.no)
		ynl_attr_put_u16(nlh, IFLA_BRPORT_NO, obj->no);
	if (obj->_present.topology_change_ack)
		ynl_attr_put_u8(nlh, IFLA_BRPORT_TOPOLOGY_CHANGE_ACK, obj->topology_change_ack);
	if (obj->_present.config_pending)
		ynl_attr_put_u8(nlh, IFLA_BRPORT_CONFIG_PENDING, obj->config_pending);
	if (obj->_present.message_age_timer)
		ynl_attr_put_u64(nlh, IFLA_BRPORT_MESSAGE_AGE_TIMER, obj->message_age_timer);
	if (obj->_present.forward_delay_timer)
		ynl_attr_put_u64(nlh, IFLA_BRPORT_FORWARD_DELAY_TIMER, obj->forward_delay_timer);
	if (obj->_present.hold_timer)
		ynl_attr_put_u64(nlh, IFLA_BRPORT_HOLD_TIMER, obj->hold_timer);
	if (obj->_present.flush)
		ynl_attr_put(nlh, IFLA_BRPORT_FLUSH, NULL, 0);
	if (obj->_present.multicast_router)
		ynl_attr_put_u8(nlh, IFLA_BRPORT_MULTICAST_ROUTER, obj->multicast_router);
	if (obj->_present.mcast_flood)
		ynl_attr_put(nlh, IFLA_BRPORT_MCAST_FLOOD, NULL, 0);
	if (obj->_present.mcast_to_ucast)
		ynl_attr_put(nlh, IFLA_BRPORT_MCAST_TO_UCAST, NULL, 0);
	if (obj->_present.vlan_tunnel)
		ynl_attr_put(nlh, IFLA_BRPORT_VLAN_TUNNEL, NULL, 0);
	if (obj->_present.bcast_flood)
		ynl_attr_put(nlh, IFLA_BRPORT_BCAST_FLOOD, NULL, 0);
	if (obj->_present.group_fwd_mask)
		ynl_attr_put_u16(nlh, IFLA_BRPORT_GROUP_FWD_MASK, obj->group_fwd_mask);
	if (obj->_present.neigh_suppress)
		ynl_attr_put(nlh, IFLA_BRPORT_NEIGH_SUPPRESS, NULL, 0);
	if (obj->_present.isolated)
		ynl_attr_put(nlh, IFLA_BRPORT_ISOLATED, NULL, 0);
	if (obj->_present.backup_port)
		ynl_attr_put_u32(nlh, IFLA_BRPORT_BACKUP_PORT, obj->backup_port);
	if (obj->_present.mrp_ring_open)
		ynl_attr_put(nlh, IFLA_BRPORT_MRP_RING_OPEN, NULL, 0);
	if (obj->_present.mrp_in_open)
		ynl_attr_put(nlh, IFLA_BRPORT_MRP_IN_OPEN, NULL, 0);
	if (obj->_present.mcast_eht_hosts_limit)
		ynl_attr_put_u32(nlh, IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT, obj->mcast_eht_hosts_limit);
	if (obj->_present.mcast_eht_hosts_cnt)
		ynl_attr_put_u32(nlh, IFLA_BRPORT_MCAST_EHT_HOSTS_CNT, obj->mcast_eht_hosts_cnt);
	if (obj->_present.locked)
		ynl_attr_put(nlh, IFLA_BRPORT_LOCKED, NULL, 0);
	if (obj->_present.mab)
		ynl_attr_put(nlh, IFLA_BRPORT_MAB, NULL, 0);
	if (obj->_present.mcast_n_groups)
		ynl_attr_put_u32(nlh, IFLA_BRPORT_MCAST_N_GROUPS, obj->mcast_n_groups);
	if (obj->_present.mcast_max_groups)
		ynl_attr_put_u32(nlh, IFLA_BRPORT_MCAST_MAX_GROUPS, obj->mcast_max_groups);
	if (obj->_present.neigh_vlan_suppress)
		ynl_attr_put(nlh, IFLA_BRPORT_NEIGH_VLAN_SUPPRESS, NULL, 0);
	if (obj->_present.backup_nhid)
		ynl_attr_put_u32(nlh, IFLA_BRPORT_BACKUP_NHID, obj->backup_nhid);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_brport_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	struct rt_link_linkinfo_brport_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BRPORT_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.state = 1;
			dst->state = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BRPORT_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.priority = 1;
			dst->priority = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_COST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cost = 1;
			dst->cost = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mode = 1;
		} else if (type == IFLA_BRPORT_GUARD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.guard = 1;
		} else if (type == IFLA_BRPORT_PROTECT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.protect = 1;
		} else if (type == IFLA_BRPORT_FAST_LEAVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fast_leave = 1;
		} else if (type == IFLA_BRPORT_LEARNING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.learning = 1;
		} else if (type == IFLA_BRPORT_UNICAST_FLOOD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.unicast_flood = 1;
		} else if (type == IFLA_BRPORT_PROXYARP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proxyarp = 1;
		} else if (type == IFLA_BRPORT_LEARNING_SYNC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.learning_sync = 1;
		} else if (type == IFLA_BRPORT_PROXYARP_WIFI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proxyarp_wifi = 1;
		} else if (type == IFLA_BRPORT_ROOT_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.root_id = len;
			if (len < sizeof(struct ifla_bridge_id))
				dst->root_id = calloc(1, sizeof(struct ifla_bridge_id));
			else
				dst->root_id = malloc(len);
			memcpy(dst->root_id, ynl_attr_data(attr), len);
		} else if (type == IFLA_BRPORT_BRIDGE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.bridge_id = len;
			if (len < sizeof(struct ifla_bridge_id))
				dst->bridge_id = calloc(1, sizeof(struct ifla_bridge_id));
			else
				dst->bridge_id = malloc(len);
			memcpy(dst->bridge_id, ynl_attr_data(attr), len);
		} else if (type == IFLA_BRPORT_DESIGNATED_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.designated_port = 1;
			dst->designated_port = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_DESIGNATED_COST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.designated_cost = 1;
			dst->designated_cost = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_NO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.no = 1;
			dst->no = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_TOPOLOGY_CHANGE_ACK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.topology_change_ack = 1;
			dst->topology_change_ack = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BRPORT_CONFIG_PENDING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.config_pending = 1;
			dst->config_pending = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BRPORT_MESSAGE_AGE_TIMER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.message_age_timer = 1;
			dst->message_age_timer = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BRPORT_FORWARD_DELAY_TIMER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.forward_delay_timer = 1;
			dst->forward_delay_timer = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BRPORT_HOLD_TIMER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hold_timer = 1;
			dst->hold_timer = ynl_attr_get_u64(attr);
		} else if (type == IFLA_BRPORT_FLUSH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flush = 1;
		} else if (type == IFLA_BRPORT_MULTICAST_ROUTER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.multicast_router = 1;
			dst->multicast_router = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BRPORT_MCAST_FLOOD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_flood = 1;
		} else if (type == IFLA_BRPORT_MCAST_TO_UCAST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_to_ucast = 1;
		} else if (type == IFLA_BRPORT_VLAN_TUNNEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vlan_tunnel = 1;
		} else if (type == IFLA_BRPORT_BCAST_FLOOD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bcast_flood = 1;
		} else if (type == IFLA_BRPORT_GROUP_FWD_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.group_fwd_mask = 1;
			dst->group_fwd_mask = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_NEIGH_SUPPRESS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.neigh_suppress = 1;
		} else if (type == IFLA_BRPORT_ISOLATED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.isolated = 1;
		} else if (type == IFLA_BRPORT_BACKUP_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.backup_port = 1;
			dst->backup_port = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_MRP_RING_OPEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mrp_ring_open = 1;
		} else if (type == IFLA_BRPORT_MRP_IN_OPEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mrp_in_open = 1;
		} else if (type == IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_eht_hosts_limit = 1;
			dst->mcast_eht_hosts_limit = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_MCAST_EHT_HOSTS_CNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_eht_hosts_cnt = 1;
			dst->mcast_eht_hosts_cnt = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_LOCKED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.locked = 1;
		} else if (type == IFLA_BRPORT_MAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mab = 1;
		} else if (type == IFLA_BRPORT_MCAST_N_GROUPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_n_groups = 1;
			dst->mcast_n_groups = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_MCAST_MAX_GROUPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_max_groups = 1;
			dst->mcast_max_groups = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_NEIGH_VLAN_SUPPRESS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.neigh_vlan_suppress = 1;
		} else if (type == IFLA_BRPORT_BACKUP_NHID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.backup_nhid = 1;
			dst->backup_nhid = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void rt_link_bond_slave_attrs_free(struct rt_link_bond_slave_attrs *obj)
{
	free(obj->perm_hwaddr);
}

int rt_link_bond_slave_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 struct rt_link_bond_slave_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.state)
		ynl_attr_put_u8(nlh, IFLA_BOND_SLAVE_STATE, obj->state);
	if (obj->_present.mii_status)
		ynl_attr_put_u8(nlh, IFLA_BOND_SLAVE_MII_STATUS, obj->mii_status);
	if (obj->_present.link_failure_count)
		ynl_attr_put_u32(nlh, IFLA_BOND_SLAVE_LINK_FAILURE_COUNT, obj->link_failure_count);
	if (obj->_len.perm_hwaddr)
		ynl_attr_put(nlh, IFLA_BOND_SLAVE_PERM_HWADDR, obj->perm_hwaddr, obj->_len.perm_hwaddr);
	if (obj->_present.queue_id)
		ynl_attr_put_u16(nlh, IFLA_BOND_SLAVE_QUEUE_ID, obj->queue_id);
	if (obj->_present.ad_aggregator_id)
		ynl_attr_put_u16(nlh, IFLA_BOND_SLAVE_AD_AGGREGATOR_ID, obj->ad_aggregator_id);
	if (obj->_present.ad_actor_oper_port_state)
		ynl_attr_put_u8(nlh, IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE, obj->ad_actor_oper_port_state);
	if (obj->_present.ad_partner_oper_port_state)
		ynl_attr_put_u16(nlh, IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE, obj->ad_partner_oper_port_state);
	if (obj->_present.prio)
		ynl_attr_put_u32(nlh, IFLA_BOND_SLAVE_PRIO, obj->prio);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_bond_slave_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	struct rt_link_bond_slave_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BOND_SLAVE_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.state = 1;
			dst->state = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_SLAVE_MII_STATUS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mii_status = 1;
			dst->mii_status = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_SLAVE_LINK_FAILURE_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link_failure_count = 1;
			dst->link_failure_count = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_SLAVE_PERM_HWADDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.perm_hwaddr = len;
			dst->perm_hwaddr = malloc(len);
			memcpy(dst->perm_hwaddr, ynl_attr_data(attr), len);
		} else if (type == IFLA_BOND_SLAVE_QUEUE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.queue_id = 1;
			dst->queue_id = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_SLAVE_AD_AGGREGATOR_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ad_aggregator_id = 1;
			dst->ad_aggregator_id = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ad_actor_oper_port_state = 1;
			dst->ad_actor_oper_port_state = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ad_partner_oper_port_state = 1;
			dst->ad_partner_oper_port_state = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_SLAVE_PRIO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.prio = 1;
			dst->prio = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void rt_link_vf_stats_attrs_free(struct rt_link_vf_stats_attrs *obj)
{
}

int rt_link_vf_stats_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       struct rt_link_vf_stats_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.rx_packets)
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_RX_PACKETS, obj->rx_packets);
	if (obj->_present.tx_packets)
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_TX_PACKETS, obj->tx_packets);
	if (obj->_present.rx_bytes)
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_RX_BYTES, obj->rx_bytes);
	if (obj->_present.tx_bytes)
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_TX_BYTES, obj->tx_bytes);
	if (obj->_present.broadcast)
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_BROADCAST, obj->broadcast);
	if (obj->_present.multicast)
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_MULTICAST, obj->multicast);
	if (obj->_present.rx_dropped)
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_RX_DROPPED, obj->rx_dropped);
	if (obj->_present.tx_dropped)
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_TX_DROPPED, obj->tx_dropped);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vf_stats_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	struct rt_link_vf_stats_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VF_STATS_RX_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rx_packets = 1;
			dst->rx_packets = ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_TX_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tx_packets = 1;
			dst->tx_packets = ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_RX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rx_bytes = 1;
			dst->rx_bytes = ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_TX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tx_bytes = 1;
			dst->tx_bytes = ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_BROADCAST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.broadcast = 1;
			dst->broadcast = ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_MULTICAST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.multicast = 1;
			dst->multicast = ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_RX_DROPPED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rx_dropped = 1;
			dst->rx_dropped = ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_TX_DROPPED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tx_dropped = 1;
			dst->tx_dropped = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

void rt_link_vf_vlan_attrs_free(struct rt_link_vf_vlan_attrs *obj)
{
	free(obj->info);
}

int rt_link_vf_vlan_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct rt_link_vf_vlan_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (i = 0; i < obj->_count.info; i++)
		ynl_attr_put(nlh, IFLA_VF_VLAN_INFO, &obj->info[i], sizeof(struct ifla_vf_vlan_info));
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vf_vlan_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	struct rt_link_vf_vlan_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int n_info = 0;
	int i;

	if (dst->info)
		return ynl_error_parse(yarg, "attribute already present (vf-vlan-attrs.info)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VF_VLAN_INFO) {
			n_info++;
		}
	}

	if (n_info) {
		dst->info = calloc(n_info, sizeof(*dst->info));
		dst->_count.info = n_info;
		i = 0;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == IFLA_VF_VLAN_INFO) {
				size_t len = ynl_attr_data_len(attr);

				if (len > sizeof(dst->info[0]))
					len = sizeof(dst->info[0]);
				memcpy(&dst->info[i], ynl_attr_data(attr), len);
				i++;
			}
		}
	}

	return 0;
}

void rt_link_bond_ad_info_attrs_free(struct rt_link_bond_ad_info_attrs *obj)
{
	free(obj->partner_mac);
}

int rt_link_bond_ad_info_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct rt_link_bond_ad_info_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.aggregator)
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_INFO_AGGREGATOR, obj->aggregator);
	if (obj->_present.num_ports)
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_INFO_NUM_PORTS, obj->num_ports);
	if (obj->_present.actor_key)
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_INFO_ACTOR_KEY, obj->actor_key);
	if (obj->_present.partner_key)
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_INFO_PARTNER_KEY, obj->partner_key);
	if (obj->_len.partner_mac)
		ynl_attr_put(nlh, IFLA_BOND_AD_INFO_PARTNER_MAC, obj->partner_mac, obj->_len.partner_mac);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_bond_ad_info_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct rt_link_bond_ad_info_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BOND_AD_INFO_AGGREGATOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.aggregator = 1;
			dst->aggregator = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_INFO_NUM_PORTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.num_ports = 1;
			dst->num_ports = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_INFO_ACTOR_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.actor_key = 1;
			dst->actor_key = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_INFO_PARTNER_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.partner_key = 1;
			dst->partner_key = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_INFO_PARTNER_MAC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.partner_mac = len;
			dst->partner_mac = malloc(len);
			memcpy(dst->partner_mac, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void rt_link_ifla_vlan_qos_free(struct rt_link_ifla_vlan_qos *obj)
{
	free(obj->mapping);
}

int rt_link_ifla_vlan_qos_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct rt_link_ifla_vlan_qos *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (i = 0; i < obj->_count.mapping; i++)
		ynl_attr_put(nlh, IFLA_VLAN_QOS_MAPPING, &obj->mapping[i], sizeof(struct ifla_vlan_qos_mapping));
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_ifla_vlan_qos_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	struct rt_link_ifla_vlan_qos *dst = yarg->data;
	unsigned int n_mapping = 0;
	const struct nlattr *attr;
	int i;

	if (dst->mapping)
		return ynl_error_parse(yarg, "attribute already present (ifla-vlan-qos.mapping)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VLAN_QOS_MAPPING) {
			n_mapping++;
		}
	}

	if (n_mapping) {
		dst->mapping = calloc(n_mapping, sizeof(*dst->mapping));
		dst->_count.mapping = n_mapping;
		i = 0;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == IFLA_VLAN_QOS_MAPPING) {
				size_t len = ynl_attr_data_len(attr);

				if (len > sizeof(dst->mapping[0]))
					len = sizeof(dst->mapping[0]);
				memcpy(&dst->mapping[i], ynl_attr_data(attr), len);
				i++;
			}
		}
	}

	return 0;
}

void rt_link_af_spec_attrs_free(struct rt_link_af_spec_attrs *obj)
{
	rt_link_ifla_attrs_free(&obj->inet);
	rt_link_ifla6_attrs_free(&obj->inet6);
	rt_link_mctp_attrs_free(&obj->mctp);
}

int rt_link_af_spec_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct rt_link_af_spec_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.inet)
		rt_link_ifla_attrs_put(nlh, AF_INET, &obj->inet);
	if (obj->_present.inet6)
		rt_link_ifla6_attrs_put(nlh, AF_INET6, &obj->inet6);
	if (obj->_present.mctp)
		rt_link_mctp_attrs_put(nlh, AF_MCTP, &obj->mctp);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_af_spec_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	struct rt_link_af_spec_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == AF_INET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.inet = 1;

			parg.rsp_policy = &rt_link_ifla_attrs_nest;
			parg.data = &dst->inet;
			if (rt_link_ifla_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == AF_INET6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.inet6 = 1;

			parg.rsp_policy = &rt_link_ifla6_attrs_nest;
			parg.data = &dst->inet6;
			if (rt_link_ifla6_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == AF_MCTP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mctp = 1;

			parg.rsp_policy = &rt_link_mctp_attrs_nest;
			parg.data = &dst->mctp;
			if (rt_link_mctp_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void rt_link_link_offload_xstats_free(struct rt_link_link_offload_xstats *obj)
{
	unsigned int i;

	free(obj->cpu_hit);
	for (i = 0; i < obj->_count.hw_s_info; i++)
		rt_link_hw_s_info_one_free(&obj->hw_s_info[i]);
	free(obj->hw_s_info);
	free(obj->l3_stats);
}

int rt_link_link_offload_xstats_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	struct rt_link_link_offload_xstats *dst = yarg->data;
	const struct nlattr *attr_hw_s_info = NULL;
	unsigned int n_hw_s_info = 0;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->hw_s_info)
		return ynl_error_parse(yarg, "attribute already present (link-offload-xstats.hw-s-info)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_OFFLOAD_XSTATS_CPU_HIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.cpu_hit = len;
			dst->cpu_hit = malloc(len);
			memcpy(dst->cpu_hit, ynl_attr_data(attr), len);
		} else if (type == IFLA_OFFLOAD_XSTATS_HW_S_INFO) {
			attr_hw_s_info = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_hw_s_info++;
			}
		} else if (type == IFLA_OFFLOAD_XSTATS_L3_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.l3_stats = len;
			dst->l3_stats = malloc(len);
			memcpy(dst->l3_stats, ynl_attr_data(attr), len);
		}
	}

	if (n_hw_s_info) {
		dst->hw_s_info = calloc(n_hw_s_info, sizeof(*dst->hw_s_info));
		dst->_count.hw_s_info = n_hw_s_info;
		i = 0;
		parg.rsp_policy = &rt_link_hw_s_info_one_nest;
		ynl_attr_for_each_nested(attr, attr_hw_s_info) {
			parg.data = &dst->hw_s_info[i];
			if (rt_link_hw_s_info_one_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void
rt_link_linkinfo_member_data_msg_free(struct rt_link_linkinfo_member_data_msg *obj)
{
	rt_link_linkinfo_brport_attrs_free(&obj->bridge);
	rt_link_bond_slave_attrs_free(&obj->bond);
}

int rt_link_linkinfo_member_data_msg_put(struct nlmsghdr *nlh,
					 unsigned int attr_type,
					 struct rt_link_linkinfo_member_data_msg *obj)
{
	if (obj->_present.bridge)
		rt_link_linkinfo_brport_attrs_put(nlh, IFLA_INFO_SLAVE_DATA, &obj->bridge);
	if (obj->_present.bond)
		rt_link_bond_slave_attrs_put(nlh, IFLA_INFO_SLAVE_DATA, &obj->bond);

	return 0;
}

int rt_link_linkinfo_member_data_msg_parse(struct ynl_parse_arg *yarg,
					   const char *sel,
					   const struct nlattr *nested)
{
	struct rt_link_linkinfo_member_data_msg *dst = yarg->data;
	const struct nlattr *attr = nested;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	if (!strcmp(sel, "bridge")) {
		parg.rsp_policy = &rt_link_linkinfo_brport_attrs_nest;
		parg.data = &dst->bridge;
		if (rt_link_linkinfo_brport_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.bridge = 1;
	} else if (!strcmp(sel, "bond")) {
		parg.rsp_policy = &rt_link_bond_slave_attrs_nest;
		parg.data = &dst->bond;
		if (rt_link_bond_slave_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.bond = 1;
	}
	return 0;
}

void rt_link_vfinfo_attrs_free(struct rt_link_vfinfo_attrs *obj)
{
	free(obj->mac);
	free(obj->vlan);
	free(obj->tx_rate);
	free(obj->spoofchk);
	free(obj->link_state);
	free(obj->rate);
	free(obj->rss_query_en);
	rt_link_vf_stats_attrs_free(&obj->stats);
	free(obj->trust);
	free(obj->ib_node_guid);
	free(obj->ib_port_guid);
	rt_link_vf_vlan_attrs_free(&obj->vlan_list);
	free(obj->broadcast);
}

int rt_link_vfinfo_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     struct rt_link_vfinfo_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.mac)
		ynl_attr_put(nlh, IFLA_VF_MAC, obj->mac, obj->_len.mac);
	if (obj->_len.vlan)
		ynl_attr_put(nlh, IFLA_VF_VLAN, obj->vlan, obj->_len.vlan);
	if (obj->_len.tx_rate)
		ynl_attr_put(nlh, IFLA_VF_TX_RATE, obj->tx_rate, obj->_len.tx_rate);
	if (obj->_len.spoofchk)
		ynl_attr_put(nlh, IFLA_VF_SPOOFCHK, obj->spoofchk, obj->_len.spoofchk);
	if (obj->_len.link_state)
		ynl_attr_put(nlh, IFLA_VF_LINK_STATE, obj->link_state, obj->_len.link_state);
	if (obj->_len.rate)
		ynl_attr_put(nlh, IFLA_VF_RATE, obj->rate, obj->_len.rate);
	if (obj->_len.rss_query_en)
		ynl_attr_put(nlh, IFLA_VF_RSS_QUERY_EN, obj->rss_query_en, obj->_len.rss_query_en);
	if (obj->_present.stats)
		rt_link_vf_stats_attrs_put(nlh, IFLA_VF_STATS, &obj->stats);
	if (obj->_len.trust)
		ynl_attr_put(nlh, IFLA_VF_TRUST, obj->trust, obj->_len.trust);
	if (obj->_len.ib_node_guid)
		ynl_attr_put(nlh, IFLA_VF_IB_NODE_GUID, obj->ib_node_guid, obj->_len.ib_node_guid);
	if (obj->_len.ib_port_guid)
		ynl_attr_put(nlh, IFLA_VF_IB_PORT_GUID, obj->ib_port_guid, obj->_len.ib_port_guid);
	if (obj->_present.vlan_list)
		rt_link_vf_vlan_attrs_put(nlh, IFLA_VF_VLAN_LIST, &obj->vlan_list);
	if (obj->_len.broadcast)
		ynl_attr_put(nlh, IFLA_VF_BROADCAST, obj->broadcast, obj->_len.broadcast);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vfinfo_attrs_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested)
{
	struct rt_link_vfinfo_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VF_MAC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.mac = len;
			if (len < sizeof(struct ifla_vf_mac))
				dst->mac = calloc(1, sizeof(struct ifla_vf_mac));
			else
				dst->mac = malloc(len);
			memcpy(dst->mac, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_VLAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.vlan = len;
			if (len < sizeof(struct ifla_vf_vlan))
				dst->vlan = calloc(1, sizeof(struct ifla_vf_vlan));
			else
				dst->vlan = malloc(len);
			memcpy(dst->vlan, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_TX_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tx_rate = len;
			if (len < sizeof(struct ifla_vf_tx_rate))
				dst->tx_rate = calloc(1, sizeof(struct ifla_vf_tx_rate));
			else
				dst->tx_rate = malloc(len);
			memcpy(dst->tx_rate, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_SPOOFCHK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.spoofchk = len;
			if (len < sizeof(struct ifla_vf_spoofchk))
				dst->spoofchk = calloc(1, sizeof(struct ifla_vf_spoofchk));
			else
				dst->spoofchk = malloc(len);
			memcpy(dst->spoofchk, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_LINK_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.link_state = len;
			if (len < sizeof(struct ifla_vf_link_state))
				dst->link_state = calloc(1, sizeof(struct ifla_vf_link_state));
			else
				dst->link_state = malloc(len);
			memcpy(dst->link_state, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rate = len;
			if (len < sizeof(struct ifla_vf_rate))
				dst->rate = calloc(1, sizeof(struct ifla_vf_rate));
			else
				dst->rate = malloc(len);
			memcpy(dst->rate, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_RSS_QUERY_EN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rss_query_en = len;
			if (len < sizeof(struct ifla_vf_rss_query_en))
				dst->rss_query_en = calloc(1, sizeof(struct ifla_vf_rss_query_en));
			else
				dst->rss_query_en = malloc(len);
			memcpy(dst->rss_query_en, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stats = 1;

			parg.rsp_policy = &rt_link_vf_stats_attrs_nest;
			parg.data = &dst->stats;
			if (rt_link_vf_stats_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_VF_TRUST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.trust = len;
			if (len < sizeof(struct ifla_vf_trust))
				dst->trust = calloc(1, sizeof(struct ifla_vf_trust));
			else
				dst->trust = malloc(len);
			memcpy(dst->trust, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_IB_NODE_GUID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ib_node_guid = len;
			if (len < sizeof(struct ifla_vf_guid))
				dst->ib_node_guid = calloc(1, sizeof(struct ifla_vf_guid));
			else
				dst->ib_node_guid = malloc(len);
			memcpy(dst->ib_node_guid, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_IB_PORT_GUID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ib_port_guid = len;
			if (len < sizeof(struct ifla_vf_guid))
				dst->ib_port_guid = calloc(1, sizeof(struct ifla_vf_guid));
			else
				dst->ib_port_guid = malloc(len);
			memcpy(dst->ib_port_guid, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_VLAN_LIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vlan_list = 1;

			parg.rsp_policy = &rt_link_vf_vlan_attrs_nest;
			parg.data = &dst->vlan_list;
			if (rt_link_vf_vlan_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_VF_BROADCAST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.broadcast = len;
			dst->broadcast = malloc(len);
			memcpy(dst->broadcast, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void rt_link_linkinfo_bond_attrs_free(struct rt_link_linkinfo_bond_attrs *obj)
{
	free(obj->arp_ip_target);
	rt_link_bond_ad_info_attrs_free(&obj->ad_info);
	free(obj->ad_actor_system);
	free(obj->ns_ip6_target);
}

int rt_link_linkinfo_bond_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    struct rt_link_linkinfo_bond_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.mode)
		ynl_attr_put_u8(nlh, IFLA_BOND_MODE, obj->mode);
	if (obj->_present.active_slave)
		ynl_attr_put_u32(nlh, IFLA_BOND_ACTIVE_SLAVE, obj->active_slave);
	if (obj->_present.miimon)
		ynl_attr_put_u32(nlh, IFLA_BOND_MIIMON, obj->miimon);
	if (obj->_present.updelay)
		ynl_attr_put_u32(nlh, IFLA_BOND_UPDELAY, obj->updelay);
	if (obj->_present.downdelay)
		ynl_attr_put_u32(nlh, IFLA_BOND_DOWNDELAY, obj->downdelay);
	if (obj->_present.use_carrier)
		ynl_attr_put_u8(nlh, IFLA_BOND_USE_CARRIER, obj->use_carrier);
	if (obj->_present.arp_interval)
		ynl_attr_put_u32(nlh, IFLA_BOND_ARP_INTERVAL, obj->arp_interval);
	array = ynl_attr_nest_start(nlh, IFLA_BOND_ARP_IP_TARGET);
	for (i = 0; i < obj->_count.arp_ip_target; i++) {
		ynl_attr_put_u32(nlh, i, obj->arp_ip_target[i]);
	}
	ynl_attr_nest_end(nlh, array);
	if (obj->_present.arp_validate)
		ynl_attr_put_u32(nlh, IFLA_BOND_ARP_VALIDATE, obj->arp_validate);
	if (obj->_present.arp_all_targets)
		ynl_attr_put_u32(nlh, IFLA_BOND_ARP_ALL_TARGETS, obj->arp_all_targets);
	if (obj->_present.primary)
		ynl_attr_put_u32(nlh, IFLA_BOND_PRIMARY, obj->primary);
	if (obj->_present.primary_reselect)
		ynl_attr_put_u8(nlh, IFLA_BOND_PRIMARY_RESELECT, obj->primary_reselect);
	if (obj->_present.fail_over_mac)
		ynl_attr_put_u8(nlh, IFLA_BOND_FAIL_OVER_MAC, obj->fail_over_mac);
	if (obj->_present.xmit_hash_policy)
		ynl_attr_put_u8(nlh, IFLA_BOND_XMIT_HASH_POLICY, obj->xmit_hash_policy);
	if (obj->_present.resend_igmp)
		ynl_attr_put_u32(nlh, IFLA_BOND_RESEND_IGMP, obj->resend_igmp);
	if (obj->_present.num_peer_notif)
		ynl_attr_put_u8(nlh, IFLA_BOND_NUM_PEER_NOTIF, obj->num_peer_notif);
	if (obj->_present.all_slaves_active)
		ynl_attr_put_u8(nlh, IFLA_BOND_ALL_SLAVES_ACTIVE, obj->all_slaves_active);
	if (obj->_present.min_links)
		ynl_attr_put_u32(nlh, IFLA_BOND_MIN_LINKS, obj->min_links);
	if (obj->_present.lp_interval)
		ynl_attr_put_u32(nlh, IFLA_BOND_LP_INTERVAL, obj->lp_interval);
	if (obj->_present.packets_per_slave)
		ynl_attr_put_u32(nlh, IFLA_BOND_PACKETS_PER_SLAVE, obj->packets_per_slave);
	if (obj->_present.ad_lacp_rate)
		ynl_attr_put_u8(nlh, IFLA_BOND_AD_LACP_RATE, obj->ad_lacp_rate);
	if (obj->_present.ad_select)
		ynl_attr_put_u8(nlh, IFLA_BOND_AD_SELECT, obj->ad_select);
	if (obj->_present.ad_info)
		rt_link_bond_ad_info_attrs_put(nlh, IFLA_BOND_AD_INFO, &obj->ad_info);
	if (obj->_present.ad_actor_sys_prio)
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_ACTOR_SYS_PRIO, obj->ad_actor_sys_prio);
	if (obj->_present.ad_user_port_key)
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_USER_PORT_KEY, obj->ad_user_port_key);
	if (obj->_len.ad_actor_system)
		ynl_attr_put(nlh, IFLA_BOND_AD_ACTOR_SYSTEM, obj->ad_actor_system, obj->_len.ad_actor_system);
	if (obj->_present.tlb_dynamic_lb)
		ynl_attr_put_u8(nlh, IFLA_BOND_TLB_DYNAMIC_LB, obj->tlb_dynamic_lb);
	if (obj->_present.peer_notif_delay)
		ynl_attr_put_u32(nlh, IFLA_BOND_PEER_NOTIF_DELAY, obj->peer_notif_delay);
	if (obj->_present.ad_lacp_active)
		ynl_attr_put_u8(nlh, IFLA_BOND_AD_LACP_ACTIVE, obj->ad_lacp_active);
	if (obj->_present.missed_max)
		ynl_attr_put_u8(nlh, IFLA_BOND_MISSED_MAX, obj->missed_max);
	array = ynl_attr_nest_start(nlh, IFLA_BOND_NS_IP6_TARGET);
	for (i = 0; i < obj->_count.ns_ip6_target; i++)
		ynl_attr_put(nlh, i, obj->ns_ip6_target[i], 16);
	ynl_attr_nest_end(nlh, array);
	if (obj->_present.coupled_control)
		ynl_attr_put_u8(nlh, IFLA_BOND_COUPLED_CONTROL, obj->coupled_control);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_bond_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	struct rt_link_linkinfo_bond_attrs *dst = yarg->data;
	const struct nlattr *attr_arp_ip_target = NULL;
	const struct nlattr *attr_ns_ip6_target = NULL;
	unsigned int n_arp_ip_target = 0;
	unsigned int n_ns_ip6_target = 0;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->arp_ip_target)
		return ynl_error_parse(yarg, "attribute already present (linkinfo-bond-attrs.arp-ip-target)");
	if (dst->ns_ip6_target)
		return ynl_error_parse(yarg, "attribute already present (linkinfo-bond-attrs.ns-ip6-target)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BOND_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mode = 1;
			dst->mode = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_ACTIVE_SLAVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.active_slave = 1;
			dst->active_slave = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_MIIMON) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.miimon = 1;
			dst->miimon = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_UPDELAY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.updelay = 1;
			dst->updelay = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_DOWNDELAY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.downdelay = 1;
			dst->downdelay = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_USE_CARRIER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.use_carrier = 1;
			dst->use_carrier = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_ARP_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.arp_interval = 1;
			dst->arp_interval = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_ARP_IP_TARGET) {
			attr_arp_ip_target = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_arp_ip_target++;
			}
		} else if (type == IFLA_BOND_ARP_VALIDATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.arp_validate = 1;
			dst->arp_validate = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_ARP_ALL_TARGETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.arp_all_targets = 1;
			dst->arp_all_targets = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_PRIMARY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.primary = 1;
			dst->primary = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_PRIMARY_RESELECT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.primary_reselect = 1;
			dst->primary_reselect = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_FAIL_OVER_MAC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fail_over_mac = 1;
			dst->fail_over_mac = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_XMIT_HASH_POLICY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.xmit_hash_policy = 1;
			dst->xmit_hash_policy = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_RESEND_IGMP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resend_igmp = 1;
			dst->resend_igmp = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_NUM_PEER_NOTIF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.num_peer_notif = 1;
			dst->num_peer_notif = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_ALL_SLAVES_ACTIVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.all_slaves_active = 1;
			dst->all_slaves_active = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_MIN_LINKS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.min_links = 1;
			dst->min_links = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_LP_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.lp_interval = 1;
			dst->lp_interval = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_PACKETS_PER_SLAVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.packets_per_slave = 1;
			dst->packets_per_slave = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_AD_LACP_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ad_lacp_rate = 1;
			dst->ad_lacp_rate = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_AD_SELECT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ad_select = 1;
			dst->ad_select = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_AD_INFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ad_info = 1;

			parg.rsp_policy = &rt_link_bond_ad_info_attrs_nest;
			parg.data = &dst->ad_info;
			if (rt_link_bond_ad_info_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_BOND_AD_ACTOR_SYS_PRIO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ad_actor_sys_prio = 1;
			dst->ad_actor_sys_prio = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_USER_PORT_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ad_user_port_key = 1;
			dst->ad_user_port_key = ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_ACTOR_SYSTEM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ad_actor_system = len;
			dst->ad_actor_system = malloc(len);
			memcpy(dst->ad_actor_system, ynl_attr_data(attr), len);
		} else if (type == IFLA_BOND_TLB_DYNAMIC_LB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tlb_dynamic_lb = 1;
			dst->tlb_dynamic_lb = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_PEER_NOTIF_DELAY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.peer_notif_delay = 1;
			dst->peer_notif_delay = ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_AD_LACP_ACTIVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ad_lacp_active = 1;
			dst->ad_lacp_active = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_MISSED_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.missed_max = 1;
			dst->missed_max = ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_NS_IP6_TARGET) {
			attr_ns_ip6_target = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_ns_ip6_target++;
			}
		} else if (type == IFLA_BOND_COUPLED_CONTROL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.coupled_control = 1;
			dst->coupled_control = ynl_attr_get_u8(attr);
		}
	}

	if (n_arp_ip_target) {
		dst->arp_ip_target = calloc(n_arp_ip_target, sizeof(*dst->arp_ip_target));
		dst->_count.arp_ip_target = n_arp_ip_target;
		i = 0;
		ynl_attr_for_each_nested(attr, attr_arp_ip_target) {
			dst->arp_ip_target[i] = ynl_attr_get_u32(attr);
			i++;
		}
	}
	if (n_ns_ip6_target) {
		dst->ns_ip6_target = calloc(n_ns_ip6_target, sizeof(*dst->ns_ip6_target));
		dst->_count.ns_ip6_target = n_ns_ip6_target;
		i = 0;
		ynl_attr_for_each_nested(attr, attr_ns_ip6_target) {
			memcpy(dst->ns_ip6_target[i], ynl_attr_data(attr), 16);
			i++;
		}
	}

	return 0;
}

void rt_link_linkinfo_vlan_attrs_free(struct rt_link_linkinfo_vlan_attrs *obj)
{
	free(obj->flags);
	rt_link_ifla_vlan_qos_free(&obj->egress_qos);
	rt_link_ifla_vlan_qos_free(&obj->ingress_qos);
}

int rt_link_linkinfo_vlan_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    struct rt_link_linkinfo_vlan_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.id)
		ynl_attr_put_u16(nlh, IFLA_VLAN_ID, obj->id);
	if (obj->_len.flags)
		ynl_attr_put(nlh, IFLA_VLAN_FLAGS, obj->flags, obj->_len.flags);
	if (obj->_present.egress_qos)
		rt_link_ifla_vlan_qos_put(nlh, IFLA_VLAN_EGRESS_QOS, &obj->egress_qos);
	if (obj->_present.ingress_qos)
		rt_link_ifla_vlan_qos_put(nlh, IFLA_VLAN_INGRESS_QOS, &obj->ingress_qos);
	if (obj->_present.protocol)
		ynl_attr_put_u16(nlh, IFLA_VLAN_PROTOCOL, obj->protocol);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_vlan_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	struct rt_link_linkinfo_vlan_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VLAN_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u16(attr);
		} else if (type == IFLA_VLAN_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.flags = len;
			if (len < sizeof(struct ifla_vlan_flags))
				dst->flags = calloc(1, sizeof(struct ifla_vlan_flags));
			else
				dst->flags = malloc(len);
			memcpy(dst->flags, ynl_attr_data(attr), len);
		} else if (type == IFLA_VLAN_EGRESS_QOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.egress_qos = 1;

			parg.rsp_policy = &rt_link_ifla_vlan_qos_nest;
			parg.data = &dst->egress_qos;
			if (rt_link_ifla_vlan_qos_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_VLAN_INGRESS_QOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ingress_qos = 1;

			parg.rsp_policy = &rt_link_ifla_vlan_qos_nest;
			parg.data = &dst->ingress_qos;
			if (rt_link_ifla_vlan_qos_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_VLAN_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.protocol = 1;
			dst->protocol = ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

void rt_link_vfinfo_list_attrs_free(struct rt_link_vfinfo_list_attrs *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.info; i++)
		rt_link_vfinfo_attrs_free(&obj->info[i]);
	free(obj->info);
}

int rt_link_vfinfo_list_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  struct rt_link_vfinfo_list_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (i = 0; i < obj->_count.info; i++)
		rt_link_vfinfo_attrs_put(nlh, IFLA_VF_INFO, &obj->info[i]);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vfinfo_list_attrs_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested)
{
	struct rt_link_vfinfo_list_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_info = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->info)
		return ynl_error_parse(yarg, "attribute already present (vfinfo-list-attrs.info)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VF_INFO) {
			n_info++;
		}
	}

	if (n_info) {
		dst->info = calloc(n_info, sizeof(*dst->info));
		dst->_count.info = n_info;
		i = 0;
		parg.rsp_policy = &rt_link_vfinfo_attrs_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == IFLA_VF_INFO) {
				parg.data = &dst->info[i];
				if (rt_link_vfinfo_attrs_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void rt_link_linkinfo_data_msg_free(struct rt_link_linkinfo_data_msg *obj)
{
	rt_link_linkinfo_bond_attrs_free(&obj->bond);
	rt_link_linkinfo_bridge_attrs_free(&obj->bridge);
	rt_link_linkinfo_gre_attrs_free(&obj->erspan);
	rt_link_linkinfo_gre_attrs_free(&obj->gre);
	rt_link_linkinfo_gre_attrs_free(&obj->gretap);
	rt_link_linkinfo_gre6_attrs_free(&obj->ip6gre);
	rt_link_linkinfo_geneve_attrs_free(&obj->geneve);
	rt_link_linkinfo_hsr_attrs_free(&obj->hsr);
	rt_link_linkinfo_iptun_attrs_free(&obj->ipip);
	rt_link_linkinfo_ip6tnl_attrs_free(&obj->ip6tnl);
	rt_link_linkinfo_iptun_attrs_free(&obj->sit);
	rt_link_linkinfo_tun_attrs_free(&obj->tun);
	rt_link_linkinfo_vlan_attrs_free(&obj->vlan);
	rt_link_linkinfo_vrf_attrs_free(&obj->vrf);
	rt_link_linkinfo_vti_attrs_free(&obj->vti);
	rt_link_linkinfo_vti6_attrs_free(&obj->vti6);
	rt_link_linkinfo_netkit_attrs_free(&obj->netkit);
	rt_link_linkinfo_ovpn_attrs_free(&obj->ovpn);
}

int rt_link_linkinfo_data_msg_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  struct rt_link_linkinfo_data_msg *obj)
{
	if (obj->_present.bond)
		rt_link_linkinfo_bond_attrs_put(nlh, IFLA_INFO_DATA, &obj->bond);
	if (obj->_present.bridge)
		rt_link_linkinfo_bridge_attrs_put(nlh, IFLA_INFO_DATA, &obj->bridge);
	if (obj->_present.erspan)
		rt_link_linkinfo_gre_attrs_put(nlh, IFLA_INFO_DATA, &obj->erspan);
	if (obj->_present.gre)
		rt_link_linkinfo_gre_attrs_put(nlh, IFLA_INFO_DATA, &obj->gre);
	if (obj->_present.gretap)
		rt_link_linkinfo_gre_attrs_put(nlh, IFLA_INFO_DATA, &obj->gretap);
	if (obj->_present.ip6gre)
		rt_link_linkinfo_gre6_attrs_put(nlh, IFLA_INFO_DATA, &obj->ip6gre);
	if (obj->_present.geneve)
		rt_link_linkinfo_geneve_attrs_put(nlh, IFLA_INFO_DATA, &obj->geneve);
	if (obj->_present.hsr)
		rt_link_linkinfo_hsr_attrs_put(nlh, IFLA_INFO_DATA, &obj->hsr);
	if (obj->_present.ipip)
		rt_link_linkinfo_iptun_attrs_put(nlh, IFLA_INFO_DATA, &obj->ipip);
	if (obj->_present.ip6tnl)
		rt_link_linkinfo_ip6tnl_attrs_put(nlh, IFLA_INFO_DATA, &obj->ip6tnl);
	if (obj->_present.sit)
		rt_link_linkinfo_iptun_attrs_put(nlh, IFLA_INFO_DATA, &obj->sit);
	if (obj->_present.tun)
		rt_link_linkinfo_tun_attrs_put(nlh, IFLA_INFO_DATA, &obj->tun);
	if (obj->_present.vlan)
		rt_link_linkinfo_vlan_attrs_put(nlh, IFLA_INFO_DATA, &obj->vlan);
	if (obj->_present.vrf)
		rt_link_linkinfo_vrf_attrs_put(nlh, IFLA_INFO_DATA, &obj->vrf);
	if (obj->_present.vti)
		rt_link_linkinfo_vti_attrs_put(nlh, IFLA_INFO_DATA, &obj->vti);
	if (obj->_present.vti6)
		rt_link_linkinfo_vti6_attrs_put(nlh, IFLA_INFO_DATA, &obj->vti6);
	if (obj->_present.netkit)
		rt_link_linkinfo_netkit_attrs_put(nlh, IFLA_INFO_DATA, &obj->netkit);
	if (obj->_present.ovpn)
		rt_link_linkinfo_ovpn_attrs_put(nlh, IFLA_INFO_DATA, &obj->ovpn);

	return 0;
}

int rt_link_linkinfo_data_msg_parse(struct ynl_parse_arg *yarg,
				    const char *sel,
				    const struct nlattr *nested)
{
	struct rt_link_linkinfo_data_msg *dst = yarg->data;
	const struct nlattr *attr = nested;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	if (!strcmp(sel, "bond")) {
		parg.rsp_policy = &rt_link_linkinfo_bond_attrs_nest;
		parg.data = &dst->bond;
		if (rt_link_linkinfo_bond_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.bond = 1;
	} else if (!strcmp(sel, "bridge")) {
		parg.rsp_policy = &rt_link_linkinfo_bridge_attrs_nest;
		parg.data = &dst->bridge;
		if (rt_link_linkinfo_bridge_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.bridge = 1;
	} else if (!strcmp(sel, "erspan")) {
		parg.rsp_policy = &rt_link_linkinfo_gre_attrs_nest;
		parg.data = &dst->erspan;
		if (rt_link_linkinfo_gre_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.erspan = 1;
	} else if (!strcmp(sel, "gre")) {
		parg.rsp_policy = &rt_link_linkinfo_gre_attrs_nest;
		parg.data = &dst->gre;
		if (rt_link_linkinfo_gre_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.gre = 1;
	} else if (!strcmp(sel, "gretap")) {
		parg.rsp_policy = &rt_link_linkinfo_gre_attrs_nest;
		parg.data = &dst->gretap;
		if (rt_link_linkinfo_gre_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.gretap = 1;
	} else if (!strcmp(sel, "ip6gre")) {
		parg.rsp_policy = &rt_link_linkinfo_gre6_attrs_nest;
		parg.data = &dst->ip6gre;
		if (rt_link_linkinfo_gre6_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.ip6gre = 1;
	} else if (!strcmp(sel, "geneve")) {
		parg.rsp_policy = &rt_link_linkinfo_geneve_attrs_nest;
		parg.data = &dst->geneve;
		if (rt_link_linkinfo_geneve_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.geneve = 1;
	} else if (!strcmp(sel, "hsr")) {
		parg.rsp_policy = &rt_link_linkinfo_hsr_attrs_nest;
		parg.data = &dst->hsr;
		if (rt_link_linkinfo_hsr_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.hsr = 1;
	} else if (!strcmp(sel, "ipip")) {
		parg.rsp_policy = &rt_link_linkinfo_iptun_attrs_nest;
		parg.data = &dst->ipip;
		if (rt_link_linkinfo_iptun_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.ipip = 1;
	} else if (!strcmp(sel, "ip6tnl")) {
		parg.rsp_policy = &rt_link_linkinfo_ip6tnl_attrs_nest;
		parg.data = &dst->ip6tnl;
		if (rt_link_linkinfo_ip6tnl_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.ip6tnl = 1;
	} else if (!strcmp(sel, "sit")) {
		parg.rsp_policy = &rt_link_linkinfo_iptun_attrs_nest;
		parg.data = &dst->sit;
		if (rt_link_linkinfo_iptun_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.sit = 1;
	} else if (!strcmp(sel, "tun")) {
		parg.rsp_policy = &rt_link_linkinfo_tun_attrs_nest;
		parg.data = &dst->tun;
		if (rt_link_linkinfo_tun_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.tun = 1;
	} else if (!strcmp(sel, "vlan")) {
		parg.rsp_policy = &rt_link_linkinfo_vlan_attrs_nest;
		parg.data = &dst->vlan;
		if (rt_link_linkinfo_vlan_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.vlan = 1;
	} else if (!strcmp(sel, "vrf")) {
		parg.rsp_policy = &rt_link_linkinfo_vrf_attrs_nest;
		parg.data = &dst->vrf;
		if (rt_link_linkinfo_vrf_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.vrf = 1;
	} else if (!strcmp(sel, "vti")) {
		parg.rsp_policy = &rt_link_linkinfo_vti_attrs_nest;
		parg.data = &dst->vti;
		if (rt_link_linkinfo_vti_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.vti = 1;
	} else if (!strcmp(sel, "vti6")) {
		parg.rsp_policy = &rt_link_linkinfo_vti6_attrs_nest;
		parg.data = &dst->vti6;
		if (rt_link_linkinfo_vti6_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.vti6 = 1;
	} else if (!strcmp(sel, "netkit")) {
		parg.rsp_policy = &rt_link_linkinfo_netkit_attrs_nest;
		parg.data = &dst->netkit;
		if (rt_link_linkinfo_netkit_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.netkit = 1;
	} else if (!strcmp(sel, "ovpn")) {
		parg.rsp_policy = &rt_link_linkinfo_ovpn_attrs_nest;
		parg.data = &dst->ovpn;
		if (rt_link_linkinfo_ovpn_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.ovpn = 1;
	}
	return 0;
}

void rt_link_linkinfo_attrs_free(struct rt_link_linkinfo_attrs *obj)
{
	free(obj->kind);
	rt_link_linkinfo_data_msg_free(&obj->data);
	free(obj->xstats);
	free(obj->slave_kind);
	rt_link_linkinfo_member_data_msg_free(&obj->slave_data);
}

int rt_link_linkinfo_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       struct rt_link_linkinfo_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.kind)
		ynl_attr_put_str(nlh, IFLA_INFO_KIND, obj->kind);
	if (obj->_present.data)
		rt_link_linkinfo_data_msg_put(nlh, IFLA_INFO_DATA, &obj->data);
	if (obj->_len.xstats)
		ynl_attr_put(nlh, IFLA_INFO_XSTATS, obj->xstats, obj->_len.xstats);
	if (obj->_len.slave_kind)
		ynl_attr_put_str(nlh, IFLA_INFO_SLAVE_KIND, obj->slave_kind);
	if (obj->_present.slave_data)
		rt_link_linkinfo_member_data_msg_put(nlh, IFLA_INFO_SLAVE_DATA, &obj->slave_data);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	struct rt_link_linkinfo_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_INFO_KIND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.kind = len;
			dst->kind = malloc(len + 1);
			memcpy(dst->kind, ynl_attr_get_str(attr), len);
			dst->kind[len] = 0;
		} else if (type == IFLA_INFO_DATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.data = 1;

			parg.rsp_policy = &rt_link_linkinfo_data_msg_nest;
			parg.data = &dst->data;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "data", "kind");
			if (rt_link_linkinfo_data_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_INFO_XSTATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.xstats = len;
			dst->xstats = malloc(len);
			memcpy(dst->xstats, ynl_attr_data(attr), len);
		} else if (type == IFLA_INFO_SLAVE_KIND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.slave_kind = len;
			dst->slave_kind = malloc(len + 1);
			memcpy(dst->slave_kind, ynl_attr_get_str(attr), len);
			dst->slave_kind[len] = 0;
		} else if (type == IFLA_INFO_SLAVE_DATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.slave_data = 1;

			parg.rsp_policy = &rt_link_linkinfo_member_data_msg_nest;
			parg.data = &dst->slave_data;
			if (!dst->slave_kind)
				return ynl_submsg_failed(yarg, "slave-data", "slave-kind");
			if (rt_link_linkinfo_member_data_msg_parse(&parg, dst->slave_kind, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

/* ============== RTM_NEWLINK ============== */
/* RTM_NEWLINK - do */
void rt_link_newlink_req_free(struct rt_link_newlink_req *req)
{
	free(req->ifname);
	rt_link_linkinfo_attrs_free(&req->linkinfo);
	free(req->address);
	free(req->broadcast);
	rt_link_af_spec_attrs_free(&req->af_spec);
	free(req);
}

int rt_link_newlink(struct ynl_sock *ys, struct rt_link_newlink_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWLINK, req->_nlmsg_flags);
	ys->req_policy = &rt_link_link_attrs_nest;
	ys->req_hdr_len = sizeof(struct ifinfomsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.ifname)
		ynl_attr_put_str(nlh, IFLA_IFNAME, req->ifname);
	if (req->_present.net_ns_pid)
		ynl_attr_put_u32(nlh, IFLA_NET_NS_PID, req->net_ns_pid);
	if (req->_present.net_ns_fd)
		ynl_attr_put_u32(nlh, IFLA_NET_NS_FD, req->net_ns_fd);
	if (req->_present.target_netnsid)
		ynl_attr_put_s32(nlh, IFLA_TARGET_NETNSID, req->target_netnsid);
	if (req->_present.link_netnsid)
		ynl_attr_put_s32(nlh, IFLA_LINK_NETNSID, req->link_netnsid);
	if (req->_present.linkinfo)
		rt_link_linkinfo_attrs_put(nlh, IFLA_LINKINFO, &req->linkinfo);
	if (req->_present.group)
		ynl_attr_put_u32(nlh, IFLA_GROUP, req->group);
	if (req->_present.num_tx_queues)
		ynl_attr_put_u32(nlh, IFLA_NUM_TX_QUEUES, req->num_tx_queues);
	if (req->_present.num_rx_queues)
		ynl_attr_put_u32(nlh, IFLA_NUM_RX_QUEUES, req->num_rx_queues);
	if (req->_len.address)
		ynl_attr_put(nlh, IFLA_ADDRESS, req->address, req->_len.address);
	if (req->_len.broadcast)
		ynl_attr_put(nlh, IFLA_BROADCAST, req->broadcast, req->_len.broadcast);
	if (req->_present.mtu)
		ynl_attr_put_u32(nlh, IFLA_MTU, req->mtu);
	if (req->_present.txqlen)
		ynl_attr_put_u32(nlh, IFLA_TXQLEN, req->txqlen);
	if (req->_present.operstate)
		ynl_attr_put_u8(nlh, IFLA_OPERSTATE, req->operstate);
	if (req->_present.linkmode)
		ynl_attr_put_u8(nlh, IFLA_LINKMODE, req->linkmode);
	if (req->_present.gso_max_size)
		ynl_attr_put_u32(nlh, IFLA_GSO_MAX_SIZE, req->gso_max_size);
	if (req->_present.gso_max_segs)
		ynl_attr_put_u32(nlh, IFLA_GSO_MAX_SEGS, req->gso_max_segs);
	if (req->_present.gro_max_size)
		ynl_attr_put_u32(nlh, IFLA_GRO_MAX_SIZE, req->gro_max_size);
	if (req->_present.gso_ipv4_max_size)
		ynl_attr_put_u32(nlh, IFLA_GSO_IPV4_MAX_SIZE, req->gso_ipv4_max_size);
	if (req->_present.gro_ipv4_max_size)
		ynl_attr_put_u32(nlh, IFLA_GRO_IPV4_MAX_SIZE, req->gro_ipv4_max_size);
	if (req->_present.af_spec)
		rt_link_af_spec_attrs_put(nlh, IFLA_AF_SPEC, &req->af_spec);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_DELLINK ============== */
/* RTM_DELLINK - do */
void rt_link_dellink_req_free(struct rt_link_dellink_req *req)
{
	free(req->ifname);
	free(req);
}

int rt_link_dellink(struct ynl_sock *ys, struct rt_link_dellink_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELLINK, req->_nlmsg_flags);
	ys->req_policy = &rt_link_link_attrs_nest;
	ys->req_hdr_len = sizeof(struct ifinfomsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.ifname)
		ynl_attr_put_str(nlh, IFLA_IFNAME, req->ifname);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_GETLINK ============== */
/* RTM_GETLINK - do */
void rt_link_getlink_req_free(struct rt_link_getlink_req *req)
{
	free(req->ifname);
	free(req->alt_ifname);
	free(req);
}

void rt_link_getlink_rsp_free(struct rt_link_getlink_rsp *rsp)
{
	free(rsp->address);
	free(rsp->broadcast);
	free(rsp->ifname);
	free(rsp->qdisc);
	free(rsp->stats);
	free(rsp->cost);
	free(rsp->priority);
	free(rsp->wireless);
	free(rsp->protinfo);
	free(rsp->map);
	rt_link_linkinfo_attrs_free(&rsp->linkinfo);
	free(rsp->ifalias);
	rt_link_vfinfo_list_attrs_free(&rsp->vfinfo_list);
	free(rsp->stats64);
	rt_link_vf_ports_attrs_free(&rsp->vf_ports);
	rt_link_port_self_attrs_free(&rsp->port_self);
	rt_link_af_spec_attrs_free(&rsp->af_spec);
	free(rsp->phys_port_id);
	free(rsp->phys_switch_id);
	free(rsp->phys_port_name);
	rt_link_xdp_attrs_free(&rsp->xdp);
	rt_link_prop_list_link_attrs_free(&rsp->prop_list);
	free(rsp->perm_address);
	free(rsp->proto_down_reason);
	free(rsp->parent_dev_name);
	free(rsp->parent_dev_bus_name);
	free(rsp->devlink_port);
	free(rsp);
}

int rt_link_getlink_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	struct rt_link_getlink_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ifinfomsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct ifinfomsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_ADDRESS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.address = len;
			dst->address = malloc(len);
			memcpy(dst->address, ynl_attr_data(attr), len);
		} else if (type == IFLA_BROADCAST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.broadcast = len;
			dst->broadcast = malloc(len);
			memcpy(dst->broadcast, ynl_attr_data(attr), len);
		} else if (type == IFLA_IFNAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.ifname = len;
			dst->ifname = malloc(len + 1);
			memcpy(dst->ifname, ynl_attr_get_str(attr), len);
			dst->ifname[len] = 0;
		} else if (type == IFLA_MTU) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mtu = 1;
			dst->mtu = ynl_attr_get_u32(attr);
		} else if (type == IFLA_LINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link = 1;
			dst->link = ynl_attr_get_u32(attr);
		} else if (type == IFLA_QDISC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.qdisc = len;
			dst->qdisc = malloc(len + 1);
			memcpy(dst->qdisc, ynl_attr_get_str(attr), len);
			dst->qdisc[len] = 0;
		} else if (type == IFLA_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stats = len;
			if (len < sizeof(struct rtnl_link_stats))
				dst->stats = calloc(1, sizeof(struct rtnl_link_stats));
			else
				dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == IFLA_COST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.cost = len;
			dst->cost = malloc(len + 1);
			memcpy(dst->cost, ynl_attr_get_str(attr), len);
			dst->cost[len] = 0;
		} else if (type == IFLA_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.priority = len;
			dst->priority = malloc(len + 1);
			memcpy(dst->priority, ynl_attr_get_str(attr), len);
			dst->priority[len] = 0;
		} else if (type == IFLA_MASTER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.master = 1;
			dst->master = ynl_attr_get_u32(attr);
		} else if (type == IFLA_WIRELESS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.wireless = len;
			dst->wireless = malloc(len + 1);
			memcpy(dst->wireless, ynl_attr_get_str(attr), len);
			dst->wireless[len] = 0;
		} else if (type == IFLA_PROTINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.protinfo = len;
			dst->protinfo = malloc(len + 1);
			memcpy(dst->protinfo, ynl_attr_get_str(attr), len);
			dst->protinfo[len] = 0;
		} else if (type == IFLA_TXQLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txqlen = 1;
			dst->txqlen = ynl_attr_get_u32(attr);
		} else if (type == IFLA_MAP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.map = len;
			if (len < sizeof(struct rtnl_link_ifmap))
				dst->map = calloc(1, sizeof(struct rtnl_link_ifmap));
			else
				dst->map = malloc(len);
			memcpy(dst->map, ynl_attr_data(attr), len);
		} else if (type == IFLA_WEIGHT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.weight = 1;
			dst->weight = ynl_attr_get_u32(attr);
		} else if (type == IFLA_OPERSTATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.operstate = 1;
			dst->operstate = ynl_attr_get_u8(attr);
		} else if (type == IFLA_LINKMODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.linkmode = 1;
			dst->linkmode = ynl_attr_get_u8(attr);
		} else if (type == IFLA_LINKINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.linkinfo = 1;

			parg.rsp_policy = &rt_link_linkinfo_attrs_nest;
			parg.data = &dst->linkinfo;
			if (rt_link_linkinfo_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_NET_NS_PID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.net_ns_pid = 1;
			dst->net_ns_pid = ynl_attr_get_u32(attr);
		} else if (type == IFLA_IFALIAS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.ifalias = len;
			dst->ifalias = malloc(len + 1);
			memcpy(dst->ifalias, ynl_attr_get_str(attr), len);
			dst->ifalias[len] = 0;
		} else if (type == IFLA_NUM_VF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.num_vf = 1;
			dst->num_vf = ynl_attr_get_u32(attr);
		} else if (type == IFLA_VFINFO_LIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vfinfo_list = 1;

			parg.rsp_policy = &rt_link_vfinfo_list_attrs_nest;
			parg.data = &dst->vfinfo_list;
			if (rt_link_vfinfo_list_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_STATS64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stats64 = len;
			if (len < sizeof(struct rtnl_link_stats64))
				dst->stats64 = calloc(1, sizeof(struct rtnl_link_stats64));
			else
				dst->stats64 = malloc(len);
			memcpy(dst->stats64, ynl_attr_data(attr), len);
		} else if (type == IFLA_VF_PORTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vf_ports = 1;

			parg.rsp_policy = &rt_link_vf_ports_attrs_nest;
			parg.data = &dst->vf_ports;
			if (rt_link_vf_ports_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_PORT_SELF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_self = 1;

			parg.rsp_policy = &rt_link_port_self_attrs_nest;
			parg.data = &dst->port_self;
			if (rt_link_port_self_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_AF_SPEC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.af_spec = 1;

			parg.rsp_policy = &rt_link_af_spec_attrs_nest;
			parg.data = &dst->af_spec;
			if (rt_link_af_spec_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_GROUP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.group = 1;
			dst->group = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NET_NS_FD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.net_ns_fd = 1;
			dst->net_ns_fd = ynl_attr_get_u32(attr);
		} else if (type == IFLA_EXT_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ext_mask = 1;
			dst->ext_mask = ynl_attr_get_u32(attr);
		} else if (type == IFLA_PROMISCUITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.promiscuity = 1;
			dst->promiscuity = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NUM_TX_QUEUES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.num_tx_queues = 1;
			dst->num_tx_queues = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NUM_RX_QUEUES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.num_rx_queues = 1;
			dst->num_rx_queues = ynl_attr_get_u32(attr);
		} else if (type == IFLA_CARRIER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.carrier = 1;
			dst->carrier = ynl_attr_get_u8(attr);
		} else if (type == IFLA_PHYS_PORT_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.phys_port_id = len;
			dst->phys_port_id = malloc(len);
			memcpy(dst->phys_port_id, ynl_attr_data(attr), len);
		} else if (type == IFLA_CARRIER_CHANGES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.carrier_changes = 1;
			dst->carrier_changes = ynl_attr_get_u32(attr);
		} else if (type == IFLA_PHYS_SWITCH_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.phys_switch_id = len;
			dst->phys_switch_id = malloc(len);
			memcpy(dst->phys_switch_id, ynl_attr_data(attr), len);
		} else if (type == IFLA_LINK_NETNSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link_netnsid = 1;
			dst->link_netnsid = ynl_attr_get_s32(attr);
		} else if (type == IFLA_PHYS_PORT_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.phys_port_name = len;
			dst->phys_port_name = malloc(len + 1);
			memcpy(dst->phys_port_name, ynl_attr_get_str(attr), len);
			dst->phys_port_name[len] = 0;
		} else if (type == IFLA_PROTO_DOWN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proto_down = 1;
			dst->proto_down = ynl_attr_get_u8(attr);
		} else if (type == IFLA_GSO_MAX_SEGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gso_max_segs = 1;
			dst->gso_max_segs = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GSO_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gso_max_size = 1;
			dst->gso_max_size = ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.xdp = 1;

			parg.rsp_policy = &rt_link_xdp_attrs_nest;
			parg.data = &dst->xdp;
			if (rt_link_xdp_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_EVENT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.event = 1;
			dst->event = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NEW_NETNSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.new_netnsid = 1;
			dst->new_netnsid = ynl_attr_get_s32(attr);
		} else if (type == IFLA_TARGET_NETNSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.target_netnsid = 1;
			dst->target_netnsid = ynl_attr_get_s32(attr);
		} else if (type == IFLA_CARRIER_UP_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.carrier_up_count = 1;
			dst->carrier_up_count = ynl_attr_get_u32(attr);
		} else if (type == IFLA_CARRIER_DOWN_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.carrier_down_count = 1;
			dst->carrier_down_count = ynl_attr_get_u32(attr);
		} else if (type == IFLA_NEW_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.new_ifindex = 1;
			dst->new_ifindex = ynl_attr_get_s32(attr);
		} else if (type == IFLA_MIN_MTU) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.min_mtu = 1;
			dst->min_mtu = ynl_attr_get_u32(attr);
		} else if (type == IFLA_MAX_MTU) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_mtu = 1;
			dst->max_mtu = ynl_attr_get_u32(attr);
		} else if (type == IFLA_PROP_LIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.prop_list = 1;

			parg.rsp_policy = &rt_link_prop_list_link_attrs_nest;
			parg.data = &dst->prop_list;
			if (rt_link_prop_list_link_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_PERM_ADDRESS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.perm_address = len;
			dst->perm_address = malloc(len);
			memcpy(dst->perm_address, ynl_attr_data(attr), len);
		} else if (type == IFLA_PROTO_DOWN_REASON) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.proto_down_reason = len;
			dst->proto_down_reason = malloc(len + 1);
			memcpy(dst->proto_down_reason, ynl_attr_get_str(attr), len);
			dst->proto_down_reason[len] = 0;
		} else if (type == IFLA_PARENT_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.parent_dev_name = len;
			dst->parent_dev_name = malloc(len + 1);
			memcpy(dst->parent_dev_name, ynl_attr_get_str(attr), len);
			dst->parent_dev_name[len] = 0;
		} else if (type == IFLA_PARENT_DEV_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.parent_dev_bus_name = len;
			dst->parent_dev_bus_name = malloc(len + 1);
			memcpy(dst->parent_dev_bus_name, ynl_attr_get_str(attr), len);
			dst->parent_dev_bus_name[len] = 0;
		} else if (type == IFLA_GRO_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gro_max_size = 1;
			dst->gro_max_size = ynl_attr_get_u32(attr);
		} else if (type == IFLA_TSO_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tso_max_size = 1;
			dst->tso_max_size = ynl_attr_get_u32(attr);
		} else if (type == IFLA_TSO_MAX_SEGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tso_max_segs = 1;
			dst->tso_max_segs = ynl_attr_get_u32(attr);
		} else if (type == IFLA_ALLMULTI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.allmulti = 1;
			dst->allmulti = ynl_attr_get_u32(attr);
		} else if (type == IFLA_DEVLINK_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.devlink_port = len;
			dst->devlink_port = malloc(len);
			memcpy(dst->devlink_port, ynl_attr_data(attr), len);
		} else if (type == IFLA_GSO_IPV4_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gso_ipv4_max_size = 1;
			dst->gso_ipv4_max_size = ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRO_IPV4_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gro_ipv4_max_size = 1;
			dst->gro_ipv4_max_size = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct rt_link_getlink_rsp *
rt_link_getlink(struct ynl_sock *ys, struct rt_link_getlink_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct rt_link_getlink_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETLINK, req->_nlmsg_flags);
	ys->req_policy = &rt_link_link_attrs_nest;
	ys->req_hdr_len = sizeof(struct ifinfomsg);
	yrs.yarg.rsp_policy = &rt_link_link_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.ifname)
		ynl_attr_put_str(nlh, IFLA_IFNAME, req->ifname);
	if (req->_len.alt_ifname)
		ynl_attr_put_str(nlh, IFLA_ALT_IFNAME, req->alt_ifname);
	if (req->_present.ext_mask)
		ynl_attr_put_u32(nlh, IFLA_EXT_MASK, req->ext_mask);
	if (req->_present.target_netnsid)
		ynl_attr_put_s32(nlh, IFLA_TARGET_NETNSID, req->target_netnsid);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = rt_link_getlink_rsp_parse;
	yrs.rsp_cmd = 16;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	rt_link_getlink_rsp_free(rsp);
	return NULL;
}

/* RTM_GETLINK - dump */
void rt_link_getlink_req_dump_free(struct rt_link_getlink_req_dump *req)
{
	rt_link_linkinfo_attrs_free(&req->linkinfo);
	free(req);
}

void rt_link_getlink_list_free(struct rt_link_getlink_list *rsp)
{
	struct rt_link_getlink_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.address);
		free(rsp->obj.broadcast);
		free(rsp->obj.ifname);
		free(rsp->obj.qdisc);
		free(rsp->obj.stats);
		free(rsp->obj.cost);
		free(rsp->obj.priority);
		free(rsp->obj.wireless);
		free(rsp->obj.protinfo);
		free(rsp->obj.map);
		rt_link_linkinfo_attrs_free(&rsp->obj.linkinfo);
		free(rsp->obj.ifalias);
		rt_link_vfinfo_list_attrs_free(&rsp->obj.vfinfo_list);
		free(rsp->obj.stats64);
		rt_link_vf_ports_attrs_free(&rsp->obj.vf_ports);
		rt_link_port_self_attrs_free(&rsp->obj.port_self);
		rt_link_af_spec_attrs_free(&rsp->obj.af_spec);
		free(rsp->obj.phys_port_id);
		free(rsp->obj.phys_switch_id);
		free(rsp->obj.phys_port_name);
		rt_link_xdp_attrs_free(&rsp->obj.xdp);
		rt_link_prop_list_link_attrs_free(&rsp->obj.prop_list);
		free(rsp->obj.perm_address);
		free(rsp->obj.proto_down_reason);
		free(rsp->obj.parent_dev_name);
		free(rsp->obj.parent_dev_bus_name);
		free(rsp->obj.devlink_port);
		free(rsp);
	}
}

struct rt_link_getlink_list *
rt_link_getlink_dump(struct ynl_sock *ys, struct rt_link_getlink_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_link_link_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct rt_link_getlink_list);
	yds.cb = rt_link_getlink_rsp_parse;
	yds.rsp_cmd = 16;

	nlh = ynl_msg_start_dump(ys, RTM_GETLINK);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &rt_link_link_attrs_nest;
	ys->req_hdr_len = sizeof(struct ifinfomsg);

	if (req->_present.target_netnsid)
		ynl_attr_put_s32(nlh, IFLA_TARGET_NETNSID, req->target_netnsid);
	if (req->_present.ext_mask)
		ynl_attr_put_u32(nlh, IFLA_EXT_MASK, req->ext_mask);
	if (req->_present.master)
		ynl_attr_put_u32(nlh, IFLA_MASTER, req->master);
	if (req->_present.linkinfo)
		rt_link_linkinfo_attrs_put(nlh, IFLA_LINKINFO, &req->linkinfo);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	rt_link_getlink_list_free(yds.first);
	return NULL;
}

/* RTM_GETLINK - notify */
void rt_link_getlink_ntf_free(struct rt_link_getlink_ntf *rsp)
{
	free(rsp->obj.address);
	free(rsp->obj.broadcast);
	free(rsp->obj.ifname);
	free(rsp->obj.qdisc);
	free(rsp->obj.stats);
	free(rsp->obj.cost);
	free(rsp->obj.priority);
	free(rsp->obj.wireless);
	free(rsp->obj.protinfo);
	free(rsp->obj.map);
	rt_link_linkinfo_attrs_free(&rsp->obj.linkinfo);
	free(rsp->obj.ifalias);
	rt_link_vfinfo_list_attrs_free(&rsp->obj.vfinfo_list);
	free(rsp->obj.stats64);
	rt_link_vf_ports_attrs_free(&rsp->obj.vf_ports);
	rt_link_port_self_attrs_free(&rsp->obj.port_self);
	rt_link_af_spec_attrs_free(&rsp->obj.af_spec);
	free(rsp->obj.phys_port_id);
	free(rsp->obj.phys_switch_id);
	free(rsp->obj.phys_port_name);
	rt_link_xdp_attrs_free(&rsp->obj.xdp);
	rt_link_prop_list_link_attrs_free(&rsp->obj.prop_list);
	free(rsp->obj.perm_address);
	free(rsp->obj.proto_down_reason);
	free(rsp->obj.parent_dev_name);
	free(rsp->obj.parent_dev_bus_name);
	free(rsp->obj.devlink_port);
	free(rsp);
}

/* ============== RTM_SETLINK ============== */
/* RTM_SETLINK - do */
void rt_link_setlink_req_free(struct rt_link_setlink_req *req)
{
	free(req->address);
	free(req->broadcast);
	free(req->ifname);
	free(req->qdisc);
	free(req->stats);
	free(req->cost);
	free(req->priority);
	free(req->wireless);
	free(req->protinfo);
	free(req->map);
	rt_link_linkinfo_attrs_free(&req->linkinfo);
	free(req->ifalias);
	rt_link_vfinfo_list_attrs_free(&req->vfinfo_list);
	free(req->stats64);
	rt_link_vf_ports_attrs_free(&req->vf_ports);
	rt_link_port_self_attrs_free(&req->port_self);
	rt_link_af_spec_attrs_free(&req->af_spec);
	free(req->phys_port_id);
	free(req->phys_switch_id);
	free(req->phys_port_name);
	rt_link_xdp_attrs_free(&req->xdp);
	rt_link_prop_list_link_attrs_free(&req->prop_list);
	free(req->perm_address);
	free(req->proto_down_reason);
	free(req->parent_dev_name);
	free(req->parent_dev_bus_name);
	free(req->devlink_port);
	free(req);
}

int rt_link_setlink(struct ynl_sock *ys, struct rt_link_setlink_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_SETLINK, req->_nlmsg_flags);
	ys->req_policy = &rt_link_link_attrs_nest;
	ys->req_hdr_len = sizeof(struct ifinfomsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.address)
		ynl_attr_put(nlh, IFLA_ADDRESS, req->address, req->_len.address);
	if (req->_len.broadcast)
		ynl_attr_put(nlh, IFLA_BROADCAST, req->broadcast, req->_len.broadcast);
	if (req->_len.ifname)
		ynl_attr_put_str(nlh, IFLA_IFNAME, req->ifname);
	if (req->_present.mtu)
		ynl_attr_put_u32(nlh, IFLA_MTU, req->mtu);
	if (req->_present.link)
		ynl_attr_put_u32(nlh, IFLA_LINK, req->link);
	if (req->_len.qdisc)
		ynl_attr_put_str(nlh, IFLA_QDISC, req->qdisc);
	if (req->_len.stats)
		ynl_attr_put(nlh, IFLA_STATS, req->stats, req->_len.stats);
	if (req->_len.cost)
		ynl_attr_put_str(nlh, IFLA_COST, req->cost);
	if (req->_len.priority)
		ynl_attr_put_str(nlh, IFLA_PRIORITY, req->priority);
	if (req->_present.master)
		ynl_attr_put_u32(nlh, IFLA_MASTER, req->master);
	if (req->_len.wireless)
		ynl_attr_put_str(nlh, IFLA_WIRELESS, req->wireless);
	if (req->_len.protinfo)
		ynl_attr_put_str(nlh, IFLA_PROTINFO, req->protinfo);
	if (req->_present.txqlen)
		ynl_attr_put_u32(nlh, IFLA_TXQLEN, req->txqlen);
	if (req->_len.map)
		ynl_attr_put(nlh, IFLA_MAP, req->map, req->_len.map);
	if (req->_present.weight)
		ynl_attr_put_u32(nlh, IFLA_WEIGHT, req->weight);
	if (req->_present.operstate)
		ynl_attr_put_u8(nlh, IFLA_OPERSTATE, req->operstate);
	if (req->_present.linkmode)
		ynl_attr_put_u8(nlh, IFLA_LINKMODE, req->linkmode);
	if (req->_present.linkinfo)
		rt_link_linkinfo_attrs_put(nlh, IFLA_LINKINFO, &req->linkinfo);
	if (req->_present.net_ns_pid)
		ynl_attr_put_u32(nlh, IFLA_NET_NS_PID, req->net_ns_pid);
	if (req->_len.ifalias)
		ynl_attr_put_str(nlh, IFLA_IFALIAS, req->ifalias);
	if (req->_present.num_vf)
		ynl_attr_put_u32(nlh, IFLA_NUM_VF, req->num_vf);
	if (req->_present.vfinfo_list)
		rt_link_vfinfo_list_attrs_put(nlh, IFLA_VFINFO_LIST, &req->vfinfo_list);
	if (req->_len.stats64)
		ynl_attr_put(nlh, IFLA_STATS64, req->stats64, req->_len.stats64);
	if (req->_present.vf_ports)
		rt_link_vf_ports_attrs_put(nlh, IFLA_VF_PORTS, &req->vf_ports);
	if (req->_present.port_self)
		rt_link_port_self_attrs_put(nlh, IFLA_PORT_SELF, &req->port_self);
	if (req->_present.af_spec)
		rt_link_af_spec_attrs_put(nlh, IFLA_AF_SPEC, &req->af_spec);
	if (req->_present.group)
		ynl_attr_put_u32(nlh, IFLA_GROUP, req->group);
	if (req->_present.net_ns_fd)
		ynl_attr_put_u32(nlh, IFLA_NET_NS_FD, req->net_ns_fd);
	if (req->_present.ext_mask)
		ynl_attr_put_u32(nlh, IFLA_EXT_MASK, req->ext_mask);
	if (req->_present.promiscuity)
		ynl_attr_put_u32(nlh, IFLA_PROMISCUITY, req->promiscuity);
	if (req->_present.num_tx_queues)
		ynl_attr_put_u32(nlh, IFLA_NUM_TX_QUEUES, req->num_tx_queues);
	if (req->_present.num_rx_queues)
		ynl_attr_put_u32(nlh, IFLA_NUM_RX_QUEUES, req->num_rx_queues);
	if (req->_present.carrier)
		ynl_attr_put_u8(nlh, IFLA_CARRIER, req->carrier);
	if (req->_len.phys_port_id)
		ynl_attr_put(nlh, IFLA_PHYS_PORT_ID, req->phys_port_id, req->_len.phys_port_id);
	if (req->_present.carrier_changes)
		ynl_attr_put_u32(nlh, IFLA_CARRIER_CHANGES, req->carrier_changes);
	if (req->_len.phys_switch_id)
		ynl_attr_put(nlh, IFLA_PHYS_SWITCH_ID, req->phys_switch_id, req->_len.phys_switch_id);
	if (req->_present.link_netnsid)
		ynl_attr_put_s32(nlh, IFLA_LINK_NETNSID, req->link_netnsid);
	if (req->_len.phys_port_name)
		ynl_attr_put_str(nlh, IFLA_PHYS_PORT_NAME, req->phys_port_name);
	if (req->_present.proto_down)
		ynl_attr_put_u8(nlh, IFLA_PROTO_DOWN, req->proto_down);
	if (req->_present.gso_max_segs)
		ynl_attr_put_u32(nlh, IFLA_GSO_MAX_SEGS, req->gso_max_segs);
	if (req->_present.gso_max_size)
		ynl_attr_put_u32(nlh, IFLA_GSO_MAX_SIZE, req->gso_max_size);
	if (req->_present.xdp)
		rt_link_xdp_attrs_put(nlh, IFLA_XDP, &req->xdp);
	if (req->_present.event)
		ynl_attr_put_u32(nlh, IFLA_EVENT, req->event);
	if (req->_present.new_netnsid)
		ynl_attr_put_s32(nlh, IFLA_NEW_NETNSID, req->new_netnsid);
	if (req->_present.target_netnsid)
		ynl_attr_put_s32(nlh, IFLA_TARGET_NETNSID, req->target_netnsid);
	if (req->_present.carrier_up_count)
		ynl_attr_put_u32(nlh, IFLA_CARRIER_UP_COUNT, req->carrier_up_count);
	if (req->_present.carrier_down_count)
		ynl_attr_put_u32(nlh, IFLA_CARRIER_DOWN_COUNT, req->carrier_down_count);
	if (req->_present.new_ifindex)
		ynl_attr_put_s32(nlh, IFLA_NEW_IFINDEX, req->new_ifindex);
	if (req->_present.min_mtu)
		ynl_attr_put_u32(nlh, IFLA_MIN_MTU, req->min_mtu);
	if (req->_present.max_mtu)
		ynl_attr_put_u32(nlh, IFLA_MAX_MTU, req->max_mtu);
	if (req->_present.prop_list)
		rt_link_prop_list_link_attrs_put(nlh, IFLA_PROP_LIST, &req->prop_list);
	if (req->_len.perm_address)
		ynl_attr_put(nlh, IFLA_PERM_ADDRESS, req->perm_address, req->_len.perm_address);
	if (req->_len.proto_down_reason)
		ynl_attr_put_str(nlh, IFLA_PROTO_DOWN_REASON, req->proto_down_reason);
	if (req->_len.parent_dev_name)
		ynl_attr_put_str(nlh, IFLA_PARENT_DEV_NAME, req->parent_dev_name);
	if (req->_len.parent_dev_bus_name)
		ynl_attr_put_str(nlh, IFLA_PARENT_DEV_BUS_NAME, req->parent_dev_bus_name);
	if (req->_present.gro_max_size)
		ynl_attr_put_u32(nlh, IFLA_GRO_MAX_SIZE, req->gro_max_size);
	if (req->_present.tso_max_size)
		ynl_attr_put_u32(nlh, IFLA_TSO_MAX_SIZE, req->tso_max_size);
	if (req->_present.tso_max_segs)
		ynl_attr_put_u32(nlh, IFLA_TSO_MAX_SEGS, req->tso_max_segs);
	if (req->_present.allmulti)
		ynl_attr_put_u32(nlh, IFLA_ALLMULTI, req->allmulti);
	if (req->_len.devlink_port)
		ynl_attr_put(nlh, IFLA_DEVLINK_PORT, req->devlink_port, req->_len.devlink_port);
	if (req->_present.gso_ipv4_max_size)
		ynl_attr_put_u32(nlh, IFLA_GSO_IPV4_MAX_SIZE, req->gso_ipv4_max_size);
	if (req->_present.gro_ipv4_max_size)
		ynl_attr_put_u32(nlh, IFLA_GRO_IPV4_MAX_SIZE, req->gro_ipv4_max_size);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_GETSTATS ============== */
/* RTM_GETSTATS - do */
void rt_link_getstats_req_free(struct rt_link_getstats_req *req)
{
	free(req);
}

void rt_link_getstats_rsp_free(struct rt_link_getstats_rsp *rsp)
{
	free(rsp->link_64);
	free(rsp->link_xstats);
	free(rsp->link_xstats_slave);
	rt_link_link_offload_xstats_free(&rsp->link_offload_xstats);
	free(rsp->af_spec);
	free(rsp);
}

int rt_link_getstats_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct rt_link_getstats_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct if_stats_msg));

	ynl_attr_for_each(attr, nlh, sizeof(struct if_stats_msg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_STATS_LINK_64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.link_64 = len;
			if (len < sizeof(struct rtnl_link_stats64))
				dst->link_64 = calloc(1, sizeof(struct rtnl_link_stats64));
			else
				dst->link_64 = malloc(len);
			memcpy(dst->link_64, ynl_attr_data(attr), len);
		} else if (type == IFLA_STATS_LINK_XSTATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.link_xstats = len;
			dst->link_xstats = malloc(len);
			memcpy(dst->link_xstats, ynl_attr_data(attr), len);
		} else if (type == IFLA_STATS_LINK_XSTATS_SLAVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.link_xstats_slave = len;
			dst->link_xstats_slave = malloc(len);
			memcpy(dst->link_xstats_slave, ynl_attr_data(attr), len);
		} else if (type == IFLA_STATS_LINK_OFFLOAD_XSTATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link_offload_xstats = 1;

			parg.rsp_policy = &rt_link_link_offload_xstats_nest;
			parg.data = &dst->link_offload_xstats;
			if (rt_link_link_offload_xstats_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == IFLA_STATS_AF_SPEC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.af_spec = len;
			dst->af_spec = malloc(len);
			memcpy(dst->af_spec, ynl_attr_data(attr), len);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct rt_link_getstats_rsp *
rt_link_getstats(struct ynl_sock *ys, struct rt_link_getstats_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct rt_link_getstats_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETSTATS, req->_nlmsg_flags);
	ys->req_policy = &rt_link_stats_attrs_nest;
	ys->req_hdr_len = sizeof(struct if_stats_msg);
	yrs.yarg.rsp_policy = &rt_link_stats_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = rt_link_getstats_rsp_parse;
	yrs.rsp_cmd = 92;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	rt_link_getstats_rsp_free(rsp);
	return NULL;
}

/* RTM_GETSTATS - dump */
void rt_link_getstats_req_dump_free(struct rt_link_getstats_req_dump *req)
{
	free(req);
}

void rt_link_getstats_list_free(struct rt_link_getstats_list *rsp)
{
	struct rt_link_getstats_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.link_64);
		free(rsp->obj.link_xstats);
		free(rsp->obj.link_xstats_slave);
		rt_link_link_offload_xstats_free(&rsp->obj.link_offload_xstats);
		free(rsp->obj.af_spec);
		free(rsp);
	}
}

struct rt_link_getstats_list *
rt_link_getstats_dump(struct ynl_sock *ys,
		      struct rt_link_getstats_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_link_stats_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct rt_link_getstats_list);
	yds.cb = rt_link_getstats_rsp_parse;
	yds.rsp_cmd = 92;

	nlh = ynl_msg_start_dump(ys, RTM_GETSTATS);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &rt_link_stats_attrs_nest;
	ys->req_hdr_len = sizeof(struct if_stats_msg);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	rt_link_getstats_list_free(yds.first);
	return NULL;
}

static const struct ynl_ntf_info rt_link_ntf_info[] =  {
	[RTM_NEWLINK] =  {
		.alloc_sz	= sizeof(struct rt_link_getlink_ntf),
		.cb		= rt_link_getlink_rsp_parse,
		.policy		= &rt_link_link_attrs_nest,
		.free		= (void *)rt_link_getlink_ntf_free,
	},
};

const struct ynl_family ynl_rt_link_family =  {
	.name		= "rt_link",
	.is_classic	= true,
	.classic_id	= 0,
	.ntf_info	= rt_link_ntf_info,
	.ntf_info_size	= YNL_ARRAY_SIZE(rt_link_ntf_info),
};
