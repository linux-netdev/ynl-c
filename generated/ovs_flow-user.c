// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/ovs_flow.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "ovs_flow-user.h"
#include "ynl.h"
#include <linux/openvswitch.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const ovs_flow_op_strmap[] = {
	[OVS_FLOW_CMD_GET] = "get",
	[OVS_FLOW_CMD_NEW] = "new",
};

const char *ovs_flow_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(ovs_flow_op_strmap))
		return NULL;
	return ovs_flow_op_strmap[op];
}

static const char * const ovs_flow_ovs_frag_type_strmap[] = {
	[0] = "none",
	[1] = "first",
	[2] = "later",
	[255] = "any",
};

const char *ovs_flow_ovs_frag_type_str(enum ovs_frag_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(ovs_flow_ovs_frag_type_strmap))
		return NULL;
	return ovs_flow_ovs_frag_type_strmap[value];
}

static const char * const ovs_flow_ovs_ufid_flags_strmap[] = {
	[0] = "omit-key",
	[1] = "omit-mask",
	[2] = "omit-actions",
};

const char *ovs_flow_ovs_ufid_flags_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(ovs_flow_ovs_ufid_flags_strmap))
		return NULL;
	return ovs_flow_ovs_ufid_flags_strmap[value];
}

static const char * const ovs_flow_ovs_hash_alg_strmap[] = {
	[0] = "ovs-hash-alg-l4",
};

const char *ovs_flow_ovs_hash_alg_str(enum ovs_hash_alg value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(ovs_flow_ovs_hash_alg_strmap))
		return NULL;
	return ovs_flow_ovs_hash_alg_strmap[value];
}

static const char * const ovs_flow_ct_state_flags_strmap[] = {
	[0] = "new",
	[1] = "established",
	[2] = "related",
	[3] = "reply-dir",
	[4] = "invalid",
	[5] = "tracked",
	[6] = "src-nat",
	[7] = "dst-nat",
};

const char *ovs_flow_ct_state_flags_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(ovs_flow_ct_state_flags_strmap))
		return NULL;
	return ovs_flow_ct_state_flags_strmap[value];
}

/* Policies */
extern struct ynl_policy_nest ovs_flow_key_attrs_nest;
extern struct ynl_policy_nest ovs_flow_action_attrs_nest;

struct ynl_policy_attr ovs_flow_ovs_nsh_key_attrs_policy[OVS_NSH_KEY_ATTR_MAX + 1] = {
	[OVS_NSH_KEY_ATTR_BASE] = { .name = "base", .type = YNL_PT_BINARY,},
	[OVS_NSH_KEY_ATTR_MD1] = { .name = "md1", .type = YNL_PT_BINARY,},
	[OVS_NSH_KEY_ATTR_MD2] = { .name = "md2", .type = YNL_PT_BINARY,},
};

struct ynl_policy_nest ovs_flow_ovs_nsh_key_attrs_nest = {
	.max_attr = OVS_NSH_KEY_ATTR_MAX,
	.table = ovs_flow_ovs_nsh_key_attrs_policy,
};

struct ynl_policy_attr ovs_flow_userspace_attrs_policy[OVS_USERSPACE_ATTR_MAX + 1] = {
	[OVS_USERSPACE_ATTR_PID] = { .name = "pid", .type = YNL_PT_U32, },
	[OVS_USERSPACE_ATTR_USERDATA] = { .name = "userdata", .type = YNL_PT_BINARY,},
	[OVS_USERSPACE_ATTR_EGRESS_TUN_PORT] = { .name = "egress-tun-port", .type = YNL_PT_U32, },
	[OVS_USERSPACE_ATTR_ACTIONS] = { .name = "actions", .type = YNL_PT_FLAG, },
};

struct ynl_policy_nest ovs_flow_userspace_attrs_nest = {
	.max_attr = OVS_USERSPACE_ATTR_MAX,
	.table = ovs_flow_userspace_attrs_policy,
};

struct ynl_policy_attr ovs_flow_vxlan_ext_attrs_policy[OVS_VXLAN_EXT_MAX + 1] = {
	[OVS_VXLAN_EXT_GBP] = { .name = "gbp", .type = YNL_PT_U32, },
};

struct ynl_policy_nest ovs_flow_vxlan_ext_attrs_nest = {
	.max_attr = OVS_VXLAN_EXT_MAX,
	.table = ovs_flow_vxlan_ext_attrs_policy,
};

struct ynl_policy_attr ovs_flow_nat_attrs_policy[OVS_NAT_ATTR_MAX + 1] = {
	[OVS_NAT_ATTR_SRC] = { .name = "src", .type = YNL_PT_FLAG, },
	[OVS_NAT_ATTR_DST] = { .name = "dst", .type = YNL_PT_FLAG, },
	[OVS_NAT_ATTR_IP_MIN] = { .name = "ip-min", .type = YNL_PT_BINARY,},
	[OVS_NAT_ATTR_IP_MAX] = { .name = "ip-max", .type = YNL_PT_BINARY,},
	[OVS_NAT_ATTR_PROTO_MIN] = { .name = "proto-min", .type = YNL_PT_U16, },
	[OVS_NAT_ATTR_PROTO_MAX] = { .name = "proto-max", .type = YNL_PT_U16, },
	[OVS_NAT_ATTR_PERSISTENT] = { .name = "persistent", .type = YNL_PT_FLAG, },
	[OVS_NAT_ATTR_PROTO_HASH] = { .name = "proto-hash", .type = YNL_PT_FLAG, },
	[OVS_NAT_ATTR_PROTO_RANDOM] = { .name = "proto-random", .type = YNL_PT_FLAG, },
};

struct ynl_policy_nest ovs_flow_nat_attrs_nest = {
	.max_attr = OVS_NAT_ATTR_MAX,
	.table = ovs_flow_nat_attrs_policy,
};

struct ynl_policy_attr ovs_flow_tunnel_key_attrs_policy[OVS_TUNNEL_KEY_ATTR_MAX + 1] = {
	[OVS_TUNNEL_KEY_ATTR_ID] = { .name = "id", .type = YNL_PT_U64, },
	[OVS_TUNNEL_KEY_ATTR_IPV4_SRC] = { .name = "ipv4-src", .type = YNL_PT_U32, },
	[OVS_TUNNEL_KEY_ATTR_IPV4_DST] = { .name = "ipv4-dst", .type = YNL_PT_U32, },
	[OVS_TUNNEL_KEY_ATTR_TOS] = { .name = "tos", .type = YNL_PT_U8, },
	[OVS_TUNNEL_KEY_ATTR_TTL] = { .name = "ttl", .type = YNL_PT_U8, },
	[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = { .name = "dont-fragment", .type = YNL_PT_FLAG, },
	[OVS_TUNNEL_KEY_ATTR_CSUM] = { .name = "csum", .type = YNL_PT_FLAG, },
	[OVS_TUNNEL_KEY_ATTR_OAM] = { .name = "oam", .type = YNL_PT_FLAG, },
	[OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS] = { .name = "geneve-opts", .type = YNL_PT_BINARY,},
	[OVS_TUNNEL_KEY_ATTR_TP_SRC] = { .name = "tp-src", .type = YNL_PT_U16, },
	[OVS_TUNNEL_KEY_ATTR_TP_DST] = { .name = "tp-dst", .type = YNL_PT_U16, },
	[OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS] = { .name = "vxlan-opts", .type = YNL_PT_NEST, .nest = &ovs_flow_vxlan_ext_attrs_nest, },
	[OVS_TUNNEL_KEY_ATTR_IPV6_SRC] = { .name = "ipv6-src", .type = YNL_PT_BINARY,},
	[OVS_TUNNEL_KEY_ATTR_IPV6_DST] = { .name = "ipv6-dst", .type = YNL_PT_BINARY,},
	[OVS_TUNNEL_KEY_ATTR_PAD] = { .name = "pad", .type = YNL_PT_BINARY,},
	[OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS] = { .name = "erspan-opts", .type = YNL_PT_BINARY,},
	[OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE] = { .name = "ipv4-info-bridge", .type = YNL_PT_FLAG, },
};

struct ynl_policy_nest ovs_flow_tunnel_key_attrs_nest = {
	.max_attr = OVS_TUNNEL_KEY_ATTR_MAX,
	.table = ovs_flow_tunnel_key_attrs_policy,
};

struct ynl_policy_attr ovs_flow_ct_attrs_policy[OVS_CT_ATTR_MAX + 1] = {
	[OVS_CT_ATTR_COMMIT] = { .name = "commit", .type = YNL_PT_FLAG, },
	[OVS_CT_ATTR_ZONE] = { .name = "zone", .type = YNL_PT_U16, },
	[OVS_CT_ATTR_MARK] = { .name = "mark", .type = YNL_PT_BINARY,},
	[OVS_CT_ATTR_LABELS] = { .name = "labels", .type = YNL_PT_BINARY,},
	[OVS_CT_ATTR_HELPER] = { .name = "helper", .type = YNL_PT_NUL_STR, },
	[OVS_CT_ATTR_NAT] = { .name = "nat", .type = YNL_PT_NEST, .nest = &ovs_flow_nat_attrs_nest, },
	[OVS_CT_ATTR_FORCE_COMMIT] = { .name = "force-commit", .type = YNL_PT_FLAG, },
	[OVS_CT_ATTR_EVENTMASK] = { .name = "eventmask", .type = YNL_PT_U32, },
	[OVS_CT_ATTR_TIMEOUT] = { .name = "timeout", .type = YNL_PT_NUL_STR, },
};

struct ynl_policy_nest ovs_flow_ct_attrs_nest = {
	.max_attr = OVS_CT_ATTR_MAX,
	.table = ovs_flow_ct_attrs_policy,
};

struct ynl_policy_attr ovs_flow_check_pkt_len_attrs_policy[OVS_CHECK_PKT_LEN_ATTR_MAX + 1] = {
	[OVS_CHECK_PKT_LEN_ATTR_PKT_LEN] = { .name = "pkt-len", .type = YNL_PT_U16, },
	[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER] = { .name = "actions-if-greater", .type = YNL_PT_NEST, .nest = &ovs_flow_action_attrs_nest, },
	[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL] = { .name = "actions-if-less-equal", .type = YNL_PT_NEST, .nest = &ovs_flow_action_attrs_nest, },
};

struct ynl_policy_nest ovs_flow_check_pkt_len_attrs_nest = {
	.max_attr = OVS_CHECK_PKT_LEN_ATTR_MAX,
	.table = ovs_flow_check_pkt_len_attrs_policy,
};

struct ynl_policy_attr ovs_flow_dec_ttl_attrs_policy[OVS_DEC_TTL_ATTR_MAX + 1] = {
	[OVS_DEC_TTL_ATTR_ACTION] = { .name = "action", .type = YNL_PT_NEST, .nest = &ovs_flow_action_attrs_nest, },
};

struct ynl_policy_nest ovs_flow_dec_ttl_attrs_nest = {
	.max_attr = OVS_DEC_TTL_ATTR_MAX,
	.table = ovs_flow_dec_ttl_attrs_policy,
};

struct ynl_policy_attr ovs_flow_key_attrs_policy[OVS_KEY_ATTR_MAX + 1] = {
	[OVS_KEY_ATTR_ENCAP] = { .name = "encap", .type = YNL_PT_NEST, .nest = &ovs_flow_key_attrs_nest, },
	[OVS_KEY_ATTR_PRIORITY] = { .name = "priority", .type = YNL_PT_U32, },
	[OVS_KEY_ATTR_IN_PORT] = { .name = "in-port", .type = YNL_PT_U32, },
	[OVS_KEY_ATTR_ETHERNET] = { .name = "ethernet", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_VLAN] = { .name = "vlan", .type = YNL_PT_U16, },
	[OVS_KEY_ATTR_ETHERTYPE] = { .name = "ethertype", .type = YNL_PT_U16, },
	[OVS_KEY_ATTR_IPV4] = { .name = "ipv4", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_IPV6] = { .name = "ipv6", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_TCP] = { .name = "tcp", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_UDP] = { .name = "udp", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_ICMP] = { .name = "icmp", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_ICMPV6] = { .name = "icmpv6", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_ARP] = { .name = "arp", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_ND] = { .name = "nd", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_SKB_MARK] = { .name = "skb-mark", .type = YNL_PT_U32, },
	[OVS_KEY_ATTR_TUNNEL] = { .name = "tunnel", .type = YNL_PT_NEST, .nest = &ovs_flow_tunnel_key_attrs_nest, },
	[OVS_KEY_ATTR_SCTP] = { .name = "sctp", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_TCP_FLAGS] = { .name = "tcp-flags", .type = YNL_PT_U16, },
	[OVS_KEY_ATTR_DP_HASH] = { .name = "dp-hash", .type = YNL_PT_U32, },
	[OVS_KEY_ATTR_RECIRC_ID] = { .name = "recirc-id", .type = YNL_PT_U32, },
	[OVS_KEY_ATTR_MPLS] = { .name = "mpls", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_CT_STATE] = { .name = "ct-state", .type = YNL_PT_U32, },
	[OVS_KEY_ATTR_CT_ZONE] = { .name = "ct-zone", .type = YNL_PT_U16, },
	[OVS_KEY_ATTR_CT_MARK] = { .name = "ct-mark", .type = YNL_PT_U32, },
	[OVS_KEY_ATTR_CT_LABELS] = { .name = "ct-labels", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4] = { .name = "ct-orig-tuple-ipv4", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6] = { .name = "ct-orig-tuple-ipv6", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_NSH] = { .name = "nsh", .type = YNL_PT_NEST, .nest = &ovs_flow_ovs_nsh_key_attrs_nest, },
	[OVS_KEY_ATTR_PACKET_TYPE] = { .name = "packet-type", .type = YNL_PT_U32, },
	[OVS_KEY_ATTR_ND_EXTENSIONS] = { .name = "nd-extensions", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_TUNNEL_INFO] = { .name = "tunnel-info", .type = YNL_PT_BINARY,},
	[OVS_KEY_ATTR_IPV6_EXTHDRS] = { .name = "ipv6-exthdrs", .type = YNL_PT_BINARY,},
};

struct ynl_policy_nest ovs_flow_key_attrs_nest = {
	.max_attr = OVS_KEY_ATTR_MAX,
	.table = ovs_flow_key_attrs_policy,
};

struct ynl_policy_attr ovs_flow_sample_attrs_policy[OVS_SAMPLE_ATTR_MAX + 1] = {
	[OVS_SAMPLE_ATTR_PROBABILITY] = { .name = "probability", .type = YNL_PT_U32, },
	[OVS_SAMPLE_ATTR_ACTIONS] = { .name = "actions", .type = YNL_PT_NEST, .nest = &ovs_flow_action_attrs_nest, },
};

struct ynl_policy_nest ovs_flow_sample_attrs_nest = {
	.max_attr = OVS_SAMPLE_ATTR_MAX,
	.table = ovs_flow_sample_attrs_policy,
};

struct ynl_policy_attr ovs_flow_action_attrs_policy[OVS_ACTION_ATTR_MAX + 1] = {
	[OVS_ACTION_ATTR_OUTPUT] = { .name = "output", .type = YNL_PT_U32, },
	[OVS_ACTION_ATTR_USERSPACE] = { .name = "userspace", .type = YNL_PT_NEST, .nest = &ovs_flow_userspace_attrs_nest, },
	[OVS_ACTION_ATTR_SET] = { .name = "set", .type = YNL_PT_NEST, .nest = &ovs_flow_key_attrs_nest, },
	[OVS_ACTION_ATTR_PUSH_VLAN] = { .name = "push-vlan", .type = YNL_PT_BINARY,},
	[OVS_ACTION_ATTR_POP_VLAN] = { .name = "pop-vlan", .type = YNL_PT_FLAG, },
	[OVS_ACTION_ATTR_SAMPLE] = { .name = "sample", .type = YNL_PT_NEST, .nest = &ovs_flow_sample_attrs_nest, },
	[OVS_ACTION_ATTR_RECIRC] = { .name = "recirc", .type = YNL_PT_U32, },
	[OVS_ACTION_ATTR_HASH] = { .name = "hash", .type = YNL_PT_BINARY,},
	[OVS_ACTION_ATTR_PUSH_MPLS] = { .name = "push-mpls", .type = YNL_PT_BINARY,},
	[OVS_ACTION_ATTR_POP_MPLS] = { .name = "pop-mpls", .type = YNL_PT_U16, },
	[OVS_ACTION_ATTR_SET_MASKED] = { .name = "set-masked", .type = YNL_PT_NEST, .nest = &ovs_flow_key_attrs_nest, },
	[OVS_ACTION_ATTR_CT] = { .name = "ct", .type = YNL_PT_NEST, .nest = &ovs_flow_ct_attrs_nest, },
	[OVS_ACTION_ATTR_TRUNC] = { .name = "trunc", .type = YNL_PT_U32, },
	[OVS_ACTION_ATTR_PUSH_ETH] = { .name = "push-eth", .type = YNL_PT_BINARY,},
	[OVS_ACTION_ATTR_POP_ETH] = { .name = "pop-eth", .type = YNL_PT_FLAG, },
	[OVS_ACTION_ATTR_CT_CLEAR] = { .name = "ct-clear", .type = YNL_PT_FLAG, },
	[OVS_ACTION_ATTR_PUSH_NSH] = { .name = "push-nsh", .type = YNL_PT_NEST, .nest = &ovs_flow_ovs_nsh_key_attrs_nest, },
	[OVS_ACTION_ATTR_POP_NSH] = { .name = "pop-nsh", .type = YNL_PT_FLAG, },
	[OVS_ACTION_ATTR_METER] = { .name = "meter", .type = YNL_PT_U32, },
	[OVS_ACTION_ATTR_CLONE] = { .name = "clone", .type = YNL_PT_NEST, .nest = &ovs_flow_action_attrs_nest, },
	[OVS_ACTION_ATTR_CHECK_PKT_LEN] = { .name = "check-pkt-len", .type = YNL_PT_NEST, .nest = &ovs_flow_check_pkt_len_attrs_nest, },
	[OVS_ACTION_ATTR_ADD_MPLS] = { .name = "add-mpls", .type = YNL_PT_BINARY,},
	[OVS_ACTION_ATTR_DEC_TTL] = { .name = "dec-ttl", .type = YNL_PT_NEST, .nest = &ovs_flow_dec_ttl_attrs_nest, },
};

struct ynl_policy_nest ovs_flow_action_attrs_nest = {
	.max_attr = OVS_ACTION_ATTR_MAX,
	.table = ovs_flow_action_attrs_policy,
};

struct ynl_policy_attr ovs_flow_flow_attrs_policy[OVS_FLOW_ATTR_MAX + 1] = {
	[OVS_FLOW_ATTR_KEY] = { .name = "key", .type = YNL_PT_NEST, .nest = &ovs_flow_key_attrs_nest, },
	[OVS_FLOW_ATTR_ACTIONS] = { .name = "actions", .type = YNL_PT_NEST, .nest = &ovs_flow_action_attrs_nest, },
	[OVS_FLOW_ATTR_STATS] = { .name = "stats", .type = YNL_PT_BINARY,},
	[OVS_FLOW_ATTR_TCP_FLAGS] = { .name = "tcp-flags", .type = YNL_PT_U8, },
	[OVS_FLOW_ATTR_USED] = { .name = "used", .type = YNL_PT_U64, },
	[OVS_FLOW_ATTR_CLEAR] = { .name = "clear", .type = YNL_PT_FLAG, },
	[OVS_FLOW_ATTR_MASK] = { .name = "mask", .type = YNL_PT_NEST, .nest = &ovs_flow_key_attrs_nest, },
	[OVS_FLOW_ATTR_PROBE] = { .name = "probe", .type = YNL_PT_BINARY,},
	[OVS_FLOW_ATTR_UFID] = { .name = "ufid", .type = YNL_PT_BINARY,},
	[OVS_FLOW_ATTR_UFID_FLAGS] = { .name = "ufid-flags", .type = YNL_PT_U32, },
	[OVS_FLOW_ATTR_PAD] = { .name = "pad", .type = YNL_PT_BINARY,},
};

struct ynl_policy_nest ovs_flow_flow_attrs_nest = {
	.max_attr = OVS_FLOW_ATTR_MAX,
	.table = ovs_flow_flow_attrs_policy,
};

/* Common nested types */
void ovs_flow_ovs_nsh_key_attrs_free(struct ovs_flow_ovs_nsh_key_attrs *obj);
int ovs_flow_ovs_nsh_key_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct ovs_flow_ovs_nsh_key_attrs *obj);
int ovs_flow_ovs_nsh_key_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested);
void ovs_flow_userspace_attrs_free(struct ovs_flow_userspace_attrs *obj);
int ovs_flow_userspace_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 struct ovs_flow_userspace_attrs *obj);
int ovs_flow_userspace_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested);
void ovs_flow_vxlan_ext_attrs_free(struct ovs_flow_vxlan_ext_attrs *obj);
int ovs_flow_vxlan_ext_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 struct ovs_flow_vxlan_ext_attrs *obj);
int ovs_flow_vxlan_ext_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested);
void ovs_flow_nat_attrs_free(struct ovs_flow_nat_attrs *obj);
int ovs_flow_nat_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct ovs_flow_nat_attrs *obj);
int ovs_flow_nat_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested);
void ovs_flow_tunnel_key_attrs_free(struct ovs_flow_tunnel_key_attrs *obj);
int ovs_flow_tunnel_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  struct ovs_flow_tunnel_key_attrs *obj);
int ovs_flow_tunnel_key_attrs_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested);
void ovs_flow_ct_attrs_free(struct ovs_flow_ct_attrs *obj);
int ovs_flow_ct_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct ovs_flow_ct_attrs *obj);
int ovs_flow_ct_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
void
ovs_flow_check_pkt_len_attrs_free(struct ovs_flow_check_pkt_len_attrs *obj);
int ovs_flow_check_pkt_len_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     struct ovs_flow_check_pkt_len_attrs *obj);
int ovs_flow_check_pkt_len_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested);
void ovs_flow_dec_ttl_attrs_free(struct ovs_flow_dec_ttl_attrs *obj);
int ovs_flow_dec_ttl_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       struct ovs_flow_dec_ttl_attrs *obj);
int ovs_flow_dec_ttl_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested);
void ovs_flow_key_attrs_free(struct ovs_flow_key_attrs *obj);
int ovs_flow_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct ovs_flow_key_attrs *obj);
int ovs_flow_key_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested);
void ovs_flow_sample_attrs_free(struct ovs_flow_sample_attrs *obj);
int ovs_flow_sample_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct ovs_flow_sample_attrs *obj);
int ovs_flow_sample_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested);
void ovs_flow_action_attrs_free(struct ovs_flow_action_attrs *obj);
int ovs_flow_action_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct ovs_flow_action_attrs *obj);
int ovs_flow_action_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested);

void ovs_flow_ovs_nsh_key_attrs_free(struct ovs_flow_ovs_nsh_key_attrs *obj)
{
	free(obj->base);
	free(obj->md1);
	free(obj->md2);
}

int ovs_flow_ovs_nsh_key_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct ovs_flow_ovs_nsh_key_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.base_len)
		ynl_attr_put(nlh, OVS_NSH_KEY_ATTR_BASE, obj->base, obj->_present.base_len);
	if (obj->_present.md1_len)
		ynl_attr_put(nlh, OVS_NSH_KEY_ATTR_MD1, obj->md1, obj->_present.md1_len);
	if (obj->_present.md2_len)
		ynl_attr_put(nlh, OVS_NSH_KEY_ATTR_MD2, obj->md2, obj->_present.md2_len);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_ovs_nsh_key_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct ovs_flow_ovs_nsh_key_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_NSH_KEY_ATTR_BASE) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.base_len = len;
			dst->base = malloc(len);
			memcpy(dst->base, ynl_attr_data(attr), len);
		} else if (type == OVS_NSH_KEY_ATTR_MD1) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.md1_len = len;
			dst->md1 = malloc(len);
			memcpy(dst->md1, ynl_attr_data(attr), len);
		} else if (type == OVS_NSH_KEY_ATTR_MD2) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.md2_len = len;
			dst->md2 = malloc(len);
			memcpy(dst->md2, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void ovs_flow_userspace_attrs_free(struct ovs_flow_userspace_attrs *obj)
{
	free(obj->userdata);
}

int ovs_flow_userspace_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 struct ovs_flow_userspace_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.pid)
		ynl_attr_put_u32(nlh, OVS_USERSPACE_ATTR_PID, obj->pid);
	if (obj->_present.userdata_len)
		ynl_attr_put(nlh, OVS_USERSPACE_ATTR_USERDATA, obj->userdata, obj->_present.userdata_len);
	if (obj->_present.egress_tun_port)
		ynl_attr_put_u32(nlh, OVS_USERSPACE_ATTR_EGRESS_TUN_PORT, obj->egress_tun_port);
	if (obj->_present.actions)
		ynl_attr_put(nlh, OVS_USERSPACE_ATTR_ACTIONS, NULL, 0);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_userspace_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	struct ovs_flow_userspace_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_USERSPACE_ATTR_PID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pid = 1;
			dst->pid = ynl_attr_get_u32(attr);
		} else if (type == OVS_USERSPACE_ATTR_USERDATA) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.userdata_len = len;
			dst->userdata = malloc(len);
			memcpy(dst->userdata, ynl_attr_data(attr), len);
		} else if (type == OVS_USERSPACE_ATTR_EGRESS_TUN_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.egress_tun_port = 1;
			dst->egress_tun_port = ynl_attr_get_u32(attr);
		} else if (type == OVS_USERSPACE_ATTR_ACTIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.actions = 1;
		}
	}

	return 0;
}

void ovs_flow_vxlan_ext_attrs_free(struct ovs_flow_vxlan_ext_attrs *obj)
{
}

int ovs_flow_vxlan_ext_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 struct ovs_flow_vxlan_ext_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.gbp)
		ynl_attr_put_u32(nlh, OVS_VXLAN_EXT_GBP, obj->gbp);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_vxlan_ext_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	struct ovs_flow_vxlan_ext_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_VXLAN_EXT_GBP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gbp = 1;
			dst->gbp = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void ovs_flow_nat_attrs_free(struct ovs_flow_nat_attrs *obj)
{
	free(obj->ip_min);
	free(obj->ip_max);
}

int ovs_flow_nat_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct ovs_flow_nat_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.src)
		ynl_attr_put(nlh, OVS_NAT_ATTR_SRC, NULL, 0);
	if (obj->_present.dst)
		ynl_attr_put(nlh, OVS_NAT_ATTR_DST, NULL, 0);
	if (obj->_present.ip_min_len)
		ynl_attr_put(nlh, OVS_NAT_ATTR_IP_MIN, obj->ip_min, obj->_present.ip_min_len);
	if (obj->_present.ip_max_len)
		ynl_attr_put(nlh, OVS_NAT_ATTR_IP_MAX, obj->ip_max, obj->_present.ip_max_len);
	if (obj->_present.proto_min)
		ynl_attr_put_u16(nlh, OVS_NAT_ATTR_PROTO_MIN, obj->proto_min);
	if (obj->_present.proto_max)
		ynl_attr_put_u16(nlh, OVS_NAT_ATTR_PROTO_MAX, obj->proto_max);
	if (obj->_present.persistent)
		ynl_attr_put(nlh, OVS_NAT_ATTR_PERSISTENT, NULL, 0);
	if (obj->_present.proto_hash)
		ynl_attr_put(nlh, OVS_NAT_ATTR_PROTO_HASH, NULL, 0);
	if (obj->_present.proto_random)
		ynl_attr_put(nlh, OVS_NAT_ATTR_PROTO_RANDOM, NULL, 0);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_nat_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	struct ovs_flow_nat_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_NAT_ATTR_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.src = 1;
		} else if (type == OVS_NAT_ATTR_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dst = 1;
		} else if (type == OVS_NAT_ATTR_IP_MIN) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ip_min_len = len;
			dst->ip_min = malloc(len);
			memcpy(dst->ip_min, ynl_attr_data(attr), len);
		} else if (type == OVS_NAT_ATTR_IP_MAX) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ip_max_len = len;
			dst->ip_max = malloc(len);
			memcpy(dst->ip_max, ynl_attr_data(attr), len);
		} else if (type == OVS_NAT_ATTR_PROTO_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proto_min = 1;
			dst->proto_min = ynl_attr_get_u16(attr);
		} else if (type == OVS_NAT_ATTR_PROTO_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proto_max = 1;
			dst->proto_max = ynl_attr_get_u16(attr);
		} else if (type == OVS_NAT_ATTR_PERSISTENT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.persistent = 1;
		} else if (type == OVS_NAT_ATTR_PROTO_HASH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proto_hash = 1;
		} else if (type == OVS_NAT_ATTR_PROTO_RANDOM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proto_random = 1;
		}
	}

	return 0;
}

void ovs_flow_tunnel_key_attrs_free(struct ovs_flow_tunnel_key_attrs *obj)
{
	free(obj->geneve_opts);
	ovs_flow_vxlan_ext_attrs_free(&obj->vxlan_opts);
	free(obj->ipv6_src);
	free(obj->ipv6_dst);
	free(obj->pad);
	free(obj->erspan_opts);
}

int ovs_flow_tunnel_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  struct ovs_flow_tunnel_key_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.id)
		ynl_attr_put_u64(nlh, OVS_TUNNEL_KEY_ATTR_ID, obj->id);
	if (obj->_present.ipv4_src)
		ynl_attr_put_u32(nlh, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, obj->ipv4_src);
	if (obj->_present.ipv4_dst)
		ynl_attr_put_u32(nlh, OVS_TUNNEL_KEY_ATTR_IPV4_DST, obj->ipv4_dst);
	if (obj->_present.tos)
		ynl_attr_put_u8(nlh, OVS_TUNNEL_KEY_ATTR_TOS, obj->tos);
	if (obj->_present.ttl)
		ynl_attr_put_u8(nlh, OVS_TUNNEL_KEY_ATTR_TTL, obj->ttl);
	if (obj->_present.dont_fragment)
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT, NULL, 0);
	if (obj->_present.csum)
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_CSUM, NULL, 0);
	if (obj->_present.oam)
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_OAM, NULL, 0);
	if (obj->_present.geneve_opts_len)
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS, obj->geneve_opts, obj->_present.geneve_opts_len);
	if (obj->_present.tp_src)
		ynl_attr_put_u16(nlh, OVS_TUNNEL_KEY_ATTR_TP_SRC, obj->tp_src);
	if (obj->_present.tp_dst)
		ynl_attr_put_u16(nlh, OVS_TUNNEL_KEY_ATTR_TP_DST, obj->tp_dst);
	if (obj->_present.vxlan_opts)
		ovs_flow_vxlan_ext_attrs_put(nlh, OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS, &obj->vxlan_opts);
	if (obj->_present.ipv6_src_len)
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_IPV6_SRC, obj->ipv6_src, obj->_present.ipv6_src_len);
	if (obj->_present.ipv6_dst_len)
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_IPV6_DST, obj->ipv6_dst, obj->_present.ipv6_dst_len);
	if (obj->_present.pad_len)
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_PAD, obj->pad, obj->_present.pad_len);
	if (obj->_present.erspan_opts_len)
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS, obj->erspan_opts, obj->_present.erspan_opts_len);
	if (obj->_present.ipv4_info_bridge)
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE, NULL, 0);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_tunnel_key_attrs_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested)
{
	struct ovs_flow_tunnel_key_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_TUNNEL_KEY_ATTR_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u64(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV4_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ipv4_src = 1;
			dst->ipv4_src = ynl_attr_get_u32(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV4_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ipv4_dst = 1;
			dst->ipv4_dst = ynl_attr_get_u32(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_TOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tos = 1;
			dst->tos = ynl_attr_get_u8(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ttl = 1;
			dst->ttl = ynl_attr_get_u8(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dont_fragment = 1;
		} else if (type == OVS_TUNNEL_KEY_ATTR_CSUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.csum = 1;
		} else if (type == OVS_TUNNEL_KEY_ATTR_OAM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.oam = 1;
		} else if (type == OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.geneve_opts_len = len;
			dst->geneve_opts = malloc(len);
			memcpy(dst->geneve_opts, ynl_attr_data(attr), len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_TP_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tp_src = 1;
			dst->tp_src = ynl_attr_get_u16(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_TP_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tp_dst = 1;
			dst->tp_dst = ynl_attr_get_u16(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vxlan_opts = 1;

			parg.rsp_policy = &ovs_flow_vxlan_ext_attrs_nest;
			parg.data = &dst->vxlan_opts;
			if (ovs_flow_vxlan_ext_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV6_SRC) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ipv6_src_len = len;
			dst->ipv6_src = malloc(len);
			memcpy(dst->ipv6_src, ynl_attr_data(attr), len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV6_DST) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ipv6_dst_len = len;
			dst->ipv6_dst = malloc(len);
			memcpy(dst->ipv6_dst, ynl_attr_data(attr), len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_PAD) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.pad_len = len;
			dst->pad = malloc(len);
			memcpy(dst->pad, ynl_attr_data(attr), len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.erspan_opts_len = len;
			dst->erspan_opts = malloc(len);
			memcpy(dst->erspan_opts, ynl_attr_data(attr), len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ipv4_info_bridge = 1;
		}
	}

	return 0;
}

void ovs_flow_ct_attrs_free(struct ovs_flow_ct_attrs *obj)
{
	free(obj->mark);
	free(obj->labels);
	free(obj->helper);
	ovs_flow_nat_attrs_free(&obj->nat);
	free(obj->timeout);
}

int ovs_flow_ct_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct ovs_flow_ct_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.commit)
		ynl_attr_put(nlh, OVS_CT_ATTR_COMMIT, NULL, 0);
	if (obj->_present.zone)
		ynl_attr_put_u16(nlh, OVS_CT_ATTR_ZONE, obj->zone);
	if (obj->_present.mark_len)
		ynl_attr_put(nlh, OVS_CT_ATTR_MARK, obj->mark, obj->_present.mark_len);
	if (obj->_present.labels_len)
		ynl_attr_put(nlh, OVS_CT_ATTR_LABELS, obj->labels, obj->_present.labels_len);
	if (obj->_present.helper_len)
		ynl_attr_put_str(nlh, OVS_CT_ATTR_HELPER, obj->helper);
	if (obj->_present.nat)
		ovs_flow_nat_attrs_put(nlh, OVS_CT_ATTR_NAT, &obj->nat);
	if (obj->_present.force_commit)
		ynl_attr_put(nlh, OVS_CT_ATTR_FORCE_COMMIT, NULL, 0);
	if (obj->_present.eventmask)
		ynl_attr_put_u32(nlh, OVS_CT_ATTR_EVENTMASK, obj->eventmask);
	if (obj->_present.timeout_len)
		ynl_attr_put_str(nlh, OVS_CT_ATTR_TIMEOUT, obj->timeout);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_ct_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct ovs_flow_ct_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_CT_ATTR_COMMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.commit = 1;
		} else if (type == OVS_CT_ATTR_ZONE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.zone = 1;
			dst->zone = ynl_attr_get_u16(attr);
		} else if (type == OVS_CT_ATTR_MARK) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.mark_len = len;
			dst->mark = malloc(len);
			memcpy(dst->mark, ynl_attr_data(attr), len);
		} else if (type == OVS_CT_ATTR_LABELS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.labels_len = len;
			dst->labels = malloc(len);
			memcpy(dst->labels, ynl_attr_data(attr), len);
		} else if (type == OVS_CT_ATTR_HELPER) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_present.helper_len = len;
			dst->helper = malloc(len + 1);
			memcpy(dst->helper, ynl_attr_get_str(attr), len);
			dst->helper[len] = 0;
		} else if (type == OVS_CT_ATTR_NAT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nat = 1;

			parg.rsp_policy = &ovs_flow_nat_attrs_nest;
			parg.data = &dst->nat;
			if (ovs_flow_nat_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_CT_ATTR_FORCE_COMMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.force_commit = 1;
		} else if (type == OVS_CT_ATTR_EVENTMASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.eventmask = 1;
			dst->eventmask = ynl_attr_get_u32(attr);
		} else if (type == OVS_CT_ATTR_TIMEOUT) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_present.timeout_len = len;
			dst->timeout = malloc(len + 1);
			memcpy(dst->timeout, ynl_attr_get_str(attr), len);
			dst->timeout[len] = 0;
		}
	}

	return 0;
}

void
ovs_flow_check_pkt_len_attrs_free(struct ovs_flow_check_pkt_len_attrs *obj)
{
	if (obj->actions_if_greater)
		ovs_flow_action_attrs_free(obj->actions_if_greater);
	if (obj->actions_if_less_equal)
		ovs_flow_action_attrs_free(obj->actions_if_less_equal);
}

int ovs_flow_check_pkt_len_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     struct ovs_flow_check_pkt_len_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.pkt_len)
		ynl_attr_put_u16(nlh, OVS_CHECK_PKT_LEN_ATTR_PKT_LEN, obj->pkt_len);
	if (obj->_present.actions_if_greater)
		ovs_flow_action_attrs_put(nlh, OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER, obj->actions_if_greater);
	if (obj->_present.actions_if_less_equal)
		ovs_flow_action_attrs_put(nlh, OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL, obj->actions_if_less_equal);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_check_pkt_len_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	struct ovs_flow_check_pkt_len_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_CHECK_PKT_LEN_ATTR_PKT_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pkt_len = 1;
			dst->pkt_len = ynl_attr_get_u16(attr);
		} else if (type == OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.actions_if_greater = 1;

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			parg.data = &dst->actions_if_greater;
			if (ovs_flow_action_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.actions_if_less_equal = 1;

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			parg.data = &dst->actions_if_less_equal;
			if (ovs_flow_action_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void ovs_flow_dec_ttl_attrs_free(struct ovs_flow_dec_ttl_attrs *obj)
{
	if (obj->action)
		ovs_flow_action_attrs_free(obj->action);
}

int ovs_flow_dec_ttl_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       struct ovs_flow_dec_ttl_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.action)
		ovs_flow_action_attrs_put(nlh, OVS_DEC_TTL_ATTR_ACTION, obj->action);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_dec_ttl_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	struct ovs_flow_dec_ttl_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_DEC_TTL_ATTR_ACTION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.action = 1;

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			parg.data = &dst->action;
			if (ovs_flow_action_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void ovs_flow_key_attrs_free(struct ovs_flow_key_attrs *obj)
{
	if (obj->encap)
		ovs_flow_key_attrs_free(obj->encap);
	free(obj->ethernet);
	free(obj->ipv4);
	free(obj->ipv6);
	free(obj->tcp);
	free(obj->udp);
	free(obj->icmp);
	free(obj->icmpv6);
	free(obj->arp);
	free(obj->nd);
	ovs_flow_tunnel_key_attrs_free(&obj->tunnel);
	free(obj->sctp);
	free(obj->mpls);
	free(obj->ct_labels);
	free(obj->ct_orig_tuple_ipv4);
	free(obj->ct_orig_tuple_ipv6);
	ovs_flow_ovs_nsh_key_attrs_free(&obj->nsh);
	free(obj->nd_extensions);
	free(obj->tunnel_info);
	free(obj->ipv6_exthdrs);
}

int ovs_flow_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct ovs_flow_key_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.encap)
		ovs_flow_key_attrs_put(nlh, OVS_KEY_ATTR_ENCAP, obj->encap);
	if (obj->_present.priority)
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_PRIORITY, obj->priority);
	if (obj->_present.in_port)
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_IN_PORT, obj->in_port);
	if (obj->_present.ethernet_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_ETHERNET, obj->ethernet, obj->_present.ethernet_len);
	if (obj->_present.vlan)
		ynl_attr_put_u16(nlh, OVS_KEY_ATTR_VLAN, obj->vlan);
	if (obj->_present.ethertype)
		ynl_attr_put_u16(nlh, OVS_KEY_ATTR_ETHERTYPE, obj->ethertype);
	if (obj->_present.ipv4_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_IPV4, obj->ipv4, obj->_present.ipv4_len);
	if (obj->_present.ipv6_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_IPV6, obj->ipv6, obj->_present.ipv6_len);
	if (obj->_present.tcp_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_TCP, obj->tcp, obj->_present.tcp_len);
	if (obj->_present.udp_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_UDP, obj->udp, obj->_present.udp_len);
	if (obj->_present.icmp_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_ICMP, obj->icmp, obj->_present.icmp_len);
	if (obj->_present.icmpv6_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_ICMPV6, obj->icmpv6, obj->_present.icmpv6_len);
	if (obj->_present.arp_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_ARP, obj->arp, obj->_present.arp_len);
	if (obj->_present.nd_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_ND, obj->nd, obj->_present.nd_len);
	if (obj->_present.skb_mark)
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_SKB_MARK, obj->skb_mark);
	if (obj->_present.tunnel)
		ovs_flow_tunnel_key_attrs_put(nlh, OVS_KEY_ATTR_TUNNEL, &obj->tunnel);
	if (obj->_present.sctp_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_SCTP, obj->sctp, obj->_present.sctp_len);
	if (obj->_present.tcp_flags)
		ynl_attr_put_u16(nlh, OVS_KEY_ATTR_TCP_FLAGS, obj->tcp_flags);
	if (obj->_present.dp_hash)
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_DP_HASH, obj->dp_hash);
	if (obj->_present.recirc_id)
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_RECIRC_ID, obj->recirc_id);
	if (obj->_present.mpls_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_MPLS, obj->mpls, obj->_present.mpls_len);
	if (obj->_present.ct_state)
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_CT_STATE, obj->ct_state);
	if (obj->_present.ct_zone)
		ynl_attr_put_u16(nlh, OVS_KEY_ATTR_CT_ZONE, obj->ct_zone);
	if (obj->_present.ct_mark)
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_CT_MARK, obj->ct_mark);
	if (obj->_present.ct_labels_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_CT_LABELS, obj->ct_labels, obj->_present.ct_labels_len);
	if (obj->_present.ct_orig_tuple_ipv4_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4, obj->ct_orig_tuple_ipv4, obj->_present.ct_orig_tuple_ipv4_len);
	if (obj->_present.ct_orig_tuple_ipv6_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6, obj->ct_orig_tuple_ipv6, obj->_present.ct_orig_tuple_ipv6_len);
	if (obj->_present.nsh)
		ovs_flow_ovs_nsh_key_attrs_put(nlh, OVS_KEY_ATTR_NSH, &obj->nsh);
	if (obj->_present.packet_type)
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_PACKET_TYPE, obj->packet_type);
	if (obj->_present.nd_extensions_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_ND_EXTENSIONS, obj->nd_extensions, obj->_present.nd_extensions_len);
	if (obj->_present.tunnel_info_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_TUNNEL_INFO, obj->tunnel_info, obj->_present.tunnel_info_len);
	if (obj->_present.ipv6_exthdrs_len)
		ynl_attr_put(nlh, OVS_KEY_ATTR_IPV6_EXTHDRS, obj->ipv6_exthdrs, obj->_present.ipv6_exthdrs_len);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_key_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	struct ovs_flow_key_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_KEY_ATTR_ENCAP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap = 1;

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			parg.data = &dst->encap;
			if (ovs_flow_key_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_KEY_ATTR_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.priority = 1;
			dst->priority = ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_IN_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.in_port = 1;
			dst->in_port = ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_ETHERNET) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ethernet_len = len;
			dst->ethernet = malloc(len);
			memcpy(dst->ethernet, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_VLAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vlan = 1;
			dst->vlan = ynl_attr_get_u16(attr);
		} else if (type == OVS_KEY_ATTR_ETHERTYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ethertype = 1;
			dst->ethertype = ynl_attr_get_u16(attr);
		} else if (type == OVS_KEY_ATTR_IPV4) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ipv4_len = len;
			dst->ipv4 = malloc(len);
			memcpy(dst->ipv4, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_IPV6) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ipv6_len = len;
			dst->ipv6 = malloc(len);
			memcpy(dst->ipv6, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_TCP) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.tcp_len = len;
			dst->tcp = malloc(len);
			memcpy(dst->tcp, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_UDP) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.udp_len = len;
			dst->udp = malloc(len);
			memcpy(dst->udp, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_ICMP) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.icmp_len = len;
			dst->icmp = malloc(len);
			memcpy(dst->icmp, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_ICMPV6) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.icmpv6_len = len;
			dst->icmpv6 = malloc(len);
			memcpy(dst->icmpv6, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_ARP) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.arp_len = len;
			dst->arp = malloc(len);
			memcpy(dst->arp, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_ND) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.nd_len = len;
			dst->nd = malloc(len);
			memcpy(dst->nd, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_SKB_MARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.skb_mark = 1;
			dst->skb_mark = ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_TUNNEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tunnel = 1;

			parg.rsp_policy = &ovs_flow_tunnel_key_attrs_nest;
			parg.data = &dst->tunnel;
			if (ovs_flow_tunnel_key_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_KEY_ATTR_SCTP) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.sctp_len = len;
			dst->sctp = malloc(len);
			memcpy(dst->sctp, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_TCP_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tcp_flags = 1;
			dst->tcp_flags = ynl_attr_get_u16(attr);
		} else if (type == OVS_KEY_ATTR_DP_HASH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dp_hash = 1;
			dst->dp_hash = ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_RECIRC_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.recirc_id = 1;
			dst->recirc_id = ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_MPLS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.mpls_len = len;
			dst->mpls = malloc(len);
			memcpy(dst->mpls, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_CT_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ct_state = 1;
			dst->ct_state = ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_CT_ZONE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ct_zone = 1;
			dst->ct_zone = ynl_attr_get_u16(attr);
		} else if (type == OVS_KEY_ATTR_CT_MARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ct_mark = 1;
			dst->ct_mark = ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_CT_LABELS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ct_labels_len = len;
			dst->ct_labels = malloc(len);
			memcpy(dst->ct_labels, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ct_orig_tuple_ipv4_len = len;
			dst->ct_orig_tuple_ipv4 = malloc(len);
			memcpy(dst->ct_orig_tuple_ipv4, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ct_orig_tuple_ipv6_len = len;
			dst->ct_orig_tuple_ipv6 = malloc(len);
			memcpy(dst->ct_orig_tuple_ipv6, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_NSH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nsh = 1;

			parg.rsp_policy = &ovs_flow_ovs_nsh_key_attrs_nest;
			parg.data = &dst->nsh;
			if (ovs_flow_ovs_nsh_key_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_KEY_ATTR_PACKET_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.packet_type = 1;
			dst->packet_type = ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_ND_EXTENSIONS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.nd_extensions_len = len;
			dst->nd_extensions = malloc(len);
			memcpy(dst->nd_extensions, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_TUNNEL_INFO) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.tunnel_info_len = len;
			dst->tunnel_info = malloc(len);
			memcpy(dst->tunnel_info, ynl_attr_data(attr), len);
		} else if (type == OVS_KEY_ATTR_IPV6_EXTHDRS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ipv6_exthdrs_len = len;
			dst->ipv6_exthdrs = malloc(len);
			memcpy(dst->ipv6_exthdrs, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void ovs_flow_sample_attrs_free(struct ovs_flow_sample_attrs *obj)
{
	if (obj->actions)
		ovs_flow_action_attrs_free(obj->actions);
}

int ovs_flow_sample_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct ovs_flow_sample_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.probability)
		ynl_attr_put_u32(nlh, OVS_SAMPLE_ATTR_PROBABILITY, obj->probability);
	if (obj->_present.actions)
		ovs_flow_action_attrs_put(nlh, OVS_SAMPLE_ATTR_ACTIONS, obj->actions);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_sample_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	struct ovs_flow_sample_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_SAMPLE_ATTR_PROBABILITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.probability = 1;
			dst->probability = ynl_attr_get_u32(attr);
		} else if (type == OVS_SAMPLE_ATTR_ACTIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.actions = 1;

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			parg.data = &dst->actions;
			if (ovs_flow_action_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void ovs_flow_action_attrs_free(struct ovs_flow_action_attrs *obj)
{
	ovs_flow_userspace_attrs_free(&obj->userspace);
	if (obj->set)
		ovs_flow_key_attrs_free(obj->set);
	free(obj->push_vlan);
	ovs_flow_sample_attrs_free(&obj->sample);
	free(obj->hash);
	free(obj->push_mpls);
	if (obj->set_masked)
		ovs_flow_key_attrs_free(obj->set_masked);
	ovs_flow_ct_attrs_free(&obj->ct);
	free(obj->push_eth);
	ovs_flow_ovs_nsh_key_attrs_free(&obj->push_nsh);
	if (obj->clone)
		ovs_flow_action_attrs_free(obj->clone);
	ovs_flow_check_pkt_len_attrs_free(&obj->check_pkt_len);
	free(obj->add_mpls);
	ovs_flow_dec_ttl_attrs_free(&obj->dec_ttl);
}

int ovs_flow_action_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct ovs_flow_action_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.output)
		ynl_attr_put_u32(nlh, OVS_ACTION_ATTR_OUTPUT, obj->output);
	if (obj->_present.userspace)
		ovs_flow_userspace_attrs_put(nlh, OVS_ACTION_ATTR_USERSPACE, &obj->userspace);
	if (obj->_present.set)
		ovs_flow_key_attrs_put(nlh, OVS_ACTION_ATTR_SET, obj->set);
	if (obj->_present.push_vlan_len)
		ynl_attr_put(nlh, OVS_ACTION_ATTR_PUSH_VLAN, obj->push_vlan, obj->_present.push_vlan_len);
	if (obj->_present.pop_vlan)
		ynl_attr_put(nlh, OVS_ACTION_ATTR_POP_VLAN, NULL, 0);
	if (obj->_present.sample)
		ovs_flow_sample_attrs_put(nlh, OVS_ACTION_ATTR_SAMPLE, &obj->sample);
	if (obj->_present.recirc)
		ynl_attr_put_u32(nlh, OVS_ACTION_ATTR_RECIRC, obj->recirc);
	if (obj->_present.hash_len)
		ynl_attr_put(nlh, OVS_ACTION_ATTR_HASH, obj->hash, obj->_present.hash_len);
	if (obj->_present.push_mpls_len)
		ynl_attr_put(nlh, OVS_ACTION_ATTR_PUSH_MPLS, obj->push_mpls, obj->_present.push_mpls_len);
	if (obj->_present.pop_mpls)
		ynl_attr_put_u16(nlh, OVS_ACTION_ATTR_POP_MPLS, obj->pop_mpls);
	if (obj->_present.set_masked)
		ovs_flow_key_attrs_put(nlh, OVS_ACTION_ATTR_SET_MASKED, obj->set_masked);
	if (obj->_present.ct)
		ovs_flow_ct_attrs_put(nlh, OVS_ACTION_ATTR_CT, &obj->ct);
	if (obj->_present.trunc)
		ynl_attr_put_u32(nlh, OVS_ACTION_ATTR_TRUNC, obj->trunc);
	if (obj->_present.push_eth_len)
		ynl_attr_put(nlh, OVS_ACTION_ATTR_PUSH_ETH, obj->push_eth, obj->_present.push_eth_len);
	if (obj->_present.pop_eth)
		ynl_attr_put(nlh, OVS_ACTION_ATTR_POP_ETH, NULL, 0);
	if (obj->_present.ct_clear)
		ynl_attr_put(nlh, OVS_ACTION_ATTR_CT_CLEAR, NULL, 0);
	if (obj->_present.push_nsh)
		ovs_flow_ovs_nsh_key_attrs_put(nlh, OVS_ACTION_ATTR_PUSH_NSH, &obj->push_nsh);
	if (obj->_present.pop_nsh)
		ynl_attr_put(nlh, OVS_ACTION_ATTR_POP_NSH, NULL, 0);
	if (obj->_present.meter)
		ynl_attr_put_u32(nlh, OVS_ACTION_ATTR_METER, obj->meter);
	if (obj->_present.clone)
		ovs_flow_action_attrs_put(nlh, OVS_ACTION_ATTR_CLONE, obj->clone);
	if (obj->_present.check_pkt_len)
		ovs_flow_check_pkt_len_attrs_put(nlh, OVS_ACTION_ATTR_CHECK_PKT_LEN, &obj->check_pkt_len);
	if (obj->_present.add_mpls_len)
		ynl_attr_put(nlh, OVS_ACTION_ATTR_ADD_MPLS, obj->add_mpls, obj->_present.add_mpls_len);
	if (obj->_present.dec_ttl)
		ovs_flow_dec_ttl_attrs_put(nlh, OVS_ACTION_ATTR_DEC_TTL, &obj->dec_ttl);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_action_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	struct ovs_flow_action_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_ACTION_ATTR_OUTPUT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.output = 1;
			dst->output = ynl_attr_get_u32(attr);
		} else if (type == OVS_ACTION_ATTR_USERSPACE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.userspace = 1;

			parg.rsp_policy = &ovs_flow_userspace_attrs_nest;
			parg.data = &dst->userspace;
			if (ovs_flow_userspace_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_ACTION_ATTR_SET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.set = 1;

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			parg.data = &dst->set;
			if (ovs_flow_key_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_ACTION_ATTR_PUSH_VLAN) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.push_vlan_len = len;
			dst->push_vlan = malloc(len);
			memcpy(dst->push_vlan, ynl_attr_data(attr), len);
		} else if (type == OVS_ACTION_ATTR_POP_VLAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pop_vlan = 1;
		} else if (type == OVS_ACTION_ATTR_SAMPLE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sample = 1;

			parg.rsp_policy = &ovs_flow_sample_attrs_nest;
			parg.data = &dst->sample;
			if (ovs_flow_sample_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_ACTION_ATTR_RECIRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.recirc = 1;
			dst->recirc = ynl_attr_get_u32(attr);
		} else if (type == OVS_ACTION_ATTR_HASH) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.hash_len = len;
			dst->hash = malloc(len);
			memcpy(dst->hash, ynl_attr_data(attr), len);
		} else if (type == OVS_ACTION_ATTR_PUSH_MPLS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.push_mpls_len = len;
			dst->push_mpls = malloc(len);
			memcpy(dst->push_mpls, ynl_attr_data(attr), len);
		} else if (type == OVS_ACTION_ATTR_POP_MPLS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pop_mpls = 1;
			dst->pop_mpls = ynl_attr_get_u16(attr);
		} else if (type == OVS_ACTION_ATTR_SET_MASKED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.set_masked = 1;

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			parg.data = &dst->set_masked;
			if (ovs_flow_key_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_ACTION_ATTR_CT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ct = 1;

			parg.rsp_policy = &ovs_flow_ct_attrs_nest;
			parg.data = &dst->ct;
			if (ovs_flow_ct_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_ACTION_ATTR_TRUNC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.trunc = 1;
			dst->trunc = ynl_attr_get_u32(attr);
		} else if (type == OVS_ACTION_ATTR_PUSH_ETH) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.push_eth_len = len;
			dst->push_eth = malloc(len);
			memcpy(dst->push_eth, ynl_attr_data(attr), len);
		} else if (type == OVS_ACTION_ATTR_POP_ETH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pop_eth = 1;
		} else if (type == OVS_ACTION_ATTR_CT_CLEAR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ct_clear = 1;
		} else if (type == OVS_ACTION_ATTR_PUSH_NSH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.push_nsh = 1;

			parg.rsp_policy = &ovs_flow_ovs_nsh_key_attrs_nest;
			parg.data = &dst->push_nsh;
			if (ovs_flow_ovs_nsh_key_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_ACTION_ATTR_POP_NSH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pop_nsh = 1;
		} else if (type == OVS_ACTION_ATTR_METER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.meter = 1;
			dst->meter = ynl_attr_get_u32(attr);
		} else if (type == OVS_ACTION_ATTR_CLONE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.clone = 1;

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			parg.data = &dst->clone;
			if (ovs_flow_action_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_ACTION_ATTR_CHECK_PKT_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.check_pkt_len = 1;

			parg.rsp_policy = &ovs_flow_check_pkt_len_attrs_nest;
			parg.data = &dst->check_pkt_len;
			if (ovs_flow_check_pkt_len_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_ACTION_ATTR_ADD_MPLS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.add_mpls_len = len;
			dst->add_mpls = malloc(len);
			memcpy(dst->add_mpls, ynl_attr_data(attr), len);
		} else if (type == OVS_ACTION_ATTR_DEC_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dec_ttl = 1;

			parg.rsp_policy = &ovs_flow_dec_ttl_attrs_nest;
			parg.data = &dst->dec_ttl;
			if (ovs_flow_dec_ttl_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

/* ============== OVS_FLOW_CMD_GET ============== */
/* OVS_FLOW_CMD_GET - do */
void ovs_flow_get_req_free(struct ovs_flow_get_req *req)
{
	ovs_flow_key_attrs_free(&req->key);
	free(req->ufid);
	free(req);
}

void ovs_flow_get_rsp_free(struct ovs_flow_get_rsp *rsp)
{
	ovs_flow_key_attrs_free(&rsp->key);
	free(rsp->ufid);
	ovs_flow_key_attrs_free(&rsp->mask);
	free(rsp->stats);
	ovs_flow_action_attrs_free(&rsp->actions);
	free(rsp);
}

int ovs_flow_get_rsp_parse(const struct nlmsghdr *nlh,
			   struct ynl_parse_arg *yarg)
{
	struct ovs_flow_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));
	memcpy(&dst->_hdr, hdr, sizeof(struct ovs_header));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_FLOW_ATTR_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key = 1;

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			parg.data = &dst->key;
			if (ovs_flow_key_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_FLOW_ATTR_UFID) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.ufid_len = len;
			dst->ufid = malloc(len);
			memcpy(dst->ufid, ynl_attr_data(attr), len);
		} else if (type == OVS_FLOW_ATTR_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mask = 1;

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			parg.data = &dst->mask;
			if (ovs_flow_key_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == OVS_FLOW_ATTR_STATS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.stats_len = len;
			dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == OVS_FLOW_ATTR_ACTIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.actions = 1;

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			parg.data = &dst->actions;
			if (ovs_flow_action_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct ovs_flow_get_rsp *
ovs_flow_get(struct ynl_sock *ys, struct ovs_flow_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct ovs_flow_get_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVS_FLOW_CMD_GET, 1);
	ys->req_policy = &ovs_flow_flow_attrs_nest;
	yrs.yarg.rsp_policy = &ovs_flow_flow_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.key)
		ovs_flow_key_attrs_put(nlh, OVS_FLOW_ATTR_KEY, &req->key);
	if (req->_present.ufid_len)
		ynl_attr_put(nlh, OVS_FLOW_ATTR_UFID, req->ufid, req->_present.ufid_len);
	if (req->_present.ufid_flags)
		ynl_attr_put_u32(nlh, OVS_FLOW_ATTR_UFID_FLAGS, req->ufid_flags);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = ovs_flow_get_rsp_parse;
	yrs.rsp_cmd = OVS_FLOW_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	ovs_flow_get_rsp_free(rsp);
	return NULL;
}

/* OVS_FLOW_CMD_GET - dump */
void ovs_flow_get_req_dump_free(struct ovs_flow_get_req_dump *req)
{
	ovs_flow_key_attrs_free(&req->key);
	free(req->ufid);
	free(req);
}

void ovs_flow_get_list_free(struct ovs_flow_get_list *rsp)
{
	struct ovs_flow_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		ovs_flow_key_attrs_free(&rsp->obj.key);
		free(rsp->obj.ufid);
		ovs_flow_key_attrs_free(&rsp->obj.mask);
		free(rsp->obj.stats);
		ovs_flow_action_attrs_free(&rsp->obj.actions);
		free(rsp);
	}
}

struct ovs_flow_get_list *
ovs_flow_get_dump(struct ynl_sock *ys, struct ovs_flow_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ovs_flow_flow_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct ovs_flow_get_list);
	yds.cb = ovs_flow_get_rsp_parse;
	yds.rsp_cmd = OVS_FLOW_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, OVS_FLOW_CMD_GET, 1);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &ovs_flow_flow_attrs_nest;

	if (req->_present.key)
		ovs_flow_key_attrs_put(nlh, OVS_FLOW_ATTR_KEY, &req->key);
	if (req->_present.ufid_len)
		ynl_attr_put(nlh, OVS_FLOW_ATTR_UFID, req->ufid, req->_present.ufid_len);
	if (req->_present.ufid_flags)
		ynl_attr_put_u32(nlh, OVS_FLOW_ATTR_UFID_FLAGS, req->ufid_flags);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	ovs_flow_get_list_free(yds.first);
	return NULL;
}

/* ============== OVS_FLOW_CMD_NEW ============== */
/* OVS_FLOW_CMD_NEW - do */
void ovs_flow_new_req_free(struct ovs_flow_new_req *req)
{
	ovs_flow_key_attrs_free(&req->key);
	free(req->ufid);
	ovs_flow_key_attrs_free(&req->mask);
	ovs_flow_action_attrs_free(&req->actions);
	free(req);
}

int ovs_flow_new(struct ynl_sock *ys, struct ovs_flow_new_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVS_FLOW_CMD_NEW, 1);
	ys->req_policy = &ovs_flow_flow_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.key)
		ovs_flow_key_attrs_put(nlh, OVS_FLOW_ATTR_KEY, &req->key);
	if (req->_present.ufid_len)
		ynl_attr_put(nlh, OVS_FLOW_ATTR_UFID, req->ufid, req->_present.ufid_len);
	if (req->_present.mask)
		ovs_flow_key_attrs_put(nlh, OVS_FLOW_ATTR_MASK, &req->mask);
	if (req->_present.actions)
		ovs_flow_action_attrs_put(nlh, OVS_FLOW_ATTR_ACTIONS, &req->actions);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

const struct ynl_family ynl_ovs_flow_family =  {
	.name		= "ovs_flow",
	.hdr_len	= sizeof(struct genlmsghdr) + sizeof(struct ovs_header),
};
