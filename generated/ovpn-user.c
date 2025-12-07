// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/ovpn.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "ovpn-user.h"
#include "ynl.h"
#include <linux/ovpn.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const ovpn_op_strmap[] = {
	[OVPN_CMD_PEER_NEW] = "peer-new",
	[OVPN_CMD_PEER_SET] = "peer-set",
	[OVPN_CMD_PEER_GET] = "peer-get",
	[OVPN_CMD_PEER_DEL] = "peer-del",
	[OVPN_CMD_PEER_DEL_NTF] = "peer-del-ntf",
	[OVPN_CMD_KEY_NEW] = "key-new",
	[OVPN_CMD_KEY_GET] = "key-get",
	[OVPN_CMD_KEY_SWAP] = "key-swap",
	[OVPN_CMD_KEY_SWAP_NTF] = "key-swap-ntf",
	[OVPN_CMD_KEY_DEL] = "key-del",
};

const char *ovpn_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(ovpn_op_strmap))
		return NULL;
	return ovpn_op_strmap[op];
}

static const char * const ovpn_cipher_alg_strmap[] = {
	[0] = "none",
	[1] = "aes-gcm",
	[2] = "chacha20-poly1305",
};

const char *ovpn_cipher_alg_str(enum ovpn_cipher_alg value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(ovpn_cipher_alg_strmap))
		return NULL;
	return ovpn_cipher_alg_strmap[value];
}

static const char * const ovpn_del_peer_reason_strmap[] = {
	[0] = "teardown",
	[1] = "userspace",
	[2] = "expired",
	[3] = "transport-error",
	[4] = "transport-disconnect",
};

const char *ovpn_del_peer_reason_str(enum ovpn_del_peer_reason value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(ovpn_del_peer_reason_strmap))
		return NULL;
	return ovpn_del_peer_reason_strmap[value];
}

static const char * const ovpn_key_slot_strmap[] = {
	[0] = "primary",
	[1] = "secondary",
};

const char *ovpn_key_slot_str(enum ovpn_key_slot value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(ovpn_key_slot_strmap))
		return NULL;
	return ovpn_key_slot_strmap[value];
}

/* Policies */
const struct ynl_policy_attr ovpn_peer_new_input_policy[OVPN_A_PEER_MAX + 1] = {
	[OVPN_A_PEER_ID] = { .name = "id", .type = YNL_PT_U32, },
	[OVPN_A_PEER_REMOTE_IPV4] = { .name = "remote-ipv4", .type = YNL_PT_U32, },
	[OVPN_A_PEER_REMOTE_IPV6] = { .name = "remote-ipv6", .type = YNL_PT_BINARY,},
	[OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID] = { .name = "remote-ipv6-scope-id", .type = YNL_PT_U32, },
	[OVPN_A_PEER_REMOTE_PORT] = { .name = "remote-port", .type = YNL_PT_U16, },
	[OVPN_A_PEER_SOCKET] = { .name = "socket", .type = YNL_PT_U32, },
	[OVPN_A_PEER_VPN_IPV4] = { .name = "vpn-ipv4", .type = YNL_PT_U32, },
	[OVPN_A_PEER_VPN_IPV6] = { .name = "vpn-ipv6", .type = YNL_PT_BINARY,},
	[OVPN_A_PEER_LOCAL_IPV4] = { .name = "local-ipv4", .type = YNL_PT_U32, },
	[OVPN_A_PEER_LOCAL_IPV6] = { .name = "local-ipv6", .type = YNL_PT_BINARY,},
	[OVPN_A_PEER_KEEPALIVE_INTERVAL] = { .name = "keepalive-interval", .type = YNL_PT_U32, },
	[OVPN_A_PEER_KEEPALIVE_TIMEOUT] = { .name = "keepalive-timeout", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest ovpn_peer_new_input_nest = {
	.max_attr = OVPN_A_PEER_MAX,
	.table = ovpn_peer_new_input_policy,
};

const struct ynl_policy_attr ovpn_peer_set_input_policy[OVPN_A_PEER_MAX + 1] = {
	[OVPN_A_PEER_ID] = { .name = "id", .type = YNL_PT_U32, },
	[OVPN_A_PEER_REMOTE_IPV4] = { .name = "remote-ipv4", .type = YNL_PT_U32, },
	[OVPN_A_PEER_REMOTE_IPV6] = { .name = "remote-ipv6", .type = YNL_PT_BINARY,},
	[OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID] = { .name = "remote-ipv6-scope-id", .type = YNL_PT_U32, },
	[OVPN_A_PEER_REMOTE_PORT] = { .name = "remote-port", .type = YNL_PT_U16, },
	[OVPN_A_PEER_VPN_IPV4] = { .name = "vpn-ipv4", .type = YNL_PT_U32, },
	[OVPN_A_PEER_VPN_IPV6] = { .name = "vpn-ipv6", .type = YNL_PT_BINARY,},
	[OVPN_A_PEER_LOCAL_IPV4] = { .name = "local-ipv4", .type = YNL_PT_U32, },
	[OVPN_A_PEER_LOCAL_IPV6] = { .name = "local-ipv6", .type = YNL_PT_BINARY,},
	[OVPN_A_PEER_KEEPALIVE_INTERVAL] = { .name = "keepalive-interval", .type = YNL_PT_U32, },
	[OVPN_A_PEER_KEEPALIVE_TIMEOUT] = { .name = "keepalive-timeout", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest ovpn_peer_set_input_nest = {
	.max_attr = OVPN_A_PEER_MAX,
	.table = ovpn_peer_set_input_policy,
};

const struct ynl_policy_attr ovpn_peer_policy[OVPN_A_PEER_MAX + 1] = {
	[OVPN_A_PEER_ID] = { .name = "id", .type = YNL_PT_U32, },
	[OVPN_A_PEER_REMOTE_IPV4] = { .name = "remote-ipv4", .type = YNL_PT_U32, },
	[OVPN_A_PEER_REMOTE_IPV6] = { .name = "remote-ipv6", .type = YNL_PT_BINARY,},
	[OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID] = { .name = "remote-ipv6-scope-id", .type = YNL_PT_U32, },
	[OVPN_A_PEER_REMOTE_PORT] = { .name = "remote-port", .type = YNL_PT_U16, },
	[OVPN_A_PEER_SOCKET] = { .name = "socket", .type = YNL_PT_U32, },
	[OVPN_A_PEER_SOCKET_NETNSID] = { .name = "socket-netnsid", .type = YNL_PT_U32, },
	[OVPN_A_PEER_VPN_IPV4] = { .name = "vpn-ipv4", .type = YNL_PT_U32, },
	[OVPN_A_PEER_VPN_IPV6] = { .name = "vpn-ipv6", .type = YNL_PT_BINARY,},
	[OVPN_A_PEER_LOCAL_IPV4] = { .name = "local-ipv4", .type = YNL_PT_U32, },
	[OVPN_A_PEER_LOCAL_IPV6] = { .name = "local-ipv6", .type = YNL_PT_BINARY,},
	[OVPN_A_PEER_LOCAL_PORT] = { .name = "local-port", .type = YNL_PT_U16, },
	[OVPN_A_PEER_KEEPALIVE_INTERVAL] = { .name = "keepalive-interval", .type = YNL_PT_U32, },
	[OVPN_A_PEER_KEEPALIVE_TIMEOUT] = { .name = "keepalive-timeout", .type = YNL_PT_U32, },
	[OVPN_A_PEER_DEL_REASON] = { .name = "del-reason", .type = YNL_PT_U32, },
	[OVPN_A_PEER_VPN_RX_BYTES] = { .name = "vpn-rx-bytes", .type = YNL_PT_UINT, },
	[OVPN_A_PEER_VPN_TX_BYTES] = { .name = "vpn-tx-bytes", .type = YNL_PT_UINT, },
	[OVPN_A_PEER_VPN_RX_PACKETS] = { .name = "vpn-rx-packets", .type = YNL_PT_UINT, },
	[OVPN_A_PEER_VPN_TX_PACKETS] = { .name = "vpn-tx-packets", .type = YNL_PT_UINT, },
	[OVPN_A_PEER_LINK_RX_BYTES] = { .name = "link-rx-bytes", .type = YNL_PT_UINT, },
	[OVPN_A_PEER_LINK_TX_BYTES] = { .name = "link-tx-bytes", .type = YNL_PT_UINT, },
	[OVPN_A_PEER_LINK_RX_PACKETS] = { .name = "link-rx-packets", .type = YNL_PT_UINT, },
	[OVPN_A_PEER_LINK_TX_PACKETS] = { .name = "link-tx-packets", .type = YNL_PT_UINT, },
};

const struct ynl_policy_nest ovpn_peer_nest = {
	.max_attr = OVPN_A_PEER_MAX,
	.table = ovpn_peer_policy,
};

const struct ynl_policy_attr ovpn_peer_del_input_policy[OVPN_A_PEER_MAX + 1] = {
	[OVPN_A_PEER_ID] = { .name = "id", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest ovpn_peer_del_input_nest = {
	.max_attr = OVPN_A_PEER_MAX,
	.table = ovpn_peer_del_input_policy,
};

const struct ynl_policy_attr ovpn_keyconf_get_policy[OVPN_A_KEYCONF_MAX + 1] = {
	[OVPN_A_KEYCONF_PEER_ID] = { .name = "peer-id", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF_SLOT] = { .name = "slot", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF_KEY_ID] = { .name = "key-id", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF_CIPHER_ALG] = { .name = "cipher-alg", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest ovpn_keyconf_get_nest = {
	.max_attr = OVPN_A_KEYCONF_MAX,
	.table = ovpn_keyconf_get_policy,
};

const struct ynl_policy_attr ovpn_keyconf_swap_input_policy[OVPN_A_KEYCONF_MAX + 1] = {
	[OVPN_A_KEYCONF_PEER_ID] = { .name = "peer-id", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest ovpn_keyconf_swap_input_nest = {
	.max_attr = OVPN_A_KEYCONF_MAX,
	.table = ovpn_keyconf_swap_input_policy,
};

const struct ynl_policy_attr ovpn_keyconf_del_input_policy[OVPN_A_KEYCONF_MAX + 1] = {
	[OVPN_A_KEYCONF_PEER_ID] = { .name = "peer-id", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF_SLOT] = { .name = "slot", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest ovpn_keyconf_del_input_nest = {
	.max_attr = OVPN_A_KEYCONF_MAX,
	.table = ovpn_keyconf_del_input_policy,
};

const struct ynl_policy_attr ovpn_keydir_policy[OVPN_A_KEYDIR_MAX + 1] = {
	[OVPN_A_KEYDIR_CIPHER_KEY] = { .name = "cipher-key", .type = YNL_PT_BINARY,},
	[OVPN_A_KEYDIR_NONCE_TAIL] = { .name = "nonce-tail", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest ovpn_keydir_nest = {
	.max_attr = OVPN_A_KEYDIR_MAX,
	.table = ovpn_keydir_policy,
};

const struct ynl_policy_attr ovpn_keyconf_policy[OVPN_A_KEYCONF_MAX + 1] = {
	[OVPN_A_KEYCONF_PEER_ID] = { .name = "peer-id", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF_SLOT] = { .name = "slot", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF_KEY_ID] = { .name = "key-id", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF_CIPHER_ALG] = { .name = "cipher-alg", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF_ENCRYPT_DIR] = { .name = "encrypt-dir", .type = YNL_PT_NEST, .nest = &ovpn_keydir_nest, },
	[OVPN_A_KEYCONF_DECRYPT_DIR] = { .name = "decrypt-dir", .type = YNL_PT_NEST, .nest = &ovpn_keydir_nest, },
};

const struct ynl_policy_nest ovpn_keyconf_nest = {
	.max_attr = OVPN_A_KEYCONF_MAX,
	.table = ovpn_keyconf_policy,
};

const struct ynl_policy_attr ovpn_ovpn_peer_new_input_policy[OVPN_A_MAX + 1] = {
	[OVPN_A_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[OVPN_A_PEER] = { .name = "peer", .type = YNL_PT_NEST, .nest = &ovpn_peer_new_input_nest, },
};

const struct ynl_policy_nest ovpn_ovpn_peer_new_input_nest = {
	.max_attr = OVPN_A_MAX,
	.table = ovpn_ovpn_peer_new_input_policy,
};

const struct ynl_policy_attr ovpn_ovpn_peer_set_input_policy[OVPN_A_MAX + 1] = {
	[OVPN_A_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[OVPN_A_PEER] = { .name = "peer", .type = YNL_PT_NEST, .nest = &ovpn_peer_set_input_nest, },
};

const struct ynl_policy_nest ovpn_ovpn_peer_set_input_nest = {
	.max_attr = OVPN_A_MAX,
	.table = ovpn_ovpn_peer_set_input_policy,
};

const struct ynl_policy_attr ovpn_policy[OVPN_A_MAX + 1] = {
	[OVPN_A_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[OVPN_A_PEER] = { .name = "peer", .type = YNL_PT_NEST, .nest = &ovpn_peer_nest, },
	[OVPN_A_KEYCONF] = { .name = "keyconf", .type = YNL_PT_NEST, .nest = &ovpn_keyconf_nest, },
};

const struct ynl_policy_nest ovpn_nest = {
	.max_attr = OVPN_A_MAX,
	.table = ovpn_policy,
};

const struct ynl_policy_attr ovpn_ovpn_peer_del_input_policy[OVPN_A_MAX + 1] = {
	[OVPN_A_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[OVPN_A_PEER] = { .name = "peer", .type = YNL_PT_NEST, .nest = &ovpn_peer_del_input_nest, },
};

const struct ynl_policy_nest ovpn_ovpn_peer_del_input_nest = {
	.max_attr = OVPN_A_MAX,
	.table = ovpn_ovpn_peer_del_input_policy,
};

const struct ynl_policy_attr ovpn_ovpn_keyconf_get_policy[OVPN_A_MAX + 1] = {
	[OVPN_A_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF] = { .name = "keyconf", .type = YNL_PT_NEST, .nest = &ovpn_keyconf_get_nest, },
};

const struct ynl_policy_nest ovpn_ovpn_keyconf_get_nest = {
	.max_attr = OVPN_A_MAX,
	.table = ovpn_ovpn_keyconf_get_policy,
};

const struct ynl_policy_attr ovpn_ovpn_keyconf_swap_input_policy[OVPN_A_MAX + 1] = {
	[OVPN_A_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF] = { .name = "keyconf", .type = YNL_PT_NEST, .nest = &ovpn_keyconf_swap_input_nest, },
};

const struct ynl_policy_nest ovpn_ovpn_keyconf_swap_input_nest = {
	.max_attr = OVPN_A_MAX,
	.table = ovpn_ovpn_keyconf_swap_input_policy,
};

const struct ynl_policy_attr ovpn_ovpn_keyconf_del_input_policy[OVPN_A_MAX + 1] = {
	[OVPN_A_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[OVPN_A_KEYCONF] = { .name = "keyconf", .type = YNL_PT_NEST, .nest = &ovpn_keyconf_del_input_nest, },
};

const struct ynl_policy_nest ovpn_ovpn_keyconf_del_input_nest = {
	.max_attr = OVPN_A_MAX,
	.table = ovpn_ovpn_keyconf_del_input_policy,
};

/* Common nested types */
void ovpn_peer_new_input_free(struct ovpn_peer_new_input *obj)
{
	free(obj->remote_ipv6);
	free(obj->vpn_ipv6);
	free(obj->local_ipv6);
}

int ovpn_peer_new_input_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct ovpn_peer_new_input *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.id)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_ID, obj->id);
	if (obj->_present.remote_ipv4)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_REMOTE_IPV4, obj->remote_ipv4);
	if (obj->_len.remote_ipv6)
		ynl_attr_put(nlh, OVPN_A_PEER_REMOTE_IPV6, obj->remote_ipv6, obj->_len.remote_ipv6);
	if (obj->_present.remote_ipv6_scope_id)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID, obj->remote_ipv6_scope_id);
	if (obj->_present.remote_port)
		ynl_attr_put_u16(nlh, OVPN_A_PEER_REMOTE_PORT, obj->remote_port);
	if (obj->_present.socket)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_SOCKET, obj->socket);
	if (obj->_present.vpn_ipv4)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_VPN_IPV4, obj->vpn_ipv4);
	if (obj->_len.vpn_ipv6)
		ynl_attr_put(nlh, OVPN_A_PEER_VPN_IPV6, obj->vpn_ipv6, obj->_len.vpn_ipv6);
	if (obj->_present.local_ipv4)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_LOCAL_IPV4, obj->local_ipv4);
	if (obj->_len.local_ipv6)
		ynl_attr_put(nlh, OVPN_A_PEER_LOCAL_IPV6, obj->local_ipv6, obj->_len.local_ipv6);
	if (obj->_present.keepalive_interval)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_KEEPALIVE_INTERVAL, obj->keepalive_interval);
	if (obj->_present.keepalive_timeout)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_KEEPALIVE_TIMEOUT, obj->keepalive_timeout);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void ovpn_peer_set_input_free(struct ovpn_peer_set_input *obj)
{
	free(obj->remote_ipv6);
	free(obj->vpn_ipv6);
	free(obj->local_ipv6);
}

int ovpn_peer_set_input_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct ovpn_peer_set_input *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.id)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_ID, obj->id);
	if (obj->_present.remote_ipv4)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_REMOTE_IPV4, obj->remote_ipv4);
	if (obj->_len.remote_ipv6)
		ynl_attr_put(nlh, OVPN_A_PEER_REMOTE_IPV6, obj->remote_ipv6, obj->_len.remote_ipv6);
	if (obj->_present.remote_ipv6_scope_id)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID, obj->remote_ipv6_scope_id);
	if (obj->_present.remote_port)
		ynl_attr_put_u16(nlh, OVPN_A_PEER_REMOTE_PORT, obj->remote_port);
	if (obj->_present.vpn_ipv4)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_VPN_IPV4, obj->vpn_ipv4);
	if (obj->_len.vpn_ipv6)
		ynl_attr_put(nlh, OVPN_A_PEER_VPN_IPV6, obj->vpn_ipv6, obj->_len.vpn_ipv6);
	if (obj->_present.local_ipv4)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_LOCAL_IPV4, obj->local_ipv4);
	if (obj->_len.local_ipv6)
		ynl_attr_put(nlh, OVPN_A_PEER_LOCAL_IPV6, obj->local_ipv6, obj->_len.local_ipv6);
	if (obj->_present.keepalive_interval)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_KEEPALIVE_INTERVAL, obj->keepalive_interval);
	if (obj->_present.keepalive_timeout)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_KEEPALIVE_TIMEOUT, obj->keepalive_timeout);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void ovpn_peer_free(struct ovpn_peer *obj)
{
	free(obj->remote_ipv6);
	free(obj->vpn_ipv6);
	free(obj->local_ipv6);
}

int ovpn_peer_put(struct nlmsghdr *nlh, unsigned int attr_type,
		  struct ovpn_peer *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.id)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_ID, obj->id);
	if (obj->_present.remote_ipv4)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_REMOTE_IPV4, obj->remote_ipv4);
	if (obj->_len.remote_ipv6)
		ynl_attr_put(nlh, OVPN_A_PEER_REMOTE_IPV6, obj->remote_ipv6, obj->_len.remote_ipv6);
	if (obj->_present.remote_ipv6_scope_id)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID, obj->remote_ipv6_scope_id);
	if (obj->_present.remote_port)
		ynl_attr_put_u16(nlh, OVPN_A_PEER_REMOTE_PORT, obj->remote_port);
	if (obj->_present.socket)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_SOCKET, obj->socket);
	if (obj->_present.socket_netnsid)
		ynl_attr_put_s32(nlh, OVPN_A_PEER_SOCKET_NETNSID, obj->socket_netnsid);
	if (obj->_present.vpn_ipv4)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_VPN_IPV4, obj->vpn_ipv4);
	if (obj->_len.vpn_ipv6)
		ynl_attr_put(nlh, OVPN_A_PEER_VPN_IPV6, obj->vpn_ipv6, obj->_len.vpn_ipv6);
	if (obj->_present.local_ipv4)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_LOCAL_IPV4, obj->local_ipv4);
	if (obj->_len.local_ipv6)
		ynl_attr_put(nlh, OVPN_A_PEER_LOCAL_IPV6, obj->local_ipv6, obj->_len.local_ipv6);
	if (obj->_present.local_port)
		ynl_attr_put_u16(nlh, OVPN_A_PEER_LOCAL_PORT, obj->local_port);
	if (obj->_present.keepalive_interval)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_KEEPALIVE_INTERVAL, obj->keepalive_interval);
	if (obj->_present.keepalive_timeout)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_KEEPALIVE_TIMEOUT, obj->keepalive_timeout);
	if (obj->_present.del_reason)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_DEL_REASON, obj->del_reason);
	if (obj->_present.vpn_rx_bytes)
		ynl_attr_put_uint(nlh, OVPN_A_PEER_VPN_RX_BYTES, obj->vpn_rx_bytes);
	if (obj->_present.vpn_tx_bytes)
		ynl_attr_put_uint(nlh, OVPN_A_PEER_VPN_TX_BYTES, obj->vpn_tx_bytes);
	if (obj->_present.vpn_rx_packets)
		ynl_attr_put_uint(nlh, OVPN_A_PEER_VPN_RX_PACKETS, obj->vpn_rx_packets);
	if (obj->_present.vpn_tx_packets)
		ynl_attr_put_uint(nlh, OVPN_A_PEER_VPN_TX_PACKETS, obj->vpn_tx_packets);
	if (obj->_present.link_rx_bytes)
		ynl_attr_put_uint(nlh, OVPN_A_PEER_LINK_RX_BYTES, obj->link_rx_bytes);
	if (obj->_present.link_tx_bytes)
		ynl_attr_put_uint(nlh, OVPN_A_PEER_LINK_TX_BYTES, obj->link_tx_bytes);
	if (obj->_present.link_rx_packets)
		ynl_attr_put_uint(nlh, OVPN_A_PEER_LINK_RX_PACKETS, obj->link_rx_packets);
	if (obj->_present.link_tx_packets)
		ynl_attr_put_uint(nlh, OVPN_A_PEER_LINK_TX_PACKETS, obj->link_tx_packets);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovpn_peer_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct ovpn_peer *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVPN_A_PEER_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_REMOTE_IPV4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.remote_ipv4 = 1;
			dst->remote_ipv4 = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_REMOTE_IPV6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.remote_ipv6 = len;
			dst->remote_ipv6 = malloc(len);
			memcpy(dst->remote_ipv6, ynl_attr_data(attr), len);
		} else if (type == OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.remote_ipv6_scope_id = 1;
			dst->remote_ipv6_scope_id = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_REMOTE_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.remote_port = 1;
			dst->remote_port = ynl_attr_get_u16(attr);
		} else if (type == OVPN_A_PEER_SOCKET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.socket = 1;
			dst->socket = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_SOCKET_NETNSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.socket_netnsid = 1;
			dst->socket_netnsid = ynl_attr_get_s32(attr);
		} else if (type == OVPN_A_PEER_VPN_IPV4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vpn_ipv4 = 1;
			dst->vpn_ipv4 = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_VPN_IPV6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.vpn_ipv6 = len;
			dst->vpn_ipv6 = malloc(len);
			memcpy(dst->vpn_ipv6, ynl_attr_data(attr), len);
		} else if (type == OVPN_A_PEER_LOCAL_IPV4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.local_ipv4 = 1;
			dst->local_ipv4 = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_LOCAL_IPV6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.local_ipv6 = len;
			dst->local_ipv6 = malloc(len);
			memcpy(dst->local_ipv6, ynl_attr_data(attr), len);
		} else if (type == OVPN_A_PEER_LOCAL_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.local_port = 1;
			dst->local_port = ynl_attr_get_u16(attr);
		} else if (type == OVPN_A_PEER_KEEPALIVE_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.keepalive_interval = 1;
			dst->keepalive_interval = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_KEEPALIVE_TIMEOUT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.keepalive_timeout = 1;
			dst->keepalive_timeout = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_DEL_REASON) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.del_reason = 1;
			dst->del_reason = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_VPN_RX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vpn_rx_bytes = 1;
			dst->vpn_rx_bytes = ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_VPN_TX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vpn_tx_bytes = 1;
			dst->vpn_tx_bytes = ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_VPN_RX_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vpn_rx_packets = 1;
			dst->vpn_rx_packets = ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_VPN_TX_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vpn_tx_packets = 1;
			dst->vpn_tx_packets = ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_LINK_RX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link_rx_bytes = 1;
			dst->link_rx_bytes = ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_LINK_TX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link_tx_bytes = 1;
			dst->link_tx_bytes = ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_LINK_RX_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link_rx_packets = 1;
			dst->link_rx_packets = ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_LINK_TX_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link_tx_packets = 1;
			dst->link_tx_packets = ynl_attr_get_uint(attr);
		}
	}

	return 0;
}

void ovpn_peer_del_input_free(struct ovpn_peer_del_input *obj)
{
}

int ovpn_peer_del_input_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct ovpn_peer_del_input *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.id)
		ynl_attr_put_u32(nlh, OVPN_A_PEER_ID, obj->id);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void ovpn_keyconf_get_free(struct ovpn_keyconf_get *obj)
{
}

int ovpn_keyconf_get_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct ovpn_keyconf_get *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.peer_id)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_PEER_ID, obj->peer_id);
	if (obj->_present.slot)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_SLOT, obj->slot);
	if (obj->_present.key_id)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_KEY_ID, obj->key_id);
	if (obj->_present.cipher_alg)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_CIPHER_ALG, obj->cipher_alg);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovpn_keyconf_get_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	struct ovpn_keyconf_get *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVPN_A_KEYCONF_PEER_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.peer_id = 1;
			dst->peer_id = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_KEYCONF_SLOT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.slot = 1;
			dst->slot = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_KEYCONF_KEY_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_id = 1;
			dst->key_id = ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_KEYCONF_CIPHER_ALG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cipher_alg = 1;
			dst->cipher_alg = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void ovpn_keyconf_swap_input_free(struct ovpn_keyconf_swap_input *obj)
{
}

int ovpn_keyconf_swap_input_put(struct nlmsghdr *nlh, unsigned int attr_type,
				struct ovpn_keyconf_swap_input *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.peer_id)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_PEER_ID, obj->peer_id);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void ovpn_keyconf_del_input_free(struct ovpn_keyconf_del_input *obj)
{
}

int ovpn_keyconf_del_input_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       struct ovpn_keyconf_del_input *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.peer_id)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_PEER_ID, obj->peer_id);
	if (obj->_present.slot)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_SLOT, obj->slot);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void ovpn_keydir_free(struct ovpn_keydir *obj)
{
	free(obj->cipher_key);
	free(obj->nonce_tail);
}

int ovpn_keydir_put(struct nlmsghdr *nlh, unsigned int attr_type,
		    struct ovpn_keydir *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.cipher_key)
		ynl_attr_put(nlh, OVPN_A_KEYDIR_CIPHER_KEY, obj->cipher_key, obj->_len.cipher_key);
	if (obj->_len.nonce_tail)
		ynl_attr_put(nlh, OVPN_A_KEYDIR_NONCE_TAIL, obj->nonce_tail, obj->_len.nonce_tail);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void ovpn_keyconf_free(struct ovpn_keyconf *obj)
{
	ovpn_keydir_free(&obj->encrypt_dir);
	ovpn_keydir_free(&obj->decrypt_dir);
}

int ovpn_keyconf_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct ovpn_keyconf *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.peer_id)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_PEER_ID, obj->peer_id);
	if (obj->_present.slot)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_SLOT, obj->slot);
	if (obj->_present.key_id)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_KEY_ID, obj->key_id);
	if (obj->_present.cipher_alg)
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_CIPHER_ALG, obj->cipher_alg);
	if (obj->_present.encrypt_dir)
		ovpn_keydir_put(nlh, OVPN_A_KEYCONF_ENCRYPT_DIR, &obj->encrypt_dir);
	if (obj->_present.decrypt_dir)
		ovpn_keydir_put(nlh, OVPN_A_KEYCONF_DECRYPT_DIR, &obj->decrypt_dir);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

/* ============== OVPN_CMD_PEER_NEW ============== */
/* OVPN_CMD_PEER_NEW - do */
void ovpn_peer_new_req_free(struct ovpn_peer_new_req *req)
{
	ovpn_peer_new_input_free(&req->peer);
	free(req);
}

int ovpn_peer_new(struct ynl_sock *ys, struct ovpn_peer_new_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVPN_CMD_PEER_NEW, 1);
	ys->req_policy = &ovpn_ovpn_peer_new_input_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req->ifindex);
	if (req->_present.peer)
		ovpn_peer_new_input_put(nlh, OVPN_A_PEER, &req->peer);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== OVPN_CMD_PEER_SET ============== */
/* OVPN_CMD_PEER_SET - do */
void ovpn_peer_set_req_free(struct ovpn_peer_set_req *req)
{
	ovpn_peer_set_input_free(&req->peer);
	free(req);
}

int ovpn_peer_set(struct ynl_sock *ys, struct ovpn_peer_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVPN_CMD_PEER_SET, 1);
	ys->req_policy = &ovpn_ovpn_peer_set_input_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req->ifindex);
	if (req->_present.peer)
		ovpn_peer_set_input_put(nlh, OVPN_A_PEER, &req->peer);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== OVPN_CMD_PEER_GET ============== */
/* OVPN_CMD_PEER_GET - do */
void ovpn_peer_get_req_free(struct ovpn_peer_get_req *req)
{
	ovpn_peer_free(&req->peer);
	free(req);
}

void ovpn_peer_get_rsp_free(struct ovpn_peer_get_rsp *rsp)
{
	ovpn_peer_free(&rsp->peer);
	free(rsp);
}

int ovpn_peer_get_rsp_parse(const struct nlmsghdr *nlh,
			    struct ynl_parse_arg *yarg)
{
	struct ovpn_peer_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVPN_A_PEER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.peer = 1;

			parg.rsp_policy = &ovpn_peer_nest;
			parg.data = &dst->peer;
			if (ovpn_peer_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct ovpn_peer_get_rsp *
ovpn_peer_get(struct ynl_sock *ys, struct ovpn_peer_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct ovpn_peer_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVPN_CMD_PEER_GET, 1);
	ys->req_policy = &ovpn_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &ovpn_nest;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req->ifindex);
	if (req->_present.peer)
		ovpn_peer_put(nlh, OVPN_A_PEER, &req->peer);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = ovpn_peer_get_rsp_parse;
	yrs.rsp_cmd = OVPN_CMD_PEER_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	ovpn_peer_get_rsp_free(rsp);
	return NULL;
}

/* OVPN_CMD_PEER_GET - dump */
void ovpn_peer_get_req_dump_free(struct ovpn_peer_get_req_dump *req)
{
	free(req);
}

void ovpn_peer_get_list_free(struct ovpn_peer_get_list *rsp)
{
	struct ovpn_peer_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		ovpn_peer_free(&rsp->obj.peer);
		free(rsp);
	}
}

struct ovpn_peer_get_list *
ovpn_peer_get_dump(struct ynl_sock *ys, struct ovpn_peer_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ovpn_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct ovpn_peer_get_list);
	yds.cb = ovpn_peer_get_rsp_parse;
	yds.rsp_cmd = OVPN_CMD_PEER_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, OVPN_CMD_PEER_GET, 1);
	ys->req_policy = &ovpn_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req->ifindex);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	ovpn_peer_get_list_free(yds.first);
	return NULL;
}

/* OVPN_CMD_PEER_GET - notify */
void ovpn_peer_get_ntf_free(struct ovpn_peer_get_ntf *rsp)
{
	ovpn_peer_free(&rsp->obj.peer);
	free(rsp);
}

/* ============== OVPN_CMD_PEER_DEL ============== */
/* OVPN_CMD_PEER_DEL - do */
void ovpn_peer_del_req_free(struct ovpn_peer_del_req *req)
{
	ovpn_peer_del_input_free(&req->peer);
	free(req);
}

int ovpn_peer_del(struct ynl_sock *ys, struct ovpn_peer_del_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVPN_CMD_PEER_DEL, 1);
	ys->req_policy = &ovpn_ovpn_peer_del_input_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req->ifindex);
	if (req->_present.peer)
		ovpn_peer_del_input_put(nlh, OVPN_A_PEER, &req->peer);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== OVPN_CMD_KEY_NEW ============== */
/* OVPN_CMD_KEY_NEW - do */
void ovpn_key_new_req_free(struct ovpn_key_new_req *req)
{
	ovpn_keyconf_free(&req->keyconf);
	free(req);
}

int ovpn_key_new(struct ynl_sock *ys, struct ovpn_key_new_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVPN_CMD_KEY_NEW, 1);
	ys->req_policy = &ovpn_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req->ifindex);
	if (req->_present.keyconf)
		ovpn_keyconf_put(nlh, OVPN_A_KEYCONF, &req->keyconf);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== OVPN_CMD_KEY_GET ============== */
/* OVPN_CMD_KEY_GET - do */
void ovpn_key_get_req_free(struct ovpn_key_get_req *req)
{
	ovpn_keyconf_get_free(&req->keyconf);
	free(req);
}

void ovpn_key_get_rsp_free(struct ovpn_key_get_rsp *rsp)
{
	ovpn_keyconf_get_free(&rsp->keyconf);
	free(rsp);
}

int ovpn_key_get_rsp_parse(const struct nlmsghdr *nlh,
			   struct ynl_parse_arg *yarg)
{
	struct ovpn_key_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVPN_A_KEYCONF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.keyconf = 1;

			parg.rsp_policy = &ovpn_keyconf_get_nest;
			parg.data = &dst->keyconf;
			if (ovpn_keyconf_get_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct ovpn_key_get_rsp *
ovpn_key_get(struct ynl_sock *ys, struct ovpn_key_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct ovpn_key_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVPN_CMD_KEY_GET, 1);
	ys->req_policy = &ovpn_ovpn_keyconf_get_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &ovpn_ovpn_keyconf_get_nest;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req->ifindex);
	if (req->_present.keyconf)
		ovpn_keyconf_get_put(nlh, OVPN_A_KEYCONF, &req->keyconf);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = ovpn_key_get_rsp_parse;
	yrs.rsp_cmd = OVPN_CMD_KEY_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	ovpn_key_get_rsp_free(rsp);
	return NULL;
}

/* OVPN_CMD_KEY_GET - notify */
void ovpn_key_get_ntf_free(struct ovpn_key_get_ntf *rsp)
{
	ovpn_keyconf_get_free(&rsp->obj.keyconf);
	free(rsp);
}

/* ============== OVPN_CMD_KEY_SWAP ============== */
/* OVPN_CMD_KEY_SWAP - do */
void ovpn_key_swap_req_free(struct ovpn_key_swap_req *req)
{
	ovpn_keyconf_swap_input_free(&req->keyconf);
	free(req);
}

int ovpn_key_swap(struct ynl_sock *ys, struct ovpn_key_swap_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVPN_CMD_KEY_SWAP, 1);
	ys->req_policy = &ovpn_ovpn_keyconf_swap_input_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req->ifindex);
	if (req->_present.keyconf)
		ovpn_keyconf_swap_input_put(nlh, OVPN_A_KEYCONF, &req->keyconf);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== OVPN_CMD_KEY_DEL ============== */
/* OVPN_CMD_KEY_DEL - do */
void ovpn_key_del_req_free(struct ovpn_key_del_req *req)
{
	ovpn_keyconf_del_input_free(&req->keyconf);
	free(req);
}

int ovpn_key_del(struct ynl_sock *ys, struct ovpn_key_del_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVPN_CMD_KEY_DEL, 1);
	ys->req_policy = &ovpn_ovpn_keyconf_del_input_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req->ifindex);
	if (req->_present.keyconf)
		ovpn_keyconf_del_input_put(nlh, OVPN_A_KEYCONF, &req->keyconf);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

static const struct ynl_ntf_info ovpn_ntf_info[] =  {
	[OVPN_CMD_PEER_DEL_NTF] =  {
		.alloc_sz	= sizeof(struct ovpn_peer_get_ntf),
		.cb		= ovpn_peer_get_rsp_parse,
		.policy		= &ovpn_nest,
		.free		= (void *)ovpn_peer_get_ntf_free,
	},
	[OVPN_CMD_KEY_SWAP_NTF] =  {
		.alloc_sz	= sizeof(struct ovpn_key_get_ntf),
		.cb		= ovpn_key_get_rsp_parse,
		.policy		= &ovpn_ovpn_keyconf_get_nest,
		.free		= (void *)ovpn_key_get_ntf_free,
	},
};

const struct ynl_family ynl_ovpn_family =  {
	.name		= "ovpn",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= ovpn_ntf_info,
	.ntf_info_size	= YNL_ARRAY_SIZE(ovpn_ntf_info),
};
