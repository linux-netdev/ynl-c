// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/wireguard.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "wireguard-user.h"
#include "ynl.h"
#include <linux/time_types.h>
#include <linux/wireguard.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const wireguard_op_strmap[] = {
	[WG_CMD_SET_DEVICE] = "set-device",
};

const char *wireguard_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(wireguard_op_strmap))
		return NULL;
	return wireguard_op_strmap[op];
}

static const char * const wireguard_wgdevice_flags_strmap[] = {
	[0] = "replace-peers",
};

const char *wireguard_wgdevice_flags_str(enum wgdevice_flag value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(wireguard_wgdevice_flags_strmap))
		return NULL;
	return wireguard_wgdevice_flags_strmap[value];
}

static const char * const wireguard_wgpeer_flags_strmap[] = {
	[0] = "remove-me",
	[1] = "replace-allowedips",
	[2] = "update-only",
};

const char *wireguard_wgpeer_flags_str(enum wgpeer_flag value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(wireguard_wgpeer_flags_strmap))
		return NULL;
	return wireguard_wgpeer_flags_strmap[value];
}

static const char * const wireguard_wgallowedip_flags_strmap[] = {
	[0] = "remove-me",
};

const char *wireguard_wgallowedip_flags_str(enum wgallowedip_flag value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(wireguard_wgallowedip_flags_strmap))
		return NULL;
	return wireguard_wgallowedip_flags_strmap[value];
}

/* Policies */
const struct ynl_policy_attr wireguard_wgallowedip_policy[WGALLOWEDIP_A_MAX + 1] = {
	[WGALLOWEDIP_A_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[WGALLOWEDIP_A_FAMILY] = { .name = "family", .type = YNL_PT_U16, },
	[WGALLOWEDIP_A_IPADDR] = { .name = "ipaddr", .type = YNL_PT_BINARY,},
	[WGALLOWEDIP_A_CIDR_MASK] = { .name = "cidr-mask", .type = YNL_PT_U8, },
	[WGALLOWEDIP_A_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest wireguard_wgallowedip_nest = {
	.max_attr = WGALLOWEDIP_A_MAX,
	.table = wireguard_wgallowedip_policy,
};

const struct ynl_policy_attr wireguard_wgpeer_policy[WGPEER_A_MAX + 1] = {
	[WGPEER_A_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[WGPEER_A_PUBLIC_KEY] = { .name = "public-key", .type = YNL_PT_BINARY,},
	[WGPEER_A_PRESHARED_KEY] = { .name = "preshared-key", .type = YNL_PT_BINARY,},
	[WGPEER_A_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[WGPEER_A_ENDPOINT] = { .name = "endpoint", .type = YNL_PT_BINARY,},
	[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL] = { .name = "persistent-keepalive-interval", .type = YNL_PT_U16, },
	[WGPEER_A_LAST_HANDSHAKE_TIME] = { .name = "last-handshake-time", .type = YNL_PT_BINARY,},
	[WGPEER_A_RX_BYTES] = { .name = "rx-bytes", .type = YNL_PT_U64, },
	[WGPEER_A_TX_BYTES] = { .name = "tx-bytes", .type = YNL_PT_U64, },
	[WGPEER_A_ALLOWEDIPS] = { .name = "allowedips", .type = YNL_PT_NEST, .nest = &wireguard_wgallowedip_nest, },
	[WGPEER_A_PROTOCOL_VERSION] = { .name = "protocol-version", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest wireguard_wgpeer_nest = {
	.max_attr = WGPEER_A_MAX,
	.table = wireguard_wgpeer_policy,
};

const struct ynl_policy_attr wireguard_wgdevice_policy[WGDEVICE_A_MAX + 1] = {
	[WGDEVICE_A_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[WGDEVICE_A_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[WGDEVICE_A_IFNAME] = { .name = "ifname", .type = YNL_PT_NUL_STR, },
	[WGDEVICE_A_PRIVATE_KEY] = { .name = "private-key", .type = YNL_PT_BINARY,},
	[WGDEVICE_A_PUBLIC_KEY] = { .name = "public-key", .type = YNL_PT_BINARY,},
	[WGDEVICE_A_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[WGDEVICE_A_LISTEN_PORT] = { .name = "listen-port", .type = YNL_PT_U16, },
	[WGDEVICE_A_FWMARK] = { .name = "fwmark", .type = YNL_PT_U32, },
	[WGDEVICE_A_PEERS] = { .name = "peers", .type = YNL_PT_NEST, .nest = &wireguard_wgpeer_nest, },
};

const struct ynl_policy_nest wireguard_wgdevice_nest = {
	.max_attr = WGDEVICE_A_MAX,
	.table = wireguard_wgdevice_policy,
};

/* Common nested types */
void wireguard_wgallowedip_free(struct wireguard_wgallowedip *obj)
{
	free(obj->ipaddr);
}

int wireguard_wgallowedip_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct wireguard_wgallowedip *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.family)
		ynl_attr_put_u16(nlh, WGALLOWEDIP_A_FAMILY, obj->family);
	if (obj->_len.ipaddr)
		ynl_attr_put(nlh, WGALLOWEDIP_A_IPADDR, obj->ipaddr, obj->_len.ipaddr);
	if (obj->_present.cidr_mask)
		ynl_attr_put_u8(nlh, WGALLOWEDIP_A_CIDR_MASK, obj->cidr_mask);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, WGALLOWEDIP_A_FLAGS, obj->flags);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int wireguard_wgallowedip_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested, __u32 idx)
{
	struct wireguard_wgallowedip *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == WGALLOWEDIP_A_FAMILY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.family = 1;
			dst->family = ynl_attr_get_u16(attr);
		} else if (type == WGALLOWEDIP_A_IPADDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ipaddr = len;
			dst->ipaddr = malloc(len);
			memcpy(dst->ipaddr, ynl_attr_data(attr), len);
		} else if (type == WGALLOWEDIP_A_CIDR_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cidr_mask = 1;
			dst->cidr_mask = ynl_attr_get_u8(attr);
		} else if (type == WGALLOWEDIP_A_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void wireguard_wgpeer_free(struct wireguard_wgpeer *obj)
{
	unsigned int i;

	free(obj->public_key);
	free(obj->preshared_key);
	free(obj->endpoint);
	free(obj->last_handshake_time);
	for (i = 0; i < obj->_count.allowedips; i++)
		wireguard_wgallowedip_free(&obj->allowedips[i]);
	free(obj->allowedips);
}

int wireguard_wgpeer_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct wireguard_wgpeer *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.public_key)
		ynl_attr_put(nlh, WGPEER_A_PUBLIC_KEY, obj->public_key, obj->_len.public_key);
	if (obj->_len.preshared_key)
		ynl_attr_put(nlh, WGPEER_A_PRESHARED_KEY, obj->preshared_key, obj->_len.preshared_key);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, WGPEER_A_FLAGS, obj->flags);
	if (obj->_len.endpoint)
		ynl_attr_put(nlh, WGPEER_A_ENDPOINT, obj->endpoint, obj->_len.endpoint);
	if (obj->_present.persistent_keepalive_interval)
		ynl_attr_put_u16(nlh, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, obj->persistent_keepalive_interval);
	if (obj->_len.last_handshake_time)
		ynl_attr_put(nlh, WGPEER_A_LAST_HANDSHAKE_TIME, obj->last_handshake_time, obj->_len.last_handshake_time);
	if (obj->_present.rx_bytes)
		ynl_attr_put_u64(nlh, WGPEER_A_RX_BYTES, obj->rx_bytes);
	if (obj->_present.tx_bytes)
		ynl_attr_put_u64(nlh, WGPEER_A_TX_BYTES, obj->tx_bytes);
	array = ynl_attr_nest_start(nlh, WGPEER_A_ALLOWEDIPS);
	for (i = 0; i < obj->_count.allowedips; i++)
		wireguard_wgallowedip_put(nlh, i, &obj->allowedips[i]);
	ynl_attr_nest_end(nlh, array);
	if (obj->_present.protocol_version)
		ynl_attr_put_u32(nlh, WGPEER_A_PROTOCOL_VERSION, obj->protocol_version);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int wireguard_wgpeer_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested, __u32 idx)
{
	const struct nlattr *attr_allowedips = NULL;
	struct wireguard_wgpeer *dst = yarg->data;
	unsigned int n_allowedips = 0;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	dst->idx = idx;
	if (dst->allowedips)
		return ynl_error_parse(yarg, "attribute already present (wgpeer.allowedips)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == WGPEER_A_PUBLIC_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.public_key = len;
			dst->public_key = malloc(len);
			memcpy(dst->public_key, ynl_attr_data(attr), len);
		} else if (type == WGPEER_A_PRESHARED_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.preshared_key = len;
			dst->preshared_key = malloc(len);
			memcpy(dst->preshared_key, ynl_attr_data(attr), len);
		} else if (type == WGPEER_A_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == WGPEER_A_ENDPOINT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.endpoint = len;
			dst->endpoint = malloc(len);
			memcpy(dst->endpoint, ynl_attr_data(attr), len);
		} else if (type == WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.persistent_keepalive_interval = 1;
			dst->persistent_keepalive_interval = ynl_attr_get_u16(attr);
		} else if (type == WGPEER_A_LAST_HANDSHAKE_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.last_handshake_time = len;
			if (len < sizeof(struct __kernel_timespec))
				dst->last_handshake_time = calloc(1, sizeof(struct __kernel_timespec));
			else
				dst->last_handshake_time = malloc(len);
			memcpy(dst->last_handshake_time, ynl_attr_data(attr), len);
		} else if (type == WGPEER_A_RX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rx_bytes = 1;
			dst->rx_bytes = ynl_attr_get_u64(attr);
		} else if (type == WGPEER_A_TX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tx_bytes = 1;
			dst->tx_bytes = ynl_attr_get_u64(attr);
		} else if (type == WGPEER_A_ALLOWEDIPS) {
			attr_allowedips = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_allowedips++;
			}
		} else if (type == WGPEER_A_PROTOCOL_VERSION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.protocol_version = 1;
			dst->protocol_version = ynl_attr_get_u32(attr);
		}
	}

	if (n_allowedips) {
		dst->allowedips = calloc(n_allowedips, sizeof(*dst->allowedips));
		dst->_count.allowedips = n_allowedips;
		i = 0;
		parg.rsp_policy = &wireguard_wgallowedip_nest;
		ynl_attr_for_each_nested(attr, attr_allowedips) {
			parg.data = &dst->allowedips[i];
			if (wireguard_wgallowedip_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

/* ============== WG_CMD_GET_DEVICE ============== */
/* WG_CMD_GET_DEVICE - dump */
int wireguard_get_device_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr_peers = NULL;
	struct wireguard_get_device_rsp *dst;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_peers = 0;
	unsigned int len;
	int i;

	dst = yarg->data;
	parg.ys = yarg->ys;

	if (dst->peers)
		return ynl_error_parse(yarg, "attribute already present (wgdevice.peers)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == WGDEVICE_A_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == WGDEVICE_A_IFNAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.ifname = len;
			dst->ifname = malloc(len + 1);
			memcpy(dst->ifname, ynl_attr_get_str(attr), len);
			dst->ifname[len] = 0;
		} else if (type == WGDEVICE_A_PRIVATE_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.private_key = len;
			dst->private_key = malloc(len);
			memcpy(dst->private_key, ynl_attr_data(attr), len);
		} else if (type == WGDEVICE_A_PUBLIC_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.public_key = len;
			dst->public_key = malloc(len);
			memcpy(dst->public_key, ynl_attr_data(attr), len);
		} else if (type == WGDEVICE_A_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == WGDEVICE_A_LISTEN_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.listen_port = 1;
			dst->listen_port = ynl_attr_get_u16(attr);
		} else if (type == WGDEVICE_A_FWMARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmark = 1;
			dst->fwmark = ynl_attr_get_u32(attr);
		} else if (type == WGDEVICE_A_PEERS) {
			attr_peers = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_peers++;
			}
		}
	}

	if (n_peers) {
		dst->peers = calloc(n_peers, sizeof(*dst->peers));
		dst->_count.peers = n_peers;
		i = 0;
		parg.rsp_policy = &wireguard_wgpeer_nest;
		ynl_attr_for_each_nested(attr, attr_peers) {
			parg.data = &dst->peers[i];
			if (wireguard_wgpeer_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return YNL_PARSE_CB_OK;
}

void wireguard_get_device_req_free(struct wireguard_get_device_req *req)
{
	free(req->ifname);
	free(req);
}

void wireguard_get_device_list_free(struct wireguard_get_device_list *rsp)
{
	struct wireguard_get_device_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		unsigned int i;

		rsp = next;
		next = rsp->next;

		free(rsp->obj.ifname);
		free(rsp->obj.private_key);
		free(rsp->obj.public_key);
		for (i = 0; i < rsp->obj._count.peers; i++)
			wireguard_wgpeer_free(&rsp->obj.peers[i]);
		free(rsp->obj.peers);
		free(rsp);
	}
}

struct wireguard_get_device_list *
wireguard_get_device_dump(struct ynl_sock *ys,
			  struct wireguard_get_device_req *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &wireguard_wgdevice_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct wireguard_get_device_list);
	yds.cb = wireguard_get_device_rsp_parse;
	yds.rsp_cmd = WG_CMD_GET_DEVICE;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, WG_CMD_GET_DEVICE, 1);
	ys->req_policy = &wireguard_wgdevice_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, WGDEVICE_A_IFINDEX, req->ifindex);
	if (req->_len.ifname)
		ynl_attr_put_str(nlh, WGDEVICE_A_IFNAME, req->ifname);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	wireguard_get_device_list_free(yds.first);
	return NULL;
}

/* ============== WG_CMD_SET_DEVICE ============== */
/* WG_CMD_SET_DEVICE - do */
void wireguard_set_device_req_free(struct wireguard_set_device_req *req)
{
	unsigned int i;

	free(req->ifname);
	free(req->private_key);
	free(req->public_key);
	for (i = 0; i < req->_count.peers; i++)
		wireguard_wgpeer_free(&req->peers[i]);
	free(req->peers);
	free(req);
}

int wireguard_set_device(struct ynl_sock *ys,
			 struct wireguard_set_device_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	struct nlattr *array;
	unsigned int i;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, WG_CMD_SET_DEVICE, 1);
	ys->req_policy = &wireguard_wgdevice_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, WGDEVICE_A_IFINDEX, req->ifindex);
	if (req->_len.ifname)
		ynl_attr_put_str(nlh, WGDEVICE_A_IFNAME, req->ifname);
	if (req->_len.private_key)
		ynl_attr_put(nlh, WGDEVICE_A_PRIVATE_KEY, req->private_key, req->_len.private_key);
	if (req->_len.public_key)
		ynl_attr_put(nlh, WGDEVICE_A_PUBLIC_KEY, req->public_key, req->_len.public_key);
	if (req->_present.flags)
		ynl_attr_put_u32(nlh, WGDEVICE_A_FLAGS, req->flags);
	if (req->_present.listen_port)
		ynl_attr_put_u16(nlh, WGDEVICE_A_LISTEN_PORT, req->listen_port);
	if (req->_present.fwmark)
		ynl_attr_put_u32(nlh, WGDEVICE_A_FWMARK, req->fwmark);
	array = ynl_attr_nest_start(nlh, WGDEVICE_A_PEERS);
	for (i = 0; i < req->_count.peers; i++)
		wireguard_wgpeer_put(nlh, i, &req->peers[i]);
	ynl_attr_nest_end(nlh, array);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

const struct ynl_family ynl_wireguard_family =  {
	.name		= "wireguard",
	.hdr_len	= sizeof(struct genlmsghdr),
};
