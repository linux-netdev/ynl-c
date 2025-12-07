// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/psp.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "psp-user.h"
#include "ynl.h"
#include <linux/psp.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const psp_op_strmap[] = {
	[PSP_CMD_DEV_GET] = "dev-get",
	[PSP_CMD_DEV_ADD_NTF] = "dev-add-ntf",
	[PSP_CMD_DEV_DEL_NTF] = "dev-del-ntf",
	[PSP_CMD_DEV_SET] = "dev-set",
	[PSP_CMD_DEV_CHANGE_NTF] = "dev-change-ntf",
	[PSP_CMD_KEY_ROTATE] = "key-rotate",
	[PSP_CMD_KEY_ROTATE_NTF] = "key-rotate-ntf",
	[PSP_CMD_RX_ASSOC] = "rx-assoc",
	[PSP_CMD_TX_ASSOC] = "tx-assoc",
	[PSP_CMD_GET_STATS] = "get-stats",
};

const char *psp_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(psp_op_strmap))
		return NULL;
	return psp_op_strmap[op];
}

static const char * const psp_version_strmap[] = {
	[0] = "hdr0-aes-gcm-128",
	[1] = "hdr0-aes-gcm-256",
	[2] = "hdr0-aes-gmac-128",
	[3] = "hdr0-aes-gmac-256",
};

const char *psp_version_str(enum psp_version value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(psp_version_strmap))
		return NULL;
	return psp_version_strmap[value];
}

/* Policies */
const struct ynl_policy_attr psp_keys_policy[PSP_A_KEYS_MAX + 1] = {
	[PSP_A_KEYS_KEY] = { .name = "key", .type = YNL_PT_BINARY,},
	[PSP_A_KEYS_SPI] = { .name = "spi", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest psp_keys_nest = {
	.max_attr = PSP_A_KEYS_MAX,
	.table = psp_keys_policy,
};

const struct ynl_policy_attr psp_dev_policy[PSP_A_DEV_MAX + 1] = {
	[PSP_A_DEV_ID] = { .name = "id", .type = YNL_PT_U32, },
	[PSP_A_DEV_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[PSP_A_DEV_PSP_VERSIONS_CAP] = { .name = "psp-versions-cap", .type = YNL_PT_U32, },
	[PSP_A_DEV_PSP_VERSIONS_ENA] = { .name = "psp-versions-ena", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest psp_dev_nest = {
	.max_attr = PSP_A_DEV_MAX,
	.table = psp_dev_policy,
};

const struct ynl_policy_attr psp_assoc_policy[PSP_A_ASSOC_MAX + 1] = {
	[PSP_A_ASSOC_DEV_ID] = { .name = "dev-id", .type = YNL_PT_U32, },
	[PSP_A_ASSOC_VERSION] = { .name = "version", .type = YNL_PT_U32, },
	[PSP_A_ASSOC_RX_KEY] = { .name = "rx-key", .type = YNL_PT_NEST, .nest = &psp_keys_nest, },
	[PSP_A_ASSOC_TX_KEY] = { .name = "tx-key", .type = YNL_PT_NEST, .nest = &psp_keys_nest, },
	[PSP_A_ASSOC_SOCK_FD] = { .name = "sock-fd", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest psp_assoc_nest = {
	.max_attr = PSP_A_ASSOC_MAX,
	.table = psp_assoc_policy,
};

const struct ynl_policy_attr psp_stats_policy[PSP_A_STATS_MAX + 1] = {
	[PSP_A_STATS_DEV_ID] = { .name = "dev-id", .type = YNL_PT_U32, },
	[PSP_A_STATS_KEY_ROTATIONS] = { .name = "key-rotations", .type = YNL_PT_UINT, },
	[PSP_A_STATS_STALE_EVENTS] = { .name = "stale-events", .type = YNL_PT_UINT, },
	[PSP_A_STATS_RX_PACKETS] = { .name = "rx-packets", .type = YNL_PT_UINT, },
	[PSP_A_STATS_RX_BYTES] = { .name = "rx-bytes", .type = YNL_PT_UINT, },
	[PSP_A_STATS_RX_AUTH_FAIL] = { .name = "rx-auth-fail", .type = YNL_PT_UINT, },
	[PSP_A_STATS_RX_ERROR] = { .name = "rx-error", .type = YNL_PT_UINT, },
	[PSP_A_STATS_RX_BAD] = { .name = "rx-bad", .type = YNL_PT_UINT, },
	[PSP_A_STATS_TX_PACKETS] = { .name = "tx-packets", .type = YNL_PT_UINT, },
	[PSP_A_STATS_TX_BYTES] = { .name = "tx-bytes", .type = YNL_PT_UINT, },
	[PSP_A_STATS_TX_ERROR] = { .name = "tx-error", .type = YNL_PT_UINT, },
};

const struct ynl_policy_nest psp_stats_nest = {
	.max_attr = PSP_A_STATS_MAX,
	.table = psp_stats_policy,
};

/* Common nested types */
void psp_keys_free(struct psp_keys *obj)
{
	free(obj->key);
}

int psp_keys_put(struct nlmsghdr *nlh, unsigned int attr_type,
		 struct psp_keys *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.key)
		ynl_attr_put(nlh, PSP_A_KEYS_KEY, obj->key, obj->_len.key);
	if (obj->_present.spi)
		ynl_attr_put_u32(nlh, PSP_A_KEYS_SPI, obj->spi);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int psp_keys_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct psp_keys *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_KEYS_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key = len;
			dst->key = malloc(len);
			memcpy(dst->key, ynl_attr_data(attr), len);
		} else if (type == PSP_A_KEYS_SPI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.spi = 1;
			dst->spi = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

/* ============== PSP_CMD_DEV_GET ============== */
/* PSP_CMD_DEV_GET - do */
void psp_dev_get_req_free(struct psp_dev_get_req *req)
{
	free(req);
}

void psp_dev_get_rsp_free(struct psp_dev_get_rsp *rsp)
{
	free(rsp);
}

int psp_dev_get_rsp_parse(const struct nlmsghdr *nlh,
			  struct ynl_parse_arg *yarg)
{
	struct psp_dev_get_rsp *dst;
	const struct nlattr *attr;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_DEV_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u32(attr);
		} else if (type == PSP_A_DEV_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == PSP_A_DEV_PSP_VERSIONS_CAP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.psp_versions_cap = 1;
			dst->psp_versions_cap = ynl_attr_get_u32(attr);
		} else if (type == PSP_A_DEV_PSP_VERSIONS_ENA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.psp_versions_ena = 1;
			dst->psp_versions_ena = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct psp_dev_get_rsp *
psp_dev_get(struct ynl_sock *ys, struct psp_dev_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct psp_dev_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, PSP_CMD_DEV_GET, 1);
	ys->req_policy = &psp_dev_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &psp_dev_nest;

	if (req->_present.id)
		ynl_attr_put_u32(nlh, PSP_A_DEV_ID, req->id);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = psp_dev_get_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_DEV_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	psp_dev_get_rsp_free(rsp);
	return NULL;
}

/* PSP_CMD_DEV_GET - dump */
void psp_dev_get_list_free(struct psp_dev_get_list *rsp)
{
	struct psp_dev_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp);
	}
}

struct psp_dev_get_list *psp_dev_get_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &psp_dev_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct psp_dev_get_list);
	yds.cb = psp_dev_get_rsp_parse;
	yds.rsp_cmd = PSP_CMD_DEV_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, PSP_CMD_DEV_GET, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	psp_dev_get_list_free(yds.first);
	return NULL;
}

/* PSP_CMD_DEV_GET - notify */
void psp_dev_get_ntf_free(struct psp_dev_get_ntf *rsp)
{
	free(rsp);
}

/* ============== PSP_CMD_DEV_SET ============== */
/* PSP_CMD_DEV_SET - do */
void psp_dev_set_req_free(struct psp_dev_set_req *req)
{
	free(req);
}

void psp_dev_set_rsp_free(struct psp_dev_set_rsp *rsp)
{
	free(rsp);
}

int psp_dev_set_rsp_parse(const struct nlmsghdr *nlh,
			  struct ynl_parse_arg *yarg)
{
	return YNL_PARSE_CB_OK;
}

struct psp_dev_set_rsp *
psp_dev_set(struct ynl_sock *ys, struct psp_dev_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct psp_dev_set_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, PSP_CMD_DEV_SET, 1);
	ys->req_policy = &psp_dev_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &psp_dev_nest;

	if (req->_present.id)
		ynl_attr_put_u32(nlh, PSP_A_DEV_ID, req->id);
	if (req->_present.psp_versions_ena)
		ynl_attr_put_u32(nlh, PSP_A_DEV_PSP_VERSIONS_ENA, req->psp_versions_ena);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = psp_dev_set_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_DEV_SET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	psp_dev_set_rsp_free(rsp);
	return NULL;
}

/* ============== PSP_CMD_KEY_ROTATE ============== */
/* PSP_CMD_KEY_ROTATE - do */
void psp_key_rotate_req_free(struct psp_key_rotate_req *req)
{
	free(req);
}

void psp_key_rotate_rsp_free(struct psp_key_rotate_rsp *rsp)
{
	free(rsp);
}

int psp_key_rotate_rsp_parse(const struct nlmsghdr *nlh,
			     struct ynl_parse_arg *yarg)
{
	struct psp_key_rotate_rsp *dst;
	const struct nlattr *attr;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_DEV_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct psp_key_rotate_rsp *
psp_key_rotate(struct ynl_sock *ys, struct psp_key_rotate_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct psp_key_rotate_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, PSP_CMD_KEY_ROTATE, 1);
	ys->req_policy = &psp_dev_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &psp_dev_nest;

	if (req->_present.id)
		ynl_attr_put_u32(nlh, PSP_A_DEV_ID, req->id);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = psp_key_rotate_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_KEY_ROTATE;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	psp_key_rotate_rsp_free(rsp);
	return NULL;
}

/* PSP_CMD_KEY_ROTATE - notify */
void psp_key_rotate_ntf_free(struct psp_key_rotate_ntf *rsp)
{
	free(rsp);
}

/* ============== PSP_CMD_RX_ASSOC ============== */
/* PSP_CMD_RX_ASSOC - do */
void psp_rx_assoc_req_free(struct psp_rx_assoc_req *req)
{
	free(req);
}

void psp_rx_assoc_rsp_free(struct psp_rx_assoc_rsp *rsp)
{
	psp_keys_free(&rsp->rx_key);
	free(rsp);
}

int psp_rx_assoc_rsp_parse(const struct nlmsghdr *nlh,
			   struct ynl_parse_arg *yarg)
{
	struct psp_rx_assoc_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_ASSOC_DEV_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dev_id = 1;
			dst->dev_id = ynl_attr_get_u32(attr);
		} else if (type == PSP_A_ASSOC_RX_KEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rx_key = 1;

			parg.rsp_policy = &psp_keys_nest;
			parg.data = &dst->rx_key;
			if (psp_keys_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct psp_rx_assoc_rsp *
psp_rx_assoc(struct ynl_sock *ys, struct psp_rx_assoc_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct psp_rx_assoc_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, PSP_CMD_RX_ASSOC, 1);
	ys->req_policy = &psp_assoc_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &psp_assoc_nest;

	if (req->_present.dev_id)
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_DEV_ID, req->dev_id);
	if (req->_present.version)
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_VERSION, req->version);
	if (req->_present.sock_fd)
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_SOCK_FD, req->sock_fd);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = psp_rx_assoc_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_RX_ASSOC;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	psp_rx_assoc_rsp_free(rsp);
	return NULL;
}

/* ============== PSP_CMD_TX_ASSOC ============== */
/* PSP_CMD_TX_ASSOC - do */
void psp_tx_assoc_req_free(struct psp_tx_assoc_req *req)
{
	psp_keys_free(&req->tx_key);
	free(req);
}

void psp_tx_assoc_rsp_free(struct psp_tx_assoc_rsp *rsp)
{
	free(rsp);
}

int psp_tx_assoc_rsp_parse(const struct nlmsghdr *nlh,
			   struct ynl_parse_arg *yarg)
{
	return YNL_PARSE_CB_OK;
}

struct psp_tx_assoc_rsp *
psp_tx_assoc(struct ynl_sock *ys, struct psp_tx_assoc_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct psp_tx_assoc_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, PSP_CMD_TX_ASSOC, 1);
	ys->req_policy = &psp_assoc_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &psp_assoc_nest;

	if (req->_present.dev_id)
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_DEV_ID, req->dev_id);
	if (req->_present.version)
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_VERSION, req->version);
	if (req->_present.tx_key)
		psp_keys_put(nlh, PSP_A_ASSOC_TX_KEY, &req->tx_key);
	if (req->_present.sock_fd)
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_SOCK_FD, req->sock_fd);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = psp_tx_assoc_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_TX_ASSOC;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	psp_tx_assoc_rsp_free(rsp);
	return NULL;
}

/* ============== PSP_CMD_GET_STATS ============== */
/* PSP_CMD_GET_STATS - do */
void psp_get_stats_req_free(struct psp_get_stats_req *req)
{
	free(req);
}

void psp_get_stats_rsp_free(struct psp_get_stats_rsp *rsp)
{
	free(rsp);
}

int psp_get_stats_rsp_parse(const struct nlmsghdr *nlh,
			    struct ynl_parse_arg *yarg)
{
	struct psp_get_stats_rsp *dst;
	const struct nlattr *attr;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_STATS_DEV_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dev_id = 1;
			dst->dev_id = ynl_attr_get_u32(attr);
		} else if (type == PSP_A_STATS_KEY_ROTATIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_rotations = 1;
			dst->key_rotations = ynl_attr_get_uint(attr);
		} else if (type == PSP_A_STATS_STALE_EVENTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stale_events = 1;
			dst->stale_events = ynl_attr_get_uint(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct psp_get_stats_rsp *
psp_get_stats(struct ynl_sock *ys, struct psp_get_stats_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct psp_get_stats_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, PSP_CMD_GET_STATS, 1);
	ys->req_policy = &psp_stats_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &psp_stats_nest;

	if (req->_present.dev_id)
		ynl_attr_put_u32(nlh, PSP_A_STATS_DEV_ID, req->dev_id);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = psp_get_stats_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_GET_STATS;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	psp_get_stats_rsp_free(rsp);
	return NULL;
}

/* PSP_CMD_GET_STATS - dump */
void psp_get_stats_list_free(struct psp_get_stats_list *rsp)
{
	struct psp_get_stats_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp);
	}
}

struct psp_get_stats_list *psp_get_stats_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &psp_stats_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct psp_get_stats_list);
	yds.cb = psp_get_stats_rsp_parse;
	yds.rsp_cmd = PSP_CMD_GET_STATS;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, PSP_CMD_GET_STATS, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	psp_get_stats_list_free(yds.first);
	return NULL;
}

static const struct ynl_ntf_info psp_ntf_info[] =  {
	[PSP_CMD_DEV_ADD_NTF] =  {
		.alloc_sz	= sizeof(struct psp_dev_get_ntf),
		.cb		= psp_dev_get_rsp_parse,
		.policy		= &psp_dev_nest,
		.free		= (void *)psp_dev_get_ntf_free,
	},
	[PSP_CMD_DEV_DEL_NTF] =  {
		.alloc_sz	= sizeof(struct psp_dev_get_ntf),
		.cb		= psp_dev_get_rsp_parse,
		.policy		= &psp_dev_nest,
		.free		= (void *)psp_dev_get_ntf_free,
	},
	[PSP_CMD_DEV_CHANGE_NTF] =  {
		.alloc_sz	= sizeof(struct psp_dev_get_ntf),
		.cb		= psp_dev_get_rsp_parse,
		.policy		= &psp_dev_nest,
		.free		= (void *)psp_dev_get_ntf_free,
	},
	[PSP_CMD_KEY_ROTATE_NTF] =  {
		.alloc_sz	= sizeof(struct psp_key_rotate_ntf),
		.cb		= psp_key_rotate_rsp_parse,
		.policy		= &psp_dev_nest,
		.free		= (void *)psp_key_rotate_ntf_free,
	},
};

const struct ynl_family ynl_psp_family =  {
	.name		= "psp",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= psp_ntf_info,
	.ntf_info_size	= YNL_ARRAY_SIZE(psp_ntf_info),
};
