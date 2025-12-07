// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/mptcp_pm.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "mptcp_pm-user.h"
#include "ynl.h"
#include <linux/mptcp_pm.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const mptcp_pm_op_strmap[] = {
	[MPTCP_PM_CMD_ADD_ADDR] = "add-addr",
	[MPTCP_PM_CMD_DEL_ADDR] = "del-addr",
	[MPTCP_PM_CMD_GET_ADDR] = "get-addr",
	[MPTCP_PM_CMD_FLUSH_ADDRS] = "flush-addrs",
	[MPTCP_PM_CMD_SET_LIMITS] = "set-limits",
	[MPTCP_PM_CMD_GET_LIMITS] = "get-limits",
	[MPTCP_PM_CMD_SET_FLAGS] = "set-flags",
	[MPTCP_PM_CMD_ANNOUNCE] = "announce",
	[MPTCP_PM_CMD_REMOVE] = "remove",
	[MPTCP_PM_CMD_SUBFLOW_CREATE] = "subflow-create",
	[MPTCP_PM_CMD_SUBFLOW_DESTROY] = "subflow-destroy",
};

const char *mptcp_pm_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(mptcp_pm_op_strmap))
		return NULL;
	return mptcp_pm_op_strmap[op];
}

static const char * const mptcp_pm_event_type_strmap[] = {
	[0] = "unspec",
	[1] = "created",
	[2] = "established",
	[3] = "closed",
	[6] = "announced",
	[7] = "removed",
	[10] = "sub-established",
	[11] = "sub-closed",
	[13] = "sub-priority",
	[15] = "listener-created",
	[16] = "listener-closed",
};

const char *mptcp_pm_event_type_str(enum mptcp_event_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(mptcp_pm_event_type_strmap))
		return NULL;
	return mptcp_pm_event_type_strmap[value];
}

/* Policies */
const struct ynl_policy_attr mptcp_pm_address_policy[MPTCP_PM_ADDR_ATTR_MAX + 1] = {
	[MPTCP_PM_ADDR_ATTR_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[MPTCP_PM_ADDR_ATTR_FAMILY] = { .name = "family", .type = YNL_PT_U16, },
	[MPTCP_PM_ADDR_ATTR_ID] = { .name = "id", .type = YNL_PT_U8, },
	[MPTCP_PM_ADDR_ATTR_ADDR4] = { .name = "addr4", .type = YNL_PT_U32, },
	[MPTCP_PM_ADDR_ATTR_ADDR6] = { .name = "addr6", .type = YNL_PT_BINARY,},
	[MPTCP_PM_ADDR_ATTR_PORT] = { .name = "port", .type = YNL_PT_U16, },
	[MPTCP_PM_ADDR_ATTR_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[MPTCP_PM_ADDR_ATTR_IF_IDX] = { .name = "if-idx", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest mptcp_pm_address_nest = {
	.max_attr = MPTCP_PM_ADDR_ATTR_MAX,
	.table = mptcp_pm_address_policy,
};

const struct ynl_policy_attr mptcp_pm_endpoint_policy[MPTCP_PM_ENDPOINT_MAX + 1] = {
	[MPTCP_PM_ENDPOINT_ADDR] = { .name = "addr", .type = YNL_PT_NEST, .nest = &mptcp_pm_address_nest, },
};

const struct ynl_policy_nest mptcp_pm_endpoint_nest = {
	.max_attr = MPTCP_PM_ENDPOINT_MAX,
	.table = mptcp_pm_endpoint_policy,
};

const struct ynl_policy_attr mptcp_pm_attr_policy[MPTCP_PM_ATTR_MAX + 1] = {
	[MPTCP_PM_ATTR_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[MPTCP_PM_ATTR_ADDR] = { .name = "addr", .type = YNL_PT_NEST, .nest = &mptcp_pm_address_nest, },
	[MPTCP_PM_ATTR_RCV_ADD_ADDRS] = { .name = "rcv-add-addrs", .type = YNL_PT_U32, },
	[MPTCP_PM_ATTR_SUBFLOWS] = { .name = "subflows", .type = YNL_PT_U32, },
	[MPTCP_PM_ATTR_TOKEN] = { .name = "token", .type = YNL_PT_U32, },
	[MPTCP_PM_ATTR_LOC_ID] = { .name = "loc-id", .type = YNL_PT_U8, },
	[MPTCP_PM_ATTR_ADDR_REMOTE] = { .name = "addr-remote", .type = YNL_PT_NEST, .nest = &mptcp_pm_address_nest, },
};

const struct ynl_policy_nest mptcp_pm_attr_nest = {
	.max_attr = MPTCP_PM_ATTR_MAX,
	.table = mptcp_pm_attr_policy,
};

/* Common nested types */
void mptcp_pm_address_free(struct mptcp_pm_address *obj)
{
	free(obj->addr6);
}

int mptcp_pm_address_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct mptcp_pm_address *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.family)
		ynl_attr_put_u16(nlh, MPTCP_PM_ADDR_ATTR_FAMILY, obj->family);
	if (obj->_present.id)
		ynl_attr_put_u8(nlh, MPTCP_PM_ADDR_ATTR_ID, obj->id);
	if (obj->_present.addr4)
		ynl_attr_put_u32(nlh, MPTCP_PM_ADDR_ATTR_ADDR4, obj->addr4);
	if (obj->_len.addr6)
		ynl_attr_put(nlh, MPTCP_PM_ADDR_ATTR_ADDR6, obj->addr6, obj->_len.addr6);
	if (obj->_present.port)
		ynl_attr_put_u16(nlh, MPTCP_PM_ADDR_ATTR_PORT, obj->port);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, MPTCP_PM_ADDR_ATTR_FLAGS, obj->flags);
	if (obj->_present.if_idx)
		ynl_attr_put_s32(nlh, MPTCP_PM_ADDR_ATTR_IF_IDX, obj->if_idx);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int mptcp_pm_address_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	struct mptcp_pm_address *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == MPTCP_PM_ADDR_ATTR_FAMILY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.family = 1;
			dst->family = ynl_attr_get_u16(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u8(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_ADDR4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.addr4 = 1;
			dst->addr4 = ynl_attr_get_u32(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_ADDR6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.addr6 = len;
			dst->addr6 = malloc(len);
			memcpy(dst->addr6, ynl_attr_data(attr), len);
		} else if (type == MPTCP_PM_ADDR_ATTR_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port = 1;
			dst->port = ynl_attr_get_u16(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_IF_IDX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.if_idx = 1;
			dst->if_idx = ynl_attr_get_s32(attr);
		}
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_ADD_ADDR ============== */
/* MPTCP_PM_CMD_ADD_ADDR - do */
void mptcp_pm_add_addr_req_free(struct mptcp_pm_add_addr_req *req)
{
	mptcp_pm_address_free(&req->addr);
	free(req);
}

int mptcp_pm_add_addr(struct ynl_sock *ys, struct mptcp_pm_add_addr_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_ADD_ADDR, 1);
	ys->req_policy = &mptcp_pm_endpoint_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.addr)
		mptcp_pm_address_put(nlh, MPTCP_PM_ENDPOINT_ADDR, &req->addr);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== MPTCP_PM_CMD_DEL_ADDR ============== */
/* MPTCP_PM_CMD_DEL_ADDR - do */
void mptcp_pm_del_addr_req_free(struct mptcp_pm_del_addr_req *req)
{
	mptcp_pm_address_free(&req->addr);
	free(req);
}

int mptcp_pm_del_addr(struct ynl_sock *ys, struct mptcp_pm_del_addr_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_DEL_ADDR, 1);
	ys->req_policy = &mptcp_pm_endpoint_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.addr)
		mptcp_pm_address_put(nlh, MPTCP_PM_ENDPOINT_ADDR, &req->addr);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== MPTCP_PM_CMD_GET_ADDR ============== */
/* MPTCP_PM_CMD_GET_ADDR - do */
void mptcp_pm_get_addr_req_free(struct mptcp_pm_get_addr_req *req)
{
	mptcp_pm_address_free(&req->addr);
	free(req);
}

void mptcp_pm_get_addr_rsp_free(struct mptcp_pm_get_addr_rsp *rsp)
{
	mptcp_pm_address_free(&rsp->addr);
	free(rsp);
}

int mptcp_pm_get_addr_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	struct mptcp_pm_get_addr_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == MPTCP_PM_ATTR_ADDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.addr = 1;

			parg.rsp_policy = &mptcp_pm_address_nest;
			parg.data = &dst->addr;
			if (mptcp_pm_address_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct mptcp_pm_get_addr_rsp *
mptcp_pm_get_addr(struct ynl_sock *ys, struct mptcp_pm_get_addr_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct mptcp_pm_get_addr_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_GET_ADDR, 1);
	ys->req_policy = &mptcp_pm_attr_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &mptcp_pm_attr_nest;

	if (req->_present.addr)
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, &req->addr);
	if (req->_present.token)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req->token);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = mptcp_pm_get_addr_rsp_parse;
	yrs.rsp_cmd = MPTCP_PM_CMD_GET_ADDR;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	mptcp_pm_get_addr_rsp_free(rsp);
	return NULL;
}

/* MPTCP_PM_CMD_GET_ADDR - dump */
void mptcp_pm_get_addr_list_free(struct mptcp_pm_get_addr_list *rsp)
{
	struct mptcp_pm_get_addr_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		mptcp_pm_address_free(&rsp->obj.addr);
		free(rsp);
	}
}

struct mptcp_pm_get_addr_list *mptcp_pm_get_addr_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &mptcp_pm_attr_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct mptcp_pm_get_addr_list);
	yds.cb = mptcp_pm_get_addr_rsp_parse;
	yds.rsp_cmd = MPTCP_PM_CMD_GET_ADDR;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, MPTCP_PM_CMD_GET_ADDR, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	mptcp_pm_get_addr_list_free(yds.first);
	return NULL;
}

/* ============== MPTCP_PM_CMD_FLUSH_ADDRS ============== */
/* MPTCP_PM_CMD_FLUSH_ADDRS - do */
void mptcp_pm_flush_addrs_req_free(struct mptcp_pm_flush_addrs_req *req)
{
	mptcp_pm_address_free(&req->addr);
	free(req);
}

int mptcp_pm_flush_addrs(struct ynl_sock *ys,
			 struct mptcp_pm_flush_addrs_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_FLUSH_ADDRS, 1);
	ys->req_policy = &mptcp_pm_endpoint_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.addr)
		mptcp_pm_address_put(nlh, MPTCP_PM_ENDPOINT_ADDR, &req->addr);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== MPTCP_PM_CMD_SET_LIMITS ============== */
/* MPTCP_PM_CMD_SET_LIMITS - do */
void mptcp_pm_set_limits_req_free(struct mptcp_pm_set_limits_req *req)
{
	free(req);
}

int mptcp_pm_set_limits(struct ynl_sock *ys,
			struct mptcp_pm_set_limits_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_SET_LIMITS, 1);
	ys->req_policy = &mptcp_pm_attr_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.rcv_add_addrs)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_RCV_ADD_ADDRS, req->rcv_add_addrs);
	if (req->_present.subflows)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_SUBFLOWS, req->subflows);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== MPTCP_PM_CMD_GET_LIMITS ============== */
/* MPTCP_PM_CMD_GET_LIMITS - do */
void mptcp_pm_get_limits_req_free(struct mptcp_pm_get_limits_req *req)
{
	free(req);
}

void mptcp_pm_get_limits_rsp_free(struct mptcp_pm_get_limits_rsp *rsp)
{
	free(rsp);
}

int mptcp_pm_get_limits_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	struct mptcp_pm_get_limits_rsp *dst;
	const struct nlattr *attr;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == MPTCP_PM_ATTR_RCV_ADD_ADDRS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rcv_add_addrs = 1;
			dst->rcv_add_addrs = ynl_attr_get_u32(attr);
		} else if (type == MPTCP_PM_ATTR_SUBFLOWS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.subflows = 1;
			dst->subflows = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct mptcp_pm_get_limits_rsp *
mptcp_pm_get_limits(struct ynl_sock *ys, struct mptcp_pm_get_limits_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct mptcp_pm_get_limits_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_GET_LIMITS, 1);
	ys->req_policy = &mptcp_pm_attr_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &mptcp_pm_attr_nest;

	if (req->_present.rcv_add_addrs)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_RCV_ADD_ADDRS, req->rcv_add_addrs);
	if (req->_present.subflows)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_SUBFLOWS, req->subflows);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = mptcp_pm_get_limits_rsp_parse;
	yrs.rsp_cmd = MPTCP_PM_CMD_GET_LIMITS;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	mptcp_pm_get_limits_rsp_free(rsp);
	return NULL;
}

/* ============== MPTCP_PM_CMD_SET_FLAGS ============== */
/* MPTCP_PM_CMD_SET_FLAGS - do */
void mptcp_pm_set_flags_req_free(struct mptcp_pm_set_flags_req *req)
{
	mptcp_pm_address_free(&req->addr);
	mptcp_pm_address_free(&req->addr_remote);
	free(req);
}

int mptcp_pm_set_flags(struct ynl_sock *ys, struct mptcp_pm_set_flags_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_SET_FLAGS, 1);
	ys->req_policy = &mptcp_pm_attr_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.addr)
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, &req->addr);
	if (req->_present.token)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req->token);
	if (req->_present.addr_remote)
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR_REMOTE, &req->addr_remote);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== MPTCP_PM_CMD_ANNOUNCE ============== */
/* MPTCP_PM_CMD_ANNOUNCE - do */
void mptcp_pm_announce_req_free(struct mptcp_pm_announce_req *req)
{
	mptcp_pm_address_free(&req->addr);
	free(req);
}

int mptcp_pm_announce(struct ynl_sock *ys, struct mptcp_pm_announce_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_ANNOUNCE, 1);
	ys->req_policy = &mptcp_pm_attr_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.addr)
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, &req->addr);
	if (req->_present.token)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req->token);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== MPTCP_PM_CMD_REMOVE ============== */
/* MPTCP_PM_CMD_REMOVE - do */
void mptcp_pm_remove_req_free(struct mptcp_pm_remove_req *req)
{
	free(req);
}

int mptcp_pm_remove(struct ynl_sock *ys, struct mptcp_pm_remove_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_REMOVE, 1);
	ys->req_policy = &mptcp_pm_attr_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.token)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req->token);
	if (req->_present.loc_id)
		ynl_attr_put_u8(nlh, MPTCP_PM_ATTR_LOC_ID, req->loc_id);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== MPTCP_PM_CMD_SUBFLOW_CREATE ============== */
/* MPTCP_PM_CMD_SUBFLOW_CREATE - do */
void mptcp_pm_subflow_create_req_free(struct mptcp_pm_subflow_create_req *req)
{
	mptcp_pm_address_free(&req->addr);
	mptcp_pm_address_free(&req->addr_remote);
	free(req);
}

int mptcp_pm_subflow_create(struct ynl_sock *ys,
			    struct mptcp_pm_subflow_create_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_SUBFLOW_CREATE, 1);
	ys->req_policy = &mptcp_pm_attr_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.addr)
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, &req->addr);
	if (req->_present.token)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req->token);
	if (req->_present.addr_remote)
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR_REMOTE, &req->addr_remote);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== MPTCP_PM_CMD_SUBFLOW_DESTROY ============== */
/* MPTCP_PM_CMD_SUBFLOW_DESTROY - do */
void
mptcp_pm_subflow_destroy_req_free(struct mptcp_pm_subflow_destroy_req *req)
{
	mptcp_pm_address_free(&req->addr);
	mptcp_pm_address_free(&req->addr_remote);
	free(req);
}

int mptcp_pm_subflow_destroy(struct ynl_sock *ys,
			     struct mptcp_pm_subflow_destroy_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, MPTCP_PM_CMD_SUBFLOW_DESTROY, 1);
	ys->req_policy = &mptcp_pm_attr_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.addr)
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, &req->addr);
	if (req->_present.token)
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req->token);
	if (req->_present.addr_remote)
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR_REMOTE, &req->addr_remote);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

const struct ynl_family ynl_mptcp_pm_family =  {
	.name		= "mptcp_pm",
	.hdr_len	= sizeof(struct genlmsghdr),
};
