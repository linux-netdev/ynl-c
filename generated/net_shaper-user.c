// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/net_shaper.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "net_shaper-user.h"
#include "ynl.h"
#include <linux/net_shaper.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const net_shaper_op_strmap[] = {
	[NET_SHAPER_CMD_GET] = "get",
	[NET_SHAPER_CMD_SET] = "set",
	[NET_SHAPER_CMD_DELETE] = "delete",
	[NET_SHAPER_CMD_GROUP] = "group",
	[NET_SHAPER_CMD_CAP_GET] = "cap-get",
};

const char *net_shaper_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(net_shaper_op_strmap))
		return NULL;
	return net_shaper_op_strmap[op];
}

static const char * const net_shaper_scope_strmap[] = {
	[0] = "unspec",
	[1] = "netdev",
	[2] = "queue",
	[3] = "node",
};

const char *net_shaper_scope_str(enum net_shaper_scope value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(net_shaper_scope_strmap))
		return NULL;
	return net_shaper_scope_strmap[value];
}

static const char * const net_shaper_metric_strmap[] = {
	[0] = "bps",
	[1] = "pps",
};

const char *net_shaper_metric_str(enum net_shaper_metric value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(net_shaper_metric_strmap))
		return NULL;
	return net_shaper_metric_strmap[value];
}

/* Policies */
const struct ynl_policy_attr net_shaper_handle_policy[NET_SHAPER_A_HANDLE_MAX + 1] = {
	[NET_SHAPER_A_HANDLE_SCOPE] = { .name = "scope", .type = YNL_PT_U32, },
	[NET_SHAPER_A_HANDLE_ID] = { .name = "id", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest net_shaper_handle_nest = {
	.max_attr = NET_SHAPER_A_HANDLE_MAX,
	.table = net_shaper_handle_policy,
};

const struct ynl_policy_attr net_shaper_leaf_info_policy[NET_SHAPER_A_MAX + 1] = {
	[NET_SHAPER_A_HANDLE] = { .name = "handle", .type = YNL_PT_NEST, .nest = &net_shaper_handle_nest, },
	[NET_SHAPER_A_PRIORITY] = { .name = "priority", .type = YNL_PT_U32, },
	[NET_SHAPER_A_WEIGHT] = { .name = "weight", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest net_shaper_leaf_info_nest = {
	.max_attr = NET_SHAPER_A_MAX,
	.table = net_shaper_leaf_info_policy,
};

const struct ynl_policy_attr net_shaper_net_shaper_policy[NET_SHAPER_A_MAX + 1] = {
	[NET_SHAPER_A_HANDLE] = { .name = "handle", .type = YNL_PT_NEST, .nest = &net_shaper_handle_nest, },
	[NET_SHAPER_A_METRIC] = { .name = "metric", .type = YNL_PT_U32, },
	[NET_SHAPER_A_BW_MIN] = { .name = "bw-min", .type = YNL_PT_UINT, },
	[NET_SHAPER_A_BW_MAX] = { .name = "bw-max", .type = YNL_PT_UINT, },
	[NET_SHAPER_A_BURST] = { .name = "burst", .type = YNL_PT_UINT, },
	[NET_SHAPER_A_PRIORITY] = { .name = "priority", .type = YNL_PT_U32, },
	[NET_SHAPER_A_WEIGHT] = { .name = "weight", .type = YNL_PT_U32, },
	[NET_SHAPER_A_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[NET_SHAPER_A_PARENT] = { .name = "parent", .type = YNL_PT_NEST, .nest = &net_shaper_handle_nest, },
	[NET_SHAPER_A_LEAVES] = { .name = "leaves", .type = YNL_PT_NEST, .nest = &net_shaper_leaf_info_nest, },
};

const struct ynl_policy_nest net_shaper_net_shaper_nest = {
	.max_attr = NET_SHAPER_A_MAX,
	.table = net_shaper_net_shaper_policy,
};

const struct ynl_policy_attr net_shaper_caps_policy[NET_SHAPER_A_CAPS_MAX + 1] = {
	[NET_SHAPER_A_CAPS_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[NET_SHAPER_A_CAPS_SCOPE] = { .name = "scope", .type = YNL_PT_U32, },
	[NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS] = { .name = "support-metric-bps", .type = YNL_PT_FLAG, },
	[NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS] = { .name = "support-metric-pps", .type = YNL_PT_FLAG, },
	[NET_SHAPER_A_CAPS_SUPPORT_NESTING] = { .name = "support-nesting", .type = YNL_PT_FLAG, },
	[NET_SHAPER_A_CAPS_SUPPORT_BW_MIN] = { .name = "support-bw-min", .type = YNL_PT_FLAG, },
	[NET_SHAPER_A_CAPS_SUPPORT_BW_MAX] = { .name = "support-bw-max", .type = YNL_PT_FLAG, },
	[NET_SHAPER_A_CAPS_SUPPORT_BURST] = { .name = "support-burst", .type = YNL_PT_FLAG, },
	[NET_SHAPER_A_CAPS_SUPPORT_PRIORITY] = { .name = "support-priority", .type = YNL_PT_FLAG, },
	[NET_SHAPER_A_CAPS_SUPPORT_WEIGHT] = { .name = "support-weight", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest net_shaper_caps_nest = {
	.max_attr = NET_SHAPER_A_CAPS_MAX,
	.table = net_shaper_caps_policy,
};

/* Common nested types */
void net_shaper_handle_free(struct net_shaper_handle *obj)
{
}

int net_shaper_handle_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct net_shaper_handle *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.scope)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_HANDLE_SCOPE, obj->scope);
	if (obj->_present.id)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_HANDLE_ID, obj->id);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int net_shaper_handle_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct net_shaper_handle *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NET_SHAPER_A_HANDLE_SCOPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.scope = 1;
			dst->scope = ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_HANDLE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void net_shaper_leaf_info_free(struct net_shaper_leaf_info *obj)
{
	net_shaper_handle_free(&obj->handle);
}

int net_shaper_leaf_info_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     struct net_shaper_leaf_info *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.handle)
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, &obj->handle);
	if (obj->_present.priority)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_PRIORITY, obj->priority);
	if (obj->_present.weight)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_WEIGHT, obj->weight);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

/* ============== NET_SHAPER_CMD_GET ============== */
/* NET_SHAPER_CMD_GET - do */
void net_shaper_get_req_free(struct net_shaper_get_req *req)
{
	net_shaper_handle_free(&req->handle);
	free(req);
}

void net_shaper_get_rsp_free(struct net_shaper_get_rsp *rsp)
{
	net_shaper_handle_free(&rsp->parent);
	net_shaper_handle_free(&rsp->handle);
	free(rsp);
}

int net_shaper_get_rsp_parse(const struct nlmsghdr *nlh,
			     struct ynl_parse_arg *yarg)
{
	struct net_shaper_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NET_SHAPER_A_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_PARENT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.parent = 1;

			parg.rsp_policy = &net_shaper_handle_nest;
			parg.data = &dst->parent;
			if (net_shaper_handle_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NET_SHAPER_A_HANDLE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.handle = 1;

			parg.rsp_policy = &net_shaper_handle_nest;
			parg.data = &dst->handle;
			if (net_shaper_handle_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NET_SHAPER_A_METRIC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.metric = 1;
			dst->metric = ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_BW_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bw_min = 1;
			dst->bw_min = ynl_attr_get_uint(attr);
		} else if (type == NET_SHAPER_A_BW_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bw_max = 1;
			dst->bw_max = ynl_attr_get_uint(attr);
		} else if (type == NET_SHAPER_A_BURST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.burst = 1;
			dst->burst = ynl_attr_get_uint(attr);
		} else if (type == NET_SHAPER_A_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.priority = 1;
			dst->priority = ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_WEIGHT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.weight = 1;
			dst->weight = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct net_shaper_get_rsp *
net_shaper_get(struct ynl_sock *ys, struct net_shaper_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct net_shaper_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NET_SHAPER_CMD_GET, 1);
	ys->req_policy = &net_shaper_net_shaper_nest;
	yrs.yarg.rsp_policy = &net_shaper_net_shaper_nest;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req->ifindex);
	if (req->_present.handle)
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, &req->handle);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = net_shaper_get_rsp_parse;
	yrs.rsp_cmd = NET_SHAPER_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	net_shaper_get_rsp_free(rsp);
	return NULL;
}

/* NET_SHAPER_CMD_GET - dump */
void net_shaper_get_req_dump_free(struct net_shaper_get_req_dump *req)
{
	free(req);
}

void net_shaper_get_list_free(struct net_shaper_get_list *rsp)
{
	struct net_shaper_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		net_shaper_handle_free(&rsp->obj.parent);
		net_shaper_handle_free(&rsp->obj.handle);
		free(rsp);
	}
}

struct net_shaper_get_list *
net_shaper_get_dump(struct ynl_sock *ys, struct net_shaper_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &net_shaper_net_shaper_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct net_shaper_get_list);
	yds.cb = net_shaper_get_rsp_parse;
	yds.rsp_cmd = NET_SHAPER_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, NET_SHAPER_CMD_GET, 1);
	ys->req_policy = &net_shaper_net_shaper_nest;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req->ifindex);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	net_shaper_get_list_free(yds.first);
	return NULL;
}

/* ============== NET_SHAPER_CMD_SET ============== */
/* NET_SHAPER_CMD_SET - do */
void net_shaper_set_req_free(struct net_shaper_set_req *req)
{
	net_shaper_handle_free(&req->handle);
	free(req);
}

int net_shaper_set(struct ynl_sock *ys, struct net_shaper_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NET_SHAPER_CMD_SET, 1);
	ys->req_policy = &net_shaper_net_shaper_nest;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req->ifindex);
	if (req->_present.handle)
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, &req->handle);
	if (req->_present.metric)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_METRIC, req->metric);
	if (req->_present.bw_min)
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BW_MIN, req->bw_min);
	if (req->_present.bw_max)
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BW_MAX, req->bw_max);
	if (req->_present.burst)
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BURST, req->burst);
	if (req->_present.priority)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_PRIORITY, req->priority);
	if (req->_present.weight)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_WEIGHT, req->weight);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== NET_SHAPER_CMD_DELETE ============== */
/* NET_SHAPER_CMD_DELETE - do */
void net_shaper_delete_req_free(struct net_shaper_delete_req *req)
{
	net_shaper_handle_free(&req->handle);
	free(req);
}

int net_shaper_delete(struct ynl_sock *ys, struct net_shaper_delete_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NET_SHAPER_CMD_DELETE, 1);
	ys->req_policy = &net_shaper_net_shaper_nest;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req->ifindex);
	if (req->_present.handle)
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, &req->handle);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== NET_SHAPER_CMD_GROUP ============== */
/* NET_SHAPER_CMD_GROUP - do */
void net_shaper_group_req_free(struct net_shaper_group_req *req)
{
	unsigned int i;

	net_shaper_handle_free(&req->parent);
	net_shaper_handle_free(&req->handle);
	for (i = 0; i < req->n_leaves; i++)
		net_shaper_leaf_info_free(&req->leaves[i]);
	free(req->leaves);
	free(req);
}

void net_shaper_group_rsp_free(struct net_shaper_group_rsp *rsp)
{
	net_shaper_handle_free(&rsp->handle);
	free(rsp);
}

int net_shaper_group_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct net_shaper_group_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NET_SHAPER_A_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_HANDLE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.handle = 1;

			parg.rsp_policy = &net_shaper_handle_nest;
			parg.data = &dst->handle;
			if (net_shaper_handle_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct net_shaper_group_rsp *
net_shaper_group(struct ynl_sock *ys, struct net_shaper_group_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct net_shaper_group_rsp *rsp;
	struct nlmsghdr *nlh;
	unsigned int i;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NET_SHAPER_CMD_GROUP, 1);
	ys->req_policy = &net_shaper_net_shaper_nest;
	yrs.yarg.rsp_policy = &net_shaper_net_shaper_nest;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req->ifindex);
	if (req->_present.parent)
		net_shaper_handle_put(nlh, NET_SHAPER_A_PARENT, &req->parent);
	if (req->_present.handle)
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, &req->handle);
	if (req->_present.metric)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_METRIC, req->metric);
	if (req->_present.bw_min)
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BW_MIN, req->bw_min);
	if (req->_present.bw_max)
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BW_MAX, req->bw_max);
	if (req->_present.burst)
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BURST, req->burst);
	if (req->_present.priority)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_PRIORITY, req->priority);
	if (req->_present.weight)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_WEIGHT, req->weight);
	for (i = 0; i < req->n_leaves; i++)
		net_shaper_leaf_info_put(nlh, NET_SHAPER_A_LEAVES, &req->leaves[i]);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = net_shaper_group_rsp_parse;
	yrs.rsp_cmd = NET_SHAPER_CMD_GROUP;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	net_shaper_group_rsp_free(rsp);
	return NULL;
}

/* ============== NET_SHAPER_CMD_CAP_GET ============== */
/* NET_SHAPER_CMD_CAP_GET - do */
void net_shaper_cap_get_req_free(struct net_shaper_cap_get_req *req)
{
	free(req);
}

void net_shaper_cap_get_rsp_free(struct net_shaper_cap_get_rsp *rsp)
{
	free(rsp);
}

int net_shaper_cap_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	struct net_shaper_cap_get_rsp *dst;
	const struct nlattr *attr;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NET_SHAPER_A_CAPS_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_CAPS_SCOPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.scope = 1;
			dst->scope = ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_metric_bps = 1;
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_metric_pps = 1;
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_NESTING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_nesting = 1;
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_BW_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_bw_min = 1;
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_BW_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_bw_max = 1;
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_BURST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_burst = 1;
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_priority = 1;
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_WEIGHT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.support_weight = 1;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct net_shaper_cap_get_rsp *
net_shaper_cap_get(struct ynl_sock *ys, struct net_shaper_cap_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct net_shaper_cap_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NET_SHAPER_CMD_CAP_GET, 1);
	ys->req_policy = &net_shaper_caps_nest;
	yrs.yarg.rsp_policy = &net_shaper_caps_nest;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_CAPS_IFINDEX, req->ifindex);
	if (req->_present.scope)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_CAPS_SCOPE, req->scope);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = net_shaper_cap_get_rsp_parse;
	yrs.rsp_cmd = NET_SHAPER_CMD_CAP_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	net_shaper_cap_get_rsp_free(rsp);
	return NULL;
}

/* NET_SHAPER_CMD_CAP_GET - dump */
void net_shaper_cap_get_req_dump_free(struct net_shaper_cap_get_req_dump *req)
{
	free(req);
}

void net_shaper_cap_get_list_free(struct net_shaper_cap_get_list *rsp)
{
	struct net_shaper_cap_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp);
	}
}

struct net_shaper_cap_get_list *
net_shaper_cap_get_dump(struct ynl_sock *ys,
			struct net_shaper_cap_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &net_shaper_caps_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct net_shaper_cap_get_list);
	yds.cb = net_shaper_cap_get_rsp_parse;
	yds.rsp_cmd = NET_SHAPER_CMD_CAP_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, NET_SHAPER_CMD_CAP_GET, 1);
	ys->req_policy = &net_shaper_caps_nest;

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NET_SHAPER_A_CAPS_IFINDEX, req->ifindex);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	net_shaper_cap_get_list_free(yds.first);
	return NULL;
}

const struct ynl_family ynl_net_shaper_family =  {
	.name		= "net_shaper",
	.hdr_len	= sizeof(struct genlmsghdr),
};
