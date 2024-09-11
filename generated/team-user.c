// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/team.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "team-user.h"
#include "ynl.h"
#include <linux/if_team.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const team_op_strmap[] = {
	[TEAM_CMD_OPTIONS_SET] = "options-set",
	[TEAM_CMD_OPTIONS_GET] = "options-get",
	[TEAM_CMD_PORT_LIST_GET] = "port-list-get",
};

const char *team_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(team_op_strmap))
		return NULL;
	return team_op_strmap[op];
}

/* Policies */
const struct ynl_policy_attr team_attr_option_policy[TEAM_ATTR_OPTION_MAX + 1] = {
	[TEAM_ATTR_OPTION_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[TEAM_ATTR_OPTION_NAME] = { .name = "name", .type = YNL_PT_NUL_STR, },
	[TEAM_ATTR_OPTION_CHANGED] = { .name = "changed", .type = YNL_PT_FLAG, },
	[TEAM_ATTR_OPTION_TYPE] = { .name = "type", .type = YNL_PT_U8, },
	[TEAM_ATTR_OPTION_DATA] = { .name = "data", .type = YNL_PT_BINARY,},
	[TEAM_ATTR_OPTION_REMOVED] = { .name = "removed", .type = YNL_PT_FLAG, },
	[TEAM_ATTR_OPTION_PORT_IFINDEX] = { .name = "port-ifindex", .type = YNL_PT_U32, },
	[TEAM_ATTR_OPTION_ARRAY_INDEX] = { .name = "array-index", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest team_attr_option_nest = {
	.max_attr = TEAM_ATTR_OPTION_MAX,
	.table = team_attr_option_policy,
};

const struct ynl_policy_attr team_attr_port_policy[TEAM_ATTR_PORT_MAX + 1] = {
	[TEAM_ATTR_PORT_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[TEAM_ATTR_PORT_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[TEAM_ATTR_PORT_CHANGED] = { .name = "changed", .type = YNL_PT_FLAG, },
	[TEAM_ATTR_PORT_LINKUP] = { .name = "linkup", .type = YNL_PT_FLAG, },
	[TEAM_ATTR_PORT_SPEED] = { .name = "speed", .type = YNL_PT_U32, },
	[TEAM_ATTR_PORT_DUPLEX] = { .name = "duplex", .type = YNL_PT_U8, },
	[TEAM_ATTR_PORT_REMOVED] = { .name = "removed", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest team_attr_port_nest = {
	.max_attr = TEAM_ATTR_PORT_MAX,
	.table = team_attr_port_policy,
};

const struct ynl_policy_attr team_item_option_policy[TEAM_ATTR_ITEM_OPTION_MAX + 1] = {
	[TEAM_ATTR_ITEM_OPTION_UNSPEC] = { .name = "option-unspec", .type = YNL_PT_REJECT, },
	[TEAM_ATTR_ITEM_OPTION] = { .name = "option", .type = YNL_PT_NEST, .nest = &team_attr_option_nest, },
};

const struct ynl_policy_nest team_item_option_nest = {
	.max_attr = TEAM_ATTR_ITEM_OPTION_MAX,
	.table = team_item_option_policy,
};

const struct ynl_policy_attr team_item_port_policy[TEAM_ATTR_ITEM_PORT_MAX + 1] = {
	[TEAM_ATTR_ITEM_PORT_UNSPEC] = { .name = "port-unspec", .type = YNL_PT_REJECT, },
	[TEAM_ATTR_ITEM_PORT] = { .name = "port", .type = YNL_PT_NEST, .nest = &team_attr_port_nest, },
};

const struct ynl_policy_nest team_item_port_nest = {
	.max_attr = TEAM_ATTR_ITEM_PORT_MAX,
	.table = team_item_port_policy,
};

const struct ynl_policy_attr team_policy[TEAM_ATTR_MAX + 1] = {
	[TEAM_ATTR_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[TEAM_ATTR_TEAM_IFINDEX] = { .name = "team-ifindex", .type = YNL_PT_U32, },
	[TEAM_ATTR_LIST_OPTION] = { .name = "list-option", .type = YNL_PT_NEST, .nest = &team_item_option_nest, },
	[TEAM_ATTR_LIST_PORT] = { .name = "list-port", .type = YNL_PT_NEST, .nest = &team_item_port_nest, },
};

const struct ynl_policy_nest team_nest = {
	.max_attr = TEAM_ATTR_MAX,
	.table = team_policy,
};

/* Common nested types */
void team_attr_option_free(struct team_attr_option *obj)
{
	free(obj->name);
	free(obj->data);
}

int team_attr_option_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct team_attr_option *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.name_len)
		ynl_attr_put_str(nlh, TEAM_ATTR_OPTION_NAME, obj->name);
	if (obj->_present.changed)
		ynl_attr_put(nlh, TEAM_ATTR_OPTION_CHANGED, NULL, 0);
	if (obj->_present.type)
		ynl_attr_put_u8(nlh, TEAM_ATTR_OPTION_TYPE, obj->type);
	if (obj->_present.data_len)
		ynl_attr_put(nlh, TEAM_ATTR_OPTION_DATA, obj->data, obj->_present.data_len);
	if (obj->_present.removed)
		ynl_attr_put(nlh, TEAM_ATTR_OPTION_REMOVED, NULL, 0);
	if (obj->_present.port_ifindex)
		ynl_attr_put_u32(nlh, TEAM_ATTR_OPTION_PORT_IFINDEX, obj->port_ifindex);
	if (obj->_present.array_index)
		ynl_attr_put_u32(nlh, TEAM_ATTR_OPTION_ARRAY_INDEX, obj->array_index);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int team_attr_option_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	struct team_attr_option *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_OPTION_NAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_present.name_len = len;
			dst->name = malloc(len + 1);
			memcpy(dst->name, ynl_attr_get_str(attr), len);
			dst->name[len] = 0;
		} else if (type == TEAM_ATTR_OPTION_CHANGED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.changed = 1;
		} else if (type == TEAM_ATTR_OPTION_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.type = 1;
			dst->type = ynl_attr_get_u8(attr);
		} else if (type == TEAM_ATTR_OPTION_DATA) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.data_len = len;
			dst->data = malloc(len);
			memcpy(dst->data, ynl_attr_data(attr), len);
		} else if (type == TEAM_ATTR_OPTION_REMOVED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.removed = 1;
		} else if (type == TEAM_ATTR_OPTION_PORT_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_ifindex = 1;
			dst->port_ifindex = ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_OPTION_ARRAY_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.array_index = 1;
			dst->array_index = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void team_attr_port_free(struct team_attr_port *obj)
{
}

int team_attr_port_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	struct team_attr_port *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_PORT_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_PORT_CHANGED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.changed = 1;
		} else if (type == TEAM_ATTR_PORT_LINKUP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.linkup = 1;
		} else if (type == TEAM_ATTR_PORT_SPEED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.speed = 1;
			dst->speed = ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_PORT_DUPLEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.duplex = 1;
			dst->duplex = ynl_attr_get_u8(attr);
		} else if (type == TEAM_ATTR_PORT_REMOVED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.removed = 1;
		}
	}

	return 0;
}

void team_item_option_free(struct team_item_option *obj)
{
	team_attr_option_free(&obj->option);
}

int team_item_option_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct team_item_option *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.option)
		team_attr_option_put(nlh, TEAM_ATTR_ITEM_OPTION, &obj->option);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int team_item_option_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	struct team_item_option *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_ITEM_OPTION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.option = 1;

			parg.rsp_policy = &team_attr_option_nest;
			parg.data = &dst->option;
			if (team_attr_option_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void team_item_port_free(struct team_item_port *obj)
{
	team_attr_port_free(&obj->port);
}

int team_item_port_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	struct team_item_port *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_ITEM_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port = 1;

			parg.rsp_policy = &team_attr_port_nest;
			parg.data = &dst->port;
			if (team_attr_port_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

/* ============== TEAM_CMD_NOOP ============== */
/* TEAM_CMD_NOOP - do */
void team_noop_rsp_free(struct team_noop_rsp *rsp)
{
	free(rsp);
}

int team_noop_rsp_parse(const struct nlmsghdr *nlh, struct ynl_parse_arg *yarg)
{
	struct team_noop_rsp *dst;
	const struct nlattr *attr;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_TEAM_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.team_ifindex = 1;
			dst->team_ifindex = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct team_noop_rsp *team_noop(struct ynl_sock *ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct team_noop_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, TEAM_CMD_NOOP, 1);
	ys->req_policy = &team_nest;
	yrs.yarg.rsp_policy = &team_nest;

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = team_noop_rsp_parse;
	yrs.rsp_cmd = TEAM_CMD_NOOP;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	team_noop_rsp_free(rsp);
	return NULL;
}

/* ============== TEAM_CMD_OPTIONS_SET ============== */
/* TEAM_CMD_OPTIONS_SET - do */
void team_options_set_req_free(struct team_options_set_req *req)
{
	team_item_option_free(&req->list_option);
	free(req);
}

void team_options_set_rsp_free(struct team_options_set_rsp *rsp)
{
	team_item_option_free(&rsp->list_option);
	free(rsp);
}

int team_options_set_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct team_options_set_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_TEAM_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.team_ifindex = 1;
			dst->team_ifindex = ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_LIST_OPTION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.list_option = 1;

			parg.rsp_policy = &team_item_option_nest;
			parg.data = &dst->list_option;
			if (team_item_option_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct team_options_set_rsp *
team_options_set(struct ynl_sock *ys, struct team_options_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct team_options_set_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, TEAM_CMD_OPTIONS_SET, 1);
	ys->req_policy = &team_nest;
	yrs.yarg.rsp_policy = &team_nest;

	if (req->_present.team_ifindex)
		ynl_attr_put_u32(nlh, TEAM_ATTR_TEAM_IFINDEX, req->team_ifindex);
	if (req->_present.list_option)
		team_item_option_put(nlh, TEAM_ATTR_LIST_OPTION, &req->list_option);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = team_options_set_rsp_parse;
	yrs.rsp_cmd = TEAM_CMD_OPTIONS_SET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	team_options_set_rsp_free(rsp);
	return NULL;
}

/* ============== TEAM_CMD_OPTIONS_GET ============== */
/* TEAM_CMD_OPTIONS_GET - do */
void team_options_get_req_free(struct team_options_get_req *req)
{
	free(req);
}

void team_options_get_rsp_free(struct team_options_get_rsp *rsp)
{
	team_item_option_free(&rsp->list_option);
	free(rsp);
}

int team_options_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct team_options_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_TEAM_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.team_ifindex = 1;
			dst->team_ifindex = ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_LIST_OPTION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.list_option = 1;

			parg.rsp_policy = &team_item_option_nest;
			parg.data = &dst->list_option;
			if (team_item_option_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct team_options_get_rsp *
team_options_get(struct ynl_sock *ys, struct team_options_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct team_options_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, TEAM_CMD_OPTIONS_GET, 1);
	ys->req_policy = &team_nest;
	yrs.yarg.rsp_policy = &team_nest;

	if (req->_present.team_ifindex)
		ynl_attr_put_u32(nlh, TEAM_ATTR_TEAM_IFINDEX, req->team_ifindex);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = team_options_get_rsp_parse;
	yrs.rsp_cmd = TEAM_CMD_OPTIONS_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	team_options_get_rsp_free(rsp);
	return NULL;
}

/* ============== TEAM_CMD_PORT_LIST_GET ============== */
/* TEAM_CMD_PORT_LIST_GET - do */
void team_port_list_get_req_free(struct team_port_list_get_req *req)
{
	free(req);
}

void team_port_list_get_rsp_free(struct team_port_list_get_rsp *rsp)
{
	team_item_port_free(&rsp->list_port);
	free(rsp);
}

int team_port_list_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	struct team_port_list_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_TEAM_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.team_ifindex = 1;
			dst->team_ifindex = ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_LIST_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.list_port = 1;

			parg.rsp_policy = &team_item_port_nest;
			parg.data = &dst->list_port;
			if (team_item_port_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct team_port_list_get_rsp *
team_port_list_get(struct ynl_sock *ys, struct team_port_list_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct team_port_list_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, TEAM_CMD_PORT_LIST_GET, 1);
	ys->req_policy = &team_nest;
	yrs.yarg.rsp_policy = &team_nest;

	if (req->_present.team_ifindex)
		ynl_attr_put_u32(nlh, TEAM_ATTR_TEAM_IFINDEX, req->team_ifindex);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = team_port_list_get_rsp_parse;
	yrs.rsp_cmd = TEAM_CMD_PORT_LIST_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	team_port_list_get_rsp_free(rsp);
	return NULL;
}

const struct ynl_family ynl_team_family =  {
	.name		= "team",
	.hdr_len	= sizeof(struct genlmsghdr),
};
