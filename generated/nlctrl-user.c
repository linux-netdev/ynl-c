// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/nlctrl.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "nlctrl-user.h"
#include "ynl.h"
#include <linux/genetlink.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const nlctrl_op_strmap[] = {
	[1] = "getfamily",
	[CTRL_CMD_GETPOLICY] = "getpolicy",
};

const char *nlctrl_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(nlctrl_op_strmap))
		return NULL;
	return nlctrl_op_strmap[op];
}

static const char * const nlctrl_op_flags_strmap[] = {
	[0] = "admin-perm",
	[1] = "cmd-cap-do",
	[2] = "cmd-cap-dump",
	[3] = "cmd-cap-haspol",
	[4] = "uns-admin-perm",
};

const char *nlctrl_op_flags_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(nlctrl_op_flags_strmap))
		return NULL;
	return nlctrl_op_flags_strmap[value];
}

static const char * const nlctrl_attr_type_strmap[] = {
	[0] = "invalid",
	[1] = "flag",
	[2] = "u8",
	[3] = "u16",
	[4] = "u32",
	[5] = "u64",
	[6] = "s8",
	[7] = "s16",
	[8] = "s32",
	[9] = "s64",
	[10] = "binary",
	[11] = "string",
	[12] = "nul-string",
	[13] = "nested",
	[14] = "nested-array",
	[15] = "bitfield32",
	[16] = "sint",
	[17] = "uint",
};

const char *nlctrl_attr_type_str(enum netlink_attribute_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(nlctrl_attr_type_strmap))
		return NULL;
	return nlctrl_attr_type_strmap[value];
}

/* Policies */
const struct ynl_policy_attr nlctrl_op_attrs_policy[CTRL_ATTR_OP_MAX + 1] = {
	[CTRL_ATTR_OP_ID] = { .name = "id", .type = YNL_PT_U32, },
	[CTRL_ATTR_OP_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest nlctrl_op_attrs_nest = {
	.max_attr = CTRL_ATTR_OP_MAX,
	.table = nlctrl_op_attrs_policy,
};

const struct ynl_policy_attr nlctrl_mcast_group_attrs_policy[CTRL_ATTR_MCAST_GRP_MAX + 1] = {
	[CTRL_ATTR_MCAST_GRP_NAME] = { .name = "name", .type = YNL_PT_NUL_STR, },
	[CTRL_ATTR_MCAST_GRP_ID] = { .name = "id", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest nlctrl_mcast_group_attrs_nest = {
	.max_attr = CTRL_ATTR_MCAST_GRP_MAX,
	.table = nlctrl_mcast_group_attrs_policy,
};

const struct ynl_policy_attr nlctrl_policy_attrs_policy[NL_POLICY_TYPE_ATTR_MAX + 1] = {
	[NL_POLICY_TYPE_ATTR_TYPE] = { .name = "type", .type = YNL_PT_U32, },
	[NL_POLICY_TYPE_ATTR_MIN_VALUE_S] = { .name = "min-value-s", .type = YNL_PT_U64, },
	[NL_POLICY_TYPE_ATTR_MAX_VALUE_S] = { .name = "max-value-s", .type = YNL_PT_U64, },
	[NL_POLICY_TYPE_ATTR_MIN_VALUE_U] = { .name = "min-value-u", .type = YNL_PT_U64, },
	[NL_POLICY_TYPE_ATTR_MAX_VALUE_U] = { .name = "max-value-u", .type = YNL_PT_U64, },
	[NL_POLICY_TYPE_ATTR_MIN_LENGTH] = { .name = "min-length", .type = YNL_PT_U32, },
	[NL_POLICY_TYPE_ATTR_MAX_LENGTH] = { .name = "max-length", .type = YNL_PT_U32, },
	[NL_POLICY_TYPE_ATTR_POLICY_IDX] = { .name = "policy-idx", .type = YNL_PT_U32, },
	[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE] = { .name = "policy-maxtype", .type = YNL_PT_U32, },
	[NL_POLICY_TYPE_ATTR_BITFIELD32_MASK] = { .name = "bitfield32-mask", .type = YNL_PT_U32, },
	[NL_POLICY_TYPE_ATTR_MASK] = { .name = "mask", .type = YNL_PT_U64, },
	[NL_POLICY_TYPE_ATTR_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest nlctrl_policy_attrs_nest = {
	.max_attr = NL_POLICY_TYPE_ATTR_MAX,
	.table = nlctrl_policy_attrs_policy,
};

const struct ynl_policy_attr nlctrl_op_policy_attrs_policy[CTRL_ATTR_POLICY_MAX + 1] = {
	[CTRL_ATTR_POLICY_DO] = { .name = "do", .type = YNL_PT_U32, },
	[CTRL_ATTR_POLICY_DUMP] = { .name = "dump", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest nlctrl_op_policy_attrs_nest = {
	.max_attr = CTRL_ATTR_POLICY_MAX,
	.table = nlctrl_op_policy_attrs_policy,
};

const struct ynl_policy_attr nlctrl_ctrl_attrs_policy[CTRL_ATTR_MAX + 1] = {
	[CTRL_ATTR_FAMILY_ID] = { .name = "family-id", .type = YNL_PT_U16, },
	[CTRL_ATTR_FAMILY_NAME] = { .name = "family-name", .type = YNL_PT_NUL_STR, },
	[CTRL_ATTR_VERSION] = { .name = "version", .type = YNL_PT_U32, },
	[CTRL_ATTR_HDRSIZE] = { .name = "hdrsize", .type = YNL_PT_U32, },
	[CTRL_ATTR_MAXATTR] = { .name = "maxattr", .type = YNL_PT_U32, },
	[CTRL_ATTR_OPS] = { .name = "ops", .type = YNL_PT_NEST, .nest = &nlctrl_op_attrs_nest, },
	[CTRL_ATTR_MCAST_GROUPS] = { .name = "mcast-groups", .type = YNL_PT_NEST, .nest = &nlctrl_mcast_group_attrs_nest, },
	[CTRL_ATTR_POLICY] = { .name = "policy", .type = YNL_PT_NEST, .nest = &nlctrl_policy_attrs_nest, },
	[CTRL_ATTR_OP_POLICY] = { .name = "op-policy", .type = YNL_PT_NEST, .nest = &nlctrl_op_policy_attrs_nest, },
	[CTRL_ATTR_OP] = { .name = "op", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest nlctrl_ctrl_attrs_nest = {
	.max_attr = CTRL_ATTR_MAX,
	.table = nlctrl_ctrl_attrs_policy,
};

/* Common nested types */
void nlctrl_op_attrs_free(struct nlctrl_op_attrs *obj)
{
}

int nlctrl_op_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested, __u32 idx)
{
	struct nlctrl_op_attrs *dst = yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_OP_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u32(attr);
		} else if (type == CTRL_ATTR_OP_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void nlctrl_mcast_group_attrs_free(struct nlctrl_mcast_group_attrs *obj)
{
	free(obj->name);
}

int nlctrl_mcast_group_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested, __u32 idx)
{
	struct nlctrl_mcast_group_attrs *dst = yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_MCAST_GRP_NAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.name = len;
			dst->name = malloc(len + 1);
			memcpy(dst->name, ynl_attr_get_str(attr), len);
			dst->name[len] = 0;
		} else if (type == CTRL_ATTR_MCAST_GRP_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void nlctrl_policy_attrs_free(struct nlctrl_policy_attrs *obj)
{
}

int nlctrl_policy_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested, __u32 attr_id,
			      __u32 policy_id)
{
	struct nlctrl_policy_attrs *dst = yarg->data;
	const struct nlattr *attr;

	dst->attr_id = attr_id;
	dst->policy_id = policy_id;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL_POLICY_TYPE_ATTR_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.type = 1;
			dst->type = ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MIN_VALUE_S) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.min_value_s = 1;
			dst->min_value_s = ynl_attr_get_s64(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MAX_VALUE_S) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_value_s = 1;
			dst->max_value_s = ynl_attr_get_s64(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MIN_VALUE_U) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.min_value_u = 1;
			dst->min_value_u = ynl_attr_get_u64(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MAX_VALUE_U) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_value_u = 1;
			dst->max_value_u = ynl_attr_get_u64(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MIN_LENGTH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.min_length = 1;
			dst->min_length = ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MAX_LENGTH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_length = 1;
			dst->max_length = ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_POLICY_IDX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.policy_idx = 1;
			dst->policy_idx = ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.policy_maxtype = 1;
			dst->policy_maxtype = ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_BITFIELD32_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bitfield32_mask = 1;
			dst->bitfield32_mask = ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mask = 1;
			dst->mask = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

void nlctrl_op_policy_attrs_free(struct nlctrl_op_policy_attrs *obj)
{
}

int nlctrl_op_policy_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested, __u32 op_id)
{
	struct nlctrl_op_policy_attrs *dst = yarg->data;
	const struct nlattr *attr;

	dst->op_id = op_id;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_POLICY_DO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.do_ = 1;
			dst->do_ = ynl_attr_get_u32(attr);
		} else if (type == CTRL_ATTR_POLICY_DUMP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dump = 1;
			dst->dump = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

/* ============== CTRL_CMD_GETFAMILY ============== */
/* CTRL_CMD_GETFAMILY - do */
void nlctrl_getfamily_req_free(struct nlctrl_getfamily_req *req)
{
	free(req->family_name);
	free(req);
}

void nlctrl_getfamily_rsp_free(struct nlctrl_getfamily_rsp *rsp)
{
	free(rsp->family_name);
	free(rsp->mcast_groups);
	free(rsp->ops);
	free(rsp);
}

int nlctrl_getfamily_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr_mcast_groups;
	struct nlctrl_getfamily_rsp *dst;
	unsigned int n_mcast_groups = 0;
	const struct nlattr *attr_ops;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_ops = 0;
	int i;

	dst = yarg->data;
	parg.ys = yarg->ys;

	if (dst->mcast_groups)
		return ynl_error_parse(yarg, "attribute already present (ctrl-attrs.mcast-groups)");
	if (dst->ops)
		return ynl_error_parse(yarg, "attribute already present (ctrl-attrs.ops)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_FAMILY_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.family_id = 1;
			dst->family_id = ynl_attr_get_u16(attr);
		} else if (type == CTRL_ATTR_FAMILY_NAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.family_name = len;
			dst->family_name = malloc(len + 1);
			memcpy(dst->family_name, ynl_attr_get_str(attr), len);
			dst->family_name[len] = 0;
		} else if (type == CTRL_ATTR_HDRSIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hdrsize = 1;
			dst->hdrsize = ynl_attr_get_u32(attr);
		} else if (type == CTRL_ATTR_MAXATTR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.maxattr = 1;
			dst->maxattr = ynl_attr_get_u32(attr);
		} else if (type == CTRL_ATTR_MCAST_GROUPS) {
			const struct nlattr *attr2;

			attr_mcast_groups = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.mcast_groups++;
			}
		} else if (type == CTRL_ATTR_OPS) {
			const struct nlattr *attr2;

			attr_ops = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (ynl_attr_validate(yarg, attr2))
					return YNL_PARSE_CB_ERROR;
				dst->_count.ops++;
			}
		} else if (type == CTRL_ATTR_VERSION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.version = 1;
			dst->version = ynl_attr_get_u32(attr);
		}
	}

	if (n_mcast_groups) {
		dst->mcast_groups = calloc(n_mcast_groups, sizeof(*dst->mcast_groups));
		dst->_count.mcast_groups = n_mcast_groups;
		i = 0;
		parg.rsp_policy = &nlctrl_mcast_group_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_mcast_groups) {
			parg.data = &dst->mcast_groups[i];
			if (nlctrl_mcast_group_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}
	if (n_ops) {
		dst->ops = calloc(n_ops, sizeof(*dst->ops));
		dst->_count.ops = n_ops;
		i = 0;
		parg.rsp_policy = &nlctrl_op_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_ops) {
			parg.data = &dst->ops[i];
			if (nlctrl_op_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct nlctrl_getfamily_rsp *
nlctrl_getfamily(struct ynl_sock *ys, struct nlctrl_getfamily_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlctrl_getfamily_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, CTRL_CMD_GETFAMILY, 1);
	ys->req_policy = &nlctrl_ctrl_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &nlctrl_ctrl_attrs_nest;

	if (req->_len.family_name)
		ynl_attr_put_str(nlh, CTRL_ATTR_FAMILY_NAME, req->family_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = nlctrl_getfamily_rsp_parse;
	yrs.rsp_cmd = 1;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	nlctrl_getfamily_rsp_free(rsp);
	return NULL;
}

/* CTRL_CMD_GETFAMILY - dump */
void nlctrl_getfamily_list_free(struct nlctrl_getfamily_list *rsp)
{
	struct nlctrl_getfamily_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.family_name);
		free(rsp->obj.mcast_groups);
		free(rsp->obj.ops);
		free(rsp);
	}
}

struct nlctrl_getfamily_list *nlctrl_getfamily_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nlctrl_ctrl_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct nlctrl_getfamily_list);
	yds.cb = nlctrl_getfamily_rsp_parse;
	yds.rsp_cmd = 1;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, CTRL_CMD_GETFAMILY, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	nlctrl_getfamily_list_free(yds.first);
	return NULL;
}

/* ============== CTRL_CMD_GETPOLICY ============== */
/* CTRL_CMD_GETPOLICY - dump */
int nlctrl_getpolicy_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct nlctrl_getpolicy_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_FAMILY_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.family_id = 1;
			dst->family_id = ynl_attr_get_u16(attr);
		} else if (type == CTRL_ATTR_OP_POLICY) {
			const struct nlattr *attr_op_id;
			__u32 op_id;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.op_policy = 1;

			parg.rsp_policy = &nlctrl_op_policy_attrs_nest;
			parg.data = &dst->op_policy;
			attr_op_id = ynl_attr_data(attr);
			op_id = ynl_attr_type(attr_op_id);
			nlctrl_op_policy_attrs_parse(&parg, attr_op_id, op_id);
		} else if (type == CTRL_ATTR_POLICY) {
			const struct nlattr *attr_policy_id, *attr_attr_id;
			__u32 policy_id, attr_id;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.policy = 1;

			parg.rsp_policy = &nlctrl_policy_attrs_nest;
			parg.data = &dst->policy;
			attr_policy_id = ynl_attr_data(attr);
			policy_id = ynl_attr_type(attr_policy_id);
			attr_attr_id = ynl_attr_data(attr_policy_id);
			attr_id = ynl_attr_type(attr_attr_id);
			nlctrl_policy_attrs_parse(&parg, attr_attr_id, policy_id, attr_id);
		}
	}

	return YNL_PARSE_CB_OK;
}

void nlctrl_getpolicy_req_free(struct nlctrl_getpolicy_req *req)
{
	free(req->family_name);
	free(req);
}

void nlctrl_getpolicy_list_free(struct nlctrl_getpolicy_list *rsp)
{
	struct nlctrl_getpolicy_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp);
	}
}

struct nlctrl_getpolicy_list *
nlctrl_getpolicy_dump(struct ynl_sock *ys, struct nlctrl_getpolicy_req *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nlctrl_ctrl_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct nlctrl_getpolicy_list);
	yds.cb = nlctrl_getpolicy_rsp_parse;
	yds.rsp_cmd = CTRL_CMD_GETPOLICY;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, CTRL_CMD_GETPOLICY, 1);
	ys->req_policy = &nlctrl_ctrl_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.family_name)
		ynl_attr_put_str(nlh, CTRL_ATTR_FAMILY_NAME, req->family_name);
	if (req->_present.family_id)
		ynl_attr_put_u16(nlh, CTRL_ATTR_FAMILY_ID, req->family_id);
	if (req->_present.op)
		ynl_attr_put_u32(nlh, CTRL_ATTR_OP, req->op);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	nlctrl_getpolicy_list_free(yds.first);
	return NULL;
}

const struct ynl_family ynl_nlctrl_family =  {
	.name		= "nlctrl",
	.hdr_len	= sizeof(struct genlmsghdr),
};
