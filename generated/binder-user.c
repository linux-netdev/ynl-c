// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/binder.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "binder-user.h"
#include "ynl.h"
#include <linux/android/binder_netlink.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const binder_op_strmap[] = {
	[BINDER_CMD_REPORT] = "report",
};

const char *binder_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(binder_op_strmap))
		return NULL;
	return binder_op_strmap[op];
}

/* Policies */
const struct ynl_policy_attr binder_report_policy[BINDER_A_REPORT_MAX + 1] = {
	[BINDER_A_REPORT_ERROR] = { .name = "error", .type = YNL_PT_U32, },
	[BINDER_A_REPORT_CONTEXT] = { .name = "context", .type = YNL_PT_NUL_STR, },
	[BINDER_A_REPORT_FROM_PID] = { .name = "from-pid", .type = YNL_PT_U32, },
	[BINDER_A_REPORT_FROM_TID] = { .name = "from-tid", .type = YNL_PT_U32, },
	[BINDER_A_REPORT_TO_PID] = { .name = "to-pid", .type = YNL_PT_U32, },
	[BINDER_A_REPORT_TO_TID] = { .name = "to-tid", .type = YNL_PT_U32, },
	[BINDER_A_REPORT_IS_REPLY] = { .name = "is-reply", .type = YNL_PT_FLAG, },
	[BINDER_A_REPORT_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[BINDER_A_REPORT_CODE] = { .name = "code", .type = YNL_PT_U32, },
	[BINDER_A_REPORT_DATA_SIZE] = { .name = "data-size", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest binder_report_nest = {
	.max_attr = BINDER_A_REPORT_MAX,
	.table = binder_report_policy,
};

/* Common nested types */
/* BINDER_CMD_REPORT - event */
int binder_report_rsp_parse(const struct nlmsghdr *nlh,
			    struct ynl_parse_arg *yarg)
{
	struct binder_report_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == BINDER_A_REPORT_ERROR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.error = 1;
			dst->error = ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_CONTEXT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.context = len;
			dst->context = malloc(len + 1);
			memcpy(dst->context, ynl_attr_get_str(attr), len);
			dst->context[len] = 0;
		} else if (type == BINDER_A_REPORT_FROM_PID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.from_pid = 1;
			dst->from_pid = ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_FROM_TID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.from_tid = 1;
			dst->from_tid = ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_TO_PID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.to_pid = 1;
			dst->to_pid = ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_TO_TID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.to_tid = 1;
			dst->to_tid = ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_IS_REPLY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.is_reply = 1;
		} else if (type == BINDER_A_REPORT_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_CODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.code = 1;
			dst->code = ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_DATA_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.data_size = 1;
			dst->data_size = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

void binder_report_free(struct binder_report *rsp)
{
	free(rsp->obj.context);
	free(rsp);
}

static const struct ynl_ntf_info binder_ntf_info[] =  {
	[BINDER_CMD_REPORT] =  {
		.alloc_sz	= sizeof(struct binder_report),
		.cb		= binder_report_rsp_parse,
		.policy		= &binder_report_nest,
		.free		= (void *)binder_report_free,
	},
};

const struct ynl_family ynl_binder_family =  {
	.name		= "binder",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= binder_ntf_info,
	.ntf_info_size	= YNL_ARRAY_SIZE(binder_ntf_info),
};
