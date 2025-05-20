// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-rule.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "rt-rule-user.h"
#include "ynl.h"
#include <linux/fib_rules.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const rt_rule_op_strmap[] = {
	// skip "newrule-ntf", duplicate reply value
	[33] = "delrule-ntf",
	[32] = "getrule",
};

const char *rt_rule_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(rt_rule_op_strmap))
		return NULL;
	return rt_rule_op_strmap[op];
}

static const char * const rt_rule_fr_act_strmap[] = {
	[0] = "unspec",
	[1] = "to-tbl",
	[2] = "goto",
	[3] = "nop",
	[4] = "res3",
	[5] = "res4",
	[6] = "blackhole",
	[7] = "unreachable",
	[8] = "prohibit",
};

const char *rt_rule_fr_act_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_rule_fr_act_strmap))
		return NULL;
	return rt_rule_fr_act_strmap[value];
}

/* Policies */
const struct ynl_policy_attr rt_rule_fib_rule_attrs_policy[FRA_MAX + 1] = {
	[FRA_DST] = { .name = "dst", .type = YNL_PT_U32, },
	[FRA_SRC] = { .name = "src", .type = YNL_PT_U32, },
	[FRA_IIFNAME] = { .name = "iifname", .type = YNL_PT_NUL_STR, },
	[FRA_GOTO] = { .name = "goto", .type = YNL_PT_U32, },
	[FRA_UNUSED2] = { .name = "unused2", .type = YNL_PT_IGNORE, },
	[FRA_PRIORITY] = { .name = "priority", .type = YNL_PT_U32, },
	[FRA_UNUSED3] = { .name = "unused3", .type = YNL_PT_IGNORE, },
	[FRA_UNUSED4] = { .name = "unused4", .type = YNL_PT_IGNORE, },
	[FRA_UNUSED5] = { .name = "unused5", .type = YNL_PT_IGNORE, },
	[FRA_FWMARK] = { .name = "fwmark", .type = YNL_PT_U32, },
	[FRA_FLOW] = { .name = "flow", .type = YNL_PT_U32, },
	[FRA_TUN_ID] = { .name = "tun-id", .type = YNL_PT_U64, },
	[FRA_SUPPRESS_IFGROUP] = { .name = "suppress-ifgroup", .type = YNL_PT_U32, },
	[FRA_SUPPRESS_PREFIXLEN] = { .name = "suppress-prefixlen", .type = YNL_PT_U32, },
	[FRA_TABLE] = { .name = "table", .type = YNL_PT_U32, },
	[FRA_FWMASK] = { .name = "fwmask", .type = YNL_PT_U32, },
	[FRA_OIFNAME] = { .name = "oifname", .type = YNL_PT_NUL_STR, },
	[FRA_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[FRA_L3MDEV] = { .name = "l3mdev", .type = YNL_PT_U8, },
	[FRA_UID_RANGE] = { .name = "uid-range", .type = YNL_PT_BINARY,},
	[FRA_PROTOCOL] = { .name = "protocol", .type = YNL_PT_U8, },
	[FRA_IP_PROTO] = { .name = "ip-proto", .type = YNL_PT_U8, },
	[FRA_SPORT_RANGE] = { .name = "sport-range", .type = YNL_PT_BINARY,},
	[FRA_DPORT_RANGE] = { .name = "dport-range", .type = YNL_PT_BINARY,},
	[FRA_DSCP] = { .name = "dscp", .type = YNL_PT_U8, },
	[FRA_FLOWLABEL] = { .name = "flowlabel", .type = YNL_PT_U32, },
	[FRA_FLOWLABEL_MASK] = { .name = "flowlabel-mask", .type = YNL_PT_U32, },
	[FRA_SPORT_MASK] = { .name = "sport-mask", .type = YNL_PT_U16, },
	[FRA_DPORT_MASK] = { .name = "dport-mask", .type = YNL_PT_U16, },
	[FRA_DSCP_MASK] = { .name = "dscp-mask", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest rt_rule_fib_rule_attrs_nest = {
	.max_attr = FRA_MAX,
	.table = rt_rule_fib_rule_attrs_policy,
};

/* Common nested types */
/* ============== RTM_NEWRULE ============== */
/* RTM_NEWRULE - do */
void rt_rule_newrule_req_free(struct rt_rule_newrule_req *req)
{
	free(req->iifname);
	free(req->oifname);
	free(req->uid_range);
	free(req->sport_range);
	free(req->dport_range);
	free(req);
}

int rt_rule_newrule(struct ynl_sock *ys, struct rt_rule_newrule_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWRULE, req->_nlmsg_flags);
	ys->req_policy = &rt_rule_fib_rule_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.iifname)
		ynl_attr_put_str(nlh, FRA_IIFNAME, req->iifname);
	if (req->_len.oifname)
		ynl_attr_put_str(nlh, FRA_OIFNAME, req->oifname);
	if (req->_present.priority)
		ynl_attr_put_u32(nlh, FRA_PRIORITY, req->priority);
	if (req->_present.fwmark)
		ynl_attr_put_u32(nlh, FRA_FWMARK, req->fwmark);
	if (req->_present.flow)
		ynl_attr_put_u32(nlh, FRA_FLOW, req->flow);
	if (req->_present.tun_id)
		ynl_attr_put_u64(nlh, FRA_TUN_ID, req->tun_id);
	if (req->_present.fwmask)
		ynl_attr_put_u32(nlh, FRA_FWMASK, req->fwmask);
	if (req->_present.table)
		ynl_attr_put_u32(nlh, FRA_TABLE, req->table);
	if (req->_present.suppress_prefixlen)
		ynl_attr_put_u32(nlh, FRA_SUPPRESS_PREFIXLEN, req->suppress_prefixlen);
	if (req->_present.suppress_ifgroup)
		ynl_attr_put_u32(nlh, FRA_SUPPRESS_IFGROUP, req->suppress_ifgroup);
	if (req->_present.goto_)
		ynl_attr_put_u32(nlh, FRA_GOTO, req->goto_);
	if (req->_present.l3mdev)
		ynl_attr_put_u8(nlh, FRA_L3MDEV, req->l3mdev);
	if (req->_len.uid_range)
		ynl_attr_put(nlh, FRA_UID_RANGE, req->uid_range, req->_len.uid_range);
	if (req->_present.protocol)
		ynl_attr_put_u8(nlh, FRA_PROTOCOL, req->protocol);
	if (req->_present.ip_proto)
		ynl_attr_put_u8(nlh, FRA_IP_PROTO, req->ip_proto);
	if (req->_len.sport_range)
		ynl_attr_put(nlh, FRA_SPORT_RANGE, req->sport_range, req->_len.sport_range);
	if (req->_len.dport_range)
		ynl_attr_put(nlh, FRA_DPORT_RANGE, req->dport_range, req->_len.dport_range);
	if (req->_present.dscp)
		ynl_attr_put_u8(nlh, FRA_DSCP, req->dscp);
	if (req->_present.flowlabel)
		ynl_attr_put_u32(nlh, FRA_FLOWLABEL, req->flowlabel);
	if (req->_present.flowlabel_mask)
		ynl_attr_put_u32(nlh, FRA_FLOWLABEL_MASK, req->flowlabel_mask);
	if (req->_present.sport_mask)
		ynl_attr_put_u16(nlh, FRA_SPORT_MASK, req->sport_mask);
	if (req->_present.dport_mask)
		ynl_attr_put_u16(nlh, FRA_DPORT_MASK, req->dport_mask);
	if (req->_present.dscp_mask)
		ynl_attr_put_u8(nlh, FRA_DSCP_MASK, req->dscp_mask);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_DELRULE ============== */
/* RTM_DELRULE - do */
void rt_rule_delrule_req_free(struct rt_rule_delrule_req *req)
{
	free(req->iifname);
	free(req->oifname);
	free(req->uid_range);
	free(req->sport_range);
	free(req->dport_range);
	free(req);
}

int rt_rule_delrule(struct ynl_sock *ys, struct rt_rule_delrule_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELRULE, req->_nlmsg_flags);
	ys->req_policy = &rt_rule_fib_rule_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.iifname)
		ynl_attr_put_str(nlh, FRA_IIFNAME, req->iifname);
	if (req->_len.oifname)
		ynl_attr_put_str(nlh, FRA_OIFNAME, req->oifname);
	if (req->_present.priority)
		ynl_attr_put_u32(nlh, FRA_PRIORITY, req->priority);
	if (req->_present.fwmark)
		ynl_attr_put_u32(nlh, FRA_FWMARK, req->fwmark);
	if (req->_present.flow)
		ynl_attr_put_u32(nlh, FRA_FLOW, req->flow);
	if (req->_present.tun_id)
		ynl_attr_put_u64(nlh, FRA_TUN_ID, req->tun_id);
	if (req->_present.fwmask)
		ynl_attr_put_u32(nlh, FRA_FWMASK, req->fwmask);
	if (req->_present.table)
		ynl_attr_put_u32(nlh, FRA_TABLE, req->table);
	if (req->_present.suppress_prefixlen)
		ynl_attr_put_u32(nlh, FRA_SUPPRESS_PREFIXLEN, req->suppress_prefixlen);
	if (req->_present.suppress_ifgroup)
		ynl_attr_put_u32(nlh, FRA_SUPPRESS_IFGROUP, req->suppress_ifgroup);
	if (req->_present.goto_)
		ynl_attr_put_u32(nlh, FRA_GOTO, req->goto_);
	if (req->_present.l3mdev)
		ynl_attr_put_u8(nlh, FRA_L3MDEV, req->l3mdev);
	if (req->_len.uid_range)
		ynl_attr_put(nlh, FRA_UID_RANGE, req->uid_range, req->_len.uid_range);
	if (req->_present.protocol)
		ynl_attr_put_u8(nlh, FRA_PROTOCOL, req->protocol);
	if (req->_present.ip_proto)
		ynl_attr_put_u8(nlh, FRA_IP_PROTO, req->ip_proto);
	if (req->_len.sport_range)
		ynl_attr_put(nlh, FRA_SPORT_RANGE, req->sport_range, req->_len.sport_range);
	if (req->_len.dport_range)
		ynl_attr_put(nlh, FRA_DPORT_RANGE, req->dport_range, req->_len.dport_range);
	if (req->_present.dscp)
		ynl_attr_put_u8(nlh, FRA_DSCP, req->dscp);
	if (req->_present.flowlabel)
		ynl_attr_put_u32(nlh, FRA_FLOWLABEL, req->flowlabel);
	if (req->_present.flowlabel_mask)
		ynl_attr_put_u32(nlh, FRA_FLOWLABEL_MASK, req->flowlabel_mask);
	if (req->_present.sport_mask)
		ynl_attr_put_u16(nlh, FRA_SPORT_MASK, req->sport_mask);
	if (req->_present.dport_mask)
		ynl_attr_put_u16(nlh, FRA_DPORT_MASK, req->dport_mask);
	if (req->_present.dscp_mask)
		ynl_attr_put_u8(nlh, FRA_DSCP_MASK, req->dscp_mask);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_GETRULE ============== */
/* RTM_GETRULE - dump */
int rt_rule_getrule_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	struct rt_rule_getrule_rsp *dst;
	const struct nlattr *attr;
	void *hdr;

	dst = yarg->data;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct fib_rule_hdr));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == FRA_IIFNAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.iifname = len;
			dst->iifname = malloc(len + 1);
			memcpy(dst->iifname, ynl_attr_get_str(attr), len);
			dst->iifname[len] = 0;
		} else if (type == FRA_OIFNAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.oifname = len;
			dst->oifname = malloc(len + 1);
			memcpy(dst->oifname, ynl_attr_get_str(attr), len);
			dst->oifname[len] = 0;
		} else if (type == FRA_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.priority = 1;
			dst->priority = ynl_attr_get_u32(attr);
		} else if (type == FRA_FWMARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmark = 1;
			dst->fwmark = ynl_attr_get_u32(attr);
		} else if (type == FRA_FLOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flow = 1;
			dst->flow = ynl_attr_get_u32(attr);
		} else if (type == FRA_TUN_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tun_id = 1;
			dst->tun_id = ynl_attr_get_u64(attr);
		} else if (type == FRA_FWMASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmask = 1;
			dst->fwmask = ynl_attr_get_u32(attr);
		} else if (type == FRA_TABLE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.table = 1;
			dst->table = ynl_attr_get_u32(attr);
		} else if (type == FRA_SUPPRESS_PREFIXLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.suppress_prefixlen = 1;
			dst->suppress_prefixlen = ynl_attr_get_u32(attr);
		} else if (type == FRA_SUPPRESS_IFGROUP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.suppress_ifgroup = 1;
			dst->suppress_ifgroup = ynl_attr_get_u32(attr);
		} else if (type == FRA_GOTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.goto_ = 1;
			dst->goto_ = ynl_attr_get_u32(attr);
		} else if (type == FRA_L3MDEV) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.l3mdev = 1;
			dst->l3mdev = ynl_attr_get_u8(attr);
		} else if (type == FRA_UID_RANGE) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.uid_range = len;
			if (len < sizeof(struct fib_rule_uid_range))
				dst->uid_range = calloc(1, sizeof(struct fib_rule_uid_range));
			else
				dst->uid_range = malloc(len);
			memcpy(dst->uid_range, ynl_attr_data(attr), len);
		} else if (type == FRA_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.protocol = 1;
			dst->protocol = ynl_attr_get_u8(attr);
		} else if (type == FRA_IP_PROTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ip_proto = 1;
			dst->ip_proto = ynl_attr_get_u8(attr);
		} else if (type == FRA_SPORT_RANGE) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.sport_range = len;
			if (len < sizeof(struct fib_rule_port_range))
				dst->sport_range = calloc(1, sizeof(struct fib_rule_port_range));
			else
				dst->sport_range = malloc(len);
			memcpy(dst->sport_range, ynl_attr_data(attr), len);
		} else if (type == FRA_DPORT_RANGE) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dport_range = len;
			if (len < sizeof(struct fib_rule_port_range))
				dst->dport_range = calloc(1, sizeof(struct fib_rule_port_range));
			else
				dst->dport_range = malloc(len);
			memcpy(dst->dport_range, ynl_attr_data(attr), len);
		} else if (type == FRA_DSCP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dscp = 1;
			dst->dscp = ynl_attr_get_u8(attr);
		} else if (type == FRA_FLOWLABEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flowlabel = 1;
			dst->flowlabel = ynl_attr_get_u32(attr);
		} else if (type == FRA_FLOWLABEL_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flowlabel_mask = 1;
			dst->flowlabel_mask = ynl_attr_get_u32(attr);
		} else if (type == FRA_SPORT_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sport_mask = 1;
			dst->sport_mask = ynl_attr_get_u16(attr);
		} else if (type == FRA_DPORT_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dport_mask = 1;
			dst->dport_mask = ynl_attr_get_u16(attr);
		} else if (type == FRA_DSCP_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dscp_mask = 1;
			dst->dscp_mask = ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

void rt_rule_getrule_req_free(struct rt_rule_getrule_req *req)
{
	free(req);
}

void rt_rule_getrule_list_free(struct rt_rule_getrule_list *rsp)
{
	struct rt_rule_getrule_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.iifname);
		free(rsp->obj.oifname);
		free(rsp->obj.uid_range);
		free(rsp->obj.sport_range);
		free(rsp->obj.dport_range);
		free(rsp);
	}
}

struct rt_rule_getrule_list *
rt_rule_getrule_dump(struct ynl_sock *ys, struct rt_rule_getrule_req *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_rule_fib_rule_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct rt_rule_getrule_list);
	yds.cb = rt_rule_getrule_rsp_parse;
	yds.rsp_cmd = 32;

	nlh = ynl_msg_start_dump(ys, RTM_GETRULE);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &rt_rule_fib_rule_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	rt_rule_getrule_list_free(yds.first);
	return NULL;
}

/* RTM_GETRULE - notify */
void rt_rule_getrule_ntf_free(struct rt_rule_getrule_ntf *rsp)
{
	free(rsp->obj.iifname);
	free(rsp->obj.oifname);
	free(rsp->obj.uid_range);
	free(rsp->obj.sport_range);
	free(rsp->obj.dport_range);
	free(rsp);
}

static const struct ynl_ntf_info rt_rule_ntf_info[] =  {
	[RTM_NEWRULE] =  {
		.alloc_sz	= sizeof(struct rt_rule_getrule_ntf),
		.cb		= rt_rule_getrule_rsp_parse,
		.policy		= &rt_rule_fib_rule_attrs_nest,
		.free		= (void *)rt_rule_getrule_ntf_free,
	},
	[RTM_DELRULE] =  {
		.alloc_sz	= sizeof(struct rt_rule_getrule_ntf),
		.cb		= rt_rule_getrule_rsp_parse,
		.policy		= &rt_rule_fib_rule_attrs_nest,
		.free		= (void *)rt_rule_getrule_ntf_free,
	},
};

const struct ynl_family ynl_rt_rule_family =  {
	.name		= "rt_rule",
	.is_classic	= true,
	.classic_id	= 0,
	.hdr_len	= sizeof(struct fib_rule_hdr),
	.ntf_info	= rt_rule_ntf_info,
	.ntf_info_size	= YNL_ARRAY_SIZE(rt_rule_ntf_info),
};
