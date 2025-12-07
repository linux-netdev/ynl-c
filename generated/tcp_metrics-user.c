// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/tcp_metrics.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "tcp_metrics-user.h"
#include "ynl.h"
#include <linux/tcp_metrics.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const tcp_metrics_op_strmap[] = {
	[TCP_METRICS_CMD_GET] = "get",
	[TCP_METRICS_CMD_DEL] = "del",
};

const char *tcp_metrics_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(tcp_metrics_op_strmap))
		return NULL;
	return tcp_metrics_op_strmap[op];
}

/* Policies */
const struct ynl_policy_attr tcp_metrics_metrics_policy[TCP_METRICS_A_METRICS_MAX + 1] = {
	[TCP_METRICS_A_METRICS_RTT] = { .name = "rtt", .type = YNL_PT_U32, },
	[TCP_METRICS_A_METRICS_RTTVAR] = { .name = "rttvar", .type = YNL_PT_U32, },
	[TCP_METRICS_A_METRICS_SSTHRESH] = { .name = "ssthresh", .type = YNL_PT_U32, },
	[TCP_METRICS_A_METRICS_CWND] = { .name = "cwnd", .type = YNL_PT_U32, },
	[TCP_METRICS_A_METRICS_REODERING] = { .name = "reodering", .type = YNL_PT_U32, },
	[TCP_METRICS_A_METRICS_RTT_US] = { .name = "rtt-us", .type = YNL_PT_U32, },
	[TCP_METRICS_A_METRICS_RTTVAR_US] = { .name = "rttvar-us", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tcp_metrics_metrics_nest = {
	.max_attr = TCP_METRICS_A_METRICS_MAX,
	.table = tcp_metrics_metrics_policy,
};

const struct ynl_policy_attr tcp_metrics_policy[TCP_METRICS_ATTR_MAX + 1] = {
	[TCP_METRICS_ATTR_ADDR_IPV4] = { .name = "addr-ipv4", .type = YNL_PT_U32, },
	[TCP_METRICS_ATTR_ADDR_IPV6] = { .name = "addr-ipv6", .type = YNL_PT_BINARY,},
	[TCP_METRICS_ATTR_AGE] = { .name = "age", .type = YNL_PT_U64, },
	[TCP_METRICS_ATTR_TW_TSVAL] = { .name = "tw-tsval", .type = YNL_PT_U32, },
	[TCP_METRICS_ATTR_TW_TS_STAMP] = { .name = "tw-ts-stamp", .type = YNL_PT_U32, },
	[TCP_METRICS_ATTR_VALS] = { .name = "vals", .type = YNL_PT_NEST, .nest = &tcp_metrics_metrics_nest, },
	[TCP_METRICS_ATTR_FOPEN_MSS] = { .name = "fopen-mss", .type = YNL_PT_U16, },
	[TCP_METRICS_ATTR_FOPEN_SYN_DROPS] = { .name = "fopen-syn-drops", .type = YNL_PT_U16, },
	[TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS] = { .name = "fopen-syn-drop-ts", .type = YNL_PT_U64, },
	[TCP_METRICS_ATTR_FOPEN_COOKIE] = { .name = "fopen-cookie", .type = YNL_PT_BINARY,},
	[TCP_METRICS_ATTR_SADDR_IPV4] = { .name = "saddr-ipv4", .type = YNL_PT_U32, },
	[TCP_METRICS_ATTR_SADDR_IPV6] = { .name = "saddr-ipv6", .type = YNL_PT_BINARY,},
	[TCP_METRICS_ATTR_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tcp_metrics_nest = {
	.max_attr = TCP_METRICS_ATTR_MAX,
	.table = tcp_metrics_policy,
};

/* Common nested types */
void tcp_metrics_metrics_free(struct tcp_metrics_metrics *obj)
{
}

int tcp_metrics_metrics_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct tcp_metrics_metrics *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCP_METRICS_A_METRICS_RTT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rtt = 1;
			dst->rtt = ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_RTTVAR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rttvar = 1;
			dst->rttvar = ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_SSTHRESH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ssthresh = 1;
			dst->ssthresh = ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_CWND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cwnd = 1;
			dst->cwnd = ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_REODERING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reodering = 1;
			dst->reodering = ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_RTT_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rtt_us = 1;
			dst->rtt_us = ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_RTTVAR_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rttvar_us = 1;
			dst->rttvar_us = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

/* ============== TCP_METRICS_CMD_GET ============== */
/* TCP_METRICS_CMD_GET - do */
void tcp_metrics_get_req_free(struct tcp_metrics_get_req *req)
{
	free(req->addr_ipv6);
	free(req->saddr_ipv6);
	free(req);
}

void tcp_metrics_get_rsp_free(struct tcp_metrics_get_rsp *rsp)
{
	free(rsp->addr_ipv6);
	free(rsp->saddr_ipv6);
	tcp_metrics_metrics_free(&rsp->vals);
	free(rsp->fopen_cookie);
	free(rsp);
}

int tcp_metrics_get_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	struct tcp_metrics_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCP_METRICS_ATTR_ADDR_IPV4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.addr_ipv4 = 1;
			dst->addr_ipv4 = ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_ATTR_ADDR_IPV6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.addr_ipv6 = len;
			dst->addr_ipv6 = malloc(len);
			memcpy(dst->addr_ipv6, ynl_attr_data(attr), len);
		} else if (type == TCP_METRICS_ATTR_SADDR_IPV4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.saddr_ipv4 = 1;
			dst->saddr_ipv4 = ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_ATTR_SADDR_IPV6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.saddr_ipv6 = len;
			dst->saddr_ipv6 = malloc(len);
			memcpy(dst->saddr_ipv6, ynl_attr_data(attr), len);
		} else if (type == TCP_METRICS_ATTR_AGE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.age = 1;
			dst->age = ynl_attr_get_u64(attr);
		} else if (type == TCP_METRICS_ATTR_VALS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vals = 1;

			parg.rsp_policy = &tcp_metrics_metrics_nest;
			parg.data = &dst->vals;
			if (tcp_metrics_metrics_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCP_METRICS_ATTR_FOPEN_MSS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fopen_mss = 1;
			dst->fopen_mss = ynl_attr_get_u16(attr);
		} else if (type == TCP_METRICS_ATTR_FOPEN_SYN_DROPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fopen_syn_drops = 1;
			dst->fopen_syn_drops = ynl_attr_get_u16(attr);
		} else if (type == TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fopen_syn_drop_ts = 1;
			dst->fopen_syn_drop_ts = ynl_attr_get_u64(attr);
		} else if (type == TCP_METRICS_ATTR_FOPEN_COOKIE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.fopen_cookie = len;
			dst->fopen_cookie = malloc(len);
			memcpy(dst->fopen_cookie, ynl_attr_data(attr), len);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct tcp_metrics_get_rsp *
tcp_metrics_get(struct ynl_sock *ys, struct tcp_metrics_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct tcp_metrics_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, TCP_METRICS_CMD_GET, 1);
	ys->req_policy = &tcp_metrics_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &tcp_metrics_nest;

	if (req->_present.addr_ipv4)
		ynl_attr_put_u32(nlh, TCP_METRICS_ATTR_ADDR_IPV4, req->addr_ipv4);
	if (req->_len.addr_ipv6)
		ynl_attr_put(nlh, TCP_METRICS_ATTR_ADDR_IPV6, req->addr_ipv6, req->_len.addr_ipv6);
	if (req->_present.saddr_ipv4)
		ynl_attr_put_u32(nlh, TCP_METRICS_ATTR_SADDR_IPV4, req->saddr_ipv4);
	if (req->_len.saddr_ipv6)
		ynl_attr_put(nlh, TCP_METRICS_ATTR_SADDR_IPV6, req->saddr_ipv6, req->_len.saddr_ipv6);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = tcp_metrics_get_rsp_parse;
	yrs.rsp_cmd = TCP_METRICS_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	tcp_metrics_get_rsp_free(rsp);
	return NULL;
}

/* TCP_METRICS_CMD_GET - dump */
void tcp_metrics_get_list_free(struct tcp_metrics_get_list *rsp)
{
	struct tcp_metrics_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.addr_ipv6);
		free(rsp->obj.saddr_ipv6);
		tcp_metrics_metrics_free(&rsp->obj.vals);
		free(rsp->obj.fopen_cookie);
		free(rsp);
	}
}

struct tcp_metrics_get_list *tcp_metrics_get_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &tcp_metrics_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct tcp_metrics_get_list);
	yds.cb = tcp_metrics_get_rsp_parse;
	yds.rsp_cmd = TCP_METRICS_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, TCP_METRICS_CMD_GET, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	tcp_metrics_get_list_free(yds.first);
	return NULL;
}

/* ============== TCP_METRICS_CMD_DEL ============== */
/* TCP_METRICS_CMD_DEL - do */
void tcp_metrics_del_req_free(struct tcp_metrics_del_req *req)
{
	free(req->addr_ipv6);
	free(req->saddr_ipv6);
	free(req);
}

int tcp_metrics_del(struct ynl_sock *ys, struct tcp_metrics_del_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, TCP_METRICS_CMD_DEL, 1);
	ys->req_policy = &tcp_metrics_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.addr_ipv4)
		ynl_attr_put_u32(nlh, TCP_METRICS_ATTR_ADDR_IPV4, req->addr_ipv4);
	if (req->_len.addr_ipv6)
		ynl_attr_put(nlh, TCP_METRICS_ATTR_ADDR_IPV6, req->addr_ipv6, req->_len.addr_ipv6);
	if (req->_present.saddr_ipv4)
		ynl_attr_put_u32(nlh, TCP_METRICS_ATTR_SADDR_IPV4, req->saddr_ipv4);
	if (req->_len.saddr_ipv6)
		ynl_attr_put(nlh, TCP_METRICS_ATTR_SADDR_IPV6, req->saddr_ipv6, req->_len.saddr_ipv6);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

const struct ynl_family ynl_tcp_metrics_family =  {
	.name		= "tcp_metrics",
	.hdr_len	= sizeof(struct genlmsghdr),
};
