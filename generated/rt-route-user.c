// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-route.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "rt-route-user.h"
#include "ynl.h"
#include <linux/rtnetlink.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const rt_route_op_strmap[] = {
	[24] = "getroute",
};

const char *rt_route_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(rt_route_op_strmap))
		return NULL;
	return rt_route_op_strmap[op];
}

static const char * const rt_route_rtm_type_strmap[] = {
	[0] = "unspec",
	[1] = "unicast",
	[2] = "local",
	[3] = "broadcast",
	[4] = "anycast",
	[5] = "multicast",
	[6] = "blackhole",
	[7] = "unreachable",
	[8] = "prohibit",
	[9] = "throw",
	[10] = "nat",
	[11] = "xresolve",
};

const char *rt_route_rtm_type_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_route_rtm_type_strmap))
		return NULL;
	return rt_route_rtm_type_strmap[value];
}

/* Policies */
const struct ynl_policy_attr rt_route_metrics_policy[RTAX_MAX + 1] = {
	[RTAX_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[RTAX_LOCK] = { .name = "lock", .type = YNL_PT_U32, },
	[RTAX_MTU] = { .name = "mtu", .type = YNL_PT_U32, },
	[RTAX_WINDOW] = { .name = "window", .type = YNL_PT_U32, },
	[RTAX_RTT] = { .name = "rtt", .type = YNL_PT_U32, },
	[RTAX_RTTVAR] = { .name = "rttvar", .type = YNL_PT_U32, },
	[RTAX_SSTHRESH] = { .name = "ssthresh", .type = YNL_PT_U32, },
	[RTAX_CWND] = { .name = "cwnd", .type = YNL_PT_U32, },
	[RTAX_ADVMSS] = { .name = "advmss", .type = YNL_PT_U32, },
	[RTAX_REORDERING] = { .name = "reordering", .type = YNL_PT_U32, },
	[RTAX_HOPLIMIT] = { .name = "hoplimit", .type = YNL_PT_U32, },
	[RTAX_INITCWND] = { .name = "initcwnd", .type = YNL_PT_U32, },
	[RTAX_FEATURES] = { .name = "features", .type = YNL_PT_U32, },
	[RTAX_RTO_MIN] = { .name = "rto-min", .type = YNL_PT_U32, },
	[RTAX_INITRWND] = { .name = "initrwnd", .type = YNL_PT_U32, },
	[RTAX_QUICKACK] = { .name = "quickack", .type = YNL_PT_U32, },
	[RTAX_CC_ALGO] = { .name = "cc-algo", .type = YNL_PT_NUL_STR, },
	[RTAX_FASTOPEN_NO_COOKIE] = { .name = "fastopen-no-cookie", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_route_metrics_nest = {
	.max_attr = RTAX_MAX,
	.table = rt_route_metrics_policy,
};

const struct ynl_policy_attr rt_route_route_attrs_policy[RTA_MAX + 1] = {
	[RTA_DST] = { .name = "dst", .type = YNL_PT_BINARY,},
	[RTA_SRC] = { .name = "src", .type = YNL_PT_BINARY,},
	[RTA_IIF] = { .name = "iif", .type = YNL_PT_U32, },
	[RTA_OIF] = { .name = "oif", .type = YNL_PT_U32, },
	[RTA_GATEWAY] = { .name = "gateway", .type = YNL_PT_BINARY,},
	[RTA_PRIORITY] = { .name = "priority", .type = YNL_PT_U32, },
	[RTA_PREFSRC] = { .name = "prefsrc", .type = YNL_PT_BINARY,},
	[RTA_METRICS] = { .name = "metrics", .type = YNL_PT_NEST, .nest = &rt_route_metrics_nest, },
	[RTA_MULTIPATH] = { .name = "multipath", .type = YNL_PT_BINARY,},
	[RTA_PROTOINFO] = { .name = "protoinfo", .type = YNL_PT_BINARY,},
	[RTA_FLOW] = { .name = "flow", .type = YNL_PT_U32, },
	[RTA_CACHEINFO] = { .name = "cacheinfo", .type = YNL_PT_BINARY,},
	[RTA_SESSION] = { .name = "session", .type = YNL_PT_BINARY,},
	[RTA_MP_ALGO] = { .name = "mp-algo", .type = YNL_PT_BINARY,},
	[RTA_TABLE] = { .name = "table", .type = YNL_PT_U32, },
	[RTA_MARK] = { .name = "mark", .type = YNL_PT_U32, },
	[RTA_MFC_STATS] = { .name = "mfc-stats", .type = YNL_PT_BINARY,},
	[RTA_VIA] = { .name = "via", .type = YNL_PT_BINARY,},
	[RTA_NEWDST] = { .name = "newdst", .type = YNL_PT_BINARY,},
	[RTA_PREF] = { .name = "pref", .type = YNL_PT_U8, },
	[RTA_ENCAP_TYPE] = { .name = "encap-type", .type = YNL_PT_U16, },
	[RTA_ENCAP] = { .name = "encap", .type = YNL_PT_BINARY,},
	[RTA_EXPIRES] = { .name = "expires", .type = YNL_PT_U32, },
	[RTA_PAD] = { .name = "pad", .type = YNL_PT_BINARY,},
	[RTA_UID] = { .name = "uid", .type = YNL_PT_U32, },
	[RTA_TTL_PROPAGATE] = { .name = "ttl-propagate", .type = YNL_PT_U8, },
	[RTA_IP_PROTO] = { .name = "ip-proto", .type = YNL_PT_U8, },
	[RTA_SPORT] = { .name = "sport", .type = YNL_PT_U16, },
	[RTA_DPORT] = { .name = "dport", .type = YNL_PT_U16, },
	[RTA_NH_ID] = { .name = "nh-id", .type = YNL_PT_U32, },
	[RTA_FLOWLABEL] = { .name = "flowlabel", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest rt_route_route_attrs_nest = {
	.max_attr = RTA_MAX,
	.table = rt_route_route_attrs_policy,
};

/* Common nested types */
void rt_route_metrics_free(struct rt_route_metrics *obj)
{
	free(obj->cc_algo);
}

int rt_route_metrics_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct rt_route_metrics *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.lock)
		ynl_attr_put_u32(nlh, RTAX_LOCK, obj->lock);
	if (obj->_present.mtu)
		ynl_attr_put_u32(nlh, RTAX_MTU, obj->mtu);
	if (obj->_present.window)
		ynl_attr_put_u32(nlh, RTAX_WINDOW, obj->window);
	if (obj->_present.rtt)
		ynl_attr_put_u32(nlh, RTAX_RTT, obj->rtt);
	if (obj->_present.rttvar)
		ynl_attr_put_u32(nlh, RTAX_RTTVAR, obj->rttvar);
	if (obj->_present.ssthresh)
		ynl_attr_put_u32(nlh, RTAX_SSTHRESH, obj->ssthresh);
	if (obj->_present.cwnd)
		ynl_attr_put_u32(nlh, RTAX_CWND, obj->cwnd);
	if (obj->_present.advmss)
		ynl_attr_put_u32(nlh, RTAX_ADVMSS, obj->advmss);
	if (obj->_present.reordering)
		ynl_attr_put_u32(nlh, RTAX_REORDERING, obj->reordering);
	if (obj->_present.hoplimit)
		ynl_attr_put_u32(nlh, RTAX_HOPLIMIT, obj->hoplimit);
	if (obj->_present.initcwnd)
		ynl_attr_put_u32(nlh, RTAX_INITCWND, obj->initcwnd);
	if (obj->_present.features)
		ynl_attr_put_u32(nlh, RTAX_FEATURES, obj->features);
	if (obj->_present.rto_min)
		ynl_attr_put_u32(nlh, RTAX_RTO_MIN, obj->rto_min);
	if (obj->_present.initrwnd)
		ynl_attr_put_u32(nlh, RTAX_INITRWND, obj->initrwnd);
	if (obj->_present.quickack)
		ynl_attr_put_u32(nlh, RTAX_QUICKACK, obj->quickack);
	if (obj->_len.cc_algo)
		ynl_attr_put_str(nlh, RTAX_CC_ALGO, obj->cc_algo);
	if (obj->_present.fastopen_no_cookie)
		ynl_attr_put_u32(nlh, RTAX_FASTOPEN_NO_COOKIE, obj->fastopen_no_cookie);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_route_metrics_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	struct rt_route_metrics *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == RTAX_LOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.lock = 1;
			dst->lock = ynl_attr_get_u32(attr);
		} else if (type == RTAX_MTU) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mtu = 1;
			dst->mtu = ynl_attr_get_u32(attr);
		} else if (type == RTAX_WINDOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.window = 1;
			dst->window = ynl_attr_get_u32(attr);
		} else if (type == RTAX_RTT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rtt = 1;
			dst->rtt = ynl_attr_get_u32(attr);
		} else if (type == RTAX_RTTVAR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rttvar = 1;
			dst->rttvar = ynl_attr_get_u32(attr);
		} else if (type == RTAX_SSTHRESH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ssthresh = 1;
			dst->ssthresh = ynl_attr_get_u32(attr);
		} else if (type == RTAX_CWND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cwnd = 1;
			dst->cwnd = ynl_attr_get_u32(attr);
		} else if (type == RTAX_ADVMSS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.advmss = 1;
			dst->advmss = ynl_attr_get_u32(attr);
		} else if (type == RTAX_REORDERING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reordering = 1;
			dst->reordering = ynl_attr_get_u32(attr);
		} else if (type == RTAX_HOPLIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hoplimit = 1;
			dst->hoplimit = ynl_attr_get_u32(attr);
		} else if (type == RTAX_INITCWND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.initcwnd = 1;
			dst->initcwnd = ynl_attr_get_u32(attr);
		} else if (type == RTAX_FEATURES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.features = 1;
			dst->features = ynl_attr_get_u32(attr);
		} else if (type == RTAX_RTO_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rto_min = 1;
			dst->rto_min = ynl_attr_get_u32(attr);
		} else if (type == RTAX_INITRWND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.initrwnd = 1;
			dst->initrwnd = ynl_attr_get_u32(attr);
		} else if (type == RTAX_QUICKACK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.quickack = 1;
			dst->quickack = ynl_attr_get_u32(attr);
		} else if (type == RTAX_CC_ALGO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.cc_algo = len;
			dst->cc_algo = malloc(len + 1);
			memcpy(dst->cc_algo, ynl_attr_get_str(attr), len);
			dst->cc_algo[len] = 0;
		} else if (type == RTAX_FASTOPEN_NO_COOKIE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fastopen_no_cookie = 1;
			dst->fastopen_no_cookie = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

/* ============== RTM_GETROUTE ============== */
/* RTM_GETROUTE - do */
void rt_route_getroute_req_free(struct rt_route_getroute_req *req)
{
	free(req->src);
	free(req->dst);
	free(req);
}

void rt_route_getroute_rsp_free(struct rt_route_getroute_rsp *rsp)
{
	free(rsp->dst);
	free(rsp->src);
	free(rsp->gateway);
	free(rsp->prefsrc);
	rt_route_metrics_free(&rsp->metrics);
	free(rsp->multipath);
	free(rsp->cacheinfo);
	free(rsp->mfc_stats);
	free(rsp->via);
	free(rsp->newdst);
	free(rsp->encap);
	free(rsp->pad);
	free(rsp);
}

int rt_route_getroute_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	struct rt_route_getroute_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct rtmsg));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == RTA_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dst = len;
			dst->dst = malloc(len);
			memcpy(dst->dst, ynl_attr_data(attr), len);
		} else if (type == RTA_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.src = len;
			dst->src = malloc(len);
			memcpy(dst->src, ynl_attr_data(attr), len);
		} else if (type == RTA_IIF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.iif = 1;
			dst->iif = ynl_attr_get_u32(attr);
		} else if (type == RTA_OIF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.oif = 1;
			dst->oif = ynl_attr_get_u32(attr);
		} else if (type == RTA_GATEWAY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.gateway = len;
			dst->gateway = malloc(len);
			memcpy(dst->gateway, ynl_attr_data(attr), len);
		} else if (type == RTA_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.priority = 1;
			dst->priority = ynl_attr_get_u32(attr);
		} else if (type == RTA_PREFSRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.prefsrc = len;
			dst->prefsrc = malloc(len);
			memcpy(dst->prefsrc, ynl_attr_data(attr), len);
		} else if (type == RTA_METRICS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.metrics = 1;

			parg.rsp_policy = &rt_route_metrics_nest;
			parg.data = &dst->metrics;
			if (rt_route_metrics_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == RTA_MULTIPATH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.multipath = len;
			dst->multipath = malloc(len);
			memcpy(dst->multipath, ynl_attr_data(attr), len);
		} else if (type == RTA_FLOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flow = 1;
			dst->flow = ynl_attr_get_u32(attr);
		} else if (type == RTA_CACHEINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.cacheinfo = len;
			if (len < sizeof(struct rta_cacheinfo))
				dst->cacheinfo = calloc(1, sizeof(struct rta_cacheinfo));
			else
				dst->cacheinfo = malloc(len);
			memcpy(dst->cacheinfo, ynl_attr_data(attr), len);
		} else if (type == RTA_TABLE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.table = 1;
			dst->table = ynl_attr_get_u32(attr);
		} else if (type == RTA_MARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mark = 1;
			dst->mark = ynl_attr_get_u32(attr);
		} else if (type == RTA_MFC_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.mfc_stats = len;
			dst->mfc_stats = malloc(len);
			memcpy(dst->mfc_stats, ynl_attr_data(attr), len);
		} else if (type == RTA_VIA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.via = len;
			dst->via = malloc(len);
			memcpy(dst->via, ynl_attr_data(attr), len);
		} else if (type == RTA_NEWDST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.newdst = len;
			dst->newdst = malloc(len);
			memcpy(dst->newdst, ynl_attr_data(attr), len);
		} else if (type == RTA_PREF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pref = 1;
			dst->pref = ynl_attr_get_u8(attr);
		} else if (type == RTA_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.encap_type = 1;
			dst->encap_type = ynl_attr_get_u16(attr);
		} else if (type == RTA_ENCAP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.encap = len;
			dst->encap = malloc(len);
			memcpy(dst->encap, ynl_attr_data(attr), len);
		} else if (type == RTA_EXPIRES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.expires = 1;
			dst->expires = ynl_attr_get_u32(attr);
		} else if (type == RTA_PAD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.pad = len;
			dst->pad = malloc(len);
			memcpy(dst->pad, ynl_attr_data(attr), len);
		} else if (type == RTA_UID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.uid = 1;
			dst->uid = ynl_attr_get_u32(attr);
		} else if (type == RTA_TTL_PROPAGATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ttl_propagate = 1;
			dst->ttl_propagate = ynl_attr_get_u8(attr);
		} else if (type == RTA_IP_PROTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ip_proto = 1;
			dst->ip_proto = ynl_attr_get_u8(attr);
		} else if (type == RTA_SPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sport = 1;
			dst->sport = ynl_attr_get_u16(attr);
		} else if (type == RTA_DPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dport = 1;
			dst->dport = ynl_attr_get_u16(attr);
		} else if (type == RTA_NH_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nh_id = 1;
			dst->nh_id = ynl_attr_get_u32(attr);
		} else if (type == RTA_FLOWLABEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flowlabel = 1;
			dst->flowlabel = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct rt_route_getroute_rsp *
rt_route_getroute(struct ynl_sock *ys, struct rt_route_getroute_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct rt_route_getroute_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETROUTE, req->_nlmsg_flags);
	ys->req_policy = &rt_route_route_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &rt_route_route_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.src)
		ynl_attr_put(nlh, RTA_SRC, req->src, req->_len.src);
	if (req->_len.dst)
		ynl_attr_put(nlh, RTA_DST, req->dst, req->_len.dst);
	if (req->_present.iif)
		ynl_attr_put_u32(nlh, RTA_IIF, req->iif);
	if (req->_present.oif)
		ynl_attr_put_u32(nlh, RTA_OIF, req->oif);
	if (req->_present.ip_proto)
		ynl_attr_put_u8(nlh, RTA_IP_PROTO, req->ip_proto);
	if (req->_present.sport)
		ynl_attr_put_u16(nlh, RTA_SPORT, req->sport);
	if (req->_present.dport)
		ynl_attr_put_u16(nlh, RTA_DPORT, req->dport);
	if (req->_present.mark)
		ynl_attr_put_u32(nlh, RTA_MARK, req->mark);
	if (req->_present.uid)
		ynl_attr_put_u32(nlh, RTA_UID, req->uid);
	if (req->_present.flowlabel)
		ynl_attr_put_u32(nlh, RTA_FLOWLABEL, req->flowlabel);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = rt_route_getroute_rsp_parse;
	yrs.rsp_cmd = 24;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	rt_route_getroute_rsp_free(rsp);
	return NULL;
}

/* RTM_GETROUTE - dump */
void rt_route_getroute_req_dump_free(struct rt_route_getroute_req_dump *req)
{
	free(req);
}

void rt_route_getroute_list_free(struct rt_route_getroute_list *rsp)
{
	struct rt_route_getroute_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.dst);
		free(rsp->obj.src);
		free(rsp->obj.gateway);
		free(rsp->obj.prefsrc);
		rt_route_metrics_free(&rsp->obj.metrics);
		free(rsp->obj.multipath);
		free(rsp->obj.cacheinfo);
		free(rsp->obj.mfc_stats);
		free(rsp->obj.via);
		free(rsp->obj.newdst);
		free(rsp->obj.encap);
		free(rsp->obj.pad);
		free(rsp);
	}
}

struct rt_route_getroute_list *
rt_route_getroute_dump(struct ynl_sock *ys,
		       struct rt_route_getroute_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_route_route_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct rt_route_getroute_list);
	yds.cb = rt_route_getroute_rsp_parse;
	yds.rsp_cmd = 24;

	nlh = ynl_msg_start_dump(ys, RTM_GETROUTE);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &rt_route_route_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	rt_route_getroute_list_free(yds.first);
	return NULL;
}

/* ============== RTM_NEWROUTE ============== */
/* RTM_NEWROUTE - do */
void rt_route_newroute_req_free(struct rt_route_newroute_req *req)
{
	free(req->dst);
	free(req->src);
	free(req->gateway);
	free(req->prefsrc);
	rt_route_metrics_free(&req->metrics);
	free(req->multipath);
	free(req->cacheinfo);
	free(req->mfc_stats);
	free(req->via);
	free(req->newdst);
	free(req->encap);
	free(req->pad);
	free(req);
}

int rt_route_newroute(struct ynl_sock *ys, struct rt_route_newroute_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWROUTE, req->_nlmsg_flags);
	ys->req_policy = &rt_route_route_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.dst)
		ynl_attr_put(nlh, RTA_DST, req->dst, req->_len.dst);
	if (req->_len.src)
		ynl_attr_put(nlh, RTA_SRC, req->src, req->_len.src);
	if (req->_present.iif)
		ynl_attr_put_u32(nlh, RTA_IIF, req->iif);
	if (req->_present.oif)
		ynl_attr_put_u32(nlh, RTA_OIF, req->oif);
	if (req->_len.gateway)
		ynl_attr_put(nlh, RTA_GATEWAY, req->gateway, req->_len.gateway);
	if (req->_present.priority)
		ynl_attr_put_u32(nlh, RTA_PRIORITY, req->priority);
	if (req->_len.prefsrc)
		ynl_attr_put(nlh, RTA_PREFSRC, req->prefsrc, req->_len.prefsrc);
	if (req->_present.metrics)
		rt_route_metrics_put(nlh, RTA_METRICS, &req->metrics);
	if (req->_len.multipath)
		ynl_attr_put(nlh, RTA_MULTIPATH, req->multipath, req->_len.multipath);
	if (req->_present.flow)
		ynl_attr_put_u32(nlh, RTA_FLOW, req->flow);
	if (req->_len.cacheinfo)
		ynl_attr_put(nlh, RTA_CACHEINFO, req->cacheinfo, req->_len.cacheinfo);
	if (req->_present.table)
		ynl_attr_put_u32(nlh, RTA_TABLE, req->table);
	if (req->_present.mark)
		ynl_attr_put_u32(nlh, RTA_MARK, req->mark);
	if (req->_len.mfc_stats)
		ynl_attr_put(nlh, RTA_MFC_STATS, req->mfc_stats, req->_len.mfc_stats);
	if (req->_len.via)
		ynl_attr_put(nlh, RTA_VIA, req->via, req->_len.via);
	if (req->_len.newdst)
		ynl_attr_put(nlh, RTA_NEWDST, req->newdst, req->_len.newdst);
	if (req->_present.pref)
		ynl_attr_put_u8(nlh, RTA_PREF, req->pref);
	if (req->_present.encap_type)
		ynl_attr_put_u16(nlh, RTA_ENCAP_TYPE, req->encap_type);
	if (req->_len.encap)
		ynl_attr_put(nlh, RTA_ENCAP, req->encap, req->_len.encap);
	if (req->_present.expires)
		ynl_attr_put_u32(nlh, RTA_EXPIRES, req->expires);
	if (req->_len.pad)
		ynl_attr_put(nlh, RTA_PAD, req->pad, req->_len.pad);
	if (req->_present.uid)
		ynl_attr_put_u32(nlh, RTA_UID, req->uid);
	if (req->_present.ttl_propagate)
		ynl_attr_put_u8(nlh, RTA_TTL_PROPAGATE, req->ttl_propagate);
	if (req->_present.ip_proto)
		ynl_attr_put_u8(nlh, RTA_IP_PROTO, req->ip_proto);
	if (req->_present.sport)
		ynl_attr_put_u16(nlh, RTA_SPORT, req->sport);
	if (req->_present.dport)
		ynl_attr_put_u16(nlh, RTA_DPORT, req->dport);
	if (req->_present.nh_id)
		ynl_attr_put_u32(nlh, RTA_NH_ID, req->nh_id);
	if (req->_present.flowlabel)
		ynl_attr_put_u32(nlh, RTA_FLOWLABEL, req->flowlabel);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_DELROUTE ============== */
/* RTM_DELROUTE - do */
void rt_route_delroute_req_free(struct rt_route_delroute_req *req)
{
	free(req->dst);
	free(req->src);
	free(req->gateway);
	free(req->prefsrc);
	rt_route_metrics_free(&req->metrics);
	free(req->multipath);
	free(req->cacheinfo);
	free(req->mfc_stats);
	free(req->via);
	free(req->newdst);
	free(req->encap);
	free(req->pad);
	free(req);
}

int rt_route_delroute(struct ynl_sock *ys, struct rt_route_delroute_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELROUTE, req->_nlmsg_flags);
	ys->req_policy = &rt_route_route_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.dst)
		ynl_attr_put(nlh, RTA_DST, req->dst, req->_len.dst);
	if (req->_len.src)
		ynl_attr_put(nlh, RTA_SRC, req->src, req->_len.src);
	if (req->_present.iif)
		ynl_attr_put_u32(nlh, RTA_IIF, req->iif);
	if (req->_present.oif)
		ynl_attr_put_u32(nlh, RTA_OIF, req->oif);
	if (req->_len.gateway)
		ynl_attr_put(nlh, RTA_GATEWAY, req->gateway, req->_len.gateway);
	if (req->_present.priority)
		ynl_attr_put_u32(nlh, RTA_PRIORITY, req->priority);
	if (req->_len.prefsrc)
		ynl_attr_put(nlh, RTA_PREFSRC, req->prefsrc, req->_len.prefsrc);
	if (req->_present.metrics)
		rt_route_metrics_put(nlh, RTA_METRICS, &req->metrics);
	if (req->_len.multipath)
		ynl_attr_put(nlh, RTA_MULTIPATH, req->multipath, req->_len.multipath);
	if (req->_present.flow)
		ynl_attr_put_u32(nlh, RTA_FLOW, req->flow);
	if (req->_len.cacheinfo)
		ynl_attr_put(nlh, RTA_CACHEINFO, req->cacheinfo, req->_len.cacheinfo);
	if (req->_present.table)
		ynl_attr_put_u32(nlh, RTA_TABLE, req->table);
	if (req->_present.mark)
		ynl_attr_put_u32(nlh, RTA_MARK, req->mark);
	if (req->_len.mfc_stats)
		ynl_attr_put(nlh, RTA_MFC_STATS, req->mfc_stats, req->_len.mfc_stats);
	if (req->_len.via)
		ynl_attr_put(nlh, RTA_VIA, req->via, req->_len.via);
	if (req->_len.newdst)
		ynl_attr_put(nlh, RTA_NEWDST, req->newdst, req->_len.newdst);
	if (req->_present.pref)
		ynl_attr_put_u8(nlh, RTA_PREF, req->pref);
	if (req->_present.encap_type)
		ynl_attr_put_u16(nlh, RTA_ENCAP_TYPE, req->encap_type);
	if (req->_len.encap)
		ynl_attr_put(nlh, RTA_ENCAP, req->encap, req->_len.encap);
	if (req->_present.expires)
		ynl_attr_put_u32(nlh, RTA_EXPIRES, req->expires);
	if (req->_len.pad)
		ynl_attr_put(nlh, RTA_PAD, req->pad, req->_len.pad);
	if (req->_present.uid)
		ynl_attr_put_u32(nlh, RTA_UID, req->uid);
	if (req->_present.ttl_propagate)
		ynl_attr_put_u8(nlh, RTA_TTL_PROPAGATE, req->ttl_propagate);
	if (req->_present.ip_proto)
		ynl_attr_put_u8(nlh, RTA_IP_PROTO, req->ip_proto);
	if (req->_present.sport)
		ynl_attr_put_u16(nlh, RTA_SPORT, req->sport);
	if (req->_present.dport)
		ynl_attr_put_u16(nlh, RTA_DPORT, req->dport);
	if (req->_present.nh_id)
		ynl_attr_put_u32(nlh, RTA_NH_ID, req->nh_id);
	if (req->_present.flowlabel)
		ynl_attr_put_u32(nlh, RTA_FLOWLABEL, req->flowlabel);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

const struct ynl_family ynl_rt_route_family =  {
	.name		= "rt_route",
	.is_classic	= true,
	.classic_id	= 0,
	.hdr_len	= sizeof(struct rtmsg),
};
