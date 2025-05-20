// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-neigh.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "rt-neigh-user.h"
#include "ynl.h"
#include <linux/rtnetlink.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const rt_neigh_op_strmap[] = {
	[29] = "delneigh-ntf",
	// skip "getneigh", duplicate reply value
	[28] = "newneigh-ntf",
	[64] = "getneightbl",
};

const char *rt_neigh_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(rt_neigh_op_strmap))
		return NULL;
	return rt_neigh_op_strmap[op];
}

static const char * const rt_neigh_nud_state_strmap[] = {
	[0] = "incomplete",
	[1] = "reachable",
	[2] = "stale",
	[3] = "delay",
	[4] = "probe",
	[5] = "failed",
	[6] = "noarp",
	[7] = "permanent",
};

const char *rt_neigh_nud_state_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_neigh_nud_state_strmap))
		return NULL;
	return rt_neigh_nud_state_strmap[value];
}

static const char * const rt_neigh_ntf_flags_strmap[] = {
	[0] = "use",
	[1] = "self",
	[2] = "master",
	[3] = "proxy",
	[4] = "ext-learned",
	[5] = "offloaded",
	[6] = "sticky",
	[7] = "router",
};

const char *rt_neigh_ntf_flags_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_neigh_ntf_flags_strmap))
		return NULL;
	return rt_neigh_ntf_flags_strmap[value];
}

static const char * const rt_neigh_ntf_ext_flags_strmap[] = {
	[0] = "managed",
	[1] = "locked",
};

const char *rt_neigh_ntf_ext_flags_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_neigh_ntf_ext_flags_strmap))
		return NULL;
	return rt_neigh_ntf_ext_flags_strmap[value];
}

static const char * const rt_neigh_rtm_type_strmap[] = {
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

const char *rt_neigh_rtm_type_str(int value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_neigh_rtm_type_strmap))
		return NULL;
	return rt_neigh_rtm_type_strmap[value];
}

/* Policies */
const struct ynl_policy_attr rt_neigh_ndtpa_attrs_policy[NDTPA_MAX + 1] = {
	[NDTPA_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[NDTPA_REFCNT] = { .name = "refcnt", .type = YNL_PT_U32, },
	[NDTPA_REACHABLE_TIME] = { .name = "reachable-time", .type = YNL_PT_U64, },
	[NDTPA_BASE_REACHABLE_TIME] = { .name = "base-reachable-time", .type = YNL_PT_U64, },
	[NDTPA_RETRANS_TIME] = { .name = "retrans-time", .type = YNL_PT_U64, },
	[NDTPA_GC_STALETIME] = { .name = "gc-staletime", .type = YNL_PT_U64, },
	[NDTPA_DELAY_PROBE_TIME] = { .name = "delay-probe-time", .type = YNL_PT_U64, },
	[NDTPA_QUEUE_LEN] = { .name = "queue-len", .type = YNL_PT_U32, },
	[NDTPA_APP_PROBES] = { .name = "app-probes", .type = YNL_PT_U32, },
	[NDTPA_UCAST_PROBES] = { .name = "ucast-probes", .type = YNL_PT_U32, },
	[NDTPA_MCAST_PROBES] = { .name = "mcast-probes", .type = YNL_PT_U32, },
	[NDTPA_ANYCAST_DELAY] = { .name = "anycast-delay", .type = YNL_PT_U64, },
	[NDTPA_PROXY_DELAY] = { .name = "proxy-delay", .type = YNL_PT_U64, },
	[NDTPA_PROXY_QLEN] = { .name = "proxy-qlen", .type = YNL_PT_U32, },
	[NDTPA_LOCKTIME] = { .name = "locktime", .type = YNL_PT_U64, },
	[NDTPA_QUEUE_LENBYTES] = { .name = "queue-lenbytes", .type = YNL_PT_U32, },
	[NDTPA_MCAST_REPROBES] = { .name = "mcast-reprobes", .type = YNL_PT_U32, },
	[NDTPA_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[NDTPA_INTERVAL_PROBE_TIME_MS] = { .name = "interval-probe-time-ms", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest rt_neigh_ndtpa_attrs_nest = {
	.max_attr = NDTPA_MAX,
	.table = rt_neigh_ndtpa_attrs_policy,
};

const struct ynl_policy_attr rt_neigh_neighbour_attrs_policy[NDA_MAX + 1] = {
	[NDA_UNSPEC] = { .name = "unspec", .type = YNL_PT_BINARY,},
	[NDA_DST] = { .name = "dst", .type = YNL_PT_BINARY,},
	[NDA_LLADDR] = { .name = "lladdr", .type = YNL_PT_BINARY,},
	[NDA_CACHEINFO] = { .name = "cacheinfo", .type = YNL_PT_BINARY,},
	[NDA_PROBES] = { .name = "probes", .type = YNL_PT_U32, },
	[NDA_VLAN] = { .name = "vlan", .type = YNL_PT_U16, },
	[NDA_PORT] = { .name = "port", .type = YNL_PT_U16, },
	[NDA_VNI] = { .name = "vni", .type = YNL_PT_U32, },
	[NDA_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[NDA_MASTER] = { .name = "master", .type = YNL_PT_U32, },
	[NDA_LINK_NETNSID] = { .name = "link-netnsid", .type = YNL_PT_U32, },
	[NDA_SRC_VNI] = { .name = "src-vni", .type = YNL_PT_U32, },
	[NDA_PROTOCOL] = { .name = "protocol", .type = YNL_PT_U8, },
	[NDA_NH_ID] = { .name = "nh-id", .type = YNL_PT_U32, },
	[NDA_FDB_EXT_ATTRS] = { .name = "fdb-ext-attrs", .type = YNL_PT_BINARY,},
	[NDA_FLAGS_EXT] = { .name = "flags-ext", .type = YNL_PT_U32, },
	[NDA_NDM_STATE_MASK] = { .name = "ndm-state-mask", .type = YNL_PT_U16, },
	[NDA_NDM_FLAGS_MASK] = { .name = "ndm-flags-mask", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest rt_neigh_neighbour_attrs_nest = {
	.max_attr = NDA_MAX,
	.table = rt_neigh_neighbour_attrs_policy,
};

const struct ynl_policy_attr rt_neigh_ndt_attrs_policy[NDTA_MAX + 1] = {
	[NDTA_NAME] = { .name = "name", .type = YNL_PT_NUL_STR, },
	[NDTA_THRESH1] = { .name = "thresh1", .type = YNL_PT_U32, },
	[NDTA_THRESH2] = { .name = "thresh2", .type = YNL_PT_U32, },
	[NDTA_THRESH3] = { .name = "thresh3", .type = YNL_PT_U32, },
	[NDTA_CONFIG] = { .name = "config", .type = YNL_PT_BINARY,},
	[NDTA_PARMS] = { .name = "parms", .type = YNL_PT_NEST, .nest = &rt_neigh_ndtpa_attrs_nest, },
	[NDTA_STATS] = { .name = "stats", .type = YNL_PT_BINARY,},
	[NDTA_GC_INTERVAL] = { .name = "gc-interval", .type = YNL_PT_U64, },
	[NDTA_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest rt_neigh_ndt_attrs_nest = {
	.max_attr = NDTA_MAX,
	.table = rt_neigh_ndt_attrs_policy,
};

/* Common nested types */
void rt_neigh_ndtpa_attrs_free(struct rt_neigh_ndtpa_attrs *obj)
{
}

int rt_neigh_ndtpa_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     struct rt_neigh_ndtpa_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.ifindex)
		ynl_attr_put_u32(nlh, NDTPA_IFINDEX, obj->ifindex);
	if (obj->_present.refcnt)
		ynl_attr_put_u32(nlh, NDTPA_REFCNT, obj->refcnt);
	if (obj->_present.reachable_time)
		ynl_attr_put_u64(nlh, NDTPA_REACHABLE_TIME, obj->reachable_time);
	if (obj->_present.base_reachable_time)
		ynl_attr_put_u64(nlh, NDTPA_BASE_REACHABLE_TIME, obj->base_reachable_time);
	if (obj->_present.retrans_time)
		ynl_attr_put_u64(nlh, NDTPA_RETRANS_TIME, obj->retrans_time);
	if (obj->_present.gc_staletime)
		ynl_attr_put_u64(nlh, NDTPA_GC_STALETIME, obj->gc_staletime);
	if (obj->_present.delay_probe_time)
		ynl_attr_put_u64(nlh, NDTPA_DELAY_PROBE_TIME, obj->delay_probe_time);
	if (obj->_present.queue_len)
		ynl_attr_put_u32(nlh, NDTPA_QUEUE_LEN, obj->queue_len);
	if (obj->_present.app_probes)
		ynl_attr_put_u32(nlh, NDTPA_APP_PROBES, obj->app_probes);
	if (obj->_present.ucast_probes)
		ynl_attr_put_u32(nlh, NDTPA_UCAST_PROBES, obj->ucast_probes);
	if (obj->_present.mcast_probes)
		ynl_attr_put_u32(nlh, NDTPA_MCAST_PROBES, obj->mcast_probes);
	if (obj->_present.anycast_delay)
		ynl_attr_put_u64(nlh, NDTPA_ANYCAST_DELAY, obj->anycast_delay);
	if (obj->_present.proxy_delay)
		ynl_attr_put_u64(nlh, NDTPA_PROXY_DELAY, obj->proxy_delay);
	if (obj->_present.proxy_qlen)
		ynl_attr_put_u32(nlh, NDTPA_PROXY_QLEN, obj->proxy_qlen);
	if (obj->_present.locktime)
		ynl_attr_put_u64(nlh, NDTPA_LOCKTIME, obj->locktime);
	if (obj->_present.queue_lenbytes)
		ynl_attr_put_u32(nlh, NDTPA_QUEUE_LENBYTES, obj->queue_lenbytes);
	if (obj->_present.mcast_reprobes)
		ynl_attr_put_u32(nlh, NDTPA_MCAST_REPROBES, obj->mcast_reprobes);
	if (obj->_present.interval_probe_time_ms)
		ynl_attr_put_u64(nlh, NDTPA_INTERVAL_PROBE_TIME_MS, obj->interval_probe_time_ms);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_neigh_ndtpa_attrs_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested)
{
	struct rt_neigh_ndtpa_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NDTPA_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == NDTPA_REFCNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.refcnt = 1;
			dst->refcnt = ynl_attr_get_u32(attr);
		} else if (type == NDTPA_REACHABLE_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reachable_time = 1;
			dst->reachable_time = ynl_attr_get_u64(attr);
		} else if (type == NDTPA_BASE_REACHABLE_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.base_reachable_time = 1;
			dst->base_reachable_time = ynl_attr_get_u64(attr);
		} else if (type == NDTPA_RETRANS_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.retrans_time = 1;
			dst->retrans_time = ynl_attr_get_u64(attr);
		} else if (type == NDTPA_GC_STALETIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gc_staletime = 1;
			dst->gc_staletime = ynl_attr_get_u64(attr);
		} else if (type == NDTPA_DELAY_PROBE_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.delay_probe_time = 1;
			dst->delay_probe_time = ynl_attr_get_u64(attr);
		} else if (type == NDTPA_QUEUE_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.queue_len = 1;
			dst->queue_len = ynl_attr_get_u32(attr);
		} else if (type == NDTPA_APP_PROBES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.app_probes = 1;
			dst->app_probes = ynl_attr_get_u32(attr);
		} else if (type == NDTPA_UCAST_PROBES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ucast_probes = 1;
			dst->ucast_probes = ynl_attr_get_u32(attr);
		} else if (type == NDTPA_MCAST_PROBES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_probes = 1;
			dst->mcast_probes = ynl_attr_get_u32(attr);
		} else if (type == NDTPA_ANYCAST_DELAY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.anycast_delay = 1;
			dst->anycast_delay = ynl_attr_get_u64(attr);
		} else if (type == NDTPA_PROXY_DELAY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proxy_delay = 1;
			dst->proxy_delay = ynl_attr_get_u64(attr);
		} else if (type == NDTPA_PROXY_QLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proxy_qlen = 1;
			dst->proxy_qlen = ynl_attr_get_u32(attr);
		} else if (type == NDTPA_LOCKTIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.locktime = 1;
			dst->locktime = ynl_attr_get_u64(attr);
		} else if (type == NDTPA_QUEUE_LENBYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.queue_lenbytes = 1;
			dst->queue_lenbytes = ynl_attr_get_u32(attr);
		} else if (type == NDTPA_MCAST_REPROBES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mcast_reprobes = 1;
			dst->mcast_reprobes = ynl_attr_get_u32(attr);
		} else if (type == NDTPA_INTERVAL_PROBE_TIME_MS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.interval_probe_time_ms = 1;
			dst->interval_probe_time_ms = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

/* ============== RTM_NEWNEIGH ============== */
/* RTM_NEWNEIGH - do */
void rt_neigh_newneigh_req_free(struct rt_neigh_newneigh_req *req)
{
	free(req->dst);
	free(req->lladdr);
	free(req->fdb_ext_attrs);
	free(req);
}

int rt_neigh_newneigh(struct ynl_sock *ys, struct rt_neigh_newneigh_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWNEIGH, req->_nlmsg_flags);
	ys->req_policy = &rt_neigh_neighbour_attrs_nest;
	ys->req_hdr_len = sizeof(struct ndmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.dst)
		ynl_attr_put(nlh, NDA_DST, req->dst, req->_len.dst);
	if (req->_len.lladdr)
		ynl_attr_put(nlh, NDA_LLADDR, req->lladdr, req->_len.lladdr);
	if (req->_present.probes)
		ynl_attr_put_u32(nlh, NDA_PROBES, req->probes);
	if (req->_present.vlan)
		ynl_attr_put_u16(nlh, NDA_VLAN, req->vlan);
	if (req->_present.port)
		ynl_attr_put_u16(nlh, NDA_PORT, req->port);
	if (req->_present.vni)
		ynl_attr_put_u32(nlh, NDA_VNI, req->vni);
	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NDA_IFINDEX, req->ifindex);
	if (req->_present.master)
		ynl_attr_put_u32(nlh, NDA_MASTER, req->master);
	if (req->_present.protocol)
		ynl_attr_put_u8(nlh, NDA_PROTOCOL, req->protocol);
	if (req->_present.nh_id)
		ynl_attr_put_u32(nlh, NDA_NH_ID, req->nh_id);
	if (req->_present.flags_ext)
		ynl_attr_put_u32(nlh, NDA_FLAGS_EXT, req->flags_ext);
	if (req->_len.fdb_ext_attrs)
		ynl_attr_put(nlh, NDA_FDB_EXT_ATTRS, req->fdb_ext_attrs, req->_len.fdb_ext_attrs);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_DELNEIGH ============== */
/* RTM_DELNEIGH - do */
void rt_neigh_delneigh_req_free(struct rt_neigh_delneigh_req *req)
{
	free(req->dst);
	free(req);
}

int rt_neigh_delneigh(struct ynl_sock *ys, struct rt_neigh_delneigh_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELNEIGH, req->_nlmsg_flags);
	ys->req_policy = &rt_neigh_neighbour_attrs_nest;
	ys->req_hdr_len = sizeof(struct ndmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.dst)
		ynl_attr_put(nlh, NDA_DST, req->dst, req->_len.dst);
	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NDA_IFINDEX, req->ifindex);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_GETNEIGH ============== */
/* RTM_GETNEIGH - do */
void rt_neigh_getneigh_req_free(struct rt_neigh_getneigh_req *req)
{
	free(req->dst);
	free(req);
}

void rt_neigh_getneigh_rsp_free(struct rt_neigh_getneigh_rsp *rsp)
{
	free(rsp->dst);
	free(rsp->lladdr);
	free(rsp->fdb_ext_attrs);
	free(rsp);
}

int rt_neigh_getneigh_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	struct rt_neigh_getneigh_rsp *dst;
	const struct nlattr *attr;
	void *hdr;

	dst = yarg->data;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ndmsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct ndmsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NDA_DST) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dst = len;
			dst->dst = malloc(len);
			memcpy(dst->dst, ynl_attr_data(attr), len);
		} else if (type == NDA_LLADDR) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.lladdr = len;
			dst->lladdr = malloc(len);
			memcpy(dst->lladdr, ynl_attr_data(attr), len);
		} else if (type == NDA_PROBES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.probes = 1;
			dst->probes = ynl_attr_get_u32(attr);
		} else if (type == NDA_VLAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vlan = 1;
			dst->vlan = ynl_attr_get_u16(attr);
		} else if (type == NDA_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port = 1;
			dst->port = ynl_attr_get_u16(attr);
		} else if (type == NDA_VNI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vni = 1;
			dst->vni = ynl_attr_get_u32(attr);
		} else if (type == NDA_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == NDA_MASTER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.master = 1;
			dst->master = ynl_attr_get_u32(attr);
		} else if (type == NDA_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.protocol = 1;
			dst->protocol = ynl_attr_get_u8(attr);
		} else if (type == NDA_NH_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nh_id = 1;
			dst->nh_id = ynl_attr_get_u32(attr);
		} else if (type == NDA_FLAGS_EXT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags_ext = 1;
			dst->flags_ext = ynl_attr_get_u32(attr);
		} else if (type == NDA_FDB_EXT_ATTRS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.fdb_ext_attrs = len;
			dst->fdb_ext_attrs = malloc(len);
			memcpy(dst->fdb_ext_attrs, ynl_attr_data(attr), len);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct rt_neigh_getneigh_rsp *
rt_neigh_getneigh(struct ynl_sock *ys, struct rt_neigh_getneigh_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct rt_neigh_getneigh_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETNEIGH, req->_nlmsg_flags);
	ys->req_policy = &rt_neigh_neighbour_attrs_nest;
	ys->req_hdr_len = sizeof(struct ndmsg);
	yrs.yarg.rsp_policy = &rt_neigh_neighbour_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.dst)
		ynl_attr_put(nlh, NDA_DST, req->dst, req->_len.dst);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = rt_neigh_getneigh_rsp_parse;
	yrs.rsp_cmd = 28;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	rt_neigh_getneigh_rsp_free(rsp);
	return NULL;
}

/* RTM_GETNEIGH - dump */
void rt_neigh_getneigh_req_dump_free(struct rt_neigh_getneigh_req_dump *req)
{
	free(req);
}

void rt_neigh_getneigh_list_free(struct rt_neigh_getneigh_list *rsp)
{
	struct rt_neigh_getneigh_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.dst);
		free(rsp->obj.lladdr);
		free(rsp->obj.fdb_ext_attrs);
		free(rsp);
	}
}

struct rt_neigh_getneigh_list *
rt_neigh_getneigh_dump(struct ynl_sock *ys,
		       struct rt_neigh_getneigh_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_neigh_neighbour_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct rt_neigh_getneigh_list);
	yds.cb = rt_neigh_getneigh_rsp_parse;
	yds.rsp_cmd = 28;

	nlh = ynl_msg_start_dump(ys, RTM_GETNEIGH);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &rt_neigh_neighbour_attrs_nest;
	ys->req_hdr_len = sizeof(struct ndmsg);

	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, NDA_IFINDEX, req->ifindex);
	if (req->_present.master)
		ynl_attr_put_u32(nlh, NDA_MASTER, req->master);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	rt_neigh_getneigh_list_free(yds.first);
	return NULL;
}

/* RTM_GETNEIGH - notify */
void rt_neigh_getneigh_ntf_free(struct rt_neigh_getneigh_ntf *rsp)
{
	free(rsp->obj.dst);
	free(rsp->obj.lladdr);
	free(rsp->obj.fdb_ext_attrs);
	free(rsp);
}

/* ============== RTM_GETNEIGHTBL ============== */
/* RTM_GETNEIGHTBL - dump */
int rt_neigh_getneightbl_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	struct rt_neigh_getneightbl_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ndtmsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct ndtmsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NDTA_NAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.name = len;
			dst->name = malloc(len + 1);
			memcpy(dst->name, ynl_attr_get_str(attr), len);
			dst->name[len] = 0;
		} else if (type == NDTA_THRESH1) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.thresh1 = 1;
			dst->thresh1 = ynl_attr_get_u32(attr);
		} else if (type == NDTA_THRESH2) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.thresh2 = 1;
			dst->thresh2 = ynl_attr_get_u32(attr);
		} else if (type == NDTA_THRESH3) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.thresh3 = 1;
			dst->thresh3 = ynl_attr_get_u32(attr);
		} else if (type == NDTA_CONFIG) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.config = len;
			if (len < sizeof(struct ndt_config))
				dst->config = calloc(1, sizeof(struct ndt_config));
			else
				dst->config = malloc(len);
			memcpy(dst->config, ynl_attr_data(attr), len);
		} else if (type == NDTA_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.parms = 1;

			parg.rsp_policy = &rt_neigh_ndtpa_attrs_nest;
			parg.data = &dst->parms;
			if (rt_neigh_ndtpa_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == NDTA_STATS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stats = len;
			if (len < sizeof(struct ndt_stats))
				dst->stats = calloc(1, sizeof(struct ndt_stats));
			else
				dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == NDTA_GC_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gc_interval = 1;
			dst->gc_interval = ynl_attr_get_u64(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

void rt_neigh_getneightbl_req_free(struct rt_neigh_getneightbl_req *req)
{
	free(req);
}

void rt_neigh_getneightbl_list_free(struct rt_neigh_getneightbl_list *rsp)
{
	struct rt_neigh_getneightbl_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.name);
		free(rsp->obj.config);
		rt_neigh_ndtpa_attrs_free(&rsp->obj.parms);
		free(rsp->obj.stats);
		free(rsp);
	}
}

struct rt_neigh_getneightbl_list *
rt_neigh_getneightbl_dump(struct ynl_sock *ys,
			  struct rt_neigh_getneightbl_req *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_neigh_ndt_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct rt_neigh_getneightbl_list);
	yds.cb = rt_neigh_getneightbl_rsp_parse;
	yds.rsp_cmd = 64;

	nlh = ynl_msg_start_dump(ys, RTM_GETNEIGHTBL);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &rt_neigh_ndt_attrs_nest;
	ys->req_hdr_len = sizeof(struct ndtmsg);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	rt_neigh_getneightbl_list_free(yds.first);
	return NULL;
}

/* ============== RTM_SETNEIGHTBL ============== */
/* RTM_SETNEIGHTBL - do */
void rt_neigh_setneightbl_req_free(struct rt_neigh_setneightbl_req *req)
{
	free(req->name);
	rt_neigh_ndtpa_attrs_free(&req->parms);
	free(req);
}

int rt_neigh_setneightbl(struct ynl_sock *ys,
			 struct rt_neigh_setneightbl_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_SETNEIGHTBL, req->_nlmsg_flags);
	ys->req_policy = &rt_neigh_ndt_attrs_nest;
	ys->req_hdr_len = sizeof(struct ndtmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.name)
		ynl_attr_put_str(nlh, NDTA_NAME, req->name);
	if (req->_present.thresh1)
		ynl_attr_put_u32(nlh, NDTA_THRESH1, req->thresh1);
	if (req->_present.thresh2)
		ynl_attr_put_u32(nlh, NDTA_THRESH2, req->thresh2);
	if (req->_present.thresh3)
		ynl_attr_put_u32(nlh, NDTA_THRESH3, req->thresh3);
	if (req->_present.parms)
		rt_neigh_ndtpa_attrs_put(nlh, NDTA_PARMS, &req->parms);
	if (req->_present.gc_interval)
		ynl_attr_put_u64(nlh, NDTA_GC_INTERVAL, req->gc_interval);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

static const struct ynl_ntf_info rt_neigh_ntf_info[] =  {
	[RTM_DELNEIGH] =  {
		.alloc_sz	= sizeof(struct rt_neigh_getneigh_ntf),
		.cb		= rt_neigh_getneigh_rsp_parse,
		.policy		= &rt_neigh_neighbour_attrs_nest,
		.free		= (void *)rt_neigh_getneigh_ntf_free,
	},
	[RTM_NEWNEIGH] =  {
		.alloc_sz	= sizeof(struct rt_neigh_getneigh_ntf),
		.cb		= rt_neigh_getneigh_rsp_parse,
		.policy		= &rt_neigh_neighbour_attrs_nest,
		.free		= (void *)rt_neigh_getneigh_ntf_free,
	},
};

const struct ynl_family ynl_rt_neigh_family =  {
	.name		= "rt_neigh",
	.is_classic	= true,
	.classic_id	= 0,
	.ntf_info	= rt_neigh_ntf_info,
	.ntf_info_size	= YNL_ARRAY_SIZE(rt_neigh_ntf_info),
};
