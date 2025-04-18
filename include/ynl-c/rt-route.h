/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-route.yaml */
/* YNL-GEN user header */

#ifndef _LINUX_RT_ROUTE_GEN_H
#define _LINUX_RT_ROUTE_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/rtnetlink.h>

struct ynl_sock;

extern const struct ynl_family ynl_rt_route_family;

/* Enums */
const char *rt_route_op_str(int op);
const char *rt_route_rtm_type_str(int value);

/* Common nested types */
struct rt_route_metrics {
	struct {
		__u32 lock:1;
		__u32 mtu:1;
		__u32 window:1;
		__u32 rtt:1;
		__u32 rttvar:1;
		__u32 ssthresh:1;
		__u32 cwnd:1;
		__u32 advmss:1;
		__u32 reordering:1;
		__u32 hoplimit:1;
		__u32 initcwnd:1;
		__u32 features:1;
		__u32 rto_min:1;
		__u32 initrwnd:1;
		__u32 quickack:1;
		__u32 cc_algo_len;
		__u32 fastopen_no_cookie:1;
	} _present;

	__u32 lock;
	__u32 mtu;
	__u32 window;
	__u32 rtt;
	__u32 rttvar;
	__u32 ssthresh;
	__u32 cwnd;
	__u32 advmss;
	__u32 reordering;
	__u32 hoplimit;
	__u32 initcwnd;
	__u32 features;
	__u32 rto_min;
	__u32 initrwnd;
	__u32 quickack;
	char *cc_algo;
	__u32 fastopen_no_cookie;
};

/* ============== RTM_GETROUTE ============== */
/* RTM_GETROUTE - do */
struct rt_route_getroute_req {
	struct rtmsg _hdr;

	struct {
		__u32 src_len;
		__u32 dst_len;
		__u32 iif:1;
		__u32 oif:1;
		__u32 ip_proto:1;
		__u32 sport:1;
		__u32 dport:1;
		__u32 mark:1;
		__u32 uid:1;
		__u32 flowlabel:1;
	} _present;

	void *src;
	void *dst;
	__u32 iif;
	__u32 oif;
	__u8 ip_proto;
	__u16 sport;
	__u16 dport;
	__u32 mark;
	__u32 uid;
	__u32 flowlabel /* big-endian */;
};

static inline struct rt_route_getroute_req *rt_route_getroute_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_route_getroute_req));
}
void rt_route_getroute_req_free(struct rt_route_getroute_req *req);

static inline void
rt_route_getroute_req_set_src(struct rt_route_getroute_req *req,
			      const void *src, size_t len)
{
	free(req->src);
	req->_present.src_len = len;
	req->src = malloc(req->_present.src_len);
	memcpy(req->src, src, req->_present.src_len);
}
static inline void
rt_route_getroute_req_set_dst(struct rt_route_getroute_req *req,
			      const void *dst, size_t len)
{
	free(req->dst);
	req->_present.dst_len = len;
	req->dst = malloc(req->_present.dst_len);
	memcpy(req->dst, dst, req->_present.dst_len);
}
static inline void
rt_route_getroute_req_set_iif(struct rt_route_getroute_req *req, __u32 iif)
{
	req->_present.iif = 1;
	req->iif = iif;
}
static inline void
rt_route_getroute_req_set_oif(struct rt_route_getroute_req *req, __u32 oif)
{
	req->_present.oif = 1;
	req->oif = oif;
}
static inline void
rt_route_getroute_req_set_ip_proto(struct rt_route_getroute_req *req,
				   __u8 ip_proto)
{
	req->_present.ip_proto = 1;
	req->ip_proto = ip_proto;
}
static inline void
rt_route_getroute_req_set_sport(struct rt_route_getroute_req *req, __u16 sport)
{
	req->_present.sport = 1;
	req->sport = sport;
}
static inline void
rt_route_getroute_req_set_dport(struct rt_route_getroute_req *req, __u16 dport)
{
	req->_present.dport = 1;
	req->dport = dport;
}
static inline void
rt_route_getroute_req_set_mark(struct rt_route_getroute_req *req, __u32 mark)
{
	req->_present.mark = 1;
	req->mark = mark;
}
static inline void
rt_route_getroute_req_set_uid(struct rt_route_getroute_req *req, __u32 uid)
{
	req->_present.uid = 1;
	req->uid = uid;
}
static inline void
rt_route_getroute_req_set_flowlabel(struct rt_route_getroute_req *req,
				    __u32 flowlabel /* big-endian */)
{
	req->_present.flowlabel = 1;
	req->flowlabel = flowlabel;
}

struct rt_route_getroute_rsp {
	struct rtmsg _hdr;

	struct {
		__u32 dst_len;
		__u32 src_len;
		__u32 iif:1;
		__u32 oif:1;
		__u32 gateway_len;
		__u32 priority:1;
		__u32 prefsrc_len;
		__u32 metrics:1;
		__u32 multipath_len;
		__u32 flow:1;
		__u32 cacheinfo_len;
		__u32 table:1;
		__u32 mark:1;
		__u32 mfc_stats_len;
		__u32 via_len;
		__u32 newdst_len;
		__u32 pref:1;
		__u32 encap_type:1;
		__u32 encap_len;
		__u32 expires:1;
		__u32 pad_len;
		__u32 uid:1;
		__u32 ttl_propagate:1;
		__u32 ip_proto:1;
		__u32 sport:1;
		__u32 dport:1;
		__u32 nh_id:1;
		__u32 flowlabel:1;
	} _present;

	void *dst;
	void *src;
	__u32 iif;
	__u32 oif;
	void *gateway;
	__u32 priority;
	void *prefsrc;
	struct rt_route_metrics metrics;
	void *multipath;
	__u32 flow;
	void *cacheinfo;
	__u32 table;
	__u32 mark;
	void *mfc_stats;
	void *via;
	void *newdst;
	__u8 pref;
	__u16 encap_type;
	void *encap;
	__u32 expires;
	void *pad;
	__u32 uid;
	__u8 ttl_propagate;
	__u8 ip_proto;
	__u16 sport;
	__u16 dport;
	__u32 nh_id;
	__u32 flowlabel /* big-endian */;
};

void rt_route_getroute_rsp_free(struct rt_route_getroute_rsp *rsp);

/*
 * Dump route information.
 */
struct rt_route_getroute_rsp *
rt_route_getroute(struct ynl_sock *ys, struct rt_route_getroute_req *req);

/* RTM_GETROUTE - dump */
struct rt_route_getroute_req_dump {
	struct rtmsg _hdr;
};

static inline struct rt_route_getroute_req_dump *
rt_route_getroute_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct rt_route_getroute_req_dump));
}
void rt_route_getroute_req_dump_free(struct rt_route_getroute_req_dump *req);

struct rt_route_getroute_list {
	struct rt_route_getroute_list *next;
	struct rt_route_getroute_rsp obj __attribute__((aligned(8)));
};

void rt_route_getroute_list_free(struct rt_route_getroute_list *rsp);

struct rt_route_getroute_list *
rt_route_getroute_dump(struct ynl_sock *ys,
		       struct rt_route_getroute_req_dump *req);

/* ============== RTM_NEWROUTE ============== */
/* RTM_NEWROUTE - do */
struct rt_route_newroute_req {
	struct rtmsg _hdr;

	struct {
		__u32 dst_len;
		__u32 src_len;
		__u32 iif:1;
		__u32 oif:1;
		__u32 gateway_len;
		__u32 priority:1;
		__u32 prefsrc_len;
		__u32 metrics:1;
		__u32 multipath_len;
		__u32 flow:1;
		__u32 cacheinfo_len;
		__u32 table:1;
		__u32 mark:1;
		__u32 mfc_stats_len;
		__u32 via_len;
		__u32 newdst_len;
		__u32 pref:1;
		__u32 encap_type:1;
		__u32 encap_len;
		__u32 expires:1;
		__u32 pad_len;
		__u32 uid:1;
		__u32 ttl_propagate:1;
		__u32 ip_proto:1;
		__u32 sport:1;
		__u32 dport:1;
		__u32 nh_id:1;
		__u32 flowlabel:1;
	} _present;

	void *dst;
	void *src;
	__u32 iif;
	__u32 oif;
	void *gateway;
	__u32 priority;
	void *prefsrc;
	struct rt_route_metrics metrics;
	void *multipath;
	__u32 flow;
	void *cacheinfo;
	__u32 table;
	__u32 mark;
	void *mfc_stats;
	void *via;
	void *newdst;
	__u8 pref;
	__u16 encap_type;
	void *encap;
	__u32 expires;
	void *pad;
	__u32 uid;
	__u8 ttl_propagate;
	__u8 ip_proto;
	__u16 sport;
	__u16 dport;
	__u32 nh_id;
	__u32 flowlabel /* big-endian */;
};

static inline struct rt_route_newroute_req *rt_route_newroute_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_route_newroute_req));
}
void rt_route_newroute_req_free(struct rt_route_newroute_req *req);

static inline void
rt_route_newroute_req_set_dst(struct rt_route_newroute_req *req,
			      const void *dst, size_t len)
{
	free(req->dst);
	req->_present.dst_len = len;
	req->dst = malloc(req->_present.dst_len);
	memcpy(req->dst, dst, req->_present.dst_len);
}
static inline void
rt_route_newroute_req_set_src(struct rt_route_newroute_req *req,
			      const void *src, size_t len)
{
	free(req->src);
	req->_present.src_len = len;
	req->src = malloc(req->_present.src_len);
	memcpy(req->src, src, req->_present.src_len);
}
static inline void
rt_route_newroute_req_set_iif(struct rt_route_newroute_req *req, __u32 iif)
{
	req->_present.iif = 1;
	req->iif = iif;
}
static inline void
rt_route_newroute_req_set_oif(struct rt_route_newroute_req *req, __u32 oif)
{
	req->_present.oif = 1;
	req->oif = oif;
}
static inline void
rt_route_newroute_req_set_gateway(struct rt_route_newroute_req *req,
				  const void *gateway, size_t len)
{
	free(req->gateway);
	req->_present.gateway_len = len;
	req->gateway = malloc(req->_present.gateway_len);
	memcpy(req->gateway, gateway, req->_present.gateway_len);
}
static inline void
rt_route_newroute_req_set_priority(struct rt_route_newroute_req *req,
				   __u32 priority)
{
	req->_present.priority = 1;
	req->priority = priority;
}
static inline void
rt_route_newroute_req_set_prefsrc(struct rt_route_newroute_req *req,
				  const void *prefsrc, size_t len)
{
	free(req->prefsrc);
	req->_present.prefsrc_len = len;
	req->prefsrc = malloc(req->_present.prefsrc_len);
	memcpy(req->prefsrc, prefsrc, req->_present.prefsrc_len);
}
static inline void
rt_route_newroute_req_set_metrics_lock(struct rt_route_newroute_req *req,
				       __u32 lock)
{
	req->_present.metrics = 1;
	req->metrics._present.lock = 1;
	req->metrics.lock = lock;
}
static inline void
rt_route_newroute_req_set_metrics_mtu(struct rt_route_newroute_req *req,
				      __u32 mtu)
{
	req->_present.metrics = 1;
	req->metrics._present.mtu = 1;
	req->metrics.mtu = mtu;
}
static inline void
rt_route_newroute_req_set_metrics_window(struct rt_route_newroute_req *req,
					 __u32 window)
{
	req->_present.metrics = 1;
	req->metrics._present.window = 1;
	req->metrics.window = window;
}
static inline void
rt_route_newroute_req_set_metrics_rtt(struct rt_route_newroute_req *req,
				      __u32 rtt)
{
	req->_present.metrics = 1;
	req->metrics._present.rtt = 1;
	req->metrics.rtt = rtt;
}
static inline void
rt_route_newroute_req_set_metrics_rttvar(struct rt_route_newroute_req *req,
					 __u32 rttvar)
{
	req->_present.metrics = 1;
	req->metrics._present.rttvar = 1;
	req->metrics.rttvar = rttvar;
}
static inline void
rt_route_newroute_req_set_metrics_ssthresh(struct rt_route_newroute_req *req,
					   __u32 ssthresh)
{
	req->_present.metrics = 1;
	req->metrics._present.ssthresh = 1;
	req->metrics.ssthresh = ssthresh;
}
static inline void
rt_route_newroute_req_set_metrics_cwnd(struct rt_route_newroute_req *req,
				       __u32 cwnd)
{
	req->_present.metrics = 1;
	req->metrics._present.cwnd = 1;
	req->metrics.cwnd = cwnd;
}
static inline void
rt_route_newroute_req_set_metrics_advmss(struct rt_route_newroute_req *req,
					 __u32 advmss)
{
	req->_present.metrics = 1;
	req->metrics._present.advmss = 1;
	req->metrics.advmss = advmss;
}
static inline void
rt_route_newroute_req_set_metrics_reordering(struct rt_route_newroute_req *req,
					     __u32 reordering)
{
	req->_present.metrics = 1;
	req->metrics._present.reordering = 1;
	req->metrics.reordering = reordering;
}
static inline void
rt_route_newroute_req_set_metrics_hoplimit(struct rt_route_newroute_req *req,
					   __u32 hoplimit)
{
	req->_present.metrics = 1;
	req->metrics._present.hoplimit = 1;
	req->metrics.hoplimit = hoplimit;
}
static inline void
rt_route_newroute_req_set_metrics_initcwnd(struct rt_route_newroute_req *req,
					   __u32 initcwnd)
{
	req->_present.metrics = 1;
	req->metrics._present.initcwnd = 1;
	req->metrics.initcwnd = initcwnd;
}
static inline void
rt_route_newroute_req_set_metrics_features(struct rt_route_newroute_req *req,
					   __u32 features)
{
	req->_present.metrics = 1;
	req->metrics._present.features = 1;
	req->metrics.features = features;
}
static inline void
rt_route_newroute_req_set_metrics_rto_min(struct rt_route_newroute_req *req,
					  __u32 rto_min)
{
	req->_present.metrics = 1;
	req->metrics._present.rto_min = 1;
	req->metrics.rto_min = rto_min;
}
static inline void
rt_route_newroute_req_set_metrics_initrwnd(struct rt_route_newroute_req *req,
					   __u32 initrwnd)
{
	req->_present.metrics = 1;
	req->metrics._present.initrwnd = 1;
	req->metrics.initrwnd = initrwnd;
}
static inline void
rt_route_newroute_req_set_metrics_quickack(struct rt_route_newroute_req *req,
					   __u32 quickack)
{
	req->_present.metrics = 1;
	req->metrics._present.quickack = 1;
	req->metrics.quickack = quickack;
}
static inline void
rt_route_newroute_req_set_metrics_cc_algo(struct rt_route_newroute_req *req,
					  const char *cc_algo)
{
	req->_present.metrics = 1;
	free(req->metrics.cc_algo);
	req->metrics._present.cc_algo_len = strlen(cc_algo);
	req->metrics.cc_algo = malloc(req->metrics._present.cc_algo_len + 1);
	memcpy(req->metrics.cc_algo, cc_algo, req->metrics._present.cc_algo_len);
	req->metrics.cc_algo[req->metrics._present.cc_algo_len] = 0;
}
static inline void
rt_route_newroute_req_set_metrics_fastopen_no_cookie(struct rt_route_newroute_req *req,
						     __u32 fastopen_no_cookie)
{
	req->_present.metrics = 1;
	req->metrics._present.fastopen_no_cookie = 1;
	req->metrics.fastopen_no_cookie = fastopen_no_cookie;
}
static inline void
rt_route_newroute_req_set_multipath(struct rt_route_newroute_req *req,
				    const void *multipath, size_t len)
{
	free(req->multipath);
	req->_present.multipath_len = len;
	req->multipath = malloc(req->_present.multipath_len);
	memcpy(req->multipath, multipath, req->_present.multipath_len);
}
static inline void
rt_route_newroute_req_set_flow(struct rt_route_newroute_req *req, __u32 flow)
{
	req->_present.flow = 1;
	req->flow = flow;
}
static inline void
rt_route_newroute_req_set_cacheinfo(struct rt_route_newroute_req *req,
				    const void *cacheinfo, size_t len)
{
	free(req->cacheinfo);
	req->_present.cacheinfo_len = len;
	req->cacheinfo = malloc(req->_present.cacheinfo_len);
	memcpy(req->cacheinfo, cacheinfo, req->_present.cacheinfo_len);
}
static inline void
rt_route_newroute_req_set_table(struct rt_route_newroute_req *req, __u32 table)
{
	req->_present.table = 1;
	req->table = table;
}
static inline void
rt_route_newroute_req_set_mark(struct rt_route_newroute_req *req, __u32 mark)
{
	req->_present.mark = 1;
	req->mark = mark;
}
static inline void
rt_route_newroute_req_set_mfc_stats(struct rt_route_newroute_req *req,
				    const void *mfc_stats, size_t len)
{
	free(req->mfc_stats);
	req->_present.mfc_stats_len = len;
	req->mfc_stats = malloc(req->_present.mfc_stats_len);
	memcpy(req->mfc_stats, mfc_stats, req->_present.mfc_stats_len);
}
static inline void
rt_route_newroute_req_set_via(struct rt_route_newroute_req *req,
			      const void *via, size_t len)
{
	free(req->via);
	req->_present.via_len = len;
	req->via = malloc(req->_present.via_len);
	memcpy(req->via, via, req->_present.via_len);
}
static inline void
rt_route_newroute_req_set_newdst(struct rt_route_newroute_req *req,
				 const void *newdst, size_t len)
{
	free(req->newdst);
	req->_present.newdst_len = len;
	req->newdst = malloc(req->_present.newdst_len);
	memcpy(req->newdst, newdst, req->_present.newdst_len);
}
static inline void
rt_route_newroute_req_set_pref(struct rt_route_newroute_req *req, __u8 pref)
{
	req->_present.pref = 1;
	req->pref = pref;
}
static inline void
rt_route_newroute_req_set_encap_type(struct rt_route_newroute_req *req,
				     __u16 encap_type)
{
	req->_present.encap_type = 1;
	req->encap_type = encap_type;
}
static inline void
rt_route_newroute_req_set_encap(struct rt_route_newroute_req *req,
				const void *encap, size_t len)
{
	free(req->encap);
	req->_present.encap_len = len;
	req->encap = malloc(req->_present.encap_len);
	memcpy(req->encap, encap, req->_present.encap_len);
}
static inline void
rt_route_newroute_req_set_expires(struct rt_route_newroute_req *req,
				  __u32 expires)
{
	req->_present.expires = 1;
	req->expires = expires;
}
static inline void
rt_route_newroute_req_set_pad(struct rt_route_newroute_req *req,
			      const void *pad, size_t len)
{
	free(req->pad);
	req->_present.pad_len = len;
	req->pad = malloc(req->_present.pad_len);
	memcpy(req->pad, pad, req->_present.pad_len);
}
static inline void
rt_route_newroute_req_set_uid(struct rt_route_newroute_req *req, __u32 uid)
{
	req->_present.uid = 1;
	req->uid = uid;
}
static inline void
rt_route_newroute_req_set_ttl_propagate(struct rt_route_newroute_req *req,
					__u8 ttl_propagate)
{
	req->_present.ttl_propagate = 1;
	req->ttl_propagate = ttl_propagate;
}
static inline void
rt_route_newroute_req_set_ip_proto(struct rt_route_newroute_req *req,
				   __u8 ip_proto)
{
	req->_present.ip_proto = 1;
	req->ip_proto = ip_proto;
}
static inline void
rt_route_newroute_req_set_sport(struct rt_route_newroute_req *req, __u16 sport)
{
	req->_present.sport = 1;
	req->sport = sport;
}
static inline void
rt_route_newroute_req_set_dport(struct rt_route_newroute_req *req, __u16 dport)
{
	req->_present.dport = 1;
	req->dport = dport;
}
static inline void
rt_route_newroute_req_set_nh_id(struct rt_route_newroute_req *req, __u32 nh_id)
{
	req->_present.nh_id = 1;
	req->nh_id = nh_id;
}
static inline void
rt_route_newroute_req_set_flowlabel(struct rt_route_newroute_req *req,
				    __u32 flowlabel /* big-endian */)
{
	req->_present.flowlabel = 1;
	req->flowlabel = flowlabel;
}

/*
 * Create a new route
 */
int rt_route_newroute(struct ynl_sock *ys, struct rt_route_newroute_req *req);

/* ============== RTM_DELROUTE ============== */
/* RTM_DELROUTE - do */
struct rt_route_delroute_req {
	struct rtmsg _hdr;

	struct {
		__u32 dst_len;
		__u32 src_len;
		__u32 iif:1;
		__u32 oif:1;
		__u32 gateway_len;
		__u32 priority:1;
		__u32 prefsrc_len;
		__u32 metrics:1;
		__u32 multipath_len;
		__u32 flow:1;
		__u32 cacheinfo_len;
		__u32 table:1;
		__u32 mark:1;
		__u32 mfc_stats_len;
		__u32 via_len;
		__u32 newdst_len;
		__u32 pref:1;
		__u32 encap_type:1;
		__u32 encap_len;
		__u32 expires:1;
		__u32 pad_len;
		__u32 uid:1;
		__u32 ttl_propagate:1;
		__u32 ip_proto:1;
		__u32 sport:1;
		__u32 dport:1;
		__u32 nh_id:1;
		__u32 flowlabel:1;
	} _present;

	void *dst;
	void *src;
	__u32 iif;
	__u32 oif;
	void *gateway;
	__u32 priority;
	void *prefsrc;
	struct rt_route_metrics metrics;
	void *multipath;
	__u32 flow;
	void *cacheinfo;
	__u32 table;
	__u32 mark;
	void *mfc_stats;
	void *via;
	void *newdst;
	__u8 pref;
	__u16 encap_type;
	void *encap;
	__u32 expires;
	void *pad;
	__u32 uid;
	__u8 ttl_propagate;
	__u8 ip_proto;
	__u16 sport;
	__u16 dport;
	__u32 nh_id;
	__u32 flowlabel /* big-endian */;
};

static inline struct rt_route_delroute_req *rt_route_delroute_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_route_delroute_req));
}
void rt_route_delroute_req_free(struct rt_route_delroute_req *req);

static inline void
rt_route_delroute_req_set_dst(struct rt_route_delroute_req *req,
			      const void *dst, size_t len)
{
	free(req->dst);
	req->_present.dst_len = len;
	req->dst = malloc(req->_present.dst_len);
	memcpy(req->dst, dst, req->_present.dst_len);
}
static inline void
rt_route_delroute_req_set_src(struct rt_route_delroute_req *req,
			      const void *src, size_t len)
{
	free(req->src);
	req->_present.src_len = len;
	req->src = malloc(req->_present.src_len);
	memcpy(req->src, src, req->_present.src_len);
}
static inline void
rt_route_delroute_req_set_iif(struct rt_route_delroute_req *req, __u32 iif)
{
	req->_present.iif = 1;
	req->iif = iif;
}
static inline void
rt_route_delroute_req_set_oif(struct rt_route_delroute_req *req, __u32 oif)
{
	req->_present.oif = 1;
	req->oif = oif;
}
static inline void
rt_route_delroute_req_set_gateway(struct rt_route_delroute_req *req,
				  const void *gateway, size_t len)
{
	free(req->gateway);
	req->_present.gateway_len = len;
	req->gateway = malloc(req->_present.gateway_len);
	memcpy(req->gateway, gateway, req->_present.gateway_len);
}
static inline void
rt_route_delroute_req_set_priority(struct rt_route_delroute_req *req,
				   __u32 priority)
{
	req->_present.priority = 1;
	req->priority = priority;
}
static inline void
rt_route_delroute_req_set_prefsrc(struct rt_route_delroute_req *req,
				  const void *prefsrc, size_t len)
{
	free(req->prefsrc);
	req->_present.prefsrc_len = len;
	req->prefsrc = malloc(req->_present.prefsrc_len);
	memcpy(req->prefsrc, prefsrc, req->_present.prefsrc_len);
}
static inline void
rt_route_delroute_req_set_metrics_lock(struct rt_route_delroute_req *req,
				       __u32 lock)
{
	req->_present.metrics = 1;
	req->metrics._present.lock = 1;
	req->metrics.lock = lock;
}
static inline void
rt_route_delroute_req_set_metrics_mtu(struct rt_route_delroute_req *req,
				      __u32 mtu)
{
	req->_present.metrics = 1;
	req->metrics._present.mtu = 1;
	req->metrics.mtu = mtu;
}
static inline void
rt_route_delroute_req_set_metrics_window(struct rt_route_delroute_req *req,
					 __u32 window)
{
	req->_present.metrics = 1;
	req->metrics._present.window = 1;
	req->metrics.window = window;
}
static inline void
rt_route_delroute_req_set_metrics_rtt(struct rt_route_delroute_req *req,
				      __u32 rtt)
{
	req->_present.metrics = 1;
	req->metrics._present.rtt = 1;
	req->metrics.rtt = rtt;
}
static inline void
rt_route_delroute_req_set_metrics_rttvar(struct rt_route_delroute_req *req,
					 __u32 rttvar)
{
	req->_present.metrics = 1;
	req->metrics._present.rttvar = 1;
	req->metrics.rttvar = rttvar;
}
static inline void
rt_route_delroute_req_set_metrics_ssthresh(struct rt_route_delroute_req *req,
					   __u32 ssthresh)
{
	req->_present.metrics = 1;
	req->metrics._present.ssthresh = 1;
	req->metrics.ssthresh = ssthresh;
}
static inline void
rt_route_delroute_req_set_metrics_cwnd(struct rt_route_delroute_req *req,
				       __u32 cwnd)
{
	req->_present.metrics = 1;
	req->metrics._present.cwnd = 1;
	req->metrics.cwnd = cwnd;
}
static inline void
rt_route_delroute_req_set_metrics_advmss(struct rt_route_delroute_req *req,
					 __u32 advmss)
{
	req->_present.metrics = 1;
	req->metrics._present.advmss = 1;
	req->metrics.advmss = advmss;
}
static inline void
rt_route_delroute_req_set_metrics_reordering(struct rt_route_delroute_req *req,
					     __u32 reordering)
{
	req->_present.metrics = 1;
	req->metrics._present.reordering = 1;
	req->metrics.reordering = reordering;
}
static inline void
rt_route_delroute_req_set_metrics_hoplimit(struct rt_route_delroute_req *req,
					   __u32 hoplimit)
{
	req->_present.metrics = 1;
	req->metrics._present.hoplimit = 1;
	req->metrics.hoplimit = hoplimit;
}
static inline void
rt_route_delroute_req_set_metrics_initcwnd(struct rt_route_delroute_req *req,
					   __u32 initcwnd)
{
	req->_present.metrics = 1;
	req->metrics._present.initcwnd = 1;
	req->metrics.initcwnd = initcwnd;
}
static inline void
rt_route_delroute_req_set_metrics_features(struct rt_route_delroute_req *req,
					   __u32 features)
{
	req->_present.metrics = 1;
	req->metrics._present.features = 1;
	req->metrics.features = features;
}
static inline void
rt_route_delroute_req_set_metrics_rto_min(struct rt_route_delroute_req *req,
					  __u32 rto_min)
{
	req->_present.metrics = 1;
	req->metrics._present.rto_min = 1;
	req->metrics.rto_min = rto_min;
}
static inline void
rt_route_delroute_req_set_metrics_initrwnd(struct rt_route_delroute_req *req,
					   __u32 initrwnd)
{
	req->_present.metrics = 1;
	req->metrics._present.initrwnd = 1;
	req->metrics.initrwnd = initrwnd;
}
static inline void
rt_route_delroute_req_set_metrics_quickack(struct rt_route_delroute_req *req,
					   __u32 quickack)
{
	req->_present.metrics = 1;
	req->metrics._present.quickack = 1;
	req->metrics.quickack = quickack;
}
static inline void
rt_route_delroute_req_set_metrics_cc_algo(struct rt_route_delroute_req *req,
					  const char *cc_algo)
{
	req->_present.metrics = 1;
	free(req->metrics.cc_algo);
	req->metrics._present.cc_algo_len = strlen(cc_algo);
	req->metrics.cc_algo = malloc(req->metrics._present.cc_algo_len + 1);
	memcpy(req->metrics.cc_algo, cc_algo, req->metrics._present.cc_algo_len);
	req->metrics.cc_algo[req->metrics._present.cc_algo_len] = 0;
}
static inline void
rt_route_delroute_req_set_metrics_fastopen_no_cookie(struct rt_route_delroute_req *req,
						     __u32 fastopen_no_cookie)
{
	req->_present.metrics = 1;
	req->metrics._present.fastopen_no_cookie = 1;
	req->metrics.fastopen_no_cookie = fastopen_no_cookie;
}
static inline void
rt_route_delroute_req_set_multipath(struct rt_route_delroute_req *req,
				    const void *multipath, size_t len)
{
	free(req->multipath);
	req->_present.multipath_len = len;
	req->multipath = malloc(req->_present.multipath_len);
	memcpy(req->multipath, multipath, req->_present.multipath_len);
}
static inline void
rt_route_delroute_req_set_flow(struct rt_route_delroute_req *req, __u32 flow)
{
	req->_present.flow = 1;
	req->flow = flow;
}
static inline void
rt_route_delroute_req_set_cacheinfo(struct rt_route_delroute_req *req,
				    const void *cacheinfo, size_t len)
{
	free(req->cacheinfo);
	req->_present.cacheinfo_len = len;
	req->cacheinfo = malloc(req->_present.cacheinfo_len);
	memcpy(req->cacheinfo, cacheinfo, req->_present.cacheinfo_len);
}
static inline void
rt_route_delroute_req_set_table(struct rt_route_delroute_req *req, __u32 table)
{
	req->_present.table = 1;
	req->table = table;
}
static inline void
rt_route_delroute_req_set_mark(struct rt_route_delroute_req *req, __u32 mark)
{
	req->_present.mark = 1;
	req->mark = mark;
}
static inline void
rt_route_delroute_req_set_mfc_stats(struct rt_route_delroute_req *req,
				    const void *mfc_stats, size_t len)
{
	free(req->mfc_stats);
	req->_present.mfc_stats_len = len;
	req->mfc_stats = malloc(req->_present.mfc_stats_len);
	memcpy(req->mfc_stats, mfc_stats, req->_present.mfc_stats_len);
}
static inline void
rt_route_delroute_req_set_via(struct rt_route_delroute_req *req,
			      const void *via, size_t len)
{
	free(req->via);
	req->_present.via_len = len;
	req->via = malloc(req->_present.via_len);
	memcpy(req->via, via, req->_present.via_len);
}
static inline void
rt_route_delroute_req_set_newdst(struct rt_route_delroute_req *req,
				 const void *newdst, size_t len)
{
	free(req->newdst);
	req->_present.newdst_len = len;
	req->newdst = malloc(req->_present.newdst_len);
	memcpy(req->newdst, newdst, req->_present.newdst_len);
}
static inline void
rt_route_delroute_req_set_pref(struct rt_route_delroute_req *req, __u8 pref)
{
	req->_present.pref = 1;
	req->pref = pref;
}
static inline void
rt_route_delroute_req_set_encap_type(struct rt_route_delroute_req *req,
				     __u16 encap_type)
{
	req->_present.encap_type = 1;
	req->encap_type = encap_type;
}
static inline void
rt_route_delroute_req_set_encap(struct rt_route_delroute_req *req,
				const void *encap, size_t len)
{
	free(req->encap);
	req->_present.encap_len = len;
	req->encap = malloc(req->_present.encap_len);
	memcpy(req->encap, encap, req->_present.encap_len);
}
static inline void
rt_route_delroute_req_set_expires(struct rt_route_delroute_req *req,
				  __u32 expires)
{
	req->_present.expires = 1;
	req->expires = expires;
}
static inline void
rt_route_delroute_req_set_pad(struct rt_route_delroute_req *req,
			      const void *pad, size_t len)
{
	free(req->pad);
	req->_present.pad_len = len;
	req->pad = malloc(req->_present.pad_len);
	memcpy(req->pad, pad, req->_present.pad_len);
}
static inline void
rt_route_delroute_req_set_uid(struct rt_route_delroute_req *req, __u32 uid)
{
	req->_present.uid = 1;
	req->uid = uid;
}
static inline void
rt_route_delroute_req_set_ttl_propagate(struct rt_route_delroute_req *req,
					__u8 ttl_propagate)
{
	req->_present.ttl_propagate = 1;
	req->ttl_propagate = ttl_propagate;
}
static inline void
rt_route_delroute_req_set_ip_proto(struct rt_route_delroute_req *req,
				   __u8 ip_proto)
{
	req->_present.ip_proto = 1;
	req->ip_proto = ip_proto;
}
static inline void
rt_route_delroute_req_set_sport(struct rt_route_delroute_req *req, __u16 sport)
{
	req->_present.sport = 1;
	req->sport = sport;
}
static inline void
rt_route_delroute_req_set_dport(struct rt_route_delroute_req *req, __u16 dport)
{
	req->_present.dport = 1;
	req->dport = dport;
}
static inline void
rt_route_delroute_req_set_nh_id(struct rt_route_delroute_req *req, __u32 nh_id)
{
	req->_present.nh_id = 1;
	req->nh_id = nh_id;
}
static inline void
rt_route_delroute_req_set_flowlabel(struct rt_route_delroute_req *req,
				    __u32 flowlabel /* big-endian */)
{
	req->_present.flowlabel = 1;
	req->flowlabel = flowlabel;
}

/*
 * Delete an existing route
 */
int rt_route_delroute(struct ynl_sock *ys, struct rt_route_delroute_req *req);

#endif /* _LINUX_RT_ROUTE_GEN_H */
