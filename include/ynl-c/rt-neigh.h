/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-neigh.yaml */
/* YNL-GEN user header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_RT_NEIGH_GEN_H
#define _LINUX_RT_NEIGH_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/rtnetlink.h>

struct ynl_sock;

extern const struct ynl_family ynl_rt_neigh_family;

/* Enums */
const char *rt_neigh_op_str(int op);
const char *rt_neigh_nud_state_str(int value);
const char *rt_neigh_ntf_flags_str(int value);
const char *rt_neigh_ntf_ext_flags_str(int value);
const char *rt_neigh_rtm_type_str(int value);

/* Common nested types */
struct rt_neigh_ndtpa_attrs {
	struct {
		__u32 ifindex:1;
		__u32 refcnt:1;
		__u32 reachable_time:1;
		__u32 base_reachable_time:1;
		__u32 retrans_time:1;
		__u32 gc_staletime:1;
		__u32 delay_probe_time:1;
		__u32 queue_len:1;
		__u32 app_probes:1;
		__u32 ucast_probes:1;
		__u32 mcast_probes:1;
		__u32 anycast_delay:1;
		__u32 proxy_delay:1;
		__u32 proxy_qlen:1;
		__u32 locktime:1;
		__u32 queue_lenbytes:1;
		__u32 mcast_reprobes:1;
		__u32 interval_probe_time_ms:1;
	} _present;

	__u32 ifindex;
	__u32 refcnt;
	__u64 reachable_time;
	__u64 base_reachable_time;
	__u64 retrans_time;
	__u64 gc_staletime;
	__u64 delay_probe_time;
	__u32 queue_len;
	__u32 app_probes;
	__u32 ucast_probes;
	__u32 mcast_probes;
	__u64 anycast_delay;
	__u64 proxy_delay;
	__u32 proxy_qlen;
	__u64 locktime;
	__u32 queue_lenbytes;
	__u32 mcast_reprobes;
	__u64 interval_probe_time_ms;
};

/* ============== RTM_NEWNEIGH ============== */
/* RTM_NEWNEIGH - do */
struct rt_neigh_newneigh_req {
	__u16 _nlmsg_flags;

	struct ndmsg _hdr;

	struct {
		__u32 probes:1;
		__u32 vlan:1;
		__u32 port:1;
		__u32 vni:1;
		__u32 ifindex:1;
		__u32 master:1;
		__u32 protocol:1;
		__u32 nh_id:1;
		__u32 flags_ext:1;
	} _present;
	struct {
		__u32 dst;
		__u32 lladdr;
		__u32 fdb_ext_attrs;
	} _len;

	void *dst;
	void *lladdr;
	__u32 probes;
	__u16 vlan;
	__u16 port;
	__u32 vni;
	__u32 ifindex;
	__u32 master;
	__u8 protocol;
	__u32 nh_id;
	__u32 flags_ext;
	void *fdb_ext_attrs;
};

static inline struct rt_neigh_newneigh_req *rt_neigh_newneigh_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_neigh_newneigh_req));
}
void rt_neigh_newneigh_req_free(struct rt_neigh_newneigh_req *req);

static inline void
rt_neigh_newneigh_req_set_nlflags(struct rt_neigh_newneigh_req *req,
				  __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_neigh_newneigh_req_set_dst(struct rt_neigh_newneigh_req *req,
			      const void *dst, size_t len)
{
	free(req->dst);
	req->_len.dst = len;
	req->dst = malloc(req->_len.dst);
	memcpy(req->dst, dst, req->_len.dst);
}
static inline void
rt_neigh_newneigh_req_set_lladdr(struct rt_neigh_newneigh_req *req,
				 const void *lladdr, size_t len)
{
	free(req->lladdr);
	req->_len.lladdr = len;
	req->lladdr = malloc(req->_len.lladdr);
	memcpy(req->lladdr, lladdr, req->_len.lladdr);
}
static inline void
rt_neigh_newneigh_req_set_probes(struct rt_neigh_newneigh_req *req,
				 __u32 probes)
{
	req->_present.probes = 1;
	req->probes = probes;
}
static inline void
rt_neigh_newneigh_req_set_vlan(struct rt_neigh_newneigh_req *req, __u16 vlan)
{
	req->_present.vlan = 1;
	req->vlan = vlan;
}
static inline void
rt_neigh_newneigh_req_set_port(struct rt_neigh_newneigh_req *req, __u16 port)
{
	req->_present.port = 1;
	req->port = port;
}
static inline void
rt_neigh_newneigh_req_set_vni(struct rt_neigh_newneigh_req *req, __u32 vni)
{
	req->_present.vni = 1;
	req->vni = vni;
}
static inline void
rt_neigh_newneigh_req_set_ifindex(struct rt_neigh_newneigh_req *req,
				  __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
rt_neigh_newneigh_req_set_master(struct rt_neigh_newneigh_req *req,
				 __u32 master)
{
	req->_present.master = 1;
	req->master = master;
}
static inline void
rt_neigh_newneigh_req_set_protocol(struct rt_neigh_newneigh_req *req,
				   __u8 protocol)
{
	req->_present.protocol = 1;
	req->protocol = protocol;
}
static inline void
rt_neigh_newneigh_req_set_nh_id(struct rt_neigh_newneigh_req *req, __u32 nh_id)
{
	req->_present.nh_id = 1;
	req->nh_id = nh_id;
}
static inline void
rt_neigh_newneigh_req_set_flags_ext(struct rt_neigh_newneigh_req *req,
				    __u32 flags_ext)
{
	req->_present.flags_ext = 1;
	req->flags_ext = flags_ext;
}
static inline void
rt_neigh_newneigh_req_set_fdb_ext_attrs(struct rt_neigh_newneigh_req *req,
					const void *fdb_ext_attrs, size_t len)
{
	free(req->fdb_ext_attrs);
	req->_len.fdb_ext_attrs = len;
	req->fdb_ext_attrs = malloc(req->_len.fdb_ext_attrs);
	memcpy(req->fdb_ext_attrs, fdb_ext_attrs, req->_len.fdb_ext_attrs);
}

/*
 * Add new neighbour entry
 */
int rt_neigh_newneigh(struct ynl_sock *ys, struct rt_neigh_newneigh_req *req);

/* ============== RTM_DELNEIGH ============== */
/* RTM_DELNEIGH - do */
struct rt_neigh_delneigh_req {
	__u16 _nlmsg_flags;

	struct ndmsg _hdr;

	struct {
		__u32 ifindex:1;
	} _present;
	struct {
		__u32 dst;
	} _len;

	void *dst;
	__u32 ifindex;
};

static inline struct rt_neigh_delneigh_req *rt_neigh_delneigh_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_neigh_delneigh_req));
}
void rt_neigh_delneigh_req_free(struct rt_neigh_delneigh_req *req);

static inline void
rt_neigh_delneigh_req_set_nlflags(struct rt_neigh_delneigh_req *req,
				  __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_neigh_delneigh_req_set_dst(struct rt_neigh_delneigh_req *req,
			      const void *dst, size_t len)
{
	free(req->dst);
	req->_len.dst = len;
	req->dst = malloc(req->_len.dst);
	memcpy(req->dst, dst, req->_len.dst);
}
static inline void
rt_neigh_delneigh_req_set_ifindex(struct rt_neigh_delneigh_req *req,
				  __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}

/*
 * Remove an existing neighbour entry
 */
int rt_neigh_delneigh(struct ynl_sock *ys, struct rt_neigh_delneigh_req *req);

/* ============== RTM_GETNEIGH ============== */
/* RTM_GETNEIGH - do */
struct rt_neigh_getneigh_req {
	__u16 _nlmsg_flags;

	struct ndmsg _hdr;

	struct {
		__u32 dst;
	} _len;

	void *dst;
};

static inline struct rt_neigh_getneigh_req *rt_neigh_getneigh_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_neigh_getneigh_req));
}
void rt_neigh_getneigh_req_free(struct rt_neigh_getneigh_req *req);

static inline void
rt_neigh_getneigh_req_set_nlflags(struct rt_neigh_getneigh_req *req,
				  __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_neigh_getneigh_req_set_dst(struct rt_neigh_getneigh_req *req,
			      const void *dst, size_t len)
{
	free(req->dst);
	req->_len.dst = len;
	req->dst = malloc(req->_len.dst);
	memcpy(req->dst, dst, req->_len.dst);
}

struct rt_neigh_getneigh_rsp {
	struct ndmsg _hdr;

	struct {
		__u32 probes:1;
		__u32 vlan:1;
		__u32 port:1;
		__u32 vni:1;
		__u32 ifindex:1;
		__u32 master:1;
		__u32 protocol:1;
		__u32 nh_id:1;
		__u32 flags_ext:1;
	} _present;
	struct {
		__u32 dst;
		__u32 lladdr;
		__u32 fdb_ext_attrs;
	} _len;

	void *dst;
	void *lladdr;
	__u32 probes;
	__u16 vlan;
	__u16 port;
	__u32 vni;
	__u32 ifindex;
	__u32 master;
	__u8 protocol;
	__u32 nh_id;
	__u32 flags_ext;
	void *fdb_ext_attrs;
};

void rt_neigh_getneigh_rsp_free(struct rt_neigh_getneigh_rsp *rsp);

/*
 * Get or dump neighbour entries
 */
struct rt_neigh_getneigh_rsp *
rt_neigh_getneigh(struct ynl_sock *ys, struct rt_neigh_getneigh_req *req);

/* RTM_GETNEIGH - dump */
struct rt_neigh_getneigh_req_dump {
	struct ndmsg _hdr;

	struct {
		__u32 ifindex:1;
		__u32 master:1;
	} _present;

	__u32 ifindex;
	__u32 master;
};

static inline struct rt_neigh_getneigh_req_dump *
rt_neigh_getneigh_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct rt_neigh_getneigh_req_dump));
}
void rt_neigh_getneigh_req_dump_free(struct rt_neigh_getneigh_req_dump *req);

static inline void
rt_neigh_getneigh_req_dump_set_ifindex(struct rt_neigh_getneigh_req_dump *req,
				       __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
rt_neigh_getneigh_req_dump_set_master(struct rt_neigh_getneigh_req_dump *req,
				      __u32 master)
{
	req->_present.master = 1;
	req->master = master;
}

struct rt_neigh_getneigh_list {
	struct rt_neigh_getneigh_list *next;
	struct rt_neigh_getneigh_rsp obj __attribute__((aligned(8)));
};

void rt_neigh_getneigh_list_free(struct rt_neigh_getneigh_list *rsp);

struct rt_neigh_getneigh_list *
rt_neigh_getneigh_dump(struct ynl_sock *ys,
		       struct rt_neigh_getneigh_req_dump *req);

/* RTM_GETNEIGH - notify */
struct rt_neigh_getneigh_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct rt_neigh_getneigh_ntf *ntf);
	struct rt_neigh_getneigh_rsp obj __attribute__((aligned(8)));
};

void rt_neigh_getneigh_ntf_free(struct rt_neigh_getneigh_ntf *rsp);

/* ============== RTM_GETNEIGHTBL ============== */
/* RTM_GETNEIGHTBL - dump */
struct rt_neigh_getneightbl_req {
	struct ndtmsg _hdr;
};

static inline struct rt_neigh_getneightbl_req *
rt_neigh_getneightbl_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_neigh_getneightbl_req));
}
void rt_neigh_getneightbl_req_free(struct rt_neigh_getneightbl_req *req);

struct rt_neigh_getneightbl_rsp {
	struct ndtmsg _hdr;

	struct {
		__u32 thresh1:1;
		__u32 thresh2:1;
		__u32 thresh3:1;
		__u32 parms:1;
		__u32 gc_interval:1;
	} _present;
	struct {
		__u32 name;
		__u32 config;
		__u32 stats;
	} _len;

	char *name;
	__u32 thresh1;
	__u32 thresh2;
	__u32 thresh3;
	struct ndt_config *config;
	struct rt_neigh_ndtpa_attrs parms;
	struct ndt_stats *stats;
	__u64 gc_interval;
};

struct rt_neigh_getneightbl_list {
	struct rt_neigh_getneightbl_list *next;
	struct rt_neigh_getneightbl_rsp obj __attribute__((aligned(8)));
};

void rt_neigh_getneightbl_list_free(struct rt_neigh_getneightbl_list *rsp);

struct rt_neigh_getneightbl_list *
rt_neigh_getneightbl_dump(struct ynl_sock *ys,
			  struct rt_neigh_getneightbl_req *req);

/* ============== RTM_SETNEIGHTBL ============== */
/* RTM_SETNEIGHTBL - do */
struct rt_neigh_setneightbl_req {
	__u16 _nlmsg_flags;

	struct ndtmsg _hdr;

	struct {
		__u32 thresh1:1;
		__u32 thresh2:1;
		__u32 thresh3:1;
		__u32 parms:1;
		__u32 gc_interval:1;
	} _present;
	struct {
		__u32 name;
	} _len;

	char *name;
	__u32 thresh1;
	__u32 thresh2;
	__u32 thresh3;
	struct rt_neigh_ndtpa_attrs parms;
	__u64 gc_interval;
};

static inline struct rt_neigh_setneightbl_req *
rt_neigh_setneightbl_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_neigh_setneightbl_req));
}
void rt_neigh_setneightbl_req_free(struct rt_neigh_setneightbl_req *req);

static inline void
rt_neigh_setneightbl_req_set_nlflags(struct rt_neigh_setneightbl_req *req,
				     __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_neigh_setneightbl_req_set_name(struct rt_neigh_setneightbl_req *req,
				  const char *name)
{
	free(req->name);
	req->_len.name = strlen(name);
	req->name = malloc(req->_len.name + 1);
	memcpy(req->name, name, req->_len.name);
	req->name[req->_len.name] = 0;
}
static inline void
rt_neigh_setneightbl_req_set_thresh1(struct rt_neigh_setneightbl_req *req,
				     __u32 thresh1)
{
	req->_present.thresh1 = 1;
	req->thresh1 = thresh1;
}
static inline void
rt_neigh_setneightbl_req_set_thresh2(struct rt_neigh_setneightbl_req *req,
				     __u32 thresh2)
{
	req->_present.thresh2 = 1;
	req->thresh2 = thresh2;
}
static inline void
rt_neigh_setneightbl_req_set_thresh3(struct rt_neigh_setneightbl_req *req,
				     __u32 thresh3)
{
	req->_present.thresh3 = 1;
	req->thresh3 = thresh3;
}
static inline void
rt_neigh_setneightbl_req_set_parms_ifindex(struct rt_neigh_setneightbl_req *req,
					   __u32 ifindex)
{
	req->_present.parms = 1;
	req->parms._present.ifindex = 1;
	req->parms.ifindex = ifindex;
}
static inline void
rt_neigh_setneightbl_req_set_parms_refcnt(struct rt_neigh_setneightbl_req *req,
					  __u32 refcnt)
{
	req->_present.parms = 1;
	req->parms._present.refcnt = 1;
	req->parms.refcnt = refcnt;
}
static inline void
rt_neigh_setneightbl_req_set_parms_reachable_time(struct rt_neigh_setneightbl_req *req,
						  __u64 reachable_time)
{
	req->_present.parms = 1;
	req->parms._present.reachable_time = 1;
	req->parms.reachable_time = reachable_time;
}
static inline void
rt_neigh_setneightbl_req_set_parms_base_reachable_time(struct rt_neigh_setneightbl_req *req,
						       __u64 base_reachable_time)
{
	req->_present.parms = 1;
	req->parms._present.base_reachable_time = 1;
	req->parms.base_reachable_time = base_reachable_time;
}
static inline void
rt_neigh_setneightbl_req_set_parms_retrans_time(struct rt_neigh_setneightbl_req *req,
						__u64 retrans_time)
{
	req->_present.parms = 1;
	req->parms._present.retrans_time = 1;
	req->parms.retrans_time = retrans_time;
}
static inline void
rt_neigh_setneightbl_req_set_parms_gc_staletime(struct rt_neigh_setneightbl_req *req,
						__u64 gc_staletime)
{
	req->_present.parms = 1;
	req->parms._present.gc_staletime = 1;
	req->parms.gc_staletime = gc_staletime;
}
static inline void
rt_neigh_setneightbl_req_set_parms_delay_probe_time(struct rt_neigh_setneightbl_req *req,
						    __u64 delay_probe_time)
{
	req->_present.parms = 1;
	req->parms._present.delay_probe_time = 1;
	req->parms.delay_probe_time = delay_probe_time;
}
static inline void
rt_neigh_setneightbl_req_set_parms_queue_len(struct rt_neigh_setneightbl_req *req,
					     __u32 queue_len)
{
	req->_present.parms = 1;
	req->parms._present.queue_len = 1;
	req->parms.queue_len = queue_len;
}
static inline void
rt_neigh_setneightbl_req_set_parms_app_probes(struct rt_neigh_setneightbl_req *req,
					      __u32 app_probes)
{
	req->_present.parms = 1;
	req->parms._present.app_probes = 1;
	req->parms.app_probes = app_probes;
}
static inline void
rt_neigh_setneightbl_req_set_parms_ucast_probes(struct rt_neigh_setneightbl_req *req,
						__u32 ucast_probes)
{
	req->_present.parms = 1;
	req->parms._present.ucast_probes = 1;
	req->parms.ucast_probes = ucast_probes;
}
static inline void
rt_neigh_setneightbl_req_set_parms_mcast_probes(struct rt_neigh_setneightbl_req *req,
						__u32 mcast_probes)
{
	req->_present.parms = 1;
	req->parms._present.mcast_probes = 1;
	req->parms.mcast_probes = mcast_probes;
}
static inline void
rt_neigh_setneightbl_req_set_parms_anycast_delay(struct rt_neigh_setneightbl_req *req,
						 __u64 anycast_delay)
{
	req->_present.parms = 1;
	req->parms._present.anycast_delay = 1;
	req->parms.anycast_delay = anycast_delay;
}
static inline void
rt_neigh_setneightbl_req_set_parms_proxy_delay(struct rt_neigh_setneightbl_req *req,
					       __u64 proxy_delay)
{
	req->_present.parms = 1;
	req->parms._present.proxy_delay = 1;
	req->parms.proxy_delay = proxy_delay;
}
static inline void
rt_neigh_setneightbl_req_set_parms_proxy_qlen(struct rt_neigh_setneightbl_req *req,
					      __u32 proxy_qlen)
{
	req->_present.parms = 1;
	req->parms._present.proxy_qlen = 1;
	req->parms.proxy_qlen = proxy_qlen;
}
static inline void
rt_neigh_setneightbl_req_set_parms_locktime(struct rt_neigh_setneightbl_req *req,
					    __u64 locktime)
{
	req->_present.parms = 1;
	req->parms._present.locktime = 1;
	req->parms.locktime = locktime;
}
static inline void
rt_neigh_setneightbl_req_set_parms_queue_lenbytes(struct rt_neigh_setneightbl_req *req,
						  __u32 queue_lenbytes)
{
	req->_present.parms = 1;
	req->parms._present.queue_lenbytes = 1;
	req->parms.queue_lenbytes = queue_lenbytes;
}
static inline void
rt_neigh_setneightbl_req_set_parms_mcast_reprobes(struct rt_neigh_setneightbl_req *req,
						  __u32 mcast_reprobes)
{
	req->_present.parms = 1;
	req->parms._present.mcast_reprobes = 1;
	req->parms.mcast_reprobes = mcast_reprobes;
}
static inline void
rt_neigh_setneightbl_req_set_parms_interval_probe_time_ms(struct rt_neigh_setneightbl_req *req,
							  __u64 interval_probe_time_ms)
{
	req->_present.parms = 1;
	req->parms._present.interval_probe_time_ms = 1;
	req->parms.interval_probe_time_ms = interval_probe_time_ms;
}
static inline void
rt_neigh_setneightbl_req_set_gc_interval(struct rt_neigh_setneightbl_req *req,
					 __u64 gc_interval)
{
	req->_present.gc_interval = 1;
	req->gc_interval = gc_interval;
}

/*
 * Set neighbour tables
 */
int rt_neigh_setneightbl(struct ynl_sock *ys,
			 struct rt_neigh_setneightbl_req *req);

#endif /* _LINUX_RT_NEIGH_GEN_H */
