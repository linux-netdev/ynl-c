/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-rule.yaml */
/* YNL-GEN user header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_RT_RULE_GEN_H
#define _LINUX_RT_RULE_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/fib_rules.h>

struct ynl_sock;

extern const struct ynl_family ynl_rt_rule_family;

/* Enums */
const char *rt_rule_op_str(int op);
const char *rt_rule_fr_act_str(int value);

/* Common nested types */
/* ============== RTM_NEWRULE ============== */
/* RTM_NEWRULE - do */
struct rt_rule_newrule_req {
	__u16 _nlmsg_flags;

	struct fib_rule_hdr _hdr;

	struct {
		__u32 priority:1;
		__u32 fwmark:1;
		__u32 flow:1;
		__u32 tun_id:1;
		__u32 fwmask:1;
		__u32 table:1;
		__u32 suppress_prefixlen:1;
		__u32 suppress_ifgroup:1;
		__u32 goto_:1;
		__u32 l3mdev:1;
		__u32 protocol:1;
		__u32 ip_proto:1;
		__u32 dscp:1;
		__u32 flowlabel:1;
		__u32 flowlabel_mask:1;
		__u32 sport_mask:1;
		__u32 dport_mask:1;
		__u32 dscp_mask:1;
	} _present;
	struct {
		__u32 iifname;
		__u32 oifname;
		__u32 uid_range;
		__u32 sport_range;
		__u32 dport_range;
	} _len;

	char *iifname;
	char *oifname;
	__u32 priority;
	__u32 fwmark;
	__u32 flow;
	__u64 tun_id;
	__u32 fwmask;
	__u32 table;
	__u32 suppress_prefixlen;
	__u32 suppress_ifgroup;
	__u32 goto_;
	__u8 l3mdev;
	struct fib_rule_uid_range *uid_range;
	__u8 protocol;
	__u8 ip_proto;
	struct fib_rule_port_range *sport_range;
	struct fib_rule_port_range *dport_range;
	__u8 dscp;
	__u32 flowlabel /* big-endian */;
	__u32 flowlabel_mask /* big-endian */;
	__u16 sport_mask;
	__u16 dport_mask;
	__u8 dscp_mask;
};

static inline struct rt_rule_newrule_req *rt_rule_newrule_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_rule_newrule_req));
}
void rt_rule_newrule_req_free(struct rt_rule_newrule_req *req);

static inline void
rt_rule_newrule_req_set_nlflags(struct rt_rule_newrule_req *req,
				__u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_rule_newrule_req_set_iifname(struct rt_rule_newrule_req *req,
				const char *iifname)
{
	free(req->iifname);
	req->_len.iifname = strlen(iifname);
	req->iifname = malloc(req->_len.iifname + 1);
	memcpy(req->iifname, iifname, req->_len.iifname);
	req->iifname[req->_len.iifname] = 0;
}
static inline void
rt_rule_newrule_req_set_oifname(struct rt_rule_newrule_req *req,
				const char *oifname)
{
	free(req->oifname);
	req->_len.oifname = strlen(oifname);
	req->oifname = malloc(req->_len.oifname + 1);
	memcpy(req->oifname, oifname, req->_len.oifname);
	req->oifname[req->_len.oifname] = 0;
}
static inline void
rt_rule_newrule_req_set_priority(struct rt_rule_newrule_req *req,
				 __u32 priority)
{
	req->_present.priority = 1;
	req->priority = priority;
}
static inline void
rt_rule_newrule_req_set_fwmark(struct rt_rule_newrule_req *req, __u32 fwmark)
{
	req->_present.fwmark = 1;
	req->fwmark = fwmark;
}
static inline void
rt_rule_newrule_req_set_flow(struct rt_rule_newrule_req *req, __u32 flow)
{
	req->_present.flow = 1;
	req->flow = flow;
}
static inline void
rt_rule_newrule_req_set_tun_id(struct rt_rule_newrule_req *req, __u64 tun_id)
{
	req->_present.tun_id = 1;
	req->tun_id = tun_id;
}
static inline void
rt_rule_newrule_req_set_fwmask(struct rt_rule_newrule_req *req, __u32 fwmask)
{
	req->_present.fwmask = 1;
	req->fwmask = fwmask;
}
static inline void
rt_rule_newrule_req_set_table(struct rt_rule_newrule_req *req, __u32 table)
{
	req->_present.table = 1;
	req->table = table;
}
static inline void
rt_rule_newrule_req_set_suppress_prefixlen(struct rt_rule_newrule_req *req,
					   __u32 suppress_prefixlen)
{
	req->_present.suppress_prefixlen = 1;
	req->suppress_prefixlen = suppress_prefixlen;
}
static inline void
rt_rule_newrule_req_set_suppress_ifgroup(struct rt_rule_newrule_req *req,
					 __u32 suppress_ifgroup)
{
	req->_present.suppress_ifgroup = 1;
	req->suppress_ifgroup = suppress_ifgroup;
}
static inline void
rt_rule_newrule_req_set_goto_(struct rt_rule_newrule_req *req, __u32 goto_)
{
	req->_present.goto_ = 1;
	req->goto_ = goto_;
}
static inline void
rt_rule_newrule_req_set_l3mdev(struct rt_rule_newrule_req *req, __u8 l3mdev)
{
	req->_present.l3mdev = 1;
	req->l3mdev = l3mdev;
}
static inline void
rt_rule_newrule_req_set_uid_range(struct rt_rule_newrule_req *req,
				  const void *uid_range, size_t len)
{
	free(req->uid_range);
	req->_len.uid_range = len;
	req->uid_range = malloc(req->_len.uid_range);
	memcpy(req->uid_range, uid_range, req->_len.uid_range);
}
static inline void
rt_rule_newrule_req_set_protocol(struct rt_rule_newrule_req *req,
				 __u8 protocol)
{
	req->_present.protocol = 1;
	req->protocol = protocol;
}
static inline void
rt_rule_newrule_req_set_ip_proto(struct rt_rule_newrule_req *req,
				 __u8 ip_proto)
{
	req->_present.ip_proto = 1;
	req->ip_proto = ip_proto;
}
static inline void
rt_rule_newrule_req_set_sport_range(struct rt_rule_newrule_req *req,
				    const void *sport_range, size_t len)
{
	free(req->sport_range);
	req->_len.sport_range = len;
	req->sport_range = malloc(req->_len.sport_range);
	memcpy(req->sport_range, sport_range, req->_len.sport_range);
}
static inline void
rt_rule_newrule_req_set_dport_range(struct rt_rule_newrule_req *req,
				    const void *dport_range, size_t len)
{
	free(req->dport_range);
	req->_len.dport_range = len;
	req->dport_range = malloc(req->_len.dport_range);
	memcpy(req->dport_range, dport_range, req->_len.dport_range);
}
static inline void
rt_rule_newrule_req_set_dscp(struct rt_rule_newrule_req *req, __u8 dscp)
{
	req->_present.dscp = 1;
	req->dscp = dscp;
}
static inline void
rt_rule_newrule_req_set_flowlabel(struct rt_rule_newrule_req *req,
				  __u32 flowlabel /* big-endian */)
{
	req->_present.flowlabel = 1;
	req->flowlabel = flowlabel;
}
static inline void
rt_rule_newrule_req_set_flowlabel_mask(struct rt_rule_newrule_req *req,
				       __u32 flowlabel_mask /* big-endian */)
{
	req->_present.flowlabel_mask = 1;
	req->flowlabel_mask = flowlabel_mask;
}
static inline void
rt_rule_newrule_req_set_sport_mask(struct rt_rule_newrule_req *req,
				   __u16 sport_mask)
{
	req->_present.sport_mask = 1;
	req->sport_mask = sport_mask;
}
static inline void
rt_rule_newrule_req_set_dport_mask(struct rt_rule_newrule_req *req,
				   __u16 dport_mask)
{
	req->_present.dport_mask = 1;
	req->dport_mask = dport_mask;
}
static inline void
rt_rule_newrule_req_set_dscp_mask(struct rt_rule_newrule_req *req,
				  __u8 dscp_mask)
{
	req->_present.dscp_mask = 1;
	req->dscp_mask = dscp_mask;
}

/*
 * Add new FIB rule
 */
int rt_rule_newrule(struct ynl_sock *ys, struct rt_rule_newrule_req *req);

/* ============== RTM_DELRULE ============== */
/* RTM_DELRULE - do */
struct rt_rule_delrule_req {
	__u16 _nlmsg_flags;

	struct fib_rule_hdr _hdr;

	struct {
		__u32 priority:1;
		__u32 fwmark:1;
		__u32 flow:1;
		__u32 tun_id:1;
		__u32 fwmask:1;
		__u32 table:1;
		__u32 suppress_prefixlen:1;
		__u32 suppress_ifgroup:1;
		__u32 goto_:1;
		__u32 l3mdev:1;
		__u32 protocol:1;
		__u32 ip_proto:1;
		__u32 dscp:1;
		__u32 flowlabel:1;
		__u32 flowlabel_mask:1;
		__u32 sport_mask:1;
		__u32 dport_mask:1;
		__u32 dscp_mask:1;
	} _present;
	struct {
		__u32 iifname;
		__u32 oifname;
		__u32 uid_range;
		__u32 sport_range;
		__u32 dport_range;
	} _len;

	char *iifname;
	char *oifname;
	__u32 priority;
	__u32 fwmark;
	__u32 flow;
	__u64 tun_id;
	__u32 fwmask;
	__u32 table;
	__u32 suppress_prefixlen;
	__u32 suppress_ifgroup;
	__u32 goto_;
	__u8 l3mdev;
	struct fib_rule_uid_range *uid_range;
	__u8 protocol;
	__u8 ip_proto;
	struct fib_rule_port_range *sport_range;
	struct fib_rule_port_range *dport_range;
	__u8 dscp;
	__u32 flowlabel /* big-endian */;
	__u32 flowlabel_mask /* big-endian */;
	__u16 sport_mask;
	__u16 dport_mask;
	__u8 dscp_mask;
};

static inline struct rt_rule_delrule_req *rt_rule_delrule_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_rule_delrule_req));
}
void rt_rule_delrule_req_free(struct rt_rule_delrule_req *req);

static inline void
rt_rule_delrule_req_set_nlflags(struct rt_rule_delrule_req *req,
				__u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_rule_delrule_req_set_iifname(struct rt_rule_delrule_req *req,
				const char *iifname)
{
	free(req->iifname);
	req->_len.iifname = strlen(iifname);
	req->iifname = malloc(req->_len.iifname + 1);
	memcpy(req->iifname, iifname, req->_len.iifname);
	req->iifname[req->_len.iifname] = 0;
}
static inline void
rt_rule_delrule_req_set_oifname(struct rt_rule_delrule_req *req,
				const char *oifname)
{
	free(req->oifname);
	req->_len.oifname = strlen(oifname);
	req->oifname = malloc(req->_len.oifname + 1);
	memcpy(req->oifname, oifname, req->_len.oifname);
	req->oifname[req->_len.oifname] = 0;
}
static inline void
rt_rule_delrule_req_set_priority(struct rt_rule_delrule_req *req,
				 __u32 priority)
{
	req->_present.priority = 1;
	req->priority = priority;
}
static inline void
rt_rule_delrule_req_set_fwmark(struct rt_rule_delrule_req *req, __u32 fwmark)
{
	req->_present.fwmark = 1;
	req->fwmark = fwmark;
}
static inline void
rt_rule_delrule_req_set_flow(struct rt_rule_delrule_req *req, __u32 flow)
{
	req->_present.flow = 1;
	req->flow = flow;
}
static inline void
rt_rule_delrule_req_set_tun_id(struct rt_rule_delrule_req *req, __u64 tun_id)
{
	req->_present.tun_id = 1;
	req->tun_id = tun_id;
}
static inline void
rt_rule_delrule_req_set_fwmask(struct rt_rule_delrule_req *req, __u32 fwmask)
{
	req->_present.fwmask = 1;
	req->fwmask = fwmask;
}
static inline void
rt_rule_delrule_req_set_table(struct rt_rule_delrule_req *req, __u32 table)
{
	req->_present.table = 1;
	req->table = table;
}
static inline void
rt_rule_delrule_req_set_suppress_prefixlen(struct rt_rule_delrule_req *req,
					   __u32 suppress_prefixlen)
{
	req->_present.suppress_prefixlen = 1;
	req->suppress_prefixlen = suppress_prefixlen;
}
static inline void
rt_rule_delrule_req_set_suppress_ifgroup(struct rt_rule_delrule_req *req,
					 __u32 suppress_ifgroup)
{
	req->_present.suppress_ifgroup = 1;
	req->suppress_ifgroup = suppress_ifgroup;
}
static inline void
rt_rule_delrule_req_set_goto_(struct rt_rule_delrule_req *req, __u32 goto_)
{
	req->_present.goto_ = 1;
	req->goto_ = goto_;
}
static inline void
rt_rule_delrule_req_set_l3mdev(struct rt_rule_delrule_req *req, __u8 l3mdev)
{
	req->_present.l3mdev = 1;
	req->l3mdev = l3mdev;
}
static inline void
rt_rule_delrule_req_set_uid_range(struct rt_rule_delrule_req *req,
				  const void *uid_range, size_t len)
{
	free(req->uid_range);
	req->_len.uid_range = len;
	req->uid_range = malloc(req->_len.uid_range);
	memcpy(req->uid_range, uid_range, req->_len.uid_range);
}
static inline void
rt_rule_delrule_req_set_protocol(struct rt_rule_delrule_req *req,
				 __u8 protocol)
{
	req->_present.protocol = 1;
	req->protocol = protocol;
}
static inline void
rt_rule_delrule_req_set_ip_proto(struct rt_rule_delrule_req *req,
				 __u8 ip_proto)
{
	req->_present.ip_proto = 1;
	req->ip_proto = ip_proto;
}
static inline void
rt_rule_delrule_req_set_sport_range(struct rt_rule_delrule_req *req,
				    const void *sport_range, size_t len)
{
	free(req->sport_range);
	req->_len.sport_range = len;
	req->sport_range = malloc(req->_len.sport_range);
	memcpy(req->sport_range, sport_range, req->_len.sport_range);
}
static inline void
rt_rule_delrule_req_set_dport_range(struct rt_rule_delrule_req *req,
				    const void *dport_range, size_t len)
{
	free(req->dport_range);
	req->_len.dport_range = len;
	req->dport_range = malloc(req->_len.dport_range);
	memcpy(req->dport_range, dport_range, req->_len.dport_range);
}
static inline void
rt_rule_delrule_req_set_dscp(struct rt_rule_delrule_req *req, __u8 dscp)
{
	req->_present.dscp = 1;
	req->dscp = dscp;
}
static inline void
rt_rule_delrule_req_set_flowlabel(struct rt_rule_delrule_req *req,
				  __u32 flowlabel /* big-endian */)
{
	req->_present.flowlabel = 1;
	req->flowlabel = flowlabel;
}
static inline void
rt_rule_delrule_req_set_flowlabel_mask(struct rt_rule_delrule_req *req,
				       __u32 flowlabel_mask /* big-endian */)
{
	req->_present.flowlabel_mask = 1;
	req->flowlabel_mask = flowlabel_mask;
}
static inline void
rt_rule_delrule_req_set_sport_mask(struct rt_rule_delrule_req *req,
				   __u16 sport_mask)
{
	req->_present.sport_mask = 1;
	req->sport_mask = sport_mask;
}
static inline void
rt_rule_delrule_req_set_dport_mask(struct rt_rule_delrule_req *req,
				   __u16 dport_mask)
{
	req->_present.dport_mask = 1;
	req->dport_mask = dport_mask;
}
static inline void
rt_rule_delrule_req_set_dscp_mask(struct rt_rule_delrule_req *req,
				  __u8 dscp_mask)
{
	req->_present.dscp_mask = 1;
	req->dscp_mask = dscp_mask;
}

/*
 * Remove an existing FIB rule
 */
int rt_rule_delrule(struct ynl_sock *ys, struct rt_rule_delrule_req *req);

/* ============== RTM_GETRULE ============== */
/* RTM_GETRULE - dump */
struct rt_rule_getrule_req {
	struct fib_rule_hdr _hdr;
};

static inline struct rt_rule_getrule_req *rt_rule_getrule_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_rule_getrule_req));
}
void rt_rule_getrule_req_free(struct rt_rule_getrule_req *req);

struct rt_rule_getrule_rsp {
	struct fib_rule_hdr _hdr;

	struct {
		__u32 priority:1;
		__u32 fwmark:1;
		__u32 flow:1;
		__u32 tun_id:1;
		__u32 fwmask:1;
		__u32 table:1;
		__u32 suppress_prefixlen:1;
		__u32 suppress_ifgroup:1;
		__u32 goto_:1;
		__u32 l3mdev:1;
		__u32 protocol:1;
		__u32 ip_proto:1;
		__u32 dscp:1;
		__u32 flowlabel:1;
		__u32 flowlabel_mask:1;
		__u32 sport_mask:1;
		__u32 dport_mask:1;
		__u32 dscp_mask:1;
	} _present;
	struct {
		__u32 iifname;
		__u32 oifname;
		__u32 uid_range;
		__u32 sport_range;
		__u32 dport_range;
	} _len;

	char *iifname;
	char *oifname;
	__u32 priority;
	__u32 fwmark;
	__u32 flow;
	__u64 tun_id;
	__u32 fwmask;
	__u32 table;
	__u32 suppress_prefixlen;
	__u32 suppress_ifgroup;
	__u32 goto_;
	__u8 l3mdev;
	struct fib_rule_uid_range *uid_range;
	__u8 protocol;
	__u8 ip_proto;
	struct fib_rule_port_range *sport_range;
	struct fib_rule_port_range *dport_range;
	__u8 dscp;
	__u32 flowlabel /* big-endian */;
	__u32 flowlabel_mask /* big-endian */;
	__u16 sport_mask;
	__u16 dport_mask;
	__u8 dscp_mask;
};

struct rt_rule_getrule_list {
	struct rt_rule_getrule_list *next;
	struct rt_rule_getrule_rsp obj __attribute__((aligned(8)));
};

void rt_rule_getrule_list_free(struct rt_rule_getrule_list *rsp);

struct rt_rule_getrule_list *
rt_rule_getrule_dump(struct ynl_sock *ys, struct rt_rule_getrule_req *req);

/* RTM_GETRULE - notify */
struct rt_rule_getrule_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct rt_rule_getrule_ntf *ntf);
	struct rt_rule_getrule_rsp obj __attribute__((aligned(8)));
};

void rt_rule_getrule_ntf_free(struct rt_rule_getrule_ntf *rsp);

#endif /* _LINUX_RT_RULE_GEN_H */
