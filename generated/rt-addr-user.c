// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-addr.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "rt-addr-user.h"
#include "ynl.h"
#include <linux/rtnetlink.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const rt_addr_op_strmap[] = {
	[20] = "getaddr",
	[RTM_GETMULTICAST] = "getmulticast",
};

const char *rt_addr_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(rt_addr_op_strmap))
		return NULL;
	return rt_addr_op_strmap[op];
}

static const char * const rt_addr_ifa_flags_strmap[] = {
	[0] = "secondary",
	[1] = "nodad",
	[2] = "optimistic",
	[3] = "dadfailed",
	[4] = "homeaddress",
	[5] = "deprecated",
	[6] = "tentative",
	[7] = "permanent",
	[8] = "managetempaddr",
	[9] = "noprefixroute",
	[10] = "mcautojoin",
	[11] = "stable-privacy",
};

const char *rt_addr_ifa_flags_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(rt_addr_ifa_flags_strmap))
		return NULL;
	return rt_addr_ifa_flags_strmap[value];
}

/* Policies */
const struct ynl_policy_attr rt_addr_addr_attrs_policy[IFA_MAX + 1] = {
	[IFA_ADDRESS] = { .name = "address", .type = YNL_PT_BINARY,},
	[IFA_LOCAL] = { .name = "local", .type = YNL_PT_BINARY,},
	[IFA_LABEL] = { .name = "label", .type = YNL_PT_NUL_STR, },
	[IFA_BROADCAST] = { .name = "broadcast", .type = YNL_PT_U32, },
	[IFA_ANYCAST] = { .name = "anycast", .type = YNL_PT_BINARY,},
	[IFA_CACHEINFO] = { .name = "cacheinfo", .type = YNL_PT_BINARY,},
	[IFA_MULTICAST] = { .name = "multicast", .type = YNL_PT_BINARY,},
	[IFA_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[IFA_RT_PRIORITY] = { .name = "rt-priority", .type = YNL_PT_U32, },
	[IFA_TARGET_NETNSID] = { .name = "target-netnsid", .type = YNL_PT_BINARY,},
	[IFA_PROTO] = { .name = "proto", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest rt_addr_addr_attrs_nest = {
	.max_attr = IFA_MAX,
	.table = rt_addr_addr_attrs_policy,
};

/* Common nested types */
/* ============== RTM_NEWADDR ============== */
/* RTM_NEWADDR - do */
void rt_addr_newaddr_req_free(struct rt_addr_newaddr_req *req)
{
	free(req->address);
	free(req->label);
	free(req->local);
	free(req->cacheinfo);
	free(req);
}

int rt_addr_newaddr(struct ynl_sock *ys, struct rt_addr_newaddr_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWADDR, req->_nlmsg_flags);
	ys->req_policy = &rt_addr_addr_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.address)
		ynl_attr_put(nlh, IFA_ADDRESS, req->address, req->_len.address);
	if (req->_len.label)
		ynl_attr_put_str(nlh, IFA_LABEL, req->label);
	if (req->_len.local)
		ynl_attr_put(nlh, IFA_LOCAL, req->local, req->_len.local);
	if (req->_len.cacheinfo)
		ynl_attr_put(nlh, IFA_CACHEINFO, req->cacheinfo, req->_len.cacheinfo);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_DELADDR ============== */
/* RTM_DELADDR - do */
void rt_addr_deladdr_req_free(struct rt_addr_deladdr_req *req)
{
	free(req->address);
	free(req->local);
	free(req);
}

int rt_addr_deladdr(struct ynl_sock *ys, struct rt_addr_deladdr_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELADDR, req->_nlmsg_flags);
	ys->req_policy = &rt_addr_addr_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.address)
		ynl_attr_put(nlh, IFA_ADDRESS, req->address, req->_len.address);
	if (req->_len.local)
		ynl_attr_put(nlh, IFA_LOCAL, req->local, req->_len.local);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_GETADDR ============== */
/* RTM_GETADDR - dump */
int rt_addr_getaddr_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	struct rt_addr_getaddr_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;
	void *hdr;

	dst = yarg->data;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ifaddrmsg));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFA_ADDRESS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.address = len;
			dst->address = malloc(len);
			memcpy(dst->address, ynl_attr_data(attr), len);
		} else if (type == IFA_LABEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.label = len;
			dst->label = malloc(len + 1);
			memcpy(dst->label, ynl_attr_get_str(attr), len);
			dst->label[len] = 0;
		} else if (type == IFA_LOCAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.local = len;
			dst->local = malloc(len);
			memcpy(dst->local, ynl_attr_data(attr), len);
		} else if (type == IFA_CACHEINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.cacheinfo = len;
			if (len < sizeof(struct ifa_cacheinfo))
				dst->cacheinfo = calloc(1, sizeof(struct ifa_cacheinfo));
			else
				dst->cacheinfo = malloc(len);
			memcpy(dst->cacheinfo, ynl_attr_data(attr), len);
		}
	}

	return YNL_PARSE_CB_OK;
}

void rt_addr_getaddr_req_free(struct rt_addr_getaddr_req *req)
{
	free(req);
}

void rt_addr_getaddr_list_free(struct rt_addr_getaddr_list *rsp)
{
	struct rt_addr_getaddr_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.address);
		free(rsp->obj.label);
		free(rsp->obj.local);
		free(rsp->obj.cacheinfo);
		free(rsp);
	}
}

struct rt_addr_getaddr_list *
rt_addr_getaddr_dump(struct ynl_sock *ys, struct rt_addr_getaddr_req *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_addr_addr_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct rt_addr_getaddr_list);
	yds.cb = rt_addr_getaddr_rsp_parse;
	yds.rsp_cmd = 20;

	nlh = ynl_msg_start_dump(ys, RTM_GETADDR);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &rt_addr_addr_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	rt_addr_getaddr_list_free(yds.first);
	return NULL;
}

/* ============== RTM_GETMULTICAST ============== */
/* RTM_GETMULTICAST - do */
void rt_addr_getmulticast_req_free(struct rt_addr_getmulticast_req *req)
{
	free(req);
}

void rt_addr_getmulticast_rsp_free(struct rt_addr_getmulticast_rsp *rsp)
{
	free(rsp->multicast);
	free(rsp->cacheinfo);
	free(rsp);
}

int rt_addr_getmulticast_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	struct rt_addr_getmulticast_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;
	void *hdr;

	dst = yarg->data;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ifaddrmsg));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFA_MULTICAST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.multicast = len;
			dst->multicast = malloc(len);
			memcpy(dst->multicast, ynl_attr_data(attr), len);
		} else if (type == IFA_CACHEINFO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.cacheinfo = len;
			if (len < sizeof(struct ifa_cacheinfo))
				dst->cacheinfo = calloc(1, sizeof(struct ifa_cacheinfo));
			else
				dst->cacheinfo = malloc(len);
			memcpy(dst->cacheinfo, ynl_attr_data(attr), len);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct rt_addr_getmulticast_rsp *
rt_addr_getmulticast(struct ynl_sock *ys, struct rt_addr_getmulticast_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct rt_addr_getmulticast_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETMULTICAST, req->_nlmsg_flags);
	ys->req_policy = &rt_addr_addr_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &rt_addr_addr_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = rt_addr_getmulticast_rsp_parse;
	yrs.rsp_cmd = RTM_GETMULTICAST;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	rt_addr_getmulticast_rsp_free(rsp);
	return NULL;
}

/* RTM_GETMULTICAST - dump */
void
rt_addr_getmulticast_req_dump_free(struct rt_addr_getmulticast_req_dump *req)
{
	free(req);
}

void rt_addr_getmulticast_list_free(struct rt_addr_getmulticast_list *rsp)
{
	struct rt_addr_getmulticast_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.multicast);
		free(rsp->obj.cacheinfo);
		free(rsp);
	}
}

struct rt_addr_getmulticast_list *
rt_addr_getmulticast_dump(struct ynl_sock *ys,
			  struct rt_addr_getmulticast_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_addr_addr_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct rt_addr_getmulticast_list);
	yds.cb = rt_addr_getmulticast_rsp_parse;
	yds.rsp_cmd = RTM_GETMULTICAST;

	nlh = ynl_msg_start_dump(ys, RTM_GETMULTICAST);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &rt_addr_addr_attrs_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	rt_addr_getmulticast_list_free(yds.first);
	return NULL;
}

const struct ynl_family ynl_rt_addr_family =  {
	.name		= "rt_addr",
	.is_classic	= true,
	.classic_id	= 0,
	.hdr_len	= sizeof(struct ifaddrmsg),
};
