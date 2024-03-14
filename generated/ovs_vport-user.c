// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/ovs_vport.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "ovs_vport-user.h"
#include "ynl.h"
#include <linux/openvswitch.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const ovs_vport_op_strmap[] = {
	[OVS_VPORT_CMD_NEW] = "new",
	[OVS_VPORT_CMD_DEL] = "del",
	[OVS_VPORT_CMD_GET] = "get",
};

const char *ovs_vport_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(ovs_vport_op_strmap))
		return NULL;
	return ovs_vport_op_strmap[op];
}

static const char * const ovs_vport_vport_type_strmap[] = {
	[0] = "unspec",
	[1] = "netdev",
	[2] = "internal",
	[3] = "gre",
	[4] = "vxlan",
	[5] = "geneve",
};

const char *ovs_vport_vport_type_str(enum ovs_vport_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(ovs_vport_vport_type_strmap))
		return NULL;
	return ovs_vport_vport_type_strmap[value];
}

/* Policies */
struct ynl_policy_attr ovs_vport_vport_options_policy[OVS_TUNNEL_ATTR_MAX + 1] = {
	[OVS_TUNNEL_ATTR_DST_PORT] = { .name = "dst-port", .type = YNL_PT_U32, },
	[OVS_TUNNEL_ATTR_EXTENSION] = { .name = "extension", .type = YNL_PT_U32, },
};

struct ynl_policy_nest ovs_vport_vport_options_nest = {
	.max_attr = OVS_TUNNEL_ATTR_MAX,
	.table = ovs_vport_vport_options_policy,
};

struct ynl_policy_attr ovs_vport_upcall_stats_policy[OVS_VPORT_UPCALL_ATTR_MAX + 1] = {
	[OVS_VPORT_UPCALL_ATTR_SUCCESS] = { .name = "success", .type = YNL_PT_U64, },
	[OVS_VPORT_UPCALL_ATTR_FAIL] = { .name = "fail", .type = YNL_PT_U64, },
};

struct ynl_policy_nest ovs_vport_upcall_stats_nest = {
	.max_attr = OVS_VPORT_UPCALL_ATTR_MAX,
	.table = ovs_vport_upcall_stats_policy,
};

struct ynl_policy_attr ovs_vport_vport_policy[OVS_VPORT_ATTR_MAX + 1] = {
	[OVS_VPORT_ATTR_UNSPEC] = { .name = "unspec", .type = YNL_PT_REJECT, },
	[OVS_VPORT_ATTR_PORT_NO] = { .name = "port-no", .type = YNL_PT_U32, },
	[OVS_VPORT_ATTR_TYPE] = { .name = "type", .type = YNL_PT_U32, },
	[OVS_VPORT_ATTR_NAME] = { .name = "name", .type = YNL_PT_NUL_STR, },
	[OVS_VPORT_ATTR_OPTIONS] = { .name = "options", .type = YNL_PT_NEST, .nest = &ovs_vport_vport_options_nest, },
	[OVS_VPORT_ATTR_UPCALL_PID] = { .name = "upcall-pid", .type = YNL_PT_BINARY,},
	[OVS_VPORT_ATTR_STATS] = { .name = "stats", .type = YNL_PT_BINARY,},
	[OVS_VPORT_ATTR_PAD] = { .name = "pad", .type = YNL_PT_REJECT, },
	[OVS_VPORT_ATTR_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
	[OVS_VPORT_ATTR_NETNSID] = { .name = "netnsid", .type = YNL_PT_U32, },
	[OVS_VPORT_ATTR_UPCALL_STATS] = { .name = "upcall-stats", .type = YNL_PT_NEST, .nest = &ovs_vport_upcall_stats_nest, },
};

struct ynl_policy_nest ovs_vport_vport_nest = {
	.max_attr = OVS_VPORT_ATTR_MAX,
	.table = ovs_vport_vport_policy,
};

/* Common nested types */
void ovs_vport_vport_options_free(struct ovs_vport_vport_options *obj)
{
}

int ovs_vport_vport_options_put(struct nlmsghdr *nlh, unsigned int attr_type,
				struct ovs_vport_vport_options *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.dst_port)
		ynl_attr_put_u32(nlh, OVS_TUNNEL_ATTR_DST_PORT, obj->dst_port);
	if (obj->_present.extension)
		ynl_attr_put_u32(nlh, OVS_TUNNEL_ATTR_EXTENSION, obj->extension);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void ovs_vport_upcall_stats_free(struct ovs_vport_upcall_stats *obj)
{
}

int ovs_vport_upcall_stats_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	struct ovs_vport_upcall_stats *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_VPORT_UPCALL_ATTR_SUCCESS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.success = 1;
			dst->success = ynl_attr_get_u64(attr);
		} else if (type == OVS_VPORT_UPCALL_ATTR_FAIL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fail = 1;
			dst->fail = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

/* ============== OVS_VPORT_CMD_NEW ============== */
/* OVS_VPORT_CMD_NEW - do */
void ovs_vport_new_req_free(struct ovs_vport_new_req *req)
{
	free(req->name);
	free(req->upcall_pid);
	ovs_vport_vport_options_free(&req->options);
	free(req);
}

int ovs_vport_new(struct ynl_sock *ys, struct ovs_vport_new_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVS_VPORT_CMD_NEW, 1);
	ys->req_policy = &ovs_vport_vport_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.name_len)
		ynl_attr_put_str(nlh, OVS_VPORT_ATTR_NAME, req->name);
	if (req->_present.type)
		ynl_attr_put_u32(nlh, OVS_VPORT_ATTR_TYPE, req->type);
	if (req->_present.upcall_pid_len)
		ynl_attr_put(nlh, OVS_VPORT_ATTR_UPCALL_PID, req->upcall_pid, req->_present.upcall_pid_len);
	if (req->_present.ifindex)
		ynl_attr_put_u32(nlh, OVS_VPORT_ATTR_IFINDEX, req->ifindex);
	if (req->_present.options)
		ovs_vport_vport_options_put(nlh, OVS_VPORT_ATTR_OPTIONS, &req->options);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== OVS_VPORT_CMD_DEL ============== */
/* OVS_VPORT_CMD_DEL - do */
void ovs_vport_del_req_free(struct ovs_vport_del_req *req)
{
	free(req->name);
	free(req);
}

int ovs_vport_del(struct ynl_sock *ys, struct ovs_vport_del_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVS_VPORT_CMD_DEL, 1);
	ys->req_policy = &ovs_vport_vport_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.port_no)
		ynl_attr_put_u32(nlh, OVS_VPORT_ATTR_PORT_NO, req->port_no);
	if (req->_present.type)
		ynl_attr_put_u32(nlh, OVS_VPORT_ATTR_TYPE, req->type);
	if (req->_present.name_len)
		ynl_attr_put_str(nlh, OVS_VPORT_ATTR_NAME, req->name);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== OVS_VPORT_CMD_GET ============== */
/* OVS_VPORT_CMD_GET - do */
void ovs_vport_get_req_free(struct ovs_vport_get_req *req)
{
	free(req->name);
	free(req);
}

void ovs_vport_get_rsp_free(struct ovs_vport_get_rsp *rsp)
{
	free(rsp->name);
	free(rsp->upcall_pid);
	free(rsp->stats);
	ovs_vport_upcall_stats_free(&rsp->upcall_stats);
	free(rsp);
}

int ovs_vport_get_rsp_parse(const struct nlmsghdr *nlh,
			    struct ynl_parse_arg *yarg)
{
	struct ovs_vport_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));
	memcpy(&dst->_hdr, hdr, sizeof(struct ovs_header));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_VPORT_ATTR_PORT_NO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_no = 1;
			dst->port_no = ynl_attr_get_u32(attr);
		} else if (type == OVS_VPORT_ATTR_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.type = 1;
			dst->type = ynl_attr_get_u32(attr);
		} else if (type == OVS_VPORT_ATTR_NAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_present.name_len = len;
			dst->name = malloc(len + 1);
			memcpy(dst->name, ynl_attr_get_str(attr), len);
			dst->name[len] = 0;
		} else if (type == OVS_VPORT_ATTR_UPCALL_PID) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.upcall_pid_len = len;
			dst->upcall_pid = malloc(len);
			memcpy(dst->upcall_pid, ynl_attr_data(attr), len);
		} else if (type == OVS_VPORT_ATTR_STATS) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.stats_len = len;
			dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == OVS_VPORT_ATTR_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ifindex = 1;
			dst->ifindex = ynl_attr_get_u32(attr);
		} else if (type == OVS_VPORT_ATTR_NETNSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.netnsid = 1;
			dst->netnsid = ynl_attr_get_u32(attr);
		} else if (type == OVS_VPORT_ATTR_UPCALL_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.upcall_stats = 1;

			parg.rsp_policy = &ovs_vport_upcall_stats_nest;
			parg.data = &dst->upcall_stats;
			if (ovs_vport_upcall_stats_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct ovs_vport_get_rsp *
ovs_vport_get(struct ynl_sock *ys, struct ovs_vport_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct ovs_vport_get_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVS_VPORT_CMD_GET, 1);
	ys->req_policy = &ovs_vport_vport_nest;
	yrs.yarg.rsp_policy = &ovs_vport_vport_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.name_len)
		ynl_attr_put_str(nlh, OVS_VPORT_ATTR_NAME, req->name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = ovs_vport_get_rsp_parse;
	yrs.rsp_cmd = OVS_VPORT_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	ovs_vport_get_rsp_free(rsp);
	return NULL;
}

/* OVS_VPORT_CMD_GET - dump */
void ovs_vport_get_req_dump_free(struct ovs_vport_get_req_dump *req)
{
	free(req->name);
	free(req);
}

void ovs_vport_get_list_free(struct ovs_vport_get_list *rsp)
{
	struct ovs_vport_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.name);
		free(rsp->obj.upcall_pid);
		free(rsp->obj.stats);
		ovs_vport_upcall_stats_free(&rsp->obj.upcall_stats);
		free(rsp);
	}
}

struct ovs_vport_get_list *
ovs_vport_get_dump(struct ynl_sock *ys, struct ovs_vport_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ovs_vport_vport_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct ovs_vport_get_list);
	yds.cb = ovs_vport_get_rsp_parse;
	yds.rsp_cmd = OVS_VPORT_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, OVS_VPORT_CMD_GET, 1);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &ovs_vport_vport_nest;

	if (req->_present.name_len)
		ynl_attr_put_str(nlh, OVS_VPORT_ATTR_NAME, req->name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	ovs_vport_get_list_free(yds.first);
	return NULL;
}

const struct ynl_family ynl_ovs_vport_family =  {
	.name		= "ovs_vport",
	.hdr_len	= sizeof(struct genlmsghdr),
};
