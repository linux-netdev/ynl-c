// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/ovs_datapath.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "ovs_datapath-user.h"
#include "ynl.h"
#include <linux/openvswitch.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const ovs_datapath_op_strmap[] = {
	[OVS_DP_CMD_GET] = "get",
	[OVS_DP_CMD_NEW] = "new",
	[OVS_DP_CMD_DEL] = "del",
};

const char *ovs_datapath_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(ovs_datapath_op_strmap))
		return NULL;
	return ovs_datapath_op_strmap[op];
}

static const char * const ovs_datapath_user_features_strmap[] = {
	[0] = "unaligned",
	[1] = "vport-pids",
	[2] = "tc-recirc-sharing",
	[3] = "dispatch-upcall-per-cpu",
};

const char *ovs_datapath_user_features_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(ovs_datapath_user_features_strmap))
		return NULL;
	return ovs_datapath_user_features_strmap[value];
}

/* Policies */
const struct ynl_policy_attr ovs_datapath_datapath_policy[OVS_DP_ATTR_MAX + 1] = {
	[OVS_DP_ATTR_NAME] = { .name = "name", .type = YNL_PT_NUL_STR, },
	[OVS_DP_ATTR_UPCALL_PID] = { .name = "upcall-pid", .type = YNL_PT_U32, },
	[OVS_DP_ATTR_STATS] = { .name = "stats", .type = YNL_PT_BINARY,},
	[OVS_DP_ATTR_MEGAFLOW_STATS] = { .name = "megaflow-stats", .type = YNL_PT_BINARY,},
	[OVS_DP_ATTR_USER_FEATURES] = { .name = "user-features", .type = YNL_PT_U32, },
	[OVS_DP_ATTR_PAD] = { .name = "pad", .type = YNL_PT_REJECT, },
	[OVS_DP_ATTR_MASKS_CACHE_SIZE] = { .name = "masks-cache-size", .type = YNL_PT_U32, },
	[OVS_DP_ATTR_PER_CPU_PIDS] = { .name = "per-cpu-pids", .type = YNL_PT_BINARY,},
	[OVS_DP_ATTR_IFINDEX] = { .name = "ifindex", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest ovs_datapath_datapath_nest = {
	.max_attr = OVS_DP_ATTR_MAX,
	.table = ovs_datapath_datapath_policy,
};

/* Common nested types */
/* ============== OVS_DP_CMD_GET ============== */
/* OVS_DP_CMD_GET - do */
void ovs_datapath_get_req_free(struct ovs_datapath_get_req *req)
{
	free(req->name);
	free(req);
}

void ovs_datapath_get_rsp_free(struct ovs_datapath_get_rsp *rsp)
{
	free(rsp->name);
	free(rsp->stats);
	free(rsp->megaflow_stats);
	free(rsp->per_cpu_pids);
	free(rsp);
}

int ovs_datapath_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct ovs_datapath_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;
	void *hdr;

	dst = yarg->data;

	hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));
	memcpy(&dst->_hdr, hdr, sizeof(struct ovs_header));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_DP_ATTR_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.name = len;
			dst->name = malloc(len + 1);
			memcpy(dst->name, ynl_attr_get_str(attr), len);
			dst->name[len] = 0;
		} else if (type == OVS_DP_ATTR_UPCALL_PID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.upcall_pid = 1;
			dst->upcall_pid = ynl_attr_get_u32(attr);
		} else if (type == OVS_DP_ATTR_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stats = len;
			if (len < sizeof(struct ovs_dp_stats))
				dst->stats = calloc(1, sizeof(struct ovs_dp_stats));
			else
				dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == OVS_DP_ATTR_MEGAFLOW_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.megaflow_stats = len;
			if (len < sizeof(struct ovs_dp_megaflow_stats))
				dst->megaflow_stats = calloc(1, sizeof(struct ovs_dp_megaflow_stats));
			else
				dst->megaflow_stats = malloc(len);
			memcpy(dst->megaflow_stats, ynl_attr_data(attr), len);
		} else if (type == OVS_DP_ATTR_USER_FEATURES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.user_features = 1;
			dst->user_features = ynl_attr_get_u32(attr);
		} else if (type == OVS_DP_ATTR_MASKS_CACHE_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.masks_cache_size = 1;
			dst->masks_cache_size = ynl_attr_get_u32(attr);
		} else if (type == OVS_DP_ATTR_PER_CPU_PIDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.per_cpu_pids = len / sizeof(__u32);
			len = dst->_count.per_cpu_pids * sizeof(__u32);
			dst->per_cpu_pids = malloc(len);
			memcpy(dst->per_cpu_pids, ynl_attr_data(attr), len);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct ovs_datapath_get_rsp *
ovs_datapath_get(struct ynl_sock *ys, struct ovs_datapath_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct ovs_datapath_get_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVS_DP_CMD_GET, 1);
	ys->req_policy = &ovs_datapath_datapath_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &ovs_datapath_datapath_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.name)
		ynl_attr_put_str(nlh, OVS_DP_ATTR_NAME, req->name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = ovs_datapath_get_rsp_parse;
	yrs.rsp_cmd = OVS_DP_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	ovs_datapath_get_rsp_free(rsp);
	return NULL;
}

/* OVS_DP_CMD_GET - dump */
void ovs_datapath_get_req_dump_free(struct ovs_datapath_get_req_dump *req)
{
	free(req->name);
	free(req);
}

void ovs_datapath_get_list_free(struct ovs_datapath_get_list *rsp)
{
	struct ovs_datapath_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.name);
		free(rsp->obj.stats);
		free(rsp->obj.megaflow_stats);
		free(rsp->obj.per_cpu_pids);
		free(rsp);
	}
}

struct ovs_datapath_get_list *
ovs_datapath_get_dump(struct ynl_sock *ys,
		      struct ovs_datapath_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ovs_datapath_datapath_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct ovs_datapath_get_list);
	yds.cb = ovs_datapath_get_rsp_parse;
	yds.rsp_cmd = OVS_DP_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, OVS_DP_CMD_GET, 1);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &ovs_datapath_datapath_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.name)
		ynl_attr_put_str(nlh, OVS_DP_ATTR_NAME, req->name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	ovs_datapath_get_list_free(yds.first);
	return NULL;
}

/* ============== OVS_DP_CMD_NEW ============== */
/* OVS_DP_CMD_NEW - do */
void ovs_datapath_new_req_free(struct ovs_datapath_new_req *req)
{
	free(req->name);
	free(req);
}

int ovs_datapath_new(struct ynl_sock *ys, struct ovs_datapath_new_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVS_DP_CMD_NEW, 1);
	ys->req_policy = &ovs_datapath_datapath_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.name)
		ynl_attr_put_str(nlh, OVS_DP_ATTR_NAME, req->name);
	if (req->_present.upcall_pid)
		ynl_attr_put_u32(nlh, OVS_DP_ATTR_UPCALL_PID, req->upcall_pid);
	if (req->_present.user_features)
		ynl_attr_put_u32(nlh, OVS_DP_ATTR_USER_FEATURES, req->user_features);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== OVS_DP_CMD_DEL ============== */
/* OVS_DP_CMD_DEL - do */
void ovs_datapath_del_req_free(struct ovs_datapath_del_req *req)
{
	free(req->name);
	free(req);
}

int ovs_datapath_del(struct ynl_sock *ys, struct ovs_datapath_del_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, OVS_DP_CMD_DEL, 1);
	ys->req_policy = &ovs_datapath_datapath_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.name)
		ynl_attr_put_str(nlh, OVS_DP_ATTR_NAME, req->name);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

const struct ynl_family ynl_ovs_datapath_family =  {
	.name		= "ovs_datapath",
	.hdr_len	= sizeof(struct genlmsghdr) + sizeof(struct ovs_header),
};
