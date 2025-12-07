// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/lockd.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "lockd-user.h"
#include "ynl.h"
#include <linux/lockd_netlink.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const lockd_op_strmap[] = {
	[LOCKD_CMD_SERVER_SET] = "server-set",
	[LOCKD_CMD_SERVER_GET] = "server-get",
};

const char *lockd_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(lockd_op_strmap))
		return NULL;
	return lockd_op_strmap[op];
}

/* Policies */
const struct ynl_policy_attr lockd_server_policy[LOCKD_A_SERVER_MAX + 1] = {
	[LOCKD_A_SERVER_GRACETIME] = { .name = "gracetime", .type = YNL_PT_U32, },
	[LOCKD_A_SERVER_TCP_PORT] = { .name = "tcp-port", .type = YNL_PT_U16, },
	[LOCKD_A_SERVER_UDP_PORT] = { .name = "udp-port", .type = YNL_PT_U16, },
};

const struct ynl_policy_nest lockd_server_nest = {
	.max_attr = LOCKD_A_SERVER_MAX,
	.table = lockd_server_policy,
};

/* Common nested types */
/* ============== LOCKD_CMD_SERVER_SET ============== */
/* LOCKD_CMD_SERVER_SET - do */
void lockd_server_set_req_free(struct lockd_server_set_req *req)
{
	free(req);
}

int lockd_server_set(struct ynl_sock *ys, struct lockd_server_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, LOCKD_CMD_SERVER_SET, 1);
	ys->req_policy = &lockd_server_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.gracetime)
		ynl_attr_put_u32(nlh, LOCKD_A_SERVER_GRACETIME, req->gracetime);
	if (req->_present.tcp_port)
		ynl_attr_put_u16(nlh, LOCKD_A_SERVER_TCP_PORT, req->tcp_port);
	if (req->_present.udp_port)
		ynl_attr_put_u16(nlh, LOCKD_A_SERVER_UDP_PORT, req->udp_port);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== LOCKD_CMD_SERVER_GET ============== */
/* LOCKD_CMD_SERVER_GET - do */
void lockd_server_get_rsp_free(struct lockd_server_get_rsp *rsp)
{
	free(rsp);
}

int lockd_server_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct lockd_server_get_rsp *dst;
	const struct nlattr *attr;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == LOCKD_A_SERVER_GRACETIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gracetime = 1;
			dst->gracetime = ynl_attr_get_u32(attr);
		} else if (type == LOCKD_A_SERVER_TCP_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tcp_port = 1;
			dst->tcp_port = ynl_attr_get_u16(attr);
		} else if (type == LOCKD_A_SERVER_UDP_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.udp_port = 1;
			dst->udp_port = ynl_attr_get_u16(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct lockd_server_get_rsp *lockd_server_get(struct ynl_sock *ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct lockd_server_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, LOCKD_CMD_SERVER_GET, 1);
	ys->req_policy = &lockd_server_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &lockd_server_nest;

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = lockd_server_get_rsp_parse;
	yrs.rsp_cmd = LOCKD_CMD_SERVER_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	lockd_server_get_rsp_free(rsp);
	return NULL;
}

const struct ynl_family ynl_lockd_family =  {
	.name		= "lockd",
	.hdr_len	= sizeof(struct genlmsghdr),
};
