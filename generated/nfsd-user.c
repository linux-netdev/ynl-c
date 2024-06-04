// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/nfsd.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "nfsd-user.h"
#include "ynl.h"
#include <linux/nfsd_netlink.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const nfsd_op_strmap[] = {
	[NFSD_CMD_RPC_STATUS_GET] = "rpc-status-get",
	[NFSD_CMD_THREADS_SET] = "threads-set",
	[NFSD_CMD_THREADS_GET] = "threads-get",
	[NFSD_CMD_VERSION_SET] = "version-set",
	[NFSD_CMD_VERSION_GET] = "version-get",
	[NFSD_CMD_LISTENER_SET] = "listener-set",
	[NFSD_CMD_LISTENER_GET] = "listener-get",
};

const char *nfsd_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(nfsd_op_strmap))
		return NULL;
	return nfsd_op_strmap[op];
}

/* Policies */
struct ynl_policy_attr nfsd_version_policy[NFSD_A_VERSION_MAX + 1] = {
	[NFSD_A_VERSION_MAJOR] = { .name = "major", .type = YNL_PT_U32, },
	[NFSD_A_VERSION_MINOR] = { .name = "minor", .type = YNL_PT_U32, },
	[NFSD_A_VERSION_ENABLED] = { .name = "enabled", .type = YNL_PT_FLAG, },
};

struct ynl_policy_nest nfsd_version_nest = {
	.max_attr = NFSD_A_VERSION_MAX,
	.table = nfsd_version_policy,
};

struct ynl_policy_attr nfsd_sock_policy[NFSD_A_SOCK_MAX + 1] = {
	[NFSD_A_SOCK_ADDR] = { .name = "addr", .type = YNL_PT_BINARY,},
	[NFSD_A_SOCK_TRANSPORT_NAME] = { .name = "transport-name", .type = YNL_PT_NUL_STR, },
};

struct ynl_policy_nest nfsd_sock_nest = {
	.max_attr = NFSD_A_SOCK_MAX,
	.table = nfsd_sock_policy,
};

struct ynl_policy_attr nfsd_rpc_status_policy[NFSD_A_RPC_STATUS_MAX + 1] = {
	[NFSD_A_RPC_STATUS_XID] = { .name = "xid", .type = YNL_PT_U32, },
	[NFSD_A_RPC_STATUS_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[NFSD_A_RPC_STATUS_PROG] = { .name = "prog", .type = YNL_PT_U32, },
	[NFSD_A_RPC_STATUS_VERSION] = { .name = "version", .type = YNL_PT_U8, },
	[NFSD_A_RPC_STATUS_PROC] = { .name = "proc", .type = YNL_PT_U32, },
	[NFSD_A_RPC_STATUS_SERVICE_TIME] = { .name = "service_time", .type = YNL_PT_U64, },
	[NFSD_A_RPC_STATUS_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[NFSD_A_RPC_STATUS_SADDR4] = { .name = "saddr4", .type = YNL_PT_U32, },
	[NFSD_A_RPC_STATUS_DADDR4] = { .name = "daddr4", .type = YNL_PT_U32, },
	[NFSD_A_RPC_STATUS_SADDR6] = { .name = "saddr6", .type = YNL_PT_BINARY,},
	[NFSD_A_RPC_STATUS_DADDR6] = { .name = "daddr6", .type = YNL_PT_BINARY,},
	[NFSD_A_RPC_STATUS_SPORT] = { .name = "sport", .type = YNL_PT_U16, },
	[NFSD_A_RPC_STATUS_DPORT] = { .name = "dport", .type = YNL_PT_U16, },
	[NFSD_A_RPC_STATUS_COMPOUND_OPS] = { .name = "compound-ops", .type = YNL_PT_U32, },
};

struct ynl_policy_nest nfsd_rpc_status_nest = {
	.max_attr = NFSD_A_RPC_STATUS_MAX,
	.table = nfsd_rpc_status_policy,
};

struct ynl_policy_attr nfsd_server_policy[NFSD_A_SERVER_MAX + 1] = {
	[NFSD_A_SERVER_THREADS] = { .name = "threads", .type = YNL_PT_U32, },
	[NFSD_A_SERVER_GRACETIME] = { .name = "gracetime", .type = YNL_PT_U32, },
	[NFSD_A_SERVER_LEASETIME] = { .name = "leasetime", .type = YNL_PT_U32, },
	[NFSD_A_SERVER_SCOPE] = { .name = "scope", .type = YNL_PT_NUL_STR, },
};

struct ynl_policy_nest nfsd_server_nest = {
	.max_attr = NFSD_A_SERVER_MAX,
	.table = nfsd_server_policy,
};

struct ynl_policy_attr nfsd_server_proto_policy[NFSD_A_SERVER_PROTO_MAX + 1] = {
	[NFSD_A_SERVER_PROTO_VERSION] = { .name = "version", .type = YNL_PT_NEST, .nest = &nfsd_version_nest, },
};

struct ynl_policy_nest nfsd_server_proto_nest = {
	.max_attr = NFSD_A_SERVER_PROTO_MAX,
	.table = nfsd_server_proto_policy,
};

struct ynl_policy_attr nfsd_server_sock_policy[NFSD_A_SERVER_SOCK_MAX + 1] = {
	[NFSD_A_SERVER_SOCK_ADDR] = { .name = "addr", .type = YNL_PT_NEST, .nest = &nfsd_sock_nest, },
};

struct ynl_policy_nest nfsd_server_sock_nest = {
	.max_attr = NFSD_A_SERVER_SOCK_MAX,
	.table = nfsd_server_sock_policy,
};

/* Common nested types */
void nfsd_version_free(struct nfsd_version *obj)
{
}

int nfsd_version_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct nfsd_version *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.major)
		ynl_attr_put_u32(nlh, NFSD_A_VERSION_MAJOR, obj->major);
	if (obj->_present.minor)
		ynl_attr_put_u32(nlh, NFSD_A_VERSION_MINOR, obj->minor);
	if (obj->_present.enabled)
		ynl_attr_put(nlh, NFSD_A_VERSION_ENABLED, NULL, 0);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int nfsd_version_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct nfsd_version *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_VERSION_MAJOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.major = 1;
			dst->major = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_VERSION_MINOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.minor = 1;
			dst->minor = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_VERSION_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.enabled = 1;
		}
	}

	return 0;
}

void nfsd_sock_free(struct nfsd_sock *obj)
{
	free(obj->addr);
	free(obj->transport_name);
}

int nfsd_sock_put(struct nlmsghdr *nlh, unsigned int attr_type,
		  struct nfsd_sock *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.addr_len)
		ynl_attr_put(nlh, NFSD_A_SOCK_ADDR, obj->addr, obj->_present.addr_len);
	if (obj->_present.transport_name_len)
		ynl_attr_put_str(nlh, NFSD_A_SOCK_TRANSPORT_NAME, obj->transport_name);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int nfsd_sock_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct nfsd_sock *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SOCK_ADDR) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.addr_len = len;
			dst->addr = malloc(len);
			memcpy(dst->addr, ynl_attr_data(attr), len);
		} else if (type == NFSD_A_SOCK_TRANSPORT_NAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_present.transport_name_len = len;
			dst->transport_name = malloc(len + 1);
			memcpy(dst->transport_name, ynl_attr_get_str(attr), len);
			dst->transport_name[len] = 0;
		}
	}

	return 0;
}

/* ============== NFSD_CMD_RPC_STATUS_GET ============== */
/* NFSD_CMD_RPC_STATUS_GET - dump */
int nfsd_rpc_status_get_rsp_dump_parse(const struct nlmsghdr *nlh,
				       struct ynl_parse_arg *yarg)
{
	struct nfsd_rpc_status_get_rsp_dump *dst;
	unsigned int n_compound_ops = 0;
	const struct nlattr *attr;
	int i;

	dst = yarg->data;

	if (dst->compound_ops)
		return ynl_error_parse(yarg, "attribute already present (rpc-status.compound-ops)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_RPC_STATUS_XID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.xid = 1;
			dst->xid = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_PROG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.prog = 1;
			dst->prog = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_VERSION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.version = 1;
			dst->version = ynl_attr_get_u8(attr);
		} else if (type == NFSD_A_RPC_STATUS_PROC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proc = 1;
			dst->proc = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_SERVICE_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.service_time = 1;
			dst->service_time = ynl_attr_get_s64(attr);
		} else if (type == NFSD_A_RPC_STATUS_SADDR4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.saddr4 = 1;
			dst->saddr4 = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_DADDR4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.daddr4 = 1;
			dst->daddr4 = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_SADDR6) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.saddr6_len = len;
			dst->saddr6 = malloc(len);
			memcpy(dst->saddr6, ynl_attr_data(attr), len);
		} else if (type == NFSD_A_RPC_STATUS_DADDR6) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_present.daddr6_len = len;
			dst->daddr6 = malloc(len);
			memcpy(dst->daddr6, ynl_attr_data(attr), len);
		} else if (type == NFSD_A_RPC_STATUS_SPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sport = 1;
			dst->sport = ynl_attr_get_u16(attr);
		} else if (type == NFSD_A_RPC_STATUS_DPORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dport = 1;
			dst->dport = ynl_attr_get_u16(attr);
		} else if (type == NFSD_A_RPC_STATUS_COMPOUND_OPS) {
			n_compound_ops++;
		}
	}

	if (n_compound_ops) {
		dst->compound_ops = calloc(n_compound_ops, sizeof(*dst->compound_ops));
		dst->n_compound_ops = n_compound_ops;
		i = 0;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_RPC_STATUS_COMPOUND_OPS) {
				dst->compound_ops[i] = ynl_attr_get_u32(attr);
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

void
nfsd_rpc_status_get_rsp_list_free(struct nfsd_rpc_status_get_rsp_list *rsp)
{
	struct nfsd_rpc_status_get_rsp_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.saddr6);
		free(rsp->obj.daddr6);
		free(rsp->obj.compound_ops);
		free(rsp);
	}
}

struct nfsd_rpc_status_get_rsp_list *
nfsd_rpc_status_get_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nfsd_rpc_status_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct nfsd_rpc_status_get_rsp_list);
	yds.cb = nfsd_rpc_status_get_rsp_dump_parse;
	yds.rsp_cmd = NFSD_CMD_RPC_STATUS_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, NFSD_CMD_RPC_STATUS_GET, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	nfsd_rpc_status_get_rsp_list_free(yds.first);
	return NULL;
}

/* ============== NFSD_CMD_THREADS_SET ============== */
/* NFSD_CMD_THREADS_SET - do */
void nfsd_threads_set_req_free(struct nfsd_threads_set_req *req)
{
	free(req->threads);
	free(req->scope);
	free(req);
}

int nfsd_threads_set(struct ynl_sock *ys, struct nfsd_threads_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NFSD_CMD_THREADS_SET, 1);
	ys->req_policy = &nfsd_server_nest;

	for (unsigned int i = 0; i < req->n_threads; i++)
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_THREADS, req->threads[i]);
	if (req->_present.gracetime)
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_GRACETIME, req->gracetime);
	if (req->_present.leasetime)
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_LEASETIME, req->leasetime);
	if (req->_present.scope_len)
		ynl_attr_put_str(nlh, NFSD_A_SERVER_SCOPE, req->scope);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== NFSD_CMD_THREADS_GET ============== */
/* NFSD_CMD_THREADS_GET - do */
void nfsd_threads_get_rsp_free(struct nfsd_threads_get_rsp *rsp)
{
	free(rsp->threads);
	free(rsp->scope);
	free(rsp);
}

int nfsd_threads_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct nfsd_threads_get_rsp *dst;
	unsigned int n_threads = 0;
	const struct nlattr *attr;
	int i;

	dst = yarg->data;

	if (dst->threads)
		return ynl_error_parse(yarg, "attribute already present (server.threads)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SERVER_THREADS) {
			n_threads++;
		} else if (type == NFSD_A_SERVER_GRACETIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gracetime = 1;
			dst->gracetime = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_LEASETIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.leasetime = 1;
			dst->leasetime = ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_SCOPE) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_present.scope_len = len;
			dst->scope = malloc(len + 1);
			memcpy(dst->scope, ynl_attr_get_str(attr), len);
			dst->scope[len] = 0;
		}
	}

	if (n_threads) {
		dst->threads = calloc(n_threads, sizeof(*dst->threads));
		dst->n_threads = n_threads;
		i = 0;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_THREADS) {
				dst->threads[i] = ynl_attr_get_u32(attr);
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

struct nfsd_threads_get_rsp *nfsd_threads_get(struct ynl_sock *ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nfsd_threads_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NFSD_CMD_THREADS_GET, 1);
	ys->req_policy = &nfsd_server_nest;
	yrs.yarg.rsp_policy = &nfsd_server_nest;

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = nfsd_threads_get_rsp_parse;
	yrs.rsp_cmd = NFSD_CMD_THREADS_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	nfsd_threads_get_rsp_free(rsp);
	return NULL;
}

/* ============== NFSD_CMD_VERSION_SET ============== */
/* NFSD_CMD_VERSION_SET - do */
void nfsd_version_set_req_free(struct nfsd_version_set_req *req)
{
	unsigned int i;

	for (i = 0; i < req->n_version; i++)
		nfsd_version_free(&req->version[i]);
	free(req->version);
	free(req);
}

int nfsd_version_set(struct ynl_sock *ys, struct nfsd_version_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NFSD_CMD_VERSION_SET, 1);
	ys->req_policy = &nfsd_server_proto_nest;

	for (unsigned int i = 0; i < req->n_version; i++)
		nfsd_version_put(nlh, NFSD_A_SERVER_PROTO_VERSION, &req->version[i]);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== NFSD_CMD_VERSION_GET ============== */
/* NFSD_CMD_VERSION_GET - do */
void nfsd_version_get_rsp_free(struct nfsd_version_get_rsp *rsp)
{
	unsigned int i;

	for (i = 0; i < rsp->n_version; i++)
		nfsd_version_free(&rsp->version[i]);
	free(rsp->version);
	free(rsp);
}

int nfsd_version_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct nfsd_version_get_rsp *dst;
	unsigned int n_version = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = yarg->data;
	parg.ys = yarg->ys;

	if (dst->version)
		return ynl_error_parse(yarg, "attribute already present (server-proto.version)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SERVER_PROTO_VERSION) {
			n_version++;
		}
	}

	if (n_version) {
		dst->version = calloc(n_version, sizeof(*dst->version));
		dst->n_version = n_version;
		i = 0;
		parg.rsp_policy = &nfsd_version_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_PROTO_VERSION) {
				parg.data = &dst->version[i];
				if (nfsd_version_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

struct nfsd_version_get_rsp *nfsd_version_get(struct ynl_sock *ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nfsd_version_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NFSD_CMD_VERSION_GET, 1);
	ys->req_policy = &nfsd_server_proto_nest;
	yrs.yarg.rsp_policy = &nfsd_server_proto_nest;

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = nfsd_version_get_rsp_parse;
	yrs.rsp_cmd = NFSD_CMD_VERSION_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	nfsd_version_get_rsp_free(rsp);
	return NULL;
}

/* ============== NFSD_CMD_LISTENER_SET ============== */
/* NFSD_CMD_LISTENER_SET - do */
void nfsd_listener_set_req_free(struct nfsd_listener_set_req *req)
{
	unsigned int i;

	for (i = 0; i < req->n_addr; i++)
		nfsd_sock_free(&req->addr[i]);
	free(req->addr);
	free(req);
}

int nfsd_listener_set(struct ynl_sock *ys, struct nfsd_listener_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NFSD_CMD_LISTENER_SET, 1);
	ys->req_policy = &nfsd_server_sock_nest;

	for (unsigned int i = 0; i < req->n_addr; i++)
		nfsd_sock_put(nlh, NFSD_A_SERVER_SOCK_ADDR, &req->addr[i]);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== NFSD_CMD_LISTENER_GET ============== */
/* NFSD_CMD_LISTENER_GET - do */
void nfsd_listener_get_rsp_free(struct nfsd_listener_get_rsp *rsp)
{
	unsigned int i;

	for (i = 0; i < rsp->n_addr; i++)
		nfsd_sock_free(&rsp->addr[i]);
	free(rsp->addr);
	free(rsp);
}

int nfsd_listener_get_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	struct nfsd_listener_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_addr = 0;
	int i;

	dst = yarg->data;
	parg.ys = yarg->ys;

	if (dst->addr)
		return ynl_error_parse(yarg, "attribute already present (server-sock.addr)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SERVER_SOCK_ADDR) {
			n_addr++;
		}
	}

	if (n_addr) {
		dst->addr = calloc(n_addr, sizeof(*dst->addr));
		dst->n_addr = n_addr;
		i = 0;
		parg.rsp_policy = &nfsd_sock_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_SOCK_ADDR) {
				parg.data = &dst->addr[i];
				if (nfsd_sock_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

struct nfsd_listener_get_rsp *nfsd_listener_get(struct ynl_sock *ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nfsd_listener_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, NFSD_CMD_LISTENER_GET, 1);
	ys->req_policy = &nfsd_server_sock_nest;
	yrs.yarg.rsp_policy = &nfsd_server_sock_nest;

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = nfsd_listener_get_rsp_parse;
	yrs.rsp_cmd = NFSD_CMD_LISTENER_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	nfsd_listener_get_rsp_free(rsp);
	return NULL;
}

const struct ynl_family ynl_nfsd_family =  {
	.name		= "nfsd",
	.hdr_len	= sizeof(struct genlmsghdr),
};
