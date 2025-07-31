// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/handshake.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "handshake-user.h"
#include "ynl.h"
#include <linux/handshake.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const handshake_op_strmap[] = {
	[HANDSHAKE_CMD_READY] = "ready",
	[HANDSHAKE_CMD_ACCEPT] = "accept",
	[HANDSHAKE_CMD_DONE] = "done",
};

const char *handshake_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(handshake_op_strmap))
		return NULL;
	return handshake_op_strmap[op];
}

static const char * const handshake_handler_class_strmap[] = {
	[0] = "none",
	[1] = "tlshd",
	[2] = "max",
};

const char *handshake_handler_class_str(enum handshake_handler_class value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(handshake_handler_class_strmap))
		return NULL;
	return handshake_handler_class_strmap[value];
}

static const char * const handshake_msg_type_strmap[] = {
	[0] = "unspec",
	[1] = "clienthello",
	[2] = "serverhello",
};

const char *handshake_msg_type_str(enum handshake_msg_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(handshake_msg_type_strmap))
		return NULL;
	return handshake_msg_type_strmap[value];
}

static const char * const handshake_auth_strmap[] = {
	[0] = "unspec",
	[1] = "unauth",
	[2] = "psk",
	[3] = "x509",
};

const char *handshake_auth_str(enum handshake_auth value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(handshake_auth_strmap))
		return NULL;
	return handshake_auth_strmap[value];
}

/* Policies */
const struct ynl_policy_attr handshake_x509_policy[HANDSHAKE_A_X509_MAX + 1] = {
	[HANDSHAKE_A_X509_CERT] = { .name = "cert", .type = YNL_PT_U32, },
	[HANDSHAKE_A_X509_PRIVKEY] = { .name = "privkey", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest handshake_x509_nest = {
	.max_attr = HANDSHAKE_A_X509_MAX,
	.table = handshake_x509_policy,
};

const struct ynl_policy_attr handshake_accept_policy[HANDSHAKE_A_ACCEPT_MAX + 1] = {
	[HANDSHAKE_A_ACCEPT_SOCKFD] = { .name = "sockfd", .type = YNL_PT_U32, },
	[HANDSHAKE_A_ACCEPT_HANDLER_CLASS] = { .name = "handler-class", .type = YNL_PT_U32, },
	[HANDSHAKE_A_ACCEPT_MESSAGE_TYPE] = { .name = "message-type", .type = YNL_PT_U32, },
	[HANDSHAKE_A_ACCEPT_TIMEOUT] = { .name = "timeout", .type = YNL_PT_U32, },
	[HANDSHAKE_A_ACCEPT_AUTH_MODE] = { .name = "auth-mode", .type = YNL_PT_U32, },
	[HANDSHAKE_A_ACCEPT_PEER_IDENTITY] = { .name = "peer-identity", .type = YNL_PT_U32, },
	[HANDSHAKE_A_ACCEPT_CERTIFICATE] = { .name = "certificate", .type = YNL_PT_NEST, .nest = &handshake_x509_nest, },
	[HANDSHAKE_A_ACCEPT_PEERNAME] = { .name = "peername", .type = YNL_PT_NUL_STR, },
	[HANDSHAKE_A_ACCEPT_KEYRING] = { .name = "keyring", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest handshake_accept_nest = {
	.max_attr = HANDSHAKE_A_ACCEPT_MAX,
	.table = handshake_accept_policy,
};

const struct ynl_policy_attr handshake_done_policy[HANDSHAKE_A_DONE_MAX + 1] = {
	[HANDSHAKE_A_DONE_STATUS] = { .name = "status", .type = YNL_PT_U32, },
	[HANDSHAKE_A_DONE_SOCKFD] = { .name = "sockfd", .type = YNL_PT_U32, },
	[HANDSHAKE_A_DONE_REMOTE_AUTH] = { .name = "remote-auth", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest handshake_done_nest = {
	.max_attr = HANDSHAKE_A_DONE_MAX,
	.table = handshake_done_policy,
};

/* Common nested types */
void handshake_x509_free(struct handshake_x509 *obj)
{
}

int handshake_x509_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	struct handshake_x509 *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == HANDSHAKE_A_X509_CERT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cert = 1;
			dst->cert = ynl_attr_get_s32(attr);
		} else if (type == HANDSHAKE_A_X509_PRIVKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.privkey = 1;
			dst->privkey = ynl_attr_get_s32(attr);
		}
	}

	return 0;
}

/* ============== HANDSHAKE_CMD_ACCEPT ============== */
/* HANDSHAKE_CMD_ACCEPT - do */
void handshake_accept_req_free(struct handshake_accept_req *req)
{
	free(req);
}

void handshake_accept_rsp_free(struct handshake_accept_rsp *rsp)
{
	unsigned int i;

	free(rsp->peer_identity);
	for (i = 0; i < rsp->_count.certificate; i++)
		handshake_x509_free(&rsp->certificate[i]);
	free(rsp->certificate);
	free(rsp->peername);
	free(rsp);
}

int handshake_accept_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct handshake_accept_rsp *dst;
	unsigned int n_peer_identity = 0;
	unsigned int n_certificate = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = yarg->data;
	parg.ys = yarg->ys;

	if (dst->certificate)
		return ynl_error_parse(yarg, "attribute already present (accept.certificate)");
	if (dst->peer_identity)
		return ynl_error_parse(yarg, "attribute already present (accept.peer-identity)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == HANDSHAKE_A_ACCEPT_SOCKFD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sockfd = 1;
			dst->sockfd = ynl_attr_get_s32(attr);
		} else if (type == HANDSHAKE_A_ACCEPT_MESSAGE_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.message_type = 1;
			dst->message_type = ynl_attr_get_u32(attr);
		} else if (type == HANDSHAKE_A_ACCEPT_TIMEOUT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.timeout = 1;
			dst->timeout = ynl_attr_get_u32(attr);
		} else if (type == HANDSHAKE_A_ACCEPT_AUTH_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.auth_mode = 1;
			dst->auth_mode = ynl_attr_get_u32(attr);
		} else if (type == HANDSHAKE_A_ACCEPT_PEER_IDENTITY) {
			n_peer_identity++;
		} else if (type == HANDSHAKE_A_ACCEPT_CERTIFICATE) {
			n_certificate++;
		} else if (type == HANDSHAKE_A_ACCEPT_PEERNAME) {
			unsigned int len;

			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.peername = len;
			dst->peername = malloc(len + 1);
			memcpy(dst->peername, ynl_attr_get_str(attr), len);
			dst->peername[len] = 0;
		} else if (type == HANDSHAKE_A_ACCEPT_KEYRING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.keyring = 1;
			dst->keyring = ynl_attr_get_u32(attr);
		}
	}

	if (n_certificate) {
		dst->certificate = calloc(n_certificate, sizeof(*dst->certificate));
		dst->_count.certificate = n_certificate;
		i = 0;
		parg.rsp_policy = &handshake_x509_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == HANDSHAKE_A_ACCEPT_CERTIFICATE) {
				parg.data = &dst->certificate[i];
				if (handshake_x509_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}
	if (n_peer_identity) {
		dst->peer_identity = calloc(n_peer_identity, sizeof(*dst->peer_identity));
		dst->_count.peer_identity = n_peer_identity;
		i = 0;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == HANDSHAKE_A_ACCEPT_PEER_IDENTITY) {
				dst->peer_identity[i] = ynl_attr_get_u32(attr);
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

struct handshake_accept_rsp *
handshake_accept(struct ynl_sock *ys, struct handshake_accept_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct handshake_accept_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, HANDSHAKE_CMD_ACCEPT, 1);
	ys->req_policy = &handshake_accept_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &handshake_accept_nest;

	if (req->_present.handler_class)
		ynl_attr_put_u32(nlh, HANDSHAKE_A_ACCEPT_HANDLER_CLASS, req->handler_class);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = handshake_accept_rsp_parse;
	yrs.rsp_cmd = HANDSHAKE_CMD_ACCEPT;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	handshake_accept_rsp_free(rsp);
	return NULL;
}

/* HANDSHAKE_CMD_ACCEPT - notify */
void handshake_accept_ntf_free(struct handshake_accept_ntf *rsp)
{
	unsigned int i;

	free(rsp->obj.peer_identity);
	for (i = 0; i < rsp->obj._count.certificate; i++)
		handshake_x509_free(&rsp->obj.certificate[i]);
	free(rsp->obj.certificate);
	free(rsp->obj.peername);
	free(rsp);
}

/* ============== HANDSHAKE_CMD_DONE ============== */
/* HANDSHAKE_CMD_DONE - do */
void handshake_done_req_free(struct handshake_done_req *req)
{
	free(req->remote_auth);
	free(req);
}

int handshake_done(struct ynl_sock *ys, struct handshake_done_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	unsigned int i;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, HANDSHAKE_CMD_DONE, 1);
	ys->req_policy = &handshake_done_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_present.status)
		ynl_attr_put_u32(nlh, HANDSHAKE_A_DONE_STATUS, req->status);
	if (req->_present.sockfd)
		ynl_attr_put_s32(nlh, HANDSHAKE_A_DONE_SOCKFD, req->sockfd);
	for (i = 0; i < req->_count.remote_auth; i++)
		ynl_attr_put_u32(nlh, HANDSHAKE_A_DONE_REMOTE_AUTH, req->remote_auth[i]);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

static const struct ynl_ntf_info handshake_ntf_info[] =  {
	[HANDSHAKE_CMD_READY] =  {
		.alloc_sz	= sizeof(struct handshake_accept_ntf),
		.cb		= handshake_accept_rsp_parse,
		.policy		= &handshake_accept_nest,
		.free		= (void *)handshake_accept_ntf_free,
	},
};

const struct ynl_family ynl_handshake_family =  {
	.name		= "handshake",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= handshake_ntf_info,
	.ntf_info_size	= YNL_ARRAY_SIZE(handshake_ntf_info),
};
