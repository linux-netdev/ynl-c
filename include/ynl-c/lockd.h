/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/lockd.yaml */
/* YNL-GEN user header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_LOCKD_GEN_H
#define _LINUX_LOCKD_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/lockd_netlink.h>

struct ynl_sock;

extern const struct ynl_family ynl_lockd_family;

/* Enums */
const char *lockd_op_str(int op);

/* Common nested types */
/* ============== LOCKD_CMD_SERVER_SET ============== */
/* LOCKD_CMD_SERVER_SET - do */
struct lockd_server_set_req {
	struct {
		__u32 gracetime:1;
		__u32 tcp_port:1;
		__u32 udp_port:1;
	} _present;

	__u32 gracetime;
	__u16 tcp_port;
	__u16 udp_port;
};

static inline struct lockd_server_set_req *lockd_server_set_req_alloc(void)
{
	return calloc(1, sizeof(struct lockd_server_set_req));
}
void lockd_server_set_req_free(struct lockd_server_set_req *req);

static inline void
lockd_server_set_req_set_gracetime(struct lockd_server_set_req *req,
				   __u32 gracetime)
{
	req->_present.gracetime = 1;
	req->gracetime = gracetime;
}
static inline void
lockd_server_set_req_set_tcp_port(struct lockd_server_set_req *req,
				  __u16 tcp_port)
{
	req->_present.tcp_port = 1;
	req->tcp_port = tcp_port;
}
static inline void
lockd_server_set_req_set_udp_port(struct lockd_server_set_req *req,
				  __u16 udp_port)
{
	req->_present.udp_port = 1;
	req->udp_port = udp_port;
}

/*
 * set the lockd server parameters
 */
int lockd_server_set(struct ynl_sock *ys, struct lockd_server_set_req *req);

/* ============== LOCKD_CMD_SERVER_GET ============== */
/* LOCKD_CMD_SERVER_GET - do */

struct lockd_server_get_rsp {
	struct {
		__u32 gracetime:1;
		__u32 tcp_port:1;
		__u32 udp_port:1;
	} _present;

	__u32 gracetime;
	__u16 tcp_port;
	__u16 udp_port;
};

void lockd_server_get_rsp_free(struct lockd_server_get_rsp *rsp);

/*
 * get the lockd server parameters
 */
struct lockd_server_get_rsp *lockd_server_get(struct ynl_sock *ys);

#endif /* _LINUX_LOCKD_GEN_H */
