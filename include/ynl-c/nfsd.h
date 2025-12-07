/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/nfsd.yaml */
/* YNL-GEN user header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_NFSD_GEN_H
#define _LINUX_NFSD_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/nfsd_netlink.h>

struct ynl_sock;

extern const struct ynl_family ynl_nfsd_family;

/* Enums */
const char *nfsd_op_str(int op);

/* Common nested types */
struct nfsd_version {
	struct {
		__u32 major:1;
		__u32 minor:1;
		__u32 enabled:1;
	} _present;

	__u32 major;
	__u32 minor;
};

static inline struct nfsd_version *nfsd_version_alloc(unsigned int n)
{
	return calloc(n, sizeof(struct nfsd_version));
}

void nfsd_version_free(struct nfsd_version *obj);

static inline void
nfsd_version_set_major(struct nfsd_version *obj, __u32 major)
{
	obj->_present.major = 1;
	obj->major = major;
}
static inline void
nfsd_version_set_minor(struct nfsd_version *obj, __u32 minor)
{
	obj->_present.minor = 1;
	obj->minor = minor;
}
static inline void nfsd_version_set_enabled(struct nfsd_version *obj)
{
	obj->_present.enabled = 1;
}

struct nfsd_sock {
	struct {
		__u32 addr;
		__u32 transport_name;
	} _len;

	void *addr;
	char *transport_name;
};

static inline struct nfsd_sock *nfsd_sock_alloc(unsigned int n)
{
	return calloc(n, sizeof(struct nfsd_sock));
}

void nfsd_sock_free(struct nfsd_sock *obj);

static inline void
nfsd_sock_set_addr(struct nfsd_sock *obj, const void *addr, size_t len)
{
	free(obj->addr);
	obj->_len.addr = len;
	obj->addr = malloc(obj->_len.addr);
	memcpy(obj->addr, addr, obj->_len.addr);
}
static inline void
nfsd_sock_set_transport_name(struct nfsd_sock *obj, const char *transport_name)
{
	free(obj->transport_name);
	obj->_len.transport_name = strlen(transport_name);
	obj->transport_name = malloc(obj->_len.transport_name + 1);
	memcpy(obj->transport_name, transport_name, obj->_len.transport_name);
	obj->transport_name[obj->_len.transport_name] = 0;
}

/* ============== NFSD_CMD_RPC_STATUS_GET ============== */
/* NFSD_CMD_RPC_STATUS_GET - dump */
struct nfsd_rpc_status_get_rsp {
	struct {
		__u32 xid:1;
		__u32 flags:1;
		__u32 prog:1;
		__u32 version:1;
		__u32 proc:1;
		__u32 service_time:1;
		__u32 saddr4:1;
		__u32 daddr4:1;
		__u32 sport:1;
		__u32 dport:1;
	} _present;
	struct {
		__u32 saddr6;
		__u32 daddr6;
	} _len;
	struct {
		__u32 compound_ops;
	} _count;

	__u32 xid /* big-endian */;
	__u32 flags;
	__u32 prog;
	__u8 version;
	__u32 proc;
	__s64 service_time;
	__u32 saddr4 /* big-endian */;
	__u32 daddr4 /* big-endian */;
	void *saddr6;
	void *daddr6;
	__u16 sport /* big-endian */;
	__u16 dport /* big-endian */;
	__u32 *compound_ops;
};

struct nfsd_rpc_status_get_list {
	struct nfsd_rpc_status_get_list *next;
	struct nfsd_rpc_status_get_rsp obj __attribute__((aligned(8)));
};

void nfsd_rpc_status_get_list_free(struct nfsd_rpc_status_get_list *rsp);

struct nfsd_rpc_status_get_list *nfsd_rpc_status_get_dump(struct ynl_sock *ys);

/* ============== NFSD_CMD_THREADS_SET ============== */
/* NFSD_CMD_THREADS_SET - do */
struct nfsd_threads_set_req {
	struct {
		__u32 gracetime:1;
		__u32 leasetime:1;
	} _present;
	struct {
		__u32 scope;
	} _len;
	struct {
		__u32 threads;
	} _count;

	__u32 *threads;
	__u32 gracetime;
	__u32 leasetime;
	char *scope;
};

static inline struct nfsd_threads_set_req *nfsd_threads_set_req_alloc(void)
{
	return calloc(1, sizeof(struct nfsd_threads_set_req));
}
void nfsd_threads_set_req_free(struct nfsd_threads_set_req *req);

static inline void
__nfsd_threads_set_req_set_threads(struct nfsd_threads_set_req *req,
				   __u32 *threads, unsigned int n_threads)
{
	free(req->threads);
	req->threads = threads;
	req->_count.threads = n_threads;
}
static inline void
nfsd_threads_set_req_set_gracetime(struct nfsd_threads_set_req *req,
				   __u32 gracetime)
{
	req->_present.gracetime = 1;
	req->gracetime = gracetime;
}
static inline void
nfsd_threads_set_req_set_leasetime(struct nfsd_threads_set_req *req,
				   __u32 leasetime)
{
	req->_present.leasetime = 1;
	req->leasetime = leasetime;
}
static inline void
nfsd_threads_set_req_set_scope(struct nfsd_threads_set_req *req,
			       const char *scope)
{
	free(req->scope);
	req->_len.scope = strlen(scope);
	req->scope = malloc(req->_len.scope + 1);
	memcpy(req->scope, scope, req->_len.scope);
	req->scope[req->_len.scope] = 0;
}

/*
 * set the number of running threads
 */
int nfsd_threads_set(struct ynl_sock *ys, struct nfsd_threads_set_req *req);

/* ============== NFSD_CMD_THREADS_GET ============== */
/* NFSD_CMD_THREADS_GET - do */

struct nfsd_threads_get_rsp {
	struct {
		__u32 gracetime:1;
		__u32 leasetime:1;
	} _present;
	struct {
		__u32 scope;
	} _len;
	struct {
		__u32 threads;
	} _count;

	__u32 *threads;
	__u32 gracetime;
	__u32 leasetime;
	char *scope;
};

void nfsd_threads_get_rsp_free(struct nfsd_threads_get_rsp *rsp);

/*
 * get the number of running threads
 */
struct nfsd_threads_get_rsp *nfsd_threads_get(struct ynl_sock *ys);

/* ============== NFSD_CMD_VERSION_SET ============== */
/* NFSD_CMD_VERSION_SET - do */
struct nfsd_version_set_req {
	struct {
		__u32 version;
	} _count;

	struct nfsd_version *version;
};

static inline struct nfsd_version_set_req *nfsd_version_set_req_alloc(void)
{
	return calloc(1, sizeof(struct nfsd_version_set_req));
}
void nfsd_version_set_req_free(struct nfsd_version_set_req *req);

static inline void
__nfsd_version_set_req_set_version(struct nfsd_version_set_req *req,
				   struct nfsd_version *version,
				   unsigned int n_version)
{
	unsigned int i;

	for (i = 0; i < req->_count.version; i++)
		nfsd_version_free(&req->version[i]);
	free(req->version);
	req->version = version;
	req->_count.version = n_version;
}

/*
 * set nfs enabled versions
 */
int nfsd_version_set(struct ynl_sock *ys, struct nfsd_version_set_req *req);

/* ============== NFSD_CMD_VERSION_GET ============== */
/* NFSD_CMD_VERSION_GET - do */

struct nfsd_version_get_rsp {
	struct {
		__u32 version;
	} _count;

	struct nfsd_version *version;
};

void nfsd_version_get_rsp_free(struct nfsd_version_get_rsp *rsp);

/*
 * get nfs enabled versions
 */
struct nfsd_version_get_rsp *nfsd_version_get(struct ynl_sock *ys);

/* ============== NFSD_CMD_LISTENER_SET ============== */
/* NFSD_CMD_LISTENER_SET - do */
struct nfsd_listener_set_req {
	struct {
		__u32 addr;
	} _count;

	struct nfsd_sock *addr;
};

static inline struct nfsd_listener_set_req *nfsd_listener_set_req_alloc(void)
{
	return calloc(1, sizeof(struct nfsd_listener_set_req));
}
void nfsd_listener_set_req_free(struct nfsd_listener_set_req *req);

static inline void
__nfsd_listener_set_req_set_addr(struct nfsd_listener_set_req *req,
				 struct nfsd_sock *addr, unsigned int n_addr)
{
	unsigned int i;

	for (i = 0; i < req->_count.addr; i++)
		nfsd_sock_free(&req->addr[i]);
	free(req->addr);
	req->addr = addr;
	req->_count.addr = n_addr;
}

/*
 * set nfs running sockets
 */
int nfsd_listener_set(struct ynl_sock *ys, struct nfsd_listener_set_req *req);

/* ============== NFSD_CMD_LISTENER_GET ============== */
/* NFSD_CMD_LISTENER_GET - do */

struct nfsd_listener_get_rsp {
	struct {
		__u32 addr;
	} _count;

	struct nfsd_sock *addr;
};

void nfsd_listener_get_rsp_free(struct nfsd_listener_get_rsp *rsp);

/*
 * get nfs running listeners
 */
struct nfsd_listener_get_rsp *nfsd_listener_get(struct ynl_sock *ys);

/* ============== NFSD_CMD_POOL_MODE_SET ============== */
/* NFSD_CMD_POOL_MODE_SET - do */
struct nfsd_pool_mode_set_req {
	struct {
		__u32 mode;
	} _len;

	char *mode;
};

static inline struct nfsd_pool_mode_set_req *nfsd_pool_mode_set_req_alloc(void)
{
	return calloc(1, sizeof(struct nfsd_pool_mode_set_req));
}
void nfsd_pool_mode_set_req_free(struct nfsd_pool_mode_set_req *req);

static inline void
nfsd_pool_mode_set_req_set_mode(struct nfsd_pool_mode_set_req *req,
				const char *mode)
{
	free(req->mode);
	req->_len.mode = strlen(mode);
	req->mode = malloc(req->_len.mode + 1);
	memcpy(req->mode, mode, req->_len.mode);
	req->mode[req->_len.mode] = 0;
}

/*
 * set the current server pool-mode
 */
int nfsd_pool_mode_set(struct ynl_sock *ys, struct nfsd_pool_mode_set_req *req);

/* ============== NFSD_CMD_POOL_MODE_GET ============== */
/* NFSD_CMD_POOL_MODE_GET - do */

struct nfsd_pool_mode_get_rsp {
	struct {
		__u32 npools:1;
	} _present;
	struct {
		__u32 mode;
	} _len;

	char *mode;
	__u32 npools;
};

void nfsd_pool_mode_get_rsp_free(struct nfsd_pool_mode_get_rsp *rsp);

/*
 * get info about server pool-mode
 */
struct nfsd_pool_mode_get_rsp *nfsd_pool_mode_get(struct ynl_sock *ys);

#endif /* _LINUX_NFSD_GEN_H */
