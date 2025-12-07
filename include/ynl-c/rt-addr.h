/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-addr.yaml */
/* YNL-GEN user header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_RT_ADDR_GEN_H
#define _LINUX_RT_ADDR_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/rtnetlink.h>

struct ynl_sock;

extern const struct ynl_family ynl_rt_addr_family;

/* Enums */
const char *rt_addr_op_str(int op);
const char *rt_addr_ifa_flags_str(int value);

/* Common nested types */
/* ============== RTM_NEWADDR ============== */
/* RTM_NEWADDR - do */
struct rt_addr_newaddr_req {
	__u16 _nlmsg_flags;

	struct ifaddrmsg _hdr;

	struct {
		__u32 address;
		__u32 label;
		__u32 local;
		__u32 cacheinfo;
	} _len;

	void *address;
	char *label;
	void *local;
	struct ifa_cacheinfo *cacheinfo;
};

static inline struct rt_addr_newaddr_req *rt_addr_newaddr_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_addr_newaddr_req));
}
void rt_addr_newaddr_req_free(struct rt_addr_newaddr_req *req);

static inline void
rt_addr_newaddr_req_set_nlflags(struct rt_addr_newaddr_req *req,
				__u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_addr_newaddr_req_set_address(struct rt_addr_newaddr_req *req,
				const void *address, size_t len)
{
	free(req->address);
	req->_len.address = len;
	req->address = malloc(req->_len.address);
	memcpy(req->address, address, req->_len.address);
}
static inline void
rt_addr_newaddr_req_set_label(struct rt_addr_newaddr_req *req,
			      const char *label)
{
	free(req->label);
	req->_len.label = strlen(label);
	req->label = malloc(req->_len.label + 1);
	memcpy(req->label, label, req->_len.label);
	req->label[req->_len.label] = 0;
}
static inline void
rt_addr_newaddr_req_set_local(struct rt_addr_newaddr_req *req,
			      const void *local, size_t len)
{
	free(req->local);
	req->_len.local = len;
	req->local = malloc(req->_len.local);
	memcpy(req->local, local, req->_len.local);
}
static inline void
rt_addr_newaddr_req_set_cacheinfo(struct rt_addr_newaddr_req *req,
				  const void *cacheinfo, size_t len)
{
	free(req->cacheinfo);
	req->_len.cacheinfo = len;
	req->cacheinfo = malloc(req->_len.cacheinfo);
	memcpy(req->cacheinfo, cacheinfo, req->_len.cacheinfo);
}

/*
 * Add new address
 */
int rt_addr_newaddr(struct ynl_sock *ys, struct rt_addr_newaddr_req *req);

/* ============== RTM_DELADDR ============== */
/* RTM_DELADDR - do */
struct rt_addr_deladdr_req {
	__u16 _nlmsg_flags;

	struct ifaddrmsg _hdr;

	struct {
		__u32 address;
		__u32 local;
	} _len;

	void *address;
	void *local;
};

static inline struct rt_addr_deladdr_req *rt_addr_deladdr_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_addr_deladdr_req));
}
void rt_addr_deladdr_req_free(struct rt_addr_deladdr_req *req);

static inline void
rt_addr_deladdr_req_set_nlflags(struct rt_addr_deladdr_req *req,
				__u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_addr_deladdr_req_set_address(struct rt_addr_deladdr_req *req,
				const void *address, size_t len)
{
	free(req->address);
	req->_len.address = len;
	req->address = malloc(req->_len.address);
	memcpy(req->address, address, req->_len.address);
}
static inline void
rt_addr_deladdr_req_set_local(struct rt_addr_deladdr_req *req,
			      const void *local, size_t len)
{
	free(req->local);
	req->_len.local = len;
	req->local = malloc(req->_len.local);
	memcpy(req->local, local, req->_len.local);
}

/*
 * Remove address
 */
int rt_addr_deladdr(struct ynl_sock *ys, struct rt_addr_deladdr_req *req);

/* ============== RTM_GETADDR ============== */
/* RTM_GETADDR - dump */
struct rt_addr_getaddr_req {
	struct ifaddrmsg _hdr;
};

static inline struct rt_addr_getaddr_req *rt_addr_getaddr_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_addr_getaddr_req));
}
void rt_addr_getaddr_req_free(struct rt_addr_getaddr_req *req);

struct rt_addr_getaddr_rsp {
	struct ifaddrmsg _hdr;

	struct {
		__u32 address;
		__u32 label;
		__u32 local;
		__u32 cacheinfo;
	} _len;

	void *address;
	char *label;
	void *local;
	struct ifa_cacheinfo *cacheinfo;
};

struct rt_addr_getaddr_list {
	struct rt_addr_getaddr_list *next;
	struct rt_addr_getaddr_rsp obj __attribute__((aligned(8)));
};

void rt_addr_getaddr_list_free(struct rt_addr_getaddr_list *rsp);

struct rt_addr_getaddr_list *
rt_addr_getaddr_dump(struct ynl_sock *ys, struct rt_addr_getaddr_req *req);

/* ============== RTM_GETMULTICAST ============== */
/* RTM_GETMULTICAST - do */
struct rt_addr_getmulticast_req {
	__u16 _nlmsg_flags;

	struct ifaddrmsg _hdr;
};

static inline struct rt_addr_getmulticast_req *
rt_addr_getmulticast_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_addr_getmulticast_req));
}
void rt_addr_getmulticast_req_free(struct rt_addr_getmulticast_req *req);

static inline void
rt_addr_getmulticast_req_set_nlflags(struct rt_addr_getmulticast_req *req,
				     __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

struct rt_addr_getmulticast_rsp {
	struct ifaddrmsg _hdr;

	struct {
		__u32 multicast;
		__u32 cacheinfo;
	} _len;

	void *multicast;
	struct ifa_cacheinfo *cacheinfo;
};

void rt_addr_getmulticast_rsp_free(struct rt_addr_getmulticast_rsp *rsp);

/*
 * Get / dump IPv4/IPv6 multicast addresses.
 */
struct rt_addr_getmulticast_rsp *
rt_addr_getmulticast(struct ynl_sock *ys, struct rt_addr_getmulticast_req *req);

/* RTM_GETMULTICAST - dump */
struct rt_addr_getmulticast_req_dump {
	struct ifaddrmsg _hdr;
};

static inline struct rt_addr_getmulticast_req_dump *
rt_addr_getmulticast_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct rt_addr_getmulticast_req_dump));
}
void
rt_addr_getmulticast_req_dump_free(struct rt_addr_getmulticast_req_dump *req);

struct rt_addr_getmulticast_list {
	struct rt_addr_getmulticast_list *next;
	struct rt_addr_getmulticast_rsp obj __attribute__((aligned(8)));
};

void rt_addr_getmulticast_list_free(struct rt_addr_getmulticast_list *rsp);

struct rt_addr_getmulticast_list *
rt_addr_getmulticast_dump(struct ynl_sock *ys,
			  struct rt_addr_getmulticast_req_dump *req);

#endif /* _LINUX_RT_ADDR_GEN_H */
