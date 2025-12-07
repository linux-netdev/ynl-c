/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/net_shaper.yaml */
/* YNL-GEN user header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_NET_SHAPER_GEN_H
#define _LINUX_NET_SHAPER_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/net_shaper.h>

struct ynl_sock;

extern const struct ynl_family ynl_net_shaper_family;

/* Enums */
const char *net_shaper_op_str(int op);
const char *net_shaper_scope_str(enum net_shaper_scope value);
const char *net_shaper_metric_str(enum net_shaper_metric value);

/* Common nested types */
struct net_shaper_handle {
	struct {
		__u32 scope:1;
		__u32 id:1;
	} _present;

	enum net_shaper_scope scope;
	__u32 id;
};

struct net_shaper_leaf_info {
	struct {
		__u32 handle:1;
		__u32 priority:1;
		__u32 weight:1;
	} _present;

	struct net_shaper_handle handle;
	__u32 priority;
	__u32 weight;
};

static inline struct net_shaper_leaf_info *
net_shaper_leaf_info_alloc(unsigned int n)
{
	return calloc(n, sizeof(struct net_shaper_leaf_info));
}

void net_shaper_leaf_info_free(struct net_shaper_leaf_info *obj);

static inline void
net_shaper_leaf_info_set_handle_scope(struct net_shaper_leaf_info *obj,
				      enum net_shaper_scope scope)
{
	obj->_present.handle = 1;
	obj->handle._present.scope = 1;
	obj->handle.scope = scope;
}
static inline void
net_shaper_leaf_info_set_handle_id(struct net_shaper_leaf_info *obj, __u32 id)
{
	obj->_present.handle = 1;
	obj->handle._present.id = 1;
	obj->handle.id = id;
}
static inline void
net_shaper_leaf_info_set_priority(struct net_shaper_leaf_info *obj,
				  __u32 priority)
{
	obj->_present.priority = 1;
	obj->priority = priority;
}
static inline void
net_shaper_leaf_info_set_weight(struct net_shaper_leaf_info *obj, __u32 weight)
{
	obj->_present.weight = 1;
	obj->weight = weight;
}

/* ============== NET_SHAPER_CMD_GET ============== */
/* NET_SHAPER_CMD_GET - do */
struct net_shaper_get_req {
	struct {
		__u32 ifindex:1;
		__u32 handle:1;
	} _present;

	__u32 ifindex;
	struct net_shaper_handle handle;
};

static inline struct net_shaper_get_req *net_shaper_get_req_alloc(void)
{
	return calloc(1, sizeof(struct net_shaper_get_req));
}
void net_shaper_get_req_free(struct net_shaper_get_req *req);

static inline void
net_shaper_get_req_set_ifindex(struct net_shaper_get_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
net_shaper_get_req_set_handle_scope(struct net_shaper_get_req *req,
				    enum net_shaper_scope scope)
{
	req->_present.handle = 1;
	req->handle._present.scope = 1;
	req->handle.scope = scope;
}
static inline void
net_shaper_get_req_set_handle_id(struct net_shaper_get_req *req, __u32 id)
{
	req->_present.handle = 1;
	req->handle._present.id = 1;
	req->handle.id = id;
}

struct net_shaper_get_rsp {
	struct {
		__u32 ifindex:1;
		__u32 parent:1;
		__u32 handle:1;
		__u32 metric:1;
		__u32 bw_min:1;
		__u32 bw_max:1;
		__u32 burst:1;
		__u32 priority:1;
		__u32 weight:1;
	} _present;

	__u32 ifindex;
	struct net_shaper_handle parent;
	struct net_shaper_handle handle;
	enum net_shaper_metric metric;
	__u64 bw_min;
	__u64 bw_max;
	__u64 burst;
	__u32 priority;
	__u32 weight;
};

void net_shaper_get_rsp_free(struct net_shaper_get_rsp *rsp);

/*
 * Get information about a shaper for a given device.

 */
struct net_shaper_get_rsp *
net_shaper_get(struct ynl_sock *ys, struct net_shaper_get_req *req);

/* NET_SHAPER_CMD_GET - dump */
struct net_shaper_get_req_dump {
	struct {
		__u32 ifindex:1;
	} _present;

	__u32 ifindex;
};

static inline struct net_shaper_get_req_dump *
net_shaper_get_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct net_shaper_get_req_dump));
}
void net_shaper_get_req_dump_free(struct net_shaper_get_req_dump *req);

static inline void
net_shaper_get_req_dump_set_ifindex(struct net_shaper_get_req_dump *req,
				    __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}

struct net_shaper_get_list {
	struct net_shaper_get_list *next;
	struct net_shaper_get_rsp obj __attribute__((aligned(8)));
};

void net_shaper_get_list_free(struct net_shaper_get_list *rsp);

struct net_shaper_get_list *
net_shaper_get_dump(struct ynl_sock *ys, struct net_shaper_get_req_dump *req);

/* ============== NET_SHAPER_CMD_SET ============== */
/* NET_SHAPER_CMD_SET - do */
struct net_shaper_set_req {
	struct {
		__u32 ifindex:1;
		__u32 handle:1;
		__u32 metric:1;
		__u32 bw_min:1;
		__u32 bw_max:1;
		__u32 burst:1;
		__u32 priority:1;
		__u32 weight:1;
	} _present;

	__u32 ifindex;
	struct net_shaper_handle handle;
	enum net_shaper_metric metric;
	__u64 bw_min;
	__u64 bw_max;
	__u64 burst;
	__u32 priority;
	__u32 weight;
};

static inline struct net_shaper_set_req *net_shaper_set_req_alloc(void)
{
	return calloc(1, sizeof(struct net_shaper_set_req));
}
void net_shaper_set_req_free(struct net_shaper_set_req *req);

static inline void
net_shaper_set_req_set_ifindex(struct net_shaper_set_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
net_shaper_set_req_set_handle_scope(struct net_shaper_set_req *req,
				    enum net_shaper_scope scope)
{
	req->_present.handle = 1;
	req->handle._present.scope = 1;
	req->handle.scope = scope;
}
static inline void
net_shaper_set_req_set_handle_id(struct net_shaper_set_req *req, __u32 id)
{
	req->_present.handle = 1;
	req->handle._present.id = 1;
	req->handle.id = id;
}
static inline void
net_shaper_set_req_set_metric(struct net_shaper_set_req *req,
			      enum net_shaper_metric metric)
{
	req->_present.metric = 1;
	req->metric = metric;
}
static inline void
net_shaper_set_req_set_bw_min(struct net_shaper_set_req *req, __u64 bw_min)
{
	req->_present.bw_min = 1;
	req->bw_min = bw_min;
}
static inline void
net_shaper_set_req_set_bw_max(struct net_shaper_set_req *req, __u64 bw_max)
{
	req->_present.bw_max = 1;
	req->bw_max = bw_max;
}
static inline void
net_shaper_set_req_set_burst(struct net_shaper_set_req *req, __u64 burst)
{
	req->_present.burst = 1;
	req->burst = burst;
}
static inline void
net_shaper_set_req_set_priority(struct net_shaper_set_req *req, __u32 priority)
{
	req->_present.priority = 1;
	req->priority = priority;
}
static inline void
net_shaper_set_req_set_weight(struct net_shaper_set_req *req, __u32 weight)
{
	req->_present.weight = 1;
	req->weight = weight;
}

/*
 * Create or update the specified shaper.
The set operation can't be used to create a @node scope shaper,
use the @group operation instead.

 */
int net_shaper_set(struct ynl_sock *ys, struct net_shaper_set_req *req);

/* ============== NET_SHAPER_CMD_DELETE ============== */
/* NET_SHAPER_CMD_DELETE - do */
struct net_shaper_delete_req {
	struct {
		__u32 ifindex:1;
		__u32 handle:1;
	} _present;

	__u32 ifindex;
	struct net_shaper_handle handle;
};

static inline struct net_shaper_delete_req *net_shaper_delete_req_alloc(void)
{
	return calloc(1, sizeof(struct net_shaper_delete_req));
}
void net_shaper_delete_req_free(struct net_shaper_delete_req *req);

static inline void
net_shaper_delete_req_set_ifindex(struct net_shaper_delete_req *req,
				  __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
net_shaper_delete_req_set_handle_scope(struct net_shaper_delete_req *req,
				       enum net_shaper_scope scope)
{
	req->_present.handle = 1;
	req->handle._present.scope = 1;
	req->handle.scope = scope;
}
static inline void
net_shaper_delete_req_set_handle_id(struct net_shaper_delete_req *req,
				    __u32 id)
{
	req->_present.handle = 1;
	req->handle._present.id = 1;
	req->handle.id = id;
}

/*
 * Clear (remove) the specified shaper. When deleting
a @node shaper, reattach all the node's leaves to the
deleted node's parent.
If, after the removal, the parent shaper has no more
leaves and the parent shaper scope is @node, the parent
node is deleted, recursively.
When deleting a @queue shaper or a @netdev shaper,
the shaper disappears from the hierarchy, but the
queue/device can still send traffic: it has an implicit
node with infinite bandwidth. The queue's implicit node
feeds an implicit RR node at the root of the hierarchy.

 */
int net_shaper_delete(struct ynl_sock *ys, struct net_shaper_delete_req *req);

/* ============== NET_SHAPER_CMD_GROUP ============== */
/* NET_SHAPER_CMD_GROUP - do */
struct net_shaper_group_req {
	struct {
		__u32 ifindex:1;
		__u32 parent:1;
		__u32 handle:1;
		__u32 metric:1;
		__u32 bw_min:1;
		__u32 bw_max:1;
		__u32 burst:1;
		__u32 priority:1;
		__u32 weight:1;
	} _present;
	struct {
		__u32 leaves;
	} _count;

	__u32 ifindex;
	struct net_shaper_handle parent;
	struct net_shaper_handle handle;
	enum net_shaper_metric metric;
	__u64 bw_min;
	__u64 bw_max;
	__u64 burst;
	__u32 priority;
	__u32 weight;
	struct net_shaper_leaf_info *leaves;
};

static inline struct net_shaper_group_req *net_shaper_group_req_alloc(void)
{
	return calloc(1, sizeof(struct net_shaper_group_req));
}
void net_shaper_group_req_free(struct net_shaper_group_req *req);

static inline void
net_shaper_group_req_set_ifindex(struct net_shaper_group_req *req,
				 __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
net_shaper_group_req_set_parent_scope(struct net_shaper_group_req *req,
				      enum net_shaper_scope scope)
{
	req->_present.parent = 1;
	req->parent._present.scope = 1;
	req->parent.scope = scope;
}
static inline void
net_shaper_group_req_set_parent_id(struct net_shaper_group_req *req, __u32 id)
{
	req->_present.parent = 1;
	req->parent._present.id = 1;
	req->parent.id = id;
}
static inline void
net_shaper_group_req_set_handle_scope(struct net_shaper_group_req *req,
				      enum net_shaper_scope scope)
{
	req->_present.handle = 1;
	req->handle._present.scope = 1;
	req->handle.scope = scope;
}
static inline void
net_shaper_group_req_set_handle_id(struct net_shaper_group_req *req, __u32 id)
{
	req->_present.handle = 1;
	req->handle._present.id = 1;
	req->handle.id = id;
}
static inline void
net_shaper_group_req_set_metric(struct net_shaper_group_req *req,
				enum net_shaper_metric metric)
{
	req->_present.metric = 1;
	req->metric = metric;
}
static inline void
net_shaper_group_req_set_bw_min(struct net_shaper_group_req *req, __u64 bw_min)
{
	req->_present.bw_min = 1;
	req->bw_min = bw_min;
}
static inline void
net_shaper_group_req_set_bw_max(struct net_shaper_group_req *req, __u64 bw_max)
{
	req->_present.bw_max = 1;
	req->bw_max = bw_max;
}
static inline void
net_shaper_group_req_set_burst(struct net_shaper_group_req *req, __u64 burst)
{
	req->_present.burst = 1;
	req->burst = burst;
}
static inline void
net_shaper_group_req_set_priority(struct net_shaper_group_req *req,
				  __u32 priority)
{
	req->_present.priority = 1;
	req->priority = priority;
}
static inline void
net_shaper_group_req_set_weight(struct net_shaper_group_req *req, __u32 weight)
{
	req->_present.weight = 1;
	req->weight = weight;
}
static inline void
__net_shaper_group_req_set_leaves(struct net_shaper_group_req *req,
				  struct net_shaper_leaf_info *leaves,
				  unsigned int n_leaves)
{
	unsigned int i;

	for (i = 0; i < req->_count.leaves; i++)
		net_shaper_leaf_info_free(&req->leaves[i]);
	free(req->leaves);
	req->leaves = leaves;
	req->_count.leaves = n_leaves;
}

struct net_shaper_group_rsp {
	struct {
		__u32 ifindex:1;
		__u32 handle:1;
	} _present;

	__u32 ifindex;
	struct net_shaper_handle handle;
};

void net_shaper_group_rsp_free(struct net_shaper_group_rsp *rsp);

/*
 * Create or update a scheduling group, attaching the specified
@leaves shapers under the specified node identified by @handle.
The @leaves shapers scope must be @queue and the node shaper
scope must be either @node or @netdev.
When the node shaper has @node scope, if the @handle @id is not
specified, a new shaper of such scope is created, otherwise the
specified node must already exist.
When updating an existing node shaper, the specified @leaves are
added to the existing node; such node will also retain any preexisting
leave.
The @parent handle for a new node shaper defaults to the parent
of all the leaves, provided all the leaves share the same parent.
Otherwise @parent handle must be specified.
The user can optionally provide shaping attributes for the node
shaper.
The operation is atomic, on failure no change is applied to
the device shaping configuration, otherwise the @node shaper
full identifier, comprising @binding and @handle, is provided
as the reply.

 */
struct net_shaper_group_rsp *
net_shaper_group(struct ynl_sock *ys, struct net_shaper_group_req *req);

/* ============== NET_SHAPER_CMD_CAP_GET ============== */
/* NET_SHAPER_CMD_CAP_GET - do */
struct net_shaper_cap_get_req {
	struct {
		__u32 ifindex:1;
		__u32 scope:1;
	} _present;

	__u32 ifindex;
	enum net_shaper_scope scope;
};

static inline struct net_shaper_cap_get_req *net_shaper_cap_get_req_alloc(void)
{
	return calloc(1, sizeof(struct net_shaper_cap_get_req));
}
void net_shaper_cap_get_req_free(struct net_shaper_cap_get_req *req);

static inline void
net_shaper_cap_get_req_set_ifindex(struct net_shaper_cap_get_req *req,
				   __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
net_shaper_cap_get_req_set_scope(struct net_shaper_cap_get_req *req,
				 enum net_shaper_scope scope)
{
	req->_present.scope = 1;
	req->scope = scope;
}

struct net_shaper_cap_get_rsp {
	struct {
		__u32 ifindex:1;
		__u32 scope:1;
		__u32 support_metric_bps:1;
		__u32 support_metric_pps:1;
		__u32 support_nesting:1;
		__u32 support_bw_min:1;
		__u32 support_bw_max:1;
		__u32 support_burst:1;
		__u32 support_priority:1;
		__u32 support_weight:1;
	} _present;

	__u32 ifindex;
	enum net_shaper_scope scope;
};

void net_shaper_cap_get_rsp_free(struct net_shaper_cap_get_rsp *rsp);

/*
 * Get the shaper capabilities supported by the given device
for the specified scope.

 */
struct net_shaper_cap_get_rsp *
net_shaper_cap_get(struct ynl_sock *ys, struct net_shaper_cap_get_req *req);

/* NET_SHAPER_CMD_CAP_GET - dump */
struct net_shaper_cap_get_req_dump {
	struct {
		__u32 ifindex:1;
	} _present;

	__u32 ifindex;
};

static inline struct net_shaper_cap_get_req_dump *
net_shaper_cap_get_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct net_shaper_cap_get_req_dump));
}
void net_shaper_cap_get_req_dump_free(struct net_shaper_cap_get_req_dump *req);

static inline void
net_shaper_cap_get_req_dump_set_ifindex(struct net_shaper_cap_get_req_dump *req,
					__u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}

struct net_shaper_cap_get_list {
	struct net_shaper_cap_get_list *next;
	struct net_shaper_cap_get_rsp obj __attribute__((aligned(8)));
};

void net_shaper_cap_get_list_free(struct net_shaper_cap_get_list *rsp);

struct net_shaper_cap_get_list *
net_shaper_cap_get_dump(struct ynl_sock *ys,
			struct net_shaper_cap_get_req_dump *req);

#endif /* _LINUX_NET_SHAPER_GEN_H */
