/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/wireguard.yaml */
/* YNL-GEN user header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_WIREGUARD_GEN_H
#define _LINUX_WIREGUARD_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/time_types.h>
#include <linux/wireguard.h>

struct ynl_sock;

extern const struct ynl_family ynl_wireguard_family;

/* Enums */
const char *wireguard_op_str(int op);
const char *wireguard_wgdevice_flags_str(enum wgdevice_flag value);
const char *wireguard_wgpeer_flags_str(enum wgpeer_flag value);
const char *wireguard_wgallowedip_flags_str(enum wgallowedip_flag value);

/* Common nested types */
struct wireguard_wgallowedip {
	struct {
		__u32 family:1;
		__u32 cidr_mask:1;
		__u32 flags:1;
	} _present;
	struct {
		__u32 ipaddr;
	} _len;

	__u32 idx;
	__u16 family;
	void *ipaddr;
	__u8 cidr_mask;
	__u32 flags;
};

static inline struct wireguard_wgallowedip *
wireguard_wgallowedip_alloc(unsigned int n)
{
	return calloc(n, sizeof(struct wireguard_wgallowedip));
}

void wireguard_wgallowedip_free(struct wireguard_wgallowedip *obj);

static inline void
wireguard_wgallowedip_set_family(struct wireguard_wgallowedip *obj,
				 __u16 family)
{
	obj->_present.family = 1;
	obj->family = family;
}
static inline void
wireguard_wgallowedip_set_ipaddr(struct wireguard_wgallowedip *obj,
				 const void *ipaddr, size_t len)
{
	free(obj->ipaddr);
	obj->_len.ipaddr = len;
	obj->ipaddr = malloc(obj->_len.ipaddr);
	memcpy(obj->ipaddr, ipaddr, obj->_len.ipaddr);
}
static inline void
wireguard_wgallowedip_set_cidr_mask(struct wireguard_wgallowedip *obj,
				    __u8 cidr_mask)
{
	obj->_present.cidr_mask = 1;
	obj->cidr_mask = cidr_mask;
}
static inline void
wireguard_wgallowedip_set_flags(struct wireguard_wgallowedip *obj, __u32 flags)
{
	obj->_present.flags = 1;
	obj->flags = flags;
}

struct wireguard_wgpeer {
	struct {
		__u32 flags:1;
		__u32 persistent_keepalive_interval:1;
		__u32 rx_bytes:1;
		__u32 tx_bytes:1;
		__u32 protocol_version:1;
	} _present;
	struct {
		__u32 public_key;
		__u32 preshared_key;
		__u32 endpoint;
		__u32 last_handshake_time;
	} _len;
	struct {
		__u32 allowedips;
	} _count;

	__u32 idx;
	void *public_key;
	void *preshared_key;
	__u32 flags;
	void *endpoint;
	__u16 persistent_keepalive_interval;
	struct __kernel_timespec *last_handshake_time;
	__u64 rx_bytes;
	__u64 tx_bytes;
	struct wireguard_wgallowedip *allowedips;
	__u32 protocol_version;
};

static inline struct wireguard_wgpeer *wireguard_wgpeer_alloc(unsigned int n)
{
	return calloc(n, sizeof(struct wireguard_wgpeer));
}

void wireguard_wgpeer_free(struct wireguard_wgpeer *obj);

static inline void
wireguard_wgpeer_set_public_key(struct wireguard_wgpeer *obj,
				const void *public_key, size_t len)
{
	free(obj->public_key);
	obj->_len.public_key = len;
	obj->public_key = malloc(obj->_len.public_key);
	memcpy(obj->public_key, public_key, obj->_len.public_key);
}
static inline void
wireguard_wgpeer_set_preshared_key(struct wireguard_wgpeer *obj,
				   const void *preshared_key, size_t len)
{
	free(obj->preshared_key);
	obj->_len.preshared_key = len;
	obj->preshared_key = malloc(obj->_len.preshared_key);
	memcpy(obj->preshared_key, preshared_key, obj->_len.preshared_key);
}
static inline void
wireguard_wgpeer_set_flags(struct wireguard_wgpeer *obj, __u32 flags)
{
	obj->_present.flags = 1;
	obj->flags = flags;
}
static inline void
wireguard_wgpeer_set_endpoint(struct wireguard_wgpeer *obj,
			      const void *endpoint, size_t len)
{
	free(obj->endpoint);
	obj->_len.endpoint = len;
	obj->endpoint = malloc(obj->_len.endpoint);
	memcpy(obj->endpoint, endpoint, obj->_len.endpoint);
}
static inline void
wireguard_wgpeer_set_persistent_keepalive_interval(struct wireguard_wgpeer *obj,
						   __u16 persistent_keepalive_interval)
{
	obj->_present.persistent_keepalive_interval = 1;
	obj->persistent_keepalive_interval = persistent_keepalive_interval;
}
static inline void
wireguard_wgpeer_set_last_handshake_time(struct wireguard_wgpeer *obj,
					 const void *last_handshake_time,
					 size_t len)
{
	free(obj->last_handshake_time);
	obj->_len.last_handshake_time = len;
	obj->last_handshake_time = malloc(obj->_len.last_handshake_time);
	memcpy(obj->last_handshake_time, last_handshake_time, obj->_len.last_handshake_time);
}
static inline void
wireguard_wgpeer_set_rx_bytes(struct wireguard_wgpeer *obj, __u64 rx_bytes)
{
	obj->_present.rx_bytes = 1;
	obj->rx_bytes = rx_bytes;
}
static inline void
wireguard_wgpeer_set_tx_bytes(struct wireguard_wgpeer *obj, __u64 tx_bytes)
{
	obj->_present.tx_bytes = 1;
	obj->tx_bytes = tx_bytes;
}
static inline void
__wireguard_wgpeer_set_allowedips(struct wireguard_wgpeer *obj,
				  struct wireguard_wgallowedip *allowedips,
				  unsigned int n_allowedips)
{
	unsigned int i;

	for (i = 0; i < obj->_count.allowedips; i++)
		wireguard_wgallowedip_free(&obj->allowedips[i]);
	free(obj->allowedips);
	obj->allowedips = allowedips;
	obj->_count.allowedips = n_allowedips;
}
static inline void
wireguard_wgpeer_set_protocol_version(struct wireguard_wgpeer *obj,
				      __u32 protocol_version)
{
	obj->_present.protocol_version = 1;
	obj->protocol_version = protocol_version;
}

/* ============== WG_CMD_GET_DEVICE ============== */
/* WG_CMD_GET_DEVICE - dump */
struct wireguard_get_device_req {
	struct {
		__u32 ifindex:1;
	} _present;
	struct {
		__u32 ifname;
	} _len;

	__u32 ifindex;
	char *ifname;
};

static inline struct wireguard_get_device_req *
wireguard_get_device_req_alloc(void)
{
	return calloc(1, sizeof(struct wireguard_get_device_req));
}
void wireguard_get_device_req_free(struct wireguard_get_device_req *req);

static inline void
wireguard_get_device_req_set_ifindex(struct wireguard_get_device_req *req,
				     __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
wireguard_get_device_req_set_ifname(struct wireguard_get_device_req *req,
				    const char *ifname)
{
	free(req->ifname);
	req->_len.ifname = strlen(ifname);
	req->ifname = malloc(req->_len.ifname + 1);
	memcpy(req->ifname, ifname, req->_len.ifname);
	req->ifname[req->_len.ifname] = 0;
}

struct wireguard_get_device_rsp {
	struct {
		__u32 ifindex:1;
		__u32 flags:1;
		__u32 listen_port:1;
		__u32 fwmark:1;
	} _present;
	struct {
		__u32 ifname;
		__u32 private_key;
		__u32 public_key;
	} _len;
	struct {
		__u32 peers;
	} _count;

	__u32 ifindex;
	char *ifname;
	void *private_key;
	void *public_key;
	__u32 flags;
	__u16 listen_port;
	__u32 fwmark;
	struct wireguard_wgpeer *peers;
};

struct wireguard_get_device_list {
	struct wireguard_get_device_list *next;
	struct wireguard_get_device_rsp obj __attribute__((aligned(8)));
};

void wireguard_get_device_list_free(struct wireguard_get_device_list *rsp);

struct wireguard_get_device_list *
wireguard_get_device_dump(struct ynl_sock *ys,
			  struct wireguard_get_device_req *req);

/* ============== WG_CMD_SET_DEVICE ============== */
/* WG_CMD_SET_DEVICE - do */
struct wireguard_set_device_req {
	struct {
		__u32 ifindex:1;
		__u32 flags:1;
		__u32 listen_port:1;
		__u32 fwmark:1;
	} _present;
	struct {
		__u32 ifname;
		__u32 private_key;
		__u32 public_key;
	} _len;
	struct {
		__u32 peers;
	} _count;

	__u32 ifindex;
	char *ifname;
	void *private_key;
	void *public_key;
	__u32 flags;
	__u16 listen_port;
	__u32 fwmark;
	struct wireguard_wgpeer *peers;
};

static inline struct wireguard_set_device_req *
wireguard_set_device_req_alloc(void)
{
	return calloc(1, sizeof(struct wireguard_set_device_req));
}
void wireguard_set_device_req_free(struct wireguard_set_device_req *req);

static inline void
wireguard_set_device_req_set_ifindex(struct wireguard_set_device_req *req,
				     __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
wireguard_set_device_req_set_ifname(struct wireguard_set_device_req *req,
				    const char *ifname)
{
	free(req->ifname);
	req->_len.ifname = strlen(ifname);
	req->ifname = malloc(req->_len.ifname + 1);
	memcpy(req->ifname, ifname, req->_len.ifname);
	req->ifname[req->_len.ifname] = 0;
}
static inline void
wireguard_set_device_req_set_private_key(struct wireguard_set_device_req *req,
					 const void *private_key, size_t len)
{
	free(req->private_key);
	req->_len.private_key = len;
	req->private_key = malloc(req->_len.private_key);
	memcpy(req->private_key, private_key, req->_len.private_key);
}
static inline void
wireguard_set_device_req_set_public_key(struct wireguard_set_device_req *req,
					const void *public_key, size_t len)
{
	free(req->public_key);
	req->_len.public_key = len;
	req->public_key = malloc(req->_len.public_key);
	memcpy(req->public_key, public_key, req->_len.public_key);
}
static inline void
wireguard_set_device_req_set_flags(struct wireguard_set_device_req *req,
				   __u32 flags)
{
	req->_present.flags = 1;
	req->flags = flags;
}
static inline void
wireguard_set_device_req_set_listen_port(struct wireguard_set_device_req *req,
					 __u16 listen_port)
{
	req->_present.listen_port = 1;
	req->listen_port = listen_port;
}
static inline void
wireguard_set_device_req_set_fwmark(struct wireguard_set_device_req *req,
				    __u32 fwmark)
{
	req->_present.fwmark = 1;
	req->fwmark = fwmark;
}
static inline void
__wireguard_set_device_req_set_peers(struct wireguard_set_device_req *req,
				     struct wireguard_wgpeer *peers,
				     unsigned int n_peers)
{
	unsigned int i;

	for (i = 0; i < req->_count.peers; i++)
		wireguard_wgpeer_free(&req->peers[i]);
	free(req->peers);
	req->peers = peers;
	req->_count.peers = n_peers;
}

/*
 * Set WireGuard device
~~~~~~~~~~~~~~~~~~~~

This command should be called with a wgdevice set, containing one but
not both of ``WGDEVICE_A_IFINDEX`` and ``WGDEVICE_A_IFNAME``.

It is possible that the amount of configuration data exceeds that of the
maximum message length accepted by the kernel. In that case, several
messages should be sent one after another, with each successive one
filling in information not contained in the prior. Note that if
``WGDEVICE_F_REPLACE_PEERS`` is specified in the first message, it
probably should not be specified in fragments that come after, so that
the list of peers is only cleared the first time but appended after.
Likewise for peers, if ``WGPEER_F_REPLACE_ALLOWEDIPS`` is specified in
the first message of a peer, it likely should not be specified in
subsequent fragments.

If an error occurs, ``NLMSG_ERROR`` will reply containing an errno.

 */
int wireguard_set_device(struct ynl_sock *ys,
			 struct wireguard_set_device_req *req);

#endif /* _LINUX_WIREGUARD_GEN_H */
