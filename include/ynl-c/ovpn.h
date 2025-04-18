/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/ovpn.yaml */
/* YNL-GEN user header */

#ifndef _LINUX_OVPN_GEN_H
#define _LINUX_OVPN_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/ovpn.h>

struct ynl_sock;

extern const struct ynl_family ynl_ovpn_family;

/* Enums */
const char *ovpn_op_str(int op);
const char *ovpn_cipher_alg_str(enum ovpn_cipher_alg value);
const char *ovpn_del_peer_reason_str(enum ovpn_del_peer_reason value);
const char *ovpn_key_slot_str(enum ovpn_key_slot value);

/* Common nested types */
struct ovpn_peer {
	struct {
		__u32 id:1;
		__u32 remote_ipv4:1;
		__u32 remote_ipv6_len;
		__u32 remote_ipv6_scope_id:1;
		__u32 remote_port:1;
		__u32 socket:1;
		__u32 socket_netnsid:1;
		__u32 vpn_ipv4:1;
		__u32 vpn_ipv6_len;
		__u32 local_ipv4:1;
		__u32 local_ipv6_len;
		__u32 local_port:1;
		__u32 keepalive_interval:1;
		__u32 keepalive_timeout:1;
		__u32 del_reason:1;
		__u32 vpn_rx_bytes:1;
		__u32 vpn_tx_bytes:1;
		__u32 vpn_rx_packets:1;
		__u32 vpn_tx_packets:1;
		__u32 link_rx_bytes:1;
		__u32 link_tx_bytes:1;
		__u32 link_rx_packets:1;
		__u32 link_tx_packets:1;
	} _present;

	__u32 id;
	__u32 remote_ipv4 /* big-endian */;
	void *remote_ipv6;
	__u32 remote_ipv6_scope_id;
	__u16 remote_port /* big-endian */;
	__u32 socket;
	__s32 socket_netnsid;
	__u32 vpn_ipv4 /* big-endian */;
	void *vpn_ipv6;
	__u32 local_ipv4 /* big-endian */;
	void *local_ipv6;
	__u16 local_port /* big-endian */;
	__u32 keepalive_interval;
	__u32 keepalive_timeout;
	enum ovpn_del_peer_reason del_reason;
	__u64 vpn_rx_bytes;
	__u64 vpn_tx_bytes;
	__u64 vpn_rx_packets;
	__u64 vpn_tx_packets;
	__u64 link_rx_bytes;
	__u64 link_tx_bytes;
	__u64 link_rx_packets;
	__u64 link_tx_packets;
};

struct ovpn_keydir {
	struct {
		__u32 cipher_key_len;
		__u32 nonce_tail_len;
	} _present;

	void *cipher_key;
	void *nonce_tail;
};

struct ovpn_keyconf {
	struct {
		__u32 peer_id:1;
		__u32 slot:1;
		__u32 key_id:1;
		__u32 cipher_alg:1;
		__u32 encrypt_dir:1;
		__u32 decrypt_dir:1;
	} _present;

	__u32 peer_id;
	enum ovpn_key_slot slot;
	__u32 key_id;
	enum ovpn_cipher_alg cipher_alg;
	struct ovpn_keydir encrypt_dir;
	struct ovpn_keydir decrypt_dir;
};

/* ============== OVPN_CMD_PEER_NEW ============== */
/* OVPN_CMD_PEER_NEW - do */
struct ovpn_peer_new_req {
	struct {
		__u32 ifindex:1;
		__u32 peer:1;
	} _present;

	__u32 ifindex;
	struct ovpn_peer peer;
};

static inline struct ovpn_peer_new_req *ovpn_peer_new_req_alloc(void)
{
	return calloc(1, sizeof(struct ovpn_peer_new_req));
}
void ovpn_peer_new_req_free(struct ovpn_peer_new_req *req);

static inline void
ovpn_peer_new_req_set_ifindex(struct ovpn_peer_new_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
ovpn_peer_new_req_set_peer_id(struct ovpn_peer_new_req *req, __u32 id)
{
	req->_present.peer = 1;
	req->peer._present.id = 1;
	req->peer.id = id;
}
static inline void
ovpn_peer_new_req_set_peer_remote_ipv4(struct ovpn_peer_new_req *req,
				       __u32 remote_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.remote_ipv4 = 1;
	req->peer.remote_ipv4 = remote_ipv4;
}
static inline void
ovpn_peer_new_req_set_peer_remote_ipv6(struct ovpn_peer_new_req *req,
				       const void *remote_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.remote_ipv6);
	req->peer._present.remote_ipv6_len = len;
	req->peer.remote_ipv6 = malloc(req->peer._present.remote_ipv6_len);
	memcpy(req->peer.remote_ipv6, remote_ipv6, req->peer._present.remote_ipv6_len);
}
static inline void
ovpn_peer_new_req_set_peer_remote_ipv6_scope_id(struct ovpn_peer_new_req *req,
						__u32 remote_ipv6_scope_id)
{
	req->_present.peer = 1;
	req->peer._present.remote_ipv6_scope_id = 1;
	req->peer.remote_ipv6_scope_id = remote_ipv6_scope_id;
}
static inline void
ovpn_peer_new_req_set_peer_remote_port(struct ovpn_peer_new_req *req,
				       __u16 remote_port /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.remote_port = 1;
	req->peer.remote_port = remote_port;
}
static inline void
ovpn_peer_new_req_set_peer_socket(struct ovpn_peer_new_req *req, __u32 socket)
{
	req->_present.peer = 1;
	req->peer._present.socket = 1;
	req->peer.socket = socket;
}
static inline void
ovpn_peer_new_req_set_peer_socket_netnsid(struct ovpn_peer_new_req *req,
					  __s32 socket_netnsid)
{
	req->_present.peer = 1;
	req->peer._present.socket_netnsid = 1;
	req->peer.socket_netnsid = socket_netnsid;
}
static inline void
ovpn_peer_new_req_set_peer_vpn_ipv4(struct ovpn_peer_new_req *req,
				    __u32 vpn_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.vpn_ipv4 = 1;
	req->peer.vpn_ipv4 = vpn_ipv4;
}
static inline void
ovpn_peer_new_req_set_peer_vpn_ipv6(struct ovpn_peer_new_req *req,
				    const void *vpn_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.vpn_ipv6);
	req->peer._present.vpn_ipv6_len = len;
	req->peer.vpn_ipv6 = malloc(req->peer._present.vpn_ipv6_len);
	memcpy(req->peer.vpn_ipv6, vpn_ipv6, req->peer._present.vpn_ipv6_len);
}
static inline void
ovpn_peer_new_req_set_peer_local_ipv4(struct ovpn_peer_new_req *req,
				      __u32 local_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.local_ipv4 = 1;
	req->peer.local_ipv4 = local_ipv4;
}
static inline void
ovpn_peer_new_req_set_peer_local_ipv6(struct ovpn_peer_new_req *req,
				      const void *local_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.local_ipv6);
	req->peer._present.local_ipv6_len = len;
	req->peer.local_ipv6 = malloc(req->peer._present.local_ipv6_len);
	memcpy(req->peer.local_ipv6, local_ipv6, req->peer._present.local_ipv6_len);
}
static inline void
ovpn_peer_new_req_set_peer_local_port(struct ovpn_peer_new_req *req,
				      __u16 local_port /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.local_port = 1;
	req->peer.local_port = local_port;
}
static inline void
ovpn_peer_new_req_set_peer_keepalive_interval(struct ovpn_peer_new_req *req,
					      __u32 keepalive_interval)
{
	req->_present.peer = 1;
	req->peer._present.keepalive_interval = 1;
	req->peer.keepalive_interval = keepalive_interval;
}
static inline void
ovpn_peer_new_req_set_peer_keepalive_timeout(struct ovpn_peer_new_req *req,
					     __u32 keepalive_timeout)
{
	req->_present.peer = 1;
	req->peer._present.keepalive_timeout = 1;
	req->peer.keepalive_timeout = keepalive_timeout;
}
static inline void
ovpn_peer_new_req_set_peer_del_reason(struct ovpn_peer_new_req *req,
				      enum ovpn_del_peer_reason del_reason)
{
	req->_present.peer = 1;
	req->peer._present.del_reason = 1;
	req->peer.del_reason = del_reason;
}
static inline void
ovpn_peer_new_req_set_peer_vpn_rx_bytes(struct ovpn_peer_new_req *req,
					__u64 vpn_rx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.vpn_rx_bytes = 1;
	req->peer.vpn_rx_bytes = vpn_rx_bytes;
}
static inline void
ovpn_peer_new_req_set_peer_vpn_tx_bytes(struct ovpn_peer_new_req *req,
					__u64 vpn_tx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.vpn_tx_bytes = 1;
	req->peer.vpn_tx_bytes = vpn_tx_bytes;
}
static inline void
ovpn_peer_new_req_set_peer_vpn_rx_packets(struct ovpn_peer_new_req *req,
					  __u64 vpn_rx_packets)
{
	req->_present.peer = 1;
	req->peer._present.vpn_rx_packets = 1;
	req->peer.vpn_rx_packets = vpn_rx_packets;
}
static inline void
ovpn_peer_new_req_set_peer_vpn_tx_packets(struct ovpn_peer_new_req *req,
					  __u64 vpn_tx_packets)
{
	req->_present.peer = 1;
	req->peer._present.vpn_tx_packets = 1;
	req->peer.vpn_tx_packets = vpn_tx_packets;
}
static inline void
ovpn_peer_new_req_set_peer_link_rx_bytes(struct ovpn_peer_new_req *req,
					 __u64 link_rx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.link_rx_bytes = 1;
	req->peer.link_rx_bytes = link_rx_bytes;
}
static inline void
ovpn_peer_new_req_set_peer_link_tx_bytes(struct ovpn_peer_new_req *req,
					 __u64 link_tx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.link_tx_bytes = 1;
	req->peer.link_tx_bytes = link_tx_bytes;
}
static inline void
ovpn_peer_new_req_set_peer_link_rx_packets(struct ovpn_peer_new_req *req,
					   __u64 link_rx_packets)
{
	req->_present.peer = 1;
	req->peer._present.link_rx_packets = 1;
	req->peer.link_rx_packets = link_rx_packets;
}
static inline void
ovpn_peer_new_req_set_peer_link_tx_packets(struct ovpn_peer_new_req *req,
					   __u64 link_tx_packets)
{
	req->_present.peer = 1;
	req->peer._present.link_tx_packets = 1;
	req->peer.link_tx_packets = link_tx_packets;
}

/*
 * Add a remote peer
 */
int ovpn_peer_new(struct ynl_sock *ys, struct ovpn_peer_new_req *req);

/* ============== OVPN_CMD_PEER_SET ============== */
/* OVPN_CMD_PEER_SET - do */
struct ovpn_peer_set_req {
	struct {
		__u32 ifindex:1;
		__u32 peer:1;
	} _present;

	__u32 ifindex;
	struct ovpn_peer peer;
};

static inline struct ovpn_peer_set_req *ovpn_peer_set_req_alloc(void)
{
	return calloc(1, sizeof(struct ovpn_peer_set_req));
}
void ovpn_peer_set_req_free(struct ovpn_peer_set_req *req);

static inline void
ovpn_peer_set_req_set_ifindex(struct ovpn_peer_set_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
ovpn_peer_set_req_set_peer_id(struct ovpn_peer_set_req *req, __u32 id)
{
	req->_present.peer = 1;
	req->peer._present.id = 1;
	req->peer.id = id;
}
static inline void
ovpn_peer_set_req_set_peer_remote_ipv4(struct ovpn_peer_set_req *req,
				       __u32 remote_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.remote_ipv4 = 1;
	req->peer.remote_ipv4 = remote_ipv4;
}
static inline void
ovpn_peer_set_req_set_peer_remote_ipv6(struct ovpn_peer_set_req *req,
				       const void *remote_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.remote_ipv6);
	req->peer._present.remote_ipv6_len = len;
	req->peer.remote_ipv6 = malloc(req->peer._present.remote_ipv6_len);
	memcpy(req->peer.remote_ipv6, remote_ipv6, req->peer._present.remote_ipv6_len);
}
static inline void
ovpn_peer_set_req_set_peer_remote_ipv6_scope_id(struct ovpn_peer_set_req *req,
						__u32 remote_ipv6_scope_id)
{
	req->_present.peer = 1;
	req->peer._present.remote_ipv6_scope_id = 1;
	req->peer.remote_ipv6_scope_id = remote_ipv6_scope_id;
}
static inline void
ovpn_peer_set_req_set_peer_remote_port(struct ovpn_peer_set_req *req,
				       __u16 remote_port /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.remote_port = 1;
	req->peer.remote_port = remote_port;
}
static inline void
ovpn_peer_set_req_set_peer_socket(struct ovpn_peer_set_req *req, __u32 socket)
{
	req->_present.peer = 1;
	req->peer._present.socket = 1;
	req->peer.socket = socket;
}
static inline void
ovpn_peer_set_req_set_peer_socket_netnsid(struct ovpn_peer_set_req *req,
					  __s32 socket_netnsid)
{
	req->_present.peer = 1;
	req->peer._present.socket_netnsid = 1;
	req->peer.socket_netnsid = socket_netnsid;
}
static inline void
ovpn_peer_set_req_set_peer_vpn_ipv4(struct ovpn_peer_set_req *req,
				    __u32 vpn_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.vpn_ipv4 = 1;
	req->peer.vpn_ipv4 = vpn_ipv4;
}
static inline void
ovpn_peer_set_req_set_peer_vpn_ipv6(struct ovpn_peer_set_req *req,
				    const void *vpn_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.vpn_ipv6);
	req->peer._present.vpn_ipv6_len = len;
	req->peer.vpn_ipv6 = malloc(req->peer._present.vpn_ipv6_len);
	memcpy(req->peer.vpn_ipv6, vpn_ipv6, req->peer._present.vpn_ipv6_len);
}
static inline void
ovpn_peer_set_req_set_peer_local_ipv4(struct ovpn_peer_set_req *req,
				      __u32 local_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.local_ipv4 = 1;
	req->peer.local_ipv4 = local_ipv4;
}
static inline void
ovpn_peer_set_req_set_peer_local_ipv6(struct ovpn_peer_set_req *req,
				      const void *local_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.local_ipv6);
	req->peer._present.local_ipv6_len = len;
	req->peer.local_ipv6 = malloc(req->peer._present.local_ipv6_len);
	memcpy(req->peer.local_ipv6, local_ipv6, req->peer._present.local_ipv6_len);
}
static inline void
ovpn_peer_set_req_set_peer_local_port(struct ovpn_peer_set_req *req,
				      __u16 local_port /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.local_port = 1;
	req->peer.local_port = local_port;
}
static inline void
ovpn_peer_set_req_set_peer_keepalive_interval(struct ovpn_peer_set_req *req,
					      __u32 keepalive_interval)
{
	req->_present.peer = 1;
	req->peer._present.keepalive_interval = 1;
	req->peer.keepalive_interval = keepalive_interval;
}
static inline void
ovpn_peer_set_req_set_peer_keepalive_timeout(struct ovpn_peer_set_req *req,
					     __u32 keepalive_timeout)
{
	req->_present.peer = 1;
	req->peer._present.keepalive_timeout = 1;
	req->peer.keepalive_timeout = keepalive_timeout;
}
static inline void
ovpn_peer_set_req_set_peer_del_reason(struct ovpn_peer_set_req *req,
				      enum ovpn_del_peer_reason del_reason)
{
	req->_present.peer = 1;
	req->peer._present.del_reason = 1;
	req->peer.del_reason = del_reason;
}
static inline void
ovpn_peer_set_req_set_peer_vpn_rx_bytes(struct ovpn_peer_set_req *req,
					__u64 vpn_rx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.vpn_rx_bytes = 1;
	req->peer.vpn_rx_bytes = vpn_rx_bytes;
}
static inline void
ovpn_peer_set_req_set_peer_vpn_tx_bytes(struct ovpn_peer_set_req *req,
					__u64 vpn_tx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.vpn_tx_bytes = 1;
	req->peer.vpn_tx_bytes = vpn_tx_bytes;
}
static inline void
ovpn_peer_set_req_set_peer_vpn_rx_packets(struct ovpn_peer_set_req *req,
					  __u64 vpn_rx_packets)
{
	req->_present.peer = 1;
	req->peer._present.vpn_rx_packets = 1;
	req->peer.vpn_rx_packets = vpn_rx_packets;
}
static inline void
ovpn_peer_set_req_set_peer_vpn_tx_packets(struct ovpn_peer_set_req *req,
					  __u64 vpn_tx_packets)
{
	req->_present.peer = 1;
	req->peer._present.vpn_tx_packets = 1;
	req->peer.vpn_tx_packets = vpn_tx_packets;
}
static inline void
ovpn_peer_set_req_set_peer_link_rx_bytes(struct ovpn_peer_set_req *req,
					 __u64 link_rx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.link_rx_bytes = 1;
	req->peer.link_rx_bytes = link_rx_bytes;
}
static inline void
ovpn_peer_set_req_set_peer_link_tx_bytes(struct ovpn_peer_set_req *req,
					 __u64 link_tx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.link_tx_bytes = 1;
	req->peer.link_tx_bytes = link_tx_bytes;
}
static inline void
ovpn_peer_set_req_set_peer_link_rx_packets(struct ovpn_peer_set_req *req,
					   __u64 link_rx_packets)
{
	req->_present.peer = 1;
	req->peer._present.link_rx_packets = 1;
	req->peer.link_rx_packets = link_rx_packets;
}
static inline void
ovpn_peer_set_req_set_peer_link_tx_packets(struct ovpn_peer_set_req *req,
					   __u64 link_tx_packets)
{
	req->_present.peer = 1;
	req->peer._present.link_tx_packets = 1;
	req->peer.link_tx_packets = link_tx_packets;
}

/*
 * modify a remote peer
 */
int ovpn_peer_set(struct ynl_sock *ys, struct ovpn_peer_set_req *req);

/* ============== OVPN_CMD_PEER_GET ============== */
/* OVPN_CMD_PEER_GET - do */
struct ovpn_peer_get_req {
	struct {
		__u32 ifindex:1;
		__u32 peer:1;
	} _present;

	__u32 ifindex;
	struct ovpn_peer peer;
};

static inline struct ovpn_peer_get_req *ovpn_peer_get_req_alloc(void)
{
	return calloc(1, sizeof(struct ovpn_peer_get_req));
}
void ovpn_peer_get_req_free(struct ovpn_peer_get_req *req);

static inline void
ovpn_peer_get_req_set_ifindex(struct ovpn_peer_get_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
ovpn_peer_get_req_set_peer_id(struct ovpn_peer_get_req *req, __u32 id)
{
	req->_present.peer = 1;
	req->peer._present.id = 1;
	req->peer.id = id;
}
static inline void
ovpn_peer_get_req_set_peer_remote_ipv4(struct ovpn_peer_get_req *req,
				       __u32 remote_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.remote_ipv4 = 1;
	req->peer.remote_ipv4 = remote_ipv4;
}
static inline void
ovpn_peer_get_req_set_peer_remote_ipv6(struct ovpn_peer_get_req *req,
				       const void *remote_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.remote_ipv6);
	req->peer._present.remote_ipv6_len = len;
	req->peer.remote_ipv6 = malloc(req->peer._present.remote_ipv6_len);
	memcpy(req->peer.remote_ipv6, remote_ipv6, req->peer._present.remote_ipv6_len);
}
static inline void
ovpn_peer_get_req_set_peer_remote_ipv6_scope_id(struct ovpn_peer_get_req *req,
						__u32 remote_ipv6_scope_id)
{
	req->_present.peer = 1;
	req->peer._present.remote_ipv6_scope_id = 1;
	req->peer.remote_ipv6_scope_id = remote_ipv6_scope_id;
}
static inline void
ovpn_peer_get_req_set_peer_remote_port(struct ovpn_peer_get_req *req,
				       __u16 remote_port /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.remote_port = 1;
	req->peer.remote_port = remote_port;
}
static inline void
ovpn_peer_get_req_set_peer_socket(struct ovpn_peer_get_req *req, __u32 socket)
{
	req->_present.peer = 1;
	req->peer._present.socket = 1;
	req->peer.socket = socket;
}
static inline void
ovpn_peer_get_req_set_peer_socket_netnsid(struct ovpn_peer_get_req *req,
					  __s32 socket_netnsid)
{
	req->_present.peer = 1;
	req->peer._present.socket_netnsid = 1;
	req->peer.socket_netnsid = socket_netnsid;
}
static inline void
ovpn_peer_get_req_set_peer_vpn_ipv4(struct ovpn_peer_get_req *req,
				    __u32 vpn_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.vpn_ipv4 = 1;
	req->peer.vpn_ipv4 = vpn_ipv4;
}
static inline void
ovpn_peer_get_req_set_peer_vpn_ipv6(struct ovpn_peer_get_req *req,
				    const void *vpn_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.vpn_ipv6);
	req->peer._present.vpn_ipv6_len = len;
	req->peer.vpn_ipv6 = malloc(req->peer._present.vpn_ipv6_len);
	memcpy(req->peer.vpn_ipv6, vpn_ipv6, req->peer._present.vpn_ipv6_len);
}
static inline void
ovpn_peer_get_req_set_peer_local_ipv4(struct ovpn_peer_get_req *req,
				      __u32 local_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.local_ipv4 = 1;
	req->peer.local_ipv4 = local_ipv4;
}
static inline void
ovpn_peer_get_req_set_peer_local_ipv6(struct ovpn_peer_get_req *req,
				      const void *local_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.local_ipv6);
	req->peer._present.local_ipv6_len = len;
	req->peer.local_ipv6 = malloc(req->peer._present.local_ipv6_len);
	memcpy(req->peer.local_ipv6, local_ipv6, req->peer._present.local_ipv6_len);
}
static inline void
ovpn_peer_get_req_set_peer_local_port(struct ovpn_peer_get_req *req,
				      __u16 local_port /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.local_port = 1;
	req->peer.local_port = local_port;
}
static inline void
ovpn_peer_get_req_set_peer_keepalive_interval(struct ovpn_peer_get_req *req,
					      __u32 keepalive_interval)
{
	req->_present.peer = 1;
	req->peer._present.keepalive_interval = 1;
	req->peer.keepalive_interval = keepalive_interval;
}
static inline void
ovpn_peer_get_req_set_peer_keepalive_timeout(struct ovpn_peer_get_req *req,
					     __u32 keepalive_timeout)
{
	req->_present.peer = 1;
	req->peer._present.keepalive_timeout = 1;
	req->peer.keepalive_timeout = keepalive_timeout;
}
static inline void
ovpn_peer_get_req_set_peer_del_reason(struct ovpn_peer_get_req *req,
				      enum ovpn_del_peer_reason del_reason)
{
	req->_present.peer = 1;
	req->peer._present.del_reason = 1;
	req->peer.del_reason = del_reason;
}
static inline void
ovpn_peer_get_req_set_peer_vpn_rx_bytes(struct ovpn_peer_get_req *req,
					__u64 vpn_rx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.vpn_rx_bytes = 1;
	req->peer.vpn_rx_bytes = vpn_rx_bytes;
}
static inline void
ovpn_peer_get_req_set_peer_vpn_tx_bytes(struct ovpn_peer_get_req *req,
					__u64 vpn_tx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.vpn_tx_bytes = 1;
	req->peer.vpn_tx_bytes = vpn_tx_bytes;
}
static inline void
ovpn_peer_get_req_set_peer_vpn_rx_packets(struct ovpn_peer_get_req *req,
					  __u64 vpn_rx_packets)
{
	req->_present.peer = 1;
	req->peer._present.vpn_rx_packets = 1;
	req->peer.vpn_rx_packets = vpn_rx_packets;
}
static inline void
ovpn_peer_get_req_set_peer_vpn_tx_packets(struct ovpn_peer_get_req *req,
					  __u64 vpn_tx_packets)
{
	req->_present.peer = 1;
	req->peer._present.vpn_tx_packets = 1;
	req->peer.vpn_tx_packets = vpn_tx_packets;
}
static inline void
ovpn_peer_get_req_set_peer_link_rx_bytes(struct ovpn_peer_get_req *req,
					 __u64 link_rx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.link_rx_bytes = 1;
	req->peer.link_rx_bytes = link_rx_bytes;
}
static inline void
ovpn_peer_get_req_set_peer_link_tx_bytes(struct ovpn_peer_get_req *req,
					 __u64 link_tx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.link_tx_bytes = 1;
	req->peer.link_tx_bytes = link_tx_bytes;
}
static inline void
ovpn_peer_get_req_set_peer_link_rx_packets(struct ovpn_peer_get_req *req,
					   __u64 link_rx_packets)
{
	req->_present.peer = 1;
	req->peer._present.link_rx_packets = 1;
	req->peer.link_rx_packets = link_rx_packets;
}
static inline void
ovpn_peer_get_req_set_peer_link_tx_packets(struct ovpn_peer_get_req *req,
					   __u64 link_tx_packets)
{
	req->_present.peer = 1;
	req->peer._present.link_tx_packets = 1;
	req->peer.link_tx_packets = link_tx_packets;
}

struct ovpn_peer_get_rsp {
	struct {
		__u32 peer:1;
	} _present;

	struct ovpn_peer peer;
};

void ovpn_peer_get_rsp_free(struct ovpn_peer_get_rsp *rsp);

/*
 * Retrieve data about existing remote peers (or a specific one)
 */
struct ovpn_peer_get_rsp *
ovpn_peer_get(struct ynl_sock *ys, struct ovpn_peer_get_req *req);

/* OVPN_CMD_PEER_GET - dump */
struct ovpn_peer_get_req_dump {
	struct {
		__u32 ifindex:1;
	} _present;

	__u32 ifindex;
};

static inline struct ovpn_peer_get_req_dump *ovpn_peer_get_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct ovpn_peer_get_req_dump));
}
void ovpn_peer_get_req_dump_free(struct ovpn_peer_get_req_dump *req);

static inline void
ovpn_peer_get_req_dump_set_ifindex(struct ovpn_peer_get_req_dump *req,
				   __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}

struct ovpn_peer_get_list {
	struct ovpn_peer_get_list *next;
	struct ovpn_peer_get_rsp obj __attribute__((aligned(8)));
};

void ovpn_peer_get_list_free(struct ovpn_peer_get_list *rsp);

struct ovpn_peer_get_list *
ovpn_peer_get_dump(struct ynl_sock *ys, struct ovpn_peer_get_req_dump *req);

/* OVPN_CMD_PEER_GET - notify */
struct ovpn_peer_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct ovpn_peer_get_ntf *ntf);
	struct ovpn_peer_get_rsp obj __attribute__((aligned(8)));
};

void ovpn_peer_get_ntf_free(struct ovpn_peer_get_ntf *rsp);

/* ============== OVPN_CMD_PEER_DEL ============== */
/* OVPN_CMD_PEER_DEL - do */
struct ovpn_peer_del_req {
	struct {
		__u32 ifindex:1;
		__u32 peer:1;
	} _present;

	__u32 ifindex;
	struct ovpn_peer peer;
};

static inline struct ovpn_peer_del_req *ovpn_peer_del_req_alloc(void)
{
	return calloc(1, sizeof(struct ovpn_peer_del_req));
}
void ovpn_peer_del_req_free(struct ovpn_peer_del_req *req);

static inline void
ovpn_peer_del_req_set_ifindex(struct ovpn_peer_del_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
ovpn_peer_del_req_set_peer_id(struct ovpn_peer_del_req *req, __u32 id)
{
	req->_present.peer = 1;
	req->peer._present.id = 1;
	req->peer.id = id;
}
static inline void
ovpn_peer_del_req_set_peer_remote_ipv4(struct ovpn_peer_del_req *req,
				       __u32 remote_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.remote_ipv4 = 1;
	req->peer.remote_ipv4 = remote_ipv4;
}
static inline void
ovpn_peer_del_req_set_peer_remote_ipv6(struct ovpn_peer_del_req *req,
				       const void *remote_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.remote_ipv6);
	req->peer._present.remote_ipv6_len = len;
	req->peer.remote_ipv6 = malloc(req->peer._present.remote_ipv6_len);
	memcpy(req->peer.remote_ipv6, remote_ipv6, req->peer._present.remote_ipv6_len);
}
static inline void
ovpn_peer_del_req_set_peer_remote_ipv6_scope_id(struct ovpn_peer_del_req *req,
						__u32 remote_ipv6_scope_id)
{
	req->_present.peer = 1;
	req->peer._present.remote_ipv6_scope_id = 1;
	req->peer.remote_ipv6_scope_id = remote_ipv6_scope_id;
}
static inline void
ovpn_peer_del_req_set_peer_remote_port(struct ovpn_peer_del_req *req,
				       __u16 remote_port /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.remote_port = 1;
	req->peer.remote_port = remote_port;
}
static inline void
ovpn_peer_del_req_set_peer_socket(struct ovpn_peer_del_req *req, __u32 socket)
{
	req->_present.peer = 1;
	req->peer._present.socket = 1;
	req->peer.socket = socket;
}
static inline void
ovpn_peer_del_req_set_peer_socket_netnsid(struct ovpn_peer_del_req *req,
					  __s32 socket_netnsid)
{
	req->_present.peer = 1;
	req->peer._present.socket_netnsid = 1;
	req->peer.socket_netnsid = socket_netnsid;
}
static inline void
ovpn_peer_del_req_set_peer_vpn_ipv4(struct ovpn_peer_del_req *req,
				    __u32 vpn_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.vpn_ipv4 = 1;
	req->peer.vpn_ipv4 = vpn_ipv4;
}
static inline void
ovpn_peer_del_req_set_peer_vpn_ipv6(struct ovpn_peer_del_req *req,
				    const void *vpn_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.vpn_ipv6);
	req->peer._present.vpn_ipv6_len = len;
	req->peer.vpn_ipv6 = malloc(req->peer._present.vpn_ipv6_len);
	memcpy(req->peer.vpn_ipv6, vpn_ipv6, req->peer._present.vpn_ipv6_len);
}
static inline void
ovpn_peer_del_req_set_peer_local_ipv4(struct ovpn_peer_del_req *req,
				      __u32 local_ipv4 /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.local_ipv4 = 1;
	req->peer.local_ipv4 = local_ipv4;
}
static inline void
ovpn_peer_del_req_set_peer_local_ipv6(struct ovpn_peer_del_req *req,
				      const void *local_ipv6, size_t len)
{
	req->_present.peer = 1;
	free(req->peer.local_ipv6);
	req->peer._present.local_ipv6_len = len;
	req->peer.local_ipv6 = malloc(req->peer._present.local_ipv6_len);
	memcpy(req->peer.local_ipv6, local_ipv6, req->peer._present.local_ipv6_len);
}
static inline void
ovpn_peer_del_req_set_peer_local_port(struct ovpn_peer_del_req *req,
				      __u16 local_port /* big-endian */)
{
	req->_present.peer = 1;
	req->peer._present.local_port = 1;
	req->peer.local_port = local_port;
}
static inline void
ovpn_peer_del_req_set_peer_keepalive_interval(struct ovpn_peer_del_req *req,
					      __u32 keepalive_interval)
{
	req->_present.peer = 1;
	req->peer._present.keepalive_interval = 1;
	req->peer.keepalive_interval = keepalive_interval;
}
static inline void
ovpn_peer_del_req_set_peer_keepalive_timeout(struct ovpn_peer_del_req *req,
					     __u32 keepalive_timeout)
{
	req->_present.peer = 1;
	req->peer._present.keepalive_timeout = 1;
	req->peer.keepalive_timeout = keepalive_timeout;
}
static inline void
ovpn_peer_del_req_set_peer_del_reason(struct ovpn_peer_del_req *req,
				      enum ovpn_del_peer_reason del_reason)
{
	req->_present.peer = 1;
	req->peer._present.del_reason = 1;
	req->peer.del_reason = del_reason;
}
static inline void
ovpn_peer_del_req_set_peer_vpn_rx_bytes(struct ovpn_peer_del_req *req,
					__u64 vpn_rx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.vpn_rx_bytes = 1;
	req->peer.vpn_rx_bytes = vpn_rx_bytes;
}
static inline void
ovpn_peer_del_req_set_peer_vpn_tx_bytes(struct ovpn_peer_del_req *req,
					__u64 vpn_tx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.vpn_tx_bytes = 1;
	req->peer.vpn_tx_bytes = vpn_tx_bytes;
}
static inline void
ovpn_peer_del_req_set_peer_vpn_rx_packets(struct ovpn_peer_del_req *req,
					  __u64 vpn_rx_packets)
{
	req->_present.peer = 1;
	req->peer._present.vpn_rx_packets = 1;
	req->peer.vpn_rx_packets = vpn_rx_packets;
}
static inline void
ovpn_peer_del_req_set_peer_vpn_tx_packets(struct ovpn_peer_del_req *req,
					  __u64 vpn_tx_packets)
{
	req->_present.peer = 1;
	req->peer._present.vpn_tx_packets = 1;
	req->peer.vpn_tx_packets = vpn_tx_packets;
}
static inline void
ovpn_peer_del_req_set_peer_link_rx_bytes(struct ovpn_peer_del_req *req,
					 __u64 link_rx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.link_rx_bytes = 1;
	req->peer.link_rx_bytes = link_rx_bytes;
}
static inline void
ovpn_peer_del_req_set_peer_link_tx_bytes(struct ovpn_peer_del_req *req,
					 __u64 link_tx_bytes)
{
	req->_present.peer = 1;
	req->peer._present.link_tx_bytes = 1;
	req->peer.link_tx_bytes = link_tx_bytes;
}
static inline void
ovpn_peer_del_req_set_peer_link_rx_packets(struct ovpn_peer_del_req *req,
					   __u64 link_rx_packets)
{
	req->_present.peer = 1;
	req->peer._present.link_rx_packets = 1;
	req->peer.link_rx_packets = link_rx_packets;
}
static inline void
ovpn_peer_del_req_set_peer_link_tx_packets(struct ovpn_peer_del_req *req,
					   __u64 link_tx_packets)
{
	req->_present.peer = 1;
	req->peer._present.link_tx_packets = 1;
	req->peer.link_tx_packets = link_tx_packets;
}

/*
 * Delete existing remote peer
 */
int ovpn_peer_del(struct ynl_sock *ys, struct ovpn_peer_del_req *req);

/* ============== OVPN_CMD_KEY_NEW ============== */
/* OVPN_CMD_KEY_NEW - do */
struct ovpn_key_new_req {
	struct {
		__u32 ifindex:1;
		__u32 keyconf:1;
	} _present;

	__u32 ifindex;
	struct ovpn_keyconf keyconf;
};

static inline struct ovpn_key_new_req *ovpn_key_new_req_alloc(void)
{
	return calloc(1, sizeof(struct ovpn_key_new_req));
}
void ovpn_key_new_req_free(struct ovpn_key_new_req *req);

static inline void
ovpn_key_new_req_set_ifindex(struct ovpn_key_new_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
ovpn_key_new_req_set_keyconf_peer_id(struct ovpn_key_new_req *req,
				     __u32 peer_id)
{
	req->_present.keyconf = 1;
	req->keyconf._present.peer_id = 1;
	req->keyconf.peer_id = peer_id;
}
static inline void
ovpn_key_new_req_set_keyconf_slot(struct ovpn_key_new_req *req,
				  enum ovpn_key_slot slot)
{
	req->_present.keyconf = 1;
	req->keyconf._present.slot = 1;
	req->keyconf.slot = slot;
}
static inline void
ovpn_key_new_req_set_keyconf_key_id(struct ovpn_key_new_req *req, __u32 key_id)
{
	req->_present.keyconf = 1;
	req->keyconf._present.key_id = 1;
	req->keyconf.key_id = key_id;
}
static inline void
ovpn_key_new_req_set_keyconf_cipher_alg(struct ovpn_key_new_req *req,
					enum ovpn_cipher_alg cipher_alg)
{
	req->_present.keyconf = 1;
	req->keyconf._present.cipher_alg = 1;
	req->keyconf.cipher_alg = cipher_alg;
}
static inline void
ovpn_key_new_req_set_keyconf_encrypt_dir_cipher_key(struct ovpn_key_new_req *req,
						    const void *cipher_key,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.encrypt_dir = 1;
	free(req->keyconf.encrypt_dir.cipher_key);
	req->keyconf.encrypt_dir._present.cipher_key_len = len;
	req->keyconf.encrypt_dir.cipher_key = malloc(req->keyconf.encrypt_dir._present.cipher_key_len);
	memcpy(req->keyconf.encrypt_dir.cipher_key, cipher_key, req->keyconf.encrypt_dir._present.cipher_key_len);
}
static inline void
ovpn_key_new_req_set_keyconf_encrypt_dir_nonce_tail(struct ovpn_key_new_req *req,
						    const void *nonce_tail,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.encrypt_dir = 1;
	free(req->keyconf.encrypt_dir.nonce_tail);
	req->keyconf.encrypt_dir._present.nonce_tail_len = len;
	req->keyconf.encrypt_dir.nonce_tail = malloc(req->keyconf.encrypt_dir._present.nonce_tail_len);
	memcpy(req->keyconf.encrypt_dir.nonce_tail, nonce_tail, req->keyconf.encrypt_dir._present.nonce_tail_len);
}
static inline void
ovpn_key_new_req_set_keyconf_decrypt_dir_cipher_key(struct ovpn_key_new_req *req,
						    const void *cipher_key,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.decrypt_dir = 1;
	free(req->keyconf.decrypt_dir.cipher_key);
	req->keyconf.decrypt_dir._present.cipher_key_len = len;
	req->keyconf.decrypt_dir.cipher_key = malloc(req->keyconf.decrypt_dir._present.cipher_key_len);
	memcpy(req->keyconf.decrypt_dir.cipher_key, cipher_key, req->keyconf.decrypt_dir._present.cipher_key_len);
}
static inline void
ovpn_key_new_req_set_keyconf_decrypt_dir_nonce_tail(struct ovpn_key_new_req *req,
						    const void *nonce_tail,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.decrypt_dir = 1;
	free(req->keyconf.decrypt_dir.nonce_tail);
	req->keyconf.decrypt_dir._present.nonce_tail_len = len;
	req->keyconf.decrypt_dir.nonce_tail = malloc(req->keyconf.decrypt_dir._present.nonce_tail_len);
	memcpy(req->keyconf.decrypt_dir.nonce_tail, nonce_tail, req->keyconf.decrypt_dir._present.nonce_tail_len);
}

/*
 * Add a cipher key for a specific peer
 */
int ovpn_key_new(struct ynl_sock *ys, struct ovpn_key_new_req *req);

/* ============== OVPN_CMD_KEY_GET ============== */
/* OVPN_CMD_KEY_GET - do */
struct ovpn_key_get_req {
	struct {
		__u32 ifindex:1;
		__u32 keyconf:1;
	} _present;

	__u32 ifindex;
	struct ovpn_keyconf keyconf;
};

static inline struct ovpn_key_get_req *ovpn_key_get_req_alloc(void)
{
	return calloc(1, sizeof(struct ovpn_key_get_req));
}
void ovpn_key_get_req_free(struct ovpn_key_get_req *req);

static inline void
ovpn_key_get_req_set_ifindex(struct ovpn_key_get_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
ovpn_key_get_req_set_keyconf_peer_id(struct ovpn_key_get_req *req,
				     __u32 peer_id)
{
	req->_present.keyconf = 1;
	req->keyconf._present.peer_id = 1;
	req->keyconf.peer_id = peer_id;
}
static inline void
ovpn_key_get_req_set_keyconf_slot(struct ovpn_key_get_req *req,
				  enum ovpn_key_slot slot)
{
	req->_present.keyconf = 1;
	req->keyconf._present.slot = 1;
	req->keyconf.slot = slot;
}
static inline void
ovpn_key_get_req_set_keyconf_key_id(struct ovpn_key_get_req *req, __u32 key_id)
{
	req->_present.keyconf = 1;
	req->keyconf._present.key_id = 1;
	req->keyconf.key_id = key_id;
}
static inline void
ovpn_key_get_req_set_keyconf_cipher_alg(struct ovpn_key_get_req *req,
					enum ovpn_cipher_alg cipher_alg)
{
	req->_present.keyconf = 1;
	req->keyconf._present.cipher_alg = 1;
	req->keyconf.cipher_alg = cipher_alg;
}
static inline void
ovpn_key_get_req_set_keyconf_encrypt_dir_cipher_key(struct ovpn_key_get_req *req,
						    const void *cipher_key,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.encrypt_dir = 1;
	free(req->keyconf.encrypt_dir.cipher_key);
	req->keyconf.encrypt_dir._present.cipher_key_len = len;
	req->keyconf.encrypt_dir.cipher_key = malloc(req->keyconf.encrypt_dir._present.cipher_key_len);
	memcpy(req->keyconf.encrypt_dir.cipher_key, cipher_key, req->keyconf.encrypt_dir._present.cipher_key_len);
}
static inline void
ovpn_key_get_req_set_keyconf_encrypt_dir_nonce_tail(struct ovpn_key_get_req *req,
						    const void *nonce_tail,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.encrypt_dir = 1;
	free(req->keyconf.encrypt_dir.nonce_tail);
	req->keyconf.encrypt_dir._present.nonce_tail_len = len;
	req->keyconf.encrypt_dir.nonce_tail = malloc(req->keyconf.encrypt_dir._present.nonce_tail_len);
	memcpy(req->keyconf.encrypt_dir.nonce_tail, nonce_tail, req->keyconf.encrypt_dir._present.nonce_tail_len);
}
static inline void
ovpn_key_get_req_set_keyconf_decrypt_dir_cipher_key(struct ovpn_key_get_req *req,
						    const void *cipher_key,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.decrypt_dir = 1;
	free(req->keyconf.decrypt_dir.cipher_key);
	req->keyconf.decrypt_dir._present.cipher_key_len = len;
	req->keyconf.decrypt_dir.cipher_key = malloc(req->keyconf.decrypt_dir._present.cipher_key_len);
	memcpy(req->keyconf.decrypt_dir.cipher_key, cipher_key, req->keyconf.decrypt_dir._present.cipher_key_len);
}
static inline void
ovpn_key_get_req_set_keyconf_decrypt_dir_nonce_tail(struct ovpn_key_get_req *req,
						    const void *nonce_tail,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.decrypt_dir = 1;
	free(req->keyconf.decrypt_dir.nonce_tail);
	req->keyconf.decrypt_dir._present.nonce_tail_len = len;
	req->keyconf.decrypt_dir.nonce_tail = malloc(req->keyconf.decrypt_dir._present.nonce_tail_len);
	memcpy(req->keyconf.decrypt_dir.nonce_tail, nonce_tail, req->keyconf.decrypt_dir._present.nonce_tail_len);
}

struct ovpn_key_get_rsp {
	struct {
		__u32 keyconf:1;
	} _present;

	struct ovpn_keyconf keyconf;
};

void ovpn_key_get_rsp_free(struct ovpn_key_get_rsp *rsp);

/*
 * Retrieve non-sensitive data about peer key and cipher
 */
struct ovpn_key_get_rsp *
ovpn_key_get(struct ynl_sock *ys, struct ovpn_key_get_req *req);

/* OVPN_CMD_KEY_GET - notify */
struct ovpn_key_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct ovpn_key_get_ntf *ntf);
	struct ovpn_key_get_rsp obj __attribute__((aligned(8)));
};

void ovpn_key_get_ntf_free(struct ovpn_key_get_ntf *rsp);

/* ============== OVPN_CMD_KEY_SWAP ============== */
/* OVPN_CMD_KEY_SWAP - do */
struct ovpn_key_swap_req {
	struct {
		__u32 ifindex:1;
		__u32 keyconf:1;
	} _present;

	__u32 ifindex;
	struct ovpn_keyconf keyconf;
};

static inline struct ovpn_key_swap_req *ovpn_key_swap_req_alloc(void)
{
	return calloc(1, sizeof(struct ovpn_key_swap_req));
}
void ovpn_key_swap_req_free(struct ovpn_key_swap_req *req);

static inline void
ovpn_key_swap_req_set_ifindex(struct ovpn_key_swap_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
ovpn_key_swap_req_set_keyconf_peer_id(struct ovpn_key_swap_req *req,
				      __u32 peer_id)
{
	req->_present.keyconf = 1;
	req->keyconf._present.peer_id = 1;
	req->keyconf.peer_id = peer_id;
}
static inline void
ovpn_key_swap_req_set_keyconf_slot(struct ovpn_key_swap_req *req,
				   enum ovpn_key_slot slot)
{
	req->_present.keyconf = 1;
	req->keyconf._present.slot = 1;
	req->keyconf.slot = slot;
}
static inline void
ovpn_key_swap_req_set_keyconf_key_id(struct ovpn_key_swap_req *req,
				     __u32 key_id)
{
	req->_present.keyconf = 1;
	req->keyconf._present.key_id = 1;
	req->keyconf.key_id = key_id;
}
static inline void
ovpn_key_swap_req_set_keyconf_cipher_alg(struct ovpn_key_swap_req *req,
					 enum ovpn_cipher_alg cipher_alg)
{
	req->_present.keyconf = 1;
	req->keyconf._present.cipher_alg = 1;
	req->keyconf.cipher_alg = cipher_alg;
}
static inline void
ovpn_key_swap_req_set_keyconf_encrypt_dir_cipher_key(struct ovpn_key_swap_req *req,
						     const void *cipher_key,
						     size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.encrypt_dir = 1;
	free(req->keyconf.encrypt_dir.cipher_key);
	req->keyconf.encrypt_dir._present.cipher_key_len = len;
	req->keyconf.encrypt_dir.cipher_key = malloc(req->keyconf.encrypt_dir._present.cipher_key_len);
	memcpy(req->keyconf.encrypt_dir.cipher_key, cipher_key, req->keyconf.encrypt_dir._present.cipher_key_len);
}
static inline void
ovpn_key_swap_req_set_keyconf_encrypt_dir_nonce_tail(struct ovpn_key_swap_req *req,
						     const void *nonce_tail,
						     size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.encrypt_dir = 1;
	free(req->keyconf.encrypt_dir.nonce_tail);
	req->keyconf.encrypt_dir._present.nonce_tail_len = len;
	req->keyconf.encrypt_dir.nonce_tail = malloc(req->keyconf.encrypt_dir._present.nonce_tail_len);
	memcpy(req->keyconf.encrypt_dir.nonce_tail, nonce_tail, req->keyconf.encrypt_dir._present.nonce_tail_len);
}
static inline void
ovpn_key_swap_req_set_keyconf_decrypt_dir_cipher_key(struct ovpn_key_swap_req *req,
						     const void *cipher_key,
						     size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.decrypt_dir = 1;
	free(req->keyconf.decrypt_dir.cipher_key);
	req->keyconf.decrypt_dir._present.cipher_key_len = len;
	req->keyconf.decrypt_dir.cipher_key = malloc(req->keyconf.decrypt_dir._present.cipher_key_len);
	memcpy(req->keyconf.decrypt_dir.cipher_key, cipher_key, req->keyconf.decrypt_dir._present.cipher_key_len);
}
static inline void
ovpn_key_swap_req_set_keyconf_decrypt_dir_nonce_tail(struct ovpn_key_swap_req *req,
						     const void *nonce_tail,
						     size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.decrypt_dir = 1;
	free(req->keyconf.decrypt_dir.nonce_tail);
	req->keyconf.decrypt_dir._present.nonce_tail_len = len;
	req->keyconf.decrypt_dir.nonce_tail = malloc(req->keyconf.decrypt_dir._present.nonce_tail_len);
	memcpy(req->keyconf.decrypt_dir.nonce_tail, nonce_tail, req->keyconf.decrypt_dir._present.nonce_tail_len);
}

/*
 * Swap primary and secondary session keys for a specific peer
 */
int ovpn_key_swap(struct ynl_sock *ys, struct ovpn_key_swap_req *req);

/* ============== OVPN_CMD_KEY_DEL ============== */
/* OVPN_CMD_KEY_DEL - do */
struct ovpn_key_del_req {
	struct {
		__u32 ifindex:1;
		__u32 keyconf:1;
	} _present;

	__u32 ifindex;
	struct ovpn_keyconf keyconf;
};

static inline struct ovpn_key_del_req *ovpn_key_del_req_alloc(void)
{
	return calloc(1, sizeof(struct ovpn_key_del_req));
}
void ovpn_key_del_req_free(struct ovpn_key_del_req *req);

static inline void
ovpn_key_del_req_set_ifindex(struct ovpn_key_del_req *req, __u32 ifindex)
{
	req->_present.ifindex = 1;
	req->ifindex = ifindex;
}
static inline void
ovpn_key_del_req_set_keyconf_peer_id(struct ovpn_key_del_req *req,
				     __u32 peer_id)
{
	req->_present.keyconf = 1;
	req->keyconf._present.peer_id = 1;
	req->keyconf.peer_id = peer_id;
}
static inline void
ovpn_key_del_req_set_keyconf_slot(struct ovpn_key_del_req *req,
				  enum ovpn_key_slot slot)
{
	req->_present.keyconf = 1;
	req->keyconf._present.slot = 1;
	req->keyconf.slot = slot;
}
static inline void
ovpn_key_del_req_set_keyconf_key_id(struct ovpn_key_del_req *req, __u32 key_id)
{
	req->_present.keyconf = 1;
	req->keyconf._present.key_id = 1;
	req->keyconf.key_id = key_id;
}
static inline void
ovpn_key_del_req_set_keyconf_cipher_alg(struct ovpn_key_del_req *req,
					enum ovpn_cipher_alg cipher_alg)
{
	req->_present.keyconf = 1;
	req->keyconf._present.cipher_alg = 1;
	req->keyconf.cipher_alg = cipher_alg;
}
static inline void
ovpn_key_del_req_set_keyconf_encrypt_dir_cipher_key(struct ovpn_key_del_req *req,
						    const void *cipher_key,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.encrypt_dir = 1;
	free(req->keyconf.encrypt_dir.cipher_key);
	req->keyconf.encrypt_dir._present.cipher_key_len = len;
	req->keyconf.encrypt_dir.cipher_key = malloc(req->keyconf.encrypt_dir._present.cipher_key_len);
	memcpy(req->keyconf.encrypt_dir.cipher_key, cipher_key, req->keyconf.encrypt_dir._present.cipher_key_len);
}
static inline void
ovpn_key_del_req_set_keyconf_encrypt_dir_nonce_tail(struct ovpn_key_del_req *req,
						    const void *nonce_tail,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.encrypt_dir = 1;
	free(req->keyconf.encrypt_dir.nonce_tail);
	req->keyconf.encrypt_dir._present.nonce_tail_len = len;
	req->keyconf.encrypt_dir.nonce_tail = malloc(req->keyconf.encrypt_dir._present.nonce_tail_len);
	memcpy(req->keyconf.encrypt_dir.nonce_tail, nonce_tail, req->keyconf.encrypt_dir._present.nonce_tail_len);
}
static inline void
ovpn_key_del_req_set_keyconf_decrypt_dir_cipher_key(struct ovpn_key_del_req *req,
						    const void *cipher_key,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.decrypt_dir = 1;
	free(req->keyconf.decrypt_dir.cipher_key);
	req->keyconf.decrypt_dir._present.cipher_key_len = len;
	req->keyconf.decrypt_dir.cipher_key = malloc(req->keyconf.decrypt_dir._present.cipher_key_len);
	memcpy(req->keyconf.decrypt_dir.cipher_key, cipher_key, req->keyconf.decrypt_dir._present.cipher_key_len);
}
static inline void
ovpn_key_del_req_set_keyconf_decrypt_dir_nonce_tail(struct ovpn_key_del_req *req,
						    const void *nonce_tail,
						    size_t len)
{
	req->_present.keyconf = 1;
	req->keyconf._present.decrypt_dir = 1;
	free(req->keyconf.decrypt_dir.nonce_tail);
	req->keyconf.decrypt_dir._present.nonce_tail_len = len;
	req->keyconf.decrypt_dir.nonce_tail = malloc(req->keyconf.decrypt_dir._present.nonce_tail_len);
	memcpy(req->keyconf.decrypt_dir.nonce_tail, nonce_tail, req->keyconf.decrypt_dir._present.nonce_tail_len);
}

/*
 * Delete cipher key for a specific peer
 */
int ovpn_key_del(struct ynl_sock *ys, struct ovpn_key_del_req *req);

#endif /* _LINUX_OVPN_GEN_H */
