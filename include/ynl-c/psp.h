/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/psp.yaml */
/* YNL-GEN user header */

#ifndef _LINUX_PSP_GEN_H
#define _LINUX_PSP_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/psp.h>

struct ynl_sock;

extern const struct ynl_family ynl_psp_family;

/* Enums */
const char *psp_op_str(int op);
const char *psp_version_str(enum psp_version value);

/* Common nested types */
struct psp_keys {
	struct {
		__u32 spi:1;
	} _present;
	struct {
		__u32 key;
	} _len;

	void *key;
	__u32 spi;
};

/* ============== PSP_CMD_DEV_GET ============== */
/* PSP_CMD_DEV_GET - do */
struct psp_dev_get_req {
	struct {
		__u32 id:1;
	} _present;

	__u32 id;
};

static inline struct psp_dev_get_req *psp_dev_get_req_alloc(void)
{
	return calloc(1, sizeof(struct psp_dev_get_req));
}
void psp_dev_get_req_free(struct psp_dev_get_req *req);

static inline void
psp_dev_get_req_set_id(struct psp_dev_get_req *req, __u32 id)
{
	req->_present.id = 1;
	req->id = id;
}

struct psp_dev_get_rsp {
	struct {
		__u32 id:1;
		__u32 ifindex:1;
		__u32 psp_versions_cap:1;
		__u32 psp_versions_ena:1;
	} _present;

	__u32 id;
	__u32 ifindex;
	__u32 psp_versions_cap;
	__u32 psp_versions_ena;
};

void psp_dev_get_rsp_free(struct psp_dev_get_rsp *rsp);

/*
 * Get / dump information about PSP capable devices on the system.
 */
struct psp_dev_get_rsp *
psp_dev_get(struct ynl_sock *ys, struct psp_dev_get_req *req);

/* PSP_CMD_DEV_GET - dump */
struct psp_dev_get_list {
	struct psp_dev_get_list *next;
	struct psp_dev_get_rsp obj __attribute__((aligned(8)));
};

void psp_dev_get_list_free(struct psp_dev_get_list *rsp);

struct psp_dev_get_list *psp_dev_get_dump(struct ynl_sock *ys);

/* PSP_CMD_DEV_GET - notify */
struct psp_dev_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct psp_dev_get_ntf *ntf);
	struct psp_dev_get_rsp obj __attribute__((aligned(8)));
};

void psp_dev_get_ntf_free(struct psp_dev_get_ntf *rsp);

/* ============== PSP_CMD_DEV_SET ============== */
/* PSP_CMD_DEV_SET - do */
struct psp_dev_set_req {
	struct {
		__u32 id:1;
		__u32 psp_versions_ena:1;
	} _present;

	__u32 id;
	__u32 psp_versions_ena;
};

static inline struct psp_dev_set_req *psp_dev_set_req_alloc(void)
{
	return calloc(1, sizeof(struct psp_dev_set_req));
}
void psp_dev_set_req_free(struct psp_dev_set_req *req);

static inline void
psp_dev_set_req_set_id(struct psp_dev_set_req *req, __u32 id)
{
	req->_present.id = 1;
	req->id = id;
}
static inline void
psp_dev_set_req_set_psp_versions_ena(struct psp_dev_set_req *req,
				     __u32 psp_versions_ena)
{
	req->_present.psp_versions_ena = 1;
	req->psp_versions_ena = psp_versions_ena;
}

struct psp_dev_set_rsp {
};

void psp_dev_set_rsp_free(struct psp_dev_set_rsp *rsp);

/*
 * Set the configuration of a PSP device.
 */
struct psp_dev_set_rsp *
psp_dev_set(struct ynl_sock *ys, struct psp_dev_set_req *req);

/* ============== PSP_CMD_KEY_ROTATE ============== */
/* PSP_CMD_KEY_ROTATE - do */
struct psp_key_rotate_req {
	struct {
		__u32 id:1;
	} _present;

	__u32 id;
};

static inline struct psp_key_rotate_req *psp_key_rotate_req_alloc(void)
{
	return calloc(1, sizeof(struct psp_key_rotate_req));
}
void psp_key_rotate_req_free(struct psp_key_rotate_req *req);

static inline void
psp_key_rotate_req_set_id(struct psp_key_rotate_req *req, __u32 id)
{
	req->_present.id = 1;
	req->id = id;
}

struct psp_key_rotate_rsp {
	struct {
		__u32 id:1;
	} _present;

	__u32 id;
};

void psp_key_rotate_rsp_free(struct psp_key_rotate_rsp *rsp);

/*
 * Rotate the device key.
 */
struct psp_key_rotate_rsp *
psp_key_rotate(struct ynl_sock *ys, struct psp_key_rotate_req *req);

/* PSP_CMD_KEY_ROTATE - notify */
struct psp_key_rotate_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct psp_key_rotate_ntf *ntf);
	struct psp_key_rotate_rsp obj __attribute__((aligned(8)));
};

void psp_key_rotate_ntf_free(struct psp_key_rotate_ntf *rsp);

/* ============== PSP_CMD_RX_ASSOC ============== */
/* PSP_CMD_RX_ASSOC - do */
struct psp_rx_assoc_req {
	struct {
		__u32 dev_id:1;
		__u32 version:1;
		__u32 sock_fd:1;
	} _present;

	__u32 dev_id;
	enum psp_version version;
	__u32 sock_fd;
};

static inline struct psp_rx_assoc_req *psp_rx_assoc_req_alloc(void)
{
	return calloc(1, sizeof(struct psp_rx_assoc_req));
}
void psp_rx_assoc_req_free(struct psp_rx_assoc_req *req);

static inline void
psp_rx_assoc_req_set_dev_id(struct psp_rx_assoc_req *req, __u32 dev_id)
{
	req->_present.dev_id = 1;
	req->dev_id = dev_id;
}
static inline void
psp_rx_assoc_req_set_version(struct psp_rx_assoc_req *req,
			     enum psp_version version)
{
	req->_present.version = 1;
	req->version = version;
}
static inline void
psp_rx_assoc_req_set_sock_fd(struct psp_rx_assoc_req *req, __u32 sock_fd)
{
	req->_present.sock_fd = 1;
	req->sock_fd = sock_fd;
}

struct psp_rx_assoc_rsp {
	struct {
		__u32 dev_id:1;
		__u32 rx_key:1;
	} _present;

	__u32 dev_id;
	struct psp_keys rx_key;
};

void psp_rx_assoc_rsp_free(struct psp_rx_assoc_rsp *rsp);

/*
 * Allocate a new Rx key + SPI pair, associate it with a socket.
 */
struct psp_rx_assoc_rsp *
psp_rx_assoc(struct ynl_sock *ys, struct psp_rx_assoc_req *req);

/* ============== PSP_CMD_TX_ASSOC ============== */
/* PSP_CMD_TX_ASSOC - do */
struct psp_tx_assoc_req {
	struct {
		__u32 dev_id:1;
		__u32 version:1;
		__u32 tx_key:1;
		__u32 sock_fd:1;
	} _present;

	__u32 dev_id;
	enum psp_version version;
	struct psp_keys tx_key;
	__u32 sock_fd;
};

static inline struct psp_tx_assoc_req *psp_tx_assoc_req_alloc(void)
{
	return calloc(1, sizeof(struct psp_tx_assoc_req));
}
void psp_tx_assoc_req_free(struct psp_tx_assoc_req *req);

static inline void
psp_tx_assoc_req_set_dev_id(struct psp_tx_assoc_req *req, __u32 dev_id)
{
	req->_present.dev_id = 1;
	req->dev_id = dev_id;
}
static inline void
psp_tx_assoc_req_set_version(struct psp_tx_assoc_req *req,
			     enum psp_version version)
{
	req->_present.version = 1;
	req->version = version;
}
static inline void
psp_tx_assoc_req_set_tx_key_key(struct psp_tx_assoc_req *req, const void *key,
				size_t len)
{
	req->_present.tx_key = 1;
	free(req->tx_key.key);
	req->tx_key._len.key = len;
	req->tx_key.key = malloc(req->tx_key._len.key);
	memcpy(req->tx_key.key, key, req->tx_key._len.key);
}
static inline void
psp_tx_assoc_req_set_tx_key_spi(struct psp_tx_assoc_req *req, __u32 spi)
{
	req->_present.tx_key = 1;
	req->tx_key._present.spi = 1;
	req->tx_key.spi = spi;
}
static inline void
psp_tx_assoc_req_set_sock_fd(struct psp_tx_assoc_req *req, __u32 sock_fd)
{
	req->_present.sock_fd = 1;
	req->sock_fd = sock_fd;
}

struct psp_tx_assoc_rsp {
};

void psp_tx_assoc_rsp_free(struct psp_tx_assoc_rsp *rsp);

/*
 * Add a PSP Tx association.
 */
struct psp_tx_assoc_rsp *
psp_tx_assoc(struct ynl_sock *ys, struct psp_tx_assoc_req *req);

#endif /* _LINUX_PSP_GEN_H */
