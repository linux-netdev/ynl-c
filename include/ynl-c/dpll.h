/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/dpll.yaml */
/* YNL-GEN user header */

#ifndef _LINUX_DPLL_GEN_H
#define _LINUX_DPLL_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/dpll.h>

struct ynl_sock;

extern const struct ynl_family ynl_dpll_family;

/* Enums */
const char *dpll_op_str(int op);
const char *dpll_mode_str(enum dpll_mode value);
const char *dpll_lock_status_str(enum dpll_lock_status value);
const char *dpll_lock_status_error_str(enum dpll_lock_status_error value);
const char *dpll_clock_quality_level_str(enum dpll_clock_quality_level value);
const char *dpll_type_str(enum dpll_type value);
const char *dpll_pin_type_str(enum dpll_pin_type value);
const char *dpll_pin_direction_str(enum dpll_pin_direction value);
const char *dpll_pin_state_str(enum dpll_pin_state value);
const char *dpll_pin_capabilities_str(enum dpll_pin_capabilities value);
const char *dpll_feature_state_str(enum dpll_feature_state value);

/* Common nested types */
struct dpll_frequency_range {
	struct {
		__u32 frequency_min:1;
		__u32 frequency_max:1;
	} _present;

	__u64 frequency_min;
	__u64 frequency_max;
};

struct dpll_pin_parent_device {
	struct {
		__u32 parent_id:1;
		__u32 direction:1;
		__u32 prio:1;
		__u32 state:1;
		__u32 phase_offset:1;
	} _present;

	__u32 parent_id;
	enum dpll_pin_direction direction;
	__u32 prio;
	enum dpll_pin_state state;
	__s64 phase_offset;
};

static inline struct dpll_pin_parent_device *
dpll_pin_parent_device_alloc(unsigned int n)
{
	return calloc(n, sizeof(struct dpll_pin_parent_device));
}

void dpll_pin_parent_device_free(struct dpll_pin_parent_device *obj);

static inline void
dpll_pin_parent_device_set_parent_id(struct dpll_pin_parent_device *obj,
				     __u32 parent_id)
{
	obj->_present.parent_id = 1;
	obj->parent_id = parent_id;
}
static inline void
dpll_pin_parent_device_set_direction(struct dpll_pin_parent_device *obj,
				     enum dpll_pin_direction direction)
{
	obj->_present.direction = 1;
	obj->direction = direction;
}
static inline void
dpll_pin_parent_device_set_prio(struct dpll_pin_parent_device *obj, __u32 prio)
{
	obj->_present.prio = 1;
	obj->prio = prio;
}
static inline void
dpll_pin_parent_device_set_state(struct dpll_pin_parent_device *obj,
				 enum dpll_pin_state state)
{
	obj->_present.state = 1;
	obj->state = state;
}
static inline void
dpll_pin_parent_device_set_phase_offset(struct dpll_pin_parent_device *obj,
					__s64 phase_offset)
{
	obj->_present.phase_offset = 1;
	obj->phase_offset = phase_offset;
}

struct dpll_pin_parent_pin {
	struct {
		__u32 parent_id:1;
		__u32 state:1;
	} _present;

	__u32 parent_id;
	enum dpll_pin_state state;
};

static inline struct dpll_pin_parent_pin *
dpll_pin_parent_pin_alloc(unsigned int n)
{
	return calloc(n, sizeof(struct dpll_pin_parent_pin));
}

void dpll_pin_parent_pin_free(struct dpll_pin_parent_pin *obj);

static inline void
dpll_pin_parent_pin_set_parent_id(struct dpll_pin_parent_pin *obj,
				  __u32 parent_id)
{
	obj->_present.parent_id = 1;
	obj->parent_id = parent_id;
}
static inline void
dpll_pin_parent_pin_set_state(struct dpll_pin_parent_pin *obj,
			      enum dpll_pin_state state)
{
	obj->_present.state = 1;
	obj->state = state;
}

struct dpll_reference_sync {
	struct {
		__u32 id:1;
		__u32 state:1;
	} _present;

	__u32 id;
	enum dpll_pin_state state;
};

static inline struct dpll_reference_sync *
dpll_reference_sync_alloc(unsigned int n)
{
	return calloc(n, sizeof(struct dpll_reference_sync));
}

void dpll_reference_sync_free(struct dpll_reference_sync *obj);

static inline void
dpll_reference_sync_set_id(struct dpll_reference_sync *obj, __u32 id)
{
	obj->_present.id = 1;
	obj->id = id;
}
static inline void
dpll_reference_sync_set_state(struct dpll_reference_sync *obj,
			      enum dpll_pin_state state)
{
	obj->_present.state = 1;
	obj->state = state;
}

/* ============== DPLL_CMD_DEVICE_ID_GET ============== */
/* DPLL_CMD_DEVICE_ID_GET - do */
struct dpll_device_id_get_req {
	struct {
		__u32 clock_id:1;
		__u32 type:1;
	} _present;
	struct {
		__u32 module_name;
	} _len;

	char *module_name;
	__u64 clock_id;
	enum dpll_type type;
};

static inline struct dpll_device_id_get_req *dpll_device_id_get_req_alloc(void)
{
	return calloc(1, sizeof(struct dpll_device_id_get_req));
}
void dpll_device_id_get_req_free(struct dpll_device_id_get_req *req);

static inline void
dpll_device_id_get_req_set_module_name(struct dpll_device_id_get_req *req,
				       const char *module_name)
{
	free(req->module_name);
	req->_len.module_name = strlen(module_name);
	req->module_name = malloc(req->_len.module_name + 1);
	memcpy(req->module_name, module_name, req->_len.module_name);
	req->module_name[req->_len.module_name] = 0;
}
static inline void
dpll_device_id_get_req_set_clock_id(struct dpll_device_id_get_req *req,
				    __u64 clock_id)
{
	req->_present.clock_id = 1;
	req->clock_id = clock_id;
}
static inline void
dpll_device_id_get_req_set_type(struct dpll_device_id_get_req *req,
				enum dpll_type type)
{
	req->_present.type = 1;
	req->type = type;
}

struct dpll_device_id_get_rsp {
	struct {
		__u32 id:1;
	} _present;

	__u32 id;
};

void dpll_device_id_get_rsp_free(struct dpll_device_id_get_rsp *rsp);

/*
 * Get id of dpll device that matches given attributes

 */
struct dpll_device_id_get_rsp *
dpll_device_id_get(struct ynl_sock *ys, struct dpll_device_id_get_req *req);

/* ============== DPLL_CMD_DEVICE_GET ============== */
/* DPLL_CMD_DEVICE_GET - do */
struct dpll_device_get_req {
	struct {
		__u32 id:1;
	} _present;

	__u32 id;
};

static inline struct dpll_device_get_req *dpll_device_get_req_alloc(void)
{
	return calloc(1, sizeof(struct dpll_device_get_req));
}
void dpll_device_get_req_free(struct dpll_device_get_req *req);

static inline void
dpll_device_get_req_set_id(struct dpll_device_get_req *req, __u32 id)
{
	req->_present.id = 1;
	req->id = id;
}

struct dpll_device_get_rsp {
	struct {
		__u32 id:1;
		__u32 mode:1;
		__u32 lock_status:1;
		__u32 lock_status_error:1;
		__u32 temp:1;
		__u32 clock_id:1;
		__u32 type:1;
		__u32 phase_offset_monitor:1;
		__u32 phase_offset_avg_factor:1;
	} _present;
	struct {
		__u32 module_name;
	} _len;
	struct {
		__u32 mode_supported;
	} _count;

	__u32 id;
	char *module_name;
	enum dpll_mode mode;
	__u32 *mode_supported;
	enum dpll_lock_status lock_status;
	enum dpll_lock_status_error lock_status_error;
	__s32 temp;
	__u64 clock_id;
	enum dpll_type type;
	enum dpll_feature_state phase_offset_monitor;
	__u32 phase_offset_avg_factor;
};

void dpll_device_get_rsp_free(struct dpll_device_get_rsp *rsp);

/*
 * Get list of DPLL devices (dump) or attributes of a single dpll device

 */
struct dpll_device_get_rsp *
dpll_device_get(struct ynl_sock *ys, struct dpll_device_get_req *req);

/* DPLL_CMD_DEVICE_GET - dump */
struct dpll_device_get_list {
	struct dpll_device_get_list *next;
	struct dpll_device_get_rsp obj __attribute__((aligned(8)));
};

void dpll_device_get_list_free(struct dpll_device_get_list *rsp);

struct dpll_device_get_list *dpll_device_get_dump(struct ynl_sock *ys);

/* DPLL_CMD_DEVICE_GET - notify */
struct dpll_device_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct dpll_device_get_ntf *ntf);
	struct dpll_device_get_rsp obj __attribute__((aligned(8)));
};

void dpll_device_get_ntf_free(struct dpll_device_get_ntf *rsp);

/* ============== DPLL_CMD_DEVICE_SET ============== */
/* DPLL_CMD_DEVICE_SET - do */
struct dpll_device_set_req {
	struct {
		__u32 id:1;
		__u32 phase_offset_monitor:1;
		__u32 phase_offset_avg_factor:1;
	} _present;

	__u32 id;
	enum dpll_feature_state phase_offset_monitor;
	__u32 phase_offset_avg_factor;
};

static inline struct dpll_device_set_req *dpll_device_set_req_alloc(void)
{
	return calloc(1, sizeof(struct dpll_device_set_req));
}
void dpll_device_set_req_free(struct dpll_device_set_req *req);

static inline void
dpll_device_set_req_set_id(struct dpll_device_set_req *req, __u32 id)
{
	req->_present.id = 1;
	req->id = id;
}
static inline void
dpll_device_set_req_set_phase_offset_monitor(struct dpll_device_set_req *req,
					     enum dpll_feature_state phase_offset_monitor)
{
	req->_present.phase_offset_monitor = 1;
	req->phase_offset_monitor = phase_offset_monitor;
}
static inline void
dpll_device_set_req_set_phase_offset_avg_factor(struct dpll_device_set_req *req,
						__u32 phase_offset_avg_factor)
{
	req->_present.phase_offset_avg_factor = 1;
	req->phase_offset_avg_factor = phase_offset_avg_factor;
}

/*
 * Set attributes for a DPLL device
 */
int dpll_device_set(struct ynl_sock *ys, struct dpll_device_set_req *req);

/* ============== DPLL_CMD_PIN_ID_GET ============== */
/* DPLL_CMD_PIN_ID_GET - do */
struct dpll_pin_id_get_req {
	struct {
		__u32 clock_id:1;
		__u32 type:1;
	} _present;
	struct {
		__u32 module_name;
		__u32 board_label;
		__u32 panel_label;
		__u32 package_label;
	} _len;

	char *module_name;
	__u64 clock_id;
	char *board_label;
	char *panel_label;
	char *package_label;
	enum dpll_pin_type type;
};

static inline struct dpll_pin_id_get_req *dpll_pin_id_get_req_alloc(void)
{
	return calloc(1, sizeof(struct dpll_pin_id_get_req));
}
void dpll_pin_id_get_req_free(struct dpll_pin_id_get_req *req);

static inline void
dpll_pin_id_get_req_set_module_name(struct dpll_pin_id_get_req *req,
				    const char *module_name)
{
	free(req->module_name);
	req->_len.module_name = strlen(module_name);
	req->module_name = malloc(req->_len.module_name + 1);
	memcpy(req->module_name, module_name, req->_len.module_name);
	req->module_name[req->_len.module_name] = 0;
}
static inline void
dpll_pin_id_get_req_set_clock_id(struct dpll_pin_id_get_req *req,
				 __u64 clock_id)
{
	req->_present.clock_id = 1;
	req->clock_id = clock_id;
}
static inline void
dpll_pin_id_get_req_set_board_label(struct dpll_pin_id_get_req *req,
				    const char *board_label)
{
	free(req->board_label);
	req->_len.board_label = strlen(board_label);
	req->board_label = malloc(req->_len.board_label + 1);
	memcpy(req->board_label, board_label, req->_len.board_label);
	req->board_label[req->_len.board_label] = 0;
}
static inline void
dpll_pin_id_get_req_set_panel_label(struct dpll_pin_id_get_req *req,
				    const char *panel_label)
{
	free(req->panel_label);
	req->_len.panel_label = strlen(panel_label);
	req->panel_label = malloc(req->_len.panel_label + 1);
	memcpy(req->panel_label, panel_label, req->_len.panel_label);
	req->panel_label[req->_len.panel_label] = 0;
}
static inline void
dpll_pin_id_get_req_set_package_label(struct dpll_pin_id_get_req *req,
				      const char *package_label)
{
	free(req->package_label);
	req->_len.package_label = strlen(package_label);
	req->package_label = malloc(req->_len.package_label + 1);
	memcpy(req->package_label, package_label, req->_len.package_label);
	req->package_label[req->_len.package_label] = 0;
}
static inline void
dpll_pin_id_get_req_set_type(struct dpll_pin_id_get_req *req,
			     enum dpll_pin_type type)
{
	req->_present.type = 1;
	req->type = type;
}

struct dpll_pin_id_get_rsp {
	struct {
		__u32 id:1;
	} _present;

	__u32 id;
};

void dpll_pin_id_get_rsp_free(struct dpll_pin_id_get_rsp *rsp);

/*
 * Get id of a pin that matches given attributes

 */
struct dpll_pin_id_get_rsp *
dpll_pin_id_get(struct ynl_sock *ys, struct dpll_pin_id_get_req *req);

/* ============== DPLL_CMD_PIN_GET ============== */
/* DPLL_CMD_PIN_GET - do */
struct dpll_pin_get_req {
	struct {
		__u32 id:1;
	} _present;

	__u32 id;
};

static inline struct dpll_pin_get_req *dpll_pin_get_req_alloc(void)
{
	return calloc(1, sizeof(struct dpll_pin_get_req));
}
void dpll_pin_get_req_free(struct dpll_pin_get_req *req);

static inline void
dpll_pin_get_req_set_id(struct dpll_pin_get_req *req, __u32 id)
{
	req->_present.id = 1;
	req->id = id;
}

struct dpll_pin_get_rsp {
	struct {
		__u32 id:1;
		__u32 clock_id:1;
		__u32 type:1;
		__u32 frequency:1;
		__u32 capabilities:1;
		__u32 phase_adjust_gran:1;
		__u32 phase_adjust_min:1;
		__u32 phase_adjust_max:1;
		__u32 phase_adjust:1;
		__u32 fractional_frequency_offset:1;
		__u32 esync_frequency:1;
		__u32 esync_pulse:1;
	} _present;
	struct {
		__u32 module_name;
		__u32 board_label;
		__u32 panel_label;
		__u32 package_label;
	} _len;
	struct {
		__u32 frequency_supported;
		__u32 parent_device;
		__u32 parent_pin;
		__u32 esync_frequency_supported;
		__u32 reference_sync;
	} _count;

	__u32 id;
	char *module_name;
	__u64 clock_id;
	char *board_label;
	char *panel_label;
	char *package_label;
	enum dpll_pin_type type;
	__u64 frequency;
	struct dpll_frequency_range *frequency_supported;
	__u32 capabilities;
	struct dpll_pin_parent_device *parent_device;
	struct dpll_pin_parent_pin *parent_pin;
	__u32 phase_adjust_gran;
	__s32 phase_adjust_min;
	__s32 phase_adjust_max;
	__s32 phase_adjust;
	__s64 fractional_frequency_offset;
	__u64 esync_frequency;
	struct dpll_frequency_range *esync_frequency_supported;
	__u32 esync_pulse;
	struct dpll_reference_sync *reference_sync;
};

void dpll_pin_get_rsp_free(struct dpll_pin_get_rsp *rsp);

/*
 * Get list of pins and its attributes.

- dump request without any attributes given - list all the pins in the
  system
- dump request with target dpll - list all the pins registered with
  a given dpll device
- do request with target dpll and target pin - single pin attributes

 */
struct dpll_pin_get_rsp *
dpll_pin_get(struct ynl_sock *ys, struct dpll_pin_get_req *req);

/* DPLL_CMD_PIN_GET - dump */
struct dpll_pin_get_req_dump {
	struct {
		__u32 id:1;
	} _present;

	__u32 id;
};

static inline struct dpll_pin_get_req_dump *dpll_pin_get_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct dpll_pin_get_req_dump));
}
void dpll_pin_get_req_dump_free(struct dpll_pin_get_req_dump *req);

static inline void
dpll_pin_get_req_dump_set_id(struct dpll_pin_get_req_dump *req, __u32 id)
{
	req->_present.id = 1;
	req->id = id;
}

struct dpll_pin_get_list {
	struct dpll_pin_get_list *next;
	struct dpll_pin_get_rsp obj __attribute__((aligned(8)));
};

void dpll_pin_get_list_free(struct dpll_pin_get_list *rsp);

struct dpll_pin_get_list *
dpll_pin_get_dump(struct ynl_sock *ys, struct dpll_pin_get_req_dump *req);

/* DPLL_CMD_PIN_GET - notify */
struct dpll_pin_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct dpll_pin_get_ntf *ntf);
	struct dpll_pin_get_rsp obj __attribute__((aligned(8)));
};

void dpll_pin_get_ntf_free(struct dpll_pin_get_ntf *rsp);

/* ============== DPLL_CMD_PIN_SET ============== */
/* DPLL_CMD_PIN_SET - do */
struct dpll_pin_set_req {
	struct {
		__u32 id:1;
		__u32 frequency:1;
		__u32 direction:1;
		__u32 prio:1;
		__u32 state:1;
		__u32 phase_adjust:1;
		__u32 esync_frequency:1;
	} _present;
	struct {
		__u32 parent_device;
		__u32 parent_pin;
		__u32 reference_sync;
	} _count;

	__u32 id;
	__u64 frequency;
	enum dpll_pin_direction direction;
	__u32 prio;
	enum dpll_pin_state state;
	struct dpll_pin_parent_device *parent_device;
	struct dpll_pin_parent_pin *parent_pin;
	__s32 phase_adjust;
	__u64 esync_frequency;
	struct dpll_reference_sync *reference_sync;
};

static inline struct dpll_pin_set_req *dpll_pin_set_req_alloc(void)
{
	return calloc(1, sizeof(struct dpll_pin_set_req));
}
void dpll_pin_set_req_free(struct dpll_pin_set_req *req);

static inline void
dpll_pin_set_req_set_id(struct dpll_pin_set_req *req, __u32 id)
{
	req->_present.id = 1;
	req->id = id;
}
static inline void
dpll_pin_set_req_set_frequency(struct dpll_pin_set_req *req, __u64 frequency)
{
	req->_present.frequency = 1;
	req->frequency = frequency;
}
static inline void
dpll_pin_set_req_set_direction(struct dpll_pin_set_req *req,
			       enum dpll_pin_direction direction)
{
	req->_present.direction = 1;
	req->direction = direction;
}
static inline void
dpll_pin_set_req_set_prio(struct dpll_pin_set_req *req, __u32 prio)
{
	req->_present.prio = 1;
	req->prio = prio;
}
static inline void
dpll_pin_set_req_set_state(struct dpll_pin_set_req *req,
			   enum dpll_pin_state state)
{
	req->_present.state = 1;
	req->state = state;
}
static inline void
__dpll_pin_set_req_set_parent_device(struct dpll_pin_set_req *req,
				     struct dpll_pin_parent_device *parent_device,
				     unsigned int n_parent_device)
{
	unsigned int i;

	for (i = 0; i < req->_count.parent_device; i++)
		dpll_pin_parent_device_free(&req->parent_device[i]);
	free(req->parent_device);
	req->parent_device = parent_device;
	req->_count.parent_device = n_parent_device;
}
static inline void
__dpll_pin_set_req_set_parent_pin(struct dpll_pin_set_req *req,
				  struct dpll_pin_parent_pin *parent_pin,
				  unsigned int n_parent_pin)
{
	unsigned int i;

	for (i = 0; i < req->_count.parent_pin; i++)
		dpll_pin_parent_pin_free(&req->parent_pin[i]);
	free(req->parent_pin);
	req->parent_pin = parent_pin;
	req->_count.parent_pin = n_parent_pin;
}
static inline void
dpll_pin_set_req_set_phase_adjust(struct dpll_pin_set_req *req,
				  __s32 phase_adjust)
{
	req->_present.phase_adjust = 1;
	req->phase_adjust = phase_adjust;
}
static inline void
dpll_pin_set_req_set_esync_frequency(struct dpll_pin_set_req *req,
				     __u64 esync_frequency)
{
	req->_present.esync_frequency = 1;
	req->esync_frequency = esync_frequency;
}
static inline void
__dpll_pin_set_req_set_reference_sync(struct dpll_pin_set_req *req,
				      struct dpll_reference_sync *reference_sync,
				      unsigned int n_reference_sync)
{
	unsigned int i;

	for (i = 0; i < req->_count.reference_sync; i++)
		dpll_reference_sync_free(&req->reference_sync[i]);
	free(req->reference_sync);
	req->reference_sync = reference_sync;
	req->_count.reference_sync = n_reference_sync;
}

/*
 * Set attributes of a target pin
 */
int dpll_pin_set(struct ynl_sock *ys, struct dpll_pin_set_req *req);

#endif /* _LINUX_DPLL_GEN_H */
