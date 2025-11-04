/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/binder.yaml */
/* YNL-GEN user header */

#ifndef _LINUX_BINDER_GEN_H
#define _LINUX_BINDER_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/android/binder_netlink.h>

struct ynl_sock;

extern const struct ynl_family ynl_binder_family;

/* Enums */
const char *binder_op_str(int op);

/* Common nested types */
/* BINDER_CMD_REPORT - event */
struct binder_report_rsp {
	struct {
		__u32 error:1;
		__u32 from_pid:1;
		__u32 from_tid:1;
		__u32 to_pid:1;
		__u32 to_tid:1;
		__u32 is_reply:1;
		__u32 flags:1;
		__u32 code:1;
		__u32 data_size:1;
	} _present;
	struct {
		__u32 context;
	} _len;

	__u32 error;
	char *context;
	__u32 from_pid;
	__u32 from_tid;
	__u32 to_pid;
	__u32 to_tid;
	__u32 flags;
	__u32 code;
	__u32 data_size;
};

struct binder_report {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct binder_report *ntf);
	struct binder_report_rsp obj __attribute__((aligned(8)));
};

void binder_report_free(struct binder_report *rsp);

#endif /* _LINUX_BINDER_GEN_H */
