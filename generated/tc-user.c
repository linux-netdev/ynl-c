// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/tc.yaml */
/* YNL-GEN user source */

#include <stdlib.h>
#include <string.h>
#include "tc-user.h"
#include "ynl.h"
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_bpf.h>
#include <linux/tc_act/tc_connmark.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/tc_act/tc_ct.h>
#include <linux/tc_act/tc_ctinfo.h>
#include <linux/tc_act/tc_gate.h>
#include <linux/tc_act/tc_ife.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_mpls.h>
#include <linux/tc_act/tc_nat.h>
#include <linux/tc_act/tc_pedit.h>
#include <linux/tc_act/tc_defact.h>
#include <linux/tc_act/tc_skbedit.h>
#include <linux/tc_act/tc_skbmod.h>
#include <linux/tc_act/tc_tunnel_key.h>
#include <linux/tc_act/tc_vlan.h>
#include <linux/tc_act/tc_sample.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/gen_stats.h>
#include <linux/pkt_cls.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const tc_op_strmap[] = {
	[36] = "getqdisc",
	[40] = "gettclass",
	[44] = "gettfilter",
	[100] = "getchain",
};

const char *tc_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(tc_op_strmap))
		return NULL;
	return tc_op_strmap[op];
}

static const char * const tc_cls_flags_strmap[] = {
	[0] = "skip-hw",
	[1] = "skip-sw",
	[2] = "in-hw",
	[3] = "not-in-nw",
	[4] = "verbose",
};

const char *tc_cls_flags_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(tc_cls_flags_strmap))
		return NULL;
	return tc_cls_flags_strmap[value];
}

static const char * const tc_flower_key_ctrl_flags_strmap[] = {
	[0] = "frag",
	[1] = "firstfrag",
	[2] = "tuncsum",
	[3] = "tundf",
	[4] = "tunoam",
	[5] = "tuncrit",
};

const char *tc_flower_key_ctrl_flags_str(int value)
{
	value = ffs(value) - 1;
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(tc_flower_key_ctrl_flags_strmap))
		return NULL;
	return tc_flower_key_ctrl_flags_strmap[value];
}

static const char * const tc_dualpi2_drop_overload_strmap[] = {
	[0] = "overflow",
	[1] = "drop",
};

const char *tc_dualpi2_drop_overload_str(enum tc_dualpi2_drop_overload value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(tc_dualpi2_drop_overload_strmap))
		return NULL;
	return tc_dualpi2_drop_overload_strmap[value];
}

static const char * const tc_dualpi2_drop_early_strmap[] = {
	[0] = "drop-dequeue",
	[1] = "drop-enqueue",
};

const char *tc_dualpi2_drop_early_str(enum tc_dualpi2_drop_early value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(tc_dualpi2_drop_early_strmap))
		return NULL;
	return tc_dualpi2_drop_early_strmap[value];
}

static const char * const tc_dualpi2_ecn_mask_strmap[] = {
	[1] = "l4s-ect",
	[2] = "cla-ect",
	[3] = "any-ect",
};

const char *tc_dualpi2_ecn_mask_str(enum tc_dualpi2_ecn_mask value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(tc_dualpi2_ecn_mask_strmap))
		return NULL;
	return tc_dualpi2_ecn_mask_strmap[value];
}

static const char * const tc_dualpi2_split_gso_strmap[] = {
	[0] = "no-split-gso",
	[1] = "split-gso",
};

const char *tc_dualpi2_split_gso_str(enum tc_dualpi2_split_gso value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(tc_dualpi2_split_gso_strmap))
		return NULL;
	return tc_dualpi2_split_gso_strmap[value];
}

/* Policies */
extern const struct ynl_policy_nest tc_ets_attrs_nest;

const struct ynl_policy_attr tc_tca_stab_attrs_policy[TCA_STAB_MAX + 1] = {
	[TCA_STAB_BASE] = { .name = "base", .type = YNL_PT_BINARY,},
	[TCA_STAB_DATA] = { .name = "data", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_tca_stab_attrs_nest = {
	.max_attr = TCA_STAB_MAX,
	.table = tc_tca_stab_attrs_policy,
};

const struct ynl_policy_attr tc_cake_attrs_policy[TCA_CAKE_MAX + 1] = {
	[TCA_CAKE_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_CAKE_BASE_RATE64] = { .name = "base-rate64", .type = YNL_PT_U64, },
	[TCA_CAKE_DIFFSERV_MODE] = { .name = "diffserv-mode", .type = YNL_PT_U32, },
	[TCA_CAKE_ATM] = { .name = "atm", .type = YNL_PT_U32, },
	[TCA_CAKE_FLOW_MODE] = { .name = "flow-mode", .type = YNL_PT_U32, },
	[TCA_CAKE_OVERHEAD] = { .name = "overhead", .type = YNL_PT_U32, },
	[TCA_CAKE_RTT] = { .name = "rtt", .type = YNL_PT_U32, },
	[TCA_CAKE_TARGET] = { .name = "target", .type = YNL_PT_U32, },
	[TCA_CAKE_AUTORATE] = { .name = "autorate", .type = YNL_PT_U32, },
	[TCA_CAKE_MEMORY] = { .name = "memory", .type = YNL_PT_U32, },
	[TCA_CAKE_NAT] = { .name = "nat", .type = YNL_PT_U32, },
	[TCA_CAKE_RAW] = { .name = "raw", .type = YNL_PT_U32, },
	[TCA_CAKE_WASH] = { .name = "wash", .type = YNL_PT_U32, },
	[TCA_CAKE_MPU] = { .name = "mpu", .type = YNL_PT_U32, },
	[TCA_CAKE_INGRESS] = { .name = "ingress", .type = YNL_PT_U32, },
	[TCA_CAKE_ACK_FILTER] = { .name = "ack-filter", .type = YNL_PT_U32, },
	[TCA_CAKE_SPLIT_GSO] = { .name = "split-gso", .type = YNL_PT_U32, },
	[TCA_CAKE_FWMARK] = { .name = "fwmark", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_cake_attrs_nest = {
	.max_attr = TCA_CAKE_MAX,
	.table = tc_cake_attrs_policy,
};

const struct ynl_policy_attr tc_cbs_attrs_policy[TCA_CBS_MAX + 1] = {
	[TCA_CBS_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_cbs_attrs_nest = {
	.max_attr = TCA_CBS_MAX,
	.table = tc_cbs_attrs_policy,
};

const struct ynl_policy_attr tc_choke_attrs_policy[TCA_CHOKE_MAX + 1] = {
	[TCA_CHOKE_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_CHOKE_STAB] = { .name = "stab", .type = YNL_PT_BINARY,},
	[TCA_CHOKE_MAX_P] = { .name = "max-p", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_choke_attrs_nest = {
	.max_attr = TCA_CHOKE_MAX,
	.table = tc_choke_attrs_policy,
};

const struct ynl_policy_attr tc_codel_attrs_policy[TCA_CODEL_MAX + 1] = {
	[TCA_CODEL_TARGET] = { .name = "target", .type = YNL_PT_U32, },
	[TCA_CODEL_LIMIT] = { .name = "limit", .type = YNL_PT_U32, },
	[TCA_CODEL_INTERVAL] = { .name = "interval", .type = YNL_PT_U32, },
	[TCA_CODEL_ECN] = { .name = "ecn", .type = YNL_PT_U32, },
	[TCA_CODEL_CE_THRESHOLD] = { .name = "ce-threshold", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_codel_attrs_nest = {
	.max_attr = TCA_CODEL_MAX,
	.table = tc_codel_attrs_policy,
};

const struct ynl_policy_attr tc_drr_attrs_policy[TCA_DRR_MAX + 1] = {
	[TCA_DRR_QUANTUM] = { .name = "quantum", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_drr_attrs_nest = {
	.max_attr = TCA_DRR_MAX,
	.table = tc_drr_attrs_policy,
};

const struct ynl_policy_attr tc_dualpi2_attrs_policy[TCA_DUALPI2_MAX + 1] = {
	[TCA_DUALPI2_LIMIT] = { .name = "limit", .type = YNL_PT_U32, },
	[TCA_DUALPI2_MEMORY_LIMIT] = { .name = "memory-limit", .type = YNL_PT_U32, },
	[TCA_DUALPI2_TARGET] = { .name = "target", .type = YNL_PT_U32, },
	[TCA_DUALPI2_TUPDATE] = { .name = "tupdate", .type = YNL_PT_U32, },
	[TCA_DUALPI2_ALPHA] = { .name = "alpha", .type = YNL_PT_U32, },
	[TCA_DUALPI2_BETA] = { .name = "beta", .type = YNL_PT_U32, },
	[TCA_DUALPI2_STEP_THRESH_PKTS] = { .name = "step-thresh-pkts", .type = YNL_PT_U32, },
	[TCA_DUALPI2_STEP_THRESH_US] = { .name = "step-thresh-us", .type = YNL_PT_U32, },
	[TCA_DUALPI2_MIN_QLEN_STEP] = { .name = "min-qlen-step", .type = YNL_PT_U32, },
	[TCA_DUALPI2_COUPLING] = { .name = "coupling", .type = YNL_PT_U8, },
	[TCA_DUALPI2_DROP_OVERLOAD] = { .name = "drop-overload", .type = YNL_PT_U8, },
	[TCA_DUALPI2_DROP_EARLY] = { .name = "drop-early", .type = YNL_PT_U8, },
	[TCA_DUALPI2_C_PROTECTION] = { .name = "c-protection", .type = YNL_PT_U8, },
	[TCA_DUALPI2_ECN_MASK] = { .name = "ecn-mask", .type = YNL_PT_U8, },
	[TCA_DUALPI2_SPLIT_GSO] = { .name = "split-gso", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest tc_dualpi2_attrs_nest = {
	.max_attr = TCA_DUALPI2_MAX,
	.table = tc_dualpi2_attrs_policy,
};

const struct ynl_policy_attr tc_etf_attrs_policy[TCA_ETF_MAX + 1] = {
	[TCA_ETF_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_etf_attrs_nest = {
	.max_attr = TCA_ETF_MAX,
	.table = tc_etf_attrs_policy,
};

const struct ynl_policy_attr tc_fq_attrs_policy[TCA_FQ_MAX + 1] = {
	[TCA_FQ_PLIMIT] = { .name = "plimit", .type = YNL_PT_U32, },
	[TCA_FQ_FLOW_PLIMIT] = { .name = "flow-plimit", .type = YNL_PT_U32, },
	[TCA_FQ_QUANTUM] = { .name = "quantum", .type = YNL_PT_U32, },
	[TCA_FQ_INITIAL_QUANTUM] = { .name = "initial-quantum", .type = YNL_PT_U32, },
	[TCA_FQ_RATE_ENABLE] = { .name = "rate-enable", .type = YNL_PT_U32, },
	[TCA_FQ_FLOW_DEFAULT_RATE] = { .name = "flow-default-rate", .type = YNL_PT_U32, },
	[TCA_FQ_FLOW_MAX_RATE] = { .name = "flow-max-rate", .type = YNL_PT_U32, },
	[TCA_FQ_BUCKETS_LOG] = { .name = "buckets-log", .type = YNL_PT_U32, },
	[TCA_FQ_FLOW_REFILL_DELAY] = { .name = "flow-refill-delay", .type = YNL_PT_U32, },
	[TCA_FQ_ORPHAN_MASK] = { .name = "orphan-mask", .type = YNL_PT_U32, },
	[TCA_FQ_LOW_RATE_THRESHOLD] = { .name = "low-rate-threshold", .type = YNL_PT_U32, },
	[TCA_FQ_CE_THRESHOLD] = { .name = "ce-threshold", .type = YNL_PT_U32, },
	[TCA_FQ_TIMER_SLACK] = { .name = "timer-slack", .type = YNL_PT_U32, },
	[TCA_FQ_HORIZON] = { .name = "horizon", .type = YNL_PT_U32, },
	[TCA_FQ_HORIZON_DROP] = { .name = "horizon-drop", .type = YNL_PT_U8, },
	[TCA_FQ_PRIOMAP] = { .name = "priomap", .type = YNL_PT_BINARY,},
	[TCA_FQ_WEIGHTS] = { .name = "weights", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_fq_attrs_nest = {
	.max_attr = TCA_FQ_MAX,
	.table = tc_fq_attrs_policy,
};

const struct ynl_policy_attr tc_fq_codel_attrs_policy[TCA_FQ_CODEL_MAX + 1] = {
	[TCA_FQ_CODEL_TARGET] = { .name = "target", .type = YNL_PT_U32, },
	[TCA_FQ_CODEL_LIMIT] = { .name = "limit", .type = YNL_PT_U32, },
	[TCA_FQ_CODEL_INTERVAL] = { .name = "interval", .type = YNL_PT_U32, },
	[TCA_FQ_CODEL_ECN] = { .name = "ecn", .type = YNL_PT_U32, },
	[TCA_FQ_CODEL_FLOWS] = { .name = "flows", .type = YNL_PT_U32, },
	[TCA_FQ_CODEL_QUANTUM] = { .name = "quantum", .type = YNL_PT_U32, },
	[TCA_FQ_CODEL_CE_THRESHOLD] = { .name = "ce-threshold", .type = YNL_PT_U32, },
	[TCA_FQ_CODEL_DROP_BATCH_SIZE] = { .name = "drop-batch-size", .type = YNL_PT_U32, },
	[TCA_FQ_CODEL_MEMORY_LIMIT] = { .name = "memory-limit", .type = YNL_PT_U32, },
	[TCA_FQ_CODEL_CE_THRESHOLD_SELECTOR] = { .name = "ce-threshold-selector", .type = YNL_PT_U8, },
	[TCA_FQ_CODEL_CE_THRESHOLD_MASK] = { .name = "ce-threshold-mask", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest tc_fq_codel_attrs_nest = {
	.max_attr = TCA_FQ_CODEL_MAX,
	.table = tc_fq_codel_attrs_policy,
};

const struct ynl_policy_attr tc_fq_pie_attrs_policy[TCA_FQ_PIE_MAX + 1] = {
	[TCA_FQ_PIE_LIMIT] = { .name = "limit", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_FLOWS] = { .name = "flows", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_TARGET] = { .name = "target", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_TUPDATE] = { .name = "tupdate", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_ALPHA] = { .name = "alpha", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_BETA] = { .name = "beta", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_QUANTUM] = { .name = "quantum", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_MEMORY_LIMIT] = { .name = "memory-limit", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_ECN_PROB] = { .name = "ecn-prob", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_ECN] = { .name = "ecn", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_BYTEMODE] = { .name = "bytemode", .type = YNL_PT_U32, },
	[TCA_FQ_PIE_DQ_RATE_ESTIMATOR] = { .name = "dq-rate-estimator", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_fq_pie_attrs_nest = {
	.max_attr = TCA_FQ_PIE_MAX,
	.table = tc_fq_pie_attrs_policy,
};

const struct ynl_policy_attr tc_hhf_attrs_policy[TCA_HHF_MAX + 1] = {
	[TCA_HHF_BACKLOG_LIMIT] = { .name = "backlog-limit", .type = YNL_PT_U32, },
	[TCA_HHF_QUANTUM] = { .name = "quantum", .type = YNL_PT_U32, },
	[TCA_HHF_HH_FLOWS_LIMIT] = { .name = "hh-flows-limit", .type = YNL_PT_U32, },
	[TCA_HHF_RESET_TIMEOUT] = { .name = "reset-timeout", .type = YNL_PT_U32, },
	[TCA_HHF_ADMIT_BYTES] = { .name = "admit-bytes", .type = YNL_PT_U32, },
	[TCA_HHF_EVICT_TIMEOUT] = { .name = "evict-timeout", .type = YNL_PT_U32, },
	[TCA_HHF_NON_HH_WEIGHT] = { .name = "non-hh-weight", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_hhf_attrs_nest = {
	.max_attr = TCA_HHF_MAX,
	.table = tc_hhf_attrs_policy,
};

const struct ynl_policy_attr tc_htb_attrs_policy[TCA_HTB_MAX + 1] = {
	[TCA_HTB_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_HTB_INIT] = { .name = "init", .type = YNL_PT_BINARY,},
	[TCA_HTB_CTAB] = { .name = "ctab", .type = YNL_PT_BINARY,},
	[TCA_HTB_RTAB] = { .name = "rtab", .type = YNL_PT_BINARY,},
	[TCA_HTB_DIRECT_QLEN] = { .name = "direct-qlen", .type = YNL_PT_U32, },
	[TCA_HTB_RATE64] = { .name = "rate64", .type = YNL_PT_U64, },
	[TCA_HTB_CEIL64] = { .name = "ceil64", .type = YNL_PT_U64, },
	[TCA_HTB_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_HTB_OFFLOAD] = { .name = "offload", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest tc_htb_attrs_nest = {
	.max_attr = TCA_HTB_MAX,
	.table = tc_htb_attrs_policy,
};

const struct ynl_policy_attr tc_pie_attrs_policy[TCA_PIE_MAX + 1] = {
	[TCA_PIE_TARGET] = { .name = "target", .type = YNL_PT_U32, },
	[TCA_PIE_LIMIT] = { .name = "limit", .type = YNL_PT_U32, },
	[TCA_PIE_TUPDATE] = { .name = "tupdate", .type = YNL_PT_U32, },
	[TCA_PIE_ALPHA] = { .name = "alpha", .type = YNL_PT_U32, },
	[TCA_PIE_BETA] = { .name = "beta", .type = YNL_PT_U32, },
	[TCA_PIE_ECN] = { .name = "ecn", .type = YNL_PT_U32, },
	[TCA_PIE_BYTEMODE] = { .name = "bytemode", .type = YNL_PT_U32, },
	[TCA_PIE_DQ_RATE_ESTIMATOR] = { .name = "dq-rate-estimator", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_pie_attrs_nest = {
	.max_attr = TCA_PIE_MAX,
	.table = tc_pie_attrs_policy,
};

const struct ynl_policy_attr tc_qfq_attrs_policy[TCA_QFQ_MAX + 1] = {
	[TCA_QFQ_WEIGHT] = { .name = "weight", .type = YNL_PT_U32, },
	[TCA_QFQ_LMAX] = { .name = "lmax", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_qfq_attrs_nest = {
	.max_attr = TCA_QFQ_MAX,
	.table = tc_qfq_attrs_policy,
};

const struct ynl_policy_attr tc_red_attrs_policy[TCA_RED_MAX + 1] = {
	[TCA_RED_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_RED_STAB] = { .name = "stab", .type = YNL_PT_BINARY,},
	[TCA_RED_MAX_P] = { .name = "max-p", .type = YNL_PT_U32, },
	[TCA_RED_FLAGS] = { .name = "flags", .type = YNL_PT_BITFIELD32, },
	[TCA_RED_EARLY_DROP_BLOCK] = { .name = "early-drop-block", .type = YNL_PT_U32, },
	[TCA_RED_MARK_BLOCK] = { .name = "mark-block", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_red_attrs_nest = {
	.max_attr = TCA_RED_MAX,
	.table = tc_red_attrs_policy,
};

const struct ynl_policy_attr tc_tbf_attrs_policy[TCA_TBF_MAX + 1] = {
	[TCA_TBF_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_TBF_RTAB] = { .name = "rtab", .type = YNL_PT_BINARY,},
	[TCA_TBF_PTAB] = { .name = "ptab", .type = YNL_PT_BINARY,},
	[TCA_TBF_RATE64] = { .name = "rate64", .type = YNL_PT_U64, },
	[TCA_TBF_PRATE64] = { .name = "prate64", .type = YNL_PT_U64, },
	[TCA_TBF_BURST] = { .name = "burst", .type = YNL_PT_U32, },
	[TCA_TBF_PBURST] = { .name = "pburst", .type = YNL_PT_U32, },
	[TCA_TBF_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_tbf_attrs_nest = {
	.max_attr = TCA_TBF_MAX,
	.table = tc_tbf_attrs_policy,
};

const struct ynl_policy_attr tc_ematch_attrs_policy[TCA_EMATCH_TREE_MAX + 1] = {
	[TCA_EMATCH_TREE_HDR] = { .name = "tree-hdr", .type = YNL_PT_BINARY,},
	[TCA_EMATCH_TREE_LIST] = { .name = "tree-list", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_ematch_attrs_nest = {
	.max_attr = TCA_EMATCH_TREE_MAX,
	.table = tc_ematch_attrs_policy,
};

const struct ynl_policy_attr tc_police_attrs_policy[TCA_POLICE_MAX + 1] = {
	[TCA_POLICE_TBF] = { .name = "tbf", .type = YNL_PT_BINARY,},
	[TCA_POLICE_RATE] = { .name = "rate", .type = YNL_PT_BINARY,},
	[TCA_POLICE_PEAKRATE] = { .name = "peakrate", .type = YNL_PT_BINARY,},
	[TCA_POLICE_AVRATE] = { .name = "avrate", .type = YNL_PT_U32, },
	[TCA_POLICE_RESULT] = { .name = "result", .type = YNL_PT_U32, },
	[TCA_POLICE_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_POLICE_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_POLICE_RATE64] = { .name = "rate64", .type = YNL_PT_U64, },
	[TCA_POLICE_PEAKRATE64] = { .name = "peakrate64", .type = YNL_PT_U64, },
	[TCA_POLICE_PKTRATE64] = { .name = "pktrate64", .type = YNL_PT_U64, },
	[TCA_POLICE_PKTBURST64] = { .name = "pktburst64", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest tc_police_attrs_nest = {
	.max_attr = TCA_POLICE_MAX,
	.table = tc_police_attrs_policy,
};

const struct ynl_policy_attr tc_flower_key_mpls_opt_attrs_policy[TCA_FLOWER_KEY_MPLS_OPT_LSE_MAX + 1] = {
	[TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH] = { .name = "lse-depth", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL] = { .name = "lse-ttl", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS] = { .name = "lse-bos", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_MPLS_OPT_LSE_TC] = { .name = "lse-tc", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL] = { .name = "lse-label", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_flower_key_mpls_opt_attrs_nest = {
	.max_attr = TCA_FLOWER_KEY_MPLS_OPT_LSE_MAX,
	.table = tc_flower_key_mpls_opt_attrs_policy,
};

const struct ynl_policy_attr tc_flower_key_cfm_attrs_policy[TCA_FLOWER_KEY_CFM_MAX + 1] = {
	[TCA_FLOWER_KEY_CFM_MD_LEVEL] = { .name = "md-level", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_CFM_OPCODE] = { .name = "opcode", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest tc_flower_key_cfm_attrs_nest = {
	.max_attr = TCA_FLOWER_KEY_CFM_MAX,
	.table = tc_flower_key_cfm_attrs_policy,
};

const struct ynl_policy_attr tc_netem_loss_attrs_policy[NETEM_LOSS_MAX + 1] = {
	[NETEM_LOSS_GI] = { .name = "gi", .type = YNL_PT_BINARY,},
	[NETEM_LOSS_GE] = { .name = "ge", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_netem_loss_attrs_nest = {
	.max_attr = NETEM_LOSS_MAX,
	.table = tc_netem_loss_attrs_policy,
};

const struct ynl_policy_attr tc_taprio_sched_entry_policy[TCA_TAPRIO_SCHED_ENTRY_MAX + 1] = {
	[TCA_TAPRIO_SCHED_ENTRY_INDEX] = { .name = "index", .type = YNL_PT_U32, },
	[TCA_TAPRIO_SCHED_ENTRY_CMD] = { .name = "cmd", .type = YNL_PT_U8, },
	[TCA_TAPRIO_SCHED_ENTRY_GATE_MASK] = { .name = "gate-mask", .type = YNL_PT_U32, },
	[TCA_TAPRIO_SCHED_ENTRY_INTERVAL] = { .name = "interval", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_taprio_sched_entry_nest = {
	.max_attr = TCA_TAPRIO_SCHED_ENTRY_MAX,
	.table = tc_taprio_sched_entry_policy,
};

const struct ynl_policy_attr tc_taprio_tc_entry_attrs_policy[TCA_TAPRIO_TC_ENTRY_MAX + 1] = {
	[TCA_TAPRIO_TC_ENTRY_INDEX] = { .name = "index", .type = YNL_PT_U32, },
	[TCA_TAPRIO_TC_ENTRY_MAX_SDU] = { .name = "max-sdu", .type = YNL_PT_U32, },
	[TCA_TAPRIO_TC_ENTRY_FP] = { .name = "fp", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_taprio_tc_entry_attrs_nest = {
	.max_attr = TCA_TAPRIO_TC_ENTRY_MAX,
	.table = tc_taprio_tc_entry_attrs_policy,
};

const struct ynl_policy_attr tc_cake_tin_stats_attrs_policy[TCA_CAKE_TIN_STATS_MAX + 1] = {
	[TCA_CAKE_TIN_STATS_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_CAKE_TIN_STATS_SENT_PACKETS] = { .name = "sent-packets", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_SENT_BYTES64] = { .name = "sent-bytes64", .type = YNL_PT_U64, },
	[TCA_CAKE_TIN_STATS_DROPPED_PACKETS] = { .name = "dropped-packets", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_DROPPED_BYTES64] = { .name = "dropped-bytes64", .type = YNL_PT_U64, },
	[TCA_CAKE_TIN_STATS_ACKS_DROPPED_PACKETS] = { .name = "acks-dropped-packets", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_ACKS_DROPPED_BYTES64] = { .name = "acks-dropped-bytes64", .type = YNL_PT_U64, },
	[TCA_CAKE_TIN_STATS_ECN_MARKED_PACKETS] = { .name = "ecn-marked-packets", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_ECN_MARKED_BYTES64] = { .name = "ecn-marked-bytes64", .type = YNL_PT_U64, },
	[TCA_CAKE_TIN_STATS_BACKLOG_PACKETS] = { .name = "backlog-packets", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_BACKLOG_BYTES] = { .name = "backlog-bytes", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_THRESHOLD_RATE64] = { .name = "threshold-rate64", .type = YNL_PT_U64, },
	[TCA_CAKE_TIN_STATS_TARGET_US] = { .name = "target-us", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_INTERVAL_US] = { .name = "interval-us", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_WAY_INDIRECT_HITS] = { .name = "way-indirect-hits", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_WAY_MISSES] = { .name = "way-misses", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_WAY_COLLISIONS] = { .name = "way-collisions", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_PEAK_DELAY_US] = { .name = "peak-delay-us", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_AVG_DELAY_US] = { .name = "avg-delay-us", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_BASE_DELAY_US] = { .name = "base-delay-us", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_SPARSE_FLOWS] = { .name = "sparse-flows", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_BULK_FLOWS] = { .name = "bulk-flows", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_UNRESPONSIVE_FLOWS] = { .name = "unresponsive-flows", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_MAX_SKBLEN] = { .name = "max-skblen", .type = YNL_PT_U32, },
	[TCA_CAKE_TIN_STATS_FLOW_QUANTUM] = { .name = "flow-quantum", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_cake_tin_stats_attrs_nest = {
	.max_attr = TCA_CAKE_TIN_STATS_MAX,
	.table = tc_cake_tin_stats_attrs_policy,
};

const struct ynl_policy_attr tc_flower_key_enc_opt_geneve_attrs_policy[TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX + 1] = {
	[TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS] = { .name = "class", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE] = { .name = "type", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA] = { .name = "data", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_flower_key_enc_opt_geneve_attrs_nest = {
	.max_attr = TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX,
	.table = tc_flower_key_enc_opt_geneve_attrs_policy,
};

const struct ynl_policy_attr tc_flower_key_enc_opt_vxlan_attrs_policy[TCA_FLOWER_KEY_ENC_OPT_VXLAN_MAX + 1] = {
	[TCA_FLOWER_KEY_ENC_OPT_VXLAN_GBP] = { .name = "gbp", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_flower_key_enc_opt_vxlan_attrs_nest = {
	.max_attr = TCA_FLOWER_KEY_ENC_OPT_VXLAN_MAX,
	.table = tc_flower_key_enc_opt_vxlan_attrs_policy,
};

const struct ynl_policy_attr tc_flower_key_enc_opt_erspan_attrs_policy[TCA_FLOWER_KEY_ENC_OPT_ERSPAN_MAX + 1] = {
	[TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER] = { .name = "ver", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX] = { .name = "index", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR] = { .name = "dir", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID] = { .name = "hwid", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest tc_flower_key_enc_opt_erspan_attrs_nest = {
	.max_attr = TCA_FLOWER_KEY_ENC_OPT_ERSPAN_MAX,
	.table = tc_flower_key_enc_opt_erspan_attrs_policy,
};

const struct ynl_policy_attr tc_flower_key_enc_opt_gtp_attrs_policy[TCA_FLOWER_KEY_ENC_OPT_GTP_MAX + 1] = {
	[TCA_FLOWER_KEY_ENC_OPT_GTP_PDU_TYPE] = { .name = "pdu-type", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ENC_OPT_GTP_QFI] = { .name = "qfi", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest tc_flower_key_enc_opt_gtp_attrs_nest = {
	.max_attr = TCA_FLOWER_KEY_ENC_OPT_GTP_MAX,
	.table = tc_flower_key_enc_opt_gtp_attrs_policy,
};

const struct ynl_policy_attr tc_tca_gred_vq_entry_attrs_policy[TCA_GRED_VQ_MAX + 1] = {
	[TCA_GRED_VQ_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_GRED_VQ_DP] = { .name = "dp", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_STAT_BYTES] = { .name = "stat-bytes", .type = YNL_PT_U64, },
	[TCA_GRED_VQ_STAT_PACKETS] = { .name = "stat-packets", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_STAT_BACKLOG] = { .name = "stat-backlog", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_STAT_PROB_DROP] = { .name = "stat-prob-drop", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_STAT_PROB_MARK] = { .name = "stat-prob-mark", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_STAT_FORCED_DROP] = { .name = "stat-forced-drop", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_STAT_FORCED_MARK] = { .name = "stat-forced-mark", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_STAT_PDROP] = { .name = "stat-pdrop", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_STAT_OTHER] = { .name = "stat-other", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_tca_gred_vq_entry_attrs_nest = {
	.max_attr = TCA_GRED_VQ_MAX,
	.table = tc_tca_gred_vq_entry_attrs_policy,
};

const struct ynl_policy_attr tc_act_bpf_attrs_policy[TCA_ACT_BPF_MAX + 1] = {
	[TCA_ACT_BPF_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_ACT_BPF_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_ACT_BPF_OPS_LEN] = { .name = "ops-len", .type = YNL_PT_U16, },
	[TCA_ACT_BPF_OPS] = { .name = "ops", .type = YNL_PT_BINARY,},
	[TCA_ACT_BPF_FD] = { .name = "fd", .type = YNL_PT_U32, },
	[TCA_ACT_BPF_NAME] = { .name = "name", .type = YNL_PT_NUL_STR, },
	[TCA_ACT_BPF_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_ACT_BPF_TAG] = { .name = "tag", .type = YNL_PT_BINARY,},
	[TCA_ACT_BPF_ID] = { .name = "id", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_act_bpf_attrs_nest = {
	.max_attr = TCA_ACT_BPF_MAX,
	.table = tc_act_bpf_attrs_policy,
};

const struct ynl_policy_attr tc_act_connmark_attrs_policy[TCA_CONNMARK_MAX + 1] = {
	[TCA_CONNMARK_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_CONNMARK_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_CONNMARK_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_act_connmark_attrs_nest = {
	.max_attr = TCA_CONNMARK_MAX,
	.table = tc_act_connmark_attrs_policy,
};

const struct ynl_policy_attr tc_act_csum_attrs_policy[TCA_CSUM_MAX + 1] = {
	[TCA_CSUM_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_CSUM_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_CSUM_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_act_csum_attrs_nest = {
	.max_attr = TCA_CSUM_MAX,
	.table = tc_act_csum_attrs_policy,
};

const struct ynl_policy_attr tc_act_ct_attrs_policy[TCA_CT_MAX + 1] = {
	[TCA_CT_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_CT_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_CT_ACTION] = { .name = "action", .type = YNL_PT_U16, },
	[TCA_CT_ZONE] = { .name = "zone", .type = YNL_PT_U16, },
	[TCA_CT_MARK] = { .name = "mark", .type = YNL_PT_U32, },
	[TCA_CT_MARK_MASK] = { .name = "mark-mask", .type = YNL_PT_U32, },
	[TCA_CT_LABELS] = { .name = "labels", .type = YNL_PT_BINARY,},
	[TCA_CT_LABELS_MASK] = { .name = "labels-mask", .type = YNL_PT_BINARY,},
	[TCA_CT_NAT_IPV4_MIN] = { .name = "nat-ipv4-min", .type = YNL_PT_U32, },
	[TCA_CT_NAT_IPV4_MAX] = { .name = "nat-ipv4-max", .type = YNL_PT_U32, },
	[TCA_CT_NAT_IPV6_MIN] = { .name = "nat-ipv6-min", .type = YNL_PT_BINARY,},
	[TCA_CT_NAT_IPV6_MAX] = { .name = "nat-ipv6-max", .type = YNL_PT_BINARY,},
	[TCA_CT_NAT_PORT_MIN] = { .name = "nat-port-min", .type = YNL_PT_U16, },
	[TCA_CT_NAT_PORT_MAX] = { .name = "nat-port-max", .type = YNL_PT_U16, },
	[TCA_CT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_CT_HELPER_NAME] = { .name = "helper-name", .type = YNL_PT_NUL_STR, },
	[TCA_CT_HELPER_FAMILY] = { .name = "helper-family", .type = YNL_PT_U8, },
	[TCA_CT_HELPER_PROTO] = { .name = "helper-proto", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest tc_act_ct_attrs_nest = {
	.max_attr = TCA_CT_MAX,
	.table = tc_act_ct_attrs_policy,
};

const struct ynl_policy_attr tc_act_ctinfo_attrs_policy[TCA_CTINFO_MAX + 1] = {
	[TCA_CTINFO_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_CTINFO_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_CTINFO_ACT] = { .name = "act", .type = YNL_PT_BINARY,},
	[TCA_CTINFO_ZONE] = { .name = "zone", .type = YNL_PT_U16, },
	[TCA_CTINFO_PARMS_DSCP_MASK] = { .name = "parms-dscp-mask", .type = YNL_PT_U32, },
	[TCA_CTINFO_PARMS_DSCP_STATEMASK] = { .name = "parms-dscp-statemask", .type = YNL_PT_U32, },
	[TCA_CTINFO_PARMS_CPMARK_MASK] = { .name = "parms-cpmark-mask", .type = YNL_PT_U32, },
	[TCA_CTINFO_STATS_DSCP_SET] = { .name = "stats-dscp-set", .type = YNL_PT_U64, },
	[TCA_CTINFO_STATS_DSCP_ERROR] = { .name = "stats-dscp-error", .type = YNL_PT_U64, },
	[TCA_CTINFO_STATS_CPMARK_SET] = { .name = "stats-cpmark-set", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest tc_act_ctinfo_attrs_nest = {
	.max_attr = TCA_CTINFO_MAX,
	.table = tc_act_ctinfo_attrs_policy,
};

const struct ynl_policy_attr tc_act_gact_attrs_policy[TCA_GACT_MAX + 1] = {
	[TCA_GACT_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_GACT_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_GACT_PROB] = { .name = "prob", .type = YNL_PT_BINARY,},
	[TCA_GACT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_act_gact_attrs_nest = {
	.max_attr = TCA_GACT_MAX,
	.table = tc_act_gact_attrs_policy,
};

const struct ynl_policy_attr tc_act_gate_attrs_policy[TCA_GATE_MAX + 1] = {
	[TCA_GATE_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_GATE_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_GATE_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_GATE_PRIORITY] = { .name = "priority", .type = YNL_PT_U32, },
	[TCA_GATE_ENTRY_LIST] = { .name = "entry-list", .type = YNL_PT_BINARY,},
	[TCA_GATE_BASE_TIME] = { .name = "base-time", .type = YNL_PT_U64, },
	[TCA_GATE_CYCLE_TIME] = { .name = "cycle-time", .type = YNL_PT_U64, },
	[TCA_GATE_CYCLE_TIME_EXT] = { .name = "cycle-time-ext", .type = YNL_PT_U64, },
	[TCA_GATE_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[TCA_GATE_CLOCKID] = { .name = "clockid", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_act_gate_attrs_nest = {
	.max_attr = TCA_GATE_MAX,
	.table = tc_act_gate_attrs_policy,
};

const struct ynl_policy_attr tc_act_ife_attrs_policy[TCA_IFE_MAX + 1] = {
	[TCA_IFE_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_IFE_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_IFE_DMAC] = { .name = "dmac", .type = YNL_PT_BINARY,},
	[TCA_IFE_SMAC] = { .name = "smac", .type = YNL_PT_BINARY,},
	[TCA_IFE_TYPE] = { .name = "type", .type = YNL_PT_U16, },
	[TCA_IFE_METALST] = { .name = "metalst", .type = YNL_PT_BINARY,},
	[TCA_IFE_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_act_ife_attrs_nest = {
	.max_attr = TCA_IFE_MAX,
	.table = tc_act_ife_attrs_policy,
};

const struct ynl_policy_attr tc_act_mirred_attrs_policy[TCA_MIRRED_MAX + 1] = {
	[TCA_MIRRED_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_MIRRED_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_MIRRED_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_MIRRED_BLOCKID] = { .name = "blockid", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_act_mirred_attrs_nest = {
	.max_attr = TCA_MIRRED_MAX,
	.table = tc_act_mirred_attrs_policy,
};

const struct ynl_policy_attr tc_act_mpls_attrs_policy[TCA_MPLS_MAX + 1] = {
	[TCA_MPLS_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_MPLS_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_MPLS_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_MPLS_PROTO] = { .name = "proto", .type = YNL_PT_U16, },
	[TCA_MPLS_LABEL] = { .name = "label", .type = YNL_PT_U32, },
	[TCA_MPLS_TC] = { .name = "tc", .type = YNL_PT_U8, },
	[TCA_MPLS_TTL] = { .name = "ttl", .type = YNL_PT_U8, },
	[TCA_MPLS_BOS] = { .name = "bos", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest tc_act_mpls_attrs_nest = {
	.max_attr = TCA_MPLS_MAX,
	.table = tc_act_mpls_attrs_policy,
};

const struct ynl_policy_attr tc_act_nat_attrs_policy[TCA_NAT_MAX + 1] = {
	[TCA_NAT_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_NAT_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_NAT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_act_nat_attrs_nest = {
	.max_attr = TCA_NAT_MAX,
	.table = tc_act_nat_attrs_policy,
};

const struct ynl_policy_attr tc_act_pedit_attrs_policy[TCA_PEDIT_MAX + 1] = {
	[TCA_PEDIT_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_PEDIT_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_PEDIT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_PEDIT_PARMS_EX] = { .name = "parms-ex", .type = YNL_PT_BINARY,},
	[TCA_PEDIT_KEYS_EX] = { .name = "keys-ex", .type = YNL_PT_BINARY,},
	[TCA_PEDIT_KEY_EX] = { .name = "key-ex", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_act_pedit_attrs_nest = {
	.max_attr = TCA_PEDIT_MAX,
	.table = tc_act_pedit_attrs_policy,
};

const struct ynl_policy_attr tc_act_sample_attrs_policy[TCA_SAMPLE_MAX + 1] = {
	[TCA_SAMPLE_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_SAMPLE_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_SAMPLE_RATE] = { .name = "rate", .type = YNL_PT_U32, },
	[TCA_SAMPLE_TRUNC_SIZE] = { .name = "trunc-size", .type = YNL_PT_U32, },
	[TCA_SAMPLE_PSAMPLE_GROUP] = { .name = "psample-group", .type = YNL_PT_U32, },
	[TCA_SAMPLE_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_act_sample_attrs_nest = {
	.max_attr = TCA_SAMPLE_MAX,
	.table = tc_act_sample_attrs_policy,
};

const struct ynl_policy_attr tc_act_simple_attrs_policy[TCA_DEF_MAX + 1] = {
	[TCA_DEF_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_DEF_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_DEF_DATA] = { .name = "data", .type = YNL_PT_BINARY,},
	[TCA_DEF_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_act_simple_attrs_nest = {
	.max_attr = TCA_DEF_MAX,
	.table = tc_act_simple_attrs_policy,
};

const struct ynl_policy_attr tc_act_skbedit_attrs_policy[TCA_SKBEDIT_MAX + 1] = {
	[TCA_SKBEDIT_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_SKBEDIT_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_SKBEDIT_PRIORITY] = { .name = "priority", .type = YNL_PT_U32, },
	[TCA_SKBEDIT_QUEUE_MAPPING] = { .name = "queue-mapping", .type = YNL_PT_U16, },
	[TCA_SKBEDIT_MARK] = { .name = "mark", .type = YNL_PT_U32, },
	[TCA_SKBEDIT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_SKBEDIT_PTYPE] = { .name = "ptype", .type = YNL_PT_U16, },
	[TCA_SKBEDIT_MASK] = { .name = "mask", .type = YNL_PT_U32, },
	[TCA_SKBEDIT_FLAGS] = { .name = "flags", .type = YNL_PT_U64, },
	[TCA_SKBEDIT_QUEUE_MAPPING_MAX] = { .name = "queue-mapping-max", .type = YNL_PT_U16, },
};

const struct ynl_policy_nest tc_act_skbedit_attrs_nest = {
	.max_attr = TCA_SKBEDIT_MAX,
	.table = tc_act_skbedit_attrs_policy,
};

const struct ynl_policy_attr tc_act_skbmod_attrs_policy[TCA_SKBMOD_MAX + 1] = {
	[TCA_SKBMOD_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_SKBMOD_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_SKBMOD_DMAC] = { .name = "dmac", .type = YNL_PT_BINARY,},
	[TCA_SKBMOD_SMAC] = { .name = "smac", .type = YNL_PT_BINARY,},
	[TCA_SKBMOD_ETYPE] = { .name = "etype", .type = YNL_PT_BINARY,},
	[TCA_SKBMOD_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_act_skbmod_attrs_nest = {
	.max_attr = TCA_SKBMOD_MAX,
	.table = tc_act_skbmod_attrs_policy,
};

const struct ynl_policy_attr tc_act_tunnel_key_attrs_policy[TCA_TUNNEL_KEY_MAX + 1] = {
	[TCA_TUNNEL_KEY_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_TUNNEL_KEY_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_TUNNEL_KEY_ENC_IPV4_SRC] = { .name = "enc-ipv4-src", .type = YNL_PT_U32, },
	[TCA_TUNNEL_KEY_ENC_IPV4_DST] = { .name = "enc-ipv4-dst", .type = YNL_PT_U32, },
	[TCA_TUNNEL_KEY_ENC_IPV6_SRC] = { .name = "enc-ipv6-src", .type = YNL_PT_BINARY,},
	[TCA_TUNNEL_KEY_ENC_IPV6_DST] = { .name = "enc-ipv6-dst", .type = YNL_PT_BINARY,},
	[TCA_TUNNEL_KEY_ENC_KEY_ID] = { .name = "enc-key-id", .type = YNL_PT_U64, },
	[TCA_TUNNEL_KEY_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_TUNNEL_KEY_ENC_DST_PORT] = { .name = "enc-dst-port", .type = YNL_PT_U16, },
	[TCA_TUNNEL_KEY_NO_CSUM] = { .name = "no-csum", .type = YNL_PT_U8, },
	[TCA_TUNNEL_KEY_ENC_OPTS] = { .name = "enc-opts", .type = YNL_PT_BINARY,},
	[TCA_TUNNEL_KEY_ENC_TOS] = { .name = "enc-tos", .type = YNL_PT_U8, },
	[TCA_TUNNEL_KEY_ENC_TTL] = { .name = "enc-ttl", .type = YNL_PT_U8, },
	[TCA_TUNNEL_KEY_NO_FRAG] = { .name = "no-frag", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest tc_act_tunnel_key_attrs_nest = {
	.max_attr = TCA_TUNNEL_KEY_MAX,
	.table = tc_act_tunnel_key_attrs_policy,
};

const struct ynl_policy_attr tc_act_vlan_attrs_policy[TCA_VLAN_MAX + 1] = {
	[TCA_VLAN_TM] = { .name = "tm", .type = YNL_PT_BINARY,},
	[TCA_VLAN_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_VLAN_PUSH_VLAN_ID] = { .name = "push-vlan-id", .type = YNL_PT_U16, },
	[TCA_VLAN_PUSH_VLAN_PROTOCOL] = { .name = "push-vlan-protocol", .type = YNL_PT_U16, },
	[TCA_VLAN_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_VLAN_PUSH_VLAN_PRIORITY] = { .name = "push-vlan-priority", .type = YNL_PT_U8, },
	[TCA_VLAN_PUSH_ETH_DST] = { .name = "push-eth-dst", .type = YNL_PT_BINARY,},
	[TCA_VLAN_PUSH_ETH_SRC] = { .name = "push-eth-src", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_act_vlan_attrs_nest = {
	.max_attr = TCA_VLAN_MAX,
	.table = tc_act_vlan_attrs_policy,
};

const struct ynl_policy_attr tc_flow_attrs_policy[TCA_FLOW_MAX + 1] = {
	[TCA_FLOW_KEYS] = { .name = "keys", .type = YNL_PT_U32, },
	[TCA_FLOW_MODE] = { .name = "mode", .type = YNL_PT_U32, },
	[TCA_FLOW_BASECLASS] = { .name = "baseclass", .type = YNL_PT_U32, },
	[TCA_FLOW_RSHIFT] = { .name = "rshift", .type = YNL_PT_U32, },
	[TCA_FLOW_ADDEND] = { .name = "addend", .type = YNL_PT_U32, },
	[TCA_FLOW_MASK] = { .name = "mask", .type = YNL_PT_U32, },
	[TCA_FLOW_XOR] = { .name = "xor", .type = YNL_PT_U32, },
	[TCA_FLOW_DIVISOR] = { .name = "divisor", .type = YNL_PT_U32, },
	[TCA_FLOW_ACT] = { .name = "act", .type = YNL_PT_BINARY,},
	[TCA_FLOW_POLICE] = { .name = "police", .type = YNL_PT_NEST, .nest = &tc_police_attrs_nest, },
	[TCA_FLOW_EMATCHES] = { .name = "ematches", .type = YNL_PT_BINARY,},
	[TCA_FLOW_PERTURB] = { .name = "perturb", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_flow_attrs_nest = {
	.max_attr = TCA_FLOW_MAX,
	.table = tc_flow_attrs_policy,
};

const struct ynl_policy_attr tc_netem_attrs_policy[TCA_NETEM_MAX + 1] = {
	[TCA_NETEM_CORR] = { .name = "corr", .type = YNL_PT_BINARY,},
	[TCA_NETEM_DELAY_DIST] = { .name = "delay-dist", .type = YNL_PT_BINARY,},
	[TCA_NETEM_REORDER] = { .name = "reorder", .type = YNL_PT_BINARY,},
	[TCA_NETEM_CORRUPT] = { .name = "corrupt", .type = YNL_PT_BINARY,},
	[TCA_NETEM_LOSS] = { .name = "loss", .type = YNL_PT_NEST, .nest = &tc_netem_loss_attrs_nest, },
	[TCA_NETEM_RATE] = { .name = "rate", .type = YNL_PT_BINARY,},
	[TCA_NETEM_ECN] = { .name = "ecn", .type = YNL_PT_U32, },
	[TCA_NETEM_RATE64] = { .name = "rate64", .type = YNL_PT_U64, },
	[TCA_NETEM_PAD] = { .name = "pad", .type = YNL_PT_U32, },
	[TCA_NETEM_LATENCY64] = { .name = "latency64", .type = YNL_PT_U64, },
	[TCA_NETEM_JITTER64] = { .name = "jitter64", .type = YNL_PT_U64, },
	[TCA_NETEM_SLOT] = { .name = "slot", .type = YNL_PT_BINARY,},
	[TCA_NETEM_SLOT_DIST] = { .name = "slot-dist", .type = YNL_PT_BINARY,},
	[TCA_NETEM_PRNG_SEED] = { .name = "prng-seed", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest tc_netem_attrs_nest = {
	.max_attr = TCA_NETEM_MAX,
	.table = tc_netem_attrs_policy,
};

const struct ynl_policy_attr tc_cake_stats_attrs_policy[TCA_CAKE_STATS_MAX + 1] = {
	[TCA_CAKE_STATS_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_CAKE_STATS_CAPACITY_ESTIMATE64] = { .name = "capacity-estimate64", .type = YNL_PT_U64, },
	[TCA_CAKE_STATS_MEMORY_LIMIT] = { .name = "memory-limit", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_MEMORY_USED] = { .name = "memory-used", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_AVG_NETOFF] = { .name = "avg-netoff", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_MIN_NETLEN] = { .name = "min-netlen", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_MAX_NETLEN] = { .name = "max-netlen", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_MIN_ADJLEN] = { .name = "min-adjlen", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_MAX_ADJLEN] = { .name = "max-adjlen", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_TIN_STATS] = { .name = "tin-stats", .type = YNL_PT_NEST, .nest = &tc_cake_tin_stats_attrs_nest, },
	[TCA_CAKE_STATS_DEFICIT] = { .name = "deficit", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_COBALT_COUNT] = { .name = "cobalt-count", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_DROPPING] = { .name = "dropping", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_DROP_NEXT_US] = { .name = "drop-next-us", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_P_DROP] = { .name = "p-drop", .type = YNL_PT_U32, },
	[TCA_CAKE_STATS_BLUE_TIMER_US] = { .name = "blue-timer-us", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_cake_stats_attrs_nest = {
	.max_attr = TCA_CAKE_STATS_MAX,
	.table = tc_cake_stats_attrs_policy,
};

const struct ynl_policy_attr tc_flower_key_enc_opts_attrs_policy[TCA_FLOWER_KEY_ENC_OPTS_MAX + 1] = {
	[TCA_FLOWER_KEY_ENC_OPTS_GENEVE] = { .name = "geneve", .type = YNL_PT_NEST, .nest = &tc_flower_key_enc_opt_geneve_attrs_nest, },
	[TCA_FLOWER_KEY_ENC_OPTS_VXLAN] = { .name = "vxlan", .type = YNL_PT_NEST, .nest = &tc_flower_key_enc_opt_vxlan_attrs_nest, },
	[TCA_FLOWER_KEY_ENC_OPTS_ERSPAN] = { .name = "erspan", .type = YNL_PT_NEST, .nest = &tc_flower_key_enc_opt_erspan_attrs_nest, },
	[TCA_FLOWER_KEY_ENC_OPTS_GTP] = { .name = "gtp", .type = YNL_PT_NEST, .nest = &tc_flower_key_enc_opt_gtp_attrs_nest, },
};

const struct ynl_policy_nest tc_flower_key_enc_opts_attrs_nest = {
	.max_attr = TCA_FLOWER_KEY_ENC_OPTS_MAX,
	.table = tc_flower_key_enc_opts_attrs_policy,
};

const struct ynl_policy_attr tc_tca_gred_vq_list_attrs_policy[TCA_GRED_VQ_MAX + 1] = {
	[TCA_GRED_VQ_ENTRY] = { .name = "entry", .type = YNL_PT_NEST, .nest = &tc_tca_gred_vq_entry_attrs_nest, },
};

const struct ynl_policy_nest tc_tca_gred_vq_list_attrs_nest = {
	.max_attr = TCA_GRED_VQ_MAX,
	.table = tc_tca_gred_vq_list_attrs_policy,
};

const struct ynl_policy_attr tc_taprio_sched_entry_list_policy[TCA_TAPRIO_SCHED_MAX + 1] = {
	[TCA_TAPRIO_SCHED_ENTRY] = { .name = "entry", .type = YNL_PT_NEST, .nest = &tc_taprio_sched_entry_nest, },
};

const struct ynl_policy_nest tc_taprio_sched_entry_list_nest = {
	.max_attr = TCA_TAPRIO_SCHED_MAX,
	.table = tc_taprio_sched_entry_list_policy,
};

const struct ynl_policy_attr tc_act_options_msg_policy[] = {
	[0] = { .type = YNL_PT_SUBMSG, .name = "bpf", .nest = &tc_act_bpf_attrs_nest, },
	[1] = { .type = YNL_PT_SUBMSG, .name = "connmark", .nest = &tc_act_connmark_attrs_nest, },
	[2] = { .type = YNL_PT_SUBMSG, .name = "csum", .nest = &tc_act_csum_attrs_nest, },
	[3] = { .type = YNL_PT_SUBMSG, .name = "ct", .nest = &tc_act_ct_attrs_nest, },
	[4] = { .type = YNL_PT_SUBMSG, .name = "ctinfo", .nest = &tc_act_ctinfo_attrs_nest, },
	[5] = { .type = YNL_PT_SUBMSG, .name = "gact", .nest = &tc_act_gact_attrs_nest, },
	[6] = { .type = YNL_PT_SUBMSG, .name = "gate", .nest = &tc_act_gate_attrs_nest, },
	[7] = { .type = YNL_PT_SUBMSG, .name = "ife", .nest = &tc_act_ife_attrs_nest, },
	[8] = { .type = YNL_PT_SUBMSG, .name = "mirred", .nest = &tc_act_mirred_attrs_nest, },
	[9] = { .type = YNL_PT_SUBMSG, .name = "mpls", .nest = &tc_act_mpls_attrs_nest, },
	[10] = { .type = YNL_PT_SUBMSG, .name = "nat", .nest = &tc_act_nat_attrs_nest, },
	[11] = { .type = YNL_PT_SUBMSG, .name = "pedit", .nest = &tc_act_pedit_attrs_nest, },
	[12] = { .type = YNL_PT_SUBMSG, .name = "police", .nest = &tc_police_attrs_nest, },
	[13] = { .type = YNL_PT_SUBMSG, .name = "sample", .nest = &tc_act_sample_attrs_nest, },
	[14] = { .type = YNL_PT_SUBMSG, .name = "simple", .nest = &tc_act_simple_attrs_nest, },
	[15] = { .type = YNL_PT_SUBMSG, .name = "skbedit", .nest = &tc_act_skbedit_attrs_nest, },
	[16] = { .type = YNL_PT_SUBMSG, .name = "skbmod", .nest = &tc_act_skbmod_attrs_nest, },
	[17] = { .type = YNL_PT_SUBMSG, .name = "tunnel_key", .nest = &tc_act_tunnel_key_attrs_nest, },
	[18] = { .type = YNL_PT_SUBMSG, .name = "vlan", .nest = &tc_act_vlan_attrs_nest, },
};

const struct ynl_policy_nest tc_act_options_msg_nest = {
	.max_attr = 18,
	.table = tc_act_options_msg_policy,
};

const struct ynl_policy_attr tc_tca_stats_app_msg_policy[] = {
	[0] = { .type = YNL_PT_SUBMSG, .name = "cake", .nest = &tc_cake_stats_attrs_nest, },
	[1] = { .type = YNL_PT_SUBMSG, .name = "choke", },
	[2] = { .type = YNL_PT_SUBMSG, .name = "codel", },
	[3] = { .type = YNL_PT_SUBMSG, .name = "dualpi2", },
	[4] = { .type = YNL_PT_SUBMSG, .name = "fq", },
	[5] = { .type = YNL_PT_SUBMSG, .name = "fq_codel", },
	[6] = { .type = YNL_PT_SUBMSG, .name = "fq_pie", },
	[7] = { .type = YNL_PT_SUBMSG, .name = "hhf", },
	[8] = { .type = YNL_PT_SUBMSG, .name = "pie", },
	[9] = { .type = YNL_PT_SUBMSG, .name = "red", },
	[10] = { .type = YNL_PT_SUBMSG, .name = "sfb", },
	[11] = { .type = YNL_PT_SUBMSG, .name = "sfq", },
};

const struct ynl_policy_nest tc_tca_stats_app_msg_nest = {
	.max_attr = 11,
	.table = tc_tca_stats_app_msg_policy,
};

const struct ynl_policy_attr tc_tca_stats_attrs_policy[TCA_STATS_MAX + 1] = {
	[TCA_STATS_BASIC] = { .name = "basic", .type = YNL_PT_BINARY,},
	[TCA_STATS_RATE_EST] = { .name = "rate-est", .type = YNL_PT_BINARY,},
	[TCA_STATS_QUEUE] = { .name = "queue", .type = YNL_PT_BINARY,},
	[TCA_STATS_APP] = { .name = "app", .type = YNL_PT_NEST, .nest = &tc_tca_stats_app_msg_nest, .is_submsg = 1, },
	[TCA_STATS_RATE_EST64] = { .name = "rate-est64", .type = YNL_PT_BINARY,},
	[TCA_STATS_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_STATS_BASIC_HW] = { .name = "basic-hw", .type = YNL_PT_BINARY,},
	[TCA_STATS_PKT64] = { .name = "pkt64", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest tc_tca_stats_attrs_nest = {
	.max_attr = TCA_STATS_MAX,
	.table = tc_tca_stats_attrs_policy,
};

const struct ynl_policy_attr tc_gred_attrs_policy[TCA_GRED_MAX + 1] = {
	[TCA_GRED_PARMS] = { .name = "parms", .type = YNL_PT_BINARY,},
	[TCA_GRED_STAB] = { .name = "stab", .type = YNL_PT_BINARY,},
	[TCA_GRED_DPS] = { .name = "dps", .type = YNL_PT_BINARY,},
	[TCA_GRED_MAX_P] = { .name = "max-p", .type = YNL_PT_BINARY,},
	[TCA_GRED_LIMIT] = { .name = "limit", .type = YNL_PT_U32, },
	[TCA_GRED_VQ_LIST] = { .name = "vq-list", .type = YNL_PT_NEST, .nest = &tc_tca_gred_vq_list_attrs_nest, },
};

const struct ynl_policy_nest tc_gred_attrs_nest = {
	.max_attr = TCA_GRED_MAX,
	.table = tc_gred_attrs_policy,
};

const struct ynl_policy_attr tc_taprio_attrs_policy[TCA_TAPRIO_ATTR_MAX + 1] = {
	[TCA_TAPRIO_ATTR_PRIOMAP] = { .name = "priomap", .type = YNL_PT_BINARY,},
	[TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST] = { .name = "sched-entry-list", .type = YNL_PT_NEST, .nest = &tc_taprio_sched_entry_list_nest, },
	[TCA_TAPRIO_ATTR_SCHED_BASE_TIME] = { .name = "sched-base-time", .type = YNL_PT_U64, },
	[TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY] = { .name = "sched-single-entry", .type = YNL_PT_NEST, .nest = &tc_taprio_sched_entry_nest, },
	[TCA_TAPRIO_ATTR_SCHED_CLOCKID] = { .name = "sched-clockid", .type = YNL_PT_U32, },
	[TCA_TAPRIO_ATTR_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_TAPRIO_ATTR_ADMIN_SCHED] = { .name = "admin-sched", .type = YNL_PT_BINARY,},
	[TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME] = { .name = "sched-cycle-time", .type = YNL_PT_U64, },
	[TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION] = { .name = "sched-cycle-time-extension", .type = YNL_PT_U64, },
	[TCA_TAPRIO_ATTR_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[TCA_TAPRIO_ATTR_TXTIME_DELAY] = { .name = "txtime-delay", .type = YNL_PT_U32, },
	[TCA_TAPRIO_ATTR_TC_ENTRY] = { .name = "tc-entry", .type = YNL_PT_NEST, .nest = &tc_taprio_tc_entry_attrs_nest, },
};

const struct ynl_policy_nest tc_taprio_attrs_nest = {
	.max_attr = TCA_TAPRIO_ATTR_MAX,
	.table = tc_taprio_attrs_policy,
};

const struct ynl_policy_attr tc_act_attrs_policy[TCA_ACT_MAX + 1] = {
	[TCA_ACT_KIND] = { .name = "kind", .type = YNL_PT_NUL_STR, .is_selector = 1, },
	[TCA_ACT_OPTIONS] = { .name = "options", .type = YNL_PT_NEST, .nest = &tc_act_options_msg_nest, .is_submsg = 1, .selector_type = 1 },
	[TCA_ACT_INDEX] = { .name = "index", .type = YNL_PT_U32, },
	[TCA_ACT_STATS] = { .name = "stats", .type = YNL_PT_NEST, .nest = &tc_tca_stats_attrs_nest, },
	[TCA_ACT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_ACT_COOKIE] = { .name = "cookie", .type = YNL_PT_BINARY,},
	[TCA_ACT_FLAGS] = { .name = "flags", .type = YNL_PT_BITFIELD32, },
	[TCA_ACT_HW_STATS] = { .name = "hw-stats", .type = YNL_PT_BITFIELD32, },
	[TCA_ACT_USED_HW_STATS] = { .name = "used-hw-stats", .type = YNL_PT_BITFIELD32, },
	[TCA_ACT_IN_HW_COUNT] = { .name = "in-hw-count", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_act_attrs_nest = {
	.max_attr = TCA_ACT_MAX,
	.table = tc_act_attrs_policy,
};

const struct ynl_policy_attr tc_basic_attrs_policy[TCA_BASIC_MAX + 1] = {
	[TCA_BASIC_CLASSID] = { .name = "classid", .type = YNL_PT_U32, },
	[TCA_BASIC_EMATCHES] = { .name = "ematches", .type = YNL_PT_NEST, .nest = &tc_ematch_attrs_nest, },
	[TCA_BASIC_ACT] = { .name = "act", .type = YNL_PT_NEST, .nest = &tc_act_attrs_nest, },
	[TCA_BASIC_POLICE] = { .name = "police", .type = YNL_PT_NEST, .nest = &tc_police_attrs_nest, },
	[TCA_BASIC_PCNT] = { .name = "pcnt", .type = YNL_PT_BINARY,},
	[TCA_BASIC_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_basic_attrs_nest = {
	.max_attr = TCA_BASIC_MAX,
	.table = tc_basic_attrs_policy,
};

const struct ynl_policy_attr tc_bpf_attrs_policy[TCA_BPF_MAX + 1] = {
	[TCA_BPF_ACT] = { .name = "act", .type = YNL_PT_NEST, .nest = &tc_act_attrs_nest, },
	[TCA_BPF_POLICE] = { .name = "police", .type = YNL_PT_NEST, .nest = &tc_police_attrs_nest, },
	[TCA_BPF_CLASSID] = { .name = "classid", .type = YNL_PT_U32, },
	[TCA_BPF_OPS_LEN] = { .name = "ops-len", .type = YNL_PT_U16, },
	[TCA_BPF_OPS] = { .name = "ops", .type = YNL_PT_BINARY,},
	[TCA_BPF_FD] = { .name = "fd", .type = YNL_PT_U32, },
	[TCA_BPF_NAME] = { .name = "name", .type = YNL_PT_NUL_STR, },
	[TCA_BPF_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[TCA_BPF_FLAGS_GEN] = { .name = "flags-gen", .type = YNL_PT_U32, },
	[TCA_BPF_TAG] = { .name = "tag", .type = YNL_PT_BINARY,},
	[TCA_BPF_ID] = { .name = "id", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_bpf_attrs_nest = {
	.max_attr = TCA_BPF_MAX,
	.table = tc_bpf_attrs_policy,
};

const struct ynl_policy_attr tc_cgroup_attrs_policy[TCA_CGROUP_MAX + 1] = {
	[TCA_CGROUP_ACT] = { .name = "act", .type = YNL_PT_NEST, .nest = &tc_act_attrs_nest, },
	[TCA_CGROUP_POLICE] = { .name = "police", .type = YNL_PT_NEST, .nest = &tc_police_attrs_nest, },
	[TCA_CGROUP_EMATCHES] = { .name = "ematches", .type = YNL_PT_BINARY,},
};

const struct ynl_policy_nest tc_cgroup_attrs_nest = {
	.max_attr = TCA_CGROUP_MAX,
	.table = tc_cgroup_attrs_policy,
};

const struct ynl_policy_attr tc_flower_attrs_policy[TCA_FLOWER_MAX + 1] = {
	[TCA_FLOWER_CLASSID] = { .name = "classid", .type = YNL_PT_U32, },
	[TCA_FLOWER_INDEV] = { .name = "indev", .type = YNL_PT_NUL_STR, },
	[TCA_FLOWER_ACT] = { .name = "act", .type = YNL_PT_NEST, .nest = &tc_act_attrs_nest, },
	[TCA_FLOWER_KEY_ETH_DST] = { .name = "key-eth-dst", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ETH_DST_MASK] = { .name = "key-eth-dst-mask", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ETH_SRC] = { .name = "key-eth-src", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ETH_SRC_MASK] = { .name = "key-eth-src-mask", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ETH_TYPE] = { .name = "key-eth-type", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_IP_PROTO] = { .name = "key-ip-proto", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_IPV4_SRC] = { .name = "key-ipv4-src", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_IPV4_SRC_MASK] = { .name = "key-ipv4-src-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_IPV4_DST] = { .name = "key-ipv4-dst", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_IPV4_DST_MASK] = { .name = "key-ipv4-dst-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_IPV6_SRC] = { .name = "key-ipv6-src", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_IPV6_SRC_MASK] = { .name = "key-ipv6-src-mask", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_IPV6_DST] = { .name = "key-ipv6-dst", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_IPV6_DST_MASK] = { .name = "key-ipv6-dst-mask", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_TCP_SRC] = { .name = "key-tcp-src", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_TCP_DST] = { .name = "key-tcp-dst", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_UDP_SRC] = { .name = "key-udp-src", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_UDP_DST] = { .name = "key-udp-dst", .type = YNL_PT_U16, },
	[TCA_FLOWER_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_VLAN_ID] = { .name = "key-vlan-id", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_VLAN_PRIO] = { .name = "key-vlan-prio", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_VLAN_ETH_TYPE] = { .name = "key-vlan-eth-type", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_ENC_KEY_ID] = { .name = "key-enc-key-id", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ENC_IPV4_SRC] = { .name = "key-enc-ipv4-src", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK] = { .name = "key-enc-ipv4-src-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ENC_IPV4_DST] = { .name = "key-enc-ipv4-dst", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ENC_IPV4_DST_MASK] = { .name = "key-enc-ipv4-dst-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ENC_IPV6_SRC] = { .name = "key-enc-ipv6-src", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK] = { .name = "key-enc-ipv6-src-mask", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ENC_IPV6_DST] = { .name = "key-enc-ipv6-dst", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ENC_IPV6_DST_MASK] = { .name = "key-enc-ipv6-dst-mask", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_TCP_SRC_MASK] = { .name = "key-tcp-src-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_TCP_DST_MASK] = { .name = "key-tcp-dst-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_UDP_SRC_MASK] = { .name = "key-udp-src-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_UDP_DST_MASK] = { .name = "key-udp-dst-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_SCTP_SRC_MASK] = { .name = "key-sctp-src-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_SCTP_DST_MASK] = { .name = "key-sctp-dst-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_SCTP_SRC] = { .name = "key-sctp-src", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_SCTP_DST] = { .name = "key-sctp-dst", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_ENC_UDP_SRC_PORT] = { .name = "key-enc-udp-src-port", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK] = { .name = "key-enc-udp-src-port-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_ENC_UDP_DST_PORT] = { .name = "key-enc-udp-dst-port", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK] = { .name = "key-enc-udp-dst-port-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_FLAGS] = { .name = "key-flags", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_FLAGS_MASK] = { .name = "key-flags-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ICMPV4_CODE] = { .name = "key-icmpv4-code", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ICMPV4_CODE_MASK] = { .name = "key-icmpv4-code-mask", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ICMPV4_TYPE] = { .name = "key-icmpv4-type", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ICMPV4_TYPE_MASK] = { .name = "key-icmpv4-type-mask", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ICMPV6_CODE] = { .name = "key-icmpv6-code", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ICMPV6_CODE_MASK] = { .name = "key-icmpv6-code-mask", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ICMPV6_TYPE] = { .name = "key-icmpv6-type", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ICMPV6_TYPE_MASK] = { .name = "key-icmpv6-type-mask", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ARP_SIP] = { .name = "key-arp-sip", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ARP_SIP_MASK] = { .name = "key-arp-sip-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ARP_TIP] = { .name = "key-arp-tip", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ARP_TIP_MASK] = { .name = "key-arp-tip-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ARP_OP] = { .name = "key-arp-op", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ARP_OP_MASK] = { .name = "key-arp-op-mask", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ARP_SHA] = { .name = "key-arp-sha", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ARP_SHA_MASK] = { .name = "key-arp-sha-mask", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ARP_THA] = { .name = "key-arp-tha", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_ARP_THA_MASK] = { .name = "key-arp-tha-mask", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_MPLS_TTL] = { .name = "key-mpls-ttl", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_MPLS_BOS] = { .name = "key-mpls-bos", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_MPLS_TC] = { .name = "key-mpls-tc", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_MPLS_LABEL] = { .name = "key-mpls-label", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_TCP_FLAGS] = { .name = "key-tcp-flags", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_TCP_FLAGS_MASK] = { .name = "key-tcp-flags-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_IP_TOS] = { .name = "key-ip-tos", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_IP_TOS_MASK] = { .name = "key-ip-tos-mask", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_IP_TTL] = { .name = "key-ip-ttl", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_IP_TTL_MASK] = { .name = "key-ip-ttl-mask", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_CVLAN_ID] = { .name = "key-cvlan-id", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_CVLAN_PRIO] = { .name = "key-cvlan-prio", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_CVLAN_ETH_TYPE] = { .name = "key-cvlan-eth-type", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_ENC_IP_TOS] = { .name = "key-enc-ip-tos", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ENC_IP_TOS_MASK] = { .name = "key-enc-ip-tos-mask", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ENC_IP_TTL] = { .name = "key-enc-ip-ttl", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ENC_IP_TTL_MASK] = { .name = "key-enc-ip-ttl-mask", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_ENC_OPTS] = { .name = "key-enc-opts", .type = YNL_PT_NEST, .nest = &tc_flower_key_enc_opts_attrs_nest, },
	[TCA_FLOWER_KEY_ENC_OPTS_MASK] = { .name = "key-enc-opts-mask", .type = YNL_PT_NEST, .nest = &tc_flower_key_enc_opts_attrs_nest, },
	[TCA_FLOWER_IN_HW_COUNT] = { .name = "in-hw-count", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_PORT_SRC_MIN] = { .name = "key-port-src-min", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_PORT_SRC_MAX] = { .name = "key-port-src-max", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_PORT_DST_MIN] = { .name = "key-port-dst-min", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_PORT_DST_MAX] = { .name = "key-port-dst-max", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_CT_STATE] = { .name = "key-ct-state", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_CT_STATE_MASK] = { .name = "key-ct-state-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_CT_ZONE] = { .name = "key-ct-zone", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_CT_ZONE_MASK] = { .name = "key-ct-zone-mask", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_CT_MARK] = { .name = "key-ct-mark", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_CT_MARK_MASK] = { .name = "key-ct-mark-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_CT_LABELS] = { .name = "key-ct-labels", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_CT_LABELS_MASK] = { .name = "key-ct-labels-mask", .type = YNL_PT_BINARY,},
	[TCA_FLOWER_KEY_MPLS_OPTS] = { .name = "key-mpls-opts", .type = YNL_PT_NEST, .nest = &tc_flower_key_mpls_opt_attrs_nest, },
	[TCA_FLOWER_KEY_HASH] = { .name = "key-hash", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_HASH_MASK] = { .name = "key-hash-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_NUM_OF_VLANS] = { .name = "key-num-of-vlans", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_PPPOE_SID] = { .name = "key-pppoe-sid", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_PPP_PROTO] = { .name = "key-ppp-proto", .type = YNL_PT_U16, },
	[TCA_FLOWER_KEY_L2TPV3_SID] = { .name = "key-l2tpv3-sid", .type = YNL_PT_U32, },
	[TCA_FLOWER_L2_MISS] = { .name = "l2-miss", .type = YNL_PT_U8, },
	[TCA_FLOWER_KEY_CFM] = { .name = "key-cfm", .type = YNL_PT_NEST, .nest = &tc_flower_key_cfm_attrs_nest, },
	[TCA_FLOWER_KEY_SPI] = { .name = "key-spi", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_SPI_MASK] = { .name = "key-spi-mask", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ENC_FLAGS] = { .name = "key-enc-flags", .type = YNL_PT_U32, },
	[TCA_FLOWER_KEY_ENC_FLAGS_MASK] = { .name = "key-enc-flags-mask", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_flower_attrs_nest = {
	.max_attr = TCA_FLOWER_MAX,
	.table = tc_flower_attrs_policy,
};

const struct ynl_policy_attr tc_fw_attrs_policy[TCA_FW_MAX + 1] = {
	[TCA_FW_CLASSID] = { .name = "classid", .type = YNL_PT_U32, },
	[TCA_FW_POLICE] = { .name = "police", .type = YNL_PT_NEST, .nest = &tc_police_attrs_nest, },
	[TCA_FW_INDEV] = { .name = "indev", .type = YNL_PT_NUL_STR, },
	[TCA_FW_ACT] = { .name = "act", .type = YNL_PT_NEST, .nest = &tc_act_attrs_nest, },
	[TCA_FW_MASK] = { .name = "mask", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest tc_fw_attrs_nest = {
	.max_attr = TCA_FW_MAX,
	.table = tc_fw_attrs_policy,
};

const struct ynl_policy_attr tc_matchall_attrs_policy[TCA_MATCHALL_MAX + 1] = {
	[TCA_MATCHALL_CLASSID] = { .name = "classid", .type = YNL_PT_U32, },
	[TCA_MATCHALL_ACT] = { .name = "act", .type = YNL_PT_NEST, .nest = &tc_act_attrs_nest, },
	[TCA_MATCHALL_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[TCA_MATCHALL_PCNT] = { .name = "pcnt", .type = YNL_PT_BINARY,},
	[TCA_MATCHALL_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_matchall_attrs_nest = {
	.max_attr = TCA_MATCHALL_MAX,
	.table = tc_matchall_attrs_policy,
};

const struct ynl_policy_attr tc_route_attrs_policy[TCA_ROUTE4_MAX + 1] = {
	[TCA_ROUTE4_CLASSID] = { .name = "classid", .type = YNL_PT_U32, },
	[TCA_ROUTE4_TO] = { .name = "to", .type = YNL_PT_U32, },
	[TCA_ROUTE4_FROM] = { .name = "from", .type = YNL_PT_U32, },
	[TCA_ROUTE4_IIF] = { .name = "iif", .type = YNL_PT_U32, },
	[TCA_ROUTE4_POLICE] = { .name = "police", .type = YNL_PT_NEST, .nest = &tc_police_attrs_nest, },
	[TCA_ROUTE4_ACT] = { .name = "act", .type = YNL_PT_NEST, .nest = &tc_act_attrs_nest, },
};

const struct ynl_policy_nest tc_route_attrs_nest = {
	.max_attr = TCA_ROUTE4_MAX,
	.table = tc_route_attrs_policy,
};

const struct ynl_policy_attr tc_u32_attrs_policy[TCA_U32_MAX + 1] = {
	[TCA_U32_CLASSID] = { .name = "classid", .type = YNL_PT_U32, },
	[TCA_U32_HASH] = { .name = "hash", .type = YNL_PT_U32, },
	[TCA_U32_LINK] = { .name = "link", .type = YNL_PT_U32, },
	[TCA_U32_DIVISOR] = { .name = "divisor", .type = YNL_PT_U32, },
	[TCA_U32_SEL] = { .name = "sel", .type = YNL_PT_BINARY,},
	[TCA_U32_POLICE] = { .name = "police", .type = YNL_PT_NEST, .nest = &tc_police_attrs_nest, },
	[TCA_U32_ACT] = { .name = "act", .type = YNL_PT_NEST, .nest = &tc_act_attrs_nest, },
	[TCA_U32_INDEV] = { .name = "indev", .type = YNL_PT_NUL_STR, },
	[TCA_U32_PCNT] = { .name = "pcnt", .type = YNL_PT_BINARY,},
	[TCA_U32_MARK] = { .name = "mark", .type = YNL_PT_BINARY,},
	[TCA_U32_FLAGS] = { .name = "flags", .type = YNL_PT_U32, },
	[TCA_U32_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
};

const struct ynl_policy_nest tc_u32_attrs_nest = {
	.max_attr = TCA_U32_MAX,
	.table = tc_u32_attrs_policy,
};

const struct ynl_policy_attr tc_ets_attrs_policy[TCA_ETS_MAX + 1] = {
	[TCA_ETS_NBANDS] = { .name = "nbands", .type = YNL_PT_U8, },
	[TCA_ETS_NSTRICT] = { .name = "nstrict", .type = YNL_PT_U8, },
	[TCA_ETS_QUANTA] = { .name = "quanta", .type = YNL_PT_NEST, .nest = &tc_ets_attrs_nest, },
	[TCA_ETS_QUANTA_BAND] = { .name = "quanta-band", .type = YNL_PT_U32, },
	[TCA_ETS_PRIOMAP] = { .name = "priomap", .type = YNL_PT_NEST, .nest = &tc_ets_attrs_nest, },
	[TCA_ETS_PRIOMAP_BAND] = { .name = "priomap-band", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest tc_ets_attrs_nest = {
	.max_attr = TCA_ETS_MAX,
	.table = tc_ets_attrs_policy,
};

const struct ynl_policy_attr tc_options_msg_policy[] = {
	[0] = { .type = YNL_PT_SUBMSG, .name = "basic", .nest = &tc_basic_attrs_nest, },
	[1] = { .type = YNL_PT_SUBMSG, .name = "bpf", .nest = &tc_bpf_attrs_nest, },
	[2] = { .type = YNL_PT_SUBMSG, .name = "bfifo", },
	[3] = { .type = YNL_PT_SUBMSG, .name = "cake", .nest = &tc_cake_attrs_nest, },
	[4] = { .type = YNL_PT_SUBMSG, .name = "cbs", .nest = &tc_cbs_attrs_nest, },
	[5] = { .type = YNL_PT_SUBMSG, .name = "cgroup", .nest = &tc_cgroup_attrs_nest, },
	[6] = { .type = YNL_PT_SUBMSG, .name = "choke", .nest = &tc_choke_attrs_nest, },
	[7] = { .type = YNL_PT_SUBMSG, .name = "clsact", },
	[8] = { .type = YNL_PT_SUBMSG, .name = "codel", .nest = &tc_codel_attrs_nest, },
	[9] = { .type = YNL_PT_SUBMSG, .name = "drr", .nest = &tc_drr_attrs_nest, },
	[10] = { .type = YNL_PT_SUBMSG, .name = "dualpi2", .nest = &tc_dualpi2_attrs_nest, },
	[11] = { .type = YNL_PT_SUBMSG, .name = "etf", .nest = &tc_etf_attrs_nest, },
	[12] = { .type = YNL_PT_SUBMSG, .name = "ets", .nest = &tc_ets_attrs_nest, },
	[13] = { .type = YNL_PT_SUBMSG, .name = "flow", .nest = &tc_flow_attrs_nest, },
	[14] = { .type = YNL_PT_SUBMSG, .name = "flower", .nest = &tc_flower_attrs_nest, },
	[15] = { .type = YNL_PT_SUBMSG, .name = "fq", .nest = &tc_fq_attrs_nest, },
	[16] = { .type = YNL_PT_SUBMSG, .name = "fq_codel", .nest = &tc_fq_codel_attrs_nest, },
	[17] = { .type = YNL_PT_SUBMSG, .name = "fq_pie", .nest = &tc_fq_pie_attrs_nest, },
	[18] = { .type = YNL_PT_SUBMSG, .name = "fw", .nest = &tc_fw_attrs_nest, },
	[19] = { .type = YNL_PT_SUBMSG, .name = "gred", .nest = &tc_gred_attrs_nest, },
	[20] = { .type = YNL_PT_SUBMSG, .name = "hfsc", },
	[21] = { .type = YNL_PT_SUBMSG, .name = "hhf", .nest = &tc_hhf_attrs_nest, },
	[22] = { .type = YNL_PT_SUBMSG, .name = "htb", .nest = &tc_htb_attrs_nest, },
	[23] = { .type = YNL_PT_SUBMSG, .name = "ingress", },
	[24] = { .type = YNL_PT_SUBMSG, .name = "matchall", .nest = &tc_matchall_attrs_nest, },
	[25] = { .type = YNL_PT_SUBMSG, .name = "mq", },
	[26] = { .type = YNL_PT_SUBMSG, .name = "mqprio", },
	[27] = { .type = YNL_PT_SUBMSG, .name = "multiq", },
	[28] = { .type = YNL_PT_SUBMSG, .name = "netem", .nest = &tc_netem_attrs_nest, },
	[29] = { .type = YNL_PT_SUBMSG, .name = "pfifo", },
	[30] = { .type = YNL_PT_SUBMSG, .name = "pfifo_fast", },
	[31] = { .type = YNL_PT_SUBMSG, .name = "pfifo_head_drop", },
	[32] = { .type = YNL_PT_SUBMSG, .name = "pie", .nest = &tc_pie_attrs_nest, },
	[33] = { .type = YNL_PT_SUBMSG, .name = "plug", },
	[34] = { .type = YNL_PT_SUBMSG, .name = "prio", },
	[35] = { .type = YNL_PT_SUBMSG, .name = "qfq", .nest = &tc_qfq_attrs_nest, },
	[36] = { .type = YNL_PT_SUBMSG, .name = "red", .nest = &tc_red_attrs_nest, },
	[37] = { .type = YNL_PT_SUBMSG, .name = "route", .nest = &tc_route_attrs_nest, },
	[38] = { .type = YNL_PT_SUBMSG, .name = "sfb", },
	[39] = { .type = YNL_PT_SUBMSG, .name = "sfq", },
	[40] = { .type = YNL_PT_SUBMSG, .name = "taprio", .nest = &tc_taprio_attrs_nest, },
	[41] = { .type = YNL_PT_SUBMSG, .name = "tbf", .nest = &tc_tbf_attrs_nest, },
	[42] = { .type = YNL_PT_SUBMSG, .name = "u32", .nest = &tc_u32_attrs_nest, },
};

const struct ynl_policy_nest tc_options_msg_nest = {
	.max_attr = 42,
	.table = tc_options_msg_policy,
};

const struct ynl_policy_attr tc_attrs_policy[TCA_MAX + 1] = {
	[TCA_KIND] = { .name = "kind", .type = YNL_PT_NUL_STR, .is_selector = 1, },
	[TCA_OPTIONS] = { .name = "options", .type = YNL_PT_NEST, .nest = &tc_options_msg_nest, .is_submsg = 1, .selector_type = 1 },
	[TCA_STATS] = { .name = "stats", .type = YNL_PT_BINARY,},
	[TCA_XSTATS] = { .name = "xstats", .type = YNL_PT_NEST, .nest = &tc_tca_stats_app_msg_nest, .is_submsg = 1, .selector_type = 1 },
	[TCA_RATE] = { .name = "rate", .type = YNL_PT_BINARY,},
	[TCA_FCNT] = { .name = "fcnt", .type = YNL_PT_U32, },
	[TCA_STATS2] = { .name = "stats2", .type = YNL_PT_NEST, .nest = &tc_tca_stats_attrs_nest, },
	[TCA_STAB] = { .name = "stab", .type = YNL_PT_NEST, .nest = &tc_tca_stab_attrs_nest, },
	[TCA_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[TCA_DUMP_INVISIBLE] = { .name = "dump-invisible", .type = YNL_PT_FLAG, },
	[TCA_CHAIN] = { .name = "chain", .type = YNL_PT_U32, },
	[TCA_HW_OFFLOAD] = { .name = "hw-offload", .type = YNL_PT_U8, },
	[TCA_INGRESS_BLOCK] = { .name = "ingress-block", .type = YNL_PT_U32, },
	[TCA_EGRESS_BLOCK] = { .name = "egress-block", .type = YNL_PT_U32, },
	[TCA_DUMP_FLAGS] = { .name = "dump-flags", .type = YNL_PT_BITFIELD32, },
	[TCA_EXT_WARN_MSG] = { .name = "ext-warn-msg", .type = YNL_PT_NUL_STR, },
};

const struct ynl_policy_nest tc_attrs_nest = {
	.max_attr = TCA_MAX,
	.table = tc_attrs_policy,
};

/* Common nested types */
void tc_tca_stab_attrs_free(struct tc_tca_stab_attrs *obj);
int tc_tca_stab_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
void tc_cake_attrs_free(struct tc_cake_attrs *obj);
int tc_cake_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		      struct tc_cake_attrs *obj);
int tc_cake_attrs_parse(struct ynl_parse_arg *yarg,
			const struct nlattr *nested);
void tc_cbs_attrs_free(struct tc_cbs_attrs *obj);
int tc_cbs_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_cbs_attrs *obj);
int tc_cbs_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_choke_attrs_free(struct tc_choke_attrs *obj);
int tc_choke_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_choke_attrs *obj);
int tc_choke_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested);
void tc_codel_attrs_free(struct tc_codel_attrs *obj);
int tc_codel_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_codel_attrs *obj);
int tc_codel_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested);
void tc_drr_attrs_free(struct tc_drr_attrs *obj);
int tc_drr_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_drr_attrs *obj);
int tc_drr_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_dualpi2_attrs_free(struct tc_dualpi2_attrs *obj);
int tc_dualpi2_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct tc_dualpi2_attrs *obj);
int tc_dualpi2_attrs_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested);
void tc_etf_attrs_free(struct tc_etf_attrs *obj);
int tc_etf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_etf_attrs *obj);
int tc_etf_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_fq_attrs_free(struct tc_fq_attrs *obj);
int tc_fq_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		    struct tc_fq_attrs *obj);
int tc_fq_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_fq_codel_attrs_free(struct tc_fq_codel_attrs *obj);
int tc_fq_codel_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_fq_codel_attrs *obj);
int tc_fq_codel_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
void tc_fq_pie_attrs_free(struct tc_fq_pie_attrs *obj);
int tc_fq_pie_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_fq_pie_attrs *obj);
int tc_fq_pie_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested);
void tc_hhf_attrs_free(struct tc_hhf_attrs *obj);
int tc_hhf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_hhf_attrs *obj);
int tc_hhf_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_htb_attrs_free(struct tc_htb_attrs *obj);
int tc_htb_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_htb_attrs *obj);
int tc_htb_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_pie_attrs_free(struct tc_pie_attrs *obj);
int tc_pie_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_pie_attrs *obj);
int tc_pie_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_qfq_attrs_free(struct tc_qfq_attrs *obj);
int tc_qfq_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_qfq_attrs *obj);
int tc_qfq_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_red_attrs_free(struct tc_red_attrs *obj);
int tc_red_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_red_attrs *obj);
int tc_red_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_tbf_attrs_free(struct tc_tbf_attrs *obj);
int tc_tbf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_tbf_attrs *obj);
int tc_tbf_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_ematch_attrs_free(struct tc_ematch_attrs *obj);
int tc_ematch_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_ematch_attrs *obj);
int tc_ematch_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested);
void tc_police_attrs_free(struct tc_police_attrs *obj);
int tc_police_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_police_attrs *obj);
int tc_police_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested);
void
tc_flower_key_mpls_opt_attrs_free(struct tc_flower_key_mpls_opt_attrs *obj);
int tc_flower_key_mpls_opt_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     struct tc_flower_key_mpls_opt_attrs *obj);
int tc_flower_key_mpls_opt_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested);
void tc_flower_key_cfm_attrs_free(struct tc_flower_key_cfm_attrs *obj);
int tc_flower_key_cfm_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				struct tc_flower_key_cfm_attrs *obj);
int tc_flower_key_cfm_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested);
void tc_netem_loss_attrs_free(struct tc_netem_loss_attrs *obj);
int tc_netem_loss_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_netem_loss_attrs *obj);
int tc_netem_loss_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested);
void tc_taprio_sched_entry_free(struct tc_taprio_sched_entry *obj);
int tc_taprio_sched_entry_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct tc_taprio_sched_entry *obj);
int tc_taprio_sched_entry_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested);
void tc_taprio_tc_entry_attrs_free(struct tc_taprio_tc_entry_attrs *obj);
int tc_taprio_tc_entry_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 struct tc_taprio_tc_entry_attrs *obj);
int tc_taprio_tc_entry_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested);
void tc_cake_tin_stats_attrs_free(struct tc_cake_tin_stats_attrs *obj);
int tc_cake_tin_stats_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				struct tc_cake_tin_stats_attrs *obj);
int tc_cake_tin_stats_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested, __u32 idx);
void
tc_flower_key_enc_opt_geneve_attrs_free(struct tc_flower_key_enc_opt_geneve_attrs *obj);
int tc_flower_key_enc_opt_geneve_attrs_put(struct nlmsghdr *nlh,
					   unsigned int attr_type,
					   struct tc_flower_key_enc_opt_geneve_attrs *obj);
int tc_flower_key_enc_opt_geneve_attrs_parse(struct ynl_parse_arg *yarg,
					     const struct nlattr *nested);
void
tc_flower_key_enc_opt_vxlan_attrs_free(struct tc_flower_key_enc_opt_vxlan_attrs *obj);
int tc_flower_key_enc_opt_vxlan_attrs_put(struct nlmsghdr *nlh,
					  unsigned int attr_type,
					  struct tc_flower_key_enc_opt_vxlan_attrs *obj);
int tc_flower_key_enc_opt_vxlan_attrs_parse(struct ynl_parse_arg *yarg,
					    const struct nlattr *nested);
void
tc_flower_key_enc_opt_erspan_attrs_free(struct tc_flower_key_enc_opt_erspan_attrs *obj);
int tc_flower_key_enc_opt_erspan_attrs_put(struct nlmsghdr *nlh,
					   unsigned int attr_type,
					   struct tc_flower_key_enc_opt_erspan_attrs *obj);
int tc_flower_key_enc_opt_erspan_attrs_parse(struct ynl_parse_arg *yarg,
					     const struct nlattr *nested);
void
tc_flower_key_enc_opt_gtp_attrs_free(struct tc_flower_key_enc_opt_gtp_attrs *obj);
int tc_flower_key_enc_opt_gtp_attrs_put(struct nlmsghdr *nlh,
					unsigned int attr_type,
					struct tc_flower_key_enc_opt_gtp_attrs *obj);
int tc_flower_key_enc_opt_gtp_attrs_parse(struct ynl_parse_arg *yarg,
					  const struct nlattr *nested);
void tc_tca_gred_vq_entry_attrs_free(struct tc_tca_gred_vq_entry_attrs *obj);
int tc_tca_gred_vq_entry_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct tc_tca_gred_vq_entry_attrs *obj);
int tc_tca_gred_vq_entry_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested);
void tc_act_bpf_attrs_free(struct tc_act_bpf_attrs *obj);
int tc_act_bpf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct tc_act_bpf_attrs *obj);
int tc_act_bpf_attrs_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested);
void tc_act_connmark_attrs_free(struct tc_act_connmark_attrs *obj);
int tc_act_connmark_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct tc_act_connmark_attrs *obj);
int tc_act_connmark_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested);
void tc_act_csum_attrs_free(struct tc_act_csum_attrs *obj);
int tc_act_csum_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_csum_attrs *obj);
int tc_act_csum_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
void tc_act_ct_attrs_free(struct tc_act_ct_attrs *obj);
int tc_act_ct_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_act_ct_attrs *obj);
int tc_act_ct_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested);
void tc_act_ctinfo_attrs_free(struct tc_act_ctinfo_attrs *obj);
int tc_act_ctinfo_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_ctinfo_attrs *obj);
int tc_act_ctinfo_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested);
void tc_act_gact_attrs_free(struct tc_act_gact_attrs *obj);
int tc_act_gact_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_gact_attrs *obj);
int tc_act_gact_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
void tc_act_gate_attrs_free(struct tc_act_gate_attrs *obj);
int tc_act_gate_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_gate_attrs *obj);
int tc_act_gate_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
void tc_act_ife_attrs_free(struct tc_act_ife_attrs *obj);
int tc_act_ife_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct tc_act_ife_attrs *obj);
int tc_act_ife_attrs_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested);
void tc_act_mirred_attrs_free(struct tc_act_mirred_attrs *obj);
int tc_act_mirred_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_mirred_attrs *obj);
int tc_act_mirred_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested);
void tc_act_mpls_attrs_free(struct tc_act_mpls_attrs *obj);
int tc_act_mpls_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_mpls_attrs *obj);
int tc_act_mpls_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
void tc_act_nat_attrs_free(struct tc_act_nat_attrs *obj);
int tc_act_nat_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct tc_act_nat_attrs *obj);
int tc_act_nat_attrs_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested);
void tc_act_pedit_attrs_free(struct tc_act_pedit_attrs *obj);
int tc_act_pedit_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct tc_act_pedit_attrs *obj);
int tc_act_pedit_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested);
void tc_act_sample_attrs_free(struct tc_act_sample_attrs *obj);
int tc_act_sample_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_sample_attrs *obj);
int tc_act_sample_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested);
void tc_act_simple_attrs_free(struct tc_act_simple_attrs *obj);
int tc_act_simple_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_simple_attrs *obj);
int tc_act_simple_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested);
void tc_act_skbedit_attrs_free(struct tc_act_skbedit_attrs *obj);
int tc_act_skbedit_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     struct tc_act_skbedit_attrs *obj);
int tc_act_skbedit_attrs_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested);
void tc_act_skbmod_attrs_free(struct tc_act_skbmod_attrs *obj);
int tc_act_skbmod_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_skbmod_attrs *obj);
int tc_act_skbmod_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested);
void tc_act_tunnel_key_attrs_free(struct tc_act_tunnel_key_attrs *obj);
int tc_act_tunnel_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				struct tc_act_tunnel_key_attrs *obj);
int tc_act_tunnel_key_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested);
void tc_act_vlan_attrs_free(struct tc_act_vlan_attrs *obj);
int tc_act_vlan_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_vlan_attrs *obj);
int tc_act_vlan_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
void tc_flow_attrs_free(struct tc_flow_attrs *obj);
int tc_flow_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		      struct tc_flow_attrs *obj);
int tc_flow_attrs_parse(struct ynl_parse_arg *yarg,
			const struct nlattr *nested);
void tc_netem_attrs_free(struct tc_netem_attrs *obj);
int tc_netem_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_netem_attrs *obj);
int tc_netem_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested);
void tc_cake_stats_attrs_free(struct tc_cake_stats_attrs *obj);
int tc_cake_stats_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_cake_stats_attrs *obj);
int tc_cake_stats_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested);
void
tc_flower_key_enc_opts_attrs_free(struct tc_flower_key_enc_opts_attrs *obj);
int tc_flower_key_enc_opts_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     struct tc_flower_key_enc_opts_attrs *obj);
int tc_flower_key_enc_opts_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested);
void tc_tca_gred_vq_list_attrs_free(struct tc_tca_gred_vq_list_attrs *obj);
int tc_tca_gred_vq_list_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  struct tc_tca_gred_vq_list_attrs *obj);
int tc_tca_gred_vq_list_attrs_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested);
void tc_taprio_sched_entry_list_free(struct tc_taprio_sched_entry_list *obj);
int tc_taprio_sched_entry_list_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct tc_taprio_sched_entry_list *obj);
int tc_taprio_sched_entry_list_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested);
void tc_act_options_msg_free(struct tc_act_options_msg *obj);
int tc_act_options_msg_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct tc_act_options_msg *obj);
int tc_act_options_msg_parse(struct ynl_parse_arg *yarg, const char *sel,
			     const struct nlattr *nested);
void tc_tca_stats_app_msg_free(struct tc_tca_stats_app_msg *obj);
int tc_tca_stats_app_msg_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     struct tc_tca_stats_app_msg *obj);
int tc_tca_stats_app_msg_parse(struct ynl_parse_arg *yarg, const char *sel,
			       const struct nlattr *nested);
void tc_tca_stats_attrs_free(struct tc_tca_stats_attrs *obj);
int tc_tca_stats_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct tc_tca_stats_attrs *obj);
int tc_tca_stats_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested,
			     const char *_sel_kind);
void tc_gred_attrs_free(struct tc_gred_attrs *obj);
int tc_gred_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		      struct tc_gred_attrs *obj);
int tc_gred_attrs_parse(struct ynl_parse_arg *yarg,
			const struct nlattr *nested);
void tc_taprio_attrs_free(struct tc_taprio_attrs *obj);
int tc_taprio_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_taprio_attrs *obj);
int tc_taprio_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested);
void tc_act_attrs_free(struct tc_act_attrs *obj);
int tc_act_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_act_attrs *obj);
int tc_act_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested,
		       __u32 idx);
void tc_basic_attrs_free(struct tc_basic_attrs *obj);
int tc_basic_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_basic_attrs *obj);
int tc_basic_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested);
void tc_bpf_attrs_free(struct tc_bpf_attrs *obj);
int tc_bpf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_bpf_attrs *obj);
int tc_bpf_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_cgroup_attrs_free(struct tc_cgroup_attrs *obj);
int tc_cgroup_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_cgroup_attrs *obj);
int tc_cgroup_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested);
void tc_flower_attrs_free(struct tc_flower_attrs *obj);
int tc_flower_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_flower_attrs *obj);
int tc_flower_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested);
void tc_fw_attrs_free(struct tc_fw_attrs *obj);
int tc_fw_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		    struct tc_fw_attrs *obj);
int tc_fw_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_matchall_attrs_free(struct tc_matchall_attrs *obj);
int tc_matchall_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_matchall_attrs *obj);
int tc_matchall_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
void tc_route_attrs_free(struct tc_route_attrs *obj);
int tc_route_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_route_attrs *obj);
int tc_route_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested);
void tc_u32_attrs_free(struct tc_u32_attrs *obj);
int tc_u32_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_u32_attrs *obj);
int tc_u32_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_ets_attrs_free(struct tc_ets_attrs *obj);
int tc_ets_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_ets_attrs *obj);
int tc_ets_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested);
void tc_options_msg_free(struct tc_options_msg *obj);
int tc_options_msg_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_options_msg *obj);
int tc_options_msg_parse(struct ynl_parse_arg *yarg, const char *sel,
			 const struct nlattr *nested);

void tc_tca_stab_attrs_free(struct tc_tca_stab_attrs *obj)
{
	free(obj->base);
	free(obj->data);
}

int tc_tca_stab_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct tc_tca_stab_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_STAB_BASE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.base = len;
			if (len < sizeof(struct tc_sizespec))
				dst->base = calloc(1, sizeof(struct tc_sizespec));
			else
				dst->base = malloc(len);
			memcpy(dst->base, ynl_attr_data(attr), len);
		} else if (type == TCA_STAB_DATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.data = len;
			dst->data = malloc(len);
			memcpy(dst->data, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_cake_attrs_free(struct tc_cake_attrs *obj)
{
}

int tc_cake_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		      struct tc_cake_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.base_rate64)
		ynl_attr_put_u64(nlh, TCA_CAKE_BASE_RATE64, obj->base_rate64);
	if (obj->_present.diffserv_mode)
		ynl_attr_put_u32(nlh, TCA_CAKE_DIFFSERV_MODE, obj->diffserv_mode);
	if (obj->_present.atm)
		ynl_attr_put_u32(nlh, TCA_CAKE_ATM, obj->atm);
	if (obj->_present.flow_mode)
		ynl_attr_put_u32(nlh, TCA_CAKE_FLOW_MODE, obj->flow_mode);
	if (obj->_present.overhead)
		ynl_attr_put_u32(nlh, TCA_CAKE_OVERHEAD, obj->overhead);
	if (obj->_present.rtt)
		ynl_attr_put_u32(nlh, TCA_CAKE_RTT, obj->rtt);
	if (obj->_present.target)
		ynl_attr_put_u32(nlh, TCA_CAKE_TARGET, obj->target);
	if (obj->_present.autorate)
		ynl_attr_put_u32(nlh, TCA_CAKE_AUTORATE, obj->autorate);
	if (obj->_present.memory)
		ynl_attr_put_u32(nlh, TCA_CAKE_MEMORY, obj->memory);
	if (obj->_present.nat)
		ynl_attr_put_u32(nlh, TCA_CAKE_NAT, obj->nat);
	if (obj->_present.raw)
		ynl_attr_put_u32(nlh, TCA_CAKE_RAW, obj->raw);
	if (obj->_present.wash)
		ynl_attr_put_u32(nlh, TCA_CAKE_WASH, obj->wash);
	if (obj->_present.mpu)
		ynl_attr_put_u32(nlh, TCA_CAKE_MPU, obj->mpu);
	if (obj->_present.ingress)
		ynl_attr_put_u32(nlh, TCA_CAKE_INGRESS, obj->ingress);
	if (obj->_present.ack_filter)
		ynl_attr_put_u32(nlh, TCA_CAKE_ACK_FILTER, obj->ack_filter);
	if (obj->_present.split_gso)
		ynl_attr_put_u32(nlh, TCA_CAKE_SPLIT_GSO, obj->split_gso);
	if (obj->_present.fwmark)
		ynl_attr_put_u32(nlh, TCA_CAKE_FWMARK, obj->fwmark);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_cake_attrs_parse(struct ynl_parse_arg *yarg,
			const struct nlattr *nested)
{
	struct tc_cake_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CAKE_BASE_RATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.base_rate64 = 1;
			dst->base_rate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_CAKE_DIFFSERV_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.diffserv_mode = 1;
			dst->diffserv_mode = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_ATM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.atm = 1;
			dst->atm = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_FLOW_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flow_mode = 1;
			dst->flow_mode = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_OVERHEAD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.overhead = 1;
			dst->overhead = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_RTT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rtt = 1;
			dst->rtt = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TARGET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.target = 1;
			dst->target = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_AUTORATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.autorate = 1;
			dst->autorate = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_MEMORY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.memory = 1;
			dst->memory = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_NAT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nat = 1;
			dst->nat = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_RAW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.raw = 1;
			dst->raw = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_WASH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.wash = 1;
			dst->wash = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_MPU) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mpu = 1;
			dst->mpu = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_INGRESS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ingress = 1;
			dst->ingress = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_ACK_FILTER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ack_filter = 1;
			dst->ack_filter = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_SPLIT_GSO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.split_gso = 1;
			dst->split_gso = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_FWMARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fwmark = 1;
			dst->fwmark = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_cbs_attrs_free(struct tc_cbs_attrs *obj)
{
	free(obj->parms);
}

int tc_cbs_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_cbs_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_CBS_PARMS, obj->parms, obj->_len.parms);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_cbs_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_cbs_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CBS_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_cbs_qopt))
				dst->parms = calloc(1, sizeof(struct tc_cbs_qopt));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_choke_attrs_free(struct tc_choke_attrs *obj)
{
	free(obj->parms);
	free(obj->stab);
}

int tc_choke_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_choke_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_CHOKE_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.stab)
		ynl_attr_put(nlh, TCA_CHOKE_STAB, obj->stab, obj->_len.stab);
	if (obj->_present.max_p)
		ynl_attr_put_u32(nlh, TCA_CHOKE_MAX_P, obj->max_p);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_choke_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	struct tc_choke_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CHOKE_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_red_qopt))
				dst->parms = calloc(1, sizeof(struct tc_red_qopt));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_CHOKE_STAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stab = len;
			dst->stab = malloc(len);
			memcpy(dst->stab, ynl_attr_data(attr), len);
		} else if (type == TCA_CHOKE_MAX_P) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_p = 1;
			dst->max_p = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_codel_attrs_free(struct tc_codel_attrs *obj)
{
}

int tc_codel_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_codel_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.target)
		ynl_attr_put_u32(nlh, TCA_CODEL_TARGET, obj->target);
	if (obj->_present.limit)
		ynl_attr_put_u32(nlh, TCA_CODEL_LIMIT, obj->limit);
	if (obj->_present.interval)
		ynl_attr_put_u32(nlh, TCA_CODEL_INTERVAL, obj->interval);
	if (obj->_present.ecn)
		ynl_attr_put_u32(nlh, TCA_CODEL_ECN, obj->ecn);
	if (obj->_present.ce_threshold)
		ynl_attr_put_u32(nlh, TCA_CODEL_CE_THRESHOLD, obj->ce_threshold);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_codel_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	struct tc_codel_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CODEL_TARGET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.target = 1;
			dst->target = ynl_attr_get_u32(attr);
		} else if (type == TCA_CODEL_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.limit = 1;
			dst->limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_CODEL_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.interval = 1;
			dst->interval = ynl_attr_get_u32(attr);
		} else if (type == TCA_CODEL_ECN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn = 1;
			dst->ecn = ynl_attr_get_u32(attr);
		} else if (type == TCA_CODEL_CE_THRESHOLD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ce_threshold = 1;
			dst->ce_threshold = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_drr_attrs_free(struct tc_drr_attrs *obj)
{
}

int tc_drr_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_drr_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.quantum)
		ynl_attr_put_u32(nlh, TCA_DRR_QUANTUM, obj->quantum);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_drr_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_drr_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_DRR_QUANTUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.quantum = 1;
			dst->quantum = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_dualpi2_attrs_free(struct tc_dualpi2_attrs *obj)
{
}

int tc_dualpi2_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct tc_dualpi2_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.limit)
		ynl_attr_put_u32(nlh, TCA_DUALPI2_LIMIT, obj->limit);
	if (obj->_present.memory_limit)
		ynl_attr_put_u32(nlh, TCA_DUALPI2_MEMORY_LIMIT, obj->memory_limit);
	if (obj->_present.target)
		ynl_attr_put_u32(nlh, TCA_DUALPI2_TARGET, obj->target);
	if (obj->_present.tupdate)
		ynl_attr_put_u32(nlh, TCA_DUALPI2_TUPDATE, obj->tupdate);
	if (obj->_present.alpha)
		ynl_attr_put_u32(nlh, TCA_DUALPI2_ALPHA, obj->alpha);
	if (obj->_present.beta)
		ynl_attr_put_u32(nlh, TCA_DUALPI2_BETA, obj->beta);
	if (obj->_present.step_thresh_pkts)
		ynl_attr_put_u32(nlh, TCA_DUALPI2_STEP_THRESH_PKTS, obj->step_thresh_pkts);
	if (obj->_present.step_thresh_us)
		ynl_attr_put_u32(nlh, TCA_DUALPI2_STEP_THRESH_US, obj->step_thresh_us);
	if (obj->_present.min_qlen_step)
		ynl_attr_put_u32(nlh, TCA_DUALPI2_MIN_QLEN_STEP, obj->min_qlen_step);
	if (obj->_present.coupling)
		ynl_attr_put_u8(nlh, TCA_DUALPI2_COUPLING, obj->coupling);
	if (obj->_present.drop_overload)
		ynl_attr_put_u8(nlh, TCA_DUALPI2_DROP_OVERLOAD, obj->drop_overload);
	if (obj->_present.drop_early)
		ynl_attr_put_u8(nlh, TCA_DUALPI2_DROP_EARLY, obj->drop_early);
	if (obj->_present.c_protection)
		ynl_attr_put_u8(nlh, TCA_DUALPI2_C_PROTECTION, obj->c_protection);
	if (obj->_present.ecn_mask)
		ynl_attr_put_u8(nlh, TCA_DUALPI2_ECN_MASK, obj->ecn_mask);
	if (obj->_present.split_gso)
		ynl_attr_put_u8(nlh, TCA_DUALPI2_SPLIT_GSO, obj->split_gso);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_dualpi2_attrs_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	struct tc_dualpi2_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_DUALPI2_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.limit = 1;
			dst->limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_DUALPI2_MEMORY_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.memory_limit = 1;
			dst->memory_limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_DUALPI2_TARGET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.target = 1;
			dst->target = ynl_attr_get_u32(attr);
		} else if (type == TCA_DUALPI2_TUPDATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tupdate = 1;
			dst->tupdate = ynl_attr_get_u32(attr);
		} else if (type == TCA_DUALPI2_ALPHA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.alpha = 1;
			dst->alpha = ynl_attr_get_u32(attr);
		} else if (type == TCA_DUALPI2_BETA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.beta = 1;
			dst->beta = ynl_attr_get_u32(attr);
		} else if (type == TCA_DUALPI2_STEP_THRESH_PKTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.step_thresh_pkts = 1;
			dst->step_thresh_pkts = ynl_attr_get_u32(attr);
		} else if (type == TCA_DUALPI2_STEP_THRESH_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.step_thresh_us = 1;
			dst->step_thresh_us = ynl_attr_get_u32(attr);
		} else if (type == TCA_DUALPI2_MIN_QLEN_STEP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.min_qlen_step = 1;
			dst->min_qlen_step = ynl_attr_get_u32(attr);
		} else if (type == TCA_DUALPI2_COUPLING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.coupling = 1;
			dst->coupling = ynl_attr_get_u8(attr);
		} else if (type == TCA_DUALPI2_DROP_OVERLOAD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.drop_overload = 1;
			dst->drop_overload = ynl_attr_get_u8(attr);
		} else if (type == TCA_DUALPI2_DROP_EARLY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.drop_early = 1;
			dst->drop_early = ynl_attr_get_u8(attr);
		} else if (type == TCA_DUALPI2_C_PROTECTION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.c_protection = 1;
			dst->c_protection = ynl_attr_get_u8(attr);
		} else if (type == TCA_DUALPI2_ECN_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn_mask = 1;
			dst->ecn_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_DUALPI2_SPLIT_GSO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.split_gso = 1;
			dst->split_gso = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void tc_etf_attrs_free(struct tc_etf_attrs *obj)
{
	free(obj->parms);
}

int tc_etf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_etf_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_ETF_PARMS, obj->parms, obj->_len.parms);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_etf_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_etf_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_ETF_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_etf_qopt))
				dst->parms = calloc(1, sizeof(struct tc_etf_qopt));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_fq_attrs_free(struct tc_fq_attrs *obj)
{
	free(obj->priomap);
	free(obj->weights);
}

int tc_fq_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		    struct tc_fq_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.plimit)
		ynl_attr_put_u32(nlh, TCA_FQ_PLIMIT, obj->plimit);
	if (obj->_present.flow_plimit)
		ynl_attr_put_u32(nlh, TCA_FQ_FLOW_PLIMIT, obj->flow_plimit);
	if (obj->_present.quantum)
		ynl_attr_put_u32(nlh, TCA_FQ_QUANTUM, obj->quantum);
	if (obj->_present.initial_quantum)
		ynl_attr_put_u32(nlh, TCA_FQ_INITIAL_QUANTUM, obj->initial_quantum);
	if (obj->_present.rate_enable)
		ynl_attr_put_u32(nlh, TCA_FQ_RATE_ENABLE, obj->rate_enable);
	if (obj->_present.flow_default_rate)
		ynl_attr_put_u32(nlh, TCA_FQ_FLOW_DEFAULT_RATE, obj->flow_default_rate);
	if (obj->_present.flow_max_rate)
		ynl_attr_put_u32(nlh, TCA_FQ_FLOW_MAX_RATE, obj->flow_max_rate);
	if (obj->_present.buckets_log)
		ynl_attr_put_u32(nlh, TCA_FQ_BUCKETS_LOG, obj->buckets_log);
	if (obj->_present.flow_refill_delay)
		ynl_attr_put_u32(nlh, TCA_FQ_FLOW_REFILL_DELAY, obj->flow_refill_delay);
	if (obj->_present.orphan_mask)
		ynl_attr_put_u32(nlh, TCA_FQ_ORPHAN_MASK, obj->orphan_mask);
	if (obj->_present.low_rate_threshold)
		ynl_attr_put_u32(nlh, TCA_FQ_LOW_RATE_THRESHOLD, obj->low_rate_threshold);
	if (obj->_present.ce_threshold)
		ynl_attr_put_u32(nlh, TCA_FQ_CE_THRESHOLD, obj->ce_threshold);
	if (obj->_present.timer_slack)
		ynl_attr_put_u32(nlh, TCA_FQ_TIMER_SLACK, obj->timer_slack);
	if (obj->_present.horizon)
		ynl_attr_put_u32(nlh, TCA_FQ_HORIZON, obj->horizon);
	if (obj->_present.horizon_drop)
		ynl_attr_put_u8(nlh, TCA_FQ_HORIZON_DROP, obj->horizon_drop);
	if (obj->_len.priomap)
		ynl_attr_put(nlh, TCA_FQ_PRIOMAP, obj->priomap, obj->_len.priomap);
	if (obj->_count.weights) {
		i = obj->_count.weights * sizeof(__s32);
		ynl_attr_put(nlh, TCA_FQ_WEIGHTS, obj->weights, i);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_fq_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_fq_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FQ_PLIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.plimit = 1;
			dst->plimit = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_FLOW_PLIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flow_plimit = 1;
			dst->flow_plimit = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_QUANTUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.quantum = 1;
			dst->quantum = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_INITIAL_QUANTUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.initial_quantum = 1;
			dst->initial_quantum = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_RATE_ENABLE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rate_enable = 1;
			dst->rate_enable = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_FLOW_DEFAULT_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flow_default_rate = 1;
			dst->flow_default_rate = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_FLOW_MAX_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flow_max_rate = 1;
			dst->flow_max_rate = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_BUCKETS_LOG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.buckets_log = 1;
			dst->buckets_log = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_FLOW_REFILL_DELAY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flow_refill_delay = 1;
			dst->flow_refill_delay = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_ORPHAN_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.orphan_mask = 1;
			dst->orphan_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_LOW_RATE_THRESHOLD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.low_rate_threshold = 1;
			dst->low_rate_threshold = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CE_THRESHOLD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ce_threshold = 1;
			dst->ce_threshold = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_TIMER_SLACK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.timer_slack = 1;
			dst->timer_slack = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_HORIZON) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.horizon = 1;
			dst->horizon = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_HORIZON_DROP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.horizon_drop = 1;
			dst->horizon_drop = ynl_attr_get_u8(attr);
		} else if (type == TCA_FQ_PRIOMAP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.priomap = len;
			if (len < sizeof(struct tc_prio_qopt))
				dst->priomap = calloc(1, sizeof(struct tc_prio_qopt));
			else
				dst->priomap = malloc(len);
			memcpy(dst->priomap, ynl_attr_data(attr), len);
		} else if (type == TCA_FQ_WEIGHTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.weights = len / sizeof(__s32);
			len = dst->_count.weights * sizeof(__s32);
			dst->weights = malloc(len);
			memcpy(dst->weights, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_fq_codel_attrs_free(struct tc_fq_codel_attrs *obj)
{
}

int tc_fq_codel_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_fq_codel_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.target)
		ynl_attr_put_u32(nlh, TCA_FQ_CODEL_TARGET, obj->target);
	if (obj->_present.limit)
		ynl_attr_put_u32(nlh, TCA_FQ_CODEL_LIMIT, obj->limit);
	if (obj->_present.interval)
		ynl_attr_put_u32(nlh, TCA_FQ_CODEL_INTERVAL, obj->interval);
	if (obj->_present.ecn)
		ynl_attr_put_u32(nlh, TCA_FQ_CODEL_ECN, obj->ecn);
	if (obj->_present.flows)
		ynl_attr_put_u32(nlh, TCA_FQ_CODEL_FLOWS, obj->flows);
	if (obj->_present.quantum)
		ynl_attr_put_u32(nlh, TCA_FQ_CODEL_QUANTUM, obj->quantum);
	if (obj->_present.ce_threshold)
		ynl_attr_put_u32(nlh, TCA_FQ_CODEL_CE_THRESHOLD, obj->ce_threshold);
	if (obj->_present.drop_batch_size)
		ynl_attr_put_u32(nlh, TCA_FQ_CODEL_DROP_BATCH_SIZE, obj->drop_batch_size);
	if (obj->_present.memory_limit)
		ynl_attr_put_u32(nlh, TCA_FQ_CODEL_MEMORY_LIMIT, obj->memory_limit);
	if (obj->_present.ce_threshold_selector)
		ynl_attr_put_u8(nlh, TCA_FQ_CODEL_CE_THRESHOLD_SELECTOR, obj->ce_threshold_selector);
	if (obj->_present.ce_threshold_mask)
		ynl_attr_put_u8(nlh, TCA_FQ_CODEL_CE_THRESHOLD_MASK, obj->ce_threshold_mask);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_fq_codel_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct tc_fq_codel_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FQ_CODEL_TARGET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.target = 1;
			dst->target = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CODEL_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.limit = 1;
			dst->limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CODEL_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.interval = 1;
			dst->interval = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CODEL_ECN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn = 1;
			dst->ecn = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CODEL_FLOWS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flows = 1;
			dst->flows = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CODEL_QUANTUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.quantum = 1;
			dst->quantum = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CODEL_CE_THRESHOLD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ce_threshold = 1;
			dst->ce_threshold = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CODEL_DROP_BATCH_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.drop_batch_size = 1;
			dst->drop_batch_size = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CODEL_MEMORY_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.memory_limit = 1;
			dst->memory_limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_CODEL_CE_THRESHOLD_SELECTOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ce_threshold_selector = 1;
			dst->ce_threshold_selector = ynl_attr_get_u8(attr);
		} else if (type == TCA_FQ_CODEL_CE_THRESHOLD_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ce_threshold_mask = 1;
			dst->ce_threshold_mask = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void tc_fq_pie_attrs_free(struct tc_fq_pie_attrs *obj)
{
}

int tc_fq_pie_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_fq_pie_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.limit)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_LIMIT, obj->limit);
	if (obj->_present.flows)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_FLOWS, obj->flows);
	if (obj->_present.target)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_TARGET, obj->target);
	if (obj->_present.tupdate)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_TUPDATE, obj->tupdate);
	if (obj->_present.alpha)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_ALPHA, obj->alpha);
	if (obj->_present.beta)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_BETA, obj->beta);
	if (obj->_present.quantum)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_QUANTUM, obj->quantum);
	if (obj->_present.memory_limit)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_MEMORY_LIMIT, obj->memory_limit);
	if (obj->_present.ecn_prob)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_ECN_PROB, obj->ecn_prob);
	if (obj->_present.ecn)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_ECN, obj->ecn);
	if (obj->_present.bytemode)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_BYTEMODE, obj->bytemode);
	if (obj->_present.dq_rate_estimator)
		ynl_attr_put_u32(nlh, TCA_FQ_PIE_DQ_RATE_ESTIMATOR, obj->dq_rate_estimator);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_fq_pie_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	struct tc_fq_pie_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FQ_PIE_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.limit = 1;
			dst->limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_FLOWS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flows = 1;
			dst->flows = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_TARGET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.target = 1;
			dst->target = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_TUPDATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tupdate = 1;
			dst->tupdate = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_ALPHA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.alpha = 1;
			dst->alpha = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_BETA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.beta = 1;
			dst->beta = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_QUANTUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.quantum = 1;
			dst->quantum = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_MEMORY_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.memory_limit = 1;
			dst->memory_limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_ECN_PROB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn_prob = 1;
			dst->ecn_prob = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_ECN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn = 1;
			dst->ecn = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_BYTEMODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bytemode = 1;
			dst->bytemode = ynl_attr_get_u32(attr);
		} else if (type == TCA_FQ_PIE_DQ_RATE_ESTIMATOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dq_rate_estimator = 1;
			dst->dq_rate_estimator = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_hhf_attrs_free(struct tc_hhf_attrs *obj)
{
}

int tc_hhf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_hhf_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.backlog_limit)
		ynl_attr_put_u32(nlh, TCA_HHF_BACKLOG_LIMIT, obj->backlog_limit);
	if (obj->_present.quantum)
		ynl_attr_put_u32(nlh, TCA_HHF_QUANTUM, obj->quantum);
	if (obj->_present.hh_flows_limit)
		ynl_attr_put_u32(nlh, TCA_HHF_HH_FLOWS_LIMIT, obj->hh_flows_limit);
	if (obj->_present.reset_timeout)
		ynl_attr_put_u32(nlh, TCA_HHF_RESET_TIMEOUT, obj->reset_timeout);
	if (obj->_present.admit_bytes)
		ynl_attr_put_u32(nlh, TCA_HHF_ADMIT_BYTES, obj->admit_bytes);
	if (obj->_present.evict_timeout)
		ynl_attr_put_u32(nlh, TCA_HHF_EVICT_TIMEOUT, obj->evict_timeout);
	if (obj->_present.non_hh_weight)
		ynl_attr_put_u32(nlh, TCA_HHF_NON_HH_WEIGHT, obj->non_hh_weight);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_hhf_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_hhf_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_HHF_BACKLOG_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.backlog_limit = 1;
			dst->backlog_limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_HHF_QUANTUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.quantum = 1;
			dst->quantum = ynl_attr_get_u32(attr);
		} else if (type == TCA_HHF_HH_FLOWS_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hh_flows_limit = 1;
			dst->hh_flows_limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_HHF_RESET_TIMEOUT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reset_timeout = 1;
			dst->reset_timeout = ynl_attr_get_u32(attr);
		} else if (type == TCA_HHF_ADMIT_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.admit_bytes = 1;
			dst->admit_bytes = ynl_attr_get_u32(attr);
		} else if (type == TCA_HHF_EVICT_TIMEOUT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.evict_timeout = 1;
			dst->evict_timeout = ynl_attr_get_u32(attr);
		} else if (type == TCA_HHF_NON_HH_WEIGHT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.non_hh_weight = 1;
			dst->non_hh_weight = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_htb_attrs_free(struct tc_htb_attrs *obj)
{
	free(obj->parms);
	free(obj->init);
	free(obj->ctab);
	free(obj->rtab);
}

int tc_htb_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_htb_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_HTB_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.init)
		ynl_attr_put(nlh, TCA_HTB_INIT, obj->init, obj->_len.init);
	if (obj->_len.ctab)
		ynl_attr_put(nlh, TCA_HTB_CTAB, obj->ctab, obj->_len.ctab);
	if (obj->_len.rtab)
		ynl_attr_put(nlh, TCA_HTB_RTAB, obj->rtab, obj->_len.rtab);
	if (obj->_present.direct_qlen)
		ynl_attr_put_u32(nlh, TCA_HTB_DIRECT_QLEN, obj->direct_qlen);
	if (obj->_present.rate64)
		ynl_attr_put_u64(nlh, TCA_HTB_RATE64, obj->rate64);
	if (obj->_present.ceil64)
		ynl_attr_put_u64(nlh, TCA_HTB_CEIL64, obj->ceil64);
	if (obj->_present.offload)
		ynl_attr_put(nlh, TCA_HTB_OFFLOAD, NULL, 0);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_htb_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_htb_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_HTB_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_htb_opt))
				dst->parms = calloc(1, sizeof(struct tc_htb_opt));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_HTB_INIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.init = len;
			if (len < sizeof(struct tc_htb_glob))
				dst->init = calloc(1, sizeof(struct tc_htb_glob));
			else
				dst->init = malloc(len);
			memcpy(dst->init, ynl_attr_data(attr), len);
		} else if (type == TCA_HTB_CTAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ctab = len;
			dst->ctab = malloc(len);
			memcpy(dst->ctab, ynl_attr_data(attr), len);
		} else if (type == TCA_HTB_RTAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rtab = len;
			dst->rtab = malloc(len);
			memcpy(dst->rtab, ynl_attr_data(attr), len);
		} else if (type == TCA_HTB_DIRECT_QLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.direct_qlen = 1;
			dst->direct_qlen = ynl_attr_get_u32(attr);
		} else if (type == TCA_HTB_RATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rate64 = 1;
			dst->rate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_HTB_CEIL64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ceil64 = 1;
			dst->ceil64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_HTB_OFFLOAD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.offload = 1;
		}
	}

	return 0;
}

void tc_pie_attrs_free(struct tc_pie_attrs *obj)
{
}

int tc_pie_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_pie_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.target)
		ynl_attr_put_u32(nlh, TCA_PIE_TARGET, obj->target);
	if (obj->_present.limit)
		ynl_attr_put_u32(nlh, TCA_PIE_LIMIT, obj->limit);
	if (obj->_present.tupdate)
		ynl_attr_put_u32(nlh, TCA_PIE_TUPDATE, obj->tupdate);
	if (obj->_present.alpha)
		ynl_attr_put_u32(nlh, TCA_PIE_ALPHA, obj->alpha);
	if (obj->_present.beta)
		ynl_attr_put_u32(nlh, TCA_PIE_BETA, obj->beta);
	if (obj->_present.ecn)
		ynl_attr_put_u32(nlh, TCA_PIE_ECN, obj->ecn);
	if (obj->_present.bytemode)
		ynl_attr_put_u32(nlh, TCA_PIE_BYTEMODE, obj->bytemode);
	if (obj->_present.dq_rate_estimator)
		ynl_attr_put_u32(nlh, TCA_PIE_DQ_RATE_ESTIMATOR, obj->dq_rate_estimator);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_pie_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_pie_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_PIE_TARGET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.target = 1;
			dst->target = ynl_attr_get_u32(attr);
		} else if (type == TCA_PIE_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.limit = 1;
			dst->limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_PIE_TUPDATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tupdate = 1;
			dst->tupdate = ynl_attr_get_u32(attr);
		} else if (type == TCA_PIE_ALPHA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.alpha = 1;
			dst->alpha = ynl_attr_get_u32(attr);
		} else if (type == TCA_PIE_BETA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.beta = 1;
			dst->beta = ynl_attr_get_u32(attr);
		} else if (type == TCA_PIE_ECN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn = 1;
			dst->ecn = ynl_attr_get_u32(attr);
		} else if (type == TCA_PIE_BYTEMODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bytemode = 1;
			dst->bytemode = ynl_attr_get_u32(attr);
		} else if (type == TCA_PIE_DQ_RATE_ESTIMATOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dq_rate_estimator = 1;
			dst->dq_rate_estimator = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_qfq_attrs_free(struct tc_qfq_attrs *obj)
{
}

int tc_qfq_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_qfq_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.weight)
		ynl_attr_put_u32(nlh, TCA_QFQ_WEIGHT, obj->weight);
	if (obj->_present.lmax)
		ynl_attr_put_u32(nlh, TCA_QFQ_LMAX, obj->lmax);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_qfq_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_qfq_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_QFQ_WEIGHT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.weight = 1;
			dst->weight = ynl_attr_get_u32(attr);
		} else if (type == TCA_QFQ_LMAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.lmax = 1;
			dst->lmax = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_red_attrs_free(struct tc_red_attrs *obj)
{
	free(obj->parms);
	free(obj->stab);
}

int tc_red_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_red_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_RED_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.stab)
		ynl_attr_put(nlh, TCA_RED_STAB, obj->stab, obj->_len.stab);
	if (obj->_present.max_p)
		ynl_attr_put_u32(nlh, TCA_RED_MAX_P, obj->max_p);
	if (obj->_present.flags)
		ynl_attr_put(nlh, TCA_RED_FLAGS, &obj->flags, sizeof(struct nla_bitfield32));
	if (obj->_present.early_drop_block)
		ynl_attr_put_u32(nlh, TCA_RED_EARLY_DROP_BLOCK, obj->early_drop_block);
	if (obj->_present.mark_block)
		ynl_attr_put_u32(nlh, TCA_RED_MARK_BLOCK, obj->mark_block);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_red_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_red_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_RED_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_red_qopt))
				dst->parms = calloc(1, sizeof(struct tc_red_qopt));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_RED_STAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stab = len;
			dst->stab = malloc(len);
			memcpy(dst->stab, ynl_attr_data(attr), len);
		} else if (type == TCA_RED_MAX_P) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_p = 1;
			dst->max_p = ynl_attr_get_u32(attr);
		} else if (type == TCA_RED_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			memcpy(&dst->flags, ynl_attr_data(attr), sizeof(struct nla_bitfield32));
		} else if (type == TCA_RED_EARLY_DROP_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.early_drop_block = 1;
			dst->early_drop_block = ynl_attr_get_u32(attr);
		} else if (type == TCA_RED_MARK_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mark_block = 1;
			dst->mark_block = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_tbf_attrs_free(struct tc_tbf_attrs *obj)
{
	free(obj->parms);
	free(obj->rtab);
	free(obj->ptab);
}

int tc_tbf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_tbf_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_TBF_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.rtab)
		ynl_attr_put(nlh, TCA_TBF_RTAB, obj->rtab, obj->_len.rtab);
	if (obj->_len.ptab)
		ynl_attr_put(nlh, TCA_TBF_PTAB, obj->ptab, obj->_len.ptab);
	if (obj->_present.rate64)
		ynl_attr_put_u64(nlh, TCA_TBF_RATE64, obj->rate64);
	if (obj->_present.prate64)
		ynl_attr_put_u64(nlh, TCA_TBF_PRATE64, obj->prate64);
	if (obj->_present.burst)
		ynl_attr_put_u32(nlh, TCA_TBF_BURST, obj->burst);
	if (obj->_present.pburst)
		ynl_attr_put_u32(nlh, TCA_TBF_PBURST, obj->pburst);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_tbf_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_tbf_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_TBF_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_tbf_qopt))
				dst->parms = calloc(1, sizeof(struct tc_tbf_qopt));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_TBF_RTAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rtab = len;
			dst->rtab = malloc(len);
			memcpy(dst->rtab, ynl_attr_data(attr), len);
		} else if (type == TCA_TBF_PTAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ptab = len;
			dst->ptab = malloc(len);
			memcpy(dst->ptab, ynl_attr_data(attr), len);
		} else if (type == TCA_TBF_RATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rate64 = 1;
			dst->rate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_TBF_PRATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.prate64 = 1;
			dst->prate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_TBF_BURST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.burst = 1;
			dst->burst = ynl_attr_get_u32(attr);
		} else if (type == TCA_TBF_PBURST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pburst = 1;
			dst->pburst = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_ematch_attrs_free(struct tc_ematch_attrs *obj)
{
	free(obj->tree_hdr);
	free(obj->tree_list);
}

int tc_ematch_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_ematch_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tree_hdr)
		ynl_attr_put(nlh, TCA_EMATCH_TREE_HDR, obj->tree_hdr, obj->_len.tree_hdr);
	if (obj->_len.tree_list)
		ynl_attr_put(nlh, TCA_EMATCH_TREE_LIST, obj->tree_list, obj->_len.tree_list);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_ematch_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	struct tc_ematch_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_EMATCH_TREE_HDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tree_hdr = len;
			if (len < sizeof(struct tcf_ematch_tree_hdr))
				dst->tree_hdr = calloc(1, sizeof(struct tcf_ematch_tree_hdr));
			else
				dst->tree_hdr = malloc(len);
			memcpy(dst->tree_hdr, ynl_attr_data(attr), len);
		} else if (type == TCA_EMATCH_TREE_LIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tree_list = len;
			dst->tree_list = malloc(len);
			memcpy(dst->tree_list, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_police_attrs_free(struct tc_police_attrs *obj)
{
	free(obj->tbf);
	free(obj->rate);
	free(obj->peakrate);
	free(obj->tm);
}

int tc_police_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_police_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tbf)
		ynl_attr_put(nlh, TCA_POLICE_TBF, obj->tbf, obj->_len.tbf);
	if (obj->_len.rate)
		ynl_attr_put(nlh, TCA_POLICE_RATE, obj->rate, obj->_len.rate);
	if (obj->_len.peakrate)
		ynl_attr_put(nlh, TCA_POLICE_PEAKRATE, obj->peakrate, obj->_len.peakrate);
	if (obj->_present.avrate)
		ynl_attr_put_u32(nlh, TCA_POLICE_AVRATE, obj->avrate);
	if (obj->_present.result)
		ynl_attr_put_u32(nlh, TCA_POLICE_RESULT, obj->result);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_POLICE_TM, obj->tm, obj->_len.tm);
	if (obj->_present.rate64)
		ynl_attr_put_u64(nlh, TCA_POLICE_RATE64, obj->rate64);
	if (obj->_present.peakrate64)
		ynl_attr_put_u64(nlh, TCA_POLICE_PEAKRATE64, obj->peakrate64);
	if (obj->_present.pktrate64)
		ynl_attr_put_u64(nlh, TCA_POLICE_PKTRATE64, obj->pktrate64);
	if (obj->_present.pktburst64)
		ynl_attr_put_u64(nlh, TCA_POLICE_PKTBURST64, obj->pktburst64);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_police_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	struct tc_police_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_POLICE_TBF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tbf = len;
			if (len < sizeof(struct tc_police))
				dst->tbf = calloc(1, sizeof(struct tc_police));
			else
				dst->tbf = malloc(len);
			memcpy(dst->tbf, ynl_attr_data(attr), len);
		} else if (type == TCA_POLICE_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rate = len;
			dst->rate = malloc(len);
			memcpy(dst->rate, ynl_attr_data(attr), len);
		} else if (type == TCA_POLICE_PEAKRATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.peakrate = len;
			dst->peakrate = malloc(len);
			memcpy(dst->peakrate, ynl_attr_data(attr), len);
		} else if (type == TCA_POLICE_AVRATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.avrate = 1;
			dst->avrate = ynl_attr_get_u32(attr);
		} else if (type == TCA_POLICE_RESULT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.result = 1;
			dst->result = ynl_attr_get_u32(attr);
		} else if (type == TCA_POLICE_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_POLICE_RATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rate64 = 1;
			dst->rate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_POLICE_PEAKRATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.peakrate64 = 1;
			dst->peakrate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_POLICE_PKTRATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pktrate64 = 1;
			dst->pktrate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_POLICE_PKTBURST64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pktburst64 = 1;
			dst->pktburst64 = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

void
tc_flower_key_mpls_opt_attrs_free(struct tc_flower_key_mpls_opt_attrs *obj)
{
}

int tc_flower_key_mpls_opt_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     struct tc_flower_key_mpls_opt_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.lse_depth)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH, obj->lse_depth);
	if (obj->_present.lse_ttl)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL, obj->lse_ttl);
	if (obj->_present.lse_bos)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS, obj->lse_bos);
	if (obj->_present.lse_tc)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_MPLS_OPT_LSE_TC, obj->lse_tc);
	if (obj->_present.lse_label)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL, obj->lse_label);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_flower_key_mpls_opt_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	struct tc_flower_key_mpls_opt_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.lse_depth = 1;
			dst->lse_depth = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.lse_ttl = 1;
			dst->lse_ttl = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.lse_bos = 1;
			dst->lse_bos = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_MPLS_OPT_LSE_TC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.lse_tc = 1;
			dst->lse_tc = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.lse_label = 1;
			dst->lse_label = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_flower_key_cfm_attrs_free(struct tc_flower_key_cfm_attrs *obj)
{
}

int tc_flower_key_cfm_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				struct tc_flower_key_cfm_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.md_level)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_CFM_MD_LEVEL, obj->md_level);
	if (obj->_present.opcode)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_CFM_OPCODE, obj->opcode);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_flower_key_cfm_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	struct tc_flower_key_cfm_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FLOWER_KEY_CFM_MD_LEVEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.md_level = 1;
			dst->md_level = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_CFM_OPCODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.opcode = 1;
			dst->opcode = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void tc_netem_loss_attrs_free(struct tc_netem_loss_attrs *obj)
{
	free(obj->gi);
	free(obj->ge);
}

int tc_netem_loss_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_netem_loss_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.gi)
		ynl_attr_put(nlh, NETEM_LOSS_GI, obj->gi, obj->_len.gi);
	if (obj->_len.ge)
		ynl_attr_put(nlh, NETEM_LOSS_GE, obj->ge, obj->_len.ge);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_netem_loss_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct tc_netem_loss_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NETEM_LOSS_GI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.gi = len;
			if (len < sizeof(struct tc_netem_gimodel))
				dst->gi = calloc(1, sizeof(struct tc_netem_gimodel));
			else
				dst->gi = malloc(len);
			memcpy(dst->gi, ynl_attr_data(attr), len);
		} else if (type == NETEM_LOSS_GE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ge = len;
			if (len < sizeof(struct tc_netem_gemodel))
				dst->ge = calloc(1, sizeof(struct tc_netem_gemodel));
			else
				dst->ge = malloc(len);
			memcpy(dst->ge, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_taprio_sched_entry_free(struct tc_taprio_sched_entry *obj)
{
}

int tc_taprio_sched_entry_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct tc_taprio_sched_entry *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.index)
		ynl_attr_put_u32(nlh, TCA_TAPRIO_SCHED_ENTRY_INDEX, obj->index);
	if (obj->_present.cmd)
		ynl_attr_put_u8(nlh, TCA_TAPRIO_SCHED_ENTRY_CMD, obj->cmd);
	if (obj->_present.gate_mask)
		ynl_attr_put_u32(nlh, TCA_TAPRIO_SCHED_ENTRY_GATE_MASK, obj->gate_mask);
	if (obj->_present.interval)
		ynl_attr_put_u32(nlh, TCA_TAPRIO_SCHED_ENTRY_INTERVAL, obj->interval);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_taprio_sched_entry_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	struct tc_taprio_sched_entry *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_TAPRIO_SCHED_ENTRY_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.index = 1;
			dst->index = ynl_attr_get_u32(attr);
		} else if (type == TCA_TAPRIO_SCHED_ENTRY_CMD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cmd = 1;
			dst->cmd = ynl_attr_get_u8(attr);
		} else if (type == TCA_TAPRIO_SCHED_ENTRY_GATE_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gate_mask = 1;
			dst->gate_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_TAPRIO_SCHED_ENTRY_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.interval = 1;
			dst->interval = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_taprio_tc_entry_attrs_free(struct tc_taprio_tc_entry_attrs *obj)
{
}

int tc_taprio_tc_entry_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 struct tc_taprio_tc_entry_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.index)
		ynl_attr_put_u32(nlh, TCA_TAPRIO_TC_ENTRY_INDEX, obj->index);
	if (obj->_present.max_sdu)
		ynl_attr_put_u32(nlh, TCA_TAPRIO_TC_ENTRY_MAX_SDU, obj->max_sdu);
	if (obj->_present.fp)
		ynl_attr_put_u32(nlh, TCA_TAPRIO_TC_ENTRY_FP, obj->fp);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_taprio_tc_entry_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	struct tc_taprio_tc_entry_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_TAPRIO_TC_ENTRY_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.index = 1;
			dst->index = ynl_attr_get_u32(attr);
		} else if (type == TCA_TAPRIO_TC_ENTRY_MAX_SDU) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_sdu = 1;
			dst->max_sdu = ynl_attr_get_u32(attr);
		} else if (type == TCA_TAPRIO_TC_ENTRY_FP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fp = 1;
			dst->fp = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_cake_tin_stats_attrs_free(struct tc_cake_tin_stats_attrs *obj)
{
}

int tc_cake_tin_stats_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				struct tc_cake_tin_stats_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.sent_packets)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_SENT_PACKETS, obj->sent_packets);
	if (obj->_present.sent_bytes64)
		ynl_attr_put_u64(nlh, TCA_CAKE_TIN_STATS_SENT_BYTES64, obj->sent_bytes64);
	if (obj->_present.dropped_packets)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_DROPPED_PACKETS, obj->dropped_packets);
	if (obj->_present.dropped_bytes64)
		ynl_attr_put_u64(nlh, TCA_CAKE_TIN_STATS_DROPPED_BYTES64, obj->dropped_bytes64);
	if (obj->_present.acks_dropped_packets)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_ACKS_DROPPED_PACKETS, obj->acks_dropped_packets);
	if (obj->_present.acks_dropped_bytes64)
		ynl_attr_put_u64(nlh, TCA_CAKE_TIN_STATS_ACKS_DROPPED_BYTES64, obj->acks_dropped_bytes64);
	if (obj->_present.ecn_marked_packets)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_ECN_MARKED_PACKETS, obj->ecn_marked_packets);
	if (obj->_present.ecn_marked_bytes64)
		ynl_attr_put_u64(nlh, TCA_CAKE_TIN_STATS_ECN_MARKED_BYTES64, obj->ecn_marked_bytes64);
	if (obj->_present.backlog_packets)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_BACKLOG_PACKETS, obj->backlog_packets);
	if (obj->_present.backlog_bytes)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_BACKLOG_BYTES, obj->backlog_bytes);
	if (obj->_present.threshold_rate64)
		ynl_attr_put_u64(nlh, TCA_CAKE_TIN_STATS_THRESHOLD_RATE64, obj->threshold_rate64);
	if (obj->_present.target_us)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_TARGET_US, obj->target_us);
	if (obj->_present.interval_us)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_INTERVAL_US, obj->interval_us);
	if (obj->_present.way_indirect_hits)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_WAY_INDIRECT_HITS, obj->way_indirect_hits);
	if (obj->_present.way_misses)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_WAY_MISSES, obj->way_misses);
	if (obj->_present.way_collisions)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_WAY_COLLISIONS, obj->way_collisions);
	if (obj->_present.peak_delay_us)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_PEAK_DELAY_US, obj->peak_delay_us);
	if (obj->_present.avg_delay_us)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_AVG_DELAY_US, obj->avg_delay_us);
	if (obj->_present.base_delay_us)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_BASE_DELAY_US, obj->base_delay_us);
	if (obj->_present.sparse_flows)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_SPARSE_FLOWS, obj->sparse_flows);
	if (obj->_present.bulk_flows)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_BULK_FLOWS, obj->bulk_flows);
	if (obj->_present.unresponsive_flows)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_UNRESPONSIVE_FLOWS, obj->unresponsive_flows);
	if (obj->_present.max_skblen)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_MAX_SKBLEN, obj->max_skblen);
	if (obj->_present.flow_quantum)
		ynl_attr_put_u32(nlh, TCA_CAKE_TIN_STATS_FLOW_QUANTUM, obj->flow_quantum);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_cake_tin_stats_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested, __u32 idx)
{
	struct tc_cake_tin_stats_attrs *dst = yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CAKE_TIN_STATS_SENT_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sent_packets = 1;
			dst->sent_packets = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_SENT_BYTES64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sent_bytes64 = 1;
			dst->sent_bytes64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_CAKE_TIN_STATS_DROPPED_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dropped_packets = 1;
			dst->dropped_packets = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_DROPPED_BYTES64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dropped_bytes64 = 1;
			dst->dropped_bytes64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_CAKE_TIN_STATS_ACKS_DROPPED_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.acks_dropped_packets = 1;
			dst->acks_dropped_packets = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_ACKS_DROPPED_BYTES64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.acks_dropped_bytes64 = 1;
			dst->acks_dropped_bytes64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_CAKE_TIN_STATS_ECN_MARKED_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn_marked_packets = 1;
			dst->ecn_marked_packets = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_ECN_MARKED_BYTES64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn_marked_bytes64 = 1;
			dst->ecn_marked_bytes64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_CAKE_TIN_STATS_BACKLOG_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.backlog_packets = 1;
			dst->backlog_packets = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_BACKLOG_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.backlog_bytes = 1;
			dst->backlog_bytes = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_THRESHOLD_RATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.threshold_rate64 = 1;
			dst->threshold_rate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_CAKE_TIN_STATS_TARGET_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.target_us = 1;
			dst->target_us = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_INTERVAL_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.interval_us = 1;
			dst->interval_us = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_WAY_INDIRECT_HITS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.way_indirect_hits = 1;
			dst->way_indirect_hits = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_WAY_MISSES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.way_misses = 1;
			dst->way_misses = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_WAY_COLLISIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.way_collisions = 1;
			dst->way_collisions = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_PEAK_DELAY_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.peak_delay_us = 1;
			dst->peak_delay_us = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_AVG_DELAY_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.avg_delay_us = 1;
			dst->avg_delay_us = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_BASE_DELAY_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.base_delay_us = 1;
			dst->base_delay_us = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_SPARSE_FLOWS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sparse_flows = 1;
			dst->sparse_flows = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_BULK_FLOWS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bulk_flows = 1;
			dst->bulk_flows = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_UNRESPONSIVE_FLOWS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.unresponsive_flows = 1;
			dst->unresponsive_flows = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_MAX_SKBLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_skblen = 1;
			dst->max_skblen = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_TIN_STATS_FLOW_QUANTUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flow_quantum = 1;
			dst->flow_quantum = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void
tc_flower_key_enc_opt_geneve_attrs_free(struct tc_flower_key_enc_opt_geneve_attrs *obj)
{
	free(obj->data);
}

int tc_flower_key_enc_opt_geneve_attrs_put(struct nlmsghdr *nlh,
					   unsigned int attr_type,
					   struct tc_flower_key_enc_opt_geneve_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.class)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS, obj->class);
	if (obj->_present.type)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE, obj->type);
	if (obj->_len.data)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA, obj->data, obj->_len.data);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_flower_key_enc_opt_geneve_attrs_parse(struct ynl_parse_arg *yarg,
					     const struct nlattr *nested)
{
	struct tc_flower_key_enc_opt_geneve_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.class = 1;
			dst->class = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.type = 1;
			dst->type = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.data = len;
			dst->data = malloc(len);
			memcpy(dst->data, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void
tc_flower_key_enc_opt_vxlan_attrs_free(struct tc_flower_key_enc_opt_vxlan_attrs *obj)
{
}

int tc_flower_key_enc_opt_vxlan_attrs_put(struct nlmsghdr *nlh,
					  unsigned int attr_type,
					  struct tc_flower_key_enc_opt_vxlan_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.gbp)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ENC_OPT_VXLAN_GBP, obj->gbp);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_flower_key_enc_opt_vxlan_attrs_parse(struct ynl_parse_arg *yarg,
					    const struct nlattr *nested)
{
	struct tc_flower_key_enc_opt_vxlan_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FLOWER_KEY_ENC_OPT_VXLAN_GBP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gbp = 1;
			dst->gbp = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void
tc_flower_key_enc_opt_erspan_attrs_free(struct tc_flower_key_enc_opt_erspan_attrs *obj)
{
}

int tc_flower_key_enc_opt_erspan_attrs_put(struct nlmsghdr *nlh,
					   unsigned int attr_type,
					   struct tc_flower_key_enc_opt_erspan_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.ver)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER, obj->ver);
	if (obj->_present.index)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX, obj->index);
	if (obj->_present.dir)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR, obj->dir);
	if (obj->_present.hwid)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID, obj->hwid);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_flower_key_enc_opt_erspan_attrs_parse(struct ynl_parse_arg *yarg,
					     const struct nlattr *nested)
{
	struct tc_flower_key_enc_opt_erspan_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ver = 1;
			dst->ver = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.index = 1;
			dst->index = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dir = 1;
			dst->dir = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hwid = 1;
			dst->hwid = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void
tc_flower_key_enc_opt_gtp_attrs_free(struct tc_flower_key_enc_opt_gtp_attrs *obj)
{
}

int tc_flower_key_enc_opt_gtp_attrs_put(struct nlmsghdr *nlh,
					unsigned int attr_type,
					struct tc_flower_key_enc_opt_gtp_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.pdu_type)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_OPT_GTP_PDU_TYPE, obj->pdu_type);
	if (obj->_present.qfi)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_OPT_GTP_QFI, obj->qfi);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_flower_key_enc_opt_gtp_attrs_parse(struct ynl_parse_arg *yarg,
					  const struct nlattr *nested)
{
	struct tc_flower_key_enc_opt_gtp_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FLOWER_KEY_ENC_OPT_GTP_PDU_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pdu_type = 1;
			dst->pdu_type = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_OPT_GTP_QFI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.qfi = 1;
			dst->qfi = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void tc_tca_gred_vq_entry_attrs_free(struct tc_tca_gred_vq_entry_attrs *obj)
{
}

int tc_tca_gred_vq_entry_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct tc_tca_gred_vq_entry_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.dp)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_DP, obj->dp);
	if (obj->_present.stat_bytes)
		ynl_attr_put_u64(nlh, TCA_GRED_VQ_STAT_BYTES, obj->stat_bytes);
	if (obj->_present.stat_packets)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_STAT_PACKETS, obj->stat_packets);
	if (obj->_present.stat_backlog)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_STAT_BACKLOG, obj->stat_backlog);
	if (obj->_present.stat_prob_drop)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_STAT_PROB_DROP, obj->stat_prob_drop);
	if (obj->_present.stat_prob_mark)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_STAT_PROB_MARK, obj->stat_prob_mark);
	if (obj->_present.stat_forced_drop)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_STAT_FORCED_DROP, obj->stat_forced_drop);
	if (obj->_present.stat_forced_mark)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_STAT_FORCED_MARK, obj->stat_forced_mark);
	if (obj->_present.stat_pdrop)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_STAT_PDROP, obj->stat_pdrop);
	if (obj->_present.stat_other)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_STAT_OTHER, obj->stat_other);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, TCA_GRED_VQ_FLAGS, obj->flags);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_tca_gred_vq_entry_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct tc_tca_gred_vq_entry_attrs *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_GRED_VQ_DP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dp = 1;
			dst->dp = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_STAT_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stat_bytes = 1;
			dst->stat_bytes = ynl_attr_get_u64(attr);
		} else if (type == TCA_GRED_VQ_STAT_PACKETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stat_packets = 1;
			dst->stat_packets = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_STAT_BACKLOG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stat_backlog = 1;
			dst->stat_backlog = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_STAT_PROB_DROP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stat_prob_drop = 1;
			dst->stat_prob_drop = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_STAT_PROB_MARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stat_prob_mark = 1;
			dst->stat_prob_mark = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_STAT_FORCED_DROP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stat_forced_drop = 1;
			dst->stat_forced_drop = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_STAT_FORCED_MARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stat_forced_mark = 1;
			dst->stat_forced_mark = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_STAT_PDROP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stat_pdrop = 1;
			dst->stat_pdrop = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_STAT_OTHER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stat_other = 1;
			dst->stat_other = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_act_bpf_attrs_free(struct tc_act_bpf_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
	free(obj->ops);
	free(obj->name);
	free(obj->tag);
	free(obj->id);
}

int tc_act_bpf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct tc_act_bpf_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_ACT_BPF_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_ACT_BPF_PARMS, obj->parms, obj->_len.parms);
	if (obj->_present.ops_len)
		ynl_attr_put_u16(nlh, TCA_ACT_BPF_OPS_LEN, obj->ops_len);
	if (obj->_len.ops)
		ynl_attr_put(nlh, TCA_ACT_BPF_OPS, obj->ops, obj->_len.ops);
	if (obj->_present.fd)
		ynl_attr_put_u32(nlh, TCA_ACT_BPF_FD, obj->fd);
	if (obj->_len.name)
		ynl_attr_put_str(nlh, TCA_ACT_BPF_NAME, obj->name);
	if (obj->_len.tag)
		ynl_attr_put(nlh, TCA_ACT_BPF_TAG, obj->tag, obj->_len.tag);
	if (obj->_len.id)
		ynl_attr_put(nlh, TCA_ACT_BPF_ID, obj->id, obj->_len.id);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_bpf_attrs_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	struct tc_act_bpf_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_ACT_BPF_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_ACT_BPF_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_ACT_BPF_OPS_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ops_len = 1;
			dst->ops_len = ynl_attr_get_u16(attr);
		} else if (type == TCA_ACT_BPF_OPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ops = len;
			dst->ops = malloc(len);
			memcpy(dst->ops, ynl_attr_data(attr), len);
		} else if (type == TCA_ACT_BPF_FD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fd = 1;
			dst->fd = ynl_attr_get_u32(attr);
		} else if (type == TCA_ACT_BPF_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.name = len;
			dst->name = malloc(len + 1);
			memcpy(dst->name, ynl_attr_get_str(attr), len);
			dst->name[len] = 0;
		} else if (type == TCA_ACT_BPF_TAG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tag = len;
			dst->tag = malloc(len);
			memcpy(dst->tag, ynl_attr_data(attr), len);
		} else if (type == TCA_ACT_BPF_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.id = len;
			dst->id = malloc(len);
			memcpy(dst->id, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_connmark_attrs_free(struct tc_act_connmark_attrs *obj)
{
	free(obj->parms);
	free(obj->tm);
}

int tc_act_connmark_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      struct tc_act_connmark_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_CONNMARK_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_CONNMARK_TM, obj->tm, obj->_len.tm);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_connmark_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	struct tc_act_connmark_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CONNMARK_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_CONNMARK_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_csum_attrs_free(struct tc_act_csum_attrs *obj)
{
	free(obj->parms);
	free(obj->tm);
}

int tc_act_csum_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_csum_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_CSUM_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_CSUM_TM, obj->tm, obj->_len.tm);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_csum_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct tc_act_csum_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CSUM_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_CSUM_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_ct_attrs_free(struct tc_act_ct_attrs *obj)
{
	free(obj->parms);
	free(obj->tm);
	free(obj->labels);
	free(obj->labels_mask);
	free(obj->nat_ipv6_min);
	free(obj->nat_ipv6_max);
	free(obj->helper_name);
}

int tc_act_ct_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_act_ct_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_CT_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_CT_TM, obj->tm, obj->_len.tm);
	if (obj->_present.action)
		ynl_attr_put_u16(nlh, TCA_CT_ACTION, obj->action);
	if (obj->_present.zone)
		ynl_attr_put_u16(nlh, TCA_CT_ZONE, obj->zone);
	if (obj->_present.mark)
		ynl_attr_put_u32(nlh, TCA_CT_MARK, obj->mark);
	if (obj->_present.mark_mask)
		ynl_attr_put_u32(nlh, TCA_CT_MARK_MASK, obj->mark_mask);
	if (obj->_len.labels)
		ynl_attr_put(nlh, TCA_CT_LABELS, obj->labels, obj->_len.labels);
	if (obj->_len.labels_mask)
		ynl_attr_put(nlh, TCA_CT_LABELS_MASK, obj->labels_mask, obj->_len.labels_mask);
	if (obj->_present.nat_ipv4_min)
		ynl_attr_put_u32(nlh, TCA_CT_NAT_IPV4_MIN, obj->nat_ipv4_min);
	if (obj->_present.nat_ipv4_max)
		ynl_attr_put_u32(nlh, TCA_CT_NAT_IPV4_MAX, obj->nat_ipv4_max);
	if (obj->_len.nat_ipv6_min)
		ynl_attr_put(nlh, TCA_CT_NAT_IPV6_MIN, obj->nat_ipv6_min, obj->_len.nat_ipv6_min);
	if (obj->_len.nat_ipv6_max)
		ynl_attr_put(nlh, TCA_CT_NAT_IPV6_MAX, obj->nat_ipv6_max, obj->_len.nat_ipv6_max);
	if (obj->_present.nat_port_min)
		ynl_attr_put_u16(nlh, TCA_CT_NAT_PORT_MIN, obj->nat_port_min);
	if (obj->_present.nat_port_max)
		ynl_attr_put_u16(nlh, TCA_CT_NAT_PORT_MAX, obj->nat_port_max);
	if (obj->_len.helper_name)
		ynl_attr_put_str(nlh, TCA_CT_HELPER_NAME, obj->helper_name);
	if (obj->_present.helper_family)
		ynl_attr_put_u8(nlh, TCA_CT_HELPER_FAMILY, obj->helper_family);
	if (obj->_present.helper_proto)
		ynl_attr_put_u8(nlh, TCA_CT_HELPER_PROTO, obj->helper_proto);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_ct_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	struct tc_act_ct_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CT_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_CT_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_CT_ACTION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.action = 1;
			dst->action = ynl_attr_get_u16(attr);
		} else if (type == TCA_CT_ZONE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.zone = 1;
			dst->zone = ynl_attr_get_u16(attr);
		} else if (type == TCA_CT_MARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mark = 1;
			dst->mark = ynl_attr_get_u32(attr);
		} else if (type == TCA_CT_MARK_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mark_mask = 1;
			dst->mark_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_CT_LABELS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.labels = len;
			dst->labels = malloc(len);
			memcpy(dst->labels, ynl_attr_data(attr), len);
		} else if (type == TCA_CT_LABELS_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.labels_mask = len;
			dst->labels_mask = malloc(len);
			memcpy(dst->labels_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_CT_NAT_IPV4_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nat_ipv4_min = 1;
			dst->nat_ipv4_min = ynl_attr_get_u32(attr);
		} else if (type == TCA_CT_NAT_IPV4_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nat_ipv4_max = 1;
			dst->nat_ipv4_max = ynl_attr_get_u32(attr);
		} else if (type == TCA_CT_NAT_IPV6_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.nat_ipv6_min = len;
			dst->nat_ipv6_min = malloc(len);
			memcpy(dst->nat_ipv6_min, ynl_attr_data(attr), len);
		} else if (type == TCA_CT_NAT_IPV6_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.nat_ipv6_max = len;
			dst->nat_ipv6_max = malloc(len);
			memcpy(dst->nat_ipv6_max, ynl_attr_data(attr), len);
		} else if (type == TCA_CT_NAT_PORT_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nat_port_min = 1;
			dst->nat_port_min = ynl_attr_get_u16(attr);
		} else if (type == TCA_CT_NAT_PORT_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nat_port_max = 1;
			dst->nat_port_max = ynl_attr_get_u16(attr);
		} else if (type == TCA_CT_HELPER_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.helper_name = len;
			dst->helper_name = malloc(len + 1);
			memcpy(dst->helper_name, ynl_attr_get_str(attr), len);
			dst->helper_name[len] = 0;
		} else if (type == TCA_CT_HELPER_FAMILY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.helper_family = 1;
			dst->helper_family = ynl_attr_get_u8(attr);
		} else if (type == TCA_CT_HELPER_PROTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.helper_proto = 1;
			dst->helper_proto = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void tc_act_ctinfo_attrs_free(struct tc_act_ctinfo_attrs *obj)
{
	free(obj->tm);
	free(obj->act);
}

int tc_act_ctinfo_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_ctinfo_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_CTINFO_TM, obj->tm, obj->_len.tm);
	if (obj->_len.act)
		ynl_attr_put(nlh, TCA_CTINFO_ACT, obj->act, obj->_len.act);
	if (obj->_present.zone)
		ynl_attr_put_u16(nlh, TCA_CTINFO_ZONE, obj->zone);
	if (obj->_present.parms_dscp_mask)
		ynl_attr_put_u32(nlh, TCA_CTINFO_PARMS_DSCP_MASK, obj->parms_dscp_mask);
	if (obj->_present.parms_dscp_statemask)
		ynl_attr_put_u32(nlh, TCA_CTINFO_PARMS_DSCP_STATEMASK, obj->parms_dscp_statemask);
	if (obj->_present.parms_cpmark_mask)
		ynl_attr_put_u32(nlh, TCA_CTINFO_PARMS_CPMARK_MASK, obj->parms_cpmark_mask);
	if (obj->_present.stats_dscp_set)
		ynl_attr_put_u64(nlh, TCA_CTINFO_STATS_DSCP_SET, obj->stats_dscp_set);
	if (obj->_present.stats_dscp_error)
		ynl_attr_put_u64(nlh, TCA_CTINFO_STATS_DSCP_ERROR, obj->stats_dscp_error);
	if (obj->_present.stats_cpmark_set)
		ynl_attr_put_u64(nlh, TCA_CTINFO_STATS_CPMARK_SET, obj->stats_cpmark_set);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_ctinfo_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct tc_act_ctinfo_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CTINFO_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_CTINFO_ACT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.act = len;
			dst->act = malloc(len);
			memcpy(dst->act, ynl_attr_data(attr), len);
		} else if (type == TCA_CTINFO_ZONE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.zone = 1;
			dst->zone = ynl_attr_get_u16(attr);
		} else if (type == TCA_CTINFO_PARMS_DSCP_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.parms_dscp_mask = 1;
			dst->parms_dscp_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_CTINFO_PARMS_DSCP_STATEMASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.parms_dscp_statemask = 1;
			dst->parms_dscp_statemask = ynl_attr_get_u32(attr);
		} else if (type == TCA_CTINFO_PARMS_CPMARK_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.parms_cpmark_mask = 1;
			dst->parms_cpmark_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_CTINFO_STATS_DSCP_SET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stats_dscp_set = 1;
			dst->stats_dscp_set = ynl_attr_get_u64(attr);
		} else if (type == TCA_CTINFO_STATS_DSCP_ERROR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stats_dscp_error = 1;
			dst->stats_dscp_error = ynl_attr_get_u64(attr);
		} else if (type == TCA_CTINFO_STATS_CPMARK_SET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stats_cpmark_set = 1;
			dst->stats_cpmark_set = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

void tc_act_gact_attrs_free(struct tc_act_gact_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
	free(obj->prob);
}

int tc_act_gact_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_gact_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_GACT_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_GACT_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.prob)
		ynl_attr_put(nlh, TCA_GACT_PROB, obj->prob, obj->_len.prob);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_gact_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct tc_act_gact_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_GACT_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_GACT_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_gact))
				dst->parms = calloc(1, sizeof(struct tc_gact));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_GACT_PROB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.prob = len;
			if (len < sizeof(struct tc_gact_p))
				dst->prob = calloc(1, sizeof(struct tc_gact_p));
			else
				dst->prob = malloc(len);
			memcpy(dst->prob, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_gate_attrs_free(struct tc_act_gate_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
	free(obj->entry_list);
}

int tc_act_gate_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_gate_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_GATE_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_GATE_PARMS, obj->parms, obj->_len.parms);
	if (obj->_present.priority)
		ynl_attr_put_s32(nlh, TCA_GATE_PRIORITY, obj->priority);
	if (obj->_len.entry_list)
		ynl_attr_put(nlh, TCA_GATE_ENTRY_LIST, obj->entry_list, obj->_len.entry_list);
	if (obj->_present.base_time)
		ynl_attr_put_u64(nlh, TCA_GATE_BASE_TIME, obj->base_time);
	if (obj->_present.cycle_time)
		ynl_attr_put_u64(nlh, TCA_GATE_CYCLE_TIME, obj->cycle_time);
	if (obj->_present.cycle_time_ext)
		ynl_attr_put_u64(nlh, TCA_GATE_CYCLE_TIME_EXT, obj->cycle_time_ext);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, TCA_GATE_FLAGS, obj->flags);
	if (obj->_present.clockid)
		ynl_attr_put_s32(nlh, TCA_GATE_CLOCKID, obj->clockid);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_gate_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct tc_act_gate_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_GATE_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_GATE_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_GATE_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.priority = 1;
			dst->priority = ynl_attr_get_s32(attr);
		} else if (type == TCA_GATE_ENTRY_LIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.entry_list = len;
			dst->entry_list = malloc(len);
			memcpy(dst->entry_list, ynl_attr_data(attr), len);
		} else if (type == TCA_GATE_BASE_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.base_time = 1;
			dst->base_time = ynl_attr_get_u64(attr);
		} else if (type == TCA_GATE_CYCLE_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cycle_time = 1;
			dst->cycle_time = ynl_attr_get_u64(attr);
		} else if (type == TCA_GATE_CYCLE_TIME_EXT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cycle_time_ext = 1;
			dst->cycle_time_ext = ynl_attr_get_u64(attr);
		} else if (type == TCA_GATE_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == TCA_GATE_CLOCKID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.clockid = 1;
			dst->clockid = ynl_attr_get_s32(attr);
		}
	}

	return 0;
}

void tc_act_ife_attrs_free(struct tc_act_ife_attrs *obj)
{
	free(obj->parms);
	free(obj->tm);
	free(obj->dmac);
	free(obj->smac);
	free(obj->metalst);
}

int tc_act_ife_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct tc_act_ife_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_IFE_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_IFE_TM, obj->tm, obj->_len.tm);
	if (obj->_len.dmac)
		ynl_attr_put(nlh, TCA_IFE_DMAC, obj->dmac, obj->_len.dmac);
	if (obj->_len.smac)
		ynl_attr_put(nlh, TCA_IFE_SMAC, obj->smac, obj->_len.smac);
	if (obj->_present.type)
		ynl_attr_put_u16(nlh, TCA_IFE_TYPE, obj->type);
	if (obj->_len.metalst)
		ynl_attr_put(nlh, TCA_IFE_METALST, obj->metalst, obj->_len.metalst);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_ife_attrs_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	struct tc_act_ife_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_IFE_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_IFE_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_IFE_DMAC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dmac = len;
			dst->dmac = malloc(len);
			memcpy(dst->dmac, ynl_attr_data(attr), len);
		} else if (type == TCA_IFE_SMAC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.smac = len;
			dst->smac = malloc(len);
			memcpy(dst->smac, ynl_attr_data(attr), len);
		} else if (type == TCA_IFE_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.type = 1;
			dst->type = ynl_attr_get_u16(attr);
		} else if (type == TCA_IFE_METALST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.metalst = len;
			dst->metalst = malloc(len);
			memcpy(dst->metalst, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_mirred_attrs_free(struct tc_act_mirred_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
	free(obj->blockid);
}

int tc_act_mirred_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_mirred_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_MIRRED_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_MIRRED_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.blockid)
		ynl_attr_put(nlh, TCA_MIRRED_BLOCKID, obj->blockid, obj->_len.blockid);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_mirred_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct tc_act_mirred_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_MIRRED_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_MIRRED_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_MIRRED_BLOCKID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.blockid = len;
			dst->blockid = malloc(len);
			memcpy(dst->blockid, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_mpls_attrs_free(struct tc_act_mpls_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
}

int tc_act_mpls_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_mpls_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_MPLS_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_MPLS_PARMS, obj->parms, obj->_len.parms);
	if (obj->_present.proto)
		ynl_attr_put_u16(nlh, TCA_MPLS_PROTO, obj->proto);
	if (obj->_present.label)
		ynl_attr_put_u32(nlh, TCA_MPLS_LABEL, obj->label);
	if (obj->_present.tc)
		ynl_attr_put_u8(nlh, TCA_MPLS_TC, obj->tc);
	if (obj->_present.ttl)
		ynl_attr_put_u8(nlh, TCA_MPLS_TTL, obj->ttl);
	if (obj->_present.bos)
		ynl_attr_put_u8(nlh, TCA_MPLS_BOS, obj->bos);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_mpls_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct tc_act_mpls_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_MPLS_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_MPLS_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_mpls))
				dst->parms = calloc(1, sizeof(struct tc_mpls));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_MPLS_PROTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.proto = 1;
			dst->proto = ynl_attr_get_u16(attr);
		} else if (type == TCA_MPLS_LABEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.label = 1;
			dst->label = ynl_attr_get_u32(attr);
		} else if (type == TCA_MPLS_TC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tc = 1;
			dst->tc = ynl_attr_get_u8(attr);
		} else if (type == TCA_MPLS_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ttl = 1;
			dst->ttl = ynl_attr_get_u8(attr);
		} else if (type == TCA_MPLS_BOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.bos = 1;
			dst->bos = ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

void tc_act_nat_attrs_free(struct tc_act_nat_attrs *obj)
{
	free(obj->parms);
	free(obj->tm);
}

int tc_act_nat_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 struct tc_act_nat_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_NAT_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_NAT_TM, obj->tm, obj->_len.tm);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_nat_attrs_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	struct tc_act_nat_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_NAT_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_NAT_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_pedit_attrs_free(struct tc_act_pedit_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
	free(obj->parms_ex);
	free(obj->keys_ex);
	free(obj->key_ex);
}

int tc_act_pedit_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct tc_act_pedit_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_PEDIT_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_PEDIT_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.parms_ex)
		ynl_attr_put(nlh, TCA_PEDIT_PARMS_EX, obj->parms_ex, obj->_len.parms_ex);
	if (obj->_len.keys_ex)
		ynl_attr_put(nlh, TCA_PEDIT_KEYS_EX, obj->keys_ex, obj->_len.keys_ex);
	if (obj->_len.key_ex)
		ynl_attr_put(nlh, TCA_PEDIT_KEY_EX, obj->key_ex, obj->_len.key_ex);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_pedit_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	struct tc_act_pedit_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_PEDIT_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_PEDIT_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_pedit_sel))
				dst->parms = calloc(1, sizeof(struct tc_pedit_sel));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_PEDIT_PARMS_EX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms_ex = len;
			dst->parms_ex = malloc(len);
			memcpy(dst->parms_ex, ynl_attr_data(attr), len);
		} else if (type == TCA_PEDIT_KEYS_EX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.keys_ex = len;
			dst->keys_ex = malloc(len);
			memcpy(dst->keys_ex, ynl_attr_data(attr), len);
		} else if (type == TCA_PEDIT_KEY_EX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_ex = len;
			dst->key_ex = malloc(len);
			memcpy(dst->key_ex, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_sample_attrs_free(struct tc_act_sample_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
}

int tc_act_sample_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_sample_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_SAMPLE_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_SAMPLE_PARMS, obj->parms, obj->_len.parms);
	if (obj->_present.rate)
		ynl_attr_put_u32(nlh, TCA_SAMPLE_RATE, obj->rate);
	if (obj->_present.trunc_size)
		ynl_attr_put_u32(nlh, TCA_SAMPLE_TRUNC_SIZE, obj->trunc_size);
	if (obj->_present.psample_group)
		ynl_attr_put_u32(nlh, TCA_SAMPLE_PSAMPLE_GROUP, obj->psample_group);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_sample_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct tc_act_sample_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_SAMPLE_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_SAMPLE_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_gact))
				dst->parms = calloc(1, sizeof(struct tc_gact));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_SAMPLE_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rate = 1;
			dst->rate = ynl_attr_get_u32(attr);
		} else if (type == TCA_SAMPLE_TRUNC_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.trunc_size = 1;
			dst->trunc_size = ynl_attr_get_u32(attr);
		} else if (type == TCA_SAMPLE_PSAMPLE_GROUP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.psample_group = 1;
			dst->psample_group = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_act_simple_attrs_free(struct tc_act_simple_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
	free(obj->data);
}

int tc_act_simple_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_simple_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_DEF_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_DEF_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.data)
		ynl_attr_put(nlh, TCA_DEF_DATA, obj->data, obj->_len.data);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_simple_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct tc_act_simple_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_DEF_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_DEF_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_DEF_DATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.data = len;
			dst->data = malloc(len);
			memcpy(dst->data, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_skbedit_attrs_free(struct tc_act_skbedit_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
}

int tc_act_skbedit_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     struct tc_act_skbedit_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_SKBEDIT_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_SKBEDIT_PARMS, obj->parms, obj->_len.parms);
	if (obj->_present.priority)
		ynl_attr_put_u32(nlh, TCA_SKBEDIT_PRIORITY, obj->priority);
	if (obj->_present.queue_mapping)
		ynl_attr_put_u16(nlh, TCA_SKBEDIT_QUEUE_MAPPING, obj->queue_mapping);
	if (obj->_present.mark)
		ynl_attr_put_u32(nlh, TCA_SKBEDIT_MARK, obj->mark);
	if (obj->_present.ptype)
		ynl_attr_put_u16(nlh, TCA_SKBEDIT_PTYPE, obj->ptype);
	if (obj->_present.mask)
		ynl_attr_put_u32(nlh, TCA_SKBEDIT_MASK, obj->mask);
	if (obj->_present.flags)
		ynl_attr_put_u64(nlh, TCA_SKBEDIT_FLAGS, obj->flags);
	if (obj->_present.queue_mapping_max)
		ynl_attr_put_u16(nlh, TCA_SKBEDIT_QUEUE_MAPPING_MAX, obj->queue_mapping_max);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_skbedit_attrs_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested)
{
	struct tc_act_skbedit_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_SKBEDIT_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_SKBEDIT_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_SKBEDIT_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.priority = 1;
			dst->priority = ynl_attr_get_u32(attr);
		} else if (type == TCA_SKBEDIT_QUEUE_MAPPING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.queue_mapping = 1;
			dst->queue_mapping = ynl_attr_get_u16(attr);
		} else if (type == TCA_SKBEDIT_MARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mark = 1;
			dst->mark = ynl_attr_get_u32(attr);
		} else if (type == TCA_SKBEDIT_PTYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ptype = 1;
			dst->ptype = ynl_attr_get_u16(attr);
		} else if (type == TCA_SKBEDIT_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mask = 1;
			dst->mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_SKBEDIT_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u64(attr);
		} else if (type == TCA_SKBEDIT_QUEUE_MAPPING_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.queue_mapping_max = 1;
			dst->queue_mapping_max = ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

void tc_act_skbmod_attrs_free(struct tc_act_skbmod_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
	free(obj->dmac);
	free(obj->smac);
	free(obj->etype);
}

int tc_act_skbmod_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_act_skbmod_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_SKBMOD_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_SKBMOD_PARMS, obj->parms, obj->_len.parms);
	if (obj->_len.dmac)
		ynl_attr_put(nlh, TCA_SKBMOD_DMAC, obj->dmac, obj->_len.dmac);
	if (obj->_len.smac)
		ynl_attr_put(nlh, TCA_SKBMOD_SMAC, obj->smac, obj->_len.smac);
	if (obj->_len.etype)
		ynl_attr_put(nlh, TCA_SKBMOD_ETYPE, obj->etype, obj->_len.etype);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_skbmod_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct tc_act_skbmod_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_SKBMOD_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_SKBMOD_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_SKBMOD_DMAC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dmac = len;
			dst->dmac = malloc(len);
			memcpy(dst->dmac, ynl_attr_data(attr), len);
		} else if (type == TCA_SKBMOD_SMAC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.smac = len;
			dst->smac = malloc(len);
			memcpy(dst->smac, ynl_attr_data(attr), len);
		} else if (type == TCA_SKBMOD_ETYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.etype = len;
			dst->etype = malloc(len);
			memcpy(dst->etype, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_act_tunnel_key_attrs_free(struct tc_act_tunnel_key_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
	free(obj->enc_ipv6_src);
	free(obj->enc_ipv6_dst);
	free(obj->enc_opts);
}

int tc_act_tunnel_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				struct tc_act_tunnel_key_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_TUNNEL_KEY_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_TUNNEL_KEY_PARMS, obj->parms, obj->_len.parms);
	if (obj->_present.enc_ipv4_src)
		ynl_attr_put_u32(nlh, TCA_TUNNEL_KEY_ENC_IPV4_SRC, obj->enc_ipv4_src);
	if (obj->_present.enc_ipv4_dst)
		ynl_attr_put_u32(nlh, TCA_TUNNEL_KEY_ENC_IPV4_DST, obj->enc_ipv4_dst);
	if (obj->_len.enc_ipv6_src)
		ynl_attr_put(nlh, TCA_TUNNEL_KEY_ENC_IPV6_SRC, obj->enc_ipv6_src, obj->_len.enc_ipv6_src);
	if (obj->_len.enc_ipv6_dst)
		ynl_attr_put(nlh, TCA_TUNNEL_KEY_ENC_IPV6_DST, obj->enc_ipv6_dst, obj->_len.enc_ipv6_dst);
	if (obj->_present.enc_key_id)
		ynl_attr_put_u64(nlh, TCA_TUNNEL_KEY_ENC_KEY_ID, obj->enc_key_id);
	if (obj->_present.enc_dst_port)
		ynl_attr_put_u16(nlh, TCA_TUNNEL_KEY_ENC_DST_PORT, obj->enc_dst_port);
	if (obj->_present.no_csum)
		ynl_attr_put_u8(nlh, TCA_TUNNEL_KEY_NO_CSUM, obj->no_csum);
	if (obj->_len.enc_opts)
		ynl_attr_put(nlh, TCA_TUNNEL_KEY_ENC_OPTS, obj->enc_opts, obj->_len.enc_opts);
	if (obj->_present.enc_tos)
		ynl_attr_put_u8(nlh, TCA_TUNNEL_KEY_ENC_TOS, obj->enc_tos);
	if (obj->_present.enc_ttl)
		ynl_attr_put_u8(nlh, TCA_TUNNEL_KEY_ENC_TTL, obj->enc_ttl);
	if (obj->_present.no_frag)
		ynl_attr_put(nlh, TCA_TUNNEL_KEY_NO_FRAG, NULL, 0);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_tunnel_key_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	struct tc_act_tunnel_key_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_TUNNEL_KEY_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_TUNNEL_KEY_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_TUNNEL_KEY_ENC_IPV4_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.enc_ipv4_src = 1;
			dst->enc_ipv4_src = ynl_attr_get_u32(attr);
		} else if (type == TCA_TUNNEL_KEY_ENC_IPV4_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.enc_ipv4_dst = 1;
			dst->enc_ipv4_dst = ynl_attr_get_u32(attr);
		} else if (type == TCA_TUNNEL_KEY_ENC_IPV6_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.enc_ipv6_src = len;
			dst->enc_ipv6_src = malloc(len);
			memcpy(dst->enc_ipv6_src, ynl_attr_data(attr), len);
		} else if (type == TCA_TUNNEL_KEY_ENC_IPV6_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.enc_ipv6_dst = len;
			dst->enc_ipv6_dst = malloc(len);
			memcpy(dst->enc_ipv6_dst, ynl_attr_data(attr), len);
		} else if (type == TCA_TUNNEL_KEY_ENC_KEY_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.enc_key_id = 1;
			dst->enc_key_id = ynl_attr_get_u64(attr);
		} else if (type == TCA_TUNNEL_KEY_ENC_DST_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.enc_dst_port = 1;
			dst->enc_dst_port = ynl_attr_get_u16(attr);
		} else if (type == TCA_TUNNEL_KEY_NO_CSUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.no_csum = 1;
			dst->no_csum = ynl_attr_get_u8(attr);
		} else if (type == TCA_TUNNEL_KEY_ENC_OPTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.enc_opts = len;
			dst->enc_opts = malloc(len);
			memcpy(dst->enc_opts, ynl_attr_data(attr), len);
		} else if (type == TCA_TUNNEL_KEY_ENC_TOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.enc_tos = 1;
			dst->enc_tos = ynl_attr_get_u8(attr);
		} else if (type == TCA_TUNNEL_KEY_ENC_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.enc_ttl = 1;
			dst->enc_ttl = ynl_attr_get_u8(attr);
		} else if (type == TCA_TUNNEL_KEY_NO_FRAG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.no_frag = 1;
		}
	}

	return 0;
}

void tc_act_vlan_attrs_free(struct tc_act_vlan_attrs *obj)
{
	free(obj->tm);
	free(obj->parms);
	free(obj->push_eth_dst);
	free(obj->push_eth_src);
}

int tc_act_vlan_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_act_vlan_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.tm)
		ynl_attr_put(nlh, TCA_VLAN_TM, obj->tm, obj->_len.tm);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_VLAN_PARMS, obj->parms, obj->_len.parms);
	if (obj->_present.push_vlan_id)
		ynl_attr_put_u16(nlh, TCA_VLAN_PUSH_VLAN_ID, obj->push_vlan_id);
	if (obj->_present.push_vlan_protocol)
		ynl_attr_put_u16(nlh, TCA_VLAN_PUSH_VLAN_PROTOCOL, obj->push_vlan_protocol);
	if (obj->_present.push_vlan_priority)
		ynl_attr_put_u8(nlh, TCA_VLAN_PUSH_VLAN_PRIORITY, obj->push_vlan_priority);
	if (obj->_len.push_eth_dst)
		ynl_attr_put(nlh, TCA_VLAN_PUSH_ETH_DST, obj->push_eth_dst, obj->_len.push_eth_dst);
	if (obj->_len.push_eth_src)
		ynl_attr_put(nlh, TCA_VLAN_PUSH_ETH_SRC, obj->push_eth_src, obj->_len.push_eth_src);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_vlan_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct tc_act_vlan_attrs *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_VLAN_TM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tm = len;
			if (len < sizeof(struct tcf_t))
				dst->tm = calloc(1, sizeof(struct tcf_t));
			else
				dst->tm = malloc(len);
			memcpy(dst->tm, ynl_attr_data(attr), len);
		} else if (type == TCA_VLAN_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			if (len < sizeof(struct tc_vlan))
				dst->parms = calloc(1, sizeof(struct tc_vlan));
			else
				dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_VLAN_PUSH_VLAN_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.push_vlan_id = 1;
			dst->push_vlan_id = ynl_attr_get_u16(attr);
		} else if (type == TCA_VLAN_PUSH_VLAN_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.push_vlan_protocol = 1;
			dst->push_vlan_protocol = ynl_attr_get_u16(attr);
		} else if (type == TCA_VLAN_PUSH_VLAN_PRIORITY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.push_vlan_priority = 1;
			dst->push_vlan_priority = ynl_attr_get_u8(attr);
		} else if (type == TCA_VLAN_PUSH_ETH_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.push_eth_dst = len;
			dst->push_eth_dst = malloc(len);
			memcpy(dst->push_eth_dst, ynl_attr_data(attr), len);
		} else if (type == TCA_VLAN_PUSH_ETH_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.push_eth_src = len;
			dst->push_eth_src = malloc(len);
			memcpy(dst->push_eth_src, ynl_attr_data(attr), len);
		}
	}

	return 0;
}

void tc_flow_attrs_free(struct tc_flow_attrs *obj)
{
	free(obj->act);
	tc_police_attrs_free(&obj->police);
	free(obj->ematches);
}

int tc_flow_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		      struct tc_flow_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.keys)
		ynl_attr_put_u32(nlh, TCA_FLOW_KEYS, obj->keys);
	if (obj->_present.mode)
		ynl_attr_put_u32(nlh, TCA_FLOW_MODE, obj->mode);
	if (obj->_present.baseclass)
		ynl_attr_put_u32(nlh, TCA_FLOW_BASECLASS, obj->baseclass);
	if (obj->_present.rshift)
		ynl_attr_put_u32(nlh, TCA_FLOW_RSHIFT, obj->rshift);
	if (obj->_present.addend)
		ynl_attr_put_u32(nlh, TCA_FLOW_ADDEND, obj->addend);
	if (obj->_present.mask)
		ynl_attr_put_u32(nlh, TCA_FLOW_MASK, obj->mask);
	if (obj->_present.xor)
		ynl_attr_put_u32(nlh, TCA_FLOW_XOR, obj->xor);
	if (obj->_present.divisor)
		ynl_attr_put_u32(nlh, TCA_FLOW_DIVISOR, obj->divisor);
	if (obj->_len.act)
		ynl_attr_put(nlh, TCA_FLOW_ACT, obj->act, obj->_len.act);
	if (obj->_present.police)
		tc_police_attrs_put(nlh, TCA_FLOW_POLICE, &obj->police);
	if (obj->_len.ematches)
		ynl_attr_put(nlh, TCA_FLOW_EMATCHES, obj->ematches, obj->_len.ematches);
	if (obj->_present.perturb)
		ynl_attr_put_u32(nlh, TCA_FLOW_PERTURB, obj->perturb);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_flow_attrs_parse(struct ynl_parse_arg *yarg,
			const struct nlattr *nested)
{
	struct tc_flow_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FLOW_KEYS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.keys = 1;
			dst->keys = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOW_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mode = 1;
			dst->mode = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOW_BASECLASS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.baseclass = 1;
			dst->baseclass = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOW_RSHIFT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rshift = 1;
			dst->rshift = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOW_ADDEND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.addend = 1;
			dst->addend = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOW_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mask = 1;
			dst->mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOW_XOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.xor = 1;
			dst->xor = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOW_DIVISOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.divisor = 1;
			dst->divisor = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOW_ACT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.act = len;
			dst->act = malloc(len);
			memcpy(dst->act, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOW_POLICE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.police = 1;

			parg.rsp_policy = &tc_police_attrs_nest;
			parg.data = &dst->police;
			if (tc_police_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_FLOW_EMATCHES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ematches = len;
			dst->ematches = malloc(len);
			memcpy(dst->ematches, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOW_PERTURB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.perturb = 1;
			dst->perturb = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_netem_attrs_free(struct tc_netem_attrs *obj)
{
	free(obj->corr);
	free(obj->delay_dist);
	free(obj->reorder);
	free(obj->corrupt);
	tc_netem_loss_attrs_free(&obj->loss);
	free(obj->rate);
	free(obj->slot);
	free(obj->slot_dist);
}

int tc_netem_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_netem_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;
	void *hdr;

	nest = ynl_attr_nest_start(nlh, attr_type);
	hdr = ynl_nlmsg_put_extra_header(nlh, sizeof(struct tc_netem_qopt));
	memcpy(hdr, &obj->_hdr, sizeof(struct tc_netem_qopt));
	if (obj->_len.corr)
		ynl_attr_put(nlh, TCA_NETEM_CORR, obj->corr, obj->_len.corr);
	if (obj->_count.delay_dist) {
		i = obj->_count.delay_dist * sizeof(__s16);
		ynl_attr_put(nlh, TCA_NETEM_DELAY_DIST, obj->delay_dist, i);
	}
	if (obj->_len.reorder)
		ynl_attr_put(nlh, TCA_NETEM_REORDER, obj->reorder, obj->_len.reorder);
	if (obj->_len.corrupt)
		ynl_attr_put(nlh, TCA_NETEM_CORRUPT, obj->corrupt, obj->_len.corrupt);
	if (obj->_present.loss)
		tc_netem_loss_attrs_put(nlh, TCA_NETEM_LOSS, &obj->loss);
	if (obj->_len.rate)
		ynl_attr_put(nlh, TCA_NETEM_RATE, obj->rate, obj->_len.rate);
	if (obj->_present.ecn)
		ynl_attr_put_u32(nlh, TCA_NETEM_ECN, obj->ecn);
	if (obj->_present.rate64)
		ynl_attr_put_u64(nlh, TCA_NETEM_RATE64, obj->rate64);
	if (obj->_present.pad)
		ynl_attr_put_u32(nlh, TCA_NETEM_PAD, obj->pad);
	if (obj->_present.latency64)
		ynl_attr_put_s64(nlh, TCA_NETEM_LATENCY64, obj->latency64);
	if (obj->_present.jitter64)
		ynl_attr_put_s64(nlh, TCA_NETEM_JITTER64, obj->jitter64);
	if (obj->_len.slot)
		ynl_attr_put(nlh, TCA_NETEM_SLOT, obj->slot, obj->_len.slot);
	if (obj->_count.slot_dist) {
		i = obj->_count.slot_dist * sizeof(__s16);
		ynl_attr_put(nlh, TCA_NETEM_SLOT_DIST, obj->slot_dist, i);
	}
	if (obj->_present.prng_seed)
		ynl_attr_put_u64(nlh, TCA_NETEM_PRNG_SEED, obj->prng_seed);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_netem_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	struct tc_netem_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	void *hdr;

	parg.ys = yarg->ys;

	hdr = ynl_attr_data(nested);
	memcpy(&dst->_hdr, hdr, sizeof(struct tc_netem_qopt));

	ynl_attr_for_each_nested_off(attr, nested, sizeof(struct tc_netem_qopt)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_NETEM_CORR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.corr = len;
			if (len < sizeof(struct tc_netem_corr))
				dst->corr = calloc(1, sizeof(struct tc_netem_corr));
			else
				dst->corr = malloc(len);
			memcpy(dst->corr, ynl_attr_data(attr), len);
		} else if (type == TCA_NETEM_DELAY_DIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.delay_dist = len / sizeof(__s16);
			len = dst->_count.delay_dist * sizeof(__s16);
			dst->delay_dist = malloc(len);
			memcpy(dst->delay_dist, ynl_attr_data(attr), len);
		} else if (type == TCA_NETEM_REORDER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.reorder = len;
			if (len < sizeof(struct tc_netem_reorder))
				dst->reorder = calloc(1, sizeof(struct tc_netem_reorder));
			else
				dst->reorder = malloc(len);
			memcpy(dst->reorder, ynl_attr_data(attr), len);
		} else if (type == TCA_NETEM_CORRUPT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.corrupt = len;
			if (len < sizeof(struct tc_netem_corrupt))
				dst->corrupt = calloc(1, sizeof(struct tc_netem_corrupt));
			else
				dst->corrupt = malloc(len);
			memcpy(dst->corrupt, ynl_attr_data(attr), len);
		} else if (type == TCA_NETEM_LOSS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.loss = 1;

			parg.rsp_policy = &tc_netem_loss_attrs_nest;
			parg.data = &dst->loss;
			if (tc_netem_loss_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_NETEM_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rate = len;
			if (len < sizeof(struct tc_netem_rate))
				dst->rate = calloc(1, sizeof(struct tc_netem_rate));
			else
				dst->rate = malloc(len);
			memcpy(dst->rate, ynl_attr_data(attr), len);
		} else if (type == TCA_NETEM_ECN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ecn = 1;
			dst->ecn = ynl_attr_get_u32(attr);
		} else if (type == TCA_NETEM_RATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.rate64 = 1;
			dst->rate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_NETEM_PAD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pad = 1;
			dst->pad = ynl_attr_get_u32(attr);
		} else if (type == TCA_NETEM_LATENCY64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.latency64 = 1;
			dst->latency64 = ynl_attr_get_s64(attr);
		} else if (type == TCA_NETEM_JITTER64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.jitter64 = 1;
			dst->jitter64 = ynl_attr_get_s64(attr);
		} else if (type == TCA_NETEM_SLOT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.slot = len;
			if (len < sizeof(struct tc_netem_slot))
				dst->slot = calloc(1, sizeof(struct tc_netem_slot));
			else
				dst->slot = malloc(len);
			memcpy(dst->slot, ynl_attr_data(attr), len);
		} else if (type == TCA_NETEM_SLOT_DIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.slot_dist = len / sizeof(__s16);
			len = dst->_count.slot_dist * sizeof(__s16);
			dst->slot_dist = malloc(len);
			memcpy(dst->slot_dist, ynl_attr_data(attr), len);
		} else if (type == TCA_NETEM_PRNG_SEED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.prng_seed = 1;
			dst->prng_seed = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

void tc_cake_stats_attrs_free(struct tc_cake_stats_attrs *obj)
{
	free(obj->tin_stats);
}

int tc_cake_stats_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    struct tc_cake_stats_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.capacity_estimate64)
		ynl_attr_put_u64(nlh, TCA_CAKE_STATS_CAPACITY_ESTIMATE64, obj->capacity_estimate64);
	if (obj->_present.memory_limit)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_MEMORY_LIMIT, obj->memory_limit);
	if (obj->_present.memory_used)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_MEMORY_USED, obj->memory_used);
	if (obj->_present.avg_netoff)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_AVG_NETOFF, obj->avg_netoff);
	if (obj->_present.min_netlen)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_MIN_NETLEN, obj->min_netlen);
	if (obj->_present.max_netlen)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_MAX_NETLEN, obj->max_netlen);
	if (obj->_present.min_adjlen)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_MIN_ADJLEN, obj->min_adjlen);
	if (obj->_present.max_adjlen)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_MAX_ADJLEN, obj->max_adjlen);
	array = ynl_attr_nest_start(nlh, TCA_CAKE_STATS_TIN_STATS);
	for (i = 0; i < obj->_count.tin_stats; i++)
		tc_cake_tin_stats_attrs_put(nlh, i, &obj->tin_stats[i]);
	ynl_attr_nest_end(nlh, array);
	if (obj->_present.deficit)
		ynl_attr_put_s32(nlh, TCA_CAKE_STATS_DEFICIT, obj->deficit);
	if (obj->_present.cobalt_count)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_COBALT_COUNT, obj->cobalt_count);
	if (obj->_present.dropping)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_DROPPING, obj->dropping);
	if (obj->_present.drop_next_us)
		ynl_attr_put_s32(nlh, TCA_CAKE_STATS_DROP_NEXT_US, obj->drop_next_us);
	if (obj->_present.p_drop)
		ynl_attr_put_u32(nlh, TCA_CAKE_STATS_P_DROP, obj->p_drop);
	if (obj->_present.blue_timer_us)
		ynl_attr_put_s32(nlh, TCA_CAKE_STATS_BLUE_TIMER_US, obj->blue_timer_us);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_cake_stats_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct tc_cake_stats_attrs *dst = yarg->data;
	const struct nlattr *attr_tin_stats = NULL;
	unsigned int n_tin_stats = 0;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->tin_stats)
		return ynl_error_parse(yarg, "attribute already present (cake-stats-attrs.tin-stats)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CAKE_STATS_CAPACITY_ESTIMATE64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.capacity_estimate64 = 1;
			dst->capacity_estimate64 = ynl_attr_get_u64(attr);
		} else if (type == TCA_CAKE_STATS_MEMORY_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.memory_limit = 1;
			dst->memory_limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_MEMORY_USED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.memory_used = 1;
			dst->memory_used = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_AVG_NETOFF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.avg_netoff = 1;
			dst->avg_netoff = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_MIN_NETLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.min_netlen = 1;
			dst->min_netlen = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_MAX_NETLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_netlen = 1;
			dst->max_netlen = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_MIN_ADJLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.min_adjlen = 1;
			dst->min_adjlen = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_MAX_ADJLEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.max_adjlen = 1;
			dst->max_adjlen = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_TIN_STATS) {
			attr_tin_stats = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_tin_stats++;
			}
		} else if (type == TCA_CAKE_STATS_DEFICIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.deficit = 1;
			dst->deficit = ynl_attr_get_s32(attr);
		} else if (type == TCA_CAKE_STATS_COBALT_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.cobalt_count = 1;
			dst->cobalt_count = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_DROPPING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dropping = 1;
			dst->dropping = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_DROP_NEXT_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.drop_next_us = 1;
			dst->drop_next_us = ynl_attr_get_s32(attr);
		} else if (type == TCA_CAKE_STATS_P_DROP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.p_drop = 1;
			dst->p_drop = ynl_attr_get_u32(attr);
		} else if (type == TCA_CAKE_STATS_BLUE_TIMER_US) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.blue_timer_us = 1;
			dst->blue_timer_us = ynl_attr_get_s32(attr);
		}
	}

	if (n_tin_stats) {
		dst->tin_stats = calloc(n_tin_stats, sizeof(*dst->tin_stats));
		dst->_count.tin_stats = n_tin_stats;
		i = 0;
		parg.rsp_policy = &tc_cake_tin_stats_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_tin_stats) {
			parg.data = &dst->tin_stats[i];
			if (tc_cake_tin_stats_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void
tc_flower_key_enc_opts_attrs_free(struct tc_flower_key_enc_opts_attrs *obj)
{
	tc_flower_key_enc_opt_geneve_attrs_free(&obj->geneve);
	tc_flower_key_enc_opt_vxlan_attrs_free(&obj->vxlan);
	tc_flower_key_enc_opt_erspan_attrs_free(&obj->erspan);
	tc_flower_key_enc_opt_gtp_attrs_free(&obj->gtp);
}

int tc_flower_key_enc_opts_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     struct tc_flower_key_enc_opts_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.geneve)
		tc_flower_key_enc_opt_geneve_attrs_put(nlh, TCA_FLOWER_KEY_ENC_OPTS_GENEVE, &obj->geneve);
	if (obj->_present.vxlan)
		tc_flower_key_enc_opt_vxlan_attrs_put(nlh, TCA_FLOWER_KEY_ENC_OPTS_VXLAN, &obj->vxlan);
	if (obj->_present.erspan)
		tc_flower_key_enc_opt_erspan_attrs_put(nlh, TCA_FLOWER_KEY_ENC_OPTS_ERSPAN, &obj->erspan);
	if (obj->_present.gtp)
		tc_flower_key_enc_opt_gtp_attrs_put(nlh, TCA_FLOWER_KEY_ENC_OPTS_GTP, &obj->gtp);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_flower_key_enc_opts_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	struct tc_flower_key_enc_opts_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FLOWER_KEY_ENC_OPTS_GENEVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.geneve = 1;

			parg.rsp_policy = &tc_flower_key_enc_opt_geneve_attrs_nest;
			parg.data = &dst->geneve;
			if (tc_flower_key_enc_opt_geneve_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_FLOWER_KEY_ENC_OPTS_VXLAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vxlan = 1;

			parg.rsp_policy = &tc_flower_key_enc_opt_vxlan_attrs_nest;
			parg.data = &dst->vxlan;
			if (tc_flower_key_enc_opt_vxlan_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_FLOWER_KEY_ENC_OPTS_ERSPAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.erspan = 1;

			parg.rsp_policy = &tc_flower_key_enc_opt_erspan_attrs_nest;
			parg.data = &dst->erspan;
			if (tc_flower_key_enc_opt_erspan_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_FLOWER_KEY_ENC_OPTS_GTP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.gtp = 1;

			parg.rsp_policy = &tc_flower_key_enc_opt_gtp_attrs_nest;
			parg.data = &dst->gtp;
			if (tc_flower_key_enc_opt_gtp_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void tc_tca_gred_vq_list_attrs_free(struct tc_tca_gred_vq_list_attrs *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.entry; i++)
		tc_tca_gred_vq_entry_attrs_free(&obj->entry[i]);
	free(obj->entry);
}

int tc_tca_gred_vq_list_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  struct tc_tca_gred_vq_list_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (i = 0; i < obj->_count.entry; i++)
		tc_tca_gred_vq_entry_attrs_put(nlh, TCA_GRED_VQ_ENTRY, &obj->entry[i]);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_tca_gred_vq_list_attrs_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested)
{
	struct tc_tca_gred_vq_list_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_entry = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->entry)
		return ynl_error_parse(yarg, "attribute already present (tca-gred-vq-list-attrs.entry)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_GRED_VQ_ENTRY) {
			n_entry++;
		}
	}

	if (n_entry) {
		dst->entry = calloc(n_entry, sizeof(*dst->entry));
		dst->_count.entry = n_entry;
		i = 0;
		parg.rsp_policy = &tc_tca_gred_vq_entry_attrs_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == TCA_GRED_VQ_ENTRY) {
				parg.data = &dst->entry[i];
				if (tc_tca_gred_vq_entry_attrs_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void tc_taprio_sched_entry_list_free(struct tc_taprio_sched_entry_list *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.entry; i++)
		tc_taprio_sched_entry_free(&obj->entry[i]);
	free(obj->entry);
}

int tc_taprio_sched_entry_list_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   struct tc_taprio_sched_entry_list *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (i = 0; i < obj->_count.entry; i++)
		tc_taprio_sched_entry_put(nlh, TCA_TAPRIO_SCHED_ENTRY, &obj->entry[i]);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_taprio_sched_entry_list_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct tc_taprio_sched_entry_list *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_entry = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->entry)
		return ynl_error_parse(yarg, "attribute already present (taprio-sched-entry-list.entry)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_TAPRIO_SCHED_ENTRY) {
			n_entry++;
		}
	}

	if (n_entry) {
		dst->entry = calloc(n_entry, sizeof(*dst->entry));
		dst->_count.entry = n_entry;
		i = 0;
		parg.rsp_policy = &tc_taprio_sched_entry_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == TCA_TAPRIO_SCHED_ENTRY) {
				parg.data = &dst->entry[i];
				if (tc_taprio_sched_entry_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void tc_act_options_msg_free(struct tc_act_options_msg *obj)
{
	tc_act_bpf_attrs_free(&obj->bpf);
	tc_act_connmark_attrs_free(&obj->connmark);
	tc_act_csum_attrs_free(&obj->csum);
	tc_act_ct_attrs_free(&obj->ct);
	tc_act_ctinfo_attrs_free(&obj->ctinfo);
	tc_act_gact_attrs_free(&obj->gact);
	tc_act_gate_attrs_free(&obj->gate);
	tc_act_ife_attrs_free(&obj->ife);
	tc_act_mirred_attrs_free(&obj->mirred);
	tc_act_mpls_attrs_free(&obj->mpls);
	tc_act_nat_attrs_free(&obj->nat);
	tc_act_pedit_attrs_free(&obj->pedit);
	tc_police_attrs_free(&obj->police);
	tc_act_sample_attrs_free(&obj->sample);
	tc_act_simple_attrs_free(&obj->simple);
	tc_act_skbedit_attrs_free(&obj->skbedit);
	tc_act_skbmod_attrs_free(&obj->skbmod);
	tc_act_tunnel_key_attrs_free(&obj->tunnel_key);
	tc_act_vlan_attrs_free(&obj->vlan);
}

int tc_act_options_msg_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct tc_act_options_msg *obj)
{
	if (obj->_present.bpf)
		tc_act_bpf_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->bpf);
	if (obj->_present.connmark)
		tc_act_connmark_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->connmark);
	if (obj->_present.csum)
		tc_act_csum_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->csum);
	if (obj->_present.ct)
		tc_act_ct_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->ct);
	if (obj->_present.ctinfo)
		tc_act_ctinfo_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->ctinfo);
	if (obj->_present.gact)
		tc_act_gact_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->gact);
	if (obj->_present.gate)
		tc_act_gate_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->gate);
	if (obj->_present.ife)
		tc_act_ife_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->ife);
	if (obj->_present.mirred)
		tc_act_mirred_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->mirred);
	if (obj->_present.mpls)
		tc_act_mpls_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->mpls);
	if (obj->_present.nat)
		tc_act_nat_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->nat);
	if (obj->_present.pedit)
		tc_act_pedit_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->pedit);
	if (obj->_present.police)
		tc_police_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->police);
	if (obj->_present.sample)
		tc_act_sample_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->sample);
	if (obj->_present.simple)
		tc_act_simple_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->simple);
	if (obj->_present.skbedit)
		tc_act_skbedit_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->skbedit);
	if (obj->_present.skbmod)
		tc_act_skbmod_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->skbmod);
	if (obj->_present.tunnel_key)
		tc_act_tunnel_key_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->tunnel_key);
	if (obj->_present.vlan)
		tc_act_vlan_attrs_put(nlh, TCA_ACT_OPTIONS, &obj->vlan);

	return 0;
}

int tc_act_options_msg_parse(struct ynl_parse_arg *yarg, const char *sel,
			     const struct nlattr *nested)
{
	struct tc_act_options_msg *dst = yarg->data;
	const struct nlattr *attr = nested;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	if (!strcmp(sel, "bpf")) {
		parg.rsp_policy = &tc_act_bpf_attrs_nest;
		parg.data = &dst->bpf;
		if (tc_act_bpf_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.bpf = 1;
	} else if (!strcmp(sel, "connmark")) {
		parg.rsp_policy = &tc_act_connmark_attrs_nest;
		parg.data = &dst->connmark;
		if (tc_act_connmark_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.connmark = 1;
	} else if (!strcmp(sel, "csum")) {
		parg.rsp_policy = &tc_act_csum_attrs_nest;
		parg.data = &dst->csum;
		if (tc_act_csum_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.csum = 1;
	} else if (!strcmp(sel, "ct")) {
		parg.rsp_policy = &tc_act_ct_attrs_nest;
		parg.data = &dst->ct;
		if (tc_act_ct_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.ct = 1;
	} else if (!strcmp(sel, "ctinfo")) {
		parg.rsp_policy = &tc_act_ctinfo_attrs_nest;
		parg.data = &dst->ctinfo;
		if (tc_act_ctinfo_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.ctinfo = 1;
	} else if (!strcmp(sel, "gact")) {
		parg.rsp_policy = &tc_act_gact_attrs_nest;
		parg.data = &dst->gact;
		if (tc_act_gact_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.gact = 1;
	} else if (!strcmp(sel, "gate")) {
		parg.rsp_policy = &tc_act_gate_attrs_nest;
		parg.data = &dst->gate;
		if (tc_act_gate_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.gate = 1;
	} else if (!strcmp(sel, "ife")) {
		parg.rsp_policy = &tc_act_ife_attrs_nest;
		parg.data = &dst->ife;
		if (tc_act_ife_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.ife = 1;
	} else if (!strcmp(sel, "mirred")) {
		parg.rsp_policy = &tc_act_mirred_attrs_nest;
		parg.data = &dst->mirred;
		if (tc_act_mirred_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.mirred = 1;
	} else if (!strcmp(sel, "mpls")) {
		parg.rsp_policy = &tc_act_mpls_attrs_nest;
		parg.data = &dst->mpls;
		if (tc_act_mpls_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.mpls = 1;
	} else if (!strcmp(sel, "nat")) {
		parg.rsp_policy = &tc_act_nat_attrs_nest;
		parg.data = &dst->nat;
		if (tc_act_nat_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.nat = 1;
	} else if (!strcmp(sel, "pedit")) {
		parg.rsp_policy = &tc_act_pedit_attrs_nest;
		parg.data = &dst->pedit;
		if (tc_act_pedit_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.pedit = 1;
	} else if (!strcmp(sel, "police")) {
		parg.rsp_policy = &tc_police_attrs_nest;
		parg.data = &dst->police;
		if (tc_police_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.police = 1;
	} else if (!strcmp(sel, "sample")) {
		parg.rsp_policy = &tc_act_sample_attrs_nest;
		parg.data = &dst->sample;
		if (tc_act_sample_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.sample = 1;
	} else if (!strcmp(sel, "simple")) {
		parg.rsp_policy = &tc_act_simple_attrs_nest;
		parg.data = &dst->simple;
		if (tc_act_simple_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.simple = 1;
	} else if (!strcmp(sel, "skbedit")) {
		parg.rsp_policy = &tc_act_skbedit_attrs_nest;
		parg.data = &dst->skbedit;
		if (tc_act_skbedit_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.skbedit = 1;
	} else if (!strcmp(sel, "skbmod")) {
		parg.rsp_policy = &tc_act_skbmod_attrs_nest;
		parg.data = &dst->skbmod;
		if (tc_act_skbmod_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.skbmod = 1;
	} else if (!strcmp(sel, "tunnel_key")) {
		parg.rsp_policy = &tc_act_tunnel_key_attrs_nest;
		parg.data = &dst->tunnel_key;
		if (tc_act_tunnel_key_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.tunnel_key = 1;
	} else if (!strcmp(sel, "vlan")) {
		parg.rsp_policy = &tc_act_vlan_attrs_nest;
		parg.data = &dst->vlan;
		if (tc_act_vlan_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.vlan = 1;
	}
	return 0;
}

void tc_tca_stats_app_msg_free(struct tc_tca_stats_app_msg *obj)
{
	tc_cake_stats_attrs_free(&obj->cake);
	free(obj->choke);
	free(obj->codel);
	free(obj->dualpi2);
	free(obj->fq);
	free(obj->fq_codel);
	free(obj->fq_pie);
	free(obj->hhf);
	free(obj->pie);
	free(obj->red);
	free(obj->sfb);
	free(obj->sfq);
}

int tc_tca_stats_app_msg_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     struct tc_tca_stats_app_msg *obj)
{
	if (obj->_present.cake)
		tc_cake_stats_attrs_put(nlh, TCA_XSTATS, &obj->cake);
	if (obj->_len.choke)
		ynl_attr_put(nlh, TCA_XSTATS, obj->choke, obj->_len.choke);
	if (obj->_len.codel)
		ynl_attr_put(nlh, TCA_XSTATS, obj->codel, obj->_len.codel);
	if (obj->_len.dualpi2)
		ynl_attr_put(nlh, TCA_XSTATS, obj->dualpi2, obj->_len.dualpi2);
	if (obj->_len.fq)
		ynl_attr_put(nlh, TCA_XSTATS, obj->fq, obj->_len.fq);
	if (obj->_len.fq_codel)
		ynl_attr_put(nlh, TCA_XSTATS, obj->fq_codel, obj->_len.fq_codel);
	if (obj->_len.fq_pie)
		ynl_attr_put(nlh, TCA_XSTATS, obj->fq_pie, obj->_len.fq_pie);
	if (obj->_len.hhf)
		ynl_attr_put(nlh, TCA_XSTATS, obj->hhf, obj->_len.hhf);
	if (obj->_len.pie)
		ynl_attr_put(nlh, TCA_XSTATS, obj->pie, obj->_len.pie);
	if (obj->_len.red)
		ynl_attr_put(nlh, TCA_XSTATS, obj->red, obj->_len.red);
	if (obj->_len.sfb)
		ynl_attr_put(nlh, TCA_XSTATS, obj->sfb, obj->_len.sfb);
	if (obj->_len.sfq)
		ynl_attr_put(nlh, TCA_XSTATS, obj->sfq, obj->_len.sfq);

	return 0;
}

int tc_tca_stats_app_msg_parse(struct ynl_parse_arg *yarg, const char *sel,
			       const struct nlattr *nested)
{
	struct tc_tca_stats_app_msg *dst = yarg->data;
	const struct nlattr *attr = nested;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	if (!strcmp(sel, "cake")) {
		parg.rsp_policy = &tc_cake_stats_attrs_nest;
		parg.data = &dst->cake;
		if (tc_cake_stats_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.cake = 1;
	} else if (!strcmp(sel, "choke")) {
		len = ynl_attr_data_len(attr);
		dst->_len.choke = len;
		if (len < sizeof(struct tc_choke_xstats))
			dst->choke = calloc(1, sizeof(struct tc_choke_xstats));
		else
			dst->choke = malloc(len);
		memcpy(dst->choke, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "codel")) {
		len = ynl_attr_data_len(attr);
		dst->_len.codel = len;
		if (len < sizeof(struct tc_codel_xstats))
			dst->codel = calloc(1, sizeof(struct tc_codel_xstats));
		else
			dst->codel = malloc(len);
		memcpy(dst->codel, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "dualpi2")) {
		len = ynl_attr_data_len(attr);
		dst->_len.dualpi2 = len;
		if (len < sizeof(struct tc_dualpi2_xstats))
			dst->dualpi2 = calloc(1, sizeof(struct tc_dualpi2_xstats));
		else
			dst->dualpi2 = malloc(len);
		memcpy(dst->dualpi2, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "fq")) {
		len = ynl_attr_data_len(attr);
		dst->_len.fq = len;
		if (len < sizeof(struct tc_fq_qd_stats))
			dst->fq = calloc(1, sizeof(struct tc_fq_qd_stats));
		else
			dst->fq = malloc(len);
		memcpy(dst->fq, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "fq_codel")) {
		len = ynl_attr_data_len(attr);
		dst->_len.fq_codel = len;
		if (len < sizeof(struct tc_fq_codel_xstats))
			dst->fq_codel = calloc(1, sizeof(struct tc_fq_codel_xstats));
		else
			dst->fq_codel = malloc(len);
		memcpy(dst->fq_codel, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "fq_pie")) {
		len = ynl_attr_data_len(attr);
		dst->_len.fq_pie = len;
		if (len < sizeof(struct tc_fq_pie_xstats))
			dst->fq_pie = calloc(1, sizeof(struct tc_fq_pie_xstats));
		else
			dst->fq_pie = malloc(len);
		memcpy(dst->fq_pie, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "hhf")) {
		len = ynl_attr_data_len(attr);
		dst->_len.hhf = len;
		if (len < sizeof(struct tc_hhf_xstats))
			dst->hhf = calloc(1, sizeof(struct tc_hhf_xstats));
		else
			dst->hhf = malloc(len);
		memcpy(dst->hhf, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "pie")) {
		len = ynl_attr_data_len(attr);
		dst->_len.pie = len;
		if (len < sizeof(struct tc_pie_xstats))
			dst->pie = calloc(1, sizeof(struct tc_pie_xstats));
		else
			dst->pie = malloc(len);
		memcpy(dst->pie, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "red")) {
		len = ynl_attr_data_len(attr);
		dst->_len.red = len;
		if (len < sizeof(struct tc_red_xstats))
			dst->red = calloc(1, sizeof(struct tc_red_xstats));
		else
			dst->red = malloc(len);
		memcpy(dst->red, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "sfb")) {
		len = ynl_attr_data_len(attr);
		dst->_len.sfb = len;
		if (len < sizeof(struct tc_sfb_xstats))
			dst->sfb = calloc(1, sizeof(struct tc_sfb_xstats));
		else
			dst->sfb = malloc(len);
		memcpy(dst->sfb, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "sfq")) {
		len = ynl_attr_data_len(attr);
		dst->_len.sfq = len;
		if (len < sizeof(struct tc_sfq_xstats))
			dst->sfq = calloc(1, sizeof(struct tc_sfq_xstats));
		else
			dst->sfq = malloc(len);
		memcpy(dst->sfq, ynl_attr_data(attr), len);
	}
	return 0;
}

void tc_tca_stats_attrs_free(struct tc_tca_stats_attrs *obj)
{
	free(obj->basic);
	free(obj->rate_est);
	free(obj->queue);
	tc_tca_stats_app_msg_free(&obj->app);
	free(obj->rate_est64);
	free(obj->basic_hw);
}

int tc_tca_stats_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   struct tc_tca_stats_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.basic)
		ynl_attr_put(nlh, TCA_STATS_BASIC, obj->basic, obj->_len.basic);
	if (obj->_len.rate_est)
		ynl_attr_put(nlh, TCA_STATS_RATE_EST, obj->rate_est, obj->_len.rate_est);
	if (obj->_len.queue)
		ynl_attr_put(nlh, TCA_STATS_QUEUE, obj->queue, obj->_len.queue);
	if (obj->_present.app)
		tc_tca_stats_app_msg_put(nlh, TCA_STATS_APP, &obj->app);
	if (obj->_len.rate_est64)
		ynl_attr_put(nlh, TCA_STATS_RATE_EST64, obj->rate_est64, obj->_len.rate_est64);
	if (obj->_len.basic_hw)
		ynl_attr_put(nlh, TCA_STATS_BASIC_HW, obj->basic_hw, obj->_len.basic_hw);
	if (obj->_present.pkt64)
		ynl_attr_put_u64(nlh, TCA_STATS_PKT64, obj->pkt64);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_tca_stats_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested,
			     const char *_sel_kind)
{
	struct tc_tca_stats_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_STATS_BASIC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.basic = len;
			if (len < sizeof(struct gnet_stats_basic))
				dst->basic = calloc(1, sizeof(struct gnet_stats_basic));
			else
				dst->basic = malloc(len);
			memcpy(dst->basic, ynl_attr_data(attr), len);
		} else if (type == TCA_STATS_RATE_EST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rate_est = len;
			if (len < sizeof(struct gnet_stats_rate_est))
				dst->rate_est = calloc(1, sizeof(struct gnet_stats_rate_est));
			else
				dst->rate_est = malloc(len);
			memcpy(dst->rate_est, ynl_attr_data(attr), len);
		} else if (type == TCA_STATS_QUEUE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.queue = len;
			if (len < sizeof(struct gnet_stats_queue))
				dst->queue = calloc(1, sizeof(struct gnet_stats_queue));
			else
				dst->queue = malloc(len);
			memcpy(dst->queue, ynl_attr_data(attr), len);
		} else if (type == TCA_STATS_APP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.app = 1;

			parg.rsp_policy = &tc_tca_stats_app_msg_nest;
			parg.data = &dst->app;
			if (!_sel_kind)
				return ynl_submsg_failed(yarg, "app", "kind");
			if (tc_tca_stats_app_msg_parse(&parg, _sel_kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_STATS_RATE_EST64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rate_est64 = len;
			if (len < sizeof(struct gnet_stats_rate_est64))
				dst->rate_est64 = calloc(1, sizeof(struct gnet_stats_rate_est64));
			else
				dst->rate_est64 = malloc(len);
			memcpy(dst->rate_est64, ynl_attr_data(attr), len);
		} else if (type == TCA_STATS_BASIC_HW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.basic_hw = len;
			if (len < sizeof(struct gnet_stats_basic))
				dst->basic_hw = calloc(1, sizeof(struct gnet_stats_basic));
			else
				dst->basic_hw = malloc(len);
			memcpy(dst->basic_hw, ynl_attr_data(attr), len);
		} else if (type == TCA_STATS_PKT64) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.pkt64 = 1;
			dst->pkt64 = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

void tc_gred_attrs_free(struct tc_gred_attrs *obj)
{
	free(obj->parms);
	free(obj->stab);
	free(obj->dps);
	free(obj->max_p);
	tc_tca_gred_vq_list_attrs_free(&obj->vq_list);
}

int tc_gred_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		      struct tc_gred_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.parms)
		ynl_attr_put(nlh, TCA_GRED_PARMS, obj->parms, obj->_len.parms);
	if (obj->_count.stab) {
		i = obj->_count.stab * sizeof(__u8);
		ynl_attr_put(nlh, TCA_GRED_STAB, obj->stab, i);
	}
	if (obj->_len.dps)
		ynl_attr_put(nlh, TCA_GRED_DPS, obj->dps, obj->_len.dps);
	if (obj->_count.max_p) {
		i = obj->_count.max_p * sizeof(__u32);
		ynl_attr_put(nlh, TCA_GRED_MAX_P, obj->max_p, i);
	}
	if (obj->_present.limit)
		ynl_attr_put_u32(nlh, TCA_GRED_LIMIT, obj->limit);
	if (obj->_present.vq_list)
		tc_tca_gred_vq_list_attrs_put(nlh, TCA_GRED_VQ_LIST, &obj->vq_list);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_gred_attrs_parse(struct ynl_parse_arg *yarg,
			const struct nlattr *nested)
{
	struct tc_gred_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_GRED_PARMS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.parms = len;
			dst->parms = malloc(len);
			memcpy(dst->parms, ynl_attr_data(attr), len);
		} else if (type == TCA_GRED_STAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.stab = len / sizeof(__u8);
			len = dst->_count.stab * sizeof(__u8);
			dst->stab = malloc(len);
			memcpy(dst->stab, ynl_attr_data(attr), len);
		} else if (type == TCA_GRED_DPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dps = len;
			if (len < sizeof(struct tc_gred_sopt))
				dst->dps = calloc(1, sizeof(struct tc_gred_sopt));
			else
				dst->dps = malloc(len);
			memcpy(dst->dps, ynl_attr_data(attr), len);
		} else if (type == TCA_GRED_MAX_P) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_count.max_p = len / sizeof(__u32);
			len = dst->_count.max_p * sizeof(__u32);
			dst->max_p = malloc(len);
			memcpy(dst->max_p, ynl_attr_data(attr), len);
		} else if (type == TCA_GRED_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.limit = 1;
			dst->limit = ynl_attr_get_u32(attr);
		} else if (type == TCA_GRED_VQ_LIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.vq_list = 1;

			parg.rsp_policy = &tc_tca_gred_vq_list_attrs_nest;
			parg.data = &dst->vq_list;
			if (tc_tca_gred_vq_list_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void tc_taprio_attrs_free(struct tc_taprio_attrs *obj)
{
	free(obj->priomap);
	tc_taprio_sched_entry_list_free(&obj->sched_entry_list);
	tc_taprio_sched_entry_free(&obj->sched_single_entry);
	free(obj->admin_sched);
	tc_taprio_tc_entry_attrs_free(&obj->tc_entry);
}

int tc_taprio_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_taprio_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.priomap)
		ynl_attr_put(nlh, TCA_TAPRIO_ATTR_PRIOMAP, obj->priomap, obj->_len.priomap);
	if (obj->_present.sched_entry_list)
		tc_taprio_sched_entry_list_put(nlh, TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST, &obj->sched_entry_list);
	if (obj->_present.sched_base_time)
		ynl_attr_put_s64(nlh, TCA_TAPRIO_ATTR_SCHED_BASE_TIME, obj->sched_base_time);
	if (obj->_present.sched_single_entry)
		tc_taprio_sched_entry_put(nlh, TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY, &obj->sched_single_entry);
	if (obj->_present.sched_clockid)
		ynl_attr_put_s32(nlh, TCA_TAPRIO_ATTR_SCHED_CLOCKID, obj->sched_clockid);
	if (obj->_len.admin_sched)
		ynl_attr_put(nlh, TCA_TAPRIO_ATTR_ADMIN_SCHED, obj->admin_sched, obj->_len.admin_sched);
	if (obj->_present.sched_cycle_time)
		ynl_attr_put_s64(nlh, TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME, obj->sched_cycle_time);
	if (obj->_present.sched_cycle_time_extension)
		ynl_attr_put_s64(nlh, TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION, obj->sched_cycle_time_extension);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, TCA_TAPRIO_ATTR_FLAGS, obj->flags);
	if (obj->_present.txtime_delay)
		ynl_attr_put_u32(nlh, TCA_TAPRIO_ATTR_TXTIME_DELAY, obj->txtime_delay);
	if (obj->_present.tc_entry)
		tc_taprio_tc_entry_attrs_put(nlh, TCA_TAPRIO_ATTR_TC_ENTRY, &obj->tc_entry);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_taprio_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	struct tc_taprio_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_TAPRIO_ATTR_PRIOMAP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.priomap = len;
			if (len < sizeof(struct tc_mqprio_qopt))
				dst->priomap = calloc(1, sizeof(struct tc_mqprio_qopt));
			else
				dst->priomap = malloc(len);
			memcpy(dst->priomap, ynl_attr_data(attr), len);
		} else if (type == TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sched_entry_list = 1;

			parg.rsp_policy = &tc_taprio_sched_entry_list_nest;
			parg.data = &dst->sched_entry_list;
			if (tc_taprio_sched_entry_list_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_TAPRIO_ATTR_SCHED_BASE_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sched_base_time = 1;
			dst->sched_base_time = ynl_attr_get_s64(attr);
		} else if (type == TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sched_single_entry = 1;

			parg.rsp_policy = &tc_taprio_sched_entry_nest;
			parg.data = &dst->sched_single_entry;
			if (tc_taprio_sched_entry_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_TAPRIO_ATTR_SCHED_CLOCKID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sched_clockid = 1;
			dst->sched_clockid = ynl_attr_get_s32(attr);
		} else if (type == TCA_TAPRIO_ATTR_ADMIN_SCHED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.admin_sched = len;
			dst->admin_sched = malloc(len);
			memcpy(dst->admin_sched, ynl_attr_data(attr), len);
		} else if (type == TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sched_cycle_time = 1;
			dst->sched_cycle_time = ynl_attr_get_s64(attr);
		} else if (type == TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sched_cycle_time_extension = 1;
			dst->sched_cycle_time_extension = ynl_attr_get_s64(attr);
		} else if (type == TCA_TAPRIO_ATTR_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == TCA_TAPRIO_ATTR_TXTIME_DELAY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.txtime_delay = 1;
			dst->txtime_delay = ynl_attr_get_u32(attr);
		} else if (type == TCA_TAPRIO_ATTR_TC_ENTRY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.tc_entry = 1;

			parg.rsp_policy = &tc_taprio_tc_entry_attrs_nest;
			parg.data = &dst->tc_entry;
			if (tc_taprio_tc_entry_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void tc_act_attrs_free(struct tc_act_attrs *obj)
{
	free(obj->kind);
	tc_act_options_msg_free(&obj->options);
	tc_tca_stats_attrs_free(&obj->stats);
	free(obj->cookie);
}

int tc_act_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_act_attrs *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.kind)
		ynl_attr_put_str(nlh, TCA_ACT_KIND, obj->kind);
	if (obj->_present.options)
		tc_act_options_msg_put(nlh, TCA_ACT_OPTIONS, &obj->options);
	if (obj->_present.index)
		ynl_attr_put_u32(nlh, TCA_ACT_INDEX, obj->index);
	if (obj->_present.stats)
		tc_tca_stats_attrs_put(nlh, TCA_ACT_STATS, &obj->stats);
	if (obj->_len.cookie)
		ynl_attr_put(nlh, TCA_ACT_COOKIE, obj->cookie, obj->_len.cookie);
	if (obj->_present.flags)
		ynl_attr_put(nlh, TCA_ACT_FLAGS, &obj->flags, sizeof(struct nla_bitfield32));
	if (obj->_present.hw_stats)
		ynl_attr_put(nlh, TCA_ACT_HW_STATS, &obj->hw_stats, sizeof(struct nla_bitfield32));
	if (obj->_present.used_hw_stats)
		ynl_attr_put(nlh, TCA_ACT_USED_HW_STATS, &obj->used_hw_stats, sizeof(struct nla_bitfield32));
	if (obj->_present.in_hw_count)
		ynl_attr_put_u32(nlh, TCA_ACT_IN_HW_COUNT, obj->in_hw_count);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_act_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested,
		       __u32 idx)
{
	struct tc_act_attrs *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_ACT_KIND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.kind = len;
			dst->kind = malloc(len + 1);
			memcpy(dst->kind, ynl_attr_get_str(attr), len);
			dst->kind[len] = 0;
		} else if (type == TCA_ACT_OPTIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.options = 1;

			parg.rsp_policy = &tc_act_options_msg_nest;
			parg.data = &dst->options;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "options", "kind");
			if (tc_act_options_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_ACT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.index = 1;
			dst->index = ynl_attr_get_u32(attr);
		} else if (type == TCA_ACT_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stats = 1;

			parg.rsp_policy = &tc_tca_stats_attrs_nest;
			parg.data = &dst->stats;
			if (tc_tca_stats_attrs_parse(&parg, attr, dst->kind))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_ACT_COOKIE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.cookie = len;
			dst->cookie = malloc(len);
			memcpy(dst->cookie, ynl_attr_data(attr), len);
		} else if (type == TCA_ACT_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			memcpy(&dst->flags, ynl_attr_data(attr), sizeof(struct nla_bitfield32));
		} else if (type == TCA_ACT_HW_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hw_stats = 1;
			memcpy(&dst->hw_stats, ynl_attr_data(attr), sizeof(struct nla_bitfield32));
		} else if (type == TCA_ACT_USED_HW_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.used_hw_stats = 1;
			memcpy(&dst->used_hw_stats, ynl_attr_data(attr), sizeof(struct nla_bitfield32));
		} else if (type == TCA_ACT_IN_HW_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.in_hw_count = 1;
			dst->in_hw_count = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void tc_basic_attrs_free(struct tc_basic_attrs *obj)
{
	tc_ematch_attrs_free(&obj->ematches);
	free(obj->act);
	tc_police_attrs_free(&obj->police);
	free(obj->pcnt);
}

int tc_basic_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_basic_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.classid)
		ynl_attr_put_u32(nlh, TCA_BASIC_CLASSID, obj->classid);
	if (obj->_present.ematches)
		tc_ematch_attrs_put(nlh, TCA_BASIC_EMATCHES, &obj->ematches);
	array = ynl_attr_nest_start(nlh, TCA_BASIC_ACT);
	for (i = 0; i < obj->_count.act; i++)
		tc_act_attrs_put(nlh, i, &obj->act[i]);
	ynl_attr_nest_end(nlh, array);
	if (obj->_present.police)
		tc_police_attrs_put(nlh, TCA_BASIC_POLICE, &obj->police);
	if (obj->_len.pcnt)
		ynl_attr_put(nlh, TCA_BASIC_PCNT, obj->pcnt, obj->_len.pcnt);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_basic_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	struct tc_basic_attrs *dst = yarg->data;
	const struct nlattr *attr_act = NULL;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_act = 0;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->act)
		return ynl_error_parse(yarg, "attribute already present (basic-attrs.act)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_BASIC_CLASSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.classid = 1;
			dst->classid = ynl_attr_get_u32(attr);
		} else if (type == TCA_BASIC_EMATCHES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ematches = 1;

			parg.rsp_policy = &tc_ematch_attrs_nest;
			parg.data = &dst->ematches;
			if (tc_ematch_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_BASIC_ACT) {
			attr_act = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_act++;
			}
		} else if (type == TCA_BASIC_POLICE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.police = 1;

			parg.rsp_policy = &tc_police_attrs_nest;
			parg.data = &dst->police;
			if (tc_police_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_BASIC_PCNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.pcnt = len;
			if (len < sizeof(struct tc_basic_pcnt))
				dst->pcnt = calloc(1, sizeof(struct tc_basic_pcnt));
			else
				dst->pcnt = malloc(len);
			memcpy(dst->pcnt, ynl_attr_data(attr), len);
		}
	}

	if (n_act) {
		dst->act = calloc(n_act, sizeof(*dst->act));
		dst->_count.act = n_act;
		i = 0;
		parg.rsp_policy = &tc_act_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_act) {
			parg.data = &dst->act[i];
			if (tc_act_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void tc_bpf_attrs_free(struct tc_bpf_attrs *obj)
{
	free(obj->act);
	tc_police_attrs_free(&obj->police);
	free(obj->ops);
	free(obj->name);
	free(obj->tag);
}

int tc_bpf_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_bpf_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	array = ynl_attr_nest_start(nlh, TCA_BPF_ACT);
	for (i = 0; i < obj->_count.act; i++)
		tc_act_attrs_put(nlh, i, &obj->act[i]);
	ynl_attr_nest_end(nlh, array);
	if (obj->_present.police)
		tc_police_attrs_put(nlh, TCA_BPF_POLICE, &obj->police);
	if (obj->_present.classid)
		ynl_attr_put_u32(nlh, TCA_BPF_CLASSID, obj->classid);
	if (obj->_present.ops_len)
		ynl_attr_put_u16(nlh, TCA_BPF_OPS_LEN, obj->ops_len);
	if (obj->_len.ops)
		ynl_attr_put(nlh, TCA_BPF_OPS, obj->ops, obj->_len.ops);
	if (obj->_present.fd)
		ynl_attr_put_u32(nlh, TCA_BPF_FD, obj->fd);
	if (obj->_len.name)
		ynl_attr_put_str(nlh, TCA_BPF_NAME, obj->name);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, TCA_BPF_FLAGS, obj->flags);
	if (obj->_present.flags_gen)
		ynl_attr_put_u32(nlh, TCA_BPF_FLAGS_GEN, obj->flags_gen);
	if (obj->_len.tag)
		ynl_attr_put(nlh, TCA_BPF_TAG, obj->tag, obj->_len.tag);
	if (obj->_present.id)
		ynl_attr_put_u32(nlh, TCA_BPF_ID, obj->id);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_bpf_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_bpf_attrs *dst = yarg->data;
	const struct nlattr *attr_act = NULL;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_act = 0;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->act)
		return ynl_error_parse(yarg, "attribute already present (bpf-attrs.act)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_BPF_ACT) {
			attr_act = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_act++;
			}
		} else if (type == TCA_BPF_POLICE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.police = 1;

			parg.rsp_policy = &tc_police_attrs_nest;
			parg.data = &dst->police;
			if (tc_police_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_BPF_CLASSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.classid = 1;
			dst->classid = ynl_attr_get_u32(attr);
		} else if (type == TCA_BPF_OPS_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ops_len = 1;
			dst->ops_len = ynl_attr_get_u16(attr);
		} else if (type == TCA_BPF_OPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ops = len;
			dst->ops = malloc(len);
			memcpy(dst->ops, ynl_attr_data(attr), len);
		} else if (type == TCA_BPF_FD) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fd = 1;
			dst->fd = ynl_attr_get_u32(attr);
		} else if (type == TCA_BPF_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.name = len;
			dst->name = malloc(len + 1);
			memcpy(dst->name, ynl_attr_get_str(attr), len);
			dst->name[len] = 0;
		} else if (type == TCA_BPF_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == TCA_BPF_FLAGS_GEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags_gen = 1;
			dst->flags_gen = ynl_attr_get_u32(attr);
		} else if (type == TCA_BPF_TAG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.tag = len;
			dst->tag = malloc(len);
			memcpy(dst->tag, ynl_attr_data(attr), len);
		} else if (type == TCA_BPF_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.id = 1;
			dst->id = ynl_attr_get_u32(attr);
		}
	}

	if (n_act) {
		dst->act = calloc(n_act, sizeof(*dst->act));
		dst->_count.act = n_act;
		i = 0;
		parg.rsp_policy = &tc_act_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_act) {
			parg.data = &dst->act[i];
			if (tc_act_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void tc_cgroup_attrs_free(struct tc_cgroup_attrs *obj)
{
	free(obj->act);
	tc_police_attrs_free(&obj->police);
	free(obj->ematches);
}

int tc_cgroup_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_cgroup_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	array = ynl_attr_nest_start(nlh, TCA_CGROUP_ACT);
	for (i = 0; i < obj->_count.act; i++)
		tc_act_attrs_put(nlh, i, &obj->act[i]);
	ynl_attr_nest_end(nlh, array);
	if (obj->_present.police)
		tc_police_attrs_put(nlh, TCA_CGROUP_POLICE, &obj->police);
	if (obj->_len.ematches)
		ynl_attr_put(nlh, TCA_CGROUP_EMATCHES, obj->ematches, obj->_len.ematches);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_cgroup_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	struct tc_cgroup_attrs *dst = yarg->data;
	const struct nlattr *attr_act = NULL;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_act = 0;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->act)
		return ynl_error_parse(yarg, "attribute already present (cgroup-attrs.act)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_CGROUP_ACT) {
			attr_act = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_act++;
			}
		} else if (type == TCA_CGROUP_POLICE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.police = 1;

			parg.rsp_policy = &tc_police_attrs_nest;
			parg.data = &dst->police;
			if (tc_police_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_CGROUP_EMATCHES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.ematches = len;
			dst->ematches = malloc(len);
			memcpy(dst->ematches, ynl_attr_data(attr), len);
		}
	}

	if (n_act) {
		dst->act = calloc(n_act, sizeof(*dst->act));
		dst->_count.act = n_act;
		i = 0;
		parg.rsp_policy = &tc_act_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_act) {
			parg.data = &dst->act[i];
			if (tc_act_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void tc_flower_attrs_free(struct tc_flower_attrs *obj)
{
	free(obj->indev);
	free(obj->act);
	free(obj->key_eth_dst);
	free(obj->key_eth_dst_mask);
	free(obj->key_eth_src);
	free(obj->key_eth_src_mask);
	free(obj->key_ipv6_src);
	free(obj->key_ipv6_src_mask);
	free(obj->key_ipv6_dst);
	free(obj->key_ipv6_dst_mask);
	free(obj->key_enc_ipv6_src);
	free(obj->key_enc_ipv6_src_mask);
	free(obj->key_enc_ipv6_dst);
	free(obj->key_enc_ipv6_dst_mask);
	free(obj->key_arp_sha);
	free(obj->key_arp_sha_mask);
	free(obj->key_arp_tha);
	free(obj->key_arp_tha_mask);
	tc_flower_key_enc_opts_attrs_free(&obj->key_enc_opts);
	tc_flower_key_enc_opts_attrs_free(&obj->key_enc_opts_mask);
	free(obj->key_ct_labels);
	free(obj->key_ct_labels_mask);
	tc_flower_key_mpls_opt_attrs_free(&obj->key_mpls_opts);
	tc_flower_key_cfm_attrs_free(&obj->key_cfm);
}

int tc_flower_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			struct tc_flower_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.classid)
		ynl_attr_put_u32(nlh, TCA_FLOWER_CLASSID, obj->classid);
	if (obj->_len.indev)
		ynl_attr_put_str(nlh, TCA_FLOWER_INDEV, obj->indev);
	array = ynl_attr_nest_start(nlh, TCA_FLOWER_ACT);
	for (i = 0; i < obj->_count.act; i++)
		tc_act_attrs_put(nlh, i, &obj->act[i]);
	ynl_attr_nest_end(nlh, array);
	if (obj->_len.key_eth_dst)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ETH_DST, obj->key_eth_dst, obj->_len.key_eth_dst);
	if (obj->_len.key_eth_dst_mask)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ETH_DST_MASK, obj->key_eth_dst_mask, obj->_len.key_eth_dst_mask);
	if (obj->_len.key_eth_src)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ETH_SRC, obj->key_eth_src, obj->_len.key_eth_src);
	if (obj->_len.key_eth_src_mask)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ETH_SRC_MASK, obj->key_eth_src_mask, obj->_len.key_eth_src_mask);
	if (obj->_present.key_eth_type)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_ETH_TYPE, obj->key_eth_type);
	if (obj->_present.key_ip_proto)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_IP_PROTO, obj->key_ip_proto);
	if (obj->_present.key_ipv4_src)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_IPV4_SRC, obj->key_ipv4_src);
	if (obj->_present.key_ipv4_src_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_IPV4_SRC_MASK, obj->key_ipv4_src_mask);
	if (obj->_present.key_ipv4_dst)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_IPV4_DST, obj->key_ipv4_dst);
	if (obj->_present.key_ipv4_dst_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_IPV4_DST_MASK, obj->key_ipv4_dst_mask);
	if (obj->_len.key_ipv6_src)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_IPV6_SRC, obj->key_ipv6_src, obj->_len.key_ipv6_src);
	if (obj->_len.key_ipv6_src_mask)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_IPV6_SRC_MASK, obj->key_ipv6_src_mask, obj->_len.key_ipv6_src_mask);
	if (obj->_len.key_ipv6_dst)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_IPV6_DST, obj->key_ipv6_dst, obj->_len.key_ipv6_dst);
	if (obj->_len.key_ipv6_dst_mask)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_IPV6_DST_MASK, obj->key_ipv6_dst_mask, obj->_len.key_ipv6_dst_mask);
	if (obj->_present.key_tcp_src)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_TCP_SRC, obj->key_tcp_src);
	if (obj->_present.key_tcp_dst)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_TCP_DST, obj->key_tcp_dst);
	if (obj->_present.key_udp_src)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_UDP_SRC, obj->key_udp_src);
	if (obj->_present.key_udp_dst)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_UDP_DST, obj->key_udp_dst);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, TCA_FLOWER_FLAGS, obj->flags);
	if (obj->_present.key_vlan_id)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_VLAN_ID, obj->key_vlan_id);
	if (obj->_present.key_vlan_prio)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_VLAN_PRIO, obj->key_vlan_prio);
	if (obj->_present.key_vlan_eth_type)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_VLAN_ETH_TYPE, obj->key_vlan_eth_type);
	if (obj->_present.key_enc_key_id)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ENC_KEY_ID, obj->key_enc_key_id);
	if (obj->_present.key_enc_ipv4_src)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ENC_IPV4_SRC, obj->key_enc_ipv4_src);
	if (obj->_present.key_enc_ipv4_src_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK, obj->key_enc_ipv4_src_mask);
	if (obj->_present.key_enc_ipv4_dst)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ENC_IPV4_DST, obj->key_enc_ipv4_dst);
	if (obj->_present.key_enc_ipv4_dst_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ENC_IPV4_DST_MASK, obj->key_enc_ipv4_dst_mask);
	if (obj->_len.key_enc_ipv6_src)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ENC_IPV6_SRC, obj->key_enc_ipv6_src, obj->_len.key_enc_ipv6_src);
	if (obj->_len.key_enc_ipv6_src_mask)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK, obj->key_enc_ipv6_src_mask, obj->_len.key_enc_ipv6_src_mask);
	if (obj->_len.key_enc_ipv6_dst)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ENC_IPV6_DST, obj->key_enc_ipv6_dst, obj->_len.key_enc_ipv6_dst);
	if (obj->_len.key_enc_ipv6_dst_mask)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ENC_IPV6_DST_MASK, obj->key_enc_ipv6_dst_mask, obj->_len.key_enc_ipv6_dst_mask);
	if (obj->_present.key_tcp_src_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_TCP_SRC_MASK, obj->key_tcp_src_mask);
	if (obj->_present.key_tcp_dst_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_TCP_DST_MASK, obj->key_tcp_dst_mask);
	if (obj->_present.key_udp_src_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_UDP_SRC_MASK, obj->key_udp_src_mask);
	if (obj->_present.key_udp_dst_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_UDP_DST_MASK, obj->key_udp_dst_mask);
	if (obj->_present.key_sctp_src_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_SCTP_SRC_MASK, obj->key_sctp_src_mask);
	if (obj->_present.key_sctp_dst_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_SCTP_DST_MASK, obj->key_sctp_dst_mask);
	if (obj->_present.key_sctp_src)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_SCTP_SRC, obj->key_sctp_src);
	if (obj->_present.key_sctp_dst)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_SCTP_DST, obj->key_sctp_dst);
	if (obj->_present.key_enc_udp_src_port)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_ENC_UDP_SRC_PORT, obj->key_enc_udp_src_port);
	if (obj->_present.key_enc_udp_src_port_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK, obj->key_enc_udp_src_port_mask);
	if (obj->_present.key_enc_udp_dst_port)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_ENC_UDP_DST_PORT, obj->key_enc_udp_dst_port);
	if (obj->_present.key_enc_udp_dst_port_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK, obj->key_enc_udp_dst_port_mask);
	if (obj->_present.key_flags)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_FLAGS, obj->key_flags);
	if (obj->_present.key_flags_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_FLAGS_MASK, obj->key_flags_mask);
	if (obj->_present.key_icmpv4_code)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ICMPV4_CODE, obj->key_icmpv4_code);
	if (obj->_present.key_icmpv4_code_mask)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ICMPV4_CODE_MASK, obj->key_icmpv4_code_mask);
	if (obj->_present.key_icmpv4_type)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ICMPV4_TYPE, obj->key_icmpv4_type);
	if (obj->_present.key_icmpv4_type_mask)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ICMPV4_TYPE_MASK, obj->key_icmpv4_type_mask);
	if (obj->_present.key_icmpv6_code)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ICMPV6_CODE, obj->key_icmpv6_code);
	if (obj->_present.key_icmpv6_code_mask)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ICMPV6_CODE_MASK, obj->key_icmpv6_code_mask);
	if (obj->_present.key_icmpv6_type)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ICMPV6_TYPE, obj->key_icmpv6_type);
	if (obj->_present.key_icmpv6_type_mask)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ICMPV6_TYPE_MASK, obj->key_icmpv6_type_mask);
	if (obj->_present.key_arp_sip)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ARP_SIP, obj->key_arp_sip);
	if (obj->_present.key_arp_sip_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ARP_SIP_MASK, obj->key_arp_sip_mask);
	if (obj->_present.key_arp_tip)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ARP_TIP, obj->key_arp_tip);
	if (obj->_present.key_arp_tip_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ARP_TIP_MASK, obj->key_arp_tip_mask);
	if (obj->_present.key_arp_op)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ARP_OP, obj->key_arp_op);
	if (obj->_present.key_arp_op_mask)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ARP_OP_MASK, obj->key_arp_op_mask);
	if (obj->_len.key_arp_sha)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ARP_SHA, obj->key_arp_sha, obj->_len.key_arp_sha);
	if (obj->_len.key_arp_sha_mask)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ARP_SHA_MASK, obj->key_arp_sha_mask, obj->_len.key_arp_sha_mask);
	if (obj->_len.key_arp_tha)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ARP_THA, obj->key_arp_tha, obj->_len.key_arp_tha);
	if (obj->_len.key_arp_tha_mask)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_ARP_THA_MASK, obj->key_arp_tha_mask, obj->_len.key_arp_tha_mask);
	if (obj->_present.key_mpls_ttl)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_MPLS_TTL, obj->key_mpls_ttl);
	if (obj->_present.key_mpls_bos)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_MPLS_BOS, obj->key_mpls_bos);
	if (obj->_present.key_mpls_tc)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_MPLS_TC, obj->key_mpls_tc);
	if (obj->_present.key_mpls_label)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_MPLS_LABEL, obj->key_mpls_label);
	if (obj->_present.key_tcp_flags)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_TCP_FLAGS, obj->key_tcp_flags);
	if (obj->_present.key_tcp_flags_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_TCP_FLAGS_MASK, obj->key_tcp_flags_mask);
	if (obj->_present.key_ip_tos)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_IP_TOS, obj->key_ip_tos);
	if (obj->_present.key_ip_tos_mask)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_IP_TOS_MASK, obj->key_ip_tos_mask);
	if (obj->_present.key_ip_ttl)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_IP_TTL, obj->key_ip_ttl);
	if (obj->_present.key_ip_ttl_mask)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_IP_TTL_MASK, obj->key_ip_ttl_mask);
	if (obj->_present.key_cvlan_id)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_CVLAN_ID, obj->key_cvlan_id);
	if (obj->_present.key_cvlan_prio)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_CVLAN_PRIO, obj->key_cvlan_prio);
	if (obj->_present.key_cvlan_eth_type)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_CVLAN_ETH_TYPE, obj->key_cvlan_eth_type);
	if (obj->_present.key_enc_ip_tos)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_IP_TOS, obj->key_enc_ip_tos);
	if (obj->_present.key_enc_ip_tos_mask)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_IP_TOS_MASK, obj->key_enc_ip_tos_mask);
	if (obj->_present.key_enc_ip_ttl)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_IP_TTL, obj->key_enc_ip_ttl);
	if (obj->_present.key_enc_ip_ttl_mask)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_ENC_IP_TTL_MASK, obj->key_enc_ip_ttl_mask);
	if (obj->_present.key_enc_opts)
		tc_flower_key_enc_opts_attrs_put(nlh, TCA_FLOWER_KEY_ENC_OPTS, &obj->key_enc_opts);
	if (obj->_present.key_enc_opts_mask)
		tc_flower_key_enc_opts_attrs_put(nlh, TCA_FLOWER_KEY_ENC_OPTS_MASK, &obj->key_enc_opts_mask);
	if (obj->_present.in_hw_count)
		ynl_attr_put_u32(nlh, TCA_FLOWER_IN_HW_COUNT, obj->in_hw_count);
	if (obj->_present.key_port_src_min)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_PORT_SRC_MIN, obj->key_port_src_min);
	if (obj->_present.key_port_src_max)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_PORT_SRC_MAX, obj->key_port_src_max);
	if (obj->_present.key_port_dst_min)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_PORT_DST_MIN, obj->key_port_dst_min);
	if (obj->_present.key_port_dst_max)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_PORT_DST_MAX, obj->key_port_dst_max);
	if (obj->_present.key_ct_state)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_CT_STATE, obj->key_ct_state);
	if (obj->_present.key_ct_state_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_CT_STATE_MASK, obj->key_ct_state_mask);
	if (obj->_present.key_ct_zone)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_CT_ZONE, obj->key_ct_zone);
	if (obj->_present.key_ct_zone_mask)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_CT_ZONE_MASK, obj->key_ct_zone_mask);
	if (obj->_present.key_ct_mark)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_CT_MARK, obj->key_ct_mark);
	if (obj->_present.key_ct_mark_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_CT_MARK_MASK, obj->key_ct_mark_mask);
	if (obj->_len.key_ct_labels)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_CT_LABELS, obj->key_ct_labels, obj->_len.key_ct_labels);
	if (obj->_len.key_ct_labels_mask)
		ynl_attr_put(nlh, TCA_FLOWER_KEY_CT_LABELS_MASK, obj->key_ct_labels_mask, obj->_len.key_ct_labels_mask);
	if (obj->_present.key_mpls_opts)
		tc_flower_key_mpls_opt_attrs_put(nlh, TCA_FLOWER_KEY_MPLS_OPTS, &obj->key_mpls_opts);
	if (obj->_present.key_hash)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_HASH, obj->key_hash);
	if (obj->_present.key_hash_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_HASH_MASK, obj->key_hash_mask);
	if (obj->_present.key_num_of_vlans)
		ynl_attr_put_u8(nlh, TCA_FLOWER_KEY_NUM_OF_VLANS, obj->key_num_of_vlans);
	if (obj->_present.key_pppoe_sid)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_PPPOE_SID, obj->key_pppoe_sid);
	if (obj->_present.key_ppp_proto)
		ynl_attr_put_u16(nlh, TCA_FLOWER_KEY_PPP_PROTO, obj->key_ppp_proto);
	if (obj->_present.key_l2tpv3_sid)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_L2TPV3_SID, obj->key_l2tpv3_sid);
	if (obj->_present.l2_miss)
		ynl_attr_put_u8(nlh, TCA_FLOWER_L2_MISS, obj->l2_miss);
	if (obj->_present.key_cfm)
		tc_flower_key_cfm_attrs_put(nlh, TCA_FLOWER_KEY_CFM, &obj->key_cfm);
	if (obj->_present.key_spi)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_SPI, obj->key_spi);
	if (obj->_present.key_spi_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_SPI_MASK, obj->key_spi_mask);
	if (obj->_present.key_enc_flags)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ENC_FLAGS, obj->key_enc_flags);
	if (obj->_present.key_enc_flags_mask)
		ynl_attr_put_u32(nlh, TCA_FLOWER_KEY_ENC_FLAGS_MASK, obj->key_enc_flags_mask);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_flower_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	struct tc_flower_attrs *dst = yarg->data;
	const struct nlattr *attr_act = NULL;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_act = 0;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->act)
		return ynl_error_parse(yarg, "attribute already present (flower-attrs.act)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FLOWER_CLASSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.classid = 1;
			dst->classid = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_INDEV) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.indev = len;
			dst->indev = malloc(len + 1);
			memcpy(dst->indev, ynl_attr_get_str(attr), len);
			dst->indev[len] = 0;
		} else if (type == TCA_FLOWER_ACT) {
			attr_act = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_act++;
			}
		} else if (type == TCA_FLOWER_KEY_ETH_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_eth_dst = len;
			dst->key_eth_dst = malloc(len);
			memcpy(dst->key_eth_dst, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ETH_DST_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_eth_dst_mask = len;
			dst->key_eth_dst_mask = malloc(len);
			memcpy(dst->key_eth_dst_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ETH_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_eth_src = len;
			dst->key_eth_src = malloc(len);
			memcpy(dst->key_eth_src, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ETH_SRC_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_eth_src_mask = len;
			dst->key_eth_src_mask = malloc(len);
			memcpy(dst->key_eth_src_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ETH_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_eth_type = 1;
			dst->key_eth_type = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_IP_PROTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ip_proto = 1;
			dst->key_ip_proto = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_IPV4_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ipv4_src = 1;
			dst->key_ipv4_src = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_IPV4_SRC_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ipv4_src_mask = 1;
			dst->key_ipv4_src_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_IPV4_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ipv4_dst = 1;
			dst->key_ipv4_dst = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_IPV4_DST_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ipv4_dst_mask = 1;
			dst->key_ipv4_dst_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_IPV6_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_ipv6_src = len;
			dst->key_ipv6_src = malloc(len);
			memcpy(dst->key_ipv6_src, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_IPV6_SRC_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_ipv6_src_mask = len;
			dst->key_ipv6_src_mask = malloc(len);
			memcpy(dst->key_ipv6_src_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_IPV6_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_ipv6_dst = len;
			dst->key_ipv6_dst = malloc(len);
			memcpy(dst->key_ipv6_dst, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_IPV6_DST_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_ipv6_dst_mask = len;
			dst->key_ipv6_dst_mask = malloc(len);
			memcpy(dst->key_ipv6_dst_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_TCP_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_tcp_src = 1;
			dst->key_tcp_src = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_TCP_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_tcp_dst = 1;
			dst->key_tcp_dst = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_UDP_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_udp_src = 1;
			dst->key_udp_src = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_UDP_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_udp_dst = 1;
			dst->key_udp_dst = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_VLAN_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_vlan_id = 1;
			dst->key_vlan_id = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_VLAN_PRIO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_vlan_prio = 1;
			dst->key_vlan_prio = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_VLAN_ETH_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_vlan_eth_type = 1;
			dst->key_vlan_eth_type = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_KEY_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_key_id = 1;
			dst->key_enc_key_id = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_IPV4_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_ipv4_src = 1;
			dst->key_enc_ipv4_src = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_ipv4_src_mask = 1;
			dst->key_enc_ipv4_src_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_IPV4_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_ipv4_dst = 1;
			dst->key_enc_ipv4_dst = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_IPV4_DST_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_ipv4_dst_mask = 1;
			dst->key_enc_ipv4_dst_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_IPV6_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_enc_ipv6_src = len;
			dst->key_enc_ipv6_src = malloc(len);
			memcpy(dst->key_enc_ipv6_src, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_enc_ipv6_src_mask = len;
			dst->key_enc_ipv6_src_mask = malloc(len);
			memcpy(dst->key_enc_ipv6_src_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ENC_IPV6_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_enc_ipv6_dst = len;
			dst->key_enc_ipv6_dst = malloc(len);
			memcpy(dst->key_enc_ipv6_dst, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ENC_IPV6_DST_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_enc_ipv6_dst_mask = len;
			dst->key_enc_ipv6_dst_mask = malloc(len);
			memcpy(dst->key_enc_ipv6_dst_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_TCP_SRC_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_tcp_src_mask = 1;
			dst->key_tcp_src_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_TCP_DST_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_tcp_dst_mask = 1;
			dst->key_tcp_dst_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_UDP_SRC_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_udp_src_mask = 1;
			dst->key_udp_src_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_UDP_DST_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_udp_dst_mask = 1;
			dst->key_udp_dst_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_SCTP_SRC_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_sctp_src_mask = 1;
			dst->key_sctp_src_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_SCTP_DST_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_sctp_dst_mask = 1;
			dst->key_sctp_dst_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_SCTP_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_sctp_src = 1;
			dst->key_sctp_src = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_SCTP_DST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_sctp_dst = 1;
			dst->key_sctp_dst = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_UDP_SRC_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_udp_src_port = 1;
			dst->key_enc_udp_src_port = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_udp_src_port_mask = 1;
			dst->key_enc_udp_src_port_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_UDP_DST_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_udp_dst_port = 1;
			dst->key_enc_udp_dst_port = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_udp_dst_port_mask = 1;
			dst->key_enc_udp_dst_port_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_flags = 1;
			dst->key_flags = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_FLAGS_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_flags_mask = 1;
			dst->key_flags_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ICMPV4_CODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_icmpv4_code = 1;
			dst->key_icmpv4_code = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ICMPV4_CODE_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_icmpv4_code_mask = 1;
			dst->key_icmpv4_code_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ICMPV4_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_icmpv4_type = 1;
			dst->key_icmpv4_type = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ICMPV4_TYPE_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_icmpv4_type_mask = 1;
			dst->key_icmpv4_type_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ICMPV6_CODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_icmpv6_code = 1;
			dst->key_icmpv6_code = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ICMPV6_CODE_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_icmpv6_code_mask = 1;
			dst->key_icmpv6_code_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ICMPV6_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_icmpv6_type = 1;
			dst->key_icmpv6_type = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ICMPV6_TYPE_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_icmpv6_type_mask = 1;
			dst->key_icmpv6_type_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ARP_SIP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_arp_sip = 1;
			dst->key_arp_sip = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ARP_SIP_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_arp_sip_mask = 1;
			dst->key_arp_sip_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ARP_TIP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_arp_tip = 1;
			dst->key_arp_tip = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ARP_TIP_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_arp_tip_mask = 1;
			dst->key_arp_tip_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ARP_OP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_arp_op = 1;
			dst->key_arp_op = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ARP_OP_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_arp_op_mask = 1;
			dst->key_arp_op_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ARP_SHA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_arp_sha = len;
			dst->key_arp_sha = malloc(len);
			memcpy(dst->key_arp_sha, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ARP_SHA_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_arp_sha_mask = len;
			dst->key_arp_sha_mask = malloc(len);
			memcpy(dst->key_arp_sha_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ARP_THA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_arp_tha = len;
			dst->key_arp_tha = malloc(len);
			memcpy(dst->key_arp_tha, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_ARP_THA_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_arp_tha_mask = len;
			dst->key_arp_tha_mask = malloc(len);
			memcpy(dst->key_arp_tha_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_MPLS_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_mpls_ttl = 1;
			dst->key_mpls_ttl = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_MPLS_BOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_mpls_bos = 1;
			dst->key_mpls_bos = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_MPLS_TC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_mpls_tc = 1;
			dst->key_mpls_tc = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_MPLS_LABEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_mpls_label = 1;
			dst->key_mpls_label = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_TCP_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_tcp_flags = 1;
			dst->key_tcp_flags = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_TCP_FLAGS_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_tcp_flags_mask = 1;
			dst->key_tcp_flags_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_IP_TOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ip_tos = 1;
			dst->key_ip_tos = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_IP_TOS_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ip_tos_mask = 1;
			dst->key_ip_tos_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_IP_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ip_ttl = 1;
			dst->key_ip_ttl = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_IP_TTL_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ip_ttl_mask = 1;
			dst->key_ip_ttl_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_CVLAN_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_cvlan_id = 1;
			dst->key_cvlan_id = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_CVLAN_PRIO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_cvlan_prio = 1;
			dst->key_cvlan_prio = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_CVLAN_ETH_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_cvlan_eth_type = 1;
			dst->key_cvlan_eth_type = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_IP_TOS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_ip_tos = 1;
			dst->key_enc_ip_tos = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_IP_TOS_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_ip_tos_mask = 1;
			dst->key_enc_ip_tos_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_IP_TTL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_ip_ttl = 1;
			dst->key_enc_ip_ttl = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_IP_TTL_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_ip_ttl_mask = 1;
			dst->key_enc_ip_ttl_mask = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_OPTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_opts = 1;

			parg.rsp_policy = &tc_flower_key_enc_opts_attrs_nest;
			parg.data = &dst->key_enc_opts;
			if (tc_flower_key_enc_opts_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_FLOWER_KEY_ENC_OPTS_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_opts_mask = 1;

			parg.rsp_policy = &tc_flower_key_enc_opts_attrs_nest;
			parg.data = &dst->key_enc_opts_mask;
			if (tc_flower_key_enc_opts_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_FLOWER_IN_HW_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.in_hw_count = 1;
			dst->in_hw_count = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_PORT_SRC_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_port_src_min = 1;
			dst->key_port_src_min = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_PORT_SRC_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_port_src_max = 1;
			dst->key_port_src_max = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_PORT_DST_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_port_dst_min = 1;
			dst->key_port_dst_min = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_PORT_DST_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_port_dst_max = 1;
			dst->key_port_dst_max = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_CT_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ct_state = 1;
			dst->key_ct_state = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_CT_STATE_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ct_state_mask = 1;
			dst->key_ct_state_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_CT_ZONE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ct_zone = 1;
			dst->key_ct_zone = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_CT_ZONE_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ct_zone_mask = 1;
			dst->key_ct_zone_mask = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_CT_MARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ct_mark = 1;
			dst->key_ct_mark = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_CT_MARK_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ct_mark_mask = 1;
			dst->key_ct_mark_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_CT_LABELS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_ct_labels = len;
			dst->key_ct_labels = malloc(len);
			memcpy(dst->key_ct_labels, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_CT_LABELS_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.key_ct_labels_mask = len;
			dst->key_ct_labels_mask = malloc(len);
			memcpy(dst->key_ct_labels_mask, ynl_attr_data(attr), len);
		} else if (type == TCA_FLOWER_KEY_MPLS_OPTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_mpls_opts = 1;

			parg.rsp_policy = &tc_flower_key_mpls_opt_attrs_nest;
			parg.data = &dst->key_mpls_opts;
			if (tc_flower_key_mpls_opt_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_FLOWER_KEY_HASH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_hash = 1;
			dst->key_hash = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_HASH_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_hash_mask = 1;
			dst->key_hash_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_NUM_OF_VLANS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_num_of_vlans = 1;
			dst->key_num_of_vlans = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_PPPOE_SID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_pppoe_sid = 1;
			dst->key_pppoe_sid = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_PPP_PROTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_ppp_proto = 1;
			dst->key_ppp_proto = ynl_attr_get_u16(attr);
		} else if (type == TCA_FLOWER_KEY_L2TPV3_SID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_l2tpv3_sid = 1;
			dst->key_l2tpv3_sid = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_L2_MISS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.l2_miss = 1;
			dst->l2_miss = ynl_attr_get_u8(attr);
		} else if (type == TCA_FLOWER_KEY_CFM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_cfm = 1;

			parg.rsp_policy = &tc_flower_key_cfm_attrs_nest;
			parg.data = &dst->key_cfm;
			if (tc_flower_key_cfm_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_FLOWER_KEY_SPI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_spi = 1;
			dst->key_spi = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_SPI_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_spi_mask = 1;
			dst->key_spi_mask = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_flags = 1;
			dst->key_enc_flags = ynl_attr_get_u32(attr);
		} else if (type == TCA_FLOWER_KEY_ENC_FLAGS_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.key_enc_flags_mask = 1;
			dst->key_enc_flags_mask = ynl_attr_get_u32(attr);
		}
	}

	if (n_act) {
		dst->act = calloc(n_act, sizeof(*dst->act));
		dst->_count.act = n_act;
		i = 0;
		parg.rsp_policy = &tc_act_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_act) {
			parg.data = &dst->act[i];
			if (tc_act_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void tc_fw_attrs_free(struct tc_fw_attrs *obj)
{
	tc_police_attrs_free(&obj->police);
	free(obj->indev);
	free(obj->act);
}

int tc_fw_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		    struct tc_fw_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.classid)
		ynl_attr_put_u32(nlh, TCA_FW_CLASSID, obj->classid);
	if (obj->_present.police)
		tc_police_attrs_put(nlh, TCA_FW_POLICE, &obj->police);
	if (obj->_len.indev)
		ynl_attr_put_str(nlh, TCA_FW_INDEV, obj->indev);
	array = ynl_attr_nest_start(nlh, TCA_FW_ACT);
	for (i = 0; i < obj->_count.act; i++)
		tc_act_attrs_put(nlh, i, &obj->act[i]);
	ynl_attr_nest_end(nlh, array);
	if (obj->_present.mask)
		ynl_attr_put_u32(nlh, TCA_FW_MASK, obj->mask);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_fw_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_fw_attrs *dst = yarg->data;
	const struct nlattr *attr_act = NULL;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_act = 0;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->act)
		return ynl_error_parse(yarg, "attribute already present (fw-attrs.act)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_FW_CLASSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.classid = 1;
			dst->classid = ynl_attr_get_u32(attr);
		} else if (type == TCA_FW_POLICE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.police = 1;

			parg.rsp_policy = &tc_police_attrs_nest;
			parg.data = &dst->police;
			if (tc_police_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_FW_INDEV) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.indev = len;
			dst->indev = malloc(len + 1);
			memcpy(dst->indev, ynl_attr_get_str(attr), len);
			dst->indev[len] = 0;
		} else if (type == TCA_FW_ACT) {
			attr_act = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_act++;
			}
		} else if (type == TCA_FW_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.mask = 1;
			dst->mask = ynl_attr_get_u32(attr);
		}
	}

	if (n_act) {
		dst->act = calloc(n_act, sizeof(*dst->act));
		dst->_count.act = n_act;
		i = 0;
		parg.rsp_policy = &tc_act_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_act) {
			parg.data = &dst->act[i];
			if (tc_act_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void tc_matchall_attrs_free(struct tc_matchall_attrs *obj)
{
	free(obj->act);
	free(obj->pcnt);
}

int tc_matchall_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  struct tc_matchall_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.classid)
		ynl_attr_put_u32(nlh, TCA_MATCHALL_CLASSID, obj->classid);
	array = ynl_attr_nest_start(nlh, TCA_MATCHALL_ACT);
	for (i = 0; i < obj->_count.act; i++)
		tc_act_attrs_put(nlh, i, &obj->act[i]);
	ynl_attr_nest_end(nlh, array);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, TCA_MATCHALL_FLAGS, obj->flags);
	if (obj->_len.pcnt)
		ynl_attr_put(nlh, TCA_MATCHALL_PCNT, obj->pcnt, obj->_len.pcnt);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_matchall_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	struct tc_matchall_attrs *dst = yarg->data;
	const struct nlattr *attr_act = NULL;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_act = 0;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->act)
		return ynl_error_parse(yarg, "attribute already present (matchall-attrs.act)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_MATCHALL_CLASSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.classid = 1;
			dst->classid = ynl_attr_get_u32(attr);
		} else if (type == TCA_MATCHALL_ACT) {
			attr_act = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_act++;
			}
		} else if (type == TCA_MATCHALL_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		} else if (type == TCA_MATCHALL_PCNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.pcnt = len;
			if (len < sizeof(struct tc_matchall_pcnt))
				dst->pcnt = calloc(1, sizeof(struct tc_matchall_pcnt));
			else
				dst->pcnt = malloc(len);
			memcpy(dst->pcnt, ynl_attr_data(attr), len);
		}
	}

	if (n_act) {
		dst->act = calloc(n_act, sizeof(*dst->act));
		dst->_count.act = n_act;
		i = 0;
		parg.rsp_policy = &tc_act_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_act) {
			parg.data = &dst->act[i];
			if (tc_act_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void tc_route_attrs_free(struct tc_route_attrs *obj)
{
	tc_police_attrs_free(&obj->police);
	free(obj->act);
}

int tc_route_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_route_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.classid)
		ynl_attr_put_u32(nlh, TCA_ROUTE4_CLASSID, obj->classid);
	if (obj->_present.to)
		ynl_attr_put_u32(nlh, TCA_ROUTE4_TO, obj->to);
	if (obj->_present.from)
		ynl_attr_put_u32(nlh, TCA_ROUTE4_FROM, obj->from);
	if (obj->_present.iif)
		ynl_attr_put_u32(nlh, TCA_ROUTE4_IIF, obj->iif);
	if (obj->_present.police)
		tc_police_attrs_put(nlh, TCA_ROUTE4_POLICE, &obj->police);
	array = ynl_attr_nest_start(nlh, TCA_ROUTE4_ACT);
	for (i = 0; i < obj->_count.act; i++)
		tc_act_attrs_put(nlh, i, &obj->act[i]);
	ynl_attr_nest_end(nlh, array);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_route_attrs_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	struct tc_route_attrs *dst = yarg->data;
	const struct nlattr *attr_act = NULL;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_act = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->act)
		return ynl_error_parse(yarg, "attribute already present (route-attrs.act)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_ROUTE4_CLASSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.classid = 1;
			dst->classid = ynl_attr_get_u32(attr);
		} else if (type == TCA_ROUTE4_TO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.to = 1;
			dst->to = ynl_attr_get_u32(attr);
		} else if (type == TCA_ROUTE4_FROM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.from = 1;
			dst->from = ynl_attr_get_u32(attr);
		} else if (type == TCA_ROUTE4_IIF) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.iif = 1;
			dst->iif = ynl_attr_get_u32(attr);
		} else if (type == TCA_ROUTE4_POLICE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.police = 1;

			parg.rsp_policy = &tc_police_attrs_nest;
			parg.data = &dst->police;
			if (tc_police_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_ROUTE4_ACT) {
			attr_act = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_act++;
			}
		}
	}

	if (n_act) {
		dst->act = calloc(n_act, sizeof(*dst->act));
		dst->_count.act = n_act;
		i = 0;
		parg.rsp_policy = &tc_act_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_act) {
			parg.data = &dst->act[i];
			if (tc_act_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void tc_u32_attrs_free(struct tc_u32_attrs *obj)
{
	free(obj->sel);
	tc_police_attrs_free(&obj->police);
	free(obj->act);
	free(obj->indev);
	free(obj->pcnt);
	free(obj->mark);
}

int tc_u32_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_u32_attrs *obj)
{
	struct nlattr *array;
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.classid)
		ynl_attr_put_u32(nlh, TCA_U32_CLASSID, obj->classid);
	if (obj->_present.hash)
		ynl_attr_put_u32(nlh, TCA_U32_HASH, obj->hash);
	if (obj->_present.link)
		ynl_attr_put_u32(nlh, TCA_U32_LINK, obj->link);
	if (obj->_present.divisor)
		ynl_attr_put_u32(nlh, TCA_U32_DIVISOR, obj->divisor);
	if (obj->_len.sel)
		ynl_attr_put(nlh, TCA_U32_SEL, obj->sel, obj->_len.sel);
	if (obj->_present.police)
		tc_police_attrs_put(nlh, TCA_U32_POLICE, &obj->police);
	array = ynl_attr_nest_start(nlh, TCA_U32_ACT);
	for (i = 0; i < obj->_count.act; i++)
		tc_act_attrs_put(nlh, i, &obj->act[i]);
	ynl_attr_nest_end(nlh, array);
	if (obj->_len.indev)
		ynl_attr_put_str(nlh, TCA_U32_INDEV, obj->indev);
	if (obj->_len.pcnt)
		ynl_attr_put(nlh, TCA_U32_PCNT, obj->pcnt, obj->_len.pcnt);
	if (obj->_len.mark)
		ynl_attr_put(nlh, TCA_U32_MARK, obj->mark, obj->_len.mark);
	if (obj->_present.flags)
		ynl_attr_put_u32(nlh, TCA_U32_FLAGS, obj->flags);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_u32_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_u32_attrs *dst = yarg->data;
	const struct nlattr *attr_act = NULL;
	const struct nlattr *attr2;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_act = 0;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->act)
		return ynl_error_parse(yarg, "attribute already present (u32-attrs.act)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_U32_CLASSID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.classid = 1;
			dst->classid = ynl_attr_get_u32(attr);
		} else if (type == TCA_U32_HASH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.hash = 1;
			dst->hash = ynl_attr_get_u32(attr);
		} else if (type == TCA_U32_LINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.link = 1;
			dst->link = ynl_attr_get_u32(attr);
		} else if (type == TCA_U32_DIVISOR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.divisor = 1;
			dst->divisor = ynl_attr_get_u32(attr);
		} else if (type == TCA_U32_SEL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.sel = len;
			if (len < sizeof(struct tc_u32_sel))
				dst->sel = calloc(1, sizeof(struct tc_u32_sel));
			else
				dst->sel = malloc(len);
			memcpy(dst->sel, ynl_attr_data(attr), len);
		} else if (type == TCA_U32_POLICE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.police = 1;

			parg.rsp_policy = &tc_police_attrs_nest;
			parg.data = &dst->police;
			if (tc_police_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_U32_ACT) {
			attr_act = attr;
			ynl_attr_for_each_nested(attr2, attr) {
				if (__ynl_attr_validate(yarg, attr2, type))
					return YNL_PARSE_CB_ERROR;
				n_act++;
			}
		} else if (type == TCA_U32_INDEV) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.indev = len;
			dst->indev = malloc(len + 1);
			memcpy(dst->indev, ynl_attr_get_str(attr), len);
			dst->indev[len] = 0;
		} else if (type == TCA_U32_PCNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.pcnt = len;
			if (len < sizeof(struct tc_u32_pcnt))
				dst->pcnt = calloc(1, sizeof(struct tc_u32_pcnt));
			else
				dst->pcnt = malloc(len);
			memcpy(dst->pcnt, ynl_attr_data(attr), len);
		} else if (type == TCA_U32_MARK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.mark = len;
			if (len < sizeof(struct tc_u32_mark))
				dst->mark = calloc(1, sizeof(struct tc_u32_mark));
			else
				dst->mark = malloc(len);
			memcpy(dst->mark, ynl_attr_data(attr), len);
		} else if (type == TCA_U32_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.flags = 1;
			dst->flags = ynl_attr_get_u32(attr);
		}
	}

	if (n_act) {
		dst->act = calloc(n_act, sizeof(*dst->act));
		dst->_count.act = n_act;
		i = 0;
		parg.rsp_policy = &tc_act_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_act) {
			parg.data = &dst->act[i];
			if (tc_act_attrs_parse(&parg, attr, ynl_attr_type(attr)))
				return YNL_PARSE_CB_ERROR;
			i++;
		}
	}

	return 0;
}

void tc_ets_attrs_free(struct tc_ets_attrs *obj)
{
	if (obj->quanta)
		tc_ets_attrs_free(obj->quanta);
	free(obj->quanta_band);
	if (obj->priomap)
		tc_ets_attrs_free(obj->priomap);
	free(obj->priomap_band);
}

int tc_ets_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     struct tc_ets_attrs *obj)
{
	struct nlattr *nest;
	unsigned int i;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.nbands)
		ynl_attr_put_u8(nlh, TCA_ETS_NBANDS, obj->nbands);
	if (obj->_present.nstrict)
		ynl_attr_put_u8(nlh, TCA_ETS_NSTRICT, obj->nstrict);
	if (obj->_present.quanta)
		tc_ets_attrs_put(nlh, TCA_ETS_QUANTA, obj->quanta);
	for (i = 0; i < obj->_count.quanta_band; i++)
		ynl_attr_put_u32(nlh, TCA_ETS_QUANTA_BAND, obj->quanta_band[i]);
	if (obj->_present.priomap)
		tc_ets_attrs_put(nlh, TCA_ETS_PRIOMAP, obj->priomap);
	for (i = 0; i < obj->_count.priomap_band; i++)
		ynl_attr_put_u8(nlh, TCA_ETS_PRIOMAP_BAND, obj->priomap_band[i]);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int tc_ets_attrs_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	struct tc_ets_attrs *dst = yarg->data;
	unsigned int n_priomap_band = 0;
	unsigned int n_quanta_band = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->priomap_band)
		return ynl_error_parse(yarg, "attribute already present (ets-attrs.priomap-band)");
	if (dst->quanta_band)
		return ynl_error_parse(yarg, "attribute already present (ets-attrs.quanta-band)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_ETS_NBANDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nbands = 1;
			dst->nbands = ynl_attr_get_u8(attr);
		} else if (type == TCA_ETS_NSTRICT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.nstrict = 1;
			dst->nstrict = ynl_attr_get_u8(attr);
		} else if (type == TCA_ETS_QUANTA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.quanta = 1;

			parg.rsp_policy = &tc_ets_attrs_nest;
			parg.data = &dst->quanta;
			if (tc_ets_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_ETS_QUANTA_BAND) {
			n_quanta_band++;
		} else if (type == TCA_ETS_PRIOMAP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.priomap = 1;

			parg.rsp_policy = &tc_ets_attrs_nest;
			parg.data = &dst->priomap;
			if (tc_ets_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_ETS_PRIOMAP_BAND) {
			n_priomap_band++;
		}
	}

	if (n_priomap_band) {
		dst->priomap_band = calloc(n_priomap_band, sizeof(*dst->priomap_band));
		dst->_count.priomap_band = n_priomap_band;
		i = 0;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == TCA_ETS_PRIOMAP_BAND) {
				dst->priomap_band[i] = ynl_attr_get_u8(attr);
				i++;
			}
		}
	}
	if (n_quanta_band) {
		dst->quanta_band = calloc(n_quanta_band, sizeof(*dst->quanta_band));
		dst->_count.quanta_band = n_quanta_band;
		i = 0;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == TCA_ETS_QUANTA_BAND) {
				dst->quanta_band[i] = ynl_attr_get_u32(attr);
				i++;
			}
		}
	}

	return 0;
}

void tc_options_msg_free(struct tc_options_msg *obj)
{
	tc_basic_attrs_free(&obj->basic);
	tc_bpf_attrs_free(&obj->bpf);
	free(obj->bfifo);
	tc_cake_attrs_free(&obj->cake);
	tc_cbs_attrs_free(&obj->cbs);
	tc_cgroup_attrs_free(&obj->cgroup);
	tc_choke_attrs_free(&obj->choke);
	tc_codel_attrs_free(&obj->codel);
	tc_drr_attrs_free(&obj->drr);
	tc_dualpi2_attrs_free(&obj->dualpi2);
	tc_etf_attrs_free(&obj->etf);
	if (obj->ets)
		tc_ets_attrs_free(obj->ets);
	tc_flow_attrs_free(&obj->flow);
	tc_flower_attrs_free(&obj->flower);
	tc_fq_attrs_free(&obj->fq);
	tc_fq_codel_attrs_free(&obj->fq_codel);
	tc_fq_pie_attrs_free(&obj->fq_pie);
	tc_fw_attrs_free(&obj->fw);
	tc_gred_attrs_free(&obj->gred);
	free(obj->hfsc);
	tc_hhf_attrs_free(&obj->hhf);
	tc_htb_attrs_free(&obj->htb);
	tc_matchall_attrs_free(&obj->matchall);
	free(obj->mqprio);
	free(obj->multiq);
	tc_netem_attrs_free(&obj->netem);
	free(obj->pfifo);
	free(obj->pfifo_fast);
	free(obj->pfifo_head_drop);
	tc_pie_attrs_free(&obj->pie);
	free(obj->plug);
	free(obj->prio);
	tc_qfq_attrs_free(&obj->qfq);
	tc_red_attrs_free(&obj->red);
	tc_route_attrs_free(&obj->route);
	free(obj->sfb);
	free(obj->sfq);
	tc_taprio_attrs_free(&obj->taprio);
	tc_tbf_attrs_free(&obj->tbf);
	tc_u32_attrs_free(&obj->u32);
}

int tc_options_msg_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       struct tc_options_msg *obj)
{
	if (obj->_present.basic)
		tc_basic_attrs_put(nlh, TCA_OPTIONS, &obj->basic);
	if (obj->_present.bpf)
		tc_bpf_attrs_put(nlh, TCA_OPTIONS, &obj->bpf);
	if (obj->_len.bfifo)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->bfifo, obj->_len.bfifo);
	if (obj->_present.cake)
		tc_cake_attrs_put(nlh, TCA_OPTIONS, &obj->cake);
	if (obj->_present.cbs)
		tc_cbs_attrs_put(nlh, TCA_OPTIONS, &obj->cbs);
	if (obj->_present.cgroup)
		tc_cgroup_attrs_put(nlh, TCA_OPTIONS, &obj->cgroup);
	if (obj->_present.choke)
		tc_choke_attrs_put(nlh, TCA_OPTIONS, &obj->choke);
	if (obj->_present.clsact)
		ynl_attr_put(nlh, TCA_OPTIONS, NULL, 0);
	if (obj->_present.codel)
		tc_codel_attrs_put(nlh, TCA_OPTIONS, &obj->codel);
	if (obj->_present.drr)
		tc_drr_attrs_put(nlh, TCA_OPTIONS, &obj->drr);
	if (obj->_present.dualpi2)
		tc_dualpi2_attrs_put(nlh, TCA_OPTIONS, &obj->dualpi2);
	if (obj->_present.etf)
		tc_etf_attrs_put(nlh, TCA_OPTIONS, &obj->etf);
	if (obj->_present.ets)
		tc_ets_attrs_put(nlh, TCA_OPTIONS, obj->ets);
	if (obj->_present.flow)
		tc_flow_attrs_put(nlh, TCA_OPTIONS, &obj->flow);
	if (obj->_present.flower)
		tc_flower_attrs_put(nlh, TCA_OPTIONS, &obj->flower);
	if (obj->_present.fq)
		tc_fq_attrs_put(nlh, TCA_OPTIONS, &obj->fq);
	if (obj->_present.fq_codel)
		tc_fq_codel_attrs_put(nlh, TCA_OPTIONS, &obj->fq_codel);
	if (obj->_present.fq_pie)
		tc_fq_pie_attrs_put(nlh, TCA_OPTIONS, &obj->fq_pie);
	if (obj->_present.fw)
		tc_fw_attrs_put(nlh, TCA_OPTIONS, &obj->fw);
	if (obj->_present.gred)
		tc_gred_attrs_put(nlh, TCA_OPTIONS, &obj->gred);
	if (obj->_len.hfsc)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->hfsc, obj->_len.hfsc);
	if (obj->_present.hhf)
		tc_hhf_attrs_put(nlh, TCA_OPTIONS, &obj->hhf);
	if (obj->_present.htb)
		tc_htb_attrs_put(nlh, TCA_OPTIONS, &obj->htb);
	if (obj->_present.ingress)
		ynl_attr_put(nlh, TCA_OPTIONS, NULL, 0);
	if (obj->_present.matchall)
		tc_matchall_attrs_put(nlh, TCA_OPTIONS, &obj->matchall);
	if (obj->_present.mq)
		ynl_attr_put(nlh, TCA_OPTIONS, NULL, 0);
	if (obj->_len.mqprio)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->mqprio, obj->_len.mqprio);
	if (obj->_len.multiq)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->multiq, obj->_len.multiq);
	if (obj->_present.netem)
		tc_netem_attrs_put(nlh, TCA_OPTIONS, &obj->netem);
	if (obj->_len.pfifo)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->pfifo, obj->_len.pfifo);
	if (obj->_len.pfifo_fast)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->pfifo_fast, obj->_len.pfifo_fast);
	if (obj->_len.pfifo_head_drop)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->pfifo_head_drop, obj->_len.pfifo_head_drop);
	if (obj->_present.pie)
		tc_pie_attrs_put(nlh, TCA_OPTIONS, &obj->pie);
	if (obj->_len.plug)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->plug, obj->_len.plug);
	if (obj->_len.prio)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->prio, obj->_len.prio);
	if (obj->_present.qfq)
		tc_qfq_attrs_put(nlh, TCA_OPTIONS, &obj->qfq);
	if (obj->_present.red)
		tc_red_attrs_put(nlh, TCA_OPTIONS, &obj->red);
	if (obj->_present.route)
		tc_route_attrs_put(nlh, TCA_OPTIONS, &obj->route);
	if (obj->_len.sfb)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->sfb, obj->_len.sfb);
	if (obj->_len.sfq)
		ynl_attr_put(nlh, TCA_OPTIONS, obj->sfq, obj->_len.sfq);
	if (obj->_present.taprio)
		tc_taprio_attrs_put(nlh, TCA_OPTIONS, &obj->taprio);
	if (obj->_present.tbf)
		tc_tbf_attrs_put(nlh, TCA_OPTIONS, &obj->tbf);
	if (obj->_present.u32)
		tc_u32_attrs_put(nlh, TCA_OPTIONS, &obj->u32);

	return 0;
}

int tc_options_msg_parse(struct ynl_parse_arg *yarg, const char *sel,
			 const struct nlattr *nested)
{
	struct tc_options_msg *dst = yarg->data;
	const struct nlattr *attr = nested;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	if (!strcmp(sel, "basic")) {
		parg.rsp_policy = &tc_basic_attrs_nest;
		parg.data = &dst->basic;
		if (tc_basic_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.basic = 1;
	} else if (!strcmp(sel, "bpf")) {
		parg.rsp_policy = &tc_bpf_attrs_nest;
		parg.data = &dst->bpf;
		if (tc_bpf_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.bpf = 1;
	} else if (!strcmp(sel, "bfifo")) {
		len = ynl_attr_data_len(attr);
		dst->_len.bfifo = len;
		if (len < sizeof(struct tc_fifo_qopt))
			dst->bfifo = calloc(1, sizeof(struct tc_fifo_qopt));
		else
			dst->bfifo = malloc(len);
		memcpy(dst->bfifo, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "cake")) {
		parg.rsp_policy = &tc_cake_attrs_nest;
		parg.data = &dst->cake;
		if (tc_cake_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.cake = 1;
	} else if (!strcmp(sel, "cbs")) {
		parg.rsp_policy = &tc_cbs_attrs_nest;
		parg.data = &dst->cbs;
		if (tc_cbs_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.cbs = 1;
	} else if (!strcmp(sel, "cgroup")) {
		parg.rsp_policy = &tc_cgroup_attrs_nest;
		parg.data = &dst->cgroup;
		if (tc_cgroup_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.cgroup = 1;
	} else if (!strcmp(sel, "choke")) {
		parg.rsp_policy = &tc_choke_attrs_nest;
		parg.data = &dst->choke;
		if (tc_choke_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.choke = 1;
	} else if (!strcmp(sel, "clsact")) {
		dst->_present.clsact = 1;
	} else if (!strcmp(sel, "codel")) {
		parg.rsp_policy = &tc_codel_attrs_nest;
		parg.data = &dst->codel;
		if (tc_codel_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.codel = 1;
	} else if (!strcmp(sel, "drr")) {
		parg.rsp_policy = &tc_drr_attrs_nest;
		parg.data = &dst->drr;
		if (tc_drr_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.drr = 1;
	} else if (!strcmp(sel, "dualpi2")) {
		parg.rsp_policy = &tc_dualpi2_attrs_nest;
		parg.data = &dst->dualpi2;
		if (tc_dualpi2_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.dualpi2 = 1;
	} else if (!strcmp(sel, "etf")) {
		parg.rsp_policy = &tc_etf_attrs_nest;
		parg.data = &dst->etf;
		if (tc_etf_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.etf = 1;
	} else if (!strcmp(sel, "ets")) {
		parg.rsp_policy = &tc_ets_attrs_nest;
		parg.data = &dst->ets;
		if (tc_ets_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.ets = 1;
	} else if (!strcmp(sel, "flow")) {
		parg.rsp_policy = &tc_flow_attrs_nest;
		parg.data = &dst->flow;
		if (tc_flow_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.flow = 1;
	} else if (!strcmp(sel, "flower")) {
		parg.rsp_policy = &tc_flower_attrs_nest;
		parg.data = &dst->flower;
		if (tc_flower_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.flower = 1;
	} else if (!strcmp(sel, "fq")) {
		parg.rsp_policy = &tc_fq_attrs_nest;
		parg.data = &dst->fq;
		if (tc_fq_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.fq = 1;
	} else if (!strcmp(sel, "fq_codel")) {
		parg.rsp_policy = &tc_fq_codel_attrs_nest;
		parg.data = &dst->fq_codel;
		if (tc_fq_codel_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.fq_codel = 1;
	} else if (!strcmp(sel, "fq_pie")) {
		parg.rsp_policy = &tc_fq_pie_attrs_nest;
		parg.data = &dst->fq_pie;
		if (tc_fq_pie_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.fq_pie = 1;
	} else if (!strcmp(sel, "fw")) {
		parg.rsp_policy = &tc_fw_attrs_nest;
		parg.data = &dst->fw;
		if (tc_fw_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.fw = 1;
	} else if (!strcmp(sel, "gred")) {
		parg.rsp_policy = &tc_gred_attrs_nest;
		parg.data = &dst->gred;
		if (tc_gred_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.gred = 1;
	} else if (!strcmp(sel, "hfsc")) {
		len = ynl_attr_data_len(attr);
		dst->_len.hfsc = len;
		if (len < sizeof(struct tc_hfsc_qopt))
			dst->hfsc = calloc(1, sizeof(struct tc_hfsc_qopt));
		else
			dst->hfsc = malloc(len);
		memcpy(dst->hfsc, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "hhf")) {
		parg.rsp_policy = &tc_hhf_attrs_nest;
		parg.data = &dst->hhf;
		if (tc_hhf_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.hhf = 1;
	} else if (!strcmp(sel, "htb")) {
		parg.rsp_policy = &tc_htb_attrs_nest;
		parg.data = &dst->htb;
		if (tc_htb_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.htb = 1;
	} else if (!strcmp(sel, "ingress")) {
		dst->_present.ingress = 1;
	} else if (!strcmp(sel, "matchall")) {
		parg.rsp_policy = &tc_matchall_attrs_nest;
		parg.data = &dst->matchall;
		if (tc_matchall_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.matchall = 1;
	} else if (!strcmp(sel, "mq")) {
		dst->_present.mq = 1;
	} else if (!strcmp(sel, "mqprio")) {
		len = ynl_attr_data_len(attr);
		dst->_len.mqprio = len;
		if (len < sizeof(struct tc_mqprio_qopt))
			dst->mqprio = calloc(1, sizeof(struct tc_mqprio_qopt));
		else
			dst->mqprio = malloc(len);
		memcpy(dst->mqprio, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "multiq")) {
		len = ynl_attr_data_len(attr);
		dst->_len.multiq = len;
		if (len < sizeof(struct tc_multiq_qopt))
			dst->multiq = calloc(1, sizeof(struct tc_multiq_qopt));
		else
			dst->multiq = malloc(len);
		memcpy(dst->multiq, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "netem")) {
		parg.rsp_policy = &tc_netem_attrs_nest;
		parg.data = &dst->netem;
		if (tc_netem_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.netem = 1;
	} else if (!strcmp(sel, "pfifo")) {
		len = ynl_attr_data_len(attr);
		dst->_len.pfifo = len;
		if (len < sizeof(struct tc_fifo_qopt))
			dst->pfifo = calloc(1, sizeof(struct tc_fifo_qopt));
		else
			dst->pfifo = malloc(len);
		memcpy(dst->pfifo, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "pfifo_fast")) {
		len = ynl_attr_data_len(attr);
		dst->_len.pfifo_fast = len;
		if (len < sizeof(struct tc_prio_qopt))
			dst->pfifo_fast = calloc(1, sizeof(struct tc_prio_qopt));
		else
			dst->pfifo_fast = malloc(len);
		memcpy(dst->pfifo_fast, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "pfifo_head_drop")) {
		len = ynl_attr_data_len(attr);
		dst->_len.pfifo_head_drop = len;
		if (len < sizeof(struct tc_fifo_qopt))
			dst->pfifo_head_drop = calloc(1, sizeof(struct tc_fifo_qopt));
		else
			dst->pfifo_head_drop = malloc(len);
		memcpy(dst->pfifo_head_drop, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "pie")) {
		parg.rsp_policy = &tc_pie_attrs_nest;
		parg.data = &dst->pie;
		if (tc_pie_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.pie = 1;
	} else if (!strcmp(sel, "plug")) {
		len = ynl_attr_data_len(attr);
		dst->_len.plug = len;
		if (len < sizeof(struct tc_plug_qopt))
			dst->plug = calloc(1, sizeof(struct tc_plug_qopt));
		else
			dst->plug = malloc(len);
		memcpy(dst->plug, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "prio")) {
		len = ynl_attr_data_len(attr);
		dst->_len.prio = len;
		if (len < sizeof(struct tc_prio_qopt))
			dst->prio = calloc(1, sizeof(struct tc_prio_qopt));
		else
			dst->prio = malloc(len);
		memcpy(dst->prio, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "qfq")) {
		parg.rsp_policy = &tc_qfq_attrs_nest;
		parg.data = &dst->qfq;
		if (tc_qfq_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.qfq = 1;
	} else if (!strcmp(sel, "red")) {
		parg.rsp_policy = &tc_red_attrs_nest;
		parg.data = &dst->red;
		if (tc_red_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.red = 1;
	} else if (!strcmp(sel, "route")) {
		parg.rsp_policy = &tc_route_attrs_nest;
		parg.data = &dst->route;
		if (tc_route_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.route = 1;
	} else if (!strcmp(sel, "sfb")) {
		len = ynl_attr_data_len(attr);
		dst->_len.sfb = len;
		if (len < sizeof(struct tc_sfb_qopt))
			dst->sfb = calloc(1, sizeof(struct tc_sfb_qopt));
		else
			dst->sfb = malloc(len);
		memcpy(dst->sfb, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "sfq")) {
		len = ynl_attr_data_len(attr);
		dst->_len.sfq = len;
		if (len < sizeof(struct tc_sfq_qopt_v1))
			dst->sfq = calloc(1, sizeof(struct tc_sfq_qopt_v1));
		else
			dst->sfq = malloc(len);
		memcpy(dst->sfq, ynl_attr_data(attr), len);
	} else if (!strcmp(sel, "taprio")) {
		parg.rsp_policy = &tc_taprio_attrs_nest;
		parg.data = &dst->taprio;
		if (tc_taprio_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.taprio = 1;
	} else if (!strcmp(sel, "tbf")) {
		parg.rsp_policy = &tc_tbf_attrs_nest;
		parg.data = &dst->tbf;
		if (tc_tbf_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.tbf = 1;
	} else if (!strcmp(sel, "u32")) {
		parg.rsp_policy = &tc_u32_attrs_nest;
		parg.data = &dst->u32;
		if (tc_u32_attrs_parse(&parg, attr))
			return YNL_PARSE_CB_ERROR;
		dst->_present.u32 = 1;
	}
	return 0;
}

/* ============== RTM_NEWQDISC ============== */
/* RTM_NEWQDISC - do */
void tc_newqdisc_req_free(struct tc_newqdisc_req *req)
{
	free(req->kind);
	tc_options_msg_free(&req->options);
	free(req->rate);
	free(req);
}

int tc_newqdisc(struct ynl_sock *ys, struct tc_newqdisc_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWQDISC, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.kind)
		ynl_attr_put_str(nlh, TCA_KIND, req->kind);
	if (req->_present.options)
		tc_options_msg_put(nlh, TCA_OPTIONS, &req->options);
	if (req->_len.rate)
		ynl_attr_put(nlh, TCA_RATE, req->rate, req->_len.rate);
	if (req->_present.chain)
		ynl_attr_put_u32(nlh, TCA_CHAIN, req->chain);
	if (req->_present.ingress_block)
		ynl_attr_put_u32(nlh, TCA_INGRESS_BLOCK, req->ingress_block);
	if (req->_present.egress_block)
		ynl_attr_put_u32(nlh, TCA_EGRESS_BLOCK, req->egress_block);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_DELQDISC ============== */
/* RTM_DELQDISC - do */
void tc_delqdisc_req_free(struct tc_delqdisc_req *req)
{
	free(req);
}

int tc_delqdisc(struct ynl_sock *ys, struct tc_delqdisc_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELQDISC, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_GETQDISC ============== */
/* RTM_GETQDISC - do */
void tc_getqdisc_req_free(struct tc_getqdisc_req *req)
{
	free(req);
}

void tc_getqdisc_rsp_free(struct tc_getqdisc_rsp *rsp)
{
	free(rsp->kind);
	tc_options_msg_free(&rsp->options);
	free(rsp->stats);
	tc_tca_stats_app_msg_free(&rsp->xstats);
	free(rsp->rate);
	tc_tca_stats_attrs_free(&rsp->stats2);
	tc_tca_stab_attrs_free(&rsp->stab);
	free(rsp);
}

int tc_getqdisc_rsp_parse(const struct nlmsghdr *nlh,
			  struct ynl_parse_arg *yarg)
{
	struct tc_getqdisc_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct tcmsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct tcmsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_KIND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.kind = len;
			dst->kind = malloc(len + 1);
			memcpy(dst->kind, ynl_attr_get_str(attr), len);
			dst->kind[len] = 0;
		} else if (type == TCA_OPTIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.options = 1;

			parg.rsp_policy = &tc_options_msg_nest;
			parg.data = &dst->options;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "options", "kind");
			if (tc_options_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stats = len;
			if (len < sizeof(struct tc_stats))
				dst->stats = calloc(1, sizeof(struct tc_stats));
			else
				dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == TCA_XSTATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.xstats = 1;

			parg.rsp_policy = &tc_tca_stats_app_msg_nest;
			parg.data = &dst->xstats;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "xstats", "kind");
			if (tc_tca_stats_app_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rate = len;
			if (len < sizeof(struct gnet_estimator))
				dst->rate = calloc(1, sizeof(struct gnet_estimator));
			else
				dst->rate = malloc(len);
			memcpy(dst->rate, ynl_attr_data(attr), len);
		} else if (type == TCA_FCNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fcnt = 1;
			dst->fcnt = ynl_attr_get_u32(attr);
		} else if (type == TCA_STATS2) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stats2 = 1;

			parg.rsp_policy = &tc_tca_stats_attrs_nest;
			parg.data = &dst->stats2;
			if (tc_tca_stats_attrs_parse(&parg, attr, dst->kind))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_STAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stab = 1;

			parg.rsp_policy = &tc_tca_stab_attrs_nest;
			parg.data = &dst->stab;
			if (tc_tca_stab_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_CHAIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.chain = 1;
			dst->chain = ynl_attr_get_u32(attr);
		} else if (type == TCA_INGRESS_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ingress_block = 1;
			dst->ingress_block = ynl_attr_get_u32(attr);
		} else if (type == TCA_EGRESS_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.egress_block = 1;
			dst->egress_block = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct tc_getqdisc_rsp *
tc_getqdisc(struct ynl_sock *ys, struct tc_getqdisc_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct tc_getqdisc_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETQDISC, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);
	yrs.yarg.rsp_policy = &tc_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.dump_invisible)
		ynl_attr_put(nlh, TCA_DUMP_INVISIBLE, NULL, 0);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = tc_getqdisc_rsp_parse;
	yrs.rsp_cmd = 36;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	tc_getqdisc_rsp_free(rsp);
	return NULL;
}

/* RTM_GETQDISC - dump */
void tc_getqdisc_req_dump_free(struct tc_getqdisc_req_dump *req)
{
	free(req);
}

void tc_getqdisc_list_free(struct tc_getqdisc_list *rsp)
{
	struct tc_getqdisc_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.kind);
		tc_options_msg_free(&rsp->obj.options);
		free(rsp->obj.stats);
		tc_tca_stats_app_msg_free(&rsp->obj.xstats);
		free(rsp->obj.rate);
		tc_tca_stats_attrs_free(&rsp->obj.stats2);
		tc_tca_stab_attrs_free(&rsp->obj.stab);
		free(rsp);
	}
}

struct tc_getqdisc_list *
tc_getqdisc_dump(struct ynl_sock *ys, struct tc_getqdisc_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &tc_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct tc_getqdisc_list);
	yds.cb = tc_getqdisc_rsp_parse;
	yds.rsp_cmd = 36;

	nlh = ynl_msg_start_dump(ys, RTM_GETQDISC);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	if (req->_present.dump_invisible)
		ynl_attr_put(nlh, TCA_DUMP_INVISIBLE, NULL, 0);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	tc_getqdisc_list_free(yds.first);
	return NULL;
}

/* ============== RTM_NEWTCLASS ============== */
/* RTM_NEWTCLASS - do */
void tc_newtclass_req_free(struct tc_newtclass_req *req)
{
	free(req->kind);
	tc_options_msg_free(&req->options);
	free(req->rate);
	free(req);
}

int tc_newtclass(struct ynl_sock *ys, struct tc_newtclass_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWTCLASS, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.kind)
		ynl_attr_put_str(nlh, TCA_KIND, req->kind);
	if (req->_present.options)
		tc_options_msg_put(nlh, TCA_OPTIONS, &req->options);
	if (req->_len.rate)
		ynl_attr_put(nlh, TCA_RATE, req->rate, req->_len.rate);
	if (req->_present.chain)
		ynl_attr_put_u32(nlh, TCA_CHAIN, req->chain);
	if (req->_present.ingress_block)
		ynl_attr_put_u32(nlh, TCA_INGRESS_BLOCK, req->ingress_block);
	if (req->_present.egress_block)
		ynl_attr_put_u32(nlh, TCA_EGRESS_BLOCK, req->egress_block);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_DELTCLASS ============== */
/* RTM_DELTCLASS - do */
void tc_deltclass_req_free(struct tc_deltclass_req *req)
{
	free(req);
}

int tc_deltclass(struct ynl_sock *ys, struct tc_deltclass_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELTCLASS, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_GETTCLASS ============== */
/* RTM_GETTCLASS - do */
void tc_gettclass_req_free(struct tc_gettclass_req *req)
{
	free(req);
}

void tc_gettclass_rsp_free(struct tc_gettclass_rsp *rsp)
{
	free(rsp->kind);
	tc_options_msg_free(&rsp->options);
	free(rsp->stats);
	tc_tca_stats_app_msg_free(&rsp->xstats);
	free(rsp->rate);
	tc_tca_stats_attrs_free(&rsp->stats2);
	tc_tca_stab_attrs_free(&rsp->stab);
	free(rsp);
}

int tc_gettclass_rsp_parse(const struct nlmsghdr *nlh,
			   struct ynl_parse_arg *yarg)
{
	struct tc_gettclass_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct tcmsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct tcmsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_KIND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.kind = len;
			dst->kind = malloc(len + 1);
			memcpy(dst->kind, ynl_attr_get_str(attr), len);
			dst->kind[len] = 0;
		} else if (type == TCA_OPTIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.options = 1;

			parg.rsp_policy = &tc_options_msg_nest;
			parg.data = &dst->options;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "options", "kind");
			if (tc_options_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stats = len;
			if (len < sizeof(struct tc_stats))
				dst->stats = calloc(1, sizeof(struct tc_stats));
			else
				dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == TCA_XSTATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.xstats = 1;

			parg.rsp_policy = &tc_tca_stats_app_msg_nest;
			parg.data = &dst->xstats;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "xstats", "kind");
			if (tc_tca_stats_app_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rate = len;
			if (len < sizeof(struct gnet_estimator))
				dst->rate = calloc(1, sizeof(struct gnet_estimator));
			else
				dst->rate = malloc(len);
			memcpy(dst->rate, ynl_attr_data(attr), len);
		} else if (type == TCA_FCNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fcnt = 1;
			dst->fcnt = ynl_attr_get_u32(attr);
		} else if (type == TCA_STATS2) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stats2 = 1;

			parg.rsp_policy = &tc_tca_stats_attrs_nest;
			parg.data = &dst->stats2;
			if (tc_tca_stats_attrs_parse(&parg, attr, dst->kind))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_STAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stab = 1;

			parg.rsp_policy = &tc_tca_stab_attrs_nest;
			parg.data = &dst->stab;
			if (tc_tca_stab_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_CHAIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.chain = 1;
			dst->chain = ynl_attr_get_u32(attr);
		} else if (type == TCA_INGRESS_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ingress_block = 1;
			dst->ingress_block = ynl_attr_get_u32(attr);
		} else if (type == TCA_EGRESS_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.egress_block = 1;
			dst->egress_block = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct tc_gettclass_rsp *
tc_gettclass(struct ynl_sock *ys, struct tc_gettclass_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct tc_gettclass_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETTCLASS, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);
	yrs.yarg.rsp_policy = &tc_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = tc_gettclass_rsp_parse;
	yrs.rsp_cmd = 40;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	tc_gettclass_rsp_free(rsp);
	return NULL;
}

/* ============== RTM_NEWTFILTER ============== */
/* RTM_NEWTFILTER - do */
void tc_newtfilter_req_free(struct tc_newtfilter_req *req)
{
	free(req->kind);
	tc_options_msg_free(&req->options);
	free(req->rate);
	free(req);
}

int tc_newtfilter(struct ynl_sock *ys, struct tc_newtfilter_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWTFILTER, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.kind)
		ynl_attr_put_str(nlh, TCA_KIND, req->kind);
	if (req->_present.options)
		tc_options_msg_put(nlh, TCA_OPTIONS, &req->options);
	if (req->_len.rate)
		ynl_attr_put(nlh, TCA_RATE, req->rate, req->_len.rate);
	if (req->_present.chain)
		ynl_attr_put_u32(nlh, TCA_CHAIN, req->chain);
	if (req->_present.ingress_block)
		ynl_attr_put_u32(nlh, TCA_INGRESS_BLOCK, req->ingress_block);
	if (req->_present.egress_block)
		ynl_attr_put_u32(nlh, TCA_EGRESS_BLOCK, req->egress_block);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_DELTFILTER ============== */
/* RTM_DELTFILTER - do */
void tc_deltfilter_req_free(struct tc_deltfilter_req *req)
{
	free(req->kind);
	free(req);
}

int tc_deltfilter(struct ynl_sock *ys, struct tc_deltfilter_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELTFILTER, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.chain)
		ynl_attr_put_u32(nlh, TCA_CHAIN, req->chain);
	if (req->_len.kind)
		ynl_attr_put_str(nlh, TCA_KIND, req->kind);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_GETTFILTER ============== */
/* RTM_GETTFILTER - do */
void tc_gettfilter_req_free(struct tc_gettfilter_req *req)
{
	free(req->kind);
	free(req);
}

void tc_gettfilter_rsp_free(struct tc_gettfilter_rsp *rsp)
{
	free(rsp->kind);
	tc_options_msg_free(&rsp->options);
	free(rsp->stats);
	tc_tca_stats_app_msg_free(&rsp->xstats);
	free(rsp->rate);
	tc_tca_stats_attrs_free(&rsp->stats2);
	tc_tca_stab_attrs_free(&rsp->stab);
	free(rsp);
}

int tc_gettfilter_rsp_parse(const struct nlmsghdr *nlh,
			    struct ynl_parse_arg *yarg)
{
	struct tc_gettfilter_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct tcmsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct tcmsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_KIND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.kind = len;
			dst->kind = malloc(len + 1);
			memcpy(dst->kind, ynl_attr_get_str(attr), len);
			dst->kind[len] = 0;
		} else if (type == TCA_OPTIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.options = 1;

			parg.rsp_policy = &tc_options_msg_nest;
			parg.data = &dst->options;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "options", "kind");
			if (tc_options_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stats = len;
			if (len < sizeof(struct tc_stats))
				dst->stats = calloc(1, sizeof(struct tc_stats));
			else
				dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == TCA_XSTATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.xstats = 1;

			parg.rsp_policy = &tc_tca_stats_app_msg_nest;
			parg.data = &dst->xstats;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "xstats", "kind");
			if (tc_tca_stats_app_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rate = len;
			if (len < sizeof(struct gnet_estimator))
				dst->rate = calloc(1, sizeof(struct gnet_estimator));
			else
				dst->rate = malloc(len);
			memcpy(dst->rate, ynl_attr_data(attr), len);
		} else if (type == TCA_FCNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fcnt = 1;
			dst->fcnt = ynl_attr_get_u32(attr);
		} else if (type == TCA_STATS2) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stats2 = 1;

			parg.rsp_policy = &tc_tca_stats_attrs_nest;
			parg.data = &dst->stats2;
			if (tc_tca_stats_attrs_parse(&parg, attr, dst->kind))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_STAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stab = 1;

			parg.rsp_policy = &tc_tca_stab_attrs_nest;
			parg.data = &dst->stab;
			if (tc_tca_stab_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_CHAIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.chain = 1;
			dst->chain = ynl_attr_get_u32(attr);
		} else if (type == TCA_INGRESS_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ingress_block = 1;
			dst->ingress_block = ynl_attr_get_u32(attr);
		} else if (type == TCA_EGRESS_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.egress_block = 1;
			dst->egress_block = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct tc_gettfilter_rsp *
tc_gettfilter(struct ynl_sock *ys, struct tc_gettfilter_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct tc_gettfilter_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETTFILTER, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);
	yrs.yarg.rsp_policy = &tc_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.chain)
		ynl_attr_put_u32(nlh, TCA_CHAIN, req->chain);
	if (req->_len.kind)
		ynl_attr_put_str(nlh, TCA_KIND, req->kind);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = tc_gettfilter_rsp_parse;
	yrs.rsp_cmd = 44;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	tc_gettfilter_rsp_free(rsp);
	return NULL;
}

/* RTM_GETTFILTER - dump */
void tc_gettfilter_req_dump_free(struct tc_gettfilter_req_dump *req)
{
	free(req);
}

void tc_gettfilter_list_free(struct tc_gettfilter_list *rsp)
{
	struct tc_gettfilter_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.kind);
		tc_options_msg_free(&rsp->obj.options);
		free(rsp->obj.stats);
		tc_tca_stats_app_msg_free(&rsp->obj.xstats);
		free(rsp->obj.rate);
		tc_tca_stats_attrs_free(&rsp->obj.stats2);
		tc_tca_stab_attrs_free(&rsp->obj.stab);
		free(rsp);
	}
}

struct tc_gettfilter_list *
tc_gettfilter_dump(struct ynl_sock *ys, struct tc_gettfilter_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &tc_attrs_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct tc_gettfilter_list);
	yds.cb = tc_gettfilter_rsp_parse;
	yds.rsp_cmd = 44;

	nlh = ynl_msg_start_dump(ys, RTM_GETTFILTER);
	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	if (req->_present.chain)
		ynl_attr_put_u32(nlh, TCA_CHAIN, req->chain);
	if (req->_present.dump_flags)
		ynl_attr_put(nlh, TCA_DUMP_FLAGS, &req->dump_flags, sizeof(struct nla_bitfield32));

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	tc_gettfilter_list_free(yds.first);
	return NULL;
}

/* ============== RTM_NEWCHAIN ============== */
/* RTM_NEWCHAIN - do */
void tc_newchain_req_free(struct tc_newchain_req *req)
{
	free(req->kind);
	tc_options_msg_free(&req->options);
	free(req->rate);
	free(req);
}

int tc_newchain(struct ynl_sock *ys, struct tc_newchain_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWCHAIN, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_len.kind)
		ynl_attr_put_str(nlh, TCA_KIND, req->kind);
	if (req->_present.options)
		tc_options_msg_put(nlh, TCA_OPTIONS, &req->options);
	if (req->_len.rate)
		ynl_attr_put(nlh, TCA_RATE, req->rate, req->_len.rate);
	if (req->_present.chain)
		ynl_attr_put_u32(nlh, TCA_CHAIN, req->chain);
	if (req->_present.ingress_block)
		ynl_attr_put_u32(nlh, TCA_INGRESS_BLOCK, req->ingress_block);
	if (req->_present.egress_block)
		ynl_attr_put_u32(nlh, TCA_EGRESS_BLOCK, req->egress_block);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_DELCHAIN ============== */
/* RTM_DELCHAIN - do */
void tc_delchain_req_free(struct tc_delchain_req *req)
{
	free(req);
}

int tc_delchain(struct ynl_sock *ys, struct tc_delchain_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELCHAIN, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.chain)
		ynl_attr_put_u32(nlh, TCA_CHAIN, req->chain);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== RTM_GETCHAIN ============== */
/* RTM_GETCHAIN - do */
void tc_getchain_req_free(struct tc_getchain_req *req)
{
	free(req);
}

void tc_getchain_rsp_free(struct tc_getchain_rsp *rsp)
{
	free(rsp->kind);
	tc_options_msg_free(&rsp->options);
	free(rsp->stats);
	tc_tca_stats_app_msg_free(&rsp->xstats);
	free(rsp->rate);
	tc_tca_stats_attrs_free(&rsp->stats2);
	tc_tca_stab_attrs_free(&rsp->stab);
	free(rsp);
}

int tc_getchain_rsp_parse(const struct nlmsghdr *nlh,
			  struct ynl_parse_arg *yarg)
{
	struct tc_getchain_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	void *hdr;

	dst = yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct tcmsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct tcmsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCA_KIND) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.kind = len;
			dst->kind = malloc(len + 1);
			memcpy(dst->kind, ynl_attr_get_str(attr), len);
			dst->kind[len] = 0;
		} else if (type == TCA_OPTIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.options = 1;

			parg.rsp_policy = &tc_options_msg_nest;
			parg.data = &dst->options;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "options", "kind");
			if (tc_options_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.stats = len;
			if (len < sizeof(struct tc_stats))
				dst->stats = calloc(1, sizeof(struct tc_stats));
			else
				dst->stats = malloc(len);
			memcpy(dst->stats, ynl_attr_data(attr), len);
		} else if (type == TCA_XSTATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.xstats = 1;

			parg.rsp_policy = &tc_tca_stats_app_msg_nest;
			parg.data = &dst->xstats;
			if (!dst->kind)
				return ynl_submsg_failed(yarg, "xstats", "kind");
			if (tc_tca_stats_app_msg_parse(&parg, dst->kind, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_RATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.rate = len;
			if (len < sizeof(struct gnet_estimator))
				dst->rate = calloc(1, sizeof(struct gnet_estimator));
			else
				dst->rate = malloc(len);
			memcpy(dst->rate, ynl_attr_data(attr), len);
		} else if (type == TCA_FCNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fcnt = 1;
			dst->fcnt = ynl_attr_get_u32(attr);
		} else if (type == TCA_STATS2) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stats2 = 1;

			parg.rsp_policy = &tc_tca_stats_attrs_nest;
			parg.data = &dst->stats2;
			if (tc_tca_stats_attrs_parse(&parg, attr, dst->kind))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_STAB) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.stab = 1;

			parg.rsp_policy = &tc_tca_stab_attrs_nest;
			parg.data = &dst->stab;
			if (tc_tca_stab_attrs_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == TCA_CHAIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.chain = 1;
			dst->chain = ynl_attr_get_u32(attr);
		} else if (type == TCA_INGRESS_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.ingress_block = 1;
			dst->ingress_block = ynl_attr_get_u32(attr);
		} else if (type == TCA_EGRESS_BLOCK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.egress_block = 1;
			dst->egress_block = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct tc_getchain_rsp *
tc_getchain(struct ynl_sock *ys, struct tc_getchain_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct tc_getchain_rsp *rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETCHAIN, req->_nlmsg_flags);
	ys->req_policy = &tc_attrs_nest;
	ys->req_hdr_len = sizeof(struct tcmsg);
	yrs.yarg.rsp_policy = &tc_attrs_nest;

	hdr_len = sizeof(req->_hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req->_hdr, hdr_len);

	if (req->_present.chain)
		ynl_attr_put_u32(nlh, TCA_CHAIN, req->chain);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = tc_getchain_rsp_parse;
	yrs.rsp_cmd = 100;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	tc_getchain_rsp_free(rsp);
	return NULL;
}

const struct ynl_family ynl_tc_family =  {
	.name		= "tc",
	.is_classic	= true,
	.classic_id	= 0,
};
