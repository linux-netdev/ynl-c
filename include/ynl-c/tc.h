/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/tc.yaml */
/* YNL-GEN user header */

#ifndef _LINUX_TC_GEN_H
#define _LINUX_TC_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/netlink.h>
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

struct ynl_sock;

extern const struct ynl_family ynl_tc_family;

/* Enums */
const char *tc_op_str(int op);
const char *tc_cls_flags_str(int value);
const char *tc_flower_key_ctrl_flags_str(int value);

/* Common nested types */
struct tc_tca_stab_attrs {
	struct {
		__u32 base;
		__u32 data;
	} _len;

	struct tc_sizespec *base;
	void *data;
};

struct tc_cake_attrs {
	struct {
		__u32 base_rate64:1;
		__u32 diffserv_mode:1;
		__u32 atm:1;
		__u32 flow_mode:1;
		__u32 overhead:1;
		__u32 rtt:1;
		__u32 target:1;
		__u32 autorate:1;
		__u32 memory:1;
		__u32 nat:1;
		__u32 raw:1;
		__u32 wash:1;
		__u32 mpu:1;
		__u32 ingress:1;
		__u32 ack_filter:1;
		__u32 split_gso:1;
		__u32 fwmark:1;
	} _present;

	__u64 base_rate64;
	__u32 diffserv_mode;
	__u32 atm;
	__u32 flow_mode;
	__u32 overhead;
	__u32 rtt;
	__u32 target;
	__u32 autorate;
	__u32 memory;
	__u32 nat;
	__u32 raw;
	__u32 wash;
	__u32 mpu;
	__u32 ingress;
	__u32 ack_filter;
	__u32 split_gso;
	__u32 fwmark;
};

struct tc_cbs_attrs {
	struct {
		__u32 parms;
	} _len;

	struct tc_cbs_qopt *parms;
};

struct tc_choke_attrs {
	struct {
		__u32 max_p:1;
	} _present;
	struct {
		__u32 parms;
		__u32 stab;
	} _len;

	struct tc_red_qopt *parms;
	void *stab;
	__u32 max_p;
};

struct tc_codel_attrs {
	struct {
		__u32 target:1;
		__u32 limit:1;
		__u32 interval:1;
		__u32 ecn:1;
		__u32 ce_threshold:1;
	} _present;

	__u32 target;
	__u32 limit;
	__u32 interval;
	__u32 ecn;
	__u32 ce_threshold;
};

struct tc_drr_attrs {
	struct {
		__u32 quantum:1;
	} _present;

	__u32 quantum;
};

struct tc_etf_attrs {
	struct {
		__u32 parms;
	} _len;

	struct tc_etf_qopt *parms;
};

struct tc_fq_attrs {
	struct {
		__u32 plimit:1;
		__u32 flow_plimit:1;
		__u32 quantum:1;
		__u32 initial_quantum:1;
		__u32 rate_enable:1;
		__u32 flow_default_rate:1;
		__u32 flow_max_rate:1;
		__u32 buckets_log:1;
		__u32 flow_refill_delay:1;
		__u32 orphan_mask:1;
		__u32 low_rate_threshold:1;
		__u32 ce_threshold:1;
		__u32 timer_slack:1;
		__u32 horizon:1;
		__u32 horizon_drop:1;
	} _present;
	struct {
		__u32 priomap;
	} _len;
	struct {
		__u32 weights;
	} _count;

	__u32 plimit;
	__u32 flow_plimit;
	__u32 quantum;
	__u32 initial_quantum;
	__u32 rate_enable;
	__u32 flow_default_rate;
	__u32 flow_max_rate;
	__u32 buckets_log;
	__u32 flow_refill_delay;
	__u32 orphan_mask;
	__u32 low_rate_threshold;
	__u32 ce_threshold;
	__u32 timer_slack;
	__u32 horizon;
	__u8 horizon_drop;
	struct tc_prio_qopt *priomap;
	__s32 *weights;
};

struct tc_fq_codel_attrs {
	struct {
		__u32 target:1;
		__u32 limit:1;
		__u32 interval:1;
		__u32 ecn:1;
		__u32 flows:1;
		__u32 quantum:1;
		__u32 ce_threshold:1;
		__u32 drop_batch_size:1;
		__u32 memory_limit:1;
		__u32 ce_threshold_selector:1;
		__u32 ce_threshold_mask:1;
	} _present;

	__u32 target;
	__u32 limit;
	__u32 interval;
	__u32 ecn;
	__u32 flows;
	__u32 quantum;
	__u32 ce_threshold;
	__u32 drop_batch_size;
	__u32 memory_limit;
	__u8 ce_threshold_selector;
	__u8 ce_threshold_mask;
};

struct tc_fq_pie_attrs {
	struct {
		__u32 limit:1;
		__u32 flows:1;
		__u32 target:1;
		__u32 tupdate:1;
		__u32 alpha:1;
		__u32 beta:1;
		__u32 quantum:1;
		__u32 memory_limit:1;
		__u32 ecn_prob:1;
		__u32 ecn:1;
		__u32 bytemode:1;
		__u32 dq_rate_estimator:1;
	} _present;

	__u32 limit;
	__u32 flows;
	__u32 target;
	__u32 tupdate;
	__u32 alpha;
	__u32 beta;
	__u32 quantum;
	__u32 memory_limit;
	__u32 ecn_prob;
	__u32 ecn;
	__u32 bytemode;
	__u32 dq_rate_estimator;
};

struct tc_hhf_attrs {
	struct {
		__u32 backlog_limit:1;
		__u32 quantum:1;
		__u32 hh_flows_limit:1;
		__u32 reset_timeout:1;
		__u32 admit_bytes:1;
		__u32 evict_timeout:1;
		__u32 non_hh_weight:1;
	} _present;

	__u32 backlog_limit;
	__u32 quantum;
	__u32 hh_flows_limit;
	__u32 reset_timeout;
	__u32 admit_bytes;
	__u32 evict_timeout;
	__u32 non_hh_weight;
};

struct tc_htb_attrs {
	struct {
		__u32 direct_qlen:1;
		__u32 rate64:1;
		__u32 ceil64:1;
		__u32 offload:1;
	} _present;
	struct {
		__u32 parms;
		__u32 init;
		__u32 ctab;
		__u32 rtab;
	} _len;

	struct tc_htb_opt *parms;
	struct tc_htb_glob *init;
	void *ctab;
	void *rtab;
	__u32 direct_qlen;
	__u64 rate64;
	__u64 ceil64;
};

struct tc_pie_attrs {
	struct {
		__u32 target:1;
		__u32 limit:1;
		__u32 tupdate:1;
		__u32 alpha:1;
		__u32 beta:1;
		__u32 ecn:1;
		__u32 bytemode:1;
		__u32 dq_rate_estimator:1;
	} _present;

	__u32 target;
	__u32 limit;
	__u32 tupdate;
	__u32 alpha;
	__u32 beta;
	__u32 ecn;
	__u32 bytemode;
	__u32 dq_rate_estimator;
};

struct tc_qfq_attrs {
	struct {
		__u32 weight:1;
		__u32 lmax:1;
	} _present;

	__u32 weight;
	__u32 lmax;
};

struct tc_red_attrs {
	struct {
		__u32 max_p:1;
		__u32 flags:1;
		__u32 early_drop_block:1;
		__u32 mark_block:1;
	} _present;
	struct {
		__u32 parms;
		__u32 stab;
	} _len;

	struct tc_red_qopt *parms;
	void *stab;
	__u32 max_p;
	struct nla_bitfield32 flags;
	__u32 early_drop_block;
	__u32 mark_block;
};

struct tc_tbf_attrs {
	struct {
		__u32 rate64:1;
		__u32 prate64:1;
		__u32 burst:1;
		__u32 pburst:1;
	} _present;
	struct {
		__u32 parms;
		__u32 rtab;
		__u32 ptab;
	} _len;

	struct tc_tbf_qopt *parms;
	void *rtab;
	void *ptab;
	__u64 rate64;
	__u64 prate64;
	__u32 burst;
	__u32 pburst;
};

struct tc_ematch_attrs {
	struct {
		__u32 tree_hdr;
		__u32 tree_list;
	} _len;

	struct tcf_ematch_tree_hdr *tree_hdr;
	void *tree_list;
};

struct tc_police_attrs {
	struct {
		__u32 avrate:1;
		__u32 result:1;
		__u32 rate64:1;
		__u32 peakrate64:1;
		__u32 pktrate64:1;
		__u32 pktburst64:1;
	} _present;
	struct {
		__u32 tbf;
		__u32 rate;
		__u32 peakrate;
		__u32 tm;
	} _len;

	struct tc_police *tbf;
	void *rate;
	void *peakrate;
	__u32 avrate;
	__u32 result;
	struct tcf_t *tm;
	__u64 rate64;
	__u64 peakrate64;
	__u64 pktrate64;
	__u64 pktburst64;
};

struct tc_flower_key_mpls_opt_attrs {
	struct {
		__u32 lse_depth:1;
		__u32 lse_ttl:1;
		__u32 lse_bos:1;
		__u32 lse_tc:1;
		__u32 lse_label:1;
	} _present;

	__u8 lse_depth;
	__u8 lse_ttl;
	__u8 lse_bos;
	__u8 lse_tc;
	__u32 lse_label;
};

struct tc_flower_key_cfm_attrs {
	struct {
		__u32 md_level:1;
		__u32 opcode:1;
	} _present;

	__u8 md_level;
	__u8 opcode;
};

struct tc_netem_loss_attrs {
	struct {
		__u32 gi;
		__u32 ge;
	} _len;

	struct tc_netem_gimodel *gi;
	struct tc_netem_gemodel *ge;
};

struct tc_taprio_sched_entry {
	struct {
		__u32 index:1;
		__u32 cmd:1;
		__u32 gate_mask:1;
		__u32 interval:1;
	} _present;

	__u32 index;
	__u8 cmd;
	__u32 gate_mask;
	__u32 interval;
};

void tc_taprio_sched_entry_free(struct tc_taprio_sched_entry *obj);

struct tc_taprio_tc_entry_attrs {
	struct {
		__u32 index:1;
		__u32 max_sdu:1;
		__u32 fp:1;
	} _present;

	__u32 index;
	__u32 max_sdu;
	__u32 fp;
};

struct tc_cake_tin_stats_attrs {
	struct {
		__u32 sent_packets:1;
		__u32 sent_bytes64:1;
		__u32 dropped_packets:1;
		__u32 dropped_bytes64:1;
		__u32 acks_dropped_packets:1;
		__u32 acks_dropped_bytes64:1;
		__u32 ecn_marked_packets:1;
		__u32 ecn_marked_bytes64:1;
		__u32 backlog_packets:1;
		__u32 backlog_bytes:1;
		__u32 threshold_rate64:1;
		__u32 target_us:1;
		__u32 interval_us:1;
		__u32 way_indirect_hits:1;
		__u32 way_misses:1;
		__u32 way_collisions:1;
		__u32 peak_delay_us:1;
		__u32 avg_delay_us:1;
		__u32 base_delay_us:1;
		__u32 sparse_flows:1;
		__u32 bulk_flows:1;
		__u32 unresponsive_flows:1;
		__u32 max_skblen:1;
		__u32 flow_quantum:1;
	} _present;

	__u32 idx;
	__u32 sent_packets;
	__u64 sent_bytes64;
	__u32 dropped_packets;
	__u64 dropped_bytes64;
	__u32 acks_dropped_packets;
	__u64 acks_dropped_bytes64;
	__u32 ecn_marked_packets;
	__u64 ecn_marked_bytes64;
	__u32 backlog_packets;
	__u32 backlog_bytes;
	__u64 threshold_rate64;
	__u32 target_us;
	__u32 interval_us;
	__u32 way_indirect_hits;
	__u32 way_misses;
	__u32 way_collisions;
	__u32 peak_delay_us;
	__u32 avg_delay_us;
	__u32 base_delay_us;
	__u32 sparse_flows;
	__u32 bulk_flows;
	__u32 unresponsive_flows;
	__u32 max_skblen;
	__u32 flow_quantum;
};

void tc_cake_tin_stats_attrs_free(struct tc_cake_tin_stats_attrs *obj);

struct tc_flower_key_enc_opt_geneve_attrs {
	struct {
		__u32 class:1;
		__u32 type:1;
	} _present;
	struct {
		__u32 data;
	} _len;

	__u16 class;
	__u8 type;
	void *data;
};

struct tc_flower_key_enc_opt_vxlan_attrs {
	struct {
		__u32 gbp:1;
	} _present;

	__u32 gbp;
};

struct tc_flower_key_enc_opt_erspan_attrs {
	struct {
		__u32 ver:1;
		__u32 index:1;
		__u32 dir:1;
		__u32 hwid:1;
	} _present;

	__u8 ver;
	__u32 index;
	__u8 dir;
	__u8 hwid;
};

struct tc_flower_key_enc_opt_gtp_attrs {
	struct {
		__u32 pdu_type:1;
		__u32 qfi:1;
	} _present;

	__u8 pdu_type;
	__u8 qfi;
};

struct tc_tca_gred_vq_entry_attrs {
	struct {
		__u32 dp:1;
		__u32 stat_bytes:1;
		__u32 stat_packets:1;
		__u32 stat_backlog:1;
		__u32 stat_prob_drop:1;
		__u32 stat_prob_mark:1;
		__u32 stat_forced_drop:1;
		__u32 stat_forced_mark:1;
		__u32 stat_pdrop:1;
		__u32 stat_other:1;
		__u32 flags:1;
	} _present;

	__u32 dp;
	__u64 stat_bytes;
	__u32 stat_packets;
	__u32 stat_backlog;
	__u32 stat_prob_drop;
	__u32 stat_prob_mark;
	__u32 stat_forced_drop;
	__u32 stat_forced_mark;
	__u32 stat_pdrop;
	__u32 stat_other;
	__u32 flags;
};

void tc_tca_gred_vq_entry_attrs_free(struct tc_tca_gred_vq_entry_attrs *obj);

struct tc_act_bpf_attrs {
	struct {
		__u32 ops_len:1;
		__u32 fd:1;
	} _present;
	struct {
		__u32 tm;
		__u32 parms;
		__u32 ops;
		__u32 name;
		__u32 tag;
		__u32 id;
	} _len;

	struct tcf_t *tm;
	void *parms;
	__u16 ops_len;
	void *ops;
	__u32 fd;
	char *name;
	void *tag;
	void *id;
};

struct tc_act_connmark_attrs {
	struct {
		__u32 parms;
		__u32 tm;
	} _len;

	void *parms;
	struct tcf_t *tm;
};

struct tc_act_csum_attrs {
	struct {
		__u32 parms;
		__u32 tm;
	} _len;

	void *parms;
	struct tcf_t *tm;
};

struct tc_act_ct_attrs {
	struct {
		__u32 action:1;
		__u32 zone:1;
		__u32 mark:1;
		__u32 mark_mask:1;
		__u32 nat_ipv4_min:1;
		__u32 nat_ipv4_max:1;
		__u32 nat_port_min:1;
		__u32 nat_port_max:1;
		__u32 helper_family:1;
		__u32 helper_proto:1;
	} _present;
	struct {
		__u32 parms;
		__u32 tm;
		__u32 labels;
		__u32 labels_mask;
		__u32 nat_ipv6_min;
		__u32 nat_ipv6_max;
		__u32 helper_name;
	} _len;

	void *parms;
	struct tcf_t *tm;
	__u16 action;
	__u16 zone;
	__u32 mark;
	__u32 mark_mask;
	void *labels;
	void *labels_mask;
	__u32 nat_ipv4_min /* big-endian */;
	__u32 nat_ipv4_max /* big-endian */;
	void *nat_ipv6_min;
	void *nat_ipv6_max;
	__u16 nat_port_min /* big-endian */;
	__u16 nat_port_max /* big-endian */;
	char *helper_name;
	__u8 helper_family;
	__u8 helper_proto;
};

struct tc_act_ctinfo_attrs {
	struct {
		__u32 zone:1;
		__u32 parms_dscp_mask:1;
		__u32 parms_dscp_statemask:1;
		__u32 parms_cpmark_mask:1;
		__u32 stats_dscp_set:1;
		__u32 stats_dscp_error:1;
		__u32 stats_cpmark_set:1;
	} _present;
	struct {
		__u32 tm;
		__u32 act;
	} _len;

	struct tcf_t *tm;
	void *act;
	__u16 zone;
	__u32 parms_dscp_mask;
	__u32 parms_dscp_statemask;
	__u32 parms_cpmark_mask;
	__u64 stats_dscp_set;
	__u64 stats_dscp_error;
	__u64 stats_cpmark_set;
};

struct tc_act_gact_attrs {
	struct {
		__u32 tm;
		__u32 parms;
		__u32 prob;
	} _len;

	struct tcf_t *tm;
	struct tc_gact *parms;
	struct tc_gact_p *prob;
};

struct tc_act_gate_attrs {
	struct {
		__u32 priority:1;
		__u32 base_time:1;
		__u32 cycle_time:1;
		__u32 cycle_time_ext:1;
		__u32 flags:1;
		__u32 clockid:1;
	} _present;
	struct {
		__u32 tm;
		__u32 parms;
		__u32 entry_list;
	} _len;

	struct tcf_t *tm;
	void *parms;
	__s32 priority;
	void *entry_list;
	__u64 base_time;
	__u64 cycle_time;
	__u64 cycle_time_ext;
	__u32 flags;
	__s32 clockid;
};

struct tc_act_ife_attrs {
	struct {
		__u32 type:1;
	} _present;
	struct {
		__u32 parms;
		__u32 tm;
		__u32 dmac;
		__u32 smac;
		__u32 metalst;
	} _len;

	void *parms;
	struct tcf_t *tm;
	void *dmac;
	void *smac;
	__u16 type;
	void *metalst;
};

struct tc_act_mirred_attrs {
	struct {
		__u32 tm;
		__u32 parms;
		__u32 blockid;
	} _len;

	struct tcf_t *tm;
	void *parms;
	void *blockid;
};

struct tc_act_mpls_attrs {
	struct {
		__u32 proto:1;
		__u32 label:1;
		__u32 tc:1;
		__u32 ttl:1;
		__u32 bos:1;
	} _present;
	struct {
		__u32 tm;
		__u32 parms;
	} _len;

	struct tcf_t *tm;
	struct tc_mpls *parms;
	__u16 proto /* big-endian */;
	__u32 label;
	__u8 tc;
	__u8 ttl;
	__u8 bos;
};

struct tc_act_nat_attrs {
	struct {
		__u32 parms;
		__u32 tm;
	} _len;

	void *parms;
	struct tcf_t *tm;
};

struct tc_act_pedit_attrs {
	struct {
		__u32 tm;
		__u32 parms;
		__u32 parms_ex;
		__u32 keys_ex;
		__u32 key_ex;
	} _len;

	struct tcf_t *tm;
	struct tc_pedit_sel *parms;
	void *parms_ex;
	void *keys_ex;
	void *key_ex;
};

struct tc_act_sample_attrs {
	struct {
		__u32 rate:1;
		__u32 trunc_size:1;
		__u32 psample_group:1;
	} _present;
	struct {
		__u32 tm;
		__u32 parms;
	} _len;

	struct tcf_t *tm;
	struct tc_gact *parms;
	__u32 rate;
	__u32 trunc_size;
	__u32 psample_group;
};

struct tc_act_simple_attrs {
	struct {
		__u32 tm;
		__u32 parms;
		__u32 data;
	} _len;

	struct tcf_t *tm;
	void *parms;
	void *data;
};

struct tc_act_skbedit_attrs {
	struct {
		__u32 priority:1;
		__u32 queue_mapping:1;
		__u32 mark:1;
		__u32 ptype:1;
		__u32 mask:1;
		__u32 flags:1;
		__u32 queue_mapping_max:1;
	} _present;
	struct {
		__u32 tm;
		__u32 parms;
	} _len;

	struct tcf_t *tm;
	void *parms;
	__u32 priority;
	__u16 queue_mapping;
	__u32 mark;
	__u16 ptype;
	__u32 mask;
	__u64 flags;
	__u16 queue_mapping_max;
};

struct tc_act_skbmod_attrs {
	struct {
		__u32 tm;
		__u32 parms;
		__u32 dmac;
		__u32 smac;
		__u32 etype;
	} _len;

	struct tcf_t *tm;
	void *parms;
	void *dmac;
	void *smac;
	void *etype;
};

struct tc_act_tunnel_key_attrs {
	struct {
		__u32 enc_ipv4_src:1;
		__u32 enc_ipv4_dst:1;
		__u32 enc_key_id:1;
		__u32 enc_dst_port:1;
		__u32 no_csum:1;
		__u32 enc_tos:1;
		__u32 enc_ttl:1;
		__u32 no_frag:1;
	} _present;
	struct {
		__u32 tm;
		__u32 parms;
		__u32 enc_ipv6_src;
		__u32 enc_ipv6_dst;
		__u32 enc_opts;
	} _len;

	struct tcf_t *tm;
	void *parms;
	__u32 enc_ipv4_src /* big-endian */;
	__u32 enc_ipv4_dst /* big-endian */;
	void *enc_ipv6_src;
	void *enc_ipv6_dst;
	__u64 enc_key_id /* big-endian */;
	__u16 enc_dst_port /* big-endian */;
	__u8 no_csum;
	void *enc_opts;
	__u8 enc_tos;
	__u8 enc_ttl;
};

struct tc_act_vlan_attrs {
	struct {
		__u32 push_vlan_id:1;
		__u32 push_vlan_protocol:1;
		__u32 push_vlan_priority:1;
	} _present;
	struct {
		__u32 tm;
		__u32 parms;
		__u32 push_eth_dst;
		__u32 push_eth_src;
	} _len;

	struct tcf_t *tm;
	struct tc_vlan *parms;
	__u16 push_vlan_id;
	__u16 push_vlan_protocol;
	__u8 push_vlan_priority;
	void *push_eth_dst;
	void *push_eth_src;
};

struct tc_flow_attrs {
	struct {
		__u32 keys:1;
		__u32 mode:1;
		__u32 baseclass:1;
		__u32 rshift:1;
		__u32 addend:1;
		__u32 mask:1;
		__u32 xor:1;
		__u32 divisor:1;
		__u32 police:1;
		__u32 perturb:1;
	} _present;
	struct {
		__u32 act;
		__u32 ematches;
	} _len;

	__u32 keys;
	__u32 mode;
	__u32 baseclass;
	__u32 rshift;
	__u32 addend;
	__u32 mask;
	__u32 xor;
	__u32 divisor;
	void *act;
	struct tc_police_attrs police;
	void *ematches;
	__u32 perturb;
};

struct tc_netem_attrs {
	struct tc_netem_qopt _hdr;

	struct {
		__u32 loss:1;
		__u32 ecn:1;
		__u32 rate64:1;
		__u32 pad:1;
		__u32 latency64:1;
		__u32 jitter64:1;
		__u32 prng_seed:1;
	} _present;
	struct {
		__u32 corr;
		__u32 reorder;
		__u32 corrupt;
		__u32 rate;
		__u32 slot;
	} _len;
	struct {
		__u32 delay_dist;
		__u32 slot_dist;
	} _count;

	struct tc_netem_corr *corr;
	__s16 *delay_dist;
	struct tc_netem_reorder *reorder;
	struct tc_netem_corrupt *corrupt;
	struct tc_netem_loss_attrs loss;
	struct tc_netem_rate *rate;
	__u32 ecn;
	__u64 rate64;
	__u32 pad;
	__s64 latency64;
	__s64 jitter64;
	struct tc_netem_slot *slot;
	__s16 *slot_dist;
	__u64 prng_seed;
};

struct tc_cake_stats_attrs {
	struct {
		__u32 capacity_estimate64:1;
		__u32 memory_limit:1;
		__u32 memory_used:1;
		__u32 avg_netoff:1;
		__u32 min_netlen:1;
		__u32 max_netlen:1;
		__u32 min_adjlen:1;
		__u32 max_adjlen:1;
		__u32 deficit:1;
		__u32 cobalt_count:1;
		__u32 dropping:1;
		__u32 drop_next_us:1;
		__u32 p_drop:1;
		__u32 blue_timer_us:1;
	} _present;
	struct {
		__u32 tin_stats;
	} _count;

	__u64 capacity_estimate64;
	__u32 memory_limit;
	__u32 memory_used;
	__u32 avg_netoff;
	__u32 min_netlen;
	__u32 max_netlen;
	__u32 min_adjlen;
	__u32 max_adjlen;
	struct tc_cake_tin_stats_attrs *tin_stats;
	__s32 deficit;
	__u32 cobalt_count;
	__u32 dropping;
	__s32 drop_next_us;
	__u32 p_drop;
	__s32 blue_timer_us;
};

struct tc_flower_key_enc_opts_attrs {
	struct {
		__u32 geneve:1;
		__u32 vxlan:1;
		__u32 erspan:1;
		__u32 gtp:1;
	} _present;

	struct tc_flower_key_enc_opt_geneve_attrs geneve;
	struct tc_flower_key_enc_opt_vxlan_attrs vxlan;
	struct tc_flower_key_enc_opt_erspan_attrs erspan;
	struct tc_flower_key_enc_opt_gtp_attrs gtp;
};

struct tc_tca_gred_vq_list_attrs {
	struct {
		__u32 entry;
	} _count;

	struct tc_tca_gred_vq_entry_attrs *entry;
};

struct tc_taprio_sched_entry_list {
	struct {
		__u32 entry;
	} _count;

	struct tc_taprio_sched_entry *entry;
};

struct tc_act_options_msg {
	struct {
		__u32 bpf:1;
		__u32 connmark:1;
		__u32 csum:1;
		__u32 ct:1;
		__u32 ctinfo:1;
		__u32 gact:1;
		__u32 gate:1;
		__u32 ife:1;
		__u32 mirred:1;
		__u32 mpls:1;
		__u32 nat:1;
		__u32 pedit:1;
		__u32 police:1;
		__u32 sample:1;
		__u32 simple:1;
		__u32 skbedit:1;
		__u32 skbmod:1;
		__u32 tunnel_key:1;
		__u32 vlan:1;
	} _present;

	struct tc_act_bpf_attrs bpf;
	struct tc_act_connmark_attrs connmark;
	struct tc_act_csum_attrs csum;
	struct tc_act_ct_attrs ct;
	struct tc_act_ctinfo_attrs ctinfo;
	struct tc_act_gact_attrs gact;
	struct tc_act_gate_attrs gate;
	struct tc_act_ife_attrs ife;
	struct tc_act_mirred_attrs mirred;
	struct tc_act_mpls_attrs mpls;
	struct tc_act_nat_attrs nat;
	struct tc_act_pedit_attrs pedit;
	struct tc_police_attrs police;
	struct tc_act_sample_attrs sample;
	struct tc_act_simple_attrs simple;
	struct tc_act_skbedit_attrs skbedit;
	struct tc_act_skbmod_attrs skbmod;
	struct tc_act_tunnel_key_attrs tunnel_key;
	struct tc_act_vlan_attrs vlan;
};

struct tc_tca_stats_app_msg {
	struct {
		__u32 cake:1;
	} _present;
	struct {
		__u32 choke;
		__u32 codel;
		__u32 fq;
		__u32 fq_codel;
		__u32 fq_pie;
		__u32 hhf;
		__u32 pie;
		__u32 red;
		__u32 sfb;
		__u32 sfq;
	} _len;

	struct tc_cake_stats_attrs cake;
	struct tc_choke_xstats *choke;
	struct tc_codel_xstats *codel;
	struct tc_fq_qd_stats *fq;
	struct tc_fq_codel_xstats *fq_codel;
	struct tc_fq_pie_xstats *fq_pie;
	struct tc_hhf_xstats *hhf;
	struct tc_pie_xstats *pie;
	struct tc_red_xstats *red;
	struct tc_sfb_xstats *sfb;
	struct tc_sfq_xstats *sfq;
};

struct tc_tca_stats_attrs {
	struct {
		__u32 app:1;
		__u32 pkt64:1;
	} _present;
	struct {
		__u32 basic;
		__u32 rate_est;
		__u32 queue;
		__u32 rate_est64;
		__u32 basic_hw;
	} _len;

	struct gnet_stats_basic *basic;
	struct gnet_stats_rate_est *rate_est;
	struct gnet_stats_queue *queue;
	struct tc_tca_stats_app_msg app;
	struct gnet_stats_rate_est64 *rate_est64;
	struct gnet_stats_basic *basic_hw;
	__u64 pkt64;
};

struct tc_gred_attrs {
	struct {
		__u32 limit:1;
		__u32 vq_list:1;
	} _present;
	struct {
		__u32 parms;
		__u32 dps;
	} _len;
	struct {
		__u32 stab;
		__u32 max_p;
	} _count;

	void *parms;
	__u8 *stab;
	struct tc_gred_sopt *dps;
	__u32 *max_p;
	__u32 limit;
	struct tc_tca_gred_vq_list_attrs vq_list;
};

struct tc_taprio_attrs {
	struct {
		__u32 sched_entry_list:1;
		__u32 sched_base_time:1;
		__u32 sched_single_entry:1;
		__u32 sched_clockid:1;
		__u32 sched_cycle_time:1;
		__u32 sched_cycle_time_extension:1;
		__u32 flags:1;
		__u32 txtime_delay:1;
		__u32 tc_entry:1;
	} _present;
	struct {
		__u32 priomap;
		__u32 admin_sched;
	} _len;

	struct tc_mqprio_qopt *priomap;
	struct tc_taprio_sched_entry_list sched_entry_list;
	__s64 sched_base_time;
	struct tc_taprio_sched_entry sched_single_entry;
	__s32 sched_clockid;
	void *admin_sched;
	__s64 sched_cycle_time;
	__s64 sched_cycle_time_extension;
	__u32 flags;
	__u32 txtime_delay;
	struct tc_taprio_tc_entry_attrs tc_entry;
};

struct tc_act_attrs {
	struct {
		__u32 options:1;
		__u32 index:1;
		__u32 stats:1;
		__u32 flags:1;
		__u32 hw_stats:1;
		__u32 used_hw_stats:1;
		__u32 in_hw_count:1;
	} _present;
	struct {
		__u32 kind;
		__u32 cookie;
	} _len;

	__u32 idx;
	char *kind;
	struct tc_act_options_msg options;
	__u32 index;
	struct tc_tca_stats_attrs stats;
	void *cookie;
	struct nla_bitfield32 flags;
	struct nla_bitfield32 hw_stats;
	struct nla_bitfield32 used_hw_stats;
	__u32 in_hw_count;
};

void tc_act_attrs_free(struct tc_act_attrs *obj);

struct tc_basic_attrs {
	struct {
		__u32 classid:1;
		__u32 ematches:1;
		__u32 police:1;
	} _present;
	struct {
		__u32 pcnt;
	} _len;
	struct {
		__u32 act;
	} _count;

	__u32 classid;
	struct tc_ematch_attrs ematches;
	struct tc_act_attrs *act;
	struct tc_police_attrs police;
	struct tc_basic_pcnt *pcnt;
};

struct tc_bpf_attrs {
	struct {
		__u32 police:1;
		__u32 classid:1;
		__u32 ops_len:1;
		__u32 fd:1;
		__u32 flags:1;
		__u32 flags_gen:1;
		__u32 id:1;
	} _present;
	struct {
		__u32 ops;
		__u32 name;
		__u32 tag;
	} _len;
	struct {
		__u32 act;
	} _count;

	struct tc_act_attrs *act;
	struct tc_police_attrs police;
	__u32 classid;
	__u16 ops_len;
	void *ops;
	__u32 fd;
	char *name;
	__u32 flags;
	__u32 flags_gen;
	void *tag;
	__u32 id;
};

struct tc_cgroup_attrs {
	struct {
		__u32 police:1;
	} _present;
	struct {
		__u32 ematches;
	} _len;
	struct {
		__u32 act;
	} _count;

	struct tc_act_attrs *act;
	struct tc_police_attrs police;
	void *ematches;
};

struct tc_flower_attrs {
	struct {
		__u32 classid:1;
		__u32 key_eth_type:1;
		__u32 key_ip_proto:1;
		__u32 key_ipv4_src:1;
		__u32 key_ipv4_src_mask:1;
		__u32 key_ipv4_dst:1;
		__u32 key_ipv4_dst_mask:1;
		__u32 key_tcp_src:1;
		__u32 key_tcp_dst:1;
		__u32 key_udp_src:1;
		__u32 key_udp_dst:1;
		__u32 flags:1;
		__u32 key_vlan_id:1;
		__u32 key_vlan_prio:1;
		__u32 key_vlan_eth_type:1;
		__u32 key_enc_key_id:1;
		__u32 key_enc_ipv4_src:1;
		__u32 key_enc_ipv4_src_mask:1;
		__u32 key_enc_ipv4_dst:1;
		__u32 key_enc_ipv4_dst_mask:1;
		__u32 key_tcp_src_mask:1;
		__u32 key_tcp_dst_mask:1;
		__u32 key_udp_src_mask:1;
		__u32 key_udp_dst_mask:1;
		__u32 key_sctp_src_mask:1;
		__u32 key_sctp_dst_mask:1;
		__u32 key_sctp_src:1;
		__u32 key_sctp_dst:1;
		__u32 key_enc_udp_src_port:1;
		__u32 key_enc_udp_src_port_mask:1;
		__u32 key_enc_udp_dst_port:1;
		__u32 key_enc_udp_dst_port_mask:1;
		__u32 key_flags:1;
		__u32 key_flags_mask:1;
		__u32 key_icmpv4_code:1;
		__u32 key_icmpv4_code_mask:1;
		__u32 key_icmpv4_type:1;
		__u32 key_icmpv4_type_mask:1;
		__u32 key_icmpv6_code:1;
		__u32 key_icmpv6_code_mask:1;
		__u32 key_icmpv6_type:1;
		__u32 key_icmpv6_type_mask:1;
		__u32 key_arp_sip:1;
		__u32 key_arp_sip_mask:1;
		__u32 key_arp_tip:1;
		__u32 key_arp_tip_mask:1;
		__u32 key_arp_op:1;
		__u32 key_arp_op_mask:1;
		__u32 key_mpls_ttl:1;
		__u32 key_mpls_bos:1;
		__u32 key_mpls_tc:1;
		__u32 key_mpls_label:1;
		__u32 key_tcp_flags:1;
		__u32 key_tcp_flags_mask:1;
		__u32 key_ip_tos:1;
		__u32 key_ip_tos_mask:1;
		__u32 key_ip_ttl:1;
		__u32 key_ip_ttl_mask:1;
		__u32 key_cvlan_id:1;
		__u32 key_cvlan_prio:1;
		__u32 key_cvlan_eth_type:1;
		__u32 key_enc_ip_tos:1;
		__u32 key_enc_ip_tos_mask:1;
		__u32 key_enc_ip_ttl:1;
		__u32 key_enc_ip_ttl_mask:1;
		__u32 key_enc_opts:1;
		__u32 key_enc_opts_mask:1;
		__u32 in_hw_count:1;
		__u32 key_port_src_min:1;
		__u32 key_port_src_max:1;
		__u32 key_port_dst_min:1;
		__u32 key_port_dst_max:1;
		__u32 key_ct_state:1;
		__u32 key_ct_state_mask:1;
		__u32 key_ct_zone:1;
		__u32 key_ct_zone_mask:1;
		__u32 key_ct_mark:1;
		__u32 key_ct_mark_mask:1;
		__u32 key_mpls_opts:1;
		__u32 key_hash:1;
		__u32 key_hash_mask:1;
		__u32 key_num_of_vlans:1;
		__u32 key_pppoe_sid:1;
		__u32 key_ppp_proto:1;
		__u32 key_l2tpv3_sid:1;
		__u32 l2_miss:1;
		__u32 key_cfm:1;
		__u32 key_spi:1;
		__u32 key_spi_mask:1;
		__u32 key_enc_flags:1;
		__u32 key_enc_flags_mask:1;
	} _present;
	struct {
		__u32 indev;
		__u32 key_eth_dst;
		__u32 key_eth_dst_mask;
		__u32 key_eth_src;
		__u32 key_eth_src_mask;
		__u32 key_ipv6_src;
		__u32 key_ipv6_src_mask;
		__u32 key_ipv6_dst;
		__u32 key_ipv6_dst_mask;
		__u32 key_enc_ipv6_src;
		__u32 key_enc_ipv6_src_mask;
		__u32 key_enc_ipv6_dst;
		__u32 key_enc_ipv6_dst_mask;
		__u32 key_arp_sha;
		__u32 key_arp_sha_mask;
		__u32 key_arp_tha;
		__u32 key_arp_tha_mask;
		__u32 key_ct_labels;
		__u32 key_ct_labels_mask;
	} _len;
	struct {
		__u32 act;
	} _count;

	__u32 classid;
	char *indev;
	struct tc_act_attrs *act;
	void *key_eth_dst;
	void *key_eth_dst_mask;
	void *key_eth_src;
	void *key_eth_src_mask;
	__u16 key_eth_type /* big-endian */;
	__u8 key_ip_proto;
	__u32 key_ipv4_src /* big-endian */;
	__u32 key_ipv4_src_mask /* big-endian */;
	__u32 key_ipv4_dst /* big-endian */;
	__u32 key_ipv4_dst_mask /* big-endian */;
	void *key_ipv6_src;
	void *key_ipv6_src_mask;
	void *key_ipv6_dst;
	void *key_ipv6_dst_mask;
	__u16 key_tcp_src /* big-endian */;
	__u16 key_tcp_dst /* big-endian */;
	__u16 key_udp_src /* big-endian */;
	__u16 key_udp_dst /* big-endian */;
	__u32 flags;
	__u16 key_vlan_id /* big-endian */;
	__u8 key_vlan_prio;
	__u16 key_vlan_eth_type /* big-endian */;
	__u32 key_enc_key_id /* big-endian */;
	__u32 key_enc_ipv4_src /* big-endian */;
	__u32 key_enc_ipv4_src_mask /* big-endian */;
	__u32 key_enc_ipv4_dst /* big-endian */;
	__u32 key_enc_ipv4_dst_mask /* big-endian */;
	void *key_enc_ipv6_src;
	void *key_enc_ipv6_src_mask;
	void *key_enc_ipv6_dst;
	void *key_enc_ipv6_dst_mask;
	__u16 key_tcp_src_mask /* big-endian */;
	__u16 key_tcp_dst_mask /* big-endian */;
	__u16 key_udp_src_mask /* big-endian */;
	__u16 key_udp_dst_mask /* big-endian */;
	__u16 key_sctp_src_mask /* big-endian */;
	__u16 key_sctp_dst_mask /* big-endian */;
	__u16 key_sctp_src /* big-endian */;
	__u16 key_sctp_dst /* big-endian */;
	__u16 key_enc_udp_src_port /* big-endian */;
	__u16 key_enc_udp_src_port_mask /* big-endian */;
	__u16 key_enc_udp_dst_port /* big-endian */;
	__u16 key_enc_udp_dst_port_mask /* big-endian */;
	__u32 key_flags /* big-endian */;
	__u32 key_flags_mask /* big-endian */;
	__u8 key_icmpv4_code;
	__u8 key_icmpv4_code_mask;
	__u8 key_icmpv4_type;
	__u8 key_icmpv4_type_mask;
	__u8 key_icmpv6_code;
	__u8 key_icmpv6_code_mask;
	__u8 key_icmpv6_type;
	__u8 key_icmpv6_type_mask;
	__u32 key_arp_sip /* big-endian */;
	__u32 key_arp_sip_mask /* big-endian */;
	__u32 key_arp_tip /* big-endian */;
	__u32 key_arp_tip_mask /* big-endian */;
	__u8 key_arp_op;
	__u8 key_arp_op_mask;
	void *key_arp_sha;
	void *key_arp_sha_mask;
	void *key_arp_tha;
	void *key_arp_tha_mask;
	__u8 key_mpls_ttl;
	__u8 key_mpls_bos;
	__u8 key_mpls_tc;
	__u32 key_mpls_label /* big-endian */;
	__u16 key_tcp_flags /* big-endian */;
	__u16 key_tcp_flags_mask /* big-endian */;
	__u8 key_ip_tos;
	__u8 key_ip_tos_mask;
	__u8 key_ip_ttl;
	__u8 key_ip_ttl_mask;
	__u16 key_cvlan_id /* big-endian */;
	__u8 key_cvlan_prio;
	__u16 key_cvlan_eth_type /* big-endian */;
	__u8 key_enc_ip_tos;
	__u8 key_enc_ip_tos_mask;
	__u8 key_enc_ip_ttl;
	__u8 key_enc_ip_ttl_mask;
	struct tc_flower_key_enc_opts_attrs key_enc_opts;
	struct tc_flower_key_enc_opts_attrs key_enc_opts_mask;
	__u32 in_hw_count;
	__u16 key_port_src_min /* big-endian */;
	__u16 key_port_src_max /* big-endian */;
	__u16 key_port_dst_min /* big-endian */;
	__u16 key_port_dst_max /* big-endian */;
	__u16 key_ct_state;
	__u16 key_ct_state_mask;
	__u16 key_ct_zone;
	__u16 key_ct_zone_mask;
	__u32 key_ct_mark;
	__u32 key_ct_mark_mask;
	void *key_ct_labels;
	void *key_ct_labels_mask;
	struct tc_flower_key_mpls_opt_attrs key_mpls_opts;
	__u32 key_hash;
	__u32 key_hash_mask;
	__u8 key_num_of_vlans;
	__u16 key_pppoe_sid /* big-endian */;
	__u16 key_ppp_proto /* big-endian */;
	__u32 key_l2tpv3_sid /* big-endian */;
	__u8 l2_miss;
	struct tc_flower_key_cfm_attrs key_cfm;
	__u32 key_spi /* big-endian */;
	__u32 key_spi_mask /* big-endian */;
	__u32 key_enc_flags /* big-endian */;
	__u32 key_enc_flags_mask /* big-endian */;
};

struct tc_fw_attrs {
	struct {
		__u32 classid:1;
		__u32 police:1;
		__u32 mask:1;
	} _present;
	struct {
		__u32 indev;
	} _len;
	struct {
		__u32 act;
	} _count;

	__u32 classid;
	struct tc_police_attrs police;
	char *indev;
	struct tc_act_attrs *act;
	__u32 mask;
};

struct tc_matchall_attrs {
	struct {
		__u32 classid:1;
		__u32 flags:1;
	} _present;
	struct {
		__u32 pcnt;
	} _len;
	struct {
		__u32 act;
	} _count;

	__u32 classid;
	struct tc_act_attrs *act;
	__u32 flags;
	struct tc_matchall_pcnt *pcnt;
};

struct tc_route_attrs {
	struct {
		__u32 classid:1;
		__u32 to:1;
		__u32 from:1;
		__u32 iif:1;
		__u32 police:1;
	} _present;
	struct {
		__u32 act;
	} _count;

	__u32 classid;
	__u32 to;
	__u32 from;
	__u32 iif;
	struct tc_police_attrs police;
	struct tc_act_attrs *act;
};

struct tc_u32_attrs {
	struct {
		__u32 classid:1;
		__u32 hash:1;
		__u32 link:1;
		__u32 divisor:1;
		__u32 police:1;
		__u32 flags:1;
	} _present;
	struct {
		__u32 sel;
		__u32 indev;
		__u32 pcnt;
		__u32 mark;
	} _len;
	struct {
		__u32 act;
	} _count;

	__u32 classid;
	__u32 hash;
	__u32 link;
	__u32 divisor;
	struct tc_u32_sel *sel;
	struct tc_police_attrs police;
	struct tc_act_attrs *act;
	char *indev;
	struct tc_u32_pcnt *pcnt;
	struct tc_u32_mark *mark;
	__u32 flags;
};

struct tc_ets_attrs {
	struct {
		__u32 nbands:1;
		__u32 nstrict:1;
		__u32 quanta:1;
		__u32 priomap:1;
	} _present;
	struct {
		__u32 quanta_band;
		__u32 priomap_band;
	} _count;

	__u8 nbands;
	__u8 nstrict;
	struct tc_ets_attrs *quanta;
	__u32 *quanta_band;
	struct tc_ets_attrs *priomap;
	__u8 *priomap_band;
};

struct tc_options_msg {
	struct {
		__u32 basic:1;
		__u32 bpf:1;
		__u32 cake:1;
		__u32 cbs:1;
		__u32 cgroup:1;
		__u32 choke:1;
		__u32 clsact:1;
		__u32 codel:1;
		__u32 drr:1;
		__u32 etf:1;
		__u32 ets:1;
		__u32 flow:1;
		__u32 flower:1;
		__u32 fq:1;
		__u32 fq_codel:1;
		__u32 fq_pie:1;
		__u32 fw:1;
		__u32 gred:1;
		__u32 hhf:1;
		__u32 htb:1;
		__u32 ingress:1;
		__u32 matchall:1;
		__u32 mq:1;
		__u32 netem:1;
		__u32 pie:1;
		__u32 qfq:1;
		__u32 red:1;
		__u32 route:1;
		__u32 taprio:1;
		__u32 tbf:1;
		__u32 u32:1;
	} _present;
	struct {
		__u32 bfifo;
		__u32 hfsc;
		__u32 mqprio;
		__u32 multiq;
		__u32 pfifo;
		__u32 pfifo_fast;
		__u32 pfifo_head_drop;
		__u32 plug;
		__u32 prio;
		__u32 sfb;
		__u32 sfq;
	} _len;

	struct tc_basic_attrs basic;
	struct tc_bpf_attrs bpf;
	struct tc_fifo_qopt *bfifo;
	struct tc_cake_attrs cake;
	struct tc_cbs_attrs cbs;
	struct tc_cgroup_attrs cgroup;
	struct tc_choke_attrs choke;
	struct tc_codel_attrs codel;
	struct tc_drr_attrs drr;
	struct tc_etf_attrs etf;
	struct tc_ets_attrs *ets;
	struct tc_flow_attrs flow;
	struct tc_flower_attrs flower;
	struct tc_fq_attrs fq;
	struct tc_fq_codel_attrs fq_codel;
	struct tc_fq_pie_attrs fq_pie;
	struct tc_fw_attrs fw;
	struct tc_gred_attrs gred;
	struct tc_hfsc_qopt *hfsc;
	struct tc_hhf_attrs hhf;
	struct tc_htb_attrs htb;
	struct tc_matchall_attrs matchall;
	struct tc_mqprio_qopt *mqprio;
	struct tc_multiq_qopt *multiq;
	struct tc_netem_attrs netem;
	struct tc_fifo_qopt *pfifo;
	struct tc_prio_qopt *pfifo_fast;
	struct tc_fifo_qopt *pfifo_head_drop;
	struct tc_pie_attrs pie;
	struct tc_plug_qopt *plug;
	struct tc_prio_qopt *prio;
	struct tc_qfq_attrs qfq;
	struct tc_red_attrs red;
	struct tc_route_attrs route;
	struct tc_sfb_qopt *sfb;
	struct tc_sfq_qopt_v1 *sfq;
	struct tc_taprio_attrs taprio;
	struct tc_tbf_attrs tbf;
	struct tc_u32_attrs u32;
};

/* ============== RTM_NEWQDISC ============== */
/* RTM_NEWQDISC - do */
struct tc_newqdisc_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;

	struct {
		__u32 options:1;
		__u32 chain:1;
		__u32 ingress_block:1;
		__u32 egress_block:1;
	} _present;
	struct {
		__u32 kind;
		__u32 rate;
	} _len;

	char *kind;
	struct tc_options_msg options;
	struct gnet_estimator *rate;
	__u32 chain;
	__u32 ingress_block;
	__u32 egress_block;
};

static inline struct tc_newqdisc_req *tc_newqdisc_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_newqdisc_req));
}
void tc_newqdisc_req_free(struct tc_newqdisc_req *req);

static inline void
tc_newqdisc_req_set_nlflags(struct tc_newqdisc_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
tc_newqdisc_req_set_kind(struct tc_newqdisc_req *req, const char *kind)
{
	free(req->kind);
	req->_len.kind = strlen(kind);
	req->kind = malloc(req->_len.kind + 1);
	memcpy(req->kind, kind, req->_len.kind);
	req->kind[req->_len.kind] = 0;
}
static inline void
tc_newqdisc_req_set_options_basic_classid(struct tc_newqdisc_req *req,
					  __u32 classid)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.classid = 1;
	req->options.basic.classid = classid;
}
static inline void
tc_newqdisc_req_set_options_basic_ematches_tree_hdr(struct tc_newqdisc_req *req,
						    const void *tree_hdr,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.ematches = 1;
	free(req->options.basic.ematches.tree_hdr);
	req->options.basic.ematches._len.tree_hdr = len;
	req->options.basic.ematches.tree_hdr = malloc(req->options.basic.ematches._len.tree_hdr);
	memcpy(req->options.basic.ematches.tree_hdr, tree_hdr, req->options.basic.ematches._len.tree_hdr);
}
static inline void
tc_newqdisc_req_set_options_basic_ematches_tree_list(struct tc_newqdisc_req *req,
						     const void *tree_list,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.ematches = 1;
	free(req->options.basic.ematches.tree_list);
	req->options.basic.ematches._len.tree_list = len;
	req->options.basic.ematches.tree_list = malloc(req->options.basic.ematches._len.tree_list);
	memcpy(req->options.basic.ematches.tree_list, tree_list, req->options.basic.ematches._len.tree_list);
}
static inline void
__tc_newqdisc_req_set_options_basic_act(struct tc_newqdisc_req *req,
					struct tc_act_attrs *act,
					unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	free(req->options.basic.act);
	req->options.basic.act = act;
	req->options.basic._count.act = n_act;
}
static inline void
tc_newqdisc_req_set_options_basic_police_tbf(struct tc_newqdisc_req *req,
					     const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.tbf);
	req->options.basic.police._len.tbf = len;
	req->options.basic.police.tbf = malloc(req->options.basic.police._len.tbf);
	memcpy(req->options.basic.police.tbf, tbf, req->options.basic.police._len.tbf);
}
static inline void
tc_newqdisc_req_set_options_basic_police_rate(struct tc_newqdisc_req *req,
					      const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.rate);
	req->options.basic.police._len.rate = len;
	req->options.basic.police.rate = malloc(req->options.basic.police._len.rate);
	memcpy(req->options.basic.police.rate, rate, req->options.basic.police._len.rate);
}
static inline void
tc_newqdisc_req_set_options_basic_police_peakrate(struct tc_newqdisc_req *req,
						  const void *peakrate,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.peakrate);
	req->options.basic.police._len.peakrate = len;
	req->options.basic.police.peakrate = malloc(req->options.basic.police._len.peakrate);
	memcpy(req->options.basic.police.peakrate, peakrate, req->options.basic.police._len.peakrate);
}
static inline void
tc_newqdisc_req_set_options_basic_police_avrate(struct tc_newqdisc_req *req,
						__u32 avrate)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.avrate = 1;
	req->options.basic.police.avrate = avrate;
}
static inline void
tc_newqdisc_req_set_options_basic_police_result(struct tc_newqdisc_req *req,
						__u32 result)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.result = 1;
	req->options.basic.police.result = result;
}
static inline void
tc_newqdisc_req_set_options_basic_police_tm(struct tc_newqdisc_req *req,
					    const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.tm);
	req->options.basic.police._len.tm = len;
	req->options.basic.police.tm = malloc(req->options.basic.police._len.tm);
	memcpy(req->options.basic.police.tm, tm, req->options.basic.police._len.tm);
}
static inline void
tc_newqdisc_req_set_options_basic_police_rate64(struct tc_newqdisc_req *req,
						__u64 rate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.rate64 = 1;
	req->options.basic.police.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_basic_police_peakrate64(struct tc_newqdisc_req *req,
						    __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.peakrate64 = 1;
	req->options.basic.police.peakrate64 = peakrate64;
}
static inline void
tc_newqdisc_req_set_options_basic_police_pktrate64(struct tc_newqdisc_req *req,
						   __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.pktrate64 = 1;
	req->options.basic.police.pktrate64 = pktrate64;
}
static inline void
tc_newqdisc_req_set_options_basic_police_pktburst64(struct tc_newqdisc_req *req,
						    __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.pktburst64 = 1;
	req->options.basic.police.pktburst64 = pktburst64;
}
static inline void
tc_newqdisc_req_set_options_basic_pcnt(struct tc_newqdisc_req *req,
				       const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	free(req->options.basic.pcnt);
	req->options.basic._len.pcnt = len;
	req->options.basic.pcnt = malloc(req->options.basic._len.pcnt);
	memcpy(req->options.basic.pcnt, pcnt, req->options.basic._len.pcnt);
}
static inline void
__tc_newqdisc_req_set_options_bpf_act(struct tc_newqdisc_req *req,
				      struct tc_act_attrs *act,
				      unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.act);
	req->options.bpf.act = act;
	req->options.bpf._count.act = n_act;
}
static inline void
tc_newqdisc_req_set_options_bpf_police_tbf(struct tc_newqdisc_req *req,
					   const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.tbf);
	req->options.bpf.police._len.tbf = len;
	req->options.bpf.police.tbf = malloc(req->options.bpf.police._len.tbf);
	memcpy(req->options.bpf.police.tbf, tbf, req->options.bpf.police._len.tbf);
}
static inline void
tc_newqdisc_req_set_options_bpf_police_rate(struct tc_newqdisc_req *req,
					    const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.rate);
	req->options.bpf.police._len.rate = len;
	req->options.bpf.police.rate = malloc(req->options.bpf.police._len.rate);
	memcpy(req->options.bpf.police.rate, rate, req->options.bpf.police._len.rate);
}
static inline void
tc_newqdisc_req_set_options_bpf_police_peakrate(struct tc_newqdisc_req *req,
						const void *peakrate,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.peakrate);
	req->options.bpf.police._len.peakrate = len;
	req->options.bpf.police.peakrate = malloc(req->options.bpf.police._len.peakrate);
	memcpy(req->options.bpf.police.peakrate, peakrate, req->options.bpf.police._len.peakrate);
}
static inline void
tc_newqdisc_req_set_options_bpf_police_avrate(struct tc_newqdisc_req *req,
					      __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.avrate = 1;
	req->options.bpf.police.avrate = avrate;
}
static inline void
tc_newqdisc_req_set_options_bpf_police_result(struct tc_newqdisc_req *req,
					      __u32 result)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.result = 1;
	req->options.bpf.police.result = result;
}
static inline void
tc_newqdisc_req_set_options_bpf_police_tm(struct tc_newqdisc_req *req,
					  const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.tm);
	req->options.bpf.police._len.tm = len;
	req->options.bpf.police.tm = malloc(req->options.bpf.police._len.tm);
	memcpy(req->options.bpf.police.tm, tm, req->options.bpf.police._len.tm);
}
static inline void
tc_newqdisc_req_set_options_bpf_police_rate64(struct tc_newqdisc_req *req,
					      __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.rate64 = 1;
	req->options.bpf.police.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_bpf_police_peakrate64(struct tc_newqdisc_req *req,
						  __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.peakrate64 = 1;
	req->options.bpf.police.peakrate64 = peakrate64;
}
static inline void
tc_newqdisc_req_set_options_bpf_police_pktrate64(struct tc_newqdisc_req *req,
						 __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.pktrate64 = 1;
	req->options.bpf.police.pktrate64 = pktrate64;
}
static inline void
tc_newqdisc_req_set_options_bpf_police_pktburst64(struct tc_newqdisc_req *req,
						  __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.pktburst64 = 1;
	req->options.bpf.police.pktburst64 = pktburst64;
}
static inline void
tc_newqdisc_req_set_options_bpf_classid(struct tc_newqdisc_req *req,
					__u32 classid)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.classid = 1;
	req->options.bpf.classid = classid;
}
static inline void
tc_newqdisc_req_set_options_bpf_ops_len(struct tc_newqdisc_req *req,
					__u16 ops_len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.ops_len = 1;
	req->options.bpf.ops_len = ops_len;
}
static inline void
tc_newqdisc_req_set_options_bpf_ops(struct tc_newqdisc_req *req,
				    const void *ops, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.ops);
	req->options.bpf._len.ops = len;
	req->options.bpf.ops = malloc(req->options.bpf._len.ops);
	memcpy(req->options.bpf.ops, ops, req->options.bpf._len.ops);
}
static inline void
tc_newqdisc_req_set_options_bpf_fd(struct tc_newqdisc_req *req, __u32 fd)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.fd = 1;
	req->options.bpf.fd = fd;
}
static inline void
tc_newqdisc_req_set_options_bpf_name(struct tc_newqdisc_req *req,
				     const char *name)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.name);
	req->options.bpf._len.name = strlen(name);
	req->options.bpf.name = malloc(req->options.bpf._len.name + 1);
	memcpy(req->options.bpf.name, name, req->options.bpf._len.name);
	req->options.bpf.name[req->options.bpf._len.name] = 0;
}
static inline void
tc_newqdisc_req_set_options_bpf_flags(struct tc_newqdisc_req *req, __u32 flags)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.flags = 1;
	req->options.bpf.flags = flags;
}
static inline void
tc_newqdisc_req_set_options_bpf_flags_gen(struct tc_newqdisc_req *req,
					  __u32 flags_gen)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.flags_gen = 1;
	req->options.bpf.flags_gen = flags_gen;
}
static inline void
tc_newqdisc_req_set_options_bpf_tag(struct tc_newqdisc_req *req,
				    const void *tag, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.tag);
	req->options.bpf._len.tag = len;
	req->options.bpf.tag = malloc(req->options.bpf._len.tag);
	memcpy(req->options.bpf.tag, tag, req->options.bpf._len.tag);
}
static inline void
tc_newqdisc_req_set_options_bpf_id(struct tc_newqdisc_req *req, __u32 id)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.id = 1;
	req->options.bpf.id = id;
}
static inline void
tc_newqdisc_req_set_options_bfifo(struct tc_newqdisc_req *req,
				  const void *bfifo, size_t len)
{
	req->_present.options = 1;
	free(req->options.bfifo);
	req->options._len.bfifo = len;
	req->options.bfifo = malloc(req->options._len.bfifo);
	memcpy(req->options.bfifo, bfifo, req->options._len.bfifo);
}
static inline void
tc_newqdisc_req_set_options_cake_base_rate64(struct tc_newqdisc_req *req,
					     __u64 base_rate64)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.base_rate64 = 1;
	req->options.cake.base_rate64 = base_rate64;
}
static inline void
tc_newqdisc_req_set_options_cake_diffserv_mode(struct tc_newqdisc_req *req,
					       __u32 diffserv_mode)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.diffserv_mode = 1;
	req->options.cake.diffserv_mode = diffserv_mode;
}
static inline void
tc_newqdisc_req_set_options_cake_atm(struct tc_newqdisc_req *req, __u32 atm)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.atm = 1;
	req->options.cake.atm = atm;
}
static inline void
tc_newqdisc_req_set_options_cake_flow_mode(struct tc_newqdisc_req *req,
					   __u32 flow_mode)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.flow_mode = 1;
	req->options.cake.flow_mode = flow_mode;
}
static inline void
tc_newqdisc_req_set_options_cake_overhead(struct tc_newqdisc_req *req,
					  __u32 overhead)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.overhead = 1;
	req->options.cake.overhead = overhead;
}
static inline void
tc_newqdisc_req_set_options_cake_rtt(struct tc_newqdisc_req *req, __u32 rtt)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.rtt = 1;
	req->options.cake.rtt = rtt;
}
static inline void
tc_newqdisc_req_set_options_cake_target(struct tc_newqdisc_req *req,
					__u32 target)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.target = 1;
	req->options.cake.target = target;
}
static inline void
tc_newqdisc_req_set_options_cake_autorate(struct tc_newqdisc_req *req,
					  __u32 autorate)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.autorate = 1;
	req->options.cake.autorate = autorate;
}
static inline void
tc_newqdisc_req_set_options_cake_memory(struct tc_newqdisc_req *req,
					__u32 memory)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.memory = 1;
	req->options.cake.memory = memory;
}
static inline void
tc_newqdisc_req_set_options_cake_nat(struct tc_newqdisc_req *req, __u32 nat)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.nat = 1;
	req->options.cake.nat = nat;
}
static inline void
tc_newqdisc_req_set_options_cake_raw(struct tc_newqdisc_req *req, __u32 raw)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.raw = 1;
	req->options.cake.raw = raw;
}
static inline void
tc_newqdisc_req_set_options_cake_wash(struct tc_newqdisc_req *req, __u32 wash)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.wash = 1;
	req->options.cake.wash = wash;
}
static inline void
tc_newqdisc_req_set_options_cake_mpu(struct tc_newqdisc_req *req, __u32 mpu)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.mpu = 1;
	req->options.cake.mpu = mpu;
}
static inline void
tc_newqdisc_req_set_options_cake_ingress(struct tc_newqdisc_req *req,
					 __u32 ingress)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.ingress = 1;
	req->options.cake.ingress = ingress;
}
static inline void
tc_newqdisc_req_set_options_cake_ack_filter(struct tc_newqdisc_req *req,
					    __u32 ack_filter)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.ack_filter = 1;
	req->options.cake.ack_filter = ack_filter;
}
static inline void
tc_newqdisc_req_set_options_cake_split_gso(struct tc_newqdisc_req *req,
					   __u32 split_gso)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.split_gso = 1;
	req->options.cake.split_gso = split_gso;
}
static inline void
tc_newqdisc_req_set_options_cake_fwmark(struct tc_newqdisc_req *req,
					__u32 fwmark)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.fwmark = 1;
	req->options.cake.fwmark = fwmark;
}
static inline void
tc_newqdisc_req_set_options_cbs_parms(struct tc_newqdisc_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.cbs = 1;
	free(req->options.cbs.parms);
	req->options.cbs._len.parms = len;
	req->options.cbs.parms = malloc(req->options.cbs._len.parms);
	memcpy(req->options.cbs.parms, parms, req->options.cbs._len.parms);
}
static inline void
__tc_newqdisc_req_set_options_cgroup_act(struct tc_newqdisc_req *req,
					 struct tc_act_attrs *act,
					 unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	free(req->options.cgroup.act);
	req->options.cgroup.act = act;
	req->options.cgroup._count.act = n_act;
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_tbf(struct tc_newqdisc_req *req,
					      const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.tbf);
	req->options.cgroup.police._len.tbf = len;
	req->options.cgroup.police.tbf = malloc(req->options.cgroup.police._len.tbf);
	memcpy(req->options.cgroup.police.tbf, tbf, req->options.cgroup.police._len.tbf);
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_rate(struct tc_newqdisc_req *req,
					       const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.rate);
	req->options.cgroup.police._len.rate = len;
	req->options.cgroup.police.rate = malloc(req->options.cgroup.police._len.rate);
	memcpy(req->options.cgroup.police.rate, rate, req->options.cgroup.police._len.rate);
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_peakrate(struct tc_newqdisc_req *req,
						   const void *peakrate,
						   size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.peakrate);
	req->options.cgroup.police._len.peakrate = len;
	req->options.cgroup.police.peakrate = malloc(req->options.cgroup.police._len.peakrate);
	memcpy(req->options.cgroup.police.peakrate, peakrate, req->options.cgroup.police._len.peakrate);
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_avrate(struct tc_newqdisc_req *req,
						 __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.avrate = 1;
	req->options.cgroup.police.avrate = avrate;
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_result(struct tc_newqdisc_req *req,
						 __u32 result)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.result = 1;
	req->options.cgroup.police.result = result;
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_tm(struct tc_newqdisc_req *req,
					     const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.tm);
	req->options.cgroup.police._len.tm = len;
	req->options.cgroup.police.tm = malloc(req->options.cgroup.police._len.tm);
	memcpy(req->options.cgroup.police.tm, tm, req->options.cgroup.police._len.tm);
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_rate64(struct tc_newqdisc_req *req,
						 __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.rate64 = 1;
	req->options.cgroup.police.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_peakrate64(struct tc_newqdisc_req *req,
						     __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.peakrate64 = 1;
	req->options.cgroup.police.peakrate64 = peakrate64;
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_pktrate64(struct tc_newqdisc_req *req,
						    __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.pktrate64 = 1;
	req->options.cgroup.police.pktrate64 = pktrate64;
}
static inline void
tc_newqdisc_req_set_options_cgroup_police_pktburst64(struct tc_newqdisc_req *req,
						     __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.pktburst64 = 1;
	req->options.cgroup.police.pktburst64 = pktburst64;
}
static inline void
tc_newqdisc_req_set_options_cgroup_ematches(struct tc_newqdisc_req *req,
					    const void *ematches, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	free(req->options.cgroup.ematches);
	req->options.cgroup._len.ematches = len;
	req->options.cgroup.ematches = malloc(req->options.cgroup._len.ematches);
	memcpy(req->options.cgroup.ematches, ematches, req->options.cgroup._len.ematches);
}
static inline void
tc_newqdisc_req_set_options_choke_parms(struct tc_newqdisc_req *req,
					const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	free(req->options.choke.parms);
	req->options.choke._len.parms = len;
	req->options.choke.parms = malloc(req->options.choke._len.parms);
	memcpy(req->options.choke.parms, parms, req->options.choke._len.parms);
}
static inline void
tc_newqdisc_req_set_options_choke_stab(struct tc_newqdisc_req *req,
				       const void *stab, size_t len)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	free(req->options.choke.stab);
	req->options.choke._len.stab = len;
	req->options.choke.stab = malloc(req->options.choke._len.stab);
	memcpy(req->options.choke.stab, stab, req->options.choke._len.stab);
}
static inline void
tc_newqdisc_req_set_options_choke_max_p(struct tc_newqdisc_req *req,
					__u32 max_p)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	req->options.choke._present.max_p = 1;
	req->options.choke.max_p = max_p;
}
static inline void
tc_newqdisc_req_set_options_clsact(struct tc_newqdisc_req *req)
{
	req->_present.options = 1;
	req->options._present.clsact = 1;
}
static inline void
tc_newqdisc_req_set_options_codel_target(struct tc_newqdisc_req *req,
					 __u32 target)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.target = 1;
	req->options.codel.target = target;
}
static inline void
tc_newqdisc_req_set_options_codel_limit(struct tc_newqdisc_req *req,
					__u32 limit)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.limit = 1;
	req->options.codel.limit = limit;
}
static inline void
tc_newqdisc_req_set_options_codel_interval(struct tc_newqdisc_req *req,
					   __u32 interval)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.interval = 1;
	req->options.codel.interval = interval;
}
static inline void
tc_newqdisc_req_set_options_codel_ecn(struct tc_newqdisc_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.ecn = 1;
	req->options.codel.ecn = ecn;
}
static inline void
tc_newqdisc_req_set_options_codel_ce_threshold(struct tc_newqdisc_req *req,
					       __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.ce_threshold = 1;
	req->options.codel.ce_threshold = ce_threshold;
}
static inline void
tc_newqdisc_req_set_options_drr_quantum(struct tc_newqdisc_req *req,
					__u32 quantum)
{
	req->_present.options = 1;
	req->options._present.drr = 1;
	req->options.drr._present.quantum = 1;
	req->options.drr.quantum = quantum;
}
static inline void
tc_newqdisc_req_set_options_etf_parms(struct tc_newqdisc_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.etf = 1;
	free(req->options.etf.parms);
	req->options.etf._len.parms = len;
	req->options.etf.parms = malloc(req->options.etf._len.parms);
	memcpy(req->options.etf.parms, parms, req->options.etf._len.parms);
}
static inline void
tc_newqdisc_req_set_options_flow_keys(struct tc_newqdisc_req *req, __u32 keys)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.keys = 1;
	req->options.flow.keys = keys;
}
static inline void
tc_newqdisc_req_set_options_flow_mode(struct tc_newqdisc_req *req, __u32 mode)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.mode = 1;
	req->options.flow.mode = mode;
}
static inline void
tc_newqdisc_req_set_options_flow_baseclass(struct tc_newqdisc_req *req,
					   __u32 baseclass)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.baseclass = 1;
	req->options.flow.baseclass = baseclass;
}
static inline void
tc_newqdisc_req_set_options_flow_rshift(struct tc_newqdisc_req *req,
					__u32 rshift)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.rshift = 1;
	req->options.flow.rshift = rshift;
}
static inline void
tc_newqdisc_req_set_options_flow_addend(struct tc_newqdisc_req *req,
					__u32 addend)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.addend = 1;
	req->options.flow.addend = addend;
}
static inline void
tc_newqdisc_req_set_options_flow_mask(struct tc_newqdisc_req *req, __u32 mask)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.mask = 1;
	req->options.flow.mask = mask;
}
static inline void
tc_newqdisc_req_set_options_flow_xor(struct tc_newqdisc_req *req, __u32 xor)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.xor = 1;
	req->options.flow.xor = xor;
}
static inline void
tc_newqdisc_req_set_options_flow_divisor(struct tc_newqdisc_req *req,
					 __u32 divisor)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.divisor = 1;
	req->options.flow.divisor = divisor;
}
static inline void
tc_newqdisc_req_set_options_flow_act(struct tc_newqdisc_req *req,
				     const void *act, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	free(req->options.flow.act);
	req->options.flow._len.act = len;
	req->options.flow.act = malloc(req->options.flow._len.act);
	memcpy(req->options.flow.act, act, req->options.flow._len.act);
}
static inline void
tc_newqdisc_req_set_options_flow_police_tbf(struct tc_newqdisc_req *req,
					    const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.tbf);
	req->options.flow.police._len.tbf = len;
	req->options.flow.police.tbf = malloc(req->options.flow.police._len.tbf);
	memcpy(req->options.flow.police.tbf, tbf, req->options.flow.police._len.tbf);
}
static inline void
tc_newqdisc_req_set_options_flow_police_rate(struct tc_newqdisc_req *req,
					     const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.rate);
	req->options.flow.police._len.rate = len;
	req->options.flow.police.rate = malloc(req->options.flow.police._len.rate);
	memcpy(req->options.flow.police.rate, rate, req->options.flow.police._len.rate);
}
static inline void
tc_newqdisc_req_set_options_flow_police_peakrate(struct tc_newqdisc_req *req,
						 const void *peakrate,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.peakrate);
	req->options.flow.police._len.peakrate = len;
	req->options.flow.police.peakrate = malloc(req->options.flow.police._len.peakrate);
	memcpy(req->options.flow.police.peakrate, peakrate, req->options.flow.police._len.peakrate);
}
static inline void
tc_newqdisc_req_set_options_flow_police_avrate(struct tc_newqdisc_req *req,
					       __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.avrate = 1;
	req->options.flow.police.avrate = avrate;
}
static inline void
tc_newqdisc_req_set_options_flow_police_result(struct tc_newqdisc_req *req,
					       __u32 result)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.result = 1;
	req->options.flow.police.result = result;
}
static inline void
tc_newqdisc_req_set_options_flow_police_tm(struct tc_newqdisc_req *req,
					   const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.tm);
	req->options.flow.police._len.tm = len;
	req->options.flow.police.tm = malloc(req->options.flow.police._len.tm);
	memcpy(req->options.flow.police.tm, tm, req->options.flow.police._len.tm);
}
static inline void
tc_newqdisc_req_set_options_flow_police_rate64(struct tc_newqdisc_req *req,
					       __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.rate64 = 1;
	req->options.flow.police.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_flow_police_peakrate64(struct tc_newqdisc_req *req,
						   __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.peakrate64 = 1;
	req->options.flow.police.peakrate64 = peakrate64;
}
static inline void
tc_newqdisc_req_set_options_flow_police_pktrate64(struct tc_newqdisc_req *req,
						  __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.pktrate64 = 1;
	req->options.flow.police.pktrate64 = pktrate64;
}
static inline void
tc_newqdisc_req_set_options_flow_police_pktburst64(struct tc_newqdisc_req *req,
						   __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.pktburst64 = 1;
	req->options.flow.police.pktburst64 = pktburst64;
}
static inline void
tc_newqdisc_req_set_options_flow_ematches(struct tc_newqdisc_req *req,
					  const void *ematches, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	free(req->options.flow.ematches);
	req->options.flow._len.ematches = len;
	req->options.flow.ematches = malloc(req->options.flow._len.ematches);
	memcpy(req->options.flow.ematches, ematches, req->options.flow._len.ematches);
}
static inline void
tc_newqdisc_req_set_options_flow_perturb(struct tc_newqdisc_req *req,
					 __u32 perturb)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.perturb = 1;
	req->options.flow.perturb = perturb;
}
static inline void
tc_newqdisc_req_set_options_flower_classid(struct tc_newqdisc_req *req,
					   __u32 classid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.classid = 1;
	req->options.flower.classid = classid;
}
static inline void
tc_newqdisc_req_set_options_flower_indev(struct tc_newqdisc_req *req,
					 const char *indev)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.indev);
	req->options.flower._len.indev = strlen(indev);
	req->options.flower.indev = malloc(req->options.flower._len.indev + 1);
	memcpy(req->options.flower.indev, indev, req->options.flower._len.indev);
	req->options.flower.indev[req->options.flower._len.indev] = 0;
}
static inline void
__tc_newqdisc_req_set_options_flower_act(struct tc_newqdisc_req *req,
					 struct tc_act_attrs *act,
					 unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.act);
	req->options.flower.act = act;
	req->options.flower._count.act = n_act;
}
static inline void
tc_newqdisc_req_set_options_flower_key_eth_dst(struct tc_newqdisc_req *req,
					       const void *key_eth_dst,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_dst);
	req->options.flower._len.key_eth_dst = len;
	req->options.flower.key_eth_dst = malloc(req->options.flower._len.key_eth_dst);
	memcpy(req->options.flower.key_eth_dst, key_eth_dst, req->options.flower._len.key_eth_dst);
}
static inline void
tc_newqdisc_req_set_options_flower_key_eth_dst_mask(struct tc_newqdisc_req *req,
						    const void *key_eth_dst_mask,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_dst_mask);
	req->options.flower._len.key_eth_dst_mask = len;
	req->options.flower.key_eth_dst_mask = malloc(req->options.flower._len.key_eth_dst_mask);
	memcpy(req->options.flower.key_eth_dst_mask, key_eth_dst_mask, req->options.flower._len.key_eth_dst_mask);
}
static inline void
tc_newqdisc_req_set_options_flower_key_eth_src(struct tc_newqdisc_req *req,
					       const void *key_eth_src,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_src);
	req->options.flower._len.key_eth_src = len;
	req->options.flower.key_eth_src = malloc(req->options.flower._len.key_eth_src);
	memcpy(req->options.flower.key_eth_src, key_eth_src, req->options.flower._len.key_eth_src);
}
static inline void
tc_newqdisc_req_set_options_flower_key_eth_src_mask(struct tc_newqdisc_req *req,
						    const void *key_eth_src_mask,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_src_mask);
	req->options.flower._len.key_eth_src_mask = len;
	req->options.flower.key_eth_src_mask = malloc(req->options.flower._len.key_eth_src_mask);
	memcpy(req->options.flower.key_eth_src_mask, key_eth_src_mask, req->options.flower._len.key_eth_src_mask);
}
static inline void
tc_newqdisc_req_set_options_flower_key_eth_type(struct tc_newqdisc_req *req,
						__u16 key_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_eth_type = 1;
	req->options.flower.key_eth_type = key_eth_type;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ip_proto(struct tc_newqdisc_req *req,
						__u8 key_ip_proto)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_proto = 1;
	req->options.flower.key_ip_proto = key_ip_proto;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ipv4_src(struct tc_newqdisc_req *req,
						__u32 key_ipv4_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_src = 1;
	req->options.flower.key_ipv4_src = key_ipv4_src;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ipv4_src_mask(struct tc_newqdisc_req *req,
						     __u32 key_ipv4_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_src_mask = 1;
	req->options.flower.key_ipv4_src_mask = key_ipv4_src_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ipv4_dst(struct tc_newqdisc_req *req,
						__u32 key_ipv4_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_dst = 1;
	req->options.flower.key_ipv4_dst = key_ipv4_dst;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ipv4_dst_mask(struct tc_newqdisc_req *req,
						     __u32 key_ipv4_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_dst_mask = 1;
	req->options.flower.key_ipv4_dst_mask = key_ipv4_dst_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ipv6_src(struct tc_newqdisc_req *req,
						const void *key_ipv6_src,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_src);
	req->options.flower._len.key_ipv6_src = len;
	req->options.flower.key_ipv6_src = malloc(req->options.flower._len.key_ipv6_src);
	memcpy(req->options.flower.key_ipv6_src, key_ipv6_src, req->options.flower._len.key_ipv6_src);
}
static inline void
tc_newqdisc_req_set_options_flower_key_ipv6_src_mask(struct tc_newqdisc_req *req,
						     const void *key_ipv6_src_mask,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_src_mask);
	req->options.flower._len.key_ipv6_src_mask = len;
	req->options.flower.key_ipv6_src_mask = malloc(req->options.flower._len.key_ipv6_src_mask);
	memcpy(req->options.flower.key_ipv6_src_mask, key_ipv6_src_mask, req->options.flower._len.key_ipv6_src_mask);
}
static inline void
tc_newqdisc_req_set_options_flower_key_ipv6_dst(struct tc_newqdisc_req *req,
						const void *key_ipv6_dst,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_dst);
	req->options.flower._len.key_ipv6_dst = len;
	req->options.flower.key_ipv6_dst = malloc(req->options.flower._len.key_ipv6_dst);
	memcpy(req->options.flower.key_ipv6_dst, key_ipv6_dst, req->options.flower._len.key_ipv6_dst);
}
static inline void
tc_newqdisc_req_set_options_flower_key_ipv6_dst_mask(struct tc_newqdisc_req *req,
						     const void *key_ipv6_dst_mask,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_dst_mask);
	req->options.flower._len.key_ipv6_dst_mask = len;
	req->options.flower.key_ipv6_dst_mask = malloc(req->options.flower._len.key_ipv6_dst_mask);
	memcpy(req->options.flower.key_ipv6_dst_mask, key_ipv6_dst_mask, req->options.flower._len.key_ipv6_dst_mask);
}
static inline void
tc_newqdisc_req_set_options_flower_key_tcp_src(struct tc_newqdisc_req *req,
					       __u16 key_tcp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_src = 1;
	req->options.flower.key_tcp_src = key_tcp_src;
}
static inline void
tc_newqdisc_req_set_options_flower_key_tcp_dst(struct tc_newqdisc_req *req,
					       __u16 key_tcp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_dst = 1;
	req->options.flower.key_tcp_dst = key_tcp_dst;
}
static inline void
tc_newqdisc_req_set_options_flower_key_udp_src(struct tc_newqdisc_req *req,
					       __u16 key_udp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_src = 1;
	req->options.flower.key_udp_src = key_udp_src;
}
static inline void
tc_newqdisc_req_set_options_flower_key_udp_dst(struct tc_newqdisc_req *req,
					       __u16 key_udp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_dst = 1;
	req->options.flower.key_udp_dst = key_udp_dst;
}
static inline void
tc_newqdisc_req_set_options_flower_flags(struct tc_newqdisc_req *req,
					 __u32 flags)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.flags = 1;
	req->options.flower.flags = flags;
}
static inline void
tc_newqdisc_req_set_options_flower_key_vlan_id(struct tc_newqdisc_req *req,
					       __u16 key_vlan_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_id = 1;
	req->options.flower.key_vlan_id = key_vlan_id;
}
static inline void
tc_newqdisc_req_set_options_flower_key_vlan_prio(struct tc_newqdisc_req *req,
						 __u8 key_vlan_prio)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_prio = 1;
	req->options.flower.key_vlan_prio = key_vlan_prio;
}
static inline void
tc_newqdisc_req_set_options_flower_key_vlan_eth_type(struct tc_newqdisc_req *req,
						     __u16 key_vlan_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_eth_type = 1;
	req->options.flower.key_vlan_eth_type = key_vlan_eth_type;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_key_id(struct tc_newqdisc_req *req,
						  __u32 key_enc_key_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_key_id = 1;
	req->options.flower.key_enc_key_id = key_enc_key_id;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ipv4_src(struct tc_newqdisc_req *req,
						    __u32 key_enc_ipv4_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_src = 1;
	req->options.flower.key_enc_ipv4_src = key_enc_ipv4_src;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ipv4_src_mask(struct tc_newqdisc_req *req,
							 __u32 key_enc_ipv4_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_src_mask = 1;
	req->options.flower.key_enc_ipv4_src_mask = key_enc_ipv4_src_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ipv4_dst(struct tc_newqdisc_req *req,
						    __u32 key_enc_ipv4_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_dst = 1;
	req->options.flower.key_enc_ipv4_dst = key_enc_ipv4_dst;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ipv4_dst_mask(struct tc_newqdisc_req *req,
							 __u32 key_enc_ipv4_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_dst_mask = 1;
	req->options.flower.key_enc_ipv4_dst_mask = key_enc_ipv4_dst_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ipv6_src(struct tc_newqdisc_req *req,
						    const void *key_enc_ipv6_src,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_src);
	req->options.flower._len.key_enc_ipv6_src = len;
	req->options.flower.key_enc_ipv6_src = malloc(req->options.flower._len.key_enc_ipv6_src);
	memcpy(req->options.flower.key_enc_ipv6_src, key_enc_ipv6_src, req->options.flower._len.key_enc_ipv6_src);
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ipv6_src_mask(struct tc_newqdisc_req *req,
							 const void *key_enc_ipv6_src_mask,
							 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_src_mask);
	req->options.flower._len.key_enc_ipv6_src_mask = len;
	req->options.flower.key_enc_ipv6_src_mask = malloc(req->options.flower._len.key_enc_ipv6_src_mask);
	memcpy(req->options.flower.key_enc_ipv6_src_mask, key_enc_ipv6_src_mask, req->options.flower._len.key_enc_ipv6_src_mask);
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ipv6_dst(struct tc_newqdisc_req *req,
						    const void *key_enc_ipv6_dst,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_dst);
	req->options.flower._len.key_enc_ipv6_dst = len;
	req->options.flower.key_enc_ipv6_dst = malloc(req->options.flower._len.key_enc_ipv6_dst);
	memcpy(req->options.flower.key_enc_ipv6_dst, key_enc_ipv6_dst, req->options.flower._len.key_enc_ipv6_dst);
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ipv6_dst_mask(struct tc_newqdisc_req *req,
							 const void *key_enc_ipv6_dst_mask,
							 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_dst_mask);
	req->options.flower._len.key_enc_ipv6_dst_mask = len;
	req->options.flower.key_enc_ipv6_dst_mask = malloc(req->options.flower._len.key_enc_ipv6_dst_mask);
	memcpy(req->options.flower.key_enc_ipv6_dst_mask, key_enc_ipv6_dst_mask, req->options.flower._len.key_enc_ipv6_dst_mask);
}
static inline void
tc_newqdisc_req_set_options_flower_key_tcp_src_mask(struct tc_newqdisc_req *req,
						    __u16 key_tcp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_src_mask = 1;
	req->options.flower.key_tcp_src_mask = key_tcp_src_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_tcp_dst_mask(struct tc_newqdisc_req *req,
						    __u16 key_tcp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_dst_mask = 1;
	req->options.flower.key_tcp_dst_mask = key_tcp_dst_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_udp_src_mask(struct tc_newqdisc_req *req,
						    __u16 key_udp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_src_mask = 1;
	req->options.flower.key_udp_src_mask = key_udp_src_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_udp_dst_mask(struct tc_newqdisc_req *req,
						    __u16 key_udp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_dst_mask = 1;
	req->options.flower.key_udp_dst_mask = key_udp_dst_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_sctp_src_mask(struct tc_newqdisc_req *req,
						     __u16 key_sctp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_src_mask = 1;
	req->options.flower.key_sctp_src_mask = key_sctp_src_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_sctp_dst_mask(struct tc_newqdisc_req *req,
						     __u16 key_sctp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_dst_mask = 1;
	req->options.flower.key_sctp_dst_mask = key_sctp_dst_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_sctp_src(struct tc_newqdisc_req *req,
						__u16 key_sctp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_src = 1;
	req->options.flower.key_sctp_src = key_sctp_src;
}
static inline void
tc_newqdisc_req_set_options_flower_key_sctp_dst(struct tc_newqdisc_req *req,
						__u16 key_sctp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_dst = 1;
	req->options.flower.key_sctp_dst = key_sctp_dst;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_udp_src_port(struct tc_newqdisc_req *req,
							__u16 key_enc_udp_src_port /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_src_port = 1;
	req->options.flower.key_enc_udp_src_port = key_enc_udp_src_port;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_udp_src_port_mask(struct tc_newqdisc_req *req,
							     __u16 key_enc_udp_src_port_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_src_port_mask = 1;
	req->options.flower.key_enc_udp_src_port_mask = key_enc_udp_src_port_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_udp_dst_port(struct tc_newqdisc_req *req,
							__u16 key_enc_udp_dst_port /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_dst_port = 1;
	req->options.flower.key_enc_udp_dst_port = key_enc_udp_dst_port;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_udp_dst_port_mask(struct tc_newqdisc_req *req,
							     __u16 key_enc_udp_dst_port_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_dst_port_mask = 1;
	req->options.flower.key_enc_udp_dst_port_mask = key_enc_udp_dst_port_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_flags(struct tc_newqdisc_req *req,
					     __u32 key_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_flags = 1;
	req->options.flower.key_flags = key_flags;
}
static inline void
tc_newqdisc_req_set_options_flower_key_flags_mask(struct tc_newqdisc_req *req,
						  __u32 key_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_flags_mask = 1;
	req->options.flower.key_flags_mask = key_flags_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_icmpv4_code(struct tc_newqdisc_req *req,
						   __u8 key_icmpv4_code)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_code = 1;
	req->options.flower.key_icmpv4_code = key_icmpv4_code;
}
static inline void
tc_newqdisc_req_set_options_flower_key_icmpv4_code_mask(struct tc_newqdisc_req *req,
							__u8 key_icmpv4_code_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_code_mask = 1;
	req->options.flower.key_icmpv4_code_mask = key_icmpv4_code_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_icmpv4_type(struct tc_newqdisc_req *req,
						   __u8 key_icmpv4_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_type = 1;
	req->options.flower.key_icmpv4_type = key_icmpv4_type;
}
static inline void
tc_newqdisc_req_set_options_flower_key_icmpv4_type_mask(struct tc_newqdisc_req *req,
							__u8 key_icmpv4_type_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_type_mask = 1;
	req->options.flower.key_icmpv4_type_mask = key_icmpv4_type_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_icmpv6_code(struct tc_newqdisc_req *req,
						   __u8 key_icmpv6_code)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_code = 1;
	req->options.flower.key_icmpv6_code = key_icmpv6_code;
}
static inline void
tc_newqdisc_req_set_options_flower_key_icmpv6_code_mask(struct tc_newqdisc_req *req,
							__u8 key_icmpv6_code_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_code_mask = 1;
	req->options.flower.key_icmpv6_code_mask = key_icmpv6_code_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_icmpv6_type(struct tc_newqdisc_req *req,
						   __u8 key_icmpv6_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_type = 1;
	req->options.flower.key_icmpv6_type = key_icmpv6_type;
}
static inline void
tc_newqdisc_req_set_options_flower_key_icmpv6_type_mask(struct tc_newqdisc_req *req,
							__u8 key_icmpv6_type_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_type_mask = 1;
	req->options.flower.key_icmpv6_type_mask = key_icmpv6_type_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_sip(struct tc_newqdisc_req *req,
					       __u32 key_arp_sip /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_sip = 1;
	req->options.flower.key_arp_sip = key_arp_sip;
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_sip_mask(struct tc_newqdisc_req *req,
						    __u32 key_arp_sip_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_sip_mask = 1;
	req->options.flower.key_arp_sip_mask = key_arp_sip_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_tip(struct tc_newqdisc_req *req,
					       __u32 key_arp_tip /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_tip = 1;
	req->options.flower.key_arp_tip = key_arp_tip;
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_tip_mask(struct tc_newqdisc_req *req,
						    __u32 key_arp_tip_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_tip_mask = 1;
	req->options.flower.key_arp_tip_mask = key_arp_tip_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_op(struct tc_newqdisc_req *req,
					      __u8 key_arp_op)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_op = 1;
	req->options.flower.key_arp_op = key_arp_op;
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_op_mask(struct tc_newqdisc_req *req,
						   __u8 key_arp_op_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_op_mask = 1;
	req->options.flower.key_arp_op_mask = key_arp_op_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_sha(struct tc_newqdisc_req *req,
					       const void *key_arp_sha,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_sha);
	req->options.flower._len.key_arp_sha = len;
	req->options.flower.key_arp_sha = malloc(req->options.flower._len.key_arp_sha);
	memcpy(req->options.flower.key_arp_sha, key_arp_sha, req->options.flower._len.key_arp_sha);
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_sha_mask(struct tc_newqdisc_req *req,
						    const void *key_arp_sha_mask,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_sha_mask);
	req->options.flower._len.key_arp_sha_mask = len;
	req->options.flower.key_arp_sha_mask = malloc(req->options.flower._len.key_arp_sha_mask);
	memcpy(req->options.flower.key_arp_sha_mask, key_arp_sha_mask, req->options.flower._len.key_arp_sha_mask);
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_tha(struct tc_newqdisc_req *req,
					       const void *key_arp_tha,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_tha);
	req->options.flower._len.key_arp_tha = len;
	req->options.flower.key_arp_tha = malloc(req->options.flower._len.key_arp_tha);
	memcpy(req->options.flower.key_arp_tha, key_arp_tha, req->options.flower._len.key_arp_tha);
}
static inline void
tc_newqdisc_req_set_options_flower_key_arp_tha_mask(struct tc_newqdisc_req *req,
						    const void *key_arp_tha_mask,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_tha_mask);
	req->options.flower._len.key_arp_tha_mask = len;
	req->options.flower.key_arp_tha_mask = malloc(req->options.flower._len.key_arp_tha_mask);
	memcpy(req->options.flower.key_arp_tha_mask, key_arp_tha_mask, req->options.flower._len.key_arp_tha_mask);
}
static inline void
tc_newqdisc_req_set_options_flower_key_mpls_ttl(struct tc_newqdisc_req *req,
						__u8 key_mpls_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_ttl = 1;
	req->options.flower.key_mpls_ttl = key_mpls_ttl;
}
static inline void
tc_newqdisc_req_set_options_flower_key_mpls_bos(struct tc_newqdisc_req *req,
						__u8 key_mpls_bos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_bos = 1;
	req->options.flower.key_mpls_bos = key_mpls_bos;
}
static inline void
tc_newqdisc_req_set_options_flower_key_mpls_tc(struct tc_newqdisc_req *req,
					       __u8 key_mpls_tc)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_tc = 1;
	req->options.flower.key_mpls_tc = key_mpls_tc;
}
static inline void
tc_newqdisc_req_set_options_flower_key_mpls_label(struct tc_newqdisc_req *req,
						  __u32 key_mpls_label /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_label = 1;
	req->options.flower.key_mpls_label = key_mpls_label;
}
static inline void
tc_newqdisc_req_set_options_flower_key_tcp_flags(struct tc_newqdisc_req *req,
						 __u16 key_tcp_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_flags = 1;
	req->options.flower.key_tcp_flags = key_tcp_flags;
}
static inline void
tc_newqdisc_req_set_options_flower_key_tcp_flags_mask(struct tc_newqdisc_req *req,
						      __u16 key_tcp_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_flags_mask = 1;
	req->options.flower.key_tcp_flags_mask = key_tcp_flags_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ip_tos(struct tc_newqdisc_req *req,
					      __u8 key_ip_tos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_tos = 1;
	req->options.flower.key_ip_tos = key_ip_tos;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ip_tos_mask(struct tc_newqdisc_req *req,
						   __u8 key_ip_tos_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_tos_mask = 1;
	req->options.flower.key_ip_tos_mask = key_ip_tos_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ip_ttl(struct tc_newqdisc_req *req,
					      __u8 key_ip_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_ttl = 1;
	req->options.flower.key_ip_ttl = key_ip_ttl;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ip_ttl_mask(struct tc_newqdisc_req *req,
						   __u8 key_ip_ttl_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_ttl_mask = 1;
	req->options.flower.key_ip_ttl_mask = key_ip_ttl_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_cvlan_id(struct tc_newqdisc_req *req,
						__u16 key_cvlan_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_id = 1;
	req->options.flower.key_cvlan_id = key_cvlan_id;
}
static inline void
tc_newqdisc_req_set_options_flower_key_cvlan_prio(struct tc_newqdisc_req *req,
						  __u8 key_cvlan_prio)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_prio = 1;
	req->options.flower.key_cvlan_prio = key_cvlan_prio;
}
static inline void
tc_newqdisc_req_set_options_flower_key_cvlan_eth_type(struct tc_newqdisc_req *req,
						      __u16 key_cvlan_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_eth_type = 1;
	req->options.flower.key_cvlan_eth_type = key_cvlan_eth_type;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ip_tos(struct tc_newqdisc_req *req,
						  __u8 key_enc_ip_tos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_tos = 1;
	req->options.flower.key_enc_ip_tos = key_enc_ip_tos;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ip_tos_mask(struct tc_newqdisc_req *req,
						       __u8 key_enc_ip_tos_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_tos_mask = 1;
	req->options.flower.key_enc_ip_tos_mask = key_enc_ip_tos_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ip_ttl(struct tc_newqdisc_req *req,
						  __u8 key_enc_ip_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_ttl = 1;
	req->options.flower.key_enc_ip_ttl = key_enc_ip_ttl;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_ip_ttl_mask(struct tc_newqdisc_req *req,
						       __u8 key_enc_ip_ttl_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_ttl_mask = 1;
	req->options.flower.key_enc_ip_ttl_mask = key_enc_ip_ttl_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_geneve_class(struct tc_newqdisc_req *req,
							     __u16 class)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	req->options.flower.key_enc_opts.geneve._present.class = 1;
	req->options.flower.key_enc_opts.geneve.class = class;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_geneve_type(struct tc_newqdisc_req *req,
							    __u8 type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	req->options.flower.key_enc_opts.geneve._present.type = 1;
	req->options.flower.key_enc_opts.geneve.type = type;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_geneve_data(struct tc_newqdisc_req *req,
							    const void *data,
							    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	free(req->options.flower.key_enc_opts.geneve.data);
	req->options.flower.key_enc_opts.geneve._len.data = len;
	req->options.flower.key_enc_opts.geneve.data = malloc(req->options.flower.key_enc_opts.geneve._len.data);
	memcpy(req->options.flower.key_enc_opts.geneve.data, data, req->options.flower.key_enc_opts.geneve._len.data);
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_vxlan_gbp(struct tc_newqdisc_req *req,
							  __u32 gbp)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.vxlan = 1;
	req->options.flower.key_enc_opts.vxlan._present.gbp = 1;
	req->options.flower.key_enc_opts.vxlan.gbp = gbp;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_erspan_ver(struct tc_newqdisc_req *req,
							   __u8 ver)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.ver = 1;
	req->options.flower.key_enc_opts.erspan.ver = ver;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_erspan_index(struct tc_newqdisc_req *req,
							     __u32 index)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.index = 1;
	req->options.flower.key_enc_opts.erspan.index = index;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_erspan_dir(struct tc_newqdisc_req *req,
							   __u8 dir)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.dir = 1;
	req->options.flower.key_enc_opts.erspan.dir = dir;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_erspan_hwid(struct tc_newqdisc_req *req,
							    __u8 hwid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.hwid = 1;
	req->options.flower.key_enc_opts.erspan.hwid = hwid;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_gtp_pdu_type(struct tc_newqdisc_req *req,
							     __u8 pdu_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.gtp = 1;
	req->options.flower.key_enc_opts.gtp._present.pdu_type = 1;
	req->options.flower.key_enc_opts.gtp.pdu_type = pdu_type;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_gtp_qfi(struct tc_newqdisc_req *req,
							__u8 qfi)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.gtp = 1;
	req->options.flower.key_enc_opts.gtp._present.qfi = 1;
	req->options.flower.key_enc_opts.gtp.qfi = qfi;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_geneve_class(struct tc_newqdisc_req *req,
								  __u16 class)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	req->options.flower.key_enc_opts_mask.geneve._present.class = 1;
	req->options.flower.key_enc_opts_mask.geneve.class = class;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_geneve_type(struct tc_newqdisc_req *req,
								 __u8 type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	req->options.flower.key_enc_opts_mask.geneve._present.type = 1;
	req->options.flower.key_enc_opts_mask.geneve.type = type;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_geneve_data(struct tc_newqdisc_req *req,
								 const void *data,
								 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	free(req->options.flower.key_enc_opts_mask.geneve.data);
	req->options.flower.key_enc_opts_mask.geneve._len.data = len;
	req->options.flower.key_enc_opts_mask.geneve.data = malloc(req->options.flower.key_enc_opts_mask.geneve._len.data);
	memcpy(req->options.flower.key_enc_opts_mask.geneve.data, data, req->options.flower.key_enc_opts_mask.geneve._len.data);
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_vxlan_gbp(struct tc_newqdisc_req *req,
							       __u32 gbp)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.vxlan = 1;
	req->options.flower.key_enc_opts_mask.vxlan._present.gbp = 1;
	req->options.flower.key_enc_opts_mask.vxlan.gbp = gbp;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_erspan_ver(struct tc_newqdisc_req *req,
								__u8 ver)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.ver = 1;
	req->options.flower.key_enc_opts_mask.erspan.ver = ver;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_erspan_index(struct tc_newqdisc_req *req,
								  __u32 index)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.index = 1;
	req->options.flower.key_enc_opts_mask.erspan.index = index;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_erspan_dir(struct tc_newqdisc_req *req,
								__u8 dir)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.dir = 1;
	req->options.flower.key_enc_opts_mask.erspan.dir = dir;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_erspan_hwid(struct tc_newqdisc_req *req,
								 __u8 hwid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.hwid = 1;
	req->options.flower.key_enc_opts_mask.erspan.hwid = hwid;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_gtp_pdu_type(struct tc_newqdisc_req *req,
								  __u8 pdu_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.gtp = 1;
	req->options.flower.key_enc_opts_mask.gtp._present.pdu_type = 1;
	req->options.flower.key_enc_opts_mask.gtp.pdu_type = pdu_type;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_opts_mask_gtp_qfi(struct tc_newqdisc_req *req,
							     __u8 qfi)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.gtp = 1;
	req->options.flower.key_enc_opts_mask.gtp._present.qfi = 1;
	req->options.flower.key_enc_opts_mask.gtp.qfi = qfi;
}
static inline void
tc_newqdisc_req_set_options_flower_in_hw_count(struct tc_newqdisc_req *req,
					       __u32 in_hw_count)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.in_hw_count = 1;
	req->options.flower.in_hw_count = in_hw_count;
}
static inline void
tc_newqdisc_req_set_options_flower_key_port_src_min(struct tc_newqdisc_req *req,
						    __u16 key_port_src_min /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_src_min = 1;
	req->options.flower.key_port_src_min = key_port_src_min;
}
static inline void
tc_newqdisc_req_set_options_flower_key_port_src_max(struct tc_newqdisc_req *req,
						    __u16 key_port_src_max /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_src_max = 1;
	req->options.flower.key_port_src_max = key_port_src_max;
}
static inline void
tc_newqdisc_req_set_options_flower_key_port_dst_min(struct tc_newqdisc_req *req,
						    __u16 key_port_dst_min /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_dst_min = 1;
	req->options.flower.key_port_dst_min = key_port_dst_min;
}
static inline void
tc_newqdisc_req_set_options_flower_key_port_dst_max(struct tc_newqdisc_req *req,
						    __u16 key_port_dst_max /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_dst_max = 1;
	req->options.flower.key_port_dst_max = key_port_dst_max;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ct_state(struct tc_newqdisc_req *req,
						__u16 key_ct_state)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_state = 1;
	req->options.flower.key_ct_state = key_ct_state;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ct_state_mask(struct tc_newqdisc_req *req,
						     __u16 key_ct_state_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_state_mask = 1;
	req->options.flower.key_ct_state_mask = key_ct_state_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ct_zone(struct tc_newqdisc_req *req,
					       __u16 key_ct_zone)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_zone = 1;
	req->options.flower.key_ct_zone = key_ct_zone;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ct_zone_mask(struct tc_newqdisc_req *req,
						    __u16 key_ct_zone_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_zone_mask = 1;
	req->options.flower.key_ct_zone_mask = key_ct_zone_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ct_mark(struct tc_newqdisc_req *req,
					       __u32 key_ct_mark)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_mark = 1;
	req->options.flower.key_ct_mark = key_ct_mark;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ct_mark_mask(struct tc_newqdisc_req *req,
						    __u32 key_ct_mark_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_mark_mask = 1;
	req->options.flower.key_ct_mark_mask = key_ct_mark_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ct_labels(struct tc_newqdisc_req *req,
						 const void *key_ct_labels,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ct_labels);
	req->options.flower._len.key_ct_labels = len;
	req->options.flower.key_ct_labels = malloc(req->options.flower._len.key_ct_labels);
	memcpy(req->options.flower.key_ct_labels, key_ct_labels, req->options.flower._len.key_ct_labels);
}
static inline void
tc_newqdisc_req_set_options_flower_key_ct_labels_mask(struct tc_newqdisc_req *req,
						      const void *key_ct_labels_mask,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ct_labels_mask);
	req->options.flower._len.key_ct_labels_mask = len;
	req->options.flower.key_ct_labels_mask = malloc(req->options.flower._len.key_ct_labels_mask);
	memcpy(req->options.flower.key_ct_labels_mask, key_ct_labels_mask, req->options.flower._len.key_ct_labels_mask);
}
static inline void
tc_newqdisc_req_set_options_flower_key_mpls_opts_lse_depth(struct tc_newqdisc_req *req,
							   __u8 lse_depth)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_depth = 1;
	req->options.flower.key_mpls_opts.lse_depth = lse_depth;
}
static inline void
tc_newqdisc_req_set_options_flower_key_mpls_opts_lse_ttl(struct tc_newqdisc_req *req,
							 __u8 lse_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_ttl = 1;
	req->options.flower.key_mpls_opts.lse_ttl = lse_ttl;
}
static inline void
tc_newqdisc_req_set_options_flower_key_mpls_opts_lse_bos(struct tc_newqdisc_req *req,
							 __u8 lse_bos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_bos = 1;
	req->options.flower.key_mpls_opts.lse_bos = lse_bos;
}
static inline void
tc_newqdisc_req_set_options_flower_key_mpls_opts_lse_tc(struct tc_newqdisc_req *req,
							__u8 lse_tc)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_tc = 1;
	req->options.flower.key_mpls_opts.lse_tc = lse_tc;
}
static inline void
tc_newqdisc_req_set_options_flower_key_mpls_opts_lse_label(struct tc_newqdisc_req *req,
							   __u32 lse_label)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_label = 1;
	req->options.flower.key_mpls_opts.lse_label = lse_label;
}
static inline void
tc_newqdisc_req_set_options_flower_key_hash(struct tc_newqdisc_req *req,
					    __u32 key_hash)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_hash = 1;
	req->options.flower.key_hash = key_hash;
}
static inline void
tc_newqdisc_req_set_options_flower_key_hash_mask(struct tc_newqdisc_req *req,
						 __u32 key_hash_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_hash_mask = 1;
	req->options.flower.key_hash_mask = key_hash_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_num_of_vlans(struct tc_newqdisc_req *req,
						    __u8 key_num_of_vlans)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_num_of_vlans = 1;
	req->options.flower.key_num_of_vlans = key_num_of_vlans;
}
static inline void
tc_newqdisc_req_set_options_flower_key_pppoe_sid(struct tc_newqdisc_req *req,
						 __u16 key_pppoe_sid /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_pppoe_sid = 1;
	req->options.flower.key_pppoe_sid = key_pppoe_sid;
}
static inline void
tc_newqdisc_req_set_options_flower_key_ppp_proto(struct tc_newqdisc_req *req,
						 __u16 key_ppp_proto /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ppp_proto = 1;
	req->options.flower.key_ppp_proto = key_ppp_proto;
}
static inline void
tc_newqdisc_req_set_options_flower_key_l2tpv3_sid(struct tc_newqdisc_req *req,
						  __u32 key_l2tpv3_sid /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_l2tpv3_sid = 1;
	req->options.flower.key_l2tpv3_sid = key_l2tpv3_sid;
}
static inline void
tc_newqdisc_req_set_options_flower_l2_miss(struct tc_newqdisc_req *req,
					   __u8 l2_miss)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.l2_miss = 1;
	req->options.flower.l2_miss = l2_miss;
}
static inline void
tc_newqdisc_req_set_options_flower_key_cfm_md_level(struct tc_newqdisc_req *req,
						    __u8 md_level)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cfm = 1;
	req->options.flower.key_cfm._present.md_level = 1;
	req->options.flower.key_cfm.md_level = md_level;
}
static inline void
tc_newqdisc_req_set_options_flower_key_cfm_opcode(struct tc_newqdisc_req *req,
						  __u8 opcode)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cfm = 1;
	req->options.flower.key_cfm._present.opcode = 1;
	req->options.flower.key_cfm.opcode = opcode;
}
static inline void
tc_newqdisc_req_set_options_flower_key_spi(struct tc_newqdisc_req *req,
					   __u32 key_spi /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_spi = 1;
	req->options.flower.key_spi = key_spi;
}
static inline void
tc_newqdisc_req_set_options_flower_key_spi_mask(struct tc_newqdisc_req *req,
						__u32 key_spi_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_spi_mask = 1;
	req->options.flower.key_spi_mask = key_spi_mask;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_flags(struct tc_newqdisc_req *req,
						 __u32 key_enc_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_flags = 1;
	req->options.flower.key_enc_flags = key_enc_flags;
}
static inline void
tc_newqdisc_req_set_options_flower_key_enc_flags_mask(struct tc_newqdisc_req *req,
						      __u32 key_enc_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_flags_mask = 1;
	req->options.flower.key_enc_flags_mask = key_enc_flags_mask;
}
static inline void
tc_newqdisc_req_set_options_fq_plimit(struct tc_newqdisc_req *req,
				      __u32 plimit)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.plimit = 1;
	req->options.fq.plimit = plimit;
}
static inline void
tc_newqdisc_req_set_options_fq_flow_plimit(struct tc_newqdisc_req *req,
					   __u32 flow_plimit)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_plimit = 1;
	req->options.fq.flow_plimit = flow_plimit;
}
static inline void
tc_newqdisc_req_set_options_fq_quantum(struct tc_newqdisc_req *req,
				       __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.quantum = 1;
	req->options.fq.quantum = quantum;
}
static inline void
tc_newqdisc_req_set_options_fq_initial_quantum(struct tc_newqdisc_req *req,
					       __u32 initial_quantum)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.initial_quantum = 1;
	req->options.fq.initial_quantum = initial_quantum;
}
static inline void
tc_newqdisc_req_set_options_fq_rate_enable(struct tc_newqdisc_req *req,
					   __u32 rate_enable)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.rate_enable = 1;
	req->options.fq.rate_enable = rate_enable;
}
static inline void
tc_newqdisc_req_set_options_fq_flow_default_rate(struct tc_newqdisc_req *req,
						 __u32 flow_default_rate)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_default_rate = 1;
	req->options.fq.flow_default_rate = flow_default_rate;
}
static inline void
tc_newqdisc_req_set_options_fq_flow_max_rate(struct tc_newqdisc_req *req,
					     __u32 flow_max_rate)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_max_rate = 1;
	req->options.fq.flow_max_rate = flow_max_rate;
}
static inline void
tc_newqdisc_req_set_options_fq_buckets_log(struct tc_newqdisc_req *req,
					   __u32 buckets_log)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.buckets_log = 1;
	req->options.fq.buckets_log = buckets_log;
}
static inline void
tc_newqdisc_req_set_options_fq_flow_refill_delay(struct tc_newqdisc_req *req,
						 __u32 flow_refill_delay)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_refill_delay = 1;
	req->options.fq.flow_refill_delay = flow_refill_delay;
}
static inline void
tc_newqdisc_req_set_options_fq_orphan_mask(struct tc_newqdisc_req *req,
					   __u32 orphan_mask)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.orphan_mask = 1;
	req->options.fq.orphan_mask = orphan_mask;
}
static inline void
tc_newqdisc_req_set_options_fq_low_rate_threshold(struct tc_newqdisc_req *req,
						  __u32 low_rate_threshold)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.low_rate_threshold = 1;
	req->options.fq.low_rate_threshold = low_rate_threshold;
}
static inline void
tc_newqdisc_req_set_options_fq_ce_threshold(struct tc_newqdisc_req *req,
					    __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.ce_threshold = 1;
	req->options.fq.ce_threshold = ce_threshold;
}
static inline void
tc_newqdisc_req_set_options_fq_timer_slack(struct tc_newqdisc_req *req,
					   __u32 timer_slack)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.timer_slack = 1;
	req->options.fq.timer_slack = timer_slack;
}
static inline void
tc_newqdisc_req_set_options_fq_horizon(struct tc_newqdisc_req *req,
				       __u32 horizon)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.horizon = 1;
	req->options.fq.horizon = horizon;
}
static inline void
tc_newqdisc_req_set_options_fq_horizon_drop(struct tc_newqdisc_req *req,
					    __u8 horizon_drop)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.horizon_drop = 1;
	req->options.fq.horizon_drop = horizon_drop;
}
static inline void
tc_newqdisc_req_set_options_fq_priomap(struct tc_newqdisc_req *req,
				       const void *priomap, size_t len)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	free(req->options.fq.priomap);
	req->options.fq._len.priomap = len;
	req->options.fq.priomap = malloc(req->options.fq._len.priomap);
	memcpy(req->options.fq.priomap, priomap, req->options.fq._len.priomap);
}
static inline void
tc_newqdisc_req_set_options_fq_weights(struct tc_newqdisc_req *req,
				       __s32 *weights, size_t count)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	free(req->options.fq.weights);
	req->options.fq._count.weights = count;
	count *= sizeof(__s32);
	req->options.fq.weights = malloc(count);
	memcpy(req->options.fq.weights, weights, count);
}
static inline void
tc_newqdisc_req_set_options_fq_codel_target(struct tc_newqdisc_req *req,
					    __u32 target)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.target = 1;
	req->options.fq_codel.target = target;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_limit(struct tc_newqdisc_req *req,
					   __u32 limit)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.limit = 1;
	req->options.fq_codel.limit = limit;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_interval(struct tc_newqdisc_req *req,
					      __u32 interval)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.interval = 1;
	req->options.fq_codel.interval = interval;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_ecn(struct tc_newqdisc_req *req,
					 __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ecn = 1;
	req->options.fq_codel.ecn = ecn;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_flows(struct tc_newqdisc_req *req,
					   __u32 flows)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.flows = 1;
	req->options.fq_codel.flows = flows;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_quantum(struct tc_newqdisc_req *req,
					     __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.quantum = 1;
	req->options.fq_codel.quantum = quantum;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_ce_threshold(struct tc_newqdisc_req *req,
						  __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold = 1;
	req->options.fq_codel.ce_threshold = ce_threshold;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_drop_batch_size(struct tc_newqdisc_req *req,
						     __u32 drop_batch_size)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.drop_batch_size = 1;
	req->options.fq_codel.drop_batch_size = drop_batch_size;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_memory_limit(struct tc_newqdisc_req *req,
						  __u32 memory_limit)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.memory_limit = 1;
	req->options.fq_codel.memory_limit = memory_limit;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_ce_threshold_selector(struct tc_newqdisc_req *req,
							   __u8 ce_threshold_selector)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold_selector = 1;
	req->options.fq_codel.ce_threshold_selector = ce_threshold_selector;
}
static inline void
tc_newqdisc_req_set_options_fq_codel_ce_threshold_mask(struct tc_newqdisc_req *req,
						       __u8 ce_threshold_mask)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold_mask = 1;
	req->options.fq_codel.ce_threshold_mask = ce_threshold_mask;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_limit(struct tc_newqdisc_req *req,
					 __u32 limit)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.limit = 1;
	req->options.fq_pie.limit = limit;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_flows(struct tc_newqdisc_req *req,
					 __u32 flows)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.flows = 1;
	req->options.fq_pie.flows = flows;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_target(struct tc_newqdisc_req *req,
					  __u32 target)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.target = 1;
	req->options.fq_pie.target = target;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_tupdate(struct tc_newqdisc_req *req,
					   __u32 tupdate)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.tupdate = 1;
	req->options.fq_pie.tupdate = tupdate;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_alpha(struct tc_newqdisc_req *req,
					 __u32 alpha)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.alpha = 1;
	req->options.fq_pie.alpha = alpha;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_beta(struct tc_newqdisc_req *req,
					__u32 beta)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.beta = 1;
	req->options.fq_pie.beta = beta;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_quantum(struct tc_newqdisc_req *req,
					   __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.quantum = 1;
	req->options.fq_pie.quantum = quantum;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_memory_limit(struct tc_newqdisc_req *req,
						__u32 memory_limit)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.memory_limit = 1;
	req->options.fq_pie.memory_limit = memory_limit;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_ecn_prob(struct tc_newqdisc_req *req,
					    __u32 ecn_prob)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.ecn_prob = 1;
	req->options.fq_pie.ecn_prob = ecn_prob;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_ecn(struct tc_newqdisc_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.ecn = 1;
	req->options.fq_pie.ecn = ecn;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_bytemode(struct tc_newqdisc_req *req,
					    __u32 bytemode)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.bytemode = 1;
	req->options.fq_pie.bytemode = bytemode;
}
static inline void
tc_newqdisc_req_set_options_fq_pie_dq_rate_estimator(struct tc_newqdisc_req *req,
						     __u32 dq_rate_estimator)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.dq_rate_estimator = 1;
	req->options.fq_pie.dq_rate_estimator = dq_rate_estimator;
}
static inline void
tc_newqdisc_req_set_options_fw_classid(struct tc_newqdisc_req *req,
				       __u32 classid)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.classid = 1;
	req->options.fw.classid = classid;
}
static inline void
tc_newqdisc_req_set_options_fw_police_tbf(struct tc_newqdisc_req *req,
					  const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.tbf);
	req->options.fw.police._len.tbf = len;
	req->options.fw.police.tbf = malloc(req->options.fw.police._len.tbf);
	memcpy(req->options.fw.police.tbf, tbf, req->options.fw.police._len.tbf);
}
static inline void
tc_newqdisc_req_set_options_fw_police_rate(struct tc_newqdisc_req *req,
					   const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.rate);
	req->options.fw.police._len.rate = len;
	req->options.fw.police.rate = malloc(req->options.fw.police._len.rate);
	memcpy(req->options.fw.police.rate, rate, req->options.fw.police._len.rate);
}
static inline void
tc_newqdisc_req_set_options_fw_police_peakrate(struct tc_newqdisc_req *req,
					       const void *peakrate,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.peakrate);
	req->options.fw.police._len.peakrate = len;
	req->options.fw.police.peakrate = malloc(req->options.fw.police._len.peakrate);
	memcpy(req->options.fw.police.peakrate, peakrate, req->options.fw.police._len.peakrate);
}
static inline void
tc_newqdisc_req_set_options_fw_police_avrate(struct tc_newqdisc_req *req,
					     __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.avrate = 1;
	req->options.fw.police.avrate = avrate;
}
static inline void
tc_newqdisc_req_set_options_fw_police_result(struct tc_newqdisc_req *req,
					     __u32 result)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.result = 1;
	req->options.fw.police.result = result;
}
static inline void
tc_newqdisc_req_set_options_fw_police_tm(struct tc_newqdisc_req *req,
					 const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.tm);
	req->options.fw.police._len.tm = len;
	req->options.fw.police.tm = malloc(req->options.fw.police._len.tm);
	memcpy(req->options.fw.police.tm, tm, req->options.fw.police._len.tm);
}
static inline void
tc_newqdisc_req_set_options_fw_police_rate64(struct tc_newqdisc_req *req,
					     __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.rate64 = 1;
	req->options.fw.police.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_fw_police_peakrate64(struct tc_newqdisc_req *req,
						 __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.peakrate64 = 1;
	req->options.fw.police.peakrate64 = peakrate64;
}
static inline void
tc_newqdisc_req_set_options_fw_police_pktrate64(struct tc_newqdisc_req *req,
						__u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.pktrate64 = 1;
	req->options.fw.police.pktrate64 = pktrate64;
}
static inline void
tc_newqdisc_req_set_options_fw_police_pktburst64(struct tc_newqdisc_req *req,
						 __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.pktburst64 = 1;
	req->options.fw.police.pktburst64 = pktburst64;
}
static inline void
tc_newqdisc_req_set_options_fw_indev(struct tc_newqdisc_req *req,
				     const char *indev)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	free(req->options.fw.indev);
	req->options.fw._len.indev = strlen(indev);
	req->options.fw.indev = malloc(req->options.fw._len.indev + 1);
	memcpy(req->options.fw.indev, indev, req->options.fw._len.indev);
	req->options.fw.indev[req->options.fw._len.indev] = 0;
}
static inline void
__tc_newqdisc_req_set_options_fw_act(struct tc_newqdisc_req *req,
				     struct tc_act_attrs *act,
				     unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	free(req->options.fw.act);
	req->options.fw.act = act;
	req->options.fw._count.act = n_act;
}
static inline void
tc_newqdisc_req_set_options_fw_mask(struct tc_newqdisc_req *req, __u32 mask)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.mask = 1;
	req->options.fw.mask = mask;
}
static inline void
tc_newqdisc_req_set_options_gred_parms(struct tc_newqdisc_req *req,
				       const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.parms);
	req->options.gred._len.parms = len;
	req->options.gred.parms = malloc(req->options.gred._len.parms);
	memcpy(req->options.gred.parms, parms, req->options.gred._len.parms);
}
static inline void
tc_newqdisc_req_set_options_gred_stab(struct tc_newqdisc_req *req, __u8 *stab,
				      size_t count)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.stab);
	req->options.gred._count.stab = count;
	count *= sizeof(__u8);
	req->options.gred.stab = malloc(count);
	memcpy(req->options.gred.stab, stab, count);
}
static inline void
tc_newqdisc_req_set_options_gred_dps(struct tc_newqdisc_req *req,
				     const void *dps, size_t len)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.dps);
	req->options.gred._len.dps = len;
	req->options.gred.dps = malloc(req->options.gred._len.dps);
	memcpy(req->options.gred.dps, dps, req->options.gred._len.dps);
}
static inline void
tc_newqdisc_req_set_options_gred_max_p(struct tc_newqdisc_req *req,
				       __u32 *max_p, size_t count)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.max_p);
	req->options.gred._count.max_p = count;
	count *= sizeof(__u32);
	req->options.gred.max_p = malloc(count);
	memcpy(req->options.gred.max_p, max_p, count);
}
static inline void
tc_newqdisc_req_set_options_gred_limit(struct tc_newqdisc_req *req,
				       __u32 limit)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	req->options.gred._present.limit = 1;
	req->options.gred.limit = limit;
}
static inline void
__tc_newqdisc_req_set_options_gred_vq_list_entry(struct tc_newqdisc_req *req,
						 struct tc_tca_gred_vq_entry_attrs *entry,
						 unsigned int n_entry)
{
	unsigned int i;

	req->_present.options = 1;
	req->options._present.gred = 1;
	req->options.gred._present.vq_list = 1;
	for (i = 0; i < req->options.gred.vq_list._count.entry; i++)
		tc_tca_gred_vq_entry_attrs_free(&req->options.gred.vq_list.entry[i]);
	free(req->options.gred.vq_list.entry);
	req->options.gred.vq_list.entry = entry;
	req->options.gred.vq_list._count.entry = n_entry;
}
static inline void
tc_newqdisc_req_set_options_hfsc(struct tc_newqdisc_req *req, const void *hfsc,
				 size_t len)
{
	req->_present.options = 1;
	free(req->options.hfsc);
	req->options._len.hfsc = len;
	req->options.hfsc = malloc(req->options._len.hfsc);
	memcpy(req->options.hfsc, hfsc, req->options._len.hfsc);
}
static inline void
tc_newqdisc_req_set_options_hhf_backlog_limit(struct tc_newqdisc_req *req,
					      __u32 backlog_limit)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.backlog_limit = 1;
	req->options.hhf.backlog_limit = backlog_limit;
}
static inline void
tc_newqdisc_req_set_options_hhf_quantum(struct tc_newqdisc_req *req,
					__u32 quantum)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.quantum = 1;
	req->options.hhf.quantum = quantum;
}
static inline void
tc_newqdisc_req_set_options_hhf_hh_flows_limit(struct tc_newqdisc_req *req,
					       __u32 hh_flows_limit)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.hh_flows_limit = 1;
	req->options.hhf.hh_flows_limit = hh_flows_limit;
}
static inline void
tc_newqdisc_req_set_options_hhf_reset_timeout(struct tc_newqdisc_req *req,
					      __u32 reset_timeout)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.reset_timeout = 1;
	req->options.hhf.reset_timeout = reset_timeout;
}
static inline void
tc_newqdisc_req_set_options_hhf_admit_bytes(struct tc_newqdisc_req *req,
					    __u32 admit_bytes)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.admit_bytes = 1;
	req->options.hhf.admit_bytes = admit_bytes;
}
static inline void
tc_newqdisc_req_set_options_hhf_evict_timeout(struct tc_newqdisc_req *req,
					      __u32 evict_timeout)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.evict_timeout = 1;
	req->options.hhf.evict_timeout = evict_timeout;
}
static inline void
tc_newqdisc_req_set_options_hhf_non_hh_weight(struct tc_newqdisc_req *req,
					      __u32 non_hh_weight)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.non_hh_weight = 1;
	req->options.hhf.non_hh_weight = non_hh_weight;
}
static inline void
tc_newqdisc_req_set_options_htb_parms(struct tc_newqdisc_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.parms);
	req->options.htb._len.parms = len;
	req->options.htb.parms = malloc(req->options.htb._len.parms);
	memcpy(req->options.htb.parms, parms, req->options.htb._len.parms);
}
static inline void
tc_newqdisc_req_set_options_htb_init(struct tc_newqdisc_req *req,
				     const void *init, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.init);
	req->options.htb._len.init = len;
	req->options.htb.init = malloc(req->options.htb._len.init);
	memcpy(req->options.htb.init, init, req->options.htb._len.init);
}
static inline void
tc_newqdisc_req_set_options_htb_ctab(struct tc_newqdisc_req *req,
				     const void *ctab, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.ctab);
	req->options.htb._len.ctab = len;
	req->options.htb.ctab = malloc(req->options.htb._len.ctab);
	memcpy(req->options.htb.ctab, ctab, req->options.htb._len.ctab);
}
static inline void
tc_newqdisc_req_set_options_htb_rtab(struct tc_newqdisc_req *req,
				     const void *rtab, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.rtab);
	req->options.htb._len.rtab = len;
	req->options.htb.rtab = malloc(req->options.htb._len.rtab);
	memcpy(req->options.htb.rtab, rtab, req->options.htb._len.rtab);
}
static inline void
tc_newqdisc_req_set_options_htb_direct_qlen(struct tc_newqdisc_req *req,
					    __u32 direct_qlen)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.direct_qlen = 1;
	req->options.htb.direct_qlen = direct_qlen;
}
static inline void
tc_newqdisc_req_set_options_htb_rate64(struct tc_newqdisc_req *req,
				       __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.rate64 = 1;
	req->options.htb.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_htb_ceil64(struct tc_newqdisc_req *req,
				       __u64 ceil64)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.ceil64 = 1;
	req->options.htb.ceil64 = ceil64;
}
static inline void
tc_newqdisc_req_set_options_htb_offload(struct tc_newqdisc_req *req)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.offload = 1;
}
static inline void
tc_newqdisc_req_set_options_ingress(struct tc_newqdisc_req *req)
{
	req->_present.options = 1;
	req->options._present.ingress = 1;
}
static inline void
tc_newqdisc_req_set_options_matchall_classid(struct tc_newqdisc_req *req,
					     __u32 classid)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	req->options.matchall._present.classid = 1;
	req->options.matchall.classid = classid;
}
static inline void
__tc_newqdisc_req_set_options_matchall_act(struct tc_newqdisc_req *req,
					   struct tc_act_attrs *act,
					   unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	free(req->options.matchall.act);
	req->options.matchall.act = act;
	req->options.matchall._count.act = n_act;
}
static inline void
tc_newqdisc_req_set_options_matchall_flags(struct tc_newqdisc_req *req,
					   __u32 flags)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	req->options.matchall._present.flags = 1;
	req->options.matchall.flags = flags;
}
static inline void
tc_newqdisc_req_set_options_matchall_pcnt(struct tc_newqdisc_req *req,
					  const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	free(req->options.matchall.pcnt);
	req->options.matchall._len.pcnt = len;
	req->options.matchall.pcnt = malloc(req->options.matchall._len.pcnt);
	memcpy(req->options.matchall.pcnt, pcnt, req->options.matchall._len.pcnt);
}
static inline void tc_newqdisc_req_set_options_mq(struct tc_newqdisc_req *req)
{
	req->_present.options = 1;
	req->options._present.mq = 1;
}
static inline void
tc_newqdisc_req_set_options_mqprio(struct tc_newqdisc_req *req,
				   const void *mqprio, size_t len)
{
	req->_present.options = 1;
	free(req->options.mqprio);
	req->options._len.mqprio = len;
	req->options.mqprio = malloc(req->options._len.mqprio);
	memcpy(req->options.mqprio, mqprio, req->options._len.mqprio);
}
static inline void
tc_newqdisc_req_set_options_multiq(struct tc_newqdisc_req *req,
				   const void *multiq, size_t len)
{
	req->_present.options = 1;
	free(req->options.multiq);
	req->options._len.multiq = len;
	req->options.multiq = malloc(req->options._len.multiq);
	memcpy(req->options.multiq, multiq, req->options._len.multiq);
}
static inline void
tc_newqdisc_req_set_options_netem_corr(struct tc_newqdisc_req *req,
				       const void *corr, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.corr);
	req->options.netem._len.corr = len;
	req->options.netem.corr = malloc(req->options.netem._len.corr);
	memcpy(req->options.netem.corr, corr, req->options.netem._len.corr);
}
static inline void
tc_newqdisc_req_set_options_netem_delay_dist(struct tc_newqdisc_req *req,
					     __s16 *delay_dist, size_t count)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.delay_dist);
	req->options.netem._count.delay_dist = count;
	count *= sizeof(__s16);
	req->options.netem.delay_dist = malloc(count);
	memcpy(req->options.netem.delay_dist, delay_dist, count);
}
static inline void
tc_newqdisc_req_set_options_netem_reorder(struct tc_newqdisc_req *req,
					  const void *reorder, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.reorder);
	req->options.netem._len.reorder = len;
	req->options.netem.reorder = malloc(req->options.netem._len.reorder);
	memcpy(req->options.netem.reorder, reorder, req->options.netem._len.reorder);
}
static inline void
tc_newqdisc_req_set_options_netem_corrupt(struct tc_newqdisc_req *req,
					  const void *corrupt, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.corrupt);
	req->options.netem._len.corrupt = len;
	req->options.netem.corrupt = malloc(req->options.netem._len.corrupt);
	memcpy(req->options.netem.corrupt, corrupt, req->options.netem._len.corrupt);
}
static inline void
tc_newqdisc_req_set_options_netem_loss_gi(struct tc_newqdisc_req *req,
					  const void *gi, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.loss = 1;
	free(req->options.netem.loss.gi);
	req->options.netem.loss._len.gi = len;
	req->options.netem.loss.gi = malloc(req->options.netem.loss._len.gi);
	memcpy(req->options.netem.loss.gi, gi, req->options.netem.loss._len.gi);
}
static inline void
tc_newqdisc_req_set_options_netem_loss_ge(struct tc_newqdisc_req *req,
					  const void *ge, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.loss = 1;
	free(req->options.netem.loss.ge);
	req->options.netem.loss._len.ge = len;
	req->options.netem.loss.ge = malloc(req->options.netem.loss._len.ge);
	memcpy(req->options.netem.loss.ge, ge, req->options.netem.loss._len.ge);
}
static inline void
tc_newqdisc_req_set_options_netem_rate(struct tc_newqdisc_req *req,
				       const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.rate);
	req->options.netem._len.rate = len;
	req->options.netem.rate = malloc(req->options.netem._len.rate);
	memcpy(req->options.netem.rate, rate, req->options.netem._len.rate);
}
static inline void
tc_newqdisc_req_set_options_netem_ecn(struct tc_newqdisc_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.ecn = 1;
	req->options.netem.ecn = ecn;
}
static inline void
tc_newqdisc_req_set_options_netem_rate64(struct tc_newqdisc_req *req,
					 __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.rate64 = 1;
	req->options.netem.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_netem_pad(struct tc_newqdisc_req *req, __u32 pad)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.pad = 1;
	req->options.netem.pad = pad;
}
static inline void
tc_newqdisc_req_set_options_netem_latency64(struct tc_newqdisc_req *req,
					    __s64 latency64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.latency64 = 1;
	req->options.netem.latency64 = latency64;
}
static inline void
tc_newqdisc_req_set_options_netem_jitter64(struct tc_newqdisc_req *req,
					   __s64 jitter64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.jitter64 = 1;
	req->options.netem.jitter64 = jitter64;
}
static inline void
tc_newqdisc_req_set_options_netem_slot(struct tc_newqdisc_req *req,
				       const void *slot, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.slot);
	req->options.netem._len.slot = len;
	req->options.netem.slot = malloc(req->options.netem._len.slot);
	memcpy(req->options.netem.slot, slot, req->options.netem._len.slot);
}
static inline void
tc_newqdisc_req_set_options_netem_slot_dist(struct tc_newqdisc_req *req,
					    __s16 *slot_dist, size_t count)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.slot_dist);
	req->options.netem._count.slot_dist = count;
	count *= sizeof(__s16);
	req->options.netem.slot_dist = malloc(count);
	memcpy(req->options.netem.slot_dist, slot_dist, count);
}
static inline void
tc_newqdisc_req_set_options_netem_prng_seed(struct tc_newqdisc_req *req,
					    __u64 prng_seed)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.prng_seed = 1;
	req->options.netem.prng_seed = prng_seed;
}
static inline void
tc_newqdisc_req_set_options_pfifo(struct tc_newqdisc_req *req,
				  const void *pfifo, size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo);
	req->options._len.pfifo = len;
	req->options.pfifo = malloc(req->options._len.pfifo);
	memcpy(req->options.pfifo, pfifo, req->options._len.pfifo);
}
static inline void
tc_newqdisc_req_set_options_pfifo_fast(struct tc_newqdisc_req *req,
				       const void *pfifo_fast, size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo_fast);
	req->options._len.pfifo_fast = len;
	req->options.pfifo_fast = malloc(req->options._len.pfifo_fast);
	memcpy(req->options.pfifo_fast, pfifo_fast, req->options._len.pfifo_fast);
}
static inline void
tc_newqdisc_req_set_options_pfifo_head_drop(struct tc_newqdisc_req *req,
					    const void *pfifo_head_drop,
					    size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo_head_drop);
	req->options._len.pfifo_head_drop = len;
	req->options.pfifo_head_drop = malloc(req->options._len.pfifo_head_drop);
	memcpy(req->options.pfifo_head_drop, pfifo_head_drop, req->options._len.pfifo_head_drop);
}
static inline void
tc_newqdisc_req_set_options_pie_target(struct tc_newqdisc_req *req,
				       __u32 target)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.target = 1;
	req->options.pie.target = target;
}
static inline void
tc_newqdisc_req_set_options_pie_limit(struct tc_newqdisc_req *req, __u32 limit)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.limit = 1;
	req->options.pie.limit = limit;
}
static inline void
tc_newqdisc_req_set_options_pie_tupdate(struct tc_newqdisc_req *req,
					__u32 tupdate)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.tupdate = 1;
	req->options.pie.tupdate = tupdate;
}
static inline void
tc_newqdisc_req_set_options_pie_alpha(struct tc_newqdisc_req *req, __u32 alpha)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.alpha = 1;
	req->options.pie.alpha = alpha;
}
static inline void
tc_newqdisc_req_set_options_pie_beta(struct tc_newqdisc_req *req, __u32 beta)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.beta = 1;
	req->options.pie.beta = beta;
}
static inline void
tc_newqdisc_req_set_options_pie_ecn(struct tc_newqdisc_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.ecn = 1;
	req->options.pie.ecn = ecn;
}
static inline void
tc_newqdisc_req_set_options_pie_bytemode(struct tc_newqdisc_req *req,
					 __u32 bytemode)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.bytemode = 1;
	req->options.pie.bytemode = bytemode;
}
static inline void
tc_newqdisc_req_set_options_pie_dq_rate_estimator(struct tc_newqdisc_req *req,
						  __u32 dq_rate_estimator)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.dq_rate_estimator = 1;
	req->options.pie.dq_rate_estimator = dq_rate_estimator;
}
static inline void
tc_newqdisc_req_set_options_plug(struct tc_newqdisc_req *req, const void *plug,
				 size_t len)
{
	req->_present.options = 1;
	free(req->options.plug);
	req->options._len.plug = len;
	req->options.plug = malloc(req->options._len.plug);
	memcpy(req->options.plug, plug, req->options._len.plug);
}
static inline void
tc_newqdisc_req_set_options_prio(struct tc_newqdisc_req *req, const void *prio,
				 size_t len)
{
	req->_present.options = 1;
	free(req->options.prio);
	req->options._len.prio = len;
	req->options.prio = malloc(req->options._len.prio);
	memcpy(req->options.prio, prio, req->options._len.prio);
}
static inline void
tc_newqdisc_req_set_options_qfq_weight(struct tc_newqdisc_req *req,
				       __u32 weight)
{
	req->_present.options = 1;
	req->options._present.qfq = 1;
	req->options.qfq._present.weight = 1;
	req->options.qfq.weight = weight;
}
static inline void
tc_newqdisc_req_set_options_qfq_lmax(struct tc_newqdisc_req *req, __u32 lmax)
{
	req->_present.options = 1;
	req->options._present.qfq = 1;
	req->options.qfq._present.lmax = 1;
	req->options.qfq.lmax = lmax;
}
static inline void
tc_newqdisc_req_set_options_red_parms(struct tc_newqdisc_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	free(req->options.red.parms);
	req->options.red._len.parms = len;
	req->options.red.parms = malloc(req->options.red._len.parms);
	memcpy(req->options.red.parms, parms, req->options.red._len.parms);
}
static inline void
tc_newqdisc_req_set_options_red_stab(struct tc_newqdisc_req *req,
				     const void *stab, size_t len)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	free(req->options.red.stab);
	req->options.red._len.stab = len;
	req->options.red.stab = malloc(req->options.red._len.stab);
	memcpy(req->options.red.stab, stab, req->options.red._len.stab);
}
static inline void
tc_newqdisc_req_set_options_red_max_p(struct tc_newqdisc_req *req, __u32 max_p)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.max_p = 1;
	req->options.red.max_p = max_p;
}
static inline void
tc_newqdisc_req_set_options_red_flags(struct tc_newqdisc_req *req,
				      struct nla_bitfield32 *flags)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.flags = 1;
	memcpy(&req->options.red.flags, flags, sizeof(struct nla_bitfield32));
}
static inline void
tc_newqdisc_req_set_options_red_early_drop_block(struct tc_newqdisc_req *req,
						 __u32 early_drop_block)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.early_drop_block = 1;
	req->options.red.early_drop_block = early_drop_block;
}
static inline void
tc_newqdisc_req_set_options_red_mark_block(struct tc_newqdisc_req *req,
					   __u32 mark_block)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.mark_block = 1;
	req->options.red.mark_block = mark_block;
}
static inline void
tc_newqdisc_req_set_options_route_classid(struct tc_newqdisc_req *req,
					  __u32 classid)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.classid = 1;
	req->options.route.classid = classid;
}
static inline void
tc_newqdisc_req_set_options_route_to(struct tc_newqdisc_req *req, __u32 to)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.to = 1;
	req->options.route.to = to;
}
static inline void
tc_newqdisc_req_set_options_route_from(struct tc_newqdisc_req *req, __u32 from)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.from = 1;
	req->options.route.from = from;
}
static inline void
tc_newqdisc_req_set_options_route_iif(struct tc_newqdisc_req *req, __u32 iif)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.iif = 1;
	req->options.route.iif = iif;
}
static inline void
tc_newqdisc_req_set_options_route_police_tbf(struct tc_newqdisc_req *req,
					     const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.tbf);
	req->options.route.police._len.tbf = len;
	req->options.route.police.tbf = malloc(req->options.route.police._len.tbf);
	memcpy(req->options.route.police.tbf, tbf, req->options.route.police._len.tbf);
}
static inline void
tc_newqdisc_req_set_options_route_police_rate(struct tc_newqdisc_req *req,
					      const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.rate);
	req->options.route.police._len.rate = len;
	req->options.route.police.rate = malloc(req->options.route.police._len.rate);
	memcpy(req->options.route.police.rate, rate, req->options.route.police._len.rate);
}
static inline void
tc_newqdisc_req_set_options_route_police_peakrate(struct tc_newqdisc_req *req,
						  const void *peakrate,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.peakrate);
	req->options.route.police._len.peakrate = len;
	req->options.route.police.peakrate = malloc(req->options.route.police._len.peakrate);
	memcpy(req->options.route.police.peakrate, peakrate, req->options.route.police._len.peakrate);
}
static inline void
tc_newqdisc_req_set_options_route_police_avrate(struct tc_newqdisc_req *req,
						__u32 avrate)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.avrate = 1;
	req->options.route.police.avrate = avrate;
}
static inline void
tc_newqdisc_req_set_options_route_police_result(struct tc_newqdisc_req *req,
						__u32 result)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.result = 1;
	req->options.route.police.result = result;
}
static inline void
tc_newqdisc_req_set_options_route_police_tm(struct tc_newqdisc_req *req,
					    const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.tm);
	req->options.route.police._len.tm = len;
	req->options.route.police.tm = malloc(req->options.route.police._len.tm);
	memcpy(req->options.route.police.tm, tm, req->options.route.police._len.tm);
}
static inline void
tc_newqdisc_req_set_options_route_police_rate64(struct tc_newqdisc_req *req,
						__u64 rate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.rate64 = 1;
	req->options.route.police.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_route_police_peakrate64(struct tc_newqdisc_req *req,
						    __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.peakrate64 = 1;
	req->options.route.police.peakrate64 = peakrate64;
}
static inline void
tc_newqdisc_req_set_options_route_police_pktrate64(struct tc_newqdisc_req *req,
						   __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.pktrate64 = 1;
	req->options.route.police.pktrate64 = pktrate64;
}
static inline void
tc_newqdisc_req_set_options_route_police_pktburst64(struct tc_newqdisc_req *req,
						    __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.pktburst64 = 1;
	req->options.route.police.pktburst64 = pktburst64;
}
static inline void
__tc_newqdisc_req_set_options_route_act(struct tc_newqdisc_req *req,
					struct tc_act_attrs *act,
					unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	free(req->options.route.act);
	req->options.route.act = act;
	req->options.route._count.act = n_act;
}
static inline void
tc_newqdisc_req_set_options_sfb(struct tc_newqdisc_req *req, const void *sfb,
				size_t len)
{
	req->_present.options = 1;
	free(req->options.sfb);
	req->options._len.sfb = len;
	req->options.sfb = malloc(req->options._len.sfb);
	memcpy(req->options.sfb, sfb, req->options._len.sfb);
}
static inline void
tc_newqdisc_req_set_options_sfq(struct tc_newqdisc_req *req, const void *sfq,
				size_t len)
{
	req->_present.options = 1;
	free(req->options.sfq);
	req->options._len.sfq = len;
	req->options.sfq = malloc(req->options._len.sfq);
	memcpy(req->options.sfq, sfq, req->options._len.sfq);
}
static inline void
tc_newqdisc_req_set_options_taprio_priomap(struct tc_newqdisc_req *req,
					   const void *priomap, size_t len)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	free(req->options.taprio.priomap);
	req->options.taprio._len.priomap = len;
	req->options.taprio.priomap = malloc(req->options.taprio._len.priomap);
	memcpy(req->options.taprio.priomap, priomap, req->options.taprio._len.priomap);
}
static inline void
__tc_newqdisc_req_set_options_taprio_sched_entry_list_entry(struct tc_newqdisc_req *req,
							    struct tc_taprio_sched_entry *entry,
							    unsigned int n_entry)
{
	unsigned int i;

	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_entry_list = 1;
	for (i = 0; i < req->options.taprio.sched_entry_list._count.entry; i++)
		tc_taprio_sched_entry_free(&req->options.taprio.sched_entry_list.entry[i]);
	free(req->options.taprio.sched_entry_list.entry);
	req->options.taprio.sched_entry_list.entry = entry;
	req->options.taprio.sched_entry_list._count.entry = n_entry;
}
static inline void
tc_newqdisc_req_set_options_taprio_sched_base_time(struct tc_newqdisc_req *req,
						   __s64 sched_base_time)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_base_time = 1;
	req->options.taprio.sched_base_time = sched_base_time;
}
static inline void
tc_newqdisc_req_set_options_taprio_sched_single_entry_index(struct tc_newqdisc_req *req,
							    __u32 index)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.index = 1;
	req->options.taprio.sched_single_entry.index = index;
}
static inline void
tc_newqdisc_req_set_options_taprio_sched_single_entry_cmd(struct tc_newqdisc_req *req,
							  __u8 cmd)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.cmd = 1;
	req->options.taprio.sched_single_entry.cmd = cmd;
}
static inline void
tc_newqdisc_req_set_options_taprio_sched_single_entry_gate_mask(struct tc_newqdisc_req *req,
								__u32 gate_mask)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.gate_mask = 1;
	req->options.taprio.sched_single_entry.gate_mask = gate_mask;
}
static inline void
tc_newqdisc_req_set_options_taprio_sched_single_entry_interval(struct tc_newqdisc_req *req,
							       __u32 interval)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.interval = 1;
	req->options.taprio.sched_single_entry.interval = interval;
}
static inline void
tc_newqdisc_req_set_options_taprio_sched_clockid(struct tc_newqdisc_req *req,
						 __s32 sched_clockid)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_clockid = 1;
	req->options.taprio.sched_clockid = sched_clockid;
}
static inline void
tc_newqdisc_req_set_options_taprio_admin_sched(struct tc_newqdisc_req *req,
					       const void *admin_sched,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	free(req->options.taprio.admin_sched);
	req->options.taprio._len.admin_sched = len;
	req->options.taprio.admin_sched = malloc(req->options.taprio._len.admin_sched);
	memcpy(req->options.taprio.admin_sched, admin_sched, req->options.taprio._len.admin_sched);
}
static inline void
tc_newqdisc_req_set_options_taprio_sched_cycle_time(struct tc_newqdisc_req *req,
						    __s64 sched_cycle_time)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_cycle_time = 1;
	req->options.taprio.sched_cycle_time = sched_cycle_time;
}
static inline void
tc_newqdisc_req_set_options_taprio_sched_cycle_time_extension(struct tc_newqdisc_req *req,
							      __s64 sched_cycle_time_extension)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_cycle_time_extension = 1;
	req->options.taprio.sched_cycle_time_extension = sched_cycle_time_extension;
}
static inline void
tc_newqdisc_req_set_options_taprio_flags(struct tc_newqdisc_req *req,
					 __u32 flags)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.flags = 1;
	req->options.taprio.flags = flags;
}
static inline void
tc_newqdisc_req_set_options_taprio_txtime_delay(struct tc_newqdisc_req *req,
						__u32 txtime_delay)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.txtime_delay = 1;
	req->options.taprio.txtime_delay = txtime_delay;
}
static inline void
tc_newqdisc_req_set_options_taprio_tc_entry_index(struct tc_newqdisc_req *req,
						  __u32 index)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.index = 1;
	req->options.taprio.tc_entry.index = index;
}
static inline void
tc_newqdisc_req_set_options_taprio_tc_entry_max_sdu(struct tc_newqdisc_req *req,
						    __u32 max_sdu)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.max_sdu = 1;
	req->options.taprio.tc_entry.max_sdu = max_sdu;
}
static inline void
tc_newqdisc_req_set_options_taprio_tc_entry_fp(struct tc_newqdisc_req *req,
					       __u32 fp)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.fp = 1;
	req->options.taprio.tc_entry.fp = fp;
}
static inline void
tc_newqdisc_req_set_options_tbf_parms(struct tc_newqdisc_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.parms);
	req->options.tbf._len.parms = len;
	req->options.tbf.parms = malloc(req->options.tbf._len.parms);
	memcpy(req->options.tbf.parms, parms, req->options.tbf._len.parms);
}
static inline void
tc_newqdisc_req_set_options_tbf_rtab(struct tc_newqdisc_req *req,
				     const void *rtab, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.rtab);
	req->options.tbf._len.rtab = len;
	req->options.tbf.rtab = malloc(req->options.tbf._len.rtab);
	memcpy(req->options.tbf.rtab, rtab, req->options.tbf._len.rtab);
}
static inline void
tc_newqdisc_req_set_options_tbf_ptab(struct tc_newqdisc_req *req,
				     const void *ptab, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.ptab);
	req->options.tbf._len.ptab = len;
	req->options.tbf.ptab = malloc(req->options.tbf._len.ptab);
	memcpy(req->options.tbf.ptab, ptab, req->options.tbf._len.ptab);
}
static inline void
tc_newqdisc_req_set_options_tbf_rate64(struct tc_newqdisc_req *req,
				       __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.rate64 = 1;
	req->options.tbf.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_tbf_prate64(struct tc_newqdisc_req *req,
					__u64 prate64)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.prate64 = 1;
	req->options.tbf.prate64 = prate64;
}
static inline void
tc_newqdisc_req_set_options_tbf_burst(struct tc_newqdisc_req *req, __u32 burst)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.burst = 1;
	req->options.tbf.burst = burst;
}
static inline void
tc_newqdisc_req_set_options_tbf_pburst(struct tc_newqdisc_req *req,
				       __u32 pburst)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.pburst = 1;
	req->options.tbf.pburst = pburst;
}
static inline void
tc_newqdisc_req_set_options_u32_classid(struct tc_newqdisc_req *req,
					__u32 classid)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.classid = 1;
	req->options.u32.classid = classid;
}
static inline void
tc_newqdisc_req_set_options_u32_hash(struct tc_newqdisc_req *req, __u32 hash)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.hash = 1;
	req->options.u32.hash = hash;
}
static inline void
tc_newqdisc_req_set_options_u32_link(struct tc_newqdisc_req *req, __u32 link)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.link = 1;
	req->options.u32.link = link;
}
static inline void
tc_newqdisc_req_set_options_u32_divisor(struct tc_newqdisc_req *req,
					__u32 divisor)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.divisor = 1;
	req->options.u32.divisor = divisor;
}
static inline void
tc_newqdisc_req_set_options_u32_sel(struct tc_newqdisc_req *req,
				    const void *sel, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.sel);
	req->options.u32._len.sel = len;
	req->options.u32.sel = malloc(req->options.u32._len.sel);
	memcpy(req->options.u32.sel, sel, req->options.u32._len.sel);
}
static inline void
tc_newqdisc_req_set_options_u32_police_tbf(struct tc_newqdisc_req *req,
					   const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.tbf);
	req->options.u32.police._len.tbf = len;
	req->options.u32.police.tbf = malloc(req->options.u32.police._len.tbf);
	memcpy(req->options.u32.police.tbf, tbf, req->options.u32.police._len.tbf);
}
static inline void
tc_newqdisc_req_set_options_u32_police_rate(struct tc_newqdisc_req *req,
					    const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.rate);
	req->options.u32.police._len.rate = len;
	req->options.u32.police.rate = malloc(req->options.u32.police._len.rate);
	memcpy(req->options.u32.police.rate, rate, req->options.u32.police._len.rate);
}
static inline void
tc_newqdisc_req_set_options_u32_police_peakrate(struct tc_newqdisc_req *req,
						const void *peakrate,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.peakrate);
	req->options.u32.police._len.peakrate = len;
	req->options.u32.police.peakrate = malloc(req->options.u32.police._len.peakrate);
	memcpy(req->options.u32.police.peakrate, peakrate, req->options.u32.police._len.peakrate);
}
static inline void
tc_newqdisc_req_set_options_u32_police_avrate(struct tc_newqdisc_req *req,
					      __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.avrate = 1;
	req->options.u32.police.avrate = avrate;
}
static inline void
tc_newqdisc_req_set_options_u32_police_result(struct tc_newqdisc_req *req,
					      __u32 result)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.result = 1;
	req->options.u32.police.result = result;
}
static inline void
tc_newqdisc_req_set_options_u32_police_tm(struct tc_newqdisc_req *req,
					  const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.tm);
	req->options.u32.police._len.tm = len;
	req->options.u32.police.tm = malloc(req->options.u32.police._len.tm);
	memcpy(req->options.u32.police.tm, tm, req->options.u32.police._len.tm);
}
static inline void
tc_newqdisc_req_set_options_u32_police_rate64(struct tc_newqdisc_req *req,
					      __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.rate64 = 1;
	req->options.u32.police.rate64 = rate64;
}
static inline void
tc_newqdisc_req_set_options_u32_police_peakrate64(struct tc_newqdisc_req *req,
						  __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.peakrate64 = 1;
	req->options.u32.police.peakrate64 = peakrate64;
}
static inline void
tc_newqdisc_req_set_options_u32_police_pktrate64(struct tc_newqdisc_req *req,
						 __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.pktrate64 = 1;
	req->options.u32.police.pktrate64 = pktrate64;
}
static inline void
tc_newqdisc_req_set_options_u32_police_pktburst64(struct tc_newqdisc_req *req,
						  __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.pktburst64 = 1;
	req->options.u32.police.pktburst64 = pktburst64;
}
static inline void
__tc_newqdisc_req_set_options_u32_act(struct tc_newqdisc_req *req,
				      struct tc_act_attrs *act,
				      unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.act);
	req->options.u32.act = act;
	req->options.u32._count.act = n_act;
}
static inline void
tc_newqdisc_req_set_options_u32_indev(struct tc_newqdisc_req *req,
				      const char *indev)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.indev);
	req->options.u32._len.indev = strlen(indev);
	req->options.u32.indev = malloc(req->options.u32._len.indev + 1);
	memcpy(req->options.u32.indev, indev, req->options.u32._len.indev);
	req->options.u32.indev[req->options.u32._len.indev] = 0;
}
static inline void
tc_newqdisc_req_set_options_u32_pcnt(struct tc_newqdisc_req *req,
				     const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.pcnt);
	req->options.u32._len.pcnt = len;
	req->options.u32.pcnt = malloc(req->options.u32._len.pcnt);
	memcpy(req->options.u32.pcnt, pcnt, req->options.u32._len.pcnt);
}
static inline void
tc_newqdisc_req_set_options_u32_mark(struct tc_newqdisc_req *req,
				     const void *mark, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.mark);
	req->options.u32._len.mark = len;
	req->options.u32.mark = malloc(req->options.u32._len.mark);
	memcpy(req->options.u32.mark, mark, req->options.u32._len.mark);
}
static inline void
tc_newqdisc_req_set_options_u32_flags(struct tc_newqdisc_req *req, __u32 flags)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.flags = 1;
	req->options.u32.flags = flags;
}
static inline void
tc_newqdisc_req_set_rate(struct tc_newqdisc_req *req, const void *rate,
			 size_t len)
{
	free(req->rate);
	req->_len.rate = len;
	req->rate = malloc(req->_len.rate);
	memcpy(req->rate, rate, req->_len.rate);
}
static inline void
tc_newqdisc_req_set_chain(struct tc_newqdisc_req *req, __u32 chain)
{
	req->_present.chain = 1;
	req->chain = chain;
}
static inline void
tc_newqdisc_req_set_ingress_block(struct tc_newqdisc_req *req,
				  __u32 ingress_block)
{
	req->_present.ingress_block = 1;
	req->ingress_block = ingress_block;
}
static inline void
tc_newqdisc_req_set_egress_block(struct tc_newqdisc_req *req,
				 __u32 egress_block)
{
	req->_present.egress_block = 1;
	req->egress_block = egress_block;
}

/*
 * Create new tc qdisc.
 */
int tc_newqdisc(struct ynl_sock *ys, struct tc_newqdisc_req *req);

/* ============== RTM_DELQDISC ============== */
/* RTM_DELQDISC - do */
struct tc_delqdisc_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;
};

static inline struct tc_delqdisc_req *tc_delqdisc_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_delqdisc_req));
}
void tc_delqdisc_req_free(struct tc_delqdisc_req *req);

static inline void
tc_delqdisc_req_set_nlflags(struct tc_delqdisc_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

/*
 * Delete existing tc qdisc.
 */
int tc_delqdisc(struct ynl_sock *ys, struct tc_delqdisc_req *req);

/* ============== RTM_GETQDISC ============== */
/* RTM_GETQDISC - do */
struct tc_getqdisc_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;

	struct {
		__u32 dump_invisible:1;
	} _present;
};

static inline struct tc_getqdisc_req *tc_getqdisc_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_getqdisc_req));
}
void tc_getqdisc_req_free(struct tc_getqdisc_req *req);

static inline void
tc_getqdisc_req_set_nlflags(struct tc_getqdisc_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
tc_getqdisc_req_set_dump_invisible(struct tc_getqdisc_req *req)
{
	req->_present.dump_invisible = 1;
}

struct tc_getqdisc_rsp {
	struct tcmsg _hdr;

	struct {
		__u32 options:1;
		__u32 xstats:1;
		__u32 fcnt:1;
		__u32 stats2:1;
		__u32 stab:1;
		__u32 chain:1;
		__u32 ingress_block:1;
		__u32 egress_block:1;
	} _present;
	struct {
		__u32 kind;
		__u32 stats;
		__u32 rate;
	} _len;

	char *kind;
	struct tc_options_msg options;
	struct tc_stats *stats;
	struct tc_tca_stats_app_msg xstats;
	struct gnet_estimator *rate;
	__u32 fcnt;
	struct tc_tca_stats_attrs stats2;
	struct tc_tca_stab_attrs stab;
	__u32 chain;
	__u32 ingress_block;
	__u32 egress_block;
};

void tc_getqdisc_rsp_free(struct tc_getqdisc_rsp *rsp);

/*
 * Get / dump tc qdisc information.
 */
struct tc_getqdisc_rsp *
tc_getqdisc(struct ynl_sock *ys, struct tc_getqdisc_req *req);

/* RTM_GETQDISC - dump */
struct tc_getqdisc_req_dump {
	struct tcmsg _hdr;

	struct {
		__u32 dump_invisible:1;
	} _present;
};

static inline struct tc_getqdisc_req_dump *tc_getqdisc_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct tc_getqdisc_req_dump));
}
void tc_getqdisc_req_dump_free(struct tc_getqdisc_req_dump *req);

static inline void
tc_getqdisc_req_dump_set_dump_invisible(struct tc_getqdisc_req_dump *req)
{
	req->_present.dump_invisible = 1;
}

struct tc_getqdisc_list {
	struct tc_getqdisc_list *next;
	struct tc_getqdisc_rsp obj __attribute__((aligned(8)));
};

void tc_getqdisc_list_free(struct tc_getqdisc_list *rsp);

struct tc_getqdisc_list *
tc_getqdisc_dump(struct ynl_sock *ys, struct tc_getqdisc_req_dump *req);

/* ============== RTM_NEWTCLASS ============== */
/* RTM_NEWTCLASS - do */
struct tc_newtclass_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;

	struct {
		__u32 options:1;
		__u32 chain:1;
		__u32 ingress_block:1;
		__u32 egress_block:1;
	} _present;
	struct {
		__u32 kind;
		__u32 rate;
	} _len;

	char *kind;
	struct tc_options_msg options;
	struct gnet_estimator *rate;
	__u32 chain;
	__u32 ingress_block;
	__u32 egress_block;
};

static inline struct tc_newtclass_req *tc_newtclass_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_newtclass_req));
}
void tc_newtclass_req_free(struct tc_newtclass_req *req);

static inline void
tc_newtclass_req_set_nlflags(struct tc_newtclass_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
tc_newtclass_req_set_kind(struct tc_newtclass_req *req, const char *kind)
{
	free(req->kind);
	req->_len.kind = strlen(kind);
	req->kind = malloc(req->_len.kind + 1);
	memcpy(req->kind, kind, req->_len.kind);
	req->kind[req->_len.kind] = 0;
}
static inline void
tc_newtclass_req_set_options_basic_classid(struct tc_newtclass_req *req,
					   __u32 classid)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.classid = 1;
	req->options.basic.classid = classid;
}
static inline void
tc_newtclass_req_set_options_basic_ematches_tree_hdr(struct tc_newtclass_req *req,
						     const void *tree_hdr,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.ematches = 1;
	free(req->options.basic.ematches.tree_hdr);
	req->options.basic.ematches._len.tree_hdr = len;
	req->options.basic.ematches.tree_hdr = malloc(req->options.basic.ematches._len.tree_hdr);
	memcpy(req->options.basic.ematches.tree_hdr, tree_hdr, req->options.basic.ematches._len.tree_hdr);
}
static inline void
tc_newtclass_req_set_options_basic_ematches_tree_list(struct tc_newtclass_req *req,
						      const void *tree_list,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.ematches = 1;
	free(req->options.basic.ematches.tree_list);
	req->options.basic.ematches._len.tree_list = len;
	req->options.basic.ematches.tree_list = malloc(req->options.basic.ematches._len.tree_list);
	memcpy(req->options.basic.ematches.tree_list, tree_list, req->options.basic.ematches._len.tree_list);
}
static inline void
__tc_newtclass_req_set_options_basic_act(struct tc_newtclass_req *req,
					 struct tc_act_attrs *act,
					 unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	free(req->options.basic.act);
	req->options.basic.act = act;
	req->options.basic._count.act = n_act;
}
static inline void
tc_newtclass_req_set_options_basic_police_tbf(struct tc_newtclass_req *req,
					      const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.tbf);
	req->options.basic.police._len.tbf = len;
	req->options.basic.police.tbf = malloc(req->options.basic.police._len.tbf);
	memcpy(req->options.basic.police.tbf, tbf, req->options.basic.police._len.tbf);
}
static inline void
tc_newtclass_req_set_options_basic_police_rate(struct tc_newtclass_req *req,
					       const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.rate);
	req->options.basic.police._len.rate = len;
	req->options.basic.police.rate = malloc(req->options.basic.police._len.rate);
	memcpy(req->options.basic.police.rate, rate, req->options.basic.police._len.rate);
}
static inline void
tc_newtclass_req_set_options_basic_police_peakrate(struct tc_newtclass_req *req,
						   const void *peakrate,
						   size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.peakrate);
	req->options.basic.police._len.peakrate = len;
	req->options.basic.police.peakrate = malloc(req->options.basic.police._len.peakrate);
	memcpy(req->options.basic.police.peakrate, peakrate, req->options.basic.police._len.peakrate);
}
static inline void
tc_newtclass_req_set_options_basic_police_avrate(struct tc_newtclass_req *req,
						 __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.avrate = 1;
	req->options.basic.police.avrate = avrate;
}
static inline void
tc_newtclass_req_set_options_basic_police_result(struct tc_newtclass_req *req,
						 __u32 result)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.result = 1;
	req->options.basic.police.result = result;
}
static inline void
tc_newtclass_req_set_options_basic_police_tm(struct tc_newtclass_req *req,
					     const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.tm);
	req->options.basic.police._len.tm = len;
	req->options.basic.police.tm = malloc(req->options.basic.police._len.tm);
	memcpy(req->options.basic.police.tm, tm, req->options.basic.police._len.tm);
}
static inline void
tc_newtclass_req_set_options_basic_police_rate64(struct tc_newtclass_req *req,
						 __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.rate64 = 1;
	req->options.basic.police.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_basic_police_peakrate64(struct tc_newtclass_req *req,
						     __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.peakrate64 = 1;
	req->options.basic.police.peakrate64 = peakrate64;
}
static inline void
tc_newtclass_req_set_options_basic_police_pktrate64(struct tc_newtclass_req *req,
						    __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.pktrate64 = 1;
	req->options.basic.police.pktrate64 = pktrate64;
}
static inline void
tc_newtclass_req_set_options_basic_police_pktburst64(struct tc_newtclass_req *req,
						     __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.pktburst64 = 1;
	req->options.basic.police.pktburst64 = pktburst64;
}
static inline void
tc_newtclass_req_set_options_basic_pcnt(struct tc_newtclass_req *req,
					const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	free(req->options.basic.pcnt);
	req->options.basic._len.pcnt = len;
	req->options.basic.pcnt = malloc(req->options.basic._len.pcnt);
	memcpy(req->options.basic.pcnt, pcnt, req->options.basic._len.pcnt);
}
static inline void
__tc_newtclass_req_set_options_bpf_act(struct tc_newtclass_req *req,
				       struct tc_act_attrs *act,
				       unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.act);
	req->options.bpf.act = act;
	req->options.bpf._count.act = n_act;
}
static inline void
tc_newtclass_req_set_options_bpf_police_tbf(struct tc_newtclass_req *req,
					    const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.tbf);
	req->options.bpf.police._len.tbf = len;
	req->options.bpf.police.tbf = malloc(req->options.bpf.police._len.tbf);
	memcpy(req->options.bpf.police.tbf, tbf, req->options.bpf.police._len.tbf);
}
static inline void
tc_newtclass_req_set_options_bpf_police_rate(struct tc_newtclass_req *req,
					     const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.rate);
	req->options.bpf.police._len.rate = len;
	req->options.bpf.police.rate = malloc(req->options.bpf.police._len.rate);
	memcpy(req->options.bpf.police.rate, rate, req->options.bpf.police._len.rate);
}
static inline void
tc_newtclass_req_set_options_bpf_police_peakrate(struct tc_newtclass_req *req,
						 const void *peakrate,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.peakrate);
	req->options.bpf.police._len.peakrate = len;
	req->options.bpf.police.peakrate = malloc(req->options.bpf.police._len.peakrate);
	memcpy(req->options.bpf.police.peakrate, peakrate, req->options.bpf.police._len.peakrate);
}
static inline void
tc_newtclass_req_set_options_bpf_police_avrate(struct tc_newtclass_req *req,
					       __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.avrate = 1;
	req->options.bpf.police.avrate = avrate;
}
static inline void
tc_newtclass_req_set_options_bpf_police_result(struct tc_newtclass_req *req,
					       __u32 result)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.result = 1;
	req->options.bpf.police.result = result;
}
static inline void
tc_newtclass_req_set_options_bpf_police_tm(struct tc_newtclass_req *req,
					   const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.tm);
	req->options.bpf.police._len.tm = len;
	req->options.bpf.police.tm = malloc(req->options.bpf.police._len.tm);
	memcpy(req->options.bpf.police.tm, tm, req->options.bpf.police._len.tm);
}
static inline void
tc_newtclass_req_set_options_bpf_police_rate64(struct tc_newtclass_req *req,
					       __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.rate64 = 1;
	req->options.bpf.police.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_bpf_police_peakrate64(struct tc_newtclass_req *req,
						   __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.peakrate64 = 1;
	req->options.bpf.police.peakrate64 = peakrate64;
}
static inline void
tc_newtclass_req_set_options_bpf_police_pktrate64(struct tc_newtclass_req *req,
						  __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.pktrate64 = 1;
	req->options.bpf.police.pktrate64 = pktrate64;
}
static inline void
tc_newtclass_req_set_options_bpf_police_pktburst64(struct tc_newtclass_req *req,
						   __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.pktburst64 = 1;
	req->options.bpf.police.pktburst64 = pktburst64;
}
static inline void
tc_newtclass_req_set_options_bpf_classid(struct tc_newtclass_req *req,
					 __u32 classid)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.classid = 1;
	req->options.bpf.classid = classid;
}
static inline void
tc_newtclass_req_set_options_bpf_ops_len(struct tc_newtclass_req *req,
					 __u16 ops_len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.ops_len = 1;
	req->options.bpf.ops_len = ops_len;
}
static inline void
tc_newtclass_req_set_options_bpf_ops(struct tc_newtclass_req *req,
				     const void *ops, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.ops);
	req->options.bpf._len.ops = len;
	req->options.bpf.ops = malloc(req->options.bpf._len.ops);
	memcpy(req->options.bpf.ops, ops, req->options.bpf._len.ops);
}
static inline void
tc_newtclass_req_set_options_bpf_fd(struct tc_newtclass_req *req, __u32 fd)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.fd = 1;
	req->options.bpf.fd = fd;
}
static inline void
tc_newtclass_req_set_options_bpf_name(struct tc_newtclass_req *req,
				      const char *name)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.name);
	req->options.bpf._len.name = strlen(name);
	req->options.bpf.name = malloc(req->options.bpf._len.name + 1);
	memcpy(req->options.bpf.name, name, req->options.bpf._len.name);
	req->options.bpf.name[req->options.bpf._len.name] = 0;
}
static inline void
tc_newtclass_req_set_options_bpf_flags(struct tc_newtclass_req *req,
				       __u32 flags)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.flags = 1;
	req->options.bpf.flags = flags;
}
static inline void
tc_newtclass_req_set_options_bpf_flags_gen(struct tc_newtclass_req *req,
					   __u32 flags_gen)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.flags_gen = 1;
	req->options.bpf.flags_gen = flags_gen;
}
static inline void
tc_newtclass_req_set_options_bpf_tag(struct tc_newtclass_req *req,
				     const void *tag, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.tag);
	req->options.bpf._len.tag = len;
	req->options.bpf.tag = malloc(req->options.bpf._len.tag);
	memcpy(req->options.bpf.tag, tag, req->options.bpf._len.tag);
}
static inline void
tc_newtclass_req_set_options_bpf_id(struct tc_newtclass_req *req, __u32 id)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.id = 1;
	req->options.bpf.id = id;
}
static inline void
tc_newtclass_req_set_options_bfifo(struct tc_newtclass_req *req,
				   const void *bfifo, size_t len)
{
	req->_present.options = 1;
	free(req->options.bfifo);
	req->options._len.bfifo = len;
	req->options.bfifo = malloc(req->options._len.bfifo);
	memcpy(req->options.bfifo, bfifo, req->options._len.bfifo);
}
static inline void
tc_newtclass_req_set_options_cake_base_rate64(struct tc_newtclass_req *req,
					      __u64 base_rate64)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.base_rate64 = 1;
	req->options.cake.base_rate64 = base_rate64;
}
static inline void
tc_newtclass_req_set_options_cake_diffserv_mode(struct tc_newtclass_req *req,
						__u32 diffserv_mode)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.diffserv_mode = 1;
	req->options.cake.diffserv_mode = diffserv_mode;
}
static inline void
tc_newtclass_req_set_options_cake_atm(struct tc_newtclass_req *req, __u32 atm)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.atm = 1;
	req->options.cake.atm = atm;
}
static inline void
tc_newtclass_req_set_options_cake_flow_mode(struct tc_newtclass_req *req,
					    __u32 flow_mode)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.flow_mode = 1;
	req->options.cake.flow_mode = flow_mode;
}
static inline void
tc_newtclass_req_set_options_cake_overhead(struct tc_newtclass_req *req,
					   __u32 overhead)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.overhead = 1;
	req->options.cake.overhead = overhead;
}
static inline void
tc_newtclass_req_set_options_cake_rtt(struct tc_newtclass_req *req, __u32 rtt)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.rtt = 1;
	req->options.cake.rtt = rtt;
}
static inline void
tc_newtclass_req_set_options_cake_target(struct tc_newtclass_req *req,
					 __u32 target)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.target = 1;
	req->options.cake.target = target;
}
static inline void
tc_newtclass_req_set_options_cake_autorate(struct tc_newtclass_req *req,
					   __u32 autorate)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.autorate = 1;
	req->options.cake.autorate = autorate;
}
static inline void
tc_newtclass_req_set_options_cake_memory(struct tc_newtclass_req *req,
					 __u32 memory)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.memory = 1;
	req->options.cake.memory = memory;
}
static inline void
tc_newtclass_req_set_options_cake_nat(struct tc_newtclass_req *req, __u32 nat)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.nat = 1;
	req->options.cake.nat = nat;
}
static inline void
tc_newtclass_req_set_options_cake_raw(struct tc_newtclass_req *req, __u32 raw)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.raw = 1;
	req->options.cake.raw = raw;
}
static inline void
tc_newtclass_req_set_options_cake_wash(struct tc_newtclass_req *req,
				       __u32 wash)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.wash = 1;
	req->options.cake.wash = wash;
}
static inline void
tc_newtclass_req_set_options_cake_mpu(struct tc_newtclass_req *req, __u32 mpu)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.mpu = 1;
	req->options.cake.mpu = mpu;
}
static inline void
tc_newtclass_req_set_options_cake_ingress(struct tc_newtclass_req *req,
					  __u32 ingress)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.ingress = 1;
	req->options.cake.ingress = ingress;
}
static inline void
tc_newtclass_req_set_options_cake_ack_filter(struct tc_newtclass_req *req,
					     __u32 ack_filter)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.ack_filter = 1;
	req->options.cake.ack_filter = ack_filter;
}
static inline void
tc_newtclass_req_set_options_cake_split_gso(struct tc_newtclass_req *req,
					    __u32 split_gso)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.split_gso = 1;
	req->options.cake.split_gso = split_gso;
}
static inline void
tc_newtclass_req_set_options_cake_fwmark(struct tc_newtclass_req *req,
					 __u32 fwmark)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.fwmark = 1;
	req->options.cake.fwmark = fwmark;
}
static inline void
tc_newtclass_req_set_options_cbs_parms(struct tc_newtclass_req *req,
				       const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.cbs = 1;
	free(req->options.cbs.parms);
	req->options.cbs._len.parms = len;
	req->options.cbs.parms = malloc(req->options.cbs._len.parms);
	memcpy(req->options.cbs.parms, parms, req->options.cbs._len.parms);
}
static inline void
__tc_newtclass_req_set_options_cgroup_act(struct tc_newtclass_req *req,
					  struct tc_act_attrs *act,
					  unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	free(req->options.cgroup.act);
	req->options.cgroup.act = act;
	req->options.cgroup._count.act = n_act;
}
static inline void
tc_newtclass_req_set_options_cgroup_police_tbf(struct tc_newtclass_req *req,
					       const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.tbf);
	req->options.cgroup.police._len.tbf = len;
	req->options.cgroup.police.tbf = malloc(req->options.cgroup.police._len.tbf);
	memcpy(req->options.cgroup.police.tbf, tbf, req->options.cgroup.police._len.tbf);
}
static inline void
tc_newtclass_req_set_options_cgroup_police_rate(struct tc_newtclass_req *req,
						const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.rate);
	req->options.cgroup.police._len.rate = len;
	req->options.cgroup.police.rate = malloc(req->options.cgroup.police._len.rate);
	memcpy(req->options.cgroup.police.rate, rate, req->options.cgroup.police._len.rate);
}
static inline void
tc_newtclass_req_set_options_cgroup_police_peakrate(struct tc_newtclass_req *req,
						    const void *peakrate,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.peakrate);
	req->options.cgroup.police._len.peakrate = len;
	req->options.cgroup.police.peakrate = malloc(req->options.cgroup.police._len.peakrate);
	memcpy(req->options.cgroup.police.peakrate, peakrate, req->options.cgroup.police._len.peakrate);
}
static inline void
tc_newtclass_req_set_options_cgroup_police_avrate(struct tc_newtclass_req *req,
						  __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.avrate = 1;
	req->options.cgroup.police.avrate = avrate;
}
static inline void
tc_newtclass_req_set_options_cgroup_police_result(struct tc_newtclass_req *req,
						  __u32 result)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.result = 1;
	req->options.cgroup.police.result = result;
}
static inline void
tc_newtclass_req_set_options_cgroup_police_tm(struct tc_newtclass_req *req,
					      const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.tm);
	req->options.cgroup.police._len.tm = len;
	req->options.cgroup.police.tm = malloc(req->options.cgroup.police._len.tm);
	memcpy(req->options.cgroup.police.tm, tm, req->options.cgroup.police._len.tm);
}
static inline void
tc_newtclass_req_set_options_cgroup_police_rate64(struct tc_newtclass_req *req,
						  __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.rate64 = 1;
	req->options.cgroup.police.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_cgroup_police_peakrate64(struct tc_newtclass_req *req,
						      __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.peakrate64 = 1;
	req->options.cgroup.police.peakrate64 = peakrate64;
}
static inline void
tc_newtclass_req_set_options_cgroup_police_pktrate64(struct tc_newtclass_req *req,
						     __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.pktrate64 = 1;
	req->options.cgroup.police.pktrate64 = pktrate64;
}
static inline void
tc_newtclass_req_set_options_cgroup_police_pktburst64(struct tc_newtclass_req *req,
						      __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.pktburst64 = 1;
	req->options.cgroup.police.pktburst64 = pktburst64;
}
static inline void
tc_newtclass_req_set_options_cgroup_ematches(struct tc_newtclass_req *req,
					     const void *ematches, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	free(req->options.cgroup.ematches);
	req->options.cgroup._len.ematches = len;
	req->options.cgroup.ematches = malloc(req->options.cgroup._len.ematches);
	memcpy(req->options.cgroup.ematches, ematches, req->options.cgroup._len.ematches);
}
static inline void
tc_newtclass_req_set_options_choke_parms(struct tc_newtclass_req *req,
					 const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	free(req->options.choke.parms);
	req->options.choke._len.parms = len;
	req->options.choke.parms = malloc(req->options.choke._len.parms);
	memcpy(req->options.choke.parms, parms, req->options.choke._len.parms);
}
static inline void
tc_newtclass_req_set_options_choke_stab(struct tc_newtclass_req *req,
					const void *stab, size_t len)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	free(req->options.choke.stab);
	req->options.choke._len.stab = len;
	req->options.choke.stab = malloc(req->options.choke._len.stab);
	memcpy(req->options.choke.stab, stab, req->options.choke._len.stab);
}
static inline void
tc_newtclass_req_set_options_choke_max_p(struct tc_newtclass_req *req,
					 __u32 max_p)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	req->options.choke._present.max_p = 1;
	req->options.choke.max_p = max_p;
}
static inline void
tc_newtclass_req_set_options_clsact(struct tc_newtclass_req *req)
{
	req->_present.options = 1;
	req->options._present.clsact = 1;
}
static inline void
tc_newtclass_req_set_options_codel_target(struct tc_newtclass_req *req,
					  __u32 target)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.target = 1;
	req->options.codel.target = target;
}
static inline void
tc_newtclass_req_set_options_codel_limit(struct tc_newtclass_req *req,
					 __u32 limit)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.limit = 1;
	req->options.codel.limit = limit;
}
static inline void
tc_newtclass_req_set_options_codel_interval(struct tc_newtclass_req *req,
					    __u32 interval)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.interval = 1;
	req->options.codel.interval = interval;
}
static inline void
tc_newtclass_req_set_options_codel_ecn(struct tc_newtclass_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.ecn = 1;
	req->options.codel.ecn = ecn;
}
static inline void
tc_newtclass_req_set_options_codel_ce_threshold(struct tc_newtclass_req *req,
						__u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.ce_threshold = 1;
	req->options.codel.ce_threshold = ce_threshold;
}
static inline void
tc_newtclass_req_set_options_drr_quantum(struct tc_newtclass_req *req,
					 __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.drr = 1;
	req->options.drr._present.quantum = 1;
	req->options.drr.quantum = quantum;
}
static inline void
tc_newtclass_req_set_options_etf_parms(struct tc_newtclass_req *req,
				       const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.etf = 1;
	free(req->options.etf.parms);
	req->options.etf._len.parms = len;
	req->options.etf.parms = malloc(req->options.etf._len.parms);
	memcpy(req->options.etf.parms, parms, req->options.etf._len.parms);
}
static inline void
tc_newtclass_req_set_options_flow_keys(struct tc_newtclass_req *req,
				       __u32 keys)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.keys = 1;
	req->options.flow.keys = keys;
}
static inline void
tc_newtclass_req_set_options_flow_mode(struct tc_newtclass_req *req,
				       __u32 mode)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.mode = 1;
	req->options.flow.mode = mode;
}
static inline void
tc_newtclass_req_set_options_flow_baseclass(struct tc_newtclass_req *req,
					    __u32 baseclass)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.baseclass = 1;
	req->options.flow.baseclass = baseclass;
}
static inline void
tc_newtclass_req_set_options_flow_rshift(struct tc_newtclass_req *req,
					 __u32 rshift)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.rshift = 1;
	req->options.flow.rshift = rshift;
}
static inline void
tc_newtclass_req_set_options_flow_addend(struct tc_newtclass_req *req,
					 __u32 addend)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.addend = 1;
	req->options.flow.addend = addend;
}
static inline void
tc_newtclass_req_set_options_flow_mask(struct tc_newtclass_req *req,
				       __u32 mask)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.mask = 1;
	req->options.flow.mask = mask;
}
static inline void
tc_newtclass_req_set_options_flow_xor(struct tc_newtclass_req *req, __u32 xor)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.xor = 1;
	req->options.flow.xor = xor;
}
static inline void
tc_newtclass_req_set_options_flow_divisor(struct tc_newtclass_req *req,
					  __u32 divisor)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.divisor = 1;
	req->options.flow.divisor = divisor;
}
static inline void
tc_newtclass_req_set_options_flow_act(struct tc_newtclass_req *req,
				      const void *act, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	free(req->options.flow.act);
	req->options.flow._len.act = len;
	req->options.flow.act = malloc(req->options.flow._len.act);
	memcpy(req->options.flow.act, act, req->options.flow._len.act);
}
static inline void
tc_newtclass_req_set_options_flow_police_tbf(struct tc_newtclass_req *req,
					     const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.tbf);
	req->options.flow.police._len.tbf = len;
	req->options.flow.police.tbf = malloc(req->options.flow.police._len.tbf);
	memcpy(req->options.flow.police.tbf, tbf, req->options.flow.police._len.tbf);
}
static inline void
tc_newtclass_req_set_options_flow_police_rate(struct tc_newtclass_req *req,
					      const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.rate);
	req->options.flow.police._len.rate = len;
	req->options.flow.police.rate = malloc(req->options.flow.police._len.rate);
	memcpy(req->options.flow.police.rate, rate, req->options.flow.police._len.rate);
}
static inline void
tc_newtclass_req_set_options_flow_police_peakrate(struct tc_newtclass_req *req,
						  const void *peakrate,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.peakrate);
	req->options.flow.police._len.peakrate = len;
	req->options.flow.police.peakrate = malloc(req->options.flow.police._len.peakrate);
	memcpy(req->options.flow.police.peakrate, peakrate, req->options.flow.police._len.peakrate);
}
static inline void
tc_newtclass_req_set_options_flow_police_avrate(struct tc_newtclass_req *req,
						__u32 avrate)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.avrate = 1;
	req->options.flow.police.avrate = avrate;
}
static inline void
tc_newtclass_req_set_options_flow_police_result(struct tc_newtclass_req *req,
						__u32 result)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.result = 1;
	req->options.flow.police.result = result;
}
static inline void
tc_newtclass_req_set_options_flow_police_tm(struct tc_newtclass_req *req,
					    const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.tm);
	req->options.flow.police._len.tm = len;
	req->options.flow.police.tm = malloc(req->options.flow.police._len.tm);
	memcpy(req->options.flow.police.tm, tm, req->options.flow.police._len.tm);
}
static inline void
tc_newtclass_req_set_options_flow_police_rate64(struct tc_newtclass_req *req,
						__u64 rate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.rate64 = 1;
	req->options.flow.police.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_flow_police_peakrate64(struct tc_newtclass_req *req,
						    __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.peakrate64 = 1;
	req->options.flow.police.peakrate64 = peakrate64;
}
static inline void
tc_newtclass_req_set_options_flow_police_pktrate64(struct tc_newtclass_req *req,
						   __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.pktrate64 = 1;
	req->options.flow.police.pktrate64 = pktrate64;
}
static inline void
tc_newtclass_req_set_options_flow_police_pktburst64(struct tc_newtclass_req *req,
						    __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.pktburst64 = 1;
	req->options.flow.police.pktburst64 = pktburst64;
}
static inline void
tc_newtclass_req_set_options_flow_ematches(struct tc_newtclass_req *req,
					   const void *ematches, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	free(req->options.flow.ematches);
	req->options.flow._len.ematches = len;
	req->options.flow.ematches = malloc(req->options.flow._len.ematches);
	memcpy(req->options.flow.ematches, ematches, req->options.flow._len.ematches);
}
static inline void
tc_newtclass_req_set_options_flow_perturb(struct tc_newtclass_req *req,
					  __u32 perturb)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.perturb = 1;
	req->options.flow.perturb = perturb;
}
static inline void
tc_newtclass_req_set_options_flower_classid(struct tc_newtclass_req *req,
					    __u32 classid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.classid = 1;
	req->options.flower.classid = classid;
}
static inline void
tc_newtclass_req_set_options_flower_indev(struct tc_newtclass_req *req,
					  const char *indev)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.indev);
	req->options.flower._len.indev = strlen(indev);
	req->options.flower.indev = malloc(req->options.flower._len.indev + 1);
	memcpy(req->options.flower.indev, indev, req->options.flower._len.indev);
	req->options.flower.indev[req->options.flower._len.indev] = 0;
}
static inline void
__tc_newtclass_req_set_options_flower_act(struct tc_newtclass_req *req,
					  struct tc_act_attrs *act,
					  unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.act);
	req->options.flower.act = act;
	req->options.flower._count.act = n_act;
}
static inline void
tc_newtclass_req_set_options_flower_key_eth_dst(struct tc_newtclass_req *req,
						const void *key_eth_dst,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_dst);
	req->options.flower._len.key_eth_dst = len;
	req->options.flower.key_eth_dst = malloc(req->options.flower._len.key_eth_dst);
	memcpy(req->options.flower.key_eth_dst, key_eth_dst, req->options.flower._len.key_eth_dst);
}
static inline void
tc_newtclass_req_set_options_flower_key_eth_dst_mask(struct tc_newtclass_req *req,
						     const void *key_eth_dst_mask,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_dst_mask);
	req->options.flower._len.key_eth_dst_mask = len;
	req->options.flower.key_eth_dst_mask = malloc(req->options.flower._len.key_eth_dst_mask);
	memcpy(req->options.flower.key_eth_dst_mask, key_eth_dst_mask, req->options.flower._len.key_eth_dst_mask);
}
static inline void
tc_newtclass_req_set_options_flower_key_eth_src(struct tc_newtclass_req *req,
						const void *key_eth_src,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_src);
	req->options.flower._len.key_eth_src = len;
	req->options.flower.key_eth_src = malloc(req->options.flower._len.key_eth_src);
	memcpy(req->options.flower.key_eth_src, key_eth_src, req->options.flower._len.key_eth_src);
}
static inline void
tc_newtclass_req_set_options_flower_key_eth_src_mask(struct tc_newtclass_req *req,
						     const void *key_eth_src_mask,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_src_mask);
	req->options.flower._len.key_eth_src_mask = len;
	req->options.flower.key_eth_src_mask = malloc(req->options.flower._len.key_eth_src_mask);
	memcpy(req->options.flower.key_eth_src_mask, key_eth_src_mask, req->options.flower._len.key_eth_src_mask);
}
static inline void
tc_newtclass_req_set_options_flower_key_eth_type(struct tc_newtclass_req *req,
						 __u16 key_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_eth_type = 1;
	req->options.flower.key_eth_type = key_eth_type;
}
static inline void
tc_newtclass_req_set_options_flower_key_ip_proto(struct tc_newtclass_req *req,
						 __u8 key_ip_proto)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_proto = 1;
	req->options.flower.key_ip_proto = key_ip_proto;
}
static inline void
tc_newtclass_req_set_options_flower_key_ipv4_src(struct tc_newtclass_req *req,
						 __u32 key_ipv4_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_src = 1;
	req->options.flower.key_ipv4_src = key_ipv4_src;
}
static inline void
tc_newtclass_req_set_options_flower_key_ipv4_src_mask(struct tc_newtclass_req *req,
						      __u32 key_ipv4_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_src_mask = 1;
	req->options.flower.key_ipv4_src_mask = key_ipv4_src_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_ipv4_dst(struct tc_newtclass_req *req,
						 __u32 key_ipv4_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_dst = 1;
	req->options.flower.key_ipv4_dst = key_ipv4_dst;
}
static inline void
tc_newtclass_req_set_options_flower_key_ipv4_dst_mask(struct tc_newtclass_req *req,
						      __u32 key_ipv4_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_dst_mask = 1;
	req->options.flower.key_ipv4_dst_mask = key_ipv4_dst_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_ipv6_src(struct tc_newtclass_req *req,
						 const void *key_ipv6_src,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_src);
	req->options.flower._len.key_ipv6_src = len;
	req->options.flower.key_ipv6_src = malloc(req->options.flower._len.key_ipv6_src);
	memcpy(req->options.flower.key_ipv6_src, key_ipv6_src, req->options.flower._len.key_ipv6_src);
}
static inline void
tc_newtclass_req_set_options_flower_key_ipv6_src_mask(struct tc_newtclass_req *req,
						      const void *key_ipv6_src_mask,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_src_mask);
	req->options.flower._len.key_ipv6_src_mask = len;
	req->options.flower.key_ipv6_src_mask = malloc(req->options.flower._len.key_ipv6_src_mask);
	memcpy(req->options.flower.key_ipv6_src_mask, key_ipv6_src_mask, req->options.flower._len.key_ipv6_src_mask);
}
static inline void
tc_newtclass_req_set_options_flower_key_ipv6_dst(struct tc_newtclass_req *req,
						 const void *key_ipv6_dst,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_dst);
	req->options.flower._len.key_ipv6_dst = len;
	req->options.flower.key_ipv6_dst = malloc(req->options.flower._len.key_ipv6_dst);
	memcpy(req->options.flower.key_ipv6_dst, key_ipv6_dst, req->options.flower._len.key_ipv6_dst);
}
static inline void
tc_newtclass_req_set_options_flower_key_ipv6_dst_mask(struct tc_newtclass_req *req,
						      const void *key_ipv6_dst_mask,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_dst_mask);
	req->options.flower._len.key_ipv6_dst_mask = len;
	req->options.flower.key_ipv6_dst_mask = malloc(req->options.flower._len.key_ipv6_dst_mask);
	memcpy(req->options.flower.key_ipv6_dst_mask, key_ipv6_dst_mask, req->options.flower._len.key_ipv6_dst_mask);
}
static inline void
tc_newtclass_req_set_options_flower_key_tcp_src(struct tc_newtclass_req *req,
						__u16 key_tcp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_src = 1;
	req->options.flower.key_tcp_src = key_tcp_src;
}
static inline void
tc_newtclass_req_set_options_flower_key_tcp_dst(struct tc_newtclass_req *req,
						__u16 key_tcp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_dst = 1;
	req->options.flower.key_tcp_dst = key_tcp_dst;
}
static inline void
tc_newtclass_req_set_options_flower_key_udp_src(struct tc_newtclass_req *req,
						__u16 key_udp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_src = 1;
	req->options.flower.key_udp_src = key_udp_src;
}
static inline void
tc_newtclass_req_set_options_flower_key_udp_dst(struct tc_newtclass_req *req,
						__u16 key_udp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_dst = 1;
	req->options.flower.key_udp_dst = key_udp_dst;
}
static inline void
tc_newtclass_req_set_options_flower_flags(struct tc_newtclass_req *req,
					  __u32 flags)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.flags = 1;
	req->options.flower.flags = flags;
}
static inline void
tc_newtclass_req_set_options_flower_key_vlan_id(struct tc_newtclass_req *req,
						__u16 key_vlan_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_id = 1;
	req->options.flower.key_vlan_id = key_vlan_id;
}
static inline void
tc_newtclass_req_set_options_flower_key_vlan_prio(struct tc_newtclass_req *req,
						  __u8 key_vlan_prio)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_prio = 1;
	req->options.flower.key_vlan_prio = key_vlan_prio;
}
static inline void
tc_newtclass_req_set_options_flower_key_vlan_eth_type(struct tc_newtclass_req *req,
						      __u16 key_vlan_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_eth_type = 1;
	req->options.flower.key_vlan_eth_type = key_vlan_eth_type;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_key_id(struct tc_newtclass_req *req,
						   __u32 key_enc_key_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_key_id = 1;
	req->options.flower.key_enc_key_id = key_enc_key_id;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ipv4_src(struct tc_newtclass_req *req,
						     __u32 key_enc_ipv4_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_src = 1;
	req->options.flower.key_enc_ipv4_src = key_enc_ipv4_src;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ipv4_src_mask(struct tc_newtclass_req *req,
							  __u32 key_enc_ipv4_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_src_mask = 1;
	req->options.flower.key_enc_ipv4_src_mask = key_enc_ipv4_src_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ipv4_dst(struct tc_newtclass_req *req,
						     __u32 key_enc_ipv4_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_dst = 1;
	req->options.flower.key_enc_ipv4_dst = key_enc_ipv4_dst;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ipv4_dst_mask(struct tc_newtclass_req *req,
							  __u32 key_enc_ipv4_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_dst_mask = 1;
	req->options.flower.key_enc_ipv4_dst_mask = key_enc_ipv4_dst_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ipv6_src(struct tc_newtclass_req *req,
						     const void *key_enc_ipv6_src,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_src);
	req->options.flower._len.key_enc_ipv6_src = len;
	req->options.flower.key_enc_ipv6_src = malloc(req->options.flower._len.key_enc_ipv6_src);
	memcpy(req->options.flower.key_enc_ipv6_src, key_enc_ipv6_src, req->options.flower._len.key_enc_ipv6_src);
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ipv6_src_mask(struct tc_newtclass_req *req,
							  const void *key_enc_ipv6_src_mask,
							  size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_src_mask);
	req->options.flower._len.key_enc_ipv6_src_mask = len;
	req->options.flower.key_enc_ipv6_src_mask = malloc(req->options.flower._len.key_enc_ipv6_src_mask);
	memcpy(req->options.flower.key_enc_ipv6_src_mask, key_enc_ipv6_src_mask, req->options.flower._len.key_enc_ipv6_src_mask);
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ipv6_dst(struct tc_newtclass_req *req,
						     const void *key_enc_ipv6_dst,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_dst);
	req->options.flower._len.key_enc_ipv6_dst = len;
	req->options.flower.key_enc_ipv6_dst = malloc(req->options.flower._len.key_enc_ipv6_dst);
	memcpy(req->options.flower.key_enc_ipv6_dst, key_enc_ipv6_dst, req->options.flower._len.key_enc_ipv6_dst);
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ipv6_dst_mask(struct tc_newtclass_req *req,
							  const void *key_enc_ipv6_dst_mask,
							  size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_dst_mask);
	req->options.flower._len.key_enc_ipv6_dst_mask = len;
	req->options.flower.key_enc_ipv6_dst_mask = malloc(req->options.flower._len.key_enc_ipv6_dst_mask);
	memcpy(req->options.flower.key_enc_ipv6_dst_mask, key_enc_ipv6_dst_mask, req->options.flower._len.key_enc_ipv6_dst_mask);
}
static inline void
tc_newtclass_req_set_options_flower_key_tcp_src_mask(struct tc_newtclass_req *req,
						     __u16 key_tcp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_src_mask = 1;
	req->options.flower.key_tcp_src_mask = key_tcp_src_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_tcp_dst_mask(struct tc_newtclass_req *req,
						     __u16 key_tcp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_dst_mask = 1;
	req->options.flower.key_tcp_dst_mask = key_tcp_dst_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_udp_src_mask(struct tc_newtclass_req *req,
						     __u16 key_udp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_src_mask = 1;
	req->options.flower.key_udp_src_mask = key_udp_src_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_udp_dst_mask(struct tc_newtclass_req *req,
						     __u16 key_udp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_dst_mask = 1;
	req->options.flower.key_udp_dst_mask = key_udp_dst_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_sctp_src_mask(struct tc_newtclass_req *req,
						      __u16 key_sctp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_src_mask = 1;
	req->options.flower.key_sctp_src_mask = key_sctp_src_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_sctp_dst_mask(struct tc_newtclass_req *req,
						      __u16 key_sctp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_dst_mask = 1;
	req->options.flower.key_sctp_dst_mask = key_sctp_dst_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_sctp_src(struct tc_newtclass_req *req,
						 __u16 key_sctp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_src = 1;
	req->options.flower.key_sctp_src = key_sctp_src;
}
static inline void
tc_newtclass_req_set_options_flower_key_sctp_dst(struct tc_newtclass_req *req,
						 __u16 key_sctp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_dst = 1;
	req->options.flower.key_sctp_dst = key_sctp_dst;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_udp_src_port(struct tc_newtclass_req *req,
							 __u16 key_enc_udp_src_port /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_src_port = 1;
	req->options.flower.key_enc_udp_src_port = key_enc_udp_src_port;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_udp_src_port_mask(struct tc_newtclass_req *req,
							      __u16 key_enc_udp_src_port_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_src_port_mask = 1;
	req->options.flower.key_enc_udp_src_port_mask = key_enc_udp_src_port_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_udp_dst_port(struct tc_newtclass_req *req,
							 __u16 key_enc_udp_dst_port /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_dst_port = 1;
	req->options.flower.key_enc_udp_dst_port = key_enc_udp_dst_port;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_udp_dst_port_mask(struct tc_newtclass_req *req,
							      __u16 key_enc_udp_dst_port_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_dst_port_mask = 1;
	req->options.flower.key_enc_udp_dst_port_mask = key_enc_udp_dst_port_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_flags(struct tc_newtclass_req *req,
					      __u32 key_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_flags = 1;
	req->options.flower.key_flags = key_flags;
}
static inline void
tc_newtclass_req_set_options_flower_key_flags_mask(struct tc_newtclass_req *req,
						   __u32 key_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_flags_mask = 1;
	req->options.flower.key_flags_mask = key_flags_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_icmpv4_code(struct tc_newtclass_req *req,
						    __u8 key_icmpv4_code)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_code = 1;
	req->options.flower.key_icmpv4_code = key_icmpv4_code;
}
static inline void
tc_newtclass_req_set_options_flower_key_icmpv4_code_mask(struct tc_newtclass_req *req,
							 __u8 key_icmpv4_code_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_code_mask = 1;
	req->options.flower.key_icmpv4_code_mask = key_icmpv4_code_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_icmpv4_type(struct tc_newtclass_req *req,
						    __u8 key_icmpv4_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_type = 1;
	req->options.flower.key_icmpv4_type = key_icmpv4_type;
}
static inline void
tc_newtclass_req_set_options_flower_key_icmpv4_type_mask(struct tc_newtclass_req *req,
							 __u8 key_icmpv4_type_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_type_mask = 1;
	req->options.flower.key_icmpv4_type_mask = key_icmpv4_type_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_icmpv6_code(struct tc_newtclass_req *req,
						    __u8 key_icmpv6_code)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_code = 1;
	req->options.flower.key_icmpv6_code = key_icmpv6_code;
}
static inline void
tc_newtclass_req_set_options_flower_key_icmpv6_code_mask(struct tc_newtclass_req *req,
							 __u8 key_icmpv6_code_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_code_mask = 1;
	req->options.flower.key_icmpv6_code_mask = key_icmpv6_code_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_icmpv6_type(struct tc_newtclass_req *req,
						    __u8 key_icmpv6_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_type = 1;
	req->options.flower.key_icmpv6_type = key_icmpv6_type;
}
static inline void
tc_newtclass_req_set_options_flower_key_icmpv6_type_mask(struct tc_newtclass_req *req,
							 __u8 key_icmpv6_type_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_type_mask = 1;
	req->options.flower.key_icmpv6_type_mask = key_icmpv6_type_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_sip(struct tc_newtclass_req *req,
						__u32 key_arp_sip /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_sip = 1;
	req->options.flower.key_arp_sip = key_arp_sip;
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_sip_mask(struct tc_newtclass_req *req,
						     __u32 key_arp_sip_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_sip_mask = 1;
	req->options.flower.key_arp_sip_mask = key_arp_sip_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_tip(struct tc_newtclass_req *req,
						__u32 key_arp_tip /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_tip = 1;
	req->options.flower.key_arp_tip = key_arp_tip;
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_tip_mask(struct tc_newtclass_req *req,
						     __u32 key_arp_tip_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_tip_mask = 1;
	req->options.flower.key_arp_tip_mask = key_arp_tip_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_op(struct tc_newtclass_req *req,
					       __u8 key_arp_op)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_op = 1;
	req->options.flower.key_arp_op = key_arp_op;
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_op_mask(struct tc_newtclass_req *req,
						    __u8 key_arp_op_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_op_mask = 1;
	req->options.flower.key_arp_op_mask = key_arp_op_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_sha(struct tc_newtclass_req *req,
						const void *key_arp_sha,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_sha);
	req->options.flower._len.key_arp_sha = len;
	req->options.flower.key_arp_sha = malloc(req->options.flower._len.key_arp_sha);
	memcpy(req->options.flower.key_arp_sha, key_arp_sha, req->options.flower._len.key_arp_sha);
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_sha_mask(struct tc_newtclass_req *req,
						     const void *key_arp_sha_mask,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_sha_mask);
	req->options.flower._len.key_arp_sha_mask = len;
	req->options.flower.key_arp_sha_mask = malloc(req->options.flower._len.key_arp_sha_mask);
	memcpy(req->options.flower.key_arp_sha_mask, key_arp_sha_mask, req->options.flower._len.key_arp_sha_mask);
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_tha(struct tc_newtclass_req *req,
						const void *key_arp_tha,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_tha);
	req->options.flower._len.key_arp_tha = len;
	req->options.flower.key_arp_tha = malloc(req->options.flower._len.key_arp_tha);
	memcpy(req->options.flower.key_arp_tha, key_arp_tha, req->options.flower._len.key_arp_tha);
}
static inline void
tc_newtclass_req_set_options_flower_key_arp_tha_mask(struct tc_newtclass_req *req,
						     const void *key_arp_tha_mask,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_tha_mask);
	req->options.flower._len.key_arp_tha_mask = len;
	req->options.flower.key_arp_tha_mask = malloc(req->options.flower._len.key_arp_tha_mask);
	memcpy(req->options.flower.key_arp_tha_mask, key_arp_tha_mask, req->options.flower._len.key_arp_tha_mask);
}
static inline void
tc_newtclass_req_set_options_flower_key_mpls_ttl(struct tc_newtclass_req *req,
						 __u8 key_mpls_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_ttl = 1;
	req->options.flower.key_mpls_ttl = key_mpls_ttl;
}
static inline void
tc_newtclass_req_set_options_flower_key_mpls_bos(struct tc_newtclass_req *req,
						 __u8 key_mpls_bos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_bos = 1;
	req->options.flower.key_mpls_bos = key_mpls_bos;
}
static inline void
tc_newtclass_req_set_options_flower_key_mpls_tc(struct tc_newtclass_req *req,
						__u8 key_mpls_tc)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_tc = 1;
	req->options.flower.key_mpls_tc = key_mpls_tc;
}
static inline void
tc_newtclass_req_set_options_flower_key_mpls_label(struct tc_newtclass_req *req,
						   __u32 key_mpls_label /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_label = 1;
	req->options.flower.key_mpls_label = key_mpls_label;
}
static inline void
tc_newtclass_req_set_options_flower_key_tcp_flags(struct tc_newtclass_req *req,
						  __u16 key_tcp_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_flags = 1;
	req->options.flower.key_tcp_flags = key_tcp_flags;
}
static inline void
tc_newtclass_req_set_options_flower_key_tcp_flags_mask(struct tc_newtclass_req *req,
						       __u16 key_tcp_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_flags_mask = 1;
	req->options.flower.key_tcp_flags_mask = key_tcp_flags_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_ip_tos(struct tc_newtclass_req *req,
					       __u8 key_ip_tos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_tos = 1;
	req->options.flower.key_ip_tos = key_ip_tos;
}
static inline void
tc_newtclass_req_set_options_flower_key_ip_tos_mask(struct tc_newtclass_req *req,
						    __u8 key_ip_tos_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_tos_mask = 1;
	req->options.flower.key_ip_tos_mask = key_ip_tos_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_ip_ttl(struct tc_newtclass_req *req,
					       __u8 key_ip_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_ttl = 1;
	req->options.flower.key_ip_ttl = key_ip_ttl;
}
static inline void
tc_newtclass_req_set_options_flower_key_ip_ttl_mask(struct tc_newtclass_req *req,
						    __u8 key_ip_ttl_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_ttl_mask = 1;
	req->options.flower.key_ip_ttl_mask = key_ip_ttl_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_cvlan_id(struct tc_newtclass_req *req,
						 __u16 key_cvlan_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_id = 1;
	req->options.flower.key_cvlan_id = key_cvlan_id;
}
static inline void
tc_newtclass_req_set_options_flower_key_cvlan_prio(struct tc_newtclass_req *req,
						   __u8 key_cvlan_prio)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_prio = 1;
	req->options.flower.key_cvlan_prio = key_cvlan_prio;
}
static inline void
tc_newtclass_req_set_options_flower_key_cvlan_eth_type(struct tc_newtclass_req *req,
						       __u16 key_cvlan_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_eth_type = 1;
	req->options.flower.key_cvlan_eth_type = key_cvlan_eth_type;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ip_tos(struct tc_newtclass_req *req,
						   __u8 key_enc_ip_tos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_tos = 1;
	req->options.flower.key_enc_ip_tos = key_enc_ip_tos;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ip_tos_mask(struct tc_newtclass_req *req,
							__u8 key_enc_ip_tos_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_tos_mask = 1;
	req->options.flower.key_enc_ip_tos_mask = key_enc_ip_tos_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ip_ttl(struct tc_newtclass_req *req,
						   __u8 key_enc_ip_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_ttl = 1;
	req->options.flower.key_enc_ip_ttl = key_enc_ip_ttl;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_ip_ttl_mask(struct tc_newtclass_req *req,
							__u8 key_enc_ip_ttl_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_ttl_mask = 1;
	req->options.flower.key_enc_ip_ttl_mask = key_enc_ip_ttl_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_geneve_class(struct tc_newtclass_req *req,
							      __u16 class)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	req->options.flower.key_enc_opts.geneve._present.class = 1;
	req->options.flower.key_enc_opts.geneve.class = class;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_geneve_type(struct tc_newtclass_req *req,
							     __u8 type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	req->options.flower.key_enc_opts.geneve._present.type = 1;
	req->options.flower.key_enc_opts.geneve.type = type;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_geneve_data(struct tc_newtclass_req *req,
							     const void *data,
							     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	free(req->options.flower.key_enc_opts.geneve.data);
	req->options.flower.key_enc_opts.geneve._len.data = len;
	req->options.flower.key_enc_opts.geneve.data = malloc(req->options.flower.key_enc_opts.geneve._len.data);
	memcpy(req->options.flower.key_enc_opts.geneve.data, data, req->options.flower.key_enc_opts.geneve._len.data);
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_vxlan_gbp(struct tc_newtclass_req *req,
							   __u32 gbp)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.vxlan = 1;
	req->options.flower.key_enc_opts.vxlan._present.gbp = 1;
	req->options.flower.key_enc_opts.vxlan.gbp = gbp;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_erspan_ver(struct tc_newtclass_req *req,
							    __u8 ver)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.ver = 1;
	req->options.flower.key_enc_opts.erspan.ver = ver;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_erspan_index(struct tc_newtclass_req *req,
							      __u32 index)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.index = 1;
	req->options.flower.key_enc_opts.erspan.index = index;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_erspan_dir(struct tc_newtclass_req *req,
							    __u8 dir)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.dir = 1;
	req->options.flower.key_enc_opts.erspan.dir = dir;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_erspan_hwid(struct tc_newtclass_req *req,
							     __u8 hwid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.hwid = 1;
	req->options.flower.key_enc_opts.erspan.hwid = hwid;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_gtp_pdu_type(struct tc_newtclass_req *req,
							      __u8 pdu_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.gtp = 1;
	req->options.flower.key_enc_opts.gtp._present.pdu_type = 1;
	req->options.flower.key_enc_opts.gtp.pdu_type = pdu_type;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_gtp_qfi(struct tc_newtclass_req *req,
							 __u8 qfi)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.gtp = 1;
	req->options.flower.key_enc_opts.gtp._present.qfi = 1;
	req->options.flower.key_enc_opts.gtp.qfi = qfi;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_geneve_class(struct tc_newtclass_req *req,
								   __u16 class)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	req->options.flower.key_enc_opts_mask.geneve._present.class = 1;
	req->options.flower.key_enc_opts_mask.geneve.class = class;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_geneve_type(struct tc_newtclass_req *req,
								  __u8 type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	req->options.flower.key_enc_opts_mask.geneve._present.type = 1;
	req->options.flower.key_enc_opts_mask.geneve.type = type;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_geneve_data(struct tc_newtclass_req *req,
								  const void *data,
								  size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	free(req->options.flower.key_enc_opts_mask.geneve.data);
	req->options.flower.key_enc_opts_mask.geneve._len.data = len;
	req->options.flower.key_enc_opts_mask.geneve.data = malloc(req->options.flower.key_enc_opts_mask.geneve._len.data);
	memcpy(req->options.flower.key_enc_opts_mask.geneve.data, data, req->options.flower.key_enc_opts_mask.geneve._len.data);
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_vxlan_gbp(struct tc_newtclass_req *req,
								__u32 gbp)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.vxlan = 1;
	req->options.flower.key_enc_opts_mask.vxlan._present.gbp = 1;
	req->options.flower.key_enc_opts_mask.vxlan.gbp = gbp;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_erspan_ver(struct tc_newtclass_req *req,
								 __u8 ver)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.ver = 1;
	req->options.flower.key_enc_opts_mask.erspan.ver = ver;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_erspan_index(struct tc_newtclass_req *req,
								   __u32 index)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.index = 1;
	req->options.flower.key_enc_opts_mask.erspan.index = index;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_erspan_dir(struct tc_newtclass_req *req,
								 __u8 dir)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.dir = 1;
	req->options.flower.key_enc_opts_mask.erspan.dir = dir;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_erspan_hwid(struct tc_newtclass_req *req,
								  __u8 hwid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.hwid = 1;
	req->options.flower.key_enc_opts_mask.erspan.hwid = hwid;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_gtp_pdu_type(struct tc_newtclass_req *req,
								   __u8 pdu_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.gtp = 1;
	req->options.flower.key_enc_opts_mask.gtp._present.pdu_type = 1;
	req->options.flower.key_enc_opts_mask.gtp.pdu_type = pdu_type;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_opts_mask_gtp_qfi(struct tc_newtclass_req *req,
							      __u8 qfi)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.gtp = 1;
	req->options.flower.key_enc_opts_mask.gtp._present.qfi = 1;
	req->options.flower.key_enc_opts_mask.gtp.qfi = qfi;
}
static inline void
tc_newtclass_req_set_options_flower_in_hw_count(struct tc_newtclass_req *req,
						__u32 in_hw_count)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.in_hw_count = 1;
	req->options.flower.in_hw_count = in_hw_count;
}
static inline void
tc_newtclass_req_set_options_flower_key_port_src_min(struct tc_newtclass_req *req,
						     __u16 key_port_src_min /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_src_min = 1;
	req->options.flower.key_port_src_min = key_port_src_min;
}
static inline void
tc_newtclass_req_set_options_flower_key_port_src_max(struct tc_newtclass_req *req,
						     __u16 key_port_src_max /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_src_max = 1;
	req->options.flower.key_port_src_max = key_port_src_max;
}
static inline void
tc_newtclass_req_set_options_flower_key_port_dst_min(struct tc_newtclass_req *req,
						     __u16 key_port_dst_min /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_dst_min = 1;
	req->options.flower.key_port_dst_min = key_port_dst_min;
}
static inline void
tc_newtclass_req_set_options_flower_key_port_dst_max(struct tc_newtclass_req *req,
						     __u16 key_port_dst_max /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_dst_max = 1;
	req->options.flower.key_port_dst_max = key_port_dst_max;
}
static inline void
tc_newtclass_req_set_options_flower_key_ct_state(struct tc_newtclass_req *req,
						 __u16 key_ct_state)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_state = 1;
	req->options.flower.key_ct_state = key_ct_state;
}
static inline void
tc_newtclass_req_set_options_flower_key_ct_state_mask(struct tc_newtclass_req *req,
						      __u16 key_ct_state_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_state_mask = 1;
	req->options.flower.key_ct_state_mask = key_ct_state_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_ct_zone(struct tc_newtclass_req *req,
						__u16 key_ct_zone)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_zone = 1;
	req->options.flower.key_ct_zone = key_ct_zone;
}
static inline void
tc_newtclass_req_set_options_flower_key_ct_zone_mask(struct tc_newtclass_req *req,
						     __u16 key_ct_zone_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_zone_mask = 1;
	req->options.flower.key_ct_zone_mask = key_ct_zone_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_ct_mark(struct tc_newtclass_req *req,
						__u32 key_ct_mark)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_mark = 1;
	req->options.flower.key_ct_mark = key_ct_mark;
}
static inline void
tc_newtclass_req_set_options_flower_key_ct_mark_mask(struct tc_newtclass_req *req,
						     __u32 key_ct_mark_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_mark_mask = 1;
	req->options.flower.key_ct_mark_mask = key_ct_mark_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_ct_labels(struct tc_newtclass_req *req,
						  const void *key_ct_labels,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ct_labels);
	req->options.flower._len.key_ct_labels = len;
	req->options.flower.key_ct_labels = malloc(req->options.flower._len.key_ct_labels);
	memcpy(req->options.flower.key_ct_labels, key_ct_labels, req->options.flower._len.key_ct_labels);
}
static inline void
tc_newtclass_req_set_options_flower_key_ct_labels_mask(struct tc_newtclass_req *req,
						       const void *key_ct_labels_mask,
						       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ct_labels_mask);
	req->options.flower._len.key_ct_labels_mask = len;
	req->options.flower.key_ct_labels_mask = malloc(req->options.flower._len.key_ct_labels_mask);
	memcpy(req->options.flower.key_ct_labels_mask, key_ct_labels_mask, req->options.flower._len.key_ct_labels_mask);
}
static inline void
tc_newtclass_req_set_options_flower_key_mpls_opts_lse_depth(struct tc_newtclass_req *req,
							    __u8 lse_depth)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_depth = 1;
	req->options.flower.key_mpls_opts.lse_depth = lse_depth;
}
static inline void
tc_newtclass_req_set_options_flower_key_mpls_opts_lse_ttl(struct tc_newtclass_req *req,
							  __u8 lse_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_ttl = 1;
	req->options.flower.key_mpls_opts.lse_ttl = lse_ttl;
}
static inline void
tc_newtclass_req_set_options_flower_key_mpls_opts_lse_bos(struct tc_newtclass_req *req,
							  __u8 lse_bos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_bos = 1;
	req->options.flower.key_mpls_opts.lse_bos = lse_bos;
}
static inline void
tc_newtclass_req_set_options_flower_key_mpls_opts_lse_tc(struct tc_newtclass_req *req,
							 __u8 lse_tc)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_tc = 1;
	req->options.flower.key_mpls_opts.lse_tc = lse_tc;
}
static inline void
tc_newtclass_req_set_options_flower_key_mpls_opts_lse_label(struct tc_newtclass_req *req,
							    __u32 lse_label)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_label = 1;
	req->options.flower.key_mpls_opts.lse_label = lse_label;
}
static inline void
tc_newtclass_req_set_options_flower_key_hash(struct tc_newtclass_req *req,
					     __u32 key_hash)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_hash = 1;
	req->options.flower.key_hash = key_hash;
}
static inline void
tc_newtclass_req_set_options_flower_key_hash_mask(struct tc_newtclass_req *req,
						  __u32 key_hash_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_hash_mask = 1;
	req->options.flower.key_hash_mask = key_hash_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_num_of_vlans(struct tc_newtclass_req *req,
						     __u8 key_num_of_vlans)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_num_of_vlans = 1;
	req->options.flower.key_num_of_vlans = key_num_of_vlans;
}
static inline void
tc_newtclass_req_set_options_flower_key_pppoe_sid(struct tc_newtclass_req *req,
						  __u16 key_pppoe_sid /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_pppoe_sid = 1;
	req->options.flower.key_pppoe_sid = key_pppoe_sid;
}
static inline void
tc_newtclass_req_set_options_flower_key_ppp_proto(struct tc_newtclass_req *req,
						  __u16 key_ppp_proto /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ppp_proto = 1;
	req->options.flower.key_ppp_proto = key_ppp_proto;
}
static inline void
tc_newtclass_req_set_options_flower_key_l2tpv3_sid(struct tc_newtclass_req *req,
						   __u32 key_l2tpv3_sid /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_l2tpv3_sid = 1;
	req->options.flower.key_l2tpv3_sid = key_l2tpv3_sid;
}
static inline void
tc_newtclass_req_set_options_flower_l2_miss(struct tc_newtclass_req *req,
					    __u8 l2_miss)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.l2_miss = 1;
	req->options.flower.l2_miss = l2_miss;
}
static inline void
tc_newtclass_req_set_options_flower_key_cfm_md_level(struct tc_newtclass_req *req,
						     __u8 md_level)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cfm = 1;
	req->options.flower.key_cfm._present.md_level = 1;
	req->options.flower.key_cfm.md_level = md_level;
}
static inline void
tc_newtclass_req_set_options_flower_key_cfm_opcode(struct tc_newtclass_req *req,
						   __u8 opcode)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cfm = 1;
	req->options.flower.key_cfm._present.opcode = 1;
	req->options.flower.key_cfm.opcode = opcode;
}
static inline void
tc_newtclass_req_set_options_flower_key_spi(struct tc_newtclass_req *req,
					    __u32 key_spi /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_spi = 1;
	req->options.flower.key_spi = key_spi;
}
static inline void
tc_newtclass_req_set_options_flower_key_spi_mask(struct tc_newtclass_req *req,
						 __u32 key_spi_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_spi_mask = 1;
	req->options.flower.key_spi_mask = key_spi_mask;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_flags(struct tc_newtclass_req *req,
						  __u32 key_enc_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_flags = 1;
	req->options.flower.key_enc_flags = key_enc_flags;
}
static inline void
tc_newtclass_req_set_options_flower_key_enc_flags_mask(struct tc_newtclass_req *req,
						       __u32 key_enc_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_flags_mask = 1;
	req->options.flower.key_enc_flags_mask = key_enc_flags_mask;
}
static inline void
tc_newtclass_req_set_options_fq_plimit(struct tc_newtclass_req *req,
				       __u32 plimit)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.plimit = 1;
	req->options.fq.plimit = plimit;
}
static inline void
tc_newtclass_req_set_options_fq_flow_plimit(struct tc_newtclass_req *req,
					    __u32 flow_plimit)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_plimit = 1;
	req->options.fq.flow_plimit = flow_plimit;
}
static inline void
tc_newtclass_req_set_options_fq_quantum(struct tc_newtclass_req *req,
					__u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.quantum = 1;
	req->options.fq.quantum = quantum;
}
static inline void
tc_newtclass_req_set_options_fq_initial_quantum(struct tc_newtclass_req *req,
						__u32 initial_quantum)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.initial_quantum = 1;
	req->options.fq.initial_quantum = initial_quantum;
}
static inline void
tc_newtclass_req_set_options_fq_rate_enable(struct tc_newtclass_req *req,
					    __u32 rate_enable)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.rate_enable = 1;
	req->options.fq.rate_enable = rate_enable;
}
static inline void
tc_newtclass_req_set_options_fq_flow_default_rate(struct tc_newtclass_req *req,
						  __u32 flow_default_rate)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_default_rate = 1;
	req->options.fq.flow_default_rate = flow_default_rate;
}
static inline void
tc_newtclass_req_set_options_fq_flow_max_rate(struct tc_newtclass_req *req,
					      __u32 flow_max_rate)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_max_rate = 1;
	req->options.fq.flow_max_rate = flow_max_rate;
}
static inline void
tc_newtclass_req_set_options_fq_buckets_log(struct tc_newtclass_req *req,
					    __u32 buckets_log)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.buckets_log = 1;
	req->options.fq.buckets_log = buckets_log;
}
static inline void
tc_newtclass_req_set_options_fq_flow_refill_delay(struct tc_newtclass_req *req,
						  __u32 flow_refill_delay)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_refill_delay = 1;
	req->options.fq.flow_refill_delay = flow_refill_delay;
}
static inline void
tc_newtclass_req_set_options_fq_orphan_mask(struct tc_newtclass_req *req,
					    __u32 orphan_mask)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.orphan_mask = 1;
	req->options.fq.orphan_mask = orphan_mask;
}
static inline void
tc_newtclass_req_set_options_fq_low_rate_threshold(struct tc_newtclass_req *req,
						   __u32 low_rate_threshold)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.low_rate_threshold = 1;
	req->options.fq.low_rate_threshold = low_rate_threshold;
}
static inline void
tc_newtclass_req_set_options_fq_ce_threshold(struct tc_newtclass_req *req,
					     __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.ce_threshold = 1;
	req->options.fq.ce_threshold = ce_threshold;
}
static inline void
tc_newtclass_req_set_options_fq_timer_slack(struct tc_newtclass_req *req,
					    __u32 timer_slack)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.timer_slack = 1;
	req->options.fq.timer_slack = timer_slack;
}
static inline void
tc_newtclass_req_set_options_fq_horizon(struct tc_newtclass_req *req,
					__u32 horizon)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.horizon = 1;
	req->options.fq.horizon = horizon;
}
static inline void
tc_newtclass_req_set_options_fq_horizon_drop(struct tc_newtclass_req *req,
					     __u8 horizon_drop)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.horizon_drop = 1;
	req->options.fq.horizon_drop = horizon_drop;
}
static inline void
tc_newtclass_req_set_options_fq_priomap(struct tc_newtclass_req *req,
					const void *priomap, size_t len)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	free(req->options.fq.priomap);
	req->options.fq._len.priomap = len;
	req->options.fq.priomap = malloc(req->options.fq._len.priomap);
	memcpy(req->options.fq.priomap, priomap, req->options.fq._len.priomap);
}
static inline void
tc_newtclass_req_set_options_fq_weights(struct tc_newtclass_req *req,
					__s32 *weights, size_t count)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	free(req->options.fq.weights);
	req->options.fq._count.weights = count;
	count *= sizeof(__s32);
	req->options.fq.weights = malloc(count);
	memcpy(req->options.fq.weights, weights, count);
}
static inline void
tc_newtclass_req_set_options_fq_codel_target(struct tc_newtclass_req *req,
					     __u32 target)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.target = 1;
	req->options.fq_codel.target = target;
}
static inline void
tc_newtclass_req_set_options_fq_codel_limit(struct tc_newtclass_req *req,
					    __u32 limit)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.limit = 1;
	req->options.fq_codel.limit = limit;
}
static inline void
tc_newtclass_req_set_options_fq_codel_interval(struct tc_newtclass_req *req,
					       __u32 interval)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.interval = 1;
	req->options.fq_codel.interval = interval;
}
static inline void
tc_newtclass_req_set_options_fq_codel_ecn(struct tc_newtclass_req *req,
					  __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ecn = 1;
	req->options.fq_codel.ecn = ecn;
}
static inline void
tc_newtclass_req_set_options_fq_codel_flows(struct tc_newtclass_req *req,
					    __u32 flows)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.flows = 1;
	req->options.fq_codel.flows = flows;
}
static inline void
tc_newtclass_req_set_options_fq_codel_quantum(struct tc_newtclass_req *req,
					      __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.quantum = 1;
	req->options.fq_codel.quantum = quantum;
}
static inline void
tc_newtclass_req_set_options_fq_codel_ce_threshold(struct tc_newtclass_req *req,
						   __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold = 1;
	req->options.fq_codel.ce_threshold = ce_threshold;
}
static inline void
tc_newtclass_req_set_options_fq_codel_drop_batch_size(struct tc_newtclass_req *req,
						      __u32 drop_batch_size)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.drop_batch_size = 1;
	req->options.fq_codel.drop_batch_size = drop_batch_size;
}
static inline void
tc_newtclass_req_set_options_fq_codel_memory_limit(struct tc_newtclass_req *req,
						   __u32 memory_limit)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.memory_limit = 1;
	req->options.fq_codel.memory_limit = memory_limit;
}
static inline void
tc_newtclass_req_set_options_fq_codel_ce_threshold_selector(struct tc_newtclass_req *req,
							    __u8 ce_threshold_selector)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold_selector = 1;
	req->options.fq_codel.ce_threshold_selector = ce_threshold_selector;
}
static inline void
tc_newtclass_req_set_options_fq_codel_ce_threshold_mask(struct tc_newtclass_req *req,
							__u8 ce_threshold_mask)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold_mask = 1;
	req->options.fq_codel.ce_threshold_mask = ce_threshold_mask;
}
static inline void
tc_newtclass_req_set_options_fq_pie_limit(struct tc_newtclass_req *req,
					  __u32 limit)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.limit = 1;
	req->options.fq_pie.limit = limit;
}
static inline void
tc_newtclass_req_set_options_fq_pie_flows(struct tc_newtclass_req *req,
					  __u32 flows)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.flows = 1;
	req->options.fq_pie.flows = flows;
}
static inline void
tc_newtclass_req_set_options_fq_pie_target(struct tc_newtclass_req *req,
					   __u32 target)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.target = 1;
	req->options.fq_pie.target = target;
}
static inline void
tc_newtclass_req_set_options_fq_pie_tupdate(struct tc_newtclass_req *req,
					    __u32 tupdate)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.tupdate = 1;
	req->options.fq_pie.tupdate = tupdate;
}
static inline void
tc_newtclass_req_set_options_fq_pie_alpha(struct tc_newtclass_req *req,
					  __u32 alpha)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.alpha = 1;
	req->options.fq_pie.alpha = alpha;
}
static inline void
tc_newtclass_req_set_options_fq_pie_beta(struct tc_newtclass_req *req,
					 __u32 beta)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.beta = 1;
	req->options.fq_pie.beta = beta;
}
static inline void
tc_newtclass_req_set_options_fq_pie_quantum(struct tc_newtclass_req *req,
					    __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.quantum = 1;
	req->options.fq_pie.quantum = quantum;
}
static inline void
tc_newtclass_req_set_options_fq_pie_memory_limit(struct tc_newtclass_req *req,
						 __u32 memory_limit)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.memory_limit = 1;
	req->options.fq_pie.memory_limit = memory_limit;
}
static inline void
tc_newtclass_req_set_options_fq_pie_ecn_prob(struct tc_newtclass_req *req,
					     __u32 ecn_prob)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.ecn_prob = 1;
	req->options.fq_pie.ecn_prob = ecn_prob;
}
static inline void
tc_newtclass_req_set_options_fq_pie_ecn(struct tc_newtclass_req *req,
					__u32 ecn)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.ecn = 1;
	req->options.fq_pie.ecn = ecn;
}
static inline void
tc_newtclass_req_set_options_fq_pie_bytemode(struct tc_newtclass_req *req,
					     __u32 bytemode)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.bytemode = 1;
	req->options.fq_pie.bytemode = bytemode;
}
static inline void
tc_newtclass_req_set_options_fq_pie_dq_rate_estimator(struct tc_newtclass_req *req,
						      __u32 dq_rate_estimator)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.dq_rate_estimator = 1;
	req->options.fq_pie.dq_rate_estimator = dq_rate_estimator;
}
static inline void
tc_newtclass_req_set_options_fw_classid(struct tc_newtclass_req *req,
					__u32 classid)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.classid = 1;
	req->options.fw.classid = classid;
}
static inline void
tc_newtclass_req_set_options_fw_police_tbf(struct tc_newtclass_req *req,
					   const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.tbf);
	req->options.fw.police._len.tbf = len;
	req->options.fw.police.tbf = malloc(req->options.fw.police._len.tbf);
	memcpy(req->options.fw.police.tbf, tbf, req->options.fw.police._len.tbf);
}
static inline void
tc_newtclass_req_set_options_fw_police_rate(struct tc_newtclass_req *req,
					    const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.rate);
	req->options.fw.police._len.rate = len;
	req->options.fw.police.rate = malloc(req->options.fw.police._len.rate);
	memcpy(req->options.fw.police.rate, rate, req->options.fw.police._len.rate);
}
static inline void
tc_newtclass_req_set_options_fw_police_peakrate(struct tc_newtclass_req *req,
						const void *peakrate,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.peakrate);
	req->options.fw.police._len.peakrate = len;
	req->options.fw.police.peakrate = malloc(req->options.fw.police._len.peakrate);
	memcpy(req->options.fw.police.peakrate, peakrate, req->options.fw.police._len.peakrate);
}
static inline void
tc_newtclass_req_set_options_fw_police_avrate(struct tc_newtclass_req *req,
					      __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.avrate = 1;
	req->options.fw.police.avrate = avrate;
}
static inline void
tc_newtclass_req_set_options_fw_police_result(struct tc_newtclass_req *req,
					      __u32 result)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.result = 1;
	req->options.fw.police.result = result;
}
static inline void
tc_newtclass_req_set_options_fw_police_tm(struct tc_newtclass_req *req,
					  const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.tm);
	req->options.fw.police._len.tm = len;
	req->options.fw.police.tm = malloc(req->options.fw.police._len.tm);
	memcpy(req->options.fw.police.tm, tm, req->options.fw.police._len.tm);
}
static inline void
tc_newtclass_req_set_options_fw_police_rate64(struct tc_newtclass_req *req,
					      __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.rate64 = 1;
	req->options.fw.police.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_fw_police_peakrate64(struct tc_newtclass_req *req,
						  __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.peakrate64 = 1;
	req->options.fw.police.peakrate64 = peakrate64;
}
static inline void
tc_newtclass_req_set_options_fw_police_pktrate64(struct tc_newtclass_req *req,
						 __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.pktrate64 = 1;
	req->options.fw.police.pktrate64 = pktrate64;
}
static inline void
tc_newtclass_req_set_options_fw_police_pktburst64(struct tc_newtclass_req *req,
						  __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.pktburst64 = 1;
	req->options.fw.police.pktburst64 = pktburst64;
}
static inline void
tc_newtclass_req_set_options_fw_indev(struct tc_newtclass_req *req,
				      const char *indev)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	free(req->options.fw.indev);
	req->options.fw._len.indev = strlen(indev);
	req->options.fw.indev = malloc(req->options.fw._len.indev + 1);
	memcpy(req->options.fw.indev, indev, req->options.fw._len.indev);
	req->options.fw.indev[req->options.fw._len.indev] = 0;
}
static inline void
__tc_newtclass_req_set_options_fw_act(struct tc_newtclass_req *req,
				      struct tc_act_attrs *act,
				      unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	free(req->options.fw.act);
	req->options.fw.act = act;
	req->options.fw._count.act = n_act;
}
static inline void
tc_newtclass_req_set_options_fw_mask(struct tc_newtclass_req *req, __u32 mask)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.mask = 1;
	req->options.fw.mask = mask;
}
static inline void
tc_newtclass_req_set_options_gred_parms(struct tc_newtclass_req *req,
					const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.parms);
	req->options.gred._len.parms = len;
	req->options.gred.parms = malloc(req->options.gred._len.parms);
	memcpy(req->options.gred.parms, parms, req->options.gred._len.parms);
}
static inline void
tc_newtclass_req_set_options_gred_stab(struct tc_newtclass_req *req,
				       __u8 *stab, size_t count)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.stab);
	req->options.gred._count.stab = count;
	count *= sizeof(__u8);
	req->options.gred.stab = malloc(count);
	memcpy(req->options.gred.stab, stab, count);
}
static inline void
tc_newtclass_req_set_options_gred_dps(struct tc_newtclass_req *req,
				      const void *dps, size_t len)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.dps);
	req->options.gred._len.dps = len;
	req->options.gred.dps = malloc(req->options.gred._len.dps);
	memcpy(req->options.gred.dps, dps, req->options.gred._len.dps);
}
static inline void
tc_newtclass_req_set_options_gred_max_p(struct tc_newtclass_req *req,
					__u32 *max_p, size_t count)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.max_p);
	req->options.gred._count.max_p = count;
	count *= sizeof(__u32);
	req->options.gred.max_p = malloc(count);
	memcpy(req->options.gred.max_p, max_p, count);
}
static inline void
tc_newtclass_req_set_options_gred_limit(struct tc_newtclass_req *req,
					__u32 limit)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	req->options.gred._present.limit = 1;
	req->options.gred.limit = limit;
}
static inline void
__tc_newtclass_req_set_options_gred_vq_list_entry(struct tc_newtclass_req *req,
						  struct tc_tca_gred_vq_entry_attrs *entry,
						  unsigned int n_entry)
{
	unsigned int i;

	req->_present.options = 1;
	req->options._present.gred = 1;
	req->options.gred._present.vq_list = 1;
	for (i = 0; i < req->options.gred.vq_list._count.entry; i++)
		tc_tca_gred_vq_entry_attrs_free(&req->options.gred.vq_list.entry[i]);
	free(req->options.gred.vq_list.entry);
	req->options.gred.vq_list.entry = entry;
	req->options.gred.vq_list._count.entry = n_entry;
}
static inline void
tc_newtclass_req_set_options_hfsc(struct tc_newtclass_req *req,
				  const void *hfsc, size_t len)
{
	req->_present.options = 1;
	free(req->options.hfsc);
	req->options._len.hfsc = len;
	req->options.hfsc = malloc(req->options._len.hfsc);
	memcpy(req->options.hfsc, hfsc, req->options._len.hfsc);
}
static inline void
tc_newtclass_req_set_options_hhf_backlog_limit(struct tc_newtclass_req *req,
					       __u32 backlog_limit)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.backlog_limit = 1;
	req->options.hhf.backlog_limit = backlog_limit;
}
static inline void
tc_newtclass_req_set_options_hhf_quantum(struct tc_newtclass_req *req,
					 __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.quantum = 1;
	req->options.hhf.quantum = quantum;
}
static inline void
tc_newtclass_req_set_options_hhf_hh_flows_limit(struct tc_newtclass_req *req,
						__u32 hh_flows_limit)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.hh_flows_limit = 1;
	req->options.hhf.hh_flows_limit = hh_flows_limit;
}
static inline void
tc_newtclass_req_set_options_hhf_reset_timeout(struct tc_newtclass_req *req,
					       __u32 reset_timeout)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.reset_timeout = 1;
	req->options.hhf.reset_timeout = reset_timeout;
}
static inline void
tc_newtclass_req_set_options_hhf_admit_bytes(struct tc_newtclass_req *req,
					     __u32 admit_bytes)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.admit_bytes = 1;
	req->options.hhf.admit_bytes = admit_bytes;
}
static inline void
tc_newtclass_req_set_options_hhf_evict_timeout(struct tc_newtclass_req *req,
					       __u32 evict_timeout)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.evict_timeout = 1;
	req->options.hhf.evict_timeout = evict_timeout;
}
static inline void
tc_newtclass_req_set_options_hhf_non_hh_weight(struct tc_newtclass_req *req,
					       __u32 non_hh_weight)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.non_hh_weight = 1;
	req->options.hhf.non_hh_weight = non_hh_weight;
}
static inline void
tc_newtclass_req_set_options_htb_parms(struct tc_newtclass_req *req,
				       const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.parms);
	req->options.htb._len.parms = len;
	req->options.htb.parms = malloc(req->options.htb._len.parms);
	memcpy(req->options.htb.parms, parms, req->options.htb._len.parms);
}
static inline void
tc_newtclass_req_set_options_htb_init(struct tc_newtclass_req *req,
				      const void *init, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.init);
	req->options.htb._len.init = len;
	req->options.htb.init = malloc(req->options.htb._len.init);
	memcpy(req->options.htb.init, init, req->options.htb._len.init);
}
static inline void
tc_newtclass_req_set_options_htb_ctab(struct tc_newtclass_req *req,
				      const void *ctab, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.ctab);
	req->options.htb._len.ctab = len;
	req->options.htb.ctab = malloc(req->options.htb._len.ctab);
	memcpy(req->options.htb.ctab, ctab, req->options.htb._len.ctab);
}
static inline void
tc_newtclass_req_set_options_htb_rtab(struct tc_newtclass_req *req,
				      const void *rtab, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.rtab);
	req->options.htb._len.rtab = len;
	req->options.htb.rtab = malloc(req->options.htb._len.rtab);
	memcpy(req->options.htb.rtab, rtab, req->options.htb._len.rtab);
}
static inline void
tc_newtclass_req_set_options_htb_direct_qlen(struct tc_newtclass_req *req,
					     __u32 direct_qlen)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.direct_qlen = 1;
	req->options.htb.direct_qlen = direct_qlen;
}
static inline void
tc_newtclass_req_set_options_htb_rate64(struct tc_newtclass_req *req,
					__u64 rate64)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.rate64 = 1;
	req->options.htb.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_htb_ceil64(struct tc_newtclass_req *req,
					__u64 ceil64)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.ceil64 = 1;
	req->options.htb.ceil64 = ceil64;
}
static inline void
tc_newtclass_req_set_options_htb_offload(struct tc_newtclass_req *req)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.offload = 1;
}
static inline void
tc_newtclass_req_set_options_ingress(struct tc_newtclass_req *req)
{
	req->_present.options = 1;
	req->options._present.ingress = 1;
}
static inline void
tc_newtclass_req_set_options_matchall_classid(struct tc_newtclass_req *req,
					      __u32 classid)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	req->options.matchall._present.classid = 1;
	req->options.matchall.classid = classid;
}
static inline void
__tc_newtclass_req_set_options_matchall_act(struct tc_newtclass_req *req,
					    struct tc_act_attrs *act,
					    unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	free(req->options.matchall.act);
	req->options.matchall.act = act;
	req->options.matchall._count.act = n_act;
}
static inline void
tc_newtclass_req_set_options_matchall_flags(struct tc_newtclass_req *req,
					    __u32 flags)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	req->options.matchall._present.flags = 1;
	req->options.matchall.flags = flags;
}
static inline void
tc_newtclass_req_set_options_matchall_pcnt(struct tc_newtclass_req *req,
					   const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	free(req->options.matchall.pcnt);
	req->options.matchall._len.pcnt = len;
	req->options.matchall.pcnt = malloc(req->options.matchall._len.pcnt);
	memcpy(req->options.matchall.pcnt, pcnt, req->options.matchall._len.pcnt);
}
static inline void
tc_newtclass_req_set_options_mq(struct tc_newtclass_req *req)
{
	req->_present.options = 1;
	req->options._present.mq = 1;
}
static inline void
tc_newtclass_req_set_options_mqprio(struct tc_newtclass_req *req,
				    const void *mqprio, size_t len)
{
	req->_present.options = 1;
	free(req->options.mqprio);
	req->options._len.mqprio = len;
	req->options.mqprio = malloc(req->options._len.mqprio);
	memcpy(req->options.mqprio, mqprio, req->options._len.mqprio);
}
static inline void
tc_newtclass_req_set_options_multiq(struct tc_newtclass_req *req,
				    const void *multiq, size_t len)
{
	req->_present.options = 1;
	free(req->options.multiq);
	req->options._len.multiq = len;
	req->options.multiq = malloc(req->options._len.multiq);
	memcpy(req->options.multiq, multiq, req->options._len.multiq);
}
static inline void
tc_newtclass_req_set_options_netem_corr(struct tc_newtclass_req *req,
					const void *corr, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.corr);
	req->options.netem._len.corr = len;
	req->options.netem.corr = malloc(req->options.netem._len.corr);
	memcpy(req->options.netem.corr, corr, req->options.netem._len.corr);
}
static inline void
tc_newtclass_req_set_options_netem_delay_dist(struct tc_newtclass_req *req,
					      __s16 *delay_dist, size_t count)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.delay_dist);
	req->options.netem._count.delay_dist = count;
	count *= sizeof(__s16);
	req->options.netem.delay_dist = malloc(count);
	memcpy(req->options.netem.delay_dist, delay_dist, count);
}
static inline void
tc_newtclass_req_set_options_netem_reorder(struct tc_newtclass_req *req,
					   const void *reorder, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.reorder);
	req->options.netem._len.reorder = len;
	req->options.netem.reorder = malloc(req->options.netem._len.reorder);
	memcpy(req->options.netem.reorder, reorder, req->options.netem._len.reorder);
}
static inline void
tc_newtclass_req_set_options_netem_corrupt(struct tc_newtclass_req *req,
					   const void *corrupt, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.corrupt);
	req->options.netem._len.corrupt = len;
	req->options.netem.corrupt = malloc(req->options.netem._len.corrupt);
	memcpy(req->options.netem.corrupt, corrupt, req->options.netem._len.corrupt);
}
static inline void
tc_newtclass_req_set_options_netem_loss_gi(struct tc_newtclass_req *req,
					   const void *gi, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.loss = 1;
	free(req->options.netem.loss.gi);
	req->options.netem.loss._len.gi = len;
	req->options.netem.loss.gi = malloc(req->options.netem.loss._len.gi);
	memcpy(req->options.netem.loss.gi, gi, req->options.netem.loss._len.gi);
}
static inline void
tc_newtclass_req_set_options_netem_loss_ge(struct tc_newtclass_req *req,
					   const void *ge, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.loss = 1;
	free(req->options.netem.loss.ge);
	req->options.netem.loss._len.ge = len;
	req->options.netem.loss.ge = malloc(req->options.netem.loss._len.ge);
	memcpy(req->options.netem.loss.ge, ge, req->options.netem.loss._len.ge);
}
static inline void
tc_newtclass_req_set_options_netem_rate(struct tc_newtclass_req *req,
					const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.rate);
	req->options.netem._len.rate = len;
	req->options.netem.rate = malloc(req->options.netem._len.rate);
	memcpy(req->options.netem.rate, rate, req->options.netem._len.rate);
}
static inline void
tc_newtclass_req_set_options_netem_ecn(struct tc_newtclass_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.ecn = 1;
	req->options.netem.ecn = ecn;
}
static inline void
tc_newtclass_req_set_options_netem_rate64(struct tc_newtclass_req *req,
					  __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.rate64 = 1;
	req->options.netem.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_netem_pad(struct tc_newtclass_req *req, __u32 pad)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.pad = 1;
	req->options.netem.pad = pad;
}
static inline void
tc_newtclass_req_set_options_netem_latency64(struct tc_newtclass_req *req,
					     __s64 latency64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.latency64 = 1;
	req->options.netem.latency64 = latency64;
}
static inline void
tc_newtclass_req_set_options_netem_jitter64(struct tc_newtclass_req *req,
					    __s64 jitter64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.jitter64 = 1;
	req->options.netem.jitter64 = jitter64;
}
static inline void
tc_newtclass_req_set_options_netem_slot(struct tc_newtclass_req *req,
					const void *slot, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.slot);
	req->options.netem._len.slot = len;
	req->options.netem.slot = malloc(req->options.netem._len.slot);
	memcpy(req->options.netem.slot, slot, req->options.netem._len.slot);
}
static inline void
tc_newtclass_req_set_options_netem_slot_dist(struct tc_newtclass_req *req,
					     __s16 *slot_dist, size_t count)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.slot_dist);
	req->options.netem._count.slot_dist = count;
	count *= sizeof(__s16);
	req->options.netem.slot_dist = malloc(count);
	memcpy(req->options.netem.slot_dist, slot_dist, count);
}
static inline void
tc_newtclass_req_set_options_netem_prng_seed(struct tc_newtclass_req *req,
					     __u64 prng_seed)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.prng_seed = 1;
	req->options.netem.prng_seed = prng_seed;
}
static inline void
tc_newtclass_req_set_options_pfifo(struct tc_newtclass_req *req,
				   const void *pfifo, size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo);
	req->options._len.pfifo = len;
	req->options.pfifo = malloc(req->options._len.pfifo);
	memcpy(req->options.pfifo, pfifo, req->options._len.pfifo);
}
static inline void
tc_newtclass_req_set_options_pfifo_fast(struct tc_newtclass_req *req,
					const void *pfifo_fast, size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo_fast);
	req->options._len.pfifo_fast = len;
	req->options.pfifo_fast = malloc(req->options._len.pfifo_fast);
	memcpy(req->options.pfifo_fast, pfifo_fast, req->options._len.pfifo_fast);
}
static inline void
tc_newtclass_req_set_options_pfifo_head_drop(struct tc_newtclass_req *req,
					     const void *pfifo_head_drop,
					     size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo_head_drop);
	req->options._len.pfifo_head_drop = len;
	req->options.pfifo_head_drop = malloc(req->options._len.pfifo_head_drop);
	memcpy(req->options.pfifo_head_drop, pfifo_head_drop, req->options._len.pfifo_head_drop);
}
static inline void
tc_newtclass_req_set_options_pie_target(struct tc_newtclass_req *req,
					__u32 target)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.target = 1;
	req->options.pie.target = target;
}
static inline void
tc_newtclass_req_set_options_pie_limit(struct tc_newtclass_req *req,
				       __u32 limit)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.limit = 1;
	req->options.pie.limit = limit;
}
static inline void
tc_newtclass_req_set_options_pie_tupdate(struct tc_newtclass_req *req,
					 __u32 tupdate)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.tupdate = 1;
	req->options.pie.tupdate = tupdate;
}
static inline void
tc_newtclass_req_set_options_pie_alpha(struct tc_newtclass_req *req,
				       __u32 alpha)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.alpha = 1;
	req->options.pie.alpha = alpha;
}
static inline void
tc_newtclass_req_set_options_pie_beta(struct tc_newtclass_req *req, __u32 beta)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.beta = 1;
	req->options.pie.beta = beta;
}
static inline void
tc_newtclass_req_set_options_pie_ecn(struct tc_newtclass_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.ecn = 1;
	req->options.pie.ecn = ecn;
}
static inline void
tc_newtclass_req_set_options_pie_bytemode(struct tc_newtclass_req *req,
					  __u32 bytemode)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.bytemode = 1;
	req->options.pie.bytemode = bytemode;
}
static inline void
tc_newtclass_req_set_options_pie_dq_rate_estimator(struct tc_newtclass_req *req,
						   __u32 dq_rate_estimator)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.dq_rate_estimator = 1;
	req->options.pie.dq_rate_estimator = dq_rate_estimator;
}
static inline void
tc_newtclass_req_set_options_plug(struct tc_newtclass_req *req,
				  const void *plug, size_t len)
{
	req->_present.options = 1;
	free(req->options.plug);
	req->options._len.plug = len;
	req->options.plug = malloc(req->options._len.plug);
	memcpy(req->options.plug, plug, req->options._len.plug);
}
static inline void
tc_newtclass_req_set_options_prio(struct tc_newtclass_req *req,
				  const void *prio, size_t len)
{
	req->_present.options = 1;
	free(req->options.prio);
	req->options._len.prio = len;
	req->options.prio = malloc(req->options._len.prio);
	memcpy(req->options.prio, prio, req->options._len.prio);
}
static inline void
tc_newtclass_req_set_options_qfq_weight(struct tc_newtclass_req *req,
					__u32 weight)
{
	req->_present.options = 1;
	req->options._present.qfq = 1;
	req->options.qfq._present.weight = 1;
	req->options.qfq.weight = weight;
}
static inline void
tc_newtclass_req_set_options_qfq_lmax(struct tc_newtclass_req *req, __u32 lmax)
{
	req->_present.options = 1;
	req->options._present.qfq = 1;
	req->options.qfq._present.lmax = 1;
	req->options.qfq.lmax = lmax;
}
static inline void
tc_newtclass_req_set_options_red_parms(struct tc_newtclass_req *req,
				       const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	free(req->options.red.parms);
	req->options.red._len.parms = len;
	req->options.red.parms = malloc(req->options.red._len.parms);
	memcpy(req->options.red.parms, parms, req->options.red._len.parms);
}
static inline void
tc_newtclass_req_set_options_red_stab(struct tc_newtclass_req *req,
				      const void *stab, size_t len)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	free(req->options.red.stab);
	req->options.red._len.stab = len;
	req->options.red.stab = malloc(req->options.red._len.stab);
	memcpy(req->options.red.stab, stab, req->options.red._len.stab);
}
static inline void
tc_newtclass_req_set_options_red_max_p(struct tc_newtclass_req *req,
				       __u32 max_p)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.max_p = 1;
	req->options.red.max_p = max_p;
}
static inline void
tc_newtclass_req_set_options_red_flags(struct tc_newtclass_req *req,
				       struct nla_bitfield32 *flags)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.flags = 1;
	memcpy(&req->options.red.flags, flags, sizeof(struct nla_bitfield32));
}
static inline void
tc_newtclass_req_set_options_red_early_drop_block(struct tc_newtclass_req *req,
						  __u32 early_drop_block)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.early_drop_block = 1;
	req->options.red.early_drop_block = early_drop_block;
}
static inline void
tc_newtclass_req_set_options_red_mark_block(struct tc_newtclass_req *req,
					    __u32 mark_block)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.mark_block = 1;
	req->options.red.mark_block = mark_block;
}
static inline void
tc_newtclass_req_set_options_route_classid(struct tc_newtclass_req *req,
					   __u32 classid)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.classid = 1;
	req->options.route.classid = classid;
}
static inline void
tc_newtclass_req_set_options_route_to(struct tc_newtclass_req *req, __u32 to)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.to = 1;
	req->options.route.to = to;
}
static inline void
tc_newtclass_req_set_options_route_from(struct tc_newtclass_req *req,
					__u32 from)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.from = 1;
	req->options.route.from = from;
}
static inline void
tc_newtclass_req_set_options_route_iif(struct tc_newtclass_req *req, __u32 iif)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.iif = 1;
	req->options.route.iif = iif;
}
static inline void
tc_newtclass_req_set_options_route_police_tbf(struct tc_newtclass_req *req,
					      const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.tbf);
	req->options.route.police._len.tbf = len;
	req->options.route.police.tbf = malloc(req->options.route.police._len.tbf);
	memcpy(req->options.route.police.tbf, tbf, req->options.route.police._len.tbf);
}
static inline void
tc_newtclass_req_set_options_route_police_rate(struct tc_newtclass_req *req,
					       const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.rate);
	req->options.route.police._len.rate = len;
	req->options.route.police.rate = malloc(req->options.route.police._len.rate);
	memcpy(req->options.route.police.rate, rate, req->options.route.police._len.rate);
}
static inline void
tc_newtclass_req_set_options_route_police_peakrate(struct tc_newtclass_req *req,
						   const void *peakrate,
						   size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.peakrate);
	req->options.route.police._len.peakrate = len;
	req->options.route.police.peakrate = malloc(req->options.route.police._len.peakrate);
	memcpy(req->options.route.police.peakrate, peakrate, req->options.route.police._len.peakrate);
}
static inline void
tc_newtclass_req_set_options_route_police_avrate(struct tc_newtclass_req *req,
						 __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.avrate = 1;
	req->options.route.police.avrate = avrate;
}
static inline void
tc_newtclass_req_set_options_route_police_result(struct tc_newtclass_req *req,
						 __u32 result)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.result = 1;
	req->options.route.police.result = result;
}
static inline void
tc_newtclass_req_set_options_route_police_tm(struct tc_newtclass_req *req,
					     const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.tm);
	req->options.route.police._len.tm = len;
	req->options.route.police.tm = malloc(req->options.route.police._len.tm);
	memcpy(req->options.route.police.tm, tm, req->options.route.police._len.tm);
}
static inline void
tc_newtclass_req_set_options_route_police_rate64(struct tc_newtclass_req *req,
						 __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.rate64 = 1;
	req->options.route.police.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_route_police_peakrate64(struct tc_newtclass_req *req,
						     __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.peakrate64 = 1;
	req->options.route.police.peakrate64 = peakrate64;
}
static inline void
tc_newtclass_req_set_options_route_police_pktrate64(struct tc_newtclass_req *req,
						    __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.pktrate64 = 1;
	req->options.route.police.pktrate64 = pktrate64;
}
static inline void
tc_newtclass_req_set_options_route_police_pktburst64(struct tc_newtclass_req *req,
						     __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.pktburst64 = 1;
	req->options.route.police.pktburst64 = pktburst64;
}
static inline void
__tc_newtclass_req_set_options_route_act(struct tc_newtclass_req *req,
					 struct tc_act_attrs *act,
					 unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	free(req->options.route.act);
	req->options.route.act = act;
	req->options.route._count.act = n_act;
}
static inline void
tc_newtclass_req_set_options_sfb(struct tc_newtclass_req *req, const void *sfb,
				 size_t len)
{
	req->_present.options = 1;
	free(req->options.sfb);
	req->options._len.sfb = len;
	req->options.sfb = malloc(req->options._len.sfb);
	memcpy(req->options.sfb, sfb, req->options._len.sfb);
}
static inline void
tc_newtclass_req_set_options_sfq(struct tc_newtclass_req *req, const void *sfq,
				 size_t len)
{
	req->_present.options = 1;
	free(req->options.sfq);
	req->options._len.sfq = len;
	req->options.sfq = malloc(req->options._len.sfq);
	memcpy(req->options.sfq, sfq, req->options._len.sfq);
}
static inline void
tc_newtclass_req_set_options_taprio_priomap(struct tc_newtclass_req *req,
					    const void *priomap, size_t len)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	free(req->options.taprio.priomap);
	req->options.taprio._len.priomap = len;
	req->options.taprio.priomap = malloc(req->options.taprio._len.priomap);
	memcpy(req->options.taprio.priomap, priomap, req->options.taprio._len.priomap);
}
static inline void
__tc_newtclass_req_set_options_taprio_sched_entry_list_entry(struct tc_newtclass_req *req,
							     struct tc_taprio_sched_entry *entry,
							     unsigned int n_entry)
{
	unsigned int i;

	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_entry_list = 1;
	for (i = 0; i < req->options.taprio.sched_entry_list._count.entry; i++)
		tc_taprio_sched_entry_free(&req->options.taprio.sched_entry_list.entry[i]);
	free(req->options.taprio.sched_entry_list.entry);
	req->options.taprio.sched_entry_list.entry = entry;
	req->options.taprio.sched_entry_list._count.entry = n_entry;
}
static inline void
tc_newtclass_req_set_options_taprio_sched_base_time(struct tc_newtclass_req *req,
						    __s64 sched_base_time)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_base_time = 1;
	req->options.taprio.sched_base_time = sched_base_time;
}
static inline void
tc_newtclass_req_set_options_taprio_sched_single_entry_index(struct tc_newtclass_req *req,
							     __u32 index)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.index = 1;
	req->options.taprio.sched_single_entry.index = index;
}
static inline void
tc_newtclass_req_set_options_taprio_sched_single_entry_cmd(struct tc_newtclass_req *req,
							   __u8 cmd)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.cmd = 1;
	req->options.taprio.sched_single_entry.cmd = cmd;
}
static inline void
tc_newtclass_req_set_options_taprio_sched_single_entry_gate_mask(struct tc_newtclass_req *req,
								 __u32 gate_mask)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.gate_mask = 1;
	req->options.taprio.sched_single_entry.gate_mask = gate_mask;
}
static inline void
tc_newtclass_req_set_options_taprio_sched_single_entry_interval(struct tc_newtclass_req *req,
								__u32 interval)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.interval = 1;
	req->options.taprio.sched_single_entry.interval = interval;
}
static inline void
tc_newtclass_req_set_options_taprio_sched_clockid(struct tc_newtclass_req *req,
						  __s32 sched_clockid)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_clockid = 1;
	req->options.taprio.sched_clockid = sched_clockid;
}
static inline void
tc_newtclass_req_set_options_taprio_admin_sched(struct tc_newtclass_req *req,
						const void *admin_sched,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	free(req->options.taprio.admin_sched);
	req->options.taprio._len.admin_sched = len;
	req->options.taprio.admin_sched = malloc(req->options.taprio._len.admin_sched);
	memcpy(req->options.taprio.admin_sched, admin_sched, req->options.taprio._len.admin_sched);
}
static inline void
tc_newtclass_req_set_options_taprio_sched_cycle_time(struct tc_newtclass_req *req,
						     __s64 sched_cycle_time)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_cycle_time = 1;
	req->options.taprio.sched_cycle_time = sched_cycle_time;
}
static inline void
tc_newtclass_req_set_options_taprio_sched_cycle_time_extension(struct tc_newtclass_req *req,
							       __s64 sched_cycle_time_extension)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_cycle_time_extension = 1;
	req->options.taprio.sched_cycle_time_extension = sched_cycle_time_extension;
}
static inline void
tc_newtclass_req_set_options_taprio_flags(struct tc_newtclass_req *req,
					  __u32 flags)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.flags = 1;
	req->options.taprio.flags = flags;
}
static inline void
tc_newtclass_req_set_options_taprio_txtime_delay(struct tc_newtclass_req *req,
						 __u32 txtime_delay)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.txtime_delay = 1;
	req->options.taprio.txtime_delay = txtime_delay;
}
static inline void
tc_newtclass_req_set_options_taprio_tc_entry_index(struct tc_newtclass_req *req,
						   __u32 index)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.index = 1;
	req->options.taprio.tc_entry.index = index;
}
static inline void
tc_newtclass_req_set_options_taprio_tc_entry_max_sdu(struct tc_newtclass_req *req,
						     __u32 max_sdu)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.max_sdu = 1;
	req->options.taprio.tc_entry.max_sdu = max_sdu;
}
static inline void
tc_newtclass_req_set_options_taprio_tc_entry_fp(struct tc_newtclass_req *req,
						__u32 fp)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.fp = 1;
	req->options.taprio.tc_entry.fp = fp;
}
static inline void
tc_newtclass_req_set_options_tbf_parms(struct tc_newtclass_req *req,
				       const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.parms);
	req->options.tbf._len.parms = len;
	req->options.tbf.parms = malloc(req->options.tbf._len.parms);
	memcpy(req->options.tbf.parms, parms, req->options.tbf._len.parms);
}
static inline void
tc_newtclass_req_set_options_tbf_rtab(struct tc_newtclass_req *req,
				      const void *rtab, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.rtab);
	req->options.tbf._len.rtab = len;
	req->options.tbf.rtab = malloc(req->options.tbf._len.rtab);
	memcpy(req->options.tbf.rtab, rtab, req->options.tbf._len.rtab);
}
static inline void
tc_newtclass_req_set_options_tbf_ptab(struct tc_newtclass_req *req,
				      const void *ptab, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.ptab);
	req->options.tbf._len.ptab = len;
	req->options.tbf.ptab = malloc(req->options.tbf._len.ptab);
	memcpy(req->options.tbf.ptab, ptab, req->options.tbf._len.ptab);
}
static inline void
tc_newtclass_req_set_options_tbf_rate64(struct tc_newtclass_req *req,
					__u64 rate64)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.rate64 = 1;
	req->options.tbf.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_tbf_prate64(struct tc_newtclass_req *req,
					 __u64 prate64)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.prate64 = 1;
	req->options.tbf.prate64 = prate64;
}
static inline void
tc_newtclass_req_set_options_tbf_burst(struct tc_newtclass_req *req,
				       __u32 burst)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.burst = 1;
	req->options.tbf.burst = burst;
}
static inline void
tc_newtclass_req_set_options_tbf_pburst(struct tc_newtclass_req *req,
					__u32 pburst)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.pburst = 1;
	req->options.tbf.pburst = pburst;
}
static inline void
tc_newtclass_req_set_options_u32_classid(struct tc_newtclass_req *req,
					 __u32 classid)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.classid = 1;
	req->options.u32.classid = classid;
}
static inline void
tc_newtclass_req_set_options_u32_hash(struct tc_newtclass_req *req, __u32 hash)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.hash = 1;
	req->options.u32.hash = hash;
}
static inline void
tc_newtclass_req_set_options_u32_link(struct tc_newtclass_req *req, __u32 link)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.link = 1;
	req->options.u32.link = link;
}
static inline void
tc_newtclass_req_set_options_u32_divisor(struct tc_newtclass_req *req,
					 __u32 divisor)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.divisor = 1;
	req->options.u32.divisor = divisor;
}
static inline void
tc_newtclass_req_set_options_u32_sel(struct tc_newtclass_req *req,
				     const void *sel, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.sel);
	req->options.u32._len.sel = len;
	req->options.u32.sel = malloc(req->options.u32._len.sel);
	memcpy(req->options.u32.sel, sel, req->options.u32._len.sel);
}
static inline void
tc_newtclass_req_set_options_u32_police_tbf(struct tc_newtclass_req *req,
					    const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.tbf);
	req->options.u32.police._len.tbf = len;
	req->options.u32.police.tbf = malloc(req->options.u32.police._len.tbf);
	memcpy(req->options.u32.police.tbf, tbf, req->options.u32.police._len.tbf);
}
static inline void
tc_newtclass_req_set_options_u32_police_rate(struct tc_newtclass_req *req,
					     const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.rate);
	req->options.u32.police._len.rate = len;
	req->options.u32.police.rate = malloc(req->options.u32.police._len.rate);
	memcpy(req->options.u32.police.rate, rate, req->options.u32.police._len.rate);
}
static inline void
tc_newtclass_req_set_options_u32_police_peakrate(struct tc_newtclass_req *req,
						 const void *peakrate,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.peakrate);
	req->options.u32.police._len.peakrate = len;
	req->options.u32.police.peakrate = malloc(req->options.u32.police._len.peakrate);
	memcpy(req->options.u32.police.peakrate, peakrate, req->options.u32.police._len.peakrate);
}
static inline void
tc_newtclass_req_set_options_u32_police_avrate(struct tc_newtclass_req *req,
					       __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.avrate = 1;
	req->options.u32.police.avrate = avrate;
}
static inline void
tc_newtclass_req_set_options_u32_police_result(struct tc_newtclass_req *req,
					       __u32 result)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.result = 1;
	req->options.u32.police.result = result;
}
static inline void
tc_newtclass_req_set_options_u32_police_tm(struct tc_newtclass_req *req,
					   const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.tm);
	req->options.u32.police._len.tm = len;
	req->options.u32.police.tm = malloc(req->options.u32.police._len.tm);
	memcpy(req->options.u32.police.tm, tm, req->options.u32.police._len.tm);
}
static inline void
tc_newtclass_req_set_options_u32_police_rate64(struct tc_newtclass_req *req,
					       __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.rate64 = 1;
	req->options.u32.police.rate64 = rate64;
}
static inline void
tc_newtclass_req_set_options_u32_police_peakrate64(struct tc_newtclass_req *req,
						   __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.peakrate64 = 1;
	req->options.u32.police.peakrate64 = peakrate64;
}
static inline void
tc_newtclass_req_set_options_u32_police_pktrate64(struct tc_newtclass_req *req,
						  __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.pktrate64 = 1;
	req->options.u32.police.pktrate64 = pktrate64;
}
static inline void
tc_newtclass_req_set_options_u32_police_pktburst64(struct tc_newtclass_req *req,
						   __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.pktburst64 = 1;
	req->options.u32.police.pktburst64 = pktburst64;
}
static inline void
__tc_newtclass_req_set_options_u32_act(struct tc_newtclass_req *req,
				       struct tc_act_attrs *act,
				       unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.act);
	req->options.u32.act = act;
	req->options.u32._count.act = n_act;
}
static inline void
tc_newtclass_req_set_options_u32_indev(struct tc_newtclass_req *req,
				       const char *indev)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.indev);
	req->options.u32._len.indev = strlen(indev);
	req->options.u32.indev = malloc(req->options.u32._len.indev + 1);
	memcpy(req->options.u32.indev, indev, req->options.u32._len.indev);
	req->options.u32.indev[req->options.u32._len.indev] = 0;
}
static inline void
tc_newtclass_req_set_options_u32_pcnt(struct tc_newtclass_req *req,
				      const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.pcnt);
	req->options.u32._len.pcnt = len;
	req->options.u32.pcnt = malloc(req->options.u32._len.pcnt);
	memcpy(req->options.u32.pcnt, pcnt, req->options.u32._len.pcnt);
}
static inline void
tc_newtclass_req_set_options_u32_mark(struct tc_newtclass_req *req,
				      const void *mark, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.mark);
	req->options.u32._len.mark = len;
	req->options.u32.mark = malloc(req->options.u32._len.mark);
	memcpy(req->options.u32.mark, mark, req->options.u32._len.mark);
}
static inline void
tc_newtclass_req_set_options_u32_flags(struct tc_newtclass_req *req,
				       __u32 flags)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.flags = 1;
	req->options.u32.flags = flags;
}
static inline void
tc_newtclass_req_set_rate(struct tc_newtclass_req *req, const void *rate,
			  size_t len)
{
	free(req->rate);
	req->_len.rate = len;
	req->rate = malloc(req->_len.rate);
	memcpy(req->rate, rate, req->_len.rate);
}
static inline void
tc_newtclass_req_set_chain(struct tc_newtclass_req *req, __u32 chain)
{
	req->_present.chain = 1;
	req->chain = chain;
}
static inline void
tc_newtclass_req_set_ingress_block(struct tc_newtclass_req *req,
				   __u32 ingress_block)
{
	req->_present.ingress_block = 1;
	req->ingress_block = ingress_block;
}
static inline void
tc_newtclass_req_set_egress_block(struct tc_newtclass_req *req,
				  __u32 egress_block)
{
	req->_present.egress_block = 1;
	req->egress_block = egress_block;
}

/*
 * Get / dump tc traffic class information.
 */
int tc_newtclass(struct ynl_sock *ys, struct tc_newtclass_req *req);

/* ============== RTM_DELTCLASS ============== */
/* RTM_DELTCLASS - do */
struct tc_deltclass_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;
};

static inline struct tc_deltclass_req *tc_deltclass_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_deltclass_req));
}
void tc_deltclass_req_free(struct tc_deltclass_req *req);

static inline void
tc_deltclass_req_set_nlflags(struct tc_deltclass_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

/*
 * Get / dump tc traffic class information.
 */
int tc_deltclass(struct ynl_sock *ys, struct tc_deltclass_req *req);

/* ============== RTM_GETTCLASS ============== */
/* RTM_GETTCLASS - do */
struct tc_gettclass_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;
};

static inline struct tc_gettclass_req *tc_gettclass_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_gettclass_req));
}
void tc_gettclass_req_free(struct tc_gettclass_req *req);

static inline void
tc_gettclass_req_set_nlflags(struct tc_gettclass_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

struct tc_gettclass_rsp {
	struct tcmsg _hdr;

	struct {
		__u32 options:1;
		__u32 xstats:1;
		__u32 fcnt:1;
		__u32 stats2:1;
		__u32 stab:1;
		__u32 chain:1;
		__u32 ingress_block:1;
		__u32 egress_block:1;
	} _present;
	struct {
		__u32 kind;
		__u32 stats;
		__u32 rate;
	} _len;

	char *kind;
	struct tc_options_msg options;
	struct tc_stats *stats;
	struct tc_tca_stats_app_msg xstats;
	struct gnet_estimator *rate;
	__u32 fcnt;
	struct tc_tca_stats_attrs stats2;
	struct tc_tca_stab_attrs stab;
	__u32 chain;
	__u32 ingress_block;
	__u32 egress_block;
};

void tc_gettclass_rsp_free(struct tc_gettclass_rsp *rsp);

/*
 * Get / dump tc traffic class information.
 */
struct tc_gettclass_rsp *
tc_gettclass(struct ynl_sock *ys, struct tc_gettclass_req *req);

/* ============== RTM_NEWTFILTER ============== */
/* RTM_NEWTFILTER - do */
struct tc_newtfilter_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;

	struct {
		__u32 options:1;
		__u32 chain:1;
		__u32 ingress_block:1;
		__u32 egress_block:1;
	} _present;
	struct {
		__u32 kind;
		__u32 rate;
	} _len;

	char *kind;
	struct tc_options_msg options;
	struct gnet_estimator *rate;
	__u32 chain;
	__u32 ingress_block;
	__u32 egress_block;
};

static inline struct tc_newtfilter_req *tc_newtfilter_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_newtfilter_req));
}
void tc_newtfilter_req_free(struct tc_newtfilter_req *req);

static inline void
tc_newtfilter_req_set_nlflags(struct tc_newtfilter_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
tc_newtfilter_req_set_kind(struct tc_newtfilter_req *req, const char *kind)
{
	free(req->kind);
	req->_len.kind = strlen(kind);
	req->kind = malloc(req->_len.kind + 1);
	memcpy(req->kind, kind, req->_len.kind);
	req->kind[req->_len.kind] = 0;
}
static inline void
tc_newtfilter_req_set_options_basic_classid(struct tc_newtfilter_req *req,
					    __u32 classid)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.classid = 1;
	req->options.basic.classid = classid;
}
static inline void
tc_newtfilter_req_set_options_basic_ematches_tree_hdr(struct tc_newtfilter_req *req,
						      const void *tree_hdr,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.ematches = 1;
	free(req->options.basic.ematches.tree_hdr);
	req->options.basic.ematches._len.tree_hdr = len;
	req->options.basic.ematches.tree_hdr = malloc(req->options.basic.ematches._len.tree_hdr);
	memcpy(req->options.basic.ematches.tree_hdr, tree_hdr, req->options.basic.ematches._len.tree_hdr);
}
static inline void
tc_newtfilter_req_set_options_basic_ematches_tree_list(struct tc_newtfilter_req *req,
						       const void *tree_list,
						       size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.ematches = 1;
	free(req->options.basic.ematches.tree_list);
	req->options.basic.ematches._len.tree_list = len;
	req->options.basic.ematches.tree_list = malloc(req->options.basic.ematches._len.tree_list);
	memcpy(req->options.basic.ematches.tree_list, tree_list, req->options.basic.ematches._len.tree_list);
}
static inline void
__tc_newtfilter_req_set_options_basic_act(struct tc_newtfilter_req *req,
					  struct tc_act_attrs *act,
					  unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	free(req->options.basic.act);
	req->options.basic.act = act;
	req->options.basic._count.act = n_act;
}
static inline void
tc_newtfilter_req_set_options_basic_police_tbf(struct tc_newtfilter_req *req,
					       const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.tbf);
	req->options.basic.police._len.tbf = len;
	req->options.basic.police.tbf = malloc(req->options.basic.police._len.tbf);
	memcpy(req->options.basic.police.tbf, tbf, req->options.basic.police._len.tbf);
}
static inline void
tc_newtfilter_req_set_options_basic_police_rate(struct tc_newtfilter_req *req,
						const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.rate);
	req->options.basic.police._len.rate = len;
	req->options.basic.police.rate = malloc(req->options.basic.police._len.rate);
	memcpy(req->options.basic.police.rate, rate, req->options.basic.police._len.rate);
}
static inline void
tc_newtfilter_req_set_options_basic_police_peakrate(struct tc_newtfilter_req *req,
						    const void *peakrate,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.peakrate);
	req->options.basic.police._len.peakrate = len;
	req->options.basic.police.peakrate = malloc(req->options.basic.police._len.peakrate);
	memcpy(req->options.basic.police.peakrate, peakrate, req->options.basic.police._len.peakrate);
}
static inline void
tc_newtfilter_req_set_options_basic_police_avrate(struct tc_newtfilter_req *req,
						  __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.avrate = 1;
	req->options.basic.police.avrate = avrate;
}
static inline void
tc_newtfilter_req_set_options_basic_police_result(struct tc_newtfilter_req *req,
						  __u32 result)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.result = 1;
	req->options.basic.police.result = result;
}
static inline void
tc_newtfilter_req_set_options_basic_police_tm(struct tc_newtfilter_req *req,
					      const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.tm);
	req->options.basic.police._len.tm = len;
	req->options.basic.police.tm = malloc(req->options.basic.police._len.tm);
	memcpy(req->options.basic.police.tm, tm, req->options.basic.police._len.tm);
}
static inline void
tc_newtfilter_req_set_options_basic_police_rate64(struct tc_newtfilter_req *req,
						  __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.rate64 = 1;
	req->options.basic.police.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_basic_police_peakrate64(struct tc_newtfilter_req *req,
						      __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.peakrate64 = 1;
	req->options.basic.police.peakrate64 = peakrate64;
}
static inline void
tc_newtfilter_req_set_options_basic_police_pktrate64(struct tc_newtfilter_req *req,
						     __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.pktrate64 = 1;
	req->options.basic.police.pktrate64 = pktrate64;
}
static inline void
tc_newtfilter_req_set_options_basic_police_pktburst64(struct tc_newtfilter_req *req,
						      __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.pktburst64 = 1;
	req->options.basic.police.pktburst64 = pktburst64;
}
static inline void
tc_newtfilter_req_set_options_basic_pcnt(struct tc_newtfilter_req *req,
					 const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	free(req->options.basic.pcnt);
	req->options.basic._len.pcnt = len;
	req->options.basic.pcnt = malloc(req->options.basic._len.pcnt);
	memcpy(req->options.basic.pcnt, pcnt, req->options.basic._len.pcnt);
}
static inline void
__tc_newtfilter_req_set_options_bpf_act(struct tc_newtfilter_req *req,
					struct tc_act_attrs *act,
					unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.act);
	req->options.bpf.act = act;
	req->options.bpf._count.act = n_act;
}
static inline void
tc_newtfilter_req_set_options_bpf_police_tbf(struct tc_newtfilter_req *req,
					     const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.tbf);
	req->options.bpf.police._len.tbf = len;
	req->options.bpf.police.tbf = malloc(req->options.bpf.police._len.tbf);
	memcpy(req->options.bpf.police.tbf, tbf, req->options.bpf.police._len.tbf);
}
static inline void
tc_newtfilter_req_set_options_bpf_police_rate(struct tc_newtfilter_req *req,
					      const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.rate);
	req->options.bpf.police._len.rate = len;
	req->options.bpf.police.rate = malloc(req->options.bpf.police._len.rate);
	memcpy(req->options.bpf.police.rate, rate, req->options.bpf.police._len.rate);
}
static inline void
tc_newtfilter_req_set_options_bpf_police_peakrate(struct tc_newtfilter_req *req,
						  const void *peakrate,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.peakrate);
	req->options.bpf.police._len.peakrate = len;
	req->options.bpf.police.peakrate = malloc(req->options.bpf.police._len.peakrate);
	memcpy(req->options.bpf.police.peakrate, peakrate, req->options.bpf.police._len.peakrate);
}
static inline void
tc_newtfilter_req_set_options_bpf_police_avrate(struct tc_newtfilter_req *req,
						__u32 avrate)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.avrate = 1;
	req->options.bpf.police.avrate = avrate;
}
static inline void
tc_newtfilter_req_set_options_bpf_police_result(struct tc_newtfilter_req *req,
						__u32 result)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.result = 1;
	req->options.bpf.police.result = result;
}
static inline void
tc_newtfilter_req_set_options_bpf_police_tm(struct tc_newtfilter_req *req,
					    const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.tm);
	req->options.bpf.police._len.tm = len;
	req->options.bpf.police.tm = malloc(req->options.bpf.police._len.tm);
	memcpy(req->options.bpf.police.tm, tm, req->options.bpf.police._len.tm);
}
static inline void
tc_newtfilter_req_set_options_bpf_police_rate64(struct tc_newtfilter_req *req,
						__u64 rate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.rate64 = 1;
	req->options.bpf.police.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_bpf_police_peakrate64(struct tc_newtfilter_req *req,
						    __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.peakrate64 = 1;
	req->options.bpf.police.peakrate64 = peakrate64;
}
static inline void
tc_newtfilter_req_set_options_bpf_police_pktrate64(struct tc_newtfilter_req *req,
						   __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.pktrate64 = 1;
	req->options.bpf.police.pktrate64 = pktrate64;
}
static inline void
tc_newtfilter_req_set_options_bpf_police_pktburst64(struct tc_newtfilter_req *req,
						    __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.pktburst64 = 1;
	req->options.bpf.police.pktburst64 = pktburst64;
}
static inline void
tc_newtfilter_req_set_options_bpf_classid(struct tc_newtfilter_req *req,
					  __u32 classid)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.classid = 1;
	req->options.bpf.classid = classid;
}
static inline void
tc_newtfilter_req_set_options_bpf_ops_len(struct tc_newtfilter_req *req,
					  __u16 ops_len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.ops_len = 1;
	req->options.bpf.ops_len = ops_len;
}
static inline void
tc_newtfilter_req_set_options_bpf_ops(struct tc_newtfilter_req *req,
				      const void *ops, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.ops);
	req->options.bpf._len.ops = len;
	req->options.bpf.ops = malloc(req->options.bpf._len.ops);
	memcpy(req->options.bpf.ops, ops, req->options.bpf._len.ops);
}
static inline void
tc_newtfilter_req_set_options_bpf_fd(struct tc_newtfilter_req *req, __u32 fd)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.fd = 1;
	req->options.bpf.fd = fd;
}
static inline void
tc_newtfilter_req_set_options_bpf_name(struct tc_newtfilter_req *req,
				       const char *name)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.name);
	req->options.bpf._len.name = strlen(name);
	req->options.bpf.name = malloc(req->options.bpf._len.name + 1);
	memcpy(req->options.bpf.name, name, req->options.bpf._len.name);
	req->options.bpf.name[req->options.bpf._len.name] = 0;
}
static inline void
tc_newtfilter_req_set_options_bpf_flags(struct tc_newtfilter_req *req,
					__u32 flags)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.flags = 1;
	req->options.bpf.flags = flags;
}
static inline void
tc_newtfilter_req_set_options_bpf_flags_gen(struct tc_newtfilter_req *req,
					    __u32 flags_gen)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.flags_gen = 1;
	req->options.bpf.flags_gen = flags_gen;
}
static inline void
tc_newtfilter_req_set_options_bpf_tag(struct tc_newtfilter_req *req,
				      const void *tag, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.tag);
	req->options.bpf._len.tag = len;
	req->options.bpf.tag = malloc(req->options.bpf._len.tag);
	memcpy(req->options.bpf.tag, tag, req->options.bpf._len.tag);
}
static inline void
tc_newtfilter_req_set_options_bpf_id(struct tc_newtfilter_req *req, __u32 id)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.id = 1;
	req->options.bpf.id = id;
}
static inline void
tc_newtfilter_req_set_options_bfifo(struct tc_newtfilter_req *req,
				    const void *bfifo, size_t len)
{
	req->_present.options = 1;
	free(req->options.bfifo);
	req->options._len.bfifo = len;
	req->options.bfifo = malloc(req->options._len.bfifo);
	memcpy(req->options.bfifo, bfifo, req->options._len.bfifo);
}
static inline void
tc_newtfilter_req_set_options_cake_base_rate64(struct tc_newtfilter_req *req,
					       __u64 base_rate64)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.base_rate64 = 1;
	req->options.cake.base_rate64 = base_rate64;
}
static inline void
tc_newtfilter_req_set_options_cake_diffserv_mode(struct tc_newtfilter_req *req,
						 __u32 diffserv_mode)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.diffserv_mode = 1;
	req->options.cake.diffserv_mode = diffserv_mode;
}
static inline void
tc_newtfilter_req_set_options_cake_atm(struct tc_newtfilter_req *req,
				       __u32 atm)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.atm = 1;
	req->options.cake.atm = atm;
}
static inline void
tc_newtfilter_req_set_options_cake_flow_mode(struct tc_newtfilter_req *req,
					     __u32 flow_mode)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.flow_mode = 1;
	req->options.cake.flow_mode = flow_mode;
}
static inline void
tc_newtfilter_req_set_options_cake_overhead(struct tc_newtfilter_req *req,
					    __u32 overhead)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.overhead = 1;
	req->options.cake.overhead = overhead;
}
static inline void
tc_newtfilter_req_set_options_cake_rtt(struct tc_newtfilter_req *req,
				       __u32 rtt)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.rtt = 1;
	req->options.cake.rtt = rtt;
}
static inline void
tc_newtfilter_req_set_options_cake_target(struct tc_newtfilter_req *req,
					  __u32 target)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.target = 1;
	req->options.cake.target = target;
}
static inline void
tc_newtfilter_req_set_options_cake_autorate(struct tc_newtfilter_req *req,
					    __u32 autorate)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.autorate = 1;
	req->options.cake.autorate = autorate;
}
static inline void
tc_newtfilter_req_set_options_cake_memory(struct tc_newtfilter_req *req,
					  __u32 memory)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.memory = 1;
	req->options.cake.memory = memory;
}
static inline void
tc_newtfilter_req_set_options_cake_nat(struct tc_newtfilter_req *req,
				       __u32 nat)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.nat = 1;
	req->options.cake.nat = nat;
}
static inline void
tc_newtfilter_req_set_options_cake_raw(struct tc_newtfilter_req *req,
				       __u32 raw)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.raw = 1;
	req->options.cake.raw = raw;
}
static inline void
tc_newtfilter_req_set_options_cake_wash(struct tc_newtfilter_req *req,
					__u32 wash)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.wash = 1;
	req->options.cake.wash = wash;
}
static inline void
tc_newtfilter_req_set_options_cake_mpu(struct tc_newtfilter_req *req,
				       __u32 mpu)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.mpu = 1;
	req->options.cake.mpu = mpu;
}
static inline void
tc_newtfilter_req_set_options_cake_ingress(struct tc_newtfilter_req *req,
					   __u32 ingress)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.ingress = 1;
	req->options.cake.ingress = ingress;
}
static inline void
tc_newtfilter_req_set_options_cake_ack_filter(struct tc_newtfilter_req *req,
					      __u32 ack_filter)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.ack_filter = 1;
	req->options.cake.ack_filter = ack_filter;
}
static inline void
tc_newtfilter_req_set_options_cake_split_gso(struct tc_newtfilter_req *req,
					     __u32 split_gso)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.split_gso = 1;
	req->options.cake.split_gso = split_gso;
}
static inline void
tc_newtfilter_req_set_options_cake_fwmark(struct tc_newtfilter_req *req,
					  __u32 fwmark)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.fwmark = 1;
	req->options.cake.fwmark = fwmark;
}
static inline void
tc_newtfilter_req_set_options_cbs_parms(struct tc_newtfilter_req *req,
					const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.cbs = 1;
	free(req->options.cbs.parms);
	req->options.cbs._len.parms = len;
	req->options.cbs.parms = malloc(req->options.cbs._len.parms);
	memcpy(req->options.cbs.parms, parms, req->options.cbs._len.parms);
}
static inline void
__tc_newtfilter_req_set_options_cgroup_act(struct tc_newtfilter_req *req,
					   struct tc_act_attrs *act,
					   unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	free(req->options.cgroup.act);
	req->options.cgroup.act = act;
	req->options.cgroup._count.act = n_act;
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_tbf(struct tc_newtfilter_req *req,
						const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.tbf);
	req->options.cgroup.police._len.tbf = len;
	req->options.cgroup.police.tbf = malloc(req->options.cgroup.police._len.tbf);
	memcpy(req->options.cgroup.police.tbf, tbf, req->options.cgroup.police._len.tbf);
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_rate(struct tc_newtfilter_req *req,
						 const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.rate);
	req->options.cgroup.police._len.rate = len;
	req->options.cgroup.police.rate = malloc(req->options.cgroup.police._len.rate);
	memcpy(req->options.cgroup.police.rate, rate, req->options.cgroup.police._len.rate);
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_peakrate(struct tc_newtfilter_req *req,
						     const void *peakrate,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.peakrate);
	req->options.cgroup.police._len.peakrate = len;
	req->options.cgroup.police.peakrate = malloc(req->options.cgroup.police._len.peakrate);
	memcpy(req->options.cgroup.police.peakrate, peakrate, req->options.cgroup.police._len.peakrate);
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_avrate(struct tc_newtfilter_req *req,
						   __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.avrate = 1;
	req->options.cgroup.police.avrate = avrate;
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_result(struct tc_newtfilter_req *req,
						   __u32 result)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.result = 1;
	req->options.cgroup.police.result = result;
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_tm(struct tc_newtfilter_req *req,
					       const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.tm);
	req->options.cgroup.police._len.tm = len;
	req->options.cgroup.police.tm = malloc(req->options.cgroup.police._len.tm);
	memcpy(req->options.cgroup.police.tm, tm, req->options.cgroup.police._len.tm);
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_rate64(struct tc_newtfilter_req *req,
						   __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.rate64 = 1;
	req->options.cgroup.police.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_peakrate64(struct tc_newtfilter_req *req,
						       __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.peakrate64 = 1;
	req->options.cgroup.police.peakrate64 = peakrate64;
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_pktrate64(struct tc_newtfilter_req *req,
						      __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.pktrate64 = 1;
	req->options.cgroup.police.pktrate64 = pktrate64;
}
static inline void
tc_newtfilter_req_set_options_cgroup_police_pktburst64(struct tc_newtfilter_req *req,
						       __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.pktburst64 = 1;
	req->options.cgroup.police.pktburst64 = pktburst64;
}
static inline void
tc_newtfilter_req_set_options_cgroup_ematches(struct tc_newtfilter_req *req,
					      const void *ematches, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	free(req->options.cgroup.ematches);
	req->options.cgroup._len.ematches = len;
	req->options.cgroup.ematches = malloc(req->options.cgroup._len.ematches);
	memcpy(req->options.cgroup.ematches, ematches, req->options.cgroup._len.ematches);
}
static inline void
tc_newtfilter_req_set_options_choke_parms(struct tc_newtfilter_req *req,
					  const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	free(req->options.choke.parms);
	req->options.choke._len.parms = len;
	req->options.choke.parms = malloc(req->options.choke._len.parms);
	memcpy(req->options.choke.parms, parms, req->options.choke._len.parms);
}
static inline void
tc_newtfilter_req_set_options_choke_stab(struct tc_newtfilter_req *req,
					 const void *stab, size_t len)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	free(req->options.choke.stab);
	req->options.choke._len.stab = len;
	req->options.choke.stab = malloc(req->options.choke._len.stab);
	memcpy(req->options.choke.stab, stab, req->options.choke._len.stab);
}
static inline void
tc_newtfilter_req_set_options_choke_max_p(struct tc_newtfilter_req *req,
					  __u32 max_p)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	req->options.choke._present.max_p = 1;
	req->options.choke.max_p = max_p;
}
static inline void
tc_newtfilter_req_set_options_clsact(struct tc_newtfilter_req *req)
{
	req->_present.options = 1;
	req->options._present.clsact = 1;
}
static inline void
tc_newtfilter_req_set_options_codel_target(struct tc_newtfilter_req *req,
					   __u32 target)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.target = 1;
	req->options.codel.target = target;
}
static inline void
tc_newtfilter_req_set_options_codel_limit(struct tc_newtfilter_req *req,
					  __u32 limit)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.limit = 1;
	req->options.codel.limit = limit;
}
static inline void
tc_newtfilter_req_set_options_codel_interval(struct tc_newtfilter_req *req,
					     __u32 interval)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.interval = 1;
	req->options.codel.interval = interval;
}
static inline void
tc_newtfilter_req_set_options_codel_ecn(struct tc_newtfilter_req *req,
					__u32 ecn)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.ecn = 1;
	req->options.codel.ecn = ecn;
}
static inline void
tc_newtfilter_req_set_options_codel_ce_threshold(struct tc_newtfilter_req *req,
						 __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.ce_threshold = 1;
	req->options.codel.ce_threshold = ce_threshold;
}
static inline void
tc_newtfilter_req_set_options_drr_quantum(struct tc_newtfilter_req *req,
					  __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.drr = 1;
	req->options.drr._present.quantum = 1;
	req->options.drr.quantum = quantum;
}
static inline void
tc_newtfilter_req_set_options_etf_parms(struct tc_newtfilter_req *req,
					const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.etf = 1;
	free(req->options.etf.parms);
	req->options.etf._len.parms = len;
	req->options.etf.parms = malloc(req->options.etf._len.parms);
	memcpy(req->options.etf.parms, parms, req->options.etf._len.parms);
}
static inline void
tc_newtfilter_req_set_options_flow_keys(struct tc_newtfilter_req *req,
					__u32 keys)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.keys = 1;
	req->options.flow.keys = keys;
}
static inline void
tc_newtfilter_req_set_options_flow_mode(struct tc_newtfilter_req *req,
					__u32 mode)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.mode = 1;
	req->options.flow.mode = mode;
}
static inline void
tc_newtfilter_req_set_options_flow_baseclass(struct tc_newtfilter_req *req,
					     __u32 baseclass)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.baseclass = 1;
	req->options.flow.baseclass = baseclass;
}
static inline void
tc_newtfilter_req_set_options_flow_rshift(struct tc_newtfilter_req *req,
					  __u32 rshift)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.rshift = 1;
	req->options.flow.rshift = rshift;
}
static inline void
tc_newtfilter_req_set_options_flow_addend(struct tc_newtfilter_req *req,
					  __u32 addend)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.addend = 1;
	req->options.flow.addend = addend;
}
static inline void
tc_newtfilter_req_set_options_flow_mask(struct tc_newtfilter_req *req,
					__u32 mask)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.mask = 1;
	req->options.flow.mask = mask;
}
static inline void
tc_newtfilter_req_set_options_flow_xor(struct tc_newtfilter_req *req,
				       __u32 xor)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.xor = 1;
	req->options.flow.xor = xor;
}
static inline void
tc_newtfilter_req_set_options_flow_divisor(struct tc_newtfilter_req *req,
					   __u32 divisor)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.divisor = 1;
	req->options.flow.divisor = divisor;
}
static inline void
tc_newtfilter_req_set_options_flow_act(struct tc_newtfilter_req *req,
				       const void *act, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	free(req->options.flow.act);
	req->options.flow._len.act = len;
	req->options.flow.act = malloc(req->options.flow._len.act);
	memcpy(req->options.flow.act, act, req->options.flow._len.act);
}
static inline void
tc_newtfilter_req_set_options_flow_police_tbf(struct tc_newtfilter_req *req,
					      const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.tbf);
	req->options.flow.police._len.tbf = len;
	req->options.flow.police.tbf = malloc(req->options.flow.police._len.tbf);
	memcpy(req->options.flow.police.tbf, tbf, req->options.flow.police._len.tbf);
}
static inline void
tc_newtfilter_req_set_options_flow_police_rate(struct tc_newtfilter_req *req,
					       const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.rate);
	req->options.flow.police._len.rate = len;
	req->options.flow.police.rate = malloc(req->options.flow.police._len.rate);
	memcpy(req->options.flow.police.rate, rate, req->options.flow.police._len.rate);
}
static inline void
tc_newtfilter_req_set_options_flow_police_peakrate(struct tc_newtfilter_req *req,
						   const void *peakrate,
						   size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.peakrate);
	req->options.flow.police._len.peakrate = len;
	req->options.flow.police.peakrate = malloc(req->options.flow.police._len.peakrate);
	memcpy(req->options.flow.police.peakrate, peakrate, req->options.flow.police._len.peakrate);
}
static inline void
tc_newtfilter_req_set_options_flow_police_avrate(struct tc_newtfilter_req *req,
						 __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.avrate = 1;
	req->options.flow.police.avrate = avrate;
}
static inline void
tc_newtfilter_req_set_options_flow_police_result(struct tc_newtfilter_req *req,
						 __u32 result)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.result = 1;
	req->options.flow.police.result = result;
}
static inline void
tc_newtfilter_req_set_options_flow_police_tm(struct tc_newtfilter_req *req,
					     const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.tm);
	req->options.flow.police._len.tm = len;
	req->options.flow.police.tm = malloc(req->options.flow.police._len.tm);
	memcpy(req->options.flow.police.tm, tm, req->options.flow.police._len.tm);
}
static inline void
tc_newtfilter_req_set_options_flow_police_rate64(struct tc_newtfilter_req *req,
						 __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.rate64 = 1;
	req->options.flow.police.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_flow_police_peakrate64(struct tc_newtfilter_req *req,
						     __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.peakrate64 = 1;
	req->options.flow.police.peakrate64 = peakrate64;
}
static inline void
tc_newtfilter_req_set_options_flow_police_pktrate64(struct tc_newtfilter_req *req,
						    __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.pktrate64 = 1;
	req->options.flow.police.pktrate64 = pktrate64;
}
static inline void
tc_newtfilter_req_set_options_flow_police_pktburst64(struct tc_newtfilter_req *req,
						     __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.pktburst64 = 1;
	req->options.flow.police.pktburst64 = pktburst64;
}
static inline void
tc_newtfilter_req_set_options_flow_ematches(struct tc_newtfilter_req *req,
					    const void *ematches, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	free(req->options.flow.ematches);
	req->options.flow._len.ematches = len;
	req->options.flow.ematches = malloc(req->options.flow._len.ematches);
	memcpy(req->options.flow.ematches, ematches, req->options.flow._len.ematches);
}
static inline void
tc_newtfilter_req_set_options_flow_perturb(struct tc_newtfilter_req *req,
					   __u32 perturb)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.perturb = 1;
	req->options.flow.perturb = perturb;
}
static inline void
tc_newtfilter_req_set_options_flower_classid(struct tc_newtfilter_req *req,
					     __u32 classid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.classid = 1;
	req->options.flower.classid = classid;
}
static inline void
tc_newtfilter_req_set_options_flower_indev(struct tc_newtfilter_req *req,
					   const char *indev)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.indev);
	req->options.flower._len.indev = strlen(indev);
	req->options.flower.indev = malloc(req->options.flower._len.indev + 1);
	memcpy(req->options.flower.indev, indev, req->options.flower._len.indev);
	req->options.flower.indev[req->options.flower._len.indev] = 0;
}
static inline void
__tc_newtfilter_req_set_options_flower_act(struct tc_newtfilter_req *req,
					   struct tc_act_attrs *act,
					   unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.act);
	req->options.flower.act = act;
	req->options.flower._count.act = n_act;
}
static inline void
tc_newtfilter_req_set_options_flower_key_eth_dst(struct tc_newtfilter_req *req,
						 const void *key_eth_dst,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_dst);
	req->options.flower._len.key_eth_dst = len;
	req->options.flower.key_eth_dst = malloc(req->options.flower._len.key_eth_dst);
	memcpy(req->options.flower.key_eth_dst, key_eth_dst, req->options.flower._len.key_eth_dst);
}
static inline void
tc_newtfilter_req_set_options_flower_key_eth_dst_mask(struct tc_newtfilter_req *req,
						      const void *key_eth_dst_mask,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_dst_mask);
	req->options.flower._len.key_eth_dst_mask = len;
	req->options.flower.key_eth_dst_mask = malloc(req->options.flower._len.key_eth_dst_mask);
	memcpy(req->options.flower.key_eth_dst_mask, key_eth_dst_mask, req->options.flower._len.key_eth_dst_mask);
}
static inline void
tc_newtfilter_req_set_options_flower_key_eth_src(struct tc_newtfilter_req *req,
						 const void *key_eth_src,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_src);
	req->options.flower._len.key_eth_src = len;
	req->options.flower.key_eth_src = malloc(req->options.flower._len.key_eth_src);
	memcpy(req->options.flower.key_eth_src, key_eth_src, req->options.flower._len.key_eth_src);
}
static inline void
tc_newtfilter_req_set_options_flower_key_eth_src_mask(struct tc_newtfilter_req *req,
						      const void *key_eth_src_mask,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_src_mask);
	req->options.flower._len.key_eth_src_mask = len;
	req->options.flower.key_eth_src_mask = malloc(req->options.flower._len.key_eth_src_mask);
	memcpy(req->options.flower.key_eth_src_mask, key_eth_src_mask, req->options.flower._len.key_eth_src_mask);
}
static inline void
tc_newtfilter_req_set_options_flower_key_eth_type(struct tc_newtfilter_req *req,
						  __u16 key_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_eth_type = 1;
	req->options.flower.key_eth_type = key_eth_type;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ip_proto(struct tc_newtfilter_req *req,
						  __u8 key_ip_proto)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_proto = 1;
	req->options.flower.key_ip_proto = key_ip_proto;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ipv4_src(struct tc_newtfilter_req *req,
						  __u32 key_ipv4_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_src = 1;
	req->options.flower.key_ipv4_src = key_ipv4_src;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ipv4_src_mask(struct tc_newtfilter_req *req,
						       __u32 key_ipv4_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_src_mask = 1;
	req->options.flower.key_ipv4_src_mask = key_ipv4_src_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ipv4_dst(struct tc_newtfilter_req *req,
						  __u32 key_ipv4_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_dst = 1;
	req->options.flower.key_ipv4_dst = key_ipv4_dst;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ipv4_dst_mask(struct tc_newtfilter_req *req,
						       __u32 key_ipv4_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_dst_mask = 1;
	req->options.flower.key_ipv4_dst_mask = key_ipv4_dst_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ipv6_src(struct tc_newtfilter_req *req,
						  const void *key_ipv6_src,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_src);
	req->options.flower._len.key_ipv6_src = len;
	req->options.flower.key_ipv6_src = malloc(req->options.flower._len.key_ipv6_src);
	memcpy(req->options.flower.key_ipv6_src, key_ipv6_src, req->options.flower._len.key_ipv6_src);
}
static inline void
tc_newtfilter_req_set_options_flower_key_ipv6_src_mask(struct tc_newtfilter_req *req,
						       const void *key_ipv6_src_mask,
						       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_src_mask);
	req->options.flower._len.key_ipv6_src_mask = len;
	req->options.flower.key_ipv6_src_mask = malloc(req->options.flower._len.key_ipv6_src_mask);
	memcpy(req->options.flower.key_ipv6_src_mask, key_ipv6_src_mask, req->options.flower._len.key_ipv6_src_mask);
}
static inline void
tc_newtfilter_req_set_options_flower_key_ipv6_dst(struct tc_newtfilter_req *req,
						  const void *key_ipv6_dst,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_dst);
	req->options.flower._len.key_ipv6_dst = len;
	req->options.flower.key_ipv6_dst = malloc(req->options.flower._len.key_ipv6_dst);
	memcpy(req->options.flower.key_ipv6_dst, key_ipv6_dst, req->options.flower._len.key_ipv6_dst);
}
static inline void
tc_newtfilter_req_set_options_flower_key_ipv6_dst_mask(struct tc_newtfilter_req *req,
						       const void *key_ipv6_dst_mask,
						       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_dst_mask);
	req->options.flower._len.key_ipv6_dst_mask = len;
	req->options.flower.key_ipv6_dst_mask = malloc(req->options.flower._len.key_ipv6_dst_mask);
	memcpy(req->options.flower.key_ipv6_dst_mask, key_ipv6_dst_mask, req->options.flower._len.key_ipv6_dst_mask);
}
static inline void
tc_newtfilter_req_set_options_flower_key_tcp_src(struct tc_newtfilter_req *req,
						 __u16 key_tcp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_src = 1;
	req->options.flower.key_tcp_src = key_tcp_src;
}
static inline void
tc_newtfilter_req_set_options_flower_key_tcp_dst(struct tc_newtfilter_req *req,
						 __u16 key_tcp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_dst = 1;
	req->options.flower.key_tcp_dst = key_tcp_dst;
}
static inline void
tc_newtfilter_req_set_options_flower_key_udp_src(struct tc_newtfilter_req *req,
						 __u16 key_udp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_src = 1;
	req->options.flower.key_udp_src = key_udp_src;
}
static inline void
tc_newtfilter_req_set_options_flower_key_udp_dst(struct tc_newtfilter_req *req,
						 __u16 key_udp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_dst = 1;
	req->options.flower.key_udp_dst = key_udp_dst;
}
static inline void
tc_newtfilter_req_set_options_flower_flags(struct tc_newtfilter_req *req,
					   __u32 flags)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.flags = 1;
	req->options.flower.flags = flags;
}
static inline void
tc_newtfilter_req_set_options_flower_key_vlan_id(struct tc_newtfilter_req *req,
						 __u16 key_vlan_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_id = 1;
	req->options.flower.key_vlan_id = key_vlan_id;
}
static inline void
tc_newtfilter_req_set_options_flower_key_vlan_prio(struct tc_newtfilter_req *req,
						   __u8 key_vlan_prio)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_prio = 1;
	req->options.flower.key_vlan_prio = key_vlan_prio;
}
static inline void
tc_newtfilter_req_set_options_flower_key_vlan_eth_type(struct tc_newtfilter_req *req,
						       __u16 key_vlan_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_eth_type = 1;
	req->options.flower.key_vlan_eth_type = key_vlan_eth_type;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_key_id(struct tc_newtfilter_req *req,
						    __u32 key_enc_key_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_key_id = 1;
	req->options.flower.key_enc_key_id = key_enc_key_id;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ipv4_src(struct tc_newtfilter_req *req,
						      __u32 key_enc_ipv4_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_src = 1;
	req->options.flower.key_enc_ipv4_src = key_enc_ipv4_src;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ipv4_src_mask(struct tc_newtfilter_req *req,
							   __u32 key_enc_ipv4_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_src_mask = 1;
	req->options.flower.key_enc_ipv4_src_mask = key_enc_ipv4_src_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ipv4_dst(struct tc_newtfilter_req *req,
						      __u32 key_enc_ipv4_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_dst = 1;
	req->options.flower.key_enc_ipv4_dst = key_enc_ipv4_dst;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ipv4_dst_mask(struct tc_newtfilter_req *req,
							   __u32 key_enc_ipv4_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_dst_mask = 1;
	req->options.flower.key_enc_ipv4_dst_mask = key_enc_ipv4_dst_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ipv6_src(struct tc_newtfilter_req *req,
						      const void *key_enc_ipv6_src,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_src);
	req->options.flower._len.key_enc_ipv6_src = len;
	req->options.flower.key_enc_ipv6_src = malloc(req->options.flower._len.key_enc_ipv6_src);
	memcpy(req->options.flower.key_enc_ipv6_src, key_enc_ipv6_src, req->options.flower._len.key_enc_ipv6_src);
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ipv6_src_mask(struct tc_newtfilter_req *req,
							   const void *key_enc_ipv6_src_mask,
							   size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_src_mask);
	req->options.flower._len.key_enc_ipv6_src_mask = len;
	req->options.flower.key_enc_ipv6_src_mask = malloc(req->options.flower._len.key_enc_ipv6_src_mask);
	memcpy(req->options.flower.key_enc_ipv6_src_mask, key_enc_ipv6_src_mask, req->options.flower._len.key_enc_ipv6_src_mask);
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ipv6_dst(struct tc_newtfilter_req *req,
						      const void *key_enc_ipv6_dst,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_dst);
	req->options.flower._len.key_enc_ipv6_dst = len;
	req->options.flower.key_enc_ipv6_dst = malloc(req->options.flower._len.key_enc_ipv6_dst);
	memcpy(req->options.flower.key_enc_ipv6_dst, key_enc_ipv6_dst, req->options.flower._len.key_enc_ipv6_dst);
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ipv6_dst_mask(struct tc_newtfilter_req *req,
							   const void *key_enc_ipv6_dst_mask,
							   size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_dst_mask);
	req->options.flower._len.key_enc_ipv6_dst_mask = len;
	req->options.flower.key_enc_ipv6_dst_mask = malloc(req->options.flower._len.key_enc_ipv6_dst_mask);
	memcpy(req->options.flower.key_enc_ipv6_dst_mask, key_enc_ipv6_dst_mask, req->options.flower._len.key_enc_ipv6_dst_mask);
}
static inline void
tc_newtfilter_req_set_options_flower_key_tcp_src_mask(struct tc_newtfilter_req *req,
						      __u16 key_tcp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_src_mask = 1;
	req->options.flower.key_tcp_src_mask = key_tcp_src_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_tcp_dst_mask(struct tc_newtfilter_req *req,
						      __u16 key_tcp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_dst_mask = 1;
	req->options.flower.key_tcp_dst_mask = key_tcp_dst_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_udp_src_mask(struct tc_newtfilter_req *req,
						      __u16 key_udp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_src_mask = 1;
	req->options.flower.key_udp_src_mask = key_udp_src_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_udp_dst_mask(struct tc_newtfilter_req *req,
						      __u16 key_udp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_dst_mask = 1;
	req->options.flower.key_udp_dst_mask = key_udp_dst_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_sctp_src_mask(struct tc_newtfilter_req *req,
						       __u16 key_sctp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_src_mask = 1;
	req->options.flower.key_sctp_src_mask = key_sctp_src_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_sctp_dst_mask(struct tc_newtfilter_req *req,
						       __u16 key_sctp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_dst_mask = 1;
	req->options.flower.key_sctp_dst_mask = key_sctp_dst_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_sctp_src(struct tc_newtfilter_req *req,
						  __u16 key_sctp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_src = 1;
	req->options.flower.key_sctp_src = key_sctp_src;
}
static inline void
tc_newtfilter_req_set_options_flower_key_sctp_dst(struct tc_newtfilter_req *req,
						  __u16 key_sctp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_dst = 1;
	req->options.flower.key_sctp_dst = key_sctp_dst;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_udp_src_port(struct tc_newtfilter_req *req,
							  __u16 key_enc_udp_src_port /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_src_port = 1;
	req->options.flower.key_enc_udp_src_port = key_enc_udp_src_port;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_udp_src_port_mask(struct tc_newtfilter_req *req,
							       __u16 key_enc_udp_src_port_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_src_port_mask = 1;
	req->options.flower.key_enc_udp_src_port_mask = key_enc_udp_src_port_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_udp_dst_port(struct tc_newtfilter_req *req,
							  __u16 key_enc_udp_dst_port /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_dst_port = 1;
	req->options.flower.key_enc_udp_dst_port = key_enc_udp_dst_port;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_udp_dst_port_mask(struct tc_newtfilter_req *req,
							       __u16 key_enc_udp_dst_port_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_dst_port_mask = 1;
	req->options.flower.key_enc_udp_dst_port_mask = key_enc_udp_dst_port_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_flags(struct tc_newtfilter_req *req,
					       __u32 key_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_flags = 1;
	req->options.flower.key_flags = key_flags;
}
static inline void
tc_newtfilter_req_set_options_flower_key_flags_mask(struct tc_newtfilter_req *req,
						    __u32 key_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_flags_mask = 1;
	req->options.flower.key_flags_mask = key_flags_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_icmpv4_code(struct tc_newtfilter_req *req,
						     __u8 key_icmpv4_code)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_code = 1;
	req->options.flower.key_icmpv4_code = key_icmpv4_code;
}
static inline void
tc_newtfilter_req_set_options_flower_key_icmpv4_code_mask(struct tc_newtfilter_req *req,
							  __u8 key_icmpv4_code_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_code_mask = 1;
	req->options.flower.key_icmpv4_code_mask = key_icmpv4_code_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_icmpv4_type(struct tc_newtfilter_req *req,
						     __u8 key_icmpv4_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_type = 1;
	req->options.flower.key_icmpv4_type = key_icmpv4_type;
}
static inline void
tc_newtfilter_req_set_options_flower_key_icmpv4_type_mask(struct tc_newtfilter_req *req,
							  __u8 key_icmpv4_type_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_type_mask = 1;
	req->options.flower.key_icmpv4_type_mask = key_icmpv4_type_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_icmpv6_code(struct tc_newtfilter_req *req,
						     __u8 key_icmpv6_code)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_code = 1;
	req->options.flower.key_icmpv6_code = key_icmpv6_code;
}
static inline void
tc_newtfilter_req_set_options_flower_key_icmpv6_code_mask(struct tc_newtfilter_req *req,
							  __u8 key_icmpv6_code_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_code_mask = 1;
	req->options.flower.key_icmpv6_code_mask = key_icmpv6_code_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_icmpv6_type(struct tc_newtfilter_req *req,
						     __u8 key_icmpv6_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_type = 1;
	req->options.flower.key_icmpv6_type = key_icmpv6_type;
}
static inline void
tc_newtfilter_req_set_options_flower_key_icmpv6_type_mask(struct tc_newtfilter_req *req,
							  __u8 key_icmpv6_type_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_type_mask = 1;
	req->options.flower.key_icmpv6_type_mask = key_icmpv6_type_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_sip(struct tc_newtfilter_req *req,
						 __u32 key_arp_sip /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_sip = 1;
	req->options.flower.key_arp_sip = key_arp_sip;
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_sip_mask(struct tc_newtfilter_req *req,
						      __u32 key_arp_sip_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_sip_mask = 1;
	req->options.flower.key_arp_sip_mask = key_arp_sip_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_tip(struct tc_newtfilter_req *req,
						 __u32 key_arp_tip /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_tip = 1;
	req->options.flower.key_arp_tip = key_arp_tip;
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_tip_mask(struct tc_newtfilter_req *req,
						      __u32 key_arp_tip_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_tip_mask = 1;
	req->options.flower.key_arp_tip_mask = key_arp_tip_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_op(struct tc_newtfilter_req *req,
						__u8 key_arp_op)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_op = 1;
	req->options.flower.key_arp_op = key_arp_op;
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_op_mask(struct tc_newtfilter_req *req,
						     __u8 key_arp_op_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_op_mask = 1;
	req->options.flower.key_arp_op_mask = key_arp_op_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_sha(struct tc_newtfilter_req *req,
						 const void *key_arp_sha,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_sha);
	req->options.flower._len.key_arp_sha = len;
	req->options.flower.key_arp_sha = malloc(req->options.flower._len.key_arp_sha);
	memcpy(req->options.flower.key_arp_sha, key_arp_sha, req->options.flower._len.key_arp_sha);
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_sha_mask(struct tc_newtfilter_req *req,
						      const void *key_arp_sha_mask,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_sha_mask);
	req->options.flower._len.key_arp_sha_mask = len;
	req->options.flower.key_arp_sha_mask = malloc(req->options.flower._len.key_arp_sha_mask);
	memcpy(req->options.flower.key_arp_sha_mask, key_arp_sha_mask, req->options.flower._len.key_arp_sha_mask);
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_tha(struct tc_newtfilter_req *req,
						 const void *key_arp_tha,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_tha);
	req->options.flower._len.key_arp_tha = len;
	req->options.flower.key_arp_tha = malloc(req->options.flower._len.key_arp_tha);
	memcpy(req->options.flower.key_arp_tha, key_arp_tha, req->options.flower._len.key_arp_tha);
}
static inline void
tc_newtfilter_req_set_options_flower_key_arp_tha_mask(struct tc_newtfilter_req *req,
						      const void *key_arp_tha_mask,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_tha_mask);
	req->options.flower._len.key_arp_tha_mask = len;
	req->options.flower.key_arp_tha_mask = malloc(req->options.flower._len.key_arp_tha_mask);
	memcpy(req->options.flower.key_arp_tha_mask, key_arp_tha_mask, req->options.flower._len.key_arp_tha_mask);
}
static inline void
tc_newtfilter_req_set_options_flower_key_mpls_ttl(struct tc_newtfilter_req *req,
						  __u8 key_mpls_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_ttl = 1;
	req->options.flower.key_mpls_ttl = key_mpls_ttl;
}
static inline void
tc_newtfilter_req_set_options_flower_key_mpls_bos(struct tc_newtfilter_req *req,
						  __u8 key_mpls_bos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_bos = 1;
	req->options.flower.key_mpls_bos = key_mpls_bos;
}
static inline void
tc_newtfilter_req_set_options_flower_key_mpls_tc(struct tc_newtfilter_req *req,
						 __u8 key_mpls_tc)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_tc = 1;
	req->options.flower.key_mpls_tc = key_mpls_tc;
}
static inline void
tc_newtfilter_req_set_options_flower_key_mpls_label(struct tc_newtfilter_req *req,
						    __u32 key_mpls_label /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_label = 1;
	req->options.flower.key_mpls_label = key_mpls_label;
}
static inline void
tc_newtfilter_req_set_options_flower_key_tcp_flags(struct tc_newtfilter_req *req,
						   __u16 key_tcp_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_flags = 1;
	req->options.flower.key_tcp_flags = key_tcp_flags;
}
static inline void
tc_newtfilter_req_set_options_flower_key_tcp_flags_mask(struct tc_newtfilter_req *req,
							__u16 key_tcp_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_flags_mask = 1;
	req->options.flower.key_tcp_flags_mask = key_tcp_flags_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ip_tos(struct tc_newtfilter_req *req,
						__u8 key_ip_tos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_tos = 1;
	req->options.flower.key_ip_tos = key_ip_tos;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ip_tos_mask(struct tc_newtfilter_req *req,
						     __u8 key_ip_tos_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_tos_mask = 1;
	req->options.flower.key_ip_tos_mask = key_ip_tos_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ip_ttl(struct tc_newtfilter_req *req,
						__u8 key_ip_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_ttl = 1;
	req->options.flower.key_ip_ttl = key_ip_ttl;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ip_ttl_mask(struct tc_newtfilter_req *req,
						     __u8 key_ip_ttl_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_ttl_mask = 1;
	req->options.flower.key_ip_ttl_mask = key_ip_ttl_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_cvlan_id(struct tc_newtfilter_req *req,
						  __u16 key_cvlan_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_id = 1;
	req->options.flower.key_cvlan_id = key_cvlan_id;
}
static inline void
tc_newtfilter_req_set_options_flower_key_cvlan_prio(struct tc_newtfilter_req *req,
						    __u8 key_cvlan_prio)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_prio = 1;
	req->options.flower.key_cvlan_prio = key_cvlan_prio;
}
static inline void
tc_newtfilter_req_set_options_flower_key_cvlan_eth_type(struct tc_newtfilter_req *req,
							__u16 key_cvlan_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_eth_type = 1;
	req->options.flower.key_cvlan_eth_type = key_cvlan_eth_type;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ip_tos(struct tc_newtfilter_req *req,
						    __u8 key_enc_ip_tos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_tos = 1;
	req->options.flower.key_enc_ip_tos = key_enc_ip_tos;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ip_tos_mask(struct tc_newtfilter_req *req,
							 __u8 key_enc_ip_tos_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_tos_mask = 1;
	req->options.flower.key_enc_ip_tos_mask = key_enc_ip_tos_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ip_ttl(struct tc_newtfilter_req *req,
						    __u8 key_enc_ip_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_ttl = 1;
	req->options.flower.key_enc_ip_ttl = key_enc_ip_ttl;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_ip_ttl_mask(struct tc_newtfilter_req *req,
							 __u8 key_enc_ip_ttl_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_ttl_mask = 1;
	req->options.flower.key_enc_ip_ttl_mask = key_enc_ip_ttl_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_geneve_class(struct tc_newtfilter_req *req,
							       __u16 class)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	req->options.flower.key_enc_opts.geneve._present.class = 1;
	req->options.flower.key_enc_opts.geneve.class = class;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_geneve_type(struct tc_newtfilter_req *req,
							      __u8 type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	req->options.flower.key_enc_opts.geneve._present.type = 1;
	req->options.flower.key_enc_opts.geneve.type = type;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_geneve_data(struct tc_newtfilter_req *req,
							      const void *data,
							      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	free(req->options.flower.key_enc_opts.geneve.data);
	req->options.flower.key_enc_opts.geneve._len.data = len;
	req->options.flower.key_enc_opts.geneve.data = malloc(req->options.flower.key_enc_opts.geneve._len.data);
	memcpy(req->options.flower.key_enc_opts.geneve.data, data, req->options.flower.key_enc_opts.geneve._len.data);
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_vxlan_gbp(struct tc_newtfilter_req *req,
							    __u32 gbp)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.vxlan = 1;
	req->options.flower.key_enc_opts.vxlan._present.gbp = 1;
	req->options.flower.key_enc_opts.vxlan.gbp = gbp;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_erspan_ver(struct tc_newtfilter_req *req,
							     __u8 ver)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.ver = 1;
	req->options.flower.key_enc_opts.erspan.ver = ver;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_erspan_index(struct tc_newtfilter_req *req,
							       __u32 index)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.index = 1;
	req->options.flower.key_enc_opts.erspan.index = index;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_erspan_dir(struct tc_newtfilter_req *req,
							     __u8 dir)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.dir = 1;
	req->options.flower.key_enc_opts.erspan.dir = dir;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_erspan_hwid(struct tc_newtfilter_req *req,
							      __u8 hwid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.hwid = 1;
	req->options.flower.key_enc_opts.erspan.hwid = hwid;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_gtp_pdu_type(struct tc_newtfilter_req *req,
							       __u8 pdu_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.gtp = 1;
	req->options.flower.key_enc_opts.gtp._present.pdu_type = 1;
	req->options.flower.key_enc_opts.gtp.pdu_type = pdu_type;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_gtp_qfi(struct tc_newtfilter_req *req,
							  __u8 qfi)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.gtp = 1;
	req->options.flower.key_enc_opts.gtp._present.qfi = 1;
	req->options.flower.key_enc_opts.gtp.qfi = qfi;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_geneve_class(struct tc_newtfilter_req *req,
								    __u16 class)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	req->options.flower.key_enc_opts_mask.geneve._present.class = 1;
	req->options.flower.key_enc_opts_mask.geneve.class = class;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_geneve_type(struct tc_newtfilter_req *req,
								   __u8 type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	req->options.flower.key_enc_opts_mask.geneve._present.type = 1;
	req->options.flower.key_enc_opts_mask.geneve.type = type;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_geneve_data(struct tc_newtfilter_req *req,
								   const void *data,
								   size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	free(req->options.flower.key_enc_opts_mask.geneve.data);
	req->options.flower.key_enc_opts_mask.geneve._len.data = len;
	req->options.flower.key_enc_opts_mask.geneve.data = malloc(req->options.flower.key_enc_opts_mask.geneve._len.data);
	memcpy(req->options.flower.key_enc_opts_mask.geneve.data, data, req->options.flower.key_enc_opts_mask.geneve._len.data);
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_vxlan_gbp(struct tc_newtfilter_req *req,
								 __u32 gbp)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.vxlan = 1;
	req->options.flower.key_enc_opts_mask.vxlan._present.gbp = 1;
	req->options.flower.key_enc_opts_mask.vxlan.gbp = gbp;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_erspan_ver(struct tc_newtfilter_req *req,
								  __u8 ver)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.ver = 1;
	req->options.flower.key_enc_opts_mask.erspan.ver = ver;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_erspan_index(struct tc_newtfilter_req *req,
								    __u32 index)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.index = 1;
	req->options.flower.key_enc_opts_mask.erspan.index = index;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_erspan_dir(struct tc_newtfilter_req *req,
								  __u8 dir)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.dir = 1;
	req->options.flower.key_enc_opts_mask.erspan.dir = dir;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_erspan_hwid(struct tc_newtfilter_req *req,
								   __u8 hwid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.hwid = 1;
	req->options.flower.key_enc_opts_mask.erspan.hwid = hwid;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_gtp_pdu_type(struct tc_newtfilter_req *req,
								    __u8 pdu_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.gtp = 1;
	req->options.flower.key_enc_opts_mask.gtp._present.pdu_type = 1;
	req->options.flower.key_enc_opts_mask.gtp.pdu_type = pdu_type;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_opts_mask_gtp_qfi(struct tc_newtfilter_req *req,
							       __u8 qfi)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.gtp = 1;
	req->options.flower.key_enc_opts_mask.gtp._present.qfi = 1;
	req->options.flower.key_enc_opts_mask.gtp.qfi = qfi;
}
static inline void
tc_newtfilter_req_set_options_flower_in_hw_count(struct tc_newtfilter_req *req,
						 __u32 in_hw_count)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.in_hw_count = 1;
	req->options.flower.in_hw_count = in_hw_count;
}
static inline void
tc_newtfilter_req_set_options_flower_key_port_src_min(struct tc_newtfilter_req *req,
						      __u16 key_port_src_min /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_src_min = 1;
	req->options.flower.key_port_src_min = key_port_src_min;
}
static inline void
tc_newtfilter_req_set_options_flower_key_port_src_max(struct tc_newtfilter_req *req,
						      __u16 key_port_src_max /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_src_max = 1;
	req->options.flower.key_port_src_max = key_port_src_max;
}
static inline void
tc_newtfilter_req_set_options_flower_key_port_dst_min(struct tc_newtfilter_req *req,
						      __u16 key_port_dst_min /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_dst_min = 1;
	req->options.flower.key_port_dst_min = key_port_dst_min;
}
static inline void
tc_newtfilter_req_set_options_flower_key_port_dst_max(struct tc_newtfilter_req *req,
						      __u16 key_port_dst_max /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_dst_max = 1;
	req->options.flower.key_port_dst_max = key_port_dst_max;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ct_state(struct tc_newtfilter_req *req,
						  __u16 key_ct_state)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_state = 1;
	req->options.flower.key_ct_state = key_ct_state;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ct_state_mask(struct tc_newtfilter_req *req,
						       __u16 key_ct_state_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_state_mask = 1;
	req->options.flower.key_ct_state_mask = key_ct_state_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ct_zone(struct tc_newtfilter_req *req,
						 __u16 key_ct_zone)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_zone = 1;
	req->options.flower.key_ct_zone = key_ct_zone;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ct_zone_mask(struct tc_newtfilter_req *req,
						      __u16 key_ct_zone_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_zone_mask = 1;
	req->options.flower.key_ct_zone_mask = key_ct_zone_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ct_mark(struct tc_newtfilter_req *req,
						 __u32 key_ct_mark)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_mark = 1;
	req->options.flower.key_ct_mark = key_ct_mark;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ct_mark_mask(struct tc_newtfilter_req *req,
						      __u32 key_ct_mark_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_mark_mask = 1;
	req->options.flower.key_ct_mark_mask = key_ct_mark_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ct_labels(struct tc_newtfilter_req *req,
						   const void *key_ct_labels,
						   size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ct_labels);
	req->options.flower._len.key_ct_labels = len;
	req->options.flower.key_ct_labels = malloc(req->options.flower._len.key_ct_labels);
	memcpy(req->options.flower.key_ct_labels, key_ct_labels, req->options.flower._len.key_ct_labels);
}
static inline void
tc_newtfilter_req_set_options_flower_key_ct_labels_mask(struct tc_newtfilter_req *req,
							const void *key_ct_labels_mask,
							size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ct_labels_mask);
	req->options.flower._len.key_ct_labels_mask = len;
	req->options.flower.key_ct_labels_mask = malloc(req->options.flower._len.key_ct_labels_mask);
	memcpy(req->options.flower.key_ct_labels_mask, key_ct_labels_mask, req->options.flower._len.key_ct_labels_mask);
}
static inline void
tc_newtfilter_req_set_options_flower_key_mpls_opts_lse_depth(struct tc_newtfilter_req *req,
							     __u8 lse_depth)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_depth = 1;
	req->options.flower.key_mpls_opts.lse_depth = lse_depth;
}
static inline void
tc_newtfilter_req_set_options_flower_key_mpls_opts_lse_ttl(struct tc_newtfilter_req *req,
							   __u8 lse_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_ttl = 1;
	req->options.flower.key_mpls_opts.lse_ttl = lse_ttl;
}
static inline void
tc_newtfilter_req_set_options_flower_key_mpls_opts_lse_bos(struct tc_newtfilter_req *req,
							   __u8 lse_bos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_bos = 1;
	req->options.flower.key_mpls_opts.lse_bos = lse_bos;
}
static inline void
tc_newtfilter_req_set_options_flower_key_mpls_opts_lse_tc(struct tc_newtfilter_req *req,
							  __u8 lse_tc)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_tc = 1;
	req->options.flower.key_mpls_opts.lse_tc = lse_tc;
}
static inline void
tc_newtfilter_req_set_options_flower_key_mpls_opts_lse_label(struct tc_newtfilter_req *req,
							     __u32 lse_label)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_label = 1;
	req->options.flower.key_mpls_opts.lse_label = lse_label;
}
static inline void
tc_newtfilter_req_set_options_flower_key_hash(struct tc_newtfilter_req *req,
					      __u32 key_hash)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_hash = 1;
	req->options.flower.key_hash = key_hash;
}
static inline void
tc_newtfilter_req_set_options_flower_key_hash_mask(struct tc_newtfilter_req *req,
						   __u32 key_hash_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_hash_mask = 1;
	req->options.flower.key_hash_mask = key_hash_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_num_of_vlans(struct tc_newtfilter_req *req,
						      __u8 key_num_of_vlans)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_num_of_vlans = 1;
	req->options.flower.key_num_of_vlans = key_num_of_vlans;
}
static inline void
tc_newtfilter_req_set_options_flower_key_pppoe_sid(struct tc_newtfilter_req *req,
						   __u16 key_pppoe_sid /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_pppoe_sid = 1;
	req->options.flower.key_pppoe_sid = key_pppoe_sid;
}
static inline void
tc_newtfilter_req_set_options_flower_key_ppp_proto(struct tc_newtfilter_req *req,
						   __u16 key_ppp_proto /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ppp_proto = 1;
	req->options.flower.key_ppp_proto = key_ppp_proto;
}
static inline void
tc_newtfilter_req_set_options_flower_key_l2tpv3_sid(struct tc_newtfilter_req *req,
						    __u32 key_l2tpv3_sid /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_l2tpv3_sid = 1;
	req->options.flower.key_l2tpv3_sid = key_l2tpv3_sid;
}
static inline void
tc_newtfilter_req_set_options_flower_l2_miss(struct tc_newtfilter_req *req,
					     __u8 l2_miss)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.l2_miss = 1;
	req->options.flower.l2_miss = l2_miss;
}
static inline void
tc_newtfilter_req_set_options_flower_key_cfm_md_level(struct tc_newtfilter_req *req,
						      __u8 md_level)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cfm = 1;
	req->options.flower.key_cfm._present.md_level = 1;
	req->options.flower.key_cfm.md_level = md_level;
}
static inline void
tc_newtfilter_req_set_options_flower_key_cfm_opcode(struct tc_newtfilter_req *req,
						    __u8 opcode)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cfm = 1;
	req->options.flower.key_cfm._present.opcode = 1;
	req->options.flower.key_cfm.opcode = opcode;
}
static inline void
tc_newtfilter_req_set_options_flower_key_spi(struct tc_newtfilter_req *req,
					     __u32 key_spi /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_spi = 1;
	req->options.flower.key_spi = key_spi;
}
static inline void
tc_newtfilter_req_set_options_flower_key_spi_mask(struct tc_newtfilter_req *req,
						  __u32 key_spi_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_spi_mask = 1;
	req->options.flower.key_spi_mask = key_spi_mask;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_flags(struct tc_newtfilter_req *req,
						   __u32 key_enc_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_flags = 1;
	req->options.flower.key_enc_flags = key_enc_flags;
}
static inline void
tc_newtfilter_req_set_options_flower_key_enc_flags_mask(struct tc_newtfilter_req *req,
							__u32 key_enc_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_flags_mask = 1;
	req->options.flower.key_enc_flags_mask = key_enc_flags_mask;
}
static inline void
tc_newtfilter_req_set_options_fq_plimit(struct tc_newtfilter_req *req,
					__u32 plimit)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.plimit = 1;
	req->options.fq.plimit = plimit;
}
static inline void
tc_newtfilter_req_set_options_fq_flow_plimit(struct tc_newtfilter_req *req,
					     __u32 flow_plimit)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_plimit = 1;
	req->options.fq.flow_plimit = flow_plimit;
}
static inline void
tc_newtfilter_req_set_options_fq_quantum(struct tc_newtfilter_req *req,
					 __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.quantum = 1;
	req->options.fq.quantum = quantum;
}
static inline void
tc_newtfilter_req_set_options_fq_initial_quantum(struct tc_newtfilter_req *req,
						 __u32 initial_quantum)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.initial_quantum = 1;
	req->options.fq.initial_quantum = initial_quantum;
}
static inline void
tc_newtfilter_req_set_options_fq_rate_enable(struct tc_newtfilter_req *req,
					     __u32 rate_enable)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.rate_enable = 1;
	req->options.fq.rate_enable = rate_enable;
}
static inline void
tc_newtfilter_req_set_options_fq_flow_default_rate(struct tc_newtfilter_req *req,
						   __u32 flow_default_rate)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_default_rate = 1;
	req->options.fq.flow_default_rate = flow_default_rate;
}
static inline void
tc_newtfilter_req_set_options_fq_flow_max_rate(struct tc_newtfilter_req *req,
					       __u32 flow_max_rate)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_max_rate = 1;
	req->options.fq.flow_max_rate = flow_max_rate;
}
static inline void
tc_newtfilter_req_set_options_fq_buckets_log(struct tc_newtfilter_req *req,
					     __u32 buckets_log)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.buckets_log = 1;
	req->options.fq.buckets_log = buckets_log;
}
static inline void
tc_newtfilter_req_set_options_fq_flow_refill_delay(struct tc_newtfilter_req *req,
						   __u32 flow_refill_delay)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_refill_delay = 1;
	req->options.fq.flow_refill_delay = flow_refill_delay;
}
static inline void
tc_newtfilter_req_set_options_fq_orphan_mask(struct tc_newtfilter_req *req,
					     __u32 orphan_mask)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.orphan_mask = 1;
	req->options.fq.orphan_mask = orphan_mask;
}
static inline void
tc_newtfilter_req_set_options_fq_low_rate_threshold(struct tc_newtfilter_req *req,
						    __u32 low_rate_threshold)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.low_rate_threshold = 1;
	req->options.fq.low_rate_threshold = low_rate_threshold;
}
static inline void
tc_newtfilter_req_set_options_fq_ce_threshold(struct tc_newtfilter_req *req,
					      __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.ce_threshold = 1;
	req->options.fq.ce_threshold = ce_threshold;
}
static inline void
tc_newtfilter_req_set_options_fq_timer_slack(struct tc_newtfilter_req *req,
					     __u32 timer_slack)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.timer_slack = 1;
	req->options.fq.timer_slack = timer_slack;
}
static inline void
tc_newtfilter_req_set_options_fq_horizon(struct tc_newtfilter_req *req,
					 __u32 horizon)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.horizon = 1;
	req->options.fq.horizon = horizon;
}
static inline void
tc_newtfilter_req_set_options_fq_horizon_drop(struct tc_newtfilter_req *req,
					      __u8 horizon_drop)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.horizon_drop = 1;
	req->options.fq.horizon_drop = horizon_drop;
}
static inline void
tc_newtfilter_req_set_options_fq_priomap(struct tc_newtfilter_req *req,
					 const void *priomap, size_t len)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	free(req->options.fq.priomap);
	req->options.fq._len.priomap = len;
	req->options.fq.priomap = malloc(req->options.fq._len.priomap);
	memcpy(req->options.fq.priomap, priomap, req->options.fq._len.priomap);
}
static inline void
tc_newtfilter_req_set_options_fq_weights(struct tc_newtfilter_req *req,
					 __s32 *weights, size_t count)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	free(req->options.fq.weights);
	req->options.fq._count.weights = count;
	count *= sizeof(__s32);
	req->options.fq.weights = malloc(count);
	memcpy(req->options.fq.weights, weights, count);
}
static inline void
tc_newtfilter_req_set_options_fq_codel_target(struct tc_newtfilter_req *req,
					      __u32 target)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.target = 1;
	req->options.fq_codel.target = target;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_limit(struct tc_newtfilter_req *req,
					     __u32 limit)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.limit = 1;
	req->options.fq_codel.limit = limit;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_interval(struct tc_newtfilter_req *req,
						__u32 interval)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.interval = 1;
	req->options.fq_codel.interval = interval;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_ecn(struct tc_newtfilter_req *req,
					   __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ecn = 1;
	req->options.fq_codel.ecn = ecn;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_flows(struct tc_newtfilter_req *req,
					     __u32 flows)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.flows = 1;
	req->options.fq_codel.flows = flows;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_quantum(struct tc_newtfilter_req *req,
					       __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.quantum = 1;
	req->options.fq_codel.quantum = quantum;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_ce_threshold(struct tc_newtfilter_req *req,
						    __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold = 1;
	req->options.fq_codel.ce_threshold = ce_threshold;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_drop_batch_size(struct tc_newtfilter_req *req,
						       __u32 drop_batch_size)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.drop_batch_size = 1;
	req->options.fq_codel.drop_batch_size = drop_batch_size;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_memory_limit(struct tc_newtfilter_req *req,
						    __u32 memory_limit)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.memory_limit = 1;
	req->options.fq_codel.memory_limit = memory_limit;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_ce_threshold_selector(struct tc_newtfilter_req *req,
							     __u8 ce_threshold_selector)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold_selector = 1;
	req->options.fq_codel.ce_threshold_selector = ce_threshold_selector;
}
static inline void
tc_newtfilter_req_set_options_fq_codel_ce_threshold_mask(struct tc_newtfilter_req *req,
							 __u8 ce_threshold_mask)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold_mask = 1;
	req->options.fq_codel.ce_threshold_mask = ce_threshold_mask;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_limit(struct tc_newtfilter_req *req,
					   __u32 limit)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.limit = 1;
	req->options.fq_pie.limit = limit;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_flows(struct tc_newtfilter_req *req,
					   __u32 flows)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.flows = 1;
	req->options.fq_pie.flows = flows;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_target(struct tc_newtfilter_req *req,
					    __u32 target)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.target = 1;
	req->options.fq_pie.target = target;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_tupdate(struct tc_newtfilter_req *req,
					     __u32 tupdate)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.tupdate = 1;
	req->options.fq_pie.tupdate = tupdate;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_alpha(struct tc_newtfilter_req *req,
					   __u32 alpha)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.alpha = 1;
	req->options.fq_pie.alpha = alpha;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_beta(struct tc_newtfilter_req *req,
					  __u32 beta)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.beta = 1;
	req->options.fq_pie.beta = beta;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_quantum(struct tc_newtfilter_req *req,
					     __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.quantum = 1;
	req->options.fq_pie.quantum = quantum;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_memory_limit(struct tc_newtfilter_req *req,
						  __u32 memory_limit)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.memory_limit = 1;
	req->options.fq_pie.memory_limit = memory_limit;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_ecn_prob(struct tc_newtfilter_req *req,
					      __u32 ecn_prob)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.ecn_prob = 1;
	req->options.fq_pie.ecn_prob = ecn_prob;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_ecn(struct tc_newtfilter_req *req,
					 __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.ecn = 1;
	req->options.fq_pie.ecn = ecn;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_bytemode(struct tc_newtfilter_req *req,
					      __u32 bytemode)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.bytemode = 1;
	req->options.fq_pie.bytemode = bytemode;
}
static inline void
tc_newtfilter_req_set_options_fq_pie_dq_rate_estimator(struct tc_newtfilter_req *req,
						       __u32 dq_rate_estimator)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.dq_rate_estimator = 1;
	req->options.fq_pie.dq_rate_estimator = dq_rate_estimator;
}
static inline void
tc_newtfilter_req_set_options_fw_classid(struct tc_newtfilter_req *req,
					 __u32 classid)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.classid = 1;
	req->options.fw.classid = classid;
}
static inline void
tc_newtfilter_req_set_options_fw_police_tbf(struct tc_newtfilter_req *req,
					    const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.tbf);
	req->options.fw.police._len.tbf = len;
	req->options.fw.police.tbf = malloc(req->options.fw.police._len.tbf);
	memcpy(req->options.fw.police.tbf, tbf, req->options.fw.police._len.tbf);
}
static inline void
tc_newtfilter_req_set_options_fw_police_rate(struct tc_newtfilter_req *req,
					     const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.rate);
	req->options.fw.police._len.rate = len;
	req->options.fw.police.rate = malloc(req->options.fw.police._len.rate);
	memcpy(req->options.fw.police.rate, rate, req->options.fw.police._len.rate);
}
static inline void
tc_newtfilter_req_set_options_fw_police_peakrate(struct tc_newtfilter_req *req,
						 const void *peakrate,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.peakrate);
	req->options.fw.police._len.peakrate = len;
	req->options.fw.police.peakrate = malloc(req->options.fw.police._len.peakrate);
	memcpy(req->options.fw.police.peakrate, peakrate, req->options.fw.police._len.peakrate);
}
static inline void
tc_newtfilter_req_set_options_fw_police_avrate(struct tc_newtfilter_req *req,
					       __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.avrate = 1;
	req->options.fw.police.avrate = avrate;
}
static inline void
tc_newtfilter_req_set_options_fw_police_result(struct tc_newtfilter_req *req,
					       __u32 result)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.result = 1;
	req->options.fw.police.result = result;
}
static inline void
tc_newtfilter_req_set_options_fw_police_tm(struct tc_newtfilter_req *req,
					   const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.tm);
	req->options.fw.police._len.tm = len;
	req->options.fw.police.tm = malloc(req->options.fw.police._len.tm);
	memcpy(req->options.fw.police.tm, tm, req->options.fw.police._len.tm);
}
static inline void
tc_newtfilter_req_set_options_fw_police_rate64(struct tc_newtfilter_req *req,
					       __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.rate64 = 1;
	req->options.fw.police.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_fw_police_peakrate64(struct tc_newtfilter_req *req,
						   __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.peakrate64 = 1;
	req->options.fw.police.peakrate64 = peakrate64;
}
static inline void
tc_newtfilter_req_set_options_fw_police_pktrate64(struct tc_newtfilter_req *req,
						  __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.pktrate64 = 1;
	req->options.fw.police.pktrate64 = pktrate64;
}
static inline void
tc_newtfilter_req_set_options_fw_police_pktburst64(struct tc_newtfilter_req *req,
						   __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.pktburst64 = 1;
	req->options.fw.police.pktburst64 = pktburst64;
}
static inline void
tc_newtfilter_req_set_options_fw_indev(struct tc_newtfilter_req *req,
				       const char *indev)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	free(req->options.fw.indev);
	req->options.fw._len.indev = strlen(indev);
	req->options.fw.indev = malloc(req->options.fw._len.indev + 1);
	memcpy(req->options.fw.indev, indev, req->options.fw._len.indev);
	req->options.fw.indev[req->options.fw._len.indev] = 0;
}
static inline void
__tc_newtfilter_req_set_options_fw_act(struct tc_newtfilter_req *req,
				       struct tc_act_attrs *act,
				       unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	free(req->options.fw.act);
	req->options.fw.act = act;
	req->options.fw._count.act = n_act;
}
static inline void
tc_newtfilter_req_set_options_fw_mask(struct tc_newtfilter_req *req,
				      __u32 mask)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.mask = 1;
	req->options.fw.mask = mask;
}
static inline void
tc_newtfilter_req_set_options_gred_parms(struct tc_newtfilter_req *req,
					 const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.parms);
	req->options.gred._len.parms = len;
	req->options.gred.parms = malloc(req->options.gred._len.parms);
	memcpy(req->options.gred.parms, parms, req->options.gred._len.parms);
}
static inline void
tc_newtfilter_req_set_options_gred_stab(struct tc_newtfilter_req *req,
					__u8 *stab, size_t count)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.stab);
	req->options.gred._count.stab = count;
	count *= sizeof(__u8);
	req->options.gred.stab = malloc(count);
	memcpy(req->options.gred.stab, stab, count);
}
static inline void
tc_newtfilter_req_set_options_gred_dps(struct tc_newtfilter_req *req,
				       const void *dps, size_t len)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.dps);
	req->options.gred._len.dps = len;
	req->options.gred.dps = malloc(req->options.gred._len.dps);
	memcpy(req->options.gred.dps, dps, req->options.gred._len.dps);
}
static inline void
tc_newtfilter_req_set_options_gred_max_p(struct tc_newtfilter_req *req,
					 __u32 *max_p, size_t count)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.max_p);
	req->options.gred._count.max_p = count;
	count *= sizeof(__u32);
	req->options.gred.max_p = malloc(count);
	memcpy(req->options.gred.max_p, max_p, count);
}
static inline void
tc_newtfilter_req_set_options_gred_limit(struct tc_newtfilter_req *req,
					 __u32 limit)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	req->options.gred._present.limit = 1;
	req->options.gred.limit = limit;
}
static inline void
__tc_newtfilter_req_set_options_gred_vq_list_entry(struct tc_newtfilter_req *req,
						   struct tc_tca_gred_vq_entry_attrs *entry,
						   unsigned int n_entry)
{
	unsigned int i;

	req->_present.options = 1;
	req->options._present.gred = 1;
	req->options.gred._present.vq_list = 1;
	for (i = 0; i < req->options.gred.vq_list._count.entry; i++)
		tc_tca_gred_vq_entry_attrs_free(&req->options.gred.vq_list.entry[i]);
	free(req->options.gred.vq_list.entry);
	req->options.gred.vq_list.entry = entry;
	req->options.gred.vq_list._count.entry = n_entry;
}
static inline void
tc_newtfilter_req_set_options_hfsc(struct tc_newtfilter_req *req,
				   const void *hfsc, size_t len)
{
	req->_present.options = 1;
	free(req->options.hfsc);
	req->options._len.hfsc = len;
	req->options.hfsc = malloc(req->options._len.hfsc);
	memcpy(req->options.hfsc, hfsc, req->options._len.hfsc);
}
static inline void
tc_newtfilter_req_set_options_hhf_backlog_limit(struct tc_newtfilter_req *req,
						__u32 backlog_limit)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.backlog_limit = 1;
	req->options.hhf.backlog_limit = backlog_limit;
}
static inline void
tc_newtfilter_req_set_options_hhf_quantum(struct tc_newtfilter_req *req,
					  __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.quantum = 1;
	req->options.hhf.quantum = quantum;
}
static inline void
tc_newtfilter_req_set_options_hhf_hh_flows_limit(struct tc_newtfilter_req *req,
						 __u32 hh_flows_limit)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.hh_flows_limit = 1;
	req->options.hhf.hh_flows_limit = hh_flows_limit;
}
static inline void
tc_newtfilter_req_set_options_hhf_reset_timeout(struct tc_newtfilter_req *req,
						__u32 reset_timeout)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.reset_timeout = 1;
	req->options.hhf.reset_timeout = reset_timeout;
}
static inline void
tc_newtfilter_req_set_options_hhf_admit_bytes(struct tc_newtfilter_req *req,
					      __u32 admit_bytes)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.admit_bytes = 1;
	req->options.hhf.admit_bytes = admit_bytes;
}
static inline void
tc_newtfilter_req_set_options_hhf_evict_timeout(struct tc_newtfilter_req *req,
						__u32 evict_timeout)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.evict_timeout = 1;
	req->options.hhf.evict_timeout = evict_timeout;
}
static inline void
tc_newtfilter_req_set_options_hhf_non_hh_weight(struct tc_newtfilter_req *req,
						__u32 non_hh_weight)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.non_hh_weight = 1;
	req->options.hhf.non_hh_weight = non_hh_weight;
}
static inline void
tc_newtfilter_req_set_options_htb_parms(struct tc_newtfilter_req *req,
					const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.parms);
	req->options.htb._len.parms = len;
	req->options.htb.parms = malloc(req->options.htb._len.parms);
	memcpy(req->options.htb.parms, parms, req->options.htb._len.parms);
}
static inline void
tc_newtfilter_req_set_options_htb_init(struct tc_newtfilter_req *req,
				       const void *init, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.init);
	req->options.htb._len.init = len;
	req->options.htb.init = malloc(req->options.htb._len.init);
	memcpy(req->options.htb.init, init, req->options.htb._len.init);
}
static inline void
tc_newtfilter_req_set_options_htb_ctab(struct tc_newtfilter_req *req,
				       const void *ctab, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.ctab);
	req->options.htb._len.ctab = len;
	req->options.htb.ctab = malloc(req->options.htb._len.ctab);
	memcpy(req->options.htb.ctab, ctab, req->options.htb._len.ctab);
}
static inline void
tc_newtfilter_req_set_options_htb_rtab(struct tc_newtfilter_req *req,
				       const void *rtab, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.rtab);
	req->options.htb._len.rtab = len;
	req->options.htb.rtab = malloc(req->options.htb._len.rtab);
	memcpy(req->options.htb.rtab, rtab, req->options.htb._len.rtab);
}
static inline void
tc_newtfilter_req_set_options_htb_direct_qlen(struct tc_newtfilter_req *req,
					      __u32 direct_qlen)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.direct_qlen = 1;
	req->options.htb.direct_qlen = direct_qlen;
}
static inline void
tc_newtfilter_req_set_options_htb_rate64(struct tc_newtfilter_req *req,
					 __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.rate64 = 1;
	req->options.htb.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_htb_ceil64(struct tc_newtfilter_req *req,
					 __u64 ceil64)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.ceil64 = 1;
	req->options.htb.ceil64 = ceil64;
}
static inline void
tc_newtfilter_req_set_options_htb_offload(struct tc_newtfilter_req *req)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.offload = 1;
}
static inline void
tc_newtfilter_req_set_options_ingress(struct tc_newtfilter_req *req)
{
	req->_present.options = 1;
	req->options._present.ingress = 1;
}
static inline void
tc_newtfilter_req_set_options_matchall_classid(struct tc_newtfilter_req *req,
					       __u32 classid)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	req->options.matchall._present.classid = 1;
	req->options.matchall.classid = classid;
}
static inline void
__tc_newtfilter_req_set_options_matchall_act(struct tc_newtfilter_req *req,
					     struct tc_act_attrs *act,
					     unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	free(req->options.matchall.act);
	req->options.matchall.act = act;
	req->options.matchall._count.act = n_act;
}
static inline void
tc_newtfilter_req_set_options_matchall_flags(struct tc_newtfilter_req *req,
					     __u32 flags)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	req->options.matchall._present.flags = 1;
	req->options.matchall.flags = flags;
}
static inline void
tc_newtfilter_req_set_options_matchall_pcnt(struct tc_newtfilter_req *req,
					    const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	free(req->options.matchall.pcnt);
	req->options.matchall._len.pcnt = len;
	req->options.matchall.pcnt = malloc(req->options.matchall._len.pcnt);
	memcpy(req->options.matchall.pcnt, pcnt, req->options.matchall._len.pcnt);
}
static inline void
tc_newtfilter_req_set_options_mq(struct tc_newtfilter_req *req)
{
	req->_present.options = 1;
	req->options._present.mq = 1;
}
static inline void
tc_newtfilter_req_set_options_mqprio(struct tc_newtfilter_req *req,
				     const void *mqprio, size_t len)
{
	req->_present.options = 1;
	free(req->options.mqprio);
	req->options._len.mqprio = len;
	req->options.mqprio = malloc(req->options._len.mqprio);
	memcpy(req->options.mqprio, mqprio, req->options._len.mqprio);
}
static inline void
tc_newtfilter_req_set_options_multiq(struct tc_newtfilter_req *req,
				     const void *multiq, size_t len)
{
	req->_present.options = 1;
	free(req->options.multiq);
	req->options._len.multiq = len;
	req->options.multiq = malloc(req->options._len.multiq);
	memcpy(req->options.multiq, multiq, req->options._len.multiq);
}
static inline void
tc_newtfilter_req_set_options_netem_corr(struct tc_newtfilter_req *req,
					 const void *corr, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.corr);
	req->options.netem._len.corr = len;
	req->options.netem.corr = malloc(req->options.netem._len.corr);
	memcpy(req->options.netem.corr, corr, req->options.netem._len.corr);
}
static inline void
tc_newtfilter_req_set_options_netem_delay_dist(struct tc_newtfilter_req *req,
					       __s16 *delay_dist, size_t count)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.delay_dist);
	req->options.netem._count.delay_dist = count;
	count *= sizeof(__s16);
	req->options.netem.delay_dist = malloc(count);
	memcpy(req->options.netem.delay_dist, delay_dist, count);
}
static inline void
tc_newtfilter_req_set_options_netem_reorder(struct tc_newtfilter_req *req,
					    const void *reorder, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.reorder);
	req->options.netem._len.reorder = len;
	req->options.netem.reorder = malloc(req->options.netem._len.reorder);
	memcpy(req->options.netem.reorder, reorder, req->options.netem._len.reorder);
}
static inline void
tc_newtfilter_req_set_options_netem_corrupt(struct tc_newtfilter_req *req,
					    const void *corrupt, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.corrupt);
	req->options.netem._len.corrupt = len;
	req->options.netem.corrupt = malloc(req->options.netem._len.corrupt);
	memcpy(req->options.netem.corrupt, corrupt, req->options.netem._len.corrupt);
}
static inline void
tc_newtfilter_req_set_options_netem_loss_gi(struct tc_newtfilter_req *req,
					    const void *gi, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.loss = 1;
	free(req->options.netem.loss.gi);
	req->options.netem.loss._len.gi = len;
	req->options.netem.loss.gi = malloc(req->options.netem.loss._len.gi);
	memcpy(req->options.netem.loss.gi, gi, req->options.netem.loss._len.gi);
}
static inline void
tc_newtfilter_req_set_options_netem_loss_ge(struct tc_newtfilter_req *req,
					    const void *ge, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.loss = 1;
	free(req->options.netem.loss.ge);
	req->options.netem.loss._len.ge = len;
	req->options.netem.loss.ge = malloc(req->options.netem.loss._len.ge);
	memcpy(req->options.netem.loss.ge, ge, req->options.netem.loss._len.ge);
}
static inline void
tc_newtfilter_req_set_options_netem_rate(struct tc_newtfilter_req *req,
					 const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.rate);
	req->options.netem._len.rate = len;
	req->options.netem.rate = malloc(req->options.netem._len.rate);
	memcpy(req->options.netem.rate, rate, req->options.netem._len.rate);
}
static inline void
tc_newtfilter_req_set_options_netem_ecn(struct tc_newtfilter_req *req,
					__u32 ecn)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.ecn = 1;
	req->options.netem.ecn = ecn;
}
static inline void
tc_newtfilter_req_set_options_netem_rate64(struct tc_newtfilter_req *req,
					   __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.rate64 = 1;
	req->options.netem.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_netem_pad(struct tc_newtfilter_req *req,
					__u32 pad)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.pad = 1;
	req->options.netem.pad = pad;
}
static inline void
tc_newtfilter_req_set_options_netem_latency64(struct tc_newtfilter_req *req,
					      __s64 latency64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.latency64 = 1;
	req->options.netem.latency64 = latency64;
}
static inline void
tc_newtfilter_req_set_options_netem_jitter64(struct tc_newtfilter_req *req,
					     __s64 jitter64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.jitter64 = 1;
	req->options.netem.jitter64 = jitter64;
}
static inline void
tc_newtfilter_req_set_options_netem_slot(struct tc_newtfilter_req *req,
					 const void *slot, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.slot);
	req->options.netem._len.slot = len;
	req->options.netem.slot = malloc(req->options.netem._len.slot);
	memcpy(req->options.netem.slot, slot, req->options.netem._len.slot);
}
static inline void
tc_newtfilter_req_set_options_netem_slot_dist(struct tc_newtfilter_req *req,
					      __s16 *slot_dist, size_t count)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.slot_dist);
	req->options.netem._count.slot_dist = count;
	count *= sizeof(__s16);
	req->options.netem.slot_dist = malloc(count);
	memcpy(req->options.netem.slot_dist, slot_dist, count);
}
static inline void
tc_newtfilter_req_set_options_netem_prng_seed(struct tc_newtfilter_req *req,
					      __u64 prng_seed)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.prng_seed = 1;
	req->options.netem.prng_seed = prng_seed;
}
static inline void
tc_newtfilter_req_set_options_pfifo(struct tc_newtfilter_req *req,
				    const void *pfifo, size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo);
	req->options._len.pfifo = len;
	req->options.pfifo = malloc(req->options._len.pfifo);
	memcpy(req->options.pfifo, pfifo, req->options._len.pfifo);
}
static inline void
tc_newtfilter_req_set_options_pfifo_fast(struct tc_newtfilter_req *req,
					 const void *pfifo_fast, size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo_fast);
	req->options._len.pfifo_fast = len;
	req->options.pfifo_fast = malloc(req->options._len.pfifo_fast);
	memcpy(req->options.pfifo_fast, pfifo_fast, req->options._len.pfifo_fast);
}
static inline void
tc_newtfilter_req_set_options_pfifo_head_drop(struct tc_newtfilter_req *req,
					      const void *pfifo_head_drop,
					      size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo_head_drop);
	req->options._len.pfifo_head_drop = len;
	req->options.pfifo_head_drop = malloc(req->options._len.pfifo_head_drop);
	memcpy(req->options.pfifo_head_drop, pfifo_head_drop, req->options._len.pfifo_head_drop);
}
static inline void
tc_newtfilter_req_set_options_pie_target(struct tc_newtfilter_req *req,
					 __u32 target)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.target = 1;
	req->options.pie.target = target;
}
static inline void
tc_newtfilter_req_set_options_pie_limit(struct tc_newtfilter_req *req,
					__u32 limit)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.limit = 1;
	req->options.pie.limit = limit;
}
static inline void
tc_newtfilter_req_set_options_pie_tupdate(struct tc_newtfilter_req *req,
					  __u32 tupdate)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.tupdate = 1;
	req->options.pie.tupdate = tupdate;
}
static inline void
tc_newtfilter_req_set_options_pie_alpha(struct tc_newtfilter_req *req,
					__u32 alpha)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.alpha = 1;
	req->options.pie.alpha = alpha;
}
static inline void
tc_newtfilter_req_set_options_pie_beta(struct tc_newtfilter_req *req,
				       __u32 beta)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.beta = 1;
	req->options.pie.beta = beta;
}
static inline void
tc_newtfilter_req_set_options_pie_ecn(struct tc_newtfilter_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.ecn = 1;
	req->options.pie.ecn = ecn;
}
static inline void
tc_newtfilter_req_set_options_pie_bytemode(struct tc_newtfilter_req *req,
					   __u32 bytemode)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.bytemode = 1;
	req->options.pie.bytemode = bytemode;
}
static inline void
tc_newtfilter_req_set_options_pie_dq_rate_estimator(struct tc_newtfilter_req *req,
						    __u32 dq_rate_estimator)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.dq_rate_estimator = 1;
	req->options.pie.dq_rate_estimator = dq_rate_estimator;
}
static inline void
tc_newtfilter_req_set_options_plug(struct tc_newtfilter_req *req,
				   const void *plug, size_t len)
{
	req->_present.options = 1;
	free(req->options.plug);
	req->options._len.plug = len;
	req->options.plug = malloc(req->options._len.plug);
	memcpy(req->options.plug, plug, req->options._len.plug);
}
static inline void
tc_newtfilter_req_set_options_prio(struct tc_newtfilter_req *req,
				   const void *prio, size_t len)
{
	req->_present.options = 1;
	free(req->options.prio);
	req->options._len.prio = len;
	req->options.prio = malloc(req->options._len.prio);
	memcpy(req->options.prio, prio, req->options._len.prio);
}
static inline void
tc_newtfilter_req_set_options_qfq_weight(struct tc_newtfilter_req *req,
					 __u32 weight)
{
	req->_present.options = 1;
	req->options._present.qfq = 1;
	req->options.qfq._present.weight = 1;
	req->options.qfq.weight = weight;
}
static inline void
tc_newtfilter_req_set_options_qfq_lmax(struct tc_newtfilter_req *req,
				       __u32 lmax)
{
	req->_present.options = 1;
	req->options._present.qfq = 1;
	req->options.qfq._present.lmax = 1;
	req->options.qfq.lmax = lmax;
}
static inline void
tc_newtfilter_req_set_options_red_parms(struct tc_newtfilter_req *req,
					const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	free(req->options.red.parms);
	req->options.red._len.parms = len;
	req->options.red.parms = malloc(req->options.red._len.parms);
	memcpy(req->options.red.parms, parms, req->options.red._len.parms);
}
static inline void
tc_newtfilter_req_set_options_red_stab(struct tc_newtfilter_req *req,
				       const void *stab, size_t len)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	free(req->options.red.stab);
	req->options.red._len.stab = len;
	req->options.red.stab = malloc(req->options.red._len.stab);
	memcpy(req->options.red.stab, stab, req->options.red._len.stab);
}
static inline void
tc_newtfilter_req_set_options_red_max_p(struct tc_newtfilter_req *req,
					__u32 max_p)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.max_p = 1;
	req->options.red.max_p = max_p;
}
static inline void
tc_newtfilter_req_set_options_red_flags(struct tc_newtfilter_req *req,
					struct nla_bitfield32 *flags)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.flags = 1;
	memcpy(&req->options.red.flags, flags, sizeof(struct nla_bitfield32));
}
static inline void
tc_newtfilter_req_set_options_red_early_drop_block(struct tc_newtfilter_req *req,
						   __u32 early_drop_block)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.early_drop_block = 1;
	req->options.red.early_drop_block = early_drop_block;
}
static inline void
tc_newtfilter_req_set_options_red_mark_block(struct tc_newtfilter_req *req,
					     __u32 mark_block)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.mark_block = 1;
	req->options.red.mark_block = mark_block;
}
static inline void
tc_newtfilter_req_set_options_route_classid(struct tc_newtfilter_req *req,
					    __u32 classid)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.classid = 1;
	req->options.route.classid = classid;
}
static inline void
tc_newtfilter_req_set_options_route_to(struct tc_newtfilter_req *req, __u32 to)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.to = 1;
	req->options.route.to = to;
}
static inline void
tc_newtfilter_req_set_options_route_from(struct tc_newtfilter_req *req,
					 __u32 from)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.from = 1;
	req->options.route.from = from;
}
static inline void
tc_newtfilter_req_set_options_route_iif(struct tc_newtfilter_req *req,
					__u32 iif)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.iif = 1;
	req->options.route.iif = iif;
}
static inline void
tc_newtfilter_req_set_options_route_police_tbf(struct tc_newtfilter_req *req,
					       const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.tbf);
	req->options.route.police._len.tbf = len;
	req->options.route.police.tbf = malloc(req->options.route.police._len.tbf);
	memcpy(req->options.route.police.tbf, tbf, req->options.route.police._len.tbf);
}
static inline void
tc_newtfilter_req_set_options_route_police_rate(struct tc_newtfilter_req *req,
						const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.rate);
	req->options.route.police._len.rate = len;
	req->options.route.police.rate = malloc(req->options.route.police._len.rate);
	memcpy(req->options.route.police.rate, rate, req->options.route.police._len.rate);
}
static inline void
tc_newtfilter_req_set_options_route_police_peakrate(struct tc_newtfilter_req *req,
						    const void *peakrate,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.peakrate);
	req->options.route.police._len.peakrate = len;
	req->options.route.police.peakrate = malloc(req->options.route.police._len.peakrate);
	memcpy(req->options.route.police.peakrate, peakrate, req->options.route.police._len.peakrate);
}
static inline void
tc_newtfilter_req_set_options_route_police_avrate(struct tc_newtfilter_req *req,
						  __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.avrate = 1;
	req->options.route.police.avrate = avrate;
}
static inline void
tc_newtfilter_req_set_options_route_police_result(struct tc_newtfilter_req *req,
						  __u32 result)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.result = 1;
	req->options.route.police.result = result;
}
static inline void
tc_newtfilter_req_set_options_route_police_tm(struct tc_newtfilter_req *req,
					      const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.tm);
	req->options.route.police._len.tm = len;
	req->options.route.police.tm = malloc(req->options.route.police._len.tm);
	memcpy(req->options.route.police.tm, tm, req->options.route.police._len.tm);
}
static inline void
tc_newtfilter_req_set_options_route_police_rate64(struct tc_newtfilter_req *req,
						  __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.rate64 = 1;
	req->options.route.police.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_route_police_peakrate64(struct tc_newtfilter_req *req,
						      __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.peakrate64 = 1;
	req->options.route.police.peakrate64 = peakrate64;
}
static inline void
tc_newtfilter_req_set_options_route_police_pktrate64(struct tc_newtfilter_req *req,
						     __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.pktrate64 = 1;
	req->options.route.police.pktrate64 = pktrate64;
}
static inline void
tc_newtfilter_req_set_options_route_police_pktburst64(struct tc_newtfilter_req *req,
						      __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.pktburst64 = 1;
	req->options.route.police.pktburst64 = pktburst64;
}
static inline void
__tc_newtfilter_req_set_options_route_act(struct tc_newtfilter_req *req,
					  struct tc_act_attrs *act,
					  unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	free(req->options.route.act);
	req->options.route.act = act;
	req->options.route._count.act = n_act;
}
static inline void
tc_newtfilter_req_set_options_sfb(struct tc_newtfilter_req *req,
				  const void *sfb, size_t len)
{
	req->_present.options = 1;
	free(req->options.sfb);
	req->options._len.sfb = len;
	req->options.sfb = malloc(req->options._len.sfb);
	memcpy(req->options.sfb, sfb, req->options._len.sfb);
}
static inline void
tc_newtfilter_req_set_options_sfq(struct tc_newtfilter_req *req,
				  const void *sfq, size_t len)
{
	req->_present.options = 1;
	free(req->options.sfq);
	req->options._len.sfq = len;
	req->options.sfq = malloc(req->options._len.sfq);
	memcpy(req->options.sfq, sfq, req->options._len.sfq);
}
static inline void
tc_newtfilter_req_set_options_taprio_priomap(struct tc_newtfilter_req *req,
					     const void *priomap, size_t len)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	free(req->options.taprio.priomap);
	req->options.taprio._len.priomap = len;
	req->options.taprio.priomap = malloc(req->options.taprio._len.priomap);
	memcpy(req->options.taprio.priomap, priomap, req->options.taprio._len.priomap);
}
static inline void
__tc_newtfilter_req_set_options_taprio_sched_entry_list_entry(struct tc_newtfilter_req *req,
							      struct tc_taprio_sched_entry *entry,
							      unsigned int n_entry)
{
	unsigned int i;

	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_entry_list = 1;
	for (i = 0; i < req->options.taprio.sched_entry_list._count.entry; i++)
		tc_taprio_sched_entry_free(&req->options.taprio.sched_entry_list.entry[i]);
	free(req->options.taprio.sched_entry_list.entry);
	req->options.taprio.sched_entry_list.entry = entry;
	req->options.taprio.sched_entry_list._count.entry = n_entry;
}
static inline void
tc_newtfilter_req_set_options_taprio_sched_base_time(struct tc_newtfilter_req *req,
						     __s64 sched_base_time)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_base_time = 1;
	req->options.taprio.sched_base_time = sched_base_time;
}
static inline void
tc_newtfilter_req_set_options_taprio_sched_single_entry_index(struct tc_newtfilter_req *req,
							      __u32 index)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.index = 1;
	req->options.taprio.sched_single_entry.index = index;
}
static inline void
tc_newtfilter_req_set_options_taprio_sched_single_entry_cmd(struct tc_newtfilter_req *req,
							    __u8 cmd)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.cmd = 1;
	req->options.taprio.sched_single_entry.cmd = cmd;
}
static inline void
tc_newtfilter_req_set_options_taprio_sched_single_entry_gate_mask(struct tc_newtfilter_req *req,
								  __u32 gate_mask)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.gate_mask = 1;
	req->options.taprio.sched_single_entry.gate_mask = gate_mask;
}
static inline void
tc_newtfilter_req_set_options_taprio_sched_single_entry_interval(struct tc_newtfilter_req *req,
								 __u32 interval)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.interval = 1;
	req->options.taprio.sched_single_entry.interval = interval;
}
static inline void
tc_newtfilter_req_set_options_taprio_sched_clockid(struct tc_newtfilter_req *req,
						   __s32 sched_clockid)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_clockid = 1;
	req->options.taprio.sched_clockid = sched_clockid;
}
static inline void
tc_newtfilter_req_set_options_taprio_admin_sched(struct tc_newtfilter_req *req,
						 const void *admin_sched,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	free(req->options.taprio.admin_sched);
	req->options.taprio._len.admin_sched = len;
	req->options.taprio.admin_sched = malloc(req->options.taprio._len.admin_sched);
	memcpy(req->options.taprio.admin_sched, admin_sched, req->options.taprio._len.admin_sched);
}
static inline void
tc_newtfilter_req_set_options_taprio_sched_cycle_time(struct tc_newtfilter_req *req,
						      __s64 sched_cycle_time)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_cycle_time = 1;
	req->options.taprio.sched_cycle_time = sched_cycle_time;
}
static inline void
tc_newtfilter_req_set_options_taprio_sched_cycle_time_extension(struct tc_newtfilter_req *req,
								__s64 sched_cycle_time_extension)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_cycle_time_extension = 1;
	req->options.taprio.sched_cycle_time_extension = sched_cycle_time_extension;
}
static inline void
tc_newtfilter_req_set_options_taprio_flags(struct tc_newtfilter_req *req,
					   __u32 flags)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.flags = 1;
	req->options.taprio.flags = flags;
}
static inline void
tc_newtfilter_req_set_options_taprio_txtime_delay(struct tc_newtfilter_req *req,
						  __u32 txtime_delay)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.txtime_delay = 1;
	req->options.taprio.txtime_delay = txtime_delay;
}
static inline void
tc_newtfilter_req_set_options_taprio_tc_entry_index(struct tc_newtfilter_req *req,
						    __u32 index)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.index = 1;
	req->options.taprio.tc_entry.index = index;
}
static inline void
tc_newtfilter_req_set_options_taprio_tc_entry_max_sdu(struct tc_newtfilter_req *req,
						      __u32 max_sdu)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.max_sdu = 1;
	req->options.taprio.tc_entry.max_sdu = max_sdu;
}
static inline void
tc_newtfilter_req_set_options_taprio_tc_entry_fp(struct tc_newtfilter_req *req,
						 __u32 fp)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.fp = 1;
	req->options.taprio.tc_entry.fp = fp;
}
static inline void
tc_newtfilter_req_set_options_tbf_parms(struct tc_newtfilter_req *req,
					const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.parms);
	req->options.tbf._len.parms = len;
	req->options.tbf.parms = malloc(req->options.tbf._len.parms);
	memcpy(req->options.tbf.parms, parms, req->options.tbf._len.parms);
}
static inline void
tc_newtfilter_req_set_options_tbf_rtab(struct tc_newtfilter_req *req,
				       const void *rtab, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.rtab);
	req->options.tbf._len.rtab = len;
	req->options.tbf.rtab = malloc(req->options.tbf._len.rtab);
	memcpy(req->options.tbf.rtab, rtab, req->options.tbf._len.rtab);
}
static inline void
tc_newtfilter_req_set_options_tbf_ptab(struct tc_newtfilter_req *req,
				       const void *ptab, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.ptab);
	req->options.tbf._len.ptab = len;
	req->options.tbf.ptab = malloc(req->options.tbf._len.ptab);
	memcpy(req->options.tbf.ptab, ptab, req->options.tbf._len.ptab);
}
static inline void
tc_newtfilter_req_set_options_tbf_rate64(struct tc_newtfilter_req *req,
					 __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.rate64 = 1;
	req->options.tbf.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_tbf_prate64(struct tc_newtfilter_req *req,
					  __u64 prate64)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.prate64 = 1;
	req->options.tbf.prate64 = prate64;
}
static inline void
tc_newtfilter_req_set_options_tbf_burst(struct tc_newtfilter_req *req,
					__u32 burst)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.burst = 1;
	req->options.tbf.burst = burst;
}
static inline void
tc_newtfilter_req_set_options_tbf_pburst(struct tc_newtfilter_req *req,
					 __u32 pburst)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.pburst = 1;
	req->options.tbf.pburst = pburst;
}
static inline void
tc_newtfilter_req_set_options_u32_classid(struct tc_newtfilter_req *req,
					  __u32 classid)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.classid = 1;
	req->options.u32.classid = classid;
}
static inline void
tc_newtfilter_req_set_options_u32_hash(struct tc_newtfilter_req *req,
				       __u32 hash)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.hash = 1;
	req->options.u32.hash = hash;
}
static inline void
tc_newtfilter_req_set_options_u32_link(struct tc_newtfilter_req *req,
				       __u32 link)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.link = 1;
	req->options.u32.link = link;
}
static inline void
tc_newtfilter_req_set_options_u32_divisor(struct tc_newtfilter_req *req,
					  __u32 divisor)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.divisor = 1;
	req->options.u32.divisor = divisor;
}
static inline void
tc_newtfilter_req_set_options_u32_sel(struct tc_newtfilter_req *req,
				      const void *sel, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.sel);
	req->options.u32._len.sel = len;
	req->options.u32.sel = malloc(req->options.u32._len.sel);
	memcpy(req->options.u32.sel, sel, req->options.u32._len.sel);
}
static inline void
tc_newtfilter_req_set_options_u32_police_tbf(struct tc_newtfilter_req *req,
					     const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.tbf);
	req->options.u32.police._len.tbf = len;
	req->options.u32.police.tbf = malloc(req->options.u32.police._len.tbf);
	memcpy(req->options.u32.police.tbf, tbf, req->options.u32.police._len.tbf);
}
static inline void
tc_newtfilter_req_set_options_u32_police_rate(struct tc_newtfilter_req *req,
					      const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.rate);
	req->options.u32.police._len.rate = len;
	req->options.u32.police.rate = malloc(req->options.u32.police._len.rate);
	memcpy(req->options.u32.police.rate, rate, req->options.u32.police._len.rate);
}
static inline void
tc_newtfilter_req_set_options_u32_police_peakrate(struct tc_newtfilter_req *req,
						  const void *peakrate,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.peakrate);
	req->options.u32.police._len.peakrate = len;
	req->options.u32.police.peakrate = malloc(req->options.u32.police._len.peakrate);
	memcpy(req->options.u32.police.peakrate, peakrate, req->options.u32.police._len.peakrate);
}
static inline void
tc_newtfilter_req_set_options_u32_police_avrate(struct tc_newtfilter_req *req,
						__u32 avrate)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.avrate = 1;
	req->options.u32.police.avrate = avrate;
}
static inline void
tc_newtfilter_req_set_options_u32_police_result(struct tc_newtfilter_req *req,
						__u32 result)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.result = 1;
	req->options.u32.police.result = result;
}
static inline void
tc_newtfilter_req_set_options_u32_police_tm(struct tc_newtfilter_req *req,
					    const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.tm);
	req->options.u32.police._len.tm = len;
	req->options.u32.police.tm = malloc(req->options.u32.police._len.tm);
	memcpy(req->options.u32.police.tm, tm, req->options.u32.police._len.tm);
}
static inline void
tc_newtfilter_req_set_options_u32_police_rate64(struct tc_newtfilter_req *req,
						__u64 rate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.rate64 = 1;
	req->options.u32.police.rate64 = rate64;
}
static inline void
tc_newtfilter_req_set_options_u32_police_peakrate64(struct tc_newtfilter_req *req,
						    __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.peakrate64 = 1;
	req->options.u32.police.peakrate64 = peakrate64;
}
static inline void
tc_newtfilter_req_set_options_u32_police_pktrate64(struct tc_newtfilter_req *req,
						   __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.pktrate64 = 1;
	req->options.u32.police.pktrate64 = pktrate64;
}
static inline void
tc_newtfilter_req_set_options_u32_police_pktburst64(struct tc_newtfilter_req *req,
						    __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.pktburst64 = 1;
	req->options.u32.police.pktburst64 = pktburst64;
}
static inline void
__tc_newtfilter_req_set_options_u32_act(struct tc_newtfilter_req *req,
					struct tc_act_attrs *act,
					unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.act);
	req->options.u32.act = act;
	req->options.u32._count.act = n_act;
}
static inline void
tc_newtfilter_req_set_options_u32_indev(struct tc_newtfilter_req *req,
					const char *indev)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.indev);
	req->options.u32._len.indev = strlen(indev);
	req->options.u32.indev = malloc(req->options.u32._len.indev + 1);
	memcpy(req->options.u32.indev, indev, req->options.u32._len.indev);
	req->options.u32.indev[req->options.u32._len.indev] = 0;
}
static inline void
tc_newtfilter_req_set_options_u32_pcnt(struct tc_newtfilter_req *req,
				       const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.pcnt);
	req->options.u32._len.pcnt = len;
	req->options.u32.pcnt = malloc(req->options.u32._len.pcnt);
	memcpy(req->options.u32.pcnt, pcnt, req->options.u32._len.pcnt);
}
static inline void
tc_newtfilter_req_set_options_u32_mark(struct tc_newtfilter_req *req,
				       const void *mark, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.mark);
	req->options.u32._len.mark = len;
	req->options.u32.mark = malloc(req->options.u32._len.mark);
	memcpy(req->options.u32.mark, mark, req->options.u32._len.mark);
}
static inline void
tc_newtfilter_req_set_options_u32_flags(struct tc_newtfilter_req *req,
					__u32 flags)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.flags = 1;
	req->options.u32.flags = flags;
}
static inline void
tc_newtfilter_req_set_rate(struct tc_newtfilter_req *req, const void *rate,
			   size_t len)
{
	free(req->rate);
	req->_len.rate = len;
	req->rate = malloc(req->_len.rate);
	memcpy(req->rate, rate, req->_len.rate);
}
static inline void
tc_newtfilter_req_set_chain(struct tc_newtfilter_req *req, __u32 chain)
{
	req->_present.chain = 1;
	req->chain = chain;
}
static inline void
tc_newtfilter_req_set_ingress_block(struct tc_newtfilter_req *req,
				    __u32 ingress_block)
{
	req->_present.ingress_block = 1;
	req->ingress_block = ingress_block;
}
static inline void
tc_newtfilter_req_set_egress_block(struct tc_newtfilter_req *req,
				   __u32 egress_block)
{
	req->_present.egress_block = 1;
	req->egress_block = egress_block;
}

/*
 * Get / dump tc filter information.
 */
int tc_newtfilter(struct ynl_sock *ys, struct tc_newtfilter_req *req);

/* ============== RTM_DELTFILTER ============== */
/* RTM_DELTFILTER - do */
struct tc_deltfilter_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;

	struct {
		__u32 chain:1;
	} _present;
	struct {
		__u32 kind;
	} _len;

	__u32 chain;
	char *kind;
};

static inline struct tc_deltfilter_req *tc_deltfilter_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_deltfilter_req));
}
void tc_deltfilter_req_free(struct tc_deltfilter_req *req);

static inline void
tc_deltfilter_req_set_nlflags(struct tc_deltfilter_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
tc_deltfilter_req_set_chain(struct tc_deltfilter_req *req, __u32 chain)
{
	req->_present.chain = 1;
	req->chain = chain;
}
static inline void
tc_deltfilter_req_set_kind(struct tc_deltfilter_req *req, const char *kind)
{
	free(req->kind);
	req->_len.kind = strlen(kind);
	req->kind = malloc(req->_len.kind + 1);
	memcpy(req->kind, kind, req->_len.kind);
	req->kind[req->_len.kind] = 0;
}

/*
 * Get / dump tc filter information.
 */
int tc_deltfilter(struct ynl_sock *ys, struct tc_deltfilter_req *req);

/* ============== RTM_GETTFILTER ============== */
/* RTM_GETTFILTER - do */
struct tc_gettfilter_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;

	struct {
		__u32 chain:1;
	} _present;
	struct {
		__u32 kind;
	} _len;

	__u32 chain;
	char *kind;
};

static inline struct tc_gettfilter_req *tc_gettfilter_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_gettfilter_req));
}
void tc_gettfilter_req_free(struct tc_gettfilter_req *req);

static inline void
tc_gettfilter_req_set_nlflags(struct tc_gettfilter_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
tc_gettfilter_req_set_chain(struct tc_gettfilter_req *req, __u32 chain)
{
	req->_present.chain = 1;
	req->chain = chain;
}
static inline void
tc_gettfilter_req_set_kind(struct tc_gettfilter_req *req, const char *kind)
{
	free(req->kind);
	req->_len.kind = strlen(kind);
	req->kind = malloc(req->_len.kind + 1);
	memcpy(req->kind, kind, req->_len.kind);
	req->kind[req->_len.kind] = 0;
}

struct tc_gettfilter_rsp {
	struct tcmsg _hdr;

	struct {
		__u32 options:1;
		__u32 xstats:1;
		__u32 fcnt:1;
		__u32 stats2:1;
		__u32 stab:1;
		__u32 chain:1;
		__u32 ingress_block:1;
		__u32 egress_block:1;
	} _present;
	struct {
		__u32 kind;
		__u32 stats;
		__u32 rate;
	} _len;

	char *kind;
	struct tc_options_msg options;
	struct tc_stats *stats;
	struct tc_tca_stats_app_msg xstats;
	struct gnet_estimator *rate;
	__u32 fcnt;
	struct tc_tca_stats_attrs stats2;
	struct tc_tca_stab_attrs stab;
	__u32 chain;
	__u32 ingress_block;
	__u32 egress_block;
};

void tc_gettfilter_rsp_free(struct tc_gettfilter_rsp *rsp);

/*
 * Get / dump tc filter information.
 */
struct tc_gettfilter_rsp *
tc_gettfilter(struct ynl_sock *ys, struct tc_gettfilter_req *req);

/* RTM_GETTFILTER - dump */
struct tc_gettfilter_req_dump {
	struct tcmsg _hdr;

	struct {
		__u32 chain:1;
		__u32 dump_flags:1;
	} _present;

	__u32 chain;
	struct nla_bitfield32 dump_flags;
};

static inline struct tc_gettfilter_req_dump *tc_gettfilter_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct tc_gettfilter_req_dump));
}
void tc_gettfilter_req_dump_free(struct tc_gettfilter_req_dump *req);

static inline void
tc_gettfilter_req_dump_set_chain(struct tc_gettfilter_req_dump *req,
				 __u32 chain)
{
	req->_present.chain = 1;
	req->chain = chain;
}
static inline void
tc_gettfilter_req_dump_set_dump_flags(struct tc_gettfilter_req_dump *req,
				      struct nla_bitfield32 *dump_flags)
{
	req->_present.dump_flags = 1;
	memcpy(&req->dump_flags, dump_flags, sizeof(struct nla_bitfield32));
}

struct tc_gettfilter_list {
	struct tc_gettfilter_list *next;
	struct tc_gettfilter_rsp obj __attribute__((aligned(8)));
};

void tc_gettfilter_list_free(struct tc_gettfilter_list *rsp);

struct tc_gettfilter_list *
tc_gettfilter_dump(struct ynl_sock *ys, struct tc_gettfilter_req_dump *req);

/* ============== RTM_NEWCHAIN ============== */
/* RTM_NEWCHAIN - do */
struct tc_newchain_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;

	struct {
		__u32 options:1;
		__u32 chain:1;
		__u32 ingress_block:1;
		__u32 egress_block:1;
	} _present;
	struct {
		__u32 kind;
		__u32 rate;
	} _len;

	char *kind;
	struct tc_options_msg options;
	struct gnet_estimator *rate;
	__u32 chain;
	__u32 ingress_block;
	__u32 egress_block;
};

static inline struct tc_newchain_req *tc_newchain_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_newchain_req));
}
void tc_newchain_req_free(struct tc_newchain_req *req);

static inline void
tc_newchain_req_set_nlflags(struct tc_newchain_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
tc_newchain_req_set_kind(struct tc_newchain_req *req, const char *kind)
{
	free(req->kind);
	req->_len.kind = strlen(kind);
	req->kind = malloc(req->_len.kind + 1);
	memcpy(req->kind, kind, req->_len.kind);
	req->kind[req->_len.kind] = 0;
}
static inline void
tc_newchain_req_set_options_basic_classid(struct tc_newchain_req *req,
					  __u32 classid)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.classid = 1;
	req->options.basic.classid = classid;
}
static inline void
tc_newchain_req_set_options_basic_ematches_tree_hdr(struct tc_newchain_req *req,
						    const void *tree_hdr,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.ematches = 1;
	free(req->options.basic.ematches.tree_hdr);
	req->options.basic.ematches._len.tree_hdr = len;
	req->options.basic.ematches.tree_hdr = malloc(req->options.basic.ematches._len.tree_hdr);
	memcpy(req->options.basic.ematches.tree_hdr, tree_hdr, req->options.basic.ematches._len.tree_hdr);
}
static inline void
tc_newchain_req_set_options_basic_ematches_tree_list(struct tc_newchain_req *req,
						     const void *tree_list,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.ematches = 1;
	free(req->options.basic.ematches.tree_list);
	req->options.basic.ematches._len.tree_list = len;
	req->options.basic.ematches.tree_list = malloc(req->options.basic.ematches._len.tree_list);
	memcpy(req->options.basic.ematches.tree_list, tree_list, req->options.basic.ematches._len.tree_list);
}
static inline void
__tc_newchain_req_set_options_basic_act(struct tc_newchain_req *req,
					struct tc_act_attrs *act,
					unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	free(req->options.basic.act);
	req->options.basic.act = act;
	req->options.basic._count.act = n_act;
}
static inline void
tc_newchain_req_set_options_basic_police_tbf(struct tc_newchain_req *req,
					     const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.tbf);
	req->options.basic.police._len.tbf = len;
	req->options.basic.police.tbf = malloc(req->options.basic.police._len.tbf);
	memcpy(req->options.basic.police.tbf, tbf, req->options.basic.police._len.tbf);
}
static inline void
tc_newchain_req_set_options_basic_police_rate(struct tc_newchain_req *req,
					      const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.rate);
	req->options.basic.police._len.rate = len;
	req->options.basic.police.rate = malloc(req->options.basic.police._len.rate);
	memcpy(req->options.basic.police.rate, rate, req->options.basic.police._len.rate);
}
static inline void
tc_newchain_req_set_options_basic_police_peakrate(struct tc_newchain_req *req,
						  const void *peakrate,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.peakrate);
	req->options.basic.police._len.peakrate = len;
	req->options.basic.police.peakrate = malloc(req->options.basic.police._len.peakrate);
	memcpy(req->options.basic.police.peakrate, peakrate, req->options.basic.police._len.peakrate);
}
static inline void
tc_newchain_req_set_options_basic_police_avrate(struct tc_newchain_req *req,
						__u32 avrate)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.avrate = 1;
	req->options.basic.police.avrate = avrate;
}
static inline void
tc_newchain_req_set_options_basic_police_result(struct tc_newchain_req *req,
						__u32 result)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.result = 1;
	req->options.basic.police.result = result;
}
static inline void
tc_newchain_req_set_options_basic_police_tm(struct tc_newchain_req *req,
					    const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	free(req->options.basic.police.tm);
	req->options.basic.police._len.tm = len;
	req->options.basic.police.tm = malloc(req->options.basic.police._len.tm);
	memcpy(req->options.basic.police.tm, tm, req->options.basic.police._len.tm);
}
static inline void
tc_newchain_req_set_options_basic_police_rate64(struct tc_newchain_req *req,
						__u64 rate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.rate64 = 1;
	req->options.basic.police.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_basic_police_peakrate64(struct tc_newchain_req *req,
						    __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.peakrate64 = 1;
	req->options.basic.police.peakrate64 = peakrate64;
}
static inline void
tc_newchain_req_set_options_basic_police_pktrate64(struct tc_newchain_req *req,
						   __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.pktrate64 = 1;
	req->options.basic.police.pktrate64 = pktrate64;
}
static inline void
tc_newchain_req_set_options_basic_police_pktburst64(struct tc_newchain_req *req,
						    __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	req->options.basic._present.police = 1;
	req->options.basic.police._present.pktburst64 = 1;
	req->options.basic.police.pktburst64 = pktburst64;
}
static inline void
tc_newchain_req_set_options_basic_pcnt(struct tc_newchain_req *req,
				       const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.basic = 1;
	free(req->options.basic.pcnt);
	req->options.basic._len.pcnt = len;
	req->options.basic.pcnt = malloc(req->options.basic._len.pcnt);
	memcpy(req->options.basic.pcnt, pcnt, req->options.basic._len.pcnt);
}
static inline void
__tc_newchain_req_set_options_bpf_act(struct tc_newchain_req *req,
				      struct tc_act_attrs *act,
				      unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.act);
	req->options.bpf.act = act;
	req->options.bpf._count.act = n_act;
}
static inline void
tc_newchain_req_set_options_bpf_police_tbf(struct tc_newchain_req *req,
					   const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.tbf);
	req->options.bpf.police._len.tbf = len;
	req->options.bpf.police.tbf = malloc(req->options.bpf.police._len.tbf);
	memcpy(req->options.bpf.police.tbf, tbf, req->options.bpf.police._len.tbf);
}
static inline void
tc_newchain_req_set_options_bpf_police_rate(struct tc_newchain_req *req,
					    const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.rate);
	req->options.bpf.police._len.rate = len;
	req->options.bpf.police.rate = malloc(req->options.bpf.police._len.rate);
	memcpy(req->options.bpf.police.rate, rate, req->options.bpf.police._len.rate);
}
static inline void
tc_newchain_req_set_options_bpf_police_peakrate(struct tc_newchain_req *req,
						const void *peakrate,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.peakrate);
	req->options.bpf.police._len.peakrate = len;
	req->options.bpf.police.peakrate = malloc(req->options.bpf.police._len.peakrate);
	memcpy(req->options.bpf.police.peakrate, peakrate, req->options.bpf.police._len.peakrate);
}
static inline void
tc_newchain_req_set_options_bpf_police_avrate(struct tc_newchain_req *req,
					      __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.avrate = 1;
	req->options.bpf.police.avrate = avrate;
}
static inline void
tc_newchain_req_set_options_bpf_police_result(struct tc_newchain_req *req,
					      __u32 result)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.result = 1;
	req->options.bpf.police.result = result;
}
static inline void
tc_newchain_req_set_options_bpf_police_tm(struct tc_newchain_req *req,
					  const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	free(req->options.bpf.police.tm);
	req->options.bpf.police._len.tm = len;
	req->options.bpf.police.tm = malloc(req->options.bpf.police._len.tm);
	memcpy(req->options.bpf.police.tm, tm, req->options.bpf.police._len.tm);
}
static inline void
tc_newchain_req_set_options_bpf_police_rate64(struct tc_newchain_req *req,
					      __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.rate64 = 1;
	req->options.bpf.police.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_bpf_police_peakrate64(struct tc_newchain_req *req,
						  __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.peakrate64 = 1;
	req->options.bpf.police.peakrate64 = peakrate64;
}
static inline void
tc_newchain_req_set_options_bpf_police_pktrate64(struct tc_newchain_req *req,
						 __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.pktrate64 = 1;
	req->options.bpf.police.pktrate64 = pktrate64;
}
static inline void
tc_newchain_req_set_options_bpf_police_pktburst64(struct tc_newchain_req *req,
						  __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.police = 1;
	req->options.bpf.police._present.pktburst64 = 1;
	req->options.bpf.police.pktburst64 = pktburst64;
}
static inline void
tc_newchain_req_set_options_bpf_classid(struct tc_newchain_req *req,
					__u32 classid)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.classid = 1;
	req->options.bpf.classid = classid;
}
static inline void
tc_newchain_req_set_options_bpf_ops_len(struct tc_newchain_req *req,
					__u16 ops_len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.ops_len = 1;
	req->options.bpf.ops_len = ops_len;
}
static inline void
tc_newchain_req_set_options_bpf_ops(struct tc_newchain_req *req,
				    const void *ops, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.ops);
	req->options.bpf._len.ops = len;
	req->options.bpf.ops = malloc(req->options.bpf._len.ops);
	memcpy(req->options.bpf.ops, ops, req->options.bpf._len.ops);
}
static inline void
tc_newchain_req_set_options_bpf_fd(struct tc_newchain_req *req, __u32 fd)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.fd = 1;
	req->options.bpf.fd = fd;
}
static inline void
tc_newchain_req_set_options_bpf_name(struct tc_newchain_req *req,
				     const char *name)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.name);
	req->options.bpf._len.name = strlen(name);
	req->options.bpf.name = malloc(req->options.bpf._len.name + 1);
	memcpy(req->options.bpf.name, name, req->options.bpf._len.name);
	req->options.bpf.name[req->options.bpf._len.name] = 0;
}
static inline void
tc_newchain_req_set_options_bpf_flags(struct tc_newchain_req *req, __u32 flags)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.flags = 1;
	req->options.bpf.flags = flags;
}
static inline void
tc_newchain_req_set_options_bpf_flags_gen(struct tc_newchain_req *req,
					  __u32 flags_gen)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.flags_gen = 1;
	req->options.bpf.flags_gen = flags_gen;
}
static inline void
tc_newchain_req_set_options_bpf_tag(struct tc_newchain_req *req,
				    const void *tag, size_t len)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	free(req->options.bpf.tag);
	req->options.bpf._len.tag = len;
	req->options.bpf.tag = malloc(req->options.bpf._len.tag);
	memcpy(req->options.bpf.tag, tag, req->options.bpf._len.tag);
}
static inline void
tc_newchain_req_set_options_bpf_id(struct tc_newchain_req *req, __u32 id)
{
	req->_present.options = 1;
	req->options._present.bpf = 1;
	req->options.bpf._present.id = 1;
	req->options.bpf.id = id;
}
static inline void
tc_newchain_req_set_options_bfifo(struct tc_newchain_req *req,
				  const void *bfifo, size_t len)
{
	req->_present.options = 1;
	free(req->options.bfifo);
	req->options._len.bfifo = len;
	req->options.bfifo = malloc(req->options._len.bfifo);
	memcpy(req->options.bfifo, bfifo, req->options._len.bfifo);
}
static inline void
tc_newchain_req_set_options_cake_base_rate64(struct tc_newchain_req *req,
					     __u64 base_rate64)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.base_rate64 = 1;
	req->options.cake.base_rate64 = base_rate64;
}
static inline void
tc_newchain_req_set_options_cake_diffserv_mode(struct tc_newchain_req *req,
					       __u32 diffserv_mode)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.diffserv_mode = 1;
	req->options.cake.diffserv_mode = diffserv_mode;
}
static inline void
tc_newchain_req_set_options_cake_atm(struct tc_newchain_req *req, __u32 atm)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.atm = 1;
	req->options.cake.atm = atm;
}
static inline void
tc_newchain_req_set_options_cake_flow_mode(struct tc_newchain_req *req,
					   __u32 flow_mode)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.flow_mode = 1;
	req->options.cake.flow_mode = flow_mode;
}
static inline void
tc_newchain_req_set_options_cake_overhead(struct tc_newchain_req *req,
					  __u32 overhead)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.overhead = 1;
	req->options.cake.overhead = overhead;
}
static inline void
tc_newchain_req_set_options_cake_rtt(struct tc_newchain_req *req, __u32 rtt)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.rtt = 1;
	req->options.cake.rtt = rtt;
}
static inline void
tc_newchain_req_set_options_cake_target(struct tc_newchain_req *req,
					__u32 target)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.target = 1;
	req->options.cake.target = target;
}
static inline void
tc_newchain_req_set_options_cake_autorate(struct tc_newchain_req *req,
					  __u32 autorate)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.autorate = 1;
	req->options.cake.autorate = autorate;
}
static inline void
tc_newchain_req_set_options_cake_memory(struct tc_newchain_req *req,
					__u32 memory)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.memory = 1;
	req->options.cake.memory = memory;
}
static inline void
tc_newchain_req_set_options_cake_nat(struct tc_newchain_req *req, __u32 nat)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.nat = 1;
	req->options.cake.nat = nat;
}
static inline void
tc_newchain_req_set_options_cake_raw(struct tc_newchain_req *req, __u32 raw)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.raw = 1;
	req->options.cake.raw = raw;
}
static inline void
tc_newchain_req_set_options_cake_wash(struct tc_newchain_req *req, __u32 wash)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.wash = 1;
	req->options.cake.wash = wash;
}
static inline void
tc_newchain_req_set_options_cake_mpu(struct tc_newchain_req *req, __u32 mpu)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.mpu = 1;
	req->options.cake.mpu = mpu;
}
static inline void
tc_newchain_req_set_options_cake_ingress(struct tc_newchain_req *req,
					 __u32 ingress)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.ingress = 1;
	req->options.cake.ingress = ingress;
}
static inline void
tc_newchain_req_set_options_cake_ack_filter(struct tc_newchain_req *req,
					    __u32 ack_filter)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.ack_filter = 1;
	req->options.cake.ack_filter = ack_filter;
}
static inline void
tc_newchain_req_set_options_cake_split_gso(struct tc_newchain_req *req,
					   __u32 split_gso)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.split_gso = 1;
	req->options.cake.split_gso = split_gso;
}
static inline void
tc_newchain_req_set_options_cake_fwmark(struct tc_newchain_req *req,
					__u32 fwmark)
{
	req->_present.options = 1;
	req->options._present.cake = 1;
	req->options.cake._present.fwmark = 1;
	req->options.cake.fwmark = fwmark;
}
static inline void
tc_newchain_req_set_options_cbs_parms(struct tc_newchain_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.cbs = 1;
	free(req->options.cbs.parms);
	req->options.cbs._len.parms = len;
	req->options.cbs.parms = malloc(req->options.cbs._len.parms);
	memcpy(req->options.cbs.parms, parms, req->options.cbs._len.parms);
}
static inline void
__tc_newchain_req_set_options_cgroup_act(struct tc_newchain_req *req,
					 struct tc_act_attrs *act,
					 unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	free(req->options.cgroup.act);
	req->options.cgroup.act = act;
	req->options.cgroup._count.act = n_act;
}
static inline void
tc_newchain_req_set_options_cgroup_police_tbf(struct tc_newchain_req *req,
					      const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.tbf);
	req->options.cgroup.police._len.tbf = len;
	req->options.cgroup.police.tbf = malloc(req->options.cgroup.police._len.tbf);
	memcpy(req->options.cgroup.police.tbf, tbf, req->options.cgroup.police._len.tbf);
}
static inline void
tc_newchain_req_set_options_cgroup_police_rate(struct tc_newchain_req *req,
					       const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.rate);
	req->options.cgroup.police._len.rate = len;
	req->options.cgroup.police.rate = malloc(req->options.cgroup.police._len.rate);
	memcpy(req->options.cgroup.police.rate, rate, req->options.cgroup.police._len.rate);
}
static inline void
tc_newchain_req_set_options_cgroup_police_peakrate(struct tc_newchain_req *req,
						   const void *peakrate,
						   size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.peakrate);
	req->options.cgroup.police._len.peakrate = len;
	req->options.cgroup.police.peakrate = malloc(req->options.cgroup.police._len.peakrate);
	memcpy(req->options.cgroup.police.peakrate, peakrate, req->options.cgroup.police._len.peakrate);
}
static inline void
tc_newchain_req_set_options_cgroup_police_avrate(struct tc_newchain_req *req,
						 __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.avrate = 1;
	req->options.cgroup.police.avrate = avrate;
}
static inline void
tc_newchain_req_set_options_cgroup_police_result(struct tc_newchain_req *req,
						 __u32 result)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.result = 1;
	req->options.cgroup.police.result = result;
}
static inline void
tc_newchain_req_set_options_cgroup_police_tm(struct tc_newchain_req *req,
					     const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	free(req->options.cgroup.police.tm);
	req->options.cgroup.police._len.tm = len;
	req->options.cgroup.police.tm = malloc(req->options.cgroup.police._len.tm);
	memcpy(req->options.cgroup.police.tm, tm, req->options.cgroup.police._len.tm);
}
static inline void
tc_newchain_req_set_options_cgroup_police_rate64(struct tc_newchain_req *req,
						 __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.rate64 = 1;
	req->options.cgroup.police.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_cgroup_police_peakrate64(struct tc_newchain_req *req,
						     __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.peakrate64 = 1;
	req->options.cgroup.police.peakrate64 = peakrate64;
}
static inline void
tc_newchain_req_set_options_cgroup_police_pktrate64(struct tc_newchain_req *req,
						    __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.pktrate64 = 1;
	req->options.cgroup.police.pktrate64 = pktrate64;
}
static inline void
tc_newchain_req_set_options_cgroup_police_pktburst64(struct tc_newchain_req *req,
						     __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	req->options.cgroup._present.police = 1;
	req->options.cgroup.police._present.pktburst64 = 1;
	req->options.cgroup.police.pktburst64 = pktburst64;
}
static inline void
tc_newchain_req_set_options_cgroup_ematches(struct tc_newchain_req *req,
					    const void *ematches, size_t len)
{
	req->_present.options = 1;
	req->options._present.cgroup = 1;
	free(req->options.cgroup.ematches);
	req->options.cgroup._len.ematches = len;
	req->options.cgroup.ematches = malloc(req->options.cgroup._len.ematches);
	memcpy(req->options.cgroup.ematches, ematches, req->options.cgroup._len.ematches);
}
static inline void
tc_newchain_req_set_options_choke_parms(struct tc_newchain_req *req,
					const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	free(req->options.choke.parms);
	req->options.choke._len.parms = len;
	req->options.choke.parms = malloc(req->options.choke._len.parms);
	memcpy(req->options.choke.parms, parms, req->options.choke._len.parms);
}
static inline void
tc_newchain_req_set_options_choke_stab(struct tc_newchain_req *req,
				       const void *stab, size_t len)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	free(req->options.choke.stab);
	req->options.choke._len.stab = len;
	req->options.choke.stab = malloc(req->options.choke._len.stab);
	memcpy(req->options.choke.stab, stab, req->options.choke._len.stab);
}
static inline void
tc_newchain_req_set_options_choke_max_p(struct tc_newchain_req *req,
					__u32 max_p)
{
	req->_present.options = 1;
	req->options._present.choke = 1;
	req->options.choke._present.max_p = 1;
	req->options.choke.max_p = max_p;
}
static inline void
tc_newchain_req_set_options_clsact(struct tc_newchain_req *req)
{
	req->_present.options = 1;
	req->options._present.clsact = 1;
}
static inline void
tc_newchain_req_set_options_codel_target(struct tc_newchain_req *req,
					 __u32 target)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.target = 1;
	req->options.codel.target = target;
}
static inline void
tc_newchain_req_set_options_codel_limit(struct tc_newchain_req *req,
					__u32 limit)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.limit = 1;
	req->options.codel.limit = limit;
}
static inline void
tc_newchain_req_set_options_codel_interval(struct tc_newchain_req *req,
					   __u32 interval)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.interval = 1;
	req->options.codel.interval = interval;
}
static inline void
tc_newchain_req_set_options_codel_ecn(struct tc_newchain_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.ecn = 1;
	req->options.codel.ecn = ecn;
}
static inline void
tc_newchain_req_set_options_codel_ce_threshold(struct tc_newchain_req *req,
					       __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.codel = 1;
	req->options.codel._present.ce_threshold = 1;
	req->options.codel.ce_threshold = ce_threshold;
}
static inline void
tc_newchain_req_set_options_drr_quantum(struct tc_newchain_req *req,
					__u32 quantum)
{
	req->_present.options = 1;
	req->options._present.drr = 1;
	req->options.drr._present.quantum = 1;
	req->options.drr.quantum = quantum;
}
static inline void
tc_newchain_req_set_options_etf_parms(struct tc_newchain_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.etf = 1;
	free(req->options.etf.parms);
	req->options.etf._len.parms = len;
	req->options.etf.parms = malloc(req->options.etf._len.parms);
	memcpy(req->options.etf.parms, parms, req->options.etf._len.parms);
}
static inline void
tc_newchain_req_set_options_flow_keys(struct tc_newchain_req *req, __u32 keys)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.keys = 1;
	req->options.flow.keys = keys;
}
static inline void
tc_newchain_req_set_options_flow_mode(struct tc_newchain_req *req, __u32 mode)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.mode = 1;
	req->options.flow.mode = mode;
}
static inline void
tc_newchain_req_set_options_flow_baseclass(struct tc_newchain_req *req,
					   __u32 baseclass)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.baseclass = 1;
	req->options.flow.baseclass = baseclass;
}
static inline void
tc_newchain_req_set_options_flow_rshift(struct tc_newchain_req *req,
					__u32 rshift)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.rshift = 1;
	req->options.flow.rshift = rshift;
}
static inline void
tc_newchain_req_set_options_flow_addend(struct tc_newchain_req *req,
					__u32 addend)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.addend = 1;
	req->options.flow.addend = addend;
}
static inline void
tc_newchain_req_set_options_flow_mask(struct tc_newchain_req *req, __u32 mask)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.mask = 1;
	req->options.flow.mask = mask;
}
static inline void
tc_newchain_req_set_options_flow_xor(struct tc_newchain_req *req, __u32 xor)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.xor = 1;
	req->options.flow.xor = xor;
}
static inline void
tc_newchain_req_set_options_flow_divisor(struct tc_newchain_req *req,
					 __u32 divisor)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.divisor = 1;
	req->options.flow.divisor = divisor;
}
static inline void
tc_newchain_req_set_options_flow_act(struct tc_newchain_req *req,
				     const void *act, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	free(req->options.flow.act);
	req->options.flow._len.act = len;
	req->options.flow.act = malloc(req->options.flow._len.act);
	memcpy(req->options.flow.act, act, req->options.flow._len.act);
}
static inline void
tc_newchain_req_set_options_flow_police_tbf(struct tc_newchain_req *req,
					    const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.tbf);
	req->options.flow.police._len.tbf = len;
	req->options.flow.police.tbf = malloc(req->options.flow.police._len.tbf);
	memcpy(req->options.flow.police.tbf, tbf, req->options.flow.police._len.tbf);
}
static inline void
tc_newchain_req_set_options_flow_police_rate(struct tc_newchain_req *req,
					     const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.rate);
	req->options.flow.police._len.rate = len;
	req->options.flow.police.rate = malloc(req->options.flow.police._len.rate);
	memcpy(req->options.flow.police.rate, rate, req->options.flow.police._len.rate);
}
static inline void
tc_newchain_req_set_options_flow_police_peakrate(struct tc_newchain_req *req,
						 const void *peakrate,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.peakrate);
	req->options.flow.police._len.peakrate = len;
	req->options.flow.police.peakrate = malloc(req->options.flow.police._len.peakrate);
	memcpy(req->options.flow.police.peakrate, peakrate, req->options.flow.police._len.peakrate);
}
static inline void
tc_newchain_req_set_options_flow_police_avrate(struct tc_newchain_req *req,
					       __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.avrate = 1;
	req->options.flow.police.avrate = avrate;
}
static inline void
tc_newchain_req_set_options_flow_police_result(struct tc_newchain_req *req,
					       __u32 result)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.result = 1;
	req->options.flow.police.result = result;
}
static inline void
tc_newchain_req_set_options_flow_police_tm(struct tc_newchain_req *req,
					   const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	free(req->options.flow.police.tm);
	req->options.flow.police._len.tm = len;
	req->options.flow.police.tm = malloc(req->options.flow.police._len.tm);
	memcpy(req->options.flow.police.tm, tm, req->options.flow.police._len.tm);
}
static inline void
tc_newchain_req_set_options_flow_police_rate64(struct tc_newchain_req *req,
					       __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.rate64 = 1;
	req->options.flow.police.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_flow_police_peakrate64(struct tc_newchain_req *req,
						   __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.peakrate64 = 1;
	req->options.flow.police.peakrate64 = peakrate64;
}
static inline void
tc_newchain_req_set_options_flow_police_pktrate64(struct tc_newchain_req *req,
						  __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.pktrate64 = 1;
	req->options.flow.police.pktrate64 = pktrate64;
}
static inline void
tc_newchain_req_set_options_flow_police_pktburst64(struct tc_newchain_req *req,
						   __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.police = 1;
	req->options.flow.police._present.pktburst64 = 1;
	req->options.flow.police.pktburst64 = pktburst64;
}
static inline void
tc_newchain_req_set_options_flow_ematches(struct tc_newchain_req *req,
					  const void *ematches, size_t len)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	free(req->options.flow.ematches);
	req->options.flow._len.ematches = len;
	req->options.flow.ematches = malloc(req->options.flow._len.ematches);
	memcpy(req->options.flow.ematches, ematches, req->options.flow._len.ematches);
}
static inline void
tc_newchain_req_set_options_flow_perturb(struct tc_newchain_req *req,
					 __u32 perturb)
{
	req->_present.options = 1;
	req->options._present.flow = 1;
	req->options.flow._present.perturb = 1;
	req->options.flow.perturb = perturb;
}
static inline void
tc_newchain_req_set_options_flower_classid(struct tc_newchain_req *req,
					   __u32 classid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.classid = 1;
	req->options.flower.classid = classid;
}
static inline void
tc_newchain_req_set_options_flower_indev(struct tc_newchain_req *req,
					 const char *indev)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.indev);
	req->options.flower._len.indev = strlen(indev);
	req->options.flower.indev = malloc(req->options.flower._len.indev + 1);
	memcpy(req->options.flower.indev, indev, req->options.flower._len.indev);
	req->options.flower.indev[req->options.flower._len.indev] = 0;
}
static inline void
__tc_newchain_req_set_options_flower_act(struct tc_newchain_req *req,
					 struct tc_act_attrs *act,
					 unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.act);
	req->options.flower.act = act;
	req->options.flower._count.act = n_act;
}
static inline void
tc_newchain_req_set_options_flower_key_eth_dst(struct tc_newchain_req *req,
					       const void *key_eth_dst,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_dst);
	req->options.flower._len.key_eth_dst = len;
	req->options.flower.key_eth_dst = malloc(req->options.flower._len.key_eth_dst);
	memcpy(req->options.flower.key_eth_dst, key_eth_dst, req->options.flower._len.key_eth_dst);
}
static inline void
tc_newchain_req_set_options_flower_key_eth_dst_mask(struct tc_newchain_req *req,
						    const void *key_eth_dst_mask,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_dst_mask);
	req->options.flower._len.key_eth_dst_mask = len;
	req->options.flower.key_eth_dst_mask = malloc(req->options.flower._len.key_eth_dst_mask);
	memcpy(req->options.flower.key_eth_dst_mask, key_eth_dst_mask, req->options.flower._len.key_eth_dst_mask);
}
static inline void
tc_newchain_req_set_options_flower_key_eth_src(struct tc_newchain_req *req,
					       const void *key_eth_src,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_src);
	req->options.flower._len.key_eth_src = len;
	req->options.flower.key_eth_src = malloc(req->options.flower._len.key_eth_src);
	memcpy(req->options.flower.key_eth_src, key_eth_src, req->options.flower._len.key_eth_src);
}
static inline void
tc_newchain_req_set_options_flower_key_eth_src_mask(struct tc_newchain_req *req,
						    const void *key_eth_src_mask,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_eth_src_mask);
	req->options.flower._len.key_eth_src_mask = len;
	req->options.flower.key_eth_src_mask = malloc(req->options.flower._len.key_eth_src_mask);
	memcpy(req->options.flower.key_eth_src_mask, key_eth_src_mask, req->options.flower._len.key_eth_src_mask);
}
static inline void
tc_newchain_req_set_options_flower_key_eth_type(struct tc_newchain_req *req,
						__u16 key_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_eth_type = 1;
	req->options.flower.key_eth_type = key_eth_type;
}
static inline void
tc_newchain_req_set_options_flower_key_ip_proto(struct tc_newchain_req *req,
						__u8 key_ip_proto)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_proto = 1;
	req->options.flower.key_ip_proto = key_ip_proto;
}
static inline void
tc_newchain_req_set_options_flower_key_ipv4_src(struct tc_newchain_req *req,
						__u32 key_ipv4_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_src = 1;
	req->options.flower.key_ipv4_src = key_ipv4_src;
}
static inline void
tc_newchain_req_set_options_flower_key_ipv4_src_mask(struct tc_newchain_req *req,
						     __u32 key_ipv4_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_src_mask = 1;
	req->options.flower.key_ipv4_src_mask = key_ipv4_src_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_ipv4_dst(struct tc_newchain_req *req,
						__u32 key_ipv4_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_dst = 1;
	req->options.flower.key_ipv4_dst = key_ipv4_dst;
}
static inline void
tc_newchain_req_set_options_flower_key_ipv4_dst_mask(struct tc_newchain_req *req,
						     __u32 key_ipv4_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ipv4_dst_mask = 1;
	req->options.flower.key_ipv4_dst_mask = key_ipv4_dst_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_ipv6_src(struct tc_newchain_req *req,
						const void *key_ipv6_src,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_src);
	req->options.flower._len.key_ipv6_src = len;
	req->options.flower.key_ipv6_src = malloc(req->options.flower._len.key_ipv6_src);
	memcpy(req->options.flower.key_ipv6_src, key_ipv6_src, req->options.flower._len.key_ipv6_src);
}
static inline void
tc_newchain_req_set_options_flower_key_ipv6_src_mask(struct tc_newchain_req *req,
						     const void *key_ipv6_src_mask,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_src_mask);
	req->options.flower._len.key_ipv6_src_mask = len;
	req->options.flower.key_ipv6_src_mask = malloc(req->options.flower._len.key_ipv6_src_mask);
	memcpy(req->options.flower.key_ipv6_src_mask, key_ipv6_src_mask, req->options.flower._len.key_ipv6_src_mask);
}
static inline void
tc_newchain_req_set_options_flower_key_ipv6_dst(struct tc_newchain_req *req,
						const void *key_ipv6_dst,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_dst);
	req->options.flower._len.key_ipv6_dst = len;
	req->options.flower.key_ipv6_dst = malloc(req->options.flower._len.key_ipv6_dst);
	memcpy(req->options.flower.key_ipv6_dst, key_ipv6_dst, req->options.flower._len.key_ipv6_dst);
}
static inline void
tc_newchain_req_set_options_flower_key_ipv6_dst_mask(struct tc_newchain_req *req,
						     const void *key_ipv6_dst_mask,
						     size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ipv6_dst_mask);
	req->options.flower._len.key_ipv6_dst_mask = len;
	req->options.flower.key_ipv6_dst_mask = malloc(req->options.flower._len.key_ipv6_dst_mask);
	memcpy(req->options.flower.key_ipv6_dst_mask, key_ipv6_dst_mask, req->options.flower._len.key_ipv6_dst_mask);
}
static inline void
tc_newchain_req_set_options_flower_key_tcp_src(struct tc_newchain_req *req,
					       __u16 key_tcp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_src = 1;
	req->options.flower.key_tcp_src = key_tcp_src;
}
static inline void
tc_newchain_req_set_options_flower_key_tcp_dst(struct tc_newchain_req *req,
					       __u16 key_tcp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_dst = 1;
	req->options.flower.key_tcp_dst = key_tcp_dst;
}
static inline void
tc_newchain_req_set_options_flower_key_udp_src(struct tc_newchain_req *req,
					       __u16 key_udp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_src = 1;
	req->options.flower.key_udp_src = key_udp_src;
}
static inline void
tc_newchain_req_set_options_flower_key_udp_dst(struct tc_newchain_req *req,
					       __u16 key_udp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_dst = 1;
	req->options.flower.key_udp_dst = key_udp_dst;
}
static inline void
tc_newchain_req_set_options_flower_flags(struct tc_newchain_req *req,
					 __u32 flags)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.flags = 1;
	req->options.flower.flags = flags;
}
static inline void
tc_newchain_req_set_options_flower_key_vlan_id(struct tc_newchain_req *req,
					       __u16 key_vlan_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_id = 1;
	req->options.flower.key_vlan_id = key_vlan_id;
}
static inline void
tc_newchain_req_set_options_flower_key_vlan_prio(struct tc_newchain_req *req,
						 __u8 key_vlan_prio)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_prio = 1;
	req->options.flower.key_vlan_prio = key_vlan_prio;
}
static inline void
tc_newchain_req_set_options_flower_key_vlan_eth_type(struct tc_newchain_req *req,
						     __u16 key_vlan_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_vlan_eth_type = 1;
	req->options.flower.key_vlan_eth_type = key_vlan_eth_type;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_key_id(struct tc_newchain_req *req,
						  __u32 key_enc_key_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_key_id = 1;
	req->options.flower.key_enc_key_id = key_enc_key_id;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ipv4_src(struct tc_newchain_req *req,
						    __u32 key_enc_ipv4_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_src = 1;
	req->options.flower.key_enc_ipv4_src = key_enc_ipv4_src;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ipv4_src_mask(struct tc_newchain_req *req,
							 __u32 key_enc_ipv4_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_src_mask = 1;
	req->options.flower.key_enc_ipv4_src_mask = key_enc_ipv4_src_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ipv4_dst(struct tc_newchain_req *req,
						    __u32 key_enc_ipv4_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_dst = 1;
	req->options.flower.key_enc_ipv4_dst = key_enc_ipv4_dst;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ipv4_dst_mask(struct tc_newchain_req *req,
							 __u32 key_enc_ipv4_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ipv4_dst_mask = 1;
	req->options.flower.key_enc_ipv4_dst_mask = key_enc_ipv4_dst_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ipv6_src(struct tc_newchain_req *req,
						    const void *key_enc_ipv6_src,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_src);
	req->options.flower._len.key_enc_ipv6_src = len;
	req->options.flower.key_enc_ipv6_src = malloc(req->options.flower._len.key_enc_ipv6_src);
	memcpy(req->options.flower.key_enc_ipv6_src, key_enc_ipv6_src, req->options.flower._len.key_enc_ipv6_src);
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ipv6_src_mask(struct tc_newchain_req *req,
							 const void *key_enc_ipv6_src_mask,
							 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_src_mask);
	req->options.flower._len.key_enc_ipv6_src_mask = len;
	req->options.flower.key_enc_ipv6_src_mask = malloc(req->options.flower._len.key_enc_ipv6_src_mask);
	memcpy(req->options.flower.key_enc_ipv6_src_mask, key_enc_ipv6_src_mask, req->options.flower._len.key_enc_ipv6_src_mask);
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ipv6_dst(struct tc_newchain_req *req,
						    const void *key_enc_ipv6_dst,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_dst);
	req->options.flower._len.key_enc_ipv6_dst = len;
	req->options.flower.key_enc_ipv6_dst = malloc(req->options.flower._len.key_enc_ipv6_dst);
	memcpy(req->options.flower.key_enc_ipv6_dst, key_enc_ipv6_dst, req->options.flower._len.key_enc_ipv6_dst);
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ipv6_dst_mask(struct tc_newchain_req *req,
							 const void *key_enc_ipv6_dst_mask,
							 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_enc_ipv6_dst_mask);
	req->options.flower._len.key_enc_ipv6_dst_mask = len;
	req->options.flower.key_enc_ipv6_dst_mask = malloc(req->options.flower._len.key_enc_ipv6_dst_mask);
	memcpy(req->options.flower.key_enc_ipv6_dst_mask, key_enc_ipv6_dst_mask, req->options.flower._len.key_enc_ipv6_dst_mask);
}
static inline void
tc_newchain_req_set_options_flower_key_tcp_src_mask(struct tc_newchain_req *req,
						    __u16 key_tcp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_src_mask = 1;
	req->options.flower.key_tcp_src_mask = key_tcp_src_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_tcp_dst_mask(struct tc_newchain_req *req,
						    __u16 key_tcp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_dst_mask = 1;
	req->options.flower.key_tcp_dst_mask = key_tcp_dst_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_udp_src_mask(struct tc_newchain_req *req,
						    __u16 key_udp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_src_mask = 1;
	req->options.flower.key_udp_src_mask = key_udp_src_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_udp_dst_mask(struct tc_newchain_req *req,
						    __u16 key_udp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_udp_dst_mask = 1;
	req->options.flower.key_udp_dst_mask = key_udp_dst_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_sctp_src_mask(struct tc_newchain_req *req,
						     __u16 key_sctp_src_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_src_mask = 1;
	req->options.flower.key_sctp_src_mask = key_sctp_src_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_sctp_dst_mask(struct tc_newchain_req *req,
						     __u16 key_sctp_dst_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_dst_mask = 1;
	req->options.flower.key_sctp_dst_mask = key_sctp_dst_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_sctp_src(struct tc_newchain_req *req,
						__u16 key_sctp_src /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_src = 1;
	req->options.flower.key_sctp_src = key_sctp_src;
}
static inline void
tc_newchain_req_set_options_flower_key_sctp_dst(struct tc_newchain_req *req,
						__u16 key_sctp_dst /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_sctp_dst = 1;
	req->options.flower.key_sctp_dst = key_sctp_dst;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_udp_src_port(struct tc_newchain_req *req,
							__u16 key_enc_udp_src_port /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_src_port = 1;
	req->options.flower.key_enc_udp_src_port = key_enc_udp_src_port;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_udp_src_port_mask(struct tc_newchain_req *req,
							     __u16 key_enc_udp_src_port_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_src_port_mask = 1;
	req->options.flower.key_enc_udp_src_port_mask = key_enc_udp_src_port_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_udp_dst_port(struct tc_newchain_req *req,
							__u16 key_enc_udp_dst_port /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_dst_port = 1;
	req->options.flower.key_enc_udp_dst_port = key_enc_udp_dst_port;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_udp_dst_port_mask(struct tc_newchain_req *req,
							     __u16 key_enc_udp_dst_port_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_udp_dst_port_mask = 1;
	req->options.flower.key_enc_udp_dst_port_mask = key_enc_udp_dst_port_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_flags(struct tc_newchain_req *req,
					     __u32 key_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_flags = 1;
	req->options.flower.key_flags = key_flags;
}
static inline void
tc_newchain_req_set_options_flower_key_flags_mask(struct tc_newchain_req *req,
						  __u32 key_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_flags_mask = 1;
	req->options.flower.key_flags_mask = key_flags_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_icmpv4_code(struct tc_newchain_req *req,
						   __u8 key_icmpv4_code)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_code = 1;
	req->options.flower.key_icmpv4_code = key_icmpv4_code;
}
static inline void
tc_newchain_req_set_options_flower_key_icmpv4_code_mask(struct tc_newchain_req *req,
							__u8 key_icmpv4_code_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_code_mask = 1;
	req->options.flower.key_icmpv4_code_mask = key_icmpv4_code_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_icmpv4_type(struct tc_newchain_req *req,
						   __u8 key_icmpv4_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_type = 1;
	req->options.flower.key_icmpv4_type = key_icmpv4_type;
}
static inline void
tc_newchain_req_set_options_flower_key_icmpv4_type_mask(struct tc_newchain_req *req,
							__u8 key_icmpv4_type_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv4_type_mask = 1;
	req->options.flower.key_icmpv4_type_mask = key_icmpv4_type_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_icmpv6_code(struct tc_newchain_req *req,
						   __u8 key_icmpv6_code)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_code = 1;
	req->options.flower.key_icmpv6_code = key_icmpv6_code;
}
static inline void
tc_newchain_req_set_options_flower_key_icmpv6_code_mask(struct tc_newchain_req *req,
							__u8 key_icmpv6_code_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_code_mask = 1;
	req->options.flower.key_icmpv6_code_mask = key_icmpv6_code_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_icmpv6_type(struct tc_newchain_req *req,
						   __u8 key_icmpv6_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_type = 1;
	req->options.flower.key_icmpv6_type = key_icmpv6_type;
}
static inline void
tc_newchain_req_set_options_flower_key_icmpv6_type_mask(struct tc_newchain_req *req,
							__u8 key_icmpv6_type_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_icmpv6_type_mask = 1;
	req->options.flower.key_icmpv6_type_mask = key_icmpv6_type_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_arp_sip(struct tc_newchain_req *req,
					       __u32 key_arp_sip /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_sip = 1;
	req->options.flower.key_arp_sip = key_arp_sip;
}
static inline void
tc_newchain_req_set_options_flower_key_arp_sip_mask(struct tc_newchain_req *req,
						    __u32 key_arp_sip_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_sip_mask = 1;
	req->options.flower.key_arp_sip_mask = key_arp_sip_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_arp_tip(struct tc_newchain_req *req,
					       __u32 key_arp_tip /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_tip = 1;
	req->options.flower.key_arp_tip = key_arp_tip;
}
static inline void
tc_newchain_req_set_options_flower_key_arp_tip_mask(struct tc_newchain_req *req,
						    __u32 key_arp_tip_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_tip_mask = 1;
	req->options.flower.key_arp_tip_mask = key_arp_tip_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_arp_op(struct tc_newchain_req *req,
					      __u8 key_arp_op)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_op = 1;
	req->options.flower.key_arp_op = key_arp_op;
}
static inline void
tc_newchain_req_set_options_flower_key_arp_op_mask(struct tc_newchain_req *req,
						   __u8 key_arp_op_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_arp_op_mask = 1;
	req->options.flower.key_arp_op_mask = key_arp_op_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_arp_sha(struct tc_newchain_req *req,
					       const void *key_arp_sha,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_sha);
	req->options.flower._len.key_arp_sha = len;
	req->options.flower.key_arp_sha = malloc(req->options.flower._len.key_arp_sha);
	memcpy(req->options.flower.key_arp_sha, key_arp_sha, req->options.flower._len.key_arp_sha);
}
static inline void
tc_newchain_req_set_options_flower_key_arp_sha_mask(struct tc_newchain_req *req,
						    const void *key_arp_sha_mask,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_sha_mask);
	req->options.flower._len.key_arp_sha_mask = len;
	req->options.flower.key_arp_sha_mask = malloc(req->options.flower._len.key_arp_sha_mask);
	memcpy(req->options.flower.key_arp_sha_mask, key_arp_sha_mask, req->options.flower._len.key_arp_sha_mask);
}
static inline void
tc_newchain_req_set_options_flower_key_arp_tha(struct tc_newchain_req *req,
					       const void *key_arp_tha,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_tha);
	req->options.flower._len.key_arp_tha = len;
	req->options.flower.key_arp_tha = malloc(req->options.flower._len.key_arp_tha);
	memcpy(req->options.flower.key_arp_tha, key_arp_tha, req->options.flower._len.key_arp_tha);
}
static inline void
tc_newchain_req_set_options_flower_key_arp_tha_mask(struct tc_newchain_req *req,
						    const void *key_arp_tha_mask,
						    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_arp_tha_mask);
	req->options.flower._len.key_arp_tha_mask = len;
	req->options.flower.key_arp_tha_mask = malloc(req->options.flower._len.key_arp_tha_mask);
	memcpy(req->options.flower.key_arp_tha_mask, key_arp_tha_mask, req->options.flower._len.key_arp_tha_mask);
}
static inline void
tc_newchain_req_set_options_flower_key_mpls_ttl(struct tc_newchain_req *req,
						__u8 key_mpls_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_ttl = 1;
	req->options.flower.key_mpls_ttl = key_mpls_ttl;
}
static inline void
tc_newchain_req_set_options_flower_key_mpls_bos(struct tc_newchain_req *req,
						__u8 key_mpls_bos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_bos = 1;
	req->options.flower.key_mpls_bos = key_mpls_bos;
}
static inline void
tc_newchain_req_set_options_flower_key_mpls_tc(struct tc_newchain_req *req,
					       __u8 key_mpls_tc)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_tc = 1;
	req->options.flower.key_mpls_tc = key_mpls_tc;
}
static inline void
tc_newchain_req_set_options_flower_key_mpls_label(struct tc_newchain_req *req,
						  __u32 key_mpls_label /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_label = 1;
	req->options.flower.key_mpls_label = key_mpls_label;
}
static inline void
tc_newchain_req_set_options_flower_key_tcp_flags(struct tc_newchain_req *req,
						 __u16 key_tcp_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_flags = 1;
	req->options.flower.key_tcp_flags = key_tcp_flags;
}
static inline void
tc_newchain_req_set_options_flower_key_tcp_flags_mask(struct tc_newchain_req *req,
						      __u16 key_tcp_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_tcp_flags_mask = 1;
	req->options.flower.key_tcp_flags_mask = key_tcp_flags_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_ip_tos(struct tc_newchain_req *req,
					      __u8 key_ip_tos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_tos = 1;
	req->options.flower.key_ip_tos = key_ip_tos;
}
static inline void
tc_newchain_req_set_options_flower_key_ip_tos_mask(struct tc_newchain_req *req,
						   __u8 key_ip_tos_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_tos_mask = 1;
	req->options.flower.key_ip_tos_mask = key_ip_tos_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_ip_ttl(struct tc_newchain_req *req,
					      __u8 key_ip_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_ttl = 1;
	req->options.flower.key_ip_ttl = key_ip_ttl;
}
static inline void
tc_newchain_req_set_options_flower_key_ip_ttl_mask(struct tc_newchain_req *req,
						   __u8 key_ip_ttl_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ip_ttl_mask = 1;
	req->options.flower.key_ip_ttl_mask = key_ip_ttl_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_cvlan_id(struct tc_newchain_req *req,
						__u16 key_cvlan_id /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_id = 1;
	req->options.flower.key_cvlan_id = key_cvlan_id;
}
static inline void
tc_newchain_req_set_options_flower_key_cvlan_prio(struct tc_newchain_req *req,
						  __u8 key_cvlan_prio)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_prio = 1;
	req->options.flower.key_cvlan_prio = key_cvlan_prio;
}
static inline void
tc_newchain_req_set_options_flower_key_cvlan_eth_type(struct tc_newchain_req *req,
						      __u16 key_cvlan_eth_type /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cvlan_eth_type = 1;
	req->options.flower.key_cvlan_eth_type = key_cvlan_eth_type;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ip_tos(struct tc_newchain_req *req,
						  __u8 key_enc_ip_tos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_tos = 1;
	req->options.flower.key_enc_ip_tos = key_enc_ip_tos;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ip_tos_mask(struct tc_newchain_req *req,
						       __u8 key_enc_ip_tos_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_tos_mask = 1;
	req->options.flower.key_enc_ip_tos_mask = key_enc_ip_tos_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ip_ttl(struct tc_newchain_req *req,
						  __u8 key_enc_ip_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_ttl = 1;
	req->options.flower.key_enc_ip_ttl = key_enc_ip_ttl;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_ip_ttl_mask(struct tc_newchain_req *req,
						       __u8 key_enc_ip_ttl_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_ip_ttl_mask = 1;
	req->options.flower.key_enc_ip_ttl_mask = key_enc_ip_ttl_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_geneve_class(struct tc_newchain_req *req,
							     __u16 class)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	req->options.flower.key_enc_opts.geneve._present.class = 1;
	req->options.flower.key_enc_opts.geneve.class = class;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_geneve_type(struct tc_newchain_req *req,
							    __u8 type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	req->options.flower.key_enc_opts.geneve._present.type = 1;
	req->options.flower.key_enc_opts.geneve.type = type;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_geneve_data(struct tc_newchain_req *req,
							    const void *data,
							    size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.geneve = 1;
	free(req->options.flower.key_enc_opts.geneve.data);
	req->options.flower.key_enc_opts.geneve._len.data = len;
	req->options.flower.key_enc_opts.geneve.data = malloc(req->options.flower.key_enc_opts.geneve._len.data);
	memcpy(req->options.flower.key_enc_opts.geneve.data, data, req->options.flower.key_enc_opts.geneve._len.data);
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_vxlan_gbp(struct tc_newchain_req *req,
							  __u32 gbp)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.vxlan = 1;
	req->options.flower.key_enc_opts.vxlan._present.gbp = 1;
	req->options.flower.key_enc_opts.vxlan.gbp = gbp;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_erspan_ver(struct tc_newchain_req *req,
							   __u8 ver)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.ver = 1;
	req->options.flower.key_enc_opts.erspan.ver = ver;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_erspan_index(struct tc_newchain_req *req,
							     __u32 index)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.index = 1;
	req->options.flower.key_enc_opts.erspan.index = index;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_erspan_dir(struct tc_newchain_req *req,
							   __u8 dir)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.dir = 1;
	req->options.flower.key_enc_opts.erspan.dir = dir;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_erspan_hwid(struct tc_newchain_req *req,
							    __u8 hwid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.erspan = 1;
	req->options.flower.key_enc_opts.erspan._present.hwid = 1;
	req->options.flower.key_enc_opts.erspan.hwid = hwid;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_gtp_pdu_type(struct tc_newchain_req *req,
							     __u8 pdu_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.gtp = 1;
	req->options.flower.key_enc_opts.gtp._present.pdu_type = 1;
	req->options.flower.key_enc_opts.gtp.pdu_type = pdu_type;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_gtp_qfi(struct tc_newchain_req *req,
							__u8 qfi)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts = 1;
	req->options.flower.key_enc_opts._present.gtp = 1;
	req->options.flower.key_enc_opts.gtp._present.qfi = 1;
	req->options.flower.key_enc_opts.gtp.qfi = qfi;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_geneve_class(struct tc_newchain_req *req,
								  __u16 class)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	req->options.flower.key_enc_opts_mask.geneve._present.class = 1;
	req->options.flower.key_enc_opts_mask.geneve.class = class;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_geneve_type(struct tc_newchain_req *req,
								 __u8 type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	req->options.flower.key_enc_opts_mask.geneve._present.type = 1;
	req->options.flower.key_enc_opts_mask.geneve.type = type;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_geneve_data(struct tc_newchain_req *req,
								 const void *data,
								 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.geneve = 1;
	free(req->options.flower.key_enc_opts_mask.geneve.data);
	req->options.flower.key_enc_opts_mask.geneve._len.data = len;
	req->options.flower.key_enc_opts_mask.geneve.data = malloc(req->options.flower.key_enc_opts_mask.geneve._len.data);
	memcpy(req->options.flower.key_enc_opts_mask.geneve.data, data, req->options.flower.key_enc_opts_mask.geneve._len.data);
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_vxlan_gbp(struct tc_newchain_req *req,
							       __u32 gbp)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.vxlan = 1;
	req->options.flower.key_enc_opts_mask.vxlan._present.gbp = 1;
	req->options.flower.key_enc_opts_mask.vxlan.gbp = gbp;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_erspan_ver(struct tc_newchain_req *req,
								__u8 ver)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.ver = 1;
	req->options.flower.key_enc_opts_mask.erspan.ver = ver;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_erspan_index(struct tc_newchain_req *req,
								  __u32 index)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.index = 1;
	req->options.flower.key_enc_opts_mask.erspan.index = index;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_erspan_dir(struct tc_newchain_req *req,
								__u8 dir)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.dir = 1;
	req->options.flower.key_enc_opts_mask.erspan.dir = dir;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_erspan_hwid(struct tc_newchain_req *req,
								 __u8 hwid)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.erspan = 1;
	req->options.flower.key_enc_opts_mask.erspan._present.hwid = 1;
	req->options.flower.key_enc_opts_mask.erspan.hwid = hwid;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_gtp_pdu_type(struct tc_newchain_req *req,
								  __u8 pdu_type)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.gtp = 1;
	req->options.flower.key_enc_opts_mask.gtp._present.pdu_type = 1;
	req->options.flower.key_enc_opts_mask.gtp.pdu_type = pdu_type;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_opts_mask_gtp_qfi(struct tc_newchain_req *req,
							     __u8 qfi)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_opts_mask = 1;
	req->options.flower.key_enc_opts_mask._present.gtp = 1;
	req->options.flower.key_enc_opts_mask.gtp._present.qfi = 1;
	req->options.flower.key_enc_opts_mask.gtp.qfi = qfi;
}
static inline void
tc_newchain_req_set_options_flower_in_hw_count(struct tc_newchain_req *req,
					       __u32 in_hw_count)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.in_hw_count = 1;
	req->options.flower.in_hw_count = in_hw_count;
}
static inline void
tc_newchain_req_set_options_flower_key_port_src_min(struct tc_newchain_req *req,
						    __u16 key_port_src_min /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_src_min = 1;
	req->options.flower.key_port_src_min = key_port_src_min;
}
static inline void
tc_newchain_req_set_options_flower_key_port_src_max(struct tc_newchain_req *req,
						    __u16 key_port_src_max /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_src_max = 1;
	req->options.flower.key_port_src_max = key_port_src_max;
}
static inline void
tc_newchain_req_set_options_flower_key_port_dst_min(struct tc_newchain_req *req,
						    __u16 key_port_dst_min /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_dst_min = 1;
	req->options.flower.key_port_dst_min = key_port_dst_min;
}
static inline void
tc_newchain_req_set_options_flower_key_port_dst_max(struct tc_newchain_req *req,
						    __u16 key_port_dst_max /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_port_dst_max = 1;
	req->options.flower.key_port_dst_max = key_port_dst_max;
}
static inline void
tc_newchain_req_set_options_flower_key_ct_state(struct tc_newchain_req *req,
						__u16 key_ct_state)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_state = 1;
	req->options.flower.key_ct_state = key_ct_state;
}
static inline void
tc_newchain_req_set_options_flower_key_ct_state_mask(struct tc_newchain_req *req,
						     __u16 key_ct_state_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_state_mask = 1;
	req->options.flower.key_ct_state_mask = key_ct_state_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_ct_zone(struct tc_newchain_req *req,
					       __u16 key_ct_zone)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_zone = 1;
	req->options.flower.key_ct_zone = key_ct_zone;
}
static inline void
tc_newchain_req_set_options_flower_key_ct_zone_mask(struct tc_newchain_req *req,
						    __u16 key_ct_zone_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_zone_mask = 1;
	req->options.flower.key_ct_zone_mask = key_ct_zone_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_ct_mark(struct tc_newchain_req *req,
					       __u32 key_ct_mark)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_mark = 1;
	req->options.flower.key_ct_mark = key_ct_mark;
}
static inline void
tc_newchain_req_set_options_flower_key_ct_mark_mask(struct tc_newchain_req *req,
						    __u32 key_ct_mark_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ct_mark_mask = 1;
	req->options.flower.key_ct_mark_mask = key_ct_mark_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_ct_labels(struct tc_newchain_req *req,
						 const void *key_ct_labels,
						 size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ct_labels);
	req->options.flower._len.key_ct_labels = len;
	req->options.flower.key_ct_labels = malloc(req->options.flower._len.key_ct_labels);
	memcpy(req->options.flower.key_ct_labels, key_ct_labels, req->options.flower._len.key_ct_labels);
}
static inline void
tc_newchain_req_set_options_flower_key_ct_labels_mask(struct tc_newchain_req *req,
						      const void *key_ct_labels_mask,
						      size_t len)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	free(req->options.flower.key_ct_labels_mask);
	req->options.flower._len.key_ct_labels_mask = len;
	req->options.flower.key_ct_labels_mask = malloc(req->options.flower._len.key_ct_labels_mask);
	memcpy(req->options.flower.key_ct_labels_mask, key_ct_labels_mask, req->options.flower._len.key_ct_labels_mask);
}
static inline void
tc_newchain_req_set_options_flower_key_mpls_opts_lse_depth(struct tc_newchain_req *req,
							   __u8 lse_depth)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_depth = 1;
	req->options.flower.key_mpls_opts.lse_depth = lse_depth;
}
static inline void
tc_newchain_req_set_options_flower_key_mpls_opts_lse_ttl(struct tc_newchain_req *req,
							 __u8 lse_ttl)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_ttl = 1;
	req->options.flower.key_mpls_opts.lse_ttl = lse_ttl;
}
static inline void
tc_newchain_req_set_options_flower_key_mpls_opts_lse_bos(struct tc_newchain_req *req,
							 __u8 lse_bos)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_bos = 1;
	req->options.flower.key_mpls_opts.lse_bos = lse_bos;
}
static inline void
tc_newchain_req_set_options_flower_key_mpls_opts_lse_tc(struct tc_newchain_req *req,
							__u8 lse_tc)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_tc = 1;
	req->options.flower.key_mpls_opts.lse_tc = lse_tc;
}
static inline void
tc_newchain_req_set_options_flower_key_mpls_opts_lse_label(struct tc_newchain_req *req,
							   __u32 lse_label)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_mpls_opts = 1;
	req->options.flower.key_mpls_opts._present.lse_label = 1;
	req->options.flower.key_mpls_opts.lse_label = lse_label;
}
static inline void
tc_newchain_req_set_options_flower_key_hash(struct tc_newchain_req *req,
					    __u32 key_hash)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_hash = 1;
	req->options.flower.key_hash = key_hash;
}
static inline void
tc_newchain_req_set_options_flower_key_hash_mask(struct tc_newchain_req *req,
						 __u32 key_hash_mask)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_hash_mask = 1;
	req->options.flower.key_hash_mask = key_hash_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_num_of_vlans(struct tc_newchain_req *req,
						    __u8 key_num_of_vlans)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_num_of_vlans = 1;
	req->options.flower.key_num_of_vlans = key_num_of_vlans;
}
static inline void
tc_newchain_req_set_options_flower_key_pppoe_sid(struct tc_newchain_req *req,
						 __u16 key_pppoe_sid /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_pppoe_sid = 1;
	req->options.flower.key_pppoe_sid = key_pppoe_sid;
}
static inline void
tc_newchain_req_set_options_flower_key_ppp_proto(struct tc_newchain_req *req,
						 __u16 key_ppp_proto /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_ppp_proto = 1;
	req->options.flower.key_ppp_proto = key_ppp_proto;
}
static inline void
tc_newchain_req_set_options_flower_key_l2tpv3_sid(struct tc_newchain_req *req,
						  __u32 key_l2tpv3_sid /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_l2tpv3_sid = 1;
	req->options.flower.key_l2tpv3_sid = key_l2tpv3_sid;
}
static inline void
tc_newchain_req_set_options_flower_l2_miss(struct tc_newchain_req *req,
					   __u8 l2_miss)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.l2_miss = 1;
	req->options.flower.l2_miss = l2_miss;
}
static inline void
tc_newchain_req_set_options_flower_key_cfm_md_level(struct tc_newchain_req *req,
						    __u8 md_level)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cfm = 1;
	req->options.flower.key_cfm._present.md_level = 1;
	req->options.flower.key_cfm.md_level = md_level;
}
static inline void
tc_newchain_req_set_options_flower_key_cfm_opcode(struct tc_newchain_req *req,
						  __u8 opcode)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_cfm = 1;
	req->options.flower.key_cfm._present.opcode = 1;
	req->options.flower.key_cfm.opcode = opcode;
}
static inline void
tc_newchain_req_set_options_flower_key_spi(struct tc_newchain_req *req,
					   __u32 key_spi /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_spi = 1;
	req->options.flower.key_spi = key_spi;
}
static inline void
tc_newchain_req_set_options_flower_key_spi_mask(struct tc_newchain_req *req,
						__u32 key_spi_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_spi_mask = 1;
	req->options.flower.key_spi_mask = key_spi_mask;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_flags(struct tc_newchain_req *req,
						 __u32 key_enc_flags /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_flags = 1;
	req->options.flower.key_enc_flags = key_enc_flags;
}
static inline void
tc_newchain_req_set_options_flower_key_enc_flags_mask(struct tc_newchain_req *req,
						      __u32 key_enc_flags_mask /* big-endian */)
{
	req->_present.options = 1;
	req->options._present.flower = 1;
	req->options.flower._present.key_enc_flags_mask = 1;
	req->options.flower.key_enc_flags_mask = key_enc_flags_mask;
}
static inline void
tc_newchain_req_set_options_fq_plimit(struct tc_newchain_req *req,
				      __u32 plimit)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.plimit = 1;
	req->options.fq.plimit = plimit;
}
static inline void
tc_newchain_req_set_options_fq_flow_plimit(struct tc_newchain_req *req,
					   __u32 flow_plimit)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_plimit = 1;
	req->options.fq.flow_plimit = flow_plimit;
}
static inline void
tc_newchain_req_set_options_fq_quantum(struct tc_newchain_req *req,
				       __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.quantum = 1;
	req->options.fq.quantum = quantum;
}
static inline void
tc_newchain_req_set_options_fq_initial_quantum(struct tc_newchain_req *req,
					       __u32 initial_quantum)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.initial_quantum = 1;
	req->options.fq.initial_quantum = initial_quantum;
}
static inline void
tc_newchain_req_set_options_fq_rate_enable(struct tc_newchain_req *req,
					   __u32 rate_enable)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.rate_enable = 1;
	req->options.fq.rate_enable = rate_enable;
}
static inline void
tc_newchain_req_set_options_fq_flow_default_rate(struct tc_newchain_req *req,
						 __u32 flow_default_rate)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_default_rate = 1;
	req->options.fq.flow_default_rate = flow_default_rate;
}
static inline void
tc_newchain_req_set_options_fq_flow_max_rate(struct tc_newchain_req *req,
					     __u32 flow_max_rate)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_max_rate = 1;
	req->options.fq.flow_max_rate = flow_max_rate;
}
static inline void
tc_newchain_req_set_options_fq_buckets_log(struct tc_newchain_req *req,
					   __u32 buckets_log)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.buckets_log = 1;
	req->options.fq.buckets_log = buckets_log;
}
static inline void
tc_newchain_req_set_options_fq_flow_refill_delay(struct tc_newchain_req *req,
						 __u32 flow_refill_delay)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.flow_refill_delay = 1;
	req->options.fq.flow_refill_delay = flow_refill_delay;
}
static inline void
tc_newchain_req_set_options_fq_orphan_mask(struct tc_newchain_req *req,
					   __u32 orphan_mask)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.orphan_mask = 1;
	req->options.fq.orphan_mask = orphan_mask;
}
static inline void
tc_newchain_req_set_options_fq_low_rate_threshold(struct tc_newchain_req *req,
						  __u32 low_rate_threshold)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.low_rate_threshold = 1;
	req->options.fq.low_rate_threshold = low_rate_threshold;
}
static inline void
tc_newchain_req_set_options_fq_ce_threshold(struct tc_newchain_req *req,
					    __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.ce_threshold = 1;
	req->options.fq.ce_threshold = ce_threshold;
}
static inline void
tc_newchain_req_set_options_fq_timer_slack(struct tc_newchain_req *req,
					   __u32 timer_slack)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.timer_slack = 1;
	req->options.fq.timer_slack = timer_slack;
}
static inline void
tc_newchain_req_set_options_fq_horizon(struct tc_newchain_req *req,
				       __u32 horizon)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.horizon = 1;
	req->options.fq.horizon = horizon;
}
static inline void
tc_newchain_req_set_options_fq_horizon_drop(struct tc_newchain_req *req,
					    __u8 horizon_drop)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	req->options.fq._present.horizon_drop = 1;
	req->options.fq.horizon_drop = horizon_drop;
}
static inline void
tc_newchain_req_set_options_fq_priomap(struct tc_newchain_req *req,
				       const void *priomap, size_t len)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	free(req->options.fq.priomap);
	req->options.fq._len.priomap = len;
	req->options.fq.priomap = malloc(req->options.fq._len.priomap);
	memcpy(req->options.fq.priomap, priomap, req->options.fq._len.priomap);
}
static inline void
tc_newchain_req_set_options_fq_weights(struct tc_newchain_req *req,
				       __s32 *weights, size_t count)
{
	req->_present.options = 1;
	req->options._present.fq = 1;
	free(req->options.fq.weights);
	req->options.fq._count.weights = count;
	count *= sizeof(__s32);
	req->options.fq.weights = malloc(count);
	memcpy(req->options.fq.weights, weights, count);
}
static inline void
tc_newchain_req_set_options_fq_codel_target(struct tc_newchain_req *req,
					    __u32 target)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.target = 1;
	req->options.fq_codel.target = target;
}
static inline void
tc_newchain_req_set_options_fq_codel_limit(struct tc_newchain_req *req,
					   __u32 limit)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.limit = 1;
	req->options.fq_codel.limit = limit;
}
static inline void
tc_newchain_req_set_options_fq_codel_interval(struct tc_newchain_req *req,
					      __u32 interval)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.interval = 1;
	req->options.fq_codel.interval = interval;
}
static inline void
tc_newchain_req_set_options_fq_codel_ecn(struct tc_newchain_req *req,
					 __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ecn = 1;
	req->options.fq_codel.ecn = ecn;
}
static inline void
tc_newchain_req_set_options_fq_codel_flows(struct tc_newchain_req *req,
					   __u32 flows)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.flows = 1;
	req->options.fq_codel.flows = flows;
}
static inline void
tc_newchain_req_set_options_fq_codel_quantum(struct tc_newchain_req *req,
					     __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.quantum = 1;
	req->options.fq_codel.quantum = quantum;
}
static inline void
tc_newchain_req_set_options_fq_codel_ce_threshold(struct tc_newchain_req *req,
						  __u32 ce_threshold)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold = 1;
	req->options.fq_codel.ce_threshold = ce_threshold;
}
static inline void
tc_newchain_req_set_options_fq_codel_drop_batch_size(struct tc_newchain_req *req,
						     __u32 drop_batch_size)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.drop_batch_size = 1;
	req->options.fq_codel.drop_batch_size = drop_batch_size;
}
static inline void
tc_newchain_req_set_options_fq_codel_memory_limit(struct tc_newchain_req *req,
						  __u32 memory_limit)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.memory_limit = 1;
	req->options.fq_codel.memory_limit = memory_limit;
}
static inline void
tc_newchain_req_set_options_fq_codel_ce_threshold_selector(struct tc_newchain_req *req,
							   __u8 ce_threshold_selector)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold_selector = 1;
	req->options.fq_codel.ce_threshold_selector = ce_threshold_selector;
}
static inline void
tc_newchain_req_set_options_fq_codel_ce_threshold_mask(struct tc_newchain_req *req,
						       __u8 ce_threshold_mask)
{
	req->_present.options = 1;
	req->options._present.fq_codel = 1;
	req->options.fq_codel._present.ce_threshold_mask = 1;
	req->options.fq_codel.ce_threshold_mask = ce_threshold_mask;
}
static inline void
tc_newchain_req_set_options_fq_pie_limit(struct tc_newchain_req *req,
					 __u32 limit)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.limit = 1;
	req->options.fq_pie.limit = limit;
}
static inline void
tc_newchain_req_set_options_fq_pie_flows(struct tc_newchain_req *req,
					 __u32 flows)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.flows = 1;
	req->options.fq_pie.flows = flows;
}
static inline void
tc_newchain_req_set_options_fq_pie_target(struct tc_newchain_req *req,
					  __u32 target)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.target = 1;
	req->options.fq_pie.target = target;
}
static inline void
tc_newchain_req_set_options_fq_pie_tupdate(struct tc_newchain_req *req,
					   __u32 tupdate)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.tupdate = 1;
	req->options.fq_pie.tupdate = tupdate;
}
static inline void
tc_newchain_req_set_options_fq_pie_alpha(struct tc_newchain_req *req,
					 __u32 alpha)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.alpha = 1;
	req->options.fq_pie.alpha = alpha;
}
static inline void
tc_newchain_req_set_options_fq_pie_beta(struct tc_newchain_req *req,
					__u32 beta)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.beta = 1;
	req->options.fq_pie.beta = beta;
}
static inline void
tc_newchain_req_set_options_fq_pie_quantum(struct tc_newchain_req *req,
					   __u32 quantum)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.quantum = 1;
	req->options.fq_pie.quantum = quantum;
}
static inline void
tc_newchain_req_set_options_fq_pie_memory_limit(struct tc_newchain_req *req,
						__u32 memory_limit)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.memory_limit = 1;
	req->options.fq_pie.memory_limit = memory_limit;
}
static inline void
tc_newchain_req_set_options_fq_pie_ecn_prob(struct tc_newchain_req *req,
					    __u32 ecn_prob)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.ecn_prob = 1;
	req->options.fq_pie.ecn_prob = ecn_prob;
}
static inline void
tc_newchain_req_set_options_fq_pie_ecn(struct tc_newchain_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.ecn = 1;
	req->options.fq_pie.ecn = ecn;
}
static inline void
tc_newchain_req_set_options_fq_pie_bytemode(struct tc_newchain_req *req,
					    __u32 bytemode)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.bytemode = 1;
	req->options.fq_pie.bytemode = bytemode;
}
static inline void
tc_newchain_req_set_options_fq_pie_dq_rate_estimator(struct tc_newchain_req *req,
						     __u32 dq_rate_estimator)
{
	req->_present.options = 1;
	req->options._present.fq_pie = 1;
	req->options.fq_pie._present.dq_rate_estimator = 1;
	req->options.fq_pie.dq_rate_estimator = dq_rate_estimator;
}
static inline void
tc_newchain_req_set_options_fw_classid(struct tc_newchain_req *req,
				       __u32 classid)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.classid = 1;
	req->options.fw.classid = classid;
}
static inline void
tc_newchain_req_set_options_fw_police_tbf(struct tc_newchain_req *req,
					  const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.tbf);
	req->options.fw.police._len.tbf = len;
	req->options.fw.police.tbf = malloc(req->options.fw.police._len.tbf);
	memcpy(req->options.fw.police.tbf, tbf, req->options.fw.police._len.tbf);
}
static inline void
tc_newchain_req_set_options_fw_police_rate(struct tc_newchain_req *req,
					   const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.rate);
	req->options.fw.police._len.rate = len;
	req->options.fw.police.rate = malloc(req->options.fw.police._len.rate);
	memcpy(req->options.fw.police.rate, rate, req->options.fw.police._len.rate);
}
static inline void
tc_newchain_req_set_options_fw_police_peakrate(struct tc_newchain_req *req,
					       const void *peakrate,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.peakrate);
	req->options.fw.police._len.peakrate = len;
	req->options.fw.police.peakrate = malloc(req->options.fw.police._len.peakrate);
	memcpy(req->options.fw.police.peakrate, peakrate, req->options.fw.police._len.peakrate);
}
static inline void
tc_newchain_req_set_options_fw_police_avrate(struct tc_newchain_req *req,
					     __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.avrate = 1;
	req->options.fw.police.avrate = avrate;
}
static inline void
tc_newchain_req_set_options_fw_police_result(struct tc_newchain_req *req,
					     __u32 result)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.result = 1;
	req->options.fw.police.result = result;
}
static inline void
tc_newchain_req_set_options_fw_police_tm(struct tc_newchain_req *req,
					 const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	free(req->options.fw.police.tm);
	req->options.fw.police._len.tm = len;
	req->options.fw.police.tm = malloc(req->options.fw.police._len.tm);
	memcpy(req->options.fw.police.tm, tm, req->options.fw.police._len.tm);
}
static inline void
tc_newchain_req_set_options_fw_police_rate64(struct tc_newchain_req *req,
					     __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.rate64 = 1;
	req->options.fw.police.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_fw_police_peakrate64(struct tc_newchain_req *req,
						 __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.peakrate64 = 1;
	req->options.fw.police.peakrate64 = peakrate64;
}
static inline void
tc_newchain_req_set_options_fw_police_pktrate64(struct tc_newchain_req *req,
						__u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.pktrate64 = 1;
	req->options.fw.police.pktrate64 = pktrate64;
}
static inline void
tc_newchain_req_set_options_fw_police_pktburst64(struct tc_newchain_req *req,
						 __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.police = 1;
	req->options.fw.police._present.pktburst64 = 1;
	req->options.fw.police.pktburst64 = pktburst64;
}
static inline void
tc_newchain_req_set_options_fw_indev(struct tc_newchain_req *req,
				     const char *indev)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	free(req->options.fw.indev);
	req->options.fw._len.indev = strlen(indev);
	req->options.fw.indev = malloc(req->options.fw._len.indev + 1);
	memcpy(req->options.fw.indev, indev, req->options.fw._len.indev);
	req->options.fw.indev[req->options.fw._len.indev] = 0;
}
static inline void
__tc_newchain_req_set_options_fw_act(struct tc_newchain_req *req,
				     struct tc_act_attrs *act,
				     unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	free(req->options.fw.act);
	req->options.fw.act = act;
	req->options.fw._count.act = n_act;
}
static inline void
tc_newchain_req_set_options_fw_mask(struct tc_newchain_req *req, __u32 mask)
{
	req->_present.options = 1;
	req->options._present.fw = 1;
	req->options.fw._present.mask = 1;
	req->options.fw.mask = mask;
}
static inline void
tc_newchain_req_set_options_gred_parms(struct tc_newchain_req *req,
				       const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.parms);
	req->options.gred._len.parms = len;
	req->options.gred.parms = malloc(req->options.gred._len.parms);
	memcpy(req->options.gred.parms, parms, req->options.gred._len.parms);
}
static inline void
tc_newchain_req_set_options_gred_stab(struct tc_newchain_req *req, __u8 *stab,
				      size_t count)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.stab);
	req->options.gred._count.stab = count;
	count *= sizeof(__u8);
	req->options.gred.stab = malloc(count);
	memcpy(req->options.gred.stab, stab, count);
}
static inline void
tc_newchain_req_set_options_gred_dps(struct tc_newchain_req *req,
				     const void *dps, size_t len)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.dps);
	req->options.gred._len.dps = len;
	req->options.gred.dps = malloc(req->options.gred._len.dps);
	memcpy(req->options.gred.dps, dps, req->options.gred._len.dps);
}
static inline void
tc_newchain_req_set_options_gred_max_p(struct tc_newchain_req *req,
				       __u32 *max_p, size_t count)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	free(req->options.gred.max_p);
	req->options.gred._count.max_p = count;
	count *= sizeof(__u32);
	req->options.gred.max_p = malloc(count);
	memcpy(req->options.gred.max_p, max_p, count);
}
static inline void
tc_newchain_req_set_options_gred_limit(struct tc_newchain_req *req,
				       __u32 limit)
{
	req->_present.options = 1;
	req->options._present.gred = 1;
	req->options.gred._present.limit = 1;
	req->options.gred.limit = limit;
}
static inline void
__tc_newchain_req_set_options_gred_vq_list_entry(struct tc_newchain_req *req,
						 struct tc_tca_gred_vq_entry_attrs *entry,
						 unsigned int n_entry)
{
	unsigned int i;

	req->_present.options = 1;
	req->options._present.gred = 1;
	req->options.gred._present.vq_list = 1;
	for (i = 0; i < req->options.gred.vq_list._count.entry; i++)
		tc_tca_gred_vq_entry_attrs_free(&req->options.gred.vq_list.entry[i]);
	free(req->options.gred.vq_list.entry);
	req->options.gred.vq_list.entry = entry;
	req->options.gred.vq_list._count.entry = n_entry;
}
static inline void
tc_newchain_req_set_options_hfsc(struct tc_newchain_req *req, const void *hfsc,
				 size_t len)
{
	req->_present.options = 1;
	free(req->options.hfsc);
	req->options._len.hfsc = len;
	req->options.hfsc = malloc(req->options._len.hfsc);
	memcpy(req->options.hfsc, hfsc, req->options._len.hfsc);
}
static inline void
tc_newchain_req_set_options_hhf_backlog_limit(struct tc_newchain_req *req,
					      __u32 backlog_limit)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.backlog_limit = 1;
	req->options.hhf.backlog_limit = backlog_limit;
}
static inline void
tc_newchain_req_set_options_hhf_quantum(struct tc_newchain_req *req,
					__u32 quantum)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.quantum = 1;
	req->options.hhf.quantum = quantum;
}
static inline void
tc_newchain_req_set_options_hhf_hh_flows_limit(struct tc_newchain_req *req,
					       __u32 hh_flows_limit)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.hh_flows_limit = 1;
	req->options.hhf.hh_flows_limit = hh_flows_limit;
}
static inline void
tc_newchain_req_set_options_hhf_reset_timeout(struct tc_newchain_req *req,
					      __u32 reset_timeout)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.reset_timeout = 1;
	req->options.hhf.reset_timeout = reset_timeout;
}
static inline void
tc_newchain_req_set_options_hhf_admit_bytes(struct tc_newchain_req *req,
					    __u32 admit_bytes)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.admit_bytes = 1;
	req->options.hhf.admit_bytes = admit_bytes;
}
static inline void
tc_newchain_req_set_options_hhf_evict_timeout(struct tc_newchain_req *req,
					      __u32 evict_timeout)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.evict_timeout = 1;
	req->options.hhf.evict_timeout = evict_timeout;
}
static inline void
tc_newchain_req_set_options_hhf_non_hh_weight(struct tc_newchain_req *req,
					      __u32 non_hh_weight)
{
	req->_present.options = 1;
	req->options._present.hhf = 1;
	req->options.hhf._present.non_hh_weight = 1;
	req->options.hhf.non_hh_weight = non_hh_weight;
}
static inline void
tc_newchain_req_set_options_htb_parms(struct tc_newchain_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.parms);
	req->options.htb._len.parms = len;
	req->options.htb.parms = malloc(req->options.htb._len.parms);
	memcpy(req->options.htb.parms, parms, req->options.htb._len.parms);
}
static inline void
tc_newchain_req_set_options_htb_init(struct tc_newchain_req *req,
				     const void *init, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.init);
	req->options.htb._len.init = len;
	req->options.htb.init = malloc(req->options.htb._len.init);
	memcpy(req->options.htb.init, init, req->options.htb._len.init);
}
static inline void
tc_newchain_req_set_options_htb_ctab(struct tc_newchain_req *req,
				     const void *ctab, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.ctab);
	req->options.htb._len.ctab = len;
	req->options.htb.ctab = malloc(req->options.htb._len.ctab);
	memcpy(req->options.htb.ctab, ctab, req->options.htb._len.ctab);
}
static inline void
tc_newchain_req_set_options_htb_rtab(struct tc_newchain_req *req,
				     const void *rtab, size_t len)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	free(req->options.htb.rtab);
	req->options.htb._len.rtab = len;
	req->options.htb.rtab = malloc(req->options.htb._len.rtab);
	memcpy(req->options.htb.rtab, rtab, req->options.htb._len.rtab);
}
static inline void
tc_newchain_req_set_options_htb_direct_qlen(struct tc_newchain_req *req,
					    __u32 direct_qlen)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.direct_qlen = 1;
	req->options.htb.direct_qlen = direct_qlen;
}
static inline void
tc_newchain_req_set_options_htb_rate64(struct tc_newchain_req *req,
				       __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.rate64 = 1;
	req->options.htb.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_htb_ceil64(struct tc_newchain_req *req,
				       __u64 ceil64)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.ceil64 = 1;
	req->options.htb.ceil64 = ceil64;
}
static inline void
tc_newchain_req_set_options_htb_offload(struct tc_newchain_req *req)
{
	req->_present.options = 1;
	req->options._present.htb = 1;
	req->options.htb._present.offload = 1;
}
static inline void
tc_newchain_req_set_options_ingress(struct tc_newchain_req *req)
{
	req->_present.options = 1;
	req->options._present.ingress = 1;
}
static inline void
tc_newchain_req_set_options_matchall_classid(struct tc_newchain_req *req,
					     __u32 classid)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	req->options.matchall._present.classid = 1;
	req->options.matchall.classid = classid;
}
static inline void
__tc_newchain_req_set_options_matchall_act(struct tc_newchain_req *req,
					   struct tc_act_attrs *act,
					   unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	free(req->options.matchall.act);
	req->options.matchall.act = act;
	req->options.matchall._count.act = n_act;
}
static inline void
tc_newchain_req_set_options_matchall_flags(struct tc_newchain_req *req,
					   __u32 flags)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	req->options.matchall._present.flags = 1;
	req->options.matchall.flags = flags;
}
static inline void
tc_newchain_req_set_options_matchall_pcnt(struct tc_newchain_req *req,
					  const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.matchall = 1;
	free(req->options.matchall.pcnt);
	req->options.matchall._len.pcnt = len;
	req->options.matchall.pcnt = malloc(req->options.matchall._len.pcnt);
	memcpy(req->options.matchall.pcnt, pcnt, req->options.matchall._len.pcnt);
}
static inline void tc_newchain_req_set_options_mq(struct tc_newchain_req *req)
{
	req->_present.options = 1;
	req->options._present.mq = 1;
}
static inline void
tc_newchain_req_set_options_mqprio(struct tc_newchain_req *req,
				   const void *mqprio, size_t len)
{
	req->_present.options = 1;
	free(req->options.mqprio);
	req->options._len.mqprio = len;
	req->options.mqprio = malloc(req->options._len.mqprio);
	memcpy(req->options.mqprio, mqprio, req->options._len.mqprio);
}
static inline void
tc_newchain_req_set_options_multiq(struct tc_newchain_req *req,
				   const void *multiq, size_t len)
{
	req->_present.options = 1;
	free(req->options.multiq);
	req->options._len.multiq = len;
	req->options.multiq = malloc(req->options._len.multiq);
	memcpy(req->options.multiq, multiq, req->options._len.multiq);
}
static inline void
tc_newchain_req_set_options_netem_corr(struct tc_newchain_req *req,
				       const void *corr, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.corr);
	req->options.netem._len.corr = len;
	req->options.netem.corr = malloc(req->options.netem._len.corr);
	memcpy(req->options.netem.corr, corr, req->options.netem._len.corr);
}
static inline void
tc_newchain_req_set_options_netem_delay_dist(struct tc_newchain_req *req,
					     __s16 *delay_dist, size_t count)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.delay_dist);
	req->options.netem._count.delay_dist = count;
	count *= sizeof(__s16);
	req->options.netem.delay_dist = malloc(count);
	memcpy(req->options.netem.delay_dist, delay_dist, count);
}
static inline void
tc_newchain_req_set_options_netem_reorder(struct tc_newchain_req *req,
					  const void *reorder, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.reorder);
	req->options.netem._len.reorder = len;
	req->options.netem.reorder = malloc(req->options.netem._len.reorder);
	memcpy(req->options.netem.reorder, reorder, req->options.netem._len.reorder);
}
static inline void
tc_newchain_req_set_options_netem_corrupt(struct tc_newchain_req *req,
					  const void *corrupt, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.corrupt);
	req->options.netem._len.corrupt = len;
	req->options.netem.corrupt = malloc(req->options.netem._len.corrupt);
	memcpy(req->options.netem.corrupt, corrupt, req->options.netem._len.corrupt);
}
static inline void
tc_newchain_req_set_options_netem_loss_gi(struct tc_newchain_req *req,
					  const void *gi, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.loss = 1;
	free(req->options.netem.loss.gi);
	req->options.netem.loss._len.gi = len;
	req->options.netem.loss.gi = malloc(req->options.netem.loss._len.gi);
	memcpy(req->options.netem.loss.gi, gi, req->options.netem.loss._len.gi);
}
static inline void
tc_newchain_req_set_options_netem_loss_ge(struct tc_newchain_req *req,
					  const void *ge, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.loss = 1;
	free(req->options.netem.loss.ge);
	req->options.netem.loss._len.ge = len;
	req->options.netem.loss.ge = malloc(req->options.netem.loss._len.ge);
	memcpy(req->options.netem.loss.ge, ge, req->options.netem.loss._len.ge);
}
static inline void
tc_newchain_req_set_options_netem_rate(struct tc_newchain_req *req,
				       const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.rate);
	req->options.netem._len.rate = len;
	req->options.netem.rate = malloc(req->options.netem._len.rate);
	memcpy(req->options.netem.rate, rate, req->options.netem._len.rate);
}
static inline void
tc_newchain_req_set_options_netem_ecn(struct tc_newchain_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.ecn = 1;
	req->options.netem.ecn = ecn;
}
static inline void
tc_newchain_req_set_options_netem_rate64(struct tc_newchain_req *req,
					 __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.rate64 = 1;
	req->options.netem.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_netem_pad(struct tc_newchain_req *req, __u32 pad)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.pad = 1;
	req->options.netem.pad = pad;
}
static inline void
tc_newchain_req_set_options_netem_latency64(struct tc_newchain_req *req,
					    __s64 latency64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.latency64 = 1;
	req->options.netem.latency64 = latency64;
}
static inline void
tc_newchain_req_set_options_netem_jitter64(struct tc_newchain_req *req,
					   __s64 jitter64)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.jitter64 = 1;
	req->options.netem.jitter64 = jitter64;
}
static inline void
tc_newchain_req_set_options_netem_slot(struct tc_newchain_req *req,
				       const void *slot, size_t len)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.slot);
	req->options.netem._len.slot = len;
	req->options.netem.slot = malloc(req->options.netem._len.slot);
	memcpy(req->options.netem.slot, slot, req->options.netem._len.slot);
}
static inline void
tc_newchain_req_set_options_netem_slot_dist(struct tc_newchain_req *req,
					    __s16 *slot_dist, size_t count)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	free(req->options.netem.slot_dist);
	req->options.netem._count.slot_dist = count;
	count *= sizeof(__s16);
	req->options.netem.slot_dist = malloc(count);
	memcpy(req->options.netem.slot_dist, slot_dist, count);
}
static inline void
tc_newchain_req_set_options_netem_prng_seed(struct tc_newchain_req *req,
					    __u64 prng_seed)
{
	req->_present.options = 1;
	req->options._present.netem = 1;
	req->options.netem._present.prng_seed = 1;
	req->options.netem.prng_seed = prng_seed;
}
static inline void
tc_newchain_req_set_options_pfifo(struct tc_newchain_req *req,
				  const void *pfifo, size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo);
	req->options._len.pfifo = len;
	req->options.pfifo = malloc(req->options._len.pfifo);
	memcpy(req->options.pfifo, pfifo, req->options._len.pfifo);
}
static inline void
tc_newchain_req_set_options_pfifo_fast(struct tc_newchain_req *req,
				       const void *pfifo_fast, size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo_fast);
	req->options._len.pfifo_fast = len;
	req->options.pfifo_fast = malloc(req->options._len.pfifo_fast);
	memcpy(req->options.pfifo_fast, pfifo_fast, req->options._len.pfifo_fast);
}
static inline void
tc_newchain_req_set_options_pfifo_head_drop(struct tc_newchain_req *req,
					    const void *pfifo_head_drop,
					    size_t len)
{
	req->_present.options = 1;
	free(req->options.pfifo_head_drop);
	req->options._len.pfifo_head_drop = len;
	req->options.pfifo_head_drop = malloc(req->options._len.pfifo_head_drop);
	memcpy(req->options.pfifo_head_drop, pfifo_head_drop, req->options._len.pfifo_head_drop);
}
static inline void
tc_newchain_req_set_options_pie_target(struct tc_newchain_req *req,
				       __u32 target)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.target = 1;
	req->options.pie.target = target;
}
static inline void
tc_newchain_req_set_options_pie_limit(struct tc_newchain_req *req, __u32 limit)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.limit = 1;
	req->options.pie.limit = limit;
}
static inline void
tc_newchain_req_set_options_pie_tupdate(struct tc_newchain_req *req,
					__u32 tupdate)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.tupdate = 1;
	req->options.pie.tupdate = tupdate;
}
static inline void
tc_newchain_req_set_options_pie_alpha(struct tc_newchain_req *req, __u32 alpha)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.alpha = 1;
	req->options.pie.alpha = alpha;
}
static inline void
tc_newchain_req_set_options_pie_beta(struct tc_newchain_req *req, __u32 beta)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.beta = 1;
	req->options.pie.beta = beta;
}
static inline void
tc_newchain_req_set_options_pie_ecn(struct tc_newchain_req *req, __u32 ecn)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.ecn = 1;
	req->options.pie.ecn = ecn;
}
static inline void
tc_newchain_req_set_options_pie_bytemode(struct tc_newchain_req *req,
					 __u32 bytemode)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.bytemode = 1;
	req->options.pie.bytemode = bytemode;
}
static inline void
tc_newchain_req_set_options_pie_dq_rate_estimator(struct tc_newchain_req *req,
						  __u32 dq_rate_estimator)
{
	req->_present.options = 1;
	req->options._present.pie = 1;
	req->options.pie._present.dq_rate_estimator = 1;
	req->options.pie.dq_rate_estimator = dq_rate_estimator;
}
static inline void
tc_newchain_req_set_options_plug(struct tc_newchain_req *req, const void *plug,
				 size_t len)
{
	req->_present.options = 1;
	free(req->options.plug);
	req->options._len.plug = len;
	req->options.plug = malloc(req->options._len.plug);
	memcpy(req->options.plug, plug, req->options._len.plug);
}
static inline void
tc_newchain_req_set_options_prio(struct tc_newchain_req *req, const void *prio,
				 size_t len)
{
	req->_present.options = 1;
	free(req->options.prio);
	req->options._len.prio = len;
	req->options.prio = malloc(req->options._len.prio);
	memcpy(req->options.prio, prio, req->options._len.prio);
}
static inline void
tc_newchain_req_set_options_qfq_weight(struct tc_newchain_req *req,
				       __u32 weight)
{
	req->_present.options = 1;
	req->options._present.qfq = 1;
	req->options.qfq._present.weight = 1;
	req->options.qfq.weight = weight;
}
static inline void
tc_newchain_req_set_options_qfq_lmax(struct tc_newchain_req *req, __u32 lmax)
{
	req->_present.options = 1;
	req->options._present.qfq = 1;
	req->options.qfq._present.lmax = 1;
	req->options.qfq.lmax = lmax;
}
static inline void
tc_newchain_req_set_options_red_parms(struct tc_newchain_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	free(req->options.red.parms);
	req->options.red._len.parms = len;
	req->options.red.parms = malloc(req->options.red._len.parms);
	memcpy(req->options.red.parms, parms, req->options.red._len.parms);
}
static inline void
tc_newchain_req_set_options_red_stab(struct tc_newchain_req *req,
				     const void *stab, size_t len)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	free(req->options.red.stab);
	req->options.red._len.stab = len;
	req->options.red.stab = malloc(req->options.red._len.stab);
	memcpy(req->options.red.stab, stab, req->options.red._len.stab);
}
static inline void
tc_newchain_req_set_options_red_max_p(struct tc_newchain_req *req, __u32 max_p)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.max_p = 1;
	req->options.red.max_p = max_p;
}
static inline void
tc_newchain_req_set_options_red_flags(struct tc_newchain_req *req,
				      struct nla_bitfield32 *flags)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.flags = 1;
	memcpy(&req->options.red.flags, flags, sizeof(struct nla_bitfield32));
}
static inline void
tc_newchain_req_set_options_red_early_drop_block(struct tc_newchain_req *req,
						 __u32 early_drop_block)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.early_drop_block = 1;
	req->options.red.early_drop_block = early_drop_block;
}
static inline void
tc_newchain_req_set_options_red_mark_block(struct tc_newchain_req *req,
					   __u32 mark_block)
{
	req->_present.options = 1;
	req->options._present.red = 1;
	req->options.red._present.mark_block = 1;
	req->options.red.mark_block = mark_block;
}
static inline void
tc_newchain_req_set_options_route_classid(struct tc_newchain_req *req,
					  __u32 classid)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.classid = 1;
	req->options.route.classid = classid;
}
static inline void
tc_newchain_req_set_options_route_to(struct tc_newchain_req *req, __u32 to)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.to = 1;
	req->options.route.to = to;
}
static inline void
tc_newchain_req_set_options_route_from(struct tc_newchain_req *req, __u32 from)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.from = 1;
	req->options.route.from = from;
}
static inline void
tc_newchain_req_set_options_route_iif(struct tc_newchain_req *req, __u32 iif)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.iif = 1;
	req->options.route.iif = iif;
}
static inline void
tc_newchain_req_set_options_route_police_tbf(struct tc_newchain_req *req,
					     const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.tbf);
	req->options.route.police._len.tbf = len;
	req->options.route.police.tbf = malloc(req->options.route.police._len.tbf);
	memcpy(req->options.route.police.tbf, tbf, req->options.route.police._len.tbf);
}
static inline void
tc_newchain_req_set_options_route_police_rate(struct tc_newchain_req *req,
					      const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.rate);
	req->options.route.police._len.rate = len;
	req->options.route.police.rate = malloc(req->options.route.police._len.rate);
	memcpy(req->options.route.police.rate, rate, req->options.route.police._len.rate);
}
static inline void
tc_newchain_req_set_options_route_police_peakrate(struct tc_newchain_req *req,
						  const void *peakrate,
						  size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.peakrate);
	req->options.route.police._len.peakrate = len;
	req->options.route.police.peakrate = malloc(req->options.route.police._len.peakrate);
	memcpy(req->options.route.police.peakrate, peakrate, req->options.route.police._len.peakrate);
}
static inline void
tc_newchain_req_set_options_route_police_avrate(struct tc_newchain_req *req,
						__u32 avrate)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.avrate = 1;
	req->options.route.police.avrate = avrate;
}
static inline void
tc_newchain_req_set_options_route_police_result(struct tc_newchain_req *req,
						__u32 result)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.result = 1;
	req->options.route.police.result = result;
}
static inline void
tc_newchain_req_set_options_route_police_tm(struct tc_newchain_req *req,
					    const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	free(req->options.route.police.tm);
	req->options.route.police._len.tm = len;
	req->options.route.police.tm = malloc(req->options.route.police._len.tm);
	memcpy(req->options.route.police.tm, tm, req->options.route.police._len.tm);
}
static inline void
tc_newchain_req_set_options_route_police_rate64(struct tc_newchain_req *req,
						__u64 rate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.rate64 = 1;
	req->options.route.police.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_route_police_peakrate64(struct tc_newchain_req *req,
						    __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.peakrate64 = 1;
	req->options.route.police.peakrate64 = peakrate64;
}
static inline void
tc_newchain_req_set_options_route_police_pktrate64(struct tc_newchain_req *req,
						   __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.pktrate64 = 1;
	req->options.route.police.pktrate64 = pktrate64;
}
static inline void
tc_newchain_req_set_options_route_police_pktburst64(struct tc_newchain_req *req,
						    __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	req->options.route._present.police = 1;
	req->options.route.police._present.pktburst64 = 1;
	req->options.route.police.pktburst64 = pktburst64;
}
static inline void
__tc_newchain_req_set_options_route_act(struct tc_newchain_req *req,
					struct tc_act_attrs *act,
					unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.route = 1;
	free(req->options.route.act);
	req->options.route.act = act;
	req->options.route._count.act = n_act;
}
static inline void
tc_newchain_req_set_options_sfb(struct tc_newchain_req *req, const void *sfb,
				size_t len)
{
	req->_present.options = 1;
	free(req->options.sfb);
	req->options._len.sfb = len;
	req->options.sfb = malloc(req->options._len.sfb);
	memcpy(req->options.sfb, sfb, req->options._len.sfb);
}
static inline void
tc_newchain_req_set_options_sfq(struct tc_newchain_req *req, const void *sfq,
				size_t len)
{
	req->_present.options = 1;
	free(req->options.sfq);
	req->options._len.sfq = len;
	req->options.sfq = malloc(req->options._len.sfq);
	memcpy(req->options.sfq, sfq, req->options._len.sfq);
}
static inline void
tc_newchain_req_set_options_taprio_priomap(struct tc_newchain_req *req,
					   const void *priomap, size_t len)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	free(req->options.taprio.priomap);
	req->options.taprio._len.priomap = len;
	req->options.taprio.priomap = malloc(req->options.taprio._len.priomap);
	memcpy(req->options.taprio.priomap, priomap, req->options.taprio._len.priomap);
}
static inline void
__tc_newchain_req_set_options_taprio_sched_entry_list_entry(struct tc_newchain_req *req,
							    struct tc_taprio_sched_entry *entry,
							    unsigned int n_entry)
{
	unsigned int i;

	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_entry_list = 1;
	for (i = 0; i < req->options.taprio.sched_entry_list._count.entry; i++)
		tc_taprio_sched_entry_free(&req->options.taprio.sched_entry_list.entry[i]);
	free(req->options.taprio.sched_entry_list.entry);
	req->options.taprio.sched_entry_list.entry = entry;
	req->options.taprio.sched_entry_list._count.entry = n_entry;
}
static inline void
tc_newchain_req_set_options_taprio_sched_base_time(struct tc_newchain_req *req,
						   __s64 sched_base_time)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_base_time = 1;
	req->options.taprio.sched_base_time = sched_base_time;
}
static inline void
tc_newchain_req_set_options_taprio_sched_single_entry_index(struct tc_newchain_req *req,
							    __u32 index)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.index = 1;
	req->options.taprio.sched_single_entry.index = index;
}
static inline void
tc_newchain_req_set_options_taprio_sched_single_entry_cmd(struct tc_newchain_req *req,
							  __u8 cmd)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.cmd = 1;
	req->options.taprio.sched_single_entry.cmd = cmd;
}
static inline void
tc_newchain_req_set_options_taprio_sched_single_entry_gate_mask(struct tc_newchain_req *req,
								__u32 gate_mask)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.gate_mask = 1;
	req->options.taprio.sched_single_entry.gate_mask = gate_mask;
}
static inline void
tc_newchain_req_set_options_taprio_sched_single_entry_interval(struct tc_newchain_req *req,
							       __u32 interval)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_single_entry = 1;
	req->options.taprio.sched_single_entry._present.interval = 1;
	req->options.taprio.sched_single_entry.interval = interval;
}
static inline void
tc_newchain_req_set_options_taprio_sched_clockid(struct tc_newchain_req *req,
						 __s32 sched_clockid)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_clockid = 1;
	req->options.taprio.sched_clockid = sched_clockid;
}
static inline void
tc_newchain_req_set_options_taprio_admin_sched(struct tc_newchain_req *req,
					       const void *admin_sched,
					       size_t len)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	free(req->options.taprio.admin_sched);
	req->options.taprio._len.admin_sched = len;
	req->options.taprio.admin_sched = malloc(req->options.taprio._len.admin_sched);
	memcpy(req->options.taprio.admin_sched, admin_sched, req->options.taprio._len.admin_sched);
}
static inline void
tc_newchain_req_set_options_taprio_sched_cycle_time(struct tc_newchain_req *req,
						    __s64 sched_cycle_time)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_cycle_time = 1;
	req->options.taprio.sched_cycle_time = sched_cycle_time;
}
static inline void
tc_newchain_req_set_options_taprio_sched_cycle_time_extension(struct tc_newchain_req *req,
							      __s64 sched_cycle_time_extension)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.sched_cycle_time_extension = 1;
	req->options.taprio.sched_cycle_time_extension = sched_cycle_time_extension;
}
static inline void
tc_newchain_req_set_options_taprio_flags(struct tc_newchain_req *req,
					 __u32 flags)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.flags = 1;
	req->options.taprio.flags = flags;
}
static inline void
tc_newchain_req_set_options_taprio_txtime_delay(struct tc_newchain_req *req,
						__u32 txtime_delay)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.txtime_delay = 1;
	req->options.taprio.txtime_delay = txtime_delay;
}
static inline void
tc_newchain_req_set_options_taprio_tc_entry_index(struct tc_newchain_req *req,
						  __u32 index)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.index = 1;
	req->options.taprio.tc_entry.index = index;
}
static inline void
tc_newchain_req_set_options_taprio_tc_entry_max_sdu(struct tc_newchain_req *req,
						    __u32 max_sdu)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.max_sdu = 1;
	req->options.taprio.tc_entry.max_sdu = max_sdu;
}
static inline void
tc_newchain_req_set_options_taprio_tc_entry_fp(struct tc_newchain_req *req,
					       __u32 fp)
{
	req->_present.options = 1;
	req->options._present.taprio = 1;
	req->options.taprio._present.tc_entry = 1;
	req->options.taprio.tc_entry._present.fp = 1;
	req->options.taprio.tc_entry.fp = fp;
}
static inline void
tc_newchain_req_set_options_tbf_parms(struct tc_newchain_req *req,
				      const void *parms, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.parms);
	req->options.tbf._len.parms = len;
	req->options.tbf.parms = malloc(req->options.tbf._len.parms);
	memcpy(req->options.tbf.parms, parms, req->options.tbf._len.parms);
}
static inline void
tc_newchain_req_set_options_tbf_rtab(struct tc_newchain_req *req,
				     const void *rtab, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.rtab);
	req->options.tbf._len.rtab = len;
	req->options.tbf.rtab = malloc(req->options.tbf._len.rtab);
	memcpy(req->options.tbf.rtab, rtab, req->options.tbf._len.rtab);
}
static inline void
tc_newchain_req_set_options_tbf_ptab(struct tc_newchain_req *req,
				     const void *ptab, size_t len)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	free(req->options.tbf.ptab);
	req->options.tbf._len.ptab = len;
	req->options.tbf.ptab = malloc(req->options.tbf._len.ptab);
	memcpy(req->options.tbf.ptab, ptab, req->options.tbf._len.ptab);
}
static inline void
tc_newchain_req_set_options_tbf_rate64(struct tc_newchain_req *req,
				       __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.rate64 = 1;
	req->options.tbf.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_tbf_prate64(struct tc_newchain_req *req,
					__u64 prate64)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.prate64 = 1;
	req->options.tbf.prate64 = prate64;
}
static inline void
tc_newchain_req_set_options_tbf_burst(struct tc_newchain_req *req, __u32 burst)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.burst = 1;
	req->options.tbf.burst = burst;
}
static inline void
tc_newchain_req_set_options_tbf_pburst(struct tc_newchain_req *req,
				       __u32 pburst)
{
	req->_present.options = 1;
	req->options._present.tbf = 1;
	req->options.tbf._present.pburst = 1;
	req->options.tbf.pburst = pburst;
}
static inline void
tc_newchain_req_set_options_u32_classid(struct tc_newchain_req *req,
					__u32 classid)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.classid = 1;
	req->options.u32.classid = classid;
}
static inline void
tc_newchain_req_set_options_u32_hash(struct tc_newchain_req *req, __u32 hash)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.hash = 1;
	req->options.u32.hash = hash;
}
static inline void
tc_newchain_req_set_options_u32_link(struct tc_newchain_req *req, __u32 link)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.link = 1;
	req->options.u32.link = link;
}
static inline void
tc_newchain_req_set_options_u32_divisor(struct tc_newchain_req *req,
					__u32 divisor)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.divisor = 1;
	req->options.u32.divisor = divisor;
}
static inline void
tc_newchain_req_set_options_u32_sel(struct tc_newchain_req *req,
				    const void *sel, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.sel);
	req->options.u32._len.sel = len;
	req->options.u32.sel = malloc(req->options.u32._len.sel);
	memcpy(req->options.u32.sel, sel, req->options.u32._len.sel);
}
static inline void
tc_newchain_req_set_options_u32_police_tbf(struct tc_newchain_req *req,
					   const void *tbf, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.tbf);
	req->options.u32.police._len.tbf = len;
	req->options.u32.police.tbf = malloc(req->options.u32.police._len.tbf);
	memcpy(req->options.u32.police.tbf, tbf, req->options.u32.police._len.tbf);
}
static inline void
tc_newchain_req_set_options_u32_police_rate(struct tc_newchain_req *req,
					    const void *rate, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.rate);
	req->options.u32.police._len.rate = len;
	req->options.u32.police.rate = malloc(req->options.u32.police._len.rate);
	memcpy(req->options.u32.police.rate, rate, req->options.u32.police._len.rate);
}
static inline void
tc_newchain_req_set_options_u32_police_peakrate(struct tc_newchain_req *req,
						const void *peakrate,
						size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.peakrate);
	req->options.u32.police._len.peakrate = len;
	req->options.u32.police.peakrate = malloc(req->options.u32.police._len.peakrate);
	memcpy(req->options.u32.police.peakrate, peakrate, req->options.u32.police._len.peakrate);
}
static inline void
tc_newchain_req_set_options_u32_police_avrate(struct tc_newchain_req *req,
					      __u32 avrate)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.avrate = 1;
	req->options.u32.police.avrate = avrate;
}
static inline void
tc_newchain_req_set_options_u32_police_result(struct tc_newchain_req *req,
					      __u32 result)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.result = 1;
	req->options.u32.police.result = result;
}
static inline void
tc_newchain_req_set_options_u32_police_tm(struct tc_newchain_req *req,
					  const void *tm, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	free(req->options.u32.police.tm);
	req->options.u32.police._len.tm = len;
	req->options.u32.police.tm = malloc(req->options.u32.police._len.tm);
	memcpy(req->options.u32.police.tm, tm, req->options.u32.police._len.tm);
}
static inline void
tc_newchain_req_set_options_u32_police_rate64(struct tc_newchain_req *req,
					      __u64 rate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.rate64 = 1;
	req->options.u32.police.rate64 = rate64;
}
static inline void
tc_newchain_req_set_options_u32_police_peakrate64(struct tc_newchain_req *req,
						  __u64 peakrate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.peakrate64 = 1;
	req->options.u32.police.peakrate64 = peakrate64;
}
static inline void
tc_newchain_req_set_options_u32_police_pktrate64(struct tc_newchain_req *req,
						 __u64 pktrate64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.pktrate64 = 1;
	req->options.u32.police.pktrate64 = pktrate64;
}
static inline void
tc_newchain_req_set_options_u32_police_pktburst64(struct tc_newchain_req *req,
						  __u64 pktburst64)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.police = 1;
	req->options.u32.police._present.pktburst64 = 1;
	req->options.u32.police.pktburst64 = pktburst64;
}
static inline void
__tc_newchain_req_set_options_u32_act(struct tc_newchain_req *req,
				      struct tc_act_attrs *act,
				      unsigned int n_act)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.act);
	req->options.u32.act = act;
	req->options.u32._count.act = n_act;
}
static inline void
tc_newchain_req_set_options_u32_indev(struct tc_newchain_req *req,
				      const char *indev)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.indev);
	req->options.u32._len.indev = strlen(indev);
	req->options.u32.indev = malloc(req->options.u32._len.indev + 1);
	memcpy(req->options.u32.indev, indev, req->options.u32._len.indev);
	req->options.u32.indev[req->options.u32._len.indev] = 0;
}
static inline void
tc_newchain_req_set_options_u32_pcnt(struct tc_newchain_req *req,
				     const void *pcnt, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.pcnt);
	req->options.u32._len.pcnt = len;
	req->options.u32.pcnt = malloc(req->options.u32._len.pcnt);
	memcpy(req->options.u32.pcnt, pcnt, req->options.u32._len.pcnt);
}
static inline void
tc_newchain_req_set_options_u32_mark(struct tc_newchain_req *req,
				     const void *mark, size_t len)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	free(req->options.u32.mark);
	req->options.u32._len.mark = len;
	req->options.u32.mark = malloc(req->options.u32._len.mark);
	memcpy(req->options.u32.mark, mark, req->options.u32._len.mark);
}
static inline void
tc_newchain_req_set_options_u32_flags(struct tc_newchain_req *req, __u32 flags)
{
	req->_present.options = 1;
	req->options._present.u32 = 1;
	req->options.u32._present.flags = 1;
	req->options.u32.flags = flags;
}
static inline void
tc_newchain_req_set_rate(struct tc_newchain_req *req, const void *rate,
			 size_t len)
{
	free(req->rate);
	req->_len.rate = len;
	req->rate = malloc(req->_len.rate);
	memcpy(req->rate, rate, req->_len.rate);
}
static inline void
tc_newchain_req_set_chain(struct tc_newchain_req *req, __u32 chain)
{
	req->_present.chain = 1;
	req->chain = chain;
}
static inline void
tc_newchain_req_set_ingress_block(struct tc_newchain_req *req,
				  __u32 ingress_block)
{
	req->_present.ingress_block = 1;
	req->ingress_block = ingress_block;
}
static inline void
tc_newchain_req_set_egress_block(struct tc_newchain_req *req,
				 __u32 egress_block)
{
	req->_present.egress_block = 1;
	req->egress_block = egress_block;
}

/*
 * Get / dump tc chain information.
 */
int tc_newchain(struct ynl_sock *ys, struct tc_newchain_req *req);

/* ============== RTM_DELCHAIN ============== */
/* RTM_DELCHAIN - do */
struct tc_delchain_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;

	struct {
		__u32 chain:1;
	} _present;

	__u32 chain;
};

static inline struct tc_delchain_req *tc_delchain_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_delchain_req));
}
void tc_delchain_req_free(struct tc_delchain_req *req);

static inline void
tc_delchain_req_set_nlflags(struct tc_delchain_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
tc_delchain_req_set_chain(struct tc_delchain_req *req, __u32 chain)
{
	req->_present.chain = 1;
	req->chain = chain;
}

/*
 * Get / dump tc chain information.
 */
int tc_delchain(struct ynl_sock *ys, struct tc_delchain_req *req);

/* ============== RTM_GETCHAIN ============== */
/* RTM_GETCHAIN - do */
struct tc_getchain_req {
	__u16 _nlmsg_flags;

	struct tcmsg _hdr;

	struct {
		__u32 chain:1;
	} _present;

	__u32 chain;
};

static inline struct tc_getchain_req *tc_getchain_req_alloc(void)
{
	return calloc(1, sizeof(struct tc_getchain_req));
}
void tc_getchain_req_free(struct tc_getchain_req *req);

static inline void
tc_getchain_req_set_nlflags(struct tc_getchain_req *req, __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
tc_getchain_req_set_chain(struct tc_getchain_req *req, __u32 chain)
{
	req->_present.chain = 1;
	req->chain = chain;
}

struct tc_getchain_rsp {
	struct tcmsg _hdr;

	struct {
		__u32 options:1;
		__u32 xstats:1;
		__u32 fcnt:1;
		__u32 stats2:1;
		__u32 stab:1;
		__u32 chain:1;
		__u32 ingress_block:1;
		__u32 egress_block:1;
	} _present;
	struct {
		__u32 kind;
		__u32 stats;
		__u32 rate;
	} _len;

	char *kind;
	struct tc_options_msg options;
	struct tc_stats *stats;
	struct tc_tca_stats_app_msg xstats;
	struct gnet_estimator *rate;
	__u32 fcnt;
	struct tc_tca_stats_attrs stats2;
	struct tc_tca_stab_attrs stab;
	__u32 chain;
	__u32 ingress_block;
	__u32 egress_block;
};

void tc_getchain_rsp_free(struct tc_getchain_rsp *rsp);

/*
 * Get / dump tc chain information.
 */
struct tc_getchain_rsp *
tc_getchain(struct ynl_sock *ys, struct tc_getchain_req *req);

#endif /* _LINUX_TC_GEN_H */
