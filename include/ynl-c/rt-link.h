/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/rt-link.yaml */
/* YNL-GEN user header */

#ifndef _LINUX_RT_LINK_GEN_H
#define _LINUX_RT_LINK_GEN_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>
#include <linux/dpll.h>
#include <linux/rtnetlink.h>

struct ynl_sock;

extern const struct ynl_family ynl_rt_link_family;

/* Enums */
const char *rt_link_op_str(int op);
const char *rt_link_ifinfo_flags_str(enum net_device_flags value);
const char *rt_link_vlan_protocols_str(int value);
const char *rt_link_ipv4_devconf_str(int value);
const char *rt_link_ipv6_devconf_str(int value);
const char *rt_link_ifla_icmp6_stats_str(int value);
const char *rt_link_ifla_inet6_stats_str(int value);
const char *rt_link_vlan_flags_str(int value);
const char *rt_link_ifla_vf_link_state_enum_str(int value);
const char *rt_link_rtext_filter_str(int value);
const char *rt_link_netkit_policy_str(int value);
const char *rt_link_netkit_mode_str(enum netkit_mode value);
const char *rt_link_netkit_scrub_str(int value);
const char *rt_link_ovpn_mode_str(enum ovpn_mode value);

/* Common nested types */
struct rt_link_vf_ports_attrs {
};

struct rt_link_port_self_attrs {
};

struct rt_link_xdp_attrs {
	struct {
		__u32 fd:1;
		__u32 attached:1;
		__u32 flags:1;
		__u32 prog_id:1;
		__u32 drv_prog_id:1;
		__u32 skb_prog_id:1;
		__u32 hw_prog_id:1;
		__u32 expected_fd:1;
	} _present;

	__s32 fd;
	__u8 attached;
	__u32 flags;
	__u32 prog_id;
	__u32 drv_prog_id;
	__u32 skb_prog_id;
	__u32 hw_prog_id;
	__s32 expected_fd;
};

struct rt_link_prop_list_link_attrs {
	struct {
		__u32 alt_ifname;
	} _count;

	struct ynl_string **alt_ifname;
};

struct rt_link_link_dpll_pin_attrs {
	struct {
		__u32 id:1;
	} _present;

	__u32 id;
};

struct rt_link_ifla_attrs {
	struct {
		__u32 conf;
	} _count;

	__u32 *conf;
};

struct rt_link_ifla6_attrs {
	struct {
		__u32 flags:1;
		__u32 addr_gen_mode:1;
		__u32 ra_mtu:1;
	} _present;
	struct {
		__u32 mcast;
		__u32 cacheinfo;
		__u32 token;
	} _len;
	struct {
		__u32 conf;
		__u32 stats;
		__u32 icmp6stats;
	} _count;

	__u32 flags;
	__u32 *conf;
	__u64 *stats;
	void *mcast;
	struct ifla_cacheinfo *cacheinfo;
	__u64 *icmp6stats;
	void *token;
	__u8 addr_gen_mode;
	__u32 ra_mtu;
};

struct rt_link_mctp_attrs {
	struct {
		__u32 net:1;
		__u32 phys_binding:1;
	} _present;

	__u32 net;
	__u8 phys_binding;
};

struct rt_link_hw_s_info_one {
	struct {
		__u32 request:1;
		__u32 used:1;
	} _present;

	__u32 idx;
	__u8 request;
	__u8 used;
};

struct rt_link_linkinfo_bridge_attrs {
	struct {
		__u32 forward_delay:1;
		__u32 hello_time:1;
		__u32 max_age:1;
		__u32 ageing_time:1;
		__u32 stp_state:1;
		__u32 priority:1;
		__u32 vlan_filtering:1;
		__u32 vlan_protocol:1;
		__u32 group_fwd_mask:1;
		__u32 root_port:1;
		__u32 root_path_cost:1;
		__u32 topology_change:1;
		__u32 topology_change_detected:1;
		__u32 hello_timer:1;
		__u32 tcn_timer:1;
		__u32 topology_change_timer:1;
		__u32 gc_timer:1;
		__u32 mcast_router:1;
		__u32 mcast_snooping:1;
		__u32 mcast_query_use_ifaddr:1;
		__u32 mcast_querier:1;
		__u32 mcast_hash_elasticity:1;
		__u32 mcast_hash_max:1;
		__u32 mcast_last_member_cnt:1;
		__u32 mcast_startup_query_cnt:1;
		__u32 mcast_last_member_intvl:1;
		__u32 mcast_membership_intvl:1;
		__u32 mcast_querier_intvl:1;
		__u32 mcast_query_intvl:1;
		__u32 mcast_query_response_intvl:1;
		__u32 mcast_startup_query_intvl:1;
		__u32 nf_call_iptables:1;
		__u32 nf_call_ip6tables:1;
		__u32 nf_call_arptables:1;
		__u32 vlan_default_pvid:1;
		__u32 vlan_stats_enabled:1;
		__u32 mcast_stats_enabled:1;
		__u32 mcast_igmp_version:1;
		__u32 mcast_mld_version:1;
		__u32 vlan_stats_per_port:1;
		__u32 fdb_n_learned:1;
		__u32 fdb_max_learned:1;
	} _present;
	struct {
		__u32 root_id;
		__u32 bridge_id;
		__u32 group_addr;
		__u32 fdb_flush;
		__u32 multi_boolopt;
		__u32 mcast_querier_state;
	} _len;

	__u32 forward_delay;
	__u32 hello_time;
	__u32 max_age;
	__u32 ageing_time;
	__u32 stp_state;
	__u16 priority;
	__u8 vlan_filtering;
	__u16 vlan_protocol;
	__u16 group_fwd_mask;
	struct ifla_bridge_id *root_id;
	struct ifla_bridge_id *bridge_id;
	__u16 root_port;
	__u32 root_path_cost;
	__u8 topology_change;
	__u8 topology_change_detected;
	__u64 hello_timer;
	__u64 tcn_timer;
	__u64 topology_change_timer;
	__u64 gc_timer;
	void *group_addr;
	void *fdb_flush;
	__u8 mcast_router;
	__u8 mcast_snooping;
	__u8 mcast_query_use_ifaddr;
	__u8 mcast_querier;
	__u32 mcast_hash_elasticity;
	__u32 mcast_hash_max;
	__u32 mcast_last_member_cnt;
	__u32 mcast_startup_query_cnt;
	__u64 mcast_last_member_intvl;
	__u64 mcast_membership_intvl;
	__u64 mcast_querier_intvl;
	__u64 mcast_query_intvl;
	__u64 mcast_query_response_intvl;
	__u64 mcast_startup_query_intvl;
	__u8 nf_call_iptables;
	__u8 nf_call_ip6tables;
	__u8 nf_call_arptables;
	__u16 vlan_default_pvid;
	__u8 vlan_stats_enabled;
	__u8 mcast_stats_enabled;
	__u8 mcast_igmp_version;
	__u8 mcast_mld_version;
	__u8 vlan_stats_per_port;
	struct br_boolopt_multi *multi_boolopt;
	void *mcast_querier_state;
	__u32 fdb_n_learned;
	__u32 fdb_max_learned;
};

struct rt_link_linkinfo_gre_attrs {
	struct {
		__u32 link:1;
		__u32 iflags:1;
		__u32 oflags:1;
		__u32 ikey:1;
		__u32 okey:1;
		__u32 ttl:1;
		__u32 tos:1;
		__u32 pmtudisc:1;
		__u32 encap_limit:1;
		__u32 flowinfo:1;
		__u32 flags:1;
		__u32 encap_type:1;
		__u32 encap_flags:1;
		__u32 encap_sport:1;
		__u32 encap_dport:1;
		__u32 collect_metadata:1;
		__u32 ignore_df:1;
		__u32 fwmark:1;
		__u32 erspan_index:1;
		__u32 erspan_ver:1;
		__u32 erspan_dir:1;
		__u32 erspan_hwid:1;
	} _present;
	struct {
		__u32 local;
		__u32 remote;
	} _len;

	__u32 link;
	__u16 iflags /* big-endian */;
	__u16 oflags /* big-endian */;
	__u32 ikey /* big-endian */;
	__u32 okey /* big-endian */;
	void *local;
	void *remote;
	__u8 ttl;
	__u8 tos;
	__u8 pmtudisc;
	__u8 encap_limit;
	__u32 flowinfo /* big-endian */;
	__u32 flags;
	__u16 encap_type;
	__u16 encap_flags;
	__u16 encap_sport /* big-endian */;
	__u16 encap_dport /* big-endian */;
	__u8 ignore_df;
	__u32 fwmark;
	__u32 erspan_index;
	__u8 erspan_ver;
	__u8 erspan_dir;
	__u16 erspan_hwid;
};

struct rt_link_linkinfo_gre6_attrs {
	struct {
		__u32 link:1;
		__u32 iflags:1;
		__u32 oflags:1;
		__u32 ikey:1;
		__u32 okey:1;
		__u32 ttl:1;
		__u32 encap_limit:1;
		__u32 flowinfo:1;
		__u32 flags:1;
		__u32 encap_type:1;
		__u32 encap_flags:1;
		__u32 encap_sport:1;
		__u32 encap_dport:1;
		__u32 collect_metadata:1;
		__u32 fwmark:1;
		__u32 erspan_index:1;
		__u32 erspan_ver:1;
		__u32 erspan_dir:1;
		__u32 erspan_hwid:1;
	} _present;
	struct {
		__u32 local;
		__u32 remote;
	} _len;

	__u32 link;
	__u16 iflags /* big-endian */;
	__u16 oflags /* big-endian */;
	__u32 ikey /* big-endian */;
	__u32 okey /* big-endian */;
	void *local;
	void *remote;
	__u8 ttl;
	__u8 encap_limit;
	__u32 flowinfo /* big-endian */;
	__u32 flags;
	__u16 encap_type;
	__u16 encap_flags;
	__u16 encap_sport /* big-endian */;
	__u16 encap_dport /* big-endian */;
	__u32 fwmark;
	__u32 erspan_index;
	__u8 erspan_ver;
	__u8 erspan_dir;
	__u16 erspan_hwid;
};

struct rt_link_linkinfo_geneve_attrs {
	struct {
		__u32 id:1;
		__u32 ttl:1;
		__u32 tos:1;
		__u32 port:1;
		__u32 collect_metadata:1;
		__u32 udp_csum:1;
		__u32 udp_zero_csum6_tx:1;
		__u32 udp_zero_csum6_rx:1;
		__u32 label:1;
		__u32 ttl_inherit:1;
		__u32 df:1;
		__u32 inner_proto_inherit:1;
	} _present;
	struct {
		__u32 remote;
		__u32 remote6;
		__u32 port_range;
	} _len;

	__u32 id;
	void *remote;
	__u8 ttl;
	__u8 tos;
	__u16 port /* big-endian */;
	void *remote6;
	__u8 udp_csum;
	__u8 udp_zero_csum6_tx;
	__u8 udp_zero_csum6_rx;
	__u32 label /* big-endian */;
	__u8 ttl_inherit;
	__u8 df;
	struct ifla_geneve_port_range *port_range;
};

struct rt_link_linkinfo_iptun_attrs {
	struct {
		__u32 link:1;
		__u32 ttl:1;
		__u32 tos:1;
		__u32 encap_limit:1;
		__u32 flowinfo:1;
		__u32 flags:1;
		__u32 proto:1;
		__u32 pmtudisc:1;
		__u32 _6rd_prefixlen:1;
		__u32 _6rd_relay_prefixlen:1;
		__u32 encap_type:1;
		__u32 encap_flags:1;
		__u32 encap_sport:1;
		__u32 encap_dport:1;
		__u32 collect_metadata:1;
		__u32 fwmark:1;
	} _present;
	struct {
		__u32 local;
		__u32 remote;
		__u32 _6rd_prefix;
		__u32 _6rd_relay_prefix;
	} _len;

	__u32 link;
	void *local;
	void *remote;
	__u8 ttl;
	__u8 tos;
	__u8 encap_limit;
	__u32 flowinfo /* big-endian */;
	__u16 flags /* big-endian */;
	__u8 proto;
	__u8 pmtudisc;
	void *_6rd_prefix;
	void *_6rd_relay_prefix;
	__u16 _6rd_prefixlen;
	__u16 _6rd_relay_prefixlen;
	__u16 encap_type;
	__u16 encap_flags;
	__u16 encap_sport /* big-endian */;
	__u16 encap_dport /* big-endian */;
	__u32 fwmark;
};

struct rt_link_linkinfo_ip6tnl_attrs {
	struct {
		__u32 link:1;
		__u32 ttl:1;
		__u32 encap_limit:1;
		__u32 flowinfo:1;
		__u32 flags:1;
		__u32 proto:1;
		__u32 encap_type:1;
		__u32 encap_flags:1;
		__u32 encap_sport:1;
		__u32 encap_dport:1;
		__u32 collect_metadata:1;
		__u32 fwmark:1;
	} _present;
	struct {
		__u32 local;
		__u32 remote;
	} _len;

	__u32 link;
	void *local;
	void *remote;
	__u8 ttl;
	__u8 encap_limit;
	__u32 flowinfo /* big-endian */;
	__u32 flags /* big-endian */;
	__u8 proto;
	__u16 encap_type;
	__u16 encap_flags;
	__u16 encap_sport /* big-endian */;
	__u16 encap_dport /* big-endian */;
	__u32 fwmark;
};

struct rt_link_linkinfo_tun_attrs {
	struct {
		__u32 owner:1;
		__u32 group:1;
		__u32 type:1;
		__u32 pi:1;
		__u32 vnet_hdr:1;
		__u32 persist:1;
		__u32 multi_queue:1;
		__u32 num_queues:1;
		__u32 num_disabled_queues:1;
	} _present;

	__u32 owner;
	__u32 group;
	__u8 type;
	__u8 pi;
	__u8 vnet_hdr;
	__u8 persist;
	__u8 multi_queue;
	__u32 num_queues;
	__u32 num_disabled_queues;
};

struct rt_link_linkinfo_vrf_attrs {
	struct {
		__u32 table:1;
	} _present;

	__u32 table;
};

struct rt_link_linkinfo_vti_attrs {
	struct {
		__u32 link:1;
		__u32 ikey:1;
		__u32 okey:1;
		__u32 fwmark:1;
	} _present;
	struct {
		__u32 local;
		__u32 remote;
	} _len;

	__u32 link;
	__u32 ikey /* big-endian */;
	__u32 okey /* big-endian */;
	void *local;
	void *remote;
	__u32 fwmark;
};

struct rt_link_linkinfo_vti6_attrs {
	struct {
		__u32 link:1;
		__u32 ikey:1;
		__u32 okey:1;
		__u32 fwmark:1;
	} _present;
	struct {
		__u32 local;
		__u32 remote;
	} _len;

	__u32 link;
	__u32 ikey /* big-endian */;
	__u32 okey /* big-endian */;
	void *local;
	void *remote;
	__u32 fwmark;
};

struct rt_link_linkinfo_netkit_attrs {
	struct {
		__u32 primary:1;
		__u32 policy:1;
		__u32 peer_policy:1;
		__u32 mode:1;
		__u32 scrub:1;
		__u32 peer_scrub:1;
		__u32 headroom:1;
		__u32 tailroom:1;
	} _present;
	struct {
		__u32 peer_info;
	} _len;

	void *peer_info;
	__u8 primary;
	int policy;
	int peer_policy;
	enum netkit_mode mode;
	int scrub;
	int peer_scrub;
	__u16 headroom;
	__u16 tailroom;
};

struct rt_link_linkinfo_ovpn_attrs {
	struct {
		__u32 mode:1;
	} _present;

	enum ovpn_mode mode;
};

struct rt_link_linkinfo_brport_attrs {
	struct {
		__u32 state:1;
		__u32 priority:1;
		__u32 cost:1;
		__u32 mode:1;
		__u32 guard:1;
		__u32 protect:1;
		__u32 fast_leave:1;
		__u32 learning:1;
		__u32 unicast_flood:1;
		__u32 proxyarp:1;
		__u32 learning_sync:1;
		__u32 proxyarp_wifi:1;
		__u32 designated_port:1;
		__u32 designated_cost:1;
		__u32 id:1;
		__u32 no:1;
		__u32 topology_change_ack:1;
		__u32 config_pending:1;
		__u32 message_age_timer:1;
		__u32 forward_delay_timer:1;
		__u32 hold_timer:1;
		__u32 flush:1;
		__u32 multicast_router:1;
		__u32 mcast_flood:1;
		__u32 mcast_to_ucast:1;
		__u32 vlan_tunnel:1;
		__u32 bcast_flood:1;
		__u32 group_fwd_mask:1;
		__u32 neigh_suppress:1;
		__u32 isolated:1;
		__u32 backup_port:1;
		__u32 mrp_ring_open:1;
		__u32 mrp_in_open:1;
		__u32 mcast_eht_hosts_limit:1;
		__u32 mcast_eht_hosts_cnt:1;
		__u32 locked:1;
		__u32 mab:1;
		__u32 mcast_n_groups:1;
		__u32 mcast_max_groups:1;
		__u32 neigh_vlan_suppress:1;
		__u32 backup_nhid:1;
	} _present;
	struct {
		__u32 root_id;
		__u32 bridge_id;
	} _len;

	__u8 state;
	__u16 priority;
	__u32 cost;
	struct ifla_bridge_id *root_id;
	struct ifla_bridge_id *bridge_id;
	__u16 designated_port;
	__u16 designated_cost;
	__u16 id;
	__u16 no;
	__u8 topology_change_ack;
	__u8 config_pending;
	__u64 message_age_timer;
	__u64 forward_delay_timer;
	__u64 hold_timer;
	__u8 multicast_router;
	__u16 group_fwd_mask;
	__u32 backup_port;
	__u32 mcast_eht_hosts_limit;
	__u32 mcast_eht_hosts_cnt;
	__u32 mcast_n_groups;
	__u32 mcast_max_groups;
	__u32 backup_nhid;
};

struct rt_link_bond_slave_attrs {
	struct {
		__u32 state:1;
		__u32 mii_status:1;
		__u32 link_failure_count:1;
		__u32 queue_id:1;
		__u32 ad_aggregator_id:1;
		__u32 ad_actor_oper_port_state:1;
		__u32 ad_partner_oper_port_state:1;
		__u32 prio:1;
	} _present;
	struct {
		__u32 perm_hwaddr;
	} _len;

	__u8 state;
	__u8 mii_status;
	__u32 link_failure_count;
	void *perm_hwaddr;
	__u16 queue_id;
	__u16 ad_aggregator_id;
	__u8 ad_actor_oper_port_state;
	__u16 ad_partner_oper_port_state;
	__u32 prio;
};

struct rt_link_vf_stats_attrs {
	struct {
		__u32 rx_packets:1;
		__u32 tx_packets:1;
		__u32 rx_bytes:1;
		__u32 tx_bytes:1;
		__u32 broadcast:1;
		__u32 multicast:1;
		__u32 rx_dropped:1;
		__u32 tx_dropped:1;
	} _present;

	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 broadcast;
	__u64 multicast;
	__u64 rx_dropped;
	__u64 tx_dropped;
};

struct rt_link_vf_vlan_attrs {
	struct {
		__u32 info;
	} _count;

	struct ifla_vf_vlan_info *info;
	unsigned int n_info;
};

struct rt_link_bond_ad_info_attrs {
	struct {
		__u32 aggregator:1;
		__u32 num_ports:1;
		__u32 actor_key:1;
		__u32 partner_key:1;
	} _present;
	struct {
		__u32 partner_mac;
	} _len;

	__u16 aggregator;
	__u16 num_ports;
	__u16 actor_key;
	__u16 partner_key;
	void *partner_mac;
};

struct rt_link_ifla_vlan_qos {
	struct {
		__u32 mapping;
	} _count;

	struct ifla_vlan_qos_mapping *mapping;
	unsigned int n_mapping;
};

struct rt_link_af_spec_attrs {
	struct {
		__u32 inet:1;
		__u32 inet6:1;
		__u32 mctp:1;
	} _present;

	struct rt_link_ifla_attrs inet;
	struct rt_link_ifla6_attrs inet6;
	struct rt_link_mctp_attrs mctp;
};

struct rt_link_link_offload_xstats {
	struct {
		__u32 cpu_hit;
		__u32 l3_stats;
	} _len;
	struct {
		__u32 hw_s_info;
	} _count;

	void *cpu_hit;
	struct rt_link_hw_s_info_one *hw_s_info;
	void *l3_stats;
};

struct rt_link_linkinfo_member_data_msg {
	struct {
		__u32 bridge:1;
		__u32 bond:1;
	} _present;

	struct rt_link_linkinfo_brport_attrs bridge;
	struct rt_link_bond_slave_attrs bond;
};

struct rt_link_vfinfo_attrs {
	struct {
		__u32 stats:1;
		__u32 vlan_list:1;
	} _present;
	struct {
		__u32 mac;
		__u32 vlan;
		__u32 tx_rate;
		__u32 spoofchk;
		__u32 link_state;
		__u32 rate;
		__u32 rss_query_en;
		__u32 trust;
		__u32 ib_node_guid;
		__u32 ib_port_guid;
		__u32 broadcast;
	} _len;

	struct ifla_vf_mac *mac;
	struct ifla_vf_vlan *vlan;
	struct ifla_vf_tx_rate *tx_rate;
	struct ifla_vf_spoofchk *spoofchk;
	struct ifla_vf_link_state *link_state;
	struct ifla_vf_rate *rate;
	struct ifla_vf_rss_query_en *rss_query_en;
	struct rt_link_vf_stats_attrs stats;
	struct ifla_vf_trust *trust;
	struct ifla_vf_guid *ib_node_guid;
	struct ifla_vf_guid *ib_port_guid;
	struct rt_link_vf_vlan_attrs vlan_list;
	void *broadcast;
};

static inline struct rt_link_vfinfo_attrs *
rt_link_vfinfo_attrs_alloc(unsigned int n)
{
	return calloc(n, sizeof(struct rt_link_vfinfo_attrs));
}

void rt_link_vfinfo_attrs_free(struct rt_link_vfinfo_attrs *obj);

static inline void
rt_link_vfinfo_attrs_set_mac(struct rt_link_vfinfo_attrs *obj, const void *mac,
			     size_t len)
{
	free(obj->mac);
	obj->_len.mac = len;
	obj->mac = malloc(obj->_len.mac);
	memcpy(obj->mac, mac, obj->_len.mac);
}
static inline void
rt_link_vfinfo_attrs_set_vlan(struct rt_link_vfinfo_attrs *obj,
			      const void *vlan, size_t len)
{
	free(obj->vlan);
	obj->_len.vlan = len;
	obj->vlan = malloc(obj->_len.vlan);
	memcpy(obj->vlan, vlan, obj->_len.vlan);
}
static inline void
rt_link_vfinfo_attrs_set_tx_rate(struct rt_link_vfinfo_attrs *obj,
				 const void *tx_rate, size_t len)
{
	free(obj->tx_rate);
	obj->_len.tx_rate = len;
	obj->tx_rate = malloc(obj->_len.tx_rate);
	memcpy(obj->tx_rate, tx_rate, obj->_len.tx_rate);
}
static inline void
rt_link_vfinfo_attrs_set_spoofchk(struct rt_link_vfinfo_attrs *obj,
				  const void *spoofchk, size_t len)
{
	free(obj->spoofchk);
	obj->_len.spoofchk = len;
	obj->spoofchk = malloc(obj->_len.spoofchk);
	memcpy(obj->spoofchk, spoofchk, obj->_len.spoofchk);
}
static inline void
rt_link_vfinfo_attrs_set_link_state(struct rt_link_vfinfo_attrs *obj,
				    const void *link_state, size_t len)
{
	free(obj->link_state);
	obj->_len.link_state = len;
	obj->link_state = malloc(obj->_len.link_state);
	memcpy(obj->link_state, link_state, obj->_len.link_state);
}
static inline void
rt_link_vfinfo_attrs_set_rate(struct rt_link_vfinfo_attrs *obj,
			      const void *rate, size_t len)
{
	free(obj->rate);
	obj->_len.rate = len;
	obj->rate = malloc(obj->_len.rate);
	memcpy(obj->rate, rate, obj->_len.rate);
}
static inline void
rt_link_vfinfo_attrs_set_rss_query_en(struct rt_link_vfinfo_attrs *obj,
				      const void *rss_query_en, size_t len)
{
	free(obj->rss_query_en);
	obj->_len.rss_query_en = len;
	obj->rss_query_en = malloc(obj->_len.rss_query_en);
	memcpy(obj->rss_query_en, rss_query_en, obj->_len.rss_query_en);
}
static inline void
rt_link_vfinfo_attrs_set_stats_rx_packets(struct rt_link_vfinfo_attrs *obj,
					  __u64 rx_packets)
{
	obj->_present.stats = 1;
	obj->stats._present.rx_packets = 1;
	obj->stats.rx_packets = rx_packets;
}
static inline void
rt_link_vfinfo_attrs_set_stats_tx_packets(struct rt_link_vfinfo_attrs *obj,
					  __u64 tx_packets)
{
	obj->_present.stats = 1;
	obj->stats._present.tx_packets = 1;
	obj->stats.tx_packets = tx_packets;
}
static inline void
rt_link_vfinfo_attrs_set_stats_rx_bytes(struct rt_link_vfinfo_attrs *obj,
					__u64 rx_bytes)
{
	obj->_present.stats = 1;
	obj->stats._present.rx_bytes = 1;
	obj->stats.rx_bytes = rx_bytes;
}
static inline void
rt_link_vfinfo_attrs_set_stats_tx_bytes(struct rt_link_vfinfo_attrs *obj,
					__u64 tx_bytes)
{
	obj->_present.stats = 1;
	obj->stats._present.tx_bytes = 1;
	obj->stats.tx_bytes = tx_bytes;
}
static inline void
rt_link_vfinfo_attrs_set_stats_broadcast(struct rt_link_vfinfo_attrs *obj,
					 __u64 broadcast)
{
	obj->_present.stats = 1;
	obj->stats._present.broadcast = 1;
	obj->stats.broadcast = broadcast;
}
static inline void
rt_link_vfinfo_attrs_set_stats_multicast(struct rt_link_vfinfo_attrs *obj,
					 __u64 multicast)
{
	obj->_present.stats = 1;
	obj->stats._present.multicast = 1;
	obj->stats.multicast = multicast;
}
static inline void
rt_link_vfinfo_attrs_set_stats_rx_dropped(struct rt_link_vfinfo_attrs *obj,
					  __u64 rx_dropped)
{
	obj->_present.stats = 1;
	obj->stats._present.rx_dropped = 1;
	obj->stats.rx_dropped = rx_dropped;
}
static inline void
rt_link_vfinfo_attrs_set_stats_tx_dropped(struct rt_link_vfinfo_attrs *obj,
					  __u64 tx_dropped)
{
	obj->_present.stats = 1;
	obj->stats._present.tx_dropped = 1;
	obj->stats.tx_dropped = tx_dropped;
}
static inline void
rt_link_vfinfo_attrs_set_trust(struct rt_link_vfinfo_attrs *obj,
			       const void *trust, size_t len)
{
	free(obj->trust);
	obj->_len.trust = len;
	obj->trust = malloc(obj->_len.trust);
	memcpy(obj->trust, trust, obj->_len.trust);
}
static inline void
rt_link_vfinfo_attrs_set_ib_node_guid(struct rt_link_vfinfo_attrs *obj,
				      const void *ib_node_guid, size_t len)
{
	free(obj->ib_node_guid);
	obj->_len.ib_node_guid = len;
	obj->ib_node_guid = malloc(obj->_len.ib_node_guid);
	memcpy(obj->ib_node_guid, ib_node_guid, obj->_len.ib_node_guid);
}
static inline void
rt_link_vfinfo_attrs_set_ib_port_guid(struct rt_link_vfinfo_attrs *obj,
				      const void *ib_port_guid, size_t len)
{
	free(obj->ib_port_guid);
	obj->_len.ib_port_guid = len;
	obj->ib_port_guid = malloc(obj->_len.ib_port_guid);
	memcpy(obj->ib_port_guid, ib_port_guid, obj->_len.ib_port_guid);
}
static inline void
__rt_link_vfinfo_attrs_set_vlan_list_info(struct rt_link_vfinfo_attrs *obj,
					  struct ifla_vf_vlan_info *info,
					  unsigned int n_info)
{
	obj->_present.vlan_list = 1;
	free(obj->vlan_list.info);
	obj->vlan_list.info = info;
	obj->vlan_list._count.info = n_info;
}
static inline void
rt_link_vfinfo_attrs_set_broadcast(struct rt_link_vfinfo_attrs *obj,
				   const void *broadcast, size_t len)
{
	free(obj->broadcast);
	obj->_len.broadcast = len;
	obj->broadcast = malloc(obj->_len.broadcast);
	memcpy(obj->broadcast, broadcast, obj->_len.broadcast);
}

struct rt_link_linkinfo_bond_attrs {
	struct {
		__u32 mode:1;
		__u32 active_slave:1;
		__u32 miimon:1;
		__u32 updelay:1;
		__u32 downdelay:1;
		__u32 use_carrier:1;
		__u32 arp_interval:1;
		__u32 arp_validate:1;
		__u32 arp_all_targets:1;
		__u32 primary:1;
		__u32 primary_reselect:1;
		__u32 fail_over_mac:1;
		__u32 xmit_hash_policy:1;
		__u32 resend_igmp:1;
		__u32 num_peer_notif:1;
		__u32 all_slaves_active:1;
		__u32 min_links:1;
		__u32 lp_interval:1;
		__u32 packets_per_slave:1;
		__u32 ad_lacp_rate:1;
		__u32 ad_select:1;
		__u32 ad_info:1;
		__u32 ad_actor_sys_prio:1;
		__u32 ad_user_port_key:1;
		__u32 tlb_dynamic_lb:1;
		__u32 peer_notif_delay:1;
		__u32 ad_lacp_active:1;
		__u32 missed_max:1;
		__u32 coupled_control:1;
	} _present;
	struct {
		__u32 ad_actor_system;
	} _len;
	struct {
		__u32 arp_ip_target;
		__u32 ns_ip6_target;
	} _count;

	__u8 mode;
	__u32 active_slave;
	__u32 miimon;
	__u32 updelay;
	__u32 downdelay;
	__u8 use_carrier;
	__u32 arp_interval;
	__u32 *arp_ip_target;
	__u32 arp_validate;
	__u32 arp_all_targets;
	__u32 primary;
	__u8 primary_reselect;
	__u8 fail_over_mac;
	__u8 xmit_hash_policy;
	__u32 resend_igmp;
	__u8 num_peer_notif;
	__u8 all_slaves_active;
	__u32 min_links;
	__u32 lp_interval;
	__u32 packets_per_slave;
	__u8 ad_lacp_rate;
	__u8 ad_select;
	struct rt_link_bond_ad_info_attrs ad_info;
	__u16 ad_actor_sys_prio;
	__u16 ad_user_port_key;
	void *ad_actor_system;
	__u8 tlb_dynamic_lb;
	__u32 peer_notif_delay;
	__u8 ad_lacp_active;
	__u8 missed_max;
	unsigned char (*ns_ip6_target)[16];
	unsigned int n_ns_ip6_target;
	__u8 coupled_control;
};

struct rt_link_linkinfo_vlan_attrs {
	struct {
		__u32 id:1;
		__u32 egress_qos:1;
		__u32 ingress_qos:1;
		__u32 protocol:1;
	} _present;
	struct {
		__u32 flags;
	} _len;

	__u16 id;
	struct ifla_vlan_flags *flags;
	struct rt_link_ifla_vlan_qos egress_qos;
	struct rt_link_ifla_vlan_qos ingress_qos;
	int protocol /* big-endian */;
};

struct rt_link_vfinfo_list_attrs {
	struct {
		__u32 info;
	} _count;

	struct rt_link_vfinfo_attrs *info;
};

struct rt_link_linkinfo_data_msg {
	struct {
		__u32 bond:1;
		__u32 bridge:1;
		__u32 erspan:1;
		__u32 gre:1;
		__u32 gretap:1;
		__u32 ip6gre:1;
		__u32 geneve:1;
		__u32 ipip:1;
		__u32 ip6tnl:1;
		__u32 sit:1;
		__u32 tun:1;
		__u32 vlan:1;
		__u32 vrf:1;
		__u32 vti:1;
		__u32 vti6:1;
		__u32 netkit:1;
		__u32 ovpn:1;
	} _present;

	struct rt_link_linkinfo_bond_attrs bond;
	struct rt_link_linkinfo_bridge_attrs bridge;
	struct rt_link_linkinfo_gre_attrs erspan;
	struct rt_link_linkinfo_gre_attrs gre;
	struct rt_link_linkinfo_gre_attrs gretap;
	struct rt_link_linkinfo_gre6_attrs ip6gre;
	struct rt_link_linkinfo_geneve_attrs geneve;
	struct rt_link_linkinfo_iptun_attrs ipip;
	struct rt_link_linkinfo_ip6tnl_attrs ip6tnl;
	struct rt_link_linkinfo_iptun_attrs sit;
	struct rt_link_linkinfo_tun_attrs tun;
	struct rt_link_linkinfo_vlan_attrs vlan;
	struct rt_link_linkinfo_vrf_attrs vrf;
	struct rt_link_linkinfo_vti_attrs vti;
	struct rt_link_linkinfo_vti6_attrs vti6;
	struct rt_link_linkinfo_netkit_attrs netkit;
	struct rt_link_linkinfo_ovpn_attrs ovpn;
};

struct rt_link_linkinfo_attrs {
	struct {
		__u32 data:1;
		__u32 slave_data:1;
	} _present;
	struct {
		__u32 kind;
		__u32 xstats;
		__u32 slave_kind;
	} _len;

	char *kind;
	struct rt_link_linkinfo_data_msg data;
	void *xstats;
	char *slave_kind;
	struct rt_link_linkinfo_member_data_msg slave_data;
};

/* ============== RTM_NEWLINK ============== */
/* RTM_NEWLINK - do */
struct rt_link_newlink_req {
	__u16 _nlmsg_flags;

	struct ifinfomsg _hdr;

	struct {
		__u32 net_ns_pid:1;
		__u32 net_ns_fd:1;
		__u32 target_netnsid:1;
		__u32 link_netnsid:1;
		__u32 linkinfo:1;
		__u32 group:1;
		__u32 num_tx_queues:1;
		__u32 num_rx_queues:1;
		__u32 mtu:1;
		__u32 txqlen:1;
		__u32 operstate:1;
		__u32 linkmode:1;
		__u32 gso_max_size:1;
		__u32 gso_max_segs:1;
		__u32 gro_max_size:1;
		__u32 gso_ipv4_max_size:1;
		__u32 gro_ipv4_max_size:1;
		__u32 af_spec:1;
	} _present;
	struct {
		__u32 ifname;
		__u32 address;
		__u32 broadcast;
	} _len;

	char *ifname;
	__u32 net_ns_pid;
	__u32 net_ns_fd;
	__s32 target_netnsid;
	__s32 link_netnsid;
	struct rt_link_linkinfo_attrs linkinfo;
	__u32 group;
	__u32 num_tx_queues;
	__u32 num_rx_queues;
	void *address;
	void *broadcast;
	__u32 mtu;
	__u32 txqlen;
	__u8 operstate;
	__u8 linkmode;
	__u32 gso_max_size;
	__u32 gso_max_segs;
	__u32 gro_max_size;
	__u32 gso_ipv4_max_size;
	__u32 gro_ipv4_max_size;
	struct rt_link_af_spec_attrs af_spec;
};

static inline struct rt_link_newlink_req *rt_link_newlink_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_link_newlink_req));
}
void rt_link_newlink_req_free(struct rt_link_newlink_req *req);

static inline void
rt_link_newlink_req_set_nlflags(struct rt_link_newlink_req *req,
				__u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_link_newlink_req_set_ifname(struct rt_link_newlink_req *req,
			       const char *ifname)
{
	free(req->ifname);
	req->_len.ifname = strlen(ifname);
	req->ifname = malloc(req->_len.ifname + 1);
	memcpy(req->ifname, ifname, req->_len.ifname);
	req->ifname[req->_len.ifname] = 0;
}
static inline void
rt_link_newlink_req_set_net_ns_pid(struct rt_link_newlink_req *req,
				   __u32 net_ns_pid)
{
	req->_present.net_ns_pid = 1;
	req->net_ns_pid = net_ns_pid;
}
static inline void
rt_link_newlink_req_set_net_ns_fd(struct rt_link_newlink_req *req,
				  __u32 net_ns_fd)
{
	req->_present.net_ns_fd = 1;
	req->net_ns_fd = net_ns_fd;
}
static inline void
rt_link_newlink_req_set_target_netnsid(struct rt_link_newlink_req *req,
				       __s32 target_netnsid)
{
	req->_present.target_netnsid = 1;
	req->target_netnsid = target_netnsid;
}
static inline void
rt_link_newlink_req_set_link_netnsid(struct rt_link_newlink_req *req,
				     __s32 link_netnsid)
{
	req->_present.link_netnsid = 1;
	req->link_netnsid = link_netnsid;
}
static inline void
rt_link_newlink_req_set_linkinfo_kind(struct rt_link_newlink_req *req,
				      const char *kind)
{
	req->_present.linkinfo = 1;
	free(req->linkinfo.kind);
	req->linkinfo._len.kind = strlen(kind);
	req->linkinfo.kind = malloc(req->linkinfo._len.kind + 1);
	memcpy(req->linkinfo.kind, kind, req->linkinfo._len.kind);
	req->linkinfo.kind[req->linkinfo._len.kind] = 0;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_mode(struct rt_link_newlink_req *req,
						__u8 mode)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.mode = 1;
	req->linkinfo.data.bond.mode = mode;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_active_slave(struct rt_link_newlink_req *req,
							__u32 active_slave)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.active_slave = 1;
	req->linkinfo.data.bond.active_slave = active_slave;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_miimon(struct rt_link_newlink_req *req,
						  __u32 miimon)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.miimon = 1;
	req->linkinfo.data.bond.miimon = miimon;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_updelay(struct rt_link_newlink_req *req,
						   __u32 updelay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.updelay = 1;
	req->linkinfo.data.bond.updelay = updelay;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_downdelay(struct rt_link_newlink_req *req,
						     __u32 downdelay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.downdelay = 1;
	req->linkinfo.data.bond.downdelay = downdelay;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_use_carrier(struct rt_link_newlink_req *req,
						       __u8 use_carrier)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.use_carrier = 1;
	req->linkinfo.data.bond.use_carrier = use_carrier;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_arp_interval(struct rt_link_newlink_req *req,
							__u32 arp_interval)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.arp_interval = 1;
	req->linkinfo.data.bond.arp_interval = arp_interval;
}
static inline void
__rt_link_newlink_req_set_linkinfo_data_bond_arp_ip_target(struct rt_link_newlink_req *req,
							   __u32 *arp_ip_target,
							   unsigned int n_arp_ip_target)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	free(req->linkinfo.data.bond.arp_ip_target);
	req->linkinfo.data.bond.arp_ip_target = arp_ip_target;
	req->linkinfo.data.bond._count.arp_ip_target = n_arp_ip_target;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_arp_validate(struct rt_link_newlink_req *req,
							__u32 arp_validate)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.arp_validate = 1;
	req->linkinfo.data.bond.arp_validate = arp_validate;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_arp_all_targets(struct rt_link_newlink_req *req,
							   __u32 arp_all_targets)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.arp_all_targets = 1;
	req->linkinfo.data.bond.arp_all_targets = arp_all_targets;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_primary(struct rt_link_newlink_req *req,
						   __u32 primary)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.primary = 1;
	req->linkinfo.data.bond.primary = primary;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_primary_reselect(struct rt_link_newlink_req *req,
							    __u8 primary_reselect)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.primary_reselect = 1;
	req->linkinfo.data.bond.primary_reselect = primary_reselect;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_fail_over_mac(struct rt_link_newlink_req *req,
							 __u8 fail_over_mac)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.fail_over_mac = 1;
	req->linkinfo.data.bond.fail_over_mac = fail_over_mac;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_xmit_hash_policy(struct rt_link_newlink_req *req,
							    __u8 xmit_hash_policy)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.xmit_hash_policy = 1;
	req->linkinfo.data.bond.xmit_hash_policy = xmit_hash_policy;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_resend_igmp(struct rt_link_newlink_req *req,
						       __u32 resend_igmp)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.resend_igmp = 1;
	req->linkinfo.data.bond.resend_igmp = resend_igmp;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_num_peer_notif(struct rt_link_newlink_req *req,
							  __u8 num_peer_notif)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.num_peer_notif = 1;
	req->linkinfo.data.bond.num_peer_notif = num_peer_notif;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_all_slaves_active(struct rt_link_newlink_req *req,
							     __u8 all_slaves_active)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.all_slaves_active = 1;
	req->linkinfo.data.bond.all_slaves_active = all_slaves_active;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_min_links(struct rt_link_newlink_req *req,
						     __u32 min_links)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.min_links = 1;
	req->linkinfo.data.bond.min_links = min_links;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_lp_interval(struct rt_link_newlink_req *req,
						       __u32 lp_interval)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.lp_interval = 1;
	req->linkinfo.data.bond.lp_interval = lp_interval;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_packets_per_slave(struct rt_link_newlink_req *req,
							     __u32 packets_per_slave)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.packets_per_slave = 1;
	req->linkinfo.data.bond.packets_per_slave = packets_per_slave;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_lacp_rate(struct rt_link_newlink_req *req,
							__u8 ad_lacp_rate)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_lacp_rate = 1;
	req->linkinfo.data.bond.ad_lacp_rate = ad_lacp_rate;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_select(struct rt_link_newlink_req *req,
						     __u8 ad_select)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_select = 1;
	req->linkinfo.data.bond.ad_select = ad_select;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_info_aggregator(struct rt_link_newlink_req *req,
							      __u16 aggregator)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.aggregator = 1;
	req->linkinfo.data.bond.ad_info.aggregator = aggregator;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_info_num_ports(struct rt_link_newlink_req *req,
							     __u16 num_ports)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.num_ports = 1;
	req->linkinfo.data.bond.ad_info.num_ports = num_ports;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_info_actor_key(struct rt_link_newlink_req *req,
							     __u16 actor_key)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.actor_key = 1;
	req->linkinfo.data.bond.ad_info.actor_key = actor_key;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_info_partner_key(struct rt_link_newlink_req *req,
							       __u16 partner_key)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.partner_key = 1;
	req->linkinfo.data.bond.ad_info.partner_key = partner_key;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_info_partner_mac(struct rt_link_newlink_req *req,
							       const void *partner_mac,
							       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	free(req->linkinfo.data.bond.ad_info.partner_mac);
	req->linkinfo.data.bond.ad_info._len.partner_mac = len;
	req->linkinfo.data.bond.ad_info.partner_mac = malloc(req->linkinfo.data.bond.ad_info._len.partner_mac);
	memcpy(req->linkinfo.data.bond.ad_info.partner_mac, partner_mac, req->linkinfo.data.bond.ad_info._len.partner_mac);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_actor_sys_prio(struct rt_link_newlink_req *req,
							     __u16 ad_actor_sys_prio)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_actor_sys_prio = 1;
	req->linkinfo.data.bond.ad_actor_sys_prio = ad_actor_sys_prio;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_user_port_key(struct rt_link_newlink_req *req,
							    __u16 ad_user_port_key)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_user_port_key = 1;
	req->linkinfo.data.bond.ad_user_port_key = ad_user_port_key;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_actor_system(struct rt_link_newlink_req *req,
							   const void *ad_actor_system,
							   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	free(req->linkinfo.data.bond.ad_actor_system);
	req->linkinfo.data.bond._len.ad_actor_system = len;
	req->linkinfo.data.bond.ad_actor_system = malloc(req->linkinfo.data.bond._len.ad_actor_system);
	memcpy(req->linkinfo.data.bond.ad_actor_system, ad_actor_system, req->linkinfo.data.bond._len.ad_actor_system);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_tlb_dynamic_lb(struct rt_link_newlink_req *req,
							  __u8 tlb_dynamic_lb)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.tlb_dynamic_lb = 1;
	req->linkinfo.data.bond.tlb_dynamic_lb = tlb_dynamic_lb;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_peer_notif_delay(struct rt_link_newlink_req *req,
							    __u32 peer_notif_delay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.peer_notif_delay = 1;
	req->linkinfo.data.bond.peer_notif_delay = peer_notif_delay;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_ad_lacp_active(struct rt_link_newlink_req *req,
							  __u8 ad_lacp_active)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_lacp_active = 1;
	req->linkinfo.data.bond.ad_lacp_active = ad_lacp_active;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_missed_max(struct rt_link_newlink_req *req,
						      __u8 missed_max)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.missed_max = 1;
	req->linkinfo.data.bond.missed_max = missed_max;
}
static inline void
__rt_link_newlink_req_set_linkinfo_data_bond_ns_ip6_target(struct rt_link_newlink_req *req,
							   unsigned char (*ns_ip6_target)[16],
							   unsigned int n_ns_ip6_target)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	free(req->linkinfo.data.bond.ns_ip6_target);
	req->linkinfo.data.bond.ns_ip6_target = ns_ip6_target;
	req->linkinfo.data.bond._count.ns_ip6_target = n_ns_ip6_target;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bond_coupled_control(struct rt_link_newlink_req *req,
							   __u8 coupled_control)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.coupled_control = 1;
	req->linkinfo.data.bond.coupled_control = coupled_control;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_forward_delay(struct rt_link_newlink_req *req,
							   __u32 forward_delay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.forward_delay = 1;
	req->linkinfo.data.bridge.forward_delay = forward_delay;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_hello_time(struct rt_link_newlink_req *req,
							__u32 hello_time)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.hello_time = 1;
	req->linkinfo.data.bridge.hello_time = hello_time;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_max_age(struct rt_link_newlink_req *req,
						     __u32 max_age)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.max_age = 1;
	req->linkinfo.data.bridge.max_age = max_age;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_ageing_time(struct rt_link_newlink_req *req,
							 __u32 ageing_time)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.ageing_time = 1;
	req->linkinfo.data.bridge.ageing_time = ageing_time;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_stp_state(struct rt_link_newlink_req *req,
						       __u32 stp_state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.stp_state = 1;
	req->linkinfo.data.bridge.stp_state = stp_state;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_priority(struct rt_link_newlink_req *req,
						      __u16 priority)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.priority = 1;
	req->linkinfo.data.bridge.priority = priority;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_vlan_filtering(struct rt_link_newlink_req *req,
							    __u8 vlan_filtering)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_filtering = 1;
	req->linkinfo.data.bridge.vlan_filtering = vlan_filtering;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_vlan_protocol(struct rt_link_newlink_req *req,
							   __u16 vlan_protocol)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_protocol = 1;
	req->linkinfo.data.bridge.vlan_protocol = vlan_protocol;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_group_fwd_mask(struct rt_link_newlink_req *req,
							    __u16 group_fwd_mask)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.group_fwd_mask = 1;
	req->linkinfo.data.bridge.group_fwd_mask = group_fwd_mask;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_root_id(struct rt_link_newlink_req *req,
						     const void *root_id,
						     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.root_id);
	req->linkinfo.data.bridge._len.root_id = len;
	req->linkinfo.data.bridge.root_id = malloc(req->linkinfo.data.bridge._len.root_id);
	memcpy(req->linkinfo.data.bridge.root_id, root_id, req->linkinfo.data.bridge._len.root_id);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_bridge_id(struct rt_link_newlink_req *req,
						       const void *bridge_id,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.bridge_id);
	req->linkinfo.data.bridge._len.bridge_id = len;
	req->linkinfo.data.bridge.bridge_id = malloc(req->linkinfo.data.bridge._len.bridge_id);
	memcpy(req->linkinfo.data.bridge.bridge_id, bridge_id, req->linkinfo.data.bridge._len.bridge_id);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_root_port(struct rt_link_newlink_req *req,
						       __u16 root_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.root_port = 1;
	req->linkinfo.data.bridge.root_port = root_port;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_root_path_cost(struct rt_link_newlink_req *req,
							    __u32 root_path_cost)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.root_path_cost = 1;
	req->linkinfo.data.bridge.root_path_cost = root_path_cost;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_topology_change(struct rt_link_newlink_req *req,
							     __u8 topology_change)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.topology_change = 1;
	req->linkinfo.data.bridge.topology_change = topology_change;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_topology_change_detected(struct rt_link_newlink_req *req,
								      __u8 topology_change_detected)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.topology_change_detected = 1;
	req->linkinfo.data.bridge.topology_change_detected = topology_change_detected;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_hello_timer(struct rt_link_newlink_req *req,
							 __u64 hello_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.hello_timer = 1;
	req->linkinfo.data.bridge.hello_timer = hello_timer;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_tcn_timer(struct rt_link_newlink_req *req,
						       __u64 tcn_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.tcn_timer = 1;
	req->linkinfo.data.bridge.tcn_timer = tcn_timer;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_topology_change_timer(struct rt_link_newlink_req *req,
								   __u64 topology_change_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.topology_change_timer = 1;
	req->linkinfo.data.bridge.topology_change_timer = topology_change_timer;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_gc_timer(struct rt_link_newlink_req *req,
						      __u64 gc_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.gc_timer = 1;
	req->linkinfo.data.bridge.gc_timer = gc_timer;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_group_addr(struct rt_link_newlink_req *req,
							const void *group_addr,
							size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.group_addr);
	req->linkinfo.data.bridge._len.group_addr = len;
	req->linkinfo.data.bridge.group_addr = malloc(req->linkinfo.data.bridge._len.group_addr);
	memcpy(req->linkinfo.data.bridge.group_addr, group_addr, req->linkinfo.data.bridge._len.group_addr);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_fdb_flush(struct rt_link_newlink_req *req,
						       const void *fdb_flush,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.fdb_flush);
	req->linkinfo.data.bridge._len.fdb_flush = len;
	req->linkinfo.data.bridge.fdb_flush = malloc(req->linkinfo.data.bridge._len.fdb_flush);
	memcpy(req->linkinfo.data.bridge.fdb_flush, fdb_flush, req->linkinfo.data.bridge._len.fdb_flush);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_router(struct rt_link_newlink_req *req,
							  __u8 mcast_router)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_router = 1;
	req->linkinfo.data.bridge.mcast_router = mcast_router;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_snooping(struct rt_link_newlink_req *req,
							    __u8 mcast_snooping)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_snooping = 1;
	req->linkinfo.data.bridge.mcast_snooping = mcast_snooping;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_query_use_ifaddr(struct rt_link_newlink_req *req,
								    __u8 mcast_query_use_ifaddr)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_query_use_ifaddr = 1;
	req->linkinfo.data.bridge.mcast_query_use_ifaddr = mcast_query_use_ifaddr;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_querier(struct rt_link_newlink_req *req,
							   __u8 mcast_querier)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_querier = 1;
	req->linkinfo.data.bridge.mcast_querier = mcast_querier;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_hash_elasticity(struct rt_link_newlink_req *req,
								   __u32 mcast_hash_elasticity)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_hash_elasticity = 1;
	req->linkinfo.data.bridge.mcast_hash_elasticity = mcast_hash_elasticity;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_hash_max(struct rt_link_newlink_req *req,
							    __u32 mcast_hash_max)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_hash_max = 1;
	req->linkinfo.data.bridge.mcast_hash_max = mcast_hash_max;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_last_member_cnt(struct rt_link_newlink_req *req,
								   __u32 mcast_last_member_cnt)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_last_member_cnt = 1;
	req->linkinfo.data.bridge.mcast_last_member_cnt = mcast_last_member_cnt;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_startup_query_cnt(struct rt_link_newlink_req *req,
								     __u32 mcast_startup_query_cnt)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_startup_query_cnt = 1;
	req->linkinfo.data.bridge.mcast_startup_query_cnt = mcast_startup_query_cnt;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_last_member_intvl(struct rt_link_newlink_req *req,
								     __u64 mcast_last_member_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_last_member_intvl = 1;
	req->linkinfo.data.bridge.mcast_last_member_intvl = mcast_last_member_intvl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_membership_intvl(struct rt_link_newlink_req *req,
								    __u64 mcast_membership_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_membership_intvl = 1;
	req->linkinfo.data.bridge.mcast_membership_intvl = mcast_membership_intvl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_querier_intvl(struct rt_link_newlink_req *req,
								 __u64 mcast_querier_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_querier_intvl = 1;
	req->linkinfo.data.bridge.mcast_querier_intvl = mcast_querier_intvl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_query_intvl(struct rt_link_newlink_req *req,
							       __u64 mcast_query_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_query_intvl = 1;
	req->linkinfo.data.bridge.mcast_query_intvl = mcast_query_intvl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_query_response_intvl(struct rt_link_newlink_req *req,
									__u64 mcast_query_response_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_query_response_intvl = 1;
	req->linkinfo.data.bridge.mcast_query_response_intvl = mcast_query_response_intvl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_startup_query_intvl(struct rt_link_newlink_req *req,
								       __u64 mcast_startup_query_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_startup_query_intvl = 1;
	req->linkinfo.data.bridge.mcast_startup_query_intvl = mcast_startup_query_intvl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_nf_call_iptables(struct rt_link_newlink_req *req,
							      __u8 nf_call_iptables)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.nf_call_iptables = 1;
	req->linkinfo.data.bridge.nf_call_iptables = nf_call_iptables;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_nf_call_ip6tables(struct rt_link_newlink_req *req,
							       __u8 nf_call_ip6tables)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.nf_call_ip6tables = 1;
	req->linkinfo.data.bridge.nf_call_ip6tables = nf_call_ip6tables;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_nf_call_arptables(struct rt_link_newlink_req *req,
							       __u8 nf_call_arptables)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.nf_call_arptables = 1;
	req->linkinfo.data.bridge.nf_call_arptables = nf_call_arptables;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_vlan_default_pvid(struct rt_link_newlink_req *req,
							       __u16 vlan_default_pvid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_default_pvid = 1;
	req->linkinfo.data.bridge.vlan_default_pvid = vlan_default_pvid;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_vlan_stats_enabled(struct rt_link_newlink_req *req,
								__u8 vlan_stats_enabled)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_stats_enabled = 1;
	req->linkinfo.data.bridge.vlan_stats_enabled = vlan_stats_enabled;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_stats_enabled(struct rt_link_newlink_req *req,
								 __u8 mcast_stats_enabled)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_stats_enabled = 1;
	req->linkinfo.data.bridge.mcast_stats_enabled = mcast_stats_enabled;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_igmp_version(struct rt_link_newlink_req *req,
								__u8 mcast_igmp_version)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_igmp_version = 1;
	req->linkinfo.data.bridge.mcast_igmp_version = mcast_igmp_version;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_mld_version(struct rt_link_newlink_req *req,
							       __u8 mcast_mld_version)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_mld_version = 1;
	req->linkinfo.data.bridge.mcast_mld_version = mcast_mld_version;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_vlan_stats_per_port(struct rt_link_newlink_req *req,
								 __u8 vlan_stats_per_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_stats_per_port = 1;
	req->linkinfo.data.bridge.vlan_stats_per_port = vlan_stats_per_port;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_multi_boolopt(struct rt_link_newlink_req *req,
							   const void *multi_boolopt,
							   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.multi_boolopt);
	req->linkinfo.data.bridge._len.multi_boolopt = len;
	req->linkinfo.data.bridge.multi_boolopt = malloc(req->linkinfo.data.bridge._len.multi_boolopt);
	memcpy(req->linkinfo.data.bridge.multi_boolopt, multi_boolopt, req->linkinfo.data.bridge._len.multi_boolopt);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_mcast_querier_state(struct rt_link_newlink_req *req,
								 const void *mcast_querier_state,
								 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.mcast_querier_state);
	req->linkinfo.data.bridge._len.mcast_querier_state = len;
	req->linkinfo.data.bridge.mcast_querier_state = malloc(req->linkinfo.data.bridge._len.mcast_querier_state);
	memcpy(req->linkinfo.data.bridge.mcast_querier_state, mcast_querier_state, req->linkinfo.data.bridge._len.mcast_querier_state);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_fdb_n_learned(struct rt_link_newlink_req *req,
							   __u32 fdb_n_learned)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.fdb_n_learned = 1;
	req->linkinfo.data.bridge.fdb_n_learned = fdb_n_learned;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_bridge_fdb_max_learned(struct rt_link_newlink_req *req,
							     __u32 fdb_max_learned)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.fdb_max_learned = 1;
	req->linkinfo.data.bridge.fdb_max_learned = fdb_max_learned;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_link(struct rt_link_newlink_req *req,
						  __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.link = 1;
	req->linkinfo.data.erspan.link = link;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_iflags(struct rt_link_newlink_req *req,
						    __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.iflags = 1;
	req->linkinfo.data.erspan.iflags = iflags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_oflags(struct rt_link_newlink_req *req,
						    __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.oflags = 1;
	req->linkinfo.data.erspan.oflags = oflags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_ikey(struct rt_link_newlink_req *req,
						  __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.ikey = 1;
	req->linkinfo.data.erspan.ikey = ikey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_okey(struct rt_link_newlink_req *req,
						  __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.okey = 1;
	req->linkinfo.data.erspan.okey = okey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_local(struct rt_link_newlink_req *req,
						   const void *local,
						   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	free(req->linkinfo.data.erspan.local);
	req->linkinfo.data.erspan._len.local = len;
	req->linkinfo.data.erspan.local = malloc(req->linkinfo.data.erspan._len.local);
	memcpy(req->linkinfo.data.erspan.local, local, req->linkinfo.data.erspan._len.local);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_remote(struct rt_link_newlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	free(req->linkinfo.data.erspan.remote);
	req->linkinfo.data.erspan._len.remote = len;
	req->linkinfo.data.erspan.remote = malloc(req->linkinfo.data.erspan._len.remote);
	memcpy(req->linkinfo.data.erspan.remote, remote, req->linkinfo.data.erspan._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_ttl(struct rt_link_newlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.ttl = 1;
	req->linkinfo.data.erspan.ttl = ttl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_tos(struct rt_link_newlink_req *req,
						 __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.tos = 1;
	req->linkinfo.data.erspan.tos = tos;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_pmtudisc(struct rt_link_newlink_req *req,
						      __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.pmtudisc = 1;
	req->linkinfo.data.erspan.pmtudisc = pmtudisc;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_encap_limit(struct rt_link_newlink_req *req,
							 __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_limit = 1;
	req->linkinfo.data.erspan.encap_limit = encap_limit;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_flowinfo(struct rt_link_newlink_req *req,
						      __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.flowinfo = 1;
	req->linkinfo.data.erspan.flowinfo = flowinfo;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_flags(struct rt_link_newlink_req *req,
						   __u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.flags = 1;
	req->linkinfo.data.erspan.flags = flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_encap_type(struct rt_link_newlink_req *req,
							__u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_type = 1;
	req->linkinfo.data.erspan.encap_type = encap_type;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_encap_flags(struct rt_link_newlink_req *req,
							 __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_flags = 1;
	req->linkinfo.data.erspan.encap_flags = encap_flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_encap_sport(struct rt_link_newlink_req *req,
							 __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_sport = 1;
	req->linkinfo.data.erspan.encap_sport = encap_sport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_encap_dport(struct rt_link_newlink_req *req,
							 __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_dport = 1;
	req->linkinfo.data.erspan.encap_dport = encap_dport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_collect_metadata(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.collect_metadata = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_ignore_df(struct rt_link_newlink_req *req,
						       __u8 ignore_df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.ignore_df = 1;
	req->linkinfo.data.erspan.ignore_df = ignore_df;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_fwmark(struct rt_link_newlink_req *req,
						    __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.fwmark = 1;
	req->linkinfo.data.erspan.fwmark = fwmark;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_erspan_index(struct rt_link_newlink_req *req,
							  __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_index = 1;
	req->linkinfo.data.erspan.erspan_index = erspan_index;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_erspan_ver(struct rt_link_newlink_req *req,
							__u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_ver = 1;
	req->linkinfo.data.erspan.erspan_ver = erspan_ver;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_erspan_dir(struct rt_link_newlink_req *req,
							__u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_dir = 1;
	req->linkinfo.data.erspan.erspan_dir = erspan_dir;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_erspan_erspan_hwid(struct rt_link_newlink_req *req,
							 __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_hwid = 1;
	req->linkinfo.data.erspan.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_link(struct rt_link_newlink_req *req,
					       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.link = 1;
	req->linkinfo.data.gre.link = link;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_iflags(struct rt_link_newlink_req *req,
						 __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.iflags = 1;
	req->linkinfo.data.gre.iflags = iflags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_oflags(struct rt_link_newlink_req *req,
						 __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.oflags = 1;
	req->linkinfo.data.gre.oflags = oflags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_ikey(struct rt_link_newlink_req *req,
					       __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.ikey = 1;
	req->linkinfo.data.gre.ikey = ikey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_okey(struct rt_link_newlink_req *req,
					       __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.okey = 1;
	req->linkinfo.data.gre.okey = okey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_local(struct rt_link_newlink_req *req,
						const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	free(req->linkinfo.data.gre.local);
	req->linkinfo.data.gre._len.local = len;
	req->linkinfo.data.gre.local = malloc(req->linkinfo.data.gre._len.local);
	memcpy(req->linkinfo.data.gre.local, local, req->linkinfo.data.gre._len.local);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_remote(struct rt_link_newlink_req *req,
						 const void *remote,
						 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	free(req->linkinfo.data.gre.remote);
	req->linkinfo.data.gre._len.remote = len;
	req->linkinfo.data.gre.remote = malloc(req->linkinfo.data.gre._len.remote);
	memcpy(req->linkinfo.data.gre.remote, remote, req->linkinfo.data.gre._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_ttl(struct rt_link_newlink_req *req,
					      __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.ttl = 1;
	req->linkinfo.data.gre.ttl = ttl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_tos(struct rt_link_newlink_req *req,
					      __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.tos = 1;
	req->linkinfo.data.gre.tos = tos;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_pmtudisc(struct rt_link_newlink_req *req,
						   __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.pmtudisc = 1;
	req->linkinfo.data.gre.pmtudisc = pmtudisc;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_encap_limit(struct rt_link_newlink_req *req,
						      __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_limit = 1;
	req->linkinfo.data.gre.encap_limit = encap_limit;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_flowinfo(struct rt_link_newlink_req *req,
						   __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.flowinfo = 1;
	req->linkinfo.data.gre.flowinfo = flowinfo;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_flags(struct rt_link_newlink_req *req,
						__u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.flags = 1;
	req->linkinfo.data.gre.flags = flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_encap_type(struct rt_link_newlink_req *req,
						     __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_type = 1;
	req->linkinfo.data.gre.encap_type = encap_type;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_encap_flags(struct rt_link_newlink_req *req,
						      __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_flags = 1;
	req->linkinfo.data.gre.encap_flags = encap_flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_encap_sport(struct rt_link_newlink_req *req,
						      __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_sport = 1;
	req->linkinfo.data.gre.encap_sport = encap_sport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_encap_dport(struct rt_link_newlink_req *req,
						      __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_dport = 1;
	req->linkinfo.data.gre.encap_dport = encap_dport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_collect_metadata(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.collect_metadata = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_ignore_df(struct rt_link_newlink_req *req,
						    __u8 ignore_df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.ignore_df = 1;
	req->linkinfo.data.gre.ignore_df = ignore_df;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_fwmark(struct rt_link_newlink_req *req,
						 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.fwmark = 1;
	req->linkinfo.data.gre.fwmark = fwmark;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_erspan_index(struct rt_link_newlink_req *req,
						       __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_index = 1;
	req->linkinfo.data.gre.erspan_index = erspan_index;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_erspan_ver(struct rt_link_newlink_req *req,
						     __u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_ver = 1;
	req->linkinfo.data.gre.erspan_ver = erspan_ver;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_erspan_dir(struct rt_link_newlink_req *req,
						     __u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_dir = 1;
	req->linkinfo.data.gre.erspan_dir = erspan_dir;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gre_erspan_hwid(struct rt_link_newlink_req *req,
						      __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_hwid = 1;
	req->linkinfo.data.gre.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_link(struct rt_link_newlink_req *req,
						  __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.link = 1;
	req->linkinfo.data.gretap.link = link;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_iflags(struct rt_link_newlink_req *req,
						    __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.iflags = 1;
	req->linkinfo.data.gretap.iflags = iflags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_oflags(struct rt_link_newlink_req *req,
						    __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.oflags = 1;
	req->linkinfo.data.gretap.oflags = oflags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_ikey(struct rt_link_newlink_req *req,
						  __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.ikey = 1;
	req->linkinfo.data.gretap.ikey = ikey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_okey(struct rt_link_newlink_req *req,
						  __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.okey = 1;
	req->linkinfo.data.gretap.okey = okey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_local(struct rt_link_newlink_req *req,
						   const void *local,
						   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	free(req->linkinfo.data.gretap.local);
	req->linkinfo.data.gretap._len.local = len;
	req->linkinfo.data.gretap.local = malloc(req->linkinfo.data.gretap._len.local);
	memcpy(req->linkinfo.data.gretap.local, local, req->linkinfo.data.gretap._len.local);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_remote(struct rt_link_newlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	free(req->linkinfo.data.gretap.remote);
	req->linkinfo.data.gretap._len.remote = len;
	req->linkinfo.data.gretap.remote = malloc(req->linkinfo.data.gretap._len.remote);
	memcpy(req->linkinfo.data.gretap.remote, remote, req->linkinfo.data.gretap._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_ttl(struct rt_link_newlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.ttl = 1;
	req->linkinfo.data.gretap.ttl = ttl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_tos(struct rt_link_newlink_req *req,
						 __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.tos = 1;
	req->linkinfo.data.gretap.tos = tos;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_pmtudisc(struct rt_link_newlink_req *req,
						      __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.pmtudisc = 1;
	req->linkinfo.data.gretap.pmtudisc = pmtudisc;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_encap_limit(struct rt_link_newlink_req *req,
							 __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_limit = 1;
	req->linkinfo.data.gretap.encap_limit = encap_limit;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_flowinfo(struct rt_link_newlink_req *req,
						      __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.flowinfo = 1;
	req->linkinfo.data.gretap.flowinfo = flowinfo;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_flags(struct rt_link_newlink_req *req,
						   __u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.flags = 1;
	req->linkinfo.data.gretap.flags = flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_encap_type(struct rt_link_newlink_req *req,
							__u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_type = 1;
	req->linkinfo.data.gretap.encap_type = encap_type;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_encap_flags(struct rt_link_newlink_req *req,
							 __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_flags = 1;
	req->linkinfo.data.gretap.encap_flags = encap_flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_encap_sport(struct rt_link_newlink_req *req,
							 __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_sport = 1;
	req->linkinfo.data.gretap.encap_sport = encap_sport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_encap_dport(struct rt_link_newlink_req *req,
							 __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_dport = 1;
	req->linkinfo.data.gretap.encap_dport = encap_dport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_collect_metadata(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.collect_metadata = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_ignore_df(struct rt_link_newlink_req *req,
						       __u8 ignore_df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.ignore_df = 1;
	req->linkinfo.data.gretap.ignore_df = ignore_df;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_fwmark(struct rt_link_newlink_req *req,
						    __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.fwmark = 1;
	req->linkinfo.data.gretap.fwmark = fwmark;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_erspan_index(struct rt_link_newlink_req *req,
							  __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_index = 1;
	req->linkinfo.data.gretap.erspan_index = erspan_index;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_erspan_ver(struct rt_link_newlink_req *req,
							__u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_ver = 1;
	req->linkinfo.data.gretap.erspan_ver = erspan_ver;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_erspan_dir(struct rt_link_newlink_req *req,
							__u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_dir = 1;
	req->linkinfo.data.gretap.erspan_dir = erspan_dir;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_gretap_erspan_hwid(struct rt_link_newlink_req *req,
							 __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_hwid = 1;
	req->linkinfo.data.gretap.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_link(struct rt_link_newlink_req *req,
						  __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.link = 1;
	req->linkinfo.data.ip6gre.link = link;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_iflags(struct rt_link_newlink_req *req,
						    __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.iflags = 1;
	req->linkinfo.data.ip6gre.iflags = iflags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_oflags(struct rt_link_newlink_req *req,
						    __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.oflags = 1;
	req->linkinfo.data.ip6gre.oflags = oflags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_ikey(struct rt_link_newlink_req *req,
						  __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.ikey = 1;
	req->linkinfo.data.ip6gre.ikey = ikey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_okey(struct rt_link_newlink_req *req,
						  __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.okey = 1;
	req->linkinfo.data.ip6gre.okey = okey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_local(struct rt_link_newlink_req *req,
						   const void *local,
						   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	free(req->linkinfo.data.ip6gre.local);
	req->linkinfo.data.ip6gre._len.local = len;
	req->linkinfo.data.ip6gre.local = malloc(req->linkinfo.data.ip6gre._len.local);
	memcpy(req->linkinfo.data.ip6gre.local, local, req->linkinfo.data.ip6gre._len.local);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_remote(struct rt_link_newlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	free(req->linkinfo.data.ip6gre.remote);
	req->linkinfo.data.ip6gre._len.remote = len;
	req->linkinfo.data.ip6gre.remote = malloc(req->linkinfo.data.ip6gre._len.remote);
	memcpy(req->linkinfo.data.ip6gre.remote, remote, req->linkinfo.data.ip6gre._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_ttl(struct rt_link_newlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.ttl = 1;
	req->linkinfo.data.ip6gre.ttl = ttl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_encap_limit(struct rt_link_newlink_req *req,
							 __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_limit = 1;
	req->linkinfo.data.ip6gre.encap_limit = encap_limit;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_flowinfo(struct rt_link_newlink_req *req,
						      __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.flowinfo = 1;
	req->linkinfo.data.ip6gre.flowinfo = flowinfo;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_flags(struct rt_link_newlink_req *req,
						   __u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.flags = 1;
	req->linkinfo.data.ip6gre.flags = flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_encap_type(struct rt_link_newlink_req *req,
							__u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_type = 1;
	req->linkinfo.data.ip6gre.encap_type = encap_type;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_encap_flags(struct rt_link_newlink_req *req,
							 __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_flags = 1;
	req->linkinfo.data.ip6gre.encap_flags = encap_flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_encap_sport(struct rt_link_newlink_req *req,
							 __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_sport = 1;
	req->linkinfo.data.ip6gre.encap_sport = encap_sport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_encap_dport(struct rt_link_newlink_req *req,
							 __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_dport = 1;
	req->linkinfo.data.ip6gre.encap_dport = encap_dport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_collect_metadata(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.collect_metadata = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_fwmark(struct rt_link_newlink_req *req,
						    __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.fwmark = 1;
	req->linkinfo.data.ip6gre.fwmark = fwmark;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_erspan_index(struct rt_link_newlink_req *req,
							  __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_index = 1;
	req->linkinfo.data.ip6gre.erspan_index = erspan_index;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_erspan_ver(struct rt_link_newlink_req *req,
							__u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_ver = 1;
	req->linkinfo.data.ip6gre.erspan_ver = erspan_ver;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_erspan_dir(struct rt_link_newlink_req *req,
							__u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_dir = 1;
	req->linkinfo.data.ip6gre.erspan_dir = erspan_dir;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6gre_erspan_hwid(struct rt_link_newlink_req *req,
							 __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_hwid = 1;
	req->linkinfo.data.ip6gre.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_id(struct rt_link_newlink_req *req,
						__u32 id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.id = 1;
	req->linkinfo.data.geneve.id = id;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_remote(struct rt_link_newlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	free(req->linkinfo.data.geneve.remote);
	req->linkinfo.data.geneve._len.remote = len;
	req->linkinfo.data.geneve.remote = malloc(req->linkinfo.data.geneve._len.remote);
	memcpy(req->linkinfo.data.geneve.remote, remote, req->linkinfo.data.geneve._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_ttl(struct rt_link_newlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.ttl = 1;
	req->linkinfo.data.geneve.ttl = ttl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_tos(struct rt_link_newlink_req *req,
						 __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.tos = 1;
	req->linkinfo.data.geneve.tos = tos;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_port(struct rt_link_newlink_req *req,
						  __u16 port /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.port = 1;
	req->linkinfo.data.geneve.port = port;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_collect_metadata(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.collect_metadata = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_remote6(struct rt_link_newlink_req *req,
						     const void *remote6,
						     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	free(req->linkinfo.data.geneve.remote6);
	req->linkinfo.data.geneve._len.remote6 = len;
	req->linkinfo.data.geneve.remote6 = malloc(req->linkinfo.data.geneve._len.remote6);
	memcpy(req->linkinfo.data.geneve.remote6, remote6, req->linkinfo.data.geneve._len.remote6);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_udp_csum(struct rt_link_newlink_req *req,
						      __u8 udp_csum)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.udp_csum = 1;
	req->linkinfo.data.geneve.udp_csum = udp_csum;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_udp_zero_csum6_tx(struct rt_link_newlink_req *req,
							       __u8 udp_zero_csum6_tx)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.udp_zero_csum6_tx = 1;
	req->linkinfo.data.geneve.udp_zero_csum6_tx = udp_zero_csum6_tx;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_udp_zero_csum6_rx(struct rt_link_newlink_req *req,
							       __u8 udp_zero_csum6_rx)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.udp_zero_csum6_rx = 1;
	req->linkinfo.data.geneve.udp_zero_csum6_rx = udp_zero_csum6_rx;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_label(struct rt_link_newlink_req *req,
						   __u32 label /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.label = 1;
	req->linkinfo.data.geneve.label = label;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_ttl_inherit(struct rt_link_newlink_req *req,
							 __u8 ttl_inherit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.ttl_inherit = 1;
	req->linkinfo.data.geneve.ttl_inherit = ttl_inherit;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_df(struct rt_link_newlink_req *req,
						__u8 df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.df = 1;
	req->linkinfo.data.geneve.df = df;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_inner_proto_inherit(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.inner_proto_inherit = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_geneve_port_range(struct rt_link_newlink_req *req,
							const void *port_range,
							size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	free(req->linkinfo.data.geneve.port_range);
	req->linkinfo.data.geneve._len.port_range = len;
	req->linkinfo.data.geneve.port_range = malloc(req->linkinfo.data.geneve._len.port_range);
	memcpy(req->linkinfo.data.geneve.port_range, port_range, req->linkinfo.data.geneve._len.port_range);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_link(struct rt_link_newlink_req *req,
						__u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.link = 1;
	req->linkinfo.data.ipip.link = link;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_local(struct rt_link_newlink_req *req,
						 const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip.local);
	req->linkinfo.data.ipip._len.local = len;
	req->linkinfo.data.ipip.local = malloc(req->linkinfo.data.ipip._len.local);
	memcpy(req->linkinfo.data.ipip.local, local, req->linkinfo.data.ipip._len.local);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_remote(struct rt_link_newlink_req *req,
						  const void *remote,
						  size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip.remote);
	req->linkinfo.data.ipip._len.remote = len;
	req->linkinfo.data.ipip.remote = malloc(req->linkinfo.data.ipip._len.remote);
	memcpy(req->linkinfo.data.ipip.remote, remote, req->linkinfo.data.ipip._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_ttl(struct rt_link_newlink_req *req,
					       __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.ttl = 1;
	req->linkinfo.data.ipip.ttl = ttl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_tos(struct rt_link_newlink_req *req,
					       __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.tos = 1;
	req->linkinfo.data.ipip.tos = tos;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_encap_limit(struct rt_link_newlink_req *req,
						       __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_limit = 1;
	req->linkinfo.data.ipip.encap_limit = encap_limit;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_flowinfo(struct rt_link_newlink_req *req,
						    __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.flowinfo = 1;
	req->linkinfo.data.ipip.flowinfo = flowinfo;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_flags(struct rt_link_newlink_req *req,
						 __u16 flags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.flags = 1;
	req->linkinfo.data.ipip.flags = flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_proto(struct rt_link_newlink_req *req,
						 __u8 proto)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.proto = 1;
	req->linkinfo.data.ipip.proto = proto;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_pmtudisc(struct rt_link_newlink_req *req,
						    __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.pmtudisc = 1;
	req->linkinfo.data.ipip.pmtudisc = pmtudisc;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip__6rd_prefix(struct rt_link_newlink_req *req,
						       const void *_6rd_prefix,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip._6rd_prefix);
	req->linkinfo.data.ipip._len._6rd_prefix = len;
	req->linkinfo.data.ipip._6rd_prefix = malloc(req->linkinfo.data.ipip._len._6rd_prefix);
	memcpy(req->linkinfo.data.ipip._6rd_prefix, _6rd_prefix, req->linkinfo.data.ipip._len._6rd_prefix);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip__6rd_relay_prefix(struct rt_link_newlink_req *req,
							     const void *_6rd_relay_prefix,
							     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip._6rd_relay_prefix);
	req->linkinfo.data.ipip._len._6rd_relay_prefix = len;
	req->linkinfo.data.ipip._6rd_relay_prefix = malloc(req->linkinfo.data.ipip._len._6rd_relay_prefix);
	memcpy(req->linkinfo.data.ipip._6rd_relay_prefix, _6rd_relay_prefix, req->linkinfo.data.ipip._len._6rd_relay_prefix);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip__6rd_prefixlen(struct rt_link_newlink_req *req,
							  __u16 _6rd_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present._6rd_prefixlen = 1;
	req->linkinfo.data.ipip._6rd_prefixlen = _6rd_prefixlen;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip__6rd_relay_prefixlen(struct rt_link_newlink_req *req,
								__u16 _6rd_relay_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present._6rd_relay_prefixlen = 1;
	req->linkinfo.data.ipip._6rd_relay_prefixlen = _6rd_relay_prefixlen;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_encap_type(struct rt_link_newlink_req *req,
						      __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_type = 1;
	req->linkinfo.data.ipip.encap_type = encap_type;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_encap_flags(struct rt_link_newlink_req *req,
						       __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_flags = 1;
	req->linkinfo.data.ipip.encap_flags = encap_flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_encap_sport(struct rt_link_newlink_req *req,
						       __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_sport = 1;
	req->linkinfo.data.ipip.encap_sport = encap_sport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_encap_dport(struct rt_link_newlink_req *req,
						       __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_dport = 1;
	req->linkinfo.data.ipip.encap_dport = encap_dport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_collect_metadata(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.collect_metadata = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ipip_fwmark(struct rt_link_newlink_req *req,
						  __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.fwmark = 1;
	req->linkinfo.data.ipip.fwmark = fwmark;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_link(struct rt_link_newlink_req *req,
						  __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.link = 1;
	req->linkinfo.data.ip6tnl.link = link;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_local(struct rt_link_newlink_req *req,
						   const void *local,
						   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	free(req->linkinfo.data.ip6tnl.local);
	req->linkinfo.data.ip6tnl._len.local = len;
	req->linkinfo.data.ip6tnl.local = malloc(req->linkinfo.data.ip6tnl._len.local);
	memcpy(req->linkinfo.data.ip6tnl.local, local, req->linkinfo.data.ip6tnl._len.local);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_remote(struct rt_link_newlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	free(req->linkinfo.data.ip6tnl.remote);
	req->linkinfo.data.ip6tnl._len.remote = len;
	req->linkinfo.data.ip6tnl.remote = malloc(req->linkinfo.data.ip6tnl._len.remote);
	memcpy(req->linkinfo.data.ip6tnl.remote, remote, req->linkinfo.data.ip6tnl._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_ttl(struct rt_link_newlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.ttl = 1;
	req->linkinfo.data.ip6tnl.ttl = ttl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_encap_limit(struct rt_link_newlink_req *req,
							 __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_limit = 1;
	req->linkinfo.data.ip6tnl.encap_limit = encap_limit;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_flowinfo(struct rt_link_newlink_req *req,
						      __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.flowinfo = 1;
	req->linkinfo.data.ip6tnl.flowinfo = flowinfo;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_flags(struct rt_link_newlink_req *req,
						   __u32 flags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.flags = 1;
	req->linkinfo.data.ip6tnl.flags = flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_proto(struct rt_link_newlink_req *req,
						   __u8 proto)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.proto = 1;
	req->linkinfo.data.ip6tnl.proto = proto;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_encap_type(struct rt_link_newlink_req *req,
							__u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_type = 1;
	req->linkinfo.data.ip6tnl.encap_type = encap_type;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_encap_flags(struct rt_link_newlink_req *req,
							 __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_flags = 1;
	req->linkinfo.data.ip6tnl.encap_flags = encap_flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_encap_sport(struct rt_link_newlink_req *req,
							 __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_sport = 1;
	req->linkinfo.data.ip6tnl.encap_sport = encap_sport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_encap_dport(struct rt_link_newlink_req *req,
							 __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_dport = 1;
	req->linkinfo.data.ip6tnl.encap_dport = encap_dport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_collect_metadata(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.collect_metadata = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ip6tnl_fwmark(struct rt_link_newlink_req *req,
						    __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.fwmark = 1;
	req->linkinfo.data.ip6tnl.fwmark = fwmark;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_link(struct rt_link_newlink_req *req,
					       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.link = 1;
	req->linkinfo.data.sit.link = link;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_local(struct rt_link_newlink_req *req,
						const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit.local);
	req->linkinfo.data.sit._len.local = len;
	req->linkinfo.data.sit.local = malloc(req->linkinfo.data.sit._len.local);
	memcpy(req->linkinfo.data.sit.local, local, req->linkinfo.data.sit._len.local);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_remote(struct rt_link_newlink_req *req,
						 const void *remote,
						 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit.remote);
	req->linkinfo.data.sit._len.remote = len;
	req->linkinfo.data.sit.remote = malloc(req->linkinfo.data.sit._len.remote);
	memcpy(req->linkinfo.data.sit.remote, remote, req->linkinfo.data.sit._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_ttl(struct rt_link_newlink_req *req,
					      __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.ttl = 1;
	req->linkinfo.data.sit.ttl = ttl;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_tos(struct rt_link_newlink_req *req,
					      __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.tos = 1;
	req->linkinfo.data.sit.tos = tos;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_encap_limit(struct rt_link_newlink_req *req,
						      __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_limit = 1;
	req->linkinfo.data.sit.encap_limit = encap_limit;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_flowinfo(struct rt_link_newlink_req *req,
						   __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.flowinfo = 1;
	req->linkinfo.data.sit.flowinfo = flowinfo;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_flags(struct rt_link_newlink_req *req,
						__u16 flags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.flags = 1;
	req->linkinfo.data.sit.flags = flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_proto(struct rt_link_newlink_req *req,
						__u8 proto)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.proto = 1;
	req->linkinfo.data.sit.proto = proto;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_pmtudisc(struct rt_link_newlink_req *req,
						   __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.pmtudisc = 1;
	req->linkinfo.data.sit.pmtudisc = pmtudisc;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit__6rd_prefix(struct rt_link_newlink_req *req,
						      const void *_6rd_prefix,
						      size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit._6rd_prefix);
	req->linkinfo.data.sit._len._6rd_prefix = len;
	req->linkinfo.data.sit._6rd_prefix = malloc(req->linkinfo.data.sit._len._6rd_prefix);
	memcpy(req->linkinfo.data.sit._6rd_prefix, _6rd_prefix, req->linkinfo.data.sit._len._6rd_prefix);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit__6rd_relay_prefix(struct rt_link_newlink_req *req,
							    const void *_6rd_relay_prefix,
							    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit._6rd_relay_prefix);
	req->linkinfo.data.sit._len._6rd_relay_prefix = len;
	req->linkinfo.data.sit._6rd_relay_prefix = malloc(req->linkinfo.data.sit._len._6rd_relay_prefix);
	memcpy(req->linkinfo.data.sit._6rd_relay_prefix, _6rd_relay_prefix, req->linkinfo.data.sit._len._6rd_relay_prefix);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit__6rd_prefixlen(struct rt_link_newlink_req *req,
							 __u16 _6rd_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present._6rd_prefixlen = 1;
	req->linkinfo.data.sit._6rd_prefixlen = _6rd_prefixlen;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit__6rd_relay_prefixlen(struct rt_link_newlink_req *req,
							       __u16 _6rd_relay_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present._6rd_relay_prefixlen = 1;
	req->linkinfo.data.sit._6rd_relay_prefixlen = _6rd_relay_prefixlen;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_encap_type(struct rt_link_newlink_req *req,
						     __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_type = 1;
	req->linkinfo.data.sit.encap_type = encap_type;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_encap_flags(struct rt_link_newlink_req *req,
						      __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_flags = 1;
	req->linkinfo.data.sit.encap_flags = encap_flags;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_encap_sport(struct rt_link_newlink_req *req,
						      __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_sport = 1;
	req->linkinfo.data.sit.encap_sport = encap_sport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_encap_dport(struct rt_link_newlink_req *req,
						      __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_dport = 1;
	req->linkinfo.data.sit.encap_dport = encap_dport;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_collect_metadata(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.collect_metadata = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_sit_fwmark(struct rt_link_newlink_req *req,
						 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.fwmark = 1;
	req->linkinfo.data.sit.fwmark = fwmark;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_tun_owner(struct rt_link_newlink_req *req,
						__u32 owner)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.owner = 1;
	req->linkinfo.data.tun.owner = owner;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_tun_group(struct rt_link_newlink_req *req,
						__u32 group)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.group = 1;
	req->linkinfo.data.tun.group = group;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_tun_type(struct rt_link_newlink_req *req,
					       __u8 type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.type = 1;
	req->linkinfo.data.tun.type = type;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_tun_pi(struct rt_link_newlink_req *req,
					     __u8 pi)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.pi = 1;
	req->linkinfo.data.tun.pi = pi;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_tun_vnet_hdr(struct rt_link_newlink_req *req,
						   __u8 vnet_hdr)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.vnet_hdr = 1;
	req->linkinfo.data.tun.vnet_hdr = vnet_hdr;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_tun_persist(struct rt_link_newlink_req *req,
						  __u8 persist)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.persist = 1;
	req->linkinfo.data.tun.persist = persist;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_tun_multi_queue(struct rt_link_newlink_req *req,
						      __u8 multi_queue)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.multi_queue = 1;
	req->linkinfo.data.tun.multi_queue = multi_queue;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_tun_num_queues(struct rt_link_newlink_req *req,
						     __u32 num_queues)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.num_queues = 1;
	req->linkinfo.data.tun.num_queues = num_queues;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_tun_num_disabled_queues(struct rt_link_newlink_req *req,
							      __u32 num_disabled_queues)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.num_disabled_queues = 1;
	req->linkinfo.data.tun.num_disabled_queues = num_disabled_queues;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vlan_id(struct rt_link_newlink_req *req,
					      __u16 id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.id = 1;
	req->linkinfo.data.vlan.id = id;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vlan_flags(struct rt_link_newlink_req *req,
						 const void *flags, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	free(req->linkinfo.data.vlan.flags);
	req->linkinfo.data.vlan._len.flags = len;
	req->linkinfo.data.vlan.flags = malloc(req->linkinfo.data.vlan._len.flags);
	memcpy(req->linkinfo.data.vlan.flags, flags, req->linkinfo.data.vlan._len.flags);
}
static inline void
__rt_link_newlink_req_set_linkinfo_data_vlan_egress_qos_mapping(struct rt_link_newlink_req *req,
								struct ifla_vlan_qos_mapping *mapping,
								unsigned int n_mapping)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.egress_qos = 1;
	free(req->linkinfo.data.vlan.egress_qos.mapping);
	req->linkinfo.data.vlan.egress_qos.mapping = mapping;
	req->linkinfo.data.vlan.egress_qos._count.mapping = n_mapping;
}
static inline void
__rt_link_newlink_req_set_linkinfo_data_vlan_ingress_qos_mapping(struct rt_link_newlink_req *req,
								 struct ifla_vlan_qos_mapping *mapping,
								 unsigned int n_mapping)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.ingress_qos = 1;
	free(req->linkinfo.data.vlan.ingress_qos.mapping);
	req->linkinfo.data.vlan.ingress_qos.mapping = mapping;
	req->linkinfo.data.vlan.ingress_qos._count.mapping = n_mapping;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vlan_protocol(struct rt_link_newlink_req *req,
						    int protocol /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.protocol = 1;
	req->linkinfo.data.vlan.protocol = protocol;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vrf_table(struct rt_link_newlink_req *req,
						__u32 table)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vrf = 1;
	req->linkinfo.data.vrf._present.table = 1;
	req->linkinfo.data.vrf.table = table;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti_link(struct rt_link_newlink_req *req,
					       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.link = 1;
	req->linkinfo.data.vti.link = link;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti_ikey(struct rt_link_newlink_req *req,
					       __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.ikey = 1;
	req->linkinfo.data.vti.ikey = ikey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti_okey(struct rt_link_newlink_req *req,
					       __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.okey = 1;
	req->linkinfo.data.vti.okey = okey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti_local(struct rt_link_newlink_req *req,
						const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	free(req->linkinfo.data.vti.local);
	req->linkinfo.data.vti._len.local = len;
	req->linkinfo.data.vti.local = malloc(req->linkinfo.data.vti._len.local);
	memcpy(req->linkinfo.data.vti.local, local, req->linkinfo.data.vti._len.local);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti_remote(struct rt_link_newlink_req *req,
						 const void *remote,
						 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	free(req->linkinfo.data.vti.remote);
	req->linkinfo.data.vti._len.remote = len;
	req->linkinfo.data.vti.remote = malloc(req->linkinfo.data.vti._len.remote);
	memcpy(req->linkinfo.data.vti.remote, remote, req->linkinfo.data.vti._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti_fwmark(struct rt_link_newlink_req *req,
						 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.fwmark = 1;
	req->linkinfo.data.vti.fwmark = fwmark;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti6_link(struct rt_link_newlink_req *req,
						__u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.link = 1;
	req->linkinfo.data.vti6.link = link;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti6_ikey(struct rt_link_newlink_req *req,
						__u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.ikey = 1;
	req->linkinfo.data.vti6.ikey = ikey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti6_okey(struct rt_link_newlink_req *req,
						__u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.okey = 1;
	req->linkinfo.data.vti6.okey = okey;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti6_local(struct rt_link_newlink_req *req,
						 const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	free(req->linkinfo.data.vti6.local);
	req->linkinfo.data.vti6._len.local = len;
	req->linkinfo.data.vti6.local = malloc(req->linkinfo.data.vti6._len.local);
	memcpy(req->linkinfo.data.vti6.local, local, req->linkinfo.data.vti6._len.local);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti6_remote(struct rt_link_newlink_req *req,
						  const void *remote,
						  size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	free(req->linkinfo.data.vti6.remote);
	req->linkinfo.data.vti6._len.remote = len;
	req->linkinfo.data.vti6.remote = malloc(req->linkinfo.data.vti6._len.remote);
	memcpy(req->linkinfo.data.vti6.remote, remote, req->linkinfo.data.vti6._len.remote);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_vti6_fwmark(struct rt_link_newlink_req *req,
						  __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.fwmark = 1;
	req->linkinfo.data.vti6.fwmark = fwmark;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_netkit_peer_info(struct rt_link_newlink_req *req,
						       const void *peer_info,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	free(req->linkinfo.data.netkit.peer_info);
	req->linkinfo.data.netkit._len.peer_info = len;
	req->linkinfo.data.netkit.peer_info = malloc(req->linkinfo.data.netkit._len.peer_info);
	memcpy(req->linkinfo.data.netkit.peer_info, peer_info, req->linkinfo.data.netkit._len.peer_info);
}
static inline void
rt_link_newlink_req_set_linkinfo_data_netkit_primary(struct rt_link_newlink_req *req,
						     __u8 primary)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.primary = 1;
	req->linkinfo.data.netkit.primary = primary;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_netkit_policy(struct rt_link_newlink_req *req,
						    int policy)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.policy = 1;
	req->linkinfo.data.netkit.policy = policy;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_netkit_peer_policy(struct rt_link_newlink_req *req,
							 int peer_policy)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.peer_policy = 1;
	req->linkinfo.data.netkit.peer_policy = peer_policy;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_netkit_mode(struct rt_link_newlink_req *req,
						  enum netkit_mode mode)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.mode = 1;
	req->linkinfo.data.netkit.mode = mode;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_netkit_scrub(struct rt_link_newlink_req *req,
						   int scrub)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.scrub = 1;
	req->linkinfo.data.netkit.scrub = scrub;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_netkit_peer_scrub(struct rt_link_newlink_req *req,
							int peer_scrub)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.peer_scrub = 1;
	req->linkinfo.data.netkit.peer_scrub = peer_scrub;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_netkit_headroom(struct rt_link_newlink_req *req,
						      __u16 headroom)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.headroom = 1;
	req->linkinfo.data.netkit.headroom = headroom;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_netkit_tailroom(struct rt_link_newlink_req *req,
						      __u16 tailroom)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.tailroom = 1;
	req->linkinfo.data.netkit.tailroom = tailroom;
}
static inline void
rt_link_newlink_req_set_linkinfo_data_ovpn_mode(struct rt_link_newlink_req *req,
						enum ovpn_mode mode)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ovpn = 1;
	req->linkinfo.data.ovpn._present.mode = 1;
	req->linkinfo.data.ovpn.mode = mode;
}
static inline void
rt_link_newlink_req_set_linkinfo_xstats(struct rt_link_newlink_req *req,
					const void *xstats, size_t len)
{
	req->_present.linkinfo = 1;
	free(req->linkinfo.xstats);
	req->linkinfo._len.xstats = len;
	req->linkinfo.xstats = malloc(req->linkinfo._len.xstats);
	memcpy(req->linkinfo.xstats, xstats, req->linkinfo._len.xstats);
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_kind(struct rt_link_newlink_req *req,
					    const char *slave_kind)
{
	req->_present.linkinfo = 1;
	free(req->linkinfo.slave_kind);
	req->linkinfo._len.slave_kind = strlen(slave_kind);
	req->linkinfo.slave_kind = malloc(req->linkinfo._len.slave_kind + 1);
	memcpy(req->linkinfo.slave_kind, slave_kind, req->linkinfo._len.slave_kind);
	req->linkinfo.slave_kind[req->linkinfo._len.slave_kind] = 0;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_state(struct rt_link_newlink_req *req,
							 __u8 state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.state = 1;
	req->linkinfo.slave_data.bridge.state = state;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_priority(struct rt_link_newlink_req *req,
							    __u16 priority)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.priority = 1;
	req->linkinfo.slave_data.bridge.priority = priority;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_cost(struct rt_link_newlink_req *req,
							__u32 cost)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.cost = 1;
	req->linkinfo.slave_data.bridge.cost = cost;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mode(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mode = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_guard(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.guard = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_protect(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.protect = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_fast_leave(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.fast_leave = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_learning(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.learning = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_unicast_flood(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.unicast_flood = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_proxyarp(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.proxyarp = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_learning_sync(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.learning_sync = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_proxyarp_wifi(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.proxyarp_wifi = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_root_id(struct rt_link_newlink_req *req,
							   const void *root_id,
							   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	free(req->linkinfo.slave_data.bridge.root_id);
	req->linkinfo.slave_data.bridge._len.root_id = len;
	req->linkinfo.slave_data.bridge.root_id = malloc(req->linkinfo.slave_data.bridge._len.root_id);
	memcpy(req->linkinfo.slave_data.bridge.root_id, root_id, req->linkinfo.slave_data.bridge._len.root_id);
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_bridge_id(struct rt_link_newlink_req *req,
							     const void *bridge_id,
							     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	free(req->linkinfo.slave_data.bridge.bridge_id);
	req->linkinfo.slave_data.bridge._len.bridge_id = len;
	req->linkinfo.slave_data.bridge.bridge_id = malloc(req->linkinfo.slave_data.bridge._len.bridge_id);
	memcpy(req->linkinfo.slave_data.bridge.bridge_id, bridge_id, req->linkinfo.slave_data.bridge._len.bridge_id);
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_designated_port(struct rt_link_newlink_req *req,
								   __u16 designated_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.designated_port = 1;
	req->linkinfo.slave_data.bridge.designated_port = designated_port;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_designated_cost(struct rt_link_newlink_req *req,
								   __u16 designated_cost)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.designated_cost = 1;
	req->linkinfo.slave_data.bridge.designated_cost = designated_cost;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_id(struct rt_link_newlink_req *req,
						      __u16 id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.id = 1;
	req->linkinfo.slave_data.bridge.id = id;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_no(struct rt_link_newlink_req *req,
						      __u16 no)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.no = 1;
	req->linkinfo.slave_data.bridge.no = no;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_topology_change_ack(struct rt_link_newlink_req *req,
								       __u8 topology_change_ack)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.topology_change_ack = 1;
	req->linkinfo.slave_data.bridge.topology_change_ack = topology_change_ack;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_config_pending(struct rt_link_newlink_req *req,
								  __u8 config_pending)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.config_pending = 1;
	req->linkinfo.slave_data.bridge.config_pending = config_pending;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_message_age_timer(struct rt_link_newlink_req *req,
								     __u64 message_age_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.message_age_timer = 1;
	req->linkinfo.slave_data.bridge.message_age_timer = message_age_timer;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_forward_delay_timer(struct rt_link_newlink_req *req,
								       __u64 forward_delay_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.forward_delay_timer = 1;
	req->linkinfo.slave_data.bridge.forward_delay_timer = forward_delay_timer;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_hold_timer(struct rt_link_newlink_req *req,
							      __u64 hold_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.hold_timer = 1;
	req->linkinfo.slave_data.bridge.hold_timer = hold_timer;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_flush(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.flush = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_multicast_router(struct rt_link_newlink_req *req,
								    __u8 multicast_router)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.multicast_router = 1;
	req->linkinfo.slave_data.bridge.multicast_router = multicast_router;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mcast_flood(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_flood = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mcast_to_ucast(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_to_ucast = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_vlan_tunnel(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.vlan_tunnel = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_bcast_flood(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.bcast_flood = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_group_fwd_mask(struct rt_link_newlink_req *req,
								  __u16 group_fwd_mask)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.group_fwd_mask = 1;
	req->linkinfo.slave_data.bridge.group_fwd_mask = group_fwd_mask;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_neigh_suppress(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.neigh_suppress = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_isolated(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.isolated = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_backup_port(struct rt_link_newlink_req *req,
							       __u32 backup_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.backup_port = 1;
	req->linkinfo.slave_data.bridge.backup_port = backup_port;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mrp_ring_open(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mrp_ring_open = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mrp_in_open(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mrp_in_open = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mcast_eht_hosts_limit(struct rt_link_newlink_req *req,
									 __u32 mcast_eht_hosts_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_eht_hosts_limit = 1;
	req->linkinfo.slave_data.bridge.mcast_eht_hosts_limit = mcast_eht_hosts_limit;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mcast_eht_hosts_cnt(struct rt_link_newlink_req *req,
								       __u32 mcast_eht_hosts_cnt)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_eht_hosts_cnt = 1;
	req->linkinfo.slave_data.bridge.mcast_eht_hosts_cnt = mcast_eht_hosts_cnt;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_locked(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.locked = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mab(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mab = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mcast_n_groups(struct rt_link_newlink_req *req,
								  __u32 mcast_n_groups)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_n_groups = 1;
	req->linkinfo.slave_data.bridge.mcast_n_groups = mcast_n_groups;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_mcast_max_groups(struct rt_link_newlink_req *req,
								    __u32 mcast_max_groups)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_max_groups = 1;
	req->linkinfo.slave_data.bridge.mcast_max_groups = mcast_max_groups;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_neigh_vlan_suppress(struct rt_link_newlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.neigh_vlan_suppress = 1;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bridge_backup_nhid(struct rt_link_newlink_req *req,
							       __u32 backup_nhid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.backup_nhid = 1;
	req->linkinfo.slave_data.bridge.backup_nhid = backup_nhid;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bond_state(struct rt_link_newlink_req *req,
						       __u8 state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.state = 1;
	req->linkinfo.slave_data.bond.state = state;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bond_mii_status(struct rt_link_newlink_req *req,
							    __u8 mii_status)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.mii_status = 1;
	req->linkinfo.slave_data.bond.mii_status = mii_status;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bond_link_failure_count(struct rt_link_newlink_req *req,
								    __u32 link_failure_count)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.link_failure_count = 1;
	req->linkinfo.slave_data.bond.link_failure_count = link_failure_count;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bond_perm_hwaddr(struct rt_link_newlink_req *req,
							     const void *perm_hwaddr,
							     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	free(req->linkinfo.slave_data.bond.perm_hwaddr);
	req->linkinfo.slave_data.bond._len.perm_hwaddr = len;
	req->linkinfo.slave_data.bond.perm_hwaddr = malloc(req->linkinfo.slave_data.bond._len.perm_hwaddr);
	memcpy(req->linkinfo.slave_data.bond.perm_hwaddr, perm_hwaddr, req->linkinfo.slave_data.bond._len.perm_hwaddr);
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bond_queue_id(struct rt_link_newlink_req *req,
							  __u16 queue_id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.queue_id = 1;
	req->linkinfo.slave_data.bond.queue_id = queue_id;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bond_ad_aggregator_id(struct rt_link_newlink_req *req,
								  __u16 ad_aggregator_id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.ad_aggregator_id = 1;
	req->linkinfo.slave_data.bond.ad_aggregator_id = ad_aggregator_id;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bond_ad_actor_oper_port_state(struct rt_link_newlink_req *req,
									  __u8 ad_actor_oper_port_state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.ad_actor_oper_port_state = 1;
	req->linkinfo.slave_data.bond.ad_actor_oper_port_state = ad_actor_oper_port_state;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bond_ad_partner_oper_port_state(struct rt_link_newlink_req *req,
									    __u16 ad_partner_oper_port_state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.ad_partner_oper_port_state = 1;
	req->linkinfo.slave_data.bond.ad_partner_oper_port_state = ad_partner_oper_port_state;
}
static inline void
rt_link_newlink_req_set_linkinfo_slave_data_bond_prio(struct rt_link_newlink_req *req,
						      __u32 prio)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.prio = 1;
	req->linkinfo.slave_data.bond.prio = prio;
}
static inline void
rt_link_newlink_req_set_group(struct rt_link_newlink_req *req, __u32 group)
{
	req->_present.group = 1;
	req->group = group;
}
static inline void
rt_link_newlink_req_set_num_tx_queues(struct rt_link_newlink_req *req,
				      __u32 num_tx_queues)
{
	req->_present.num_tx_queues = 1;
	req->num_tx_queues = num_tx_queues;
}
static inline void
rt_link_newlink_req_set_num_rx_queues(struct rt_link_newlink_req *req,
				      __u32 num_rx_queues)
{
	req->_present.num_rx_queues = 1;
	req->num_rx_queues = num_rx_queues;
}
static inline void
rt_link_newlink_req_set_address(struct rt_link_newlink_req *req,
				const void *address, size_t len)
{
	free(req->address);
	req->_len.address = len;
	req->address = malloc(req->_len.address);
	memcpy(req->address, address, req->_len.address);
}
static inline void
rt_link_newlink_req_set_broadcast(struct rt_link_newlink_req *req,
				  const void *broadcast, size_t len)
{
	free(req->broadcast);
	req->_len.broadcast = len;
	req->broadcast = malloc(req->_len.broadcast);
	memcpy(req->broadcast, broadcast, req->_len.broadcast);
}
static inline void
rt_link_newlink_req_set_mtu(struct rt_link_newlink_req *req, __u32 mtu)
{
	req->_present.mtu = 1;
	req->mtu = mtu;
}
static inline void
rt_link_newlink_req_set_txqlen(struct rt_link_newlink_req *req, __u32 txqlen)
{
	req->_present.txqlen = 1;
	req->txqlen = txqlen;
}
static inline void
rt_link_newlink_req_set_operstate(struct rt_link_newlink_req *req,
				  __u8 operstate)
{
	req->_present.operstate = 1;
	req->operstate = operstate;
}
static inline void
rt_link_newlink_req_set_linkmode(struct rt_link_newlink_req *req,
				 __u8 linkmode)
{
	req->_present.linkmode = 1;
	req->linkmode = linkmode;
}
static inline void
rt_link_newlink_req_set_gso_max_size(struct rt_link_newlink_req *req,
				     __u32 gso_max_size)
{
	req->_present.gso_max_size = 1;
	req->gso_max_size = gso_max_size;
}
static inline void
rt_link_newlink_req_set_gso_max_segs(struct rt_link_newlink_req *req,
				     __u32 gso_max_segs)
{
	req->_present.gso_max_segs = 1;
	req->gso_max_segs = gso_max_segs;
}
static inline void
rt_link_newlink_req_set_gro_max_size(struct rt_link_newlink_req *req,
				     __u32 gro_max_size)
{
	req->_present.gro_max_size = 1;
	req->gro_max_size = gro_max_size;
}
static inline void
rt_link_newlink_req_set_gso_ipv4_max_size(struct rt_link_newlink_req *req,
					  __u32 gso_ipv4_max_size)
{
	req->_present.gso_ipv4_max_size = 1;
	req->gso_ipv4_max_size = gso_ipv4_max_size;
}
static inline void
rt_link_newlink_req_set_gro_ipv4_max_size(struct rt_link_newlink_req *req,
					  __u32 gro_ipv4_max_size)
{
	req->_present.gro_ipv4_max_size = 1;
	req->gro_ipv4_max_size = gro_ipv4_max_size;
}
static inline void
rt_link_newlink_req_set_af_spec_inet_conf(struct rt_link_newlink_req *req,
					  __u32 *conf, size_t count)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet = 1;
	free(req->af_spec.inet.conf);
	req->af_spec.inet._count.conf = count;
	count *= sizeof(__u32);
	req->af_spec.inet.conf = malloc(count);
	memcpy(req->af_spec.inet.conf, conf, count);
}
static inline void
rt_link_newlink_req_set_af_spec_inet6_flags(struct rt_link_newlink_req *req,
					    __u32 flags)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	req->af_spec.inet6._present.flags = 1;
	req->af_spec.inet6.flags = flags;
}
static inline void
rt_link_newlink_req_set_af_spec_inet6_conf(struct rt_link_newlink_req *req,
					   __u32 *conf, size_t count)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.conf);
	req->af_spec.inet6._count.conf = count;
	count *= sizeof(__u32);
	req->af_spec.inet6.conf = malloc(count);
	memcpy(req->af_spec.inet6.conf, conf, count);
}
static inline void
rt_link_newlink_req_set_af_spec_inet6_stats(struct rt_link_newlink_req *req,
					    __u64 *stats, size_t count)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.stats);
	req->af_spec.inet6._count.stats = count;
	count *= sizeof(__u64);
	req->af_spec.inet6.stats = malloc(count);
	memcpy(req->af_spec.inet6.stats, stats, count);
}
static inline void
rt_link_newlink_req_set_af_spec_inet6_mcast(struct rt_link_newlink_req *req,
					    const void *mcast, size_t len)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.mcast);
	req->af_spec.inet6._len.mcast = len;
	req->af_spec.inet6.mcast = malloc(req->af_spec.inet6._len.mcast);
	memcpy(req->af_spec.inet6.mcast, mcast, req->af_spec.inet6._len.mcast);
}
static inline void
rt_link_newlink_req_set_af_spec_inet6_cacheinfo(struct rt_link_newlink_req *req,
						const void *cacheinfo,
						size_t len)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.cacheinfo);
	req->af_spec.inet6._len.cacheinfo = len;
	req->af_spec.inet6.cacheinfo = malloc(req->af_spec.inet6._len.cacheinfo);
	memcpy(req->af_spec.inet6.cacheinfo, cacheinfo, req->af_spec.inet6._len.cacheinfo);
}
static inline void
rt_link_newlink_req_set_af_spec_inet6_icmp6stats(struct rt_link_newlink_req *req,
						 __u64 *icmp6stats,
						 size_t count)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.icmp6stats);
	req->af_spec.inet6._count.icmp6stats = count;
	count *= sizeof(__u64);
	req->af_spec.inet6.icmp6stats = malloc(count);
	memcpy(req->af_spec.inet6.icmp6stats, icmp6stats, count);
}
static inline void
rt_link_newlink_req_set_af_spec_inet6_token(struct rt_link_newlink_req *req,
					    const void *token, size_t len)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.token);
	req->af_spec.inet6._len.token = len;
	req->af_spec.inet6.token = malloc(req->af_spec.inet6._len.token);
	memcpy(req->af_spec.inet6.token, token, req->af_spec.inet6._len.token);
}
static inline void
rt_link_newlink_req_set_af_spec_inet6_addr_gen_mode(struct rt_link_newlink_req *req,
						    __u8 addr_gen_mode)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	req->af_spec.inet6._present.addr_gen_mode = 1;
	req->af_spec.inet6.addr_gen_mode = addr_gen_mode;
}
static inline void
rt_link_newlink_req_set_af_spec_inet6_ra_mtu(struct rt_link_newlink_req *req,
					     __u32 ra_mtu)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	req->af_spec.inet6._present.ra_mtu = 1;
	req->af_spec.inet6.ra_mtu = ra_mtu;
}
static inline void
rt_link_newlink_req_set_af_spec_mctp_net(struct rt_link_newlink_req *req,
					 __u32 net)
{
	req->_present.af_spec = 1;
	req->af_spec._present.mctp = 1;
	req->af_spec.mctp._present.net = 1;
	req->af_spec.mctp.net = net;
}
static inline void
rt_link_newlink_req_set_af_spec_mctp_phys_binding(struct rt_link_newlink_req *req,
						  __u8 phys_binding)
{
	req->_present.af_spec = 1;
	req->af_spec._present.mctp = 1;
	req->af_spec.mctp._present.phys_binding = 1;
	req->af_spec.mctp.phys_binding = phys_binding;
}

/*
 * Create a new link.
 */
int rt_link_newlink(struct ynl_sock *ys, struct rt_link_newlink_req *req);

/* ============== RTM_DELLINK ============== */
/* RTM_DELLINK - do */
struct rt_link_dellink_req {
	__u16 _nlmsg_flags;

	struct ifinfomsg _hdr;

	struct {
		__u32 ifname;
	} _len;

	char *ifname;
};

static inline struct rt_link_dellink_req *rt_link_dellink_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_link_dellink_req));
}
void rt_link_dellink_req_free(struct rt_link_dellink_req *req);

static inline void
rt_link_dellink_req_set_nlflags(struct rt_link_dellink_req *req,
				__u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_link_dellink_req_set_ifname(struct rt_link_dellink_req *req,
			       const char *ifname)
{
	free(req->ifname);
	req->_len.ifname = strlen(ifname);
	req->ifname = malloc(req->_len.ifname + 1);
	memcpy(req->ifname, ifname, req->_len.ifname);
	req->ifname[req->_len.ifname] = 0;
}

/*
 * Delete an existing link.
 */
int rt_link_dellink(struct ynl_sock *ys, struct rt_link_dellink_req *req);

/* ============== RTM_GETLINK ============== */
/* RTM_GETLINK - do */
struct rt_link_getlink_req {
	__u16 _nlmsg_flags;

	struct ifinfomsg _hdr;

	struct {
		__u32 ext_mask:1;
		__u32 target_netnsid:1;
	} _present;
	struct {
		__u32 ifname;
		__u32 alt_ifname;
	} _len;

	char *ifname;
	char *alt_ifname;
	__u32 ext_mask;
	__s32 target_netnsid;
};

static inline struct rt_link_getlink_req *rt_link_getlink_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_link_getlink_req));
}
void rt_link_getlink_req_free(struct rt_link_getlink_req *req);

static inline void
rt_link_getlink_req_set_nlflags(struct rt_link_getlink_req *req,
				__u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_link_getlink_req_set_ifname(struct rt_link_getlink_req *req,
			       const char *ifname)
{
	free(req->ifname);
	req->_len.ifname = strlen(ifname);
	req->ifname = malloc(req->_len.ifname + 1);
	memcpy(req->ifname, ifname, req->_len.ifname);
	req->ifname[req->_len.ifname] = 0;
}
static inline void
rt_link_getlink_req_set_alt_ifname(struct rt_link_getlink_req *req,
				   const char *alt_ifname)
{
	free(req->alt_ifname);
	req->_len.alt_ifname = strlen(alt_ifname);
	req->alt_ifname = malloc(req->_len.alt_ifname + 1);
	memcpy(req->alt_ifname, alt_ifname, req->_len.alt_ifname);
	req->alt_ifname[req->_len.alt_ifname] = 0;
}
static inline void
rt_link_getlink_req_set_ext_mask(struct rt_link_getlink_req *req,
				 __u32 ext_mask)
{
	req->_present.ext_mask = 1;
	req->ext_mask = ext_mask;
}
static inline void
rt_link_getlink_req_set_target_netnsid(struct rt_link_getlink_req *req,
				       __s32 target_netnsid)
{
	req->_present.target_netnsid = 1;
	req->target_netnsid = target_netnsid;
}

struct rt_link_getlink_rsp {
	struct ifinfomsg _hdr;

	struct {
		__u32 mtu:1;
		__u32 link:1;
		__u32 master:1;
		__u32 txqlen:1;
		__u32 weight:1;
		__u32 operstate:1;
		__u32 linkmode:1;
		__u32 linkinfo:1;
		__u32 net_ns_pid:1;
		__u32 num_vf:1;
		__u32 vfinfo_list:1;
		__u32 vf_ports:1;
		__u32 port_self:1;
		__u32 af_spec:1;
		__u32 group:1;
		__u32 net_ns_fd:1;
		__u32 ext_mask:1;
		__u32 promiscuity:1;
		__u32 num_tx_queues:1;
		__u32 num_rx_queues:1;
		__u32 carrier:1;
		__u32 carrier_changes:1;
		__u32 link_netnsid:1;
		__u32 proto_down:1;
		__u32 gso_max_segs:1;
		__u32 gso_max_size:1;
		__u32 xdp:1;
		__u32 event:1;
		__u32 new_netnsid:1;
		__u32 target_netnsid:1;
		__u32 carrier_up_count:1;
		__u32 carrier_down_count:1;
		__u32 new_ifindex:1;
		__u32 min_mtu:1;
		__u32 max_mtu:1;
		__u32 prop_list:1;
		__u32 gro_max_size:1;
		__u32 tso_max_size:1;
		__u32 tso_max_segs:1;
		__u32 allmulti:1;
		__u32 gso_ipv4_max_size:1;
		__u32 gro_ipv4_max_size:1;
	} _present;
	struct {
		__u32 address;
		__u32 broadcast;
		__u32 ifname;
		__u32 qdisc;
		__u32 stats;
		__u32 cost;
		__u32 priority;
		__u32 wireless;
		__u32 protinfo;
		__u32 map;
		__u32 ifalias;
		__u32 stats64;
		__u32 phys_port_id;
		__u32 phys_switch_id;
		__u32 phys_port_name;
		__u32 perm_address;
		__u32 proto_down_reason;
		__u32 parent_dev_name;
		__u32 parent_dev_bus_name;
		__u32 devlink_port;
	} _len;

	void *address;
	void *broadcast;
	char *ifname;
	__u32 mtu;
	__u32 link;
	char *qdisc;
	struct rtnl_link_stats *stats;
	char *cost;
	char *priority;
	__u32 master;
	char *wireless;
	char *protinfo;
	__u32 txqlen;
	struct rtnl_link_ifmap *map;
	__u32 weight;
	__u8 operstate;
	__u8 linkmode;
	struct rt_link_linkinfo_attrs linkinfo;
	__u32 net_ns_pid;
	char *ifalias;
	__u32 num_vf;
	struct rt_link_vfinfo_list_attrs vfinfo_list;
	struct rtnl_link_stats64 *stats64;
	struct rt_link_vf_ports_attrs vf_ports;
	struct rt_link_port_self_attrs port_self;
	struct rt_link_af_spec_attrs af_spec;
	__u32 group;
	__u32 net_ns_fd;
	__u32 ext_mask;
	__u32 promiscuity;
	__u32 num_tx_queues;
	__u32 num_rx_queues;
	__u8 carrier;
	void *phys_port_id;
	__u32 carrier_changes;
	void *phys_switch_id;
	__s32 link_netnsid;
	char *phys_port_name;
	__u8 proto_down;
	__u32 gso_max_segs;
	__u32 gso_max_size;
	struct rt_link_xdp_attrs xdp;
	__u32 event;
	__s32 new_netnsid;
	__s32 target_netnsid;
	__u32 carrier_up_count;
	__u32 carrier_down_count;
	__s32 new_ifindex;
	__u32 min_mtu;
	__u32 max_mtu;
	struct rt_link_prop_list_link_attrs prop_list;
	void *perm_address;
	char *proto_down_reason;
	char *parent_dev_name;
	char *parent_dev_bus_name;
	__u32 gro_max_size;
	__u32 tso_max_size;
	__u32 tso_max_segs;
	__u32 allmulti;
	void *devlink_port;
	__u32 gso_ipv4_max_size;
	__u32 gro_ipv4_max_size;
};

void rt_link_getlink_rsp_free(struct rt_link_getlink_rsp *rsp);

/*
 * Get / dump information about a link.
 */
struct rt_link_getlink_rsp *
rt_link_getlink(struct ynl_sock *ys, struct rt_link_getlink_req *req);

/* RTM_GETLINK - dump */
struct rt_link_getlink_req_dump {
	struct ifinfomsg _hdr;

	struct {
		__u32 target_netnsid:1;
		__u32 ext_mask:1;
		__u32 master:1;
		__u32 linkinfo:1;
	} _present;

	__s32 target_netnsid;
	__u32 ext_mask;
	__u32 master;
	struct rt_link_linkinfo_attrs linkinfo;
};

static inline struct rt_link_getlink_req_dump *
rt_link_getlink_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct rt_link_getlink_req_dump));
}
void rt_link_getlink_req_dump_free(struct rt_link_getlink_req_dump *req);

static inline void
rt_link_getlink_req_dump_set_target_netnsid(struct rt_link_getlink_req_dump *req,
					    __s32 target_netnsid)
{
	req->_present.target_netnsid = 1;
	req->target_netnsid = target_netnsid;
}
static inline void
rt_link_getlink_req_dump_set_ext_mask(struct rt_link_getlink_req_dump *req,
				      __u32 ext_mask)
{
	req->_present.ext_mask = 1;
	req->ext_mask = ext_mask;
}
static inline void
rt_link_getlink_req_dump_set_master(struct rt_link_getlink_req_dump *req,
				    __u32 master)
{
	req->_present.master = 1;
	req->master = master;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_kind(struct rt_link_getlink_req_dump *req,
					   const char *kind)
{
	req->_present.linkinfo = 1;
	free(req->linkinfo.kind);
	req->linkinfo._len.kind = strlen(kind);
	req->linkinfo.kind = malloc(req->linkinfo._len.kind + 1);
	memcpy(req->linkinfo.kind, kind, req->linkinfo._len.kind);
	req->linkinfo.kind[req->linkinfo._len.kind] = 0;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_mode(struct rt_link_getlink_req_dump *req,
						     __u8 mode)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.mode = 1;
	req->linkinfo.data.bond.mode = mode;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_active_slave(struct rt_link_getlink_req_dump *req,
							     __u32 active_slave)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.active_slave = 1;
	req->linkinfo.data.bond.active_slave = active_slave;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_miimon(struct rt_link_getlink_req_dump *req,
						       __u32 miimon)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.miimon = 1;
	req->linkinfo.data.bond.miimon = miimon;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_updelay(struct rt_link_getlink_req_dump *req,
							__u32 updelay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.updelay = 1;
	req->linkinfo.data.bond.updelay = updelay;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_downdelay(struct rt_link_getlink_req_dump *req,
							  __u32 downdelay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.downdelay = 1;
	req->linkinfo.data.bond.downdelay = downdelay;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_use_carrier(struct rt_link_getlink_req_dump *req,
							    __u8 use_carrier)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.use_carrier = 1;
	req->linkinfo.data.bond.use_carrier = use_carrier;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_arp_interval(struct rt_link_getlink_req_dump *req,
							     __u32 arp_interval)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.arp_interval = 1;
	req->linkinfo.data.bond.arp_interval = arp_interval;
}
static inline void
__rt_link_getlink_req_dump_set_linkinfo_data_bond_arp_ip_target(struct rt_link_getlink_req_dump *req,
								__u32 *arp_ip_target,
								unsigned int n_arp_ip_target)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	free(req->linkinfo.data.bond.arp_ip_target);
	req->linkinfo.data.bond.arp_ip_target = arp_ip_target;
	req->linkinfo.data.bond._count.arp_ip_target = n_arp_ip_target;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_arp_validate(struct rt_link_getlink_req_dump *req,
							     __u32 arp_validate)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.arp_validate = 1;
	req->linkinfo.data.bond.arp_validate = arp_validate;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_arp_all_targets(struct rt_link_getlink_req_dump *req,
								__u32 arp_all_targets)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.arp_all_targets = 1;
	req->linkinfo.data.bond.arp_all_targets = arp_all_targets;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_primary(struct rt_link_getlink_req_dump *req,
							__u32 primary)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.primary = 1;
	req->linkinfo.data.bond.primary = primary;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_primary_reselect(struct rt_link_getlink_req_dump *req,
								 __u8 primary_reselect)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.primary_reselect = 1;
	req->linkinfo.data.bond.primary_reselect = primary_reselect;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_fail_over_mac(struct rt_link_getlink_req_dump *req,
							      __u8 fail_over_mac)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.fail_over_mac = 1;
	req->linkinfo.data.bond.fail_over_mac = fail_over_mac;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_xmit_hash_policy(struct rt_link_getlink_req_dump *req,
								 __u8 xmit_hash_policy)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.xmit_hash_policy = 1;
	req->linkinfo.data.bond.xmit_hash_policy = xmit_hash_policy;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_resend_igmp(struct rt_link_getlink_req_dump *req,
							    __u32 resend_igmp)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.resend_igmp = 1;
	req->linkinfo.data.bond.resend_igmp = resend_igmp;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_num_peer_notif(struct rt_link_getlink_req_dump *req,
							       __u8 num_peer_notif)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.num_peer_notif = 1;
	req->linkinfo.data.bond.num_peer_notif = num_peer_notif;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_all_slaves_active(struct rt_link_getlink_req_dump *req,
								  __u8 all_slaves_active)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.all_slaves_active = 1;
	req->linkinfo.data.bond.all_slaves_active = all_slaves_active;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_min_links(struct rt_link_getlink_req_dump *req,
							  __u32 min_links)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.min_links = 1;
	req->linkinfo.data.bond.min_links = min_links;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_lp_interval(struct rt_link_getlink_req_dump *req,
							    __u32 lp_interval)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.lp_interval = 1;
	req->linkinfo.data.bond.lp_interval = lp_interval;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_packets_per_slave(struct rt_link_getlink_req_dump *req,
								  __u32 packets_per_slave)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.packets_per_slave = 1;
	req->linkinfo.data.bond.packets_per_slave = packets_per_slave;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_lacp_rate(struct rt_link_getlink_req_dump *req,
							     __u8 ad_lacp_rate)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_lacp_rate = 1;
	req->linkinfo.data.bond.ad_lacp_rate = ad_lacp_rate;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_select(struct rt_link_getlink_req_dump *req,
							  __u8 ad_select)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_select = 1;
	req->linkinfo.data.bond.ad_select = ad_select;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_info_aggregator(struct rt_link_getlink_req_dump *req,
								   __u16 aggregator)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.aggregator = 1;
	req->linkinfo.data.bond.ad_info.aggregator = aggregator;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_info_num_ports(struct rt_link_getlink_req_dump *req,
								  __u16 num_ports)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.num_ports = 1;
	req->linkinfo.data.bond.ad_info.num_ports = num_ports;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_info_actor_key(struct rt_link_getlink_req_dump *req,
								  __u16 actor_key)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.actor_key = 1;
	req->linkinfo.data.bond.ad_info.actor_key = actor_key;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_info_partner_key(struct rt_link_getlink_req_dump *req,
								    __u16 partner_key)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.partner_key = 1;
	req->linkinfo.data.bond.ad_info.partner_key = partner_key;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_info_partner_mac(struct rt_link_getlink_req_dump *req,
								    const void *partner_mac,
								    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	free(req->linkinfo.data.bond.ad_info.partner_mac);
	req->linkinfo.data.bond.ad_info._len.partner_mac = len;
	req->linkinfo.data.bond.ad_info.partner_mac = malloc(req->linkinfo.data.bond.ad_info._len.partner_mac);
	memcpy(req->linkinfo.data.bond.ad_info.partner_mac, partner_mac, req->linkinfo.data.bond.ad_info._len.partner_mac);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_actor_sys_prio(struct rt_link_getlink_req_dump *req,
								  __u16 ad_actor_sys_prio)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_actor_sys_prio = 1;
	req->linkinfo.data.bond.ad_actor_sys_prio = ad_actor_sys_prio;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_user_port_key(struct rt_link_getlink_req_dump *req,
								 __u16 ad_user_port_key)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_user_port_key = 1;
	req->linkinfo.data.bond.ad_user_port_key = ad_user_port_key;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_actor_system(struct rt_link_getlink_req_dump *req,
								const void *ad_actor_system,
								size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	free(req->linkinfo.data.bond.ad_actor_system);
	req->linkinfo.data.bond._len.ad_actor_system = len;
	req->linkinfo.data.bond.ad_actor_system = malloc(req->linkinfo.data.bond._len.ad_actor_system);
	memcpy(req->linkinfo.data.bond.ad_actor_system, ad_actor_system, req->linkinfo.data.bond._len.ad_actor_system);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_tlb_dynamic_lb(struct rt_link_getlink_req_dump *req,
							       __u8 tlb_dynamic_lb)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.tlb_dynamic_lb = 1;
	req->linkinfo.data.bond.tlb_dynamic_lb = tlb_dynamic_lb;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_peer_notif_delay(struct rt_link_getlink_req_dump *req,
								 __u32 peer_notif_delay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.peer_notif_delay = 1;
	req->linkinfo.data.bond.peer_notif_delay = peer_notif_delay;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_ad_lacp_active(struct rt_link_getlink_req_dump *req,
							       __u8 ad_lacp_active)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_lacp_active = 1;
	req->linkinfo.data.bond.ad_lacp_active = ad_lacp_active;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_missed_max(struct rt_link_getlink_req_dump *req,
							   __u8 missed_max)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.missed_max = 1;
	req->linkinfo.data.bond.missed_max = missed_max;
}
static inline void
__rt_link_getlink_req_dump_set_linkinfo_data_bond_ns_ip6_target(struct rt_link_getlink_req_dump *req,
								unsigned char (*ns_ip6_target)[16],
								unsigned int n_ns_ip6_target)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	free(req->linkinfo.data.bond.ns_ip6_target);
	req->linkinfo.data.bond.ns_ip6_target = ns_ip6_target;
	req->linkinfo.data.bond._count.ns_ip6_target = n_ns_ip6_target;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bond_coupled_control(struct rt_link_getlink_req_dump *req,
								__u8 coupled_control)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.coupled_control = 1;
	req->linkinfo.data.bond.coupled_control = coupled_control;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_forward_delay(struct rt_link_getlink_req_dump *req,
								__u32 forward_delay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.forward_delay = 1;
	req->linkinfo.data.bridge.forward_delay = forward_delay;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_hello_time(struct rt_link_getlink_req_dump *req,
							     __u32 hello_time)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.hello_time = 1;
	req->linkinfo.data.bridge.hello_time = hello_time;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_max_age(struct rt_link_getlink_req_dump *req,
							  __u32 max_age)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.max_age = 1;
	req->linkinfo.data.bridge.max_age = max_age;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_ageing_time(struct rt_link_getlink_req_dump *req,
							      __u32 ageing_time)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.ageing_time = 1;
	req->linkinfo.data.bridge.ageing_time = ageing_time;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_stp_state(struct rt_link_getlink_req_dump *req,
							    __u32 stp_state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.stp_state = 1;
	req->linkinfo.data.bridge.stp_state = stp_state;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_priority(struct rt_link_getlink_req_dump *req,
							   __u16 priority)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.priority = 1;
	req->linkinfo.data.bridge.priority = priority;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_vlan_filtering(struct rt_link_getlink_req_dump *req,
								 __u8 vlan_filtering)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_filtering = 1;
	req->linkinfo.data.bridge.vlan_filtering = vlan_filtering;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_vlan_protocol(struct rt_link_getlink_req_dump *req,
								__u16 vlan_protocol)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_protocol = 1;
	req->linkinfo.data.bridge.vlan_protocol = vlan_protocol;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_group_fwd_mask(struct rt_link_getlink_req_dump *req,
								 __u16 group_fwd_mask)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.group_fwd_mask = 1;
	req->linkinfo.data.bridge.group_fwd_mask = group_fwd_mask;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_root_id(struct rt_link_getlink_req_dump *req,
							  const void *root_id,
							  size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.root_id);
	req->linkinfo.data.bridge._len.root_id = len;
	req->linkinfo.data.bridge.root_id = malloc(req->linkinfo.data.bridge._len.root_id);
	memcpy(req->linkinfo.data.bridge.root_id, root_id, req->linkinfo.data.bridge._len.root_id);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_bridge_id(struct rt_link_getlink_req_dump *req,
							    const void *bridge_id,
							    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.bridge_id);
	req->linkinfo.data.bridge._len.bridge_id = len;
	req->linkinfo.data.bridge.bridge_id = malloc(req->linkinfo.data.bridge._len.bridge_id);
	memcpy(req->linkinfo.data.bridge.bridge_id, bridge_id, req->linkinfo.data.bridge._len.bridge_id);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_root_port(struct rt_link_getlink_req_dump *req,
							    __u16 root_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.root_port = 1;
	req->linkinfo.data.bridge.root_port = root_port;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_root_path_cost(struct rt_link_getlink_req_dump *req,
								 __u32 root_path_cost)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.root_path_cost = 1;
	req->linkinfo.data.bridge.root_path_cost = root_path_cost;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_topology_change(struct rt_link_getlink_req_dump *req,
								  __u8 topology_change)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.topology_change = 1;
	req->linkinfo.data.bridge.topology_change = topology_change;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_topology_change_detected(struct rt_link_getlink_req_dump *req,
									   __u8 topology_change_detected)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.topology_change_detected = 1;
	req->linkinfo.data.bridge.topology_change_detected = topology_change_detected;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_hello_timer(struct rt_link_getlink_req_dump *req,
							      __u64 hello_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.hello_timer = 1;
	req->linkinfo.data.bridge.hello_timer = hello_timer;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_tcn_timer(struct rt_link_getlink_req_dump *req,
							    __u64 tcn_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.tcn_timer = 1;
	req->linkinfo.data.bridge.tcn_timer = tcn_timer;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_topology_change_timer(struct rt_link_getlink_req_dump *req,
									__u64 topology_change_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.topology_change_timer = 1;
	req->linkinfo.data.bridge.topology_change_timer = topology_change_timer;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_gc_timer(struct rt_link_getlink_req_dump *req,
							   __u64 gc_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.gc_timer = 1;
	req->linkinfo.data.bridge.gc_timer = gc_timer;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_group_addr(struct rt_link_getlink_req_dump *req,
							     const void *group_addr,
							     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.group_addr);
	req->linkinfo.data.bridge._len.group_addr = len;
	req->linkinfo.data.bridge.group_addr = malloc(req->linkinfo.data.bridge._len.group_addr);
	memcpy(req->linkinfo.data.bridge.group_addr, group_addr, req->linkinfo.data.bridge._len.group_addr);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_fdb_flush(struct rt_link_getlink_req_dump *req,
							    const void *fdb_flush,
							    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.fdb_flush);
	req->linkinfo.data.bridge._len.fdb_flush = len;
	req->linkinfo.data.bridge.fdb_flush = malloc(req->linkinfo.data.bridge._len.fdb_flush);
	memcpy(req->linkinfo.data.bridge.fdb_flush, fdb_flush, req->linkinfo.data.bridge._len.fdb_flush);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_router(struct rt_link_getlink_req_dump *req,
							       __u8 mcast_router)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_router = 1;
	req->linkinfo.data.bridge.mcast_router = mcast_router;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_snooping(struct rt_link_getlink_req_dump *req,
								 __u8 mcast_snooping)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_snooping = 1;
	req->linkinfo.data.bridge.mcast_snooping = mcast_snooping;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_query_use_ifaddr(struct rt_link_getlink_req_dump *req,
									 __u8 mcast_query_use_ifaddr)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_query_use_ifaddr = 1;
	req->linkinfo.data.bridge.mcast_query_use_ifaddr = mcast_query_use_ifaddr;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_querier(struct rt_link_getlink_req_dump *req,
								__u8 mcast_querier)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_querier = 1;
	req->linkinfo.data.bridge.mcast_querier = mcast_querier;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_hash_elasticity(struct rt_link_getlink_req_dump *req,
									__u32 mcast_hash_elasticity)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_hash_elasticity = 1;
	req->linkinfo.data.bridge.mcast_hash_elasticity = mcast_hash_elasticity;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_hash_max(struct rt_link_getlink_req_dump *req,
								 __u32 mcast_hash_max)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_hash_max = 1;
	req->linkinfo.data.bridge.mcast_hash_max = mcast_hash_max;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_last_member_cnt(struct rt_link_getlink_req_dump *req,
									__u32 mcast_last_member_cnt)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_last_member_cnt = 1;
	req->linkinfo.data.bridge.mcast_last_member_cnt = mcast_last_member_cnt;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_startup_query_cnt(struct rt_link_getlink_req_dump *req,
									  __u32 mcast_startup_query_cnt)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_startup_query_cnt = 1;
	req->linkinfo.data.bridge.mcast_startup_query_cnt = mcast_startup_query_cnt;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_last_member_intvl(struct rt_link_getlink_req_dump *req,
									  __u64 mcast_last_member_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_last_member_intvl = 1;
	req->linkinfo.data.bridge.mcast_last_member_intvl = mcast_last_member_intvl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_membership_intvl(struct rt_link_getlink_req_dump *req,
									 __u64 mcast_membership_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_membership_intvl = 1;
	req->linkinfo.data.bridge.mcast_membership_intvl = mcast_membership_intvl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_querier_intvl(struct rt_link_getlink_req_dump *req,
								      __u64 mcast_querier_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_querier_intvl = 1;
	req->linkinfo.data.bridge.mcast_querier_intvl = mcast_querier_intvl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_query_intvl(struct rt_link_getlink_req_dump *req,
								    __u64 mcast_query_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_query_intvl = 1;
	req->linkinfo.data.bridge.mcast_query_intvl = mcast_query_intvl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_query_response_intvl(struct rt_link_getlink_req_dump *req,
									     __u64 mcast_query_response_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_query_response_intvl = 1;
	req->linkinfo.data.bridge.mcast_query_response_intvl = mcast_query_response_intvl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_startup_query_intvl(struct rt_link_getlink_req_dump *req,
									    __u64 mcast_startup_query_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_startup_query_intvl = 1;
	req->linkinfo.data.bridge.mcast_startup_query_intvl = mcast_startup_query_intvl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_nf_call_iptables(struct rt_link_getlink_req_dump *req,
								   __u8 nf_call_iptables)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.nf_call_iptables = 1;
	req->linkinfo.data.bridge.nf_call_iptables = nf_call_iptables;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_nf_call_ip6tables(struct rt_link_getlink_req_dump *req,
								    __u8 nf_call_ip6tables)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.nf_call_ip6tables = 1;
	req->linkinfo.data.bridge.nf_call_ip6tables = nf_call_ip6tables;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_nf_call_arptables(struct rt_link_getlink_req_dump *req,
								    __u8 nf_call_arptables)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.nf_call_arptables = 1;
	req->linkinfo.data.bridge.nf_call_arptables = nf_call_arptables;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_vlan_default_pvid(struct rt_link_getlink_req_dump *req,
								    __u16 vlan_default_pvid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_default_pvid = 1;
	req->linkinfo.data.bridge.vlan_default_pvid = vlan_default_pvid;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_vlan_stats_enabled(struct rt_link_getlink_req_dump *req,
								     __u8 vlan_stats_enabled)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_stats_enabled = 1;
	req->linkinfo.data.bridge.vlan_stats_enabled = vlan_stats_enabled;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_stats_enabled(struct rt_link_getlink_req_dump *req,
								      __u8 mcast_stats_enabled)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_stats_enabled = 1;
	req->linkinfo.data.bridge.mcast_stats_enabled = mcast_stats_enabled;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_igmp_version(struct rt_link_getlink_req_dump *req,
								     __u8 mcast_igmp_version)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_igmp_version = 1;
	req->linkinfo.data.bridge.mcast_igmp_version = mcast_igmp_version;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_mld_version(struct rt_link_getlink_req_dump *req,
								    __u8 mcast_mld_version)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_mld_version = 1;
	req->linkinfo.data.bridge.mcast_mld_version = mcast_mld_version;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_vlan_stats_per_port(struct rt_link_getlink_req_dump *req,
								      __u8 vlan_stats_per_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_stats_per_port = 1;
	req->linkinfo.data.bridge.vlan_stats_per_port = vlan_stats_per_port;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_multi_boolopt(struct rt_link_getlink_req_dump *req,
								const void *multi_boolopt,
								size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.multi_boolopt);
	req->linkinfo.data.bridge._len.multi_boolopt = len;
	req->linkinfo.data.bridge.multi_boolopt = malloc(req->linkinfo.data.bridge._len.multi_boolopt);
	memcpy(req->linkinfo.data.bridge.multi_boolopt, multi_boolopt, req->linkinfo.data.bridge._len.multi_boolopt);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_mcast_querier_state(struct rt_link_getlink_req_dump *req,
								      const void *mcast_querier_state,
								      size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.mcast_querier_state);
	req->linkinfo.data.bridge._len.mcast_querier_state = len;
	req->linkinfo.data.bridge.mcast_querier_state = malloc(req->linkinfo.data.bridge._len.mcast_querier_state);
	memcpy(req->linkinfo.data.bridge.mcast_querier_state, mcast_querier_state, req->linkinfo.data.bridge._len.mcast_querier_state);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_fdb_n_learned(struct rt_link_getlink_req_dump *req,
								__u32 fdb_n_learned)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.fdb_n_learned = 1;
	req->linkinfo.data.bridge.fdb_n_learned = fdb_n_learned;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_bridge_fdb_max_learned(struct rt_link_getlink_req_dump *req,
								  __u32 fdb_max_learned)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.fdb_max_learned = 1;
	req->linkinfo.data.bridge.fdb_max_learned = fdb_max_learned;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_link(struct rt_link_getlink_req_dump *req,
						       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.link = 1;
	req->linkinfo.data.erspan.link = link;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_iflags(struct rt_link_getlink_req_dump *req,
							 __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.iflags = 1;
	req->linkinfo.data.erspan.iflags = iflags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_oflags(struct rt_link_getlink_req_dump *req,
							 __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.oflags = 1;
	req->linkinfo.data.erspan.oflags = oflags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_ikey(struct rt_link_getlink_req_dump *req,
						       __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.ikey = 1;
	req->linkinfo.data.erspan.ikey = ikey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_okey(struct rt_link_getlink_req_dump *req,
						       __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.okey = 1;
	req->linkinfo.data.erspan.okey = okey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_local(struct rt_link_getlink_req_dump *req,
							const void *local,
							size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	free(req->linkinfo.data.erspan.local);
	req->linkinfo.data.erspan._len.local = len;
	req->linkinfo.data.erspan.local = malloc(req->linkinfo.data.erspan._len.local);
	memcpy(req->linkinfo.data.erspan.local, local, req->linkinfo.data.erspan._len.local);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_remote(struct rt_link_getlink_req_dump *req,
							 const void *remote,
							 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	free(req->linkinfo.data.erspan.remote);
	req->linkinfo.data.erspan._len.remote = len;
	req->linkinfo.data.erspan.remote = malloc(req->linkinfo.data.erspan._len.remote);
	memcpy(req->linkinfo.data.erspan.remote, remote, req->linkinfo.data.erspan._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_ttl(struct rt_link_getlink_req_dump *req,
						      __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.ttl = 1;
	req->linkinfo.data.erspan.ttl = ttl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_tos(struct rt_link_getlink_req_dump *req,
						      __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.tos = 1;
	req->linkinfo.data.erspan.tos = tos;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_pmtudisc(struct rt_link_getlink_req_dump *req,
							   __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.pmtudisc = 1;
	req->linkinfo.data.erspan.pmtudisc = pmtudisc;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_encap_limit(struct rt_link_getlink_req_dump *req,
							      __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_limit = 1;
	req->linkinfo.data.erspan.encap_limit = encap_limit;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_flowinfo(struct rt_link_getlink_req_dump *req,
							   __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.flowinfo = 1;
	req->linkinfo.data.erspan.flowinfo = flowinfo;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_flags(struct rt_link_getlink_req_dump *req,
							__u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.flags = 1;
	req->linkinfo.data.erspan.flags = flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_encap_type(struct rt_link_getlink_req_dump *req,
							     __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_type = 1;
	req->linkinfo.data.erspan.encap_type = encap_type;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_encap_flags(struct rt_link_getlink_req_dump *req,
							      __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_flags = 1;
	req->linkinfo.data.erspan.encap_flags = encap_flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_encap_sport(struct rt_link_getlink_req_dump *req,
							      __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_sport = 1;
	req->linkinfo.data.erspan.encap_sport = encap_sport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_encap_dport(struct rt_link_getlink_req_dump *req,
							      __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_dport = 1;
	req->linkinfo.data.erspan.encap_dport = encap_dport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_collect_metadata(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.collect_metadata = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_ignore_df(struct rt_link_getlink_req_dump *req,
							    __u8 ignore_df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.ignore_df = 1;
	req->linkinfo.data.erspan.ignore_df = ignore_df;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_fwmark(struct rt_link_getlink_req_dump *req,
							 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.fwmark = 1;
	req->linkinfo.data.erspan.fwmark = fwmark;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_erspan_index(struct rt_link_getlink_req_dump *req,
							       __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_index = 1;
	req->linkinfo.data.erspan.erspan_index = erspan_index;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_erspan_ver(struct rt_link_getlink_req_dump *req,
							     __u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_ver = 1;
	req->linkinfo.data.erspan.erspan_ver = erspan_ver;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_erspan_dir(struct rt_link_getlink_req_dump *req,
							     __u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_dir = 1;
	req->linkinfo.data.erspan.erspan_dir = erspan_dir;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_erspan_erspan_hwid(struct rt_link_getlink_req_dump *req,
							      __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_hwid = 1;
	req->linkinfo.data.erspan.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_link(struct rt_link_getlink_req_dump *req,
						    __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.link = 1;
	req->linkinfo.data.gre.link = link;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_iflags(struct rt_link_getlink_req_dump *req,
						      __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.iflags = 1;
	req->linkinfo.data.gre.iflags = iflags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_oflags(struct rt_link_getlink_req_dump *req,
						      __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.oflags = 1;
	req->linkinfo.data.gre.oflags = oflags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_ikey(struct rt_link_getlink_req_dump *req,
						    __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.ikey = 1;
	req->linkinfo.data.gre.ikey = ikey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_okey(struct rt_link_getlink_req_dump *req,
						    __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.okey = 1;
	req->linkinfo.data.gre.okey = okey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_local(struct rt_link_getlink_req_dump *req,
						     const void *local,
						     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	free(req->linkinfo.data.gre.local);
	req->linkinfo.data.gre._len.local = len;
	req->linkinfo.data.gre.local = malloc(req->linkinfo.data.gre._len.local);
	memcpy(req->linkinfo.data.gre.local, local, req->linkinfo.data.gre._len.local);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_remote(struct rt_link_getlink_req_dump *req,
						      const void *remote,
						      size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	free(req->linkinfo.data.gre.remote);
	req->linkinfo.data.gre._len.remote = len;
	req->linkinfo.data.gre.remote = malloc(req->linkinfo.data.gre._len.remote);
	memcpy(req->linkinfo.data.gre.remote, remote, req->linkinfo.data.gre._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_ttl(struct rt_link_getlink_req_dump *req,
						   __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.ttl = 1;
	req->linkinfo.data.gre.ttl = ttl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_tos(struct rt_link_getlink_req_dump *req,
						   __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.tos = 1;
	req->linkinfo.data.gre.tos = tos;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_pmtudisc(struct rt_link_getlink_req_dump *req,
							__u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.pmtudisc = 1;
	req->linkinfo.data.gre.pmtudisc = pmtudisc;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_encap_limit(struct rt_link_getlink_req_dump *req,
							   __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_limit = 1;
	req->linkinfo.data.gre.encap_limit = encap_limit;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_flowinfo(struct rt_link_getlink_req_dump *req,
							__u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.flowinfo = 1;
	req->linkinfo.data.gre.flowinfo = flowinfo;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_flags(struct rt_link_getlink_req_dump *req,
						     __u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.flags = 1;
	req->linkinfo.data.gre.flags = flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_encap_type(struct rt_link_getlink_req_dump *req,
							  __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_type = 1;
	req->linkinfo.data.gre.encap_type = encap_type;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_encap_flags(struct rt_link_getlink_req_dump *req,
							   __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_flags = 1;
	req->linkinfo.data.gre.encap_flags = encap_flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_encap_sport(struct rt_link_getlink_req_dump *req,
							   __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_sport = 1;
	req->linkinfo.data.gre.encap_sport = encap_sport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_encap_dport(struct rt_link_getlink_req_dump *req,
							   __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_dport = 1;
	req->linkinfo.data.gre.encap_dport = encap_dport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_collect_metadata(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.collect_metadata = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_ignore_df(struct rt_link_getlink_req_dump *req,
							 __u8 ignore_df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.ignore_df = 1;
	req->linkinfo.data.gre.ignore_df = ignore_df;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_fwmark(struct rt_link_getlink_req_dump *req,
						      __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.fwmark = 1;
	req->linkinfo.data.gre.fwmark = fwmark;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_erspan_index(struct rt_link_getlink_req_dump *req,
							    __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_index = 1;
	req->linkinfo.data.gre.erspan_index = erspan_index;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_erspan_ver(struct rt_link_getlink_req_dump *req,
							  __u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_ver = 1;
	req->linkinfo.data.gre.erspan_ver = erspan_ver;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_erspan_dir(struct rt_link_getlink_req_dump *req,
							  __u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_dir = 1;
	req->linkinfo.data.gre.erspan_dir = erspan_dir;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gre_erspan_hwid(struct rt_link_getlink_req_dump *req,
							   __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_hwid = 1;
	req->linkinfo.data.gre.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_link(struct rt_link_getlink_req_dump *req,
						       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.link = 1;
	req->linkinfo.data.gretap.link = link;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_iflags(struct rt_link_getlink_req_dump *req,
							 __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.iflags = 1;
	req->linkinfo.data.gretap.iflags = iflags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_oflags(struct rt_link_getlink_req_dump *req,
							 __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.oflags = 1;
	req->linkinfo.data.gretap.oflags = oflags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_ikey(struct rt_link_getlink_req_dump *req,
						       __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.ikey = 1;
	req->linkinfo.data.gretap.ikey = ikey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_okey(struct rt_link_getlink_req_dump *req,
						       __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.okey = 1;
	req->linkinfo.data.gretap.okey = okey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_local(struct rt_link_getlink_req_dump *req,
							const void *local,
							size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	free(req->linkinfo.data.gretap.local);
	req->linkinfo.data.gretap._len.local = len;
	req->linkinfo.data.gretap.local = malloc(req->linkinfo.data.gretap._len.local);
	memcpy(req->linkinfo.data.gretap.local, local, req->linkinfo.data.gretap._len.local);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_remote(struct rt_link_getlink_req_dump *req,
							 const void *remote,
							 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	free(req->linkinfo.data.gretap.remote);
	req->linkinfo.data.gretap._len.remote = len;
	req->linkinfo.data.gretap.remote = malloc(req->linkinfo.data.gretap._len.remote);
	memcpy(req->linkinfo.data.gretap.remote, remote, req->linkinfo.data.gretap._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_ttl(struct rt_link_getlink_req_dump *req,
						      __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.ttl = 1;
	req->linkinfo.data.gretap.ttl = ttl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_tos(struct rt_link_getlink_req_dump *req,
						      __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.tos = 1;
	req->linkinfo.data.gretap.tos = tos;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_pmtudisc(struct rt_link_getlink_req_dump *req,
							   __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.pmtudisc = 1;
	req->linkinfo.data.gretap.pmtudisc = pmtudisc;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_encap_limit(struct rt_link_getlink_req_dump *req,
							      __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_limit = 1;
	req->linkinfo.data.gretap.encap_limit = encap_limit;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_flowinfo(struct rt_link_getlink_req_dump *req,
							   __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.flowinfo = 1;
	req->linkinfo.data.gretap.flowinfo = flowinfo;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_flags(struct rt_link_getlink_req_dump *req,
							__u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.flags = 1;
	req->linkinfo.data.gretap.flags = flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_encap_type(struct rt_link_getlink_req_dump *req,
							     __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_type = 1;
	req->linkinfo.data.gretap.encap_type = encap_type;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_encap_flags(struct rt_link_getlink_req_dump *req,
							      __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_flags = 1;
	req->linkinfo.data.gretap.encap_flags = encap_flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_encap_sport(struct rt_link_getlink_req_dump *req,
							      __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_sport = 1;
	req->linkinfo.data.gretap.encap_sport = encap_sport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_encap_dport(struct rt_link_getlink_req_dump *req,
							      __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_dport = 1;
	req->linkinfo.data.gretap.encap_dport = encap_dport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_collect_metadata(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.collect_metadata = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_ignore_df(struct rt_link_getlink_req_dump *req,
							    __u8 ignore_df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.ignore_df = 1;
	req->linkinfo.data.gretap.ignore_df = ignore_df;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_fwmark(struct rt_link_getlink_req_dump *req,
							 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.fwmark = 1;
	req->linkinfo.data.gretap.fwmark = fwmark;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_erspan_index(struct rt_link_getlink_req_dump *req,
							       __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_index = 1;
	req->linkinfo.data.gretap.erspan_index = erspan_index;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_erspan_ver(struct rt_link_getlink_req_dump *req,
							     __u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_ver = 1;
	req->linkinfo.data.gretap.erspan_ver = erspan_ver;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_erspan_dir(struct rt_link_getlink_req_dump *req,
							     __u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_dir = 1;
	req->linkinfo.data.gretap.erspan_dir = erspan_dir;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_gretap_erspan_hwid(struct rt_link_getlink_req_dump *req,
							      __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_hwid = 1;
	req->linkinfo.data.gretap.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_link(struct rt_link_getlink_req_dump *req,
						       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.link = 1;
	req->linkinfo.data.ip6gre.link = link;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_iflags(struct rt_link_getlink_req_dump *req,
							 __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.iflags = 1;
	req->linkinfo.data.ip6gre.iflags = iflags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_oflags(struct rt_link_getlink_req_dump *req,
							 __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.oflags = 1;
	req->linkinfo.data.ip6gre.oflags = oflags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_ikey(struct rt_link_getlink_req_dump *req,
						       __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.ikey = 1;
	req->linkinfo.data.ip6gre.ikey = ikey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_okey(struct rt_link_getlink_req_dump *req,
						       __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.okey = 1;
	req->linkinfo.data.ip6gre.okey = okey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_local(struct rt_link_getlink_req_dump *req,
							const void *local,
							size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	free(req->linkinfo.data.ip6gre.local);
	req->linkinfo.data.ip6gre._len.local = len;
	req->linkinfo.data.ip6gre.local = malloc(req->linkinfo.data.ip6gre._len.local);
	memcpy(req->linkinfo.data.ip6gre.local, local, req->linkinfo.data.ip6gre._len.local);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_remote(struct rt_link_getlink_req_dump *req,
							 const void *remote,
							 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	free(req->linkinfo.data.ip6gre.remote);
	req->linkinfo.data.ip6gre._len.remote = len;
	req->linkinfo.data.ip6gre.remote = malloc(req->linkinfo.data.ip6gre._len.remote);
	memcpy(req->linkinfo.data.ip6gre.remote, remote, req->linkinfo.data.ip6gre._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_ttl(struct rt_link_getlink_req_dump *req,
						      __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.ttl = 1;
	req->linkinfo.data.ip6gre.ttl = ttl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_encap_limit(struct rt_link_getlink_req_dump *req,
							      __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_limit = 1;
	req->linkinfo.data.ip6gre.encap_limit = encap_limit;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_flowinfo(struct rt_link_getlink_req_dump *req,
							   __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.flowinfo = 1;
	req->linkinfo.data.ip6gre.flowinfo = flowinfo;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_flags(struct rt_link_getlink_req_dump *req,
							__u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.flags = 1;
	req->linkinfo.data.ip6gre.flags = flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_encap_type(struct rt_link_getlink_req_dump *req,
							     __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_type = 1;
	req->linkinfo.data.ip6gre.encap_type = encap_type;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_encap_flags(struct rt_link_getlink_req_dump *req,
							      __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_flags = 1;
	req->linkinfo.data.ip6gre.encap_flags = encap_flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_encap_sport(struct rt_link_getlink_req_dump *req,
							      __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_sport = 1;
	req->linkinfo.data.ip6gre.encap_sport = encap_sport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_encap_dport(struct rt_link_getlink_req_dump *req,
							      __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_dport = 1;
	req->linkinfo.data.ip6gre.encap_dport = encap_dport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_collect_metadata(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.collect_metadata = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_fwmark(struct rt_link_getlink_req_dump *req,
							 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.fwmark = 1;
	req->linkinfo.data.ip6gre.fwmark = fwmark;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_erspan_index(struct rt_link_getlink_req_dump *req,
							       __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_index = 1;
	req->linkinfo.data.ip6gre.erspan_index = erspan_index;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_erspan_ver(struct rt_link_getlink_req_dump *req,
							     __u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_ver = 1;
	req->linkinfo.data.ip6gre.erspan_ver = erspan_ver;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_erspan_dir(struct rt_link_getlink_req_dump *req,
							     __u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_dir = 1;
	req->linkinfo.data.ip6gre.erspan_dir = erspan_dir;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6gre_erspan_hwid(struct rt_link_getlink_req_dump *req,
							      __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_hwid = 1;
	req->linkinfo.data.ip6gre.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_id(struct rt_link_getlink_req_dump *req,
						     __u32 id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.id = 1;
	req->linkinfo.data.geneve.id = id;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_remote(struct rt_link_getlink_req_dump *req,
							 const void *remote,
							 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	free(req->linkinfo.data.geneve.remote);
	req->linkinfo.data.geneve._len.remote = len;
	req->linkinfo.data.geneve.remote = malloc(req->linkinfo.data.geneve._len.remote);
	memcpy(req->linkinfo.data.geneve.remote, remote, req->linkinfo.data.geneve._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_ttl(struct rt_link_getlink_req_dump *req,
						      __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.ttl = 1;
	req->linkinfo.data.geneve.ttl = ttl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_tos(struct rt_link_getlink_req_dump *req,
						      __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.tos = 1;
	req->linkinfo.data.geneve.tos = tos;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_port(struct rt_link_getlink_req_dump *req,
						       __u16 port /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.port = 1;
	req->linkinfo.data.geneve.port = port;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_collect_metadata(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.collect_metadata = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_remote6(struct rt_link_getlink_req_dump *req,
							  const void *remote6,
							  size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	free(req->linkinfo.data.geneve.remote6);
	req->linkinfo.data.geneve._len.remote6 = len;
	req->linkinfo.data.geneve.remote6 = malloc(req->linkinfo.data.geneve._len.remote6);
	memcpy(req->linkinfo.data.geneve.remote6, remote6, req->linkinfo.data.geneve._len.remote6);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_udp_csum(struct rt_link_getlink_req_dump *req,
							   __u8 udp_csum)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.udp_csum = 1;
	req->linkinfo.data.geneve.udp_csum = udp_csum;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_udp_zero_csum6_tx(struct rt_link_getlink_req_dump *req,
								    __u8 udp_zero_csum6_tx)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.udp_zero_csum6_tx = 1;
	req->linkinfo.data.geneve.udp_zero_csum6_tx = udp_zero_csum6_tx;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_udp_zero_csum6_rx(struct rt_link_getlink_req_dump *req,
								    __u8 udp_zero_csum6_rx)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.udp_zero_csum6_rx = 1;
	req->linkinfo.data.geneve.udp_zero_csum6_rx = udp_zero_csum6_rx;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_label(struct rt_link_getlink_req_dump *req,
							__u32 label /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.label = 1;
	req->linkinfo.data.geneve.label = label;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_ttl_inherit(struct rt_link_getlink_req_dump *req,
							      __u8 ttl_inherit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.ttl_inherit = 1;
	req->linkinfo.data.geneve.ttl_inherit = ttl_inherit;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_df(struct rt_link_getlink_req_dump *req,
						     __u8 df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.df = 1;
	req->linkinfo.data.geneve.df = df;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_inner_proto_inherit(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.inner_proto_inherit = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_geneve_port_range(struct rt_link_getlink_req_dump *req,
							     const void *port_range,
							     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	free(req->linkinfo.data.geneve.port_range);
	req->linkinfo.data.geneve._len.port_range = len;
	req->linkinfo.data.geneve.port_range = malloc(req->linkinfo.data.geneve._len.port_range);
	memcpy(req->linkinfo.data.geneve.port_range, port_range, req->linkinfo.data.geneve._len.port_range);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_link(struct rt_link_getlink_req_dump *req,
						     __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.link = 1;
	req->linkinfo.data.ipip.link = link;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_local(struct rt_link_getlink_req_dump *req,
						      const void *local,
						      size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip.local);
	req->linkinfo.data.ipip._len.local = len;
	req->linkinfo.data.ipip.local = malloc(req->linkinfo.data.ipip._len.local);
	memcpy(req->linkinfo.data.ipip.local, local, req->linkinfo.data.ipip._len.local);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_remote(struct rt_link_getlink_req_dump *req,
						       const void *remote,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip.remote);
	req->linkinfo.data.ipip._len.remote = len;
	req->linkinfo.data.ipip.remote = malloc(req->linkinfo.data.ipip._len.remote);
	memcpy(req->linkinfo.data.ipip.remote, remote, req->linkinfo.data.ipip._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_ttl(struct rt_link_getlink_req_dump *req,
						    __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.ttl = 1;
	req->linkinfo.data.ipip.ttl = ttl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_tos(struct rt_link_getlink_req_dump *req,
						    __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.tos = 1;
	req->linkinfo.data.ipip.tos = tos;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_encap_limit(struct rt_link_getlink_req_dump *req,
							    __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_limit = 1;
	req->linkinfo.data.ipip.encap_limit = encap_limit;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_flowinfo(struct rt_link_getlink_req_dump *req,
							 __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.flowinfo = 1;
	req->linkinfo.data.ipip.flowinfo = flowinfo;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_flags(struct rt_link_getlink_req_dump *req,
						      __u16 flags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.flags = 1;
	req->linkinfo.data.ipip.flags = flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_proto(struct rt_link_getlink_req_dump *req,
						      __u8 proto)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.proto = 1;
	req->linkinfo.data.ipip.proto = proto;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_pmtudisc(struct rt_link_getlink_req_dump *req,
							 __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.pmtudisc = 1;
	req->linkinfo.data.ipip.pmtudisc = pmtudisc;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip__6rd_prefix(struct rt_link_getlink_req_dump *req,
							    const void *_6rd_prefix,
							    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip._6rd_prefix);
	req->linkinfo.data.ipip._len._6rd_prefix = len;
	req->linkinfo.data.ipip._6rd_prefix = malloc(req->linkinfo.data.ipip._len._6rd_prefix);
	memcpy(req->linkinfo.data.ipip._6rd_prefix, _6rd_prefix, req->linkinfo.data.ipip._len._6rd_prefix);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip__6rd_relay_prefix(struct rt_link_getlink_req_dump *req,
								  const void *_6rd_relay_prefix,
								  size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip._6rd_relay_prefix);
	req->linkinfo.data.ipip._len._6rd_relay_prefix = len;
	req->linkinfo.data.ipip._6rd_relay_prefix = malloc(req->linkinfo.data.ipip._len._6rd_relay_prefix);
	memcpy(req->linkinfo.data.ipip._6rd_relay_prefix, _6rd_relay_prefix, req->linkinfo.data.ipip._len._6rd_relay_prefix);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip__6rd_prefixlen(struct rt_link_getlink_req_dump *req,
							       __u16 _6rd_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present._6rd_prefixlen = 1;
	req->linkinfo.data.ipip._6rd_prefixlen = _6rd_prefixlen;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip__6rd_relay_prefixlen(struct rt_link_getlink_req_dump *req,
								     __u16 _6rd_relay_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present._6rd_relay_prefixlen = 1;
	req->linkinfo.data.ipip._6rd_relay_prefixlen = _6rd_relay_prefixlen;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_encap_type(struct rt_link_getlink_req_dump *req,
							   __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_type = 1;
	req->linkinfo.data.ipip.encap_type = encap_type;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_encap_flags(struct rt_link_getlink_req_dump *req,
							    __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_flags = 1;
	req->linkinfo.data.ipip.encap_flags = encap_flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_encap_sport(struct rt_link_getlink_req_dump *req,
							    __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_sport = 1;
	req->linkinfo.data.ipip.encap_sport = encap_sport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_encap_dport(struct rt_link_getlink_req_dump *req,
							    __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_dport = 1;
	req->linkinfo.data.ipip.encap_dport = encap_dport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_collect_metadata(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.collect_metadata = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ipip_fwmark(struct rt_link_getlink_req_dump *req,
						       __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.fwmark = 1;
	req->linkinfo.data.ipip.fwmark = fwmark;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_link(struct rt_link_getlink_req_dump *req,
						       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.link = 1;
	req->linkinfo.data.ip6tnl.link = link;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_local(struct rt_link_getlink_req_dump *req,
							const void *local,
							size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	free(req->linkinfo.data.ip6tnl.local);
	req->linkinfo.data.ip6tnl._len.local = len;
	req->linkinfo.data.ip6tnl.local = malloc(req->linkinfo.data.ip6tnl._len.local);
	memcpy(req->linkinfo.data.ip6tnl.local, local, req->linkinfo.data.ip6tnl._len.local);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_remote(struct rt_link_getlink_req_dump *req,
							 const void *remote,
							 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	free(req->linkinfo.data.ip6tnl.remote);
	req->linkinfo.data.ip6tnl._len.remote = len;
	req->linkinfo.data.ip6tnl.remote = malloc(req->linkinfo.data.ip6tnl._len.remote);
	memcpy(req->linkinfo.data.ip6tnl.remote, remote, req->linkinfo.data.ip6tnl._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_ttl(struct rt_link_getlink_req_dump *req,
						      __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.ttl = 1;
	req->linkinfo.data.ip6tnl.ttl = ttl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_encap_limit(struct rt_link_getlink_req_dump *req,
							      __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_limit = 1;
	req->linkinfo.data.ip6tnl.encap_limit = encap_limit;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_flowinfo(struct rt_link_getlink_req_dump *req,
							   __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.flowinfo = 1;
	req->linkinfo.data.ip6tnl.flowinfo = flowinfo;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_flags(struct rt_link_getlink_req_dump *req,
							__u32 flags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.flags = 1;
	req->linkinfo.data.ip6tnl.flags = flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_proto(struct rt_link_getlink_req_dump *req,
							__u8 proto)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.proto = 1;
	req->linkinfo.data.ip6tnl.proto = proto;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_encap_type(struct rt_link_getlink_req_dump *req,
							     __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_type = 1;
	req->linkinfo.data.ip6tnl.encap_type = encap_type;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_encap_flags(struct rt_link_getlink_req_dump *req,
							      __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_flags = 1;
	req->linkinfo.data.ip6tnl.encap_flags = encap_flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_encap_sport(struct rt_link_getlink_req_dump *req,
							      __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_sport = 1;
	req->linkinfo.data.ip6tnl.encap_sport = encap_sport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_encap_dport(struct rt_link_getlink_req_dump *req,
							      __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_dport = 1;
	req->linkinfo.data.ip6tnl.encap_dport = encap_dport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_collect_metadata(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.collect_metadata = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ip6tnl_fwmark(struct rt_link_getlink_req_dump *req,
							 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.fwmark = 1;
	req->linkinfo.data.ip6tnl.fwmark = fwmark;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_link(struct rt_link_getlink_req_dump *req,
						    __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.link = 1;
	req->linkinfo.data.sit.link = link;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_local(struct rt_link_getlink_req_dump *req,
						     const void *local,
						     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit.local);
	req->linkinfo.data.sit._len.local = len;
	req->linkinfo.data.sit.local = malloc(req->linkinfo.data.sit._len.local);
	memcpy(req->linkinfo.data.sit.local, local, req->linkinfo.data.sit._len.local);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_remote(struct rt_link_getlink_req_dump *req,
						      const void *remote,
						      size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit.remote);
	req->linkinfo.data.sit._len.remote = len;
	req->linkinfo.data.sit.remote = malloc(req->linkinfo.data.sit._len.remote);
	memcpy(req->linkinfo.data.sit.remote, remote, req->linkinfo.data.sit._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_ttl(struct rt_link_getlink_req_dump *req,
						   __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.ttl = 1;
	req->linkinfo.data.sit.ttl = ttl;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_tos(struct rt_link_getlink_req_dump *req,
						   __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.tos = 1;
	req->linkinfo.data.sit.tos = tos;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_encap_limit(struct rt_link_getlink_req_dump *req,
							   __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_limit = 1;
	req->linkinfo.data.sit.encap_limit = encap_limit;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_flowinfo(struct rt_link_getlink_req_dump *req,
							__u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.flowinfo = 1;
	req->linkinfo.data.sit.flowinfo = flowinfo;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_flags(struct rt_link_getlink_req_dump *req,
						     __u16 flags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.flags = 1;
	req->linkinfo.data.sit.flags = flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_proto(struct rt_link_getlink_req_dump *req,
						     __u8 proto)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.proto = 1;
	req->linkinfo.data.sit.proto = proto;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_pmtudisc(struct rt_link_getlink_req_dump *req,
							__u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.pmtudisc = 1;
	req->linkinfo.data.sit.pmtudisc = pmtudisc;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit__6rd_prefix(struct rt_link_getlink_req_dump *req,
							   const void *_6rd_prefix,
							   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit._6rd_prefix);
	req->linkinfo.data.sit._len._6rd_prefix = len;
	req->linkinfo.data.sit._6rd_prefix = malloc(req->linkinfo.data.sit._len._6rd_prefix);
	memcpy(req->linkinfo.data.sit._6rd_prefix, _6rd_prefix, req->linkinfo.data.sit._len._6rd_prefix);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit__6rd_relay_prefix(struct rt_link_getlink_req_dump *req,
								 const void *_6rd_relay_prefix,
								 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit._6rd_relay_prefix);
	req->linkinfo.data.sit._len._6rd_relay_prefix = len;
	req->linkinfo.data.sit._6rd_relay_prefix = malloc(req->linkinfo.data.sit._len._6rd_relay_prefix);
	memcpy(req->linkinfo.data.sit._6rd_relay_prefix, _6rd_relay_prefix, req->linkinfo.data.sit._len._6rd_relay_prefix);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit__6rd_prefixlen(struct rt_link_getlink_req_dump *req,
							      __u16 _6rd_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present._6rd_prefixlen = 1;
	req->linkinfo.data.sit._6rd_prefixlen = _6rd_prefixlen;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit__6rd_relay_prefixlen(struct rt_link_getlink_req_dump *req,
								    __u16 _6rd_relay_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present._6rd_relay_prefixlen = 1;
	req->linkinfo.data.sit._6rd_relay_prefixlen = _6rd_relay_prefixlen;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_encap_type(struct rt_link_getlink_req_dump *req,
							  __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_type = 1;
	req->linkinfo.data.sit.encap_type = encap_type;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_encap_flags(struct rt_link_getlink_req_dump *req,
							   __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_flags = 1;
	req->linkinfo.data.sit.encap_flags = encap_flags;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_encap_sport(struct rt_link_getlink_req_dump *req,
							   __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_sport = 1;
	req->linkinfo.data.sit.encap_sport = encap_sport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_encap_dport(struct rt_link_getlink_req_dump *req,
							   __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_dport = 1;
	req->linkinfo.data.sit.encap_dport = encap_dport;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_collect_metadata(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.collect_metadata = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_sit_fwmark(struct rt_link_getlink_req_dump *req,
						      __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.fwmark = 1;
	req->linkinfo.data.sit.fwmark = fwmark;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_tun_owner(struct rt_link_getlink_req_dump *req,
						     __u32 owner)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.owner = 1;
	req->linkinfo.data.tun.owner = owner;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_tun_group(struct rt_link_getlink_req_dump *req,
						     __u32 group)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.group = 1;
	req->linkinfo.data.tun.group = group;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_tun_type(struct rt_link_getlink_req_dump *req,
						    __u8 type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.type = 1;
	req->linkinfo.data.tun.type = type;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_tun_pi(struct rt_link_getlink_req_dump *req,
						  __u8 pi)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.pi = 1;
	req->linkinfo.data.tun.pi = pi;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_tun_vnet_hdr(struct rt_link_getlink_req_dump *req,
							__u8 vnet_hdr)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.vnet_hdr = 1;
	req->linkinfo.data.tun.vnet_hdr = vnet_hdr;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_tun_persist(struct rt_link_getlink_req_dump *req,
						       __u8 persist)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.persist = 1;
	req->linkinfo.data.tun.persist = persist;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_tun_multi_queue(struct rt_link_getlink_req_dump *req,
							   __u8 multi_queue)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.multi_queue = 1;
	req->linkinfo.data.tun.multi_queue = multi_queue;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_tun_num_queues(struct rt_link_getlink_req_dump *req,
							  __u32 num_queues)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.num_queues = 1;
	req->linkinfo.data.tun.num_queues = num_queues;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_tun_num_disabled_queues(struct rt_link_getlink_req_dump *req,
								   __u32 num_disabled_queues)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.num_disabled_queues = 1;
	req->linkinfo.data.tun.num_disabled_queues = num_disabled_queues;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vlan_id(struct rt_link_getlink_req_dump *req,
						   __u16 id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.id = 1;
	req->linkinfo.data.vlan.id = id;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vlan_flags(struct rt_link_getlink_req_dump *req,
						      const void *flags,
						      size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	free(req->linkinfo.data.vlan.flags);
	req->linkinfo.data.vlan._len.flags = len;
	req->linkinfo.data.vlan.flags = malloc(req->linkinfo.data.vlan._len.flags);
	memcpy(req->linkinfo.data.vlan.flags, flags, req->linkinfo.data.vlan._len.flags);
}
static inline void
__rt_link_getlink_req_dump_set_linkinfo_data_vlan_egress_qos_mapping(struct rt_link_getlink_req_dump *req,
								     struct ifla_vlan_qos_mapping *mapping,
								     unsigned int n_mapping)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.egress_qos = 1;
	free(req->linkinfo.data.vlan.egress_qos.mapping);
	req->linkinfo.data.vlan.egress_qos.mapping = mapping;
	req->linkinfo.data.vlan.egress_qos._count.mapping = n_mapping;
}
static inline void
__rt_link_getlink_req_dump_set_linkinfo_data_vlan_ingress_qos_mapping(struct rt_link_getlink_req_dump *req,
								      struct ifla_vlan_qos_mapping *mapping,
								      unsigned int n_mapping)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.ingress_qos = 1;
	free(req->linkinfo.data.vlan.ingress_qos.mapping);
	req->linkinfo.data.vlan.ingress_qos.mapping = mapping;
	req->linkinfo.data.vlan.ingress_qos._count.mapping = n_mapping;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vlan_protocol(struct rt_link_getlink_req_dump *req,
							 int protocol /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.protocol = 1;
	req->linkinfo.data.vlan.protocol = protocol;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vrf_table(struct rt_link_getlink_req_dump *req,
						     __u32 table)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vrf = 1;
	req->linkinfo.data.vrf._present.table = 1;
	req->linkinfo.data.vrf.table = table;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti_link(struct rt_link_getlink_req_dump *req,
						    __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.link = 1;
	req->linkinfo.data.vti.link = link;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti_ikey(struct rt_link_getlink_req_dump *req,
						    __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.ikey = 1;
	req->linkinfo.data.vti.ikey = ikey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti_okey(struct rt_link_getlink_req_dump *req,
						    __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.okey = 1;
	req->linkinfo.data.vti.okey = okey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti_local(struct rt_link_getlink_req_dump *req,
						     const void *local,
						     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	free(req->linkinfo.data.vti.local);
	req->linkinfo.data.vti._len.local = len;
	req->linkinfo.data.vti.local = malloc(req->linkinfo.data.vti._len.local);
	memcpy(req->linkinfo.data.vti.local, local, req->linkinfo.data.vti._len.local);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti_remote(struct rt_link_getlink_req_dump *req,
						      const void *remote,
						      size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	free(req->linkinfo.data.vti.remote);
	req->linkinfo.data.vti._len.remote = len;
	req->linkinfo.data.vti.remote = malloc(req->linkinfo.data.vti._len.remote);
	memcpy(req->linkinfo.data.vti.remote, remote, req->linkinfo.data.vti._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti_fwmark(struct rt_link_getlink_req_dump *req,
						      __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.fwmark = 1;
	req->linkinfo.data.vti.fwmark = fwmark;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti6_link(struct rt_link_getlink_req_dump *req,
						     __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.link = 1;
	req->linkinfo.data.vti6.link = link;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti6_ikey(struct rt_link_getlink_req_dump *req,
						     __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.ikey = 1;
	req->linkinfo.data.vti6.ikey = ikey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti6_okey(struct rt_link_getlink_req_dump *req,
						     __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.okey = 1;
	req->linkinfo.data.vti6.okey = okey;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti6_local(struct rt_link_getlink_req_dump *req,
						      const void *local,
						      size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	free(req->linkinfo.data.vti6.local);
	req->linkinfo.data.vti6._len.local = len;
	req->linkinfo.data.vti6.local = malloc(req->linkinfo.data.vti6._len.local);
	memcpy(req->linkinfo.data.vti6.local, local, req->linkinfo.data.vti6._len.local);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti6_remote(struct rt_link_getlink_req_dump *req,
						       const void *remote,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	free(req->linkinfo.data.vti6.remote);
	req->linkinfo.data.vti6._len.remote = len;
	req->linkinfo.data.vti6.remote = malloc(req->linkinfo.data.vti6._len.remote);
	memcpy(req->linkinfo.data.vti6.remote, remote, req->linkinfo.data.vti6._len.remote);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_vti6_fwmark(struct rt_link_getlink_req_dump *req,
						       __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.fwmark = 1;
	req->linkinfo.data.vti6.fwmark = fwmark;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_netkit_peer_info(struct rt_link_getlink_req_dump *req,
							    const void *peer_info,
							    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	free(req->linkinfo.data.netkit.peer_info);
	req->linkinfo.data.netkit._len.peer_info = len;
	req->linkinfo.data.netkit.peer_info = malloc(req->linkinfo.data.netkit._len.peer_info);
	memcpy(req->linkinfo.data.netkit.peer_info, peer_info, req->linkinfo.data.netkit._len.peer_info);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_netkit_primary(struct rt_link_getlink_req_dump *req,
							  __u8 primary)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.primary = 1;
	req->linkinfo.data.netkit.primary = primary;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_netkit_policy(struct rt_link_getlink_req_dump *req,
							 int policy)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.policy = 1;
	req->linkinfo.data.netkit.policy = policy;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_netkit_peer_policy(struct rt_link_getlink_req_dump *req,
							      int peer_policy)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.peer_policy = 1;
	req->linkinfo.data.netkit.peer_policy = peer_policy;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_netkit_mode(struct rt_link_getlink_req_dump *req,
						       enum netkit_mode mode)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.mode = 1;
	req->linkinfo.data.netkit.mode = mode;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_netkit_scrub(struct rt_link_getlink_req_dump *req,
							int scrub)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.scrub = 1;
	req->linkinfo.data.netkit.scrub = scrub;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_netkit_peer_scrub(struct rt_link_getlink_req_dump *req,
							     int peer_scrub)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.peer_scrub = 1;
	req->linkinfo.data.netkit.peer_scrub = peer_scrub;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_netkit_headroom(struct rt_link_getlink_req_dump *req,
							   __u16 headroom)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.headroom = 1;
	req->linkinfo.data.netkit.headroom = headroom;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_netkit_tailroom(struct rt_link_getlink_req_dump *req,
							   __u16 tailroom)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.tailroom = 1;
	req->linkinfo.data.netkit.tailroom = tailroom;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_data_ovpn_mode(struct rt_link_getlink_req_dump *req,
						     enum ovpn_mode mode)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ovpn = 1;
	req->linkinfo.data.ovpn._present.mode = 1;
	req->linkinfo.data.ovpn.mode = mode;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_xstats(struct rt_link_getlink_req_dump *req,
					     const void *xstats, size_t len)
{
	req->_present.linkinfo = 1;
	free(req->linkinfo.xstats);
	req->linkinfo._len.xstats = len;
	req->linkinfo.xstats = malloc(req->linkinfo._len.xstats);
	memcpy(req->linkinfo.xstats, xstats, req->linkinfo._len.xstats);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_kind(struct rt_link_getlink_req_dump *req,
						 const char *slave_kind)
{
	req->_present.linkinfo = 1;
	free(req->linkinfo.slave_kind);
	req->linkinfo._len.slave_kind = strlen(slave_kind);
	req->linkinfo.slave_kind = malloc(req->linkinfo._len.slave_kind + 1);
	memcpy(req->linkinfo.slave_kind, slave_kind, req->linkinfo._len.slave_kind);
	req->linkinfo.slave_kind[req->linkinfo._len.slave_kind] = 0;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_state(struct rt_link_getlink_req_dump *req,
							      __u8 state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.state = 1;
	req->linkinfo.slave_data.bridge.state = state;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_priority(struct rt_link_getlink_req_dump *req,
								 __u16 priority)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.priority = 1;
	req->linkinfo.slave_data.bridge.priority = priority;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_cost(struct rt_link_getlink_req_dump *req,
							     __u32 cost)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.cost = 1;
	req->linkinfo.slave_data.bridge.cost = cost;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mode(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mode = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_guard(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.guard = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_protect(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.protect = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_fast_leave(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.fast_leave = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_learning(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.learning = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_unicast_flood(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.unicast_flood = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_proxyarp(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.proxyarp = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_learning_sync(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.learning_sync = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_proxyarp_wifi(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.proxyarp_wifi = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_root_id(struct rt_link_getlink_req_dump *req,
								const void *root_id,
								size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	free(req->linkinfo.slave_data.bridge.root_id);
	req->linkinfo.slave_data.bridge._len.root_id = len;
	req->linkinfo.slave_data.bridge.root_id = malloc(req->linkinfo.slave_data.bridge._len.root_id);
	memcpy(req->linkinfo.slave_data.bridge.root_id, root_id, req->linkinfo.slave_data.bridge._len.root_id);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_bridge_id(struct rt_link_getlink_req_dump *req,
								  const void *bridge_id,
								  size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	free(req->linkinfo.slave_data.bridge.bridge_id);
	req->linkinfo.slave_data.bridge._len.bridge_id = len;
	req->linkinfo.slave_data.bridge.bridge_id = malloc(req->linkinfo.slave_data.bridge._len.bridge_id);
	memcpy(req->linkinfo.slave_data.bridge.bridge_id, bridge_id, req->linkinfo.slave_data.bridge._len.bridge_id);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_designated_port(struct rt_link_getlink_req_dump *req,
									__u16 designated_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.designated_port = 1;
	req->linkinfo.slave_data.bridge.designated_port = designated_port;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_designated_cost(struct rt_link_getlink_req_dump *req,
									__u16 designated_cost)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.designated_cost = 1;
	req->linkinfo.slave_data.bridge.designated_cost = designated_cost;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_id(struct rt_link_getlink_req_dump *req,
							   __u16 id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.id = 1;
	req->linkinfo.slave_data.bridge.id = id;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_no(struct rt_link_getlink_req_dump *req,
							   __u16 no)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.no = 1;
	req->linkinfo.slave_data.bridge.no = no;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_topology_change_ack(struct rt_link_getlink_req_dump *req,
									    __u8 topology_change_ack)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.topology_change_ack = 1;
	req->linkinfo.slave_data.bridge.topology_change_ack = topology_change_ack;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_config_pending(struct rt_link_getlink_req_dump *req,
								       __u8 config_pending)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.config_pending = 1;
	req->linkinfo.slave_data.bridge.config_pending = config_pending;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_message_age_timer(struct rt_link_getlink_req_dump *req,
									  __u64 message_age_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.message_age_timer = 1;
	req->linkinfo.slave_data.bridge.message_age_timer = message_age_timer;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_forward_delay_timer(struct rt_link_getlink_req_dump *req,
									    __u64 forward_delay_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.forward_delay_timer = 1;
	req->linkinfo.slave_data.bridge.forward_delay_timer = forward_delay_timer;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_hold_timer(struct rt_link_getlink_req_dump *req,
								   __u64 hold_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.hold_timer = 1;
	req->linkinfo.slave_data.bridge.hold_timer = hold_timer;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_flush(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.flush = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_multicast_router(struct rt_link_getlink_req_dump *req,
									 __u8 multicast_router)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.multicast_router = 1;
	req->linkinfo.slave_data.bridge.multicast_router = multicast_router;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mcast_flood(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_flood = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mcast_to_ucast(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_to_ucast = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_vlan_tunnel(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.vlan_tunnel = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_bcast_flood(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.bcast_flood = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_group_fwd_mask(struct rt_link_getlink_req_dump *req,
								       __u16 group_fwd_mask)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.group_fwd_mask = 1;
	req->linkinfo.slave_data.bridge.group_fwd_mask = group_fwd_mask;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_neigh_suppress(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.neigh_suppress = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_isolated(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.isolated = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_backup_port(struct rt_link_getlink_req_dump *req,
								    __u32 backup_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.backup_port = 1;
	req->linkinfo.slave_data.bridge.backup_port = backup_port;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mrp_ring_open(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mrp_ring_open = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mrp_in_open(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mrp_in_open = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mcast_eht_hosts_limit(struct rt_link_getlink_req_dump *req,
									      __u32 mcast_eht_hosts_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_eht_hosts_limit = 1;
	req->linkinfo.slave_data.bridge.mcast_eht_hosts_limit = mcast_eht_hosts_limit;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mcast_eht_hosts_cnt(struct rt_link_getlink_req_dump *req,
									    __u32 mcast_eht_hosts_cnt)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_eht_hosts_cnt = 1;
	req->linkinfo.slave_data.bridge.mcast_eht_hosts_cnt = mcast_eht_hosts_cnt;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_locked(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.locked = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mab(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mab = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mcast_n_groups(struct rt_link_getlink_req_dump *req,
								       __u32 mcast_n_groups)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_n_groups = 1;
	req->linkinfo.slave_data.bridge.mcast_n_groups = mcast_n_groups;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_mcast_max_groups(struct rt_link_getlink_req_dump *req,
									 __u32 mcast_max_groups)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_max_groups = 1;
	req->linkinfo.slave_data.bridge.mcast_max_groups = mcast_max_groups;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_neigh_vlan_suppress(struct rt_link_getlink_req_dump *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.neigh_vlan_suppress = 1;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bridge_backup_nhid(struct rt_link_getlink_req_dump *req,
								    __u32 backup_nhid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.backup_nhid = 1;
	req->linkinfo.slave_data.bridge.backup_nhid = backup_nhid;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bond_state(struct rt_link_getlink_req_dump *req,
							    __u8 state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.state = 1;
	req->linkinfo.slave_data.bond.state = state;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bond_mii_status(struct rt_link_getlink_req_dump *req,
								 __u8 mii_status)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.mii_status = 1;
	req->linkinfo.slave_data.bond.mii_status = mii_status;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bond_link_failure_count(struct rt_link_getlink_req_dump *req,
									 __u32 link_failure_count)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.link_failure_count = 1;
	req->linkinfo.slave_data.bond.link_failure_count = link_failure_count;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bond_perm_hwaddr(struct rt_link_getlink_req_dump *req,
								  const void *perm_hwaddr,
								  size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	free(req->linkinfo.slave_data.bond.perm_hwaddr);
	req->linkinfo.slave_data.bond._len.perm_hwaddr = len;
	req->linkinfo.slave_data.bond.perm_hwaddr = malloc(req->linkinfo.slave_data.bond._len.perm_hwaddr);
	memcpy(req->linkinfo.slave_data.bond.perm_hwaddr, perm_hwaddr, req->linkinfo.slave_data.bond._len.perm_hwaddr);
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bond_queue_id(struct rt_link_getlink_req_dump *req,
							       __u16 queue_id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.queue_id = 1;
	req->linkinfo.slave_data.bond.queue_id = queue_id;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bond_ad_aggregator_id(struct rt_link_getlink_req_dump *req,
								       __u16 ad_aggregator_id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.ad_aggregator_id = 1;
	req->linkinfo.slave_data.bond.ad_aggregator_id = ad_aggregator_id;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bond_ad_actor_oper_port_state(struct rt_link_getlink_req_dump *req,
									       __u8 ad_actor_oper_port_state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.ad_actor_oper_port_state = 1;
	req->linkinfo.slave_data.bond.ad_actor_oper_port_state = ad_actor_oper_port_state;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bond_ad_partner_oper_port_state(struct rt_link_getlink_req_dump *req,
										 __u16 ad_partner_oper_port_state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.ad_partner_oper_port_state = 1;
	req->linkinfo.slave_data.bond.ad_partner_oper_port_state = ad_partner_oper_port_state;
}
static inline void
rt_link_getlink_req_dump_set_linkinfo_slave_data_bond_prio(struct rt_link_getlink_req_dump *req,
							   __u32 prio)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.prio = 1;
	req->linkinfo.slave_data.bond.prio = prio;
}

struct rt_link_getlink_list {
	struct rt_link_getlink_list *next;
	struct rt_link_getlink_rsp obj __attribute__((aligned(8)));
};

void rt_link_getlink_list_free(struct rt_link_getlink_list *rsp);

struct rt_link_getlink_list *
rt_link_getlink_dump(struct ynl_sock *ys, struct rt_link_getlink_req_dump *req);

/* RTM_GETLINK - notify */
struct rt_link_getlink_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type *next;
	void (*free)(struct rt_link_getlink_ntf *ntf);
	struct rt_link_getlink_rsp obj __attribute__((aligned(8)));
};

void rt_link_getlink_ntf_free(struct rt_link_getlink_ntf *rsp);

/* ============== RTM_SETLINK ============== */
/* RTM_SETLINK - do */
struct rt_link_setlink_req {
	__u16 _nlmsg_flags;

	struct ifinfomsg _hdr;

	struct {
		__u32 mtu:1;
		__u32 link:1;
		__u32 master:1;
		__u32 txqlen:1;
		__u32 weight:1;
		__u32 operstate:1;
		__u32 linkmode:1;
		__u32 linkinfo:1;
		__u32 net_ns_pid:1;
		__u32 num_vf:1;
		__u32 vfinfo_list:1;
		__u32 vf_ports:1;
		__u32 port_self:1;
		__u32 af_spec:1;
		__u32 group:1;
		__u32 net_ns_fd:1;
		__u32 ext_mask:1;
		__u32 promiscuity:1;
		__u32 num_tx_queues:1;
		__u32 num_rx_queues:1;
		__u32 carrier:1;
		__u32 carrier_changes:1;
		__u32 link_netnsid:1;
		__u32 proto_down:1;
		__u32 gso_max_segs:1;
		__u32 gso_max_size:1;
		__u32 xdp:1;
		__u32 event:1;
		__u32 new_netnsid:1;
		__u32 target_netnsid:1;
		__u32 carrier_up_count:1;
		__u32 carrier_down_count:1;
		__u32 new_ifindex:1;
		__u32 min_mtu:1;
		__u32 max_mtu:1;
		__u32 prop_list:1;
		__u32 gro_max_size:1;
		__u32 tso_max_size:1;
		__u32 tso_max_segs:1;
		__u32 allmulti:1;
		__u32 gso_ipv4_max_size:1;
		__u32 gro_ipv4_max_size:1;
	} _present;
	struct {
		__u32 address;
		__u32 broadcast;
		__u32 ifname;
		__u32 qdisc;
		__u32 stats;
		__u32 cost;
		__u32 priority;
		__u32 wireless;
		__u32 protinfo;
		__u32 map;
		__u32 ifalias;
		__u32 stats64;
		__u32 phys_port_id;
		__u32 phys_switch_id;
		__u32 phys_port_name;
		__u32 perm_address;
		__u32 proto_down_reason;
		__u32 parent_dev_name;
		__u32 parent_dev_bus_name;
		__u32 devlink_port;
	} _len;

	void *address;
	void *broadcast;
	char *ifname;
	__u32 mtu;
	__u32 link;
	char *qdisc;
	struct rtnl_link_stats *stats;
	char *cost;
	char *priority;
	__u32 master;
	char *wireless;
	char *protinfo;
	__u32 txqlen;
	struct rtnl_link_ifmap *map;
	__u32 weight;
	__u8 operstate;
	__u8 linkmode;
	struct rt_link_linkinfo_attrs linkinfo;
	__u32 net_ns_pid;
	char *ifalias;
	__u32 num_vf;
	struct rt_link_vfinfo_list_attrs vfinfo_list;
	struct rtnl_link_stats64 *stats64;
	struct rt_link_vf_ports_attrs vf_ports;
	struct rt_link_port_self_attrs port_self;
	struct rt_link_af_spec_attrs af_spec;
	__u32 group;
	__u32 net_ns_fd;
	__u32 ext_mask;
	__u32 promiscuity;
	__u32 num_tx_queues;
	__u32 num_rx_queues;
	__u8 carrier;
	void *phys_port_id;
	__u32 carrier_changes;
	void *phys_switch_id;
	__s32 link_netnsid;
	char *phys_port_name;
	__u8 proto_down;
	__u32 gso_max_segs;
	__u32 gso_max_size;
	struct rt_link_xdp_attrs xdp;
	__u32 event;
	__s32 new_netnsid;
	__s32 target_netnsid;
	__u32 carrier_up_count;
	__u32 carrier_down_count;
	__s32 new_ifindex;
	__u32 min_mtu;
	__u32 max_mtu;
	struct rt_link_prop_list_link_attrs prop_list;
	void *perm_address;
	char *proto_down_reason;
	char *parent_dev_name;
	char *parent_dev_bus_name;
	__u32 gro_max_size;
	__u32 tso_max_size;
	__u32 tso_max_segs;
	__u32 allmulti;
	void *devlink_port;
	__u32 gso_ipv4_max_size;
	__u32 gro_ipv4_max_size;
};

static inline struct rt_link_setlink_req *rt_link_setlink_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_link_setlink_req));
}
void rt_link_setlink_req_free(struct rt_link_setlink_req *req);

static inline void
rt_link_setlink_req_set_nlflags(struct rt_link_setlink_req *req,
				__u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

static inline void
rt_link_setlink_req_set_address(struct rt_link_setlink_req *req,
				const void *address, size_t len)
{
	free(req->address);
	req->_len.address = len;
	req->address = malloc(req->_len.address);
	memcpy(req->address, address, req->_len.address);
}
static inline void
rt_link_setlink_req_set_broadcast(struct rt_link_setlink_req *req,
				  const void *broadcast, size_t len)
{
	free(req->broadcast);
	req->_len.broadcast = len;
	req->broadcast = malloc(req->_len.broadcast);
	memcpy(req->broadcast, broadcast, req->_len.broadcast);
}
static inline void
rt_link_setlink_req_set_ifname(struct rt_link_setlink_req *req,
			       const char *ifname)
{
	free(req->ifname);
	req->_len.ifname = strlen(ifname);
	req->ifname = malloc(req->_len.ifname + 1);
	memcpy(req->ifname, ifname, req->_len.ifname);
	req->ifname[req->_len.ifname] = 0;
}
static inline void
rt_link_setlink_req_set_mtu(struct rt_link_setlink_req *req, __u32 mtu)
{
	req->_present.mtu = 1;
	req->mtu = mtu;
}
static inline void
rt_link_setlink_req_set_link(struct rt_link_setlink_req *req, __u32 link)
{
	req->_present.link = 1;
	req->link = link;
}
static inline void
rt_link_setlink_req_set_qdisc(struct rt_link_setlink_req *req,
			      const char *qdisc)
{
	free(req->qdisc);
	req->_len.qdisc = strlen(qdisc);
	req->qdisc = malloc(req->_len.qdisc + 1);
	memcpy(req->qdisc, qdisc, req->_len.qdisc);
	req->qdisc[req->_len.qdisc] = 0;
}
static inline void
rt_link_setlink_req_set_stats(struct rt_link_setlink_req *req,
			      const void *stats, size_t len)
{
	free(req->stats);
	req->_len.stats = len;
	req->stats = malloc(req->_len.stats);
	memcpy(req->stats, stats, req->_len.stats);
}
static inline void
rt_link_setlink_req_set_cost(struct rt_link_setlink_req *req, const char *cost)
{
	free(req->cost);
	req->_len.cost = strlen(cost);
	req->cost = malloc(req->_len.cost + 1);
	memcpy(req->cost, cost, req->_len.cost);
	req->cost[req->_len.cost] = 0;
}
static inline void
rt_link_setlink_req_set_priority(struct rt_link_setlink_req *req,
				 const char *priority)
{
	free(req->priority);
	req->_len.priority = strlen(priority);
	req->priority = malloc(req->_len.priority + 1);
	memcpy(req->priority, priority, req->_len.priority);
	req->priority[req->_len.priority] = 0;
}
static inline void
rt_link_setlink_req_set_master(struct rt_link_setlink_req *req, __u32 master)
{
	req->_present.master = 1;
	req->master = master;
}
static inline void
rt_link_setlink_req_set_wireless(struct rt_link_setlink_req *req,
				 const char *wireless)
{
	free(req->wireless);
	req->_len.wireless = strlen(wireless);
	req->wireless = malloc(req->_len.wireless + 1);
	memcpy(req->wireless, wireless, req->_len.wireless);
	req->wireless[req->_len.wireless] = 0;
}
static inline void
rt_link_setlink_req_set_protinfo(struct rt_link_setlink_req *req,
				 const char *protinfo)
{
	free(req->protinfo);
	req->_len.protinfo = strlen(protinfo);
	req->protinfo = malloc(req->_len.protinfo + 1);
	memcpy(req->protinfo, protinfo, req->_len.protinfo);
	req->protinfo[req->_len.protinfo] = 0;
}
static inline void
rt_link_setlink_req_set_txqlen(struct rt_link_setlink_req *req, __u32 txqlen)
{
	req->_present.txqlen = 1;
	req->txqlen = txqlen;
}
static inline void
rt_link_setlink_req_set_map(struct rt_link_setlink_req *req, const void *map,
			    size_t len)
{
	free(req->map);
	req->_len.map = len;
	req->map = malloc(req->_len.map);
	memcpy(req->map, map, req->_len.map);
}
static inline void
rt_link_setlink_req_set_weight(struct rt_link_setlink_req *req, __u32 weight)
{
	req->_present.weight = 1;
	req->weight = weight;
}
static inline void
rt_link_setlink_req_set_operstate(struct rt_link_setlink_req *req,
				  __u8 operstate)
{
	req->_present.operstate = 1;
	req->operstate = operstate;
}
static inline void
rt_link_setlink_req_set_linkmode(struct rt_link_setlink_req *req,
				 __u8 linkmode)
{
	req->_present.linkmode = 1;
	req->linkmode = linkmode;
}
static inline void
rt_link_setlink_req_set_linkinfo_kind(struct rt_link_setlink_req *req,
				      const char *kind)
{
	req->_present.linkinfo = 1;
	free(req->linkinfo.kind);
	req->linkinfo._len.kind = strlen(kind);
	req->linkinfo.kind = malloc(req->linkinfo._len.kind + 1);
	memcpy(req->linkinfo.kind, kind, req->linkinfo._len.kind);
	req->linkinfo.kind[req->linkinfo._len.kind] = 0;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_mode(struct rt_link_setlink_req *req,
						__u8 mode)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.mode = 1;
	req->linkinfo.data.bond.mode = mode;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_active_slave(struct rt_link_setlink_req *req,
							__u32 active_slave)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.active_slave = 1;
	req->linkinfo.data.bond.active_slave = active_slave;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_miimon(struct rt_link_setlink_req *req,
						  __u32 miimon)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.miimon = 1;
	req->linkinfo.data.bond.miimon = miimon;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_updelay(struct rt_link_setlink_req *req,
						   __u32 updelay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.updelay = 1;
	req->linkinfo.data.bond.updelay = updelay;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_downdelay(struct rt_link_setlink_req *req,
						     __u32 downdelay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.downdelay = 1;
	req->linkinfo.data.bond.downdelay = downdelay;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_use_carrier(struct rt_link_setlink_req *req,
						       __u8 use_carrier)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.use_carrier = 1;
	req->linkinfo.data.bond.use_carrier = use_carrier;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_arp_interval(struct rt_link_setlink_req *req,
							__u32 arp_interval)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.arp_interval = 1;
	req->linkinfo.data.bond.arp_interval = arp_interval;
}
static inline void
__rt_link_setlink_req_set_linkinfo_data_bond_arp_ip_target(struct rt_link_setlink_req *req,
							   __u32 *arp_ip_target,
							   unsigned int n_arp_ip_target)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	free(req->linkinfo.data.bond.arp_ip_target);
	req->linkinfo.data.bond.arp_ip_target = arp_ip_target;
	req->linkinfo.data.bond._count.arp_ip_target = n_arp_ip_target;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_arp_validate(struct rt_link_setlink_req *req,
							__u32 arp_validate)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.arp_validate = 1;
	req->linkinfo.data.bond.arp_validate = arp_validate;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_arp_all_targets(struct rt_link_setlink_req *req,
							   __u32 arp_all_targets)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.arp_all_targets = 1;
	req->linkinfo.data.bond.arp_all_targets = arp_all_targets;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_primary(struct rt_link_setlink_req *req,
						   __u32 primary)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.primary = 1;
	req->linkinfo.data.bond.primary = primary;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_primary_reselect(struct rt_link_setlink_req *req,
							    __u8 primary_reselect)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.primary_reselect = 1;
	req->linkinfo.data.bond.primary_reselect = primary_reselect;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_fail_over_mac(struct rt_link_setlink_req *req,
							 __u8 fail_over_mac)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.fail_over_mac = 1;
	req->linkinfo.data.bond.fail_over_mac = fail_over_mac;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_xmit_hash_policy(struct rt_link_setlink_req *req,
							    __u8 xmit_hash_policy)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.xmit_hash_policy = 1;
	req->linkinfo.data.bond.xmit_hash_policy = xmit_hash_policy;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_resend_igmp(struct rt_link_setlink_req *req,
						       __u32 resend_igmp)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.resend_igmp = 1;
	req->linkinfo.data.bond.resend_igmp = resend_igmp;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_num_peer_notif(struct rt_link_setlink_req *req,
							  __u8 num_peer_notif)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.num_peer_notif = 1;
	req->linkinfo.data.bond.num_peer_notif = num_peer_notif;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_all_slaves_active(struct rt_link_setlink_req *req,
							     __u8 all_slaves_active)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.all_slaves_active = 1;
	req->linkinfo.data.bond.all_slaves_active = all_slaves_active;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_min_links(struct rt_link_setlink_req *req,
						     __u32 min_links)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.min_links = 1;
	req->linkinfo.data.bond.min_links = min_links;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_lp_interval(struct rt_link_setlink_req *req,
						       __u32 lp_interval)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.lp_interval = 1;
	req->linkinfo.data.bond.lp_interval = lp_interval;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_packets_per_slave(struct rt_link_setlink_req *req,
							     __u32 packets_per_slave)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.packets_per_slave = 1;
	req->linkinfo.data.bond.packets_per_slave = packets_per_slave;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_lacp_rate(struct rt_link_setlink_req *req,
							__u8 ad_lacp_rate)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_lacp_rate = 1;
	req->linkinfo.data.bond.ad_lacp_rate = ad_lacp_rate;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_select(struct rt_link_setlink_req *req,
						     __u8 ad_select)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_select = 1;
	req->linkinfo.data.bond.ad_select = ad_select;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_info_aggregator(struct rt_link_setlink_req *req,
							      __u16 aggregator)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.aggregator = 1;
	req->linkinfo.data.bond.ad_info.aggregator = aggregator;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_info_num_ports(struct rt_link_setlink_req *req,
							     __u16 num_ports)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.num_ports = 1;
	req->linkinfo.data.bond.ad_info.num_ports = num_ports;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_info_actor_key(struct rt_link_setlink_req *req,
							     __u16 actor_key)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.actor_key = 1;
	req->linkinfo.data.bond.ad_info.actor_key = actor_key;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_info_partner_key(struct rt_link_setlink_req *req,
							       __u16 partner_key)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	req->linkinfo.data.bond.ad_info._present.partner_key = 1;
	req->linkinfo.data.bond.ad_info.partner_key = partner_key;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_info_partner_mac(struct rt_link_setlink_req *req,
							       const void *partner_mac,
							       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_info = 1;
	free(req->linkinfo.data.bond.ad_info.partner_mac);
	req->linkinfo.data.bond.ad_info._len.partner_mac = len;
	req->linkinfo.data.bond.ad_info.partner_mac = malloc(req->linkinfo.data.bond.ad_info._len.partner_mac);
	memcpy(req->linkinfo.data.bond.ad_info.partner_mac, partner_mac, req->linkinfo.data.bond.ad_info._len.partner_mac);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_actor_sys_prio(struct rt_link_setlink_req *req,
							     __u16 ad_actor_sys_prio)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_actor_sys_prio = 1;
	req->linkinfo.data.bond.ad_actor_sys_prio = ad_actor_sys_prio;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_user_port_key(struct rt_link_setlink_req *req,
							    __u16 ad_user_port_key)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_user_port_key = 1;
	req->linkinfo.data.bond.ad_user_port_key = ad_user_port_key;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_actor_system(struct rt_link_setlink_req *req,
							   const void *ad_actor_system,
							   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	free(req->linkinfo.data.bond.ad_actor_system);
	req->linkinfo.data.bond._len.ad_actor_system = len;
	req->linkinfo.data.bond.ad_actor_system = malloc(req->linkinfo.data.bond._len.ad_actor_system);
	memcpy(req->linkinfo.data.bond.ad_actor_system, ad_actor_system, req->linkinfo.data.bond._len.ad_actor_system);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_tlb_dynamic_lb(struct rt_link_setlink_req *req,
							  __u8 tlb_dynamic_lb)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.tlb_dynamic_lb = 1;
	req->linkinfo.data.bond.tlb_dynamic_lb = tlb_dynamic_lb;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_peer_notif_delay(struct rt_link_setlink_req *req,
							    __u32 peer_notif_delay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.peer_notif_delay = 1;
	req->linkinfo.data.bond.peer_notif_delay = peer_notif_delay;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_ad_lacp_active(struct rt_link_setlink_req *req,
							  __u8 ad_lacp_active)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.ad_lacp_active = 1;
	req->linkinfo.data.bond.ad_lacp_active = ad_lacp_active;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_missed_max(struct rt_link_setlink_req *req,
						      __u8 missed_max)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.missed_max = 1;
	req->linkinfo.data.bond.missed_max = missed_max;
}
static inline void
__rt_link_setlink_req_set_linkinfo_data_bond_ns_ip6_target(struct rt_link_setlink_req *req,
							   unsigned char (*ns_ip6_target)[16],
							   unsigned int n_ns_ip6_target)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	free(req->linkinfo.data.bond.ns_ip6_target);
	req->linkinfo.data.bond.ns_ip6_target = ns_ip6_target;
	req->linkinfo.data.bond._count.ns_ip6_target = n_ns_ip6_target;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bond_coupled_control(struct rt_link_setlink_req *req,
							   __u8 coupled_control)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bond = 1;
	req->linkinfo.data.bond._present.coupled_control = 1;
	req->linkinfo.data.bond.coupled_control = coupled_control;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_forward_delay(struct rt_link_setlink_req *req,
							   __u32 forward_delay)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.forward_delay = 1;
	req->linkinfo.data.bridge.forward_delay = forward_delay;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_hello_time(struct rt_link_setlink_req *req,
							__u32 hello_time)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.hello_time = 1;
	req->linkinfo.data.bridge.hello_time = hello_time;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_max_age(struct rt_link_setlink_req *req,
						     __u32 max_age)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.max_age = 1;
	req->linkinfo.data.bridge.max_age = max_age;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_ageing_time(struct rt_link_setlink_req *req,
							 __u32 ageing_time)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.ageing_time = 1;
	req->linkinfo.data.bridge.ageing_time = ageing_time;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_stp_state(struct rt_link_setlink_req *req,
						       __u32 stp_state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.stp_state = 1;
	req->linkinfo.data.bridge.stp_state = stp_state;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_priority(struct rt_link_setlink_req *req,
						      __u16 priority)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.priority = 1;
	req->linkinfo.data.bridge.priority = priority;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_vlan_filtering(struct rt_link_setlink_req *req,
							    __u8 vlan_filtering)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_filtering = 1;
	req->linkinfo.data.bridge.vlan_filtering = vlan_filtering;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_vlan_protocol(struct rt_link_setlink_req *req,
							   __u16 vlan_protocol)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_protocol = 1;
	req->linkinfo.data.bridge.vlan_protocol = vlan_protocol;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_group_fwd_mask(struct rt_link_setlink_req *req,
							    __u16 group_fwd_mask)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.group_fwd_mask = 1;
	req->linkinfo.data.bridge.group_fwd_mask = group_fwd_mask;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_root_id(struct rt_link_setlink_req *req,
						     const void *root_id,
						     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.root_id);
	req->linkinfo.data.bridge._len.root_id = len;
	req->linkinfo.data.bridge.root_id = malloc(req->linkinfo.data.bridge._len.root_id);
	memcpy(req->linkinfo.data.bridge.root_id, root_id, req->linkinfo.data.bridge._len.root_id);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_bridge_id(struct rt_link_setlink_req *req,
						       const void *bridge_id,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.bridge_id);
	req->linkinfo.data.bridge._len.bridge_id = len;
	req->linkinfo.data.bridge.bridge_id = malloc(req->linkinfo.data.bridge._len.bridge_id);
	memcpy(req->linkinfo.data.bridge.bridge_id, bridge_id, req->linkinfo.data.bridge._len.bridge_id);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_root_port(struct rt_link_setlink_req *req,
						       __u16 root_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.root_port = 1;
	req->linkinfo.data.bridge.root_port = root_port;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_root_path_cost(struct rt_link_setlink_req *req,
							    __u32 root_path_cost)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.root_path_cost = 1;
	req->linkinfo.data.bridge.root_path_cost = root_path_cost;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_topology_change(struct rt_link_setlink_req *req,
							     __u8 topology_change)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.topology_change = 1;
	req->linkinfo.data.bridge.topology_change = topology_change;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_topology_change_detected(struct rt_link_setlink_req *req,
								      __u8 topology_change_detected)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.topology_change_detected = 1;
	req->linkinfo.data.bridge.topology_change_detected = topology_change_detected;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_hello_timer(struct rt_link_setlink_req *req,
							 __u64 hello_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.hello_timer = 1;
	req->linkinfo.data.bridge.hello_timer = hello_timer;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_tcn_timer(struct rt_link_setlink_req *req,
						       __u64 tcn_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.tcn_timer = 1;
	req->linkinfo.data.bridge.tcn_timer = tcn_timer;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_topology_change_timer(struct rt_link_setlink_req *req,
								   __u64 topology_change_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.topology_change_timer = 1;
	req->linkinfo.data.bridge.topology_change_timer = topology_change_timer;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_gc_timer(struct rt_link_setlink_req *req,
						      __u64 gc_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.gc_timer = 1;
	req->linkinfo.data.bridge.gc_timer = gc_timer;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_group_addr(struct rt_link_setlink_req *req,
							const void *group_addr,
							size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.group_addr);
	req->linkinfo.data.bridge._len.group_addr = len;
	req->linkinfo.data.bridge.group_addr = malloc(req->linkinfo.data.bridge._len.group_addr);
	memcpy(req->linkinfo.data.bridge.group_addr, group_addr, req->linkinfo.data.bridge._len.group_addr);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_fdb_flush(struct rt_link_setlink_req *req,
						       const void *fdb_flush,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.fdb_flush);
	req->linkinfo.data.bridge._len.fdb_flush = len;
	req->linkinfo.data.bridge.fdb_flush = malloc(req->linkinfo.data.bridge._len.fdb_flush);
	memcpy(req->linkinfo.data.bridge.fdb_flush, fdb_flush, req->linkinfo.data.bridge._len.fdb_flush);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_router(struct rt_link_setlink_req *req,
							  __u8 mcast_router)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_router = 1;
	req->linkinfo.data.bridge.mcast_router = mcast_router;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_snooping(struct rt_link_setlink_req *req,
							    __u8 mcast_snooping)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_snooping = 1;
	req->linkinfo.data.bridge.mcast_snooping = mcast_snooping;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_query_use_ifaddr(struct rt_link_setlink_req *req,
								    __u8 mcast_query_use_ifaddr)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_query_use_ifaddr = 1;
	req->linkinfo.data.bridge.mcast_query_use_ifaddr = mcast_query_use_ifaddr;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_querier(struct rt_link_setlink_req *req,
							   __u8 mcast_querier)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_querier = 1;
	req->linkinfo.data.bridge.mcast_querier = mcast_querier;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_hash_elasticity(struct rt_link_setlink_req *req,
								   __u32 mcast_hash_elasticity)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_hash_elasticity = 1;
	req->linkinfo.data.bridge.mcast_hash_elasticity = mcast_hash_elasticity;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_hash_max(struct rt_link_setlink_req *req,
							    __u32 mcast_hash_max)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_hash_max = 1;
	req->linkinfo.data.bridge.mcast_hash_max = mcast_hash_max;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_last_member_cnt(struct rt_link_setlink_req *req,
								   __u32 mcast_last_member_cnt)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_last_member_cnt = 1;
	req->linkinfo.data.bridge.mcast_last_member_cnt = mcast_last_member_cnt;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_startup_query_cnt(struct rt_link_setlink_req *req,
								     __u32 mcast_startup_query_cnt)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_startup_query_cnt = 1;
	req->linkinfo.data.bridge.mcast_startup_query_cnt = mcast_startup_query_cnt;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_last_member_intvl(struct rt_link_setlink_req *req,
								     __u64 mcast_last_member_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_last_member_intvl = 1;
	req->linkinfo.data.bridge.mcast_last_member_intvl = mcast_last_member_intvl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_membership_intvl(struct rt_link_setlink_req *req,
								    __u64 mcast_membership_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_membership_intvl = 1;
	req->linkinfo.data.bridge.mcast_membership_intvl = mcast_membership_intvl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_querier_intvl(struct rt_link_setlink_req *req,
								 __u64 mcast_querier_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_querier_intvl = 1;
	req->linkinfo.data.bridge.mcast_querier_intvl = mcast_querier_intvl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_query_intvl(struct rt_link_setlink_req *req,
							       __u64 mcast_query_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_query_intvl = 1;
	req->linkinfo.data.bridge.mcast_query_intvl = mcast_query_intvl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_query_response_intvl(struct rt_link_setlink_req *req,
									__u64 mcast_query_response_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_query_response_intvl = 1;
	req->linkinfo.data.bridge.mcast_query_response_intvl = mcast_query_response_intvl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_startup_query_intvl(struct rt_link_setlink_req *req,
								       __u64 mcast_startup_query_intvl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_startup_query_intvl = 1;
	req->linkinfo.data.bridge.mcast_startup_query_intvl = mcast_startup_query_intvl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_nf_call_iptables(struct rt_link_setlink_req *req,
							      __u8 nf_call_iptables)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.nf_call_iptables = 1;
	req->linkinfo.data.bridge.nf_call_iptables = nf_call_iptables;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_nf_call_ip6tables(struct rt_link_setlink_req *req,
							       __u8 nf_call_ip6tables)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.nf_call_ip6tables = 1;
	req->linkinfo.data.bridge.nf_call_ip6tables = nf_call_ip6tables;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_nf_call_arptables(struct rt_link_setlink_req *req,
							       __u8 nf_call_arptables)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.nf_call_arptables = 1;
	req->linkinfo.data.bridge.nf_call_arptables = nf_call_arptables;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_vlan_default_pvid(struct rt_link_setlink_req *req,
							       __u16 vlan_default_pvid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_default_pvid = 1;
	req->linkinfo.data.bridge.vlan_default_pvid = vlan_default_pvid;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_vlan_stats_enabled(struct rt_link_setlink_req *req,
								__u8 vlan_stats_enabled)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_stats_enabled = 1;
	req->linkinfo.data.bridge.vlan_stats_enabled = vlan_stats_enabled;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_stats_enabled(struct rt_link_setlink_req *req,
								 __u8 mcast_stats_enabled)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_stats_enabled = 1;
	req->linkinfo.data.bridge.mcast_stats_enabled = mcast_stats_enabled;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_igmp_version(struct rt_link_setlink_req *req,
								__u8 mcast_igmp_version)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_igmp_version = 1;
	req->linkinfo.data.bridge.mcast_igmp_version = mcast_igmp_version;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_mld_version(struct rt_link_setlink_req *req,
							       __u8 mcast_mld_version)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.mcast_mld_version = 1;
	req->linkinfo.data.bridge.mcast_mld_version = mcast_mld_version;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_vlan_stats_per_port(struct rt_link_setlink_req *req,
								 __u8 vlan_stats_per_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.vlan_stats_per_port = 1;
	req->linkinfo.data.bridge.vlan_stats_per_port = vlan_stats_per_port;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_multi_boolopt(struct rt_link_setlink_req *req,
							   const void *multi_boolopt,
							   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.multi_boolopt);
	req->linkinfo.data.bridge._len.multi_boolopt = len;
	req->linkinfo.data.bridge.multi_boolopt = malloc(req->linkinfo.data.bridge._len.multi_boolopt);
	memcpy(req->linkinfo.data.bridge.multi_boolopt, multi_boolopt, req->linkinfo.data.bridge._len.multi_boolopt);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_mcast_querier_state(struct rt_link_setlink_req *req,
								 const void *mcast_querier_state,
								 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	free(req->linkinfo.data.bridge.mcast_querier_state);
	req->linkinfo.data.bridge._len.mcast_querier_state = len;
	req->linkinfo.data.bridge.mcast_querier_state = malloc(req->linkinfo.data.bridge._len.mcast_querier_state);
	memcpy(req->linkinfo.data.bridge.mcast_querier_state, mcast_querier_state, req->linkinfo.data.bridge._len.mcast_querier_state);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_fdb_n_learned(struct rt_link_setlink_req *req,
							   __u32 fdb_n_learned)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.fdb_n_learned = 1;
	req->linkinfo.data.bridge.fdb_n_learned = fdb_n_learned;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_bridge_fdb_max_learned(struct rt_link_setlink_req *req,
							     __u32 fdb_max_learned)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.bridge = 1;
	req->linkinfo.data.bridge._present.fdb_max_learned = 1;
	req->linkinfo.data.bridge.fdb_max_learned = fdb_max_learned;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_link(struct rt_link_setlink_req *req,
						  __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.link = 1;
	req->linkinfo.data.erspan.link = link;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_iflags(struct rt_link_setlink_req *req,
						    __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.iflags = 1;
	req->linkinfo.data.erspan.iflags = iflags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_oflags(struct rt_link_setlink_req *req,
						    __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.oflags = 1;
	req->linkinfo.data.erspan.oflags = oflags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_ikey(struct rt_link_setlink_req *req,
						  __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.ikey = 1;
	req->linkinfo.data.erspan.ikey = ikey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_okey(struct rt_link_setlink_req *req,
						  __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.okey = 1;
	req->linkinfo.data.erspan.okey = okey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_local(struct rt_link_setlink_req *req,
						   const void *local,
						   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	free(req->linkinfo.data.erspan.local);
	req->linkinfo.data.erspan._len.local = len;
	req->linkinfo.data.erspan.local = malloc(req->linkinfo.data.erspan._len.local);
	memcpy(req->linkinfo.data.erspan.local, local, req->linkinfo.data.erspan._len.local);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_remote(struct rt_link_setlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	free(req->linkinfo.data.erspan.remote);
	req->linkinfo.data.erspan._len.remote = len;
	req->linkinfo.data.erspan.remote = malloc(req->linkinfo.data.erspan._len.remote);
	memcpy(req->linkinfo.data.erspan.remote, remote, req->linkinfo.data.erspan._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_ttl(struct rt_link_setlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.ttl = 1;
	req->linkinfo.data.erspan.ttl = ttl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_tos(struct rt_link_setlink_req *req,
						 __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.tos = 1;
	req->linkinfo.data.erspan.tos = tos;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_pmtudisc(struct rt_link_setlink_req *req,
						      __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.pmtudisc = 1;
	req->linkinfo.data.erspan.pmtudisc = pmtudisc;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_encap_limit(struct rt_link_setlink_req *req,
							 __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_limit = 1;
	req->linkinfo.data.erspan.encap_limit = encap_limit;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_flowinfo(struct rt_link_setlink_req *req,
						      __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.flowinfo = 1;
	req->linkinfo.data.erspan.flowinfo = flowinfo;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_flags(struct rt_link_setlink_req *req,
						   __u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.flags = 1;
	req->linkinfo.data.erspan.flags = flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_encap_type(struct rt_link_setlink_req *req,
							__u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_type = 1;
	req->linkinfo.data.erspan.encap_type = encap_type;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_encap_flags(struct rt_link_setlink_req *req,
							 __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_flags = 1;
	req->linkinfo.data.erspan.encap_flags = encap_flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_encap_sport(struct rt_link_setlink_req *req,
							 __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_sport = 1;
	req->linkinfo.data.erspan.encap_sport = encap_sport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_encap_dport(struct rt_link_setlink_req *req,
							 __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.encap_dport = 1;
	req->linkinfo.data.erspan.encap_dport = encap_dport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_collect_metadata(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.collect_metadata = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_ignore_df(struct rt_link_setlink_req *req,
						       __u8 ignore_df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.ignore_df = 1;
	req->linkinfo.data.erspan.ignore_df = ignore_df;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_fwmark(struct rt_link_setlink_req *req,
						    __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.fwmark = 1;
	req->linkinfo.data.erspan.fwmark = fwmark;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_erspan_index(struct rt_link_setlink_req *req,
							  __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_index = 1;
	req->linkinfo.data.erspan.erspan_index = erspan_index;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_erspan_ver(struct rt_link_setlink_req *req,
							__u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_ver = 1;
	req->linkinfo.data.erspan.erspan_ver = erspan_ver;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_erspan_dir(struct rt_link_setlink_req *req,
							__u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_dir = 1;
	req->linkinfo.data.erspan.erspan_dir = erspan_dir;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_erspan_erspan_hwid(struct rt_link_setlink_req *req,
							 __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.erspan = 1;
	req->linkinfo.data.erspan._present.erspan_hwid = 1;
	req->linkinfo.data.erspan.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_link(struct rt_link_setlink_req *req,
					       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.link = 1;
	req->linkinfo.data.gre.link = link;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_iflags(struct rt_link_setlink_req *req,
						 __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.iflags = 1;
	req->linkinfo.data.gre.iflags = iflags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_oflags(struct rt_link_setlink_req *req,
						 __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.oflags = 1;
	req->linkinfo.data.gre.oflags = oflags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_ikey(struct rt_link_setlink_req *req,
					       __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.ikey = 1;
	req->linkinfo.data.gre.ikey = ikey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_okey(struct rt_link_setlink_req *req,
					       __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.okey = 1;
	req->linkinfo.data.gre.okey = okey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_local(struct rt_link_setlink_req *req,
						const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	free(req->linkinfo.data.gre.local);
	req->linkinfo.data.gre._len.local = len;
	req->linkinfo.data.gre.local = malloc(req->linkinfo.data.gre._len.local);
	memcpy(req->linkinfo.data.gre.local, local, req->linkinfo.data.gre._len.local);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_remote(struct rt_link_setlink_req *req,
						 const void *remote,
						 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	free(req->linkinfo.data.gre.remote);
	req->linkinfo.data.gre._len.remote = len;
	req->linkinfo.data.gre.remote = malloc(req->linkinfo.data.gre._len.remote);
	memcpy(req->linkinfo.data.gre.remote, remote, req->linkinfo.data.gre._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_ttl(struct rt_link_setlink_req *req,
					      __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.ttl = 1;
	req->linkinfo.data.gre.ttl = ttl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_tos(struct rt_link_setlink_req *req,
					      __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.tos = 1;
	req->linkinfo.data.gre.tos = tos;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_pmtudisc(struct rt_link_setlink_req *req,
						   __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.pmtudisc = 1;
	req->linkinfo.data.gre.pmtudisc = pmtudisc;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_encap_limit(struct rt_link_setlink_req *req,
						      __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_limit = 1;
	req->linkinfo.data.gre.encap_limit = encap_limit;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_flowinfo(struct rt_link_setlink_req *req,
						   __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.flowinfo = 1;
	req->linkinfo.data.gre.flowinfo = flowinfo;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_flags(struct rt_link_setlink_req *req,
						__u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.flags = 1;
	req->linkinfo.data.gre.flags = flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_encap_type(struct rt_link_setlink_req *req,
						     __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_type = 1;
	req->linkinfo.data.gre.encap_type = encap_type;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_encap_flags(struct rt_link_setlink_req *req,
						      __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_flags = 1;
	req->linkinfo.data.gre.encap_flags = encap_flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_encap_sport(struct rt_link_setlink_req *req,
						      __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_sport = 1;
	req->linkinfo.data.gre.encap_sport = encap_sport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_encap_dport(struct rt_link_setlink_req *req,
						      __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.encap_dport = 1;
	req->linkinfo.data.gre.encap_dport = encap_dport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_collect_metadata(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.collect_metadata = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_ignore_df(struct rt_link_setlink_req *req,
						    __u8 ignore_df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.ignore_df = 1;
	req->linkinfo.data.gre.ignore_df = ignore_df;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_fwmark(struct rt_link_setlink_req *req,
						 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.fwmark = 1;
	req->linkinfo.data.gre.fwmark = fwmark;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_erspan_index(struct rt_link_setlink_req *req,
						       __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_index = 1;
	req->linkinfo.data.gre.erspan_index = erspan_index;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_erspan_ver(struct rt_link_setlink_req *req,
						     __u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_ver = 1;
	req->linkinfo.data.gre.erspan_ver = erspan_ver;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_erspan_dir(struct rt_link_setlink_req *req,
						     __u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_dir = 1;
	req->linkinfo.data.gre.erspan_dir = erspan_dir;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gre_erspan_hwid(struct rt_link_setlink_req *req,
						      __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gre = 1;
	req->linkinfo.data.gre._present.erspan_hwid = 1;
	req->linkinfo.data.gre.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_link(struct rt_link_setlink_req *req,
						  __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.link = 1;
	req->linkinfo.data.gretap.link = link;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_iflags(struct rt_link_setlink_req *req,
						    __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.iflags = 1;
	req->linkinfo.data.gretap.iflags = iflags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_oflags(struct rt_link_setlink_req *req,
						    __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.oflags = 1;
	req->linkinfo.data.gretap.oflags = oflags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_ikey(struct rt_link_setlink_req *req,
						  __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.ikey = 1;
	req->linkinfo.data.gretap.ikey = ikey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_okey(struct rt_link_setlink_req *req,
						  __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.okey = 1;
	req->linkinfo.data.gretap.okey = okey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_local(struct rt_link_setlink_req *req,
						   const void *local,
						   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	free(req->linkinfo.data.gretap.local);
	req->linkinfo.data.gretap._len.local = len;
	req->linkinfo.data.gretap.local = malloc(req->linkinfo.data.gretap._len.local);
	memcpy(req->linkinfo.data.gretap.local, local, req->linkinfo.data.gretap._len.local);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_remote(struct rt_link_setlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	free(req->linkinfo.data.gretap.remote);
	req->linkinfo.data.gretap._len.remote = len;
	req->linkinfo.data.gretap.remote = malloc(req->linkinfo.data.gretap._len.remote);
	memcpy(req->linkinfo.data.gretap.remote, remote, req->linkinfo.data.gretap._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_ttl(struct rt_link_setlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.ttl = 1;
	req->linkinfo.data.gretap.ttl = ttl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_tos(struct rt_link_setlink_req *req,
						 __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.tos = 1;
	req->linkinfo.data.gretap.tos = tos;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_pmtudisc(struct rt_link_setlink_req *req,
						      __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.pmtudisc = 1;
	req->linkinfo.data.gretap.pmtudisc = pmtudisc;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_encap_limit(struct rt_link_setlink_req *req,
							 __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_limit = 1;
	req->linkinfo.data.gretap.encap_limit = encap_limit;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_flowinfo(struct rt_link_setlink_req *req,
						      __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.flowinfo = 1;
	req->linkinfo.data.gretap.flowinfo = flowinfo;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_flags(struct rt_link_setlink_req *req,
						   __u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.flags = 1;
	req->linkinfo.data.gretap.flags = flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_encap_type(struct rt_link_setlink_req *req,
							__u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_type = 1;
	req->linkinfo.data.gretap.encap_type = encap_type;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_encap_flags(struct rt_link_setlink_req *req,
							 __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_flags = 1;
	req->linkinfo.data.gretap.encap_flags = encap_flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_encap_sport(struct rt_link_setlink_req *req,
							 __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_sport = 1;
	req->linkinfo.data.gretap.encap_sport = encap_sport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_encap_dport(struct rt_link_setlink_req *req,
							 __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.encap_dport = 1;
	req->linkinfo.data.gretap.encap_dport = encap_dport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_collect_metadata(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.collect_metadata = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_ignore_df(struct rt_link_setlink_req *req,
						       __u8 ignore_df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.ignore_df = 1;
	req->linkinfo.data.gretap.ignore_df = ignore_df;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_fwmark(struct rt_link_setlink_req *req,
						    __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.fwmark = 1;
	req->linkinfo.data.gretap.fwmark = fwmark;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_erspan_index(struct rt_link_setlink_req *req,
							  __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_index = 1;
	req->linkinfo.data.gretap.erspan_index = erspan_index;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_erspan_ver(struct rt_link_setlink_req *req,
							__u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_ver = 1;
	req->linkinfo.data.gretap.erspan_ver = erspan_ver;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_erspan_dir(struct rt_link_setlink_req *req,
							__u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_dir = 1;
	req->linkinfo.data.gretap.erspan_dir = erspan_dir;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_gretap_erspan_hwid(struct rt_link_setlink_req *req,
							 __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.gretap = 1;
	req->linkinfo.data.gretap._present.erspan_hwid = 1;
	req->linkinfo.data.gretap.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_link(struct rt_link_setlink_req *req,
						  __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.link = 1;
	req->linkinfo.data.ip6gre.link = link;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_iflags(struct rt_link_setlink_req *req,
						    __u16 iflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.iflags = 1;
	req->linkinfo.data.ip6gre.iflags = iflags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_oflags(struct rt_link_setlink_req *req,
						    __u16 oflags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.oflags = 1;
	req->linkinfo.data.ip6gre.oflags = oflags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_ikey(struct rt_link_setlink_req *req,
						  __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.ikey = 1;
	req->linkinfo.data.ip6gre.ikey = ikey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_okey(struct rt_link_setlink_req *req,
						  __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.okey = 1;
	req->linkinfo.data.ip6gre.okey = okey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_local(struct rt_link_setlink_req *req,
						   const void *local,
						   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	free(req->linkinfo.data.ip6gre.local);
	req->linkinfo.data.ip6gre._len.local = len;
	req->linkinfo.data.ip6gre.local = malloc(req->linkinfo.data.ip6gre._len.local);
	memcpy(req->linkinfo.data.ip6gre.local, local, req->linkinfo.data.ip6gre._len.local);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_remote(struct rt_link_setlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	free(req->linkinfo.data.ip6gre.remote);
	req->linkinfo.data.ip6gre._len.remote = len;
	req->linkinfo.data.ip6gre.remote = malloc(req->linkinfo.data.ip6gre._len.remote);
	memcpy(req->linkinfo.data.ip6gre.remote, remote, req->linkinfo.data.ip6gre._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_ttl(struct rt_link_setlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.ttl = 1;
	req->linkinfo.data.ip6gre.ttl = ttl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_encap_limit(struct rt_link_setlink_req *req,
							 __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_limit = 1;
	req->linkinfo.data.ip6gre.encap_limit = encap_limit;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_flowinfo(struct rt_link_setlink_req *req,
						      __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.flowinfo = 1;
	req->linkinfo.data.ip6gre.flowinfo = flowinfo;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_flags(struct rt_link_setlink_req *req,
						   __u32 flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.flags = 1;
	req->linkinfo.data.ip6gre.flags = flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_encap_type(struct rt_link_setlink_req *req,
							__u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_type = 1;
	req->linkinfo.data.ip6gre.encap_type = encap_type;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_encap_flags(struct rt_link_setlink_req *req,
							 __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_flags = 1;
	req->linkinfo.data.ip6gre.encap_flags = encap_flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_encap_sport(struct rt_link_setlink_req *req,
							 __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_sport = 1;
	req->linkinfo.data.ip6gre.encap_sport = encap_sport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_encap_dport(struct rt_link_setlink_req *req,
							 __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.encap_dport = 1;
	req->linkinfo.data.ip6gre.encap_dport = encap_dport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_collect_metadata(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.collect_metadata = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_fwmark(struct rt_link_setlink_req *req,
						    __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.fwmark = 1;
	req->linkinfo.data.ip6gre.fwmark = fwmark;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_erspan_index(struct rt_link_setlink_req *req,
							  __u32 erspan_index)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_index = 1;
	req->linkinfo.data.ip6gre.erspan_index = erspan_index;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_erspan_ver(struct rt_link_setlink_req *req,
							__u8 erspan_ver)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_ver = 1;
	req->linkinfo.data.ip6gre.erspan_ver = erspan_ver;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_erspan_dir(struct rt_link_setlink_req *req,
							__u8 erspan_dir)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_dir = 1;
	req->linkinfo.data.ip6gre.erspan_dir = erspan_dir;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6gre_erspan_hwid(struct rt_link_setlink_req *req,
							 __u16 erspan_hwid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6gre = 1;
	req->linkinfo.data.ip6gre._present.erspan_hwid = 1;
	req->linkinfo.data.ip6gre.erspan_hwid = erspan_hwid;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_id(struct rt_link_setlink_req *req,
						__u32 id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.id = 1;
	req->linkinfo.data.geneve.id = id;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_remote(struct rt_link_setlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	free(req->linkinfo.data.geneve.remote);
	req->linkinfo.data.geneve._len.remote = len;
	req->linkinfo.data.geneve.remote = malloc(req->linkinfo.data.geneve._len.remote);
	memcpy(req->linkinfo.data.geneve.remote, remote, req->linkinfo.data.geneve._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_ttl(struct rt_link_setlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.ttl = 1;
	req->linkinfo.data.geneve.ttl = ttl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_tos(struct rt_link_setlink_req *req,
						 __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.tos = 1;
	req->linkinfo.data.geneve.tos = tos;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_port(struct rt_link_setlink_req *req,
						  __u16 port /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.port = 1;
	req->linkinfo.data.geneve.port = port;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_collect_metadata(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.collect_metadata = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_remote6(struct rt_link_setlink_req *req,
						     const void *remote6,
						     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	free(req->linkinfo.data.geneve.remote6);
	req->linkinfo.data.geneve._len.remote6 = len;
	req->linkinfo.data.geneve.remote6 = malloc(req->linkinfo.data.geneve._len.remote6);
	memcpy(req->linkinfo.data.geneve.remote6, remote6, req->linkinfo.data.geneve._len.remote6);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_udp_csum(struct rt_link_setlink_req *req,
						      __u8 udp_csum)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.udp_csum = 1;
	req->linkinfo.data.geneve.udp_csum = udp_csum;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_udp_zero_csum6_tx(struct rt_link_setlink_req *req,
							       __u8 udp_zero_csum6_tx)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.udp_zero_csum6_tx = 1;
	req->linkinfo.data.geneve.udp_zero_csum6_tx = udp_zero_csum6_tx;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_udp_zero_csum6_rx(struct rt_link_setlink_req *req,
							       __u8 udp_zero_csum6_rx)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.udp_zero_csum6_rx = 1;
	req->linkinfo.data.geneve.udp_zero_csum6_rx = udp_zero_csum6_rx;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_label(struct rt_link_setlink_req *req,
						   __u32 label /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.label = 1;
	req->linkinfo.data.geneve.label = label;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_ttl_inherit(struct rt_link_setlink_req *req,
							 __u8 ttl_inherit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.ttl_inherit = 1;
	req->linkinfo.data.geneve.ttl_inherit = ttl_inherit;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_df(struct rt_link_setlink_req *req,
						__u8 df)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.df = 1;
	req->linkinfo.data.geneve.df = df;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_inner_proto_inherit(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	req->linkinfo.data.geneve._present.inner_proto_inherit = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_geneve_port_range(struct rt_link_setlink_req *req,
							const void *port_range,
							size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.geneve = 1;
	free(req->linkinfo.data.geneve.port_range);
	req->linkinfo.data.geneve._len.port_range = len;
	req->linkinfo.data.geneve.port_range = malloc(req->linkinfo.data.geneve._len.port_range);
	memcpy(req->linkinfo.data.geneve.port_range, port_range, req->linkinfo.data.geneve._len.port_range);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_link(struct rt_link_setlink_req *req,
						__u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.link = 1;
	req->linkinfo.data.ipip.link = link;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_local(struct rt_link_setlink_req *req,
						 const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip.local);
	req->linkinfo.data.ipip._len.local = len;
	req->linkinfo.data.ipip.local = malloc(req->linkinfo.data.ipip._len.local);
	memcpy(req->linkinfo.data.ipip.local, local, req->linkinfo.data.ipip._len.local);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_remote(struct rt_link_setlink_req *req,
						  const void *remote,
						  size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip.remote);
	req->linkinfo.data.ipip._len.remote = len;
	req->linkinfo.data.ipip.remote = malloc(req->linkinfo.data.ipip._len.remote);
	memcpy(req->linkinfo.data.ipip.remote, remote, req->linkinfo.data.ipip._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_ttl(struct rt_link_setlink_req *req,
					       __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.ttl = 1;
	req->linkinfo.data.ipip.ttl = ttl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_tos(struct rt_link_setlink_req *req,
					       __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.tos = 1;
	req->linkinfo.data.ipip.tos = tos;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_encap_limit(struct rt_link_setlink_req *req,
						       __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_limit = 1;
	req->linkinfo.data.ipip.encap_limit = encap_limit;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_flowinfo(struct rt_link_setlink_req *req,
						    __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.flowinfo = 1;
	req->linkinfo.data.ipip.flowinfo = flowinfo;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_flags(struct rt_link_setlink_req *req,
						 __u16 flags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.flags = 1;
	req->linkinfo.data.ipip.flags = flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_proto(struct rt_link_setlink_req *req,
						 __u8 proto)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.proto = 1;
	req->linkinfo.data.ipip.proto = proto;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_pmtudisc(struct rt_link_setlink_req *req,
						    __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.pmtudisc = 1;
	req->linkinfo.data.ipip.pmtudisc = pmtudisc;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip__6rd_prefix(struct rt_link_setlink_req *req,
						       const void *_6rd_prefix,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip._6rd_prefix);
	req->linkinfo.data.ipip._len._6rd_prefix = len;
	req->linkinfo.data.ipip._6rd_prefix = malloc(req->linkinfo.data.ipip._len._6rd_prefix);
	memcpy(req->linkinfo.data.ipip._6rd_prefix, _6rd_prefix, req->linkinfo.data.ipip._len._6rd_prefix);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip__6rd_relay_prefix(struct rt_link_setlink_req *req,
							     const void *_6rd_relay_prefix,
							     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	free(req->linkinfo.data.ipip._6rd_relay_prefix);
	req->linkinfo.data.ipip._len._6rd_relay_prefix = len;
	req->linkinfo.data.ipip._6rd_relay_prefix = malloc(req->linkinfo.data.ipip._len._6rd_relay_prefix);
	memcpy(req->linkinfo.data.ipip._6rd_relay_prefix, _6rd_relay_prefix, req->linkinfo.data.ipip._len._6rd_relay_prefix);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip__6rd_prefixlen(struct rt_link_setlink_req *req,
							  __u16 _6rd_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present._6rd_prefixlen = 1;
	req->linkinfo.data.ipip._6rd_prefixlen = _6rd_prefixlen;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip__6rd_relay_prefixlen(struct rt_link_setlink_req *req,
								__u16 _6rd_relay_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present._6rd_relay_prefixlen = 1;
	req->linkinfo.data.ipip._6rd_relay_prefixlen = _6rd_relay_prefixlen;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_encap_type(struct rt_link_setlink_req *req,
						      __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_type = 1;
	req->linkinfo.data.ipip.encap_type = encap_type;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_encap_flags(struct rt_link_setlink_req *req,
						       __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_flags = 1;
	req->linkinfo.data.ipip.encap_flags = encap_flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_encap_sport(struct rt_link_setlink_req *req,
						       __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_sport = 1;
	req->linkinfo.data.ipip.encap_sport = encap_sport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_encap_dport(struct rt_link_setlink_req *req,
						       __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.encap_dport = 1;
	req->linkinfo.data.ipip.encap_dport = encap_dport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_collect_metadata(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.collect_metadata = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ipip_fwmark(struct rt_link_setlink_req *req,
						  __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ipip = 1;
	req->linkinfo.data.ipip._present.fwmark = 1;
	req->linkinfo.data.ipip.fwmark = fwmark;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_link(struct rt_link_setlink_req *req,
						  __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.link = 1;
	req->linkinfo.data.ip6tnl.link = link;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_local(struct rt_link_setlink_req *req,
						   const void *local,
						   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	free(req->linkinfo.data.ip6tnl.local);
	req->linkinfo.data.ip6tnl._len.local = len;
	req->linkinfo.data.ip6tnl.local = malloc(req->linkinfo.data.ip6tnl._len.local);
	memcpy(req->linkinfo.data.ip6tnl.local, local, req->linkinfo.data.ip6tnl._len.local);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_remote(struct rt_link_setlink_req *req,
						    const void *remote,
						    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	free(req->linkinfo.data.ip6tnl.remote);
	req->linkinfo.data.ip6tnl._len.remote = len;
	req->linkinfo.data.ip6tnl.remote = malloc(req->linkinfo.data.ip6tnl._len.remote);
	memcpy(req->linkinfo.data.ip6tnl.remote, remote, req->linkinfo.data.ip6tnl._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_ttl(struct rt_link_setlink_req *req,
						 __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.ttl = 1;
	req->linkinfo.data.ip6tnl.ttl = ttl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_encap_limit(struct rt_link_setlink_req *req,
							 __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_limit = 1;
	req->linkinfo.data.ip6tnl.encap_limit = encap_limit;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_flowinfo(struct rt_link_setlink_req *req,
						      __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.flowinfo = 1;
	req->linkinfo.data.ip6tnl.flowinfo = flowinfo;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_flags(struct rt_link_setlink_req *req,
						   __u32 flags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.flags = 1;
	req->linkinfo.data.ip6tnl.flags = flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_proto(struct rt_link_setlink_req *req,
						   __u8 proto)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.proto = 1;
	req->linkinfo.data.ip6tnl.proto = proto;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_encap_type(struct rt_link_setlink_req *req,
							__u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_type = 1;
	req->linkinfo.data.ip6tnl.encap_type = encap_type;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_encap_flags(struct rt_link_setlink_req *req,
							 __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_flags = 1;
	req->linkinfo.data.ip6tnl.encap_flags = encap_flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_encap_sport(struct rt_link_setlink_req *req,
							 __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_sport = 1;
	req->linkinfo.data.ip6tnl.encap_sport = encap_sport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_encap_dport(struct rt_link_setlink_req *req,
							 __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.encap_dport = 1;
	req->linkinfo.data.ip6tnl.encap_dport = encap_dport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_collect_metadata(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.collect_metadata = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ip6tnl_fwmark(struct rt_link_setlink_req *req,
						    __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ip6tnl = 1;
	req->linkinfo.data.ip6tnl._present.fwmark = 1;
	req->linkinfo.data.ip6tnl.fwmark = fwmark;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_link(struct rt_link_setlink_req *req,
					       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.link = 1;
	req->linkinfo.data.sit.link = link;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_local(struct rt_link_setlink_req *req,
						const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit.local);
	req->linkinfo.data.sit._len.local = len;
	req->linkinfo.data.sit.local = malloc(req->linkinfo.data.sit._len.local);
	memcpy(req->linkinfo.data.sit.local, local, req->linkinfo.data.sit._len.local);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_remote(struct rt_link_setlink_req *req,
						 const void *remote,
						 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit.remote);
	req->linkinfo.data.sit._len.remote = len;
	req->linkinfo.data.sit.remote = malloc(req->linkinfo.data.sit._len.remote);
	memcpy(req->linkinfo.data.sit.remote, remote, req->linkinfo.data.sit._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_ttl(struct rt_link_setlink_req *req,
					      __u8 ttl)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.ttl = 1;
	req->linkinfo.data.sit.ttl = ttl;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_tos(struct rt_link_setlink_req *req,
					      __u8 tos)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.tos = 1;
	req->linkinfo.data.sit.tos = tos;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_encap_limit(struct rt_link_setlink_req *req,
						      __u8 encap_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_limit = 1;
	req->linkinfo.data.sit.encap_limit = encap_limit;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_flowinfo(struct rt_link_setlink_req *req,
						   __u32 flowinfo /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.flowinfo = 1;
	req->linkinfo.data.sit.flowinfo = flowinfo;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_flags(struct rt_link_setlink_req *req,
						__u16 flags /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.flags = 1;
	req->linkinfo.data.sit.flags = flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_proto(struct rt_link_setlink_req *req,
						__u8 proto)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.proto = 1;
	req->linkinfo.data.sit.proto = proto;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_pmtudisc(struct rt_link_setlink_req *req,
						   __u8 pmtudisc)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.pmtudisc = 1;
	req->linkinfo.data.sit.pmtudisc = pmtudisc;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit__6rd_prefix(struct rt_link_setlink_req *req,
						      const void *_6rd_prefix,
						      size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit._6rd_prefix);
	req->linkinfo.data.sit._len._6rd_prefix = len;
	req->linkinfo.data.sit._6rd_prefix = malloc(req->linkinfo.data.sit._len._6rd_prefix);
	memcpy(req->linkinfo.data.sit._6rd_prefix, _6rd_prefix, req->linkinfo.data.sit._len._6rd_prefix);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit__6rd_relay_prefix(struct rt_link_setlink_req *req,
							    const void *_6rd_relay_prefix,
							    size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	free(req->linkinfo.data.sit._6rd_relay_prefix);
	req->linkinfo.data.sit._len._6rd_relay_prefix = len;
	req->linkinfo.data.sit._6rd_relay_prefix = malloc(req->linkinfo.data.sit._len._6rd_relay_prefix);
	memcpy(req->linkinfo.data.sit._6rd_relay_prefix, _6rd_relay_prefix, req->linkinfo.data.sit._len._6rd_relay_prefix);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit__6rd_prefixlen(struct rt_link_setlink_req *req,
							 __u16 _6rd_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present._6rd_prefixlen = 1;
	req->linkinfo.data.sit._6rd_prefixlen = _6rd_prefixlen;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit__6rd_relay_prefixlen(struct rt_link_setlink_req *req,
							       __u16 _6rd_relay_prefixlen)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present._6rd_relay_prefixlen = 1;
	req->linkinfo.data.sit._6rd_relay_prefixlen = _6rd_relay_prefixlen;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_encap_type(struct rt_link_setlink_req *req,
						     __u16 encap_type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_type = 1;
	req->linkinfo.data.sit.encap_type = encap_type;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_encap_flags(struct rt_link_setlink_req *req,
						      __u16 encap_flags)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_flags = 1;
	req->linkinfo.data.sit.encap_flags = encap_flags;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_encap_sport(struct rt_link_setlink_req *req,
						      __u16 encap_sport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_sport = 1;
	req->linkinfo.data.sit.encap_sport = encap_sport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_encap_dport(struct rt_link_setlink_req *req,
						      __u16 encap_dport /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.encap_dport = 1;
	req->linkinfo.data.sit.encap_dport = encap_dport;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_collect_metadata(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.collect_metadata = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_sit_fwmark(struct rt_link_setlink_req *req,
						 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.sit = 1;
	req->linkinfo.data.sit._present.fwmark = 1;
	req->linkinfo.data.sit.fwmark = fwmark;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_tun_owner(struct rt_link_setlink_req *req,
						__u32 owner)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.owner = 1;
	req->linkinfo.data.tun.owner = owner;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_tun_group(struct rt_link_setlink_req *req,
						__u32 group)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.group = 1;
	req->linkinfo.data.tun.group = group;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_tun_type(struct rt_link_setlink_req *req,
					       __u8 type)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.type = 1;
	req->linkinfo.data.tun.type = type;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_tun_pi(struct rt_link_setlink_req *req,
					     __u8 pi)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.pi = 1;
	req->linkinfo.data.tun.pi = pi;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_tun_vnet_hdr(struct rt_link_setlink_req *req,
						   __u8 vnet_hdr)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.vnet_hdr = 1;
	req->linkinfo.data.tun.vnet_hdr = vnet_hdr;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_tun_persist(struct rt_link_setlink_req *req,
						  __u8 persist)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.persist = 1;
	req->linkinfo.data.tun.persist = persist;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_tun_multi_queue(struct rt_link_setlink_req *req,
						      __u8 multi_queue)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.multi_queue = 1;
	req->linkinfo.data.tun.multi_queue = multi_queue;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_tun_num_queues(struct rt_link_setlink_req *req,
						     __u32 num_queues)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.num_queues = 1;
	req->linkinfo.data.tun.num_queues = num_queues;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_tun_num_disabled_queues(struct rt_link_setlink_req *req,
							      __u32 num_disabled_queues)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.tun = 1;
	req->linkinfo.data.tun._present.num_disabled_queues = 1;
	req->linkinfo.data.tun.num_disabled_queues = num_disabled_queues;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vlan_id(struct rt_link_setlink_req *req,
					      __u16 id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.id = 1;
	req->linkinfo.data.vlan.id = id;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vlan_flags(struct rt_link_setlink_req *req,
						 const void *flags, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	free(req->linkinfo.data.vlan.flags);
	req->linkinfo.data.vlan._len.flags = len;
	req->linkinfo.data.vlan.flags = malloc(req->linkinfo.data.vlan._len.flags);
	memcpy(req->linkinfo.data.vlan.flags, flags, req->linkinfo.data.vlan._len.flags);
}
static inline void
__rt_link_setlink_req_set_linkinfo_data_vlan_egress_qos_mapping(struct rt_link_setlink_req *req,
								struct ifla_vlan_qos_mapping *mapping,
								unsigned int n_mapping)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.egress_qos = 1;
	free(req->linkinfo.data.vlan.egress_qos.mapping);
	req->linkinfo.data.vlan.egress_qos.mapping = mapping;
	req->linkinfo.data.vlan.egress_qos._count.mapping = n_mapping;
}
static inline void
__rt_link_setlink_req_set_linkinfo_data_vlan_ingress_qos_mapping(struct rt_link_setlink_req *req,
								 struct ifla_vlan_qos_mapping *mapping,
								 unsigned int n_mapping)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.ingress_qos = 1;
	free(req->linkinfo.data.vlan.ingress_qos.mapping);
	req->linkinfo.data.vlan.ingress_qos.mapping = mapping;
	req->linkinfo.data.vlan.ingress_qos._count.mapping = n_mapping;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vlan_protocol(struct rt_link_setlink_req *req,
						    int protocol /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vlan = 1;
	req->linkinfo.data.vlan._present.protocol = 1;
	req->linkinfo.data.vlan.protocol = protocol;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vrf_table(struct rt_link_setlink_req *req,
						__u32 table)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vrf = 1;
	req->linkinfo.data.vrf._present.table = 1;
	req->linkinfo.data.vrf.table = table;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti_link(struct rt_link_setlink_req *req,
					       __u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.link = 1;
	req->linkinfo.data.vti.link = link;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti_ikey(struct rt_link_setlink_req *req,
					       __u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.ikey = 1;
	req->linkinfo.data.vti.ikey = ikey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti_okey(struct rt_link_setlink_req *req,
					       __u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.okey = 1;
	req->linkinfo.data.vti.okey = okey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti_local(struct rt_link_setlink_req *req,
						const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	free(req->linkinfo.data.vti.local);
	req->linkinfo.data.vti._len.local = len;
	req->linkinfo.data.vti.local = malloc(req->linkinfo.data.vti._len.local);
	memcpy(req->linkinfo.data.vti.local, local, req->linkinfo.data.vti._len.local);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti_remote(struct rt_link_setlink_req *req,
						 const void *remote,
						 size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	free(req->linkinfo.data.vti.remote);
	req->linkinfo.data.vti._len.remote = len;
	req->linkinfo.data.vti.remote = malloc(req->linkinfo.data.vti._len.remote);
	memcpy(req->linkinfo.data.vti.remote, remote, req->linkinfo.data.vti._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti_fwmark(struct rt_link_setlink_req *req,
						 __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti = 1;
	req->linkinfo.data.vti._present.fwmark = 1;
	req->linkinfo.data.vti.fwmark = fwmark;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti6_link(struct rt_link_setlink_req *req,
						__u32 link)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.link = 1;
	req->linkinfo.data.vti6.link = link;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti6_ikey(struct rt_link_setlink_req *req,
						__u32 ikey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.ikey = 1;
	req->linkinfo.data.vti6.ikey = ikey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti6_okey(struct rt_link_setlink_req *req,
						__u32 okey /* big-endian */)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.okey = 1;
	req->linkinfo.data.vti6.okey = okey;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti6_local(struct rt_link_setlink_req *req,
						 const void *local, size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	free(req->linkinfo.data.vti6.local);
	req->linkinfo.data.vti6._len.local = len;
	req->linkinfo.data.vti6.local = malloc(req->linkinfo.data.vti6._len.local);
	memcpy(req->linkinfo.data.vti6.local, local, req->linkinfo.data.vti6._len.local);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti6_remote(struct rt_link_setlink_req *req,
						  const void *remote,
						  size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	free(req->linkinfo.data.vti6.remote);
	req->linkinfo.data.vti6._len.remote = len;
	req->linkinfo.data.vti6.remote = malloc(req->linkinfo.data.vti6._len.remote);
	memcpy(req->linkinfo.data.vti6.remote, remote, req->linkinfo.data.vti6._len.remote);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_vti6_fwmark(struct rt_link_setlink_req *req,
						  __u32 fwmark)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.vti6 = 1;
	req->linkinfo.data.vti6._present.fwmark = 1;
	req->linkinfo.data.vti6.fwmark = fwmark;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_netkit_peer_info(struct rt_link_setlink_req *req,
						       const void *peer_info,
						       size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	free(req->linkinfo.data.netkit.peer_info);
	req->linkinfo.data.netkit._len.peer_info = len;
	req->linkinfo.data.netkit.peer_info = malloc(req->linkinfo.data.netkit._len.peer_info);
	memcpy(req->linkinfo.data.netkit.peer_info, peer_info, req->linkinfo.data.netkit._len.peer_info);
}
static inline void
rt_link_setlink_req_set_linkinfo_data_netkit_primary(struct rt_link_setlink_req *req,
						     __u8 primary)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.primary = 1;
	req->linkinfo.data.netkit.primary = primary;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_netkit_policy(struct rt_link_setlink_req *req,
						    int policy)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.policy = 1;
	req->linkinfo.data.netkit.policy = policy;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_netkit_peer_policy(struct rt_link_setlink_req *req,
							 int peer_policy)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.peer_policy = 1;
	req->linkinfo.data.netkit.peer_policy = peer_policy;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_netkit_mode(struct rt_link_setlink_req *req,
						  enum netkit_mode mode)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.mode = 1;
	req->linkinfo.data.netkit.mode = mode;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_netkit_scrub(struct rt_link_setlink_req *req,
						   int scrub)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.scrub = 1;
	req->linkinfo.data.netkit.scrub = scrub;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_netkit_peer_scrub(struct rt_link_setlink_req *req,
							int peer_scrub)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.peer_scrub = 1;
	req->linkinfo.data.netkit.peer_scrub = peer_scrub;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_netkit_headroom(struct rt_link_setlink_req *req,
						      __u16 headroom)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.headroom = 1;
	req->linkinfo.data.netkit.headroom = headroom;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_netkit_tailroom(struct rt_link_setlink_req *req,
						      __u16 tailroom)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.netkit = 1;
	req->linkinfo.data.netkit._present.tailroom = 1;
	req->linkinfo.data.netkit.tailroom = tailroom;
}
static inline void
rt_link_setlink_req_set_linkinfo_data_ovpn_mode(struct rt_link_setlink_req *req,
						enum ovpn_mode mode)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.data = 1;
	req->linkinfo.data._present.ovpn = 1;
	req->linkinfo.data.ovpn._present.mode = 1;
	req->linkinfo.data.ovpn.mode = mode;
}
static inline void
rt_link_setlink_req_set_linkinfo_xstats(struct rt_link_setlink_req *req,
					const void *xstats, size_t len)
{
	req->_present.linkinfo = 1;
	free(req->linkinfo.xstats);
	req->linkinfo._len.xstats = len;
	req->linkinfo.xstats = malloc(req->linkinfo._len.xstats);
	memcpy(req->linkinfo.xstats, xstats, req->linkinfo._len.xstats);
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_kind(struct rt_link_setlink_req *req,
					    const char *slave_kind)
{
	req->_present.linkinfo = 1;
	free(req->linkinfo.slave_kind);
	req->linkinfo._len.slave_kind = strlen(slave_kind);
	req->linkinfo.slave_kind = malloc(req->linkinfo._len.slave_kind + 1);
	memcpy(req->linkinfo.slave_kind, slave_kind, req->linkinfo._len.slave_kind);
	req->linkinfo.slave_kind[req->linkinfo._len.slave_kind] = 0;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_state(struct rt_link_setlink_req *req,
							 __u8 state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.state = 1;
	req->linkinfo.slave_data.bridge.state = state;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_priority(struct rt_link_setlink_req *req,
							    __u16 priority)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.priority = 1;
	req->linkinfo.slave_data.bridge.priority = priority;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_cost(struct rt_link_setlink_req *req,
							__u32 cost)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.cost = 1;
	req->linkinfo.slave_data.bridge.cost = cost;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mode(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mode = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_guard(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.guard = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_protect(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.protect = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_fast_leave(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.fast_leave = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_learning(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.learning = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_unicast_flood(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.unicast_flood = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_proxyarp(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.proxyarp = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_learning_sync(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.learning_sync = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_proxyarp_wifi(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.proxyarp_wifi = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_root_id(struct rt_link_setlink_req *req,
							   const void *root_id,
							   size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	free(req->linkinfo.slave_data.bridge.root_id);
	req->linkinfo.slave_data.bridge._len.root_id = len;
	req->linkinfo.slave_data.bridge.root_id = malloc(req->linkinfo.slave_data.bridge._len.root_id);
	memcpy(req->linkinfo.slave_data.bridge.root_id, root_id, req->linkinfo.slave_data.bridge._len.root_id);
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_bridge_id(struct rt_link_setlink_req *req,
							     const void *bridge_id,
							     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	free(req->linkinfo.slave_data.bridge.bridge_id);
	req->linkinfo.slave_data.bridge._len.bridge_id = len;
	req->linkinfo.slave_data.bridge.bridge_id = malloc(req->linkinfo.slave_data.bridge._len.bridge_id);
	memcpy(req->linkinfo.slave_data.bridge.bridge_id, bridge_id, req->linkinfo.slave_data.bridge._len.bridge_id);
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_designated_port(struct rt_link_setlink_req *req,
								   __u16 designated_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.designated_port = 1;
	req->linkinfo.slave_data.bridge.designated_port = designated_port;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_designated_cost(struct rt_link_setlink_req *req,
								   __u16 designated_cost)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.designated_cost = 1;
	req->linkinfo.slave_data.bridge.designated_cost = designated_cost;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_id(struct rt_link_setlink_req *req,
						      __u16 id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.id = 1;
	req->linkinfo.slave_data.bridge.id = id;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_no(struct rt_link_setlink_req *req,
						      __u16 no)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.no = 1;
	req->linkinfo.slave_data.bridge.no = no;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_topology_change_ack(struct rt_link_setlink_req *req,
								       __u8 topology_change_ack)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.topology_change_ack = 1;
	req->linkinfo.slave_data.bridge.topology_change_ack = topology_change_ack;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_config_pending(struct rt_link_setlink_req *req,
								  __u8 config_pending)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.config_pending = 1;
	req->linkinfo.slave_data.bridge.config_pending = config_pending;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_message_age_timer(struct rt_link_setlink_req *req,
								     __u64 message_age_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.message_age_timer = 1;
	req->linkinfo.slave_data.bridge.message_age_timer = message_age_timer;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_forward_delay_timer(struct rt_link_setlink_req *req,
								       __u64 forward_delay_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.forward_delay_timer = 1;
	req->linkinfo.slave_data.bridge.forward_delay_timer = forward_delay_timer;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_hold_timer(struct rt_link_setlink_req *req,
							      __u64 hold_timer)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.hold_timer = 1;
	req->linkinfo.slave_data.bridge.hold_timer = hold_timer;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_flush(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.flush = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_multicast_router(struct rt_link_setlink_req *req,
								    __u8 multicast_router)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.multicast_router = 1;
	req->linkinfo.slave_data.bridge.multicast_router = multicast_router;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mcast_flood(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_flood = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mcast_to_ucast(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_to_ucast = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_vlan_tunnel(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.vlan_tunnel = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_bcast_flood(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.bcast_flood = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_group_fwd_mask(struct rt_link_setlink_req *req,
								  __u16 group_fwd_mask)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.group_fwd_mask = 1;
	req->linkinfo.slave_data.bridge.group_fwd_mask = group_fwd_mask;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_neigh_suppress(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.neigh_suppress = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_isolated(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.isolated = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_backup_port(struct rt_link_setlink_req *req,
							       __u32 backup_port)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.backup_port = 1;
	req->linkinfo.slave_data.bridge.backup_port = backup_port;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mrp_ring_open(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mrp_ring_open = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mrp_in_open(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mrp_in_open = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mcast_eht_hosts_limit(struct rt_link_setlink_req *req,
									 __u32 mcast_eht_hosts_limit)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_eht_hosts_limit = 1;
	req->linkinfo.slave_data.bridge.mcast_eht_hosts_limit = mcast_eht_hosts_limit;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mcast_eht_hosts_cnt(struct rt_link_setlink_req *req,
								       __u32 mcast_eht_hosts_cnt)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_eht_hosts_cnt = 1;
	req->linkinfo.slave_data.bridge.mcast_eht_hosts_cnt = mcast_eht_hosts_cnt;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_locked(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.locked = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mab(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mab = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mcast_n_groups(struct rt_link_setlink_req *req,
								  __u32 mcast_n_groups)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_n_groups = 1;
	req->linkinfo.slave_data.bridge.mcast_n_groups = mcast_n_groups;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_mcast_max_groups(struct rt_link_setlink_req *req,
								    __u32 mcast_max_groups)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.mcast_max_groups = 1;
	req->linkinfo.slave_data.bridge.mcast_max_groups = mcast_max_groups;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_neigh_vlan_suppress(struct rt_link_setlink_req *req)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.neigh_vlan_suppress = 1;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bridge_backup_nhid(struct rt_link_setlink_req *req,
							       __u32 backup_nhid)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bridge = 1;
	req->linkinfo.slave_data.bridge._present.backup_nhid = 1;
	req->linkinfo.slave_data.bridge.backup_nhid = backup_nhid;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bond_state(struct rt_link_setlink_req *req,
						       __u8 state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.state = 1;
	req->linkinfo.slave_data.bond.state = state;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bond_mii_status(struct rt_link_setlink_req *req,
							    __u8 mii_status)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.mii_status = 1;
	req->linkinfo.slave_data.bond.mii_status = mii_status;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bond_link_failure_count(struct rt_link_setlink_req *req,
								    __u32 link_failure_count)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.link_failure_count = 1;
	req->linkinfo.slave_data.bond.link_failure_count = link_failure_count;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bond_perm_hwaddr(struct rt_link_setlink_req *req,
							     const void *perm_hwaddr,
							     size_t len)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	free(req->linkinfo.slave_data.bond.perm_hwaddr);
	req->linkinfo.slave_data.bond._len.perm_hwaddr = len;
	req->linkinfo.slave_data.bond.perm_hwaddr = malloc(req->linkinfo.slave_data.bond._len.perm_hwaddr);
	memcpy(req->linkinfo.slave_data.bond.perm_hwaddr, perm_hwaddr, req->linkinfo.slave_data.bond._len.perm_hwaddr);
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bond_queue_id(struct rt_link_setlink_req *req,
							  __u16 queue_id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.queue_id = 1;
	req->linkinfo.slave_data.bond.queue_id = queue_id;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bond_ad_aggregator_id(struct rt_link_setlink_req *req,
								  __u16 ad_aggregator_id)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.ad_aggregator_id = 1;
	req->linkinfo.slave_data.bond.ad_aggregator_id = ad_aggregator_id;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bond_ad_actor_oper_port_state(struct rt_link_setlink_req *req,
									  __u8 ad_actor_oper_port_state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.ad_actor_oper_port_state = 1;
	req->linkinfo.slave_data.bond.ad_actor_oper_port_state = ad_actor_oper_port_state;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bond_ad_partner_oper_port_state(struct rt_link_setlink_req *req,
									    __u16 ad_partner_oper_port_state)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.ad_partner_oper_port_state = 1;
	req->linkinfo.slave_data.bond.ad_partner_oper_port_state = ad_partner_oper_port_state;
}
static inline void
rt_link_setlink_req_set_linkinfo_slave_data_bond_prio(struct rt_link_setlink_req *req,
						      __u32 prio)
{
	req->_present.linkinfo = 1;
	req->linkinfo._present.slave_data = 1;
	req->linkinfo.slave_data._present.bond = 1;
	req->linkinfo.slave_data.bond._present.prio = 1;
	req->linkinfo.slave_data.bond.prio = prio;
}
static inline void
rt_link_setlink_req_set_net_ns_pid(struct rt_link_setlink_req *req,
				   __u32 net_ns_pid)
{
	req->_present.net_ns_pid = 1;
	req->net_ns_pid = net_ns_pid;
}
static inline void
rt_link_setlink_req_set_ifalias(struct rt_link_setlink_req *req,
				const char *ifalias)
{
	free(req->ifalias);
	req->_len.ifalias = strlen(ifalias);
	req->ifalias = malloc(req->_len.ifalias + 1);
	memcpy(req->ifalias, ifalias, req->_len.ifalias);
	req->ifalias[req->_len.ifalias] = 0;
}
static inline void
rt_link_setlink_req_set_num_vf(struct rt_link_setlink_req *req, __u32 num_vf)
{
	req->_present.num_vf = 1;
	req->num_vf = num_vf;
}
static inline void
__rt_link_setlink_req_set_vfinfo_list_info(struct rt_link_setlink_req *req,
					   struct rt_link_vfinfo_attrs *info,
					   unsigned int n_info)
{
	unsigned int i;

	req->_present.vfinfo_list = 1;
	for (i = 0; i < req->vfinfo_list._count.info; i++)
		rt_link_vfinfo_attrs_free(&req->vfinfo_list.info[i]);
	free(req->vfinfo_list.info);
	req->vfinfo_list.info = info;
	req->vfinfo_list._count.info = n_info;
}
static inline void
rt_link_setlink_req_set_stats64(struct rt_link_setlink_req *req,
				const void *stats64, size_t len)
{
	free(req->stats64);
	req->_len.stats64 = len;
	req->stats64 = malloc(req->_len.stats64);
	memcpy(req->stats64, stats64, req->_len.stats64);
}
static inline void
rt_link_setlink_req_set_af_spec_inet_conf(struct rt_link_setlink_req *req,
					  __u32 *conf, size_t count)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet = 1;
	free(req->af_spec.inet.conf);
	req->af_spec.inet._count.conf = count;
	count *= sizeof(__u32);
	req->af_spec.inet.conf = malloc(count);
	memcpy(req->af_spec.inet.conf, conf, count);
}
static inline void
rt_link_setlink_req_set_af_spec_inet6_flags(struct rt_link_setlink_req *req,
					    __u32 flags)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	req->af_spec.inet6._present.flags = 1;
	req->af_spec.inet6.flags = flags;
}
static inline void
rt_link_setlink_req_set_af_spec_inet6_conf(struct rt_link_setlink_req *req,
					   __u32 *conf, size_t count)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.conf);
	req->af_spec.inet6._count.conf = count;
	count *= sizeof(__u32);
	req->af_spec.inet6.conf = malloc(count);
	memcpy(req->af_spec.inet6.conf, conf, count);
}
static inline void
rt_link_setlink_req_set_af_spec_inet6_stats(struct rt_link_setlink_req *req,
					    __u64 *stats, size_t count)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.stats);
	req->af_spec.inet6._count.stats = count;
	count *= sizeof(__u64);
	req->af_spec.inet6.stats = malloc(count);
	memcpy(req->af_spec.inet6.stats, stats, count);
}
static inline void
rt_link_setlink_req_set_af_spec_inet6_mcast(struct rt_link_setlink_req *req,
					    const void *mcast, size_t len)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.mcast);
	req->af_spec.inet6._len.mcast = len;
	req->af_spec.inet6.mcast = malloc(req->af_spec.inet6._len.mcast);
	memcpy(req->af_spec.inet6.mcast, mcast, req->af_spec.inet6._len.mcast);
}
static inline void
rt_link_setlink_req_set_af_spec_inet6_cacheinfo(struct rt_link_setlink_req *req,
						const void *cacheinfo,
						size_t len)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.cacheinfo);
	req->af_spec.inet6._len.cacheinfo = len;
	req->af_spec.inet6.cacheinfo = malloc(req->af_spec.inet6._len.cacheinfo);
	memcpy(req->af_spec.inet6.cacheinfo, cacheinfo, req->af_spec.inet6._len.cacheinfo);
}
static inline void
rt_link_setlink_req_set_af_spec_inet6_icmp6stats(struct rt_link_setlink_req *req,
						 __u64 *icmp6stats,
						 size_t count)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.icmp6stats);
	req->af_spec.inet6._count.icmp6stats = count;
	count *= sizeof(__u64);
	req->af_spec.inet6.icmp6stats = malloc(count);
	memcpy(req->af_spec.inet6.icmp6stats, icmp6stats, count);
}
static inline void
rt_link_setlink_req_set_af_spec_inet6_token(struct rt_link_setlink_req *req,
					    const void *token, size_t len)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	free(req->af_spec.inet6.token);
	req->af_spec.inet6._len.token = len;
	req->af_spec.inet6.token = malloc(req->af_spec.inet6._len.token);
	memcpy(req->af_spec.inet6.token, token, req->af_spec.inet6._len.token);
}
static inline void
rt_link_setlink_req_set_af_spec_inet6_addr_gen_mode(struct rt_link_setlink_req *req,
						    __u8 addr_gen_mode)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	req->af_spec.inet6._present.addr_gen_mode = 1;
	req->af_spec.inet6.addr_gen_mode = addr_gen_mode;
}
static inline void
rt_link_setlink_req_set_af_spec_inet6_ra_mtu(struct rt_link_setlink_req *req,
					     __u32 ra_mtu)
{
	req->_present.af_spec = 1;
	req->af_spec._present.inet6 = 1;
	req->af_spec.inet6._present.ra_mtu = 1;
	req->af_spec.inet6.ra_mtu = ra_mtu;
}
static inline void
rt_link_setlink_req_set_af_spec_mctp_net(struct rt_link_setlink_req *req,
					 __u32 net)
{
	req->_present.af_spec = 1;
	req->af_spec._present.mctp = 1;
	req->af_spec.mctp._present.net = 1;
	req->af_spec.mctp.net = net;
}
static inline void
rt_link_setlink_req_set_af_spec_mctp_phys_binding(struct rt_link_setlink_req *req,
						  __u8 phys_binding)
{
	req->_present.af_spec = 1;
	req->af_spec._present.mctp = 1;
	req->af_spec.mctp._present.phys_binding = 1;
	req->af_spec.mctp.phys_binding = phys_binding;
}
static inline void
rt_link_setlink_req_set_group(struct rt_link_setlink_req *req, __u32 group)
{
	req->_present.group = 1;
	req->group = group;
}
static inline void
rt_link_setlink_req_set_net_ns_fd(struct rt_link_setlink_req *req,
				  __u32 net_ns_fd)
{
	req->_present.net_ns_fd = 1;
	req->net_ns_fd = net_ns_fd;
}
static inline void
rt_link_setlink_req_set_ext_mask(struct rt_link_setlink_req *req,
				 __u32 ext_mask)
{
	req->_present.ext_mask = 1;
	req->ext_mask = ext_mask;
}
static inline void
rt_link_setlink_req_set_promiscuity(struct rt_link_setlink_req *req,
				    __u32 promiscuity)
{
	req->_present.promiscuity = 1;
	req->promiscuity = promiscuity;
}
static inline void
rt_link_setlink_req_set_num_tx_queues(struct rt_link_setlink_req *req,
				      __u32 num_tx_queues)
{
	req->_present.num_tx_queues = 1;
	req->num_tx_queues = num_tx_queues;
}
static inline void
rt_link_setlink_req_set_num_rx_queues(struct rt_link_setlink_req *req,
				      __u32 num_rx_queues)
{
	req->_present.num_rx_queues = 1;
	req->num_rx_queues = num_rx_queues;
}
static inline void
rt_link_setlink_req_set_carrier(struct rt_link_setlink_req *req, __u8 carrier)
{
	req->_present.carrier = 1;
	req->carrier = carrier;
}
static inline void
rt_link_setlink_req_set_phys_port_id(struct rt_link_setlink_req *req,
				     const void *phys_port_id, size_t len)
{
	free(req->phys_port_id);
	req->_len.phys_port_id = len;
	req->phys_port_id = malloc(req->_len.phys_port_id);
	memcpy(req->phys_port_id, phys_port_id, req->_len.phys_port_id);
}
static inline void
rt_link_setlink_req_set_carrier_changes(struct rt_link_setlink_req *req,
					__u32 carrier_changes)
{
	req->_present.carrier_changes = 1;
	req->carrier_changes = carrier_changes;
}
static inline void
rt_link_setlink_req_set_phys_switch_id(struct rt_link_setlink_req *req,
				       const void *phys_switch_id, size_t len)
{
	free(req->phys_switch_id);
	req->_len.phys_switch_id = len;
	req->phys_switch_id = malloc(req->_len.phys_switch_id);
	memcpy(req->phys_switch_id, phys_switch_id, req->_len.phys_switch_id);
}
static inline void
rt_link_setlink_req_set_link_netnsid(struct rt_link_setlink_req *req,
				     __s32 link_netnsid)
{
	req->_present.link_netnsid = 1;
	req->link_netnsid = link_netnsid;
}
static inline void
rt_link_setlink_req_set_phys_port_name(struct rt_link_setlink_req *req,
				       const char *phys_port_name)
{
	free(req->phys_port_name);
	req->_len.phys_port_name = strlen(phys_port_name);
	req->phys_port_name = malloc(req->_len.phys_port_name + 1);
	memcpy(req->phys_port_name, phys_port_name, req->_len.phys_port_name);
	req->phys_port_name[req->_len.phys_port_name] = 0;
}
static inline void
rt_link_setlink_req_set_proto_down(struct rt_link_setlink_req *req,
				   __u8 proto_down)
{
	req->_present.proto_down = 1;
	req->proto_down = proto_down;
}
static inline void
rt_link_setlink_req_set_gso_max_segs(struct rt_link_setlink_req *req,
				     __u32 gso_max_segs)
{
	req->_present.gso_max_segs = 1;
	req->gso_max_segs = gso_max_segs;
}
static inline void
rt_link_setlink_req_set_gso_max_size(struct rt_link_setlink_req *req,
				     __u32 gso_max_size)
{
	req->_present.gso_max_size = 1;
	req->gso_max_size = gso_max_size;
}
static inline void
rt_link_setlink_req_set_xdp_fd(struct rt_link_setlink_req *req, __s32 fd)
{
	req->_present.xdp = 1;
	req->xdp._present.fd = 1;
	req->xdp.fd = fd;
}
static inline void
rt_link_setlink_req_set_xdp_attached(struct rt_link_setlink_req *req,
				     __u8 attached)
{
	req->_present.xdp = 1;
	req->xdp._present.attached = 1;
	req->xdp.attached = attached;
}
static inline void
rt_link_setlink_req_set_xdp_flags(struct rt_link_setlink_req *req, __u32 flags)
{
	req->_present.xdp = 1;
	req->xdp._present.flags = 1;
	req->xdp.flags = flags;
}
static inline void
rt_link_setlink_req_set_xdp_prog_id(struct rt_link_setlink_req *req,
				    __u32 prog_id)
{
	req->_present.xdp = 1;
	req->xdp._present.prog_id = 1;
	req->xdp.prog_id = prog_id;
}
static inline void
rt_link_setlink_req_set_xdp_drv_prog_id(struct rt_link_setlink_req *req,
					__u32 drv_prog_id)
{
	req->_present.xdp = 1;
	req->xdp._present.drv_prog_id = 1;
	req->xdp.drv_prog_id = drv_prog_id;
}
static inline void
rt_link_setlink_req_set_xdp_skb_prog_id(struct rt_link_setlink_req *req,
					__u32 skb_prog_id)
{
	req->_present.xdp = 1;
	req->xdp._present.skb_prog_id = 1;
	req->xdp.skb_prog_id = skb_prog_id;
}
static inline void
rt_link_setlink_req_set_xdp_hw_prog_id(struct rt_link_setlink_req *req,
				       __u32 hw_prog_id)
{
	req->_present.xdp = 1;
	req->xdp._present.hw_prog_id = 1;
	req->xdp.hw_prog_id = hw_prog_id;
}
static inline void
rt_link_setlink_req_set_xdp_expected_fd(struct rt_link_setlink_req *req,
					__s32 expected_fd)
{
	req->_present.xdp = 1;
	req->xdp._present.expected_fd = 1;
	req->xdp.expected_fd = expected_fd;
}
static inline void
rt_link_setlink_req_set_event(struct rt_link_setlink_req *req, __u32 event)
{
	req->_present.event = 1;
	req->event = event;
}
static inline void
rt_link_setlink_req_set_new_netnsid(struct rt_link_setlink_req *req,
				    __s32 new_netnsid)
{
	req->_present.new_netnsid = 1;
	req->new_netnsid = new_netnsid;
}
static inline void
rt_link_setlink_req_set_target_netnsid(struct rt_link_setlink_req *req,
				       __s32 target_netnsid)
{
	req->_present.target_netnsid = 1;
	req->target_netnsid = target_netnsid;
}
static inline void
rt_link_setlink_req_set_carrier_up_count(struct rt_link_setlink_req *req,
					 __u32 carrier_up_count)
{
	req->_present.carrier_up_count = 1;
	req->carrier_up_count = carrier_up_count;
}
static inline void
rt_link_setlink_req_set_carrier_down_count(struct rt_link_setlink_req *req,
					   __u32 carrier_down_count)
{
	req->_present.carrier_down_count = 1;
	req->carrier_down_count = carrier_down_count;
}
static inline void
rt_link_setlink_req_set_new_ifindex(struct rt_link_setlink_req *req,
				    __s32 new_ifindex)
{
	req->_present.new_ifindex = 1;
	req->new_ifindex = new_ifindex;
}
static inline void
rt_link_setlink_req_set_min_mtu(struct rt_link_setlink_req *req, __u32 min_mtu)
{
	req->_present.min_mtu = 1;
	req->min_mtu = min_mtu;
}
static inline void
rt_link_setlink_req_set_max_mtu(struct rt_link_setlink_req *req, __u32 max_mtu)
{
	req->_present.max_mtu = 1;
	req->max_mtu = max_mtu;
}
static inline void
__rt_link_setlink_req_set_prop_list_alt_ifname(struct rt_link_setlink_req *req,
					       struct ynl_string **alt_ifname,
					       unsigned int n_alt_ifname)
{
	unsigned int i;

	req->_present.prop_list = 1;
	for (i = 0; i < req->prop_list._count.alt_ifname; i++)
		free(req->prop_list.alt_ifname[i]);
	free(req->prop_list.alt_ifname);
	req->prop_list.alt_ifname = alt_ifname;
	req->prop_list._count.alt_ifname = n_alt_ifname;
}
static inline void
rt_link_setlink_req_set_perm_address(struct rt_link_setlink_req *req,
				     const void *perm_address, size_t len)
{
	free(req->perm_address);
	req->_len.perm_address = len;
	req->perm_address = malloc(req->_len.perm_address);
	memcpy(req->perm_address, perm_address, req->_len.perm_address);
}
static inline void
rt_link_setlink_req_set_proto_down_reason(struct rt_link_setlink_req *req,
					  const char *proto_down_reason)
{
	free(req->proto_down_reason);
	req->_len.proto_down_reason = strlen(proto_down_reason);
	req->proto_down_reason = malloc(req->_len.proto_down_reason + 1);
	memcpy(req->proto_down_reason, proto_down_reason, req->_len.proto_down_reason);
	req->proto_down_reason[req->_len.proto_down_reason] = 0;
}
static inline void
rt_link_setlink_req_set_parent_dev_name(struct rt_link_setlink_req *req,
					const char *parent_dev_name)
{
	free(req->parent_dev_name);
	req->_len.parent_dev_name = strlen(parent_dev_name);
	req->parent_dev_name = malloc(req->_len.parent_dev_name + 1);
	memcpy(req->parent_dev_name, parent_dev_name, req->_len.parent_dev_name);
	req->parent_dev_name[req->_len.parent_dev_name] = 0;
}
static inline void
rt_link_setlink_req_set_parent_dev_bus_name(struct rt_link_setlink_req *req,
					    const char *parent_dev_bus_name)
{
	free(req->parent_dev_bus_name);
	req->_len.parent_dev_bus_name = strlen(parent_dev_bus_name);
	req->parent_dev_bus_name = malloc(req->_len.parent_dev_bus_name + 1);
	memcpy(req->parent_dev_bus_name, parent_dev_bus_name, req->_len.parent_dev_bus_name);
	req->parent_dev_bus_name[req->_len.parent_dev_bus_name] = 0;
}
static inline void
rt_link_setlink_req_set_gro_max_size(struct rt_link_setlink_req *req,
				     __u32 gro_max_size)
{
	req->_present.gro_max_size = 1;
	req->gro_max_size = gro_max_size;
}
static inline void
rt_link_setlink_req_set_tso_max_size(struct rt_link_setlink_req *req,
				     __u32 tso_max_size)
{
	req->_present.tso_max_size = 1;
	req->tso_max_size = tso_max_size;
}
static inline void
rt_link_setlink_req_set_tso_max_segs(struct rt_link_setlink_req *req,
				     __u32 tso_max_segs)
{
	req->_present.tso_max_segs = 1;
	req->tso_max_segs = tso_max_segs;
}
static inline void
rt_link_setlink_req_set_allmulti(struct rt_link_setlink_req *req,
				 __u32 allmulti)
{
	req->_present.allmulti = 1;
	req->allmulti = allmulti;
}
static inline void
rt_link_setlink_req_set_devlink_port(struct rt_link_setlink_req *req,
				     const void *devlink_port, size_t len)
{
	free(req->devlink_port);
	req->_len.devlink_port = len;
	req->devlink_port = malloc(req->_len.devlink_port);
	memcpy(req->devlink_port, devlink_port, req->_len.devlink_port);
}
static inline void
rt_link_setlink_req_set_gso_ipv4_max_size(struct rt_link_setlink_req *req,
					  __u32 gso_ipv4_max_size)
{
	req->_present.gso_ipv4_max_size = 1;
	req->gso_ipv4_max_size = gso_ipv4_max_size;
}
static inline void
rt_link_setlink_req_set_gro_ipv4_max_size(struct rt_link_setlink_req *req,
					  __u32 gro_ipv4_max_size)
{
	req->_present.gro_ipv4_max_size = 1;
	req->gro_ipv4_max_size = gro_ipv4_max_size;
}

/*
 * Set information about a link.
 */
int rt_link_setlink(struct ynl_sock *ys, struct rt_link_setlink_req *req);

/* ============== RTM_GETSTATS ============== */
/* RTM_GETSTATS - do */
struct rt_link_getstats_req {
	__u16 _nlmsg_flags;

	struct if_stats_msg _hdr;
};

static inline struct rt_link_getstats_req *rt_link_getstats_req_alloc(void)
{
	return calloc(1, sizeof(struct rt_link_getstats_req));
}
void rt_link_getstats_req_free(struct rt_link_getstats_req *req);

static inline void
rt_link_getstats_req_set_nlflags(struct rt_link_getstats_req *req,
				 __u16 nl_flags)
{
	req->_nlmsg_flags = nl_flags;
}

struct rt_link_getstats_rsp {
	struct if_stats_msg _hdr;

	struct {
		__u32 link_offload_xstats:1;
	} _present;
	struct {
		__u32 link_64;
		__u32 link_xstats;
		__u32 link_xstats_slave;
		__u32 af_spec;
	} _len;

	struct rtnl_link_stats64 *link_64;
	void *link_xstats;
	void *link_xstats_slave;
	struct rt_link_link_offload_xstats link_offload_xstats;
	void *af_spec;
};

void rt_link_getstats_rsp_free(struct rt_link_getstats_rsp *rsp);

/*
 * Get / dump link stats.
 */
struct rt_link_getstats_rsp *
rt_link_getstats(struct ynl_sock *ys, struct rt_link_getstats_req *req);

/* RTM_GETSTATS - dump */
struct rt_link_getstats_req_dump {
	struct if_stats_msg _hdr;
};

static inline struct rt_link_getstats_req_dump *
rt_link_getstats_req_dump_alloc(void)
{
	return calloc(1, sizeof(struct rt_link_getstats_req_dump));
}
void rt_link_getstats_req_dump_free(struct rt_link_getstats_req_dump *req);

struct rt_link_getstats_list {
	struct rt_link_getstats_list *next;
	struct rt_link_getstats_rsp obj __attribute__((aligned(8)));
};

void rt_link_getstats_list_free(struct rt_link_getstats_list *rsp);

struct rt_link_getstats_list *
rt_link_getstats_dump(struct ynl_sock *ys,
		      struct rt_link_getstats_req_dump *req);

#endif /* _LINUX_RT_LINK_GEN_H */
